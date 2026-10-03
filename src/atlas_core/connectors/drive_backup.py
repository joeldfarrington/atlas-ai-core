"""Narrow Drive backup transport; no automatic credential discovery or activation.

Reference: developers.google.com/workspace/drive/api/guides/create-file
The private state directory and staged archive are trusted, quiescent inputs.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import time
from typing import Any, Callable
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx

from atlas_core.errors import ConnectorError
from atlas_core.connectors.google import SecretStore

DRIVE_SCOPE = "https://www.googleapis.com/auth/drive.file"
API = "https://www.googleapis.com/drive/v3"
UPLOAD = "https://www.googleapis.com/upload/drive/v3/files"
AUTH = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN = "https://oauth2.googleapis.com/token"
ID = re.compile(r"[A-Za-z0-9_-]{1,160}\Z")
SNAPSHOT = re.compile(r"[a-z0-9][a-z0-9_-]{0,79}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
MAX_JSON = 65536
FILE_FIELDS = "id,mimeType,parents,trashed,size,sha256Checksum,appProperties,shared,ownedByMe"
_ERROR_REASONS = frozenset({
    "accessNotConfigured", "SERVICE_DISABLED", "API_DISABLED",
    "insufficientPermissions", "ACCESS_TOKEN_SCOPE_INSUFFICIENT",
    "appNotAuthorizedToFile", "insufficientFilePermissions", "domainPolicy",
    "rateLimitExceeded", "userRateLimitExceeded", "dailyLimitExceeded",
    "RATE_LIMIT_EXCEEDED", "invalid_grant", "invalid_client",
    "unauthorized_client", "access_denied", "admin_policy_enforced", "org_internal",
    "invalid_scope",
})
_OPERATIONS = frozenset({"request", "authorization exchange", "account verification", "folder verification"})


def _error_reason(response):
    """Read bounded error metadata; return only a fixed public reason code."""
    try:
        if response.headers.get("Content-Encoding", "identity").lower() != "identity":
            return "unavailable"
        length = response.headers.get("Content-Length")
        if length is not None and (not length.isdigit() or int(length) > MAX_JSON):
            return "unavailable"
        raw = bytearray()
        for chunk in response.iter_raw(chunk_size=65536):
            if len(raw) + len(chunk) > MAX_JSON:
                return "unavailable"
            raw.extend(chunk)
        error = _json(bytes(raw)).get("error")
        candidates = [error] if isinstance(error, str) else []
        if isinstance(error, dict):
            for field in ("errors", "details"):
                entries = error.get(field)
                if isinstance(entries, list):
                    candidates.extend(item.get("reason") for item in entries if isinstance(item, dict))
        return next((item for item in candidates if isinstance(item, str) and item in _ERROR_REASONS), "unavailable")
    except (ConnectorError, httpx.HTTPError, ValueError):
        return "unavailable"


def _identifier(value: Any) -> str:
    if not isinstance(value, str) or not ID.fullmatch(value) or value == "root":
        raise ConnectorError("A concrete Drive identifier is required")
    return value


def _json(raw: bytes) -> dict[str, Any]:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate")
            result[key] = value
        return result
    try:
        data = json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ConnectorError("Drive returned invalid metadata") from exc
    if not isinstance(data, dict):
        raise ConnectorError("Drive returned invalid metadata")
    return data


@contextmanager
def _directory(path: Path):
    path = path.absolute()
    if ".." in path.parts:
        raise ConnectorError("Parent traversal is forbidden")
    descriptor = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            newer = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = newer
        yield descriptor
    except OSError as exc:
        raise ConnectorError("Backup directory is unavailable or linked") from exc
    finally:
        os.close(descriptor)


def _signature(value):
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
            value.st_ctime_ns, value.st_mode, value.st_nlink)


class _HTTP:
    def __init__(self, transport=None):
        self.client = httpx.Client(transport=transport, timeout=30, follow_redirects=False,
                                   trust_env=False, headers={"Accept-Encoding": "identity"})

    def close(self):
        self.client.close()

    def request(self, method, url, *, token=None, params=None, content=None, headers=None, data=None,
                limit=MAX_JSON, allowed=(200,), operation="request"):
        if operation not in _OPERATIONS:
            raise ConnectorError("Invalid Drive request operation")
        request_headers = dict(headers or {})
        if token is not None:
            if not isinstance(token, str) or not token or len(token) > 16384 or any(ord(c) < 33 or ord(c) > 126 for c in token):
                raise ConnectorError("Backup authorization is unavailable")
            request_headers["Authorization"] = "Bearer " + token
        # Do not accept server cookies or ambient client authentication on later calls.
        self.client.cookies.clear()
        try:
            with self.client.stream(method, url, params=params, content=content, data=data,
                                    headers=request_headers) as response:
                if response.status_code not in allowed:
                    reason = _error_reason(response)
                    raise ConnectorError(f"Drive {operation} rejected (HTTP {response.status_code}; reason={reason})")
                if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                    raise ConnectorError("Encoded Drive responses are unsupported")
                length = response.headers.get("Content-Length")
                if length is not None and (not length.isdigit() or int(length) > limit):
                    raise ConnectorError("Drive response exceeds its bound")
                result = bytearray()
                for chunk in response.iter_raw(chunk_size=65536):
                    if len(result) + len(chunk) > limit:
                        raise ConnectorError("Drive response exceeds its bound")
                    result.extend(chunk)
                return response.status_code, bytes(result)
        except httpx.HTTPError as exc:
            raise ConnectorError("Drive request interrupted; retain the same upload identity") from exc
        finally:
            self.client.cookies.clear()


class DriveBackupTransport:
    """Explicitly bound, single-folder binary backup upload and verified download.

    Nothing reads Keychain or connects during construction. token_provider is an
    owner-bound callable; no provider means every remote operation fails closed.
    No delete/update/list-all/permission operation is exposed.
    """
    def __init__(self, *, folder_id: str, state_dir: Path,
                 token_provider: Callable[[], str] | None = None,
                 http_transport=None, max_archive_bytes: int = 5_000_000):
        self.folder_id = _identifier(folder_id)
        self.destination_id = self.folder_id
        if type(max_archive_bytes) is not int or not 1 <= max_archive_bytes <= 5_000_000:
            raise ConnectorError("This multipart adapter is limited to 5 MB; larger archives require resumable uploads")
        self.max_archive_bytes = max_archive_bytes
        self.token_provider = token_provider
        self.http = _HTTP(http_transport)
        self.state_dir = Path(state_dir).absolute()
        self.state_dir.mkdir(mode=0o700, exist_ok=True)
        with _directory(self.state_dir) as parent:
            info = os.fstat(parent)
            if info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ConnectorError("Backup state directory must be private and owner-controlled")
            try:
                fd = os.open("drive-uploads.sqlite", os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            except FileExistsError:
                pass
            else:
                os.close(fd)
            info = os.stat("drive-uploads.sqlite", dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ConnectorError("Backup upload ledger must be a private regular file")
        self.ledger = self.state_dir / "drive-uploads.sqlite"
        with self._db() as connection:
            connection.execute("CREATE TABLE IF NOT EXISTS uploads (snapshot TEXT PRIMARY KEY, folder TEXT NOT NULL, digest TEXT NOT NULL, size INTEGER NOT NULL, file_id TEXT NOT NULL UNIQUE)")

    @contextmanager
    def _db(self):
        info = self.ledger.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ConnectorError("Backup upload ledger changed")
        connection = sqlite3.connect(self.ledger, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA synchronous=FULL")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def close(self):
        self.http.close()

    def _token(self):
        if self.token_provider is None:
            raise ConnectorError("Atlas backup Drive connection is not bound")
        try:
            token = self.token_provider()
            if not isinstance(token, str) or not token:
                raise ValueError("missing token")
            return token
        except Exception as exc:
            raise ConnectorError("Atlas backup authorization is unavailable") from exc

    def _metadata(self, file_id, *, allow_missing=False):
        status, raw = self.http.request("GET", API + "/files/" + _identifier(file_id),
                                       token=self._token(), params={"fields": FILE_FIELDS},
                                       allowed=(200, 404) if allow_missing else (200,))
        return None if status == 404 else _json(raw)

    def verify_folder(self):
        _, raw = self.http.request("GET", API + "/files/" + self.folder_id, token=self._token(),
                                  params={"fields": "id,mimeType,trashed,shared,ownedByMe,capabilities(canAddChildren)"})
        data = _json(raw)
        if (data.get("id") != self.folder_id or data.get("mimeType") != "application/vnd.google-apps.folder"
                or data.get("trashed") is not False or data.get("shared") is not False
                or data.get("ownedByMe") is not True or not isinstance(data.get("capabilities"), dict)
                or data["capabilities"].get("canAddChildren") is not True):
            raise ConnectorError("The selected backup folder is not verified private, owned, and writable")
        return {"folder_id": self.folder_id, "private": True, "writable": True}

    def _identity(self, snapshot, digest, size):
        # Commit the pre-generated ID before any remote creation. A crash may
        # waste an unused generated ID, but cannot create an unrecorded file.
        with self._db() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM uploads WHERE snapshot=?", (snapshot,)).fetchone()
            if row is not None:
                if (row["folder"], row["digest"], row["size"]) != (self.folder_id, digest, size):
                    raise ConnectorError("Snapshot identity is already bound to different backup content")
                return row["file_id"]
            _, raw = self.http.request("GET", API + "/files/generateIds", token=self._token(),
                                      params={"count": 1, "space": "drive", "type": "files"})
            ids = _json(raw).get("ids")
            if not isinstance(ids, list) or len(ids) != 1:
                raise ConnectorError("Drive did not allocate one upload identity")
            file_id = _identifier(ids[0])
            connection.execute("INSERT INTO uploads VALUES (?,?,?,?,?)", (snapshot, self.folder_id, digest, size, file_id))
        return file_id

    def _verify(self, data, file_id, snapshot, digest, size):
        expected = {"atlas_snapshot": snapshot, "atlas_sha256": digest, "atlas_backup": "1"}
        if (data.get("id") != file_id or data.get("parents") != [self.folder_id]
                or data.get("trashed") is not False or data.get("mimeType") != "application/zip"
                or data.get("shared") is not False or data.get("ownedByMe") is not True
                or data.get("size") != str(size) or data.get("sha256Checksum") != digest
                or data.get("appProperties") != expected):
            raise ConnectorError("Drive backup does not match its recorded identity and content")

    def upload(self, path: Path, *, snapshot_id: str, archive_sha256: str, archive_bytes: int) -> str:
        snapshot = _identifier(snapshot_id)
        if not SNAPSHOT.fullmatch(snapshot):
            raise ConnectorError("Invalid bounded snapshot identifier")
        if not isinstance(archive_sha256, str) or not DIGEST.fullmatch(archive_sha256):
            raise ConnectorError("Invalid backup digest")
        if type(archive_bytes) is not int or not 1 <= archive_bytes <= self.max_archive_bytes:
            raise ConnectorError("Backup exceeds the configured size bound")
        self._token()  # Refuse unbound state before opening any staged content.
        source = Path(path).absolute()
        with _directory(source.parent) as directory:
            try:
                fd = os.open(source.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            except OSError as exc:
                raise ConnectorError("Backup source is unavailable or linked") from exc
            with os.fdopen(fd, "rb") as handle:
                before = os.fstat(handle.fileno())
                if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != archive_bytes:
                    raise ConnectorError("Backup source is not the expected regular archive")
                digest = hashlib.sha256()
                remaining = archive_bytes
                while remaining:
                    chunk = handle.read(min(65536, remaining))
                    if not chunk:
                        raise ConnectorError("Backup source changed")
                    digest.update(chunk)
                    remaining -= len(chunk)
                if handle.read(1) or digest.hexdigest() != archive_sha256 or _signature(os.fstat(handle.fileno())) != _signature(before):
                    raise ConnectorError("Backup source digest changed")
                self.verify_folder()
                file_id = self._identity(snapshot, archive_sha256, archive_bytes)
                remote = self._metadata(file_id, allow_missing=True)
                if remote is None:
                    metadata = {"id": file_id, "name": "atlas-" + snapshot + ".zip", "mimeType": "application/zip",
                                "parents": [self.folder_id], "appProperties": {"atlas_snapshot": snapshot,
                                "atlas_sha256": archive_sha256, "atlas_backup": "1"}}
                    boundary = "atlas_" + secrets.token_hex(24)
                    prefix = ("--" + boundary + "\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n" +
                              json.dumps(metadata, separators=(",", ":")) + "\r\n--" + boundary +
                              "\r\nContent-Type: application/zip\r\n\r\n").encode()
                    suffix = ("\r\n--" + boundary + "--\r\n").encode()
                    def body():
                        handle.seek(0)
                        yield prefix
                        remaining = archive_bytes
                        while remaining:
                            chunk = handle.read(min(65536, remaining))
                            if not chunk:
                                raise ConnectorError("Backup source changed during upload")
                            remaining -= len(chunk)
                            yield chunk
                        if _signature(os.fstat(handle.fileno())) != _signature(before):
                            raise ConnectorError("Backup source changed during upload")
                        yield suffix
                    self.http.request("POST", UPLOAD, token=self._token(), params={"uploadType": "multipart", "fields": "id"},
                                      content=body(), headers={"Content-Type": "multipart/related; boundary=" + boundary,
                                      "Content-Length": str(len(prefix) + archive_bytes + len(suffix))}, allowed=(200, 201, 409))
                    remote = self._metadata(file_id)
                self._verify(remote, file_id, snapshot, archive_sha256, archive_bytes)
                return file_id

    def download(self, file_id: str):
        file_id = _identifier(file_id)
        with self._db() as connection:
            row = connection.execute("SELECT * FROM uploads WHERE file_id=? AND folder=?", (file_id, self.folder_id)).fetchone()
        if row is None:
            raise ConnectorError("Only an upload recorded by this backup connection can be downloaded")
        self.verify_folder()
        self._verify(self._metadata(file_id), file_id, row["snapshot"], row["digest"], row["size"])
        # The maintenance caller owns its exclusive download target and its own
        # verification. Do not create destination files or buffer whole archives.
        total, digest = 0, hashlib.sha256()
        token = self._token()
        if len(token) > 16384 or any(ord(c) < 33 or ord(c) > 126 for c in token):
            raise ConnectorError("Backup authorization is unavailable")
        self.http.client.cookies.clear()
        try:
            with self.http.client.stream("GET", API + "/files/" + file_id, params={"alt": "media"},
                                        headers={"Authorization": "Bearer " + token}) as response:
                if response.status_code != 200 or response.headers.get("Content-Encoding", "identity").lower() != "identity":
                    raise ConnectorError("Drive backup download was refused or encoded")
                for chunk in response.iter_raw(chunk_size=65536):
                    if total + len(chunk) > min(row["size"], self.max_archive_bytes):
                        raise ConnectorError("Downloaded backup exceeds its recorded size")
                    total += len(chunk)
                    digest.update(chunk)
                    if chunk:
                        yield chunk
                if total != row["size"] or digest.hexdigest() != row["digest"]:
                    raise ConnectorError("Downloaded backup failed byte verification")
        except httpx.HTTPError as exc:
            raise ConnectorError("Drive backup download was interrupted") from exc
        finally:
            self.http.client.cookies.clear()


class DriveBackupOAuth:
    """Explicit owner consent helper; separate token store from Gmail/Calendar.

    Caller owns a short-lived numeric-loopback listener and browser opening.
    No listener, credential lookup, consent, or request starts automatically.
    """
    TOKEN_KEY = "drive-backup-refresh-v1"

    def __init__(self, *, client_id: str, client_secret: str, expected_account: str,
                 folder_id: str, secrets_store: SecretStore, http_transport=None):
        if (not isinstance(client_id, str) or not client_id.endswith(".apps.googleusercontent.com")
                or not isinstance(client_secret, str) or not client_secret
                or not isinstance(expected_account, str) or "@" not in expected_account):
            raise ConnectorError("Owner-supplied Desktop OAuth client and expected account are required")
        self.client_id, self.client_secret = client_id, client_secret
        self.expected_account = expected_account.strip().lower()
        self.folder_id = _identifier(folder_id)
        self.store = secrets_store
        self.http = _HTTP(http_transport)
        self.pending = None

    def begin(self, redirect_uri: str) -> str:
        try:
            parsed = urlsplit(redirect_uri)
            port = parsed.port
        except (TypeError, ValueError) as exc:
            raise ConnectorError("Invalid backup OAuth callback") from exc
        if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.username or parsed.password
                or not port or parsed.path != "/oauth2/drive-backup" or parsed.query or parsed.fragment):
            raise ConnectorError("Backup OAuth requires its numeric-loopback callback")
        state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(64)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        self.pending = {"state": state, "verifier": verifier, "redirect": redirect_uri, "expires": time.monotonic() + 300}
        return AUTH + "?" + urlencode({"client_id": self.client_id, "scope": DRIVE_SCOPE, "redirect_uri": redirect_uri,
            "response_type": "code", "access_type": "offline", "prompt": "consent", "trigger_onepick": "true",
            "allow_folder_selection": "true", "allow_multiple": "false", "file_ids": self.folder_id,
            "mimetypes": "application/vnd.google-apps.folder", "include_granted_scopes": "false",
            "state": state, "code_challenge": challenge, "code_challenge_method": "S256", "login_hint": self.expected_account})

    def finish(self, callback_url: str) -> dict[str, Any]:
        pending, self.pending = self.pending, None
        if pending is None or time.monotonic() > pending["expires"] or len(callback_url) > 16384:
            raise ConnectorError("Backup OAuth attempt is missing or expired")
        parsed = urlsplit(callback_url)
        if parsed._replace(query="").geturl() != pending["redirect"]:
            raise ConnectorError("Backup OAuth callback does not match")
        values = parse_qs(parsed.query, keep_blank_values=True, max_num_fields=12)
        if any(len(value) != 1 for value in values.values()) or values.get("error"):
            raise ConnectorError("Backup OAuth was refused or malformed")
        if not secrets.compare_digest(values.get("state", [""])[0], pending["state"]):
            raise ConnectorError("Backup OAuth state validation failed")
        if values.get("picked_file_ids") != [self.folder_id] or not values.get("code", [""])[0]:
            raise ConnectorError("Select exactly the approved backup folder")
        _, raw = self.http.request("POST", TOKEN, data={"client_id": self.client_id, "client_secret": self.client_secret,
            "code": values["code"][0], "code_verifier": pending["verifier"], "redirect_uri": pending["redirect"],
            "grant_type": "authorization_code"}, operation="authorization exchange")
        data = _json(raw)
        if set(str(data.get("scope", "")).split()) != {DRIVE_SCOPE} or not isinstance(data.get("refresh_token"), str) or not data["refresh_token"]:
            raise ConnectorError("Backup OAuth did not return only Drive file access with a refresh token")
        access = data.get("access_token")
        if not isinstance(access, str) or not access:
            raise ConnectorError("Backup OAuth did not return an access token")
        _, raw = self.http.request("GET", API + "/about", token=access, params={"fields": "user(emailAddress)"},
                                  operation="account verification")
        profile = _json(raw).get("user")
        account = profile.get("emailAddress") if isinstance(profile, dict) else None
        if not isinstance(account, str) or account.lower() != self.expected_account:
            raise ConnectorError("Backup Google account does not match the owner-selected account")
        _, raw = self.http.request("GET", API + "/files/" + self.folder_id, token=access,
                                  params={"fields": "id,mimeType,trashed,shared,ownedByMe,capabilities(canAddChildren)"},
                                  operation="folder verification")
        folder = _json(raw)
        if (folder.get("id") != self.folder_id or folder.get("mimeType") != "application/vnd.google-apps.folder"
                or folder.get("trashed") is not False or folder.get("shared") is not False
                or folder.get("ownedByMe") is not True or not isinstance(folder.get("capabilities"), dict)
                or folder["capabilities"].get("canAddChildren") is not True):
            raise ConnectorError("Selected backup folder is not private, owned, and writable")
        self.store.set(self.TOKEN_KEY, json.dumps({"refresh_token": data["refresh_token"], "scope": DRIVE_SCOPE,
            "folder_id": self.folder_id, "account": self.expected_account,
            "client_sha256": hashlib.sha256(self.client_id.encode()).hexdigest()}))
        return {"connected": True, "folder_id": self.folder_id, "scope": DRIVE_SCOPE}

    def access_token(self) -> str:
        raw = self.store.get(self.TOKEN_KEY)
        if raw is None:
            raise ConnectorError("Atlas backup Drive consent has not completed")
        data = _json(raw.encode())
        if (data.get("scope") != DRIVE_SCOPE or data.get("folder_id") != self.folder_id
                or data.get("account") != self.expected_account
                or data.get("client_sha256") != hashlib.sha256(self.client_id.encode()).hexdigest()):
            raise ConnectorError("Stored backup consent does not match this connection")
        _, raw = self.http.request("POST", TOKEN, data={"client_id": self.client_id, "client_secret": self.client_secret,
            "refresh_token": data.get("refresh_token"), "grant_type": "refresh_token"})
        response = _json(raw)
        if "scope" in response and set(str(response["scope"]).split()) != {DRIVE_SCOPE}:
            raise ConnectorError("Refreshed backup token has unexpected scopes")
        access = response.get("access_token")
        if not isinstance(access, str) or not access:
            raise ConnectorError("Backup authorization refresh failed")
        return access

    def close(self):
        self.http.close()
