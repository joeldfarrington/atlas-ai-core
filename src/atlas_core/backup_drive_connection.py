"""Owner-invoked Drive consent and a separate routine-backup credential binding.

No secrets are discovered, browser opened, or service started at import time.
"""
from __future__ import annotations

import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time
from urllib.parse import parse_qs, urlsplit
import webbrowser

from atlas_core.connectors.drive_backup import DriveBackupOAuth, DriveBackupTransport, _directory, _json, _identifier
from atlas_core.connectors.google import KeyringSecretStore
from atlas_core.errors import ConnectorError

BACKUP_NAMESPACE = "com.atlas.core.backup-drive"
EXISTING_NAMESPACE = "com.atlas.core.google-workspace"
CLIENT_KEY = "desktop-client-v1"
PROFILE_KEYS = {"version", "expected_account", "folder_id", "state_dir", "client_fingerprint"}


def _absolute(path):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts or any(ord(char) < 32 or ord(char) == 127 for char in str(path)):
        raise ConnectorError("An explicit absolute backup path is required")
    return path


def _read_owned(path: Path):
    with _directory(path.parent) as directory:
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except OSError as exc:
            raise ConnectorError("The selected connection file is unavailable or linked") from exc
        with os.fdopen(fd, "rb") as handle:
            before = os.fstat(handle.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != os.getuid() or before.st_size > 65536:
                raise ConnectorError("The selected connection file must be a bounded owner-controlled regular file")
            raw = handle.read(65537)
            after = os.fstat(handle.fileno())
            if len(raw) > 65536 or (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ConnectorError("The selected connection file changed")
            return _json(raw)


def _profile(path: Path):
    value = _read_owned(path)
    if set(value) != PROFILE_KEYS or value.get("version") != 1 or type(value.get("version")) is not int:
        raise ConnectorError("Backup connection profile is invalid")
    _identifier(value.get("folder_id"))
    _absolute(value.get("state_dir"))
    if (not isinstance(value.get("expected_account"), str) or "@" not in value["expected_account"]
            or not isinstance(value.get("client_fingerprint"), str) or not re.fullmatch(r"[0-9a-f]{64}", value["client_fingerprint"])):
        raise ConnectorError("Backup connection profile is invalid")
    return value


def _save_profile(path: Path, value):
    raw = (json.dumps(value, sort_keys=True) + "\n").encode()
    with _directory(path.parent) as directory:
        try:
            fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        except FileExistsError:
            if _profile(path) != value:
                raise ConnectorError("Existing backup profile differs; it was not overwritten")
            return
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            os.fsync(directory)
        except BaseException:
            # A partially written profile is never treated as a valid binding.
            # Preserve it for owner inspection instead of replacing user files.
            raise


class _LoopbackServer(HTTPServer):
    allow_reuse_address = False

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(2)
        return connection, address


def connect_drive_backup(*, expected_account: str, folder_id: str, profile_path: Path,
                         state_dir: Path, client_json: Path | None = None,
                         reuse_existing_client: bool = False, backup_store=None,
                         existing_store=None, http_transport=None, open_browser=None,
                         timeout_seconds: int = 180, server_factory=None):
    """Invoke only after the owner chooses to connect Atlas's private backups.

    Reuse means read only the existing Desktop client record, never its Gmail or
    Calendar refresh token. Separate backup credentials retain drive.file only.
    """
    profile_path, state_dir = _absolute(profile_path), _absolute(state_dir)
    folder_id = _identifier(folder_id)
    if type(reuse_existing_client) is not bool or bool(client_json) == reuse_existing_client:
        raise ConnectorError("Select exactly one Desktop client file or existing-client reuse")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 180:
        raise ConnectorError("Backup consent timeout must be at most 180 seconds")
    if not isinstance(expected_account, str) or "@" not in expected_account or any(ord(c) < 33 for c in expected_account):
        raise ConnectorError("An owner-selected Google account is required")
    expected_account = expected_account.lower()
    # Verify the known profile directory before touching any credential store.
    with _directory(profile_path.parent):
        pass
    existing_profile = _profile(profile_path) if profile_path.exists() or profile_path.is_symlink() else None
    if existing_profile and any(existing_profile[key] != value for key, value in {
            "expected_account": expected_account, "folder_id": folder_id, "state_dir": str(state_dir)}.items()):
        raise ConnectorError("Existing backup profile differs; it was not overwritten")
    if reuse_existing_client:
        old_store = existing_store if existing_store is not None else KeyringSecretStore(EXISTING_NAMESPACE)
        raw = old_store.get("oauth-client")
        if raw is None:
            raise ConnectorError("No existing Desktop OAuth client is stored; select its downloaded Desktop client JSON file")
        client = _json(raw.encode())
    else:
        payload = _read_owned(_absolute(client_json))
        client = payload.get("installed")
        if not isinstance(client, dict):
            raise ConnectorError("The selected JSON must contain a Desktop installed OAuth client")
    client_id, client_secret = client.get("client_id"), client.get("client_secret")
    store = backup_store if backup_store is not None else KeyringSecretStore(BACKUP_NAMESPACE)
    auth = DriveBackupOAuth(client_id=client_id, client_secret=client_secret, expected_account=expected_account,
                           folder_id=folder_id, secrets_store=store, http_transport=http_transport)
    fingerprint = hashlib.sha256(client_id.encode()).hexdigest()
    if existing_profile and existing_profile["client_fingerprint"] != fingerprint:
        auth.close()
        raise ConnectorError("Existing backup client identity differs; reconnect into a separate profile")
    callback = {}
    server = None
    try:
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                accepted = False
                try:
                    if len(self.path) > 8192 or sum(len(k) + len(v) for k, v in self.headers.items()) > 8192:
                        raise ValueError("too long")
                    parsed = urlsplit(self.path)
                    if parsed.scheme or parsed.netloc or parsed.path != "/oauth2/drive-backup" or parsed.fragment:
                        raise ValueError("wrong path")
                    if self.headers.get("Host") != "127.0.0.1:" + str(self.server.server_port):
                        raise ValueError("wrong host")
                    values = parse_qs(parsed.query, keep_blank_values=True, max_num_fields=12)
                    if any(len(value) != 1 for value in values.values()):
                        raise ValueError("duplicate")
                    if not auth.pending or not secrets.compare_digest(values.get("state", [""])[0], auth.pending["state"]):
                        raise ValueError("wrong state")
                    callback["url"] = auth.pending["redirect"] + "?" + parsed.query
                    accepted = True
                except (ValueError, TypeError):
                    pass
                self.send_response(200 if accepted else 400)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(b"Return to Atlas to see the connection result." if accepted else b"Invalid callback.")

        server = (server_factory or _LoopbackServer)(("127.0.0.1", 0), Handler)
        server.timeout = 1
        redirect = "http://127.0.0.1:" + str(server.server_port) + "/oauth2/drive-backup"
        url = auth.begin(redirect)
        if not (open_browser or webbrowser.open)(url):
            raise ConnectorError("The system browser did not open for backup consent")
        deadline = time.monotonic() + timeout_seconds
        while not callback and time.monotonic() < deadline:
            server.timeout = min(1, max(0.01, deadline - time.monotonic()))
            server.handle_request()
        server.server_close()
        server = None
        if not callback:
            raise ConnectorError("Backup Drive consent timed out")
        # Only after callback validation store the explicitly selected Desktop
        # client in the separate namespace; no Gmail/Calendar token is read.
        store.set(CLIENT_KEY, json.dumps({"client_id": client_id, "client_secret": client_secret}))
        result = auth.finish(callback["url"])
        profile = {"version": 1, "expected_account": expected_account, "folder_id": folder_id,
                   "state_dir": str(state_dir), "client_fingerprint": fingerprint}
        _save_profile(profile_path, profile)
        return result | {"profile_saved": True}
    finally:
        if server is not None:
            server.server_close()
        auth.close()


def build_drive_backup_transport(profile_path: Path, *, backup_store=None, http_transport=None):
    """Read only the explicit owner-created binding; never search for credentials."""
    profile = _profile(_absolute(profile_path))
    store = backup_store if backup_store is not None else KeyringSecretStore(BACKUP_NAMESPACE)
    raw = store.get(CLIENT_KEY)
    if raw is None:
        raise ConnectorError("Atlas backup Desktop client is not connected")
    client = _json(raw.encode())
    client_id = client.get("client_id")
    if not isinstance(client_id, str) or hashlib.sha256(client_id.encode()).hexdigest() != profile["client_fingerprint"]:
        raise ConnectorError("Stored backup client does not match the owner profile")
    auth = DriveBackupOAuth(client_id=client_id, client_secret=client.get("client_secret"),
                           expected_account=profile["expected_account"], folder_id=profile["folder_id"],
                           secrets_store=store, http_transport=http_transport)
    # Fail locally if consent is absent, without performing a token refresh.
    if store.get(auth.TOKEN_KEY) is None:
        auth.close()
        raise ConnectorError("Atlas backup Drive consent has not completed")
    try:
        transport = DriveBackupTransport(folder_id=profile["folder_id"], state_dir=Path(profile["state_dir"]),
                                         token_provider=auth.access_token, http_transport=http_transport)
    except BaseException:
        auth.close()
        raise
    original_close = transport.close
    def close():
        try:
            original_close()
        finally:
            auth.close()
    transport.close = close
    return transport
