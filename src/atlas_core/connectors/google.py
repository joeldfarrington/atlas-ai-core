from __future__ import annotations

import base64
import hashlib
import json
import secrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx

from atlas_core.config import GoogleWorkspaceConfig
from atlas_core.errors import ConnectorError


GOOGLE_AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke"
GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1"
CALENDAR_API_BASE = "https://www.googleapis.com/calendar/v3"


class SecretStore(Protocol):
    def get(self, name: str) -> str | None: ...

    def set(self, name: str, value: str) -> None: ...

    def delete(self, name: str) -> None: ...


class KeyringSecretStore:
    """Stores OAuth material in the signed-in macOS user's Keychain."""

    def __init__(self, service: str) -> None:
        try:
            import keyring
            from keyring.errors import KeyringError, PasswordDeleteError
        except ImportError as exc:  # pragma: no cover - packaging guard
            raise ConnectorError(
                "The keyring package is required for Google Workspace credentials"
            ) from exc
        self.service = service
        self._keyring = keyring
        self._keyring_error = KeyringError
        self._password_delete_error = PasswordDeleteError

    def get(self, name: str) -> str | None:
        try:
            return self._keyring.get_password(self.service, name)
        except self._keyring_error as exc:
            raise ConnectorError("macOS Keychain could not be read") from exc

    def set(self, name: str, value: str) -> None:
        try:
            self._keyring.set_password(self.service, name, value)
        except self._keyring_error as exc:
            raise ConnectorError("macOS Keychain could not store the credential") from exc

    def delete(self, name: str) -> None:
        try:
            self._keyring.delete_password(self.service, name)
        except self._password_delete_error:
            return
        except self._keyring_error as exc:
            raise ConnectorError("macOS Keychain could not delete the credential") from exc


class MemorySecretStore:
    """Non-persistent secret store for unit tests."""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def get(self, name: str) -> str | None:
        return self.values.get(name)

    def set(self, name: str, value: str) -> None:
        self.values[name] = value

    def delete(self, name: str) -> None:
        self.values.pop(name, None)


class GoogleWorkspaceConnector:
    CLIENT_KEY = "oauth-client"
    TOKEN_KEY = "oauth-token"

    def __init__(
        self,
        config: GoogleWorkspaceConfig,
        *,
        secrets_store: SecretStore | None = None,
        http: httpx.Client | None = None,
    ) -> None:
        self.config = config
        self.secrets = secrets_store or KeyringSecretStore(config.keyring_service)
        self.http = http or httpx.Client(
            timeout=config.timeout_seconds,
            follow_redirects=False,
        )

    @staticmethod
    def _load_json(raw: str | None, label: str) -> dict[str, Any] | None:
        if raw is None:
            return None
        try:
            value = json.loads(raw)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ConnectorError(f"The stored Google {label} record is invalid") from exc
        if not isinstance(value, dict):
            raise ConnectorError(f"The stored Google {label} record is invalid")
        return value

    def _client_record(self) -> dict[str, Any]:
        value = self._load_json(self.secrets.get(self.CLIENT_KEY), "OAuth client")
        if not value or not value.get("client_id") or not value.get("client_secret"):
            raise ConnectorError(
                "No Google Desktop OAuth client is configured. Import its downloaded JSON file first."
            )
        return value

    def _token_record(self) -> dict[str, Any]:
        value = self._load_json(self.secrets.get(self.TOKEN_KEY), "token")
        if not value or not value.get("refresh_token"):
            raise ConnectorError("Google Workspace is not connected")
        return value

    @staticmethod
    def _client_fingerprint(client_id: str) -> str:
        return hashlib.sha256(client_id.encode("utf-8")).hexdigest()[:12]

    def import_client_file(self, path: str | Path) -> dict[str, Any]:
        source = Path(path).expanduser().resolve()
        try:
            payload = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConnectorError("The selected OAuth client file is not valid JSON") from exc
        installed = payload.get("installed") if isinstance(payload, dict) else None
        if not isinstance(installed, dict):
            raise ConnectorError(
                "Atlas requires a Google OAuth client created as a Desktop app"
            )
        client_id = str(installed.get("client_id") or "").strip()
        client_secret = str(installed.get("client_secret") or "").strip()
        if not client_id or not client_secret:
            raise ConnectorError("The Desktop OAuth client file is incomplete")
        record = {
            "client_id": client_id,
            "client_secret": client_secret,
        }
        self.secrets.set(self.CLIENT_KEY, json.dumps(record, separators=(",", ":")))
        return {
            "configured": True,
            "client_type": "desktop",
            "client_fingerprint": self._client_fingerprint(client_id),
            "source_removed": False,
        }

    def status(self) -> dict[str, Any]:
        client = self._load_json(self.secrets.get(self.CLIENT_KEY), "OAuth client")
        token = self._load_json(self.secrets.get(self.TOKEN_KEY), "token")
        client_id = str((client or {}).get("client_id") or "")
        return {
            "enabled": self.config.enabled,
            "client_configured": bool(client_id and (client or {}).get("client_secret")),
            "client_fingerprint": (
                self._client_fingerprint(client_id) if client_id else None
            ),
            "connected": bool((token or {}).get("refresh_token")),
            "expected_account": self.config.expected_account,
            "connected_account": (token or {}).get("account"),
            "calendar": self.config.calendar_id,
            "time_zone": self.config.time_zone,
            "scopes": list(self.config.scopes),
            "send_mail_available": False,
            "permanent_delete_available": False,
        }

    @staticmethod
    def new_pkce_pair() -> tuple[str, str]:
        verifier = secrets.token_urlsafe(64)
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode("ascii")).digest()
        ).rstrip(b"=").decode("ascii")
        return verifier, challenge

    def authorization_url(
        self,
        *,
        redirect_uri: str,
        state: str,
        code_challenge: str,
    ) -> str:
        client = self._client_record()
        query = urlencode(
            {
                "client_id": client["client_id"],
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "scope": " ".join(self.config.scopes),
                "access_type": "offline",
                "prompt": "consent",
                "include_granted_scopes": "false",
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "login_hint": self.config.expected_account or "",
            }
        )
        return f"{GOOGLE_AUTHORIZATION_URL}?{query}"

    def _exchange_code(
        self,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: str,
    ) -> dict[str, Any]:
        client = self._client_record()
        response = self.http.post(
            GOOGLE_TOKEN_URL,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": client["client_id"],
                "client_secret": client["client_secret"],
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
            },
        )
        token = self._response_json(response, "Google authorization")
        access_token = str(token.get("access_token") or "")
        refresh_token = str(token.get("refresh_token") or "")
        if not access_token or not refresh_token:
            raise ConnectorError(
                "Google did not return persistent access. Reconnect and approve offline access."
            )
        granted = set(str(token.get("scope") or "").split())
        if granted and not set(self.config.scopes).issubset(granted):
            self._revoke_value(refresh_token)
            raise ConnectorError("Google did not grant all of the configured Atlas scopes")
        profile = self._gmail_profile(access_token)
        account = str(profile.get("emailAddress") or "").strip().lower()
        expected = self.config.expected_account
        if not account or (expected and account != expected):
            self._revoke_value(refresh_token)
            raise ConnectorError(
                f"Google connected {account or 'an unknown account'}, but Atlas expects {expected}"
            )
        record = {
            "refresh_token": refresh_token,
            "account": account,
            "scopes": list(self.config.scopes),
        }
        self.secrets.set(self.TOKEN_KEY, json.dumps(record, separators=(",", ":")))
        return self.status()

    def authorize_interactive(self, *, open_browser: bool = True) -> dict[str, Any]:
        if not self.config.expected_account:
            raise ConnectorError("Configure expected_account before connecting Google")
        callback: dict[str, str] = {}
        callback_event = threading.Event()

        class CallbackHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - stdlib API
                parsed = urlsplit(self.path)
                if parsed.path != "/oauth2/callback":
                    self.send_response(404)
                    self.end_headers()
                    return
                values = parse_qs(parsed.query)
                for key in ("code", "state", "error"):
                    if values.get(key):
                        callback[key] = values[key][0]
                body = (
                    b"<html><body><h1>Atlas connection received</h1>"
                    b"<p>You can return to Atlas.</p></body></html>"
                )
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Frame-Options", "DENY")
                self.end_headers()
                self.wfile.write(body)
                callback_event.set()

            def log_message(self, format: str, *args: Any) -> None:
                del format, args

        server = HTTPServer(("127.0.0.1", 0), CallbackHandler)
        server.timeout = 1
        redirect_uri = f"http://127.0.0.1:{server.server_port}/oauth2/callback"
        state = secrets.token_urlsafe(32)
        verifier, challenge = self.new_pkce_pair()
        url = self.authorization_url(
            redirect_uri=redirect_uri,
            state=state,
            code_challenge=challenge,
        )
        if open_browser and not webbrowser.open(url):
            server.server_close()
            raise ConnectorError("Atlas could not open the Google authorization page")
        remaining = self.config.authorization_timeout_seconds
        try:
            while remaining > 0 and not callback_event.is_set():
                server.handle_request()
                remaining -= 1
        finally:
            server.server_close()
        if not callback_event.is_set():
            raise ConnectorError("Google authorization timed out")
        if callback.get("error"):
            raise ConnectorError("Google authorization was not approved")
        if not secrets.compare_digest(callback.get("state", ""), state):
            raise ConnectorError("Google authorization state validation failed")
        code = callback.get("code")
        if not code:
            raise ConnectorError("Google did not return an authorization code")
        return self._exchange_code(
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=verifier,
        )

    @staticmethod
    def _response_json(response: httpx.Response, operation: str) -> dict[str, Any]:
        if response.status_code >= 400:
            reason = "request rejected"
            try:
                payload = response.json()
                error = payload.get("error") if isinstance(payload, dict) else None
                if isinstance(error, dict):
                    reason = str(error.get("message") or reason)
                elif isinstance(error, str):
                    reason = error
            except (ValueError, TypeError):
                pass
            raise ConnectorError(
                f"{operation} failed with HTTP {response.status_code}: {reason[:240]}"
            )
        if not response.content:
            return {}
        try:
            payload = response.json()
        except ValueError as exc:
            raise ConnectorError(f"{operation} returned invalid JSON") from exc
        if not isinstance(payload, dict):
            raise ConnectorError(f"{operation} returned an invalid response")
        return payload

    def _gmail_profile(self, access_token: str) -> dict[str, Any]:
        response = self.http.get(
            f"{GMAIL_API_BASE}/users/me/profile",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        return self._response_json(response, "Gmail profile check")

    def _access_token(self) -> str:
        client = self._client_record()
        token = self._token_record()
        response = self.http.post(
            GOOGLE_TOKEN_URL,
            data={
                "grant_type": "refresh_token",
                "refresh_token": token["refresh_token"],
                "client_id": client["client_id"],
                "client_secret": client["client_secret"],
            },
        )
        payload = self._response_json(response, "Google token refresh")
        access_token = str(payload.get("access_token") or "")
        if not access_token:
            raise ConnectorError("Google token refresh returned no access token")
        return access_token

    def api_json(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        access_token = self._access_token()
        response = self.http.request(
            method,
            url,
            params=params,
            json=json_body,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        return self._response_json(response, "Google Workspace request")

    def verify_connection(self) -> dict[str, Any]:
        access_token = self._access_token()
        profile = self._gmail_profile(access_token)
        account = str(profile.get("emailAddress") or "").strip().lower()
        if self.config.expected_account and account != self.config.expected_account:
            raise ConnectorError("The connected Google account no longer matches Atlas configuration")
        return {
            "connected": True,
            "account": account,
            "calendar": self.config.calendar_id,
            "scopes": list(self.config.scopes),
        }

    def _revoke_value(self, token: str) -> None:
        try:
            response = self.http.post(GOOGLE_REVOKE_URL, data={"token": token})
            if response.status_code >= 400:
                return
        except httpx.HTTPError:
            return

    def disconnect(self) -> dict[str, Any]:
        token = self._load_json(self.secrets.get(self.TOKEN_KEY), "token")
        if token and token.get("refresh_token"):
            response = self.http.post(
                GOOGLE_REVOKE_URL,
                data={"token": token["refresh_token"]},
            )
            self._response_json(response, "Google token revocation")
        self.secrets.delete(self.TOKEN_KEY)
        return {"connected": False, "revoked": bool(token)}
