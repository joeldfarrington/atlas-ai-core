from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import secrets
import ssl
import subprocess
import tempfile
import threading
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator

from atlas_core import __version__
from atlas_core.config import PhoneCompanionConfig, load_config
from atlas_core.memory import Database


PHONE_PROTOCOL_VERSION = 1
_PAIR_CODE = re.compile(r"[0-9]{6}")
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_text(value: datetime | None = None) -> str:
    return (value or utc_now()).astimezone(timezone.utc).isoformat()


def parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


class PhoneCompanionStateStore:
    """Secret-free bridge and device status shared with the Atlas tool."""

    def __init__(self, config: PhoneCompanionConfig) -> None:
        self.config = config
        self.path = config.state_file.expanduser().resolve()
        self.pause_file = config.pause_file.expanduser().resolve()
        self._lock = threading.RLock()

    @staticmethod
    def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, ensure_ascii=False, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            path.chmod(0o600)
        finally:
            temporary.unlink(missing_ok=True)

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {}
        if self.path.is_symlink() or not self.path.is_file():
            raise ValueError("Phone companion state must be a regular owner file")
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("Phone companion state is unreadable") from exc
        if not isinstance(payload, dict):
            raise ValueError("Phone companion state has an invalid format")
        return payload

    def _write(self, payload: dict[str, Any]) -> None:
        self._write_json_atomic(self.path, payload)

    def is_paused(self) -> bool:
        if self.pause_file.is_symlink():
            raise ValueError("Phone companion pause control must be a regular file")
        return self.pause_file.exists()

    def pause(self) -> dict[str, Any]:
        if self.pause_file.is_symlink():
            raise ValueError("Phone companion pause control must be a regular file")
        self._write_json_atomic(
            self.pause_file,
            {"paused_at": utc_text(), "scope": "phone_companion"},
        )
        with self._lock:
            payload = self._read()
            if isinstance(payload.get("device"), dict):
                payload["device"]["connected"] = False
            if payload:
                payload["updated_at"] = utc_text()
                self._write(payload)
        return self.status()

    def resume(self) -> dict[str, Any]:
        if self.pause_file.is_symlink():
            raise ValueError("Phone companion pause control must be a regular file")
        self.pause_file.unlink(missing_ok=True)
        return self.status()

    def bridge_started(self, *, host: str, port: int) -> None:
        now = utc_text()
        with self._lock:
            previous = self._read()
            device = previous.get("device")
            if isinstance(device, dict):
                device = dict(device)
                device["connected"] = False
            else:
                device = None
            payload: dict[str, Any] = {
                "format": "atlas-phone-companion-state",
                "version": 1,
                "bridge": {
                    "active": True,
                    "pid": os.getpid(),
                    "host": host,
                    "port": port,
                    "started_at": now,
                    "heartbeat_at": now,
                },
                "device": device,
                "updated_at": now,
            }
            self._write(payload)

    def heartbeat(self) -> None:
        with self._lock:
            payload = self._read()
            bridge = payload.get("bridge")
            if not isinstance(bridge, dict) or bridge.get("pid") != os.getpid():
                return
            bridge["active"] = True
            bridge["heartbeat_at"] = utc_text()
            payload["updated_at"] = bridge["heartbeat_at"]
            self._write(payload)

    def bridge_stopped(self) -> None:
        with self._lock:
            payload = self._read()
            bridge = payload.get("bridge")
            if isinstance(bridge, dict) and bridge.get("pid") == os.getpid():
                bridge["active"] = False
                bridge["stopped_at"] = utc_text()
            if isinstance(payload.get("device"), dict):
                payload["device"]["connected"] = False
            if payload:
                payload["updated_at"] = utc_text()
                self._write(payload)

    def record_device_status(self, device: dict[str, Any]) -> dict[str, Any]:
        if self.is_paused():
            raise ValueError("The phone companion is paused by the owner stop control")
        with self._lock:
            payload = self._read()
            bridge = payload.get("bridge")
            if not isinstance(bridge, dict) or bridge.get("pid") != os.getpid():
                raise ValueError("The phone bridge is not the active bridge process")
            received_at = utc_text()
            payload["device"] = {
                "connected": True,
                **device,
                "received_at": received_at,
            }
            bridge["heartbeat_at"] = received_at
            payload["updated_at"] = received_at
            self._write(payload)
            return dict(payload["device"])

    def disconnect_device(self) -> None:
        with self._lock:
            payload = self._read()
            if isinstance(payload.get("device"), dict):
                payload["device"]["connected"] = False
                payload["device"]["disconnected_at"] = utc_text()
                payload["updated_at"] = payload["device"]["disconnected_at"]
                self._write(payload)

    @staticmethod
    def _pid_is_active(value: Any) -> bool:
        if not isinstance(value, int) or value <= 0:
            return False
        try:
            os.kill(value, 0)
        except (OSError, ValueError):
            return False
        return True

    def status(self) -> dict[str, Any]:
        paused = self.is_paused()
        base: dict[str, Any] = {
            "enabled": self.config.enabled,
            "paused": paused,
            "ready": self.config.enabled and not paused,
            "task_family": "native-ios-read-only-device-status",
            "bridge_active": False,
            "device_connected": False,
            "supported_actions": ["status"],
            "required_phone_permissions": ["Local Network while the bridge is running"],
            "not_requested": [
                "Contacts",
                "Calendars",
                "Photos",
                "Microphone",
                "Camera",
                "Location",
                "Bluetooth",
                "Notifications",
                "Background execution",
            ],
            "stop_controls": [
                "run Pause Atlas Phone Companion.command",
                "stop the separate Atlas Phone Bridge terminal",
                "disconnect inside the iPhone app",
            ],
        }
        if not self.config.enabled:
            return base
        with self._lock:
            payload = self._read()
        bridge = payload.get("bridge")
        if isinstance(bridge, dict):
            heartbeat = parse_utc(bridge.get("heartbeat_at"))
            heartbeat_fresh = bool(
                heartbeat and utc_now() - heartbeat <= timedelta(seconds=20)
            )
            bridge_active = bool(
                bridge.get("active")
                and self._pid_is_active(bridge.get("pid"))
                and heartbeat_fresh
                and not paused
            )
            base.update(
                {
                    "bridge_active": bridge_active,
                    "bridge_host": bridge.get("host") if bridge_active else None,
                    "bridge_port": bridge.get("port") if bridge_active else None,
                    "bridge_started_at": bridge.get("started_at"),
                }
            )
        device = payload.get("device")
        if isinstance(device, dict):
            received = parse_utc(device.get("received_at"))
            status_fresh = bool(
                received
                and utc_now() - received
                <= timedelta(seconds=self.config.status_max_age_seconds)
            )
            connected = bool(
                device.get("connected")
                and status_fresh
                and base["bridge_active"]
                and not paused
            )
            base.update(
                {
                    "device_connected": connected,
                    "last_seen": device.get("received_at"),
                    "device_model": device.get("device_model"),
                    "os_name": device.get("os_name"),
                    "os_version": device.get("os_version"),
                    "app_version": device.get("app_version"),
                    "battery_level": device.get("battery_level"),
                    "battery_state": device.get("battery_state"),
                    "status_fresh": status_fresh,
                }
            )
        return base


class PairingError(ValueError):
    pass


class PhoneBridgeSession:
    """One-process, one-device pairing state; no secret is persisted."""

    def __init__(
        self,
        config: PhoneCompanionConfig,
        *,
        pairing_code: str | None = None,
        now: Callable[[], datetime] = utc_now,
    ) -> None:
        code = pairing_code or f"{secrets.randbelow(1_000_000):06d}"
        if not _PAIR_CODE.fullmatch(code):
            raise ValueError("pairing code must contain exactly six digits")
        self.config = config
        self.pairing_code = code
        self._now = now
        self.pairing_expires_at = now() + timedelta(
            seconds=config.pairing_ttl_seconds
        )
        self.session_expires_at: datetime | None = None
        self._session_digest: str | None = None
        self._failed_attempts = 0
        self._paired_device_name: str | None = None
        self._ever_paired = False
        self._lock = threading.Lock()

    @property
    def pairing_open(self) -> bool:
        with self._lock:
            return bool(
                self._session_digest is None
                and not self._ever_paired
                and self._failed_attempts < self.config.max_pairing_attempts
                and self._now() <= self.pairing_expires_at
            )

    def pair(self, code: str, device_name: str) -> tuple[str, datetime]:
        with self._lock:
            if self._session_digest is not None or self._ever_paired:
                raise PairingError("This bridge already has one paired device")
            if self._now() > self.pairing_expires_at:
                raise PairingError("The pairing window expired; restart the bridge")
            if self._failed_attempts >= self.config.max_pairing_attempts:
                raise PairingError("Pairing is locked; restart the bridge")
            if not secrets.compare_digest(code, self.pairing_code):
                self._failed_attempts += 1
                raise PairingError("Pairing failed")
            normalized = device_name.strip()
            if not normalized or _CONTROL_CHARACTERS.search(normalized):
                raise PairingError("The device name is invalid")
            token = secrets.token_urlsafe(32)
            self._session_digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
            self.session_expires_at = self._now() + timedelta(
                seconds=self.config.session_ttl_seconds
            )
            self._paired_device_name = normalized[:80]
            self._ever_paired = True
            self.pairing_code = "000000"
            return token, self.session_expires_at

    def authenticate(self, token: str) -> None:
        with self._lock:
            if self._session_digest is None or self.session_expires_at is None:
                raise PairingError("The phone bridge is not paired")
            if self._now() > self.session_expires_at:
                self._session_digest = None
                self._paired_device_name = None
                raise PairingError("The phone bridge session expired")
            supplied = hashlib.sha256(token.encode("utf-8")).hexdigest()
            if not secrets.compare_digest(supplied, self._session_digest):
                raise PairingError("The phone bridge session is invalid")

    def disconnect(self) -> None:
        with self._lock:
            self._session_digest = None
            self.session_expires_at = None
            self._paired_device_name = None


class PairRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(pattern=r"^[0-9]{6}$")
    device_name: str = Field(min_length=1, max_length=80)


class DeviceStatusPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    protocol_version: int = Field(ge=PHONE_PROTOCOL_VERSION, le=PHONE_PROTOCOL_VERSION)
    app_version: str = Field(min_length=1, max_length=40)
    os_name: str = Field(min_length=1, max_length=24)
    os_version: str = Field(min_length=1, max_length=40)
    device_model: str = Field(min_length=1, max_length=80)
    battery_level: float | None = Field(default=None, ge=0, le=1)
    battery_state: str = Field(pattern=r"^(unknown|unplugged|charging|full)$")
    observed_at: datetime

    @field_validator("app_version", "os_name", "os_version", "device_model")
    @classmethod
    def reject_control_characters(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized or _CONTROL_CHARACTERS.search(normalized):
            raise ValueError("status text contains invalid characters")
        return normalized


def _bearer_token(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise PairingError("A paired phone session is required")
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise PairingError("A paired phone session is required")
    return token


def create_phone_bridge_app(
    config_path: str | Path,
    *,
    host: str,
    port: int,
    pairing_code: str | None = None,
) -> FastAPI:
    config = load_config(config_path)
    if not config.phone_companion.enabled:
        raise ValueError("The Atlas phone companion is disabled")
    database = Database(config.database_path)
    store = PhoneCompanionStateStore(config.phone_companion)
    session = PhoneBridgeSession(config.phone_companion, pairing_code=pairing_code)
    stop_heartbeat = threading.Event()

    def audit(action: str, outcome: str, details: dict[str, Any]) -> None:
        database.audit(
            event_type="phone_companion",
            actor="native-phone-bridge",
            action=action,
            resource="phone_companion",
            outcome=outcome,
            details=details,
        )

    def heartbeat_loop() -> None:
        while not stop_heartbeat.wait(5):
            try:
                store.heartbeat()
            except ValueError:
                break

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        del app
        store.bridge_started(host=host, port=port)
        audit("phone_bridge.start", "success", {"host": host, "port": port})
        thread = threading.Thread(
            target=heartbeat_loop,
            name="atlas-phone-heartbeat",
            daemon=True,
        )
        thread.start()
        try:
            yield
        finally:
            stop_heartbeat.set()
            thread.join(timeout=2)
            session.disconnect()
            store.bridge_stopped()
            audit("phone_bridge.stop", "success", {"host": host, "port": port})

    app = FastAPI(
        title="Atlas Native Phone Bridge",
        version=__version__,
        description="Ephemeral, explicitly paired, read-only local phone bridge.",
        lifespan=lifespan,
    )
    app.state.phone_store = store
    app.state.phone_session = session

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response: Response = await call_next(request)
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response

    @app.exception_handler(PairingError)
    async def pairing_error_handler(request: Request, exc: PairingError) -> JSONResponse:
        del request, exc
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": "phone_pairing_denied", "detail": "Pairing or session validation failed"},
        )

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {
            "ok": True,
            "service": "atlas-native-phone-bridge",
            "protocol_version": PHONE_PROTOCOL_VERSION,
            "pairing_open": session.pairing_open,
            "paused": store.is_paused(),
            "supported_actions": ["device_status"],
        }

    @app.post("/v1/pair")
    async def pair(payload: PairRequest) -> dict[str, Any]:
        if store.is_paused():
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail="The owner paused the phone companion",
            )
        try:
            token, expires_at = session.pair(payload.code, payload.device_name)
        except PairingError:
            audit("phone_bridge.pair", "denied", {"reason": "validation_failed"})
            raise
        audit(
            "phone_bridge.pair",
            "success",
            {"protocol_version": PHONE_PROTOCOL_VERSION},
        )
        return {
            "session_token": token,
            "expires_at": utc_text(expires_at),
            "supported_actions": ["device_status"],
        }

    def authenticate(authorization: str | None) -> None:
        token = _bearer_token(authorization)
        session.authenticate(token)
        if store.is_paused():
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail="The owner paused the phone companion",
            )

    @app.post("/v1/device-status")
    async def device_status(
        payload: DeviceStatusPayload,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        authenticate(authorization)
        observed = payload.observed_at
        if observed.tzinfo is None:
            observed = observed.replace(tzinfo=timezone.utc)
        if abs((utc_now() - observed.astimezone(timezone.utc)).total_seconds()) > 600:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="The device status timestamp is outside the ten-minute acceptance window",
            )
        stored = store.record_device_status(payload.model_dump(mode="json"))
        audit(
            "phone_bridge.device_status",
            "success",
            {
                "protocol_version": payload.protocol_version,
                "device_model": payload.device_model,
                "os_name": payload.os_name,
                "os_version": payload.os_version,
                "app_version": payload.app_version,
            },
        )
        return {"accepted": True, "received_at": stored["received_at"]}

    @app.post("/v1/disconnect")
    async def disconnect(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        authenticate(authorization)
        session.disconnect()
        store.disconnect_device()
        audit("phone_bridge.disconnect", "success", {})
        return {"disconnected": True}

    return app


def validate_bridge_host(host: str) -> str:
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("Phone bridge host must be one exact IPv4 address") from exc
    if address.version != 4 or address.is_unspecified or address.is_multicast:
        raise ValueError("Phone bridge host must be one exact private or loopback IPv4 address")
    allowed_networks = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
    )
    if not any(address in network for network in allowed_networks):
        raise ValueError("Phone bridge refuses public network addresses")
    return str(address)


def certificate_confirmation_code(fingerprint: str) -> str:
    normalized = re.sub(r"[^0-9A-Fa-f]", "", fingerprint).upper()
    if len(normalized) < 12:
        raise ValueError("Certificate fingerprint is too short")
    return "-".join(normalized[index : index + 4] for index in range(0, 12, 4))


@dataclass(frozen=True, slots=True)
class EphemeralTLSMaterial:
    certificate_path: Path
    private_key_path: Path
    fingerprint_sha256: str
    confirmation_code: str


@contextmanager
def ephemeral_tls_material(host: str) -> Iterator[EphemeralTLSMaterial]:
    validated_host = validate_bridge_host(host)
    with tempfile.TemporaryDirectory(prefix="atlas-phone-tls-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        certificate = root / "certificate.pem"
        private_key = root / "private-key.pem"
        command = [
            "/usr/bin/openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-sha256",
            "-days",
            "1",
            "-subj",
            "/CN=Atlas Native Phone Bridge",
            "-addext",
            f"subjectAltName=IP:{validated_host}",
            "-keyout",
            str(private_key),
            "-out",
            str(certificate),
        ]
        completed = subprocess.run(
            command,
            shell=False,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"},
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if completed.returncode != 0:
            detail = completed.stderr.strip()[-500:] or "unknown certificate error"
            raise RuntimeError(f"Could not create the ephemeral phone certificate: {detail}")
        private_key.chmod(0o600)
        certificate.chmod(0o600)
        pem = certificate.read_text(encoding="ascii")
        der = ssl.PEM_cert_to_DER_cert(pem)
        fingerprint = hashlib.sha256(der).hexdigest().upper()
        yield EphemeralTLSMaterial(
            certificate_path=certificate,
            private_key_path=private_key,
            fingerprint_sha256=fingerprint,
            confirmation_code=certificate_confirmation_code(fingerprint),
        )
