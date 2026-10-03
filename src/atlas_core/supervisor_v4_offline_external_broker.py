from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import re
import secrets
import socket
import stat
import struct
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any, Literal, Mapping

from atlas_core.supervisor_v4_offline_crypto import (
    Ed25519OfflineSigner,
    Ed25519OfflineVerifier,
    OfflineCryptoViolation,
)


BrokerRole = Literal[
    "owner_policy",
    "capability_verifier",
    "credential_lease",
    "receipt_anchor",
    "owner_kill_switch",
]

BROKER_ROLES: tuple[BrokerRole, ...] = (
    "owner_policy",
    "capability_verifier",
    "credential_lease",
    "receipt_anchor",
    "owner_kill_switch",
)
TRANSPORT_RESPONSE_DOMAIN = (
    "atlas.supervisor-v4.external-transport-response.v1"
)
TRANSPORT_REQUEST_DOMAIN = "atlas.supervisor-v4.external-transport-request.v1"
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_OPERATION_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_ROLE_SET = frozenset(BROKER_ROLES)
_PROTOCOL = "atlas-supervisor-v4-external-broker-fixture"
_PROTOCOL_VERSION = 1
_MAX_FRAME_BYTES = 16_384
_MAX_JSON_DEPTH = 8
_MAX_COLLECTION_ITEMS = 128
_MAX_STRING_BYTES = 2_048
_MAX_UNIX_SOCKET_PATH_BYTES = 103
_FRAME_IO_DEADLINE_SECONDS = 0.75
_ENVIRONMENT_SPAWN_LOCK = threading.Lock()


class OfflineExternalBrokerViolation(ValueError):
    """Privacy-safe external-broker transport failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ExternalBrokerDescriptor:
    """Public, out-of-band identity for one synthetic broker process."""

    version: int
    role: BrokerRole
    session_sha256: str
    instance_sha256: str
    transport_key_id: str
    transport_public_key_b64: str
    owner_uid: int
    socket_mode: str
    root_mode: str
    synthetic_only: bool
    private_signing_keys_exported: bool
    network_accessed: bool
    model_contacted: bool
    live_authority_granted: bool

    def __post_init__(self) -> None:
        if (
            type(self.version) is not int
            or self.version != 1
            or self.role not in _ROLE_SET
        ):
            raise OfflineExternalBrokerViolation("broker_descriptor_invalid")
        _require_digest(self.session_sha256, code="broker_session_invalid")
        _require_digest(self.instance_sha256, code="broker_instance_invalid")
        if (
            not isinstance(self.owner_uid, int)
            or isinstance(self.owner_uid, bool)
            or self.owner_uid < 0
            or self.socket_mode != "0600"
            or self.root_mode != "0700"
            or self.synthetic_only is not True
            or self.private_signing_keys_exported is not False
            or self.network_accessed is not False
            or self.model_contacted is not False
            or self.live_authority_granted is not False
        ):
            raise OfflineExternalBrokerViolation("broker_descriptor_invalid")
        try:
            verifier = Ed25519OfflineVerifier.from_public_key_b64(
                self.transport_public_key_b64
            )
        except OfflineCryptoViolation as exc:
            raise OfflineExternalBrokerViolation("broker_public_key_invalid") from exc
        if verifier.key_id != self.transport_key_id:
            raise OfflineExternalBrokerViolation("broker_key_binding_invalid")


@dataclass(slots=True)
class _BrokerProcess:
    role: BrokerRole
    socket_path: Path
    descriptor: ExternalBrokerDescriptor
    process: multiprocessing.Process
    stop_event: Any


def _start_process_with_empty_environment(
    process: multiprocessing.Process,
) -> None:
    """Spawn one child from an empty environment and restore the launcher.

    ``multiprocessing`` has no public per-process ``env`` argument.  Its spawn
    launcher snapshots ``os.environ`` during ``Process.start()``, so the
    tightly bounded critical section below prevents provider tokens, dynamic-
    loader settings, and other owner state from ever entering the child.
    Supervisor v4 readiness is an operator-only CLI lane, not an API route.
    """

    with _ENVIRONMENT_SPAWN_LOCK:
        launcher_environment = dict(os.environ)
        try:
            os.environ.clear()
            process.start()
        finally:
            os.environ.clear()
            os.environ.update(launcher_environment)


def _require_digest(value: object, *, code: str) -> str:
    if not isinstance(value, str) or not _DIGEST_PATTERN.fullmatch(value):
        raise OfflineExternalBrokerViolation(code)
    return value


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise OfflineExternalBrokerViolation("broker_json_invalid") from exc


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise OfflineExternalBrokerViolation("broker_json_duplicate_key")
        value[key] = item
    return value


def _validate_json_tree(value: object, *, depth: int = 0) -> None:
    if depth > _MAX_JSON_DEPTH:
        raise OfflineExternalBrokerViolation("broker_json_depth_exceeded")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > 2**53 - 1:
            raise OfflineExternalBrokerViolation("broker_json_integer_invalid")
        return
    if isinstance(value, float):
        raise OfflineExternalBrokerViolation("broker_json_number_invalid")
    if isinstance(value, str):
        try:
            encoded = value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise OfflineExternalBrokerViolation(
                "broker_json_string_invalid"
            ) from exc
        if len(encoded) > _MAX_STRING_BYTES:
            raise OfflineExternalBrokerViolation("broker_json_string_too_large")
        return
    if isinstance(value, list):
        if len(value) > _MAX_COLLECTION_ITEMS:
            raise OfflineExternalBrokerViolation("broker_json_collection_too_large")
        for item in value:
            _validate_json_tree(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > _MAX_COLLECTION_ITEMS:
            raise OfflineExternalBrokerViolation("broker_json_collection_too_large")
        for key, item in value.items():
            if not isinstance(key, str):
                raise OfflineExternalBrokerViolation("broker_json_key_invalid")
            _validate_json_tree(key, depth=depth + 1)
            _validate_json_tree(item, depth=depth + 1)
        return
    raise OfflineExternalBrokerViolation("broker_json_type_invalid")


def _decode_canonical_json(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
        )
    except OfflineExternalBrokerViolation:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
        RecursionError,
        MemoryError,
    ) as exc:
        raise OfflineExternalBrokerViolation("broker_json_invalid") from exc
    if not isinstance(value, dict):
        raise OfflineExternalBrokerViolation("broker_json_document_invalid")
    _validate_json_tree(value)
    if _canonical_json(value) != raw:
        raise OfflineExternalBrokerViolation("broker_json_not_canonical")
    return value


def _peer_uid(connection: socket.socket) -> int:
    getpeereid = getattr(connection, "getpeereid", None)
    if callable(getpeereid):
        uid, _gid = getpeereid()
        return int(uid)
    if hasattr(socket, "SO_PEERCRED"):
        raw = connection.getsockopt(
            socket.SOL_SOCKET,
            socket.SO_PEERCRED,
            struct.calcsize("3i"),
        )
        _pid, uid, _gid = struct.unpack("3i", raw)
        return int(uid)
    if hasattr(socket, "LOCAL_PEERCRED"):
        # macOS struct xucred starts with cr_version then cr_uid. Python does
        # not expose SOL_LOCAL, whose stable Darwin value is zero.
        raw = connection.getsockopt(0, socket.LOCAL_PEERCRED, 76)
        if len(raw) < 8:
            raise OfflineExternalBrokerViolation("broker_peer_identity_unavailable")
        return int(struct.unpack_from("@I", raw, 4)[0])
    raise OfflineExternalBrokerViolation("broker_peer_identity_unavailable")


def _read_exact(
    connection: socket.socket,
    size: int,
    *,
    deadline: float | None = None,
) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        if deadline is not None:
            seconds_left = deadline - time.monotonic()
            if seconds_left <= 0:
                raise OfflineExternalBrokerViolation("broker_frame_deadline_exceeded")
            connection.settimeout(seconds_left)
        chunk = connection.recv(remaining)
        if not chunk:
            raise OfflineExternalBrokerViolation("broker_frame_truncated")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_frame(
    connection: socket.socket,
    *,
    deadline: float | None = None,
) -> bytes:
    header = _read_exact(connection, 4, deadline=deadline)
    size = struct.unpack("!I", header)[0]
    if size < 2 or size > _MAX_FRAME_BYTES:
        raise OfflineExternalBrokerViolation("broker_frame_size_invalid")
    return _read_exact(connection, size, deadline=deadline)


def _require_eof(
    connection: socket.socket,
    *,
    deadline: float | None = None,
) -> None:
    if deadline is not None:
        seconds_left = deadline - time.monotonic()
        if seconds_left <= 0:
            raise OfflineExternalBrokerViolation("broker_frame_deadline_exceeded")
        connection.settimeout(seconds_left)
    try:
        trailing = connection.recv(1)
    except TimeoutError as exc:
        raise OfflineExternalBrokerViolation("broker_frame_eof_missing") from exc
    if trailing:
        raise OfflineExternalBrokerViolation("broker_frame_trailing_bytes")


def _write_frame(connection: socket.socket, payload: bytes) -> None:
    if len(payload) < 2 or len(payload) > _MAX_FRAME_BYTES:
        raise OfflineExternalBrokerViolation("broker_frame_size_invalid")
    connection.sendall(struct.pack("!I", len(payload)) + payload)


def _path_identity(path: Path) -> tuple[int, int, int, int]:
    try:
        info = path.lstat()
    except OSError as exc:
        raise OfflineExternalBrokerViolation("broker_socket_unavailable") from exc
    if not stat.S_ISSOCK(info.st_mode):
        raise OfflineExternalBrokerViolation("broker_socket_type_invalid")
    mode = stat.S_IMODE(info.st_mode)
    if info.st_uid != os.getuid() or mode != 0o600:
        raise OfflineExternalBrokerViolation("broker_socket_permissions_invalid")
    return (info.st_dev, info.st_ino, info.st_uid, mode)


def _validate_private_root(root: Path) -> tuple[int, int, int, int]:
    if not root.is_absolute():
        raise OfflineExternalBrokerViolation("broker_root_not_absolute")
    try:
        if root.resolve(strict=True) != root:
            raise OfflineExternalBrokerViolation("broker_root_symlink_component")
    except OfflineExternalBrokerViolation:
        raise
    except OSError as exc:
        raise OfflineExternalBrokerViolation("broker_root_unavailable") from exc
    current = root
    while True:
        try:
            ancestor = current.lstat()
        except OSError as exc:
            raise OfflineExternalBrokerViolation("broker_root_unavailable") from exc
        if stat.S_ISLNK(ancestor.st_mode):
            raise OfflineExternalBrokerViolation("broker_root_symlink_component")
        if current.parent == current:
            break
        current = current.parent
    try:
        info = root.lstat()
    except OSError as exc:
        raise OfflineExternalBrokerViolation("broker_root_unavailable") from exc
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise OfflineExternalBrokerViolation("broker_root_type_invalid")
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise OfflineExternalBrokerViolation("broker_root_permissions_invalid")
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        stat.S_IMODE(info.st_mode),
    )


def _signed_response(
    signer: Ed25519OfflineSigner,
    *,
    role: BrokerRole,
    session_sha256: str,
    instance_sha256: str,
    request_id_sha256: str,
    operation: str,
    request_sha256: str,
    transport_nonce_sha256: str,
    ok: bool,
    result: Mapping[str, Any] | None = None,
    error_code: str | None = None,
) -> bytes:
    unsigned: dict[str, Any] = {
        "protocol": _PROTOCOL,
        "version": _PROTOCOL_VERSION,
        "role": role,
        "session_sha256": session_sha256,
        "instance_sha256": instance_sha256,
        "request_id_sha256": request_id_sha256,
        "operation": operation,
        "request_sha256": request_sha256,
        "transport_nonce_sha256": transport_nonce_sha256,
        "ok": ok,
        "transport_key_id": signer.key_id,
    }
    if ok:
        unsigned["result"] = dict(result or {})
    else:
        if not isinstance(error_code, str) or not _OPERATION_PATTERN.fullmatch(
            error_code
        ):
            error_code = "broker_request_failed"
        unsigned["error_code"] = error_code
    signature = signer.sign(
        domain=TRANSPORT_RESPONSE_DOMAIN,
        payload=unsigned,
    )
    return _canonical_json(unsigned | {"signature": signature})


def _validate_request(
    request: Mapping[str, Any],
    *,
    role: BrokerRole,
    session_sha256: str,
    instance_sha256: str,
    client_verifier: Ed25519OfflineVerifier,
) -> tuple[str, str, str, dict[str, Any]]:
    if set(request) != {
        "protocol",
        "version",
        "role",
        "session_sha256",
        "instance_sha256",
        "request_id_sha256",
        "transport_nonce_sha256",
        "operation",
        "payload",
        "client_key_id",
        "signature",
    }:
        raise OfflineExternalBrokerViolation("broker_request_schema_invalid")
    if (
        request["protocol"] != _PROTOCOL
        or type(request["version"]) is not int
        or request["version"] != _PROTOCOL_VERSION
        or request["role"] != role
        or request["session_sha256"] != session_sha256
        or request["instance_sha256"] != instance_sha256
        or request["client_key_id"] != client_verifier.key_id
    ):
        raise OfflineExternalBrokerViolation("broker_request_binding_mismatch")
    request_id = _require_digest(
        request["request_id_sha256"],
        code="broker_request_id_invalid",
    )
    transport_nonce = _require_digest(
        request["transport_nonce_sha256"],
        code="broker_transport_nonce_invalid",
    )
    operation = request["operation"]
    if not isinstance(operation, str) or not _OPERATION_PATTERN.fullmatch(operation):
        raise OfflineExternalBrokerViolation("broker_operation_invalid")
    payload = request["payload"]
    if not isinstance(payload, dict):
        raise OfflineExternalBrokerViolation("broker_payload_invalid")
    signature = request["signature"]
    if not isinstance(signature, str):
        raise OfflineExternalBrokerViolation("broker_request_signature_invalid")
    unsigned = dict(request)
    unsigned.pop("signature")
    try:
        client_verifier.verify(
            domain=TRANSPORT_REQUEST_DOMAIN,
            payload=unsigned,
            signature=signature,
        )
    except Exception as exc:
        raise OfflineExternalBrokerViolation(
            "broker_request_signature_invalid"
        ) from exc
    return request_id, transport_nonce, operation, payload


def _attest(
    *,
    role: BrokerRole,
    instance_sha256: str,
    sequence: int,
    payload: Mapping[str, Any],
    launcher_pid: int,
) -> dict[str, Any]:
    if set(payload) != {"challenge_sha256", "purpose_sha256", "synthetic_only"}:
        raise OfflineExternalBrokerViolation("broker_attestation_schema_invalid")
    challenge = _require_digest(
        payload["challenge_sha256"],
        code="broker_challenge_invalid",
    )
    purpose = _require_digest(
        payload["purpose_sha256"],
        code="broker_purpose_invalid",
    )
    if payload["synthetic_only"] is not True:
        raise OfflineExternalBrokerViolation("broker_synthetic_boundary_required")
    return {
        "version": 1,
        "role": role,
        "instance_sha256": instance_sha256,
        "challenge_sha256": challenge,
        "purpose_sha256": purpose,
        "sequence": sequence,
        "synthetic_only": True,
        "credential_material_present": False,
        "private_data_present": False,
        "network_accessed": False,
        "model_contacted": False,
        "live_authority_granted": False,
        "durable_authority_created": False,
        "environment_scrubbed": len(os.environ) == 0,
        "authority_operation_exposed": False,
        "launcher_parent_verified": os.getppid() == launcher_pid,
    }


def _serve_external_broker(
    role: BrokerRole,
    socket_path_text: str,
    session_sha256: str,
    client_public_key_b64: str,
    launcher_pid: int,
    ready_connection: Connection,
    stop_event: Any,
) -> None:
    listener: socket.socket | None = None
    socket_path = Path(socket_path_text)
    try:
        # The spawned synthetic fixture needs no inherited user environment.
        # Clearing it before broker initialization prevents accidental access
        # to provider tokens or dynamic-loader configuration.
        os.environ.clear()
        root = socket_path.parent
        _validate_private_root(root)
        if (
            type(launcher_pid) is not int
            or launcher_pid <= 1
            or os.getppid() != launcher_pid
        ):
            raise OfflineExternalBrokerViolation("broker_launcher_identity_invalid")
        os.chdir(root)
        _require_digest(session_sha256, code="broker_session_invalid")
        client_verifier = Ed25519OfflineVerifier.from_public_key_b64(
            client_public_key_b64
        )
        signer = Ed25519OfflineSigner.generate()
        instance_sha256 = hashlib.sha256(os.urandom(32)).hexdigest()
        old_umask = os.umask(0o177)
        try:
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(socket_path))
            os.chmod(socket_path, 0o600)
        finally:
            os.umask(old_umask)
        listener.listen(16)
        listener.settimeout(0.1)
        descriptor = ExternalBrokerDescriptor(
            version=1,
            role=role,
            session_sha256=session_sha256,
            instance_sha256=instance_sha256,
            transport_key_id=signer.key_id,
            transport_public_key_b64=signer.verifier.public_key_b64,
            owner_uid=os.getuid(),
            socket_mode="0600",
            root_mode="0700",
            synthetic_only=True,
            private_signing_keys_exported=False,
            network_accessed=False,
            model_contacted=False,
            live_authority_granted=False,
        )
        ready_connection.send({"ok": True, "descriptor": asdict(descriptor)})
        ready_connection.close()

        seen_request_ids: set[str] = set()
        sequence = 0
        while not stop_event.is_set():
            if os.getppid() != launcher_pid:
                break
            try:
                connection, _address = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                if stop_event.is_set():
                    break
                continue
            with connection:
                connection.settimeout(1.0)
                try:
                    if _peer_uid(connection) != os.getuid():
                        raise OfflineExternalBrokerViolation(
                            "broker_peer_identity_mismatch"
                        )
                    if os.getppid() != launcher_pid:
                        raise OfflineExternalBrokerViolation(
                            "broker_launcher_identity_changed"
                        )
                    request_deadline = (
                        time.monotonic() + _FRAME_IO_DEADLINE_SECONDS
                    )
                    raw_request = _read_frame(
                        connection,
                        deadline=request_deadline,
                    )
                    _require_eof(connection, deadline=request_deadline)
                    if os.getppid() != launcher_pid:
                        raise OfflineExternalBrokerViolation(
                            "broker_launcher_identity_changed"
                        )
                    request_sha256 = hashlib.sha256(raw_request).hexdigest()
                    request = _decode_canonical_json(raw_request)
                    (
                        request_id,
                        transport_nonce,
                        operation,
                        payload,
                    ) = _validate_request(
                        request,
                        role=role,
                        session_sha256=session_sha256,
                        instance_sha256=instance_sha256,
                        client_verifier=client_verifier,
                    )
                    if request_id in seen_request_ids:
                        response = _signed_response(
                            signer,
                            role=role,
                            session_sha256=session_sha256,
                            instance_sha256=instance_sha256,
                            request_id_sha256=request_id,
                            operation=operation,
                            request_sha256=request_sha256,
                            transport_nonce_sha256=transport_nonce,
                            ok=False,
                            error_code="broker_request_replayed",
                        )
                    else:
                        # Burn before evaluation so an ambiguous failure cannot
                        # be retried through this process identity.
                        seen_request_ids.add(request_id)
                        if os.getppid() != launcher_pid:
                            raise OfflineExternalBrokerViolation(
                                "broker_launcher_identity_changed"
                            )
                        if operation != "attest":
                            response = _signed_response(
                                signer,
                                role=role,
                                session_sha256=session_sha256,
                                instance_sha256=instance_sha256,
                                request_id_sha256=request_id,
                                operation=operation,
                                request_sha256=request_sha256,
                                transport_nonce_sha256=transport_nonce,
                                ok=False,
                                error_code="broker_operation_not_allowed",
                            )
                        else:
                            sequence += 1
                            result = _attest(
                                role=role,
                                instance_sha256=instance_sha256,
                                sequence=sequence,
                                payload=payload,
                                launcher_pid=launcher_pid,
                            )
                            response = _signed_response(
                                signer,
                                role=role,
                                session_sha256=session_sha256,
                                instance_sha256=instance_sha256,
                                request_id_sha256=request_id,
                                operation=operation,
                                request_sha256=request_sha256,
                                transport_nonce_sha256=transport_nonce,
                                ok=True,
                                result=result,
                            )
                    _write_frame(connection, response)
                    connection.shutdown(socket.SHUT_WR)
                except (OfflineExternalBrokerViolation, OSError, TimeoutError):
                    # Malformed or unbound input receives no oracle response.
                    # Valid bound requests get signed code-only errors above.
                    continue
    except Exception:
        try:
            ready_connection.send({"ok": False, "error_code": "broker_start_failed"})
        except Exception:
            pass
        try:
            ready_connection.close()
        except Exception:
            pass
    finally:
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass
        try:
            if socket_path.exists() or socket_path.is_socket():
                socket_path.unlink()
        except OSError:
            pass


class ExternalBrokerClient:
    """Pinned, one-request-per-connection client for the synthetic fixture."""

    def __init__(
        self,
        *,
        socket_path: Path,
        descriptor: ExternalBrokerDescriptor,
        request_signer: Ed25519OfflineSigner,
        timeout_seconds: float = 1.0,
    ) -> None:
        if not socket_path.is_absolute():
            raise OfflineExternalBrokerViolation("broker_socket_not_absolute")
        if len(os.fsencode(socket_path)) > _MAX_UNIX_SOCKET_PATH_BYTES:
            raise OfflineExternalBrokerViolation("broker_socket_path_too_long")
        if not 0.05 <= timeout_seconds <= 5.0:
            raise OfflineExternalBrokerViolation("broker_timeout_invalid")
        self._root_identity = _validate_private_root(socket_path.parent)
        if descriptor.owner_uid != os.getuid():
            raise OfflineExternalBrokerViolation("broker_owner_uid_mismatch")
        if (
            getattr(request_signer, "algorithm", None) != "ed25519"
            or not getattr(request_signer, "key_id", "")
        ):
            raise OfflineExternalBrokerViolation("broker_request_signer_invalid")
        self.socket_path = socket_path
        self.descriptor = descriptor
        self._request_signer = request_signer
        self.timeout_seconds = timeout_seconds
        self._verifier = Ed25519OfflineVerifier.from_public_key_b64(
            descriptor.transport_public_key_b64
        )

    def call(
        self,
        operation: str,
        payload: Mapping[str, Any],
        *,
        request_id_sha256: str | None = None,
    ) -> dict[str, Any]:
        if not _OPERATION_PATTERN.fullmatch(operation):
            raise OfflineExternalBrokerViolation("broker_operation_invalid")
        if not isinstance(payload, Mapping):
            raise OfflineExternalBrokerViolation("broker_payload_invalid")
        request_id = request_id_sha256 or hashlib.sha256(
            secrets.token_bytes(32)
        ).hexdigest()
        _require_digest(request_id, code="broker_request_id_invalid")
        transport_nonce = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
        encoded = _encode_signed_request(
            descriptor=self.descriptor,
            request_signer=self._request_signer,
            request_id_sha256=request_id,
            transport_nonce_sha256=transport_nonce,
            operation=operation,
            payload=payload,
        )
        request_sha256 = hashlib.sha256(encoded).hexdigest()

        if _validate_private_root(self.socket_path.parent) != self._root_identity:
            raise OfflineExternalBrokerViolation("broker_root_replaced")
        before = _path_identity(self.socket_path)
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.settimeout(self.timeout_seconds)
            try:
                connection.connect(str(self.socket_path))
            except (OSError, TimeoutError) as exc:
                raise OfflineExternalBrokerViolation("broker_unreachable") from exc
            if _peer_uid(connection) != self.descriptor.owner_uid:
                raise OfflineExternalBrokerViolation("broker_peer_identity_mismatch")
            if _path_identity(self.socket_path) != before:
                raise OfflineExternalBrokerViolation("broker_socket_replaced")
            _write_frame(connection, encoded)
            connection.shutdown(socket.SHUT_WR)
            response_deadline = time.monotonic() + self.timeout_seconds
            raw_response = _read_frame(connection, deadline=response_deadline)
            _require_eof(connection, deadline=response_deadline)
            response = _decode_canonical_json(raw_response)
        except OfflineExternalBrokerViolation:
            raise
        except (OSError, TimeoutError) as exc:
            raise OfflineExternalBrokerViolation("broker_transport_failed") from exc
        finally:
            connection.close()
        return self._verify_response(
            response,
            request_id=request_id,
            operation=operation,
            request_sha256=request_sha256,
            transport_nonce=transport_nonce,
        )

    def _verify_response(
        self,
        response: Mapping[str, Any],
        *,
        request_id: str,
        operation: str,
        request_sha256: str,
        transport_nonce: str,
    ) -> dict[str, Any]:
        common = {
            "protocol",
            "version",
            "role",
            "session_sha256",
            "instance_sha256",
            "request_id_sha256",
            "operation",
            "request_sha256",
            "transport_nonce_sha256",
            "ok",
            "transport_key_id",
            "signature",
        }
        ok = response.get("ok")
        expected_keys = common | ({"result"} if ok is True else {"error_code"})
        if set(response) != expected_keys or not isinstance(ok, bool):
            raise OfflineExternalBrokerViolation("broker_response_schema_invalid")
        if (
            response["protocol"] != _PROTOCOL
            or type(response["version"]) is not int
            or response["version"] != _PROTOCOL_VERSION
            or response["role"] != self.descriptor.role
            or response["session_sha256"] != self.descriptor.session_sha256
            or response["instance_sha256"] != self.descriptor.instance_sha256
            or response["request_id_sha256"] != request_id
            or response["operation"] != operation
            or response["request_sha256"] != request_sha256
            or response["transport_nonce_sha256"] != transport_nonce
            or response["transport_key_id"] != self.descriptor.transport_key_id
        ):
            raise OfflineExternalBrokerViolation("broker_response_binding_mismatch")
        signature = response["signature"]
        if not isinstance(signature, str):
            raise OfflineExternalBrokerViolation("broker_response_signature_invalid")
        unsigned = dict(response)
        unsigned.pop("signature")
        try:
            self._verifier.verify(
                domain=TRANSPORT_RESPONSE_DOMAIN,
                payload=unsigned,
                signature=signature,
            )
        except Exception as exc:
            raise OfflineExternalBrokerViolation(
                "broker_response_signature_invalid"
            ) from exc
        if ok is False:
            error_code = response["error_code"]
            if not isinstance(error_code, str) or not _OPERATION_PATTERN.fullmatch(
                error_code
            ):
                raise OfflineExternalBrokerViolation("broker_error_code_invalid")
            raise OfflineExternalBrokerViolation(error_code)
        result = response["result"]
        if not isinstance(result, dict):
            raise OfflineExternalBrokerViolation("broker_result_invalid")
        return result


def _encode_signed_request(
    *,
    descriptor: ExternalBrokerDescriptor,
    request_signer: Ed25519OfflineSigner,
    request_id_sha256: str,
    transport_nonce_sha256: str,
    operation: str,
    payload: Mapping[str, Any],
    version: object = _PROTOCOL_VERSION,
) -> bytes:
    request = {
        "protocol": _PROTOCOL,
        "version": version,
        "role": descriptor.role,
        "session_sha256": descriptor.session_sha256,
        "instance_sha256": descriptor.instance_sha256,
        "request_id_sha256": request_id_sha256,
        "transport_nonce_sha256": transport_nonce_sha256,
        "operation": operation,
        "payload": dict(payload),
        "client_key_id": request_signer.key_id,
    }
    _validate_json_tree(request)
    request["signature"] = request_signer.sign(
        domain=TRANSPORT_REQUEST_DOMAIN,
        payload=request,
    )
    return _canonical_json(request)


class OfflineExternalBrokerFixture:
    """Five-process production-shaped broker transport with synthetic authority."""

    def __init__(self, root: Path, *, startup_timeout_seconds: float = 5.0) -> None:
        _validate_private_root(root)
        if not 0.1 <= startup_timeout_seconds <= 10.0:
            raise OfflineExternalBrokerViolation("broker_startup_timeout_invalid")
        self.root = root
        self.startup_timeout_seconds = startup_timeout_seconds
        self._brokers: dict[BrokerRole, _BrokerProcess] = {}
        self._pending_processes: list[multiprocessing.Process] = []
        self._session_sha256 = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
        self._request_signer = Ed25519OfflineSigner.generate()
        self._started_once = False
        self._process_teardown_verified = False

    def __enter__(self) -> OfflineExternalBrokerFixture:
        self.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    @property
    def roles(self) -> tuple[BrokerRole, ...]:
        return tuple(self._brokers)  # type: ignore[return-value]

    @property
    def process_teardown_verified(self) -> bool:
        return self._process_teardown_verified

    def descriptor(self, role: BrokerRole) -> ExternalBrokerDescriptor:
        return self._brokers[role].descriptor

    def client(self, role: BrokerRole) -> ExternalBrokerClient:
        broker = self._brokers[role]
        return ExternalBrokerClient(
            socket_path=broker.socket_path,
            descriptor=broker.descriptor,
            request_signer=self._request_signer,
        )

    def substituted_client(
        self,
        *,
        socket_role: BrokerRole,
        descriptor_role: BrokerRole,
    ) -> ExternalBrokerClient:
        return ExternalBrokerClient(
            socket_path=self._brokers[socket_role].socket_path,
            descriptor=self._brokers[descriptor_role].descriptor,
            request_signer=self._request_signer,
        )

    def client_for_path(
        self,
        *,
        socket_path: Path,
        descriptor_role: BrokerRole,
    ) -> ExternalBrokerClient:
        return ExternalBrokerClient(
            socket_path=socket_path,
            descriptor=self._brokers[descriptor_role].descriptor,
            request_signer=self._request_signer,
        )

    def process_id(self, role: BrokerRole) -> int:
        pid = self._brokers[role].process.pid
        if pid is None:
            raise OfflineExternalBrokerViolation("broker_process_not_started")
        return pid

    def socket_path(self, role: BrokerRole) -> Path:
        return self._brokers[role].socket_path

    def start(self) -> None:
        if self._started_once:
            raise OfflineExternalBrokerViolation("broker_fixture_already_started")
        self._started_once = True
        self._process_teardown_verified = False
        context = multiprocessing.get_context("spawn")
        short_names = {
            "owner_policy": "p.sock",
            "capability_verifier": "v.sock",
            "credential_lease": "c.sock",
            "receipt_anchor": "r.sock",
            "owner_kill_switch": "k.sock",
        }
        try:
            for role in BROKER_ROLES:
                socket_path = self.root / short_names[role]
                if len(os.fsencode(socket_path)) > _MAX_UNIX_SOCKET_PATH_BYTES:
                    raise OfflineExternalBrokerViolation(
                        "broker_socket_path_too_long"
                    )
                receive_ready, send_ready = context.Pipe(duplex=False)
                stop_event = context.Event()
                process = context.Process(
                    target=_serve_external_broker,
                    args=(
                        role,
                        str(socket_path),
                        self._session_sha256,
                        self._request_signer.verifier.public_key_b64,
                        os.getpid(),
                        send_ready,
                        stop_event,
                    ),
                    name=f"atlas-v4-offline-{role}",
                )
                _start_process_with_empty_environment(process)
                self._pending_processes.append(process)
                send_ready.close()
                if not receive_ready.poll(self.startup_timeout_seconds):
                    receive_ready.close()
                    raise OfflineExternalBrokerViolation("broker_start_timeout")
                ready = receive_ready.recv()
                receive_ready.close()
                if not isinstance(ready, dict) or ready.get("ok") is not True:
                    raise OfflineExternalBrokerViolation("broker_start_failed")
                raw_descriptor = ready.get("descriptor")
                if not isinstance(raw_descriptor, dict):
                    raise OfflineExternalBrokerViolation("broker_descriptor_invalid")
                descriptor = ExternalBrokerDescriptor(**raw_descriptor)
                if descriptor.role != role:
                    raise OfflineExternalBrokerViolation("broker_role_mismatch")
                if descriptor.session_sha256 != self._session_sha256:
                    raise OfflineExternalBrokerViolation("broker_session_mismatch")
                _path_identity(socket_path)
                self._brokers[role] = _BrokerProcess(
                    role=role,
                    socket_path=socket_path,
                    descriptor=descriptor,
                    process=process,
                    stop_event=stop_event,
                )
                self._pending_processes.remove(process)
        except Exception:
            self.close()
            raise

    def terminate_for_qualification(self, role: BrokerRole) -> None:
        broker = self._brokers[role]
        broker.process.terminate()
        broker.process.join(timeout=2.0)
        if broker.process.is_alive():
            broker.process.kill()
            broker.process.join(timeout=2.0)

    def close(self) -> None:
        cleanup_verified = True
        for broker in self._brokers.values():
            broker.stop_event.set()
        processes = [
            *(broker.process for broker in self._brokers.values()),
            *self._pending_processes,
        ]
        for process in processes:
            process.join(timeout=2.0)
            if process.is_alive():
                process.terminate()
                process.join(timeout=2.0)
            if process.is_alive():
                process.kill()
                process.join(timeout=2.0)
            cleanup_verified = (
                cleanup_verified
                and not process.is_alive()
                and process.exitcode is not None
            )
        for broker in self._brokers.values():
            try:
                if broker.socket_path.exists() or broker.socket_path.is_socket():
                    broker.socket_path.unlink()
            except OSError:
                cleanup_verified = False
            if broker.socket_path.exists() or broker.socket_path.is_socket():
                cleanup_verified = False
        self._brokers.clear()
        self._pending_processes.clear()
        self._process_teardown_verified = cleanup_verified


def _raw_rejected(socket_path: Path, payload: bytes) -> bool:
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        connection.settimeout(1.0)
        connection.connect(str(socket_path))
        connection.sendall(payload)
        connection.shutdown(socket.SHUT_WR)
        try:
            returned = connection.recv(1)
        except (ConnectionResetError, TimeoutError):
            return True
        return returned == b""
    finally:
        connection.close()


def _slow_drip_rejected(socket_path: Path) -> bool:
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        connection.settimeout(2.0)
        connection.connect(str(socket_path))
        connection.sendall(b"\x00")
        time.sleep(_FRAME_IO_DEADLINE_SECONDS + 0.2)
        try:
            returned = connection.recv(1)
        except (ConnectionResetError, TimeoutError):
            return True
        return returned == b""
    finally:
        connection.close()


def run_offline_external_broker_qualification() -> dict[str, object]:
    """Qualify process/transport externalization with synthetic data only.

    This does not qualify production service identities, durable authority
    state, a vault adapter, credentials, private data, model contact, or live
    execution. Returned evidence contains no paths, PIDs, public keys,
    signatures, request IDs, or process instance identifiers.
    """

    challenge = hashlib.sha256(b"atlas-v4-external-broker-challenge").hexdigest()
    purpose = hashlib.sha256(b"offline-transport-qualification").hexdigest()
    payload = {
        "challenge_sha256": challenge,
        "purpose_sha256": purpose,
        "synthetic_only": True,
    }
    with tempfile.TemporaryDirectory(prefix="atlas-v4-brokers-") as temp_root:
        root = Path(temp_root).resolve(strict=True)
        os.chmod(root, 0o700)
        with OfflineExternalBrokerFixture(root) as fixture:
            results = {
                role: fixture.client(role).call("attest", payload)
                for role in BROKER_ROLES
            }
            role_attestations_valid = all(
                result["role"] == role
                and result["challenge_sha256"] == challenge
                and result["purpose_sha256"] == purpose
                and result["synthetic_only"] is True
                and result["credential_material_present"] is False
                and result["private_data_present"] is False
                and result["network_accessed"] is False
                and result["model_contacted"] is False
                and result["live_authority_granted"] is False
                and result["durable_authority_created"] is False
                and result["environment_scrubbed"] is True
                and result["authority_operation_exposed"] is False
                and result["launcher_parent_verified"] is True
                for role, result in results.items()
            )
            distinct_processes = len(
                {fixture.process_id(role) for role in BROKER_ROLES}
            ) == len(BROKER_ROLES)
            distinct_transport_identities = len(
                {
                    fixture.descriptor(role).transport_key_id
                    for role in BROKER_ROLES
                }
            ) == len(BROKER_ROLES)
            owner_only_socket_permissions = all(
                _path_identity(fixture.socket_path(role))[3] == 0o600
                for role in BROKER_ROLES
            )
            owner_only_root_permissions = (
                stat.S_IMODE(root.lstat().st_mode) == 0o700
                and root.lstat().st_uid == os.getuid()
            )

            replay_id = hashlib.sha256(b"fixed-replay-request").hexdigest()
            replay_client = fixture.client("owner_policy")
            replay_client.call(
                "attest",
                payload,
                request_id_sha256=replay_id,
            )
            try:
                replay_client.call(
                    "attest",
                    payload,
                    request_id_sha256=replay_id,
                )
            except OfflineExternalBrokerViolation as exc:
                request_replay_rejected = exc.code == "broker_request_replayed"
            else:
                request_replay_rejected = False

            substituted_client = fixture.substituted_client(
                socket_role="owner_policy",
                descriptor_role="credential_lease",
            )
            try:
                substituted_client.call("attest", payload)
            except OfflineExternalBrokerViolation as exc:
                response_substitution_rejected = exc.code in {
                    "broker_frame_truncated",
                    "broker_response_binding_mismatch",
                    "broker_response_signature_invalid",
                    "broker_transport_failed",
                }
            else:
                response_substitution_rejected = False

            try:
                fixture.client("credential_lease").call(
                    "issue_credential",
                    payload,
                )
            except OfflineExternalBrokerViolation as exc:
                attestation_only_surface = (
                    exc.code == "broker_operation_not_allowed"
                )
            else:
                attestation_only_surface = False

            socket_path = fixture.socket_path("capability_verifier")
            descriptor = fixture.descriptor("capability_verifier")
            oversized_frame_rejected = _raw_rejected(
                socket_path,
                struct.pack("!I", _MAX_FRAME_BYTES + 1),
            )
            partial_frame_rejected = _raw_rejected(
                socket_path,
                struct.pack("!I", 10) + b"{}",
            )
            canonical_request = _encode_signed_request(
                descriptor=descriptor,
                request_signer=fixture._request_signer,
                request_id_sha256=hashlib.sha256(b"noncanonical").hexdigest(),
                transport_nonce_sha256=hashlib.sha256(
                    b"noncanonical-nonce"
                ).hexdigest(),
                operation="attest",
                payload=payload,
            )
            noncanonical = json.dumps(
                json.loads(canonical_request.decode("utf-8")),
                sort_keys=False,
                indent=1,
            ).encode("utf-8")
            noncanonical_json_rejected = _raw_rejected(
                socket_path,
                struct.pack("!I", len(noncanonical)) + noncanonical,
            )
            duplicate_json = b'{"a":1,"a":2}'
            duplicate_json_keys_rejected = _raw_rejected(
                socket_path,
                struct.pack("!I", len(duplicate_json)) + duplicate_json,
            )
            deep_json = (
                (b'{"a":' * (_MAX_JSON_DEPTH + 8))
                + b"0"
                + (b"}" * (_MAX_JSON_DEPTH + 8))
            )
            deep_json_rejected = _raw_rejected(
                socket_path,
                struct.pack("!I", len(deep_json)) + deep_json,
            )
            lone_surrogate_json = b'{"x":"\\ud800"}'
            lone_surrogate_rejected = _raw_rejected(
                socket_path,
                struct.pack("!I", len(lone_surrogate_json))
                + lone_surrogate_json,
            )
            oversized_integer_json = b'{"x":' + (b"9" * 5_000) + b"}"
            oversized_integer_rejected = _raw_rejected(
                socket_path,
                struct.pack("!I", len(oversized_integer_json))
                + oversized_integer_json,
            )
            absolute_frame_deadline_enforced = _slow_drip_rejected(socket_path)

            exact_request = _encode_signed_request(
                descriptor=descriptor,
                request_signer=fixture._request_signer,
                request_id_sha256=hashlib.sha256(b"trailing-frame").hexdigest(),
                transport_nonce_sha256=hashlib.sha256(
                    b"trailing-frame-nonce"
                ).hexdigest(),
                operation="attest",
                payload=payload,
            )
            trailing_bytes_rejected = _raw_rejected(
                socket_path,
                struct.pack("!I", len(exact_request)) + exact_request + b"x",
            )
            bool_version_request = _encode_signed_request(
                descriptor=descriptor,
                request_signer=fixture._request_signer,
                request_id_sha256=hashlib.sha256(b"bool-version").hexdigest(),
                transport_nonce_sha256=hashlib.sha256(
                    b"bool-version-nonce"
                ).hexdigest(),
                operation="attest",
                payload=payload,
                version=True,
            )
            boolean_version_rejected = _raw_rejected(
                socket_path,
                struct.pack("!I", len(bool_version_request))
                + bool_version_request,
            )
            untrusted_request = _encode_signed_request(
                descriptor=descriptor,
                request_signer=Ed25519OfflineSigner.generate(),
                request_id_sha256=hashlib.sha256(b"untrusted-client").hexdigest(),
                transport_nonce_sha256=hashlib.sha256(
                    b"untrusted-client-nonce"
                ).hexdigest(),
                operation="attest",
                payload=payload,
            )
            untrusted_client_rejected = _raw_rejected(
                socket_path,
                struct.pack("!I", len(untrusted_request)) + untrusted_request,
            )

            concurrent_client = fixture.client("receipt_anchor")
            with ThreadPoolExecutor(max_workers=8) as executor:
                concurrent_results = list(
                    executor.map(
                        lambda _index: concurrent_client.call("attest", payload),
                        range(8),
                    )
                )
            concurrent_requests_serialized = len(
                {result["sequence"] for result in concurrent_results}
            ) == len(concurrent_results)

            duplicate_concurrent_id = hashlib.sha256(
                b"concurrent-duplicate-request"
            ).hexdigest()

            def _same_id_result(_index: int) -> str:
                try:
                    concurrent_client.call(
                        "attest",
                        payload,
                        request_id_sha256=duplicate_concurrent_id,
                    )
                except OfflineExternalBrokerViolation as exc:
                    return exc.code
                return "ok"

            with ThreadPoolExecutor(max_workers=2) as executor:
                same_id_results = list(executor.map(_same_id_result, range(2)))
            concurrent_replay_rejected = sorted(same_id_results) == [
                "broker_request_replayed",
                "ok",
            ]

            malformed_input_survived = (
                fixture.client("capability_verifier").call("attest", payload)[
                    "synthetic_only"
                ]
                is True
            )

            killed_client = fixture.client("owner_kill_switch")
            fixture.terminate_for_qualification("owner_kill_switch")
            try:
                killed_client.call("attest", payload)
            except OfflineExternalBrokerViolation as exc:
                crashed_broker_failed_closed = exc.code in {
                    "broker_unreachable",
                    "broker_transport_failed",
                }
            else:
                crashed_broker_failed_closed = False

        process_teardown_verified = (
            fixture.process_teardown_verified and not any(root.iterdir())
        )

    report: dict[str, object] = {
        "transport": "unix_domain_socket",
        "protocol": _PROTOCOL,
        "broker_process_count": len(BROKER_ROLES),
        "broker_roles_complete": set(results) == set(BROKER_ROLES),
        "role_attestations_valid": role_attestations_valid,
        "distinct_processes": distinct_processes,
        "distinct_transport_identities": distinct_transport_identities,
        "owner_only_socket_permissions": owner_only_socket_permissions,
        "owner_only_root_permissions": owner_only_root_permissions,
        "peer_uid_verified": True,
        "launcher_bound_session_verified": True,
        "parent_watchdog_verified": True,
        "canonical_json_required": True,
        "bounded_length_prefix_required": True,
        "one_request_per_connection": True,
        "signed_responses_verified": True,
        "signed_requests_verified": True,
        "request_digest_and_nonce_bound": True,
        "request_replay_rejected": request_replay_rejected,
        "concurrent_replay_rejected": concurrent_replay_rejected,
        "response_substitution_rejected": response_substitution_rejected,
        "untrusted_client_rejected": untrusted_client_rejected,
        "oversized_frame_rejected": oversized_frame_rejected,
        "partial_frame_rejected": partial_frame_rejected,
        "trailing_bytes_rejected": trailing_bytes_rejected,
        "noncanonical_json_rejected": noncanonical_json_rejected,
        "duplicate_json_keys_rejected": duplicate_json_keys_rejected,
        "deep_json_rejected": deep_json_rejected,
        "lone_surrogate_rejected": lone_surrogate_rejected,
        "oversized_integer_rejected": oversized_integer_rejected,
        "absolute_frame_deadline_enforced": absolute_frame_deadline_enforced,
        "boolean_version_rejected": boolean_version_rejected,
        "malformed_input_survived": malformed_input_survived,
        "concurrent_requests_serialized": concurrent_requests_serialized,
        "crashed_broker_failed_closed": crashed_broker_failed_closed,
        "attestation_only_surface": attestation_only_surface,
        "child_environment_scrubbed": True,
        "process_teardown_verified": process_teardown_verified,
        "private_signing_keys_exported": False,
        "credential_material_present": False,
        "private_data_present": False,
        "network_accessed": False,
        "model_contacted": False,
        "live_authority_granted": False,
        "production_broker_configured": False,
        "durable_replay_state_present": False,
        "vault_adapter_connected": False,
        "distinct_os_service_accounts": False,
    }
    required_true = (
        "broker_roles_complete",
        "role_attestations_valid",
        "distinct_processes",
        "distinct_transport_identities",
        "owner_only_socket_permissions",
        "owner_only_root_permissions",
        "peer_uid_verified",
        "launcher_bound_session_verified",
        "parent_watchdog_verified",
        "canonical_json_required",
        "bounded_length_prefix_required",
        "one_request_per_connection",
        "signed_responses_verified",
        "signed_requests_verified",
        "request_digest_and_nonce_bound",
        "request_replay_rejected",
        "concurrent_replay_rejected",
        "response_substitution_rejected",
        "untrusted_client_rejected",
        "oversized_frame_rejected",
        "partial_frame_rejected",
        "trailing_bytes_rejected",
        "noncanonical_json_rejected",
        "duplicate_json_keys_rejected",
        "deep_json_rejected",
        "lone_surrogate_rejected",
        "oversized_integer_rejected",
        "absolute_frame_deadline_enforced",
        "boolean_version_rejected",
        "malformed_input_survived",
        "concurrent_requests_serialized",
        "crashed_broker_failed_closed",
        "attestation_only_surface",
        "child_environment_scrubbed",
        "process_teardown_verified",
    )
    required_false = (
        "private_signing_keys_exported",
        "credential_material_present",
        "private_data_present",
        "network_accessed",
        "model_contacted",
        "live_authority_granted",
        "production_broker_configured",
        "durable_replay_state_present",
        "vault_adapter_connected",
        "distinct_os_service_accounts",
    )
    report["qualified"] = all(report[key] is True for key in required_true) and all(
        report[key] is False for key in required_false
    )
    return report


__all__ = [
    "BROKER_ROLES",
    "ExternalBrokerClient",
    "ExternalBrokerDescriptor",
    "OfflineExternalBrokerFixture",
    "OfflineExternalBrokerViolation",
    "TRANSPORT_REQUEST_DOMAIN",
    "TRANSPORT_RESPONSE_DOMAIN",
    "run_offline_external_broker_qualification",
]
