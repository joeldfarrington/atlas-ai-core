from __future__ import annotations

"""Guarded same-user broker for offline, synthetic Option 1 qualification."""

import hashlib
import json
import os
import re
import secrets
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Mapping, Protocol

from atlas_core.supervisor_v4_live_contract import (
    CapabilityVerificationReceipt,
    CredentialLeaseMetadata,
    CredentialLeaseRequest,
    CredentialRevocationReceipt,
    document_sha256,
)
from atlas_core.supervisor_v4_offline_credential_broker import (
    CREDENTIAL_LEASE_DOMAIN,
    SyntheticOneUseChannelHandle,
)
from atlas_core.supervisor_v4_offline_crypto import (
    OfflineSigner,
    OfflineVerifier,
    unsigned_document,
)
from atlas_core.supervisor_v4_offline_policy_broker import (
    CAPABILITY_DOMAIN,
    CAPABILITY_VERIFICATION_DOMAIN,
)
from atlas_core.supervisor_v4_protocol import SignedCapabilityEnvelope
from atlas_core.supervisor_v4_same_user_state import (
    DurableSameUserTrustState,
    SameUserStateViolation,
)


_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_LABEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_SIGNATURE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{86}$")
_MAX_REGISTRY_BYTES = 128 * 1024
_MAX_CONNECTOR_OUTPUT_BYTES = 16_384
_SENTINEL_PREFIX = b"atlas-option1-synthetic-v1_"
_DELIVERY_DOMAIN = "atlas.supervisor-v4.same-user-delivery.v1"
_REVOCATION_DOMAIN = "atlas.supervisor-v4.credential-revocation.v1"
_DARWIN_SANDBOX_PROFILE = (
    '(version 1)(allow default)(deny network*)(deny file-write*)'
    '(deny process-fork)'
)


class SameUserBrokerViolation(ValueError):
    """Privacy-safe, fail-closed Option 1 broker failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


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
        raise SameUserBrokerViolation("same_user_document_invalid") from exc


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise SameUserBrokerViolation("same_user_registry_duplicate_key")
        value[key] = item
    return value


def _require_digest(value: object, *, code: str) -> str:
    if not isinstance(value, str) or not _DIGEST_PATTERN.fullmatch(value) or value == "0" * 64:
        raise SameUserBrokerViolation(code)
    return value


def _require_label(value: object, *, code: str) -> str:
    if not isinstance(value, str) or not _LABEL_PATTERN.fullmatch(value):
        raise SameUserBrokerViolation(code)
    return value


def _parse_time(value: str, *, code: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError) as exc:
        raise SameUserBrokerViolation(code) from exc
    if parsed.tzinfo is None:
        raise SameUserBrokerViolation(code)
    return parsed.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise SameUserBrokerViolation("same_user_clock_invalid")
    return value.astimezone(timezone.utc).isoformat()


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


@dataclass(frozen=True, slots=True)
class SameUserTaskBinding:
    version: int
    mapping_id: str
    task_sha256: str
    job_sha256: str
    policy_bundle_sha256: str
    egress_manifest_sha256: str
    provider: str
    model: str
    audience: str
    credential_scope_sha256: str
    destination_sha256: str
    vault_item_label_sha256: str
    connector_profile: str
    synthetic_only: bool
    network_allowed: bool

    def __post_init__(self) -> None:
        if self.version != 1 or self.synthetic_only is not True or self.network_allowed is not False:
            raise SameUserBrokerViolation("same_user_mapping_profile_invalid")
        _require_label(self.mapping_id, code="same_user_mapping_id_invalid")
        _require_label(self.provider, code="same_user_mapping_provider_invalid")
        _require_label(self.model, code="same_user_mapping_model_invalid")
        _require_label(self.audience, code="same_user_mapping_audience_invalid")
        _require_label(self.connector_profile, code="same_user_connector_profile_invalid")
        for value in (
            self.task_sha256,
            self.job_sha256,
            self.policy_bundle_sha256,
            self.egress_manifest_sha256,
            self.credential_scope_sha256,
            self.destination_sha256,
            self.vault_item_label_sha256,
        ):
            _require_digest(value, code="same_user_mapping_digest_invalid")

    @property
    def sha256(self) -> str:
        return _sha256(_canonical_json(asdict(self)))


class OwnerTaskRegistry:
    """Source-pinned immutable task map with no item-enumeration operation."""

    def __init__(self, *, bindings: tuple[SameUserTaskBinding, ...], source_sha256: str) -> None:
        _require_digest(source_sha256, code="same_user_registry_source_invalid")
        if not bindings or len(bindings) > 32:
            raise SameUserBrokerViolation("same_user_registry_size_invalid")
        tasks: dict[str, SameUserTaskBinding] = {}
        mapping_ids: set[str] = set()
        for binding in bindings:
            if binding.task_sha256 in tasks or binding.mapping_id in mapping_ids:
                raise SameUserBrokerViolation("same_user_registry_mapping_duplicate")
            tasks[binding.task_sha256] = binding
            mapping_ids.add(binding.mapping_id)
        self._tasks = tasks
        self.source_sha256 = source_sha256
        self.sha256 = _sha256(
            _canonical_json(
                {
                    "version": 1,
                    "classification": "offline_synthetic_option1",
                    "mappings": [asdict(item) for item in bindings],
                }
            )
        )

    @classmethod
    def load(cls, path: Path) -> OwnerTaskRegistry:
        if not path.is_absolute() or path.is_symlink():
            raise SameUserBrokerViolation("same_user_registry_path_invalid")
        try:
            metadata = path.stat()
        except OSError as exc:
            raise SameUserBrokerViolation("same_user_registry_unavailable") from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > _MAX_REGISTRY_BYTES
        ):
            raise SameUserBrokerViolation("same_user_registry_file_invalid")
        try:
            raw = path.read_bytes()
            document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
        except SameUserBrokerViolation:
            raise
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SameUserBrokerViolation("same_user_registry_invalid") from exc
        if not isinstance(document, dict) or set(document) != {
            "version",
            "classification",
            "mappings",
        }:
            raise SameUserBrokerViolation("same_user_registry_schema_invalid")
        if document["version"] != 1 or document["classification"] != "offline_synthetic_option1":
            raise SameUserBrokerViolation("same_user_registry_profile_invalid")
        mappings = document["mappings"]
        if not isinstance(mappings, list):
            raise SameUserBrokerViolation("same_user_registry_mappings_invalid")
        try:
            bindings = tuple(SameUserTaskBinding(**item) for item in mappings if isinstance(item, dict))
        except TypeError as exc:
            raise SameUserBrokerViolation("same_user_registry_mapping_invalid") from exc
        if len(bindings) != len(mappings):
            raise SameUserBrokerViolation("same_user_registry_mapping_invalid")
        return cls(bindings=bindings, source_sha256=_sha256(raw))

    @property
    def task_count(self) -> int:
        return len(self._tasks)

    def _resolve(
        self,
        request: CredentialLeaseRequest,
        capability: SignedCapabilityEnvelope,
    ) -> SameUserTaskBinding:
        binding = self._tasks.get(request.task_sha256)
        if binding is None:
            raise SameUserBrokerViolation("same_user_task_not_registered")
        expected = {
            "job": (request.job_sha256, binding.job_sha256),
            "policy": (request.policy_bundle_sha256, binding.policy_bundle_sha256),
            "egress": (request.egress_manifest_sha256, binding.egress_manifest_sha256),
            "provider": (request.provider, binding.provider),
            "model": (request.model, binding.model),
            "audience": (request.audience, binding.audience),
            "scope": (request.credential_scope_sha256, binding.credential_scope_sha256),
            "capability_task": (capability.bindings.task_sha256, binding.task_sha256),
            "capability_job": (capability.bindings.job_sha256, binding.job_sha256),
            "capability_policy": (
                capability.bindings.policy_bundle_sha256,
                binding.policy_bundle_sha256,
            ),
            "capability_egress": (
                capability.bindings.data_egress_manifest_sha256,
                binding.egress_manifest_sha256,
            ),
        }
        mismatch = next((name for name, pair in expected.items() if pair[0] != pair[1]), None)
        if mismatch is not None:
            raise SameUserBrokerViolation(f"same_user_mapping_{mismatch}_mismatch")
        return binding

    def _item_labels_for_adapter(self) -> tuple[str, ...]:
        return tuple(binding.vault_item_label_sha256 for binding in self._tasks.values())


class SyntheticLockedVaultAdapter:
    """One-use fake vault; material can only be written to an existing fd."""

    def __init__(self, registry: OwnerTaskRegistry) -> None:
        self._lock = threading.RLock()
        self._locked = True
        self._materials = {
            item: bytearray(_SENTINEL_PREFIX + secrets.token_urlsafe(32).encode("ascii"))
            for item in registry._item_labels_for_adapter()
        }
        self._fingerprints: set[tuple[int, str]] = set()

    def __repr__(self) -> str:
        return f"{type(self).__name__}(locked={self._locked}, material='<redacted>')"

    @property
    def locked(self) -> bool:
        return self._locked

    @property
    def remaining_item_count(self) -> int:
        return len(self._materials)

    def unlock_for_qualification(self) -> None:
        with self._lock:
            self._locked = False

    def lock(self) -> None:
        with self._lock:
            self._locked = True

    def destroy(self) -> None:
        """Zeroize every unused synthetic item and permanently lock the adapter."""

        with self._lock:
            for material in self._materials.values():
                for index in range(len(material)):
                    material[index] = 0
            self._materials.clear()
            self._locked = True

    def consume_to_descriptor(self, item_label_sha256: str, descriptor: int) -> None:
        _require_digest(item_label_sha256, code="same_user_vault_item_invalid")
        if not isinstance(descriptor, int) or descriptor < 0:
            raise SameUserBrokerViolation("same_user_vault_channel_invalid")
        with self._lock:
            if self._locked:
                raise SameUserBrokerViolation("same_user_vault_locked")
            material = self._materials.pop(item_label_sha256, None)
            if material is None:
                raise SameUserBrokerViolation("same_user_vault_item_unavailable")
            fingerprint = (len(material), hashlib.sha256(material).hexdigest())
            self._fingerprints.add(fingerprint)
            try:
                header = struct.pack(">I", len(material))
                view = memoryview(header)
                while view:
                    view = view[os.write(descriptor, view) :]
                view = memoryview(material)
                while view:
                    view = view[os.write(descriptor, view) :]
            except OSError as exc:
                raise SameUserBrokerViolation("same_user_vault_delivery_failed") from exc
            finally:
                for index in range(len(material)):
                    material[index] = 0

    def contains_known_material(self, value: bytes) -> bool:
        if not isinstance(value, bytes):
            raise SameUserBrokerViolation("same_user_leak_scan_input_invalid")
        for length, expected in self._fingerprints:
            if len(value) < length:
                continue
            for start in range(0, len(value) - length + 1):
                if secrets.compare_digest(_sha256(value[start : start + length]), expected):
                    return True
        return False


@dataclass(frozen=True, slots=True)
class ConnectorResult:
    environment_empty: bool
    network_socket_blocked: bool
    filesystem_write_blocked: bool
    process_fork_blocked: bool
    working_buffer_zeroized: bool
    material_persisted: bool
    material_returned: bool
    model_contacted: bool
    provider_contacted: bool
    parent_verified: bool
    inherited_descriptor_count: int
    remaining_descriptor_count: int
    process_group_reaped: bool
    output_material_absent: bool


class SyntheticConnector(Protocol):
    profile_id: str

    def deliver(
        self,
        *,
        vault: SyntheticLockedVaultAdapter,
        item_label_sha256: str,
    ) -> ConnectorResult: ...


def _terminate_process(
    process: subprocess.Popen[bytes],
    *,
    owns_process_group: bool,
) -> None:
    if process.poll() is not None:
        return
    try:
        if owns_process_group:
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
        process.wait(timeout=1.0)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        if process.poll() is None:
            try:
                if owns_process_group:
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            except ProcessLookupError:
                pass
            process.wait(timeout=2.0)


class DarwinSandboxedSyntheticConnector:
    """Mac qualification adapter; the broker-facing interface is host-neutral."""

    profile_id = "darwin-sandboxed-null-connector-v1"

    def __init__(
        self,
        *,
        runtime_root: Path,
        python_executable: Path,
        connector_source: Path,
        sandbox_exec: Path = Path("/usr/bin/sandbox-exec"),
        timeout_seconds: float = 5.0,
        join_current_process_group: bool = False,
    ) -> None:
        if sys.platform != "darwin":
            raise SameUserBrokerViolation("same_user_connector_platform_unsupported")
        if type(join_current_process_group) is not bool:
            raise SameUserBrokerViolation("same_user_connector_process_group_mode_invalid")
        if not 0.5 <= timeout_seconds <= 30:
            raise SameUserBrokerViolation("same_user_connector_timeout_invalid")
        self.runtime_root = runtime_root.resolve(strict=True)
        root_metadata = self.runtime_root.stat()
        if root_metadata.st_uid != os.getuid() or stat.S_IMODE(root_metadata.st_mode) & 0o077:
            raise SameUserBrokerViolation("same_user_connector_root_not_private")
        self.python_executable = python_executable.resolve(strict=True)
        self.connector_source = connector_source.resolve(strict=True)
        self.sandbox_exec = sandbox_exec.resolve(strict=True)
        for path, code in (
            (self.python_executable, "same_user_connector_python_invalid"),
            (self.connector_source, "same_user_connector_source_invalid"),
            (self.sandbox_exec, "same_user_connector_sandbox_invalid"),
        ):
            metadata = path.stat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise SameUserBrokerViolation(code)
        self.timeout_seconds = timeout_seconds
        self.join_current_process_group = join_current_process_group

    def deliver(
        self,
        *,
        vault: SyntheticLockedVaultAdapter,
        item_label_sha256: str,
    ) -> ConnectorResult:
        read_descriptor, write_descriptor = os.pipe()
        os.set_inheritable(read_descriptor, True)
        os.set_inheritable(write_descriptor, False)
        process: subprocess.Popen[bytes] | None = None
        stdout = b""
        stderr = b""
        try:
            with tempfile.TemporaryDirectory(
                prefix="atlas-option1-connector-", dir=self.runtime_root
            ) as temporary:
                working_root = Path(temporary)
                os.chmod(working_root, 0o700)
                process = subprocess.Popen(
                    [
                        str(self.sandbox_exec),
                        "-p",
                        _DARWIN_SANDBOX_PROFILE,
                        str(self.python_executable),
                        "-I",
                        "-B",
                        str(self.connector_source),
                        "--material-fd",
                        str(read_descriptor),
                        "--parent-pid",
                        str(os.getpid()),
                    ],
                    cwd=working_root,
                    env={},
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    close_fds=True,
                    pass_fds=(read_descriptor,),
                    start_new_session=not self.join_current_process_group,
                )
                os.close(read_descriptor)
                read_descriptor = -1
                try:
                    vault.consume_to_descriptor(item_label_sha256, write_descriptor)
                finally:
                    os.close(write_descriptor)
                    write_descriptor = -1
                try:
                    stdout, stderr = process.communicate(timeout=self.timeout_seconds)
                except subprocess.TimeoutExpired as exc:
                    _terminate_process(
                        process,
                        owns_process_group=not self.join_current_process_group,
                    )
                    raise SameUserBrokerViolation("same_user_connector_timeout") from exc
                if len(stdout) + len(stderr) > _MAX_CONNECTOR_OUTPUT_BYTES:
                    raise SameUserBrokerViolation("same_user_connector_output_too_large")
                output_material_absent = not vault.contains_known_material(stdout + stderr)
                if process.returncode != 0 or stderr or not output_material_absent:
                    connector_code = stderr.decode("utf-8", errors="strict")
                    if (
                        connector_code.startswith("connector_")
                        and len(connector_code) <= 96
                    ):
                        raise SameUserBrokerViolation(connector_code)
                    raise SameUserBrokerViolation("same_user_connector_failed")
                try:
                    report = json.loads(stdout.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise SameUserBrokerViolation("same_user_connector_report_invalid") from exc
                if not isinstance(report, dict) or _canonical_json(report) != stdout:
                    raise SameUserBrokerViolation("same_user_connector_report_noncanonical")
                expected_keys = {
                    "version",
                    "delivered",
                    "synthetic_only",
                    "environment_empty",
                    "network_socket_blocked",
                    "filesystem_write_blocked",
                    "process_fork_blocked",
                    "working_buffer_zeroized",
                    "material_persisted",
                    "material_returned",
                    "model_contacted",
                    "provider_contacted",
                    "parent_verified",
                    "inherited_descriptor_count",
                    "remaining_descriptor_count",
                }
                if set(report) != expected_keys or any(
                    report[key] is not expected
                    for key, expected in {
                        "version": 1,
                        "delivered": True,
                        "synthetic_only": True,
                        "environment_empty": True,
                        "network_socket_blocked": True,
                        "filesystem_write_blocked": True,
                        "process_fork_blocked": True,
                        "working_buffer_zeroized": True,
                        "material_persisted": False,
                        "material_returned": False,
                        "model_contacted": False,
                        "provider_contacted": False,
                        "parent_verified": True,
                    }.items()
                ):
                    raise SameUserBrokerViolation("same_user_connector_report_mismatch")
                if (
                    type(report["inherited_descriptor_count"]) is not int
                    or type(report["remaining_descriptor_count"]) is not int
                    or report["inherited_descriptor_count"] < 1
                    or report["inherited_descriptor_count"] > 4
                    or report["remaining_descriptor_count"] < 0
                    or report["remaining_descriptor_count"] > 3
                ):
                    raise SameUserBrokerViolation("same_user_connector_report_mismatch")
                if self.join_current_process_group:
                    process_group_reaped = process.poll() is not None
                else:
                    try:
                        os.killpg(process.pid, 0)
                    except ProcessLookupError:
                        process_group_reaped = True
                    else:
                        process_group_reaped = False
                if not process_group_reaped or any(working_root.iterdir()):
                    raise SameUserBrokerViolation("same_user_connector_teardown_failed")
                return ConnectorResult(
                    environment_empty=True,
                    network_socket_blocked=True,
                    filesystem_write_blocked=True,
                    process_fork_blocked=True,
                    working_buffer_zeroized=True,
                    material_persisted=False,
                    material_returned=False,
                    model_contacted=False,
                    provider_contacted=False,
                    parent_verified=True,
                    inherited_descriptor_count=int(report["inherited_descriptor_count"]),
                    remaining_descriptor_count=int(report["remaining_descriptor_count"]),
                    process_group_reaped=process_group_reaped,
                    output_material_absent=True,
                )
        finally:
            if process is not None:
                _terminate_process(
                    process,
                    owns_process_group=not self.join_current_process_group,
                )
            for descriptor in (read_descriptor, write_descriptor):
                if descriptor >= 0:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass


@dataclass(frozen=True, slots=True)
class SameUserDeliveryReceipt:
    version: int
    lease_metadata_sha256: str
    request_sha256: str
    mapping_sha256: str
    destination_sha256: str
    delivery_channel_sha256: str
    delivery_claim_sha256: str
    connector_profile_sha256: str
    delivered_at: str
    synthetic_only: bool
    material_present: bool
    material_persisted: bool
    material_returned: bool
    connector_working_buffer_zeroized: bool
    environment_scrubbed: bool
    network_accessed: bool
    filesystem_write_allowed: bool
    process_fork_allowed: bool
    process_teardown_verified: bool
    same_user_residual_risk: bool
    production_ready: bool
    live_authority_granted: bool
    model_contacted: bool
    broker_key_id: str
    algorithm: str
    signature: str

    def __post_init__(self) -> None:
        if (
            self.version != 1
            or self.synthetic_only is not True
            or self.material_present is not False
            or self.material_persisted is not False
            or self.material_returned is not False
            or self.connector_working_buffer_zeroized is not True
            or self.environment_scrubbed is not True
            or self.network_accessed is not False
            or self.filesystem_write_allowed is not False
            or self.process_fork_allowed is not False
            or self.process_teardown_verified is not True
            or self.same_user_residual_risk is not True
            or self.production_ready is not False
            or self.live_authority_granted is not False
            or self.model_contacted is not False
            or self.algorithm != "ed25519"
        ):
            raise SameUserBrokerViolation("same_user_delivery_receipt_profile_invalid")
        for value in (
            self.lease_metadata_sha256,
            self.request_sha256,
            self.mapping_sha256,
            self.destination_sha256,
            self.delivery_channel_sha256,
            self.delivery_claim_sha256,
            self.connector_profile_sha256,
        ):
            _require_digest(value, code="same_user_delivery_receipt_digest_invalid")
        _parse_time(self.delivered_at, code="same_user_delivery_receipt_time_invalid")
        _require_label(self.broker_key_id, code="same_user_delivery_broker_key_invalid")
        if not _SIGNATURE_PATTERN.fullmatch(self.signature):
            raise SameUserBrokerViolation("same_user_delivery_signature_invalid")

    @property
    def sha256(self) -> str:
        return document_sha256(self)


class GuardedSameUserBroker:
    """Production-shaped but non-authorizing broker under the owner's UID."""

    def __init__(
        self,
        *,
        registry: OwnerTaskRegistry,
        state: DurableSameUserTrustState,
        vault: SyntheticLockedVaultAdapter,
        connector: SyntheticConnector,
        capability: SignedCapabilityEnvelope,
        capability_verifier: OfflineVerifier,
        capability_receipt_verifier: OfflineVerifier,
        broker_signer: OfflineSigner,
        broker_verifier: OfflineVerifier,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if state.registry_sha256 != registry.sha256:
            raise SameUserBrokerViolation("same_user_state_registry_mismatch")
        for verifier, code in (
            (capability_verifier, "same_user_capability_verifier_invalid"),
            (capability_receipt_verifier, "same_user_receipt_verifier_invalid"),
            (broker_verifier, "same_user_broker_verifier_invalid"),
        ):
            if getattr(verifier, "algorithm", None) != "ed25519" or not getattr(verifier, "key_id", ""):
                raise SameUserBrokerViolation(code)
        if (
            getattr(broker_signer, "algorithm", None) != "ed25519"
            or broker_signer.key_id != broker_verifier.key_id
        ):
            raise SameUserBrokerViolation("same_user_broker_signer_invalid")
        if capability.key_id != capability_verifier.key_id:
            raise SameUserBrokerViolation("same_user_capability_key_mismatch")
        try:
            capability_verifier.verify(
                domain=CAPABILITY_DOMAIN,
                payload=unsigned_document(capability),
                signature=capability.signature,
            )
        except Exception as exc:
            raise SameUserBrokerViolation("same_user_capability_signature_invalid") from exc
        if connector.profile_id not in {
            binding.connector_profile for binding in registry._tasks.values()
        }:
            raise SameUserBrokerViolation("same_user_connector_profile_unregistered")
        if clock is not None and not callable(clock):
            raise SameUserBrokerViolation("same_user_clock_invalid")
        self.registry = registry
        self.state = state
        self.vault = vault
        self.connector = connector
        self.capability = capability
        self._capability_verifier = capability_verifier
        self._receipt_verifier = capability_receipt_verifier
        self._signer = broker_signer
        self._verifier = broker_verifier
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(registry_tasks={self.registry.task_count}, "
            "credential_material='<redacted>', production_ready=False)"
        )

    @property
    def broker_key_id(self) -> str:
        return self._verifier.key_id

    def _now(self) -> datetime:
        try:
            value = self._clock()
        except Exception as exc:
            raise SameUserBrokerViolation("same_user_clock_unavailable") from exc
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise SameUserBrokerViolation("same_user_clock_invalid")
        return value.astimezone(timezone.utc)

    def _sign(self, *, domain: str, payload: Mapping[str, object]) -> str:
        try:
            signature = self._signer.sign(domain=domain, payload=payload)
            self._verifier.verify(domain=domain, payload=payload, signature=signature)
        except Exception as exc:
            raise SameUserBrokerViolation("same_user_broker_signing_failed") from exc
        if not _SIGNATURE_PATTERN.fullmatch(signature):
            raise SameUserBrokerViolation("same_user_broker_signature_invalid")
        return signature

    def _verify_capability_receipt(self, receipt: CapabilityVerificationReceipt) -> None:
        if receipt.verifier_key_id != self._receipt_verifier.key_id:
            raise SameUserBrokerViolation("same_user_capability_receipt_key_mismatch")
        try:
            self._receipt_verifier.verify(
                domain=CAPABILITY_VERIFICATION_DOMAIN,
                payload=unsigned_document(receipt),
                signature=receipt.signature,
            )
        except Exception as exc:
            raise SameUserBrokerViolation("same_user_capability_receipt_invalid") from exc

    def _validate_request(
        self,
        request: CredentialLeaseRequest,
        verification: CapabilityVerificationReceipt,
    ) -> SameUserTaskBinding:
        if not isinstance(request, CredentialLeaseRequest) or not isinstance(
            verification, CapabilityVerificationReceipt
        ):
            raise SameUserBrokerViolation("same_user_request_type_invalid")
        self._verify_capability_receipt(verification)
        capability_sha256 = document_sha256(self.capability)
        expected = {
            "verification": (request.capability_verification_sha256, verification.sha256),
            "capability": (request.capability_envelope_sha256, capability_sha256),
            "verification_capability": (
                verification.capability_envelope_sha256,
                capability_sha256,
            ),
            "verification_payload": (
                verification.capability_sha256,
                self.capability.capability_sha256,
            ),
            "policy": (
                request.policy_bundle_sha256,
                verification.policy_bundle_sha256,
            ),
            "egress": (
                request.egress_manifest_sha256,
                verification.egress_manifest_sha256,
            ),
            "task": (request.task_sha256, self.capability.bindings.task_sha256),
            "job": (request.job_sha256, self.capability.bindings.job_sha256),
            "provider": (request.provider, self.capability.bindings.provider),
            "model": (request.model, self.capability.bindings.model),
            "audience": (request.audience, self.capability.bindings.audience),
            "scope": (
                request.credential_scope_sha256,
                self.capability.bindings.credential_scope_sha256,
            ),
            "channel": (
                request.delivery_channel_sha256,
                self.capability.bindings.credential_delivery_channel_sha256,
            ),
        }
        mismatch = next((name for name, pair in expected.items() if pair[0] != pair[1]), None)
        if mismatch is not None:
            raise SameUserBrokerViolation(f"same_user_request_{mismatch}_mismatch")
        now = self._now()
        starts = (
            _parse_time(request.requested_at, code="same_user_request_time_invalid"),
            _parse_time(verification.verified_at, code="same_user_verification_time_invalid"),
            _parse_time(self.capability.bindings.issued_at, code="same_user_capability_time_invalid"),
        )
        expiries = (
            _parse_time(request.expires_at, code="same_user_request_expiry_invalid"),
            _parse_time(verification.expires_at, code="same_user_verification_expiry_invalid"),
            _parse_time(self.capability.bindings.expires_at, code="same_user_capability_expiry_invalid"),
        )
        if any(now < start for start in starts) or any(now >= expiry for expiry in expiries):
            raise SameUserBrokerViolation("same_user_authority_window_invalid")
        return self.registry._resolve(request, self.capability)

    def issue_lease(
        self,
        request: CredentialLeaseRequest,
        verification: CapabilityVerificationReceipt,
    ) -> CredentialLeaseMetadata:
        binding = self._validate_request(request, verification)
        now = self._now()
        hard_expiry = min(
            _parse_time(request.expires_at, code="same_user_request_expiry_invalid"),
            _parse_time(verification.expires_at, code="same_user_verification_expiry_invalid"),
            _parse_time(self.capability.bindings.expires_at, code="same_user_capability_expiry_invalid"),
            now + timedelta(seconds=min(request.max_ttl_seconds, 300)),
        )
        if hard_expiry <= now:
            raise SameUserBrokerViolation("same_user_authority_expired")
        request_sha256 = request.sha256
        capability_sha256 = document_sha256(self.capability)
        try:
            self.state.begin_issue(
                request_sha256=request_sha256,
                capability_sha256=capability_sha256,
                mapping_sha256=binding.sha256,
                channel_sha256=request.delivery_channel_sha256,
                expires_at=_iso(hard_expiry),
            )
        except SameUserStateViolation as exc:
            raise SameUserBrokerViolation(exc.code) from exc

        lease_id_sha256 = _sha256(
            b"atlas-option1-lease-v1\x00"
            + bytes.fromhex(request_sha256)
            + secrets.token_bytes(32)
        )
        unsigned: dict[str, object] = {
            "version": 1,
            "lease_id_sha256": lease_id_sha256,
            "request_sha256": request_sha256,
            "capability_envelope_sha256": request.capability_envelope_sha256,
            "egress_manifest_sha256": request.egress_manifest_sha256,
            "task_sha256": request.task_sha256,
            "job_sha256": request.job_sha256,
            "provider": request.provider,
            "model": request.model,
            "audience": request.audience,
            "credential_scope_sha256": request.credential_scope_sha256,
            "delivery_channel_sha256": request.delivery_channel_sha256,
            "revocation_handle_sha256": _sha256(
                b"atlas-option1-revocation-v1\x00"
                + bytes.fromhex(lease_id_sha256)
                + secrets.token_bytes(32)
            ),
            "issued_at": _iso(now),
            "expires_at": _iso(hard_expiry),
            "max_uses": 1,
            "one_use": True,
            "broker_key_id": self.broker_key_id,
            "algorithm": "ed25519",
            "credential_material_persisted": False,
            "exposed_to_prompt": False,
            "included_in_receipt": False,
            "included_in_backup": False,
        }
        signature = self._sign(domain=CREDENTIAL_LEASE_DOMAIN, payload=unsigned)
        lease = CredentialLeaseMetadata(signature=signature, **unsigned)  # type: ignore[arg-type]
        try:
            self.state.finish_issue(
                request_sha256=request_sha256,
                lease_sha256=lease.sha256,
            )
        except SameUserStateViolation as exc:
            raise SameUserBrokerViolation(exc.code) from exc
        return lease

    def verify_lease(
        self,
        request: CredentialLeaseRequest,
        lease: CredentialLeaseMetadata,
        verification: CapabilityVerificationReceipt,
    ) -> SameUserTaskBinding:
        binding = self._validate_request(request, verification)
        if lease.broker_key_id != self.broker_key_id:
            raise SameUserBrokerViolation("same_user_lease_key_mismatch")
        try:
            self._verifier.verify(
                domain=CREDENTIAL_LEASE_DOMAIN,
                payload=unsigned_document(lease),
                signature=lease.signature,
            )
        except Exception as exc:
            raise SameUserBrokerViolation("same_user_lease_signature_invalid") from exc
        expected = {
            "request": (lease.request_sha256, request.sha256),
            "capability": (lease.capability_envelope_sha256, request.capability_envelope_sha256),
            "egress": (lease.egress_manifest_sha256, request.egress_manifest_sha256),
            "task": (lease.task_sha256, request.task_sha256),
            "job": (lease.job_sha256, request.job_sha256),
            "provider": (lease.provider, request.provider),
            "model": (lease.model, request.model),
            "audience": (lease.audience, request.audience),
            "scope": (lease.credential_scope_sha256, request.credential_scope_sha256),
            "channel": (lease.delivery_channel_sha256, request.delivery_channel_sha256),
        }
        mismatch = next((name for name, pair in expected.items() if pair[0] != pair[1]), None)
        if mismatch is not None:
            raise SameUserBrokerViolation(f"same_user_lease_{mismatch}_mismatch")
        if self._now() >= _parse_time(lease.expires_at, code="same_user_lease_expiry_invalid"):
            raise SameUserBrokerViolation("same_user_lease_expired")
        try:
            state = self.state.assert_lease(
                request_sha256=request.sha256,
                lease_sha256=lease.sha256,
                mapping_sha256=binding.sha256,
                channel_sha256=request.delivery_channel_sha256,
            )
        except SameUserStateViolation as exc:
            raise SameUserBrokerViolation(exc.code) from exc
        if state["delivered"] is True:
            raise SameUserBrokerViolation("same_user_delivery_replayed")
        if state["delivery_claimed"] is True:
            raise SameUserBrokerViolation("same_user_delivery_replayed")
        if self.connector.profile_id != binding.connector_profile:
            raise SameUserBrokerViolation("same_user_connector_profile_mismatch")
        return binding

    def deliver_once(
        self,
        channel: SyntheticOneUseChannelHandle,
        *,
        request: CredentialLeaseRequest,
        lease: CredentialLeaseMetadata,
        verification: CapabilityVerificationReceipt,
    ) -> SameUserDeliveryReceipt:
        if not isinstance(channel, SyntheticOneUseChannelHandle):
            raise SameUserBrokerViolation("same_user_delivery_channel_required")
        binding = self.verify_lease(request, lease, verification)
        if channel.sha256 != lease.delivery_channel_sha256:
            raise SameUserBrokerViolation("same_user_delivery_channel_mismatch")
        claim_sha256 = _sha256(
            b"atlas-option1-delivery-claim-v1\x00"
            + bytes.fromhex(request.sha256)
            + bytes.fromhex(lease.sha256)
            + secrets.token_bytes(32)
        )
        try:
            self.state.claim_lease_delivery(
                request_sha256=request.sha256,
                lease_sha256=lease.sha256,
                mapping_sha256=binding.sha256,
                channel_sha256=channel.sha256,
                claim_sha256=claim_sha256,
            )
        except SameUserStateViolation as exc:
            raise SameUserBrokerViolation(exc.code) from exc
        receipt_snapshot = self.state.receipt_snapshot()
        try:
            result = self.connector.deliver(
                vault=self.vault,
                item_label_sha256=binding.vault_item_label_sha256,
            )
        except Exception:
            try:
                self.state.set_pause("paused")
            except SameUserStateViolation:
                pass
            raise
        if not all(
            (
                result.environment_empty,
                result.network_socket_blocked,
                result.filesystem_write_blocked,
                result.process_fork_blocked,
                result.working_buffer_zeroized,
                result.material_persisted is False,
                result.material_returned is False,
                result.model_contacted is False,
                result.provider_contacted is False,
                result.parent_verified,
                result.process_group_reaped,
                result.output_material_absent,
            )
        ):
            raise SameUserBrokerViolation("same_user_connector_evidence_invalid")
        unsigned: dict[str, object] = {
            "version": 1,
            "lease_metadata_sha256": lease.sha256,
            "request_sha256": request.sha256,
            "mapping_sha256": binding.sha256,
            "destination_sha256": binding.destination_sha256,
            "delivery_channel_sha256": channel.sha256,
            "delivery_claim_sha256": claim_sha256,
            "connector_profile_sha256": _sha256(binding.connector_profile.encode("utf-8")),
            "delivered_at": _iso(self._now()),
            "synthetic_only": True,
            "material_present": False,
            "material_persisted": False,
            "material_returned": False,
            "connector_working_buffer_zeroized": True,
            "environment_scrubbed": True,
            "network_accessed": False,
            "filesystem_write_allowed": False,
            "process_fork_allowed": False,
            "process_teardown_verified": True,
            "same_user_residual_risk": True,
            "production_ready": False,
            "live_authority_granted": False,
            "model_contacted": False,
            "broker_key_id": self.broker_key_id,
            "algorithm": "ed25519",
        }
        try:
            signature = self._sign(domain=_DELIVERY_DOMAIN, payload=unsigned)
            receipt = SameUserDeliveryReceipt(signature=signature, **unsigned)  # type: ignore[arg-type]
        except Exception:
            try:
                self.state.set_pause("paused")
            except SameUserStateViolation:
                pass
            raise
        try:
            self.state.consume_lease(
                request_sha256=request.sha256,
                lease_sha256=lease.sha256,
                mapping_sha256=binding.sha256,
                channel_sha256=channel.sha256,
                receipt_sha256=receipt.sha256,
                claim_sha256=claim_sha256,
                expected_receipt_head=str(receipt_snapshot["head_sha256"]),
            )
        except SameUserStateViolation as exc:
            raise SameUserBrokerViolation(exc.code) from exc
        return receipt

    def verify_delivery_receipt(self, receipt: SameUserDeliveryReceipt) -> None:
        if not isinstance(receipt, SameUserDeliveryReceipt) or receipt.broker_key_id != self.broker_key_id:
            raise SameUserBrokerViolation("same_user_delivery_receipt_invalid")
        try:
            self._verifier.verify(
                domain=_DELIVERY_DOMAIN,
                payload=unsigned_document(receipt),
                signature=receipt.signature,
            )
        except Exception as exc:
            raise SameUserBrokerViolation("same_user_delivery_receipt_signature_invalid") from exc

    def revoke_lease(
        self,
        lease: CredentialLeaseMetadata,
        *,
        reason_sha256: str,
    ) -> CredentialRevocationReceipt:
        _require_digest(reason_sha256, code="same_user_revocation_reason_invalid")
        if lease.broker_key_id != self.broker_key_id:
            raise SameUserBrokerViolation("same_user_lease_key_mismatch")
        try:
            self._verifier.verify(
                domain=CREDENTIAL_LEASE_DOMAIN,
                payload=unsigned_document(lease),
                signature=lease.signature,
            )
        except Exception as exc:
            raise SameUserBrokerViolation("same_user_lease_signature_invalid") from exc
        unsigned: dict[str, object] = {
            "version": 1,
            "lease_metadata_sha256": lease.sha256,
            "lease_id_sha256": lease.lease_id_sha256,
            "reason_sha256": reason_sha256,
            "revoked_at": _iso(self._now()),
            "delivery_closed": True,
            "credential_material_persisted": False,
            "broker_key_id": self.broker_key_id,
            "algorithm": "ed25519",
        }
        signature = self._sign(domain=_REVOCATION_DOMAIN, payload=unsigned)
        receipt = CredentialRevocationReceipt(signature=signature, **unsigned)  # type: ignore[arg-type]
        try:
            self.state.revoke_lease(
                request_sha256=lease.request_sha256,
                lease_sha256=lease.sha256,
                revocation_receipt_sha256=document_sha256(receipt),
            )
        except SameUserStateViolation as exc:
            raise SameUserBrokerViolation(exc.code) from exc
        return receipt


__all__ = [
    "ConnectorResult",
    "DarwinSandboxedSyntheticConnector",
    "GuardedSameUserBroker",
    "OwnerTaskRegistry",
    "SameUserBrokerViolation",
    "SameUserDeliveryReceipt",
    "SameUserTaskBinding",
    "SyntheticConnector",
    "SyntheticLockedVaultAdapter",
]
