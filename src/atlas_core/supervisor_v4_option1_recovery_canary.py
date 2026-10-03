from __future__ import annotations

"""Distinct, one-shot recovery lineage for the Atlas Option 1 canary.

The original Option 1 launch receipt is immutable terminal evidence.  This
module accepts only that exact failed-preclaim receipt as its predecessor and
uses new authorization, launch, and data-plane receipt namespaces.  Merely
importing or inspecting this module cannot query Keychain or start delivery.
"""

import hashlib
import importlib.metadata
import json
import os
import re
import secrets
import stat
import sys
import tempfile
import uuid
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from atlas_core.config import AtlasConfig
from atlas_core.supervisor_v4_live_contract import (
    CredentialLeaseRequest,
    DataEgressManifest,
    document_sha256,
)
from atlas_core.supervisor_v4_offline_credential_broker import (
    SyntheticOneUseChannelHandle,
)
from atlas_core.supervisor_v4_offline_crypto import (
    Ed25519OfflineSigner,
    Ed25519OfflineVerifier,
    unsigned_document,
)
from atlas_core.supervisor_v4_offline_policy_broker import (
    OfflineCapabilityVerificationBroker,
    OfflineOwnerPolicyBroker,
)
from atlas_core.supervisor_v4_option1_canary import (
    CANARY_LAUNCH_RECEIPT_NAME,
    CANARY_RECEIPT_NAME,
    Option1CanaryViolation,
    load_canary_launch_receipt,
)
from atlas_core.supervisor_v4_option1_keychain import (
    MacOSKeychainSyntheticVaultAdapter,
    SYNTHETIC_PREFIX,
    VAULT_ITEM_LABEL_SHA256,
)
from atlas_core.supervisor_v4_protocol import (
    CapabilityBindings,
    ImmutablePolicyBundle,
    ZERO_DIGEST,
)
from atlas_core.supervisor_v4_same_user_broker import (
    DarwinSandboxedSyntheticConnector,
    GuardedSameUserBroker,
    OwnerTaskRegistry,
    SameUserDeliveryReceipt,
    SameUserTaskBinding,
)
from atlas_core.supervisor_v4_same_user_state import DurableSameUserTrustState


RECOVERY_CANARY_GATE_ID = (
    "owner_authorize_option1_synthetic_integration_recovery_canary"
)
RECOVERY_CANARY_CONFIRMATION = (
    "AUTHORIZE OPTION1 ONE-SHOT SYNTHETIC INTEGRATION RECOVERY CANARY"
)
RECOVERY_CANARY_LAUNCH_RECEIPT_NAME = (
    "synthetic-integration-recovery-canary-launch-receipt.json"
)
RECOVERY_CANARY_LAUNCH_RECEIPT_NEXT_NAME = (
    f".{RECOVERY_CANARY_LAUNCH_RECEIPT_NAME}.next"
)
RECOVERY_CANARY_RECEIPT_NAME = (
    "synthetic-integration-recovery-canary-receipt.json"
)
RECOVERY_CANARY_RECEIPT_NEXT_NAME = f".{RECOVERY_CANARY_RECEIPT_NAME}.next"
RECOVERY_CANARY_LAUNCH_CLASSIFICATION = (
    "option1_atlas_facing_synthetic_integration_recovery_canary_launch"
)
RECOVERY_CANARY_CLASSIFICATION = (
    "option1_atlas_facing_synthetic_integration_recovery_canary"
)
RECOVERY_CANARY_LAUNCH_LIMIT = 1
RECOVERY_CANARY_ATTEMPT_LIMIT = 1

EXPECTED_PREDECESSOR_LAUNCH_ID = "81684743-b8f6-4865-b243-44db0caecfdb"
EXPECTED_PREDECESSOR_EVIDENCE_SHA256 = (
    "143df457de75cf9c1aecb05a01e668467ffe7d34d3b3edf8a85be83dd225b181"
)
EXPECTED_PREDECESSOR_STATUS = "failed_preclaim"
EXPECTED_PREDECESSOR_ACCOUNTING_ORIGIN = "postflight_reconciliation"
EXPECTED_PREDECESSOR_PARENT_ERROR_CODE = "option1_canary_child_output_unsafe"

_EXPECTED_PREDECESSOR = {
    "version": 1,
    "classification": "option1_atlas_facing_synthetic_integration_canary_launch",
    "launch_id": EXPECTED_PREDECESSOR_LAUNCH_ID,
    "authorization_gate_id": (
        "owner_authorize_option1_on_demand_synthetic_integration_canary"
    ),
    "authorization_binding_sha256": (
        "d6ac282a97a7e391664848a2da69cb9e1ea5eb75bcda72bb2b9cf7019cba7e1d"
    ),
    "authorization_confirmation_sha256": (
        "41abf0c9b7d62c1cc5a7947ece52158a2cb938007f2d5ed34f142db3024b0d43"
    ),
    "launch_index": 1,
    "launch_limit": 1,
    "launch_consumed": True,
    "accounting_origin": EXPECTED_PREDECESSOR_ACCOUNTING_ORIGIN,
    "recorded_at": "2026-08-30T00:49:08.223457+00:00",
    "completed_at": "2026-08-30T00:49:08.223457+00:00",
    "status": EXPECTED_PREDECESSOR_STATUS,
    "parent_error_code": EXPECTED_PREDECESSOR_PARENT_ERROR_CODE,
    "child_process_started": True,
    "child_process_completed": True,
    "data_plane_receipt_present": False,
    "data_plane_receipt_status": None,
    "data_plane_receipt_evidence_sha256": None,
    "keychain_query_performed": False,
    "synthetic_delivery_started": False,
    "synthetic_material_read_by_native_helper": False,
    "failed_preclaim_no_keychain_query_or_delivery_verified": True,
    "evidence_sha256": EXPECTED_PREDECESSOR_EVIDENCE_SHA256,
}

_MAX_RECEIPT_BYTES = 64 * 1024
_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_FAILURE_PATTERN = re.compile(
    r"^(?:option1_recovery_canary|same_user|connector|state)_[a-z0-9_]{1,87}$"
)
_PARENT_ERROR_PATTERN = re.compile(
    r"^option1_recovery_canary_[a-z0-9_]{1,70}$"
)
_DELIVERY_DOMAIN = "atlas.supervisor-v4.same-user-delivery.v1"
_FIXTURE_POLICY_SHA256 = (
    "49317dd85f379743f578e489b3ae84224238a82ba35f731b17bdb35bdced1813"
)
_FIXTURE_EGRESS_SHA256 = (
    "ea817c5e070204a2f72d8edbd6f72500510711d18b1bdd5165d10aa89dcec6a5"
)

_CONNECTOR_FIELDS = (
    "connector_environment_scrubbed",
    "connector_network_blocked",
    "connector_filesystem_write_blocked",
    "connector_process_fork_blocked",
    "connector_working_buffer_zeroized",
    "connector_process_group_reaped",
    "connector_output_material_absent",
)
_STATE_FIELDS = {
    "version",
    "event_count",
    "state_generation",
    "pause_state",
    "pause_generation",
    "lease_count",
    "delivery_claimed_count",
    "delivered_count",
    "revoked_count",
    "receipt_count",
    "quarantined",
    "credential_material_present",
}
_BINDING_HASH_FIELDS = (
    "helper_sha256",
    "provisioning_receipt_evidence_sha256",
    "runtime_path_sha256",
    "vault_item_label_sha256",
    "sdk_lock_sha256",
    "policy_sha256",
    "connector_source_sha256",
    "recovery_canary_module_sha256",
    "recovery_canary_runner_sha256",
    "recovery_python_executable_sha256",
    "recovery_dependency_manifest_sha256",
    "registry_sha256",
)

_RECOVERY_DEPENDENCY_DISTRIBUTIONS = (
    "PyYAML",
    "annotated-types",
    "cffi",
    "cryptography",
    "jaraco.classes",
    "jaraco.context",
    "jaraco.functools",
    "keyring",
    "more-itertools",
    "pydantic",
    "pydantic-core",
    "typing-extensions",
    "typing-inspection",
)
_RECOVERY_DEPENDENCY_CODE_SUFFIXES = {
    ".dylib",
    ".py",
    ".pyi",
    ".so",
    ".typed",
}
_RECOVERY_DEPENDENCY_METADATA_FILES = {
    "METADATA",
    "WHEEL",
    "entry_points.txt",
    "top_level.txt",
}
_DATA_RECEIPT_FIELDS = {
    "version",
    "classification",
    "canary_id",
    "launch_id",
    "launch_claim_binding_sha256",
    "predecessor_launch_id",
    "predecessor_launch_evidence_sha256",
    "authorization_gate_id",
    "authorization_binding_sha256",
    "attempt_index",
    "attempt_limit",
    "attempt_consumed",
    "started_at",
    "completed_at",
    "status",
    "failure_code",
    "delivery_started",
    "selected_vault",
    "selected_runtime_mode",
    *_BINDING_HASH_FIELDS,
    "keychain_query_performed",
    "synthetic_material_read_by_native_helper",
    "synthetic_material_read_state",
    "synthetic_material_present_in_atlas_parent",
    "keychain_secret_read_by_atlas_python",
    "keychain_secret_returned",
    "material_persisted",
    "material_returned",
    "network_accessed",
    "real_credential_used",
    "private_data_present",
    "model_contacted",
    "provider_contacted",
    "external_communication_performed",
    "background_service_enrolled",
    "ordinary_startup_wired",
    "live_authority_granted",
    "ready",
    "ready_offline",
    "ready_live",
    "broker_process_parent_verified",
    "broker_process_network_guard_verified",
    "broker_process_os_network_sandboxed",
    "broker_descendants_joined_supervised_group",
    "keychain_helper_os_network_sandboxed",
    "connector_os_network_sandboxed",
    "broker_repaused",
    "broker_state_snapshot",
    "broker_delivery_receipt",
    "broker_delivery_receipt_sha256",
    "broker_public_key_b64",
    *_CONNECTOR_FIELDS,
    "evidence_sha256",
}
_LAUNCH_RECEIPT_FIELDS = {
    "version",
    "classification",
    "launch_id",
    "launch_claim_binding_sha256",
    "predecessor_launch_id",
    "predecessor_launch_evidence_sha256",
    "predecessor_status",
    "authorization_gate_id",
    "authorization_binding_sha256",
    "authorization_confirmation_sha256",
    "launch_index",
    "launch_limit",
    "launch_consumed",
    "accounting_origin",
    "recorded_at",
    "completed_at",
    "status",
    "parent_error_code",
    "child_process_started",
    "child_process_completed",
    "data_plane_receipt_present",
    "data_plane_receipt_status",
    "data_plane_receipt_evidence_sha256",
    "keychain_query_performed",
    "synthetic_delivery_started",
    "synthetic_material_read_by_native_helper",
    "failed_preclaim_no_keychain_query_or_delivery_verified",
    "evidence_sha256",
}
_CHILD_FAILURE_FIELDS = {
    "version",
    "classification",
    "status",
    "failure_code",
    "broker_process_parent_verified",
    "broker_process_network_guard_verified",
    "broker_process_supervised_reaping_required",
    "connector_process_group_reaped",
    "synthetic_material_returned",
    "real_credential_used",
    "private_data_present",
    "network_accessed",
    "model_contacted",
    "provider_contacted",
    "background_service_enrolled",
    "ordinary_startup_wired",
    "live_authority_granted",
    "ready",
    "ready_offline",
    "ready_live",
    "evidence_sha256",
}
_ACCOUNTING_RUNTIME_NAMES = {
    "atlas-option1-keychain-helper",
    "provisioning-receipt.json",
    CANARY_LAUNCH_RECEIPT_NAME,
    RECOVERY_CANARY_LAUNCH_RECEIPT_NAME,
    RECOVERY_CANARY_RECEIPT_NAME,
}


class Option1RecoveryCanaryViolation(RuntimeError):
    """Privacy-safe failure from the recovery canary lifecycle."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_receipt_invalid"
        ) from exc


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_source_unavailable"
        ) from exc
    return digest.hexdigest()


def _recovery_runtime_dependency_snapshot() -> dict[str, object]:
    """Hash the exact executable and imported-code distributions used here."""

    environment = Path(sys.prefix).resolve(strict=True)
    executable = Path(sys.executable)
    try:
        executable_target = executable.resolve(strict=True)
    except OSError as exc:
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_python_runtime_invalid"
        ) from exc
    if not executable.is_absolute() or not executable_target.is_file():
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_python_runtime_invalid"
        )

    distributions: dict[str, object] = {}
    for requested_name in _RECOVERY_DEPENDENCY_DISTRIBUTIONS:
        try:
            distribution = importlib.metadata.distribution(requested_name)
        except importlib.metadata.PackageNotFoundError as exc:
            raise Option1RecoveryCanaryViolation(
                "option1_recovery_canary_dependency_unavailable"
            ) from exc
        canonical_name = str(distribution.metadata.get("Name") or requested_name)
        files = distribution.files
        if files is None:
            raise Option1RecoveryCanaryViolation(
                "option1_recovery_canary_dependency_manifest_invalid"
            )
        manifest_rows: list[str] = []
        for relative in sorted(files, key=lambda item: item.as_posix()):
            relative_text = relative.as_posix()
            if (
                "__pycache__" in relative.parts
                or (
                    relative.suffix not in _RECOVERY_DEPENDENCY_CODE_SUFFIXES
                    and relative.name not in _RECOVERY_DEPENDENCY_METADATA_FILES
                )
            ):
                continue
            candidate = Path(distribution.locate_file(relative))
            try:
                metadata = candidate.lstat()
                resolved = candidate.resolve(strict=True)
                resolved.relative_to(environment)
            except (OSError, ValueError) as exc:
                raise Option1RecoveryCanaryViolation(
                    "option1_recovery_canary_dependency_manifest_invalid"
                ) from exc
            if (
                candidate.is_symlink()
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid not in {0, os.getuid()}
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                raise Option1RecoveryCanaryViolation(
                    "option1_recovery_canary_dependency_manifest_invalid"
                )
            manifest_rows.append(f"{sha256_file(resolved)}  {relative_text}\n")
        if not manifest_rows:
            raise Option1RecoveryCanaryViolation(
                "option1_recovery_canary_dependency_manifest_invalid"
            )
        distributions[requested_name] = {
            "canonical_name": canonical_name,
            "version": distribution.version,
            "file_count": len(manifest_rows),
            "manifest_sha256": hashlib.sha256(
                "".join(manifest_rows).encode("utf-8")
            ).hexdigest(),
        }

    dependency_manifest_sha256 = hashlib.sha256(
        canonical_json(distributions)
    ).hexdigest()
    return {
        "python_version": (
            f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        ),
        "python_executable_sha256": sha256_file(executable_target),
        "dependency_manifest_sha256": dependency_manifest_sha256,
        "distributions": distributions,
    }


def attest_recovery_runtime_dependencies(
    lock: Mapping[str, object],
    *,
    expected_python_executable: Path,
) -> dict[str, str]:
    """Fail closed if the active recovery interpreter or dependencies drift."""

    candidate = Path(sys.executable)
    if (
        not expected_python_executable.is_absolute()
        or candidate != expected_python_executable
    ):
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_python_runtime_invalid"
        )
    expected = lock.get("option1_recovery_runtime_dependencies")
    observed = _recovery_runtime_dependency_snapshot()
    if not isinstance(expected, Mapping) or dict(expected) != observed:
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_dependency_attestation_failed"
        )
    return {
        "recovery_python_executable_sha256": str(
            observed["python_executable_sha256"]
        ),
        "recovery_dependency_manifest_sha256": str(
            observed["dependency_manifest_sha256"]
        ),
    }


def _load_recovery_sdk_lock(path: Path) -> dict[str, object]:
    """Load one owner-controlled, non-aliased SDK lock with duplicate rejection."""

    absolute = path.absolute()
    try:
        metadata = absolute.lstat()
        if (
            absolute.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or metadata.st_size <= 0
            or metadata.st_size > 1024 * 1024
        ):
            raise OSError("unsafe SDK lock")
        raw = absolute.read_bytes()

        def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, item in pairs:
                if key in result:
                    raise ValueError("duplicate SDK lock key")
                result[key] = item
            return result

        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_dependency_attestation_failed"
        ) from exc
    if not isinstance(value, dict):
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_dependency_attestation_failed"
        )
    return value


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _valid_time(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _time_at_or_after(value: object, earlier: object) -> bool:
    if not isinstance(value, str) or not isinstance(earlier, str):
        return False
    try:
        parsed = datetime.fromisoformat(value)
        parsed_earlier = datetime.fromisoformat(earlier)
    except ValueError:
        return False
    return (
        parsed.tzinfo is not None
        and parsed_earlier.tzinfo is not None
        and parsed >= parsed_earlier
    )


def _exact(value: object, expected: object) -> bool:
    if expected is None or type(expected) is bool:
        return value is expected
    return type(value) is type(expected) and value == expected


def _with_evidence(value: Mapping[str, object]) -> dict[str, object]:
    result = dict(value)
    result.pop("evidence_sha256", None)
    result["evidence_sha256"] = hashlib.sha256(canonical_json(result)).hexdigest()
    return result


def _evidence_valid(value: Mapping[str, object]) -> bool:
    evidence = value.get("evidence_sha256")
    if not isinstance(evidence, str) or not _HASH_PATTERN.fullmatch(evidence):
        return False
    unsigned = dict(value)
    unsigned.pop("evidence_sha256", None)
    return hashlib.sha256(canonical_json(unsigned)).hexdigest() == evidence


def _authorization_binding() -> str:
    material = "\n".join(
        (
            RECOVERY_CANARY_GATE_ID,
            EXPECTED_PREDECESSOR_LAUNCH_ID,
            EXPECTED_PREDECESSOR_EVIDENCE_SHA256,
        )
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _launch_claim_binding(value: Mapping[str, object]) -> str:
    fixed = {
        key: value[key]
        for key in (
            "version",
            "classification",
            "launch_id",
            "predecessor_launch_id",
            "predecessor_launch_evidence_sha256",
            "predecessor_status",
            "authorization_gate_id",
            "authorization_binding_sha256",
            "authorization_confirmation_sha256",
            "launch_index",
            "launch_limit",
            "launch_consumed",
            "accounting_origin",
            "recorded_at",
        )
    }
    return hashlib.sha256(canonical_json(fixed)).hexdigest()


def _write_all(descriptor: int, value: bytes) -> None:
    remaining = memoryview(value)
    while remaining:
        try:
            written = os.write(descriptor, remaining)
        except InterruptedError:
            continue
        if written <= 0:
            raise Option1RecoveryCanaryViolation(
                "option1_recovery_canary_receipt_write_failed"
            )
        remaining = remaining[written:]


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _private_runtime(path: Path) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_runtime_unavailable"
        ) from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_runtime_invalid"
        )
    return path.resolve(strict=True)


def _read_receipt(path: Path, *, launch: bool) -> dict[str, object]:
    code = (
        "option1_recovery_canary_launch_receipt_invalid"
        if launch
        else "option1_recovery_canary_receipt_invalid"
    )
    try:
        metadata = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size <= 0
            or metadata.st_size > _MAX_RECEIPT_BYTES
        ):
            raise Option1RecoveryCanaryViolation(code)
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except Option1RecoveryCanaryViolation:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Option1RecoveryCanaryViolation(code) from exc
    if (
        not isinstance(value, dict)
        or canonical_json(value) != raw
        or SYNTHETIC_PREFIX in raw
    ):
        raise Option1RecoveryCanaryViolation(code)
    return value


def validate_recovery_canary_predecessor(
    runtime_root: Path,
) -> dict[str, object]:
    """Require the exact immutable failed-preclaim predecessor receipt."""

    runtime_root = _private_runtime(runtime_root)
    original_launch = runtime_root / CANARY_LAUNCH_RECEIPT_NAME
    original_data = runtime_root / CANARY_RECEIPT_NAME
    if not os.path.lexists(original_launch) or os.path.lexists(original_data):
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_predecessor_invalid"
        )
    try:
        receipt = load_canary_launch_receipt(original_launch)
    except (Option1CanaryViolation, OSError) as exc:
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_predecessor_invalid"
        ) from exc
    if receipt != _EXPECTED_PREDECESSOR:
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_predecessor_invalid"
        )
    return receipt


def _validate_state_snapshot(value: object) -> None:
    if not isinstance(value, dict) or set(value) != _STATE_FIELDS:
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_state_snapshot_invalid"
        )
    expected = {
        "version": 1,
        "pause_state": "paused",
        "lease_count": 1,
        "delivery_claimed_count": 1,
        "delivered_count": 1,
        "revoked_count": 0,
        "receipt_count": 1,
        "quarantined": False,
        "credential_material_present": False,
    }
    if any(value.get(key) != item for key, item in expected.items()):
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_state_snapshot_invalid"
        )
    if any(
        type(value.get(key)) is not int or int(value[key]) < 1
        for key in ("event_count", "state_generation", "pause_generation")
    ):
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_state_snapshot_invalid"
        )


def _validate_signed_delivery(
    value: object, *, expected_sha256: object, public_key_b64: object
) -> None:
    if (
        not isinstance(value, dict)
        or not isinstance(expected_sha256, str)
        or not _HASH_PATTERN.fullmatch(expected_sha256)
        or not isinstance(public_key_b64, str)
    ):
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_delivery_receipt_invalid"
        )
    try:
        receipt = SameUserDeliveryReceipt(**value)
        verifier = Ed25519OfflineVerifier.from_public_key_b64(public_key_b64)
        if receipt.sha256 != expected_sha256 or receipt.broker_key_id != verifier.key_id:
            raise Option1RecoveryCanaryViolation(
                "option1_recovery_canary_delivery_receipt_invalid"
            )
        verifier.verify(
            domain=_DELIVERY_DOMAIN,
            payload=unsigned_document(receipt),
            signature=receipt.signature,
        )
    except Option1RecoveryCanaryViolation:
        raise
    except Exception as exc:
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_delivery_receipt_invalid"
        ) from exc


def validate_recovery_canary_receipt(value: Mapping[str, object]) -> None:
    """Validate the independent recovery data-plane receipt."""

    if set(value) != _DATA_RECEIPT_FIELDS or not _evidence_valid(value):
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_receipt_invalid"
        )
    fixed = {
        "version": 1,
        "classification": RECOVERY_CANARY_CLASSIFICATION,
        "predecessor_launch_id": EXPECTED_PREDECESSOR_LAUNCH_ID,
        "predecessor_launch_evidence_sha256": (
            EXPECTED_PREDECESSOR_EVIDENCE_SHA256
        ),
        "authorization_gate_id": RECOVERY_CANARY_GATE_ID,
        "authorization_binding_sha256": _authorization_binding(),
        "attempt_index": 1,
        "attempt_limit": RECOVERY_CANARY_ATTEMPT_LIMIT,
        "attempt_consumed": True,
        "selected_vault": "macos_login_keychain",
        "selected_runtime_mode": "on_demand_owner_private",
    }
    fixed_booleans = {
        "synthetic_material_present_in_atlas_parent": False,
        "keychain_secret_read_by_atlas_python": False,
        "keychain_secret_returned": False,
        "real_credential_used": False,
        "private_data_present": False,
        "model_contacted": False,
        "provider_contacted": False,
        "external_communication_performed": False,
        "background_service_enrolled": False,
        "ordinary_startup_wired": False,
        "live_authority_granted": False,
        "ready": False,
        "ready_offline": False,
        "ready_live": False,
        "broker_process_network_guard_verified": True,
        "broker_process_parent_verified": True,
        "broker_process_os_network_sandboxed": False,
        "broker_descendants_joined_supervised_group": True,
        "keychain_helper_os_network_sandboxed": True,
        "connector_os_network_sandboxed": True,
    }
    if any(not _exact(value.get(key), item) for key, item in fixed.items()) or any(
        value.get(key) is not item for key, item in fixed_booleans.items()
    ):
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_receipt_invalid"
        )
    for key in (*_BINDING_HASH_FIELDS, "launch_claim_binding_sha256"):
        if not isinstance(value.get(key), str) or not _HASH_PATTERN.fullmatch(
            str(value[key])
        ):
            raise Option1RecoveryCanaryViolation(
                "option1_recovery_canary_receipt_invalid"
            )
    try:
        canary_id = uuid.UUID(str(value["canary_id"]))
        launch_id = uuid.UUID(str(value["launch_id"]))
    except (ValueError, AttributeError):
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_receipt_invalid"
        ) from None
    if str(canary_id) != value["canary_id"] or str(launch_id) != value["launch_id"]:
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_receipt_invalid"
        )
    if not _valid_time(value.get("started_at")):
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_receipt_invalid"
        )

    status = value.get("status")
    if status == "attempt_claimed":
        if any(
            (
                value.get("completed_at") is not None,
                value.get("failure_code") is not None,
                value.get("delivery_started") is not None,
                value.get("keychain_query_performed") is not None,
                value.get("synthetic_material_read_by_native_helper") is not None,
                value.get("synthetic_material_read_state") != "unknown_after_claim",
                value.get("material_persisted") is not None,
                value.get("material_returned") is not None,
                value.get("network_accessed") is not False,
                value.get("broker_repaused") is not None,
                value.get("broker_state_snapshot") is not None,
                value.get("broker_delivery_receipt") is not None,
                value.get("broker_delivery_receipt_sha256") is not None,
                value.get("broker_public_key_b64") is not None,
                any(value.get(field) is not None for field in _CONNECTOR_FIELDS),
            )
        ):
            raise Option1RecoveryCanaryViolation(
                "option1_recovery_canary_receipt_invalid"
            )
        return

    if status == "passed":
        expected_pass = {
            "failure_code": None,
            "delivery_started": True,
            "keychain_query_performed": True,
            "synthetic_material_read_by_native_helper": True,
            "synthetic_material_read_state": "delivered_to_connector",
            "material_persisted": False,
            "material_returned": False,
            "network_accessed": False,
            "broker_repaused": True,
            **{field: True for field in _CONNECTOR_FIELDS},
        }
        if not _time_at_or_after(value.get("completed_at"), value.get("started_at")) or any(
            not _exact(value.get(key), item) for key, item in expected_pass.items()
        ):
            raise Option1RecoveryCanaryViolation(
                "option1_recovery_canary_receipt_invalid"
            )
        _validate_state_snapshot(value.get("broker_state_snapshot"))
        _validate_signed_delivery(
            value.get("broker_delivery_receipt"),
            expected_sha256=value.get("broker_delivery_receipt_sha256"),
            public_key_b64=value.get("broker_public_key_b64"),
        )
        return

    if status == "failed":
        failure = value.get("failure_code")
        if (
            not _time_at_or_after(value.get("completed_at"), value.get("started_at"))
            or not isinstance(failure, str)
            or not _FAILURE_PATTERN.fullmatch(failure)
            or type(value.get("delivery_started")) is not bool
            or type(value.get("keychain_query_performed")) is not bool
            or value.get("synthetic_material_read_by_native_helper") is not None
            or value.get("synthetic_material_read_state")
            != (
                "unknown_after_attempt"
                if value.get("delivery_started") is True
                else "not_started"
            )
            or any(
                value.get(field) is not None
                for field in (
                    "material_persisted",
                    "material_returned",
                    "network_accessed",
                    "broker_repaused",
                    "broker_state_snapshot",
                    "broker_delivery_receipt",
                    "broker_delivery_receipt_sha256",
                    "broker_public_key_b64",
                    *_CONNECTOR_FIELDS,
                )
            )
        ):
            raise Option1RecoveryCanaryViolation(
                "option1_recovery_canary_receipt_invalid"
            )
        return
    raise Option1RecoveryCanaryViolation(
        "option1_recovery_canary_receipt_invalid"
    )


def load_recovery_canary_receipt(path: Path) -> dict[str, object]:
    value = _read_receipt(path, launch=False)
    validate_recovery_canary_receipt(value)
    return value


def validate_recovery_canary_launch_receipt(value: Mapping[str, object]) -> None:
    """Validate recovery launch accounting without touching Keychain."""

    if set(value) != _LAUNCH_RECEIPT_FIELDS or not _evidence_valid(value):
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_launch_receipt_invalid"
        )
    fixed = {
        "version": 1,
        "classification": RECOVERY_CANARY_LAUNCH_CLASSIFICATION,
        "predecessor_launch_id": EXPECTED_PREDECESSOR_LAUNCH_ID,
        "predecessor_launch_evidence_sha256": (
            EXPECTED_PREDECESSOR_EVIDENCE_SHA256
        ),
        "predecessor_status": EXPECTED_PREDECESSOR_STATUS,
        "authorization_gate_id": RECOVERY_CANARY_GATE_ID,
        "authorization_binding_sha256": _authorization_binding(),
        "authorization_confirmation_sha256": hashlib.sha256(
            RECOVERY_CANARY_CONFIRMATION.encode("utf-8")
        ).hexdigest(),
        "launch_index": 1,
        "launch_limit": RECOVERY_CANARY_LAUNCH_LIMIT,
        "launch_consumed": True,
        "accounting_origin": "prelaunch_claim",
    }
    if any(not _exact(value.get(key), item) for key, item in fixed.items()):
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_launch_receipt_invalid"
        )
    try:
        launch_id = uuid.UUID(str(value["launch_id"]))
    except (ValueError, AttributeError):
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_launch_receipt_invalid"
        ) from None
    if (
        str(launch_id) != value["launch_id"]
        or not _valid_time(value.get("recorded_at"))
        or value.get("launch_claim_binding_sha256") != _launch_claim_binding(value)
    ):
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_launch_receipt_invalid"
        )

    status = value.get("status")
    if status == "launch_claimed":
        if any(
            value.get(field) is not None
            for field in (
                "completed_at",
                "parent_error_code",
                "child_process_started",
                "child_process_completed",
                "data_plane_receipt_present",
                "data_plane_receipt_status",
                "data_plane_receipt_evidence_sha256",
                "keychain_query_performed",
                "synthetic_delivery_started",
                "synthetic_material_read_by_native_helper",
                "failed_preclaim_no_keychain_query_or_delivery_verified",
            )
        ):
            raise Option1RecoveryCanaryViolation(
                "option1_recovery_canary_launch_receipt_invalid"
            )
        return

    if not _time_at_or_after(value.get("completed_at"), value.get("recorded_at")):
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_launch_receipt_invalid"
        )
    parent_error = value.get("parent_error_code")
    if parent_error is not None and (
        not isinstance(parent_error, str)
        or not _PARENT_ERROR_PATTERN.fullmatch(parent_error)
    ):
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_launch_receipt_invalid"
        )
    if status == "failed_preclaim":
        if (
            parent_error is None
            or type(value.get("child_process_started")) is not bool
            or type(value.get("child_process_completed")) is not bool
            or (
                value.get("child_process_completed") is True
                and value.get("child_process_started") is not True
            )
            or value.get("data_plane_receipt_present") is not False
            or value.get("data_plane_receipt_status") is not None
            or value.get("data_plane_receipt_evidence_sha256") is not None
            or value.get("keychain_query_performed") is not False
            or value.get("synthetic_delivery_started") is not False
            or value.get("synthetic_material_read_by_native_helper") is not False
            or value.get(
                "failed_preclaim_no_keychain_query_or_delivery_verified"
            )
            is not True
        ):
            raise Option1RecoveryCanaryViolation(
                "option1_recovery_canary_launch_receipt_invalid"
            )
        return
    if status in {"child_completed", "child_stopped_with_data_receipt"}:
        data_status = value.get("data_plane_receipt_status")
        child_completed = status == "child_completed"
        if (
            value.get("child_process_started") is not True
            or value.get("child_process_completed") is not child_completed
            or value.get("data_plane_receipt_present") is not True
            or data_status not in {"attempt_claimed", "failed", "passed"}
            or (
                (not child_completed or data_status != "passed")
                and parent_error is None
            )
            or not isinstance(value.get("data_plane_receipt_evidence_sha256"), str)
            or not _HASH_PATTERN.fullmatch(
                str(value["data_plane_receipt_evidence_sha256"])
            )
            or value.get(
                "failed_preclaim_no_keychain_query_or_delivery_verified"
            )
            is not False
        ):
            raise Option1RecoveryCanaryViolation(
                "option1_recovery_canary_launch_receipt_invalid"
            )
        facts = (
            value.get("keychain_query_performed"),
            value.get("synthetic_delivery_started"),
            value.get("synthetic_material_read_by_native_helper"),
        )
        if data_status == "attempt_claimed" and facts != (None, None, None):
            raise Option1RecoveryCanaryViolation(
                "option1_recovery_canary_launch_receipt_invalid"
            )
        if data_status == "failed" and (
            type(facts[0]) is not bool
            or type(facts[1]) is not bool
            or facts[2] is not None
        ):
            raise Option1RecoveryCanaryViolation(
                "option1_recovery_canary_launch_receipt_invalid"
            )
        if data_status == "passed" and facts != (True, True, True):
            raise Option1RecoveryCanaryViolation(
                "option1_recovery_canary_launch_receipt_invalid"
            )
        return
    raise Option1RecoveryCanaryViolation(
        "option1_recovery_canary_launch_receipt_invalid"
    )


def load_recovery_canary_launch_receipt(path: Path) -> dict[str, object]:
    value = _read_receipt(path, launch=True)
    validate_recovery_canary_launch_receipt(value)
    return value


def inspect_recovery_canary_accounting(runtime_root: Path) -> dict[str, object]:
    """Reconcile the immutable predecessor with the recovery receipt pair."""

    runtime_root = _private_runtime(runtime_root)
    predecessor = validate_recovery_canary_predecessor(runtime_root)
    try:
        runtime_names = {entry.name for entry in runtime_root.iterdir()}
    except OSError as exc:
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_accounting_invalid"
        ) from exc
    if not runtime_names.issubset(_ACCOUNTING_RUNTIME_NAMES):
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_accounting_invalid"
        )
    launch_path = runtime_root / RECOVERY_CANARY_LAUNCH_RECEIPT_NAME
    data_path = runtime_root / RECOVERY_CANARY_RECEIPT_NAME
    launch = (
        load_recovery_canary_launch_receipt(launch_path)
        if os.path.lexists(launch_path)
        else None
    )
    data = (
        load_recovery_canary_receipt(data_path)
        if os.path.lexists(data_path)
        else None
    )
    if launch is None:
        if data is not None:
            raise Option1RecoveryCanaryViolation(
                "option1_recovery_canary_accounting_invalid"
            )
        return {
            "recovery_canary_predecessor_verified": True,
            "recovery_canary_predecessor_launch_id": predecessor["launch_id"],
            "recovery_canary_predecessor_evidence_sha256": predecessor[
                "evidence_sha256"
            ],
            "recovery_canary_launch_state": "not_launched",
            "recovery_canary_launch_evidence_sha256": None,
            "recovery_canary_parent_error_code": None,
            "recovery_canary_attempt_state": "not_attempted",
            "recovery_canary_evidence_sha256": None,
            "recovery_canary_keychain_query_performed": False,
            "recovery_canary_synthetic_delivery_started": False,
            "recovery_canary_launches_used": 0,
            "recovery_canary_attempts_used": 0,
        }
    if data is not None and any(
        (
            data.get("launch_id") != launch.get("launch_id"),
            data.get("launch_claim_binding_sha256")
            != launch.get("launch_claim_binding_sha256"),
            data.get("predecessor_launch_id")
            != launch.get("predecessor_launch_id"),
            data.get("predecessor_launch_evidence_sha256")
            != launch.get("predecessor_launch_evidence_sha256"),
        )
    ):
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_accounting_invalid"
        )
    launch_state = str(launch["status"])
    if launch_state == "failed_preclaim":
        if data is not None:
            raise Option1RecoveryCanaryViolation(
                "option1_recovery_canary_accounting_invalid"
            )
    elif launch_state in {"child_completed", "child_stopped_with_data_receipt"}:
        if data is None or any(
            launch.get(launch_key) != data.get(data_key)
            for launch_key, data_key in (
                ("data_plane_receipt_status", "status"),
                ("data_plane_receipt_evidence_sha256", "evidence_sha256"),
                ("keychain_query_performed", "keychain_query_performed"),
                ("synthetic_delivery_started", "delivery_started"),
                (
                    "synthetic_material_read_by_native_helper",
                    "synthetic_material_read_by_native_helper",
                ),
            )
        ):
            raise Option1RecoveryCanaryViolation(
                "option1_recovery_canary_accounting_invalid"
            )
    elif launch_state != "launch_claimed":
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_accounting_invalid"
        )
    return {
        "recovery_canary_predecessor_verified": True,
        "recovery_canary_predecessor_launch_id": predecessor["launch_id"],
        "recovery_canary_predecessor_evidence_sha256": predecessor[
            "evidence_sha256"
        ],
        "recovery_canary_launch_state": launch_state,
        "recovery_canary_launch_evidence_sha256": launch["evidence_sha256"],
        "recovery_canary_parent_error_code": launch["parent_error_code"],
        "recovery_canary_attempt_state": (
            str(data["status"]) if data is not None else "not_attempted"
        ),
        "recovery_canary_evidence_sha256": (
            data["evidence_sha256"] if data is not None else None
        ),
        "recovery_canary_keychain_query_performed": (
            data["keychain_query_performed"] if data is not None else False
        ),
        "recovery_canary_synthetic_delivery_started": (
            data["delivery_started"] if data is not None else False
        ),
        "recovery_canary_launches_used": 1,
        "recovery_canary_attempts_used": 1 if data is not None else 0,
    }


def _write_new_receipt(
    runtime_root: Path,
    *,
    name: str,
    value: Mapping[str, object],
    launch: bool,
) -> tuple[Path, dict[str, object]]:
    receipt = dict(value)
    if launch:
        validate_recovery_canary_launch_receipt(receipt)
    else:
        validate_recovery_canary_receipt(receipt)
    encoded = canonical_json(receipt)
    if SYNTHETIC_PREFIX in encoded:
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_material_returned"
        )
    path = runtime_root / name
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except FileExistsError as exc:
        code = (
            "option1_recovery_canary_launch_exhausted"
            if launch
            else "option1_recovery_canary_attempt_exhausted"
        )
        raise Option1RecoveryCanaryViolation(code) from exc
    except OSError as exc:
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_receipt_write_failed"
        ) from exc
    try:
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, encoded)
        os.fsync(descriptor)
    except OSError as exc:
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_receipt_write_failed"
        ) from exc
    finally:
        os.close(descriptor)
    try:
        _fsync_directory(runtime_root)
    except OSError as exc:
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_receipt_write_failed"
        ) from exc
    return path, receipt


def claim_recovery_canary_launch(
    runtime_root: Path, *, confirmation: str
) -> tuple[Path, dict[str, object]]:
    """Consume the new owner authorization before starting the recovery child."""

    if confirmation != RECOVERY_CANARY_CONFIRMATION:
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_confirmation_invalid"
        )
    runtime_root = _private_runtime(runtime_root)
    validate_recovery_canary_predecessor(runtime_root)
    if os.path.lexists(runtime_root / RECOVERY_CANARY_RECEIPT_NAME):
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_launch_order_invalid"
        )
    claim: dict[str, object] = {
        "version": 1,
        "classification": RECOVERY_CANARY_LAUNCH_CLASSIFICATION,
        "launch_id": str(uuid.uuid4()),
        "launch_claim_binding_sha256": "",
        "predecessor_launch_id": EXPECTED_PREDECESSOR_LAUNCH_ID,
        "predecessor_launch_evidence_sha256": (
            EXPECTED_PREDECESSOR_EVIDENCE_SHA256
        ),
        "predecessor_status": EXPECTED_PREDECESSOR_STATUS,
        "authorization_gate_id": RECOVERY_CANARY_GATE_ID,
        "authorization_binding_sha256": _authorization_binding(),
        "authorization_confirmation_sha256": hashlib.sha256(
            RECOVERY_CANARY_CONFIRMATION.encode("utf-8")
        ).hexdigest(),
        "launch_index": 1,
        "launch_limit": RECOVERY_CANARY_LAUNCH_LIMIT,
        "launch_consumed": True,
        "accounting_origin": "prelaunch_claim",
        "recorded_at": _iso_now(),
        "completed_at": None,
        "status": "launch_claimed",
        "parent_error_code": None,
        "child_process_started": None,
        "child_process_completed": None,
        "data_plane_receipt_present": None,
        "data_plane_receipt_status": None,
        "data_plane_receipt_evidence_sha256": None,
        "keychain_query_performed": None,
        "synthetic_delivery_started": None,
        "synthetic_material_read_by_native_helper": None,
        "failed_preclaim_no_keychain_query_or_delivery_verified": None,
    }
    claim["launch_claim_binding_sha256"] = _launch_claim_binding(claim)
    claim = _with_evidence(claim)
    return _write_new_receipt(
        runtime_root,
        name=RECOVERY_CANARY_LAUNCH_RECEIPT_NAME,
        value=claim,
        launch=True,
    )


def finalize_recovery_canary_launch(
    receipt_path: Path,
    claim: Mapping[str, object],
    *,
    parent_error_code: str | None,
    child_process_started: bool,
    child_process_completed: bool,
) -> dict[str, object]:
    """Bind the recovery launch outcome to its separate data-plane receipt."""

    validate_recovery_canary_launch_receipt(claim)
    if claim.get("status") != "launch_claimed":
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_launch_claim_invalid"
        )
    if (
        type(child_process_started) is not bool
        or type(child_process_completed) is not bool
        or (child_process_completed and not child_process_started)
        or (
            parent_error_code is not None
            and not _PARENT_ERROR_PATTERN.fullmatch(parent_error_code)
        )
    ):
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_launch_result_invalid"
        )
    runtime_root = _private_runtime(receipt_path.parent)
    if (
        receipt_path.name != RECOVERY_CANARY_LAUNCH_RECEIPT_NAME
        or receipt_path.parent.resolve(strict=True) != runtime_root
    ):
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_launch_receipt_path_invalid"
        )
    validate_recovery_canary_predecessor(runtime_root)
    current = load_recovery_canary_launch_receipt(receipt_path)
    if current != claim:
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_launch_claim_changed"
        )
    data_path = runtime_root / RECOVERY_CANARY_RECEIPT_NAME
    data = (
        load_recovery_canary_receipt(data_path)
        if os.path.lexists(data_path)
        else None
    )
    terminal = dict(claim)
    terminal.update(
        {
            "completed_at": _iso_now(),
            "parent_error_code": parent_error_code,
            "child_process_started": child_process_started,
            "child_process_completed": child_process_completed,
        }
    )
    if data is None:
        if parent_error_code is None:
            raise Option1RecoveryCanaryViolation(
                "option1_recovery_canary_launch_result_invalid"
            )
        terminal.update(
            {
                "status": "failed_preclaim",
                "data_plane_receipt_present": False,
                "data_plane_receipt_status": None,
                "data_plane_receipt_evidence_sha256": None,
                "keychain_query_performed": False,
                "synthetic_delivery_started": False,
                "synthetic_material_read_by_native_helper": False,
                "failed_preclaim_no_keychain_query_or_delivery_verified": True,
            }
        )
    else:
        if child_process_started is not True or any(
            (
                data.get("launch_id") != claim.get("launch_id"),
                data.get("launch_claim_binding_sha256")
                != claim.get("launch_claim_binding_sha256"),
                data.get("predecessor_launch_id")
                != claim.get("predecessor_launch_id"),
                data.get("predecessor_launch_evidence_sha256")
                != claim.get("predecessor_launch_evidence_sha256"),
            )
        ):
            raise Option1RecoveryCanaryViolation(
                "option1_recovery_canary_launch_result_invalid"
            )
        if (
            (data["status"] != "passed" or not child_process_completed)
            and parent_error_code is None
        ):
            raise Option1RecoveryCanaryViolation(
                "option1_recovery_canary_launch_result_invalid"
            )
        terminal.update(
            {
                "status": (
                    "child_completed"
                    if child_process_completed
                    else "child_stopped_with_data_receipt"
                ),
                "data_plane_receipt_present": True,
                "data_plane_receipt_status": data["status"],
                "data_plane_receipt_evidence_sha256": data["evidence_sha256"],
                "keychain_query_performed": data["keychain_query_performed"],
                "synthetic_delivery_started": data["delivery_started"],
                "synthetic_material_read_by_native_helper": data[
                    "synthetic_material_read_by_native_helper"
                ],
                "failed_preclaim_no_keychain_query_or_delivery_verified": False,
            }
        )
    terminal = _with_evidence(terminal)
    validate_recovery_canary_launch_receipt(terminal)
    temporary = runtime_root / RECOVERY_CANARY_LAUNCH_RECEIPT_NEXT_NAME
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            os.fchmod(descriptor, 0o600)
            _write_all(descriptor, canonical_json(terminal))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, receipt_path)
        _fsync_directory(runtime_root)
    except OSError as exc:
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_launch_receipt_finalize_failed"
        ) from exc
    return terminal


def claim_recovery_canary_attempt(
    runtime_root: Path,
    *,
    helper_sha256: str,
    provisioning_receipt_evidence_sha256: str,
    runtime_path_sha256: str,
    vault_item_label_sha256: str,
    sdk_lock_sha256: str,
    policy_sha256: str,
    connector_source_sha256: str,
    recovery_canary_module_sha256: str,
    recovery_canary_runner_sha256: str,
    recovery_python_executable_sha256: str,
    recovery_dependency_manifest_sha256: str,
    registry_sha256: str,
    broker_process_network_guard_verified: bool,
    broker_process_parent_verified: bool,
) -> tuple[Path, dict[str, object]]:
    """Consume the recovery data-plane attempt before any Keychain query."""

    runtime_root = _private_runtime(runtime_root)
    validate_recovery_canary_predecessor(runtime_root)
    launch_path = runtime_root / RECOVERY_CANARY_LAUNCH_RECEIPT_NAME
    if not os.path.lexists(launch_path):
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_launch_claim_required"
        )
    launch = load_recovery_canary_launch_receipt(launch_path)
    if launch.get("status") != "launch_claimed":
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_launch_claim_invalid"
        )
    if broker_process_network_guard_verified is not True:
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_network_guard_absent"
        )
    if broker_process_parent_verified is not True:
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_parent_invalid"
        )
    hashes = {
        "helper_sha256": helper_sha256,
        "provisioning_receipt_evidence_sha256": (
            provisioning_receipt_evidence_sha256
        ),
        "runtime_path_sha256": runtime_path_sha256,
        "vault_item_label_sha256": vault_item_label_sha256,
        "sdk_lock_sha256": sdk_lock_sha256,
        "policy_sha256": policy_sha256,
        "connector_source_sha256": connector_source_sha256,
        "recovery_canary_module_sha256": recovery_canary_module_sha256,
        "recovery_canary_runner_sha256": recovery_canary_runner_sha256,
        "recovery_python_executable_sha256": recovery_python_executable_sha256,
        "recovery_dependency_manifest_sha256": (
            recovery_dependency_manifest_sha256
        ),
        "registry_sha256": registry_sha256,
    }
    if any(
        not isinstance(item, str) or not _HASH_PATTERN.fullmatch(item)
        for item in hashes.values()
    ):
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_binding_invalid"
        )
    claim: dict[str, object] = {
        "version": 1,
        "classification": RECOVERY_CANARY_CLASSIFICATION,
        "canary_id": str(uuid.uuid4()),
        "launch_id": launch["launch_id"],
        "launch_claim_binding_sha256": launch["launch_claim_binding_sha256"],
        "predecessor_launch_id": EXPECTED_PREDECESSOR_LAUNCH_ID,
        "predecessor_launch_evidence_sha256": (
            EXPECTED_PREDECESSOR_EVIDENCE_SHA256
        ),
        "authorization_gate_id": RECOVERY_CANARY_GATE_ID,
        "authorization_binding_sha256": _authorization_binding(),
        "attempt_index": 1,
        "attempt_limit": RECOVERY_CANARY_ATTEMPT_LIMIT,
        "attempt_consumed": True,
        "started_at": _iso_now(),
        "completed_at": None,
        "status": "attempt_claimed",
        "failure_code": None,
        "delivery_started": None,
        "selected_vault": "macos_login_keychain",
        "selected_runtime_mode": "on_demand_owner_private",
        **hashes,
        "keychain_query_performed": None,
        "synthetic_material_read_by_native_helper": None,
        "synthetic_material_read_state": "unknown_after_claim",
        "synthetic_material_present_in_atlas_parent": False,
        "keychain_secret_read_by_atlas_python": False,
        "keychain_secret_returned": False,
        "material_persisted": None,
        "material_returned": None,
        "network_accessed": False,
        "real_credential_used": False,
        "private_data_present": False,
        "model_contacted": False,
        "provider_contacted": False,
        "external_communication_performed": False,
        "background_service_enrolled": False,
        "ordinary_startup_wired": False,
        "live_authority_granted": False,
        "ready": False,
        "ready_offline": False,
        "ready_live": False,
        "broker_process_network_guard_verified": True,
        "broker_process_parent_verified": True,
        "broker_process_os_network_sandboxed": False,
        "broker_descendants_joined_supervised_group": True,
        "keychain_helper_os_network_sandboxed": True,
        "connector_os_network_sandboxed": True,
        "broker_repaused": None,
        "broker_state_snapshot": None,
        "broker_delivery_receipt": None,
        "broker_delivery_receipt_sha256": None,
        "broker_public_key_b64": None,
        **{field: None for field in _CONNECTOR_FIELDS},
    }
    claim = _with_evidence(claim)
    return _write_new_receipt(
        runtime_root,
        name=RECOVERY_CANARY_RECEIPT_NAME,
        value=claim,
        launch=False,
    )


def finalize_recovery_canary_attempt(
    receipt_path: Path,
    claim: Mapping[str, object],
    *,
    passed: bool,
    delivery_started: bool,
    keychain_query_performed: bool,
    connector_evidence: Mapping[str, bool] | None = None,
    broker_state_snapshot: Mapping[str, object] | None = None,
    broker_delivery_receipt: Mapping[str, object] | None = None,
    broker_delivery_receipt_sha256: str | None = None,
    broker_public_key_b64: str | None = None,
    failure_code: str | None = None,
) -> dict[str, object]:
    validate_recovery_canary_receipt(claim)
    if claim.get("status") != "attempt_claimed":
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_claim_invalid"
        )
    if type(delivery_started) is not bool or type(keychain_query_performed) is not bool:
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_result_invalid"
        )
    terminal = dict(claim)
    terminal.update(
        {
            "completed_at": _iso_now(),
            "delivery_started": delivery_started,
            "keychain_query_performed": keychain_query_performed,
        }
    )
    if passed:
        if (
            not delivery_started
            or not keychain_query_performed
            or connector_evidence is None
            or broker_state_snapshot is None
            or broker_delivery_receipt is None
            or broker_delivery_receipt_sha256 is None
            or broker_public_key_b64 is None
            or failure_code is not None
            or set(connector_evidence) != set(_CONNECTOR_FIELDS)
            or not all(
                connector_evidence.get(field) is True for field in _CONNECTOR_FIELDS
            )
        ):
            raise Option1RecoveryCanaryViolation(
                "option1_recovery_canary_result_invalid"
            )
        terminal.update(
            {
                "status": "passed",
                "failure_code": None,
                "synthetic_material_read_by_native_helper": True,
                "synthetic_material_read_state": "delivered_to_connector",
                "material_persisted": False,
                "material_returned": False,
                "network_accessed": False,
                "broker_repaused": True,
                "broker_state_snapshot": dict(broker_state_snapshot),
                "broker_delivery_receipt": dict(broker_delivery_receipt),
                "broker_delivery_receipt_sha256": broker_delivery_receipt_sha256,
                "broker_public_key_b64": broker_public_key_b64,
                **connector_evidence,
            }
        )
    else:
        safe_failure = failure_code or "option1_recovery_canary_failed"
        if not _FAILURE_PATTERN.fullmatch(safe_failure):
            safe_failure = "option1_recovery_canary_failed"
        terminal.update(
            {
                "status": "failed",
                "failure_code": safe_failure,
                "synthetic_material_read_by_native_helper": None,
                "synthetic_material_read_state": (
                    "unknown_after_attempt" if delivery_started else "not_started"
                ),
                "material_persisted": None,
                "material_returned": None,
                "network_accessed": None,
                "broker_repaused": None,
                "broker_state_snapshot": None,
                "broker_delivery_receipt": None,
                "broker_delivery_receipt_sha256": None,
                "broker_public_key_b64": None,
                **{field: None for field in _CONNECTOR_FIELDS},
            }
        )
    terminal = _with_evidence(terminal)
    validate_recovery_canary_receipt(terminal)
    if SYNTHETIC_PREFIX in canonical_json(terminal):
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_material_returned"
        )
    runtime_root = _private_runtime(receipt_path.parent)
    if (
        receipt_path.name != RECOVERY_CANARY_RECEIPT_NAME
        or receipt_path.parent.resolve(strict=True) != runtime_root
    ):
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_receipt_path_invalid"
        )
    validate_recovery_canary_predecessor(runtime_root)
    current = load_recovery_canary_receipt(receipt_path)
    if current != claim:
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_claim_changed"
        )
    temporary = runtime_root / RECOVERY_CANARY_RECEIPT_NEXT_NAME
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            os.fchmod(descriptor, 0o600)
            _write_all(descriptor, canonical_json(terminal))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, receipt_path)
        _fsync_directory(runtime_root)
    except OSError as exc:
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_receipt_finalize_failed"
        ) from exc
    return terminal


def _digest(label: str) -> str:
    return hashlib.sha256(
        f"atlas-option1-recovery-qualification:{label}".encode("utf-8")
    ).hexdigest()


def _build_fixture_documents(now: datetime) -> tuple[Any, ...]:
    """Build a recovery-specific, synthetic-only, registry-bound request."""

    policy_bundle = ImmutablePolicyBundle(
        version=1,
        policy_sha256=_digest("policy"),
        protocol_sha256=_digest("protocol"),
        sdk_lock_sha256=_digest("sdk-lock"),
        replay_corpus_sha256=_digest("replay-corpus"),
    )
    egress = DataEgressManifest(
        version=1,
        task_sha256=_digest("task"),
        job_sha256=_digest("job"),
        source_manifest_sha256=_digest("source-manifest"),
        payload_sha256=_digest("payload"),
        output_schema_sha256=_digest("output-schema"),
        purpose_sha256=_digest("purpose"),
        provider="offline-recovery-fixture-provider",
        model="offline-recovery-fixture-model",
        classification="synthetic_fictional_bounded",
        record_count=1,
        payload_bytes=128,
        max_payload_bytes=256,
        contains_private_data=False,
        contains_credentials=False,
    )
    if (
        policy_bundle.sha256 != _FIXTURE_POLICY_SHA256
        or egress.sha256 != _FIXTURE_EGRESS_SHA256
    ):
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_fixture_drift"
        )
    policy_signer = Ed25519OfflineSigner.generate()
    capability_receipt_signer = Ed25519OfflineSigner.generate()
    broker_signer = Ed25519OfflineSigner.generate()
    policy_broker = OfflineOwnerPolicyBroker(
        signer=policy_signer,
        verifier=policy_signer.verifier,
        clock=lambda: now,
    )
    capability_broker = OfflineCapabilityVerificationBroker(
        capability_verifier=policy_signer.verifier,
        receipt_signer=capability_receipt_signer,
        receipt_verifier=capability_receipt_signer.verifier,
        not_revoked_snapshot=lambda _envelope, _time: _digest("not-revoked"),
        clock=lambda: now,
        verification_ttl_seconds=180,
    )
    channel = SyntheticOneUseChannelHandle.generate()
    bindings = CapabilityBindings(
        capability_version=4,
        capability_id_sha256=_digest("capability:recovery-canary"),
        task_sha256=egress.task_sha256,
        job_sha256=egress.job_sha256,
        project_sha256=_digest("project"),
        nonce_sha256=_digest("nonce:recovery-canary"),
        audience="atlas-supervisor-v4-proposal-worker",
        provider=egress.provider,
        sdk_version="0.147.0",
        signing_key_id=policy_signer.key_id,
        one_use=True,
        issued_at=(now - timedelta(seconds=1)).isoformat(),
        expires_at=(now + timedelta(seconds=240)).isoformat(),
        max_ttl_seconds=300,
        source_baseline_sha256=_digest("source-baseline"),
        policy_bundle_sha256=policy_bundle.sha256,
        replay_corpus_sha256=policy_bundle.replay_corpus_sha256,
        adapter_sha256=_digest("adapter"),
        model=egress.model,
        reasoning_effort="low",
        runtime_sha256=_digest("runtime"),
        sandbox="read_only_empty_root",
        sandbox_profile_sha256=_digest("sandbox-profile"),
        network_access=False,
        budgets_sha256=_digest("budgets"),
        attempt_limit=1,
        process_limit=1,
        timeout_seconds=180,
        max_output_bytes=262_144,
        max_changed_files=1,
        max_changed_lines=20,
        max_patch_bytes=16_384,
        pause_channel_sha256=_digest("pause-channel"),
        operation="replace_existing_file",
        result_type="structured_replacement_proposal",
        path_sha256=_digest("path"),
        expected_original_sha256=_digest("original"),
        verification_recipe_sha256=_digest("verification-recipe"),
        data_egress_class=egress.classification,
        data_egress_manifest_sha256=egress.sha256,
        credential_scope_sha256=_digest("credential-scope"),
        credential_delivery_channel_sha256=channel.sha256,
        receipt_chain_id_sha256=_digest("receipt-chain"),
        receipt_predecessor_sha256=ZERO_DIGEST,
        receipt_predecessor_count=0,
        kill_switch_channel_sha256=_digest("kill-switch-channel"),
    )
    capability = policy_broker.issue_capability(policy_bundle, bindings)
    verification = capability_broker.verify_capability(
        capability,
        policy_bundle=policy_bundle,
        expected_egress_manifest_sha256=egress.sha256,
        observed_at=now.isoformat(),
    )
    request = CredentialLeaseRequest(
        version=1,
        capability_envelope_sha256=document_sha256(capability),
        capability_verification_sha256=verification.sha256,
        policy_bundle_sha256=policy_bundle.sha256,
        egress_manifest_sha256=egress.sha256,
        task_sha256=egress.task_sha256,
        job_sha256=egress.job_sha256,
        provider=egress.provider,
        model=egress.model,
        audience=bindings.audience,
        credential_scope_sha256=bindings.credential_scope_sha256,
        delivery_channel_sha256=channel.sha256,
        requested_at=now.isoformat(),
        expires_at=(now + timedelta(seconds=180)).isoformat(),
        max_ttl_seconds=180,
        max_uses=1,
        credential_class="model_transport",
        delivery_mode="broker_delivered_one_use_channel",
    )
    return (
        capability,
        verification,
        request,
        channel,
        policy_signer,
        capability_receipt_signer,
        broker_signer,
    )


def _build_recovery_registry() -> OwnerTaskRegistry:
    """Build the recovery-only synthetic allowance without the old registry."""

    binding = SameUserTaskBinding(
        version=1,
        mapping_id="option1-offline-recovery-fixture",
        task_sha256=_digest("task"),
        job_sha256=_digest("job"),
        policy_bundle_sha256=_FIXTURE_POLICY_SHA256,
        egress_manifest_sha256=_FIXTURE_EGRESS_SHA256,
        provider="offline-recovery-fixture-provider",
        model="offline-recovery-fixture-model",
        audience="atlas-supervisor-v4-proposal-worker",
        credential_scope_sha256=_digest("credential-scope"),
        destination_sha256=_digest("destination"),
        vault_item_label_sha256=VAULT_ITEM_LABEL_SHA256,
        connector_profile="darwin-sandboxed-null-connector-v1",
        synthetic_only=True,
        network_allowed=False,
    )
    return OwnerTaskRegistry(
        bindings=(binding,),
        source_sha256=_digest("registry-source"),
    )


def _safe_failure_code(exc: Exception) -> str:
    candidate = getattr(exc, "code", None)
    if not isinstance(candidate, str):
        candidate = str(exc)
    return (
        candidate
        if _FAILURE_PATTERN.fullmatch(candidate)
        else "option1_recovery_canary_failed"
    )


def _scan_tree_for_material(
    root: Path, adapter: MacOSKeychainSyntheticVaultAdapter
) -> bool:
    for path in root.rglob("*"):
        if path.is_symlink():
            return False
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > 2 * 1024 * 1024:
                return False
            if adapter.contains_known_material(path.read_bytes()):
                return False
        except OSError:
            return False
    return True


def _validate_runtime_preflight(
    config: AtlasConfig,
    runtime_root: Path,
    integration_report: Mapping[str, object],
    recovery_canary_runner_path: Path,
) -> dict[str, str]:
    if integration_report.get("integration_passed") is not True:
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_integration_review_failed"
        )
    required_false = (
        "background_service_enrolled",
        "real_credential_stored",
        "private_data_present",
        "network_accessed",
        "model_contacted",
        "provider_contacted",
        "live_authority_granted",
        "ordinary_startup_wired",
        "ready",
        "ready_offline",
        "ready_live",
    )
    if any(integration_report.get(key) is not False for key in required_false):
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_integration_review_unsafe"
        )
    if (
        integration_report.get("selected_vault") != "macos_login_keychain"
        or integration_report.get("selected_runtime_mode")
        != "on_demand_owner_private"
        or integration_report.get("vault_item_label_sha256")
        != VAULT_ITEM_LABEL_SHA256
    ):
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_integration_binding_invalid"
        )
    accounting = inspect_recovery_canary_accounting(runtime_root)
    expected_accounting = {
        "recovery_canary_predecessor_verified": True,
        "recovery_canary_predecessor_launch_id": EXPECTED_PREDECESSOR_LAUNCH_ID,
        "recovery_canary_predecessor_evidence_sha256": (
            EXPECTED_PREDECESSOR_EVIDENCE_SHA256
        ),
        "recovery_canary_launch_state": "launch_claimed",
        "recovery_canary_parent_error_code": None,
        "recovery_canary_attempt_state": "not_attempted",
        "recovery_canary_evidence_sha256": None,
        "recovery_canary_keychain_query_performed": False,
        "recovery_canary_synthetic_delivery_started": False,
        "recovery_canary_launches_used": 1,
        "recovery_canary_attempts_used": 0,
    }
    if any(accounting.get(key) != item for key, item in expected_accounting.items()):
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_launch_claim_invalid"
        )
    report_keys = tuple(accounting)
    if any(integration_report.get(key) != accounting[key] for key in report_keys):
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_integration_binding_invalid"
        )

    policy = config.supervisor_v4_policy
    supervisor = config.supervisor_v4
    if (
        policy is None
        or not supervisor.enabled
        or not supervisor.offline_qualification_enabled
        or not supervisor.same_user_broker_qualification_enabled
        or supervisor.same_user_broker_mode != "offline_synthetic_qualification"
        or supervisor.pause_file.exists()
    ):
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_supervisor_state_invalid"
        )
    live_flags = (
        "background_execution",
        "live_model_execution",
        "live_canary_execution",
        "canonical_mutations",
        "candidate_application",
        "external_actions",
        "command_network_access",
        "model_side_commands",
        "model_side_file_changes",
        "model_side_tools",
        "approval_requests",
        "experimental_api",
    )
    if any(getattr(policy, field) is not False for field in live_flags):
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_live_control_open"
        )
    trust_fields = (
        "owner_policy_broker_socket",
        "owner_policy_verification_key_file",
        "credential_broker_socket",
        "credential_broker_verification_key_file",
        "receipt_verification_key_file",
        "receipt_anchor_broker_socket",
        "receipt_anchor_verification_key_file",
        "owner_kill_switch_socket",
        "owner_kill_switch_verification_key_file",
    )
    if any(getattr(supervisor, field) is not None for field in trust_fields):
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_production_trust_present"
        )
    runtime_root = _private_runtime(runtime_root)
    expected_runtime_sha256 = hashlib.sha256(
        str(runtime_root).encode("utf-8")
    ).hexdigest()
    module_path = Path(__file__).resolve(strict=True)
    connector_path = (
        config.project_root
        / "src"
        / "atlas_core"
        / "supervisor_v4_same_user_connector.py"
    ).resolve(strict=True)
    runner_path = recovery_canary_runner_path.resolve(strict=True)
    recovery_registry = _build_recovery_registry()
    runtime_dependency_bindings = attest_recovery_runtime_dependencies(
        _load_recovery_sdk_lock(config.app.supervisor_v4_lock_file),
        expected_python_executable=Path(sys.executable),
    )
    values = {
        "helper_sha256": integration_report.get("helper_sha256"),
        "provisioning_receipt_evidence_sha256": integration_report.get(
            "receipt_evidence_sha256"
        ),
        "runtime_path_sha256": integration_report.get("runtime_path_sha256"),
        "vault_item_label_sha256": integration_report.get(
            "vault_item_label_sha256"
        ),
        "sdk_lock_sha256": integration_report.get("sdk_lock_sha256"),
        "policy_sha256": integration_report.get("policy_sha256"),
        "connector_source_sha256": sha256_file(connector_path),
        "recovery_canary_module_sha256": sha256_file(module_path),
        "recovery_canary_runner_sha256": sha256_file(runner_path),
        **runtime_dependency_bindings,
        "registry_sha256": recovery_registry.sha256,
    }
    if (
        values["runtime_path_sha256"] != expected_runtime_sha256
        or any(
            not isinstance(item, str) or not _HASH_PATTERN.fullmatch(item)
            for item in values.values()
        )
    ):
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_integration_binding_invalid"
        )
    return {key: str(item) for key, item in values.items()}


def run_option1_synthetic_integration_recovery_canary(
    *,
    config: AtlasConfig,
    runtime_root: Path,
    integration_report: Mapping[str, object],
    recovery_canary_runner_path: Path,
    confirmation: str,
    broker_process_network_guard_verified: bool,
    broker_process_parent_verified: bool,
) -> dict[str, object]:
    """Consume the distinct recovery attempt through the guarded broker seam."""

    if confirmation != RECOVERY_CANARY_CONFIRMATION:
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_confirmation_invalid"
        )
    if broker_process_network_guard_verified is not True:
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_network_guard_absent"
        )
    if broker_process_parent_verified is not True:
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_parent_invalid"
        )
    bindings = _validate_runtime_preflight(
        config,
        runtime_root,
        integration_report,
        recovery_canary_runner_path,
    )
    runtime_root = _private_runtime(runtime_root)
    adapter = MacOSKeychainSyntheticVaultAdapter(
        helper_path=runtime_root / "atlas-option1-keychain-helper",
        helper_sha256=bindings["helper_sha256"],
        join_current_process_group=True,
        use_network_sandbox=True,
    )
    registry = _build_recovery_registry()
    if registry.task_count != 1 or registry.sha256 != bindings["registry_sha256"]:
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_registry_invalid"
        )
    now = datetime.now(timezone.utc)
    (
        capability,
        verification,
        request,
        channel,
        policy_signer,
        capability_receipt_signer,
        broker_signer,
    ) = _build_fixture_documents(now)
    receipt_path, claim = claim_recovery_canary_attempt(
        runtime_root,
        **bindings,
        broker_process_network_guard_verified=True,
        broker_process_parent_verified=True,
    )
    keychain_query_performed = False
    delivery_started = False
    state: DurableSameUserTrustState | None = None
    try:
        keychain_query_performed = True
        if adapter.status() != {
            "version": 1,
            "present": True,
            "synthetic_only": True,
            "secret_read": False,
            "secret_returned": False,
        }:
            raise Option1RecoveryCanaryViolation(
                "option1_recovery_canary_synthetic_item_unavailable"
            )
        with tempfile.TemporaryDirectory(
            prefix=".integration-recovery-canary-state-", dir=runtime_root
        ) as temporary:
            temporary_root = Path(temporary).resolve(strict=True)
            os.chmod(temporary_root, 0o700)
            state_root = temporary_root / "state"
            state = DurableSameUserTrustState(
                root=state_root,
                registry_sha256=registry.sha256,
                integrity_key=secrets.token_bytes(32),
                clock=lambda: now,
            )
            state.set_pause("armed")
            connector = DarwinSandboxedSyntheticConnector(
                runtime_root=temporary_root,
                python_executable=Path(sys.executable),
                connector_source=(
                    config.project_root
                    / "src"
                    / "atlas_core"
                    / "supervisor_v4_same_user_connector.py"
                ),
                join_current_process_group=True,
            )
            broker = GuardedSameUserBroker(
                registry=registry,
                state=state,
                vault=adapter,  # type: ignore[arg-type]
                connector=connector,
                capability=capability,
                capability_verifier=policy_signer.verifier,
                capability_receipt_verifier=capability_receipt_signer.verifier,
                broker_signer=broker_signer,
                broker_verifier=broker_signer.verifier,
                clock=lambda: now,
            )
            lease = broker.issue_lease(request, verification)
            delivery_started = True
            delivery = broker.deliver_once(
                channel,
                request=request,
                lease=lease,
                verification=verification,
            )
            broker.verify_delivery_receipt(delivery)
            state.set_pause("paused")
            state_snapshot = state.snapshot()
            state.close()
            state = None
            if not _scan_tree_for_material(state_root, adapter):
                raise Option1RecoveryCanaryViolation(
                    "option1_recovery_canary_material_persistence_detected"
                )
        connector_evidence = {
            "connector_environment_scrubbed": delivery.environment_scrubbed,
            "connector_network_blocked": delivery.network_accessed is False,
            "connector_filesystem_write_blocked": (
                delivery.filesystem_write_allowed is False
            ),
            "connector_process_fork_blocked": (
                delivery.process_fork_allowed is False
            ),
            "connector_working_buffer_zeroized": (
                delivery.connector_working_buffer_zeroized
            ),
            "connector_process_group_reaped": delivery.process_teardown_verified,
            "connector_output_material_absent": delivery.material_returned is False,
        }
        return finalize_recovery_canary_attempt(
            receipt_path,
            claim,
            passed=True,
            delivery_started=True,
            keychain_query_performed=True,
            connector_evidence=connector_evidence,
            broker_state_snapshot=state_snapshot,
            broker_delivery_receipt=asdict(delivery),
            broker_delivery_receipt_sha256=delivery.sha256,
            broker_public_key_b64=broker_signer.verifier.public_key_b64,
        )
    except Exception as exc:
        if state is not None:
            try:
                state.close()
            except Exception:
                pass
        code = _safe_failure_code(exc)
        try:
            finalize_recovery_canary_attempt(
                receipt_path,
                claim,
                passed=False,
                delivery_started=delivery_started,
                keychain_query_performed=keychain_query_performed,
                failure_code=code,
            )
        except Exception as finalize_exc:
            raise Option1RecoveryCanaryViolation(
                "option1_recovery_canary_receipt_finalize_failed"
            ) from finalize_exc
        raise Option1RecoveryCanaryViolation(code) from exc


def validate_recovery_canary_child_result(
    value: Mapping[str, object],
) -> dict[str, object]:
    """Validate the only two canonical child output shapes."""

    result = dict(value)
    if result.get("classification") == RECOVERY_CANARY_CLASSIFICATION:
        validate_recovery_canary_receipt(result)
        return result
    if set(result) != _CHILD_FAILURE_FIELDS or not _evidence_valid(result):
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_child_result_invalid"
        )
    fixed = {
        "version": 1,
        "classification": f"{RECOVERY_CANARY_CLASSIFICATION}_child_result",
        "status": "failed",
        "broker_process_supervised_reaping_required": True,
        "real_credential_used": False,
        "private_data_present": False,
        "model_contacted": False,
        "provider_contacted": False,
        "background_service_enrolled": False,
        "ordinary_startup_wired": False,
        "live_authority_granted": False,
        "ready": False,
        "ready_offline": False,
        "ready_live": False,
    }
    failure = result.get("failure_code")
    booleans = (
        "broker_process_parent_verified",
        "broker_process_network_guard_verified",
        "connector_process_group_reaped",
    )
    if (
        any(not _exact(result.get(key), item) for key, item in fixed.items())
        or not isinstance(failure, str)
        or not _PARENT_ERROR_PATTERN.fullmatch(failure)
        or any(type(result.get(key)) is not bool for key in booleans)
        or result.get("synthetic_material_returned") is not None
        or result.get("network_accessed")
        is not (
            False
            if result.get("broker_process_network_guard_verified") is True
            else None
        )
    ):
        raise Option1RecoveryCanaryViolation(
            "option1_recovery_canary_child_result_invalid"
        )
    return result


__all__ = [
    "EXPECTED_PREDECESSOR_ACCOUNTING_ORIGIN",
    "EXPECTED_PREDECESSOR_EVIDENCE_SHA256",
    "EXPECTED_PREDECESSOR_LAUNCH_ID",
    "EXPECTED_PREDECESSOR_PARENT_ERROR_CODE",
    "EXPECTED_PREDECESSOR_STATUS",
    "Option1RecoveryCanaryViolation",
    "RECOVERY_CANARY_ATTEMPT_LIMIT",
    "RECOVERY_CANARY_CLASSIFICATION",
    "RECOVERY_CANARY_CONFIRMATION",
    "RECOVERY_CANARY_GATE_ID",
    "RECOVERY_CANARY_LAUNCH_CLASSIFICATION",
    "RECOVERY_CANARY_LAUNCH_LIMIT",
    "RECOVERY_CANARY_LAUNCH_RECEIPT_NAME",
    "RECOVERY_CANARY_LAUNCH_RECEIPT_NEXT_NAME",
    "RECOVERY_CANARY_RECEIPT_NAME",
    "RECOVERY_CANARY_RECEIPT_NEXT_NAME",
    "attest_recovery_runtime_dependencies",
    "canonical_json",
    "claim_recovery_canary_attempt",
    "claim_recovery_canary_launch",
    "finalize_recovery_canary_attempt",
    "finalize_recovery_canary_launch",
    "inspect_recovery_canary_accounting",
    "load_recovery_canary_launch_receipt",
    "load_recovery_canary_receipt",
    "run_option1_synthetic_integration_recovery_canary",
    "validate_recovery_canary_child_result",
    "validate_recovery_canary_launch_receipt",
    "validate_recovery_canary_predecessor",
    "validate_recovery_canary_receipt",
]
