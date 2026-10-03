from __future__ import annotations

"""One-shot receipt controls for Atlas's installed Option 1 synthetic canary.

This module never reads Keychain material.  It owns only the privacy-safe,
at-most-once claim and terminal receipt used by the explicit local canary
runner.  The native fixed-selector helper delivers the synthetic sentinel
directly to the short-lived sandboxed connector.
"""

import hashlib
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
    ConnectorResult,
    DarwinSandboxedSyntheticConnector,
    GuardedSameUserBroker,
    OwnerTaskRegistry,
    SameUserDeliveryReceipt,
)
from atlas_core.supervisor_v4_same_user_state import DurableSameUserTrustState


CANARY_GATE_ID = "owner_authorize_option1_on_demand_synthetic_integration_canary"
CANARY_CONFIRMATION = (
    "AUTHORIZE OPTION1 ONE-SHOT ON-DEMAND SYNTHETIC INTEGRATION CANARY"
)
CANARY_RECEIPT_NAME = "synthetic-integration-canary-receipt.json"
CANARY_RECEIPT_NEXT_NAME = f".{CANARY_RECEIPT_NAME}.next"
CANARY_CLASSIFICATION = "option1_atlas_facing_synthetic_integration_canary"
CANARY_ATTEMPT_LIMIT = 1
CANARY_LAUNCH_RECEIPT_NAME = "synthetic-integration-canary-launch-receipt.json"
CANARY_LAUNCH_RECEIPT_NEXT_NAME = f".{CANARY_LAUNCH_RECEIPT_NAME}.next"
CANARY_LAUNCH_CLASSIFICATION = (
    "option1_atlas_facing_synthetic_integration_canary_launch"
)
CANARY_LAUNCH_LIMIT = 1
# The original and recovery lineages intentionally share one owner-private
# runtime. Original accounting ignores only the two finalized recovery
# receipts; recovery accounting independently validates their contents.
_RECOVERY_CANARY_FINAL_RECEIPT_NAMES = {
    "synthetic-integration-recovery-canary-launch-receipt.json",
    "synthetic-integration-recovery-canary-receipt.json",
}
_CANARY_ACCOUNTING_RUNTIME_NAMES = {
    "atlas-option1-keychain-helper",
    "provisioning-receipt.json",
    CANARY_LAUNCH_RECEIPT_NAME,
    CANARY_RECEIPT_NAME,
    *_RECOVERY_CANARY_FINAL_RECEIPT_NAMES,
}
_MAX_RECEIPT_BYTES = 64 * 1024
_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_FAILURE_PATTERN = re.compile(
    r"^(?:option1|same_user|connector|state)_[a-z0-9_]{1,87}$"
)
_PARENT_ERROR_PATTERN = re.compile(r"^option1_canary_[a-z0-9_]{1,80}$")
_DELIVERY_DOMAIN = "atlas.supervisor-v4.same-user-delivery.v1"
_FIXTURE_POLICY_SHA256 = (
    "55118b901783368428117855cb47cf220f367b09c046b6c03a6b29cfa5f38584"
)
_FIXTURE_EGRESS_SHA256 = (
    "5c94f5d2e7d04a5e726241fcfbaae8d3a0748cdb6df7b71f4786af792b4bde1a"
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
_HASH_FIELDS = (
    "helper_sha256",
    "provisioning_receipt_evidence_sha256",
    "runtime_path_sha256",
    "vault_item_label_sha256",
    "sdk_lock_sha256",
    "policy_sha256",
    "connector_source_sha256",
    "canary_module_sha256",
    "canary_runner_sha256",
    "authorization_binding_sha256",
    "launch_receipt_evidence_sha256",
    "registry_sha256",
)
_RECEIPT_FIELDS = {
    "version",
    "classification",
    "canary_id",
    "launch_id",
    "launch_receipt_evidence_sha256",
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
    "helper_sha256",
    "provisioning_receipt_evidence_sha256",
    "runtime_path_sha256",
    "vault_item_label_sha256",
    "sdk_lock_sha256",
    "policy_sha256",
    "connector_source_sha256",
    "canary_module_sha256",
    "canary_runner_sha256",
    "registry_sha256",
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


class Option1CanaryViolation(RuntimeError):
    """Privacy-safe failure from the synthetic canary receipt lifecycle."""

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
        raise Option1CanaryViolation("option1_canary_receipt_invalid") from exc


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise Option1CanaryViolation("option1_canary_source_unavailable") from exc
    return digest.hexdigest()


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


def _exact_value(value: object, expected: object) -> bool:
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


def _write_all(descriptor: int, value: bytes) -> None:
    view = memoryview(value)
    while view:
        try:
            written = os.write(descriptor, view)
        except InterruptedError:
            continue
        if written <= 0:
            raise Option1CanaryViolation("option1_canary_receipt_write_failed")
        view = view[written:]


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _private_runtime(path: Path) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise Option1CanaryViolation("option1_canary_runtime_unavailable") from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise Option1CanaryViolation("option1_canary_runtime_invalid")
    return path.resolve(strict=True)


def _validate_signed_delivery(
    value: object,
    *,
    expected_sha256: object,
    public_key_b64: object,
) -> None:
    if (
        not isinstance(value, dict)
        or not isinstance(expected_sha256, str)
        or not _HASH_PATTERN.fullmatch(expected_sha256)
        or not isinstance(public_key_b64, str)
    ):
        raise Option1CanaryViolation("option1_canary_delivery_receipt_invalid")
    try:
        receipt = SameUserDeliveryReceipt(**value)
        verifier = Ed25519OfflineVerifier.from_public_key_b64(public_key_b64)
        if receipt.sha256 != expected_sha256 or receipt.broker_key_id != verifier.key_id:
            raise Option1CanaryViolation("option1_canary_delivery_receipt_invalid")
        verifier.verify(
            domain=_DELIVERY_DOMAIN,
            payload=unsigned_document(receipt),
            signature=receipt.signature,
        )
    except Option1CanaryViolation:
        raise
    except Exception as exc:
        raise Option1CanaryViolation(
            "option1_canary_delivery_receipt_invalid"
        ) from exc


def _validate_state_snapshot(value: object) -> None:
    if not isinstance(value, dict) or set(value) != _STATE_FIELDS:
        raise Option1CanaryViolation("option1_canary_state_snapshot_invalid")
    exact = {
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
    if any(value.get(key) != expected for key, expected in exact.items()):
        raise Option1CanaryViolation("option1_canary_state_snapshot_invalid")
    for key in ("event_count", "state_generation", "pause_generation"):
        if type(value.get(key)) is not int or int(value[key]) < 1:
            raise Option1CanaryViolation("option1_canary_state_snapshot_invalid")


def validate_canary_receipt(value: Mapping[str, object]) -> None:
    if set(value) != _RECEIPT_FIELDS or not _evidence_valid(value):
        raise Option1CanaryViolation("option1_canary_receipt_invalid")
    fixed_scalars = {
        "version": 1,
        "classification": CANARY_CLASSIFICATION,
        "authorization_gate_id": CANARY_GATE_ID,
        "attempt_index": 1,
        "attempt_limit": CANARY_ATTEMPT_LIMIT,
        "selected_vault": "macos_login_keychain",
        "selected_runtime_mode": "on_demand_owner_private",
    }
    fixed_booleans = {
        "attempt_consumed": True,
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
    scalar_mismatch = any(
        not _exact_value(value.get(key), expected)
        for key, expected in fixed_scalars.items()
    )
    boolean_mismatch = any(
        value.get(key) is not expected for key, expected in fixed_booleans.items()
    )
    if scalar_mismatch or boolean_mismatch:
        raise Option1CanaryViolation("option1_canary_receipt_invalid")
    if any(
        not isinstance(value.get(key), str)
        or not _HASH_PATTERN.fullmatch(str(value[key]))
        for key in _HASH_FIELDS
    ):
        raise Option1CanaryViolation("option1_canary_receipt_invalid")
    if value["authorization_binding_sha256"] != hashlib.sha256(
        CANARY_GATE_ID.encode("utf-8")
    ).hexdigest():
        raise Option1CanaryViolation("option1_canary_receipt_invalid")
    try:
        canary_id = uuid.UUID(str(value["canary_id"]))
        launch_id = uuid.UUID(str(value["launch_id"]))
    except (ValueError, AttributeError):
        raise Option1CanaryViolation("option1_canary_receipt_invalid") from None
    if str(canary_id) != value["canary_id"] or str(launch_id) != value["launch_id"]:
        raise Option1CanaryViolation("option1_canary_receipt_invalid")
    if not _valid_time(value.get("started_at")):
        raise Option1CanaryViolation("option1_canary_receipt_invalid")

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
            raise Option1CanaryViolation("option1_canary_receipt_invalid")
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
        if not _valid_time(value.get("completed_at")) or any(
            not _exact_value(value.get(key), expected)
            for key, expected in expected_pass.items()
        ):
            raise Option1CanaryViolation("option1_canary_receipt_invalid")
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
            not _valid_time(value.get("completed_at"))
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
            raise Option1CanaryViolation("option1_canary_receipt_invalid")
        return

    raise Option1CanaryViolation("option1_canary_receipt_invalid")


def load_canary_receipt(path: Path) -> dict[str, object]:
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
            raise Option1CanaryViolation("option1_canary_receipt_invalid")
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Option1CanaryViolation("option1_canary_receipt_invalid") from exc
    if (
        not isinstance(value, dict)
        or canonical_json(value) != raw
        or b"atlas-option1-synthetic-v1_" in raw
    ):
        raise Option1CanaryViolation("option1_canary_receipt_invalid")
    validate_canary_receipt(value)
    return value


def validate_canary_launch_receipt(value: Mapping[str, object]) -> None:
    """Validate the owner-launch accounting layer without touching Keychain."""

    if set(value) != _LAUNCH_RECEIPT_FIELDS or not _evidence_valid(value):
        raise Option1CanaryViolation("option1_canary_launch_receipt_invalid")
    fixed = {
        "version": 1,
        "classification": CANARY_LAUNCH_CLASSIFICATION,
        "authorization_gate_id": CANARY_GATE_ID,
        "authorization_binding_sha256": hashlib.sha256(
            CANARY_GATE_ID.encode("utf-8")
        ).hexdigest(),
        "authorization_confirmation_sha256": hashlib.sha256(
            CANARY_CONFIRMATION.encode("utf-8")
        ).hexdigest(),
        "launch_index": 1,
        "launch_limit": CANARY_LAUNCH_LIMIT,
        "launch_consumed": True,
    }
    if any(not _exact_value(value.get(key), expected) for key, expected in fixed.items()):
        raise Option1CanaryViolation("option1_canary_launch_receipt_invalid")
    try:
        launch_id = uuid.UUID(str(value["launch_id"]))
    except (ValueError, AttributeError):
        raise Option1CanaryViolation(
            "option1_canary_launch_receipt_invalid"
        ) from None
    if str(launch_id) != value["launch_id"]:
        raise Option1CanaryViolation("option1_canary_launch_receipt_invalid")
    origin = value.get("accounting_origin")
    if origin not in {"prelaunch_claim", "postflight_reconciliation"}:
        raise Option1CanaryViolation("option1_canary_launch_receipt_invalid")
    if not _valid_time(value.get("recorded_at")):
        raise Option1CanaryViolation("option1_canary_launch_receipt_invalid")

    status = value.get("status")
    if status == "launch_claimed":
        if origin != "prelaunch_claim" or any(
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
            raise Option1CanaryViolation("option1_canary_launch_receipt_invalid")
        return

    if not _time_at_or_after(value.get("completed_at"), value.get("recorded_at")):
        raise Option1CanaryViolation("option1_canary_launch_receipt_invalid")
    parent_error = value.get("parent_error_code")
    if parent_error is not None and (
        not isinstance(parent_error, str)
        or not _PARENT_ERROR_PATTERN.fullmatch(parent_error)
    ):
        raise Option1CanaryViolation("option1_canary_launch_receipt_invalid")

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
            raise Option1CanaryViolation("option1_canary_launch_receipt_invalid")
        return

    if status in {"child_completed", "child_stopped_with_data_receipt"}:
        data_status = value.get("data_plane_receipt_status")
        child_completed = status == "child_completed"
        if (
            origin != "prelaunch_claim"
            or value.get("child_process_started") is not True
            or value.get("child_process_completed") is not child_completed
            or value.get("data_plane_receipt_present") is not True
            or not isinstance(data_status, str)
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
            raise Option1CanaryViolation("option1_canary_launch_receipt_invalid")
        facts = (
            value.get("keychain_query_performed"),
            value.get("synthetic_delivery_started"),
            value.get("synthetic_material_read_by_native_helper"),
        )
        if data_status == "attempt_claimed" and facts != (None, None, None):
            raise Option1CanaryViolation("option1_canary_launch_receipt_invalid")
        if data_status == "failed" and (
            type(facts[0]) is not bool
            or type(facts[1]) is not bool
            or facts[2] is not None
        ):
            raise Option1CanaryViolation("option1_canary_launch_receipt_invalid")
        if data_status == "passed" and facts != (True, True, True):
            raise Option1CanaryViolation("option1_canary_launch_receipt_invalid")
        return

    raise Option1CanaryViolation("option1_canary_launch_receipt_invalid")


def load_canary_launch_receipt(path: Path) -> dict[str, object]:
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
            raise Option1CanaryViolation("option1_canary_launch_receipt_invalid")
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except Option1CanaryViolation:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Option1CanaryViolation(
            "option1_canary_launch_receipt_invalid"
        ) from exc
    if (
        not isinstance(value, dict)
        or canonical_json(value) != raw
        or SYNTHETIC_PREFIX in raw
    ):
        raise Option1CanaryViolation("option1_canary_launch_receipt_invalid")
    validate_canary_launch_receipt(value)
    return value


def inspect_canary_accounting(runtime_root: Path) -> dict[str, object]:
    """Read only the fixed launch/data receipts and reconcile their state."""

    runtime_root = _private_runtime(runtime_root)
    try:
        runtime_names = {entry.name for entry in runtime_root.iterdir()}
    except OSError as exc:
        raise Option1CanaryViolation("option1_canary_accounting_invalid") from exc
    if not runtime_names.issubset(_CANARY_ACCOUNTING_RUNTIME_NAMES):
        raise Option1CanaryViolation("option1_canary_accounting_invalid")
    launch_path = runtime_root / CANARY_LAUNCH_RECEIPT_NAME
    data_path = runtime_root / CANARY_RECEIPT_NAME
    launch_receipt = (
        load_canary_launch_receipt(launch_path)
        if os.path.lexists(launch_path)
        else None
    )
    data_receipt = (
        load_canary_receipt(data_path) if os.path.lexists(data_path) else None
    )
    if data_receipt is not None and launch_receipt is not None:
        if data_receipt.get("launch_id") != launch_receipt.get("launch_id"):
            raise Option1CanaryViolation("option1_canary_accounting_invalid")
        if (
            launch_receipt.get("status") == "launch_claimed"
            and data_receipt.get("launch_receipt_evidence_sha256")
            != launch_receipt.get("evidence_sha256")
        ):
            raise Option1CanaryViolation("option1_canary_accounting_invalid")
    if launch_receipt is None:
        if data_receipt is not None:
            raise Option1CanaryViolation("option1_canary_accounting_invalid")
        return {
            "canary_launch_state": "not_launched",
            "canary_accounting_origin": None,
            "canary_launch_evidence_sha256": None,
            "canary_parent_error_code": None,
            "canary_attempt_state": "not_attempted",
            "canary_evidence_sha256": None,
            "canary_keychain_query_performed": False,
            "canary_synthetic_delivery_started": False,
            "failed_preclaim_no_keychain_query_or_delivery_verified": False,
        }

    launch_state = str(launch_receipt["status"])
    if launch_state == "failed_preclaim":
        if data_receipt is not None:
            raise Option1CanaryViolation("option1_canary_accounting_invalid")
        return {
            "canary_launch_state": launch_state,
            "canary_accounting_origin": launch_receipt["accounting_origin"],
            "canary_launch_evidence_sha256": launch_receipt["evidence_sha256"],
            "canary_parent_error_code": launch_receipt["parent_error_code"],
            "canary_attempt_state": "failed_preclaim",
            "canary_evidence_sha256": None,
            "canary_keychain_query_performed": False,
            "canary_synthetic_delivery_started": False,
            "failed_preclaim_no_keychain_query_or_delivery_verified": True,
        }

    if launch_state in {"child_completed", "child_stopped_with_data_receipt"}:
        if data_receipt is None or any(
            launch_receipt.get(launch_field) != data_receipt.get(data_field)
            for launch_field, data_field in (
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
            raise Option1CanaryViolation("option1_canary_accounting_invalid")
    elif launch_state != "launch_claimed":
        raise Option1CanaryViolation("option1_canary_accounting_invalid")

    return {
        "canary_launch_state": launch_state,
        "canary_accounting_origin": launch_receipt["accounting_origin"],
        "canary_launch_evidence_sha256": launch_receipt["evidence_sha256"],
        "canary_parent_error_code": launch_receipt["parent_error_code"],
        "canary_attempt_state": (
            str(data_receipt["status"])
            if data_receipt is not None
            else "not_attempted"
        ),
        "canary_evidence_sha256": (
            data_receipt["evidence_sha256"] if data_receipt is not None else None
        ),
        "canary_keychain_query_performed": (
            data_receipt["keychain_query_performed"]
            if data_receipt is not None
            else False
        ),
        "canary_synthetic_delivery_started": (
            data_receipt["delivery_started"] if data_receipt is not None else False
        ),
        "failed_preclaim_no_keychain_query_or_delivery_verified": False,
    }


def _write_new_canary_launch_receipt(
    runtime_root: Path,
    receipt: Mapping[str, object],
) -> tuple[Path, dict[str, object]]:
    value = dict(receipt)
    validate_canary_launch_receipt(value)
    encoded = canonical_json(value)
    if SYNTHETIC_PREFIX in encoded:
        raise Option1CanaryViolation("option1_canary_material_returned")
    receipt_path = runtime_root / CANARY_LAUNCH_RECEIPT_NAME
    try:
        descriptor = os.open(
            receipt_path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except FileExistsError as exc:
        raise Option1CanaryViolation("option1_canary_launch_exhausted") from exc
    except OSError as exc:
        raise Option1CanaryViolation(
            "option1_canary_launch_receipt_write_failed"
        ) from exc
    try:
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, encoded)
        os.fsync(descriptor)
    except OSError as exc:
        raise Option1CanaryViolation(
            "option1_canary_launch_receipt_write_failed"
        ) from exc
    finally:
        os.close(descriptor)
    try:
        _fsync_directory(runtime_root)
    except OSError as exc:
        raise Option1CanaryViolation(
            "option1_canary_launch_receipt_write_failed"
        ) from exc
    return receipt_path, value


def claim_canary_launch(
    runtime_root: Path,
    *,
    confirmation: str,
) -> tuple[Path, dict[str, object]]:
    """Consume the single owner-authorized launch before starting the child."""

    if confirmation != CANARY_CONFIRMATION:
        raise Option1CanaryViolation("option1_canary_confirmation_invalid")
    runtime_root = _private_runtime(runtime_root)
    if os.path.lexists(runtime_root / CANARY_RECEIPT_NAME):
        raise Option1CanaryViolation("option1_canary_launch_order_invalid")
    claim = _with_evidence(
        {
            "version": 1,
            "classification": CANARY_LAUNCH_CLASSIFICATION,
            "launch_id": str(uuid.uuid4()),
            "authorization_gate_id": CANARY_GATE_ID,
            "authorization_binding_sha256": hashlib.sha256(
                CANARY_GATE_ID.encode("utf-8")
            ).hexdigest(),
            "authorization_confirmation_sha256": hashlib.sha256(
                CANARY_CONFIRMATION.encode("utf-8")
            ).hexdigest(),
            "launch_index": 1,
            "launch_limit": CANARY_LAUNCH_LIMIT,
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
    )
    return _write_new_canary_launch_receipt(runtime_root, claim)


def reconcile_failed_preclaim_launch(
    runtime_root: Path,
    *,
    original_confirmation: str,
    observed_parent_error_code: str,
    child_process_started: bool,
    child_process_completed: bool,
) -> tuple[Path, dict[str, object]]:
    """Record an already-finished preclaim failure without authorizing a retry."""

    if original_confirmation != CANARY_CONFIRMATION:
        raise Option1CanaryViolation("option1_canary_confirmation_invalid")
    if (
        not isinstance(observed_parent_error_code, str)
        or not _PARENT_ERROR_PATTERN.fullmatch(observed_parent_error_code)
        or type(child_process_started) is not bool
        or type(child_process_completed) is not bool
        or (child_process_completed and not child_process_started)
    ):
        raise Option1CanaryViolation(
            "option1_canary_postflight_reconciliation_invalid"
        )
    runtime_root = _private_runtime(runtime_root)
    if os.path.lexists(runtime_root / CANARY_RECEIPT_NAME):
        raise Option1CanaryViolation(
            "option1_canary_postflight_reconciliation_data_receipt_present"
        )
    recorded_at = _iso_now()
    receipt = _with_evidence(
        {
            "version": 1,
            "classification": CANARY_LAUNCH_CLASSIFICATION,
            "launch_id": str(uuid.uuid4()),
            "authorization_gate_id": CANARY_GATE_ID,
            "authorization_binding_sha256": hashlib.sha256(
                CANARY_GATE_ID.encode("utf-8")
            ).hexdigest(),
            "authorization_confirmation_sha256": hashlib.sha256(
                CANARY_CONFIRMATION.encode("utf-8")
            ).hexdigest(),
            "launch_index": 1,
            "launch_limit": CANARY_LAUNCH_LIMIT,
            "launch_consumed": True,
            "accounting_origin": "postflight_reconciliation",
            "recorded_at": recorded_at,
            "completed_at": recorded_at,
            "status": "failed_preclaim",
            "parent_error_code": observed_parent_error_code,
            "child_process_started": child_process_started,
            "child_process_completed": child_process_completed,
            "data_plane_receipt_present": False,
            "data_plane_receipt_status": None,
            "data_plane_receipt_evidence_sha256": None,
            "keychain_query_performed": False,
            "synthetic_delivery_started": False,
            "synthetic_material_read_by_native_helper": False,
            "failed_preclaim_no_keychain_query_or_delivery_verified": True,
        }
    )
    return _write_new_canary_launch_receipt(runtime_root, receipt)


def finalize_canary_launch(
    receipt_path: Path,
    claim: Mapping[str, object],
    *,
    parent_error_code: str | None,
    child_process_started: bool,
    child_process_completed: bool,
) -> dict[str, object]:
    """Bind the launch outcome to the separately persisted data-plane claim."""

    validate_canary_launch_receipt(claim)
    if claim.get("status") != "launch_claimed":
        raise Option1CanaryViolation("option1_canary_launch_claim_invalid")
    if (
        type(child_process_started) is not bool
        or type(child_process_completed) is not bool
        or (child_process_completed and not child_process_started)
        or (
            parent_error_code is not None
            and not _PARENT_ERROR_PATTERN.fullmatch(parent_error_code)
        )
    ):
        raise Option1CanaryViolation("option1_canary_launch_result_invalid")

    runtime_root = _private_runtime(receipt_path.parent)
    if (
        receipt_path.name != CANARY_LAUNCH_RECEIPT_NAME
        or receipt_path.parent.resolve(strict=True) != runtime_root
    ):
        raise Option1CanaryViolation("option1_canary_launch_receipt_path_invalid")
    current = load_canary_launch_receipt(receipt_path)
    if current != claim:
        raise Option1CanaryViolation("option1_canary_launch_claim_changed")

    data_path = runtime_root / CANARY_RECEIPT_NAME
    data_receipt = (
        load_canary_receipt(data_path) if os.path.lexists(data_path) else None
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
    if data_receipt is None:
        if parent_error_code is None:
            raise Option1CanaryViolation("option1_canary_launch_result_invalid")
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
        if child_process_started is not True:
            raise Option1CanaryViolation("option1_canary_launch_result_invalid")
        if (
            data_receipt.get("launch_id") != claim.get("launch_id")
            or data_receipt.get("launch_receipt_evidence_sha256")
            != claim.get("evidence_sha256")
        ):
            raise Option1CanaryViolation("option1_canary_launch_result_invalid")
        if (
            (data_receipt["status"] != "passed" or not child_process_completed)
            and parent_error_code is None
        ):
            raise Option1CanaryViolation("option1_canary_launch_result_invalid")
        terminal.update(
            {
                "status": (
                    "child_completed"
                    if child_process_completed
                    else "child_stopped_with_data_receipt"
                ),
                "data_plane_receipt_present": True,
                "data_plane_receipt_status": data_receipt["status"],
                "data_plane_receipt_evidence_sha256": data_receipt[
                    "evidence_sha256"
                ],
                "keychain_query_performed": data_receipt[
                    "keychain_query_performed"
                ],
                "synthetic_delivery_started": data_receipt["delivery_started"],
                "synthetic_material_read_by_native_helper": data_receipt[
                    "synthetic_material_read_by_native_helper"
                ],
                "failed_preclaim_no_keychain_query_or_delivery_verified": False,
            }
        )

    terminal = _with_evidence(terminal)
    validate_canary_launch_receipt(terminal)
    if SYNTHETIC_PREFIX in canonical_json(terminal):
        raise Option1CanaryViolation("option1_canary_material_returned")
    temporary = runtime_root / CANARY_LAUNCH_RECEIPT_NEXT_NAME
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except OSError as exc:
        raise Option1CanaryViolation(
            "option1_canary_launch_receipt_finalize_failed"
        ) from exc
    try:
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, canonical_json(terminal))
        os.fsync(descriptor)
    except OSError as exc:
        raise Option1CanaryViolation(
            "option1_canary_launch_receipt_finalize_failed"
        ) from exc
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, receipt_path)
        _fsync_directory(runtime_root)
    except OSError as exc:
        raise Option1CanaryViolation(
            "option1_canary_launch_receipt_finalize_failed"
        ) from exc
    return terminal


def claim_canary_attempt(
    runtime_root: Path,
    *,
    helper_sha256: str,
    provisioning_receipt_evidence_sha256: str,
    runtime_path_sha256: str,
    vault_item_label_sha256: str,
    sdk_lock_sha256: str,
    policy_sha256: str,
    connector_source_sha256: str,
    canary_module_sha256: str,
    canary_runner_sha256: str,
    registry_sha256: str,
    broker_process_network_guard_verified: bool,
    broker_process_parent_verified: bool,
) -> tuple[Path, dict[str, object]]:
    runtime_root = _private_runtime(runtime_root)
    launch_path = runtime_root / CANARY_LAUNCH_RECEIPT_NAME
    if not os.path.lexists(launch_path):
        raise Option1CanaryViolation("option1_canary_launch_claim_required")
    launch_receipt = load_canary_launch_receipt(launch_path)
    if (
        launch_receipt.get("status") != "launch_claimed"
        or launch_receipt.get("accounting_origin") != "prelaunch_claim"
    ):
        raise Option1CanaryViolation("option1_canary_launch_claim_invalid")
    if broker_process_network_guard_verified is not True:
        raise Option1CanaryViolation("option1_canary_network_guard_absent")
    if broker_process_parent_verified is not True:
        raise Option1CanaryViolation("option1_canary_parent_invalid")
    receipt_path = runtime_root / CANARY_RECEIPT_NAME
    hashes = {
        "helper_sha256": helper_sha256,
        "provisioning_receipt_evidence_sha256": provisioning_receipt_evidence_sha256,
        "runtime_path_sha256": runtime_path_sha256,
        "vault_item_label_sha256": vault_item_label_sha256,
        "sdk_lock_sha256": sdk_lock_sha256,
        "policy_sha256": policy_sha256,
        "connector_source_sha256": connector_source_sha256,
        "canary_module_sha256": canary_module_sha256,
        "canary_runner_sha256": canary_runner_sha256,
        "registry_sha256": registry_sha256,
    }
    if any(not _HASH_PATTERN.fullmatch(value) for value in hashes.values()):
        raise Option1CanaryViolation("option1_canary_binding_invalid")
    claim: dict[str, object] = {
        "version": 1,
        "classification": CANARY_CLASSIFICATION,
        "canary_id": str(uuid.uuid4()),
        "launch_id": launch_receipt["launch_id"],
        "launch_receipt_evidence_sha256": launch_receipt["evidence_sha256"],
        "authorization_gate_id": CANARY_GATE_ID,
        "authorization_binding_sha256": hashlib.sha256(
            CANARY_GATE_ID.encode("utf-8")
        ).hexdigest(),
        "attempt_index": 1,
        "attempt_limit": CANARY_ATTEMPT_LIMIT,
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
    validate_canary_receipt(claim)
    try:
        descriptor = os.open(
            receipt_path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except FileExistsError as exc:
        raise Option1CanaryViolation("option1_canary_attempt_exhausted") from exc
    try:
        _write_all(descriptor, canonical_json(claim))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(runtime_root)
    return receipt_path, claim


def finalize_canary_attempt(
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
    validate_canary_receipt(claim)
    if claim.get("status") != "attempt_claimed":
        raise Option1CanaryViolation("option1_canary_claim_invalid")
    terminal = dict(claim)
    terminal["completed_at"] = _iso_now()
    terminal["delivery_started"] = delivery_started
    terminal["keychain_query_performed"] = keychain_query_performed
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
        ):
            raise Option1CanaryViolation("option1_canary_result_invalid")
        if set(connector_evidence) != set(_CONNECTOR_FIELDS) or not all(
            connector_evidence.get(field) is True for field in _CONNECTOR_FIELDS
        ):
            raise Option1CanaryViolation("option1_canary_connector_evidence_invalid")
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
        safe_failure = failure_code or "option1_canary_failed"
        if not _FAILURE_PATTERN.fullmatch(safe_failure):
            safe_failure = "option1_canary_failed"
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
    validate_canary_receipt(terminal)
    if SYNTHETIC_PREFIX in canonical_json(terminal):
        raise Option1CanaryViolation("option1_canary_material_returned")

    runtime_root = _private_runtime(receipt_path.parent)
    if receipt_path.parent.resolve(strict=True) != runtime_root:
        raise Option1CanaryViolation("option1_canary_receipt_path_invalid")
    current = load_canary_receipt(receipt_path)
    if current != claim:
        raise Option1CanaryViolation("option1_canary_claim_changed")
    temporary = runtime_root / CANARY_RECEIPT_NEXT_NAME
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        _write_all(descriptor, canonical_json(terminal))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, receipt_path)
    _fsync_directory(runtime_root)
    return terminal


def _digest(label: str) -> str:
    return hashlib.sha256(
        f"atlas-option1-qualification:{label}".encode("utf-8")
    ).hexdigest()


def _build_fixture_documents(now: datetime) -> tuple[
    ImmutablePolicyBundle,
    DataEgressManifest,
    CapabilityBindings,
    object,
    object,
    CredentialLeaseRequest,
    SyntheticOneUseChannelHandle,
    Ed25519OfflineSigner,
    Ed25519OfflineSigner,
    Ed25519OfflineSigner,
]:
    """Build the one registry-bound synthetic request without external inputs."""

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
        provider="offline-fixture-provider",
        model="offline-fixture-model",
        classification="synthetic_fictional_bounded",
        record_count=1,
        payload_bytes=128,
        max_payload_bytes=256,
        contains_private_data=False,
        contains_credentials=False,
    )
    if policy_bundle.sha256 != _FIXTURE_POLICY_SHA256 or egress.sha256 != _FIXTURE_EGRESS_SHA256:
        raise Option1CanaryViolation("option1_canary_fixture_drift")

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
        capability_id_sha256=_digest("capability:integration-canary"),
        task_sha256=egress.task_sha256,
        job_sha256=egress.job_sha256,
        project_sha256=_digest("project"),
        nonce_sha256=_digest("nonce:integration-canary"),
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
        policy_bundle,
        egress,
        bindings,
        capability,
        verification,
        request,
        channel,
        policy_signer,
        capability_receipt_signer,
        broker_signer,
    )


def _safe_failure_code(exc: Exception) -> str:
    candidate = getattr(exc, "code", None)
    if not isinstance(candidate, str):
        candidate = str(exc)
    return candidate if _FAILURE_PATTERN.fullmatch(candidate) else "option1_canary_failed"


def _scan_tree_for_material(root: Path, adapter: MacOSKeychainSyntheticVaultAdapter) -> bool:
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
    canary_runner_path: Path,
) -> dict[str, str]:
    if integration_report.get("integration_passed") is not True:
        raise Option1CanaryViolation("option1_canary_integration_review_failed")
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
        raise Option1CanaryViolation("option1_canary_integration_review_unsafe")
    if (
        integration_report.get("selected_vault") != "macos_login_keychain"
        or integration_report.get("selected_runtime_mode") != "on_demand_owner_private"
        or integration_report.get("vault_item_label_sha256") != VAULT_ITEM_LABEL_SHA256
    ):
        raise Option1CanaryViolation("option1_canary_integration_binding_invalid")
    if (
        integration_report.get("canary_launch_state") != "launch_claimed"
        or integration_report.get("canary_accounting_origin") != "prelaunch_claim"
        or integration_report.get("canary_attempt_state") != "not_attempted"
        or integration_report.get("canary_parent_error_code") is not None
        or not isinstance(
            integration_report.get("canary_launch_evidence_sha256"), str
        )
        or not _HASH_PATTERN.fullmatch(
            str(integration_report["canary_launch_evidence_sha256"])
        )
    ):
        raise Option1CanaryViolation("option1_canary_launch_claim_invalid")

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
        raise Option1CanaryViolation("option1_canary_supervisor_state_invalid")
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
        raise Option1CanaryViolation("option1_canary_live_control_open")
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
        raise Option1CanaryViolation("option1_canary_production_trust_present")

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
    runner_path = canary_runner_path.resolve(strict=True)
    registry_path = config.app.supervisor_v4_same_user_registry_file.resolve(strict=True)
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
        "canary_module_sha256": sha256_file(module_path),
        "canary_runner_sha256": sha256_file(runner_path),
        "registry_sha256": sha256_file(registry_path),
    }
    if (
        values["runtime_path_sha256"] != expected_runtime_sha256
        or any(
            not isinstance(value, str) or not _HASH_PATTERN.fullmatch(value)
            for value in values.values()
        )
    ):
        raise Option1CanaryViolation("option1_canary_integration_binding_invalid")
    return {key: str(value) for key, value in values.items()}


def run_option1_synthetic_integration_canary(
    *,
    config: AtlasConfig,
    runtime_root: Path,
    integration_report: Mapping[str, object],
    canary_runner_path: Path,
    confirmation: str,
    broker_process_network_guard_verified: bool,
    broker_process_parent_verified: bool,
) -> dict[str, object]:
    """Consume exactly one synthetic lease through Atlas's guarded broker seam."""

    if confirmation != CANARY_CONFIRMATION:
        raise Option1CanaryViolation("option1_canary_confirmation_invalid")
    if broker_process_network_guard_verified is not True:
        raise Option1CanaryViolation("option1_canary_network_guard_absent")
    if broker_process_parent_verified is not True:
        raise Option1CanaryViolation("option1_canary_parent_invalid")
    bindings = _validate_runtime_preflight(
        config,
        runtime_root,
        integration_report,
        canary_runner_path,
    )
    runtime_root = _private_runtime(runtime_root)
    helper_path = runtime_root / "atlas-option1-keychain-helper"
    adapter = MacOSKeychainSyntheticVaultAdapter(
        helper_path=helper_path,
        helper_sha256=bindings["helper_sha256"],
        join_current_process_group=True,
        use_network_sandbox=True,
    )
    registry = OwnerTaskRegistry.load(
        config.app.supervisor_v4_same_user_registry_file.resolve(strict=True)
    )
    if registry.task_count != 1 or registry.source_sha256 != bindings["registry_sha256"]:
        raise Option1CanaryViolation("option1_canary_registry_invalid")

    now = datetime.now(timezone.utc)
    (
        _policy_bundle,
        _egress,
        _capability_bindings,
        capability,
        verification,
        request,
        channel,
        policy_signer,
        capability_receipt_signer,
        broker_signer,
    ) = _build_fixture_documents(now)
    receipt_path, claim = claim_canary_attempt(
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
            raise Option1CanaryViolation("option1_canary_synthetic_item_unavailable")

        with tempfile.TemporaryDirectory(
            prefix=".integration-canary-state-", dir=runtime_root
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
                raise Option1CanaryViolation("option1_canary_material_persistence_detected")

        connector_evidence = {
            "connector_environment_scrubbed": delivery.environment_scrubbed,
            "connector_network_blocked": delivery.network_accessed is False,
            "connector_filesystem_write_blocked": (
                delivery.filesystem_write_allowed is False
            ),
            "connector_process_fork_blocked": delivery.process_fork_allowed is False,
            "connector_working_buffer_zeroized": (
                delivery.connector_working_buffer_zeroized
            ),
            "connector_process_group_reaped": delivery.process_teardown_verified,
            "connector_output_material_absent": delivery.material_returned is False,
        }
        terminal = finalize_canary_attempt(
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
        return terminal
    except Exception as exc:
        if state is not None:
            try:
                state.close()
            except Exception:
                pass
        code = _safe_failure_code(exc)
        try:
            finalize_canary_attempt(
                receipt_path,
                claim,
                passed=False,
                delivery_started=delivery_started,
                keychain_query_performed=keychain_query_performed,
                failure_code=code,
            )
        except Exception as finalize_exc:
            raise Option1CanaryViolation(
                "option1_canary_receipt_finalize_failed"
            ) from finalize_exc
        raise Option1CanaryViolation(code) from exc


__all__ = [
    "CANARY_ATTEMPT_LIMIT",
    "CANARY_CLASSIFICATION",
    "CANARY_CONFIRMATION",
    "CANARY_GATE_ID",
    "CANARY_LAUNCH_CLASSIFICATION",
    "CANARY_LAUNCH_LIMIT",
    "CANARY_LAUNCH_RECEIPT_NAME",
    "CANARY_LAUNCH_RECEIPT_NEXT_NAME",
    "CANARY_RECEIPT_NAME",
    "CANARY_RECEIPT_NEXT_NAME",
    "Option1CanaryViolation",
    "canonical_json",
    "claim_canary_attempt",
    "claim_canary_launch",
    "finalize_canary_attempt",
    "finalize_canary_launch",
    "inspect_canary_accounting",
    "load_canary_launch_receipt",
    "load_canary_receipt",
    "reconcile_failed_preclaim_launch",
    "run_option1_synthetic_integration_canary",
    "sha256_file",
    "validate_canary_launch_receipt",
    "validate_canary_receipt",
]
