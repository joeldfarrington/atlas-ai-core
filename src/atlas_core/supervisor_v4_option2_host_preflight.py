"""Bounded read-only Option 2 identity host preflight.

The only live operation in this module is a fixed, network-denied read of the
macOS local directory node.  Raw account and group names remain transient in
memory and are never returned or persisted.  The result is an inactive,
short-lived identity-only candidate; this module has no mutation operation.
"""

from __future__ import annotations

import hashlib
import json
import plistlib
import re
from uuid import UUID
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from atlas_core.supervisor_v4_option2_identity_candidate import (
    OPTION2_IDENTITY_CANDIDATE_AUTHORITY_FIELDS,
    OPTION2_IDENTITY_CANDIDATE_MAX_VALIDITY_SECONDS,
    OPTION2_SERVICE_IDENTITIES,
)
from atlas_core.supervisor_v4_option2_provisioner import (
    PRODUCTION_CONFIGURATION_FIELDS,
)
from atlas_core.supervisor_v4_process import (
    ProcessSupervisionError,
    SupervisedCompletedProcess,
    run_supervised,
)


OPTION2_HOST_PREFLIGHT_VERSION = 1
OPTION2_HOST_PREFLIGHT_CLASSIFICATION = (
    "option2_identity_only_local_host_preflight_candidate"
)
OPTION2_HOST_PREFLIGHT_STATE = "candidate_generated_inactive"
# Historical candidate-schema marker only.  The current service never returns
# this as a next gate and the phrase builder below is permanently retired.
OPTION2_HOST_PREFLIGHT_NEXT_GATE = (
    "owner_authorize_option2_service_identity_provisioning"
)
OPTION2_HOST_PREFLIGHT_RECOVERY_GATE = (
    "owner_review_option2_identity_only_host_preflight_recovery"
)
OPTION2_HOST_PREFLIGHT_SUBJECT = (
    "option2.identity-only-host-preflight.candidate.v1"
)
OPTION2_HOST_PREFLIGHT_CLAIM_SUBJECT = (
    "option2.identity-only-host-preflight.claim.v1"
)
OPTION2_HOST_PREFLIGHT_CLAIM_STATE = "read_only_preflight_claimed_inactive"
OPTION2_LOCAL_DIRECTORY_NODE = "/Local/Default"
OPTION2_HOST_NUMERIC_ID_RANGE = (400, 499)
OPTION2_HOST_INVENTORY_MAX_ENTITIES = 1_024
OPTION2_HOST_QUERY_COUNT = 4
OPTION2_HOST_QUERY_TIMEOUT_SECONDS = 5
OPTION2_HOST_QUERY_MAX_OUTPUT_BYTES = 1024 * 1024
OPTION2_HOST_QUERY_MAX_STDERR_BYTES = 16 * 1024
OPTION2_HOST_SANDBOX_PROFILE = (
    "(version 1)(allow default)(deny network*)(deny file-write*)"
    "(deny process-fork)"
)
OPTION2_HOST_SANDBOX_PROFILE_SHA256 = hashlib.sha256(
    OPTION2_HOST_SANDBOX_PROFILE.encode("utf-8")
).hexdigest()

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_RECORD_NAME_KEY = "RecordName"
_UNIQUE_ID_KEY = "UniqueID"
_PRIMARY_GROUP_ID_KEY = "PrimaryGroupID"
_ASSIGNMENT_FIELDS = {
    "name",
    "uid",
    "gid",
    "password_state",
    "hidden_account",
    "login_shell",
    "home_directory",
    "supplementary_groups",
}
_HOST_EFFECTS = {
    "effect_scope_sandboxed_directory_query_child": True,
    "account_namespace_queried": True,
    "group_namespace_queried": True,
    "host_inspected": True,
    "local_directory_read": True,
    "directory_service_ipc_performed": True,
    "subprocess_started": True,
    "network_accessed": False,
    "network_request_performed": False,
    "filesystem_written": False,
    "temporary_files_written": False,
    "accounts_created": False,
    "groups_created": False,
    "users_created": False,
    "access_permissions_changed": False,
    "admin_prompt_displayed": False,
    "background_service_installed": False,
    "keychain_opened": False,
    "keychain_queried": False,
    "launchd_contacted": False,
    "listening_service_socket_created": False,
    "credential_material_present": False,
    "private_identity_data_transiently_present": True,
    "private_data_present": True,
    "model_contacted": False,
    "provider_contacted": False,
}
_PRIVACY_CLAIMS = {
    "raw_inventory_persisted": False,
    "raw_inventory_returned": False,
    "unrelated_identity_names_persisted": False,
    "unrelated_identity_names_returned": False,
    "in_band_numeric_occupancy_inference_possible": True,
    "raw_host_identifier_persisted": False,
    "raw_host_identifier_returned": False,
    "authorization_challenge_persisted": False,
}


class Option2HostPreflightViolation(RuntimeError):
    """Raised when the read-only host preflight cannot prove an exact result."""


HostRunner = Callable[..., SupervisedCompletedProcess]


def _canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _sha256(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _validate_sha256(value: object, *, code: str) -> str:
    if (
        not isinstance(value, str)
        or _SHA256_PATTERN.fullmatch(value) is None
        or value == "0" * 64
    ):
        raise Option2HostPreflightViolation(code)
    return value


def _validate_uuid4(value: object, *, code: str) -> str:
    if not isinstance(value, str):
        raise Option2HostPreflightViolation(code)
    try:
        parsed = UUID(value)
    except ValueError as error:
        raise Option2HostPreflightViolation(code) from error
    if parsed.version != 4 or str(parsed) != value:
        raise Option2HostPreflightViolation(code)
    return value


def _normalize_lineage(
    *,
    generation: object,
    previous_candidate_sha256: object,
    supersession_reason: object,
) -> dict[str, object]:
    if (
        type(generation) is not int
        or generation < 1
        or generation > 10_000
        or (
            generation == 1
            and (
                previous_candidate_sha256 is not None
                or supersession_reason != "initial"
            )
        )
        or (
            generation > 1
            and (
                not isinstance(previous_candidate_sha256, str)
                or _SHA256_PATTERN.fullmatch(previous_candidate_sha256) is None
                or previous_candidate_sha256 == "0" * 64
                or supersession_reason not in {"expired", "stale"}
            )
        )
    ):
        raise Option2HostPreflightViolation(
            "option2_host_candidate_lineage_invalid"
        )
    return {
        "generation": generation,
        "previous_candidate_sha256": previous_candidate_sha256,
        "supersession_reason": supersession_reason,
    }


def _parse_timestamp(value: object, *, code: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise Option2HostPreflightViolation(code)
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as error:
        raise Option2HostPreflightViolation(code) from error
    if parsed.tzinfo is None or parsed.utcoffset() is None or parsed.microsecond:
        raise Option2HostPreflightViolation(code)
    return parsed.astimezone(timezone.utc)


def _canonical_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalize_window(*, issued_at: object, expires_at: object) -> tuple[str, str]:
    issued = _parse_timestamp(
        issued_at, code="option2_host_candidate_issued_at_invalid"
    )
    expires = _parse_timestamp(
        expires_at, code="option2_host_candidate_expires_at_invalid"
    )
    lifetime = (expires - issued).total_seconds()
    if lifetime <= 0 or lifetime > OPTION2_IDENTITY_CANDIDATE_MAX_VALIDITY_SECONDS:
        raise Option2HostPreflightViolation(
            "option2_host_candidate_validity_window_invalid"
        )
    return _canonical_timestamp(issued), _canonical_timestamp(expires)


def parse_option2_dscl_plist_projection(
    output: str,
    *,
    numeric_field: str,
) -> dict[str, object]:
    """Project one plist inventory to target-name and in-band ID facts only."""

    if numeric_field not in {"uid", "gid"}:
        raise Option2HostPreflightViolation(
            "option2_host_inventory_numeric_field_invalid"
        )
    if not isinstance(output, str) or not output or "\ufffd" in output:
        raise Option2HostPreflightViolation(
            "option2_host_inventory_output_invalid"
        )
    try:
        records = plistlib.loads(output.encode("utf-8"))
    except (ValueError, plistlib.InvalidFileException) as error:
        raise Option2HostPreflightViolation(
            "option2_host_inventory_plist_invalid"
        ) from error
    if (
        not isinstance(records, list)
        or not records
        or len(records) > OPTION2_HOST_INVENTORY_MAX_ENTITIES
    ):
        raise Option2HostPreflightViolation(
            "option2_host_inventory_record_count_invalid"
        )
    numeric_key = _UNIQUE_ID_KEY if numeric_field == "uid" else _PRIMARY_GROUP_ID_KEY
    target_names = {name.casefold(): name for name in OPTION2_SERVICE_IDENTITIES}
    present_targets: set[str] = set()
    occupied_in_band: set[int] = set()
    observed_aliases: set[str] = set()
    observed_numeric: set[int] = set()
    for record in records:
        if not isinstance(record, Mapping) or set(record) != {
            _RECORD_NAME_KEY,
            numeric_key,
        }:
            raise Option2HostPreflightViolation(
                "option2_host_inventory_record_schema_invalid"
            )
        aliases = record.get(_RECORD_NAME_KEY)
        numeric_values = record.get(numeric_key)
        if (
            not isinstance(aliases, list)
            or not aliases
            or len(aliases) > 16
            or not isinstance(numeric_values, list)
            or len(numeric_values) != 1
        ):
            raise Option2HostPreflightViolation(
                "option2_host_inventory_record_values_invalid"
            )
        numeric_text = numeric_values[0]
        if (
            not isinstance(numeric_text, str)
            or not numeric_text.isascii()
            or re.fullmatch(r"-?[0-9]{1,10}", numeric_text) is None
        ):
            raise Option2HostPreflightViolation(
                "option2_host_inventory_numeric_identity_invalid"
            )
        numeric_value = int(numeric_text)
        if (
            numeric_value < -2_147_483_648
            or numeric_value > 2_147_483_647
            or numeric_value in observed_numeric
        ):
            raise Option2HostPreflightViolation(
                "option2_host_inventory_numeric_identity_invalid"
            )
        observed_numeric.add(numeric_value)
        if (
            OPTION2_HOST_NUMERIC_ID_RANGE[0]
            <= numeric_value
            <= OPTION2_HOST_NUMERIC_ID_RANGE[1]
        ):
            occupied_in_band.add(numeric_value)
        for alias in aliases:
            if (
                not isinstance(alias, str)
                or not alias
                or len(alias.encode("utf-8")) > 255
                or any(ord(character) < 32 or ord(character) == 127 for character in alias)
                or "/" in alias
            ):
                raise Option2HostPreflightViolation(
                    "option2_host_inventory_record_name_invalid"
                )
            folded = alias.casefold()
            if folded in observed_aliases:
                raise Option2HostPreflightViolation(
                    "option2_host_inventory_alias_duplicate"
                )
            observed_aliases.add(folded)
            if folded in target_names:
                present_targets.add(target_names[folded])
    return {
        "target_names_present": sorted(
            present_targets, key=OPTION2_SERVICE_IDENTITIES.index
        ),
        "occupied_numeric_ids": sorted(occupied_in_band),
    }


def _inventory_document(
    *, user_projection: Mapping[str, object], group_projection: Mapping[str, object]
) -> dict[str, object]:
    users = _normalize_projection(user_projection)
    groups = _normalize_projection(group_projection)
    return {
        "version": 1,
        "classification": "option2_minimized_local_identity_projection",
        "directory_node": OPTION2_LOCAL_DIRECTORY_NODE,
        "allocation_band": list(OPTION2_HOST_NUMERIC_ID_RANGE),
        "user_target_names_present": deepcopy(
            users["target_names_present"]
        ),
        "group_target_names_present": deepcopy(
            groups["target_names_present"]
        ),
        "occupied_numeric_ids": sorted(
            {
                *users["occupied_numeric_ids"],
                *groups["occupied_numeric_ids"],
            }
        ),
    }


def _normalize_projection(value: Mapping[str, object]) -> dict[str, list[object]]:
    if not isinstance(value, Mapping) or set(value) != {
        "target_names_present",
        "occupied_numeric_ids",
    }:
        raise Option2HostPreflightViolation(
            "option2_host_inventory_projection_invalid"
        )
    names = value.get("target_names_present")
    numeric = value.get("occupied_numeric_ids")
    if (
        not isinstance(names, list)
        or any(name not in OPTION2_SERVICE_IDENTITIES for name in names)
        or names != sorted(set(names), key=OPTION2_SERVICE_IDENTITIES.index)
        or not isinstance(numeric, list)
        or any(type(item) is not int for item in numeric)
        or any(
            item < OPTION2_HOST_NUMERIC_ID_RANGE[0]
            or item > OPTION2_HOST_NUMERIC_ID_RANGE[1]
            for item in numeric
        )
        or numeric != sorted(set(numeric))
    ):
        raise Option2HostPreflightViolation(
            "option2_host_inventory_projection_invalid"
        )
    return {
        "target_names_present": list(names),
        "occupied_numeric_ids": list(numeric),
    }


def option2_host_inventory_sha256(
    *, user_projection: Mapping[str, object], group_projection: Mapping[str, object]
) -> str:
    """Hash only the fixed-name and in-band numeric projection."""

    return _sha256(
        _inventory_document(
            user_projection=user_projection,
            group_projection=group_projection,
        )
    )


def _select_numeric_identities(
    occupied: set[int], *, bounds: tuple[int, int], code: str
) -> list[int]:
    selected = [
        value
        for value in range(bounds[1], bounds[0] - 1, -1)
        if value not in occupied
    ][: len(OPTION2_SERVICE_IDENTITIES)]
    if len(selected) != len(OPTION2_SERVICE_IDENTITIES):
        raise Option2HostPreflightViolation(code)
    return selected


def propose_option2_host_assignments(
    *, user_projection: Mapping[str, object], group_projection: Mapping[str, object]
) -> list[dict[str, object]]:
    """Choose deterministic free IDs while rejecting target-name collisions."""

    users = _normalize_projection(user_projection)
    groups = _normalize_projection(group_projection)
    present_names = {
        *users["target_names_present"],
        *groups["target_names_present"],
    }
    if present_names:
        raise Option2HostPreflightViolation(
            "option2_host_candidate_target_name_collision"
        )
    occupied = {
        *users["occupied_numeric_ids"],
        *groups["occupied_numeric_ids"],
    }
    numeric_identities = _select_numeric_identities(
        occupied,
        bounds=OPTION2_HOST_NUMERIC_ID_RANGE,
        code="option2_host_candidate_numeric_range_exhausted",
    )
    return [
        {
            "name": name,
            "uid": numeric_identities[index],
            "gid": numeric_identities[index],
            "password_state": "locked",
            "hidden_account": True,
            "login_shell": "/usr/bin/false",
            "home_directory": "/var/empty",
            "supplementary_groups": [],
        }
        for index, name in enumerate(OPTION2_SERVICE_IDENTITIES)
    ]


def _validate_assignments(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) != len(OPTION2_SERVICE_IDENTITIES):
        raise Option2HostPreflightViolation(
            "option2_host_candidate_assignments_invalid"
        )
    assignments: list[dict[str, object]] = []
    for expected_name, item in zip(OPTION2_SERVICE_IDENTITIES, value, strict=True):
        if not isinstance(item, Mapping) or set(item) != _ASSIGNMENT_FIELDS:
            raise Option2HostPreflightViolation(
                "option2_host_candidate_assignment_schema_invalid"
            )
        if (
            item.get("name") != expected_name
            or type(item.get("uid")) is not int
            or type(item.get("gid")) is not int
            or not OPTION2_HOST_NUMERIC_ID_RANGE[0]
            <= int(item["uid"])
            <= OPTION2_HOST_NUMERIC_ID_RANGE[1]
            or not OPTION2_HOST_NUMERIC_ID_RANGE[0]
            <= int(item["gid"])
            <= OPTION2_HOST_NUMERIC_ID_RANGE[1]
            or item.get("uid") != item.get("gid")
            or item.get("password_state") != "locked"
            or item.get("hidden_account") is not True
            or item.get("login_shell") != "/usr/bin/false"
            or item.get("home_directory") != "/var/empty"
            or item.get("supplementary_groups") != []
        ):
            raise Option2HostPreflightViolation(
                "option2_host_candidate_assignment_invalid"
            )
        assignments.append(deepcopy(dict(item)))
    if len({item["uid"] for item in assignments}) != len(assignments) or len(
        {item["gid"] for item in assignments}
    ) != len(assignments):
        raise Option2HostPreflightViolation(
            "option2_host_candidate_assignment_duplicate"
        )
    return assignments


def _binding_document(
    *,
    reviewed_manifest_sha256: str,
    manifest_review_content_sha256: str,
    fixture_qualification_content_sha256: str,
    sdk_lock_sha256: str,
    policy_sha256: str,
    host_preflight_source_sha256: str,
    host_instance_sha256: str,
    dscl_sha256: str,
    sandbox_exec_sha256: str,
    sandbox_profile_sha256: str,
) -> dict[str, str]:
    values = {
        "reviewed_manifest_sha256": reviewed_manifest_sha256,
        "manifest_review_content_sha256": manifest_review_content_sha256,
        "fixture_qualification_content_sha256": (
            fixture_qualification_content_sha256
        ),
        "sdk_lock_sha256": sdk_lock_sha256,
        "policy_sha256": policy_sha256,
        "host_preflight_source_sha256": host_preflight_source_sha256,
        "host_instance_sha256": host_instance_sha256,
        "dscl_sha256": dscl_sha256,
        "sandbox_exec_sha256": sandbox_exec_sha256,
        "sandbox_profile_sha256": sandbox_profile_sha256,
    }
    return {
        key: _validate_sha256(
            value, code=f"option2_host_candidate_{key}_invalid"
        )
        for key, value in values.items()
    }


def _validate_binding_document(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise Option2HostPreflightViolation(
            "option2_host_candidate_bindings_invalid"
        )
    expected = {
        "reviewed_manifest_sha256",
        "manifest_review_content_sha256",
        "fixture_qualification_content_sha256",
        "sdk_lock_sha256",
        "policy_sha256",
        "host_preflight_source_sha256",
        "host_instance_sha256",
        "dscl_sha256",
        "sandbox_exec_sha256",
        "sandbox_profile_sha256",
    }
    if set(value) != expected:
        raise Option2HostPreflightViolation(
            "option2_host_candidate_bindings_invalid"
        )
    return {
        field: _validate_sha256(
            value.get(field), code=f"option2_host_candidate_{field}_invalid"
        )
        for field in expected
    }


def _claim_body(
    *,
    bindings: Mapping[str, str],
    authorization_challenge_sha256: str,
    issued_at: str,
    expires_at: str,
    lineage: Mapping[str, object],
) -> dict[str, object]:
    return {
        "version": OPTION2_HOST_PREFLIGHT_VERSION,
        "classification": "option2_identity_only_host_preflight_one_use_claim",
        "claim_state": OPTION2_HOST_PREFLIGHT_CLAIM_STATE,
        "bindings": dict(bindings),
        "lineage": dict(lineage),
        "authorization_challenge_sha256": authorization_challenge_sha256,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "max_validity_seconds": OPTION2_IDENTITY_CANDIDATE_MAX_VALIDITY_SECONDS,
        "preflight_attempt_limit": 1,
        "inventory_snapshot_limit": 2,
        "directory_query_limit": OPTION2_HOST_QUERY_COUNT,
        "candidate_limit": 1,
        "local_directory_node": OPTION2_LOCAL_DIRECTORY_NODE,
        "host_inventory_read_authorized": True,
        "approval_evidence_scope": (
            "local_process_invocation_not_authenticated_owner_signature"
        ),
        "automatic_runtime_route_present": False,
        "repeat_invocation_not_cryptographically_gated": True,
        "identity_mutation_authorized": False,
        "host_inspected": False,
        "raw_inventory_persisted": False,
        "authorization_challenge_persisted": False,
        "authority": {
            field: False for field in OPTION2_IDENTITY_CANDIDATE_AUTHORITY_FIELDS
        },
        "ready": False,
        "ready_offline": False,
        "ready_live": False,
        "next_internal_milestone": "option2_identity_only_host_preflight",
    }


def build_option2_host_preflight_claim(
    *,
    authorization_challenge: str,
    reviewed_manifest_sha256: str,
    manifest_review_content_sha256: str,
    fixture_qualification_content_sha256: str,
    sdk_lock_sha256: str,
    policy_sha256: str,
    host_preflight_source_sha256: str,
    host_instance_sha256: str,
    dscl_sha256: str,
    sandbox_exec_sha256: str,
    sandbox_profile_sha256: str,
    issued_at: str,
    expires_at: str,
    generation: int = 1,
    previous_candidate_sha256: str | None = None,
    supersession_reason: str = "initial",
) -> dict[str, object]:
    """Build the one-use append-only claim that must precede a host query."""

    if (
        not isinstance(authorization_challenge, str)
        or re.fullmatch(r"[0-9a-f]{32}", authorization_challenge) is None
    ):
        raise Option2HostPreflightViolation(
            "option2_host_authorization_challenge_invalid"
        )
    issued, expires = _normalize_window(issued_at=issued_at, expires_at=expires_at)
    bindings = _binding_document(
        reviewed_manifest_sha256=reviewed_manifest_sha256,
        manifest_review_content_sha256=manifest_review_content_sha256,
        fixture_qualification_content_sha256=(
            fixture_qualification_content_sha256
        ),
        sdk_lock_sha256=sdk_lock_sha256,
        policy_sha256=policy_sha256,
        host_preflight_source_sha256=host_preflight_source_sha256,
        host_instance_sha256=host_instance_sha256,
        dscl_sha256=dscl_sha256,
        sandbox_exec_sha256=sandbox_exec_sha256,
        sandbox_profile_sha256=sandbox_profile_sha256,
    )
    lineage = _normalize_lineage(
        generation=generation,
        previous_candidate_sha256=previous_candidate_sha256,
        supersession_reason=supersession_reason,
    )
    body = _claim_body(
        bindings=bindings,
        authorization_challenge_sha256=hashlib.sha256(
            authorization_challenge.encode("ascii")
        ).hexdigest(),
        issued_at=issued,
        expires_at=expires,
        lineage=lineage,
    )
    claim = {**body, "claim_sha256": _sha256(body)}
    validate_option2_host_preflight_claim(claim)
    return claim


def validate_option2_host_preflight_claim(claim: Mapping[str, Any]) -> None:
    """Validate one immutable query claim without inspecting the host."""

    if not isinstance(claim, Mapping):
        raise Option2HostPreflightViolation("option2_host_claim_invalid")
    body = {
        key: deepcopy(value) for key, value in claim.items() if key != "claim_sha256"
    }
    if claim.get("claim_sha256") != _sha256(body):
        raise Option2HostPreflightViolation("option2_host_claim_digest_invalid")
    bindings = _validate_binding_document(body.get("bindings"))
    lineage_value = body.get("lineage")
    if not isinstance(lineage_value, Mapping):
        raise Option2HostPreflightViolation("option2_host_claim_lineage_invalid")
    lineage = _normalize_lineage(
        generation=lineage_value.get("generation"),
        previous_candidate_sha256=lineage_value.get(
            "previous_candidate_sha256"
        ),
        supersession_reason=lineage_value.get("supersession_reason"),
    )
    issued, expires = _normalize_window(
        issued_at=body.get("issued_at"), expires_at=body.get("expires_at")
    )
    challenge_sha256 = _validate_sha256(
        body.get("authorization_challenge_sha256"),
        code="option2_host_claim_challenge_invalid",
    )
    expected = _claim_body(
        bindings=bindings,
        authorization_challenge_sha256=challenge_sha256,
        issued_at=issued,
        expires_at=expires,
        lineage=lineage,
    )
    if body != expected:
        raise Option2HostPreflightViolation("option2_host_claim_contract_invalid")


def _candidate_body(
    *,
    inventory_sha256: str,
    assignments: Sequence[Mapping[str, object]],
    authorization_challenge_sha256: str,
    reviewed_manifest_sha256: str,
    manifest_review_content_sha256: str,
    fixture_qualification_content_sha256: str,
    sdk_lock_sha256: str,
    policy_sha256: str,
    host_preflight_source_sha256: str,
    host_instance_sha256: str,
    dscl_sha256: str,
    sandbox_exec_sha256: str,
    sandbox_profile_sha256: str,
    preflight_claim_id: str,
    preflight_claim_sha256: str,
    issued_at: str,
    expires_at: str,
    generation: int,
    previous_candidate_sha256: str | None,
    supersession_reason: str,
) -> dict[str, object]:
    bindings = {
        "reviewed_manifest_sha256": reviewed_manifest_sha256,
        "manifest_review_content_sha256": manifest_review_content_sha256,
        "fixture_qualification_content_sha256": (
            fixture_qualification_content_sha256
        ),
        "sdk_lock_sha256": sdk_lock_sha256,
        "policy_sha256": policy_sha256,
        "host_preflight_source_sha256": host_preflight_source_sha256,
        "host_instance_sha256": host_instance_sha256,
        "dscl_sha256": dscl_sha256,
        "sandbox_exec_sha256": sandbox_exec_sha256,
        "sandbox_profile_sha256": sandbox_profile_sha256,
    }
    host_binding_sha256 = _sha256(
        {
            "directory_node": OPTION2_LOCAL_DIRECTORY_NODE,
            "inventory_sha256": inventory_sha256,
            "bindings": bindings,
        }
    )
    return {
        "version": OPTION2_HOST_PREFLIGHT_VERSION,
        "classification": OPTION2_HOST_PREFLIGHT_CLASSIFICATION,
        "preflight_state": OPTION2_HOST_PREFLIGHT_STATE,
        "candidate_state": "host_specific_identity_only_inactive",
        "candidate_scope": "six_service_users_and_matching_groups_only",
        "candidate_complete": True,
        "candidate_completion_scope": "local_directory_assignment_only",
        "candidate_complete_for_host_mutation": False,
        "host_specific": True,
        "host_binding_scope": (
            "local_installation_filesystem_identity_not_hardware_attestation"
        ),
        "directory_node": OPTION2_LOCAL_DIRECTORY_NODE,
        "inventory_sha256": inventory_sha256,
        "host_binding_sha256": host_binding_sha256,
        "bindings": bindings,
        "preflight_claim_id": preflight_claim_id,
        "preflight_claim_sha256": preflight_claim_sha256,
        "preflight_claim_consumed": True,
        "lineage": {
            "generation": generation,
            "previous_candidate_sha256": previous_candidate_sha256,
            "supersession_reason": supersession_reason,
        },
        "assignments": deepcopy(list(assignments)),
        "numeric_identity_candidate_range": list(OPTION2_HOST_NUMERIC_ID_RANGE),
        "issued_at": issued_at,
        "expires_at": expires_at,
        "max_validity_seconds": OPTION2_IDENTITY_CANDIDATE_MAX_VALIDITY_SECONDS,
        "authorization_challenge_sha256": authorization_challenge_sha256,
        "authorization_challenge_persisted": False,
        "authorization_one_use_required": True,
        "inventory_recheck_immediately_before_mutation_required": True,
        "source_recheck_immediately_before_mutation_required": True,
        "effective_search_path_collision_check_required_before_mutation": True,
        "effective_search_path_collision_check_performed": False,
        "filesystem_ownership_reuse_check_required_before_mutation": True,
        "filesystem_ownership_reuse_check_performed": False,
        "owner_pause_latched": True,
        "owner_pause_basis": "identity_mutation_route_absent_and_authorization_closed",
        "query_count": OPTION2_HOST_QUERY_COUNT,
        "second_inventory_read_matched": True,
        "network_denial_enforced": True,
        "filesystem_write_denial_enforced": True,
        "raw_inventory_persisted": False,
        "raw_inventory_returned": False,
        "privacy": dict(_PRIVACY_CLAIMS),
        "production_configuration": {
            field: None for field in PRODUCTION_CONFIGURATION_FIELDS
        },
        "production_manifest_complete": False,
        "host_preflight_required": True,
        "host_preflight_performed": True,
        "host_apply_present": False,
        "operation_allowlist": [
            "create_exact_service_group",
            "create_exact_service_user",
        ],
        "authority": {
            field: False for field in OPTION2_IDENTITY_CANDIDATE_AUTHORITY_FIELDS
        },
        "effects": dict(_HOST_EFFECTS),
        "ready": False,
        "ready_offline": False,
        "ready_live": False,
        "next_gate": OPTION2_HOST_PREFLIGHT_NEXT_GATE,
    }


def build_option2_host_candidate(
    *,
    user_projection: Mapping[str, object],
    group_projection: Mapping[str, object],
    authorization_challenge: str,
    reviewed_manifest_sha256: str,
    manifest_review_content_sha256: str,
    fixture_qualification_content_sha256: str,
    sdk_lock_sha256: str,
    policy_sha256: str,
    host_preflight_source_sha256: str,
    host_instance_sha256: str,
    dscl_sha256: str,
    sandbox_exec_sha256: str,
    sandbox_profile_sha256: str,
    preflight_claim_id: str,
    preflight_claim_sha256: str,
    issued_at: str,
    expires_at: str,
    generation: int = 1,
    previous_candidate_sha256: str | None = None,
    supersession_reason: str = "initial",
) -> dict[str, object]:
    """Build one inactive candidate while discarding unrelated names."""

    if (
        not isinstance(authorization_challenge, str)
        or re.fullmatch(r"[0-9a-f]{32}", authorization_challenge) is None
    ):
        raise Option2HostPreflightViolation(
            "option2_host_authorization_challenge_invalid"
        )
    inventory_sha256 = option2_host_inventory_sha256(
        user_projection=user_projection,
        group_projection=group_projection,
    )
    assignments = propose_option2_host_assignments(
        user_projection=user_projection,
        group_projection=group_projection,
    )
    issued, expires = _normalize_window(issued_at=issued_at, expires_at=expires_at)
    lineage = _normalize_lineage(
        generation=generation,
        previous_candidate_sha256=previous_candidate_sha256,
        supersession_reason=supersession_reason,
    )
    bindings = _binding_document(
        reviewed_manifest_sha256=reviewed_manifest_sha256,
        manifest_review_content_sha256=manifest_review_content_sha256,
        fixture_qualification_content_sha256=(
            fixture_qualification_content_sha256
        ),
        sdk_lock_sha256=sdk_lock_sha256,
        policy_sha256=policy_sha256,
        host_preflight_source_sha256=host_preflight_source_sha256,
        host_instance_sha256=host_instance_sha256,
        dscl_sha256=dscl_sha256,
        sandbox_exec_sha256=sandbox_exec_sha256,
        sandbox_profile_sha256=sandbox_profile_sha256,
    )
    claim_id = _validate_uuid4(
        preflight_claim_id, code="option2_host_candidate_claim_id_invalid"
    )
    claim_sha256 = _validate_sha256(
        preflight_claim_sha256,
        code="option2_host_candidate_claim_digest_invalid",
    )
    body = _candidate_body(
        inventory_sha256=inventory_sha256,
        assignments=assignments,
        authorization_challenge_sha256=hashlib.sha256(
            authorization_challenge.encode("ascii")
        ).hexdigest(),
        issued_at=issued,
        expires_at=expires,
        generation=int(lineage["generation"]),
        previous_candidate_sha256=lineage["previous_candidate_sha256"],
        supersession_reason=str(lineage["supersession_reason"]),
        preflight_claim_id=claim_id,
        preflight_claim_sha256=claim_sha256,
        **bindings,
    )
    candidate = {**body, "candidate_sha256": _sha256(body)}
    validate_option2_host_candidate(candidate)
    return candidate


def validate_option2_host_candidate(
    candidate: Mapping[str, Any],
    *,
    observed_at: str | None = None,
) -> None:
    """Validate the exact candidate shape and optionally require it be active."""

    if not isinstance(candidate, Mapping):
        raise Option2HostPreflightViolation(
            "option2_host_candidate_invalid"
        )
    body = {
        key: deepcopy(value)
        for key, value in candidate.items()
        if key != "candidate_sha256"
    }
    if candidate.get("candidate_sha256") != _sha256(body):
        raise Option2HostPreflightViolation(
            "option2_host_candidate_digest_invalid"
        )
    expected_keys = set(
        _candidate_body(
            inventory_sha256="1" * 64,
            assignments=[],
            authorization_challenge_sha256="2" * 64,
            reviewed_manifest_sha256="3" * 64,
            manifest_review_content_sha256="4" * 64,
            fixture_qualification_content_sha256="5" * 64,
            sdk_lock_sha256="6" * 64,
            policy_sha256="7" * 64,
            host_preflight_source_sha256="8" * 64,
            host_instance_sha256="9" * 64,
            dscl_sha256="a" * 64,
            sandbox_exec_sha256="b" * 64,
            sandbox_profile_sha256="c" * 64,
            preflight_claim_id="11111111-1111-4111-8111-111111111111",
            preflight_claim_sha256="d" * 64,
            issued_at="2026-01-01T00:00:00Z",
            expires_at="2026-01-01T00:01:00Z",
            generation=1,
            previous_candidate_sha256=None,
            supersession_reason="initial",
        )
    )
    if set(body) != expected_keys:
        raise Option2HostPreflightViolation(
            "option2_host_candidate_schema_invalid"
        )
    issued, expires = _normalize_window(
        issued_at=body.get("issued_at"), expires_at=body.get("expires_at")
    )
    if body.get("issued_at") != issued or body.get("expires_at") != expires:
        raise Option2HostPreflightViolation(
            "option2_host_candidate_timestamp_not_canonical"
        )
    for field in (
        "inventory_sha256",
        "host_binding_sha256",
        "authorization_challenge_sha256",
        "preflight_claim_sha256",
    ):
        _validate_sha256(
            body.get(field), code=f"option2_host_candidate_{field}_invalid"
        )
    bindings = body.get("bindings")
    lineage = body.get("lineage")
    bindings = _validate_binding_document(bindings)
    if not isinstance(lineage, Mapping):
        raise Option2HostPreflightViolation(
            "option2_host_candidate_lineage_invalid"
        )
    normalized_lineage = _normalize_lineage(
        generation=lineage.get("generation"),
        previous_candidate_sha256=lineage.get("previous_candidate_sha256"),
        supersession_reason=lineage.get("supersession_reason"),
    )
    if dict(lineage) != normalized_lineage:
        raise Option2HostPreflightViolation(
            "option2_host_candidate_lineage_invalid"
        )
    _validate_uuid4(
        body.get("preflight_claim_id"),
        code="option2_host_candidate_claim_id_invalid",
    )
    expected_host_binding = _sha256(
        {
            "directory_node": OPTION2_LOCAL_DIRECTORY_NODE,
            "inventory_sha256": body["inventory_sha256"],
            "bindings": dict(bindings),
        }
    )
    if body.get("host_binding_sha256") != expected_host_binding:
        raise Option2HostPreflightViolation(
            "option2_host_candidate_binding_digest_invalid"
        )
    assignments = _validate_assignments(body.get("assignments"))
    if body.get("assignments") != assignments:
        raise Option2HostPreflightViolation(
            "option2_host_candidate_assignments_not_canonical"
        )
    production = body.get("production_configuration")
    authority = body.get("authority")
    effects = body.get("effects")
    privacy = body.get("privacy")
    if (
        not isinstance(production, Mapping)
        or set(production) != set(PRODUCTION_CONFIGURATION_FIELDS)
        or any(production[field] is not None for field in PRODUCTION_CONFIGURATION_FIELDS)
        or not isinstance(authority, Mapping)
        or set(authority) != set(OPTION2_IDENTITY_CANDIDATE_AUTHORITY_FIELDS)
        or any(authority[field] is not False for field in authority)
        or effects != _HOST_EFFECTS
        or privacy != _PRIVACY_CLAIMS
    ):
        raise Option2HostPreflightViolation(
            "option2_host_candidate_authority_effect_or_privacy_invalid"
        )
    fixed = {
        "version": OPTION2_HOST_PREFLIGHT_VERSION,
        "classification": OPTION2_HOST_PREFLIGHT_CLASSIFICATION,
        "preflight_state": OPTION2_HOST_PREFLIGHT_STATE,
        "candidate_state": "host_specific_identity_only_inactive",
        "candidate_scope": "six_service_users_and_matching_groups_only",
        "candidate_complete": True,
        "candidate_completion_scope": "local_directory_assignment_only",
        "candidate_complete_for_host_mutation": False,
        "host_specific": True,
        "host_binding_scope": (
            "local_installation_filesystem_identity_not_hardware_attestation"
        ),
        "directory_node": OPTION2_LOCAL_DIRECTORY_NODE,
        "numeric_identity_candidate_range": list(OPTION2_HOST_NUMERIC_ID_RANGE),
        "max_validity_seconds": OPTION2_IDENTITY_CANDIDATE_MAX_VALIDITY_SECONDS,
        "authorization_challenge_persisted": False,
        "preflight_claim_consumed": True,
        "authorization_one_use_required": True,
        "inventory_recheck_immediately_before_mutation_required": True,
        "source_recheck_immediately_before_mutation_required": True,
        "effective_search_path_collision_check_required_before_mutation": True,
        "effective_search_path_collision_check_performed": False,
        "filesystem_ownership_reuse_check_required_before_mutation": True,
        "filesystem_ownership_reuse_check_performed": False,
        "owner_pause_latched": True,
        "owner_pause_basis": "identity_mutation_route_absent_and_authorization_closed",
        "query_count": OPTION2_HOST_QUERY_COUNT,
        "second_inventory_read_matched": True,
        "network_denial_enforced": True,
        "filesystem_write_denial_enforced": True,
        "raw_inventory_persisted": False,
        "raw_inventory_returned": False,
        "production_manifest_complete": False,
        "host_preflight_required": True,
        "host_preflight_performed": True,
        "host_apply_present": False,
        "operation_allowlist": [
            "create_exact_service_group",
            "create_exact_service_user",
        ],
        "ready": False,
        "ready_offline": False,
        "ready_live": False,
        "next_gate": OPTION2_HOST_PREFLIGHT_NEXT_GATE,
    }
    if any(body.get(key) != value for key, value in fixed.items()):
        raise Option2HostPreflightViolation(
            "option2_host_candidate_boundary_invalid"
        )
    if observed_at is not None:
        observed = _parse_timestamp(
            observed_at, code="option2_host_candidate_observed_at_invalid"
        )
        if observed < _parse_timestamp(issued, code="invalid") or observed >= _parse_timestamp(
            expires, code="invalid"
        ):
            raise Option2HostPreflightViolation(
                "option2_host_candidate_expired"
            )


def build_option2_identity_provisioning_authorization_phrase(
    *,
    candidate: Mapping[str, Any],
    authorization_challenge: str,
    observed_at: str,
) -> str:
    """Reject generation of the retired legacy mutation phrase."""

    del candidate, authorization_challenge, observed_at
    raise Option2HostPreflightViolation(
        "option2_host_legacy_authorization_gate_retired"
    )


def _run_dscl_listing(
    *,
    record_path: str,
    attribute: str,
    sandbox_exec_path: Path,
    dscl_path: Path,
    cwd: Path,
    pause_file: Path | None,
    runner: HostRunner,
) -> str:
    argv = [
        str(sandbox_exec_path),
        "-p",
        OPTION2_HOST_SANDBOX_PROFILE,
        str(dscl_path),
        "-q",
        "-plist",
        OPTION2_LOCAL_DIRECTORY_NODE,
        "-readall",
        record_path,
        "RecordName",
        attribute,
    ]
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/var/empty",
        "TMPDIR": "/var/empty",
        "LANG": "C",
        "LC_ALL": "C",
    }
    try:
        completed = runner(
            argv,
            cwd=cwd,
            timeout=OPTION2_HOST_QUERY_TIMEOUT_SECONDS,
            env=environment,
            pause_file=pause_file,
            max_output_bytes=OPTION2_HOST_QUERY_MAX_OUTPUT_BYTES,
            max_stderr_bytes=OPTION2_HOST_QUERY_MAX_STDERR_BYTES,
            process_fork_denied=True,
        )
    except ProcessSupervisionError as error:
        raise Option2HostPreflightViolation(
            f"option2_host_inventory_query_stopped:{error.code}"
        ) from error
    if (
        completed.args != tuple(argv)
        or completed.returncode != 0
        or completed.process_group_reaped is not True
        or completed.stderr != ""
    ):
        raise Option2HostPreflightViolation(
            "option2_host_inventory_query_failed"
        )
    return completed.stdout


def perform_option2_identity_only_host_preflight(
    *,
    authorization_challenge: str,
    reviewed_manifest_sha256: str,
    manifest_review_content_sha256: str,
    fixture_qualification_content_sha256: str,
    sdk_lock_sha256: str,
    policy_sha256: str,
    host_preflight_source_sha256: str,
    host_instance_sha256: str,
    dscl_sha256: str,
    sandbox_exec_sha256: str,
    sandbox_profile_sha256: str,
    preflight_claim_id: str,
    preflight_claim_sha256: str,
    issued_at: str,
    expires_at: str,
    sandbox_exec_path: Path = Path("/usr/bin/sandbox-exec"),
    dscl_path: Path = Path("/usr/bin/dscl"),
    cwd: Path = Path("/var/empty"),
    pause_file: Path | None = None,
    runner: HostRunner = run_supervised,
    generation: int = 1,
    previous_candidate_sha256: str | None = None,
    supersession_reason: str = "initial",
) -> dict[str, object]:
    """Read the local identity namespace twice and build one exact candidate."""

    snapshots: list[tuple[dict[str, object], dict[str, object]]] = []
    for _index in range(2):
        users = parse_option2_dscl_plist_projection(
            _run_dscl_listing(
                record_path="/Users",
                attribute="UniqueID",
                sandbox_exec_path=sandbox_exec_path,
                dscl_path=dscl_path,
                cwd=cwd,
                pause_file=pause_file,
                runner=runner,
            ),
            numeric_field="uid",
        )
        groups = parse_option2_dscl_plist_projection(
            _run_dscl_listing(
                record_path="/Groups",
                attribute="PrimaryGroupID",
                sandbox_exec_path=sandbox_exec_path,
                dscl_path=dscl_path,
                cwd=cwd,
                pause_file=pause_file,
                runner=runner,
            ),
            numeric_field="gid",
        )
        snapshots.append((users, groups))
    if snapshots[0] != snapshots[1]:
        raise Option2HostPreflightViolation(
            "option2_host_inventory_changed_during_preflight"
        )
    user_projection, group_projection = snapshots[1]
    candidate = build_option2_host_candidate(
        user_projection=user_projection,
        group_projection=group_projection,
        authorization_challenge=authorization_challenge,
        reviewed_manifest_sha256=reviewed_manifest_sha256,
        manifest_review_content_sha256=manifest_review_content_sha256,
        fixture_qualification_content_sha256=(
            fixture_qualification_content_sha256
        ),
        sdk_lock_sha256=sdk_lock_sha256,
        policy_sha256=policy_sha256,
        host_preflight_source_sha256=host_preflight_source_sha256,
        host_instance_sha256=host_instance_sha256,
        dscl_sha256=dscl_sha256,
        sandbox_exec_sha256=sandbox_exec_sha256,
        sandbox_profile_sha256=sandbox_profile_sha256,
        preflight_claim_id=preflight_claim_id,
        preflight_claim_sha256=preflight_claim_sha256,
        issued_at=issued_at,
        expires_at=expires_at,
        generation=generation,
        previous_candidate_sha256=previous_candidate_sha256,
        supersession_reason=supersession_reason,
    )
    # Explicitly discard the only structures that contain unrelated names
    # before returning the privacy-minimized candidate.
    snapshots.clear()
    user_projection.clear()
    group_projection.clear()
    return candidate


__all__ = [
    "OPTION2_HOST_NUMERIC_ID_RANGE",
    "OPTION2_HOST_PREFLIGHT_CLASSIFICATION",
    "OPTION2_HOST_PREFLIGHT_CLAIM_STATE",
    "OPTION2_HOST_PREFLIGHT_CLAIM_SUBJECT",
    "OPTION2_HOST_PREFLIGHT_NEXT_GATE",
    "OPTION2_HOST_PREFLIGHT_RECOVERY_GATE",
    "OPTION2_HOST_PREFLIGHT_STATE",
    "OPTION2_HOST_PREFLIGHT_SUBJECT",
    "OPTION2_HOST_SANDBOX_PROFILE_SHA256",
    "Option2HostPreflightViolation",
    "build_option2_host_candidate",
    "build_option2_host_preflight_claim",
    "build_option2_identity_provisioning_authorization_phrase",
    "option2_host_inventory_sha256",
    "parse_option2_dscl_plist_projection",
    "perform_option2_identity_only_host_preflight",
    "propose_option2_host_assignments",
    "validate_option2_host_candidate",
    "validate_option2_host_preflight_claim",
]
