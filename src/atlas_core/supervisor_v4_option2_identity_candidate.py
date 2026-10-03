"""Pure Option 2 identity-candidate qualification.

This module accepts caller-supplied synthetic values and transforms only
in-memory data.  It deliberately has no host executor and does not inspect an
account database, filesystem, Keychain, socket, launchd, process, network, or
model.  A qualified result remains inactive and advances only to owner review
of a later, identity-only, read-only host preflight.
"""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Mapping

from atlas_core.supervisor_v4_option2_plan import (
    build_option2_service_identity_and_vault_plan,
    validate_option2_service_identity_and_vault_plan,
)
from atlas_core.supervisor_v4_option2_manifest_review import (
    validate_option2_service_identity_provisioning_manifest_review_content,
)
from atlas_core.supervisor_v4_option2_provisioner import (
    OPTION2_PROVISIONER_QUALIFICATION_STATE,
    PRODUCTION_CONFIGURATION_FIELDS,
    build_option2_provisioner_manifest,
    review_option2_provisioner_contract,
    validate_option2_provisioner_manifest,
)


OPTION2_IDENTITY_CANDIDATE_VERSION = 1
OPTION2_IDENTITY_CANDIDATE_CLASSIFICATION = (
    "option2_identity_only_synthetic_candidate"
)
OPTION2_IDENTITY_CANDIDATE_RESOLVER_STATE = "qualified_inactive"
OPTION2_IDENTITY_CANDIDATE_NEXT_GATE = (
    "owner_review_option2_identity_only_host_preflight"
)
OPTION2_SYNTHETIC_INVENTORY_CLASSIFICATION = (
    "option2_normalized_synthetic_identity_inventory"
)
OPTION2_IDENTITY_CANDIDATE_MAX_VALIDITY_SECONDS = 15 * 60

OPTION2_SERVICE_IDENTITIES: tuple[str, ...] = (
    "_atlaspolicy",
    "_atlasverify",
    "_atlasvault",
    "_atlasreceipt",
    "_atlasstop",
    "_atlasconnector",
)

_ASSIGNMENT_FIELDS = {
    "uid",
    "gid",
    "password_state",
    "hidden_account",
    "login_shell",
    "home_directory",
    "supplementary_groups",
}
_INVENTORY_FIELDS = {
    "version",
    "classification",
    "synthetic_only",
    "owner_pause_latched",
    "users",
    "groups",
    "production_configuration",
}
_NAME_PATTERN = re.compile(r"[A-Za-z0-9_.:-]{1,96}\Z")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_MAX_INVENTORY_ENTITIES = 1024

_AUTHORITY_FALSE_FIELDS: tuple[str, ...] = (
    "access_change_authorized",
    "admin_prompt_authorized",
    "authority_granted",
    "background_execution_authorized",
    "credential_use_authorized",
    "deployment_authorized",
    "live_execution_authorized",
    "model_contact_authorized",
    "network_access_authorized",
    "private_data_transmission_authorized",
    "provisioning_authorized",
    "service_identity_creation_authorized",
    "service_identity_provisioning_authorized",
    "vault_provisioning_authorized",
)

_EFFECT_FALSE_FIELDS: tuple[str, ...] = (
    "access_permissions_changed",
    "account_api_called",
    "accounts_created",
    "admin_prompt_displayed",
    "background_service_installed",
    "credential_material_present",
    "filesystem_read",
    "filesystem_written",
    "group_api_called",
    "groups_created",
    "host_inspected",
    "keychain_opened",
    "keychain_queried",
    "launchd_contacted",
    "live_path_read",
    "live_path_written",
    "model_contacted",
    "network_accessed",
    "private_data_present",
    "provider_contacted",
    "socket_opened",
    "subprocess_started",
    "temporary_files_written",
    "user_api_called",
    "users_created",
)

# Public immutable schemas let the service boundary independently enforce the
# exact nested report shape instead of accepting an underspecified mapping.
OPTION2_IDENTITY_CANDIDATE_AUTHORITY_FIELDS = _AUTHORITY_FALSE_FIELDS
OPTION2_IDENTITY_CANDIDATE_EFFECT_FIELDS = _EFFECT_FALSE_FIELDS

_ATTEST_STAGE = "attest_candidate"
_INVENTORY_STAGE = "recheck_synthetic_inventory"
_GROUP_STAGE_PREFIX = "create_group:"
_USER_STAGE_PREFIX = "create_user:"
_VERIFY_STAGE = "validate_inactive_projection"
_RECEIPT_STAGE = "seal_non_authorizing_receipt"

OPTION2_IDENTITY_CANDIDATE_TRANSACTION_STAGE_IDS: tuple[str, ...] = (
    _ATTEST_STAGE,
    _INVENTORY_STAGE,
    *(f"{_GROUP_STAGE_PREFIX}{name}" for name in OPTION2_SERVICE_IDENTITIES),
    *(f"{_USER_STAGE_PREFIX}{name}" for name in OPTION2_SERVICE_IDENTITIES),
    _VERIFY_STAGE,
    _RECEIPT_STAGE,
)
OPTION2_IDENTITY_CANDIDATE_CREATION_STAGE_IDS: tuple[str, ...] = (
    *(
        f"{_GROUP_STAGE_PREFIX}{name}"
        for name in OPTION2_SERVICE_IDENTITIES
    ),
    *(f"{_USER_STAGE_PREFIX}{name}" for name in OPTION2_SERVICE_IDENTITIES),
)


class Option2IdentityCandidateViolation(RuntimeError):
    """Raised when a synthetic identity candidate is not exact."""


class _InjectedFixtureFailure(RuntimeError):
    """Internal marker used only by the in-memory simulator."""


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
        raise Option2IdentityCandidateViolation(code)
    return value


def _validate_integer(value: object, *, code: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 1
        or value > 2_147_483_647
    ):
        raise Option2IdentityCandidateViolation(code)
    return value


def _validate_name(value: object, *, code: str) -> str:
    if not isinstance(value, str) or _NAME_PATTERN.fullmatch(value) is None:
        raise Option2IdentityCandidateViolation(code)
    return value


def _parse_timestamp(value: object, *, code: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise Option2IdentityCandidateViolation(code)
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as error:
        raise Option2IdentityCandidateViolation(code) from error
    if parsed.tzinfo is None or parsed.utcoffset() is None or parsed.microsecond:
        raise Option2IdentityCandidateViolation(code)
    return parsed.astimezone(timezone.utc)


def _canonical_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalize_window(*, issued_at: object, expires_at: object) -> tuple[str, str]:
    issued = _parse_timestamp(issued_at, code="option2_candidate_issued_at_invalid")
    expires = _parse_timestamp(
        expires_at, code="option2_candidate_expires_at_invalid"
    )
    lifetime = (expires - issued).total_seconds()
    if lifetime <= 0 or lifetime > OPTION2_IDENTITY_CANDIDATE_MAX_VALIDITY_SECONDS:
        raise Option2IdentityCandidateViolation(
            "option2_candidate_validity_window_invalid"
        )
    return _canonical_timestamp(issued), _canonical_timestamp(expires)


def _assert_observed_in_window(
    candidate: Mapping[str, Any], *, observed_at: object
) -> str:
    observed = _parse_timestamp(
        observed_at, code="option2_candidate_observed_at_invalid"
    )
    issued = _parse_timestamp(
        candidate.get("issued_at"), code="option2_candidate_issued_at_invalid"
    )
    expires = _parse_timestamp(
        candidate.get("expires_at"), code="option2_candidate_expires_at_invalid"
    )
    if observed < issued or observed >= expires:
        raise Option2IdentityCandidateViolation("option2_candidate_expired")
    return _canonical_timestamp(observed)


def _normalize_inventory_entry(
    value: object, *, kind: str
) -> dict[str, object]:
    numeric_field = "uid" if kind == "user" else "gid"
    if not isinstance(value, Mapping) or set(value) != {
        "name",
        numeric_field,
        "synthetic",
    }:
        raise Option2IdentityCandidateViolation(
            f"option2_synthetic_inventory_{kind}_invalid"
        )
    if value.get("synthetic") is not True:
        raise Option2IdentityCandidateViolation(
            f"option2_synthetic_inventory_{kind}_not_synthetic"
        )
    return {
        "name": _validate_name(
            value.get("name"),
            code=f"option2_synthetic_inventory_{kind}_name_invalid",
        ),
        numeric_field: _validate_integer(
            value.get(numeric_field),
            code=f"option2_synthetic_inventory_{kind}_{numeric_field}_invalid",
        ),
        "synthetic": True,
    }


def _normalize_synthetic_inventory(
    synthetic_inventory: Mapping[str, Any],
) -> dict[str, object]:
    if not isinstance(synthetic_inventory, Mapping) or set(
        synthetic_inventory
    ) != _INVENTORY_FIELDS:
        raise Option2IdentityCandidateViolation(
            "option2_synthetic_inventory_schema_invalid"
        )
    if (
        synthetic_inventory.get("version") != 1
        or synthetic_inventory.get("classification")
        != OPTION2_SYNTHETIC_INVENTORY_CLASSIFICATION
        or synthetic_inventory.get("synthetic_only") is not True
    ):
        raise Option2IdentityCandidateViolation(
            "option2_synthetic_inventory_boundary_invalid"
        )
    if synthetic_inventory.get("owner_pause_latched") is not True:
        raise Option2IdentityCandidateViolation(
            "option2_synthetic_inventory_owner_pause_not_latched"
        )
    users_value = synthetic_inventory.get("users")
    groups_value = synthetic_inventory.get("groups")
    if not isinstance(users_value, list) or not isinstance(groups_value, list):
        raise Option2IdentityCandidateViolation(
            "option2_synthetic_inventory_entities_invalid"
        )
    if (
        len(users_value) > _MAX_INVENTORY_ENTITIES
        or len(groups_value) > _MAX_INVENTORY_ENTITIES
    ):
        raise Option2IdentityCandidateViolation(
            "option2_synthetic_inventory_too_large"
        )
    users = [_normalize_inventory_entry(item, kind="user") for item in users_value]
    groups = [
        _normalize_inventory_entry(item, kind="group") for item in groups_value
    ]
    users.sort(key=lambda item: (str(item["name"]), int(item["uid"])))
    groups.sort(key=lambda item: (str(item["name"]), int(item["gid"])))
    user_names = [str(item["name"]) for item in users]
    user_ids = [int(item["uid"]) for item in users]
    group_names = [str(item["name"]) for item in groups]
    group_ids = [int(item["gid"]) for item in groups]
    if len(set(user_names)) != len(user_names) or len(set(user_ids)) != len(
        user_ids
    ):
        raise Option2IdentityCandidateViolation(
            "option2_synthetic_inventory_user_duplicate"
        )
    if len(set(group_names)) != len(group_names) or len(set(group_ids)) != len(
        group_ids
    ):
        raise Option2IdentityCandidateViolation(
            "option2_synthetic_inventory_group_duplicate"
        )
    production = synthetic_inventory.get("production_configuration")
    if (
        not isinstance(production, Mapping)
        or set(production) != set(PRODUCTION_CONFIGURATION_FIELDS)
        or any(
            production[field] is not None
            for field in PRODUCTION_CONFIGURATION_FIELDS
        )
    ):
        raise Option2IdentityCandidateViolation(
            "option2_synthetic_inventory_production_configuration_not_null"
        )
    return {
        "version": 1,
        "classification": OPTION2_SYNTHETIC_INVENTORY_CLASSIFICATION,
        "synthetic_only": True,
        "owner_pause_latched": True,
        "users": users,
        "groups": groups,
        "production_configuration": {
            field: None for field in PRODUCTION_CONFIGURATION_FIELDS
        },
    }


def _normalize_assignments(
    proposed_assignments: Mapping[str, Any],
) -> list[dict[str, object]]:
    if not isinstance(proposed_assignments, Mapping) or set(
        proposed_assignments
    ) != set(OPTION2_SERVICE_IDENTITIES):
        raise Option2IdentityCandidateViolation(
            "option2_candidate_identity_set_invalid"
        )
    assignments: list[dict[str, object]] = []
    for name in OPTION2_SERVICE_IDENTITIES:
        value = proposed_assignments.get(name)
        if not isinstance(value, Mapping) or set(value) != _ASSIGNMENT_FIELDS:
            raise Option2IdentityCandidateViolation(
                "option2_candidate_assignment_schema_invalid"
            )
        assignment = {
            "name": name,
            "uid": _validate_integer(
                value.get("uid"), code="option2_candidate_uid_invalid"
            ),
            "gid": _validate_integer(
                value.get("gid"), code="option2_candidate_gid_invalid"
            ),
            "password_state": value.get("password_state"),
            "hidden_account": value.get("hidden_account"),
            "login_shell": value.get("login_shell"),
            "home_directory": value.get("home_directory"),
            "supplementary_groups": deepcopy(value.get("supplementary_groups")),
        }
        if assignment["password_state"] != "locked":
            raise Option2IdentityCandidateViolation(
                "option2_candidate_authentication_not_locked"
            )
        if assignment["hidden_account"] is not True:
            raise Option2IdentityCandidateViolation(
                "option2_candidate_identity_not_hidden"
            )
        if assignment["login_shell"] != "/usr/bin/false":
            raise Option2IdentityCandidateViolation(
                "option2_candidate_login_shell_invalid"
            )
        if assignment["home_directory"] != "/var/empty":
            raise Option2IdentityCandidateViolation(
                "option2_candidate_home_directory_invalid"
            )
        if assignment["supplementary_groups"] != []:
            raise Option2IdentityCandidateViolation(
                "option2_candidate_supplementary_groups_present"
            )
        assignments.append(assignment)
    uids = [int(item["uid"]) for item in assignments]
    gids = [int(item["gid"]) for item in assignments]
    if len(set(uids)) != len(uids):
        raise Option2IdentityCandidateViolation(
            "option2_candidate_uid_assignment_duplicate"
        )
    if len(set(gids)) != len(gids):
        raise Option2IdentityCandidateViolation(
            "option2_candidate_gid_assignment_duplicate"
        )
    return assignments


def _assert_collision_free(
    inventory: Mapping[str, Any], assignments: list[dict[str, object]]
) -> None:
    users = inventory.get("users")
    groups = inventory.get("groups")
    if not isinstance(users, list) or not isinstance(groups, list):
        raise Option2IdentityCandidateViolation(
            "option2_synthetic_inventory_entities_invalid"
        )
    user_names = {item["name"] for item in users}
    user_ids = {item["uid"] for item in users}
    group_names = {item["name"] for item in groups}
    group_ids = {item["gid"] for item in groups}
    if any(
        assignment["name"] in user_names
        or assignment["uid"] in user_ids
        or assignment["name"] in group_names
        or assignment["gid"] in group_ids
        for assignment in assignments
    ):
        raise Option2IdentityCandidateViolation(
            "option2_candidate_inventory_collision"
        )


def _reviewed_manifest() -> dict[str, object]:
    manifest = build_option2_provisioner_manifest()
    body = {
        key: deepcopy(value)
        for key, value in manifest.items()
        if key != "manifest_sha256"
    }
    validate_option2_provisioner_manifest(body)
    plan = build_option2_service_identity_and_vault_plan()
    plan_body = {
        key: deepcopy(value)
        for key, value in plan.items()
        if key != "plan_sha256"
    }
    validate_option2_service_identity_and_vault_plan(plan_body)
    components = manifest.get("components")
    identities = (
        tuple(component.get("service_identity") for component in components)
        if isinstance(components, list)
        else ()
    )
    if identities != OPTION2_SERVICE_IDENTITIES:
        raise Option2IdentityCandidateViolation(
            "option2_candidate_manifest_identity_set_drifted"
        )
    if (
        manifest.get("production_manifest_complete") is not False
        or manifest.get("host_apply_present") is not False
    ):
        raise Option2IdentityCandidateViolation(
            "option2_candidate_manifest_boundary_open"
        )
    return manifest


def _validate_manifest_review_binding(
    manifest_review_content: Mapping[str, Any],
    *,
    service_verified_manifest_review_content_sha256: str,
    manifest: Mapping[str, Any],
) -> str:
    if not isinstance(manifest_review_content, Mapping):
        raise Option2IdentityCandidateViolation(
            "option2_candidate_manifest_review_content_invalid"
        )
    binding_fields = (
        "plan_review_content_sha256",
        "fixture_qualification_content_sha256",
        "reviewed_plan_sha256",
        "manifest_sha256",
        "fixture_qualification_sha256",
    )
    bindings = {
        field: _validate_sha256(
            manifest_review_content.get(field),
            code=f"option2_candidate_manifest_review_{field}_invalid",
        )
        for field in binding_fields
    }
    try:
        validate_option2_service_identity_provisioning_manifest_review_content(
            manifest_review_content,
            **bindings,
        )
    except RuntimeError as error:
        raise Option2IdentityCandidateViolation(
            "option2_candidate_manifest_review_content_not_canonical"
        ) from error
    manifest_sha256 = _validate_sha256(
        manifest.get("manifest_sha256"),
        code="option2_candidate_manifest_sha256_invalid",
    )
    if bindings["manifest_sha256"] != manifest_sha256:
        raise Option2IdentityCandidateViolation(
            "option2_candidate_reviewed_manifest_binding_mismatch"
        )
    if bindings["reviewed_plan_sha256"] != manifest.get("reviewed_plan_sha256"):
        raise Option2IdentityCandidateViolation(
            "option2_candidate_reviewed_plan_binding_mismatch"
        )
    fixture_qualification = review_option2_provisioner_contract(
        service_verified_plan_review_content_sha256=(
            bindings["plan_review_content_sha256"]
        )
    )
    if (
        fixture_qualification.get("qualification_sha256")
        != bindings["fixture_qualification_sha256"]
        or fixture_qualification.get("manifest_sha256") != manifest_sha256
        or fixture_qualification.get("reviewed_plan_sha256")
        != bindings["reviewed_plan_sha256"]
    ):
        raise Option2IdentityCandidateViolation(
            "option2_candidate_fixture_qualification_binding_mismatch"
        )
    content_sha256 = _sha256(manifest_review_content)
    if content_sha256 != _validate_sha256(
        service_verified_manifest_review_content_sha256,
        code=(
            "option2_candidate_service_verified_manifest_review_content_"
            "sha256_invalid"
        ),
    ):
        raise Option2IdentityCandidateViolation(
            "option2_candidate_manifest_review_content_binding_mismatch"
        )
    return content_sha256


def _candidate_body(
    *,
    inventory: Mapping[str, Any],
    assignments: list[dict[str, object]],
    reviewed_manifest_sha256: str,
    manifest_review_content_sha256: str,
    issued_at: str,
    expires_at: str,
) -> dict[str, object]:
    return {
        "version": OPTION2_IDENTITY_CANDIDATE_VERSION,
        "classification": OPTION2_IDENTITY_CANDIDATE_CLASSIFICATION,
        "resolver_state": OPTION2_IDENTITY_CANDIDATE_RESOLVER_STATE,
        "candidate_state": "synthetic_identity_only_inactive",
        "synthetic_only": True,
        "candidate_complete": True,
        "candidate_scope": "six_service_users_and_matching_groups_only",
        "synthetic_inventory_sha256": _sha256(inventory),
        "reviewed_manifest_sha256": reviewed_manifest_sha256,
        "manifest_review_content_sha256": manifest_review_content_sha256,
        "manifest_review_state": "service_verified_append_once_inactive",
        "provisioner_fixture_qualification_state": (
            OPTION2_PROVISIONER_QUALIFICATION_STATE
        ),
        "issued_at": issued_at,
        "expires_at": expires_at,
        "max_validity_seconds": (
            OPTION2_IDENTITY_CANDIDATE_MAX_VALIDITY_SECONDS
        ),
        "assignments": deepcopy(assignments),
        "owner_pause_latched": True,
        "production_configuration": {
            field: None for field in PRODUCTION_CONFIGURATION_FIELDS
        },
        "production_manifest_complete": False,
        "host_preflight_required": True,
        "host_preflight_performed": False,
        "host_apply_present": False,
        "operation_allowlist": ["create_exact_service_group", "create_exact_service_user"],
        "authority": {field: False for field in _AUTHORITY_FALSE_FIELDS},
        "effects": {field: False for field in _EFFECT_FALSE_FIELDS},
        "ready": False,
        "ready_offline": False,
        "ready_live": False,
        "next_gate": OPTION2_IDENTITY_CANDIDATE_NEXT_GATE,
    }


def build_option2_identity_candidate(
    *,
    synthetic_inventory: Mapping[str, Any],
    proposed_assignments: Mapping[str, Any],
    manifest_review_content: Mapping[str, Any],
    service_verified_manifest_review_content_sha256: str,
    issued_at: str,
    expires_at: str,
) -> dict[str, object]:
    """Build a digest-bound candidate from normalized synthetic values only."""

    inventory = _normalize_synthetic_inventory(synthetic_inventory)
    assignments = _normalize_assignments(proposed_assignments)
    _assert_collision_free(inventory, assignments)
    manifest = _reviewed_manifest()
    supplied_manifest_sha256 = _validate_sha256(
        manifest.get("manifest_sha256"),
        code="option2_candidate_manifest_sha256_invalid",
    )
    review_sha256 = _validate_manifest_review_binding(
        manifest_review_content,
        service_verified_manifest_review_content_sha256=(
            service_verified_manifest_review_content_sha256
        ),
        manifest=manifest,
    )
    normalized_issued_at, normalized_expires_at = _normalize_window(
        issued_at=issued_at, expires_at=expires_at
    )
    body = _candidate_body(
        inventory=inventory,
        assignments=assignments,
        reviewed_manifest_sha256=supplied_manifest_sha256,
        manifest_review_content_sha256=review_sha256,
        issued_at=normalized_issued_at,
        expires_at=normalized_expires_at,
    )
    candidate = {**deepcopy(body), "candidate_sha256": _sha256(body)}
    validate_option2_identity_candidate(candidate)
    return candidate


def _candidate_body_from_envelope(
    candidate: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(candidate, Mapping):
        raise Option2IdentityCandidateViolation(
            "option2_identity_candidate_invalid"
        )
    body = {
        key: deepcopy(value)
        for key, value in candidate.items()
        if key != "candidate_sha256"
    }
    if candidate.get("candidate_sha256") != _sha256(body):
        raise Option2IdentityCandidateViolation(
            "option2_identity_candidate_digest_invalid"
        )
    return body


def validate_option2_identity_candidate(candidate: Mapping[str, Any]) -> None:
    """Require an exact inactive candidate envelope and current manifest."""

    body = _candidate_body_from_envelope(candidate)
    expected_keys = set(
        _candidate_body(
            inventory={"users": [], "groups": []},
            assignments=[],
            reviewed_manifest_sha256="a" * 64,
            manifest_review_content_sha256="b" * 64,
            issued_at="2026-01-01T00:00:00Z",
            expires_at="2026-01-01T00:01:00Z",
        )
    )
    if set(body) != expected_keys:
        raise Option2IdentityCandidateViolation(
            "option2_identity_candidate_schema_invalid"
        )
    manifest = _reviewed_manifest()
    if body.get("reviewed_manifest_sha256") != manifest.get("manifest_sha256"):
        raise Option2IdentityCandidateViolation(
            "option2_candidate_reviewed_manifest_binding_mismatch"
        )
    _validate_sha256(
        body.get("manifest_review_content_sha256"),
        code="option2_candidate_manifest_review_content_sha256_invalid",
    )
    issued_at, expires_at = _normalize_window(
        issued_at=body.get("issued_at"), expires_at=body.get("expires_at")
    )
    if body.get("issued_at") != issued_at or body.get("expires_at") != expires_at:
        raise Option2IdentityCandidateViolation(
            "option2_candidate_timestamp_not_canonical"
        )
    assignment_values = body.get("assignments")
    if not isinstance(assignment_values, list):
        raise Option2IdentityCandidateViolation(
            "option2_candidate_assignments_invalid"
        )
    assignment_mapping = {
        item.get("name"): {
            key: deepcopy(value) for key, value in item.items() if key != "name"
        }
        for item in assignment_values
        if isinstance(item, Mapping)
    }
    assignments = _normalize_assignments(assignment_mapping)
    if assignment_values != assignments:
        raise Option2IdentityCandidateViolation(
            "option2_candidate_assignments_not_canonical"
        )
    production = body.get("production_configuration")
    if (
        not isinstance(production, Mapping)
        or set(production) != set(PRODUCTION_CONFIGURATION_FIELDS)
        or any(
            production[field] is not None
            for field in PRODUCTION_CONFIGURATION_FIELDS
        )
    ):
        raise Option2IdentityCandidateViolation(
            "option2_candidate_production_configuration_not_null"
        )
    authority = body.get("authority")
    effects = body.get("effects")
    if (
        not isinstance(authority, Mapping)
        or set(authority) != set(_AUTHORITY_FALSE_FIELDS)
        or any(authority[field] is not False for field in _AUTHORITY_FALSE_FIELDS)
        or not isinstance(effects, Mapping)
        or set(effects) != set(_EFFECT_FALSE_FIELDS)
        or any(effects[field] is not False for field in _EFFECT_FALSE_FIELDS)
    ):
        raise Option2IdentityCandidateViolation(
            "option2_candidate_authority_or_effect_open"
        )
    fixed = {
        "version": OPTION2_IDENTITY_CANDIDATE_VERSION,
        "classification": OPTION2_IDENTITY_CANDIDATE_CLASSIFICATION,
        "resolver_state": OPTION2_IDENTITY_CANDIDATE_RESOLVER_STATE,
        "candidate_state": "synthetic_identity_only_inactive",
        "synthetic_only": True,
        "candidate_complete": True,
        "candidate_scope": "six_service_users_and_matching_groups_only",
        "manifest_review_state": "service_verified_append_once_inactive",
        "provisioner_fixture_qualification_state": (
            OPTION2_PROVISIONER_QUALIFICATION_STATE
        ),
        "max_validity_seconds": OPTION2_IDENTITY_CANDIDATE_MAX_VALIDITY_SECONDS,
        "owner_pause_latched": True,
        "production_manifest_complete": False,
        "host_preflight_required": True,
        "host_preflight_performed": False,
        "host_apply_present": False,
        "operation_allowlist": ["create_exact_service_group", "create_exact_service_user"],
        "ready": False,
        "ready_offline": False,
        "ready_live": False,
        "next_gate": OPTION2_IDENTITY_CANDIDATE_NEXT_GATE,
    }
    if any(body.get(key) != value for key, value in fixed.items()):
        raise Option2IdentityCandidateViolation(
            "option2_identity_candidate_boundary_invalid"
        )
    _validate_sha256(
        body.get("synthetic_inventory_sha256"),
        code="option2_identity_candidate_inventory_sha256_invalid",
    )


def _state_from_inventory(inventory: Mapping[str, Any]) -> dict[str, object]:
    return {
        "users": {
            item["name"]: {
                "uid": item["uid"],
                "synthetic": True,
                "origin": "preexisting",
            }
            for item in inventory["users"]
        },
        "groups": {
            item["name"]: {
                "gid": item["gid"],
                "synthetic": True,
                "origin": "preexisting",
            }
            for item in inventory["groups"]
        },
        "owner_pause_latched": True,
        "production_configuration": {
            field: None for field in PRODUCTION_CONFIGURATION_FIELDS
        },
        "virtual_receipt_sealed": False,
        "quarantined": False,
    }


def _preexisting_entities_preserved(
    state: Mapping[str, Any], inventory: Mapping[str, Any]
) -> bool:
    users = state.get("users")
    groups = state.get("groups")
    if not isinstance(users, Mapping) or not isinstance(groups, Mapping):
        return False
    return all(
        users.get(item["name"])
        == {
            "uid": item["uid"],
            "synthetic": True,
            "origin": "preexisting",
        }
        for item in inventory["users"]
    ) and all(
        groups.get(item["name"])
        == {
            "gid": item["gid"],
            "synthetic": True,
            "origin": "preexisting",
        }
        for item in inventory["groups"]
    )


def _transaction_entity_counts(state: Mapping[str, Any]) -> tuple[int, int]:
    users = state.get("users")
    groups = state.get("groups")
    if not isinstance(users, Mapping) or not isinstance(groups, Mapping):
        raise Option2IdentityCandidateViolation(
            "option2_identity_fixture_state_invalid"
        )
    return (
        sum(
            1
            for item in users.values()
            if isinstance(item, Mapping) and item.get("origin") == "transaction"
        ),
        sum(
            1
            for item in groups.values()
            if isinstance(item, Mapping) and item.get("origin") == "transaction"
        ),
    )


def _apply_fixture_stage(
    state: dict[str, object],
    *,
    stage_id: str,
    assignments: Mapping[str, Mapping[str, Any]],
    created: list[tuple[str, str, str]],
) -> None:
    if stage_id in {_ATTEST_STAGE, _INVENTORY_STAGE}:
        return
    if stage_id.startswith(_GROUP_STAGE_PREFIX):
        name = stage_id.removeprefix(_GROUP_STAGE_PREFIX)
        groups = state.get("groups")
        if not isinstance(groups, dict) or name in groups:
            raise Option2IdentityCandidateViolation(
                "option2_identity_fixture_group_collision"
            )
        groups[name] = {
            "gid": assignments[name]["gid"],
            "synthetic": True,
            "origin": "transaction",
        }
        created.append(("groups", name, stage_id))
        return
    if stage_id.startswith(_USER_STAGE_PREFIX):
        name = stage_id.removeprefix(_USER_STAGE_PREFIX)
        users = state.get("users")
        groups = state.get("groups")
        if (
            not isinstance(users, dict)
            or not isinstance(groups, dict)
            or name in users
            or name not in groups
        ):
            raise Option2IdentityCandidateViolation(
                "option2_identity_fixture_user_precondition_invalid"
            )
        users[name] = {
            **deepcopy(dict(assignments[name])),
            "synthetic": True,
            "origin": "transaction",
        }
        created.append(("users", name, stage_id))
        return
    if stage_id == _VERIFY_STAGE:
        transaction_users, transaction_groups = _transaction_entity_counts(state)
        if (
            transaction_users != len(OPTION2_SERVICE_IDENTITIES)
            or transaction_groups != len(OPTION2_SERVICE_IDENTITIES)
            or state.get("owner_pause_latched") is not True
            or any(
                state["production_configuration"][field] is not None
                for field in PRODUCTION_CONFIGURATION_FIELDS
            )
        ):
            raise Option2IdentityCandidateViolation(
                "option2_identity_fixture_postflight_invalid"
            )
        return
    if stage_id == _RECEIPT_STAGE:
        state["virtual_receipt_sealed"] = True
        return
    raise Option2IdentityCandidateViolation(
        "option2_identity_fixture_stage_invalid"
    )


def _rollback_fixture_entities(
    state: dict[str, object],
    *,
    created: list[tuple[str, str, str]],
    rollback_uncertain_stage: str | None,
) -> tuple[list[str], bool]:
    rollback_order: list[str] = []
    for collection_name, name, creation_stage in reversed(created):
        collection = state.get(collection_name)
        if not isinstance(collection, dict):
            return rollback_order, False
        if creation_stage == rollback_uncertain_stage:
            state["quarantined"] = True
            return rollback_order, False
        entity = collection.get(name)
        if not isinstance(entity, Mapping) or entity.get("origin") != "transaction":
            state["quarantined"] = True
            return rollback_order, False
        del collection[name]
        rollback_order.append(creation_stage)
    state["virtual_receipt_sealed"] = False
    return rollback_order, True


def simulate_option2_identity_candidate_transaction(
    candidate: Mapping[str, Any],
    *,
    synthetic_inventory: Mapping[str, Any],
    manifest_review_content: Mapping[str, Any],
    observed_at: str,
    fail_after_stage: str | None = None,
    rollback_uncertain_stage: str | None = None,
) -> dict[str, object]:
    """Transform only a synthetic in-memory projection.

    Failure injection occurs after the named stage.  Rollback removes only
    entities tagged as created by this simulated transaction.
    """

    validate_option2_identity_candidate(candidate)
    manifest = _reviewed_manifest()
    review_sha256 = _validate_manifest_review_binding(
        manifest_review_content,
        service_verified_manifest_review_content_sha256=str(
            candidate.get("manifest_review_content_sha256")
        ),
        manifest=manifest,
    )
    if review_sha256 != candidate.get("manifest_review_content_sha256"):
        raise Option2IdentityCandidateViolation(
            "option2_candidate_manifest_review_content_drifted"
        )
    inventory = _normalize_synthetic_inventory(synthetic_inventory)
    if _sha256(inventory) != candidate.get("synthetic_inventory_sha256"):
        raise Option2IdentityCandidateViolation(
            "option2_candidate_synthetic_inventory_drifted"
        )
    normalized_observed_at = _assert_observed_in_window(
        candidate, observed_at=observed_at
    )
    assignment_list = candidate.get("assignments")
    if not isinstance(assignment_list, list):
        raise Option2IdentityCandidateViolation(
            "option2_candidate_assignments_invalid"
        )
    assignment_mapping = {
        str(item["name"]): {
            key: deepcopy(value) for key, value in item.items() if key != "name"
        }
        for item in assignment_list
    }
    normalized_assignments = _normalize_assignments(assignment_mapping)
    _assert_collision_free(inventory, normalized_assignments)
    assignments = {
        str(item["name"]): {
            key: deepcopy(value) for key, value in item.items() if key != "name"
        }
        for item in normalized_assignments
    }
    if fail_after_stage is not None and fail_after_stage not in (
        OPTION2_IDENTITY_CANDIDATE_TRANSACTION_STAGE_IDS
    ):
        raise Option2IdentityCandidateViolation(
            "option2_identity_fixture_failure_stage_invalid"
        )
    if rollback_uncertain_stage is not None and (
        fail_after_stage is None
        or rollback_uncertain_stage
        not in OPTION2_IDENTITY_CANDIDATE_CREATION_STAGE_IDS
    ):
        raise Option2IdentityCandidateViolation(
            "option2_identity_fixture_rollback_uncertainty_invalid"
        )
    state = _state_from_inventory(inventory)
    completed_stages: list[str] = []
    created: list[tuple[str, str, str]] = []
    rollback_order: list[str] = []
    rollback_complete: bool | None = None
    outcome = OPTION2_IDENTITY_CANDIDATE_RESOLVER_STATE
    try:
        for stage_id in OPTION2_IDENTITY_CANDIDATE_TRANSACTION_STAGE_IDS:
            _apply_fixture_stage(
                state,
                stage_id=stage_id,
                assignments=assignments,
                created=created,
            )
            completed_stages.append(stage_id)
            if stage_id == fail_after_stage:
                raise _InjectedFixtureFailure(stage_id)
    except _InjectedFixtureFailure:
        rollback_order, rollback_complete = _rollback_fixture_entities(
            state,
            created=created,
            rollback_uncertain_stage=rollback_uncertain_stage,
        )
        outcome = (
            "rolled_back_inactive"
            if rollback_complete
            else "quarantined_inactive"
        )
    if rollback_uncertain_stage is not None and outcome != "quarantined_inactive":
        raise Option2IdentityCandidateViolation(
            "option2_identity_fixture_rollback_uncertainty_not_reached"
        )
    transaction_users, transaction_groups = _transaction_entity_counts(state)
    preexisting_preserved = _preexisting_entities_preserved(state, inventory)
    if not preexisting_preserved or state.get("owner_pause_latched") is not True:
        raise Option2IdentityCandidateViolation(
            "option2_identity_fixture_preexisting_state_not_preserved"
        )
    body = {
        "version": 1,
        "classification": "option2_identity_candidate_in_memory_simulation",
        "state": outcome,
        "synthetic_only": True,
        "candidate_sha256": candidate["candidate_sha256"],
        "synthetic_inventory_sha256": candidate["synthetic_inventory_sha256"],
        "observed_at": normalized_observed_at,
        "failure_injected_after_stage": fail_after_stage,
        "rollback_uncertain_stage": rollback_uncertain_stage,
        "completed_stages": completed_stages,
        "rollback_stage_order": rollback_order,
        "rollback_attempted": fail_after_stage is not None,
        "rollback_complete": rollback_complete,
        "rollback_deleted_only_transaction_created_entities": True,
        "preexisting_entities_preserved": True,
        "transaction_user_count_remaining": transaction_users,
        "transaction_group_count_remaining": transaction_groups,
        "simulated_projection_complete": (
            outcome == OPTION2_IDENTITY_CANDIDATE_RESOLVER_STATE
        ),
        "quarantined": outcome == "quarantined_inactive",
        "owner_pause_latched": True,
        "production_configuration": {
            field: None for field in PRODUCTION_CONFIGURATION_FIELDS
        },
        "production_manifest_complete": False,
        "host_preflight_performed": False,
        "host_apply_present": False,
        "authority": {field: False for field in _AUTHORITY_FALSE_FIELDS},
        "effects": {field: False for field in _EFFECT_FALSE_FIELDS},
        "ready": False,
        "ready_offline": False,
        "ready_live": False,
        "next_gate": OPTION2_IDENTITY_CANDIDATE_NEXT_GATE,
    }
    return {**deepcopy(body), "simulation_sha256": _sha256(body)}


def qualify_option2_identity_candidate_resolver(
    *,
    synthetic_inventory: Mapping[str, Any],
    proposed_assignments: Mapping[str, Any],
    manifest_review_content: Mapping[str, Any],
    service_verified_manifest_review_content_sha256: str,
    issued_at: str,
    expires_at: str,
    observed_at: str,
) -> dict[str, object]:
    """Exercise success, every partial stage, and rollback uncertainty."""

    candidate = build_option2_identity_candidate(
        synthetic_inventory=synthetic_inventory,
        proposed_assignments=proposed_assignments,
        manifest_review_content=manifest_review_content,
        service_verified_manifest_review_content_sha256=(
            service_verified_manifest_review_content_sha256
        ),
        issued_at=issued_at,
        expires_at=expires_at,
    )
    success = simulate_option2_identity_candidate_transaction(
        candidate,
        synthetic_inventory=synthetic_inventory,
        manifest_review_content=manifest_review_content,
        observed_at=observed_at,
    )
    partial_failures = {
        stage_id: simulate_option2_identity_candidate_transaction(
            candidate,
            synthetic_inventory=synthetic_inventory,
            manifest_review_content=manifest_review_content,
            observed_at=observed_at,
            fail_after_stage=stage_id,
        )
        for stage_id in OPTION2_IDENTITY_CANDIDATE_TRANSACTION_STAGE_IDS
    }
    rollback_uncertainty = {
        stage_id: simulate_option2_identity_candidate_transaction(
            candidate,
            synthetic_inventory=synthetic_inventory,
            manifest_review_content=manifest_review_content,
            observed_at=observed_at,
            fail_after_stage=stage_id,
            rollback_uncertain_stage=stage_id,
        )
        for stage_id in OPTION2_IDENTITY_CANDIDATE_CREATION_STAGE_IDS
    }
    def expected_rollback_order(value: Mapping[str, Any]) -> list[str]:
        completed = value.get("completed_stages")
        if not isinstance(completed, list):
            return []
        return list(
            reversed(
                [
                    stage_id
                    for stage_id in completed
                    if stage_id
                    in OPTION2_IDENTITY_CANDIDATE_CREATION_STAGE_IDS
                ]
            )
        )

    if (
        success.get("state") != OPTION2_IDENTITY_CANDIDATE_RESOLVER_STATE
        or success.get("simulated_projection_complete") is not True
        or success.get("preexisting_entities_preserved") is not True
        or any(
            item.get("state") != "rolled_back_inactive"
            or item.get("rollback_complete") is not True
            or item.get("preexisting_entities_preserved") is not True
            or item.get("transaction_user_count_remaining") != 0
            or item.get("transaction_group_count_remaining") != 0
            or item.get("rollback_stage_order")
            != expected_rollback_order(item)
            or item.get("rollback_deleted_only_transaction_created_entities")
            is not True
            for item in partial_failures.values()
        )
        or any(
            item.get("state") != "quarantined_inactive"
            or item.get("rollback_complete") is not False
            or item.get("quarantined") is not True
            or item.get("owner_pause_latched") is not True
            or item.get("preexisting_entities_preserved") is not True
            for item in rollback_uncertainty.values()
        )
    ):
        raise Option2IdentityCandidateViolation(
            "option2_identity_candidate_fixture_qualification_failed"
        )
    body = {
        "version": 1,
        "classification": "option2_identity_candidate_resolver_fixture_qualification",
        "resolver_state": OPTION2_IDENTITY_CANDIDATE_RESOLVER_STATE,
        "synthetic_only": True,
        "candidate_sha256": candidate["candidate_sha256"],
        "synthetic_inventory_sha256": candidate["synthetic_inventory_sha256"],
        "reviewed_manifest_sha256": candidate["reviewed_manifest_sha256"],
        "manifest_review_content_sha256": candidate[
            "manifest_review_content_sha256"
        ],
        "success_case_sha256": success["simulation_sha256"],
        "partial_failure_case_sha256": {
            stage_id: value["simulation_sha256"]
            for stage_id, value in partial_failures.items()
        },
        "rollback_uncertainty_case_sha256": {
            stage_id: value["simulation_sha256"]
            for stage_id, value in rollback_uncertainty.items()
        },
        "partial_stage_count": len(
            OPTION2_IDENTITY_CANDIDATE_TRANSACTION_STAGE_IDS
        ),
        "partial_stages_all_covered": True,
        "reverse_rollback_verified": True,
        "rollback_only_transaction_created_entities_verified": True,
        "preexisting_entity_preservation_verified": True,
        "rollback_uncertainty_quarantine_verified": True,
        "owner_pause_latched": True,
        "production_configuration": {
            field: None for field in PRODUCTION_CONFIGURATION_FIELDS
        },
        "production_manifest_complete": False,
        "host_preflight_performed": False,
        "host_apply_present": False,
        "authority": {field: False for field in _AUTHORITY_FALSE_FIELDS},
        "effects": {field: False for field in _EFFECT_FALSE_FIELDS},
        "ready": False,
        "ready_offline": False,
        "ready_live": False,
        "next_gate": OPTION2_IDENTITY_CANDIDATE_NEXT_GATE,
    }
    return {**deepcopy(body), "qualification_sha256": _sha256(body)}
