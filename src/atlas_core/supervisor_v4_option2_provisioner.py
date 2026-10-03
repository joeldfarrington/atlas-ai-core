"""Inactive Option 2 provisioning manifest and fixture-only simulator.

The real provisioner described here must remain outside Atlas and would need a
later point-of-action owner authorization.  This module is intentionally pure:
it does not inspect or modify the host, open files, create identities, query a
vault, create sockets, start services, invoke subprocesses, contact a network,
or grant authority.  Its simulator transforms an in-memory fixture projection
only.
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import PurePosixPath
from typing import Any, Mapping

from atlas_core.supervisor_v4_option2_plan import (
    build_option2_service_identity_and_vault_plan,
    validate_option2_service_identity_and_vault_plan,
)


OPTION2_PROVISIONER_VERSION = 1
OPTION2_PROVISIONER_CLASSIFICATION = (
    "option2_service_identity_offline_provisioner_contract"
)
OPTION2_PROVISIONER_STATE = "implemented_inactive"
OPTION2_PROVISIONER_QUALIFICATION_STATE = "qualified_inactive"
OPTION2_PROVISIONER_NEXT_GATE = (
    "owner_review_option2_service_identity_provisioning_manifest"
)
EXPECTED_OPTION2_PLAN_SHA256 = (
    "bf3160931dfd5dca306135fefe75b7829bed2497c32d78a9976e18d74cb34da5"
)
PRODUCTION_CONFIGURATION_FIELDS: tuple[str, ...] = (
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

_AUTHORITY_FALSE_FIELDS: tuple[str, ...] = (
    "access_change_authorized",
    "access_permissions_changed",
    "accounts_queried",
    "accounts_created",
    "admin_prompt_authorized",
    "authority_granted",
    "background_execution_authorized",
    "background_service_installed",
    "codesign_invoked",
    "credential_insertion_authorized",
    "credential_material_present",
    "credential_use_authorized",
    "deployment_authorized",
    "deployment_performed",
    "dscl_invoked",
    "external_communication_authorized",
    "filesystem_changes_performed",
    "ip_socket_created",
    "key_material_created",
    "keychain_mutated",
    "keychain_opened",
    "keychain_queried",
    "launchctl_invoked",
    "launchd_job_loaded",
    "launchd_plist_written",
    "launchd_queried",
    "live_path_read",
    "live_path_written",
    "live_authority_granted",
    "live_execution_authorized",
    "model_contacted",
    "model_contact_authorized",
    "network_accessed",
    "network_access_authorized",
    "private_data_present",
    "private_data_authorized",
    "private_data_transmission_authorized",
    "provider_contacted",
    "provider_contact_authorized",
    "provisioning_performed",
    "provisioning_authorized",
    "real_credential_present",
    "runtime_installed",
    "security_cli_invoked",
    "service_started",
    "service_identity_creation_authorized",
    "service_identity_provisioning_authorized",
    "subprocess_spawned",
    "sysadminctl_invoked",
    "unix_socket_connected",
    "unix_socket_created",
    "vault_adapter_connected",
    "vault_provisioning_authorized",
)

_DIRECTED_PEER_INTENT: Mapping[str, tuple[tuple[str, tuple[str, ...]], ...]] = {
    "policy_broker": (
        ("fixture:atlas-core-runtime", ("request_metadata_capability",)),
        (
            "fixture:owner-provisioner",
            ("install_owner_policy", "rotate_subordinate_issuer_certificate"),
        ),
    ),
    "capability_verifier": (
        ("fixture:atlas-core-runtime", ("verify_metadata_capability",)),
        ("fixture:service:policy-broker", ("verify_issuer",)),
        ("fixture:service:vault-broker", ("verify_lease",)),
        ("fixture:service:receipt-anchor", ("verify_receipt",)),
        ("fixture:service:owner-stop", ("verify_resume_token",)),
        (
            "fixture:service:connector-runner",
            ("verify_connector_capability",),
        ),
    ),
    "vault_broker": (
        ("fixture:atlas-core-runtime", ("request_bound_one_use_lease",)),
        (
            "fixture:service:connector-runner",
            ("confirm_material_channel_consumed",),
        ),
    ),
    "receipt_anchor": (
        ("fixture:atlas-core-runtime", ("compare_and_append_receipt",)),
        (
            "fixture:service:policy-broker",
            ("compare_and_append_receipt",),
        ),
        (
            "fixture:service:capability-verifier",
            ("compare_and_append_receipt",),
        ),
        (
            "fixture:service:vault-broker",
            ("compare_and_append_receipt",),
        ),
        (
            "fixture:service:owner-stop",
            ("compare_and_append_receipt",),
        ),
        (
            "fixture:service:connector-runner",
            ("compare_and_append_receipt",),
        ),
    ),
    "owner_stop": (
        ("fixture:atlas-core-runtime", ("read_pause_latch",)),
        (
            "fixture:owner-provisioner",
            ("assert_pause", "submit_owner_signed_monotonic_resume_token"),
        ),
        (
            "fixture:service:policy-broker",
            ("read_pause_latch",),
        ),
        (
            "fixture:service:vault-broker",
            ("read_pause_latch",),
        ),
        (
            "fixture:service:connector-runner",
            ("read_pause_latch",),
        ),
    ),
    "connector_runner": (
        (
            "fixture:atlas-core-runtime",
            ("request_destination_bound_connector",),
        ),
        (
            "fixture:service:vault-broker",
            ("deliver_one_use_material_descriptor",),
        ),
    ),
}

_PREFLIGHT_INVARIANTS: tuple[dict[str, object], ...] = (
    {
        "id": "exact_reviewed_plan",
        "requirement": "append_once_plan_review_matches_exact_plan_digest",
    },
    {
        "id": "separate_point_of_action_authorization",
        "requirement": "fresh_owner_authorization_bound_to_exact_manifest",
    },
    {
        "id": "external_owner_provisioner",
        "requirement": "signed_root_owned_provisioner_not_callable_by_atlas",
    },
    {
        "id": "supported_host",
        "requirement": "macos_host_and_owner_present_administrator_session",
    },
    {
        "id": "collision_free_identities",
        "requirement": "all_six_names_and_allocated_uid_gid_pairs_are_distinct",
    },
    {
        "id": "canonical_no_follow_targets",
        "requirement": "all_target_components_are_canonical_and_not_symlinks",
    },
    {
        "id": "signed_artifact_binding",
        "requirement": "every_binary_hash_and_designated_requirement_is_exact",
    },
    {
        "id": "production_paths_closed",
        "requirement": "all_nine_supervisor_production_paths_remain_null",
    },
    {
        "id": "inactive_service_baseline",
        "requirement": "no_target_service_loaded_running_or_socket_active",
    },
    {
        "id": "vault_and_keys_absent",
        "requirement": "no_vault_item_private_key_or_live_credential_is_created",
    },
    {
        "id": "rollback_snapshot_ready",
        "requirement": "owner_private_backup_and_exact_transaction_inventory_exist",
    },
    {
        "id": "pause_latched",
        "requirement": "owner_stop_state_is_paused_before_and_after_provisioning",
    },
)

_TRANSACTION_STAGES: tuple[dict[str, object], ...] = (
    {
        "id": "attest_manifest",
        "future_effect": "verify exact plan, review, authorization, and manifest digests",
    },
    {
        "id": "preflight_host",
        "future_effect": "verify every preflight invariant before the first mutation",
    },
    {
        "id": "attest_future_owner_authorization_contract",
        "future_effect": "verify that a later host provisioner must atomically claim a fresh manifest-bound one-use authorization",
    },
    {
        "id": "create_service_groups",
        "future_effect": "allocate six distinct locked system groups",
    },
    {
        "id": "create_service_identities",
        "future_effect": "create six hidden non-login users with no supplementary groups",
    },
    {
        "id": "create_disjoint_roots",
        "future_effect": "create exact state and socket directories with no-follow checks",
    },
    {
        "id": "install_signed_artifacts",
        "future_effect": "install exact root-owned binaries after hash and signature checks",
    },
    {
        "id": "stage_service_definitions_outside_live_launchd",
        "future_effect": "stage inert definitions outside /Library/LaunchDaemons without loading services",
    },
    {
        "id": "validate_inactive_postflight",
        "future_effect": "prove accounts are locked and all services, sockets, keys, and vaults inactive",
    },
    {
        "id": "seal_non_authorizing_receipt",
        "future_effect": "append a privacy-minimized inactive provisioning receipt",
    },
)


class Option2ProvisionerViolation(RuntimeError):
    """Raised when the inactive manifest or fixture simulation is not exact."""


def _canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _validate_sha256(value: object, *, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value == "0" * 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise Option2ProvisionerViolation(code)
    return value


def build_option2_plan_review_content(
    *, predecessor_option1_result_review_sha256: str
) -> dict[str, object]:
    """Return the exact non-authorizing owner-review receipt content."""

    _validate_sha256(
        predecessor_option1_result_review_sha256,
        code="option2_predecessor_result_review_sha256_invalid",
    )
    plan = build_option2_service_identity_and_vault_plan()
    if plan.get("plan_sha256") != EXPECTED_OPTION2_PLAN_SHA256:
        raise Option2ProvisionerViolation("option2_reviewed_plan_digest_drifted")
    return {
        "version": 1,
        "classification": "option2_service_identity_and_vault_offline_plan_review",
        "status": "reviewed_inactive",
        "predecessor_option1_result_review_sha256": (
            predecessor_option1_result_review_sha256
        ),
        "plan_version": plan["version"],
        "plan_classification": plan["classification"],
        "plan_state": plan["state"],
        "plan_sha256": plan["plan_sha256"],
        "review_passed": True,
        "component_count": len(plan["components"]),
        "owner_side_provisioner_outside_atlas": True,
        "owner_present_admin_required_for_future_provisioning": True,
        "production_paths_configured": 0,
        "accounts_created": False,
        "access_permissions_changed": False,
        "background_service_installed": False,
        "keychain_queried": False,
        "runtime_installed": False,
        "vault_adapter_connected": False,
        "real_credential_present": False,
        "private_data_present": False,
        "model_contacted": False,
        "provider_contacted": False,
        "network_accessed": False,
        "deployment_performed": False,
        "authority_granted": False,
        "provisioning_authorized": False,
        "service_identity_creation_authorized": False,
        "service_identity_provisioning_authorized": False,
        "vault_provisioning_authorized": False,
        "credential_use_authorized": False,
        "private_data_transmission_authorized": False,
        "model_contact_authorized": False,
        "network_access_authorized": False,
        "access_change_authorized": False,
        "background_execution_authorized": False,
        "deployment_authorized": False,
        "live_execution_authorized": False,
    }


def option2_plan_review_content_sha256(
    *, predecessor_option1_result_review_sha256: str
) -> str:
    """Bind the manifest to the exact append-once review content."""

    return _sha256(
        build_option2_plan_review_content(
            predecessor_option1_result_review_sha256=(
                predecessor_option1_result_review_sha256
            )
        )
    )


def _component_manifest(component: Mapping[str, Any]) -> dict[str, object]:
    name = str(component["name"])
    peer_intent = _DIRECTED_PEER_INTENT[name]
    return {
        "name": name,
        "service_identity": component["service_identity"],
        "bundle_id": component["bundle_id"],
        "responsibility": component["responsibility"],
        "uid_state": "unassigned_until_authorized_provisioning",
        "gid_state": "unassigned_until_authorized_provisioning",
        "user_and_group_must_be_distinct": True,
        "password_state": "locked",
        "hidden_account": True,
        "login_shell": "/usr/bin/false",
        "home_directory": "/var/empty",
        "supplementary_groups": [],
        "process_user": component["service_identity"],
        "process_group": component["service_identity"],
        "binary_path": component["binary_path"],
        "binary_owner": "root",
        "binary_group": "wheel",
        "binary_mode": "0555",
        "binary_sha256_state": "unassigned_until_artifact_review",
        "launchd_plist_path": component["launchd_plist_path"],
        "launchd_owner": "root",
        "launchd_group": "wheel",
        "launchd_mode": "0644",
        "launchd_user_name": component["service_identity"],
        "launchd_run_at_load": False,
        "launchd_keep_alive": False,
        "launchd_disabled": True,
        "launchd_definition_present_on_host": False,
        "launchd_install_authorized": False,
        "state_root": component["state_root"],
        "state_owner": component["service_identity"],
        "state_group": component["service_identity"],
        "state_mode": "0700",
        "socket_directory": component["socket_directory"],
        "socket_path": component["socket_path"],
        "socket_owner": component["service_identity"],
        "socket_group": component["service_identity"],
        "socket_mode": "0600_plus_exact_named_peer_acl",
        "no_follow_creation_required": True,
        "stale_socket_rejected": True,
        "designated_requirement_template": (
            f'identifier "{component["bundle_id"]}" and anchor apple generic '
            "and certificate leaf[subject.OU] = OPTION2_OWNER_TEAM_ID"
        ),
        "owner_team_id_state": "unassigned_until_artifact_review",
        "designated_requirement_sha256_state": "unassigned_until_artifact_review",
        "production_code_requirement_complete": False,
        "hardened_runtime_required": True,
        "adhoc_signature_allowed": False,
        "minimal_entitlements_digest_state": "unassigned_until_artifact_review",
        "debugger_or_dyld_entitlement_allowed": False,
        "verification_key_id_state": "unassigned_until_key_review",
        "verification_key_epoch_state": "unassigned_until_key_review",
        "private_key_material_state": "absent",
        "directed_peer_intent": [
            {
                "principal": principal,
                "operations": list(operations),
                "audit_token_required": True,
                "exact_code_identity_required": True,
                "one_use_nonce_required": True,
            }
            for principal, operations in peer_intent
        ],
        "peer_acl_activation_state": "withheld_until_manifest_and_artifact_review",
        "caller_selectable_peer_or_operation": False,
        "broad_group_access": False,
        "world_access": False,
        "ip_network_authority": False,
        "service_loaded": False,
        "socket_active": False,
        "simulation_paths": {
            "identity": f"identities/{name}.json",
            "group": f"groups/{name}.json",
            "state_root": f"components/{name}/state",
            "socket_directory": f"components/{name}/socket",
            "binary": f"components/{name}/binary",
            "service_definition": f"staged-service-definitions/{name}.json",
        },
    }


def _rollback_contract() -> dict[str, object]:
    return {
        "order": "strict_reverse_completed_stage_order",
        "coverage": {
            str(stage["id"]): {
                "action": "restore_preflight_snapshot_for_exact_transaction_inventory",
                "delete_only_new_transaction_owned_artifacts": True,
                "restore_only_digest_bound_preexisting_artifacts": True,
                "service_load_or_start_allowed": False,
            }
            for stage in _TRANSACTION_STAGES
        },
        "rollback_uncertainty_result": "quarantined_inactive",
        "quarantine": {
            "assert_owner_pause": True,
            "load_or_start_service": False,
            "activate_socket": False,
            "create_key_or_vault_item": False,
            "set_production_configuration_path": False,
            "continue_transaction": False,
            "retain_only_privacy_minimized_digest_evidence": True,
            "fresh_owner_review_required": True,
        },
    }


def _manifest_body() -> dict[str, object]:
    plan = build_option2_service_identity_and_vault_plan()
    if plan.get("plan_sha256") != EXPECTED_OPTION2_PLAN_SHA256:
        raise Option2ProvisionerViolation("option2_reviewed_plan_digest_drifted")
    plan_body = {key: value for key, value in plan.items() if key != "plan_sha256"}
    validate_option2_service_identity_and_vault_plan(plan_body)
    components = plan.get("components")
    if not isinstance(components, list):  # pragma: no cover - plan validator owns this
        raise Option2ProvisionerViolation("option2_reviewed_plan_components_invalid")
    return {
        "version": OPTION2_PROVISIONER_VERSION,
        "classification": OPTION2_PROVISIONER_CLASSIFICATION,
        "state": OPTION2_PROVISIONER_STATE,
        "reviewed_plan_sha256": EXPECTED_OPTION2_PLAN_SHA256,
        "plan_review_content_sha256_state": (
            "bound_by_append_once_service_receipt_before_fixture_qualification"
        ),
        "platform": "macos",
        "execution_mode": "in_memory_fixture_simulation_only",
        "fixture_only": True,
        "production_manifest_complete": False,
        "production_artifact_bindings_present": False,
        "host_apply_present": False,
        "live_paths_descriptive_only": True,
        "provisioner_boundary": {
            "owner_side_external_to_atlas": True,
            "atlas_runtime_callable": False,
            "signed_installer_required": True,
            "owner_present_admin_required_for_future_execution": True,
            "fresh_manifest_bound_authorization_required": True,
            "host_inspection_performed_by_this_module": False,
            "filesystem_access_performed_by_this_module": False,
            "subprocess_allowed_by_this_module": False,
            "socket_access_allowed_by_this_module": False,
            "keychain_access_allowed_by_this_module": False,
            "network_access_allowed_by_this_module": False,
            "model_contact_allowed_by_this_module": False,
        },
        "components": [_component_manifest(item) for item in components],
        "preflight_invariants": deepcopy(list(_PREFLIGHT_INVARIANTS)),
        "transaction_stages": deepcopy(list(_TRANSACTION_STAGES)),
        "rollback": _rollback_contract(),
        "production_configuration": {
            field: None for field in PRODUCTION_CONFIGURATION_FIELDS
        },
        "separate_later_gates": {
            "actual_service_identity_provisioning": True,
            "artifact_signing_and_key_epoch_binding": True,
            "live_launchd_definition_installation": True,
            "service_enablement": True,
            "empty_vault_provisioning": True,
            "credential_insertion": True,
            "independent_production_broker_qualification": True,
            "model_or_provider_contact": True,
            "task_bound_live_authorization": True,
        },
        "authority": {field: False for field in _AUTHORITY_FALSE_FIELDS},
        "ready": False,
        "ready_offline": False,
        "ready_live": False,
        "next_gate": OPTION2_PROVISIONER_NEXT_GATE,
    }


def validate_option2_provisioner_manifest(manifest: Mapping[str, Any]) -> None:
    """Require the exact non-authorizing manifest and its separation rules."""

    expected = _manifest_body()
    if not isinstance(manifest, Mapping) or dict(manifest) != expected:
        raise Option2ProvisionerViolation("option2_provisioner_manifest_not_canonical")
    components = manifest.get("components")
    if not isinstance(components, list) or len(components) != 6:
        raise Option2ProvisionerViolation("option2_provisioner_component_count_invalid")
    identities = [component.get("service_identity") for component in components]
    paths = [
        component.get(field)
        for component in components
        for field in ("binary_path", "launchd_plist_path", "state_root", "socket_path")
    ]
    if len(set(identities)) != 6 or len(set(paths)) != 24:
        raise Option2ProvisionerViolation("option2_provisioner_separation_invalid")
    if any(
        component.get("process_user") != component.get("service_identity")
        or component.get("process_group") != component.get("service_identity")
        or component.get("supplementary_groups") != []
        or component.get("binary_owner") != "root"
        or component.get("binary_group") != "wheel"
        or component.get("launchd_disabled") is not True
        or component.get("service_loaded") is not False
        or component.get("socket_active") is not False
        or component.get("private_key_material_state") != "absent"
        or component.get("caller_selectable_peer_or_operation") is not False
        or component.get("broad_group_access") is not False
        or component.get("world_access") is not False
        for component in components
    ):
        raise Option2ProvisionerViolation("option2_provisioner_identity_boundary_invalid")
    production = manifest.get("production_configuration")
    if not isinstance(production, Mapping) or set(production) != set(
        PRODUCTION_CONFIGURATION_FIELDS
    ) or any(production[field] is not None for field in PRODUCTION_CONFIGURATION_FIELDS):
        raise Option2ProvisionerViolation("option2_production_configuration_not_null")
    stages = manifest.get("transaction_stages")
    rollback = manifest.get("rollback")
    if not isinstance(stages, list) or not isinstance(rollback, Mapping):
        raise Option2ProvisionerViolation("option2_provisioner_transaction_invalid")
    stage_ids = [stage.get("id") for stage in stages]
    coverage = rollback.get("coverage")
    if not isinstance(coverage, Mapping) or set(coverage) != set(stage_ids):
        raise Option2ProvisionerViolation("option2_provisioner_rollback_incomplete")
    authority = manifest.get("authority")
    if not isinstance(authority, Mapping) or set(authority) != set(
        _AUTHORITY_FALSE_FIELDS
    ) or any(authority[field] is not False for field in _AUTHORITY_FALSE_FIELDS):
        raise Option2ProvisionerViolation("option2_provisioner_authority_open")


def build_option2_provisioner_manifest() -> dict[str, object]:
    """Return the exact inactive manifest plus its deterministic digest."""

    body = _manifest_body()
    validate_option2_provisioner_manifest(body)
    return {**deepcopy(body), "manifest_sha256": _sha256(body)}


def _manifest_body_from_envelope(manifest: Mapping[str, Any]) -> dict[str, Any]:
    body = {key: deepcopy(value) for key, value in manifest.items() if key != "manifest_sha256"}
    validate_option2_provisioner_manifest(body)
    expected_digest = _sha256(body)
    if manifest.get("manifest_sha256") != expected_digest:
        raise Option2ProvisionerViolation("option2_provisioner_manifest_digest_invalid")
    return body


def _validate_fixture_root(value: str) -> str:
    if not isinstance(value, str) or not value.startswith("/") or "\x00" in value:
        raise Option2ProvisionerViolation("option2_fixture_root_invalid")
    root = PurePosixPath(value)
    if (
        ".." in root.parts
        or root.parent != PurePosixPath("/private/tmp")
        or not root.name.startswith("atlas-option2-fixture-")
    ):
        raise Option2ProvisionerViolation("option2_fixture_root_invalid")
    return str(root)


_PREFLIGHT_CASES = (
    "clean",
    "group_collision",
    "identity_collision",
    "directory_collision",
    "artifact_collision",
    "service_definition_collision",
    "symlink_target",
    "acl_drift",
    "code_signing_drift",
    "production_path_configured",
    "service_loaded",
    "socket_active",
    "key_present",
    "vault_item_present",
    "owner_pause_unlatched",
)


def _virtual_prestate(
    manifest: Mapping[str, Any], *, preflight_case: str
) -> dict[str, object]:
    state: dict[str, object] = {
        "manifest_attested": False,
        "preflight_verified": False,
        "future_authorization_contract_attested": False,
        "groups": {},
        "identities": {},
        "directories": {},
        "artifacts": {},
        "staged_service_definitions": {},
        "services_loaded": [],
        "sockets_active": [],
        "keys": [],
        "vault_items": [],
        "owner_pause_latched": True,
        "inactive_postflight_verified": False,
        "receipts": [],
        "quarantined": False,
        "conflicts": {},
        "production_configuration": {
            field: None for field in PRODUCTION_CONFIGURATION_FIELDS
        },
    }
    conflicts = state["conflicts"]
    if not isinstance(conflicts, dict):  # pragma: no cover - local invariant
        raise Option2ProvisionerViolation("option2_fixture_state_invalid")
    if preflight_case == "group_collision":
        groups = state["groups"]
        if not isinstance(groups, dict):  # pragma: no cover - local invariant
            raise Option2ProvisionerViolation("option2_fixture_state_invalid")
        groups["_atlaspolicy"] = {"fixture_gid": "preexisting"}
    elif preflight_case == "identity_collision":
        conflicts["identity"] = "_atlaspolicy"
    elif preflight_case == "directory_collision":
        directories = state["directories"]
        if not isinstance(directories, dict):  # pragma: no cover
            raise Option2ProvisionerViolation("option2_fixture_state_invalid")
        directories["policy_broker"] = {"kind": "preexisting"}
    elif preflight_case == "artifact_collision":
        artifacts = state["artifacts"]
        if not isinstance(artifacts, dict):  # pragma: no cover
            raise Option2ProvisionerViolation("option2_fixture_state_invalid")
        artifacts["policy_broker"] = {"kind": "preexisting"}
    elif preflight_case == "service_definition_collision":
        definitions = state["staged_service_definitions"]
        if not isinstance(definitions, dict):  # pragma: no cover
            raise Option2ProvisionerViolation("option2_fixture_state_invalid")
        definitions["policy_broker"] = {"kind": "preexisting"}
    elif preflight_case == "symlink_target":
        conflicts["target_kind"] = "symlink"
    elif preflight_case == "acl_drift":
        conflicts["acl"] = "unexpected_named_principal"
    elif preflight_case == "code_signing_drift":
        conflicts["code_signing"] = "designated_requirement_mismatch"
    elif preflight_case == "production_path_configured":
        production = state["production_configuration"]
        if not isinstance(production, dict):  # pragma: no cover - local invariant
            raise Option2ProvisionerViolation("option2_fixture_state_invalid")
        production[PRODUCTION_CONFIGURATION_FIELDS[0]] = "fixture:unexpected"
    elif preflight_case == "service_loaded":
        loaded = state["services_loaded"]
        if not isinstance(loaded, list):  # pragma: no cover - local invariant
            raise Option2ProvisionerViolation("option2_fixture_state_invalid")
        loaded.append(str(manifest["components"][0]["bundle_id"]))
    elif preflight_case == "socket_active":
        sockets = state["sockets_active"]
        if not isinstance(sockets, list):  # pragma: no cover
            raise Option2ProvisionerViolation("option2_fixture_state_invalid")
        sockets.append(str(manifest["components"][0]["socket_path"]))
    elif preflight_case == "key_present":
        keys = state["keys"]
        if not isinstance(keys, list):  # pragma: no cover
            raise Option2ProvisionerViolation("option2_fixture_state_invalid")
        keys.append("fixture:preexisting-key")
    elif preflight_case == "vault_item_present":
        vault_items = state["vault_items"]
        if not isinstance(vault_items, list):  # pragma: no cover
            raise Option2ProvisionerViolation("option2_fixture_state_invalid")
        vault_items.append("fixture:preexisting-vault-item")
    elif preflight_case == "owner_pause_unlatched":
        state["owner_pause_latched"] = False
    return state


def _virtual_preflight_clean(state: Mapping[str, Any]) -> bool:
    production = state.get("production_configuration")
    return (
        state.get("conflicts") == {}
        and state.get("groups") == {}
        and state.get("identities") == {}
        and state.get("directories") == {}
        and state.get("artifacts") == {}
        and state.get("staged_service_definitions") == {}
        and state.get("services_loaded") == []
        and state.get("sockets_active") == []
        and state.get("keys") == []
        and state.get("vault_items") == []
        and state.get("owner_pause_latched") is True
        and isinstance(production, Mapping)
        and set(production) == set(PRODUCTION_CONFIGURATION_FIELDS)
        and all(production[field] is None for field in PRODUCTION_CONFIGURATION_FIELDS)
    )


def _apply_virtual_stage(
    state: dict[str, object],
    *,
    stage_id: str,
    manifest: Mapping[str, Any],
) -> None:
    components = manifest["components"]
    if stage_id == "attest_manifest":
        state["manifest_attested"] = True
    elif stage_id == "preflight_host":
        if not _virtual_preflight_clean(state):
            raise Option2ProvisionerViolation("option2_fixture_preflight_rejected")
        state["preflight_verified"] = True
    elif stage_id == "attest_future_owner_authorization_contract":
        state["future_authorization_contract_attested"] = True
    elif stage_id == "create_service_groups":
        state["groups"] = {
            str(component["service_identity"]): {
                "fixture_gid": f"fixture-gid-{index + 1}",
                "supplementary_members": [],
            }
            for index, component in enumerate(components)
        }
    elif stage_id == "create_service_identities":
        state["identities"] = {
            str(component["service_identity"]): {
                "fixture_uid": f"fixture-uid-{index + 1}",
                "primary_group": component["service_identity"],
                "hidden": True,
                "password_locked": True,
                "login_shell": "/usr/bin/false",
                "home_directory": "/var/empty",
            }
            for index, component in enumerate(components)
        }
    elif stage_id == "create_disjoint_roots":
        state["directories"] = {
            str(component["name"]): {
                "state_root": component["simulation_paths"]["state_root"],
                "socket_directory": component["simulation_paths"][
                    "socket_directory"
                ],
                "owner": component["service_identity"],
                "mode": "0700",
            }
            for component in components
        }
    elif stage_id == "install_signed_artifacts":
        state["artifacts"] = {
            str(component["name"]): {
                "relative_path": component["simulation_paths"]["binary"],
                "synthetic_sha256": hashlib.sha256(
                    f"fixture:{component['bundle_id']}".encode("utf-8")
                ).hexdigest(),
                "signature": "synthetic-placeholder-not-production",
                "owner": "root",
                "group": "wheel",
                "mode": "0555",
            }
            for component in components
        }
    elif stage_id == "stage_service_definitions_outside_live_launchd":
        state["staged_service_definitions"] = {
            str(component["name"]): {
                "relative_path": component["simulation_paths"][
                    "service_definition"
                ],
                "live_launchd_path_written": False,
                "disabled": True,
            }
            for component in components
        }
    elif stage_id == "validate_inactive_postflight":
        state["inactive_postflight_verified"] = (
            state.get("owner_pause_latched") is True
            and state.get("services_loaded") == []
            and state.get("sockets_active") == []
            and state.get("keys") == []
            and state.get("vault_items") == []
        )
    elif stage_id == "seal_non_authorizing_receipt":
        state["receipts"] = [
            {
                "classification": "fixture_only_non_authorizing_receipt",
                "predecessor_state_sha256": _sha256(state),
                "authority_granted": False,
            }
        ]
    else:  # pragma: no cover - exact manifest validation owns the stage list
        raise Option2ProvisionerViolation("option2_fixture_stage_unknown")


def _virtual_resource_counts(state: Mapping[str, Any]) -> dict[str, int]:
    return {
        field: len(state.get(field, {}))
        for field in (
            "groups",
            "identities",
            "directories",
            "artifacts",
            "staged_service_definitions",
            "services_loaded",
            "sockets_active",
            "keys",
            "vault_items",
            "receipts",
        )
    }


def _virtual_success_invariants(state: Mapping[str, Any]) -> dict[str, bool]:
    receipts = state.get("receipts")
    receipt = receipts[0] if isinstance(receipts, list) and len(receipts) == 1 else None
    pre_receipt_state = deepcopy(dict(state))
    pre_receipt_state["receipts"] = []
    expected_predecessor_sha256 = _sha256(pre_receipt_state)
    production = state.get("production_configuration")
    counts = _virtual_resource_counts(state)
    return {
        "manifest_attested": state.get("manifest_attested") is True,
        "preflight_verified": state.get("preflight_verified") is True,
        "future_authorization_contract_attested": (
            state.get("future_authorization_contract_attested") is True
        ),
        "six_groups_projected": counts["groups"] == 6,
        "six_identities_projected": counts["identities"] == 6,
        "six_disjoint_roots_projected": counts["directories"] == 6,
        "six_synthetic_artifacts_projected": counts["artifacts"] == 6,
        "six_inert_service_definitions_projected": (
            counts["staged_service_definitions"] == 6
        ),
        "no_service_loaded": counts["services_loaded"] == 0,
        "no_socket_active": counts["sockets_active"] == 0,
        "no_key_present": counts["keys"] == 0,
        "no_vault_item_present": counts["vault_items"] == 0,
        "owner_pause_latched": state.get("owner_pause_latched") is True,
        "inactive_postflight_verified": (
            state.get("inactive_postflight_verified") is True
        ),
        "one_non_authorizing_receipt_projected": (
            isinstance(receipt, Mapping)
            and set(receipt)
            == {
                "classification",
                "predecessor_state_sha256",
                "authority_granted",
            }
            and receipt.get("classification")
            == "fixture_only_non_authorizing_receipt"
            and receipt.get("authority_granted") is False
            and isinstance(receipt.get("predecessor_state_sha256"), str)
            and receipt.get("predecessor_state_sha256")
            == expected_predecessor_sha256
        ),
        "production_configuration_null": (
            isinstance(production, Mapping)
            and set(production) == set(PRODUCTION_CONFIGURATION_FIELDS)
            and all(
                production[field] is None
                for field in PRODUCTION_CONFIGURATION_FIELDS
            )
        ),
    }


def simulate_option2_provisioner(
    manifest: Mapping[str, Any],
    *,
    fixture_root: str,
    fail_after_stage: str | None = None,
    fail_rollback_at_stage: str | None = None,
    preflight_case: str = "clean",
) -> dict[str, object]:
    """Simulate the transaction in memory without inspecting or writing a path."""

    body = _manifest_body_from_envelope(manifest)
    normalized_fixture_root = _validate_fixture_root(fixture_root)
    stages = body["transaction_stages"]
    stage_ids = [str(stage["id"]) for stage in stages]
    if fail_after_stage is not None and fail_after_stage not in stage_ids:
        raise Option2ProvisionerViolation("option2_fixture_failure_stage_invalid")
    if fail_rollback_at_stage is not None and (
        fail_after_stage is None or fail_rollback_at_stage not in stage_ids
    ):
        raise Option2ProvisionerViolation("option2_fixture_rollback_stage_invalid")
    if preflight_case not in _PREFLIGHT_CASES:
        raise Option2ProvisionerViolation("option2_fixture_preflight_case_invalid")
    state = _virtual_prestate(body, preflight_case=preflight_case)
    preflight_snapshot = deepcopy(state)
    preflight_snapshot_sha256 = _sha256(preflight_snapshot)
    completed: list[str] = []
    snapshots: list[tuple[str, dict[str, object]]] = []
    preflight_rejected = False
    for stage_id in stage_ids:
        before_stage = deepcopy(state)
        try:
            _apply_virtual_stage(state, stage_id=stage_id, manifest=body)
        except Option2ProvisionerViolation as exc:
            if str(exc) != "option2_fixture_preflight_rejected":
                raise
            preflight_rejected = True
            state = before_stage
            break
        snapshots.append((stage_id, before_stage))
        completed.append(stage_id)
        if stage_id == fail_after_stage:
            break
    rolled_back: list[str] = []
    quarantined = False
    if fail_after_stage is not None:
        for stage_id, before_stage in reversed(snapshots):
            if stage_id == fail_rollback_at_stage:
                quarantined = True
                state["quarantined"] = True
                state["owner_pause_latched"] = True
                break
            state = before_stage
            rolled_back.append(stage_id)
    restored_to_preflight = _sha256(state) == preflight_snapshot_sha256
    if preflight_rejected:
        outcome = "rejected_inactive"
    elif quarantined:
        outcome = "quarantined_inactive"
    elif fail_after_stage is not None:
        outcome = "rolled_back_inactive"
    else:
        outcome = "qualified_inactive"
    report_body: dict[str, object] = {
        "classification": "option2_provisioner_in_memory_fixture_simulation",
        "manifest_sha256": manifest["manifest_sha256"],
        "fixture_root_sha256": hashlib.sha256(
            normalized_fixture_root.encode("utf-8")
        ).hexdigest(),
        "in_memory_only": True,
        "fixture_only": True,
        "production_manifest_complete": False,
        "host_apply_present": False,
        "owner_authorization_claimed": False,
        "future_authorization_contract_attested": state.get(
            "future_authorization_contract_attested"
        )
        is True,
        "fixture_engine_host_inspected": False,
        "fixture_engine_filesystem_read": False,
        "fixture_engine_filesystem_written": False,
        "fixture_engine_temporary_files_written": False,
        "fixture_engine_subprocess_started": False,
        "fixture_engine_account_api_called": False,
        "code_signature_contract_validated": True,
        "host_code_signature_verified": False,
        "fixture_engine_keychain_queried": False,
        "fixture_engine_socket_opened": False,
        "fixture_engine_launchd_contacted": False,
        "fixture_engine_network_accessed": False,
        "fixture_engine_model_contacted": False,
        "fixture_engine_provider_contacted": False,
        "completed_stages": completed,
        "stage_order_valid": completed == stage_ids[: len(completed)],
        "failure_injected_after_stage": fail_after_stage,
        "rollback_failure_injected_at_stage": fail_rollback_at_stage,
        "preflight_case": preflight_case,
        "preflight_rejected": preflight_rejected,
        "rollback_stages": rolled_back,
        "rollback_complete": (
            fail_after_stage is None
            or (
                not quarantined
                and rolled_back == list(reversed(completed))
                and restored_to_preflight
            )
        ),
        "quarantined": quarantined,
        "preflight_snapshot_sha256": preflight_snapshot_sha256,
        "final_virtual_state_sha256": _sha256(state),
        "restored_to_preflight_snapshot": restored_to_preflight,
        "virtual_resource_counts": _virtual_resource_counts(state),
        "virtual_success_invariants": _virtual_success_invariants(state),
        "simulated_accounts_created": len(state.get("identities", {})),
        "simulated_groups_created": len(state.get("groups", {})),
        "production_configuration": {
            field: None for field in PRODUCTION_CONFIGURATION_FIELDS
        },
        "authority": {field: False for field in _AUTHORITY_FALSE_FIELDS},
        "outcome": outcome,
        "ready": False,
        "ready_offline": False,
        "ready_live": False,
    }
    return {**report_body, "simulation_sha256": _sha256(report_body)}


def review_option2_provisioner_contract(
    *, service_verified_plan_review_content_sha256: str
) -> dict[str, object]:
    """Qualify the exact in-memory fixture engine within its stated scope.

    The pure engine cannot inspect the Atlas ledger. Its caller must first
    verify the exact append-once plan-review receipt and pass that content
    digest. Only the Supervisor service may persist this report.
    """

    _validate_sha256(
        service_verified_plan_review_content_sha256,
        code="option2_plan_review_content_sha256_invalid",
    )
    manifest = build_option2_provisioner_manifest()
    fixture_root = "/private/tmp/atlas-option2-fixture-contract-v1"
    success = simulate_option2_provisioner(manifest, fixture_root=fixture_root)
    stage_ids = [str(stage["id"]) for stage in manifest["transaction_stages"]]
    post_stage_failure_cases = {
        stage_id: {
            "simulation_sha256": failure["simulation_sha256"],
            "outcome": failure["outcome"],
            "restored_to_preflight_snapshot": failure[
                "restored_to_preflight_snapshot"
            ],
            "rollback_complete": failure["rollback_complete"],
        }
        for stage_id in stage_ids
        for failure in (
            simulate_option2_provisioner(
                manifest,
                fixture_root=fixture_root,
                fail_after_stage=stage_id,
            ),
        )
    }
    rejection_cases = {
        case: rejected["simulation_sha256"]
        for case in _PREFLIGHT_CASES
        if case != "clean"
        for rejected in (
            simulate_option2_provisioner(
                manifest,
                fixture_root=fixture_root,
                preflight_case=case,
            ),
        )
        if rejected["outcome"] == "rejected_inactive"
    }
    rollback_uncertainty_cases = {
        stage_id: uncertain["simulation_sha256"]
        for stage_id in stage_ids
        for uncertain in (
            simulate_option2_provisioner(
                manifest,
                fixture_root=fixture_root,
                fail_after_stage=stage_id,
                fail_rollback_at_stage=stage_id,
            ),
        )
        if (
            uncertain["outcome"] == "quarantined_inactive"
            and uncertain["quarantined"] is True
            and uncertain["rollback_complete"] is False
        )
    }
    all_virtual_post_stage_snapshot_rollbacks_covered = (
        set(post_stage_failure_cases) == set(stage_ids)
        and all(
            case["restored_to_preflight_snapshot"] is True
            and case["rollback_complete"] is True
            and case["outcome"] == "rolled_back_inactive"
            for case in post_stage_failure_cases.values()
        )
    )
    all_declared_fixture_conflict_cases_rejected = set(rejection_cases) == (
        set(_PREFLIGHT_CASES) - {"clean"}
    )
    all_virtual_rollback_failures_quarantined = set(
        rollback_uncertainty_cases
    ) == set(stage_ids)
    expected_counts = {
        "groups": 6,
        "identities": 6,
        "directories": 6,
        "artifacts": 6,
        "staged_service_definitions": 6,
        "services_loaded": 0,
        "sockets_active": 0,
        "keys": 0,
        "vault_items": 0,
        "receipts": 1,
    }
    success_exact = (
        success["outcome"] == "qualified_inactive"
        and success["completed_stages"] == stage_ids
        and success["stage_order_valid"] is True
        and success["virtual_resource_counts"] == expected_counts
        and all(success["virtual_success_invariants"].values())
        and success["owner_authorization_claimed"] is False
        and success["fixture_engine_host_inspected"] is False
        and success["fixture_engine_filesystem_read"] is False
        and success["fixture_engine_filesystem_written"] is False
        and success["fixture_engine_temporary_files_written"] is False
        and success["fixture_engine_subprocess_started"] is False
        and success["fixture_engine_account_api_called"] is False
        and success["fixture_engine_keychain_queried"] is False
        and success["fixture_engine_socket_opened"] is False
        and success["fixture_engine_launchd_contacted"] is False
        and success["fixture_engine_network_accessed"] is False
        and success["fixture_engine_model_contacted"] is False
        and success["fixture_engine_provider_contacted"] is False
        and success["ready"] is False
        and success["ready_offline"] is False
        and success["ready_live"] is False
        and success["authority"] == manifest["authority"]
        and success["production_configuration"]
        == manifest["production_configuration"]
    )
    if not (
        success_exact
        and all_virtual_post_stage_snapshot_rollbacks_covered
        and all_declared_fixture_conflict_cases_rejected
        and all_virtual_rollback_failures_quarantined
    ):
        raise Option2ProvisionerViolation(
            "option2_provisioner_fixture_qualification_failed"
        )
    qualification_body: dict[str, object] = {
        "classification": "option2_provisioner_offline_fixture_qualification",
        "state": OPTION2_PROVISIONER_QUALIFICATION_STATE,
        "reviewed_plan_sha256": EXPECTED_OPTION2_PLAN_SHA256,
        "service_verified_plan_review_content_sha256": (
            service_verified_plan_review_content_sha256
        ),
        "manifest_sha256": manifest["manifest_sha256"],
        "success_simulation_sha256": success["simulation_sha256"],
        "virtual_success_invariants": success["virtual_success_invariants"],
        "post_stage_rollback_cases": post_stage_failure_cases,
        "virtual_post_stage_rollback_case_count": len(post_stage_failure_cases),
        "all_virtual_post_stage_snapshot_rollbacks_covered": (
            all_virtual_post_stage_snapshot_rollbacks_covered
        ),
        "declared_fixture_preflight_rejection_case_sha256": rejection_cases,
        "declared_fixture_preflight_rejection_case_count": len(rejection_cases),
        "all_declared_fixture_conflict_cases_rejected": (
            all_declared_fixture_conflict_cases_rejected
        ),
        "virtual_rollback_uncertainty_case_sha256": rollback_uncertainty_cases,
        "virtual_rollback_uncertainty_case_count": len(
            rollback_uncertainty_cases
        ),
        "all_virtual_rollback_failures_quarantined": (
            all_virtual_rollback_failures_quarantined
        ),
        "production_preflight_qualified": False,
        "production_rollback_qualified": False,
        "in_memory_fixture_engine_only": True,
        "production_manifest_complete": False,
        "host_apply_present": False,
        "fixture_engine_host_inspected": False,
        "fixture_engine_filesystem_read": False,
        "fixture_engine_filesystem_written": False,
        "fixture_engine_temporary_files_written": False,
        "fixture_engine_subprocess_started": False,
        "fixture_engine_account_api_called": False,
        "fixture_engine_keychain_queried": False,
        "fixture_engine_socket_opened": False,
        "fixture_engine_launchd_contacted": False,
        "fixture_engine_network_accessed": False,
        "fixture_engine_model_contacted": False,
        "fixture_engine_provider_contacted": False,
        "production_configuration": {
            field: None for field in PRODUCTION_CONFIGURATION_FIELDS
        },
        "authority": {field: False for field in _AUTHORITY_FALSE_FIELDS},
        "ready": False,
        "ready_offline": False,
        "ready_live": False,
        "next_gate": OPTION2_PROVISIONER_NEXT_GATE,
    }
    return {**qualification_body, "qualification_sha256": _sha256(qualification_body)}
