"""Inactive Option 2 point-of-action provisioning contract.

This module is a deterministic, data-only design and fixture qualification.
It cannot inspect a host, request administrator privileges, create an account,
touch a filesystem, open Keychain, start a service, contact a network, or grant
authority.  A future root-owned provisioner remains separately unimplemented.

The design deliberately separates two future owner decisions.  The first may
authorize one fresh privileged *read-only* preflight.  A successful preflight
may produce a short-lived, privacy-minimized evidence envelope, but it cannot
authorize mutation.  Identity creation would still require a second exact
owner confirmation bound to that envelope and to the whole transaction.
"""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from typing import Any, Mapping


OPTION2_POINT_ACTION_VERSION = 1
OPTION2_POINT_ACTION_CLASSIFICATION = (
    "option2_service_identity_point_action_provisioning_contract"
)
OPTION2_POINT_ACTION_STATE = "implemented_inactive"
OPTION2_POINT_ACTION_QUALIFICATION_STATE = "qualified_inactive"
OPTION2_POINT_ACTION_NEXT_GATE = (
    "owner_authorize_option2_identity_only_point_of_action_read_only_preflight"
)
OPTION2_POINT_ACTION_MUTATION_GATE = (
    "owner_authorize_option2_identity_only_point_of_action_provisioning_apply"
)
OPTION2_POINT_ACTION_PREFLIGHT_VALIDITY_SECONDS = 300
OPTION2_POINT_ACTION_PREFLIGHT_CONFIRMATION_PREFIX = (
    "AUTHORIZE OPTION2 ONE-SHOT ADMIN READ-ONLY IDENTITY-ONLY "
    "POINT-OF-ACTION PREFLIGHT"
)

OPTION2_POINT_ACTION_PREFLIGHT_CONFIRMATION_BINDING_FIELDS: tuple[str, ...] = (
    "preflight_request_id",
    "one_use_nonce_sha256",
    "point_action_qualification_id",
    "point_action_qualification_content_sha256",
    "manifest_sha256",
    "policy_sha256",
    "sdk_lock_sha256",
    "source_bundle_sha256",
    "platform_tool_manifest_sha256",
    "fixed_target_identity_set_sha256",
    "identity_allocation_policy_sha256",
    "fixed_query_scope_sha256",
    "host_instance_sha256",
    "os_build_sha256",
    "boot_session_sha256",
    "executor_instance_sha256",
    "root_provisioner_sha256",
    "root_provisioner_code_requirement_sha256",
    "authorization_claim_ledger_instance_sha256",
    "authorization_claim_ledger_epoch",
    "authorization_claim_ledger_head_sha256",
    "authorization_claim_ledger_anti_rollback_anchor_sha256",
    "predecessor_ledger_head_sha256",
    "issued_at",
    "expires_at",
    "monotonic_deadline_ns",
)
OPTION2_POINT_ACTION_MUTATION_CONFIRMATION_PREFIX = (
    "AUTHORIZE OPTION2 ONE-SHOT IDENTITY-ONLY POINT-OF-ACTION "
    "PROVISIONING APPLY"
)

OPTION2_POINT_ACTION_AUTHORITY_FIELDS: tuple[str, ...] = (
    "access_change_authorized",
    "admin_prompt_authorized",
    "authority_granted",
    "background_execution_authorized",
    "credential_use_authorized",
    "deployment_authorized",
    "external_communication_authorized",
    "filesystem_mutation_authorized",
    "host_query_authorized",
    "identity_creation_authorized",
    "live_execution_authorized",
    "model_contact_authorized",
    "network_access_authorized",
    "private_data_transmission_authorized",
    "provisioning_authorized",
    "service_identity_provisioning_authorized",
    "vault_provisioning_authorized",
)

OPTION2_POINT_ACTION_EFFECT_FIELDS: tuple[str, ...] = (
    "accounts_created",
    "admin_prompt_displayed",
    "background_service_installed",
    "credentials_accessed",
    "directory_service_queried",
    "filesystem_ownership_scanned",
    "filesystem_written",
    "groups_created",
    "host_inspected",
    "key_material_created",
    "keychain_queried",
    "launchd_contacted",
    "model_contacted",
    "network_accessed",
    "private_data_present",
    "provider_contacted",
    "subprocess_started",
    "vault_item_created",
)

OPTION2_POINT_ACTION_PREFLIGHT_REQUIREMENT_IDS: tuple[str, ...] = (
    "fresh_one_use_preflight_authorization_claimed_before_prompt",
    "separately_signed_root_owned_provisioner_attested",
    "atlas_source_tree_not_executable_as_root",
    "privileged_process_environment_working_directory_and_io_fixed",
    "effective_directory_search_path_fully_inspected",
    "target_names_absent_case_insensitively_on_effective_search_path",
    "candidate_uid_gid_pairs_absent_from_directory_search_path",
    "candidate_uid_gid_pairs_absent_from_mounted_filesystem_ownership",
    "all_mounts_classified_and_all_local_ownership_bearing_mounts_inspected",
    "host_instance_and_os_build_bound",
    "manifest_source_tool_and_code_requirement_digests_bound",
    "all_targets_canonical_no_follow_and_collision_free",
    "services_sockets_keys_vault_items_and_production_paths_absent",
    "owner_pause_latched",
    "privacy_minimized_evidence_only",
    "short_lived_monotonic_deadline_bound",
)

OPTION2_POINT_ACTION_MUTATION_BINDING_FIELDS: tuple[str, ...] = (
    "transaction_id",
    "one_use_nonce_sha256",
    "point_action_qualification_id",
    "point_action_qualification_content_sha256",
    "preflight_claim_id",
    "preflight_claim_content_sha256",
    "preflight_evidence_sha256",
    "candidate_sha256",
    "manifest_sha256",
    "policy_sha256",
    "sdk_lock_sha256",
    "source_bundle_sha256",
    "root_provisioner_sha256",
    "root_provisioner_code_requirement_sha256",
    "platform_tool_manifest_sha256",
    "host_instance_sha256",
    "os_build_sha256",
    "boot_session_sha256",
    "executor_instance_sha256",
    "authorization_claim_ledger_instance_sha256",
    "authorization_claim_ledger_epoch",
    "authorization_claim_ledger_head_sha256",
    "authorization_claim_ledger_anti_rollback_anchor_sha256",
    "predecessor_ledger_head_sha256",
    "mounted_filesystem_classification_sha256",
    "mounted_ownership_bearing_filesystem_set_sha256",
    "effective_search_path_sha256",
    "target_collision_projection_sha256",
    "filesystem_ownership_scan_result_sha256",
    "fixed_target_identity_set_sha256",
    "identity_allocation_policy_sha256",
    "fixed_query_scope_sha256",
    "identity_assignments_sha256",
    "issued_at",
    "expires_at",
    "monotonic_deadline_ns",
)

_OPTION2_POINT_ACTION_IDENTITY_SLUGS: tuple[str, ...] = (
    "atlaspolicy",
    "atlasverify",
    "atlasvault",
    "atlasreceipt",
    "atlasstop",
    "atlasconnector",
)

_OPTION2_POINT_ACTION_GROUP_STAGE_IDS: tuple[str, ...] = tuple(
    f"create_group_{slug}" for slug in _OPTION2_POINT_ACTION_IDENTITY_SLUGS
)
_OPTION2_POINT_ACTION_IDENTITY_STAGE_IDS: tuple[str, ...] = tuple(
    f"create_locked_identity_{slug}"
    for slug in _OPTION2_POINT_ACTION_IDENTITY_SLUGS
)
_OPTION2_POINT_ACTION_CREATE_STAGE_IDS = (
    _OPTION2_POINT_ACTION_GROUP_STAGE_IDS
    + _OPTION2_POINT_ACTION_IDENTITY_STAGE_IDS
)
_OPTION2_POINT_ACTION_REVALIDATE_AND_CREATE_STAGE_IDS: tuple[str, ...] = tuple(
    stage_id
    for create_stage_id in _OPTION2_POINT_ACTION_CREATE_STAGE_IDS
    for stage_id in (
        f"revalidate_before_{create_stage_id}",
        create_stage_id,
    )
)

OPTION2_POINT_ACTION_TRANSACTION_STAGE_IDS: tuple[str, ...] = (
    "claim_mutation_authorization",
    "reattest_bound_preflight_evidence",
    "reattest_root_provisioner_and_platform_tools",
    "verify_owner_pause_latched",
    *_OPTION2_POINT_ACTION_REVALIDATE_AND_CREATE_STAGE_IDS,
    "validate_inactive_postflight",
    "seal_non_authorizing_receipt",
)

OPTION2_POINT_ACTION_PREMUTATION_REJECTION_CASE_IDS: tuple[str, ...] = (
    "administrator_prompt_cancelled",
    "effective_search_path_name_collision",
    "effective_search_path_uid_collision",
    "effective_search_path_gid_collision",
    "effective_search_path_nonlocal",
    "effective_search_path_unresolved",
    "mounted_filesystem_uid_collision",
    "mounted_filesystem_gid_collision",
    "mounted_filesystem_remote_or_unknown",
    "mounted_filesystem_uninspectable",
    "mounted_filesystem_classification_changed",
    "mount_set_changed",
    "sleep_or_boot_session_changed",
    "process_identity_changed",
    "root_provisioner_binding_drift",
    "host_binding_drift",
    "os_build_drift",
    "platform_tool_binding_drift",
    "source_bundle_drift",
    "code_requirement_drift",
    "manifest_binding_drift",
    "predecessor_ledger_head_changed",
    "authorization_claim_ledger_unavailable",
    "authorization_claim_ledger_rollback_or_clone_detected",
    "preflight_authorization_substitution",
    "preflight_evidence_expired",
    "mutation_confirmation_absent",
    "mutation_confirmation_substitution",
    "mutation_deadline_expired",
    "owner_pause_unlatched",
    "write_ahead_journal_tampered",
    "privileged_environment_not_exact",
    "privileged_cwd_not_exact",
    "privileged_inherited_fd_present",
    "privileged_stdin_or_shell_channel_invalid",
)

OPTION2_POINT_ACTION_POSTMUTATION_QUARANTINE_CASE_IDS: tuple[str, ...] = tuple(
    f"rollback_uncertainty_after_{stage_id}"
    for stage_id in _OPTION2_POINT_ACTION_CREATE_STAGE_IDS
)

OPTION2_POINT_ACTION_REJECTION_CASE_IDS: tuple[str, ...] = (
    *OPTION2_POINT_ACTION_PREMUTATION_REJECTION_CASE_IDS,
    *OPTION2_POINT_ACTION_POSTMUTATION_QUARANTINE_CASE_IDS,
)

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


class Option2PointActionViolation(RuntimeError):
    """Raised when the inert point-of-action contract is not exact."""


def _canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _sha256(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _validated_sha256(value: object, *, code: str) -> str:
    if (
        not isinstance(value, str)
        or _SHA256_PATTERN.fullmatch(value) is None
        or value == "0" * 64
    ):
        raise Option2PointActionViolation(code)
    return value


def _false_map(fields: tuple[str, ...]) -> dict[str, bool]:
    return {field: False for field in fields}


def _contract_body(
    *, recovery_result_review_content_sha256: str
) -> dict[str, object]:
    predecessor = _validated_sha256(
        recovery_result_review_content_sha256,
        code="option2_point_action_recovery_review_sha256_invalid",
    )
    return {
        "version": OPTION2_POINT_ACTION_VERSION,
        "classification": OPTION2_POINT_ACTION_CLASSIFICATION,
        "state": OPTION2_POINT_ACTION_STATE,
        "predecessor_recovery_result_review_content_sha256": predecessor,
        "implementation_scope": "offline_contract_and_in_memory_fixture_only",
        "future_root_provisioner": {
            "implementation_present": False,
            "outside_atlas": True,
            "root_owned": True,
            "owner_writable": False,
            "separately_signed": True,
            "exact_designated_requirement_required": True,
            "atlas_runtime_callable": False,
            "owner_direct_invocation_required": True,
            "atlas_python_or_source_may_execute_as_root": False,
            "caller_selectable_command_or_path": False,
            "native_root_owned_executable_only": True,
            "shell_or_python_execution_allowed": False,
            "absolute_no_follow_platform_tool_paths_required": True,
            "fixed_root_owned_working_directory_required": True,
            "fixed_environment_allowlist_required": True,
            "path_pythonpath_dyld_and_tool_config_inheritance_allowed": False,
            "inherited_file_descriptors_closed": True,
            "fixed_umask_required": True,
            "stdin_closed_except_exact_authorization_channel": True,
            "environment_config_or_plugin_lookup_allowed": False,
        },
        "authorization_gates": {
            "privileged_preflight": {
                "gate": OPTION2_POINT_ACTION_NEXT_GATE,
                "confirmation_prefix": (
                    OPTION2_POINT_ACTION_PREFLIGHT_CONFIRMATION_PREFIX
                ),
                "confirmation_binding_fields": list(
                    OPTION2_POINT_ACTION_PREFLIGHT_CONFIRMATION_BINDING_FIELDS
                ),
                "exact_confirmation_required": True,
                "confirmation_generated_in_this_contract": False,
                "one_use": True,
                "claim_before_administrator_prompt": True,
                "claim_is_atomic_against_exact_ledger_head": True,
                "read_only": True,
                "host_query_authority_in_this_contract": False,
                "administrator_prompt_authority_in_this_contract": False,
                "mutation_authority": False,
                "cancel_or_failure_consumes_claim": True,
            },
            "identity_mutation": {
                "gate": OPTION2_POINT_ACTION_MUTATION_GATE,
                "confirmation_prefix": (
                    OPTION2_POINT_ACTION_MUTATION_CONFIRMATION_PREFIX
                ),
                "exact_confirmation_required": True,
                "confirmation_generated_in_this_contract": False,
                "one_use": True,
                "separate_from_preflight_authorization": True,
                "requires_fresh_preflight_evidence": True,
                "binding_fields": list(
                    OPTION2_POINT_ACTION_MUTATION_BINDING_FIELDS
                ),
                "authority_in_this_contract": False,
                "claim_before_first_mutation": True,
                "cancel_or_failure_consumes_claim": True,
            },
        },
        "authorization_claim_ledger": {
            "implementation_present": False,
            "outside_atlas": True,
            "root_owned": True,
            "atlas_writable": False,
            "append_only": True,
            "update_or_delete_allowed": False,
            "fsync_before_prompt_or_mutation_required": True,
            "anti_rollback_anchor_required": True,
            "instance_epoch_and_head_bound_to_both_confirmations": True,
            "restoring_or_cloning_atlas_database_can_rearm_claim": False,
            "consumed_request_replay_rejected_after_atlas_database_restore": True,
        },
        "preflight": {
            "validity_seconds": OPTION2_POINT_ACTION_PREFLIGHT_VALIDITY_SECONDS,
            "requirements": list(OPTION2_POINT_ACTION_PREFLIGHT_REQUIREMENT_IDS),
            "effective_directory_search_path_required": True,
            "accepted_effective_directory_nodes": ["/Local/Default"],
            "nonlocal_or_unresolved_search_path_rejected_before_remote_query": True,
            "mounted_filesystem_ownership_scan_required": True,
            "all_mounted_filesystems_classified_before_scan": True,
            "remote_or_unknown_mount_rejected_before_traversal_or_query": True,
            "every_local_ownership_bearing_mount_scanned": True,
            "read_only_and_removable_local_mounts_included": True,
            "uninspectable_local_mount_rejected": True,
            "mount_classification_and_set_bound_to_evidence": True,
            "raw_identity_names_persisted": False,
            "raw_filesystem_paths_persisted": False,
            "unrelated_identity_values_returned_to_atlas": False,
            "candidate_is_authority": False,
            "caller_supplied_target_or_search_scope_allowed": False,
            "exact_fixed_target_and_query_scope_bound_before_prompt": True,
            "expired_candidate_reusable": False,
            "prior_recovery_candidate_reusable": False,
        },
        "transaction": {
            "stage_ids": list(OPTION2_POINT_ACTION_TRANSACTION_STAGE_IDS),
            "first_mutating_stage": "create_group_atlaspolicy",
            "created_resource_scope": (
                "six_fixed_groups_and_six_fixed_locked_nonlogin_users_only"
            ),
            "reverse_rollback_transaction_created_entities_only": True,
            "preexisting_entities_never_deleted_or_modified": True,
            "revalidate_all_bindings_and_collisions_immediately_before_each_create": True,
            "directory_service_create_is_atomic_exclusive_create_if_absent": True,
            "exclusive_create_collision_never_becomes_update": True,
            "created_record_marker_readback_required_before_next_stage": True,
            "rollback_uncertainty_quarantines_and_keeps_pause_latched": True,
            "state_or_socket_roots_created": False,
            "runtime_artifacts_or_acls_installed": False,
            "service_definitions_staged_or_loaded": False,
            "sockets_keys_vault_items_and_credentials_remain_absent": True,
        },
        "write_ahead_journal": {
            "implementation_present": False,
            "root_owned": True,
            "atlas_writable": False,
            "canonical_no_follow_creation_required": True,
            "fsync_intent_before_each_mutation_required": True,
            "exact_transaction_marker_required": True,
            "exact_attribute_readback_after_each_mutation_required": True,
            "reverse_rollback_required": True,
            "rollback_deletes_transaction_created_exact_matches_only": True,
            "ambiguous_record_deletion_allowed": False,
            "atomic_exclusive_create_required": True,
            "durable_quarantine_on_uncertainty_required": True,
        },
        "failure_semantics": {
            "authorization_missing_or_substituted": "reject_before_prompt_or_query",
            "preflight_failure": "consume_claim_and_stop_before_mutation",
            "preflight_expiry": "discard_and_require_fresh_owner_authorized_preflight",
            "mutation_authorization_missing_or_invalid": "stop_without_mutation",
            "mutation_failure": "reverse_rollback_transaction_created_entities",
            "rollback_uncertainty": "quarantine_inactive_and_keep_owner_pause_latched",
            "automatic_retry_authority": False,
        },
        "rejection_case_ids": list(OPTION2_POINT_ACTION_REJECTION_CASE_IDS),
        "fixture_evidence_scope": (
            "contract_structure_and_rejection_enumeration_only"
        ),
        "production_preflight_qualified": False,
        "production_rollback_qualified": False,
        "authority": _false_map(OPTION2_POINT_ACTION_AUTHORITY_FIELDS),
        "effects": _false_map(OPTION2_POINT_ACTION_EFFECT_FIELDS),
        "host_query_present": False,
        "host_apply_present": False,
        "administrator_prompt_present": False,
        "future_preflight_implementation_present": False,
        "future_provisioning_implementation_present": False,
        "ordinary_startup_wired": False,
        "http_route_present": False,
        "ui_action_present": False,
        "ready": False,
        "ready_offline": False,
        "ready_live": False,
        "next_gate": OPTION2_POINT_ACTION_NEXT_GATE,
    }


def build_option2_point_action_contract(
    *, recovery_result_review_content_sha256: str
) -> dict[str, object]:
    """Build the exact inert contract bound to the reviewed terminal result."""

    body = _contract_body(
        recovery_result_review_content_sha256=(
            recovery_result_review_content_sha256
        )
    )
    return {**deepcopy(body), "contract_sha256": _sha256(body)}


def validate_option2_point_action_contract(
    value: Mapping[str, object],
) -> None:
    """Reject any substitution, authority bit, or effect in the contract."""

    if not isinstance(value, Mapping):
        raise Option2PointActionViolation(
            "option2_point_action_contract_invalid"
        )
    predecessor = value.get(
        "predecessor_recovery_result_review_content_sha256"
    )
    expected = build_option2_point_action_contract(
        recovery_result_review_content_sha256=_validated_sha256(
            predecessor,
            code="option2_point_action_recovery_review_sha256_invalid",
        )
    )
    if dict(value) != expected:
        raise Option2PointActionViolation(
            "option2_point_action_contract_not_canonical"
        )
    authority = value.get("authority")
    effects = value.get("effects")
    if (
        not isinstance(authority, Mapping)
        or set(authority) != set(OPTION2_POINT_ACTION_AUTHORITY_FIELDS)
        or any(item is not False for item in authority.values())
        or not isinstance(effects, Mapping)
        or set(effects) != set(OPTION2_POINT_ACTION_EFFECT_FIELDS)
        or any(item is not False for item in effects.values())
    ):
        raise Option2PointActionViolation(
            "option2_point_action_contract_authority_invalid"
        )


def _simulate_rejection_case(
    contract: Mapping[str, object], *, case_id: str
) -> dict[str, object]:
    if case_id not in OPTION2_POINT_ACTION_REJECTION_CASE_IDS:
        raise Option2PointActionViolation(
            "option2_point_action_fixture_case_invalid"
        )
    if case_id in OPTION2_POINT_ACTION_POSTMUTATION_QUARANTINE_CASE_IDS:
        return {
            "case_id": case_id,
            "outcome": "quarantined_inactive",
            "stopped_before_first_mutation": False,
            "first_mutating_stage_entered": True,
            "rollback_attempted": True,
            "rollback_verified": False,
            "residual_created_entity_possible": True,
            "owner_pause_latched": True,
            "automatic_retry_authority": False,
            "preflight_claim_reusable": False,
            "prior_candidate_reused": False,
            "fixture_live_effects_present": False,
            "authority": deepcopy(contract["authority"]),
            "effects": deepcopy(contract["effects"]),
        }
    return {
        "case_id": case_id,
        "outcome": "rejected_inactive",
        "stopped_before_first_mutation": True,
        "first_mutating_stage_entered": False,
        "rollback_attempted": False,
        "rollback_verified": False,
        "residual_created_entity_possible": False,
        "owner_pause_latched": True,
        "automatic_retry_authority": False,
        "preflight_claim_reusable": False,
        "prior_candidate_reused": False,
        "fixture_live_effects_present": False,
        "authority": deepcopy(contract["authority"]),
        "effects": deepcopy(contract["effects"]),
    }


def qualify_option2_point_action_contract(
    *, recovery_result_review_content_sha256: str
) -> dict[str, object]:
    """Qualify only deterministic fixture behavior; never inspect the host."""

    contract = build_option2_point_action_contract(
        recovery_result_review_content_sha256=(
            recovery_result_review_content_sha256
        )
    )
    validate_option2_point_action_contract(contract)
    rejection_case_sha256: dict[str, str] = {}
    for case_id in OPTION2_POINT_ACTION_REJECTION_CASE_IDS:
        result = _simulate_rejection_case(contract, case_id=case_id)
        authority = result.get("authority")
        effects = result.get("effects")
        postmutation_quarantine = (
            case_id in OPTION2_POINT_ACTION_POSTMUTATION_QUARANTINE_CASE_IDS
        )
        if (
            result.get("outcome")
            != (
                "quarantined_inactive"
                if postmutation_quarantine
                else "rejected_inactive"
            )
            or result.get("stopped_before_first_mutation")
            is not (not postmutation_quarantine)
            or result.get("first_mutating_stage_entered")
            is not postmutation_quarantine
            or result.get("rollback_attempted")
            is not postmutation_quarantine
            or result.get("rollback_verified") is not False
            or result.get("residual_created_entity_possible")
            is not postmutation_quarantine
            or result.get("owner_pause_latched") is not True
            or result.get("automatic_retry_authority") is not False
            or result.get("preflight_claim_reusable") is not False
            or result.get("prior_candidate_reused") is not False
            or result.get("fixture_live_effects_present") is not False
            or not isinstance(authority, Mapping)
            or any(value is not False for value in authority.values())
            or not isinstance(effects, Mapping)
            or any(value is not False for value in effects.values())
        ):
            raise Option2PointActionViolation(
                "option2_point_action_fixture_qualification_failed"
            )
        rejection_case_sha256[case_id] = _sha256(result)

    clean_preflight_projection = {
        "outcome": "awaiting_separate_mutation_authorization_inactive",
        "fresh_privileged_preflight_fixture_passed": True,
        "candidate_authority": False,
        "identity_mutation_authorized": False,
        "first_mutating_stage_entered": False,
        "prior_recovery_candidate_reused": False,
        "authority": deepcopy(contract["authority"]),
        "effects": deepcopy(contract["effects"]),
    }
    report_body: dict[str, object] = {
        "version": OPTION2_POINT_ACTION_VERSION,
        "classification": (
            "option2_point_action_provisioner_offline_fixture_qualification"
        ),
        "state": OPTION2_POINT_ACTION_QUALIFICATION_STATE,
        "contract_sha256": contract["contract_sha256"],
        "predecessor_recovery_result_review_content_sha256": (
            recovery_result_review_content_sha256
        ),
        "clean_preflight_projection_sha256": _sha256(
            clean_preflight_projection
        ),
        "rejection_case_sha256": rejection_case_sha256,
        "rejection_case_count": len(OPTION2_POINT_ACTION_REJECTION_CASE_IDS),
        "premutation_rejection_case_count": len(
            OPTION2_POINT_ACTION_PREMUTATION_REJECTION_CASE_IDS
        ),
        "postmutation_quarantine_case_count": len(
            OPTION2_POINT_ACTION_POSTMUTATION_QUARANTINE_CASE_IDS
        ),
        "all_premutation_rejections_stop_before_first_mutation": True,
        "all_postmutation_rollback_uncertainties_quarantine": True,
        "postmutation_residual_entity_risk_explicit": True,
        "fixture_evidence_scope": (
            "contract_structure_and_rejection_enumeration_only"
        ),
        "production_preflight_qualified": False,
        "production_rollback_qualified": False,
        "two_distinct_owner_gates_verified": True,
        "preflight_candidate_grants_no_mutation_authority": True,
        "expired_recovery_candidate_reused": False,
        "in_memory_fixture_only": True,
        "authority": deepcopy(contract["authority"]),
        "effects": deepcopy(contract["effects"]),
        "host_query_present": False,
        "host_apply_present": False,
        "administrator_prompt_present": False,
        "future_preflight_implementation_present": False,
        "future_provisioning_implementation_present": False,
        "ordinary_startup_wired": False,
        "http_route_present": False,
        "ui_action_present": False,
        "ready": False,
        "ready_offline": False,
        "ready_live": False,
        "next_gate": OPTION2_POINT_ACTION_NEXT_GATE,
    }
    return {**report_body, "qualification_sha256": _sha256(report_body)}
