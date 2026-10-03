"""Inactive native Option 2 preflight and authorization-ledger core.

This module qualifies only a deterministic Swift core and its injected
fixtures.  It does not compile or execute Swift, inspect the host, request
privilege, create a durable system ledger, or grant authority.  Production
host, custody, signing, durability, and external-anchor adapters remain absent.
"""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from typing import Any, Mapping


OPTION2_NATIVE_PREFLIGHT_VERSION = 1
OPTION2_NATIVE_PREFLIGHT_STATE = (
    "native_preflight_and_claim_ledger_implemented_inactive"
)
OPTION2_NATIVE_PREFLIGHT_QUALIFICATION_STATE = (
    "native_preflight_and_claim_ledger_fixture_qualified_inactive"
)
OPTION2_NATIVE_PREFLIGHT_NEXT_GATE = (
    "owner_review_option2_native_preflight_installation_and_signing_plan"
)
OPTION2_NATIVE_PREFLIGHT_QUARANTINE_GATE = (
    "owner_review_option2_native_preflight_offline_qualification_quarantine"
)
OPTION2_NATIVE_PREFLIGHT_SOURCE_PATHS: tuple[str, ...] = (
    "native/option2_identity_preflight/BoundRequest.swift",
    "native/option2_identity_preflight/CanonicalJSON.swift",
    "native/option2_identity_preflight/ClaimLedger.swift",
    "native/option2_identity_preflight/OfflineFixtures.swift",
    "native/option2_identity_preflight/Option2FixtureMain.swift",
    "native/option2_identity_preflight/PreflightEvaluator.swift",
)
OPTION2_NATIVE_PREFLIGHT_REQUIRED_BINDING_FIELDS: tuple[str, ...] = (
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
    "power_session_generation_sha256",
    "executor_instance_sha256",
    "root_provisioner_sha256",
    "root_provisioner_code_requirement_sha256",
    "authorization_claim_ledger_instance_sha256",
    "authorization_claim_ledger_epoch",
    "authorization_claim_ledger_predecessor_count",
    "authorization_claim_ledger_head_sha256",
    "authorization_claim_ledger_anti_rollback_anchor_sha256",
    "predecessor_ledger_head_sha256",
    "authorization_claim_record_sha256",
    "authorization_claim_expected_committed_count",
    "authorization_claim_expected_committed_head_sha256",
    "authorization_claim_anchor_key_id_sha256",
    "authorization_claim_anchor_epoch",
    "authorization_claim_anchor_count",
    "authorization_claim_anchor_head_sha256",
    "authorization_claim_expected_anchor_count",
    "authorization_claim_expected_anchor_head_sha256",
    "issued_at",
    "expires_at",
    "monotonic_deadline_ns",
)
_BINDING_SUBSTITUTION_CASE_FIELDS: tuple[str, ...] = (
    "one_use_nonce_sha256",
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
    "power_session_generation_sha256",
    "executor_instance_sha256",
    "root_provisioner_sha256",
    "root_provisioner_code_requirement_sha256",
    "authorization_claim_ledger_instance_sha256",
    "authorization_claim_ledger_head_sha256",
    "authorization_claim_ledger_anti_rollback_anchor_sha256",
    "predecessor_ledger_head_sha256",
    "authorization_claim_record_sha256",
    "authorization_claim_expected_committed_head_sha256",
    "authorization_claim_anchor_key_id_sha256",
    "authorization_claim_anchor_head_sha256",
    "authorization_claim_expected_anchor_head_sha256",
)
OPTION2_NATIVE_PREFLIGHT_EXPECTED_CASE_IDS = frozenset(
    {f"binding_substitution_{field}" for field in _BINDING_SUBSTITUTION_CASE_FIELDS}
    | {
        "caller_supplied_scope",
        "clean_claim",
        "clean_preflight",
        "concurrent_duplicate_claim",
        "crash_window_advanceAnchor",
        "crash_window_appendIntent",
        "crash_window_appendTerminal",
        "crash_window_syncAnchor",
        "crash_window_syncIntent",
        "crash_window_syncTerminal",
        "expected_transition_mismatch",
        "extra_binding",
        "gid_collision",
        "invalid_digest",
        "invalid_numeric_binding",
        "invalid_privileged_context",
        "invalid_time_window",
        "invalid_uuid",
        "ledger_anchor_integrity_rollback",
        "missing_binding",
        "mount_set_drift",
        "nonce_replay_after_restart",
        "remote_mount",
        "request_replay_after_restart",
        "stale_anchor_count_binding",
        "stale_anchor_envelope_binding",
        "stale_anchor_epoch_binding",
        "stale_anchor_head_binding",
        "stale_anchor_key_binding",
        "stale_ledger_count_binding",
        "stale_ledger_epoch_binding",
        "stale_ledger_head_binding",
        "stale_ledger_instance_binding",
        "target_name_collision",
        "uid_collision",
        "uninspectable_local_mount",
        "unknown_mount",
    }
)
OPTION2_NATIVE_PREFLIGHT_FIXTURE_CASE_COUNT = len(
    OPTION2_NATIVE_PREFLIGHT_EXPECTED_CASE_IDS
)

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_FORBIDDEN_NATIVE_TOKENS: tuple[str, ...] = (
    "import OpenDirectory",
    "import Security",
    "AuthorizationCopyRights",
    "ODNode",
    "getfsstat",
    "dscl",
    "sysadminctl",
    "dseditgroup",
    "launchctl",
    "SecItem",
    "URLSession",
    "Process(",
    "posix_spawn",
    "execve",
    "fork(",
    "socket(",
    "dlopen",
)
_REQUIRED_NATIVE_TOKENS: tuple[str, ...] = (
    'case "describe"',
    'case "qualify-fixtures"',
    "exclusive_compare_and_append",
    "projected_fsync_claim_ledger_and_parent",
    "projected_advance_independent_anchor",
    "quarantined_inactive",
    "power_session_generation_sha256",
    "authorization_claim_expected_committed_head_sha256",
)


class Option2NativePreflightViolation(RuntimeError):
    """Raised when the inactive native-core evidence is not exact."""


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
        raise Option2NativePreflightViolation(code)
    return value


def native_source_manifest_sha256(
    source_sha256: Mapping[str, str],
) -> str:
    if set(source_sha256) != set(OPTION2_NATIVE_PREFLIGHT_SOURCE_PATHS):
        raise Option2NativePreflightViolation(
            "option2_native_source_manifest_paths_invalid"
        )
    normalized = {
        path: _validated_sha256(
            source_sha256[path], code="option2_native_source_sha256_invalid"
        )
        for path in OPTION2_NATIVE_PREFLIGHT_SOURCE_PATHS
    }
    return _sha256(normalized)


def validate_native_source_texts(source_text: Mapping[str, str]) -> None:
    """Reject a hidden live provider or command in the offline Swift target."""

    if set(source_text) != set(OPTION2_NATIVE_PREFLIGHT_SOURCE_PATHS):
        raise Option2NativePreflightViolation(
            "option2_native_source_text_paths_invalid"
        )
    joined = "\n".join(source_text[path] for path in sorted(source_text))
    imports = set(
        re.findall(r"^\s*import\s+([A-Za-z_][A-Za-z0-9_]*)\s*$", joined, re.MULTILINE)
    )
    if imports != {"CryptoKit", "Foundation"}:
        raise Option2NativePreflightViolation(
            "option2_native_import_allowlist_invalid"
        )
    if any(token in joined for token in _FORBIDDEN_NATIVE_TOKENS):
        raise Option2NativePreflightViolation(
            "option2_native_forbidden_provider_or_api_present"
        )
    if any(token not in joined for token in _REQUIRED_NATIVE_TOKENS):
        raise Option2NativePreflightViolation(
            "option2_native_required_invariant_missing"
        )
    command_switch = source_text[
        "native/option2_identity_preflight/Option2FixtureMain.swift"
    ]
    if command_switch.count('case "') != 2:
        raise Option2NativePreflightViolation(
            "option2_native_command_surface_invalid"
        )


def build_option2_native_preflight_contract(
    *,
    point_action_qualification_id: str,
    point_action_qualification_content_sha256: str,
    point_action_contract_sha256: str,
    source_sha256: Mapping[str, str],
) -> dict[str, object]:
    source_manifest = native_source_manifest_sha256(source_sha256)
    body: dict[str, object] = {
        "version": OPTION2_NATIVE_PREFLIGHT_VERSION,
        "classification": (
            "option2_identity_only_native_preflight_and_claim_ledger_core"
        ),
        "state": OPTION2_NATIVE_PREFLIGHT_STATE,
        "predecessor_point_action_qualification_id": (
            point_action_qualification_id
        ),
        "predecessor_point_action_qualification_content_sha256": (
            _validated_sha256(
                point_action_qualification_content_sha256,
                code="option2_native_predecessor_content_sha256_invalid",
            )
        ),
        "predecessor_point_action_contract_sha256": _validated_sha256(
            point_action_contract_sha256,
            code="option2_native_predecessor_contract_sha256_invalid",
        ),
        "native_source_sha256": dict(sorted(source_sha256.items())),
        "native_source_manifest_sha256": source_manifest,
        "required_binding_fields": list(
            OPTION2_NATIVE_PREFLIGHT_REQUIRED_BINDING_FIELDS
        ),
        "native_core_implemented": True,
        "authorization_claim_ledger_core_implemented": True,
        "injected_fixture_providers_only": True,
        "supported_native_commands": ["describe", "qualify-fixtures"],
        "claim_transition": {
            "exclusive_compare_and_append": True,
            "exact_predecessor_count_and_head_bound": True,
            "deterministic_claim_record_digest_bound": True,
            "expected_committed_count_and_head_bound": True,
            "anchor_key_epoch_count_and_head_bound": True,
            "durable_claim_intent_required_before_future_prompt_or_query": True,
            "external_anchor_advance_required_before_future_prompt_or_query": True,
            "crash_ambiguity_consumes_and_quarantines": True,
            "automatic_retry_or_repair": False,
        },
        "preflight_semantics": {
            "power_session_generation_bound": True,
            "remote_or_unknown_mount_rejected_before_traversal": True,
            "all_inspectable_local_ownership_mounts_included": True,
            "read_only_and_removable_local_mounts_included": True,
            "uninspectable_local_mount_rejected": True,
            "mount_set_drift_rejected": True,
            "caller_selected_scope_supported": False,
            "candidate_grants_authority": False,
        },
        "atlas_database_restore_replay_rejected_in_fixture": True,
        "whole_host_snapshot_rollback_resistance_qualified": False,
        "fixture_native_process_may_run_during_verification": True,
        "fixture_temporary_binary_may_be_created_during_verification": True,
        "fixture_ledger_in_memory_only": True,
        "fixture_durability_order_projection_only": True,
        "durable_filesystem_io_verified": False,
        "independent_anchor_verified": False,
        "production_host_adapter_present": False,
        "production_durable_ledger_adapter_present": False,
        "production_anti_rollback_anchor_present": False,
        "root_owned_installation_present": False,
        "separately_signed_installation_present": False,
        "administrator_prompt_present": False,
        "point_action_host_query_present": False,
        "filesystem_ownership_scan_present": False,
        "identity_mutation_present": False,
        "network_route_present": False,
        "atlas_to_native_execution_route_present": False,
        "ordinary_startup_wired": False,
        "http_route_present": False,
        "ui_action_present": False,
        "production_preflight_qualified": False,
        "production_rollback_qualified": False,
        "authority_granted": False,
        "ready": False,
        "ready_offline": False,
        "ready_live": False,
        "next_gate": OPTION2_NATIVE_PREFLIGHT_NEXT_GATE,
    }
    return {**deepcopy(body), "contract_sha256": _sha256(body)}


def validate_native_fixture_report(report: Mapping[str, object]) -> None:
    body = {key: value for key, value in report.items() if key != "qualification_sha256"}
    case_digests = report.get("case_result_sha256")
    if (
        report.get("version") != OPTION2_NATIVE_PREFLIGHT_VERSION
        or report.get("classification")
        != "option2_native_preflight_offline_qualification"
        or report.get("state") != "qualified_inactive"
        or report.get("case_count") != OPTION2_NATIVE_PREFLIGHT_FIXTURE_CASE_COUNT
        or not isinstance(case_digests, Mapping)
        or len(case_digests) != OPTION2_NATIVE_PREFLIGHT_FIXTURE_CASE_COUNT
        or set(case_digests) != OPTION2_NATIVE_PREFLIGHT_EXPECTED_CASE_IDS
        or any(
            not isinstance(value, str)
            or _SHA256_PATTERN.fullmatch(value) is None
            or value == "0" * 64
            for value in case_digests.values()
        )
        or report.get("qualification_sha256") != _sha256(body)
        or report.get("next_gate") != OPTION2_NATIVE_PREFLIGHT_NEXT_GATE
        or any(
            report.get(field) is not True
            for field in (
                "native_core_implemented",
                "all_cases_passed",
                "claim_compare_and_append_verified",
                "claim_durability_order_projection_verified",
                "crash_ambiguity_consumes_and_quarantines",
                "remote_or_unknown_mount_rejected_before_traversal",
                "read_only_and_removable_local_mounts_included",
                "privacy_minimized_output_only",
                "fixture_native_process_started",
                "fixture_binary_created_by_verification_harness",
                "fixture_ledger_in_memory_only",
                "atlas_database_restore_replay_rejected_in_fixture",
            )
        )
        or any(
            report.get(field) is not False
            for field in (
                "caller_selected_scope_supported",
                "durable_filesystem_io_verified",
                "independent_anchor_verified",
                "whole_host_snapshot_rollback_resistance_qualified",
                "production_host_adapter_present",
                "production_durable_ledger_adapter_present",
                "production_anti_rollback_anchor_present",
                "root_owned_installation_present",
                "separately_signed_installation_present",
                "administrator_prompt_present",
                "host_query_present",
                "filesystem_ownership_scan_present",
                "identity_mutation_present",
                "network_route_present",
                "atlas_to_native_execution_route_present",
                "ordinary_startup_wired",
                "http_route_present",
                "ui_action_present",
                "production_preflight_qualified",
                "production_rollback_qualified",
                "ready",
                "ready_offline",
                "ready_live",
            )
        )
    ):
        raise Option2NativePreflightViolation(
            "option2_native_fixture_report_invalid"
        )


def qualify_option2_native_preflight_contract(
    *,
    point_action_qualification_id: str,
    point_action_qualification_content_sha256: str,
    point_action_contract_sha256: str,
    source_sha256: Mapping[str, str],
) -> dict[str, object]:
    contract = build_option2_native_preflight_contract(
        point_action_qualification_id=point_action_qualification_id,
        point_action_qualification_content_sha256=(
            point_action_qualification_content_sha256
        ),
        point_action_contract_sha256=point_action_contract_sha256,
        source_sha256=source_sha256,
    )
    body: dict[str, object] = {
        "version": OPTION2_NATIVE_PREFLIGHT_VERSION,
        "classification": (
            "option2_native_preflight_and_claim_ledger_offline_qualification"
        ),
        "state": OPTION2_NATIVE_PREFLIGHT_QUALIFICATION_STATE,
        "contract_sha256": contract["contract_sha256"],
        "predecessor_point_action_qualification_id": (
            point_action_qualification_id
        ),
        "predecessor_point_action_qualification_content_sha256": (
            point_action_qualification_content_sha256
        ),
        "native_source_manifest_sha256": contract[
            "native_source_manifest_sha256"
        ],
        "native_fixture_case_count": OPTION2_NATIVE_PREFLIGHT_FIXTURE_CASE_COUNT,
        "required_binding_field_count": len(
            OPTION2_NATIVE_PREFLIGHT_REQUIRED_BINDING_FIELDS
        ),
        "native_core_implemented": True,
        "authorization_claim_ledger_core_implemented": True,
        "native_fixture_qualified": True,
        "authorization_claim_ledger_crash_fixture_qualified": True,
        "claim_durability_order_projection_qualified": True,
        "durable_filesystem_io_verified": False,
        "independent_anchor_verified": False,
        "historical_point_action_receipt_recomputed_against_current_source": False,
        "atlas_database_restore_replay_rejected_in_fixture": True,
        "whole_host_snapshot_rollback_resistance_qualified": False,
        "production_host_adapter_present": False,
        "production_durable_ledger_adapter_present": False,
        "production_anti_rollback_anchor_present": False,
        "root_owned_installation_present": False,
        "separately_signed_installation_present": False,
        "administrator_prompt_present": False,
        "point_action_host_query_present": False,
        "identity_mutation_present": False,
        "network_route_present": False,
        "atlas_to_native_execution_route_present": False,
        "ordinary_startup_wired": False,
        "http_route_present": False,
        "ui_action_present": False,
        "production_preflight_qualified": False,
        "production_rollback_qualified": False,
        "authority_granted": False,
        "ready": False,
        "ready_offline": False,
        "ready_live": False,
        "next_gate": OPTION2_NATIVE_PREFLIGHT_NEXT_GATE,
    }
    return {**body, "qualification_sha256": _sha256(body)}
