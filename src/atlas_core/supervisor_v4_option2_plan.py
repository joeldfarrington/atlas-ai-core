"""Inactive Option 2 service-identity and vault provisioning plan.

This module is deliberately data-only.  It defines and validates the future
privileged installation boundary without inspecting the host, reading a vault,
creating an account, opening a socket, starting a service, or granting Atlas
authority.
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from typing import Any, Mapping


OPTION2_PLAN_VERSION = 1
OPTION2_PLAN_CLASSIFICATION = (
    "option2_service_identity_and_vault_offline_provisioning_plan"
)
OPTION2_PLAN_STATE = "implemented_inactive"
OPTION2_PLAN_NEXT_GATE = (
    "owner_review_option2_service_identity_and_vault_offline_plan"
)

_INSTALL_ROOT = "/Library/Application Support/Atlas Core/option2"
_SOCKET_ROOT = "/private/var/run/atlas-core-option2"
_HELPER_ROOT = "/Library/PrivilegedHelperTools"
_LAUNCHD_ROOT = "/Library/LaunchDaemons"

_COMPONENTS: tuple[dict[str, str], ...] = (
    {
        "name": "policy_broker",
        "service_identity": "_atlaspolicy",
        "bundle_id": "net.atlaswithin.atlascore.policy-broker",
        "responsibility": (
            "verify owner policy and issue metadata-only capabilities with a "
            "constrained subordinate issuer"
        ),
    },
    {
        "name": "capability_verifier",
        "service_identity": "_atlasverify",
        "bundle_id": "net.atlaswithin.atlascore.capability-verifier",
        "responsibility": "verify capability signatures without signing authority",
    },
    {
        "name": "vault_broker",
        "service_identity": "_atlasvault",
        "bundle_id": "net.atlaswithin.atlascore.vault-broker",
        "responsibility": "mediate one-use vault leases and material delivery",
    },
    {
        "name": "receipt_anchor",
        "service_identity": "_atlasreceipt",
        "bundle_id": "net.atlaswithin.atlascore.receipt-anchor",
        "responsibility": "retain and verify the append-only receipt chain",
    },
    {
        "name": "owner_stop",
        "service_identity": "_atlasstop",
        "bundle_id": "net.atlaswithin.atlascore.owner-stop",
        "responsibility": (
            "latch owner pause; resume only with a fresh owner-signed monotonic token"
        ),
    },
    {
        "name": "connector_runner",
        "service_identity": "_atlasconnector",
        "bundle_id": "net.atlaswithin.atlascore.connector-runner",
        "responsibility": "run one destination-bound connector without returning material",
    },
)

_AUTHORITY_FALSE_FIELDS = (
    "accounts_created",
    "access_permissions_changed",
    "background_service_installed",
    "credential_use_authorized",
    "deployment_performed",
    "keychain_queried",
    "live_authority_granted",
    "live_execution_authorized",
    "model_contact_authorized",
    "network_access_authorized",
    "private_data_authorized",
    "provisioning_authorized",
    "real_credential_present",
    "runtime_installed",
    "vault_adapter_connected",
)


class Option2PlanViolation(RuntimeError):
    """Raised when the inactive provisioning plan is not exact."""


def _canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _component_projection(component: Mapping[str, str]) -> dict[str, object]:
    name = component["name"]
    bundle_id = component["bundle_id"]
    return {
        **component,
        "binary_path": f"{_HELPER_ROOT}/{bundle_id}",
        "launchd_plist_path": f"{_LAUNCHD_ROOT}/{bundle_id}.plist",
        "state_root": f"{_INSTALL_ROOT}/{name}",
        "socket_directory": f"{_SOCKET_ROOT}/{name}",
        "socket_path": f"{_SOCKET_ROOT}/{name}/{name}.sock",
        "binary_owner": "root",
        "binary_group": "wheel",
        "binary_mode": "0555",
        "launchd_definition_owner": "root",
        "launchd_definition_group": "wheel",
        "launchd_definition_mode": "0644",
        "process_user": component["service_identity"],
        "process_group": component["service_identity"],
        "supplementary_groups_allowed": False,
        "hidden_account": True,
        "password_state": "locked",
        "login_shell": "/usr/bin/false",
        "home_directory": "/var/empty",
        "launchd_user_name": component["service_identity"],
        "state_owner": component["service_identity"],
        "state_group": component["service_identity"],
        "state_mode": "0700",
        "socket_directory_owner": component["service_identity"],
        "socket_directory_mode": "0700_plus_exact_named_peer_acl",
        "socket_owner": component["service_identity"],
        "socket_mode": "0600_plus_exact_named_peer_acl",
        "socket_no_follow_creation_required": True,
        "stale_socket_rejected": True,
        "launch_mode": "socket_activated_on_demand",
        "principal_ref": f"service:{bundle_id}",
        "principal_generation_state": "unassigned_until_provisioning",
        "code_identity_policy": "owner_pinned_designated_requirement_at_provisioning",
        "verification_key_id_state": "unassigned_until_provisioning",
        "verification_key_epoch_state": "unassigned_until_provisioning",
        "private_key_material_state": "absent",
        "peer_acl_policy": (
            "exact_named_principal_plus_audit_token_and_code_identity"
        ),
        "accepted_peer_principals_state": "unassigned_until_manifest_review",
        "peer_operation_allowlist_state": "unassigned_until_manifest_review",
        "signed_session_binding_required": True,
        "one_use_nonce_and_replay_rejection_required": True,
        "broad_group_access": False,
        "world_access": False,
        "ip_network_authority": False,
        "credential_material_persisted": False,
    }


def _plan_body() -> dict[str, object]:
    return {
        "version": OPTION2_PLAN_VERSION,
        "classification": OPTION2_PLAN_CLASSIFICATION,
        "state": OPTION2_PLAN_STATE,
        "platform": "macos",
        "architecture": "separate_os_service_identities",
        "owner_policy_signer": {
            "principal_ref": "owner-controlled-external-signer",
            "inside_atlas_worker": False,
            "inside_service_runtime": False,
            "private_key_material_state": "absent",
            "verification_key_id_state": "unassigned_until_provisioning",
            "verification_key_epoch_state": "unassigned_until_provisioning",
            "signs_owner_policy": True,
            "signs_subordinate_issuer_certificates": True,
            "signs_fresh_monotonic_resume_tokens": True,
            "service_runtime_may_use_owner_root_key": False,
        },
        "policy_broker_issuer": {
            "key_state": "absent_until_separate_provisioning",
            "key_type": "nonexportable_constrained_subordinate",
            "scope": "metadata_only_capability_issuance",
            "owner_signed_certificate_required": True,
            "owner_root_key_present": False,
        },
        "installation_root": _INSTALL_ROOT,
        "socket_root": _SOCKET_ROOT,
        "components": [_component_projection(item) for item in _COMPONENTS],
        "vault": {
            "backend": "macos_system_keychain",
            "custodian_identity": "_atlasvault",
            "item_selection": "owner_provisioned_opaque_random_binding_only",
            "binding_may_derive_from_label_or_secret": False,
            "caller_selectable_binding": False,
            "owner_signed_fixed_registry_required": True,
            "registry_binding_fields": [
                "credential_scope",
                "provider",
                "destination",
                "connector_identity",
                "action",
                "nonce",
                "verification_key_epoch",
            ],
            "access_control": "designated_signed_vault_broker_only",
            "interactive_unlock": "owner_present_only",
            "unattended_keychain_ui_prompt_allowed": False,
            "acl_or_signer_uncertainty_result": "terminal_denial",
            "material_delivery": "direct_broker_to_connector_scm_rights",
            "atlas_possesses_material_endpoint": False,
            "descriptor_cloexec_required": True,
            "descriptor_duplicate_closure_required": True,
            "bounded_one_use_transfer_required": True,
            "connector_crash_dump_prevention_required": True,
            "connector_buffer_best_effort_zeroization_required": True,
            "connector_ephemeral_buffer_allowed": True,
            "material_in_environment": False,
            "material_in_argv": False,
            "material_in_stdout": False,
            "material_in_atlas_python": False,
            "material_in_atlas_or_general_purpose_memory": False,
            "material_in_durable_storage": False,
            "material_in_receipts": False,
        },
        "custody": {
            "atlas_worker_identity_excluded": True,
            "owner_side_provisioner_outside_atlas": True,
            "agent_writable_roots_excluded": True,
            "component_state_roots_disjoint": True,
            "private_signing_keys_nonexportable": True,
            "durable_replay_state_required": True,
            "receipt_chain_independently_retained": True,
            "receipt_compare_and_append_atomic": True,
            "receipt_monotonic_generation_required": True,
            "owner_retained_signed_count_and_head_anchor_required": True,
            "stale_truncated_or_forked_receipt_state_result": "terminal_denial",
            "pause_may_be_asserted_without_material_access": True,
            "resume_requires_owner_control": True,
            "resume_requires_fresh_owner_signed_monotonic_token": True,
        },
        "provisioning": {
            "owner_present_admin_required": True,
            "signed_installer_required": True,
            "provisioner_not_callable_by_atlas_runtime": True,
            "exact_manifest_required": True,
            "preflight_and_rollback_required": True,
            "service_creation_separate_from_live_authority": True,
            "credential_insertion_separate_from_service_creation": True,
            "production_qualification_separate_from_provisioning": True,
            "task_bound_live_authorization_separate": True,
        },
        "availability": {
            "current_host": "owner_laptop",
            "works_only_while_host_awake": True,
            "host_migration_preserves_protocol_contracts": True,
            "cloud_or_always_on_host_configured": False,
        },
        "authority": {field: False for field in _AUTHORITY_FALSE_FIELDS},
        "next_gate": OPTION2_PLAN_NEXT_GATE,
    }


def validate_option2_service_identity_and_vault_plan(
    plan: Mapping[str, Any],
) -> None:
    """Require the exact inactive, non-authorizing Option 2 plan."""

    expected = _plan_body()
    if not isinstance(plan, Mapping) or dict(plan) != expected:
        raise Option2PlanViolation("option2_plan_not_canonical")

    components = plan.get("components")
    if not isinstance(components, list) or len(components) != len(_COMPONENTS):
        raise Option2PlanViolation("option2_plan_components_invalid")
    identities = [item.get("service_identity") for item in components]
    state_roots = [item.get("state_root") for item in components]
    socket_paths = [item.get("socket_path") for item in components]
    if (
        len(set(identities)) != len(identities)
        or len(set(state_roots)) != len(state_roots)
        or len(set(socket_paths)) != len(socket_paths)
    ):
        raise Option2PlanViolation("option2_plan_separation_invalid")
    if any(
        not isinstance(identity, str)
        or not identity.startswith("_atlas")
        or identity == "_atlas"
        for identity in identities
    ):
        raise Option2PlanViolation("option2_plan_identity_invalid")
    if any(
        item.get("principal_ref") != f"service:{item.get('bundle_id')}"
        or item.get("peer_acl_policy")
        != "exact_named_principal_plus_audit_token_and_code_identity"
        or item.get("process_user") != item.get("service_identity")
        or item.get("process_group") != item.get("service_identity")
        or item.get("supplementary_groups_allowed") is not False
        or item.get("state_owner") != item.get("service_identity")
        or item.get("socket_owner") != item.get("service_identity")
        or item.get("socket_no_follow_creation_required") is not True
        or item.get("broad_group_access") is not False
        or item.get("world_access") is not False
        or item.get("private_key_material_state") != "absent"
        for item in components
    ):
        raise Option2PlanViolation("option2_plan_peer_or_key_boundary_invalid")
    authority = plan.get("authority")
    if not isinstance(authority, Mapping) or set(authority) != set(
        _AUTHORITY_FALSE_FIELDS
    ):
        raise Option2PlanViolation("option2_plan_authority_invalid")
    if any(authority[field] is not False for field in _AUTHORITY_FALSE_FIELDS):
        raise Option2PlanViolation("option2_plan_authority_open")


def build_option2_service_identity_and_vault_plan() -> dict[str, object]:
    """Return a deterministic copy of the inactive plan plus its digest."""

    body = _plan_body()
    validate_option2_service_identity_and_vault_plan(body)
    return {**deepcopy(body), "plan_sha256": _sha256(body)}


def review_option2_service_identity_and_vault_plan() -> dict[str, object]:
    """Validate the design without inspecting or changing the operating system."""

    plan = build_option2_service_identity_and_vault_plan()
    body = {key: value for key, value in plan.items() if key != "plan_sha256"}
    validate_option2_service_identity_and_vault_plan(body)
    return {
        "classification": "option2_service_identity_and_vault_offline_plan_review",
        "review_passed": True,
        "plan_sha256": plan["plan_sha256"],
        "component_count": len(_COMPONENTS),
        "service_identities_distinct": True,
        "state_roots_disjoint": True,
        "atlas_worker_excluded_from_vault_custody": True,
        "owner_side_provisioner_outside_atlas": True,
        "owner_present_admin_required": True,
        "keychain_queried": False,
        "accounts_created": False,
        "access_permissions_changed": False,
        "background_service_installed": False,
        "runtime_installed": False,
        "vault_adapter_connected": False,
        "real_credential_present": False,
        "private_data_present": False,
        "ip_network_accessed": False,
        "model_contacted": False,
        "provider_contacted": False,
        "deployment_performed": False,
        "provisioning_authorized": False,
        "live_authority_granted": False,
        "ready": False,
        "ready_offline": False,
        "ready_live": False,
        "next_gate": OPTION2_PLAN_NEXT_GATE,
    }
