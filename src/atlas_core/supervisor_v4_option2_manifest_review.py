"""Pure contract for reviewing the inactive Option 2 provisioning manifest.

This module only constructs and validates deterministic data.  It does not
inspect the host, read or write files, invoke a subprocess, open a socket,
contact a network, query a vault, or grant provisioning authority.
"""

from __future__ import annotations

from typing import Any, Mapping


OPTION2_MANIFEST_REVIEW_VERSION = 1
OPTION2_MANIFEST_REVIEW_CLASSIFICATION = (
    "option2_incomplete_service_identity_provisioning_manifest_contract_review"
)
OPTION2_MANIFEST_REVIEW_STATE = "reviewed_inactive"
OPTION2_MANIFEST_REVIEW_NEXT_INTERNAL_MILESTONE = (
    "option2_identity_candidate_resolver_offline_implementation"
)

OPTION2_MANIFEST_REVIEW_PRODUCTION_CONFIGURATION_FIELDS: tuple[str, ...] = (
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

OPTION2_MANIFEST_REVIEW_AUTHORITY_FIELDS: tuple[str, ...] = (
    "access_change_authorized",
    "admin_prompt_authorized",
    "artifact_signing_authorized",
    "authority_granted",
    "background_execution_authorized",
    "credential_insertion_authorized",
    "credential_use_authorized",
    "deployment_authorized",
    "external_communication_authorized",
    "host_apply_authorized",
    "key_material_creation_authorized",
    "launchd_installation_authorized",
    "live_authority_granted",
    "live_execution_authorized",
    "model_contact_authorized",
    "network_access_authorized",
    "private_data_authorized",
    "private_data_transmission_authorized",
    "production_path_configuration_authorized",
    "provider_contact_authorized",
    "provisioning_authorized",
    "service_enablement_authorized",
    "service_identity_creation_authorized",
    "service_identity_provisioning_authorized",
    "vault_provisioning_authorized",
)

OPTION2_MANIFEST_REVIEW_EFFECT_FIELDS: tuple[str, ...] = (
    "access_permissions_changed",
    "accounts_created",
    "accounts_queried",
    "admin_prompt_requested",
    "artifact_signed",
    "background_service_installed",
    "codesign_invoked",
    "credential_material_present",
    "deployment_performed",
    "dscl_invoked",
    "external_communication_performed",
    "filesystem_changes_performed",
    "host_inspected",
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
    "model_contacted",
    "network_accessed",
    "owner_authorization_claimed",
    "private_data_present",
    "provider_contacted",
    "provisioning_performed",
    "real_credential_present",
    "runtime_installed",
    "security_cli_invoked",
    "service_group_created",
    "service_identity_created",
    "service_started",
    "subprocess_spawned",
    "sysadminctl_invoked",
    "unix_socket_connected",
    "unix_socket_created",
    "vault_adapter_connected",
)

OPTION2_MANIFEST_REVIEW_READINESS_FIELDS: tuple[str, ...] = (
    "candidate_complete",
    "candidate_generated",
    "production_brokers_qualified",
    "production_manifest_ready",
    "ready",
    "ready_live",
    "ready_offline",
    "service_identities_provisioned",
    "service_identity_gate_satisfied",
    "vault_provisioned",
)


class Option2ManifestReviewViolation(RuntimeError):
    """Raised when the inactive manifest-review content is not exact."""


def _validate_sha256(value: object, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value == "0" * 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise Option2ManifestReviewViolation(
            f"option2_manifest_review_{field}_invalid"
        )
    return value


def _review_content_body(
    *,
    plan_review_content_sha256: str,
    fixture_qualification_content_sha256: str,
    reviewed_plan_sha256: str,
    manifest_sha256: str,
    fixture_qualification_sha256: str,
) -> dict[str, object]:
    bindings = {
        "plan_review_content_sha256": _validate_sha256(
            plan_review_content_sha256,
            field="plan_review_content_sha256",
        ),
        "fixture_qualification_content_sha256": _validate_sha256(
            fixture_qualification_content_sha256,
            field="fixture_qualification_content_sha256",
        ),
        "reviewed_plan_sha256": _validate_sha256(
            reviewed_plan_sha256,
            field="reviewed_plan_sha256",
        ),
        "manifest_sha256": _validate_sha256(
            manifest_sha256,
            field="manifest_sha256",
        ),
        "fixture_qualification_sha256": _validate_sha256(
            fixture_qualification_sha256,
            field="fixture_qualification_sha256",
        ),
    }
    return {
        "version": OPTION2_MANIFEST_REVIEW_VERSION,
        "classification": OPTION2_MANIFEST_REVIEW_CLASSIFICATION,
        "state": OPTION2_MANIFEST_REVIEW_STATE,
        "review_scope": (
            "incomplete_inactive_non_authorizing_manifest_contract_only"
        ),
        **bindings,
        "production_manifest_complete": False,
        "production_artifact_bindings_present": False,
        "production_preflight_qualified": False,
        "production_rollback_qualified": False,
        "host_apply_present": False,
        "production_configuration": {
            field: None
            for field in OPTION2_MANIFEST_REVIEW_PRODUCTION_CONFIGURATION_FIELDS
        },
        "authority": {
            field: False for field in OPTION2_MANIFEST_REVIEW_AUTHORITY_FIELDS
        },
        "effects": {
            field: False for field in OPTION2_MANIFEST_REVIEW_EFFECT_FIELDS
        },
        "readiness": {
            field: False for field in OPTION2_MANIFEST_REVIEW_READINESS_FIELDS
        },
        "next_internal_milestone": (
            OPTION2_MANIFEST_REVIEW_NEXT_INTERNAL_MILESTONE
        ),
    }


def validate_option2_service_identity_provisioning_manifest_review_content(
    content: Mapping[str, Any],
    *,
    plan_review_content_sha256: str,
    fixture_qualification_content_sha256: str,
    reviewed_plan_sha256: str,
    manifest_sha256: str,
    fixture_qualification_sha256: str,
) -> None:
    """Require the exact inactive review body and its caller-supplied bindings."""

    expected = _review_content_body(
        plan_review_content_sha256=plan_review_content_sha256,
        fixture_qualification_content_sha256=(
            fixture_qualification_content_sha256
        ),
        reviewed_plan_sha256=reviewed_plan_sha256,
        manifest_sha256=manifest_sha256,
        fixture_qualification_sha256=fixture_qualification_sha256,
    )
    if not isinstance(content, Mapping) or dict(content) != expected:
        raise Option2ManifestReviewViolation(
            "option2_manifest_review_content_not_canonical"
        )

    production_configuration = content.get("production_configuration")
    if (
        not isinstance(production_configuration, Mapping)
        or set(production_configuration)
        != set(OPTION2_MANIFEST_REVIEW_PRODUCTION_CONFIGURATION_FIELDS)
        or any(
            production_configuration[field] is not None
            for field in OPTION2_MANIFEST_REVIEW_PRODUCTION_CONFIGURATION_FIELDS
        )
    ):
        raise Option2ManifestReviewViolation(
            "option2_manifest_review_production_configuration_open"
        )

    for category, fields in (
        ("authority", OPTION2_MANIFEST_REVIEW_AUTHORITY_FIELDS),
        ("effects", OPTION2_MANIFEST_REVIEW_EFFECT_FIELDS),
        ("readiness", OPTION2_MANIFEST_REVIEW_READINESS_FIELDS),
    ):
        values = content.get(category)
        if (
            not isinstance(values, Mapping)
            or set(values) != set(fields)
            or any(values[field] is not False for field in fields)
        ):
            raise Option2ManifestReviewViolation(
                f"option2_manifest_review_{category}_open"
            )


def build_option2_service_identity_provisioning_manifest_review_content(
    *,
    plan_review_content_sha256: str,
    fixture_qualification_content_sha256: str,
    reviewed_plan_sha256: str,
    manifest_sha256: str,
    fixture_qualification_sha256: str,
) -> dict[str, object]:
    """Build deterministic non-authorizing content for the owner-review receipt."""

    content = _review_content_body(
        plan_review_content_sha256=plan_review_content_sha256,
        fixture_qualification_content_sha256=(
            fixture_qualification_content_sha256
        ),
        reviewed_plan_sha256=reviewed_plan_sha256,
        manifest_sha256=manifest_sha256,
        fixture_qualification_sha256=fixture_qualification_sha256,
    )
    validate_option2_service_identity_provisioning_manifest_review_content(
        content,
        plan_review_content_sha256=plan_review_content_sha256,
        fixture_qualification_content_sha256=(
            fixture_qualification_content_sha256
        ),
        reviewed_plan_sha256=reviewed_plan_sha256,
        manifest_sha256=manifest_sha256,
        fixture_qualification_sha256=fixture_qualification_sha256,
    )
    return content
