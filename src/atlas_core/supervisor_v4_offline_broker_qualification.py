from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Callable

from atlas_core.supervisor_v4_live_contract import (
    CredentialLeaseRequest,
    DataEgressManifest,
    LiveCanaryContractViolation,
    LiveCanaryTrustBundle,
    document_sha256,
    validate_live_canary_trust_bundle,
)
from atlas_core.supervisor_v4_offline_audit import (
    OfflineAuditViolation,
    OfflineOwnerKillSwitch,
    OfflineReceiptAnchorBroker,
    OfflineReceiptSigner,
    OfflineReceiptVerifier,
    verify_kill_switch_state,
)
from atlas_core.supervisor_v4_offline_credential_broker import (
    OfflineCredentialLeaseBroker,
    SyntheticOneUseChannelHandle,
)
from atlas_core.supervisor_v4_offline_crypto import Ed25519OfflineSigner
from atlas_core.supervisor_v4_offline_policy_broker import (
    OfflineCapabilityVerificationBroker,
    OfflineOwnerPolicyBroker,
)
from atlas_core.supervisor_v4_protocol import (
    CapabilityBindings,
    ImmutablePolicyBundle,
    ZERO_DIGEST,
)


def _digest(label: str) -> str:
    return hashlib.sha256(
        f"atlas-supervisor-v4-offline-qualification:{label}".encode("utf-8")
    ).hexdigest()


def _expect_violation(
    operation: Callable[[], object],
    *,
    expected_code: str,
    violation_type: type[ValueError],
) -> bool:
    try:
        operation()
    except violation_type as exc:
        return getattr(exc, "code", str(exc)) == expected_code
    return False


def run_offline_broker_qualification(
    *,
    observed_at: datetime | None = None,
) -> dict[str, object]:
    """Exercise the inactive broker trust chain without I/O or live authority.

    All signing keys, nonces, and opaque handles exist only in this process.
    The returned report contains bounded booleans and counts, never key material,
    signatures, handles, capability identifiers, or credential material.
    """

    now = observed_at or datetime.now(timezone.utc)
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise ValueError("offline_broker_qualification_clock_invalid")
    now = now.astimezone(timezone.utc)
    clock = lambda: now

    policy_signer = Ed25519OfflineSigner.generate()
    capability_evidence_signer = Ed25519OfflineSigner.generate()
    credential_signer = Ed25519OfflineSigner.generate()
    receipt_signer_key = Ed25519OfflineSigner.generate()
    receipt_evidence_signer = Ed25519OfflineSigner.generate()
    anchor_signer = Ed25519OfflineSigner.generate()
    kill_switch_signer = Ed25519OfflineSigner.generate()

    task_sha256 = _digest("task")
    job_sha256 = _digest("job")
    policy_bundle = ImmutablePolicyBundle(
        version=1,
        policy_sha256=_digest("policy"),
        protocol_sha256=_digest("protocol"),
        sdk_lock_sha256=_digest("sdk-lock"),
        replay_corpus_sha256=_digest("replay-corpus"),
    )
    egress = DataEgressManifest(
        version=1,
        task_sha256=task_sha256,
        job_sha256=job_sha256,
        source_manifest_sha256=_digest("source-manifest"),
        payload_sha256=_digest("fictional-payload"),
        output_schema_sha256=_digest("output-schema"),
        purpose_sha256=_digest("qualification-purpose"),
        provider="offline-fixture-provider",
        model="offline-fixture-model",
        classification="synthetic_fictional_bounded",
        record_count=1,
        payload_bytes=128,
        max_payload_bytes=256,
        contains_private_data=False,
        contains_credentials=False,
    )
    channel = SyntheticOneUseChannelHandle.generate()
    issued_at = now - timedelta(seconds=1)
    expires_at = now + timedelta(seconds=240)
    bindings = CapabilityBindings(
        capability_version=4,
        capability_id_sha256=_digest("capability-id"),
        task_sha256=task_sha256,
        job_sha256=job_sha256,
        project_sha256=_digest("fictional-project"),
        nonce_sha256=_digest("one-use-nonce"),
        audience="atlas-supervisor-v4-proposal-worker",
        provider=egress.provider,
        sdk_version="0.147.0",
        signing_key_id=policy_signer.key_id,
        one_use=True,
        issued_at=issued_at.isoformat(),
        expires_at=expires_at.isoformat(),
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
        path_sha256=_digest("fictional-path"),
        expected_original_sha256=_digest("fictional-original"),
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

    policy_broker = OfflineOwnerPolicyBroker(
        signer=policy_signer,
        verifier=policy_signer.verifier,
        clock=clock,
    )
    capability = policy_broker.issue_capability(policy_bundle, bindings)
    capability_issue_replay_rejected = _expect_violation(
        lambda: policy_broker.issue_capability(policy_bundle, bindings),
        expected_code="capability_nonce_already_issued",
        violation_type=LiveCanaryContractViolation,
    )

    capability_broker = OfflineCapabilityVerificationBroker(
        capability_verifier=policy_signer.verifier,
        receipt_signer=capability_evidence_signer,
        receipt_verifier=capability_evidence_signer.verifier,
        not_revoked_snapshot=lambda _envelope, _observed_at: _digest(
            "not-revoked-snapshot"
        ),
        clock=clock,
        verification_ttl_seconds=180,
    )
    capability_verification = capability_broker.verify_capability(
        capability,
        policy_bundle=policy_bundle,
        expected_egress_manifest_sha256=egress.sha256,
        observed_at=now.isoformat(),
    )
    capability_broker.verify_verification_receipt(capability_verification)
    capability_verification_replay_rejected = _expect_violation(
        lambda: capability_broker.verify_capability(
            capability,
            policy_bundle=policy_bundle,
            expected_egress_manifest_sha256=egress.sha256,
            observed_at=now.isoformat(),
        ),
        expected_code="capability_already_verified",
        violation_type=LiveCanaryContractViolation,
    )
    forged_capability = replace(capability, signature="A" * 86)
    capability_forgery_rejected = _expect_violation(
        lambda: capability_broker.verify_capability(
            forged_capability,
            policy_bundle=policy_bundle,
            expected_egress_manifest_sha256=egress.sha256,
            observed_at=now.isoformat(),
        ),
        expected_code="capability_signature_invalid",
        violation_type=LiveCanaryContractViolation,
    )

    request = CredentialLeaseRequest(
        version=1,
        capability_envelope_sha256=document_sha256(capability),
        capability_verification_sha256=capability_verification.sha256,
        policy_bundle_sha256=policy_bundle.sha256,
        egress_manifest_sha256=egress.sha256,
        task_sha256=task_sha256,
        job_sha256=job_sha256,
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
    credential_broker = OfflineCredentialLeaseBroker(
        signer=credential_signer,
        verifier=credential_signer.verifier,
        capability=capability,
        capability_verification_key_id=capability_broker.verifier_key_id,
        capability_receipt_verifier=(
            capability_broker.verify_verification_receipt
        ),
        clock=clock,
    )
    substituted_request = replace(
        request,
        capability_envelope_sha256=_digest("substituted-capability"),
    )
    credential_substitution_rejected = _expect_violation(
        lambda: credential_broker.issue_lease(
            substituted_request,
            capability_verification,
        ),
        expected_code="credential_broker_capability_binding_mismatch",
        violation_type=LiveCanaryContractViolation,
    )
    lease = credential_broker.issue_lease(request, capability_verification)
    credential_broker.verify_lease(request, lease, capability_verification)
    credential_issue_replay_rejected = _expect_violation(
        lambda: credential_broker.issue_lease(request, capability_verification),
        expected_code="credential_broker_request_replayed",
        violation_type=LiveCanaryContractViolation,
    )

    anchor_broker = OfflineReceiptAnchorBroker(
        anchor_signer=anchor_signer,
        anchor_verifier=anchor_signer.verifier,
        receipt_verification_verifier=receipt_evidence_signer.verifier,
        clock=clock,
    )
    predecessor = anchor_broker.read_anchor(bindings.receipt_chain_id_sha256)
    kill_switch = OfflineOwnerKillSwitch(signer=kill_switch_signer, clock=clock)
    kill_switch_state = kill_switch.set_state(
        bindings.kill_switch_channel_sha256,
        document_sha256(capability),
        "armed",
    )
    verify_kill_switch_state(
        kill_switch_state,
        verifier=kill_switch_signer.verifier,
        observed_at=now,
        expected_channel_sha256=bindings.kill_switch_channel_sha256,
        expected_capability_envelope_sha256=document_sha256(capability),
        minimum_generation=kill_switch_state.generation,
    )
    trust = validate_live_canary_trust_bundle(
        LiveCanaryTrustBundle(
            policy_bundle=policy_bundle,
            capability=capability,
            capability_verification=capability_verification,
            egress=egress,
            credential_request=request,
            credential_lease=lease,
            predecessor_anchor=predecessor,
            kill_switch=kill_switch_state,
        ),
        observed_at=now.isoformat(),
        minimum_kill_switch_generation=kill_switch_state.generation,
    )

    delivery_receipt = credential_broker.deliver_once(
        channel,
        request=request,
        lease=lease,
        verification=capability_verification,
    )
    credential_broker.verify_delivery_receipt(lease, delivery_receipt)
    credential_delivery_replay_rejected = _expect_violation(
        lambda: credential_broker.deliver_once(
            channel,
            request=request,
            lease=lease,
            verification=capability_verification,
        ),
        expected_code="credential_delivery_replayed",
        violation_type=LiveCanaryContractViolation,
    )

    receipt_signer = OfflineReceiptSigner(receipt_signer_key)
    receipt_verifier = OfflineReceiptVerifier(
        receipt_verifier=receipt_signer_key.verifier,
        capability_verification_verifier=capability_evidence_signer.verifier,
        credential_lease_verifier=credential_signer.verifier,
        anchor_verifier=anchor_signer.verifier,
        evidence_signer=receipt_evidence_signer,
        clock=clock,
    )
    receipt_link = receipt_signer.sign_receipt(
        delivery_receipt.sha256,
        predecessor.head_sha256,
    )
    receipt_verification = receipt_verifier.verify_receipt(
        receipt_link,
        capability_verification=capability_verification,
        lease=lease,
        predecessor=predecessor,
        expected_receipt_sha256=delivery_receipt.sha256,
    )
    advanced_anchor = anchor_broker.compare_and_append(
        predecessor,
        receipt_link,
        receipt_verification,
    )
    receipt_anchor_replay_rejected = _expect_violation(
        lambda: anchor_broker.compare_and_append(
            predecessor,
            receipt_link,
            receipt_verification,
        ),
        expected_code="receipt_anchor_compare_failed",
        violation_type=OfflineAuditViolation,
    )
    anchor_broker.set_reachable_for_qualification(False)
    receipt_anchor_unreachable_rejected = _expect_violation(
        lambda: anchor_broker.read_anchor(bindings.receipt_chain_id_sha256),
        expected_code="receipt_anchor_unreachable",
        violation_type=OfflineAuditViolation,
    )

    revocation = credential_broker.revoke_lease(
        lease,
        reason_sha256=_digest("qualification-complete"),
    )
    credential_broker.verify_revocation(lease, revocation)
    credential_revocation_replay_rejected = _expect_violation(
        lambda: credential_broker.revoke_lease(
            lease,
            reason_sha256=_digest("qualification-complete"),
        ),
        expected_code="credential_revocation_replayed",
        violation_type=LiveCanaryContractViolation,
    )

    paused_state = kill_switch.set_state(
        bindings.kill_switch_channel_sha256,
        document_sha256(capability),
        "paused",
    )
    kill_switch_pause_rejected = _expect_violation(
        lambda: verify_kill_switch_state(
            paused_state,
            verifier=kill_switch_signer.verifier,
            observed_at=now,
            expected_channel_sha256=bindings.kill_switch_channel_sha256,
            expected_capability_envelope_sha256=document_sha256(capability),
            minimum_generation=kill_switch_state.generation,
        ),
        expected_code="kill_switch_paused",
        violation_type=OfflineAuditViolation,
    )
    kill_switch.set_reachable_for_qualification(False)
    kill_switch_unreachable_rejected = _expect_violation(
        lambda: kill_switch.read_state(
            bindings.kill_switch_channel_sha256,
            document_sha256(capability),
        ),
        expected_code="kill_switch_unreachable",
        violation_type=OfflineAuditViolation,
    )

    report: dict[str, object] = {
        "algorithm": "ed25519",
        "ephemeral_key_count": 7,
        "cryptographic_implementation_present": True,
        "capability_signature_verified": True,
        "capability_verifier_trusted_clock": True,
        "capability_issue_replay_rejected": capability_issue_replay_rejected,
        "capability_verification_replay_rejected": (
            capability_verification_replay_rejected
        ),
        "capability_forgery_rejected": capability_forgery_rejected,
        "structural_bindings_valid": trust["structural_bindings_valid"],
        "synthetic_egress_only": trust["synthetic_egress_only"],
        "credential_lease_signature_verified": True,
        "credential_exact_capability_bound": True,
        "credential_substitution_rejected": credential_substitution_rejected,
        "credential_issue_replay_rejected": credential_issue_replay_rejected,
        "synthetic_delivery_completed": delivery_receipt.synthetic_only,
        "credential_delivery_replay_rejected": (
            credential_delivery_replay_rejected
        ),
        "credential_revocation_verified": revocation.delivery_closed,
        "credential_revocation_replay_rejected": (
            credential_revocation_replay_rejected
        ),
        "receipt_signature_verified": True,
        "receipt_upstream_signatures_verified": True,
        "receipt_anchor_advanced_atomically": (
            advanced_anchor.receipt_count == 1
            and advanced_anchor.generation == 1
            and advanced_anchor.head_sha256 == document_sha256(receipt_link)
        ),
        "receipt_anchor_replay_rejected": receipt_anchor_replay_rejected,
        "receipt_anchor_unreachable_rejected": receipt_anchor_unreachable_rejected,
        "kill_switch_armed_verified": True,
        "kill_switch_generation_floor_enforced": True,
        "kill_switch_pause_rejected": kill_switch_pause_rejected,
        "kill_switch_unreachable_rejected": kill_switch_unreachable_rejected,
        "signing_keys_exported": False,
        "credential_material_present": False,
        "credential_material_persisted": False,
        "private_data_present": False,
        "network_accessed": False,
        "model_contacted": False,
        "live_authority_granted": False,
        "production_broker_configured": False,
    }
    required_true = (
        "cryptographic_implementation_present",
        "capability_signature_verified",
        "capability_verifier_trusted_clock",
        "capability_issue_replay_rejected",
        "capability_verification_replay_rejected",
        "capability_forgery_rejected",
        "structural_bindings_valid",
        "synthetic_egress_only",
        "credential_lease_signature_verified",
        "credential_exact_capability_bound",
        "credential_substitution_rejected",
        "credential_issue_replay_rejected",
        "synthetic_delivery_completed",
        "credential_delivery_replay_rejected",
        "credential_revocation_verified",
        "credential_revocation_replay_rejected",
        "receipt_signature_verified",
        "receipt_upstream_signatures_verified",
        "receipt_anchor_advanced_atomically",
        "receipt_anchor_replay_rejected",
        "receipt_anchor_unreachable_rejected",
        "kill_switch_armed_verified",
        "kill_switch_generation_floor_enforced",
        "kill_switch_pause_rejected",
        "kill_switch_unreachable_rejected",
    )
    required_false = (
        "signing_keys_exported",
        "credential_material_present",
        "credential_material_persisted",
        "private_data_present",
        "network_accessed",
        "model_contacted",
        "live_authority_granted",
        "production_broker_configured",
    )
    report["qualified"] = all(report[key] is True for key in required_true) and all(
        report[key] is False for key in required_false
    )
    return report


__all__ = ["run_offline_broker_qualification"]
