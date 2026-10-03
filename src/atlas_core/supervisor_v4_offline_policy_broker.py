from __future__ import annotations

import re
import threading
from datetime import datetime, timedelta
from typing import Callable

from atlas_core.supervisor_v4_live_contract import (
    CapabilityVerificationReceipt,
    LiveCanaryContractViolation,
    document_sha256,
)
from atlas_core.supervisor_v4_offline_crypto import (
    OfflineSigner,
    OfflineVerifier,
    unsigned_document,
)
from atlas_core.supervisor_v4_protocol import (
    CapabilityBindings,
    ImmutablePolicyBundle,
    SignedCapabilityEnvelope,
)


CAPABILITY_DOMAIN = "atlas.supervisor-v4.capability.v1"
CAPABILITY_VERIFICATION_DOMAIN = "atlas.supervisor-v4.capability-verification.v1"
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")

Clock = Callable[[], datetime]
NotRevokedSnapshot = Callable[[SignedCapabilityEnvelope, str], str | None]


def _parse_time(value: str, *, code: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError) as exc:
        raise LiveCanaryContractViolation(code) from exc
    if parsed.tzinfo is None:
        raise LiveCanaryContractViolation(code)
    return parsed


def _require_digest(value: str, *, code: str) -> None:
    if (
        not isinstance(value, str)
        or not _SHA256_PATTERN.fullmatch(value)
        or value == "0" * 64
    ):
        raise LiveCanaryContractViolation(code)


def _require_ed25519_pair(
    signer: OfflineSigner,
    verifier: OfflineVerifier,
    *,
    code: str,
) -> None:
    if (
        getattr(signer, "algorithm", None) != "ed25519"
        or getattr(verifier, "algorithm", None) != "ed25519"
        or not getattr(signer, "key_id", "")
        or signer.key_id != getattr(verifier, "key_id", None)
    ):
        raise LiveCanaryContractViolation(code)


def _verify_capability_signature(
    envelope: SignedCapabilityEnvelope,
    verifier: OfflineVerifier,
) -> None:
    if (
        getattr(verifier, "algorithm", None) != "ed25519"
        or envelope.key_id != getattr(verifier, "key_id", None)
    ):
        raise LiveCanaryContractViolation("capability_verifier_key_mismatch")
    try:
        verifier.verify(
            domain=CAPABILITY_DOMAIN,
            payload=unsigned_document(envelope),
            signature=envelope.signature,
        )
    except Exception as exc:
        raise LiveCanaryContractViolation("capability_signature_invalid") from exc


def _verify_verification_signature(
    receipt: CapabilityVerificationReceipt,
    verifier: OfflineVerifier,
) -> None:
    if (
        getattr(verifier, "algorithm", None) != "ed25519"
        or receipt.verifier_key_id != getattr(verifier, "key_id", None)
    ):
        raise LiveCanaryContractViolation("capability_verification_key_mismatch")
    try:
        verifier.verify(
            domain=CAPABILITY_VERIFICATION_DOMAIN,
            payload=unsigned_document(receipt),
            signature=receipt.signature,
        )
    except Exception as exc:
        raise LiveCanaryContractViolation(
            "capability_verification_signature_invalid"
        ) from exc


class OfflineOwnerPolicyBroker:
    """Inactive owner-side capability signer with an in-memory replay guard.

    The broker accepts an injected Ed25519 signer and retains only public key
    identity plus nonce digests in its observable output. Its in-memory replay
    guard is qualification evidence, not a production authority store.
    """

    __slots__ = ("_clock", "_issued_nonce_sha256", "_lock", "_signer", "_verifier")

    def __init__(
        self,
        *,
        signer: OfflineSigner,
        verifier: OfflineVerifier,
        clock: Clock,
    ) -> None:
        _require_ed25519_pair(
            signer,
            verifier,
            code="capability_signing_key_pair_invalid",
        )
        if not callable(clock):
            raise LiveCanaryContractViolation("capability_clock_invalid")
        self._signer = signer
        self._verifier = verifier
        self._clock = clock
        self._issued_nonce_sha256: set[str] = set()
        self._lock = threading.Lock()

    @property
    def key_id(self) -> str:
        return self._signer.key_id

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(key_id={self.key_id!r}, "
            "secret_material='<injected-redacted>')"
        )

    def issue_capability(
        self,
        bundle: ImmutablePolicyBundle,
        bindings: CapabilityBindings,
    ) -> SignedCapabilityEnvelope:
        if not isinstance(bundle, ImmutablePolicyBundle) or not isinstance(
            bindings, CapabilityBindings
        ):
            raise LiveCanaryContractViolation("capability_issue_document_invalid")
        if (
            bindings.signing_key_id != self.key_id
            or bindings.policy_bundle_sha256 != bundle.sha256
            or bindings.replay_corpus_sha256 != bundle.replay_corpus_sha256
            or bindings.one_use is not True
        ):
            raise LiveCanaryContractViolation("capability_issue_binding_mismatch")

        try:
            observed_at = self._clock()
        except Exception as exc:
            raise LiveCanaryContractViolation("capability_clock_unavailable") from exc
        if not isinstance(observed_at, datetime) or observed_at.tzinfo is None:
            raise LiveCanaryContractViolation("capability_clock_invalid")
        issued_at = _parse_time(bindings.issued_at, code="capability_issued_at_invalid")
        expires_at = _parse_time(bindings.expires_at, code="capability_expires_at_invalid")
        if observed_at < issued_at:
            raise LiveCanaryContractViolation("capability_not_yet_valid")
        if observed_at >= expires_at:
            raise LiveCanaryContractViolation("capability_expired")

        # Burn the nonce before calling the signer. An ambiguous signing failure
        # cannot be retried with the same work-order nonce in this broker process.
        with self._lock:
            if bindings.nonce_sha256 in self._issued_nonce_sha256:
                raise LiveCanaryContractViolation("capability_nonce_already_issued")
            self._issued_nonce_sha256.add(bindings.nonce_sha256)

        unsigned = SignedCapabilityEnvelope(
            version=1,
            key_id=self.key_id,
            capability_sha256=bindings.sha256,
            signature="unsigned",
            nonce_sha256=bindings.nonce_sha256,
            bindings=bindings,
        )
        try:
            signature = self._signer.sign(
                domain=CAPABILITY_DOMAIN,
                payload=unsigned_document(unsigned),
            )
        except Exception as exc:
            raise LiveCanaryContractViolation("capability_signing_failed") from exc
        envelope = SignedCapabilityEnvelope(
            version=unsigned.version,
            key_id=unsigned.key_id,
            capability_sha256=unsigned.capability_sha256,
            signature=signature,
            nonce_sha256=unsigned.nonce_sha256,
            bindings=bindings,
        )
        _verify_capability_signature(envelope, self._verifier)
        return envelope


class OfflineCapabilityVerificationBroker:
    """Verify one exact owner capability and issue public signed evidence.

    This inactive broker cannot dispatch work, obtain a credential, contact a
    model, or grant live authority. A caller must inject a fail-closed external
    revocation snapshot function; a missing, revoked, or malformed snapshot is
    terminal.
    """

    __slots__ = (
        "_capability_verifier",
        "_clock",
        "_lock",
        "_not_revoked_snapshot",
        "_receipt_signer",
        "_receipt_verifier",
        "_verification_ttl_seconds",
        "_verified_capabilities",
    )

    def __init__(
        self,
        *,
        capability_verifier: OfflineVerifier,
        receipt_signer: OfflineSigner,
        receipt_verifier: OfflineVerifier,
        not_revoked_snapshot: NotRevokedSnapshot,
        clock: Clock,
        verification_ttl_seconds: int = 300,
    ) -> None:
        if getattr(capability_verifier, "algorithm", None) != "ed25519" or not getattr(
            capability_verifier, "key_id", ""
        ):
            raise LiveCanaryContractViolation("capability_verifier_invalid")
        _require_ed25519_pair(
            receipt_signer,
            receipt_verifier,
            code="capability_verification_key_pair_invalid",
        )
        if not callable(not_revoked_snapshot):
            raise LiveCanaryContractViolation("capability_revocation_source_invalid")
        if not callable(clock):
            raise LiveCanaryContractViolation("capability_verification_clock_invalid")
        if (
            not isinstance(verification_ttl_seconds, int)
            or isinstance(verification_ttl_seconds, bool)
            or not 1 <= verification_ttl_seconds <= 300
        ):
            raise LiveCanaryContractViolation("capability_verification_ttl_invalid")
        self._capability_verifier = capability_verifier
        self._clock = clock
        self._receipt_signer = receipt_signer
        self._receipt_verifier = receipt_verifier
        self._not_revoked_snapshot = not_revoked_snapshot
        self._verification_ttl_seconds = verification_ttl_seconds
        self._verified_capabilities: set[tuple[str, str]] = set()
        self._lock = threading.Lock()

    @property
    def verifier_key_id(self) -> str:
        return self._receipt_signer.key_id

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(capability_key_id="
            f"{self._capability_verifier.key_id!r}, verifier_key_id="
            f"{self.verifier_key_id!r}, secret_material='<injected-redacted>')"
        )

    def verify_verification_receipt(
        self,
        receipt: CapabilityVerificationReceipt,
    ) -> None:
        """Verify only this broker's detached receipt signature.

        Callers remain responsible for freshness and task-specific cross-binding.
        """

        if not isinstance(receipt, CapabilityVerificationReceipt):
            raise LiveCanaryContractViolation(
                "capability_verification_document_invalid"
            )
        _verify_verification_signature(receipt, self._receipt_verifier)

    def verify_capability(
        self,
        envelope: SignedCapabilityEnvelope,
        *,
        policy_bundle: ImmutablePolicyBundle,
        expected_egress_manifest_sha256: str,
        observed_at: str,
    ) -> CapabilityVerificationReceipt:
        if not isinstance(envelope, SignedCapabilityEnvelope) or not isinstance(
            policy_bundle, ImmutablePolicyBundle
        ):
            raise LiveCanaryContractViolation("capability_verification_document_invalid")
        _require_digest(
            expected_egress_manifest_sha256,
            code="expected_egress_manifest_sha256_invalid",
        )
        bindings = envelope.bindings
        if (
            bindings.policy_bundle_sha256 != policy_bundle.sha256
            or bindings.replay_corpus_sha256 != policy_bundle.replay_corpus_sha256
            or bindings.data_egress_manifest_sha256
            != expected_egress_manifest_sha256
            or envelope.capability_sha256 != bindings.sha256
            or envelope.nonce_sha256 != bindings.nonce_sha256
            or envelope.one_use is not True
        ):
            raise LiveCanaryContractViolation("capability_verification_binding_mismatch")

        reported_at = _parse_time(
            observed_at,
            code="capability_verification_time_invalid",
        )
        try:
            now = self._clock()
        except Exception as exc:
            raise LiveCanaryContractViolation(
                "capability_verification_clock_unavailable"
            ) from exc
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise LiveCanaryContractViolation("capability_verification_clock_invalid")
        if abs((reported_at - now).total_seconds()) > 1:
            raise LiveCanaryContractViolation(
                "capability_verification_observed_time_mismatch"
            )
        issued_at = _parse_time(bindings.issued_at, code="capability_issued_at_invalid")
        capability_expiry = _parse_time(
            bindings.expires_at,
            code="capability_expires_at_invalid",
        )
        if now < issued_at:
            raise LiveCanaryContractViolation("capability_not_yet_valid")
        if now >= capability_expiry:
            raise LiveCanaryContractViolation("capability_expired")

        _verify_capability_signature(envelope, self._capability_verifier)
        try:
            revocation_snapshot_sha256 = self._not_revoked_snapshot(
                envelope,
                now.isoformat(),
            )
        except Exception as exc:
            raise LiveCanaryContractViolation(
                "capability_revocation_snapshot_unavailable"
            ) from exc
        if revocation_snapshot_sha256 is None:
            raise LiveCanaryContractViolation("capability_revoked_or_unknown")
        _require_digest(
            revocation_snapshot_sha256,
            code="capability_revocation_snapshot_invalid",
        )

        envelope_sha256 = document_sha256(envelope)
        replay_identity = (
            envelope.capability_sha256,
            envelope.nonce_sha256,
        )
        # As with issuance, ambiguous signer failure burns this verification
        # attempt inside the inactive broker rather than permitting a replay.
        with self._lock:
            if replay_identity in self._verified_capabilities:
                raise LiveCanaryContractViolation("capability_already_verified")
            self._verified_capabilities.add(replay_identity)

        verification_expiry = min(
            capability_expiry,
            now + timedelta(seconds=self._verification_ttl_seconds),
        )
        if verification_expiry <= now:
            raise LiveCanaryContractViolation("capability_verification_expired")
        unsigned = CapabilityVerificationReceipt(
            version=1,
            decision="verified",
            capability_envelope_sha256=envelope_sha256,
            capability_sha256=envelope.capability_sha256,
            policy_bundle_sha256=policy_bundle.sha256,
            egress_manifest_sha256=expected_egress_manifest_sha256,
            revocation_snapshot_sha256=revocation_snapshot_sha256,
            verified_at=now.isoformat(),
            expires_at=verification_expiry.isoformat(),
            verifier_key_id=self.verifier_key_id,
            algorithm="ed25519",
            signature="A" * 86,
        )
        try:
            signature = self._receipt_signer.sign(
                domain=CAPABILITY_VERIFICATION_DOMAIN,
                payload=unsigned_document(unsigned),
            )
        except Exception as exc:
            raise LiveCanaryContractViolation(
                "capability_verification_signing_failed"
            ) from exc
        receipt = CapabilityVerificationReceipt(
            version=unsigned.version,
            decision=unsigned.decision,
            capability_envelope_sha256=unsigned.capability_envelope_sha256,
            capability_sha256=unsigned.capability_sha256,
            policy_bundle_sha256=unsigned.policy_bundle_sha256,
            egress_manifest_sha256=unsigned.egress_manifest_sha256,
            revocation_snapshot_sha256=unsigned.revocation_snapshot_sha256,
            verified_at=unsigned.verified_at,
            expires_at=unsigned.expires_at,
            verifier_key_id=unsigned.verifier_key_id,
            algorithm=unsigned.algorithm,
            signature=signature,
        )
        _verify_verification_signature(receipt, self._receipt_verifier)
        return receipt


__all__ = [
    "CAPABILITY_DOMAIN",
    "CAPABILITY_VERIFICATION_DOMAIN",
    "NotRevokedSnapshot",
    "OfflineCapabilityVerificationBroker",
    "OfflineOwnerPolicyBroker",
]
