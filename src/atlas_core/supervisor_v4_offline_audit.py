from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone
from typing import Callable, Literal

from atlas_core.supervisor_v4_live_contract import (
    CapabilityVerificationReceipt,
    CredentialLeaseMetadata,
    OwnerKillSwitchState,
    ReceiptChainAnchor,
    ReceiptVerificationReceipt,
    document_sha256,
)
from atlas_core.supervisor_v4_offline_crypto import (
    OfflineSigner,
    OfflineVerifier,
    unsigned_document,
)
from atlas_core.supervisor_v4_offline_credential_broker import (
    CREDENTIAL_LEASE_DOMAIN,
)
from atlas_core.supervisor_v4_offline_policy_broker import (
    CAPABILITY_VERIFICATION_DOMAIN,
)
from atlas_core.supervisor_v4_protocol import SignedReceiptLink, ZERO_DIGEST


RECEIPT_LINK_DOMAIN = "atlas.supervisor-v4.receipt-link.v1"
RECEIPT_VERIFICATION_DOMAIN = "atlas.supervisor-v4.receipt-verification.v1"
RECEIPT_ANCHOR_DOMAIN = "atlas.supervisor-v4.receipt-anchor.v1"
KILL_SWITCH_DOMAIN = "atlas.supervisor-v4.kill-switch.v1"


class OfflineAuditViolation(ValueError):
    """Privacy-safe failure from inactive receipt or kill-switch qualification."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _parse_time(value: str, *, code: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise OfflineAuditViolation(code) from exc
    if parsed.tzinfo is None:
        raise OfflineAuditViolation(code)
    return parsed.astimezone(timezone.utc)


def _require_aware(value: datetime, *, code: str) -> datetime:
    if value.tzinfo is None:
        raise OfflineAuditViolation(code)
    return value.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return _require_aware(value, code="clock_invalid").isoformat()


def _require_digest(value: str, *, code: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
        or value == ZERO_DIGEST
    ):
        raise OfflineAuditViolation(code)


def _require_verifier(verifier: OfflineVerifier, *, code: str) -> None:
    if (
        getattr(verifier, "algorithm", None) != "ed25519"
        or not getattr(verifier, "key_id", "")
    ):
        raise OfflineAuditViolation(code)


def _verify_signature(
    verifier: OfflineVerifier,
    *,
    expected_key_id: str,
    domain: str,
    value: object,
    signature: str,
    code: str,
) -> None:
    if verifier.key_id != expected_key_id or verifier.algorithm != "ed25519":
        raise OfflineAuditViolation(f"{code}_key_mismatch")
    try:
        verifier.verify(
            domain=domain,
            payload=unsigned_document(value),
            signature=signature,
        )
    except Exception as exc:
        raise OfflineAuditViolation(f"{code}_signature_invalid") from exc


class OfflineReceiptSigner:
    """Creates signed receipt links without persisting receipt content or keys."""

    def __init__(self, signer: OfflineSigner) -> None:
        if (
            getattr(signer, "algorithm", None) != "ed25519"
            or not getattr(signer, "key_id", "")
        ):
            raise OfflineAuditViolation("receipt_signer_invalid")
        self._signer = signer

    def sign_receipt(
        self,
        receipt_sha256: str,
        predecessor_sha256: str,
    ) -> SignedReceiptLink:
        unsigned = {
            "version": 1,
            "predecessor_sha256": predecessor_sha256,
            "receipt_sha256": receipt_sha256,
            "key_id": self._signer.key_id,
        }
        try:
            signature = self._signer.sign(
                domain=RECEIPT_LINK_DOMAIN,
                payload=unsigned,
            )
        except Exception as exc:
            raise OfflineAuditViolation("receipt_link_signing_failed") from exc
        return SignedReceiptLink(signature=signature, **unsigned)


class OfflineReceiptVerifier:
    """Verifies one receipt link and signs secret-free verification evidence."""

    def __init__(
        self,
        *,
        receipt_verifier: OfflineVerifier,
        capability_verification_verifier: OfflineVerifier,
        credential_lease_verifier: OfflineVerifier,
        anchor_verifier: OfflineVerifier,
        evidence_signer: OfflineSigner,
        clock: Callable[[], datetime],
    ) -> None:
        for verifier, code in (
            (receipt_verifier, "receipt_verifier_invalid"),
            (
                capability_verification_verifier,
                "capability_verification_verifier_invalid",
            ),
            (credential_lease_verifier, "credential_lease_verifier_invalid"),
            (anchor_verifier, "receipt_anchor_verifier_invalid"),
        ):
            _require_verifier(verifier, code=code)
        if (
            getattr(evidence_signer, "algorithm", None) != "ed25519"
            or not getattr(evidence_signer, "key_id", "")
        ):
            raise OfflineAuditViolation("receipt_evidence_signer_invalid")
        if not callable(clock):
            raise OfflineAuditViolation("receipt_verifier_clock_invalid")
        self._receipt_verifier = receipt_verifier
        self._capability_verification_verifier = capability_verification_verifier
        self._credential_lease_verifier = credential_lease_verifier
        self._anchor_verifier = anchor_verifier
        self._evidence_signer = evidence_signer
        self._clock = clock

    def verify_receipt(
        self,
        link: SignedReceiptLink,
        *,
        capability_verification: CapabilityVerificationReceipt,
        lease: CredentialLeaseMetadata,
        predecessor: ReceiptChainAnchor,
        expected_receipt_sha256: str,
    ) -> ReceiptVerificationReceipt:
        _require_digest(
            expected_receipt_sha256,
            code="expected_receipt_sha256_invalid",
        )
        if link.receipt_sha256 != expected_receipt_sha256:
            raise OfflineAuditViolation("receipt_digest_mismatch")
        if link.predecessor_sha256 != predecessor.head_sha256:
            raise OfflineAuditViolation("receipt_predecessor_mismatch")
        _verify_signature(
            self._anchor_verifier,
            expected_key_id=predecessor.anchor_key_id,
            domain=RECEIPT_ANCHOR_DOMAIN,
            value=predecessor,
            signature=predecessor.signature,
            code="receipt_anchor",
        )
        _verify_signature(
            self._capability_verification_verifier,
            expected_key_id=capability_verification.verifier_key_id,
            domain=CAPABILITY_VERIFICATION_DOMAIN,
            value=capability_verification,
            signature=capability_verification.signature,
            code="capability_verification",
        )
        _verify_signature(
            self._credential_lease_verifier,
            expected_key_id=lease.broker_key_id,
            domain=CREDENTIAL_LEASE_DOMAIN,
            value=lease,
            signature=lease.signature,
            code="credential_lease",
        )
        if (
            lease.capability_envelope_sha256
            != capability_verification.capability_envelope_sha256
            or lease.egress_manifest_sha256
            != capability_verification.egress_manifest_sha256
        ):
            raise OfflineAuditViolation("receipt_upstream_binding_mismatch")
        _verify_signature(
            self._receipt_verifier,
            expected_key_id=link.key_id,
            domain=RECEIPT_LINK_DOMAIN,
            value=link,
            signature=link.signature,
            code="receipt_link",
        )
        verified_at = _require_aware(self._clock(), code="clock_invalid")
        for starts_at, expires_at, code in (
            (
                capability_verification.verified_at,
                capability_verification.expires_at,
                "capability_verification",
            ),
            (lease.issued_at, lease.expires_at, "credential_lease"),
            (predecessor.observed_at, predecessor.valid_until, "receipt_anchor"),
        ):
            start = _parse_time(starts_at, code=f"{code}_time_invalid")
            expiry = _parse_time(expires_at, code=f"{code}_time_invalid")
            if verified_at < start:
                raise OfflineAuditViolation(f"{code}_not_yet_valid")
            if verified_at >= expiry:
                raise OfflineAuditViolation(f"{code}_stale")
        unsigned = {
            "version": 1,
            "receipt_link_sha256": document_sha256(link),
            "capability_verification_sha256": capability_verification.sha256,
            "lease_metadata_sha256": lease.sha256,
            "predecessor_anchor_sha256": predecessor.sha256,
            "verified_at": _iso(verified_at),
            "verifier_key_id": self._evidence_signer.key_id,
            "algorithm": "ed25519",
        }
        try:
            signature = self._evidence_signer.sign(
                domain=RECEIPT_VERIFICATION_DOMAIN,
                payload=unsigned,
            )
        except Exception as exc:
            raise OfflineAuditViolation("receipt_verification_signing_failed") from exc
        return ReceiptVerificationReceipt(signature=signature, **unsigned)


class OfflineReceiptAnchorBroker:
    """In-memory atomic count/head anchor used only by offline qualification."""

    def __init__(
        self,
        *,
        anchor_signer: OfflineSigner,
        anchor_verifier: OfflineVerifier,
        receipt_verification_verifier: OfflineVerifier,
        clock: Callable[[], datetime],
        freshness_seconds: int = 30,
    ) -> None:
        if not 1 <= freshness_seconds <= 30:
            raise OfflineAuditViolation("anchor_freshness_invalid")
        if (
            getattr(anchor_signer, "algorithm", None) != "ed25519"
            or anchor_signer.key_id != getattr(anchor_verifier, "key_id", None)
        ):
            raise OfflineAuditViolation("receipt_anchor_key_pair_invalid")
        _require_verifier(
            receipt_verification_verifier,
            code="receipt_verification_verifier_invalid",
        )
        if not callable(clock):
            raise OfflineAuditViolation("receipt_anchor_clock_invalid")
        self._anchor_signer = anchor_signer
        self._anchor_verifier = anchor_verifier
        self._receipt_verification_verifier = receipt_verification_verifier
        self._clock = clock
        self._freshness_seconds = freshness_seconds
        self._states: dict[str, tuple[int, str, int]] = {}
        self._lock = threading.Lock()
        self._reachable = True

    def set_reachable_for_qualification(self, reachable: bool) -> None:
        self._reachable = bool(reachable)

    def _now(self) -> datetime:
        if not self._reachable:
            raise OfflineAuditViolation("receipt_anchor_unreachable")
        return _require_aware(self._clock(), code="clock_invalid")

    def _signed_anchor(
        self,
        chain_id_sha256: str,
        *,
        receipt_count: int,
        head_sha256: str,
        generation: int,
        observed_at: datetime,
    ) -> ReceiptChainAnchor:
        unsigned = {
            "version": 1,
            "chain_id_sha256": chain_id_sha256,
            "receipt_count": receipt_count,
            "head_sha256": head_sha256,
            "generation": generation,
            "observed_at": _iso(observed_at),
            "valid_until": _iso(
                observed_at + timedelta(seconds=self._freshness_seconds)
            ),
            "anchor_key_id": self._anchor_signer.key_id,
            "algorithm": "ed25519",
        }
        try:
            signature = self._anchor_signer.sign(
                domain=RECEIPT_ANCHOR_DOMAIN,
                payload=unsigned,
            )
        except Exception as exc:
            raise OfflineAuditViolation("receipt_anchor_signing_failed") from exc
        return ReceiptChainAnchor(signature=signature, **unsigned)

    def read_anchor(self, chain_id_sha256: str) -> ReceiptChainAnchor:
        now = self._now()
        with self._lock:
            count, head, generation = self._states.get(
                chain_id_sha256,
                (0, ZERO_DIGEST, 0),
            )
            return self._signed_anchor(
                chain_id_sha256,
                receipt_count=count,
                head_sha256=head,
                generation=generation,
                observed_at=now,
            )

    def compare_and_append(
        self,
        expected: ReceiptChainAnchor,
        link: SignedReceiptLink,
        verification: ReceiptVerificationReceipt,
    ) -> ReceiptChainAnchor:
        now = self._now()
        _verify_signature(
            self._anchor_verifier,
            expected_key_id=expected.anchor_key_id,
            domain=RECEIPT_ANCHOR_DOMAIN,
            value=expected,
            signature=expected.signature,
            code="receipt_anchor",
        )
        if now >= _parse_time(expected.valid_until, code="receipt_anchor_time_invalid"):
            raise OfflineAuditViolation("receipt_anchor_stale")
        if link.predecessor_sha256 != expected.head_sha256:
            raise OfflineAuditViolation("receipt_predecessor_mismatch")
        if verification.receipt_link_sha256 != document_sha256(link):
            raise OfflineAuditViolation("receipt_verification_link_mismatch")
        if verification.predecessor_anchor_sha256 != expected.sha256:
            raise OfflineAuditViolation("receipt_verification_anchor_mismatch")
        verification_time = _parse_time(
            verification.verified_at,
            code="receipt_verification_time_invalid",
        )
        if verification_time > now or (now - verification_time).total_seconds() > 30:
            raise OfflineAuditViolation("receipt_verification_stale")
        _verify_signature(
            self._receipt_verification_verifier,
            expected_key_id=verification.verifier_key_id,
            domain=RECEIPT_VERIFICATION_DOMAIN,
            value=verification,
            signature=verification.signature,
            code="receipt_verification",
        )

        with self._lock:
            current = self._states.get(
                expected.chain_id_sha256,
                (0, ZERO_DIGEST, 0),
            )
            supplied = (
                expected.receipt_count,
                expected.head_sha256,
                expected.generation,
            )
            if current != supplied:
                raise OfflineAuditViolation("receipt_anchor_compare_failed")
            new_state = (
                expected.receipt_count + 1,
                document_sha256(link),
                expected.generation + 1,
            )
            self._states[expected.chain_id_sha256] = new_state
            return self._signed_anchor(
                expected.chain_id_sha256,
                receipt_count=new_state[0],
                head_sha256=new_state[1],
                generation=new_state[2],
                observed_at=now,
            )


class OfflineOwnerKillSwitch:
    """Explicitly armed, monotonic, fail-closed owner state for offline tests."""

    def __init__(
        self,
        *,
        signer: OfflineSigner,
        clock: Callable[[], datetime],
        freshness_seconds: int = 10,
    ) -> None:
        if not 1 <= freshness_seconds <= 10:
            raise OfflineAuditViolation("kill_switch_freshness_invalid")
        if (
            getattr(signer, "algorithm", None) != "ed25519"
            or not getattr(signer, "key_id", "")
        ):
            raise OfflineAuditViolation("kill_switch_signer_invalid")
        if not callable(clock):
            raise OfflineAuditViolation("kill_switch_clock_invalid")
        self._signer = signer
        self._clock = clock
        self._freshness_seconds = freshness_seconds
        self._states: dict[tuple[str, str], tuple[int, Literal["armed", "paused"]]] = {}
        self._lock = threading.Lock()
        self._reachable = True

    def set_reachable_for_qualification(self, reachable: bool) -> None:
        self._reachable = bool(reachable)

    def _now(self) -> datetime:
        if not self._reachable:
            raise OfflineAuditViolation("kill_switch_unreachable")
        return _require_aware(self._clock(), code="clock_invalid")

    def _signed_state(
        self,
        *,
        channel_sha256: str,
        capability_envelope_sha256: str,
        generation: int,
        state: Literal["armed", "paused"],
        observed_at: datetime,
    ) -> OwnerKillSwitchState:
        unsigned = {
            "version": 1,
            "channel_sha256": channel_sha256,
            "capability_envelope_sha256": capability_envelope_sha256,
            "generation": generation,
            "state": state,
            "observed_at": _iso(observed_at),
            "valid_until": _iso(
                observed_at + timedelta(seconds=self._freshness_seconds)
            ),
            "oracle_key_id": self._signer.key_id,
            "algorithm": "ed25519",
            "fail_closed_on_unreachable": True,
        }
        try:
            signature = self._signer.sign(
                domain=KILL_SWITCH_DOMAIN,
                payload=unsigned,
            )
        except Exception as exc:
            raise OfflineAuditViolation("kill_switch_signing_failed") from exc
        return OwnerKillSwitchState(signature=signature, **unsigned)

    def set_state(
        self,
        channel_sha256: str,
        capability_envelope_sha256: str,
        state: Literal["armed", "paused"],
    ) -> OwnerKillSwitchState:
        now = self._now()
        key = (channel_sha256, capability_envelope_sha256)
        with self._lock:
            prior_generation = self._states.get(key, (-1, "paused"))[0]
            current = (prior_generation + 1, state)
            if state == "paused":
                # A failed pause signature must still leave the in-process
                # oracle stopped. A failed arm signature must never arm it.
                self._states[key] = current
            signed = self._signed_state(
                channel_sha256=channel_sha256,
                capability_envelope_sha256=capability_envelope_sha256,
                generation=current[0],
                state=current[1],
                observed_at=now,
            )
            if state == "armed":
                self._states[key] = current
            return signed

    def read_state(
        self,
        channel_sha256: str,
        capability_envelope_sha256: str,
    ) -> OwnerKillSwitchState:
        now = self._now()
        key = (channel_sha256, capability_envelope_sha256)
        with self._lock:
            if key not in self._states:
                raise OfflineAuditViolation("kill_switch_not_initialized")
            generation, state = self._states[key]
            return self._signed_state(
                channel_sha256=channel_sha256,
                capability_envelope_sha256=capability_envelope_sha256,
                generation=generation,
                state=state,
                observed_at=now,
            )


def verify_kill_switch_state(
    state: OwnerKillSwitchState,
    *,
    verifier: OfflineVerifier,
    observed_at: datetime,
    expected_channel_sha256: str,
    expected_capability_envelope_sha256: str,
    minimum_generation: int,
) -> None:
    if (
        not isinstance(minimum_generation, int)
        or isinstance(minimum_generation, bool)
        or minimum_generation < 0
    ):
        raise OfflineAuditViolation("kill_switch_generation_floor_invalid")
    now = _require_aware(observed_at, code="clock_invalid")
    _verify_signature(
        verifier,
        expected_key_id=state.oracle_key_id,
        domain=KILL_SWITCH_DOMAIN,
        value=state,
        signature=state.signature,
        code="kill_switch",
    )
    if (
        state.channel_sha256 != expected_channel_sha256
        or state.capability_envelope_sha256 != expected_capability_envelope_sha256
    ):
        raise OfflineAuditViolation("kill_switch_binding_mismatch")
    if state.generation < minimum_generation:
        raise OfflineAuditViolation("kill_switch_generation_rollback")
    start = _parse_time(state.observed_at, code="kill_switch_time_invalid")
    expiry = _parse_time(state.valid_until, code="kill_switch_time_invalid")
    if now < start or now >= expiry:
        raise OfflineAuditViolation("kill_switch_stale")
    if state.state != "armed":
        raise OfflineAuditViolation("kill_switch_paused")


__all__ = [
    "KILL_SWITCH_DOMAIN",
    "OfflineAuditViolation",
    "OfflineOwnerKillSwitch",
    "OfflineReceiptAnchorBroker",
    "OfflineReceiptSigner",
    "OfflineReceiptVerifier",
    "RECEIPT_ANCHOR_DOMAIN",
    "RECEIPT_LINK_DOMAIN",
    "RECEIPT_VERIFICATION_DOMAIN",
    "verify_kill_switch_state",
]
