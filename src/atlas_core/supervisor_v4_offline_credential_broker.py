from __future__ import annotations

import hashlib
import re
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Literal

from atlas_core.supervisor_v4_live_contract import (
    CapabilityVerificationReceipt,
    CredentialLeaseMetadata,
    CredentialLeaseRequest,
    CredentialRevocationReceipt,
    LiveCanaryContractViolation,
    document_sha256,
)
from atlas_core.supervisor_v4_offline_crypto import (
    OfflineSigner,
    OfflineVerifier,
    unsigned_document,
)
from atlas_core.supervisor_v4_protocol import SignedCapabilityEnvelope


_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_HANDLE_PATTERN = re.compile(r"^atlas-v4-offline-channel-v1_[A-Za-z0-9_-]{43}$")
_LABEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_SIGNATURE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{86}$")
CREDENTIAL_LEASE_DOMAIN = "atlas.supervisor-v4.credential-lease.v1"
_DELIVERY_DOMAIN = "atlas.supervisor-v4.credential-delivery.v1"
_REVOCATION_DOMAIN = "atlas.supervisor-v4.credential-revocation.v1"

CapabilityReceiptVerifier = Callable[[CapabilityVerificationReceipt], None]


def _parse_time(value: str, *, code: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise LiveCanaryContractViolation(code) from exc
    if parsed.tzinfo is None:
        raise LiveCanaryContractViolation(code)
    return parsed.astimezone(timezone.utc)


def _format_time(value: datetime) -> str:
    if value.tzinfo is None:
        raise LiveCanaryContractViolation("credential_broker_clock_naive")
    return value.astimezone(timezone.utc).isoformat()


def _validate_digest(value: str, *, code: str) -> None:
    if not _DIGEST_PATTERN.fullmatch(value) or value == "0" * 64:
        raise LiveCanaryContractViolation(code)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


@dataclass(frozen=True, slots=True)
class SyntheticOneUseChannelHandle:
    """Opaque fictional handle; it can never carry credential material."""

    opaque: str

    def __post_init__(self) -> None:
        if not _HANDLE_PATTERN.fullmatch(self.opaque):
            raise LiveCanaryContractViolation("synthetic_delivery_handle_invalid")

    @classmethod
    def generate(cls) -> SyntheticOneUseChannelHandle:
        return cls(f"atlas-v4-offline-channel-v1_{secrets.token_urlsafe(32)}")

    @property
    def sha256(self) -> str:
        return _sha256(self.opaque.encode("ascii"))

    def __repr__(self) -> str:
        return f"{type(self).__name__}(opaque='<redacted>')"


@dataclass(frozen=True, slots=True)
class SyntheticDeliveryReceipt:
    """Signed evidence of one simulated delivery with no delivered material."""

    version: int
    receipt_id_sha256: str
    lease_metadata_sha256: str
    request_sha256: str
    capability_verification_sha256: str
    delivery_channel_sha256: str
    delivered_at: str
    use_count: Literal[1]
    synthetic_only: Literal[True]
    material_present: Literal[False]
    material_persisted: Literal[False]
    live_authority_granted: Literal[False]
    model_contacted: Literal[False]
    broker_key_id: str
    algorithm: Literal["ed25519"]
    signature: str

    def __post_init__(self) -> None:
        if (
            self.version != 1
            or self.use_count != 1
            or self.synthetic_only is not True
            or self.material_present is not False
            or self.material_persisted is not False
            or self.live_authority_granted is not False
            or self.model_contacted is not False
            or self.algorithm != "ed25519"
        ):
            raise LiveCanaryContractViolation("synthetic_delivery_profile_invalid")
        for value in (
            self.receipt_id_sha256,
            self.lease_metadata_sha256,
            self.request_sha256,
            self.capability_verification_sha256,
            self.delivery_channel_sha256,
        ):
            _validate_digest(value, code="synthetic_delivery_digest_invalid")
        _parse_time(self.delivered_at, code="synthetic_delivery_time_invalid")
        if not _LABEL_PATTERN.fullmatch(self.broker_key_id):
            raise LiveCanaryContractViolation("synthetic_delivery_broker_key_invalid")
        if not _SIGNATURE_PATTERN.fullmatch(self.signature):
            raise LiveCanaryContractViolation("synthetic_delivery_signature_invalid")

    @property
    def sha256(self) -> str:
        return document_sha256(self)


@dataclass(slots=True)
class _LeaseState:
    request: CredentialLeaseRequest
    verification: CapabilityVerificationReceipt
    lease: CredentialLeaseMetadata
    delivered: bool = False
    revoked: bool = False
    delivery_receipt: SyntheticDeliveryReceipt | None = None
    revocation_receipt: CredentialRevocationReceipt | None = None


class OfflineCredentialLeaseBroker:
    """In-memory, signed simulator for the inactive v4 credential boundary.

    The broker accepts only the secret-free live contract documents and an opaque
    synthetic channel handle. There is deliberately no parameter, method, file,
    socket, or callback through which credential material can be supplied.
    """

    __slots__ = (
        "_capability_receipt_verifier",
        "_capability",
        "_capability_verification_key_id",
        "_clock",
        "_issued_capability_sha256",
        "_issued_request_sha256",
        "_leases",
        "_lock",
        "_signer",
        "_verifier",
    )

    def __init__(
        self,
        *,
        signer: OfflineSigner,
        verifier: OfflineVerifier,
        capability: SignedCapabilityEnvelope,
        capability_verification_key_id: str,
        capability_receipt_verifier: CapabilityReceiptVerifier,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if (
            getattr(signer, "algorithm", None) != "ed25519"
            or getattr(verifier, "algorithm", None) != "ed25519"
            or not getattr(signer, "key_id", "")
            or signer.key_id != getattr(verifier, "key_id", None)
        ):
            raise LiveCanaryContractViolation("credential_broker_signing_identity_invalid")
        if not callable(capability_receipt_verifier):
            raise LiveCanaryContractViolation(
                "credential_broker_capability_verifier_invalid"
            )
        if not isinstance(capability, SignedCapabilityEnvelope):
            raise LiveCanaryContractViolation(
                "credential_broker_capability_document_invalid"
            )
        if not _LABEL_PATTERN.fullmatch(capability_verification_key_id):
            raise LiveCanaryContractViolation(
                "credential_broker_capability_verification_key_invalid"
            )
        if clock is not None and not callable(clock):
            raise LiveCanaryContractViolation("credential_broker_clock_invalid")
        self._signer = signer
        self._verifier = verifier
        self._capability = capability
        self._capability_verification_key_id = capability_verification_key_id
        self._capability_receipt_verifier = capability_receipt_verifier
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = threading.RLock()
        self._leases: dict[str, _LeaseState] = {}
        self._issued_request_sha256: set[str] = set()
        self._issued_capability_sha256: set[str] = set()

    @property
    def broker_key_id(self) -> str:
        return self._verifier.key_id

    def _now(self) -> datetime:
        try:
            value = self._clock()
        except Exception as exc:
            raise LiveCanaryContractViolation("credential_broker_clock_unavailable") from exc
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise LiveCanaryContractViolation("credential_broker_clock_invalid")
        return value.astimezone(timezone.utc)

    def _validate_request_verification_bindings(
        self,
        request: CredentialLeaseRequest,
        verification: CapabilityVerificationReceipt,
    ) -> None:
        capability = self._capability
        bindings = capability.bindings
        envelope_sha256 = document_sha256(capability)
        expected = {
            "verification": (
                request.capability_verification_sha256,
                verification.sha256,
            ),
            "capability": (
                request.capability_envelope_sha256,
                verification.capability_envelope_sha256,
            ),
            "capability_document": (
                verification.capability_envelope_sha256,
                envelope_sha256,
            ),
            "capability_payload": (
                verification.capability_sha256,
                capability.capability_sha256,
            ),
            "policy_bundle": (
                request.policy_bundle_sha256,
                verification.policy_bundle_sha256,
            ),
            "policy_capability": (
                request.policy_bundle_sha256,
                bindings.policy_bundle_sha256,
            ),
            "egress": (
                request.egress_manifest_sha256,
                verification.egress_manifest_sha256,
            ),
            "egress_capability": (
                request.egress_manifest_sha256,
                bindings.data_egress_manifest_sha256,
            ),
            "task": (request.task_sha256, bindings.task_sha256),
            "job": (request.job_sha256, bindings.job_sha256),
            "provider": (request.provider, bindings.provider),
            "model": (request.model, bindings.model),
            "audience": (request.audience, bindings.audience),
            "scope": (
                request.credential_scope_sha256,
                bindings.credential_scope_sha256,
            ),
            "channel": (
                request.delivery_channel_sha256,
                bindings.credential_delivery_channel_sha256,
            ),
        }
        mismatch = next(
            (name for name, values in expected.items() if values[0] != values[1]),
            None,
        )
        if mismatch is not None:
            raise LiveCanaryContractViolation(
                f"credential_broker_{mismatch}_binding_mismatch"
            )

        verified_at = _parse_time(
            verification.verified_at,
            code="credential_broker_verification_time_invalid",
        )
        requested_at = _parse_time(
            request.requested_at,
            code="credential_broker_request_time_invalid",
        )
        request_expires = _parse_time(
            request.expires_at,
            code="credential_broker_request_expiry_invalid",
        )
        verification_expires = _parse_time(
            verification.expires_at,
            code="credential_broker_verification_expiry_invalid",
        )
        capability_issued = _parse_time(
            bindings.issued_at,
            code="credential_broker_capability_time_invalid",
        )
        capability_expires = _parse_time(
            bindings.expires_at,
            code="credential_broker_capability_expiry_invalid",
        )
        if verified_at < capability_issued or requested_at < verified_at:
            raise LiveCanaryContractViolation("credential_broker_time_order_invalid")
        if (
            verification_expires > capability_expires
            or request_expires > verification_expires
        ):
            raise LiveCanaryContractViolation(
                "credential_broker_request_exceeds_verification"
            )

    def _verify_capability_receipt(
        self,
        verification: CapabilityVerificationReceipt,
    ) -> None:
        if verification.verifier_key_id != self._capability_verification_key_id:
            raise LiveCanaryContractViolation(
                "credential_broker_capability_verification_key_mismatch"
            )
        try:
            self._capability_receipt_verifier(verification)
        except Exception as exc:
            raise LiveCanaryContractViolation(
                "credential_broker_capability_verification_invalid"
            ) from exc

    @staticmethod
    def _validate_current_window(
        request: CredentialLeaseRequest,
        verification: CapabilityVerificationReceipt,
        *,
        now: datetime,
    ) -> None:
        requested_at = _parse_time(
            request.requested_at,
            code="credential_broker_request_time_invalid",
        )
        verified_at = _parse_time(
            verification.verified_at,
            code="credential_broker_verification_time_invalid",
        )
        if now < requested_at or now < verified_at:
            raise LiveCanaryContractViolation("credential_broker_not_yet_valid")
        request_expires = _parse_time(
            request.expires_at,
            code="credential_broker_request_expiry_invalid",
        )
        verification_expires = _parse_time(
            verification.expires_at,
            code="credential_broker_verification_expiry_invalid",
        )
        if now >= request_expires or now >= verification_expires:
            raise LiveCanaryContractViolation("credential_broker_authority_expired")

    def _sign(self, *, domain: str, payload: dict[str, object]) -> str:
        try:
            signature = self._signer.sign(domain=domain, payload=payload)
            self._verifier.verify(
                domain=domain,
                payload=payload,
                signature=signature,
            )
        except Exception as exc:
            raise LiveCanaryContractViolation("credential_broker_signing_failed") from exc
        if not isinstance(signature, str) or not _SIGNATURE_PATTERN.fullmatch(signature):
            raise LiveCanaryContractViolation("credential_broker_signature_invalid")
        return signature

    def _verify_signature(
        self,
        value: object,
        *,
        domain: str,
        code: str,
    ) -> None:
        signature = getattr(value, "signature", None)
        if not isinstance(signature, str):
            raise LiveCanaryContractViolation(code)
        try:
            self._verifier.verify(
                domain=domain,
                payload=unsigned_document(value),
                signature=signature,
            )
        except Exception as exc:
            raise LiveCanaryContractViolation(code) from exc

    def issue_lease(
        self,
        request: CredentialLeaseRequest,
        verification: CapabilityVerificationReceipt,
    ) -> CredentialLeaseMetadata:
        """Issue exactly one short-lived, secret-free lease metadata document."""

        if not isinstance(request, CredentialLeaseRequest) or not isinstance(
            verification, CapabilityVerificationReceipt
        ):
            raise LiveCanaryContractViolation("credential_broker_document_type_invalid")
        self._verify_capability_receipt(verification)
        self._validate_request_verification_bindings(request, verification)
        now = self._now()
        self._validate_current_window(request, verification, now=now)
        request_sha256 = request.sha256

        with self._lock:
            if request_sha256 in self._issued_request_sha256:
                raise LiveCanaryContractViolation("credential_broker_request_replayed")
            if request.capability_envelope_sha256 in self._issued_capability_sha256:
                raise LiveCanaryContractViolation("credential_broker_capability_replayed")

            hard_expiry = min(
                _parse_time(
                    request.expires_at,
                    code="credential_broker_request_expiry_invalid",
                ),
                _parse_time(
                    verification.expires_at,
                    code="credential_broker_verification_expiry_invalid",
                ),
                now + timedelta(seconds=request.max_ttl_seconds),
                now + timedelta(seconds=300),
            )
            if hard_expiry <= now:
                raise LiveCanaryContractViolation("credential_broker_authority_expired")

            # Burn both one-use identifiers before entropy generation or signing.
            # An ambiguous local failure must never make the same request or
            # capability eligible for a second issuance attempt.
            self._issued_request_sha256.add(request_sha256)
            self._issued_capability_sha256.add(request.capability_envelope_sha256)

            entropy = secrets.token_bytes(32)
            lease_id_sha256 = _sha256(
                b"atlas-v4-offline-lease-v1\x00"
                + bytes.fromhex(request_sha256)
                + entropy
            )
            revocation_handle_sha256 = _sha256(
                b"atlas-v4-offline-revocation-v1\x00"
                + bytes.fromhex(lease_id_sha256)
                + secrets.token_bytes(32)
            )
            unsigned: dict[str, object] = {
                "version": 1,
                "lease_id_sha256": lease_id_sha256,
                "request_sha256": request_sha256,
                "capability_envelope_sha256": request.capability_envelope_sha256,
                "egress_manifest_sha256": request.egress_manifest_sha256,
                "task_sha256": request.task_sha256,
                "job_sha256": request.job_sha256,
                "provider": request.provider,
                "model": request.model,
                "audience": request.audience,
                "credential_scope_sha256": request.credential_scope_sha256,
                "delivery_channel_sha256": request.delivery_channel_sha256,
                "revocation_handle_sha256": revocation_handle_sha256,
                "issued_at": _format_time(now),
                "expires_at": _format_time(hard_expiry),
                "max_uses": 1,
                "one_use": True,
                "broker_key_id": self.broker_key_id,
                "algorithm": "ed25519",
                "credential_material_persisted": False,
                "exposed_to_prompt": False,
                "included_in_receipt": False,
                "included_in_backup": False,
            }
            signature = self._sign(domain=CREDENTIAL_LEASE_DOMAIN, payload=unsigned)
            lease = CredentialLeaseMetadata(**unsigned, signature=signature)  # type: ignore[arg-type]
            self._leases[lease_id_sha256] = _LeaseState(
                request=request,
                verification=verification,
                lease=lease,
            )
            return lease

    def _state_for_exact_lease(self, lease: CredentialLeaseMetadata) -> _LeaseState:
        state = self._leases.get(lease.lease_id_sha256)
        if state is None:
            raise LiveCanaryContractViolation("credential_lease_unknown")
        if state.lease != lease:
            raise LiveCanaryContractViolation("credential_lease_tampered")
        return state

    def verify_lease(
        self,
        request: CredentialLeaseRequest,
        lease: CredentialLeaseMetadata,
        verification: CapabilityVerificationReceipt,
    ) -> None:
        """Verify signature, exact request bindings, state, and current validity."""

        if not isinstance(request, CredentialLeaseRequest) or not isinstance(
            lease, CredentialLeaseMetadata
        ) or not isinstance(verification, CapabilityVerificationReceipt):
            raise LiveCanaryContractViolation("credential_broker_document_type_invalid")
        self._verify_capability_receipt(verification)
        self._validate_request_verification_bindings(request, verification)
        expected = {
            "request": (lease.request_sha256, request.sha256),
            "capability": (
                lease.capability_envelope_sha256,
                request.capability_envelope_sha256,
            ),
            "egress": (lease.egress_manifest_sha256, request.egress_manifest_sha256),
            "task": (lease.task_sha256, request.task_sha256),
            "job": (lease.job_sha256, request.job_sha256),
            "provider": (lease.provider, request.provider),
            "model": (lease.model, request.model),
            "audience": (lease.audience, request.audience),
            "scope": (
                lease.credential_scope_sha256,
                request.credential_scope_sha256,
            ),
            "channel": (
                lease.delivery_channel_sha256,
                request.delivery_channel_sha256,
            ),
            "broker_key": (lease.broker_key_id, self.broker_key_id),
        }
        mismatch = next(
            (name for name, values in expected.items() if values[0] != values[1]),
            None,
        )
        if mismatch is not None:
            raise LiveCanaryContractViolation(
                f"credential_lease_{mismatch}_binding_mismatch"
            )
        self._verify_signature(
            lease,
            domain=CREDENTIAL_LEASE_DOMAIN,
            code="credential_lease_signature_invalid",
        )
        now = self._now()
        self._validate_current_window(request, verification, now=now)
        lease_issued = _parse_time(
            lease.issued_at,
            code="credential_lease_issue_time_invalid",
        )
        lease_expires = _parse_time(
            lease.expires_at,
            code="credential_lease_expiry_invalid",
        )
        if now < lease_issued:
            raise LiveCanaryContractViolation("credential_lease_not_yet_valid")
        if now >= lease_expires:
            raise LiveCanaryContractViolation("credential_lease_expired")
        if (lease_expires - lease_issued).total_seconds() > 300:
            raise LiveCanaryContractViolation("credential_lease_ttl_invalid")
        with self._lock:
            state = self._state_for_exact_lease(lease)
            if state.request != request or state.verification != verification:
                raise LiveCanaryContractViolation("credential_lease_state_binding_mismatch")
            if state.revoked:
                raise LiveCanaryContractViolation("credential_lease_revoked")

    def deliver_once(
        self,
        handle: SyntheticOneUseChannelHandle,
        *,
        request: CredentialLeaseRequest,
        lease: CredentialLeaseMetadata,
        verification: CapabilityVerificationReceipt,
    ) -> SyntheticDeliveryReceipt:
        """Consume one synthetic channel handle and return evidence only."""

        if not isinstance(handle, SyntheticOneUseChannelHandle):
            raise LiveCanaryContractViolation("synthetic_delivery_handle_required")
        with self._lock:
            self.verify_lease(request, lease, verification)
            state = self._state_for_exact_lease(lease)
            if state.delivered:
                raise LiveCanaryContractViolation("credential_delivery_replayed")
            if not secrets.compare_digest(handle.sha256, lease.delivery_channel_sha256):
                raise LiveCanaryContractViolation("credential_delivery_channel_mismatch")

            now = self._now()
            state.delivered = True
            unsigned: dict[str, object] = {
                "version": 1,
                "receipt_id_sha256": _sha256(
                    b"atlas-v4-offline-delivery-receipt-v1\x00"
                    + bytes.fromhex(lease.sha256)
                    + secrets.token_bytes(32)
                ),
                "lease_metadata_sha256": lease.sha256,
                "request_sha256": request.sha256,
                "capability_verification_sha256": verification.sha256,
                "delivery_channel_sha256": handle.sha256,
                "delivered_at": _format_time(now),
                "use_count": 1,
                "synthetic_only": True,
                "material_present": False,
                "material_persisted": False,
                "live_authority_granted": False,
                "model_contacted": False,
                "broker_key_id": self.broker_key_id,
                "algorithm": "ed25519",
            }
            signature = self._sign(domain=_DELIVERY_DOMAIN, payload=unsigned)
            receipt = SyntheticDeliveryReceipt(**unsigned, signature=signature)  # type: ignore[arg-type]
            state.delivery_receipt = receipt
            return receipt

    def verify_delivery_receipt(
        self,
        lease: CredentialLeaseMetadata,
        receipt: SyntheticDeliveryReceipt,
    ) -> None:
        if not isinstance(receipt, SyntheticDeliveryReceipt):
            raise LiveCanaryContractViolation("synthetic_delivery_receipt_type_invalid")
        self._verify_signature(
            receipt,
            domain=_DELIVERY_DOMAIN,
            code="synthetic_delivery_signature_invalid",
        )
        with self._lock:
            state = self._state_for_exact_lease(lease)
            if state.delivery_receipt != receipt:
                raise LiveCanaryContractViolation("synthetic_delivery_receipt_unknown")
            if (
                receipt.lease_metadata_sha256 != lease.sha256
                or receipt.request_sha256 != state.request.sha256
                or receipt.capability_verification_sha256 != state.verification.sha256
                or receipt.delivery_channel_sha256 != lease.delivery_channel_sha256
                or receipt.broker_key_id != self.broker_key_id
            ):
                raise LiveCanaryContractViolation(
                    "synthetic_delivery_receipt_binding_mismatch"
                )

    def revoke_lease(
        self,
        lease: CredentialLeaseMetadata,
        *,
        reason_sha256: str,
    ) -> CredentialRevocationReceipt:
        """Permanently close one known lease, whether unused or already consumed."""

        if not isinstance(lease, CredentialLeaseMetadata):
            raise LiveCanaryContractViolation("credential_broker_document_type_invalid")
        _validate_digest(reason_sha256, code="credential_revocation_reason_invalid")
        with self._lock:
            state = self._state_for_exact_lease(lease)
            self._verify_signature(
                lease,
                domain=CREDENTIAL_LEASE_DOMAIN,
                code="credential_lease_signature_invalid",
            )
            if state.revoked:
                raise LiveCanaryContractViolation("credential_revocation_replayed")
            state.revoked = True
            revoked_at = self._now()
            if revoked_at < _parse_time(
                lease.issued_at,
                code="credential_lease_issue_time_invalid",
            ):
                raise LiveCanaryContractViolation("credential_broker_clock_rollback")
            unsigned: dict[str, object] = {
                "version": 1,
                "lease_metadata_sha256": lease.sha256,
                "lease_id_sha256": lease.lease_id_sha256,
                "reason_sha256": reason_sha256,
                "revoked_at": _format_time(revoked_at),
                "delivery_closed": True,
                "credential_material_persisted": False,
                "broker_key_id": self.broker_key_id,
                "algorithm": "ed25519",
            }
            signature = self._sign(domain=_REVOCATION_DOMAIN, payload=unsigned)
            receipt = CredentialRevocationReceipt(**unsigned, signature=signature)  # type: ignore[arg-type]
            state.revocation_receipt = receipt
            return receipt

    def verify_revocation(
        self,
        lease: CredentialLeaseMetadata,
        receipt: CredentialRevocationReceipt,
    ) -> None:
        if not isinstance(receipt, CredentialRevocationReceipt):
            raise LiveCanaryContractViolation("credential_revocation_receipt_type_invalid")
        self._verify_signature(
            receipt,
            domain=_REVOCATION_DOMAIN,
            code="credential_revocation_signature_invalid",
        )
        with self._lock:
            state = self._state_for_exact_lease(lease)
            if state.revocation_receipt != receipt:
                raise LiveCanaryContractViolation("credential_revocation_receipt_unknown")
            if (
                receipt.lease_metadata_sha256 != lease.sha256
                or receipt.lease_id_sha256 != lease.lease_id_sha256
                or receipt.broker_key_id != self.broker_key_id
                or receipt.delivery_closed is not True
                or receipt.credential_material_persisted is not False
            ):
                raise LiveCanaryContractViolation(
                    "credential_revocation_receipt_binding_mismatch"
                )


__all__ = [
    "CapabilityReceiptVerifier",
    "CREDENTIAL_LEASE_DOMAIN",
    "OfflineCredentialLeaseBroker",
    "SyntheticDeliveryReceipt",
    "SyntheticOneUseChannelHandle",
]
