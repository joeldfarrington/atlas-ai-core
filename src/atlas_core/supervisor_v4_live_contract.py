from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, fields
from datetime import datetime
from typing import Any, Literal, Protocol

from atlas_core.supervisor_v4_protocol import (
    CapabilityBindings,
    ImmutablePolicyBundle,
    SignedCapabilityEnvelope,
    SignedReceiptLink,
    ZERO_DIGEST,
)


_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_LABEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_SIGNATURE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{64,512}$")
_SECRET_FIELD_MARKERS = (
    "api_key",
    "access_token",
    "refresh_token",
    "password",
    "private_key",
    "secret",
    "credential_value",
)


class LiveCanaryContractViolation(ValueError):
    """A privacy-safe, fail-closed live-canary contract violation."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def document_sha256(value: object) -> str:
    """Hash one non-secret contract document using its canonical representation."""

    if hasattr(value, "__dataclass_fields__"):
        document: object = asdict(value)
    elif isinstance(value, dict):
        document = value
    else:
        raise TypeError("live-canary document must be a dataclass or mapping")
    return hashlib.sha256(_canonical_json(document).encode("utf-8")).hexdigest()


def _validate_digest(value: str, *, field_name: str, allow_zero: bool = True) -> None:
    if not _SHA256_PATTERN.fullmatch(value) or (not allow_zero and value == ZERO_DIGEST):
        raise LiveCanaryContractViolation(f"{field_name}_invalid")


def _validate_label(value: str, *, field_name: str) -> None:
    if not _LABEL_PATTERN.fullmatch(value):
        raise LiveCanaryContractViolation(f"{field_name}_invalid")


def _validate_signature(value: str, *, field_name: str) -> None:
    if not _SIGNATURE_PATTERN.fullmatch(value):
        raise LiveCanaryContractViolation(f"{field_name}_invalid")


def _parse_time(value: str, *, field_name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise LiveCanaryContractViolation(f"{field_name}_invalid") from exc
    if parsed.tzinfo is None:
        raise LiveCanaryContractViolation(f"{field_name}_invalid")
    return parsed


def _validate_window(
    issued_at: str,
    expires_at: str,
    *,
    maximum_seconds: int,
    field_name: str,
) -> tuple[datetime, datetime]:
    issued = _parse_time(issued_at, field_name=f"{field_name}_issued_at")
    expiry = _parse_time(expires_at, field_name=f"{field_name}_expires_at")
    duration = (expiry - issued).total_seconds()
    if not 0 < duration <= maximum_seconds:
        raise LiveCanaryContractViolation(f"{field_name}_ttl_invalid")
    return issued, expiry


def _assert_secret_free_schema(value: object) -> None:
    names = {item.name.lower() for item in fields(value)}
    if any(marker in name for marker in _SECRET_FIELD_MARKERS for name in names):
        raise LiveCanaryContractViolation("secret_bearing_contract_field_prohibited")


@dataclass(frozen=True, slots=True)
class DataEgressManifest:
    """Exact synthetic bytes permitted to cross the first live-canary boundary."""

    version: int
    task_sha256: str
    job_sha256: str
    source_manifest_sha256: str
    payload_sha256: str
    output_schema_sha256: str
    purpose_sha256: str
    provider: str
    model: str
    classification: Literal["synthetic_fictional_bounded"]
    record_count: int
    payload_bytes: int
    max_payload_bytes: int
    contains_private_data: Literal[False]
    contains_credentials: Literal[False]

    def __post_init__(self) -> None:
        _assert_secret_free_schema(self)
        if self.version != 1:
            raise LiveCanaryContractViolation("egress_version_invalid")
        for field_name in (
            "task_sha256",
            "job_sha256",
            "source_manifest_sha256",
            "payload_sha256",
            "output_schema_sha256",
            "purpose_sha256",
        ):
            _validate_digest(getattr(self, field_name), field_name=field_name, allow_zero=False)
        _validate_label(self.provider, field_name="egress_provider")
        _validate_label(self.model, field_name="egress_model")
        if (
            self.classification != "synthetic_fictional_bounded"
            or self.contains_private_data is not False
            or self.contains_credentials is not False
            or not isinstance(self.record_count, int)
            or isinstance(self.record_count, bool)
            or not 1 <= self.record_count <= 32
            or not isinstance(self.payload_bytes, int)
            or isinstance(self.payload_bytes, bool)
            or not isinstance(self.max_payload_bytes, int)
            or isinstance(self.max_payload_bytes, bool)
            or not 1 <= self.payload_bytes <= self.max_payload_bytes <= 16_384
        ):
            raise LiveCanaryContractViolation("egress_bounds_invalid")

    @property
    def sha256(self) -> str:
        return document_sha256(self)


@dataclass(frozen=True, slots=True)
class CapabilityVerificationReceipt:
    """Signed public evidence that an external verifier accepted one capability."""

    version: int
    decision: Literal["verified"]
    capability_envelope_sha256: str
    capability_sha256: str
    policy_bundle_sha256: str
    egress_manifest_sha256: str
    revocation_snapshot_sha256: str
    verified_at: str
    expires_at: str
    verifier_key_id: str
    algorithm: Literal["ed25519"]
    signature: str

    def __post_init__(self) -> None:
        _assert_secret_free_schema(self)
        if self.version != 1 or self.decision != "verified" or self.algorithm != "ed25519":
            raise LiveCanaryContractViolation("capability_verification_profile_invalid")
        for field_name in (
            "capability_envelope_sha256",
            "capability_sha256",
            "policy_bundle_sha256",
            "egress_manifest_sha256",
            "revocation_snapshot_sha256",
        ):
            _validate_digest(getattr(self, field_name), field_name=field_name, allow_zero=False)
        _validate_window(
            self.verified_at,
            self.expires_at,
            maximum_seconds=300,
            field_name="capability_verification",
        )
        _validate_label(self.verifier_key_id, field_name="capability_verifier_key_id")
        _validate_signature(self.signature, field_name="capability_verification_signature")

    @property
    def sha256(self) -> str:
        return document_sha256(self)


@dataclass(frozen=True, slots=True)
class CredentialLeaseRequest:
    """Non-secret request for broker delivery over one pre-bound channel."""

    version: int
    capability_envelope_sha256: str
    capability_verification_sha256: str
    policy_bundle_sha256: str
    egress_manifest_sha256: str
    task_sha256: str
    job_sha256: str
    provider: str
    model: str
    audience: str
    credential_scope_sha256: str
    delivery_channel_sha256: str
    requested_at: str
    expires_at: str
    max_ttl_seconds: int
    max_uses: int
    credential_class: Literal["model_transport"]
    delivery_mode: Literal["broker_delivered_one_use_channel"]

    def __post_init__(self) -> None:
        _assert_secret_free_schema(self)
        if self.version != 1:
            raise LiveCanaryContractViolation("credential_request_version_invalid")
        for field_name in (
            "capability_envelope_sha256",
            "capability_verification_sha256",
            "policy_bundle_sha256",
            "egress_manifest_sha256",
            "task_sha256",
            "job_sha256",
            "credential_scope_sha256",
            "delivery_channel_sha256",
        ):
            _validate_digest(getattr(self, field_name), field_name=field_name, allow_zero=False)
        for field_name in ("provider", "model", "audience"):
            _validate_label(getattr(self, field_name), field_name=f"credential_{field_name}")
        if (
            not isinstance(self.max_ttl_seconds, int)
            or isinstance(self.max_ttl_seconds, bool)
            or not 1 <= self.max_ttl_seconds <= 300
            or self.max_uses != 1
            or self.credential_class != "model_transport"
            or self.delivery_mode != "broker_delivered_one_use_channel"
        ):
            raise LiveCanaryContractViolation("credential_request_bounds_invalid")
        _validate_window(
            self.requested_at,
            self.expires_at,
            maximum_seconds=self.max_ttl_seconds,
            field_name="credential_request",
        )

    @property
    def sha256(self) -> str:
        return document_sha256(self)


@dataclass(frozen=True, slots=True)
class CredentialLeaseMetadata:
    """Signed lease metadata; the credential itself travels outside this object."""

    version: int
    lease_id_sha256: str
    request_sha256: str
    capability_envelope_sha256: str
    egress_manifest_sha256: str
    task_sha256: str
    job_sha256: str
    provider: str
    model: str
    audience: str
    credential_scope_sha256: str
    delivery_channel_sha256: str
    revocation_handle_sha256: str
    issued_at: str
    expires_at: str
    max_uses: int
    one_use: Literal[True]
    broker_key_id: str
    algorithm: Literal["ed25519"]
    signature: str
    credential_material_persisted: Literal[False]
    exposed_to_prompt: Literal[False]
    included_in_receipt: Literal[False]
    included_in_backup: Literal[False]

    def __post_init__(self) -> None:
        _assert_secret_free_schema(self)
        if self.version != 1 or self.max_uses != 1 or self.one_use is not True:
            raise LiveCanaryContractViolation("credential_lease_profile_invalid")
        if self.algorithm != "ed25519" or any(
            value is not False
            for value in (
                self.credential_material_persisted,
                self.exposed_to_prompt,
                self.included_in_receipt,
                self.included_in_backup,
            )
        ):
            raise LiveCanaryContractViolation("credential_lease_secrecy_invalid")
        for field_name in (
            "lease_id_sha256",
            "request_sha256",
            "capability_envelope_sha256",
            "egress_manifest_sha256",
            "task_sha256",
            "job_sha256",
            "credential_scope_sha256",
            "delivery_channel_sha256",
            "revocation_handle_sha256",
        ):
            _validate_digest(getattr(self, field_name), field_name=field_name, allow_zero=False)
        for field_name in ("provider", "model", "audience", "broker_key_id"):
            _validate_label(getattr(self, field_name), field_name=f"lease_{field_name}")
        _validate_window(
            self.issued_at,
            self.expires_at,
            maximum_seconds=300,
            field_name="credential_lease",
        )
        _validate_signature(self.signature, field_name="credential_lease_signature")

    @property
    def sha256(self) -> str:
        return document_sha256(self)


@dataclass(frozen=True, slots=True)
class CredentialRevocationReceipt:
    """Signed cleanup evidence that contains no credential or delivery handle."""

    version: int
    lease_metadata_sha256: str
    lease_id_sha256: str
    reason_sha256: str
    revoked_at: str
    delivery_closed: Literal[True]
    credential_material_persisted: Literal[False]
    broker_key_id: str
    algorithm: Literal["ed25519"]
    signature: str

    def __post_init__(self) -> None:
        _assert_secret_free_schema(self)
        if (
            self.version != 1
            or self.delivery_closed is not True
            or self.credential_material_persisted is not False
            or self.algorithm != "ed25519"
        ):
            raise LiveCanaryContractViolation("credential_revocation_profile_invalid")
        for field_name in ("lease_metadata_sha256", "lease_id_sha256", "reason_sha256"):
            _validate_digest(getattr(self, field_name), field_name=field_name, allow_zero=False)
        _parse_time(self.revoked_at, field_name="credential_revoked_at")
        _validate_label(self.broker_key_id, field_name="revocation_broker_key_id")
        _validate_signature(self.signature, field_name="credential_revocation_signature")


@dataclass(frozen=True, slots=True)
class ReceiptChainAnchor:
    """Externally retained signed count/head pair for rollback detection."""

    version: int
    chain_id_sha256: str
    receipt_count: int
    head_sha256: str
    generation: int
    observed_at: str
    valid_until: str
    anchor_key_id: str
    algorithm: Literal["ed25519"]
    signature: str

    def __post_init__(self) -> None:
        _assert_secret_free_schema(self)
        if self.version != 1 or self.algorithm != "ed25519":
            raise LiveCanaryContractViolation("receipt_anchor_profile_invalid")
        for field_name in ("chain_id_sha256", "head_sha256"):
            _validate_digest(getattr(self, field_name), field_name=field_name)
        if (
            not isinstance(self.receipt_count, int)
            or isinstance(self.receipt_count, bool)
            or self.receipt_count < 0
            or not isinstance(self.generation, int)
            or isinstance(self.generation, bool)
            or self.generation < self.receipt_count
            or (self.receipt_count == 0 and self.head_sha256 != ZERO_DIGEST)
            or (self.receipt_count > 0 and self.head_sha256 == ZERO_DIGEST)
        ):
            raise LiveCanaryContractViolation("receipt_anchor_state_invalid")
        _validate_window(
            self.observed_at,
            self.valid_until,
            maximum_seconds=30,
            field_name="receipt_anchor",
        )
        _validate_label(self.anchor_key_id, field_name="receipt_anchor_key_id")
        _validate_signature(self.signature, field_name="receipt_anchor_signature")

    @property
    def sha256(self) -> str:
        return document_sha256(self)


@dataclass(frozen=True, slots=True)
class ReceiptVerificationReceipt:
    """Signed evidence that one receipt link passed the public-key verifier."""

    version: int
    receipt_link_sha256: str
    capability_verification_sha256: str
    lease_metadata_sha256: str
    predecessor_anchor_sha256: str
    verified_at: str
    verifier_key_id: str
    algorithm: Literal["ed25519"]
    signature: str

    def __post_init__(self) -> None:
        _assert_secret_free_schema(self)
        if self.version != 1 or self.algorithm != "ed25519":
            raise LiveCanaryContractViolation("receipt_verification_profile_invalid")
        for field_name in (
            "receipt_link_sha256",
            "capability_verification_sha256",
            "lease_metadata_sha256",
            "predecessor_anchor_sha256",
        ):
            _validate_digest(getattr(self, field_name), field_name=field_name, allow_zero=False)
        _parse_time(self.verified_at, field_name="receipt_verified_at")
        _validate_label(self.verifier_key_id, field_name="receipt_verifier_key_id")
        _validate_signature(self.signature, field_name="receipt_verification_signature")


@dataclass(frozen=True, slots=True)
class OwnerKillSwitchState:
    """Short-lived signed owner state; stale or unreachable means stop."""

    version: int
    channel_sha256: str
    capability_envelope_sha256: str
    generation: int
    state: Literal["armed", "paused"]
    observed_at: str
    valid_until: str
    oracle_key_id: str
    algorithm: Literal["ed25519"]
    fail_closed_on_unreachable: Literal[True]
    signature: str

    def __post_init__(self) -> None:
        _assert_secret_free_schema(self)
        if (
            self.version != 1
            or self.algorithm != "ed25519"
            or self.fail_closed_on_unreachable is not True
            or not isinstance(self.generation, int)
            or isinstance(self.generation, bool)
            or self.generation < 0
        ):
            raise LiveCanaryContractViolation("kill_switch_profile_invalid")
        for field_name in ("channel_sha256", "capability_envelope_sha256"):
            _validate_digest(getattr(self, field_name), field_name=field_name, allow_zero=False)
        _validate_window(
            self.observed_at,
            self.valid_until,
            maximum_seconds=10,
            field_name="kill_switch",
        )
        _validate_label(self.oracle_key_id, field_name="kill_switch_oracle_key_id")
        _validate_signature(self.signature, field_name="kill_switch_signature")


class CapabilityVerifier(Protocol):
    def verify_capability(
        self,
        envelope: SignedCapabilityEnvelope,
        *,
        policy_bundle: ImmutablePolicyBundle,
        expected_egress_manifest_sha256: str,
        observed_at: str,
    ) -> CapabilityVerificationReceipt: ...


class CredentialBroker(Protocol):
    def issue_lease(
        self,
        request: CredentialLeaseRequest,
        verification: CapabilityVerificationReceipt,
    ) -> CredentialLeaseMetadata: ...

    def revoke_lease(
        self,
        lease: CredentialLeaseMetadata,
        *,
        reason_sha256: str,
    ) -> CredentialRevocationReceipt: ...


class CredentialLeaseVerifier(Protocol):
    def verify_lease(
        self,
        request: CredentialLeaseRequest,
        lease: CredentialLeaseMetadata,
        verification: CapabilityVerificationReceipt,
    ) -> None: ...

    def verify_revocation(
        self,
        lease: CredentialLeaseMetadata,
        receipt: CredentialRevocationReceipt,
    ) -> None: ...


class ReceiptVerifier(Protocol):
    def verify_receipt(
        self,
        link: SignedReceiptLink,
        *,
        capability_verification: CapabilityVerificationReceipt,
        lease: CredentialLeaseMetadata,
        predecessor: ReceiptChainAnchor,
        expected_receipt_sha256: str,
    ) -> ReceiptVerificationReceipt: ...


class ReceiptAnchorBroker(Protocol):
    def read_anchor(self, chain_id_sha256: str) -> ReceiptChainAnchor: ...

    def compare_and_append(
        self,
        expected: ReceiptChainAnchor,
        link: SignedReceiptLink,
        verification: ReceiptVerificationReceipt,
    ) -> ReceiptChainAnchor: ...


class OwnerKillSwitchOracle(Protocol):
    def read_state(
        self,
        channel_sha256: str,
        capability_envelope_sha256: str,
    ) -> OwnerKillSwitchState: ...


@dataclass(frozen=True, slots=True)
class LiveCanaryTrustBundle:
    policy_bundle: ImmutablePolicyBundle
    capability: SignedCapabilityEnvelope
    capability_verification: CapabilityVerificationReceipt
    egress: DataEgressManifest
    credential_request: CredentialLeaseRequest
    credential_lease: CredentialLeaseMetadata
    predecessor_anchor: ReceiptChainAnchor
    kill_switch: OwnerKillSwitchState


def validate_live_canary_trust_bundle(
    bundle: LiveCanaryTrustBundle,
    *,
    observed_at: str,
    minimum_kill_switch_generation: int,
) -> dict[str, bool]:
    """Validate cross-bindings only; this function grants no live authority."""

    now = _parse_time(observed_at, field_name="trust_bundle_observed_at")
    policy_bundle = bundle.policy_bundle
    capability = bundle.capability
    bindings: CapabilityBindings = capability.bindings
    envelope_sha256 = document_sha256(capability)
    verification = bundle.capability_verification
    egress = bundle.egress
    request = bundle.credential_request
    lease = bundle.credential_lease
    anchor = bundle.predecessor_anchor
    kill_switch = bundle.kill_switch

    if (
        not isinstance(minimum_kill_switch_generation, int)
        or isinstance(minimum_kill_switch_generation, bool)
        or minimum_kill_switch_generation < 0
    ):
        raise LiveCanaryContractViolation("kill_switch_generation_floor_invalid")
    if kill_switch.generation < minimum_kill_switch_generation:
        raise LiveCanaryContractViolation("kill_switch_generation_rollback")

    for start_value, code in (
        (bindings.issued_at, "capability_not_yet_valid"),
        (verification.verified_at, "capability_verification_not_yet_valid"),
        (request.requested_at, "credential_request_not_yet_valid"),
        (lease.issued_at, "credential_lease_not_yet_valid"),
        (anchor.observed_at, "receipt_anchor_not_yet_valid"),
        (kill_switch.observed_at, "kill_switch_not_yet_valid"),
    ):
        if now < _parse_time(start_value, field_name=code):
            raise LiveCanaryContractViolation(code)

    for expiry_value, code in (
        (verification.expires_at, "capability_verification_expired"),
        (request.expires_at, "credential_request_expired"),
        (lease.expires_at, "credential_lease_expired"),
        (anchor.valid_until, "receipt_anchor_stale"),
        (kill_switch.valid_until, "kill_switch_stale"),
    ):
        if now >= _parse_time(expiry_value, field_name=code):
            raise LiveCanaryContractViolation(code)
    if kill_switch.state != "armed":
        raise LiveCanaryContractViolation("kill_switch_paused")

    expected = {
        "capability_verification_envelope": (
            verification.capability_envelope_sha256,
            envelope_sha256,
        ),
        "capability_verification_payload": (
            verification.capability_sha256,
            capability.capability_sha256,
        ),
        "capability_verification_policy": (
            verification.policy_bundle_sha256,
            bindings.policy_bundle_sha256,
        ),
        "capability_policy_bundle": (
            bindings.policy_bundle_sha256,
            policy_bundle.sha256,
        ),
        "capability_egress": (bindings.data_egress_manifest_sha256, egress.sha256),
        "verification_egress": (verification.egress_manifest_sha256, egress.sha256),
        "egress_task": (egress.task_sha256, bindings.task_sha256),
        "egress_job": (egress.job_sha256, bindings.job_sha256),
        "egress_model": (egress.model, bindings.model),
        "egress_class": (egress.classification, bindings.data_egress_class),
        "request_envelope": (request.capability_envelope_sha256, envelope_sha256),
        "request_verification": (
            request.capability_verification_sha256,
            verification.sha256,
        ),
        "request_policy": (request.policy_bundle_sha256, bindings.policy_bundle_sha256),
        "request_egress": (request.egress_manifest_sha256, egress.sha256),
        "request_task": (request.task_sha256, bindings.task_sha256),
        "request_job": (request.job_sha256, bindings.job_sha256),
        "request_model": (request.model, bindings.model),
        "request_provider": (request.provider, egress.provider),
        "request_audience": (request.audience, bindings.audience),
        "request_scope": (request.credential_scope_sha256, bindings.credential_scope_sha256),
        "request_channel": (
            request.delivery_channel_sha256,
            bindings.credential_delivery_channel_sha256,
        ),
        "lease_request": (lease.request_sha256, request.sha256),
        "lease_envelope": (lease.capability_envelope_sha256, envelope_sha256),
        "lease_egress": (lease.egress_manifest_sha256, egress.sha256),
        "lease_task": (lease.task_sha256, bindings.task_sha256),
        "lease_job": (lease.job_sha256, bindings.job_sha256),
        "lease_provider": (lease.provider, request.provider),
        "lease_model": (lease.model, request.model),
        "lease_audience": (lease.audience, request.audience),
        "lease_scope": (lease.credential_scope_sha256, request.credential_scope_sha256),
        "lease_channel": (lease.delivery_channel_sha256, request.delivery_channel_sha256),
        "anchor_chain": (anchor.chain_id_sha256, bindings.receipt_chain_id_sha256),
        "anchor_head": (anchor.head_sha256, bindings.receipt_predecessor_sha256),
        "anchor_count": (anchor.receipt_count, bindings.receipt_predecessor_count),
        "kill_switch_channel": (kill_switch.channel_sha256, bindings.kill_switch_channel_sha256),
        "kill_switch_envelope": (kill_switch.capability_envelope_sha256, envelope_sha256),
    }
    mismatch = next((name for name, values in expected.items() if values[0] != values[1]), None)
    if mismatch is not None:
        raise LiveCanaryContractViolation(f"trust_binding_{mismatch}_mismatch")

    capability_issued = _parse_time(bindings.issued_at, field_name="capability_issued_at")
    capability_expiry = _parse_time(bindings.expires_at, field_name="capability_expires_at")
    verification_time = _parse_time(verification.verified_at, field_name="verification_time")
    request_time = _parse_time(request.requested_at, field_name="request_time")
    lease_time = _parse_time(lease.issued_at, field_name="lease_time")
    if not (
        capability_issued
        <= verification_time
        <= request_time
        <= lease_time
        < capability_expiry
    ):
        raise LiveCanaryContractViolation("trust_time_order_invalid")
    if any(
        _parse_time(value, field_name="bounded_expiry") > capability_expiry
        for value in (verification.expires_at, request.expires_at, lease.expires_at)
    ):
        raise LiveCanaryContractViolation("trust_expiry_exceeds_capability")

    return {
        "structural_bindings_valid": True,
        "synthetic_egress_only": True,
        "credential_material_present": False,
        "credential_material_persisted": False,
        "external_anchor_bound": True,
        "kill_switch_armed": True,
        "cryptographic_implementation_present": False,
        "production_broker_configured": False,
        "live_authority_granted": False,
        "model_contacted": False,
    }
