from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import asdict, is_dataclass
from typing import Any, Literal, Mapping, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


_DOMAIN_PATTERN = re.compile(r"^atlas\.supervisor-v4\.[a-z0-9._-]{1,96}\.v[1-9][0-9]*$")
_SIGNATURE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{86}$")
_PUBLIC_KEY_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")


class OfflineCryptoViolation(ValueError):
    """Privacy-safe failure from the inactive Supervisor v4 signing layer."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class OfflineSigner(Protocol):
    key_id: str
    algorithm: Literal["ed25519"]

    def sign(self, *, domain: str, payload: Mapping[str, Any]) -> str: ...


class OfflineVerifier(Protocol):
    key_id: str
    algorithm: Literal["ed25519"]

    def verify(
        self,
        *,
        domain: str,
        payload: Mapping[str, Any],
        signature: str,
    ) -> None: ...


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64url_decode(value: str, *, code: str) -> bytes:
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise OfflineCryptoViolation(code) from exc
    # Reject alternate unpadded encodings whose unused trailing bits decode to
    # the same bytes. Otherwise a signature could acquire a different document
    # hash while Ed25519 still sees the same 64-byte value.
    if _b64url_encode(decoded) != value:
        raise OfflineCryptoViolation(code)
    return decoded


def unsigned_document(value: object) -> dict[str, Any]:
    """Return a detached signing projection with any signature field removed."""

    if is_dataclass(value) and not isinstance(value, type):
        document = asdict(value)
    elif isinstance(value, Mapping):
        document = dict(value)
    else:
        raise TypeError("signed document must be a dataclass or mapping")
    document.pop("signature", None)
    return document


def canonical_signed_bytes(*, domain: str, payload: Mapping[str, Any]) -> bytes:
    """Create one domain-separated canonical message for an Ed25519 signature."""

    if not _DOMAIN_PATTERN.fullmatch(domain):
        raise OfflineCryptoViolation("signature_domain_invalid")
    if not isinstance(payload, Mapping):
        raise OfflineCryptoViolation("signature_payload_invalid")
    try:
        encoded = json.dumps(
            {"domain": domain, "payload": dict(payload)},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise OfflineCryptoViolation("signature_payload_invalid") from exc
    return encoded


class Ed25519OfflineVerifier:
    """Public-key-only verifier for inactive, no-network broker qualification."""

    algorithm: Literal["ed25519"] = "ed25519"

    def __init__(self, key: Ed25519PublicKey) -> None:
        self._key = key
        raw = key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.key_id = f"v4-offline-{hashlib.sha256(raw).hexdigest()[:24]}"

    @classmethod
    def from_public_key_b64(cls, value: str) -> Ed25519OfflineVerifier:
        if not _PUBLIC_KEY_PATTERN.fullmatch(value):
            raise OfflineCryptoViolation("public_key_encoding_invalid")
        raw = _b64url_decode(value, code="public_key_encoding_invalid")
        if len(raw) != 32:
            raise OfflineCryptoViolation("public_key_length_invalid")
        try:
            return cls(Ed25519PublicKey.from_public_bytes(raw))
        except ValueError as exc:
            raise OfflineCryptoViolation("public_key_invalid") from exc

    @property
    def public_key_b64(self) -> str:
        raw = self._key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return _b64url_encode(raw)

    def verify(
        self,
        *,
        domain: str,
        payload: Mapping[str, Any],
        signature: str,
    ) -> None:
        if not _SIGNATURE_PATTERN.fullmatch(signature):
            raise OfflineCryptoViolation("signature_encoding_invalid")
        raw_signature = _b64url_decode(signature, code="signature_encoding_invalid")
        if len(raw_signature) != 64:
            raise OfflineCryptoViolation("signature_length_invalid")
        message = canonical_signed_bytes(domain=domain, payload=payload)
        try:
            self._key.verify(raw_signature, message)
        except InvalidSignature as exc:
            raise OfflineCryptoViolation("signature_invalid") from exc


class Ed25519OfflineSigner:
    """Ephemeral signer with no public private-key serialization surface."""

    algorithm: Literal["ed25519"] = "ed25519"

    def __init__(self, key: Ed25519PrivateKey) -> None:
        self._key = key
        self._verifier = Ed25519OfflineVerifier(key.public_key())
        self.key_id = self._verifier.key_id

    @classmethod
    def generate(cls) -> Ed25519OfflineSigner:
        return cls(Ed25519PrivateKey.generate())

    @property
    def verifier(self) -> Ed25519OfflineVerifier:
        return self._verifier

    def sign(self, *, domain: str, payload: Mapping[str, Any]) -> str:
        message = canonical_signed_bytes(domain=domain, payload=payload)
        signature = _b64url_encode(self._key.sign(message))
        if not _SIGNATURE_PATTERN.fullmatch(signature):
            raise OfflineCryptoViolation("signature_encoding_invalid")
        return signature

    def __repr__(self) -> str:
        return f"{type(self).__name__}(key_id={self.key_id!r}, secret_material='<redacted>')"


__all__ = [
    "Ed25519OfflineSigner",
    "Ed25519OfflineVerifier",
    "OfflineCryptoViolation",
    "OfflineSigner",
    "OfflineVerifier",
    "canonical_signed_bytes",
    "unsigned_document",
]
