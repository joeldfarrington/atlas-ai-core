from __future__ import annotations

"""Durable, secret-free trust state for the transitional Option 1 broker."""

import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import stat
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Literal


ZERO_DIGEST = "0" * 64
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_EVENT_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_MAX_ANCHOR_BYTES = 8_192
_MAX_EVENT_BYTES = 4_096


class SameUserStateViolation(ValueError):
    """Privacy-safe, fail-closed durable-state failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class _StateIntegrityError(RuntimeError):
    pass


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise SameUserStateViolation("state_document_invalid") from exc


def _require_digest(value: str, *, code: str, allow_zero: bool = False) -> str:
    if not isinstance(value, str) or not _DIGEST_PATTERN.fullmatch(value):
        raise SameUserStateViolation(code)
    if not allow_zero and value == ZERO_DIGEST:
        raise SameUserStateViolation(code)
    return value


def _parse_time(value: str, *, code: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError) as exc:
        raise SameUserStateViolation(code) from exc
    if parsed.tzinfo is None:
        raise SameUserStateViolation(code)
    return parsed.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise SameUserStateViolation("state_clock_invalid")
    return value.astimezone(timezone.utc).isoformat()


def _private_regular(path: Path, *, code: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise SameUserStateViolation(code) from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise SameUserStateViolation(code)
    return metadata


def _prepare_private_root(path: Path) -> Path:
    candidate = path.expanduser()
    if not candidate.is_absolute():
        raise SameUserStateViolation("state_root_not_absolute")
    if candidate.exists():
        if candidate.is_symlink() or not candidate.is_dir():
            raise SameUserStateViolation("state_root_invalid")
    else:
        candidate.mkdir(mode=0o700, parents=True)
    resolved = candidate.resolve(strict=True)
    metadata = resolved.stat()
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise SameUserStateViolation("state_root_not_private")
    return resolved


class DurableSameUserTrustState:
    """Single-writer SQLite state with an external HMAC-bound head.

    This store intentionally contains only digests, timestamps, booleans, and
    monotonic counters.  The injected integrity key is never written.  A whole
    directory rollback by a compromised same-UID process remains an accepted
    Option 1 limitation; inconsistent, partial, or corrupted state quarantines
    the broker instead of falling back.
    """

    def __init__(
        self,
        *,
        root: Path,
        registry_sha256: str,
        integrity_key: bytes,
        clock: Callable[[], datetime] | None = None,
        max_events: int = 512,
    ) -> None:
        _require_digest(registry_sha256, code="state_registry_digest_invalid")
        if not isinstance(integrity_key, bytes) or len(integrity_key) < 32:
            raise SameUserStateViolation("state_integrity_key_invalid")
        if not isinstance(max_events, int) or isinstance(max_events, bool) or not 16 <= max_events <= 100_000:
            raise SameUserStateViolation("state_event_limit_invalid")
        if clock is not None and not callable(clock):
            raise SameUserStateViolation("state_clock_invalid")

        self.root = _prepare_private_root(root)
        self.database_path = self.root / "trust-state.sqlite3"
        self.anchor_path = self.root / "trust-state.anchor.json"
        self.quarantine_path = self.root / "QUARANTINED"
        self.lock_path = self.root / "broker.lock"
        self.registry_sha256 = registry_sha256
        self._key = bytes(integrity_key)
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._max_events = max_events
        self._thread_lock = threading.RLock()
        self._closed = False
        self._quarantined = self.quarantine_path.exists()

        database_existed = self.database_path.exists()
        anchor_existed = self.anchor_path.exists()
        lock_existed = self.lock_path.exists()
        if self._quarantined:
            raise SameUserStateViolation("state_quarantined")
        if database_existed != anchor_existed or (
            lock_existed and not database_existed and not anchor_existed
        ):
            self._enter_quarantine("state_artifact_set_incomplete")
            raise SameUserStateViolation("state_integrity_failed")

        self._lock_descriptor = os.open(
            self.lock_path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.fchmod(self._lock_descriptor, 0o600)
        try:
            fcntl.flock(self._lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(self._lock_descriptor)
            raise SameUserStateViolation("state_writer_already_active") from exc

        created = not database_existed
        if created:
            descriptor = os.open(
                self.database_path,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                0o600,
            )
            os.close(descriptor)
        _private_regular(self.database_path, code="state_database_invalid")
        self._connection = sqlite3.connect(
            self.database_path,
            timeout=0.25,
            isolation_level=None,
            check_same_thread=False,
        )
        self._connection.row_factory = sqlite3.Row
        try:
            self._configure_connection()
            self._create_schema()
            if created:
                self._initialize_state()
            else:
                self._verify_or_quarantine()
        except Exception:
            self.close()
            raise

    def __enter__(self) -> DurableSameUserTrustState:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(root={self.root!s}, "
            f"quarantined={self._quarantined})"
        )

    def _configure_connection(self) -> None:
        for pragma in (
            "PRAGMA journal_mode=DELETE",
            "PRAGMA synchronous=FULL",
            "PRAGMA foreign_keys=ON",
            "PRAGMA trusted_schema=OFF",
            "PRAGMA secure_delete=ON",
        ):
            self._connection.execute(pragma)

    def _create_schema(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS state_meta (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                version INTEGER NOT NULL CHECK(version = 1),
                registry_sha256 TEXT NOT NULL,
                event_count INTEGER NOT NULL CHECK(event_count >= 0),
                event_head TEXT NOT NULL,
                generation INTEGER NOT NULL CHECK(generation >= 0)
            );
            CREATE TABLE IF NOT EXISTS control_state (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                state TEXT NOT NULL CHECK(state IN ('armed', 'paused')),
                generation INTEGER NOT NULL CHECK(generation >= 0),
                updated_at TEXT NOT NULL,
                row_hmac TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS leases (
                request_sha256 TEXT PRIMARY KEY,
                capability_sha256 TEXT NOT NULL UNIQUE,
                lease_sha256 TEXT UNIQUE,
                mapping_sha256 TEXT NOT NULL,
                channel_sha256 TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                delivery_claimed INTEGER NOT NULL CHECK(delivery_claimed IN (0, 1)),
                delivery_claim_sha256 TEXT,
                delivered INTEGER NOT NULL CHECK(delivered IN (0, 1)),
                revoked INTEGER NOT NULL CHECK(revoked IN (0, 1)),
                delivery_receipt_sha256 TEXT,
                revocation_receipt_sha256 TEXT,
                generation INTEGER NOT NULL CHECK(generation >= 0),
                row_hmac TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS receipt_chain (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                receipt_count INTEGER NOT NULL CHECK(receipt_count >= 0),
                head_sha256 TEXT NOT NULL,
                generation INTEGER NOT NULL CHECK(generation >= 0),
                row_hmac TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
                sequence INTEGER PRIMARY KEY,
                event_type TEXT NOT NULL,
                subject_sha256 TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                predecessor_hmac TEXT NOT NULL,
                event_hmac TEXT NOT NULL UNIQUE,
                generation INTEGER NOT NULL UNIQUE
            );
            """
        )

    def _now(self) -> datetime:
        try:
            value = self._clock()
        except Exception as exc:
            raise SameUserStateViolation("state_clock_unavailable") from exc
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise SameUserStateViolation("state_clock_invalid")
        return value.astimezone(timezone.utc)

    def _mac(self, domain: str, value: object) -> str:
        return hmac.new(
            self._key,
            domain.encode("ascii") + b"\x00" + _canonical_json(value),
            hashlib.sha256,
        ).hexdigest()

    def _control_hmac(self, state: str, generation: int, updated_at: str) -> str:
        return self._mac(
            "atlas.option1.control.v1",
            {"state": state, "generation": generation, "updated_at": updated_at},
        )

    def _lease_hmac(self, values: dict[str, object]) -> str:
        return self._mac("atlas.option1.lease-state.v1", values)

    def _receipt_hmac(self, count: int, head: str, generation: int) -> str:
        return self._mac(
            "atlas.option1.receipt-state.v1",
            {"receipt_count": count, "head_sha256": head, "generation": generation},
        )

    def _event_hmac(self, value: dict[str, object]) -> str:
        return self._mac("atlas.option1.event.v1", value)

    def _initialize_state(self) -> None:
        now = _iso(self._now())
        connection = self._connection
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute(
                "INSERT INTO state_meta VALUES (1, 1, ?, 0, ?, 0)",
                (self.registry_sha256, ZERO_DIGEST),
            )
            connection.execute(
                "INSERT INTO control_state VALUES (1, 'paused', 0, ?, ?)",
                (now, self._control_hmac("paused", 0, now)),
            )
            connection.execute(
                "INSERT INTO receipt_chain VALUES (1, 0, ?, 0, ?)",
                (ZERO_DIGEST, self._receipt_hmac(0, ZERO_DIGEST, 0)),
            )
            self._append_event(
                connection,
                event_type="state_initialized",
                subject_sha256=self.registry_sha256,
                payload={"synthetic_only": True, "state": "paused"},
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        self._write_anchor()
        self._verify_or_quarantine()

    def _append_event(
        self,
        connection: sqlite3.Connection,
        *,
        event_type: str,
        subject_sha256: str,
        payload: dict[str, object],
    ) -> int:
        if not _EVENT_PATTERN.fullmatch(event_type):
            raise SameUserStateViolation("state_event_type_invalid")
        _require_digest(subject_sha256, code="state_event_subject_invalid", allow_zero=True)
        payload_bytes = _canonical_json(payload)
        if len(payload_bytes) > _MAX_EVENT_BYTES:
            raise SameUserStateViolation("state_event_payload_too_large")
        meta = connection.execute("SELECT * FROM state_meta WHERE singleton=1").fetchone()
        if meta is None or meta["event_count"] >= self._max_events:
            raise SameUserStateViolation("state_event_retention_exhausted")
        sequence = int(meta["event_count"]) + 1
        generation = int(meta["generation"]) + 1
        predecessor = str(meta["event_head"])
        unsigned = {
            "sequence": sequence,
            "event_type": event_type,
            "subject_sha256": subject_sha256,
            "payload": payload,
            "predecessor_hmac": predecessor,
            "generation": generation,
        }
        event_hmac = self._event_hmac(unsigned)
        connection.execute(
            "INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                sequence,
                event_type,
                subject_sha256,
                payload_bytes.decode("utf-8"),
                predecessor,
                event_hmac,
                generation,
            ),
        )
        connection.execute(
            "UPDATE state_meta SET event_count=?, event_head=?, generation=? WHERE singleton=1",
            (sequence, event_hmac, generation),
        )
        return generation

    def _anchor_payload(self) -> dict[str, object]:
        meta = self._connection.execute(
            "SELECT * FROM state_meta WHERE singleton=1"
        ).fetchone()
        if meta is None:
            raise _StateIntegrityError("state_meta_missing")
        return {
            "version": 1,
            "registry_sha256": str(meta["registry_sha256"]),
            "event_count": int(meta["event_count"]),
            "event_head": str(meta["event_head"]),
            "generation": int(meta["generation"]),
        }

    def _atomic_private_write(self, path: Path, content: bytes) -> None:
        temporary = self.root / f".{path.name}.{secrets.token_hex(12)}.tmp"
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        try:
            view = memoryview(content)
            while view:
                view = view[os.write(descriptor, view) :]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
        directory_descriptor = os.open(
            self.root,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)

    def _write_anchor(self) -> None:
        payload = self._anchor_payload()
        document = dict(payload)
        document["hmac_sha256"] = self._mac("atlas.option1.anchor.v1", payload)
        self._atomic_private_write(self.anchor_path, _canonical_json(document))

    def _read_anchor(self) -> dict[str, object]:
        metadata = _private_regular(self.anchor_path, code="state_anchor_invalid")
        if metadata.st_size > _MAX_ANCHOR_BYTES:
            raise _StateIntegrityError("state_anchor_too_large")
        try:
            raw = self.anchor_path.read_bytes()
            value = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _StateIntegrityError("state_anchor_invalid") from exc
        if not isinstance(value, dict) or _canonical_json(value) != raw:
            raise _StateIntegrityError("state_anchor_noncanonical")
        expected_keys = {
            "version",
            "registry_sha256",
            "event_count",
            "event_head",
            "generation",
            "hmac_sha256",
        }
        if set(value) != expected_keys:
            raise _StateIntegrityError("state_anchor_schema_invalid")
        supplied = value.pop("hmac_sha256")
        expected = self._mac("atlas.option1.anchor.v1", value)
        if not isinstance(supplied, str) or not hmac.compare_digest(supplied, expected):
            raise _StateIntegrityError("state_anchor_hmac_invalid")
        return value

    def _verify_integrity(self) -> None:
        quick = self._connection.execute("PRAGMA quick_check").fetchone()
        if quick is None or quick[0] != "ok":
            raise _StateIntegrityError("state_database_corrupt")
        meta = self._connection.execute("SELECT * FROM state_meta").fetchall()
        if len(meta) != 1:
            raise _StateIntegrityError("state_meta_invalid")
        metadata = meta[0]
        if (
            metadata["version"] != 1
            or metadata["registry_sha256"] != self.registry_sha256
        ):
            raise _StateIntegrityError("state_registry_binding_mismatch")

        predecessor = ZERO_DIGEST
        expected_sequence = 1
        expected_generation = 1
        event_records: list[dict[str, object]] = []
        events = self._connection.execute("SELECT * FROM events ORDER BY sequence").fetchall()
        for event in events:
            try:
                payload = json.loads(str(event["payload_json"]))
            except json.JSONDecodeError as exc:
                raise _StateIntegrityError("state_event_payload_invalid") from exc
            if not isinstance(payload, dict) or _canonical_json(payload).decode("utf-8") != event["payload_json"]:
                raise _StateIntegrityError("state_event_payload_noncanonical")
            unsigned = {
                "sequence": int(event["sequence"]),
                "event_type": str(event["event_type"]),
                "subject_sha256": str(event["subject_sha256"]),
                "payload": payload,
                "predecessor_hmac": str(event["predecessor_hmac"]),
                "generation": int(event["generation"]),
            }
            if (
                unsigned["sequence"] != expected_sequence
                or unsigned["generation"] != expected_generation
                or unsigned["predecessor_hmac"] != predecessor
                or self._event_hmac(unsigned) != event["event_hmac"]
            ):
                raise _StateIntegrityError("state_event_chain_invalid")
            predecessor = str(event["event_hmac"])
            event_records.append(unsigned)
            expected_sequence += 1
            expected_generation += 1
        if (
            int(metadata["event_count"]) != len(events)
            or str(metadata["event_head"]) != predecessor
            or int(metadata["generation"]) != len(events)
        ):
            raise _StateIntegrityError("state_event_head_mismatch")

        controls = self._connection.execute("SELECT * FROM control_state").fetchall()
        if len(controls) != 1:
            raise _StateIntegrityError("state_control_invalid")
        control = controls[0]
        if self._control_hmac(
            str(control["state"]),
            int(control["generation"]),
            str(control["updated_at"]),
        ) != control["row_hmac"]:
            raise _StateIntegrityError("state_control_hmac_invalid")

        receipts = self._connection.execute("SELECT * FROM receipt_chain").fetchall()
        if len(receipts) != 1:
            raise _StateIntegrityError("state_receipt_invalid")
        receipt = receipts[0]
        if self._receipt_hmac(
            int(receipt["receipt_count"]),
            str(receipt["head_sha256"]),
            int(receipt["generation"]),
        ) != receipt["row_hmac"]:
            raise _StateIntegrityError("state_receipt_hmac_invalid")

        lease_rows = self._connection.execute("SELECT * FROM leases").fetchall()
        for lease in lease_rows:
            values = self._lease_values(lease)
            if self._lease_hmac(values) != lease["row_hmac"]:
                raise _StateIntegrityError("state_lease_hmac_invalid")

        # Row HMACs prevent invention, but a captured older valid row could be
        # replayed independently of the still-current event chain. Reconstruct
        # every mutable projection from the authenticated events and require
        # the current rows to match the latest event for their subject.
        if not event_records:
            raise _StateIntegrityError("state_event_initialization_missing")
        initialized = event_records[0]
        if (
            initialized["event_type"] != "state_initialized"
            or initialized["subject_sha256"] != self.registry_sha256
            or initialized["payload"] != {"state": "paused", "synthetic_only": True}
        ):
            raise _StateIntegrityError("state_event_initialization_invalid")

        projected_control_state = "paused"
        projected_control_generation = 0
        projected_leases: dict[str, dict[str, object]] = {}
        lease_to_request: dict[str, str] = {}
        projected_receipt_count = 0
        projected_receipt_head = ZERO_DIGEST
        projected_receipt_generation = 0

        def event_digest(value: object, code: str, *, allow_zero: bool = False) -> str:
            if not isinstance(value, str) or not _DIGEST_PATTERN.fullmatch(value):
                raise _StateIntegrityError(code)
            if not allow_zero and value == ZERO_DIGEST:
                raise _StateIntegrityError(code)
            return value

        for event in event_records[1:]:
            event_type = str(event["event_type"])
            subject = event_digest(
                event["subject_sha256"], "state_event_subject_invalid", allow_zero=True
            )
            payload = event["payload"]
            if not isinstance(payload, dict):
                raise _StateIntegrityError("state_event_payload_invalid")
            generation = int(event["generation"])

            if event_type == "pause_changed":
                if set(payload) != {"state", "control_generation"}:
                    raise _StateIntegrityError("state_pause_event_invalid")
                next_state = payload["state"]
                next_generation = payload["control_generation"]
                if (
                    next_state not in {"armed", "paused"}
                    or type(next_generation) is not int
                    or next_generation != projected_control_generation + 1
                ):
                    raise _StateIntegrityError("state_pause_event_invalid")
                projected_control_state = str(next_state)
                projected_control_generation = int(next_generation)
                continue

            if event_type == "lease_request_burned":
                if (
                    set(payload) != {"mapping_sha256", "synthetic_only"}
                    or payload["synthetic_only"] is not True
                    or subject in projected_leases
                ):
                    raise _StateIntegrityError("state_lease_request_event_invalid")
                projected_leases[subject] = {
                    "mapping_sha256": event_digest(
                        payload["mapping_sha256"], "state_mapping_digest_invalid"
                    ),
                    "lease_sha256": None,
                    "delivery_claim_sha256": None,
                    "delivery_receipt_sha256": None,
                    "revocation_receipt_sha256": None,
                    "generation": generation,
                }
                continue

            if event_type == "lease_issued":
                if set(payload) != {"request_sha256", "synthetic_only"} or payload[
                    "synthetic_only"
                ] is not True:
                    raise _StateIntegrityError("state_lease_issue_event_invalid")
                request_sha256 = event_digest(
                    payload["request_sha256"], "state_request_digest_invalid"
                )
                projected = projected_leases.get(request_sha256)
                lease_sha256 = event_digest(subject, "state_lease_digest_invalid")
                if (
                    projected is None
                    or projected["lease_sha256"] is not None
                    or lease_sha256 in lease_to_request
                ):
                    raise _StateIntegrityError("state_lease_issue_event_invalid")
                projected["lease_sha256"] = lease_sha256
                projected["generation"] = generation
                lease_to_request[lease_sha256] = request_sha256
                continue

            if event_type in {
                "lease_delivery_claimed",
                "lease_consumed",
                "lease_revoked",
            }:
                lease_sha256 = event_digest(subject, "state_lease_digest_invalid")
                request_sha256 = lease_to_request.get(lease_sha256)
                projected = (
                    projected_leases.get(request_sha256)
                    if request_sha256 is not None
                    else None
                )
                if projected is None:
                    raise _StateIntegrityError("state_lease_lifecycle_event_invalid")

                if event_type == "lease_delivery_claimed":
                    if (
                        set(payload) != {"claim_sha256", "synthetic_only"}
                        or payload["synthetic_only"] is not True
                        or projected["delivery_claim_sha256"] is not None
                    ):
                        raise _StateIntegrityError("state_delivery_claim_event_invalid")
                    projected["delivery_claim_sha256"] = event_digest(
                        payload["claim_sha256"], "state_delivery_claim_digest_invalid"
                    )
                elif event_type == "lease_consumed":
                    if (
                        set(payload)
                        != {
                            "claim_sha256",
                            "receipt_sha256",
                            "receipt_count",
                            "synthetic_only",
                        }
                        or payload["synthetic_only"] is not True
                        or projected["delivery_claim_sha256"] is None
                        or projected["delivery_receipt_sha256"] is not None
                        or projected["revocation_receipt_sha256"] is not None
                        or payload["claim_sha256"]
                        != projected["delivery_claim_sha256"]
                        or type(payload["receipt_count"]) is not int
                        or payload["receipt_count"] != projected_receipt_count + 1
                    ):
                        raise _StateIntegrityError("state_delivery_event_invalid")
                    receipt_sha256 = event_digest(
                        payload["receipt_sha256"], "state_receipt_digest_invalid"
                    )
                    projected_receipt_count += 1
                    projected_receipt_head = hashlib.sha256(
                        b"atlas-option1-receipt-head-v1\x00"
                        + bytes.fromhex(projected_receipt_head)
                        + bytes.fromhex(receipt_sha256)
                        + projected_receipt_count.to_bytes(8, "big")
                    ).hexdigest()
                    projected_receipt_generation = generation
                    projected["delivery_receipt_sha256"] = receipt_sha256
                else:
                    if (
                        set(payload) != {"receipt_sha256"}
                        or projected["revocation_receipt_sha256"] is not None
                    ):
                        raise _StateIntegrityError("state_revocation_event_invalid")
                    projected["revocation_receipt_sha256"] = event_digest(
                        payload["receipt_sha256"], "state_revocation_digest_invalid"
                    )
                projected["generation"] = generation
                continue

            raise _StateIntegrityError("state_event_type_unknown")

        if (
            str(control["state"]) != projected_control_state
            or int(control["generation"]) != projected_control_generation
        ):
            raise _StateIntegrityError("state_control_projection_mismatch")
        if (
            int(receipt["receipt_count"]) != projected_receipt_count
            or str(receipt["head_sha256"]) != projected_receipt_head
            or int(receipt["generation"]) != projected_receipt_generation
        ):
            raise _StateIntegrityError("state_receipt_projection_mismatch")
        if len(lease_rows) != len(projected_leases):
            raise _StateIntegrityError("state_lease_projection_mismatch")
        for lease in lease_rows:
            request_sha256 = str(lease["request_sha256"])
            projected = projected_leases.get(request_sha256)
            if projected is None:
                raise _StateIntegrityError("state_lease_projection_mismatch")
            expected_claim = projected["delivery_claim_sha256"]
            expected_delivery = projected["delivery_receipt_sha256"]
            expected_revocation = projected["revocation_receipt_sha256"]
            if (
                lease["mapping_sha256"] != projected["mapping_sha256"]
                or lease["lease_sha256"] != projected["lease_sha256"]
                or bool(lease["delivery_claimed"])
                is not (expected_claim is not None)
                or lease["delivery_claim_sha256"] != expected_claim
                or bool(lease["delivered"])
                is not (expected_delivery is not None)
                or lease["delivery_receipt_sha256"] != expected_delivery
                or bool(lease["revoked"])
                is not (expected_revocation is not None)
                or lease["revocation_receipt_sha256"] != expected_revocation
                or int(lease["generation"]) != int(projected["generation"])
            ):
                raise _StateIntegrityError("state_lease_projection_mismatch")

        anchor = self._read_anchor()
        expected_anchor = self._anchor_payload()
        if anchor != expected_anchor:
            raise _StateIntegrityError("state_anchor_head_mismatch")

    @staticmethod
    def _lease_values(row: sqlite3.Row | dict[str, object]) -> dict[str, object]:
        return {
            "request_sha256": row["request_sha256"],
            "capability_sha256": row["capability_sha256"],
            "lease_sha256": row["lease_sha256"],
            "mapping_sha256": row["mapping_sha256"],
            "channel_sha256": row["channel_sha256"],
            "expires_at": row["expires_at"],
            "delivery_claimed": int(row["delivery_claimed"]),
            "delivery_claim_sha256": row["delivery_claim_sha256"],
            "delivered": int(row["delivered"]),
            "revoked": int(row["revoked"]),
            "delivery_receipt_sha256": row["delivery_receipt_sha256"],
            "revocation_receipt_sha256": row["revocation_receipt_sha256"],
            "generation": int(row["generation"]),
        }

    def _enter_quarantine(self, code: str) -> None:
        self._quarantined = True
        payload = {
            "version": 1,
            "failure_code_sha256": hashlib.sha256(code.encode("utf-8")).hexdigest(),
            "observed_at": _iso(self._now()),
        }
        document = dict(payload)
        document["hmac_sha256"] = self._mac("atlas.option1.quarantine.v1", payload)
        try:
            if not self.quarantine_path.exists():
                self._atomic_private_write(self.quarantine_path, _canonical_json(document))
        except OSError:
            pass

    def _verify_or_quarantine(self) -> None:
        if self._quarantined:
            raise SameUserStateViolation("state_quarantined")
        try:
            self._verify_integrity()
        except (_StateIntegrityError, SameUserStateViolation, OSError, sqlite3.Error) as exc:
            self._enter_quarantine(type(exc).__name__)
            raise SameUserStateViolation("state_integrity_failed") from exc

    def _assert_available(self) -> None:
        if self._closed:
            raise SameUserStateViolation("state_closed")
        if self._quarantined or self.quarantine_path.exists():
            self._quarantined = True
            raise SameUserStateViolation("state_quarantined")

    def _transaction(self, operation: Callable[[sqlite3.Connection], object]) -> object:
        with self._thread_lock:
            self._assert_available()
            self._verify_or_quarantine()
            connection = self._connection
            connection.execute("BEGIN IMMEDIATE")
            try:
                result = operation(connection)
                connection.commit()
            except SameUserStateViolation:
                connection.rollback()
                raise
            except Exception as exc:
                connection.rollback()
                self._enter_quarantine(type(exc).__name__)
                raise SameUserStateViolation("state_commit_uncertain") from exc
            try:
                self._write_anchor()
                self._verify_integrity()
            except Exception as exc:
                self._enter_quarantine(type(exc).__name__)
                raise SameUserStateViolation("state_commit_uncertain") from exc
            return result

    def _require_armed(self, connection: sqlite3.Connection) -> sqlite3.Row:
        control = connection.execute("SELECT * FROM control_state WHERE singleton=1").fetchone()
        if control is None or control["state"] != "armed":
            raise SameUserStateViolation("state_paused")
        return control

    def set_pause(self, state: Literal["armed", "paused"]) -> dict[str, object]:
        if state not in {"armed", "paused"}:
            raise SameUserStateViolation("state_pause_value_invalid")
        now = _iso(self._now())

        def operation(connection: sqlite3.Connection) -> dict[str, object]:
            prior = connection.execute("SELECT * FROM control_state WHERE singleton=1").fetchone()
            if prior is None:
                raise SameUserStateViolation("state_control_missing")
            control_generation = int(prior["generation"]) + 1
            event_generation = self._append_event(
                connection,
                event_type="pause_changed",
                subject_sha256=self.registry_sha256,
                payload={"state": state, "control_generation": control_generation},
            )
            row_hmac = self._control_hmac(state, control_generation, now)
            connection.execute(
                "UPDATE control_state SET state=?, generation=?, updated_at=?, row_hmac=? WHERE singleton=1",
                (state, control_generation, now, row_hmac),
            )
            return {
                "state": state,
                "control_generation": control_generation,
                "state_generation": event_generation,
            }

        return self._transaction(operation)  # type: ignore[return-value]

    def begin_issue(
        self,
        *,
        request_sha256: str,
        capability_sha256: str,
        mapping_sha256: str,
        channel_sha256: str,
        expires_at: str,
    ) -> int:
        for value, code in (
            (request_sha256, "state_request_digest_invalid"),
            (capability_sha256, "state_capability_digest_invalid"),
            (mapping_sha256, "state_mapping_digest_invalid"),
            (channel_sha256, "state_channel_digest_invalid"),
        ):
            _require_digest(value, code=code)
        _parse_time(expires_at, code="state_lease_expiry_invalid")

        def operation(connection: sqlite3.Connection) -> int:
            self._require_armed(connection)
            if connection.execute(
                "SELECT 1 FROM leases WHERE request_sha256=? OR capability_sha256=?",
                (request_sha256, capability_sha256),
            ).fetchone():
                raise SameUserStateViolation("state_lease_request_replayed")
            generation = self._append_event(
                connection,
                event_type="lease_request_burned",
                subject_sha256=request_sha256,
                payload={"mapping_sha256": mapping_sha256, "synthetic_only": True},
            )
            values: dict[str, object] = {
                "request_sha256": request_sha256,
                "capability_sha256": capability_sha256,
                "lease_sha256": None,
                "mapping_sha256": mapping_sha256,
                "channel_sha256": channel_sha256,
                "expires_at": expires_at,
                "delivery_claimed": 0,
                "delivery_claim_sha256": None,
                "delivered": 0,
                "revoked": 0,
                "delivery_receipt_sha256": None,
                "revocation_receipt_sha256": None,
                "generation": generation,
            }
            connection.execute(
                """
                INSERT INTO leases (
                    request_sha256, capability_sha256, lease_sha256,
                    mapping_sha256, channel_sha256, expires_at,
                    delivery_claimed, delivery_claim_sha256, delivered, revoked,
                    delivery_receipt_sha256, revocation_receipt_sha256,
                    generation, row_hmac
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (*values.values(), self._lease_hmac(values)),
            )
            return generation

        return self._transaction(operation)  # type: ignore[return-value]

    def finish_issue(self, *, request_sha256: str, lease_sha256: str) -> int:
        _require_digest(request_sha256, code="state_request_digest_invalid")
        _require_digest(lease_sha256, code="state_lease_digest_invalid")

        def operation(connection: sqlite3.Connection) -> int:
            self._require_armed(connection)
            row = connection.execute(
                "SELECT * FROM leases WHERE request_sha256=?", (request_sha256,)
            ).fetchone()
            if row is None or row["lease_sha256"] is not None:
                raise SameUserStateViolation("state_lease_issue_not_pending")
            if connection.execute(
                "SELECT 1 FROM leases WHERE lease_sha256=?", (lease_sha256,)
            ).fetchone():
                raise SameUserStateViolation("state_lease_digest_replayed")
            generation = self._append_event(
                connection,
                event_type="lease_issued",
                subject_sha256=lease_sha256,
                payload={"request_sha256": request_sha256, "synthetic_only": True},
            )
            values = self._lease_values(row)
            values["lease_sha256"] = lease_sha256
            values["generation"] = generation
            connection.execute(
                "UPDATE leases SET lease_sha256=?, generation=?, row_hmac=? WHERE request_sha256=?",
                (lease_sha256, generation, self._lease_hmac(values), request_sha256),
            )
            return generation

        return self._transaction(operation)  # type: ignore[return-value]

    def assert_lease(
        self,
        *,
        request_sha256: str,
        lease_sha256: str,
        mapping_sha256: str,
        channel_sha256: str,
        require_armed: bool = True,
    ) -> dict[str, object]:
        for value, code in (
            (request_sha256, "state_request_digest_invalid"),
            (lease_sha256, "state_lease_digest_invalid"),
            (mapping_sha256, "state_mapping_digest_invalid"),
            (channel_sha256, "state_channel_digest_invalid"),
        ):
            _require_digest(value, code=code)
        with self._thread_lock:
            self._assert_available()
            self._verify_or_quarantine()
            if require_armed:
                self._require_armed(self._connection)
            row = self._connection.execute(
                "SELECT * FROM leases WHERE request_sha256=?", (request_sha256,)
            ).fetchone()
            if row is None or row["lease_sha256"] != lease_sha256:
                raise SameUserStateViolation("state_lease_unknown")
            if row["mapping_sha256"] != mapping_sha256 or row["channel_sha256"] != channel_sha256:
                raise SameUserStateViolation("state_lease_binding_mismatch")
            if row["revoked"]:
                raise SameUserStateViolation("state_lease_revoked")
            if self._now() >= _parse_time(row["expires_at"], code="state_lease_expiry_invalid"):
                raise SameUserStateViolation("state_lease_expired")
            return {
                "delivery_claimed": bool(row["delivery_claimed"]),
                "delivered": bool(row["delivered"]),
                "revoked": bool(row["revoked"]),
                "generation": int(row["generation"]),
            }

    def claim_lease_delivery(
        self,
        *,
        request_sha256: str,
        lease_sha256: str,
        mapping_sha256: str,
        channel_sha256: str,
        claim_sha256: str,
    ) -> int:
        """Irreversibly burn delivery authority before material is exposed.

        A crash, pause, timeout, or connector failure after this transaction
        leaves the lease closed.  Completion evidence may be missing, but the
        same authority can never be used for a second delivery attempt.
        """

        for value, code in (
            (request_sha256, "state_request_digest_invalid"),
            (lease_sha256, "state_lease_digest_invalid"),
            (mapping_sha256, "state_mapping_digest_invalid"),
            (channel_sha256, "state_channel_digest_invalid"),
            (claim_sha256, "state_delivery_claim_digest_invalid"),
        ):
            _require_digest(value, code=code)

        def operation(connection: sqlite3.Connection) -> int:
            self._require_armed(connection)
            row = connection.execute(
                "SELECT * FROM leases WHERE request_sha256=?", (request_sha256,)
            ).fetchone()
            if row is None or row["lease_sha256"] != lease_sha256:
                raise SameUserStateViolation("state_lease_unknown")
            if row["mapping_sha256"] != mapping_sha256 or row["channel_sha256"] != channel_sha256:
                raise SameUserStateViolation("state_lease_binding_mismatch")
            if row["revoked"]:
                raise SameUserStateViolation("state_lease_revoked")
            if row["delivery_claimed"] or row["delivered"]:
                raise SameUserStateViolation("state_lease_delivery_replayed")
            if self._now() >= _parse_time(row["expires_at"], code="state_lease_expiry_invalid"):
                raise SameUserStateViolation("state_lease_expired")
            generation = self._append_event(
                connection,
                event_type="lease_delivery_claimed",
                subject_sha256=lease_sha256,
                payload={"claim_sha256": claim_sha256, "synthetic_only": True},
            )
            values = self._lease_values(row)
            values["delivery_claimed"] = 1
            values["delivery_claim_sha256"] = claim_sha256
            values["generation"] = generation
            connection.execute(
                """
                UPDATE leases
                SET delivery_claimed=1, delivery_claim_sha256=?, generation=?, row_hmac=?
                WHERE request_sha256=?
                """,
                (claim_sha256, generation, self._lease_hmac(values), request_sha256),
            )
            return generation

        return self._transaction(operation)  # type: ignore[return-value]

    def receipt_snapshot(self) -> dict[str, object]:
        with self._thread_lock:
            self._assert_available()
            self._verify_or_quarantine()
            row = self._connection.execute("SELECT * FROM receipt_chain WHERE singleton=1").fetchone()
            if row is None:
                raise SameUserStateViolation("state_receipt_missing")
            return {
                "receipt_count": int(row["receipt_count"]),
                "head_sha256": str(row["head_sha256"]),
                "generation": int(row["generation"]),
            }

    def consume_lease(
        self,
        *,
        request_sha256: str,
        lease_sha256: str,
        mapping_sha256: str,
        channel_sha256: str,
        receipt_sha256: str,
        claim_sha256: str,
        expected_receipt_head: str,
    ) -> dict[str, object]:
        for value, code, allow_zero in (
            (request_sha256, "state_request_digest_invalid", False),
            (lease_sha256, "state_lease_digest_invalid", False),
            (mapping_sha256, "state_mapping_digest_invalid", False),
            (channel_sha256, "state_channel_digest_invalid", False),
            (receipt_sha256, "state_receipt_digest_invalid", False),
            (claim_sha256, "state_delivery_claim_digest_invalid", False),
            (expected_receipt_head, "state_receipt_head_invalid", True),
        ):
            _require_digest(value, code=code, allow_zero=allow_zero)

        def operation(connection: sqlite3.Connection) -> dict[str, object]:
            self._require_armed(connection)
            row = connection.execute(
                "SELECT * FROM leases WHERE request_sha256=?", (request_sha256,)
            ).fetchone()
            if row is None or row["lease_sha256"] != lease_sha256:
                raise SameUserStateViolation("state_lease_unknown")
            if row["mapping_sha256"] != mapping_sha256 or row["channel_sha256"] != channel_sha256:
                raise SameUserStateViolation("state_lease_binding_mismatch")
            if row["revoked"]:
                raise SameUserStateViolation("state_lease_revoked")
            if not row["delivery_claimed"] or row["delivery_claim_sha256"] != claim_sha256:
                raise SameUserStateViolation("state_delivery_claim_unknown")
            if row["delivered"]:
                raise SameUserStateViolation("state_lease_delivery_replayed")
            if self._now() >= _parse_time(row["expires_at"], code="state_lease_expiry_invalid"):
                raise SameUserStateViolation("state_lease_expired")

            receipt = connection.execute("SELECT * FROM receipt_chain WHERE singleton=1").fetchone()
            if receipt is None or receipt["head_sha256"] != expected_receipt_head:
                raise SameUserStateViolation("state_receipt_compare_failed")
            count = int(receipt["receipt_count"]) + 1
            new_head = hashlib.sha256(
                b"atlas-option1-receipt-head-v1\x00"
                + bytes.fromhex(expected_receipt_head)
                + bytes.fromhex(receipt_sha256)
                + count.to_bytes(8, "big")
            ).hexdigest()
            generation = self._append_event(
                connection,
                event_type="lease_consumed",
                subject_sha256=lease_sha256,
                payload={
                    "claim_sha256": claim_sha256,
                    "receipt_sha256": receipt_sha256,
                    "receipt_count": count,
                    "synthetic_only": True,
                },
            )
            values = self._lease_values(row)
            values["delivered"] = 1
            values["delivery_receipt_sha256"] = receipt_sha256
            values["generation"] = generation
            connection.execute(
                "UPDATE leases SET delivered=1, delivery_receipt_sha256=?, generation=?, row_hmac=? WHERE request_sha256=?",
                (receipt_sha256, generation, self._lease_hmac(values), request_sha256),
            )
            connection.execute(
                "UPDATE receipt_chain SET receipt_count=?, head_sha256=?, generation=?, row_hmac=? WHERE singleton=1",
                (count, new_head, generation, self._receipt_hmac(count, new_head, generation)),
            )
            return {
                "receipt_count": count,
                "head_sha256": new_head,
                "state_generation": generation,
            }

        return self._transaction(operation)  # type: ignore[return-value]

    def revoke_lease(
        self,
        *,
        request_sha256: str,
        lease_sha256: str,
        revocation_receipt_sha256: str,
    ) -> int:
        for value, code in (
            (request_sha256, "state_request_digest_invalid"),
            (lease_sha256, "state_lease_digest_invalid"),
            (revocation_receipt_sha256, "state_revocation_digest_invalid"),
        ):
            _require_digest(value, code=code)

        def operation(connection: sqlite3.Connection) -> int:
            row = connection.execute(
                "SELECT * FROM leases WHERE request_sha256=?", (request_sha256,)
            ).fetchone()
            if row is None or row["lease_sha256"] != lease_sha256:
                raise SameUserStateViolation("state_lease_unknown")
            if row["revoked"]:
                raise SameUserStateViolation("state_lease_revocation_replayed")
            generation = self._append_event(
                connection,
                event_type="lease_revoked",
                subject_sha256=lease_sha256,
                payload={"receipt_sha256": revocation_receipt_sha256},
            )
            values = self._lease_values(row)
            values["revoked"] = 1
            values["revocation_receipt_sha256"] = revocation_receipt_sha256
            values["generation"] = generation
            connection.execute(
                "UPDATE leases SET revoked=1, revocation_receipt_sha256=?, generation=?, row_hmac=? WHERE request_sha256=?",
                (
                    revocation_receipt_sha256,
                    generation,
                    self._lease_hmac(values),
                    request_sha256,
                ),
            )
            return generation

        return self._transaction(operation)  # type: ignore[return-value]

    def snapshot(self) -> dict[str, object]:
        with self._thread_lock:
            self._assert_available()
            self._verify_or_quarantine()
            meta = self._connection.execute("SELECT * FROM state_meta WHERE singleton=1").fetchone()
            control = self._connection.execute("SELECT * FROM control_state WHERE singleton=1").fetchone()
            receipt = self._connection.execute("SELECT * FROM receipt_chain WHERE singleton=1").fetchone()
            counts = self._connection.execute(
                "SELECT COUNT(*), COALESCE(SUM(delivery_claimed),0), "
                "COALESCE(SUM(delivered),0), COALESCE(SUM(revoked),0) FROM leases"
            ).fetchone()
            if meta is None or control is None or receipt is None or counts is None:
                raise SameUserStateViolation("state_snapshot_unavailable")
            return {
                "version": 1,
                "event_count": int(meta["event_count"]),
                "state_generation": int(meta["generation"]),
                "pause_state": str(control["state"]),
                "pause_generation": int(control["generation"]),
                "lease_count": int(counts[0]),
                "delivery_claimed_count": int(counts[1]),
                "delivered_count": int(counts[2]),
                "revoked_count": int(counts[3]),
                "receipt_count": int(receipt["receipt_count"]),
                "quarantined": False,
                "credential_material_present": False,
            }

    def close(self) -> None:
        if getattr(self, "_closed", True):
            return
        self._closed = True
        try:
            self._connection.close()
        finally:
            try:
                fcntl.flock(self._lock_descriptor, fcntl.LOCK_UN)
            finally:
                os.close(self._lock_descriptor)


__all__ = [
    "DurableSameUserTrustState",
    "SameUserStateViolation",
    "ZERO_DIGEST",
]
