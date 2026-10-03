from __future__ import annotations

import hashlib
import json
import re
import secrets
import shutil
import sqlite3
import threading
import uuid
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping

_UNSET = object()
_SUPERVISOR_V4_ZERO_DIGEST = "0" * 64
_SUPERVISOR_V4_MODEL_CONTACT_RANK = {
    "not_dispatched": 0,
    "contact_possible": 1,
    "contacted": 2,
}
_SUPERVISOR_V4_OFFLINE_TRANSITIONS = {
    "inactive": frozenset({"offline_qualifying", "cancelled"}),
    "offline_qualifying": frozenset(
        {"offline_qualified", "offline_failed", "stopped", "interrupted"}
    ),
    "offline_qualified": frozenset(),
    "offline_failed": frozenset(),
    "stopped": frozenset(),
    "interrupted": frozenset(),
    "cancelled": frozenset(),
}
_SUPERVISOR_V4_TIMESTAMP_KEYS = frozenset(
    {
        # Only observation-time fields are removed from deterministic evidence.
        # Security-semantic times such as issued_at and expires_at must remain
        # bound into the content digest.
        "timestamp",
        "timestamps",
        "monotonic_ns",
        "created_at",
        "updated_at",
        "recorded_at",
        "occurred_at",
        "observed_at",
        "observed_timestamp",
        "event_timestamp",
        "started_at",
        "completed_at",
    }
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def arguments_digest(arguments: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(arguments).encode("utf-8")).hexdigest()


def _supervisor_v4_without_timestamps(value: Any) -> Any:
    """Return JSON content with nondeterministic timestamp fields removed."""

    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for raw_key, item in value.items():
            key = str(raw_key)
            lowered = key.lower()
            if lowered in _SUPERVISOR_V4_TIMESTAMP_KEYS:
                continue
            normalized[key] = _supervisor_v4_without_timestamps(item)
        return normalized
    if isinstance(value, list):
        return [_supervisor_v4_without_timestamps(item) for item in value]
    if isinstance(value, tuple):
        return [_supervisor_v4_without_timestamps(item) for item in value]
    return value


def _supervisor_v4_content(value: dict[str, Any] | None) -> tuple[str, str]:
    normalized = _supervisor_v4_without_timestamps(value or {})
    encoded = canonical_json(normalized)
    return encoded, hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _supervisor_v4_nonce_digest(nonce: str) -> str:
    encoded = nonce.encode("utf-8")
    if not (32 <= len(encoded) <= 512) or any(character.isspace() for character in nonce):
        raise ValueError("Supervisor v4 capability nonce must be 32-512 non-space bytes")
    return hashlib.sha256(encoded).hexdigest()


def _supervisor_v4_digest(value: str, *, field: str, allow_zero: bool = False) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError(f"Supervisor v4 {field} must be a lowercase SHA-256 digest")
    if not allow_zero and value == _SUPERVISOR_V4_ZERO_DIGEST:
        raise ValueError(f"Supervisor v4 {field} must not be the zero digest")
    return value


def _supervisor_v4_public_metadata(value: dict[str, Any]) -> tuple[str, str]:
    """Canonicalize a deliberately narrow, public-only verifier description."""

    if not isinstance(value, dict):
        raise ValueError("Supervisor v4 receipt public metadata must be an object")
    allowed = {
        "public_key_fingerprint_sha256",
        "verification_profile",
        "certificate_fingerprint_sha256",
    }
    if set(value) - allowed or not {
        "public_key_fingerprint_sha256",
        "verification_profile",
    }.issubset(value):
        raise ValueError("Supervisor v4 receipt public metadata fields are invalid")
    public_key_fingerprint = value["public_key_fingerprint_sha256"]
    _supervisor_v4_digest(
        public_key_fingerprint, field="public-key fingerprint"
    )
    verification_profile = value["verification_profile"]
    if not isinstance(verification_profile, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", verification_profile
    ):
        raise ValueError("Supervisor v4 receipt verification profile is invalid")
    certificate_fingerprint = value.get("certificate_fingerprint_sha256")
    if certificate_fingerprint is not None:
        _supervisor_v4_digest(
            certificate_fingerprint, field="certificate fingerprint"
        )
    encoded = canonical_json(value)
    return encoded, hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _supervisor_v4_parse_timestamp(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("Supervisor v4 timestamp must be ISO-8601")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Supervisor v4 timestamp must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ValueError("Supervisor v4 timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


class Database:
    """SQLite persistence with migrations, FTS memory search, runs, and approvals."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_lock = threading.Lock()
        self._initialized = False
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 30000")
        except BaseException:
            connection.close()
            raise
        return connection

    @contextmanager
    def session(self) -> Iterator[sqlite3.Connection]:
        """Commit or roll back one owned transaction, then always close it.

        Public connect() retains SQLite's raw connection contract for callers
        that own their connection lifetime. Atlas-owned scopes use this helper.
        """
        connection = self.connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @staticmethod
    def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
        return {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}

    @classmethod
    def _ensure_column(
        cls,
        connection: sqlite3.Connection,
        table: str,
        name: str,
        declaration: str,
    ) -> None:
        if name not in cls._columns(connection, table):
            connection.execute(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")

    @staticmethod
    def _discard_empty_legacy_supervisor_v4_schema(
        connection: sqlite3.Connection,
    ) -> None:
        """Replace only an empty, pre-release v4 schema; never rewrite evidence."""

        expected_fragments = {
            "supervisor_v4_qualifications": ("authority_granted",),
            "supervisor_v4_jobs": ("authority_granted",),
            "supervisor_v4_job_transitions": (
                "contact_possible",
                "contacted",
                "authority_granted",
            ),
            "supervisor_v4_capabilities": (
                "verified_envelope_sha256",
                "authority_state",
                "authority_granted",
                "envelope_issued_at",
                "envelope_expires_at",
            ),
            "supervisor_v4_receipts": (
                "public_metadata_json",
                "public_metadata_sha256",
                "signature_text",
                "authority_granted",
            ),
        }
        obsolete = False
        for table, fragments in expected_fragments.items():
            row = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
                (table,),
            ).fetchone()
            if row is not None and any(
                fragment not in str(row["sql"] or "") for fragment in fragments
            ):
                obsolete = True
        if not obsolete:
            return

        tables = (
            "supervisor_v4_qualifications",
            "supervisor_v4_jobs",
            "supervisor_v4_job_transitions",
            "supervisor_v4_capabilities",
            "supervisor_v4_capability_consumptions",
            "supervisor_v4_receipts",
        )
        for table in tables:
            exists = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                (table,),
            ).fetchone()
            if exists is None:
                continue
            count = int(
                connection.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]
            )
            if count:
                raise RuntimeError(
                    "Supervisor v4 legacy pre-release rows require explicit review; "
                    "the database will not rewrite append-only evidence"
                )

        for table in (
            "supervisor_v4_receipts",
            "supervisor_v4_capability_consumptions",
            "supervisor_v4_job_transitions",
            "supervisor_v4_jobs",
            "supervisor_v4_capabilities",
            "supervisor_v4_qualifications",
        ):
            connection.execute(f"DROP TABLE IF EXISTS {table}")

    @staticmethod
    def _ensure_supervisor_v3_successor_stage(connection: sqlite3.Connection) -> None:
        """Transactionally widen the v3 stage check without rewriting receipts."""

        row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'supervisor_v3_tasks'"
        ).fetchone()
        schema = str(row["sql"] or "") if row is not None else ""
        if "successor_canary" in schema:
            return
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute(
                """
                CREATE TABLE supervisor_v3_tasks_v31 (
                    id TEXT PRIMARY KEY,
                    stage TEXT NOT NULL CHECK(
                        stage IN ('canary', 'successor_canary', 'fixture')
                    ),
                    recipe_slug TEXT,
                    project_slug TEXT,
                    driver TEXT NOT NULL CHECK(driver = 'python_sdk'),
                    status TEXT NOT NULL CHECK(
                        status IN (
                            'planned', 'approved', 'preparing', 'contacting',
                            'executing', 'validating', 'verifying',
                            'canary_passed', 'candidate_ready', 'stopped',
                            'failed', 'interrupted', 'cancelled', 'expired'
                        )
                    ),
                    plan_json TEXT NOT NULL DEFAULT '{}',
                    result_json TEXT NOT NULL DEFAULT '{}',
                    transitions_json TEXT NOT NULL DEFAULT '[]',
                    error TEXT,
                    stop_code TEXT,
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    model_contacted INTEGER NOT NULL DEFAULT 0,
                    envelope_count INTEGER NOT NULL DEFAULT 0,
                    envelope_chain_sha256 TEXT,
                    runner_pid INTEGER,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT
                )
                """
            )
            connection.execute(
                """
                INSERT INTO supervisor_v3_tasks_v31 (
                    id, stage, recipe_slug, project_slug, driver, status,
                    plan_json, result_json, transitions_json, error, stop_code,
                    attempt_count, model_contacted, envelope_count,
                    envelope_chain_sha256, runner_pid, created_at, updated_at,
                    expires_at, started_at, completed_at
                )
                SELECT
                    id, stage, recipe_slug, project_slug, driver, status,
                    plan_json, result_json, transitions_json, error, stop_code,
                    attempt_count, model_contacted, envelope_count,
                    envelope_chain_sha256, runner_pid, created_at, updated_at,
                    expires_at, started_at, completed_at
                FROM supervisor_v3_tasks
                """
            )
            connection.execute("DROP TABLE supervisor_v3_tasks")
            connection.execute(
                "ALTER TABLE supervisor_v3_tasks_v31 RENAME TO supervisor_v3_tasks"
            )
            connection.execute(
                "CREATE INDEX idx_supervisor_v3_tasks_status "
                "ON supervisor_v3_tasks(status, created_at DESC)"
            )
            connection.execute(
                "CREATE INDEX idx_supervisor_v3_tasks_stage "
                "ON supervisor_v3_tasks(stage, created_at DESC)"
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise

    @staticmethod
    def _ensure_supervisor_v3_recovery_stages(connection: sqlite3.Connection) -> None:
        """Add recovery stages without resetting or rewriting prior receipts."""

        row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'supervisor_v3_tasks'"
        ).fetchone()
        schema = str(row["sql"] or "") if row is not None else ""
        if "recovery_canary" in schema and "recovery_fixture" in schema:
            return
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute(
                """
                CREATE TABLE supervisor_v3_tasks_v32 (
                    id TEXT PRIMARY KEY,
                    stage TEXT NOT NULL CHECK(
                        stage IN (
                            'canary', 'successor_canary', 'fixture',
                            'recovery_canary', 'recovery_fixture'
                        )
                    ),
                    recipe_slug TEXT,
                    project_slug TEXT,
                    driver TEXT NOT NULL CHECK(driver = 'python_sdk'),
                    status TEXT NOT NULL CHECK(
                        status IN (
                            'planned', 'approved', 'preparing', 'contacting',
                            'executing', 'validating', 'verifying',
                            'canary_passed', 'candidate_ready', 'stopped',
                            'failed', 'interrupted', 'cancelled', 'expired'
                        )
                    ),
                    plan_json TEXT NOT NULL DEFAULT '{}',
                    result_json TEXT NOT NULL DEFAULT '{}',
                    transitions_json TEXT NOT NULL DEFAULT '[]',
                    error TEXT,
                    stop_code TEXT,
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    model_contacted INTEGER NOT NULL DEFAULT 0,
                    envelope_count INTEGER NOT NULL DEFAULT 0,
                    envelope_chain_sha256 TEXT,
                    runner_pid INTEGER,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT
                )
                """
            )
            connection.execute(
                """
                INSERT INTO supervisor_v3_tasks_v32 (
                    id, stage, recipe_slug, project_slug, driver, status,
                    plan_json, result_json, transitions_json, error, stop_code,
                    attempt_count, model_contacted, envelope_count,
                    envelope_chain_sha256, runner_pid, created_at, updated_at,
                    expires_at, started_at, completed_at
                )
                SELECT
                    id, stage, recipe_slug, project_slug, driver, status,
                    plan_json, result_json, transitions_json, error, stop_code,
                    attempt_count, model_contacted, envelope_count,
                    envelope_chain_sha256, runner_pid, created_at, updated_at,
                    expires_at, started_at, completed_at
                FROM supervisor_v3_tasks
                """
            )
            connection.execute("DROP TABLE supervisor_v3_tasks")
            connection.execute(
                "ALTER TABLE supervisor_v3_tasks_v32 RENAME TO supervisor_v3_tasks"
            )
            connection.execute(
                "CREATE INDEX idx_supervisor_v3_tasks_status "
                "ON supervisor_v3_tasks(status, created_at DESC)"
            )
            connection.execute(
                "CREATE INDEX idx_supervisor_v3_tasks_stage "
                "ON supervisor_v3_tasks(stage, created_at DESC)"
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise

    def initialize(self) -> None:
        with self._init_lock:
            if self._initialized:
                return
            with self.session() as connection:
                connection.execute("PRAGMA journal_mode = WAL")
                self._discard_empty_legacy_supervisor_v4_schema(connection)
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS conversations (
                        id TEXT PRIMARY KEY,
                        title TEXT,
                        project_slug TEXT,
                        agent_slug TEXT NOT NULL DEFAULT 'atlas',
                        archived INTEGER NOT NULL DEFAULT 0,
                        external_source TEXT,
                        external_id TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS messages (
                        id TEXT PRIMARY KEY,
                        conversation_id TEXT NOT NULL,
                        role TEXT NOT NULL CHECK(role IN ('system', 'user', 'assistant', 'tool')),
                        content TEXT NOT NULL,
                        provider TEXT,
                        model TEXT,
                        metadata_json TEXT NOT NULL DEFAULT '{}',
                        external_id TEXT,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY(conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
                    );
                    CREATE INDEX IF NOT EXISTS idx_messages_conversation_created
                        ON messages(conversation_id, created_at);

                    CREATE TABLE IF NOT EXISTS memories (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        namespace TEXT NOT NULL,
                        kind TEXT NOT NULL,
                        key TEXT NOT NULL,
                        content TEXT NOT NULL,
                        importance INTEGER NOT NULL DEFAULT 5,
                        metadata_json TEXT NOT NULL DEFAULT '{}',
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        UNIQUE(namespace, key)
                    );
                    CREATE INDEX IF NOT EXISTS idx_memories_namespace
                        ON memories(namespace);

                    CREATE TABLE IF NOT EXISTS projects (
                        id TEXT PRIMARY KEY,
                        slug TEXT NOT NULL UNIQUE,
                        name TEXT NOT NULL,
                        status TEXT NOT NULL,
                        summary TEXT NOT NULL,
                        next_action TEXT NOT NULL,
                        metadata_json TEXT NOT NULL DEFAULT '{}',
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS audit_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_type TEXT NOT NULL,
                        actor TEXT NOT NULL,
                        action TEXT NOT NULL,
                        resource TEXT NOT NULL,
                        outcome TEXT NOT NULL,
                        details_json TEXT NOT NULL DEFAULT '{}',
                        created_at TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_audit_created
                        ON audit_events(created_at DESC);

                    CREATE TABLE IF NOT EXISTS approvals (
                        id TEXT PRIMARY KEY,
                        tool TEXT NOT NULL,
                        action TEXT NOT NULL,
                        arguments_json TEXT NOT NULL,
                        arguments_digest TEXT NOT NULL,
                        status TEXT NOT NULL,
                        note TEXT,
                        run_id TEXT,
                        call_id TEXT,
                        requested_at TEXT NOT NULL,
                        decided_at TEXT,
                        executed_at TEXT
                    );
                    CREATE INDEX IF NOT EXISTS idx_approvals_status
                        ON approvals(status, requested_at DESC);

                    CREATE TABLE IF NOT EXISTS runs (
                        id TEXT PRIMARY KEY,
                        conversation_id TEXT NOT NULL,
                        status TEXT NOT NULL,
                        agent_slug TEXT NOT NULL,
                        provider TEXT,
                        model TEXT,
                        project_slug TEXT,
                        local_only INTEGER NOT NULL DEFAULT 1,
                        state_json TEXT NOT NULL DEFAULT '{}',
                        pending_approval_id TEXT,
                        error TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        completed_at TEXT,
                        FOREIGN KEY(conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
                    );
                    CREATE INDEX IF NOT EXISTS idx_runs_conversation
                        ON runs(conversation_id, created_at DESC);
                    CREATE INDEX IF NOT EXISTS idx_runs_status
                        ON runs(status, updated_at DESC);

                    CREATE TABLE IF NOT EXISTS objective_requests (
                        request_id TEXT PRIMARY KEY,
                        payload_json TEXT NOT NULL,
                        request_sha256 TEXT NOT NULL,
                        state TEXT NOT NULL CHECK(state IN ('pending','claimed','cancel_requested','cancelled','resolved')),
                        revision INTEGER NOT NULL,
                        selection_sha256 TEXT,
                        created_at TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS objective_request_results (
                        request_id TEXT PRIMARY KEY,
                        result_json TEXT NOT NULL,
                        result_sha256 TEXT NOT NULL,
                        FOREIGN KEY(request_id) REFERENCES objective_requests(request_id)
                    );
                    CREATE TABLE IF NOT EXISTS objective_request_events (
                        request_id TEXT NOT NULL,
                        revision INTEGER NOT NULL,
                        state TEXT NOT NULL,
                        selection_sha256 TEXT,
                        event_sha256 TEXT NOT NULL,
                        previous_sha256 TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        PRIMARY KEY(request_id,revision),
                        FOREIGN KEY(request_id) REFERENCES objective_requests(request_id)
                    );

                    CREATE TABLE IF NOT EXISTS chat_requests (
                        request_id TEXT PRIMARY KEY,
                        request_digest TEXT NOT NULL,
                        conversation_id TEXT,
                        run_id TEXT UNIQUE,
                        created_at TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_chat_requests_conversation
                        ON chat_requests(conversation_id);

                    CREATE TABLE IF NOT EXISTS import_jobs (
                        id TEXT PRIMARY KEY,
                        source TEXT NOT NULL,
                        filename TEXT NOT NULL,
                        status TEXT NOT NULL,
                        stats_json TEXT NOT NULL DEFAULT '{}',
                        error TEXT,
                        created_at TEXT NOT NULL,
                        completed_at TEXT
                    );

                    CREATE TABLE IF NOT EXISTS supervisor_tasks (
                        id TEXT PRIMARY KEY,
                        kind TEXT NOT NULL CHECK(
                            kind IN ('development.status', 'development.run_check')
                        ),
                        project_slug TEXT NOT NULL,
                        check_name TEXT,
                        status TEXT NOT NULL CHECK(
                            status IN (
                                'planned', 'running', 'succeeded', 'failed',
                                'stopped', 'cancelled', 'interrupted'
                            )
                        ),
                        plan_json TEXT NOT NULL DEFAULT '{}',
                        result_json TEXT NOT NULL DEFAULT '{}',
                        error TEXT,
                        attempt_count INTEGER NOT NULL DEFAULT 0,
                        runner_pid INTEGER,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        started_at TEXT,
                        completed_at TEXT
                    );
                    CREATE INDEX IF NOT EXISTS idx_supervisor_tasks_status
                        ON supervisor_tasks(status, created_at DESC);
                    CREATE INDEX IF NOT EXISTS idx_supervisor_tasks_project
                        ON supervisor_tasks(project_slug, created_at DESC);

                    CREATE TABLE IF NOT EXISTS supervisor_v2_tasks (
                        id TEXT PRIMARY KEY,
                        recipe_slug TEXT NOT NULL,
                        project_slug TEXT NOT NULL,
                        status TEXT NOT NULL CHECK(
                            status IN (
                                'planned', 'approved', 'preparing', 'executing',
                                'validating', 'verifying', 'candidate_ready',
                                'stopped', 'failed', 'interrupted', 'cancelled',
                                'expired'
                            )
                        ),
                        plan_json TEXT NOT NULL DEFAULT '{}',
                        result_json TEXT NOT NULL DEFAULT '{}',
                        transitions_json TEXT NOT NULL DEFAULT '[]',
                        error TEXT,
                        attempt_count INTEGER NOT NULL DEFAULT 0,
                        runner_pid INTEGER,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        expires_at TEXT NOT NULL,
                        started_at TEXT,
                        completed_at TEXT
                    );
                    CREATE INDEX IF NOT EXISTS idx_supervisor_v2_tasks_status
                        ON supervisor_v2_tasks(status, created_at DESC);
                    CREATE INDEX IF NOT EXISTS idx_supervisor_v2_tasks_project
                        ON supervisor_v2_tasks(project_slug, created_at DESC);

                    CREATE TABLE IF NOT EXISTS supervisor_v3_tasks (
                        id TEXT PRIMARY KEY,
                        stage TEXT NOT NULL CHECK(
                            stage IN (
                                'canary', 'successor_canary', 'fixture',
                                'recovery_canary', 'recovery_fixture'
                            )
                        ),
                        recipe_slug TEXT,
                        project_slug TEXT,
                        driver TEXT NOT NULL CHECK(driver = 'python_sdk'),
                        status TEXT NOT NULL CHECK(
                            status IN (
                                'planned', 'approved', 'preparing', 'contacting',
                                'executing', 'validating', 'verifying',
                                'canary_passed', 'candidate_ready', 'stopped',
                                'failed', 'interrupted', 'cancelled', 'expired'
                            )
                        ),
                        plan_json TEXT NOT NULL DEFAULT '{}',
                        result_json TEXT NOT NULL DEFAULT '{}',
                        transitions_json TEXT NOT NULL DEFAULT '[]',
                        error TEXT,
                        stop_code TEXT,
                        attempt_count INTEGER NOT NULL DEFAULT 0,
                        model_contacted INTEGER NOT NULL DEFAULT 0,
                        envelope_count INTEGER NOT NULL DEFAULT 0,
                        envelope_chain_sha256 TEXT,
                        runner_pid INTEGER,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        expires_at TEXT NOT NULL,
                        started_at TEXT,
                        completed_at TEXT
                    );
                    CREATE INDEX IF NOT EXISTS idx_supervisor_v3_tasks_status
                        ON supervisor_v3_tasks(status, created_at DESC);
                    CREATE INDEX IF NOT EXISTS idx_supervisor_v3_tasks_stage
                        ON supervisor_v3_tasks(stage, created_at DESC);

                    CREATE TABLE IF NOT EXISTS supervisor_v4_qualifications (
                        id TEXT PRIMARY KEY,
                        subject TEXT NOT NULL,
                        status TEXT NOT NULL CHECK(
                            status IN ('inactive', 'offline_qualified', 'offline_failed')
                        ),
                        content_json TEXT NOT NULL,
                        content_sha256 TEXT NOT NULL,
                        authority_granted INTEGER NOT NULL DEFAULT 0 CHECK(
                            authority_granted = 0
                        ),
                        created_at TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_supervisor_v4_qualifications_subject
                        ON supervisor_v4_qualifications(subject, created_at DESC);

                    CREATE TABLE IF NOT EXISTS supervisor_v4_jobs (
                        id TEXT PRIMARY KEY,
                        kind TEXT NOT NULL CHECK(kind = 'offline_qualification'),
                        qualification_id TEXT,
                        definition_json TEXT NOT NULL,
                        definition_sha256 TEXT NOT NULL,
                        authority_granted INTEGER NOT NULL DEFAULT 0 CHECK(
                            authority_granted = 0
                        ),
                        created_at TEXT NOT NULL,
                        FOREIGN KEY(qualification_id)
                            REFERENCES supervisor_v4_qualifications(id)
                    );

                    CREATE TABLE IF NOT EXISTS supervisor_v4_job_transitions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        job_id TEXT NOT NULL,
                        job_sequence INTEGER NOT NULL CHECK(job_sequence > 0),
                        state TEXT NOT NULL CHECK(
                            state IN (
                                'inactive', 'offline_qualifying', 'offline_qualified',
                                'offline_failed', 'stopped', 'interrupted', 'cancelled'
                            )
                        ),
                        model_contact_state TEXT NOT NULL CHECK(
                            model_contact_state IN (
                                'not_dispatched', 'contact_possible', 'contacted'
                            )
                        ),
                        worker_id TEXT,
                        worker_pid INTEGER CHECK(worker_pid IS NULL OR worker_pid > 0),
                        worker_start_token TEXT,
                        process_group_id INTEGER CHECK(
                            process_group_id IS NULL OR process_group_id > 0
                        ),
                        process_group_start_token TEXT,
                        executable_sha256 TEXT,
                        details_json TEXT NOT NULL,
                        details_sha256 TEXT NOT NULL,
                        authority_granted INTEGER NOT NULL DEFAULT 0 CHECK(
                            authority_granted = 0
                        ),
                        recorded_at TEXT NOT NULL,
                        UNIQUE(job_id, job_sequence),
                        FOREIGN KEY(job_id) REFERENCES supervisor_v4_jobs(id)
                    );
                    CREATE INDEX IF NOT EXISTS idx_supervisor_v4_transitions_job
                        ON supervisor_v4_job_transitions(job_id, job_sequence DESC);
                    CREATE INDEX IF NOT EXISTS idx_supervisor_v4_transitions_state
                        ON supervisor_v4_job_transitions(state, recorded_at DESC);

                    CREATE TRIGGER IF NOT EXISTS supervisor_v4_transitions_validate_insert
                    BEFORE INSERT ON supervisor_v4_job_transitions BEGIN
                        SELECT CASE WHEN NEW.job_sequence != COALESCE((
                            SELECT MAX(existing.job_sequence) + 1
                            FROM supervisor_v4_job_transitions AS existing
                            WHERE existing.job_id = NEW.job_id
                        ), 1) THEN RAISE(
                            ABORT, 'Supervisor v4 transition sequence is invalid'
                        ) END;
                        SELECT CASE WHEN NEW.job_sequence = 1 AND (
                            NEW.state != 'inactive'
                            OR NEW.model_contact_state != 'not_dispatched'
                        ) THEN RAISE(
                            ABORT, 'Supervisor v4 initial transition is invalid'
                        ) END;
                        SELECT CASE WHEN NEW.job_sequence > 1 AND NOT EXISTS (
                            SELECT 1
                            FROM supervisor_v4_job_transitions AS previous
                            WHERE previous.job_id = NEW.job_id
                              AND previous.job_sequence = NEW.job_sequence - 1
                              AND (
                                  (
                                      previous.state = 'inactive'
                                      AND NEW.state IN ('offline_qualifying', 'cancelled')
                                  )
                                  OR (
                                      previous.state = 'offline_qualifying'
                                      AND NEW.state IN (
                                          'offline_qualified', 'offline_failed',
                                          'stopped', 'interrupted'
                                      )
                                  )
                              )
                        ) THEN RAISE(
                            ABORT, 'Supervisor v4 state transition is invalid'
                        ) END;
                        SELECT CASE WHEN NEW.job_sequence > 1 AND (
                            CASE NEW.model_contact_state
                                WHEN 'not_dispatched' THEN 0
                                WHEN 'contact_possible' THEN 1
                                WHEN 'contacted' THEN 2
                            END
                        ) < (
                            SELECT CASE previous.model_contact_state
                                WHEN 'not_dispatched' THEN 0
                                WHEN 'contact_possible' THEN 1
                                WHEN 'contacted' THEN 2
                            END
                            FROM supervisor_v4_job_transitions AS previous
                            WHERE previous.job_id = NEW.job_id
                              AND previous.job_sequence = NEW.job_sequence - 1
                        ) THEN RAISE(
                            ABORT, 'Supervisor v4 model-contact state cannot move backward'
                        ) END;
                        SELECT CASE WHEN NEW.state = 'offline_qualifying' AND (
                            NEW.worker_id IS NULL
                            OR NEW.worker_pid IS NULL
                            OR NEW.worker_start_token IS NULL
                            OR NEW.process_group_id IS NULL
                            OR NEW.process_group_start_token IS NULL
                            OR NEW.executable_sha256 IS NULL
                        ) THEN RAISE(
                            ABORT, 'Supervisor v4 active identity is incomplete'
                        ) END;
                    END;

                    CREATE TABLE IF NOT EXISTS supervisor_v4_capabilities (
                        id TEXT PRIMARY KEY,
                        nonce_sha256 TEXT NOT NULL UNIQUE CHECK(
                            length(nonce_sha256) = 64
                            AND nonce_sha256 NOT GLOB '*[^0-9a-f]*'
                        ),
                        capability TEXT NOT NULL CHECK(
                            capability = 'offline.qualification.claim'
                        ),
                        scope_json TEXT NOT NULL,
                        scope_sha256 TEXT NOT NULL CHECK(
                            length(scope_sha256) = 64
                            AND scope_sha256 NOT GLOB '*[^0-9a-f]*'
                        ),
                        verified_envelope_sha256 TEXT NOT NULL CHECK(
                            length(verified_envelope_sha256) = 64
                            AND verified_envelope_sha256 NOT GLOB '*[^0-9a-f]*'
                            AND verified_envelope_sha256 !=
                                '0000000000000000000000000000000000000000000000000000000000000000'
                        ),
                        authority_state TEXT NOT NULL CHECK(
                            authority_state = 'inert_offline'
                        ),
                        authority_granted INTEGER NOT NULL CHECK(
                            authority_granted = 0
                        ),
                        envelope_issued_at TEXT NOT NULL,
                        envelope_expires_at TEXT NOT NULL,
                        recorded_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS supervisor_v4_capability_consumptions (
                        id TEXT PRIMARY KEY,
                        capability_id TEXT NOT NULL UNIQUE,
                        job_id TEXT,
                        action TEXT NOT NULL CHECK(
                            action = 'offline.qualification.claim'
                        ),
                        scope_sha256 TEXT NOT NULL CHECK(
                            length(scope_sha256) = 64
                            AND scope_sha256 NOT GLOB '*[^0-9a-f]*'
                        ),
                        verified_envelope_sha256 TEXT NOT NULL CHECK(
                            length(verified_envelope_sha256) = 64
                            AND verified_envelope_sha256 NOT GLOB '*[^0-9a-f]*'
                            AND verified_envelope_sha256 !=
                                '0000000000000000000000000000000000000000000000000000000000000000'
                        ),
                        authority_granted INTEGER NOT NULL CHECK(
                            authority_granted = 0
                        ),
                        consumed_at TEXT NOT NULL,
                        FOREIGN KEY(capability_id) REFERENCES supervisor_v4_capabilities(id),
                        FOREIGN KEY(job_id) REFERENCES supervisor_v4_jobs(id)
                    );

                    CREATE TRIGGER IF NOT EXISTS supervisor_v4_consumptions_validate_insert
                    BEFORE INSERT ON supervisor_v4_capability_consumptions BEGIN
                        SELECT CASE WHEN NOT EXISTS (
                            SELECT 1 FROM supervisor_v4_capabilities AS capability
                            WHERE capability.id = NEW.capability_id
                              AND capability.capability = NEW.action
                              AND capability.scope_sha256 = NEW.scope_sha256
                              AND capability.verified_envelope_sha256 =
                                  NEW.verified_envelope_sha256
                              AND capability.authority_state = 'inert_offline'
                              AND capability.authority_granted = 0
                        ) THEN RAISE(
                            ABORT, 'Supervisor v4 capability binding does not match'
                        ) END;
                    END;

                    CREATE TABLE IF NOT EXISTS supervisor_v4_receipts (
                        sequence INTEGER PRIMARY KEY AUTOINCREMENT CHECK(sequence > 0),
                        id TEXT NOT NULL UNIQUE,
                        receipt_kind TEXT NOT NULL,
                        subject_id TEXT NOT NULL,
                        content_json TEXT NOT NULL,
                        content_sha256 TEXT NOT NULL CHECK(
                            length(content_sha256) = 64
                            AND content_sha256 NOT GLOB '*[^0-9a-f]*'
                        ),
                        previous_chain_sha256 TEXT NOT NULL CHECK(
                            length(previous_chain_sha256) = 64
                            AND previous_chain_sha256 NOT GLOB '*[^0-9a-f]*'
                        ),
                        signer_key_id TEXT NOT NULL,
                        signature_algorithm TEXT NOT NULL CHECK(
                            length(signature_algorithm) BETWEEN 1 AND 128
                            AND instr(lower(signature_algorithm), 'hmac') = 0
                            AND instr(lower(signature_algorithm), 'shared-secret') = 0
                            AND instr(lower(signature_algorithm), 'symmetric') = 0
                        ),
                        public_metadata_json TEXT NOT NULL,
                        public_metadata_sha256 TEXT NOT NULL CHECK(
                            length(public_metadata_sha256) = 64
                            AND public_metadata_sha256 NOT GLOB '*[^0-9a-f]*'
                        ),
                        signature_text TEXT NOT NULL CHECK(
                            length(signature_text) BETWEEN 1 AND 65536
                        ),
                        chain_sha256 TEXT NOT NULL UNIQUE CHECK(
                            length(chain_sha256) = 64
                            AND chain_sha256 NOT GLOB '*[^0-9a-f]*'
                        ),
                        authority_granted INTEGER NOT NULL CHECK(
                            authority_granted = 0
                        ),
                        recorded_at TEXT NOT NULL
                    );

                    CREATE TRIGGER IF NOT EXISTS supervisor_v4_receipts_validate_insert
                    BEFORE INSERT ON supervisor_v4_receipts BEGIN
                        SELECT CASE WHEN NEW.sequence != COALESCE((
                            SELECT MAX(existing.sequence) + 1
                            FROM supervisor_v4_receipts AS existing
                        ), 1) THEN RAISE(
                            ABORT, 'Supervisor v4 receipt sequence is invalid'
                        ) END;
                        SELECT CASE WHEN NEW.previous_chain_sha256 != COALESCE((
                            SELECT existing.chain_sha256
                            FROM supervisor_v4_receipts AS existing
                            ORDER BY existing.sequence DESC LIMIT 1
                        ), '0000000000000000000000000000000000000000000000000000000000000000')
                        THEN RAISE(
                            ABORT, 'Supervisor v4 previous receipt chain is invalid'
                        ) END;
                    END;

                    CREATE TRIGGER IF NOT EXISTS supervisor_v4_qualifications_no_update
                    BEFORE UPDATE ON supervisor_v4_qualifications BEGIN
                        SELECT RAISE(ABORT, 'Supervisor v4 qualification ledger is append-only');
                    END;
                    CREATE TRIGGER IF NOT EXISTS supervisor_v4_qualifications_no_delete
                    BEFORE DELETE ON supervisor_v4_qualifications BEGIN
                        SELECT RAISE(ABORT, 'Supervisor v4 qualification ledger is append-only');
                    END;
                    CREATE TRIGGER IF NOT EXISTS supervisor_v4_jobs_no_update
                    BEFORE UPDATE ON supervisor_v4_jobs BEGIN
                        SELECT RAISE(ABORT, 'Supervisor v4 job ledger is append-only');
                    END;
                    CREATE TRIGGER IF NOT EXISTS supervisor_v4_jobs_no_delete
                    BEFORE DELETE ON supervisor_v4_jobs BEGIN
                        SELECT RAISE(ABORT, 'Supervisor v4 job ledger is append-only');
                    END;
                    CREATE TRIGGER IF NOT EXISTS supervisor_v4_transitions_no_update
                    BEFORE UPDATE ON supervisor_v4_job_transitions BEGIN
                        SELECT RAISE(ABORT, 'Supervisor v4 transition ledger is append-only');
                    END;
                    CREATE TRIGGER IF NOT EXISTS supervisor_v4_transitions_no_delete
                    BEFORE DELETE ON supervisor_v4_job_transitions BEGIN
                        SELECT RAISE(ABORT, 'Supervisor v4 transition ledger is append-only');
                    END;
                    CREATE TRIGGER IF NOT EXISTS supervisor_v4_capabilities_no_update
                    BEFORE UPDATE ON supervisor_v4_capabilities BEGIN
                        SELECT RAISE(ABORT, 'Supervisor v4 capability ledger is append-only');
                    END;
                    CREATE TRIGGER IF NOT EXISTS supervisor_v4_capabilities_no_delete
                    BEFORE DELETE ON supervisor_v4_capabilities BEGIN
                        SELECT RAISE(ABORT, 'Supervisor v4 capability ledger is append-only');
                    END;
                    CREATE TRIGGER IF NOT EXISTS supervisor_v4_consumptions_no_update
                    BEFORE UPDATE ON supervisor_v4_capability_consumptions BEGIN
                        SELECT RAISE(ABORT, 'Supervisor v4 capability claims are append-only');
                    END;
                    CREATE TRIGGER IF NOT EXISTS supervisor_v4_consumptions_no_delete
                    BEFORE DELETE ON supervisor_v4_capability_consumptions BEGIN
                        SELECT RAISE(ABORT, 'Supervisor v4 capability claims are append-only');
                    END;
                    CREATE TRIGGER IF NOT EXISTS supervisor_v4_receipts_no_update
                    BEFORE UPDATE ON supervisor_v4_receipts BEGIN
                        SELECT RAISE(ABORT, 'Supervisor v4 receipt ledger is append-only');
                    END;
                    CREATE TRIGGER IF NOT EXISTS supervisor_v4_receipts_no_delete
                    BEFORE DELETE ON supervisor_v4_receipts BEGIN
                        SELECT RAISE(ABORT, 'Supervisor v4 receipt ledger is append-only');
                    END;
                    """
                )

                self._ensure_supervisor_v3_successor_stage(connection)
                self._ensure_supervisor_v3_recovery_stages(connection)

                # Migrate v0.1 databases in place.
                self._ensure_column(connection, "conversations", "project_slug", "TEXT")
                self._ensure_column(
                    connection, "conversations", "agent_slug", "TEXT NOT NULL DEFAULT 'atlas'"
                )
                self._ensure_column(
                    connection, "conversations", "archived", "INTEGER NOT NULL DEFAULT 0"
                )
                self._ensure_column(connection, "conversations", "external_source", "TEXT")
                self._ensure_column(connection, "conversations", "external_id", "TEXT")
                self._ensure_column(
                    connection, "messages", "metadata_json", "TEXT NOT NULL DEFAULT '{}'"
                )
                self._ensure_column(connection, "messages", "external_id", "TEXT")
                self._ensure_column(connection, "approvals", "run_id", "TEXT")
                self._ensure_column(connection, "approvals", "call_id", "TEXT")

                # Indexes that reference v1 columns must be created only after the
                # v0.1 tables have been migrated.
                connection.executescript(
                    """
                    CREATE INDEX IF NOT EXISTS idx_conversations_updated
                        ON conversations(archived, updated_at DESC);
                    CREATE UNIQUE INDEX IF NOT EXISTS idx_conversations_external
                        ON conversations(external_source, external_id)
                        WHERE external_source IS NOT NULL AND external_id IS NOT NULL;
                    CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_external
                        ON messages(conversation_id, external_id)
                        WHERE external_id IS NOT NULL;
                    CREATE INDEX IF NOT EXISTS idx_approvals_run
                        ON approvals(run_id, requested_at DESC);
                    """
                )

                try:
                    connection.executescript(
                        """
                        CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(
                            key,
                            content,
                            namespace UNINDEXED,
                            content='memories',
                            content_rowid='id'
                        );

                        CREATE TRIGGER IF NOT EXISTS memories_ai AFTER INSERT ON memories BEGIN
                            INSERT INTO memories_fts(rowid, key, content, namespace)
                            VALUES (new.id, new.key, new.content, new.namespace);
                        END;

                        CREATE TRIGGER IF NOT EXISTS memories_ad AFTER DELETE ON memories BEGIN
                            INSERT INTO memories_fts(memories_fts, rowid, key, content, namespace)
                            VALUES ('delete', old.id, old.key, old.content, old.namespace);
                        END;

                        CREATE TRIGGER IF NOT EXISTS memories_au AFTER UPDATE ON memories BEGIN
                            INSERT INTO memories_fts(memories_fts, rowid, key, content, namespace)
                            VALUES ('delete', old.id, old.key, old.content, old.namespace);
                            INSERT INTO memories_fts(rowid, key, content, namespace)
                            VALUES (new.id, new.key, new.content, new.namespace);
                        END;
                        """
                    )
                    count = connection.execute(
                        "SELECT COUNT(*) AS value FROM memories_fts"
                    ).fetchone()["value"]
                    if count == 0:
                        connection.execute(
                            "INSERT INTO memories_fts(memories_fts) VALUES ('rebuild')"
                        )
                except sqlite3.OperationalError:
                    pass
            self._initialized = True

    def backup_to(self, destination: str | Path) -> Path:
        target = Path(destination).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        with self.session() as source, closing(sqlite3.connect(target)) as output, output:
            source.backup(output)
        return target

    def _fts_available(self, connection: sqlite3.Connection) -> bool:
        row = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='memories_fts'"
        ).fetchone()
        return row is not None

    @staticmethod
    def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        result = dict(row)
        for key in (
            "metadata_json",
            "details_json",
            "arguments_json",
            "state_json",
            "stats_json",
            "plan_json",
            "result_json",
            "transitions_json",
        ):
            if key in result:
                target = key.removesuffix("_json")
                try:
                    result[target] = json.loads(result.pop(key))
                except (json.JSONDecodeError, TypeError):
                    result[target] = {}
                    result.pop(key, None)
        for key in ("archived", "local_only"):
            if key in result:
                result[key] = bool(result[key])
        return result

    # Conversations and messages -------------------------------------------------

    def create_conversation(
        self,
        title: str | None = None,
        *,
        project_slug: str | None = None,
        agent_slug: str = "atlas",
        external_source: str | None = None,
        external_id: str | None = None,
        created_at: str | None = None,
        updated_at: str | None = None,
    ) -> dict[str, Any]:
        conversation_id = str(uuid.uuid4())
        now = utc_now()
        created = created_at or now
        updated = updated_at or created
        with self.session() as connection:
            connection.execute(
                """
                INSERT INTO conversations(
                    id, title, project_slug, agent_slug, archived,
                    external_source, external_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?)
                """,
                (
                    conversation_id,
                    title,
                    project_slug,
                    agent_slug,
                    external_source,
                    external_id,
                    created,
                    updated,
                ),
            )
        return self.get_conversation(conversation_id)  # type: ignore[return-value]

    def get_conversation(self, conversation_id: str) -> dict[str, Any] | None:
        with self.session() as connection:
            row = connection.execute(
                "SELECT * FROM conversations WHERE id = ?", (conversation_id,)
            ).fetchone()
        return self._row(row)

    def find_conversation_by_external(
        self, source: str, external_id: str
    ) -> dict[str, Any] | None:
        with self.session() as connection:
            row = connection.execute(
                "SELECT * FROM conversations WHERE external_source = ? AND external_id = ?",
                (source, external_id),
            ).fetchone()
        return self._row(row)

    def list_conversations(
        self,
        *,
        search: str | None = None,
        archived: bool = False,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        sql = """
            SELECT c.*,
                   (SELECT content FROM messages m
                    WHERE m.conversation_id = c.id
                    ORDER BY m.created_at DESC LIMIT 1) AS last_message,
                   (SELECT COUNT(*) FROM messages m WHERE m.conversation_id = c.id) AS message_count
            FROM conversations c
            WHERE c.archived = ?
        """
        parameters: list[Any] = [1 if archived else 0]
        if search:
            sql += " AND (c.title LIKE ? COLLATE NOCASE OR EXISTS (SELECT 1 FROM messages sm WHERE sm.conversation_id = c.id AND sm.content LIKE ? COLLATE NOCASE))"
            like = f"%{search}%"
            parameters.extend([like, like])
        sql += " ORDER BY c.updated_at DESC LIMIT ?"
        parameters.append(limit)
        with self.session() as connection:
            rows = connection.execute(sql, parameters).fetchall()
        return [self._row(row) for row in rows]  # type: ignore[misc]

    def update_conversation(
        self,
        conversation_id: str,
        *,
        title: str | None | object = _UNSET,
        project_slug: str | None | object = _UNSET,
        agent_slug: str | object = _UNSET,
        archived: bool | object = _UNSET,
    ) -> dict[str, Any]:
        current = self.get_conversation(conversation_id)
        if current is None:
            raise KeyError(f"Conversation not found: {conversation_id}")
        values = {
            "title": current.get("title") if title is _UNSET else title,
            "project_slug": current.get("project_slug") if project_slug is _UNSET else project_slug,
            "agent_slug": current.get("agent_slug") if agent_slug is _UNSET else agent_slug,
            "archived": current.get("archived") if archived is _UNSET else bool(archived),
        }
        if not values["agent_slug"]:
            values["agent_slug"] = "atlas"
        with self.session() as connection:
            connection.execute(
                """
                UPDATE conversations
                SET title = ?, project_slug = ?, agent_slug = ?, archived = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    values["title"],
                    values["project_slug"],
                    values["agent_slug"],
                    1 if values["archived"] else 0,
                    utc_now(),
                    conversation_id,
                ),
            )
        return self.get_conversation(conversation_id)  # type: ignore[return-value]

    def delete_conversation(self, conversation_id: str) -> bool:
        with self.session() as connection:
            cursor = connection.execute(
                "DELETE FROM conversations WHERE id = ?", (conversation_id,)
            )
        return cursor.rowcount > 0

    def add_message(
        self,
        conversation_id: str,
        role: str,
        content: str,
        provider: str | None = None,
        model: str | None = None,
        *,
        metadata: dict[str, Any] | None = None,
        external_id: str | None = None,
        created_at: str | None = None,
    ) -> dict[str, Any]:
        message_id = str(uuid.uuid4())
        now = created_at or utc_now()
        with self.session() as connection:
            exists = connection.execute(
                "SELECT 1 FROM conversations WHERE id = ?", (conversation_id,)
            ).fetchone()
            if exists is None:
                raise KeyError(f"Conversation not found: {conversation_id}")
            if external_id:
                existing = connection.execute(
                    "SELECT * FROM messages WHERE conversation_id = ? AND external_id = ?",
                    (conversation_id, external_id),
                ).fetchone()
                if existing is not None:
                    return self._row(existing)  # type: ignore[return-value]
            connection.execute(
                """
                INSERT INTO messages(
                    id, conversation_id, role, content, provider, model,
                    metadata_json, external_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    message_id,
                    conversation_id,
                    role,
                    content,
                    provider,
                    model,
                    canonical_json(metadata or {}),
                    external_id,
                    now,
                ),
            )
            connection.execute(
                "UPDATE conversations SET updated_at = ? WHERE id = ?",
                (now, conversation_id),
            )
            row = connection.execute(
                "SELECT * FROM messages WHERE id = ?", (message_id,)
            ).fetchone()
        return self._row(row)  # type: ignore[return-value]

    def message_exists_external(self, conversation_id: str, external_id: str) -> bool:
        with self.session() as connection:
            row = connection.execute(
                "SELECT 1 FROM messages WHERE conversation_id = ? AND external_id = ?",
                (conversation_id, external_id),
            ).fetchone()
        return row is not None

    def list_messages(
        self, conversation_id: str, *, limit: int = 500
    ) -> list[dict[str, Any]]:
        with self.session() as connection:
            rows = connection.execute(
                """
                SELECT * FROM messages
                WHERE conversation_id = ?
                ORDER BY created_at ASC, rowid ASC
                LIMIT ?
                """,
                (conversation_id, limit),
            ).fetchall()
        return [self._row(row) for row in rows]  # type: ignore[misc]

    def recent_messages(
        self, conversation_id: str, limit: int = 30
    ) -> list[dict[str, Any]]:
        with self.session() as connection:
            rows = connection.execute(
                """
                SELECT * FROM messages
                WHERE conversation_id = ?
                ORDER BY created_at DESC, rowid DESC
                LIMIT ?
                """,
                (conversation_id, limit),
            ).fetchall()
        return [self._row(row) for row in reversed(rows)]  # type: ignore[misc]

    # Memory --------------------------------------------------------------------

    def upsert_memory(
        self,
        *,
        namespace: str,
        kind: str,
        key: str,
        content: str,
        importance: int = 5,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = utc_now()
        with self.session() as connection:
            connection.execute(
                """
                INSERT INTO memories(
                    namespace, kind, key, content, importance, metadata_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(namespace, key) DO UPDATE SET
                    kind = excluded.kind,
                    content = excluded.content,
                    importance = excluded.importance,
                    metadata_json = excluded.metadata_json,
                    updated_at = excluded.updated_at
                """,
                (
                    namespace,
                    kind,
                    key,
                    content,
                    importance,
                    canonical_json(metadata or {}),
                    now,
                    now,
                ),
            )
            row = connection.execute(
                "SELECT * FROM memories WHERE namespace = ? AND key = ?",
                (namespace, key),
            ).fetchone()
        return self._row(row)  # type: ignore[return-value]

    def get_memory(self, memory_id: int) -> dict[str, Any] | None:
        with self.session() as connection:
            row = connection.execute(
                "SELECT * FROM memories WHERE id = ?", (memory_id,)
            ).fetchone()
        return self._row(row)

    def update_memory(
        self,
        memory_id: int,
        *,
        namespace: str,
        kind: str,
        key: str,
        content: str,
        importance: int = 5,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if self.get_memory(memory_id) is None:
            raise KeyError(f"Memory not found: {memory_id}")
        with self.session() as connection:
            try:
                connection.execute(
                    """
                    UPDATE memories SET namespace = ?, kind = ?, key = ?, content = ?,
                        importance = ?, metadata_json = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        namespace,
                        kind,
                        key,
                        content,
                        importance,
                        canonical_json(metadata or {}),
                        utc_now(),
                        memory_id,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError(
                    f"A memory with namespace '{namespace}' and key '{key}' already exists"
                ) from exc
        return self.get_memory(memory_id)  # type: ignore[return-value]

    def list_memories(
        self, namespace: str | None = None, limit: int = 100, *, exclude_research: bool = False
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM memories"
        parameters: list[Any] = []
        if namespace:
            sql += " WHERE namespace = ?"
            parameters.append(namespace)
        if exclude_research:
            sql += (" AND " if namespace else " WHERE ") + "namespace NOT GLOB 'research:*'"
        sql += " ORDER BY importance DESC, updated_at DESC LIMIT ?"
        parameters.append(limit)
        with self.session() as connection:
            rows = connection.execute(sql, parameters).fetchall()
        return [self._row(row) for row in rows]  # type: ignore[misc]

    def search_memories(
        self,
        query: str,
        namespace: str | None = None,
        limit: int = 8,
        *,
        exclude_research: bool = False,
    ) -> list[dict[str, Any]]:
        query = query.strip()
        if not query:
            return self.list_memories(namespace=namespace, limit=limit, exclude_research=exclude_research)
        with self.session() as connection:
            if self._fts_available(connection):
                tokens = re.findall(r"[A-Za-z0-9_]{2,}", query.lower())[:16]
                if tokens:
                    match_query = " OR ".join(f'"{token}"*' for token in tokens)
                    sql = """
                        SELECT m.*, bm25(memories_fts) AS search_score
                        FROM memories_fts
                        JOIN memories AS m ON m.id = memories_fts.rowid
                        WHERE memories_fts MATCH ?
                    """
                    parameters: list[Any] = [match_query]
                    if namespace:
                        sql += " AND m.namespace = ?"
                        parameters.append(namespace)
                    if exclude_research:
                        sql += " AND m.namespace NOT GLOB 'research:*'"
                    sql += " ORDER BY search_score ASC, m.importance DESC LIMIT ?"
                    parameters.append(limit)
                    try:
                        rows = connection.execute(sql, parameters).fetchall()
                        return [self._row(row) for row in rows]  # type: ignore[misc]
                    except sqlite3.OperationalError:
                        pass
            like = f"%{query}%"
            sql = """
                SELECT * FROM memories
                WHERE (key LIKE ? COLLATE NOCASE OR content LIKE ? COLLATE NOCASE)
            """
            parameters = [like, like]
            if namespace:
                sql += " AND namespace = ?"
                parameters.append(namespace)
            if exclude_research:
                sql += " AND namespace NOT GLOB 'research:*'"
            sql += " ORDER BY importance DESC, updated_at DESC LIMIT ?"
            parameters.append(limit)
            rows = connection.execute(sql, parameters).fetchall()
        return [self._row(row) for row in rows]  # type: ignore[misc]

    def delete_memory(self, memory_id: int, *, exclude_research: bool = False) -> bool:
        # Apply the namespace condition in the deletion itself, never a separate
        # read/check followed by a deletion that could race a namespace change.
        sql = "DELETE FROM memories WHERE id = ?"
        if exclude_research:
            sql += " AND namespace NOT GLOB 'research:*'"
        with self.session() as connection:
            cursor = connection.execute(sql, (memory_id,))
        return cursor.rowcount > 0

    # Projects ------------------------------------------------------------------

    def upsert_project(
        self,
        *,
        slug: str,
        name: str,
        status: str,
        summary: str,
        next_action: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = utc_now()
        with self.session() as connection:
            existing = connection.execute(
                "SELECT id, created_at FROM projects WHERE slug = ?", (slug,)
            ).fetchone()
            project_id = existing["id"] if existing else str(uuid.uuid4())
            created_at = existing["created_at"] if existing else now
            connection.execute(
                """
                INSERT INTO projects(
                    id, slug, name, status, summary, next_action, metadata_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(slug) DO UPDATE SET
                    name = excluded.name,
                    status = excluded.status,
                    summary = excluded.summary,
                    next_action = excluded.next_action,
                    metadata_json = excluded.metadata_json,
                    updated_at = excluded.updated_at
                """,
                (
                    project_id,
                    slug,
                    name,
                    status,
                    summary,
                    next_action,
                    canonical_json(metadata or {}),
                    created_at,
                    now,
                ),
            )
            row = connection.execute(
                "SELECT * FROM projects WHERE slug = ?", (slug,)
            ).fetchone()
        return self._row(row)  # type: ignore[return-value]

    def get_project(self, slug: str) -> dict[str, Any] | None:
        with self.session() as connection:
            row = connection.execute(
                "SELECT * FROM projects WHERE slug = ?", (slug,)
            ).fetchone()
        return self._row(row)

    def list_projects(self, limit: int = 200) -> list[dict[str, Any]]:
        with self.session() as connection:
            rows = connection.execute(
                "SELECT * FROM projects ORDER BY updated_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._row(row) for row in rows]  # type: ignore[misc]

    def delete_project(self, slug: str) -> bool:
        with self.session() as connection:
            cursor = connection.execute("DELETE FROM projects WHERE slug = ?", (slug,))
        return cursor.rowcount > 0

    # Audit ---------------------------------------------------------------------

    def audit(
        self,
        *,
        event_type: str,
        actor: str,
        action: str,
        resource: str,
        outcome: str,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = utc_now()
        with self.session() as connection:
            cursor = connection.execute(
                """
                INSERT INTO audit_events(
                    event_type, actor, action, resource, outcome, details_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_type,
                    actor,
                    action,
                    resource,
                    outcome,
                    canonical_json(details or {}),
                    now,
                ),
            )
            row = connection.execute(
                "SELECT * FROM audit_events WHERE id = ?", (cursor.lastrowid,)
            ).fetchone()
        return self._row(row)  # type: ignore[return-value]

    def list_audit(
        self,
        limit: int = 100,
        *,
        event_type: str | None = None,
        outcome: str | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        parameters: list[Any] = []
        if event_type:
            clauses.append("event_type = ?")
            parameters.append(event_type)
        if outcome:
            clauses.append("outcome = ?")
            parameters.append(outcome)
        sql = "SELECT * FROM audit_events"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC LIMIT ?"
        parameters.append(limit)
        with self.session() as connection:
            rows = connection.execute(sql, parameters).fetchall()
        return [self._row(row) for row in rows]  # type: ignore[misc]

    # Approvals -----------------------------------------------------------------

    def create_approval(
        self,
        tool: str,
        action: str,
        arguments: dict[str, Any],
        *,
        run_id: str | None = None,
        call_id: str | None = None,
    ) -> dict[str, Any]:
        if run_id and call_id:
            with self.session() as connection:
                existing = connection.execute(
                    """
                    SELECT * FROM approvals
                    WHERE run_id = ? AND call_id = ? AND status IN ('pending', 'approved')
                    ORDER BY requested_at DESC LIMIT 1
                    """,
                    (run_id, call_id),
                ).fetchone()
            if existing is not None:
                return self._row(existing)  # type: ignore[return-value]
        approval_id = str(uuid.uuid4())
        now = utc_now()
        with self.session() as connection:
            connection.execute(
                """
                INSERT INTO approvals(
                    id, tool, action, arguments_json, arguments_digest, status,
                    note, run_id, call_id, requested_at
                ) VALUES (?, ?, ?, ?, ?, 'pending', NULL, ?, ?, ?)
                """,
                (
                    approval_id,
                    tool,
                    action,
                    canonical_json(arguments),
                    arguments_digest(arguments),
                    run_id,
                    call_id,
                    now,
                ),
            )
            row = connection.execute(
                "SELECT * FROM approvals WHERE id = ?", (approval_id,)
            ).fetchone()
        return self._row(row)  # type: ignore[return-value]

    def get_approval(self, approval_id: str) -> dict[str, Any] | None:
        with self.session() as connection:
            row = connection.execute(
                "SELECT * FROM approvals WHERE id = ?", (approval_id,)
            ).fetchone()
        return self._row(row)

    def decide_approval(
        self, approval_id: str, decision: str, note: str | None = None
    ) -> dict[str, Any]:
        if decision not in {"approved", "rejected"}:
            raise ValueError("Decision must be approved or rejected")
        now = utc_now()
        with self.session() as connection:
            current = connection.execute(
                "SELECT * FROM approvals WHERE id = ?", (approval_id,)
            ).fetchone()
            if current is None:
                raise KeyError(f"Approval not found: {approval_id}")
            if current["status"] != "pending":
                raise ValueError(f"Approval {approval_id} is already {current['status']}")
            connection.execute(
                "UPDATE approvals SET status = ?, note = ?, decided_at = ? WHERE id = ?",
                (decision, note, now, approval_id),
            )
            row = connection.execute(
                "SELECT * FROM approvals WHERE id = ?", (approval_id,)
            ).fetchone()
        return self._row(row)  # type: ignore[return-value]

    def mark_approval_executed(self, approval_id: str) -> None:
        with self.session() as connection:
            cursor = connection.execute(
                """
                UPDATE approvals SET status = 'executed', executed_at = ?
                WHERE id = ? AND status = 'approved'
                """,
                (utc_now(), approval_id),
            )
            if cursor.rowcount == 0:
                raise ValueError(f"Approval {approval_id} was not approved")

    def list_approvals(
        self, status: str | None = None, limit: int = 200
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM approvals"
        parameters: list[Any] = []
        if status:
            sql += " WHERE status = ?"
            parameters.append(status)
        sql += " ORDER BY requested_at DESC LIMIT ?"
        parameters.append(limit)
        with self.session() as connection:
            rows = connection.execute(sql, parameters).fetchall()
        return [self._row(row) for row in rows]  # type: ignore[misc]

    # Agent runs ----------------------------------------------------------------

    def get_message(self, message_id: str) -> dict[str, Any] | None:
        with self.session() as connection:
            row = connection.execute("SELECT * FROM messages WHERE id = ?", (message_id,)).fetchone()
        return self._row(row)

    def get_chat_request(self, request_id: str) -> dict[str, Any] | None:
        with self.session() as connection:
            row = connection.execute("SELECT * FROM chat_requests WHERE request_id = ?", (request_id,)).fetchone()
        return self._row(row)

    @staticmethod
    def _unresolved_chat_work(connection, conversation_id):
        unresolved = connection.execute("""
            SELECT 1 FROM chat_requests q LEFT JOIN runs r ON r.id = q.run_id
            WHERE q.conversation_id = ? AND
                (r.id IS NULL OR r.status NOT IN ('completed','failed','interrupted','stopped','cancelled','rolled_back'))
            LIMIT 1
        """, (conversation_id,)).fetchone()
        active = connection.execute("""
            SELECT 1 FROM runs WHERE conversation_id = ? AND
                (status NOT IN ('completed','failed','interrupted','stopped','cancelled','rolled_back')
                 OR json_array_length(json_extract(state_json, '$.pending_calls')) > 0
                 OR json_extract(state_json, '$.cleanup_required') = 1
                 OR json_extract(state_json, '$.interruption.cleanup_required') = 1) LIMIT 1
        """, (conversation_id,)).fetchone()
        return bool(unresolved or active)

    def has_unresolved_chat_work(self, conversation_id):
        with self.session() as connection:
            return self._unresolved_chat_work(connection, conversation_id)

    def reserve_chat_request(self, request_id: str, digest: str, conversation_id: str | None):
        """Atomically reserve once. Tombstones survive deletion of conversations.

        No expiry authorizes replay: missing runs require reconciliation. Two
        processes cannot both reserve a request, or start overlapping turns.
        """
        with self.session() as connection:
            connection.execute("BEGIN IMMEDIATE")
            old = connection.execute("SELECT * FROM chat_requests WHERE request_id = ?", (request_id,)).fetchone()
            if old is not None:
                if old["request_digest"] != digest:
                    raise ValueError("Request ID already belongs to different input; nothing was executed")
                return False, dict(old)
            if conversation_id is not None:
                if self._unresolved_chat_work(connection, conversation_id):
                    raise ValueError("Conversation has unresolved work; reconcile its saved result before new work")
            connection.execute("INSERT INTO chat_requests VALUES (?, ?, ?, NULL, ?)",
                               (request_id, digest, conversation_id, utc_now()))
        return True, self.get_chat_request(request_id)

    def create_run(
        self,
        *,
        conversation_id: str,
        agent_slug: str,
        provider: str | None,
        model: str | None,
        project_slug: str | None,
        local_only: bool,
        state: dict[str, Any],
        request_id: str | None = None,
    ) -> dict[str, Any]:
        run_id = str(uuid.uuid4())
        now = utc_now()
        with self.session() as connection:
            connection.execute(
                """
                INSERT INTO runs(
                    id, conversation_id, status, agent_slug, provider, model,
                    project_slug, local_only, state_json, created_at, updated_at
                ) VALUES (?, ?, 'running', ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    conversation_id,
                    agent_slug,
                    provider,
                    model,
                    project_slug,
                    1 if local_only else 0,
                    canonical_json(state),
                    now,
                    now,
                ),
            )
            if request_id is not None:
                linked = connection.execute("""UPDATE chat_requests SET run_id = ?, conversation_id = ?
                    WHERE request_id = ? AND run_id IS NULL""", (run_id, conversation_id, request_id))
                if linked.rowcount != 1:
                    raise ValueError("Request reservation missing or already bound")
        return self.get_run(run_id)  # type: ignore[return-value]

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        with self.session() as connection:
            row = connection.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        return self._row(row)

    def update_run(
        self,
        run_id: str,
        *,
        status: str | None = None,
        state: dict[str, Any] | None = None,
        pending_approval_id: str | None = None,
        error: str | None = None,
        provider: str | None = None,
        model: str | None = None,
        completed: bool = False,
    ) -> dict[str, Any]:
        current = self.get_run(run_id)
        if current is None:
            raise KeyError(f"Run not found: {run_id}")
        now = utc_now()
        with self.session() as connection:
            connection.execute(
                """
                UPDATE runs SET
                    status = ?,
                    state_json = ?,
                    pending_approval_id = ?,
                    error = ?,
                    provider = ?,
                    model = ?,
                    updated_at = ?,
                    completed_at = ?
                WHERE id = ?
                """,
                (
                    status or current["status"],
                    canonical_json(state if state is not None else current.get("state") or {}),
                    pending_approval_id,
                    error,
                    provider if provider is not None else current.get("provider"),
                    model if model is not None else current.get("model"),
                    now,
                    now if completed else current.get("completed_at"),
                    run_id,
                ),
            )
        return self.get_run(run_id)  # type: ignore[return-value]

    def list_runs(
        self,
        *,
        conversation_id: str | None = None,
        status: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        parameters: list[Any] = []
        if conversation_id:
            clauses.append("conversation_id = ?")
            parameters.append(conversation_id)
        if status:
            clauses.append("status = ?")
            parameters.append(status)
        sql = "SELECT * FROM runs"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY created_at DESC LIMIT ?"
        parameters.append(limit)
        with self.session() as connection:
            rows = connection.execute(sql, parameters).fetchall()
        return [self._row(row) for row in rows]  # type: ignore[misc]

    # Imports -------------------------------------------------------------------

    def create_import_job(self, source: str, filename: str) -> dict[str, Any]:
        job_id = str(uuid.uuid4())
        with self.session() as connection:
            connection.execute(
                """
                INSERT INTO import_jobs(id, source, filename, status, stats_json, created_at)
                VALUES (?, ?, ?, 'running', '{}', ?)
                """,
                (job_id, source, filename, utc_now()),
            )
        return self.get_import_job(job_id)  # type: ignore[return-value]

    def get_import_job(self, job_id: str) -> dict[str, Any] | None:
        with self.session() as connection:
            row = connection.execute(
                "SELECT * FROM import_jobs WHERE id = ?", (job_id,)
            ).fetchone()
        return self._row(row)

    def finish_import_job(
        self,
        job_id: str,
        *,
        status: str,
        stats: dict[str, Any],
        error: str | None = None,
    ) -> dict[str, Any]:
        with self.session() as connection:
            connection.execute(
                """
                UPDATE import_jobs
                SET status = ?, stats_json = ?, error = ?, completed_at = ?
                WHERE id = ?
                """,
                (status, canonical_json(stats), error, utc_now(), job_id),
            )
        return self.get_import_job(job_id)  # type: ignore[return-value]

    def list_import_jobs(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.session() as connection:
            rows = connection.execute(
                "SELECT * FROM import_jobs ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._row(row) for row in rows]  # type: ignore[misc]

    # Supervisor tasks ----------------------------------------------------------

    def create_supervisor_task(
        self,
        *,
        kind: str,
        project_slug: str,
        check_name: str | None,
        plan: dict[str, Any],
    ) -> dict[str, Any]:
        task_id = str(uuid.uuid4())
        now = utc_now()
        with self.session() as connection:
            connection.execute(
                """
                INSERT INTO supervisor_tasks(
                    id, kind, project_slug, check_name, status, plan_json,
                    result_json, attempt_count, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'planned', ?, '{}', 0, ?, ?)
                """,
                (
                    task_id,
                    kind,
                    project_slug,
                    check_name,
                    canonical_json(plan),
                    now,
                    now,
                ),
            )
        return self.get_supervisor_task(task_id)  # type: ignore[return-value]

    def get_supervisor_task(self, task_id: str) -> dict[str, Any] | None:
        with self.session() as connection:
            row = connection.execute(
                "SELECT * FROM supervisor_tasks WHERE id = ?", (task_id,)
            ).fetchone()
        return self._row(row)

    def list_supervisor_tasks(
        self,
        *,
        status: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM supervisor_tasks"
        parameters: list[Any] = []
        if status is not None:
            sql += " WHERE status = ?"
            parameters.append(status)
        sql += " ORDER BY created_at DESC LIMIT ?"
        parameters.append(limit)
        with self.session() as connection:
            rows = connection.execute(sql, parameters).fetchall()
        return [self._row(row) for row in rows]  # type: ignore[misc]

    def supervisor_task_counts(self) -> dict[str, int]:
        with self.session() as connection:
            rows = connection.execute(
                "SELECT status, COUNT(*) AS n FROM supervisor_tasks GROUP BY status"
            ).fetchall()
        return {str(row["status"]): int(row["n"]) for row in rows}

    def claim_supervisor_task(
        self,
        task_id: str,
        *,
        max_attempts: int,
        runner_pid: int,
        plan_validator: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        now = utc_now()
        with self.session() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                "SELECT * FROM supervisor_tasks WHERE id = ?", (task_id,)
            ).fetchone()
            if current is None:
                raise KeyError(f"Supervisor task not found: {task_id}")
            if current["status"] != "planned":
                raise ValueError(
                    f"Supervisor task {task_id} is {current['status']}, not planned"
                )
            if int(current["attempt_count"]) >= max_attempts:
                raise ValueError(
                    f"Supervisor task {task_id} has reached its attempt limit"
                )
            # The continuity caller checks its persisted plan inside this same
            # transaction, so a stop/revocation cannot race a pre-claim read.
            if plan_validator is not None:
                plan_validator(self._row(current))
            running = connection.execute(
                "SELECT id FROM supervisor_tasks WHERE status = 'running' LIMIT 1"
            ).fetchone()
            if running is not None:
                raise ValueError(
                    f"Supervisor task {running['id']} is already running"
                )
            active_v2 = connection.execute(
                """
                SELECT id FROM supervisor_v2_tasks
                WHERE status IN ('approved', 'preparing', 'executing', 'validating', 'verifying')
                LIMIT 1
                """
            ).fetchone()
            if active_v2 is not None:
                raise ValueError(
                    f"Supervisor v2 task {active_v2['id']} is already active"
                )
            active_v3 = connection.execute(
                """
                SELECT id FROM supervisor_v3_tasks
                WHERE status IN (
                    'approved', 'preparing', 'contacting', 'executing',
                    'validating', 'verifying'
                )
                LIMIT 1
                """
            ).fetchone()
            if active_v3 is not None:
                raise ValueError(
                    f"Supervisor v3 task {active_v3['id']} is already active"
                )
            cursor = connection.execute(
                """
                UPDATE supervisor_tasks
                SET status = 'running', attempt_count = attempt_count + 1,
                    runner_pid = ?, started_at = ?, updated_at = ?
                WHERE id = ? AND status = 'planned'
                """,
                (runner_pid, now, now, task_id),
            )
            if cursor.rowcount != 1:
                raise ValueError(f"Supervisor task {task_id} could not be claimed")
        return self.get_supervisor_task(task_id)  # type: ignore[return-value]

    def finish_supervisor_task(
        self,
        task_id: str,
        *,
        status: str,
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> dict[str, Any]:
        if status not in {"succeeded", "failed", "stopped", "interrupted"}:
            raise ValueError(f"Invalid Supervisor terminal status: {status}")
        now = utc_now()
        with self.session() as connection:
            cursor = connection.execute(
                """
                UPDATE supervisor_tasks
                SET status = ?, result_json = ?, error = ?, runner_pid = NULL,
                    updated_at = ?, completed_at = ?
                WHERE id = ? AND status = 'running'
                """,
                (
                    status,
                    canonical_json(result or {}),
                    error,
                    now,
                    now,
                    task_id,
                ),
            )
            if cursor.rowcount != 1:
                raise ValueError(
                    f"Supervisor task {task_id} is not running and cannot be finished"
                )
        return self.get_supervisor_task(task_id)  # type: ignore[return-value]

    def cancel_supervisor_task(self, task_id: str) -> dict[str, Any]:
        now = utc_now()
        with self.session() as connection:
            cursor = connection.execute(
                """
                UPDATE supervisor_tasks
                SET status = 'cancelled', updated_at = ?, completed_at = ?
                WHERE id = ? AND status = 'planned'
                """,
                (now, now, task_id),
            )
            if cursor.rowcount != 1:
                current = connection.execute(
                    "SELECT status FROM supervisor_tasks WHERE id = ?", (task_id,)
                ).fetchone()
                if current is None:
                    raise KeyError(f"Supervisor task not found: {task_id}")
                raise ValueError(
                    f"Supervisor task {task_id} is {current['status']}, not planned"
                )
        return self.get_supervisor_task(task_id)  # type: ignore[return-value]

    def recover_supervisor_task(self, task_id: str) -> dict[str, Any]:
        now = utc_now()
        with self.session() as connection:
            cursor = connection.execute(
                """
                UPDATE supervisor_tasks
                SET status = 'interrupted', error = 'Recovered manually while paused',
                    runner_pid = NULL, updated_at = ?, completed_at = ?
                WHERE id = ? AND status = 'running'
                """,
                (now, now, task_id),
            )
            if cursor.rowcount != 1:
                current = connection.execute(
                    "SELECT status FROM supervisor_tasks WHERE id = ?", (task_id,)
                ).fetchone()
                if current is None:
                    raise KeyError(f"Supervisor task not found: {task_id}")
                raise ValueError(
                    f"Supervisor task {task_id} is {current['status']}, not running"
                )
        return self.get_supervisor_task(task_id)  # type: ignore[return-value]

    # Supervisor v2 candidate tasks --------------------------------------------

    def create_supervisor_v2_task(
        self,
        *,
        recipe_slug: str,
        project_slug: str,
        plan: dict[str, Any],
        expires_at: str,
    ) -> dict[str, Any]:
        task_id = str(uuid.uuid4())
        now = utc_now()
        transitions = [{"status": "planned", "at": now}]
        with self.session() as connection:
            connection.execute(
                """
                INSERT INTO supervisor_v2_tasks(
                    id, recipe_slug, project_slug, status, plan_json,
                    result_json, transitions_json, attempt_count, created_at,
                    updated_at, expires_at
                ) VALUES (?, ?, ?, 'planned', ?, '{}', ?, 0, ?, ?, ?)
                """,
                (
                    task_id,
                    recipe_slug,
                    project_slug,
                    canonical_json(plan),
                    canonical_json(transitions),
                    now,
                    now,
                    expires_at,
                ),
            )
        return self.get_supervisor_v2_task(task_id)  # type: ignore[return-value]

    def get_supervisor_v2_task(self, task_id: str) -> dict[str, Any] | None:
        with self.session() as connection:
            row = connection.execute(
                "SELECT * FROM supervisor_v2_tasks WHERE id = ?", (task_id,)
            ).fetchone()
        return self._row(row)

    def list_supervisor_v2_tasks(
        self,
        *,
        status: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM supervisor_v2_tasks"
        parameters: list[Any] = []
        if status is not None:
            sql += " WHERE status = ?"
            parameters.append(status)
        sql += " ORDER BY created_at DESC LIMIT ?"
        parameters.append(limit)
        with self.session() as connection:
            rows = connection.execute(sql, parameters).fetchall()
        return [self._row(row) for row in rows]  # type: ignore[misc]

    def supervisor_v2_task_counts(self) -> dict[str, int]:
        with self.session() as connection:
            rows = connection.execute(
                "SELECT status, COUNT(*) AS n FROM supervisor_v2_tasks GROUP BY status"
            ).fetchall()
        return {str(row["status"]): int(row["n"]) for row in rows}

    def supervisor_v2_total_attempts(self) -> int:
        """Return the durable lifetime count of claimed v2 execution attempts."""
        with self.session() as connection:
            row = connection.execute(
                "SELECT COALESCE(SUM(attempt_count), 0) AS n FROM supervisor_v2_tasks"
            ).fetchone()
        return int(row["n"])

    def expire_supervisor_v2_tasks(self, *, now: str | None = None) -> int:
        current = now or utc_now()
        with self.session() as connection:
            rows = connection.execute(
                """
                SELECT id, transitions_json FROM supervisor_v2_tasks
                WHERE status = 'planned' AND expires_at <= ?
                """,
                (current,),
            ).fetchall()
            for row in rows:
                try:
                    transitions = json.loads(row["transitions_json"])
                except (TypeError, json.JSONDecodeError):
                    transitions = []
                transitions.append({"status": "expired", "at": current})
                connection.execute(
                    """
                    UPDATE supervisor_v2_tasks
                    SET status = 'expired', transitions_json = ?, updated_at = ?,
                        completed_at = ?, error = 'Plan expired before execution'
                    WHERE id = ? AND status = 'planned'
                    """,
                    (canonical_json(transitions), current, current, row["id"]),
                )
        return len(rows)

    def cancel_supervisor_v2_task(self, task_id: str) -> dict[str, Any]:
        now = utc_now()
        with self.session() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                "SELECT * FROM supervisor_v2_tasks WHERE id = ?", (task_id,)
            ).fetchone()
            if current is None:
                raise KeyError(f"Supervisor v2 task not found: {task_id}")
            if current["status"] != "planned":
                raise ValueError(
                    f"Supervisor v2 task {task_id} is {current['status']}, not planned"
                )
            transitions = json.loads(current["transitions_json"] or "[]")
            transitions.append({"status": "cancelled", "at": now})
            connection.execute(
                """
                UPDATE supervisor_v2_tasks
                SET status = 'cancelled', transitions_json = ?, updated_at = ?,
                    completed_at = ?
                WHERE id = ? AND status = 'planned'
                """,
                (canonical_json(transitions), now, now, task_id),
            )
        return self.get_supervisor_v2_task(task_id)  # type: ignore[return-value]

    def claim_supervisor_v2_task(
        self,
        task_id: str,
        *,
        max_attempts: int,
        max_total_attempts: int,
        runner_pid: int,
    ) -> dict[str, Any]:
        now = utc_now()
        active_v2 = ("approved", "preparing", "executing", "validating", "verifying")
        with self.session() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                "SELECT * FROM supervisor_v2_tasks WHERE id = ?", (task_id,)
            ).fetchone()
            if current is None:
                raise KeyError(f"Supervisor v2 task not found: {task_id}")
            if current["status"] != "planned":
                raise ValueError(
                    f"Supervisor v2 task {task_id} is {current['status']}, not planned"
                )
            if current["expires_at"] <= now:
                raise ValueError(f"Supervisor v2 task {task_id} has expired")
            if int(current["attempt_count"]) >= max_attempts:
                raise ValueError(f"Supervisor v2 task {task_id} reached its attempt limit")
            total_attempts = connection.execute(
                "SELECT COALESCE(SUM(attempt_count), 0) AS n FROM supervisor_v2_tasks"
            ).fetchone()
            if int(total_attempts["n"]) >= max_total_attempts:
                raise ValueError("Supervisor v2 reached its lifetime live-attempt limit")
            running_v1 = connection.execute(
                "SELECT id FROM supervisor_tasks WHERE status = 'running' LIMIT 1"
            ).fetchone()
            if running_v1 is not None:
                raise ValueError(f"Supervisor task {running_v1['id']} is already running")
            placeholders = ",".join("?" for _ in active_v2)
            running_v2 = connection.execute(
                f"SELECT id FROM supervisor_v2_tasks WHERE status IN ({placeholders}) LIMIT 1",
                active_v2,
            ).fetchone()
            if running_v2 is not None:
                raise ValueError(
                    f"Supervisor v2 task {running_v2['id']} is already active"
                )
            running_v3 = connection.execute(
                """
                SELECT id FROM supervisor_v3_tasks
                WHERE status IN (
                    'approved', 'preparing', 'contacting', 'executing',
                    'validating', 'verifying'
                )
                LIMIT 1
                """
            ).fetchone()
            if running_v3 is not None:
                raise ValueError(
                    f"Supervisor v3 task {running_v3['id']} is already active"
                )
            transitions = json.loads(current["transitions_json"] or "[]")
            transitions.append({"status": "approved", "at": now})
            connection.execute(
                """
                UPDATE supervisor_v2_tasks
                SET status = 'approved', attempt_count = attempt_count + 1,
                    runner_pid = ?, transitions_json = ?, started_at = ?, updated_at = ?
                WHERE id = ? AND status = 'planned'
                """,
                (runner_pid, canonical_json(transitions), now, now, task_id),
            )
        return self.get_supervisor_v2_task(task_id)  # type: ignore[return-value]

    def transition_supervisor_v2_task(
        self,
        task_id: str,
        *,
        expected_statuses: set[str],
        status: str,
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> dict[str, Any]:
        allowed = {
            "approved", "preparing", "executing", "validating", "verifying",
            "candidate_ready", "stopped", "failed", "interrupted",
        }
        if status not in allowed:
            raise ValueError(f"Invalid Supervisor v2 transition target: {status}")
        now = utc_now()
        terminal = status in {"candidate_ready", "stopped", "failed", "interrupted"}
        with self.session() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                "SELECT * FROM supervisor_v2_tasks WHERE id = ?", (task_id,)
            ).fetchone()
            if current is None:
                raise KeyError(f"Supervisor v2 task not found: {task_id}")
            if current["status"] not in expected_statuses:
                raise ValueError(
                    f"Supervisor v2 task {task_id} is {current['status']}; "
                    f"expected one of {sorted(expected_statuses)}"
                )
            transitions = json.loads(current["transitions_json"] or "[]")
            transitions.append({"status": status, "at": now})
            connection.execute(
                """
                UPDATE supervisor_v2_tasks
                SET status = ?, result_json = ?, transitions_json = ?, error = ?,
                    runner_pid = CASE WHEN ? THEN NULL ELSE runner_pid END,
                    updated_at = ?, completed_at = CASE WHEN ? THEN ? ELSE completed_at END
                WHERE id = ?
                """,
                (
                    status,
                    canonical_json(result or {}),
                    canonical_json(transitions),
                    error,
                    terminal,
                    now,
                    terminal,
                    now,
                    task_id,
                ),
            )
        return self.get_supervisor_v2_task(task_id)  # type: ignore[return-value]

    def interrupt_active_supervisor_v2_tasks(self, *, reason: str) -> int:
        """Fail closed on stale active receipts; never resume or retry them."""
        now = utc_now()
        active = ("approved", "preparing", "executing", "validating", "verifying")
        with self.session() as connection:
            connection.execute("BEGIN IMMEDIATE")
            placeholders = ",".join("?" for _ in active)
            rows = connection.execute(
                f"SELECT id, transitions_json FROM supervisor_v2_tasks "
                f"WHERE status IN ({placeholders})",
                active,
            ).fetchall()
            for row in rows:
                try:
                    transitions = json.loads(row["transitions_json"] or "[]")
                except (TypeError, json.JSONDecodeError):
                    transitions = []
                transitions.append({"status": "interrupted", "at": now})
                connection.execute(
                    """
                    UPDATE supervisor_v2_tasks
                    SET status = 'interrupted', transitions_json = ?, error = ?,
                        runner_pid = NULL, updated_at = ?, completed_at = ?
                    WHERE id = ?
                    """,
                    (canonical_json(transitions), reason[:2_000], now, now, row["id"]),
                )
        return len(rows)

    # Supervisor v3 staged pilot tasks ----------------------------------------

    def create_supervisor_v3_task(
        self,
        *,
        stage: str,
        recipe_slug: str | None,
        project_slug: str | None,
        plan: dict[str, Any],
        expires_at: str,
    ) -> dict[str, Any]:
        if stage not in {
            "canary",
            "successor_canary",
            "fixture",
            "recovery_canary",
            "recovery_fixture",
        }:
            raise ValueError(f"Invalid Supervisor v3 stage: {stage}")
        if (
            stage in {"canary", "successor_canary"}
            and (recipe_slug is not None or project_slug is not None)
        ) or (
            stage in {"fixture", "recovery_canary", "recovery_fixture"}
            and (not recipe_slug or not project_slug)
        ):
            raise ValueError("Supervisor v3 task fields do not match the stage")
        task_id = str(uuid.uuid4())
        now = utc_now()
        transitions = [{"status": "planned", "at": now}]
        with self.session() as connection:
            connection.execute("BEGIN IMMEDIATE")
            active = connection.execute(
                """
                SELECT id FROM supervisor_v3_tasks
                WHERE stage = ? AND status = 'planned' AND expires_at > ?
                ORDER BY created_at DESC LIMIT 1
                """,
                (stage, now),
            ).fetchone()
            if active is not None:
                task_id = str(active["id"])
            else:
                connection.execute(
                    """
                    INSERT INTO supervisor_v3_tasks(
                        id, stage, recipe_slug, project_slug, driver, status,
                        plan_json, result_json, transitions_json, attempt_count,
                        model_contacted, envelope_count, created_at, updated_at,
                        expires_at
                    ) VALUES (?, ?, ?, ?, 'python_sdk', 'planned', ?, '{}', ?, 0, 0, 0, ?, ?, ?)
                    """,
                    (
                        task_id,
                        stage,
                        recipe_slug,
                        project_slug,
                        canonical_json(plan),
                        canonical_json(transitions),
                        now,
                        now,
                        expires_at,
                    ),
                )
        return self.get_supervisor_v3_task(task_id)  # type: ignore[return-value]

    def active_supervisor_v3_plan(self, stage: str) -> dict[str, Any] | None:
        now = utc_now()
        with self.session() as connection:
            row = connection.execute(
                """
                SELECT * FROM supervisor_v3_tasks
                WHERE stage = ? AND status = 'planned' AND expires_at > ?
                ORDER BY created_at DESC LIMIT 1
                """,
                (stage, now),
            ).fetchone()
        result = self._row(row)
        if result is not None:
            result["model_contacted"] = bool(result.get("model_contacted"))
        return result

    def get_supervisor_v3_task(self, task_id: str) -> dict[str, Any] | None:
        with self.session() as connection:
            row = connection.execute(
                "SELECT * FROM supervisor_v3_tasks WHERE id = ?", (task_id,)
            ).fetchone()
        result = self._row(row)
        if result is not None:
            result["model_contacted"] = bool(result.get("model_contacted"))
        return result

    def list_supervisor_v3_tasks(
        self,
        *,
        status: str | None = None,
        stage: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        parameters: list[Any] = []
        if status:
            clauses.append("status = ?")
            parameters.append(status)
        if stage:
            clauses.append("stage = ?")
            parameters.append(stage)
        sql = "SELECT * FROM supervisor_v3_tasks"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY created_at DESC LIMIT ?"
        parameters.append(limit)
        with self.session() as connection:
            rows = connection.execute(sql, parameters).fetchall()
        results = [self._row(row) for row in rows]
        for result in results:
            if result is not None:
                result["model_contacted"] = bool(result.get("model_contacted"))
        return results  # type: ignore[return-value]

    def supervisor_v3_task_counts(self) -> dict[str, int]:
        with self.session() as connection:
            rows = connection.execute(
                "SELECT status, COUNT(*) AS n FROM supervisor_v3_tasks GROUP BY status"
            ).fetchall()
        return {str(row["status"]): int(row["n"]) for row in rows}

    def supervisor_v3_stage_attempts(self, stage: str) -> int:
        if stage not in {
            "canary",
            "successor_canary",
            "fixture",
            "recovery_canary",
            "recovery_fixture",
        }:
            raise ValueError(f"Invalid Supervisor v3 stage: {stage}")
        with self.session() as connection:
            row = connection.execute(
                """
                SELECT COALESCE(SUM(attempt_count), 0) AS n
                FROM supervisor_v3_tasks WHERE stage = ?
                """,
                (stage,),
            ).fetchone()
        return int(row["n"])

    def supervisor_v3_any_model_contacted(self) -> bool:
        with self.session() as connection:
            row = connection.execute(
                "SELECT EXISTS(SELECT 1 FROM supervisor_v3_tasks WHERE model_contacted = 1) AS yes"
            ).fetchone()
        return bool(row["yes"])

    def latest_supervisor_v3_canary_pass(self) -> dict[str, Any] | None:
        with self.session() as connection:
            row = connection.execute(
                """
                SELECT * FROM supervisor_v3_tasks
                WHERE stage = 'canary' AND status = 'canary_passed'
                ORDER BY completed_at DESC LIMIT 1
                """
            ).fetchone()
        result = self._row(row)
        if result is not None:
            result["model_contacted"] = bool(result.get("model_contacted"))
        return result

    def latest_supervisor_v3_successor_canary_pass(self) -> dict[str, Any] | None:
        with self.session() as connection:
            row = connection.execute(
                """
                SELECT * FROM supervisor_v3_tasks
                WHERE stage = 'successor_canary' AND status = 'canary_passed'
                ORDER BY completed_at DESC LIMIT 1
                """
            ).fetchone()
        result = self._row(row)
        if result is not None:
            result["model_contacted"] = bool(result.get("model_contacted"))
        return result

    def latest_supervisor_v3_recovery_canary_pass(self) -> dict[str, Any] | None:
        with self.session() as connection:
            row = connection.execute(
                """
                SELECT * FROM supervisor_v3_tasks
                WHERE stage = 'recovery_canary' AND status = 'canary_passed'
                ORDER BY completed_at DESC LIMIT 1
                """
            ).fetchone()
        result = self._row(row)
        if result is not None:
            result["model_contacted"] = bool(result.get("model_contacted"))
        return result

    def expire_supervisor_v3_tasks(self, *, now: str | None = None) -> int:
        current = now or utc_now()
        with self.session() as connection:
            rows = connection.execute(
                """
                SELECT id, transitions_json FROM supervisor_v3_tasks
                WHERE status = 'planned' AND expires_at <= ?
                """,
                (current,),
            ).fetchall()
            for row in rows:
                try:
                    transitions = json.loads(row["transitions_json"] or "[]")
                except (TypeError, json.JSONDecodeError):
                    transitions = []
                transitions.append({"status": "expired", "at": current})
                connection.execute(
                    """
                    UPDATE supervisor_v3_tasks
                    SET status = 'expired', transitions_json = ?, updated_at = ?,
                        completed_at = ?, error = 'Plan expired before execution',
                        stop_code = 'plan_expired'
                    WHERE id = ? AND status = 'planned'
                    """,
                    (canonical_json(transitions), current, current, row["id"]),
                )
        return len(rows)

    def cancel_supervisor_v3_task(self, task_id: str) -> dict[str, Any]:
        now = utc_now()
        with self.session() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                "SELECT * FROM supervisor_v3_tasks WHERE id = ?", (task_id,)
            ).fetchone()
            if current is None:
                raise KeyError(f"Supervisor v3 task not found: {task_id}")
            if current["status"] != "planned":
                raise ValueError(
                    f"Supervisor v3 task {task_id} is {current['status']}, not planned"
                )
            transitions = json.loads(current["transitions_json"] or "[]")
            transitions.append({"status": "cancelled", "at": now})
            connection.execute(
                """
                UPDATE supervisor_v3_tasks
                SET status = 'cancelled', transitions_json = ?, updated_at = ?,
                    completed_at = ?, stop_code = 'cancelled_by_owner'
                WHERE id = ? AND status = 'planned'
                """,
                (canonical_json(transitions), now, now, task_id),
            )
        return self.get_supervisor_v3_task(task_id)  # type: ignore[return-value]

    def claim_supervisor_v3_task(
        self,
        task_id: str,
        *,
        max_attempts_per_stage: int,
        max_total_attempts: int,
        runner_pid: int,
    ) -> dict[str, Any]:
        now = utc_now()
        active_v2 = ("approved", "preparing", "executing", "validating", "verifying")
        active_v3 = (
            "approved",
            "preparing",
            "contacting",
            "executing",
            "validating",
            "verifying",
        )
        with self.session() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                "SELECT * FROM supervisor_v3_tasks WHERE id = ?", (task_id,)
            ).fetchone()
            if current is None:
                raise KeyError(f"Supervisor v3 task not found: {task_id}")
            if current["status"] != "planned":
                raise ValueError(
                    f"Supervisor v3 task {task_id} is {current['status']}, not planned"
                )
            if current["expires_at"] <= now:
                raise ValueError(f"Supervisor v3 task {task_id} has expired")
            if int(current["attempt_count"]) >= max_attempts_per_stage:
                raise ValueError(f"Supervisor v3 task {task_id} reached its attempt limit")
            attempts = connection.execute(
                """
                SELECT COALESCE(SUM(attempt_count), 0) AS n
                FROM supervisor_v3_tasks WHERE stage = ?
                """,
                (current["stage"],),
            ).fetchone()
            if int(attempts["n"]) >= max_total_attempts:
                raise ValueError(
                    f"Supervisor v3 {current['stage']} lifetime attempt limit is exhausted"
                )
            if current["stage"] == "fixture":
                canary = connection.execute(
                    """
                    SELECT id FROM supervisor_v3_tasks
                    WHERE stage = 'successor_canary' AND status = 'canary_passed'
                    LIMIT 1
                    """
                ).fetchone()
                if canary is None:
                    raise ValueError(
                        "Supervisor v3 fixture requires a passed successor canary"
                    )
            if current["stage"] == "recovery_canary":
                failed_fixture = connection.execute(
                    """
                    SELECT id FROM supervisor_v3_tasks
                    WHERE stage = 'fixture' AND status = 'failed' AND attempt_count = 1
                    LIMIT 1
                    """
                ).fetchone()
                if failed_fixture is None:
                    raise ValueError(
                        "Supervisor v3 recovery canary requires a failed fixture"
                    )
            if current["stage"] == "recovery_fixture":
                recovery_canary = connection.execute(
                    """
                    SELECT id FROM supervisor_v3_tasks
                    WHERE stage = 'recovery_canary' AND status = 'canary_passed'
                    LIMIT 1
                    """
                ).fetchone()
                if recovery_canary is None:
                    raise ValueError(
                        "Supervisor v3 recovery fixture requires a passed recovery canary"
                    )
            running_v1 = connection.execute(
                "SELECT id FROM supervisor_tasks WHERE status = 'running' LIMIT 1"
            ).fetchone()
            if running_v1 is not None:
                raise ValueError(f"Supervisor task {running_v1['id']} is already running")
            placeholders_v2 = ",".join("?" for _ in active_v2)
            running_v2 = connection.execute(
                f"SELECT id FROM supervisor_v2_tasks WHERE status IN ({placeholders_v2}) LIMIT 1",
                active_v2,
            ).fetchone()
            if running_v2 is not None:
                raise ValueError(f"Supervisor v2 task {running_v2['id']} is already active")
            placeholders_v3 = ",".join("?" for _ in active_v3)
            running_v3 = connection.execute(
                f"SELECT id FROM supervisor_v3_tasks WHERE status IN ({placeholders_v3}) LIMIT 1",
                active_v3,
            ).fetchone()
            if running_v3 is not None:
                raise ValueError(f"Supervisor v3 task {running_v3['id']} is already active")
            transitions = json.loads(current["transitions_json"] or "[]")
            transitions.append({"status": "approved", "at": now})
            cursor = connection.execute(
                """
                UPDATE supervisor_v3_tasks
                SET status = 'approved', attempt_count = attempt_count + 1,
                    runner_pid = ?, transitions_json = ?, started_at = ?, updated_at = ?
                WHERE id = ? AND status = 'planned'
                """,
                (runner_pid, canonical_json(transitions), now, now, task_id),
            )
            if cursor.rowcount != 1:
                raise ValueError(f"Supervisor v3 task {task_id} could not be claimed")
        return self.get_supervisor_v3_task(task_id)  # type: ignore[return-value]

    def transition_supervisor_v3_task(
        self,
        task_id: str,
        *,
        expected_statuses: set[str],
        status: str,
        result: dict[str, Any] | None = None,
        error: str | None = None,
        stop_code: str | None = None,
        model_contacted: bool = False,
        envelope_count: int = 0,
        envelope_chain_sha256: str | None = None,
    ) -> dict[str, Any]:
        allowed = {
            "approved",
            "preparing",
            "contacting",
            "executing",
            "validating",
            "verifying",
            "canary_passed",
            "candidate_ready",
            "stopped",
            "failed",
            "interrupted",
        }
        if status not in allowed:
            raise ValueError(f"Invalid Supervisor v3 transition target: {status}")
        if envelope_count < 0 or (
            envelope_chain_sha256 is not None
            and not re.fullmatch(r"[0-9a-f]{64}", envelope_chain_sha256)
        ):
            raise ValueError("Invalid Supervisor v3 envelope metadata")
        now = utc_now()
        terminal = status in {
            "canary_passed",
            "candidate_ready",
            "stopped",
            "failed",
            "interrupted",
        }
        with self.session() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                "SELECT * FROM supervisor_v3_tasks WHERE id = ?", (task_id,)
            ).fetchone()
            if current is None:
                raise KeyError(f"Supervisor v3 task not found: {task_id}")
            if current["status"] not in expected_statuses:
                raise ValueError(
                    f"Supervisor v3 task {task_id} is {current['status']}; "
                    f"expected one of {sorted(expected_statuses)}"
                )
            stage_transitions = {
                "canary": {
                    "approved": {"preparing", "stopped", "failed", "interrupted"},
                    "preparing": {"contacting", "stopped", "failed", "interrupted"},
                    "contacting": {"validating", "stopped", "failed", "interrupted"},
                    "validating": {"canary_passed", "stopped", "failed", "interrupted"},
                },
                "successor_canary": {
                    "approved": {"preparing", "stopped", "failed", "interrupted"},
                    "preparing": {"contacting", "stopped", "failed", "interrupted"},
                    "contacting": {"validating", "stopped", "failed", "interrupted"},
                    "validating": {"canary_passed", "stopped", "failed", "interrupted"},
                },
                "recovery_canary": {
                    "approved": {"preparing", "stopped", "failed", "interrupted"},
                    "preparing": {"contacting", "stopped", "failed", "interrupted"},
                    "contacting": {"validating", "stopped", "failed", "interrupted"},
                    "validating": {"canary_passed", "stopped", "failed", "interrupted"},
                },
                "fixture": {
                    "approved": {"preparing", "stopped", "failed", "interrupted"},
                    "preparing": {"executing", "stopped", "failed", "interrupted"},
                    "executing": {"validating", "stopped", "failed", "interrupted"},
                    "validating": {"verifying", "stopped", "failed", "interrupted"},
                    "verifying": {"candidate_ready", "stopped", "failed", "interrupted"},
                },
                "recovery_fixture": {
                    "approved": {"preparing", "stopped", "failed", "interrupted"},
                    "preparing": {"executing", "stopped", "failed", "interrupted"},
                    "executing": {"validating", "stopped", "failed", "interrupted"},
                    "validating": {"verifying", "stopped", "failed", "interrupted"},
                    "verifying": {"candidate_ready", "stopped", "failed", "interrupted"},
                },
            }
            permitted = stage_transitions[str(current["stage"])].get(
                str(current["status"]), set()
            )
            if status not in permitted:
                raise ValueError(
                    f"Invalid Supervisor v3 {current['stage']} transition: "
                    f"{current['status']} -> {status}"
                )
            transitions = json.loads(current["transitions_json"] or "[]")
            transitions.append({"status": status, "at": now})
            connection.execute(
                """
                UPDATE supervisor_v3_tasks
                SET status = ?, result_json = ?, transitions_json = ?, error = ?,
                    stop_code = ?, model_contacted = CASE
                        WHEN model_contacted = 1 OR ? = 1 THEN 1 ELSE 0 END,
                    envelope_count = ?, envelope_chain_sha256 = ?,
                    runner_pid = CASE WHEN ? THEN NULL ELSE runner_pid END,
                    updated_at = ?, completed_at = CASE WHEN ? THEN ? ELSE completed_at END
                WHERE id = ?
                """,
                (
                    status,
                    canonical_json(result or {}),
                    canonical_json(transitions),
                    error[:2_000] if error else None,
                    stop_code[:200] if stop_code else None,
                    model_contacted,
                    envelope_count,
                    envelope_chain_sha256,
                    terminal,
                    now,
                    terminal,
                    now,
                    task_id,
                ),
            )
        return self.get_supervisor_v3_task(task_id)  # type: ignore[return-value]

    def record_supervisor_v3_protocol_receipt(
        self,
        task_id: str,
        *,
        expected_statuses: set[str],
        model_contacted: bool,
        envelope_count: int,
        envelope_chain_sha256: str | None,
    ) -> dict[str, Any]:
        """Persist bounded protocol evidence before interpreting worker success."""

        if envelope_count < 0 or (
            envelope_chain_sha256 is not None
            and not re.fullmatch(r"[0-9a-f]{64}", envelope_chain_sha256)
        ):
            raise ValueError("Invalid Supervisor v3 envelope metadata")
        now = utc_now()
        with self.session() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                "SELECT status FROM supervisor_v3_tasks WHERE id = ?", (task_id,)
            ).fetchone()
            if current is None:
                raise KeyError(f"Supervisor v3 task not found: {task_id}")
            if current["status"] not in expected_statuses:
                raise ValueError(
                    f"Supervisor v3 task {task_id} is {current['status']}; "
                    f"expected one of {sorted(expected_statuses)}"
                )
            connection.execute(
                """
                UPDATE supervisor_v3_tasks
                SET model_contacted = CASE
                        WHEN model_contacted = 1 OR ? = 1 THEN 1 ELSE 0 END,
                    envelope_count = ?, envelope_chain_sha256 = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    model_contacted,
                    envelope_count,
                    envelope_chain_sha256,
                    now,
                    task_id,
                ),
            )
        return self.get_supervisor_v3_task(task_id)  # type: ignore[return-value]

    def interrupt_active_supervisor_v3_tasks(self, *, reason: str) -> int:
        now = utc_now()
        active = (
            "approved",
            "preparing",
            "contacting",
            "executing",
            "validating",
            "verifying",
        )
        with self.session() as connection:
            connection.execute("BEGIN IMMEDIATE")
            placeholders = ",".join("?" for _ in active)
            rows = connection.execute(
                f"SELECT id, transitions_json FROM supervisor_v3_tasks "
                f"WHERE status IN ({placeholders})",
                active,
            ).fetchall()
            for row in rows:
                try:
                    transitions = json.loads(row["transitions_json"] or "[]")
                except (TypeError, json.JSONDecodeError):
                    transitions = []
                transitions.append({"status": "interrupted", "at": now})
                connection.execute(
                    """
                    UPDATE supervisor_v3_tasks
                    SET status = 'interrupted', transitions_json = ?, error = ?,
                        stop_code = 'startup_reconciliation', runner_pid = NULL,
                        updated_at = ?, completed_at = ?
                    WHERE id = ?
                    """,
                    (canonical_json(transitions), reason[:2_000], now, now, row["id"]),
                )
        return len(rows)

    # Supervisor v4 inactive/offline append-only ledger ------------------------

    @staticmethod
    def _supervisor_v4_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        result = dict(row)
        for key in (
            "content_json",
            "definition_json",
            "details_json",
            "scope_json",
            "public_metadata_json",
        ):
            if key not in result:
                continue
            target = key.removesuffix("_json")
            try:
                result[target] = json.loads(result.pop(key))
            except (json.JSONDecodeError, TypeError):
                result[target] = {}
                result.pop(key, None)
        return result

    @staticmethod
    def _supervisor_v4_label(value: str, *, field: str, maximum: int = 128) -> str:
        if not isinstance(value, str) or not re.fullmatch(
            rf"[A-Za-z0-9][A-Za-z0-9_.:-]{{0,{maximum - 1}}}", value
        ):
            raise ValueError(f"Supervisor v4 {field} is invalid")
        return value

    def record_supervisor_v4_qualification(
        self,
        *,
        subject: str,
        status: str,
        content: dict[str, Any] | None = None,
        created_at: str | None = None,
    ) -> dict[str, Any]:
        """Append an inactive or no-model qualification record."""

        self._supervisor_v4_label(subject, field="qualification subject", maximum=160)
        if status not in {"inactive", "offline_qualified", "offline_failed"}:
            raise ValueError("Supervisor v4 qualification status is invalid")
        observed_at = created_at or utc_now()
        _supervisor_v4_parse_timestamp(observed_at)
        content_json, content_sha256 = _supervisor_v4_content(content)
        qualification_id = str(uuid.uuid4())
        with self.session() as connection:
            connection.execute(
                """
                INSERT INTO supervisor_v4_qualifications(
                    id, subject, status, content_json, content_sha256, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    qualification_id,
                    subject,
                    status,
                    content_json,
                    content_sha256,
                    observed_at,
                ),
            )
        return self.get_supervisor_v4_qualification(qualification_id)  # type: ignore[return-value]

    def record_supervisor_v4_qualification_if_heads(
        self,
        *,
        subject: str,
        status: str,
        content: dict[str, Any] | None = None,
        expected_heads: Mapping[str, str | None],
        created_at: str | None = None,
    ) -> dict[str, Any]:
        """Atomically append only when every named qualification head matches."""

        self._supervisor_v4_label(subject, field="qualification subject", maximum=160)
        if status not in {"inactive", "offline_qualified", "offline_failed"}:
            raise ValueError("Supervisor v4 qualification status is invalid")
        if not isinstance(expected_heads, Mapping) or not 1 <= len(expected_heads) <= 8:
            raise ValueError("Supervisor v4 qualification head set is invalid")
        normalized_heads: dict[str, str | None] = {}
        for head_subject, expected_id in expected_heads.items():
            self._supervisor_v4_label(
                head_subject, field="qualification subject", maximum=160
            )
            if expected_id is not None:
                try:
                    expected_id = str(uuid.UUID(expected_id))
                except (ValueError, AttributeError) as error:
                    raise ValueError(
                        "Supervisor v4 qualification head ID is invalid"
                    ) from error
            normalized_heads[head_subject] = expected_id
        observed_at = created_at or utc_now()
        _supervisor_v4_parse_timestamp(observed_at)
        content_json, content_sha256 = _supervisor_v4_content(content)
        qualification_id = str(uuid.uuid4())
        with self.session() as connection:
            connection.execute("BEGIN IMMEDIATE")
            for head_subject, expected_id in sorted(normalized_heads.items()):
                row = connection.execute(
                    """
                    SELECT id FROM supervisor_v4_qualifications
                    WHERE subject = ? ORDER BY created_at DESC, id DESC LIMIT 1
                    """,
                    (head_subject,),
                ).fetchone()
                actual_id = None if row is None else str(row["id"])
                if actual_id != expected_id:
                    raise ValueError(
                        "Supervisor v4 qualification ledger head changed"
                    )
            connection.execute(
                """
                INSERT INTO supervisor_v4_qualifications(
                    id, subject, status, content_json, content_sha256, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    qualification_id,
                    subject,
                    status,
                    content_json,
                    content_sha256,
                    observed_at,
                ),
            )
            row = connection.execute(
                "SELECT * FROM supervisor_v4_qualifications WHERE id = ?",
                (qualification_id,),
            ).fetchone()
            result = self._supervisor_v4_row(row)
        if result is None:  # pragma: no cover - protected by insert/select
            raise RuntimeError("Supervisor v4 qualification was not recorded")
        return result

    def record_supervisor_v4_qualification_once(
        self,
        *,
        subject: str,
        status: str,
        content: dict[str, Any] | None = None,
        created_at: str | None = None,
    ) -> dict[str, Any]:
        """Append one exact inactive qualification, or return its exact match.

        This is intentionally stricter than the general qualification ledger:
        a subject may have only one row, and an existing row must match the
        requested status, normalized content, digest, and zero-authority bit.
        ``BEGIN IMMEDIATE`` makes the absence check and append one transaction.
        """

        self._supervisor_v4_label(subject, field="qualification subject", maximum=160)
        if status not in {"inactive", "offline_qualified", "offline_failed"}:
            raise ValueError("Supervisor v4 qualification status is invalid")
        observed_at = created_at or utc_now()
        _supervisor_v4_parse_timestamp(observed_at)
        content_json, content_sha256 = _supervisor_v4_content(content)
        qualification_id = str(uuid.uuid4())
        with self.session() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                """
                SELECT * FROM supervisor_v4_qualifications
                WHERE subject = ? ORDER BY created_at ASC, id ASC
                """,
                (subject,),
            ).fetchall()
            if len(rows) > 1:
                raise ValueError(
                    "Supervisor v4 one-shot qualification subject has duplicate rows"
                )
            if rows:
                row = rows[0]
                if (
                    row["status"] != status
                    or row["content_json"] != content_json
                    or row["content_sha256"] != content_sha256
                    or int(row["authority_granted"]) != 0
                ):
                    raise ValueError(
                        "Supervisor v4 one-shot qualification does not match existing evidence"
                    )
                result = self._supervisor_v4_row(row)
            else:
                connection.execute(
                    """
                    INSERT INTO supervisor_v4_qualifications(
                        id, subject, status, content_json, content_sha256, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        qualification_id,
                        subject,
                        status,
                        content_json,
                        content_sha256,
                        observed_at,
                    ),
                )
                row = connection.execute(
                    "SELECT * FROM supervisor_v4_qualifications WHERE id = ?",
                    (qualification_id,),
                ).fetchone()
                result = self._supervisor_v4_row(row)
        if result is None:  # pragma: no cover - protected by the insert/select pair
            raise RuntimeError("Supervisor v4 one-shot qualification was not recorded")
        return result

    def record_supervisor_v4_qualification_once_if_heads(
        self,
        *,
        subject: str,
        status: str,
        content: dict[str, Any] | None = None,
        expected_heads: Mapping[str, str | None],
        created_at: str | None = None,
    ) -> dict[str, Any]:
        """Append one exact record only while predecessor heads remain fixed.

        This combines the idempotence and zero-authority checks of
        ``record_supervisor_v4_qualification_once`` with the atomic predecessor
        comparison of ``record_supervisor_v4_qualification_if_heads``.
        """

        self._supervisor_v4_label(subject, field="qualification subject", maximum=160)
        if status not in {"inactive", "offline_qualified", "offline_failed"}:
            raise ValueError("Supervisor v4 qualification status is invalid")
        if not isinstance(expected_heads, Mapping) or not 1 <= len(expected_heads) <= 8:
            raise ValueError("Supervisor v4 qualification head set is invalid")
        normalized_heads: dict[str, str | None] = {}
        for head_subject, expected_id in expected_heads.items():
            self._supervisor_v4_label(
                head_subject, field="qualification subject", maximum=160
            )
            if head_subject == subject:
                raise ValueError(
                    "Supervisor v4 one-shot target cannot be its own predecessor head"
                )
            if expected_id is not None:
                try:
                    expected_id = str(uuid.UUID(expected_id))
                except (ValueError, AttributeError) as error:
                    raise ValueError(
                        "Supervisor v4 qualification head ID is invalid"
                    ) from error
            normalized_heads[head_subject] = expected_id
        observed_at = created_at or utc_now()
        _supervisor_v4_parse_timestamp(observed_at)
        content_json, content_sha256 = _supervisor_v4_content(content)
        qualification_id = str(uuid.uuid4())
        with self.session() as connection:
            connection.execute("BEGIN IMMEDIATE")
            for head_subject, expected_id in sorted(normalized_heads.items()):
                rows = connection.execute(
                    """
                    SELECT id FROM supervisor_v4_qualifications
                    WHERE subject = ? ORDER BY created_at DESC, id DESC
                    """,
                    (head_subject,),
                ).fetchall()
                exact = (
                    len(rows) == 0
                    if expected_id is None
                    else len(rows) == 1 and str(rows[0]["id"]) == expected_id
                )
                if not exact:
                    raise ValueError(
                        "Supervisor v4 qualification ledger head changed"
                    )
            rows = connection.execute(
                """
                SELECT * FROM supervisor_v4_qualifications
                WHERE subject = ? ORDER BY created_at ASC, id ASC
                """,
                (subject,),
            ).fetchall()
            if len(rows) > 1:
                raise ValueError(
                    "Supervisor v4 one-shot qualification subject has duplicate rows"
                )
            if rows:
                row = rows[0]
                if (
                    row["status"] != status
                    or row["content_json"] != content_json
                    or row["content_sha256"] != content_sha256
                    or int(row["authority_granted"]) != 0
                ):
                    raise ValueError(
                        "Supervisor v4 one-shot qualification does not match existing evidence"
                    )
                result = self._supervisor_v4_row(row)
            else:
                connection.execute(
                    """
                    INSERT INTO supervisor_v4_qualifications(
                        id, subject, status, content_json, content_sha256, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        qualification_id,
                        subject,
                        status,
                        content_json,
                        content_sha256,
                        observed_at,
                    ),
                )
                row = connection.execute(
                    "SELECT * FROM supervisor_v4_qualifications WHERE id = ?",
                    (qualification_id,),
                ).fetchone()
                result = self._supervisor_v4_row(row)
        if result is None:  # pragma: no cover - protected by insert/select pair
            raise RuntimeError("Supervisor v4 one-shot qualification was not recorded")
        return result

    def get_supervisor_v4_qualification(
        self, qualification_id: str
    ) -> dict[str, Any] | None:
        with self.session() as connection:
            row = connection.execute(
                "SELECT * FROM supervisor_v4_qualifications WHERE id = ?",
                (qualification_id,),
            ).fetchone()
        return self._supervisor_v4_row(row)

    def list_supervisor_v4_qualifications(
        self, *, subject: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        if not 1 <= limit <= 10_000:
            raise ValueError("Supervisor v4 qualification limit is invalid")
        sql = "SELECT * FROM supervisor_v4_qualifications"
        parameters: list[Any] = []
        if subject is not None:
            self._supervisor_v4_label(subject, field="qualification subject", maximum=160)
            sql += " WHERE subject = ?"
            parameters.append(subject)
        sql += " ORDER BY created_at DESC, id DESC LIMIT ?"
        parameters.append(limit)
        with self.session() as connection:
            rows = connection.execute(sql, parameters).fetchall()
        return [self._supervisor_v4_row(row) for row in rows]  # type: ignore[misc]

    def create_supervisor_v4_offline_job(
        self,
        *,
        qualification_id: str | None = None,
        definition: dict[str, Any] | None = None,
        created_at: str | None = None,
    ) -> dict[str, Any]:
        """Create an inert offline-qualification job with no execution route."""

        observed_at = created_at or utc_now()
        _supervisor_v4_parse_timestamp(observed_at)
        definition_value = dict(definition or {})
        if definition_value.get("model_contact_allowed") not in (None, False):
            raise ValueError("Supervisor v4 offline jobs cannot allow model contact")
        if definition_value.get("authority_granted") not in (None, False):
            raise ValueError("Supervisor v4 offline jobs cannot grant authority")
        definition_value["model_contact_allowed"] = False
        definition_value["authority_granted"] = False
        definition_json, definition_sha256 = _supervisor_v4_content(definition_value)
        details_json, details_sha256 = _supervisor_v4_content(
            {"authority": "offline_only", "model_contact": "not_dispatched"}
        )
        job_id = str(uuid.uuid4())
        with self.session() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if qualification_id is not None:
                exists = connection.execute(
                    "SELECT 1 FROM supervisor_v4_qualifications WHERE id = ?",
                    (qualification_id,),
                ).fetchone()
                if exists is None:
                    raise KeyError(
                        f"Supervisor v4 qualification not found: {qualification_id}"
                    )
            connection.execute(
                """
                INSERT INTO supervisor_v4_jobs(
                    id, kind, qualification_id, definition_json,
                    definition_sha256, created_at
                ) VALUES (?, 'offline_qualification', ?, ?, ?, ?)
                """,
                (
                    job_id,
                    qualification_id,
                    definition_json,
                    definition_sha256,
                    observed_at,
                ),
            )
            connection.execute(
                """
                INSERT INTO supervisor_v4_job_transitions(
                    job_id, job_sequence, state, model_contact_state,
                    details_json, details_sha256, recorded_at
                ) VALUES (?, 1, 'inactive', 'not_dispatched', ?, ?, ?)
                """,
                (job_id, details_json, details_sha256, observed_at),
            )
        return self.get_supervisor_v4_job(job_id)  # type: ignore[return-value]

    def get_supervisor_v4_job(self, job_id: str) -> dict[str, Any] | None:
        with self.session() as connection:
            job = connection.execute(
                "SELECT * FROM supervisor_v4_jobs WHERE id = ?", (job_id,)
            ).fetchone()
            transition = connection.execute(
                """
                SELECT * FROM supervisor_v4_job_transitions
                WHERE job_id = ? ORDER BY job_sequence DESC LIMIT 1
                """,
                (job_id,),
            ).fetchone()
        result = self._supervisor_v4_row(job)
        if result is None:
            return None
        latest = self._supervisor_v4_row(transition)
        result["latest_transition"] = latest
        if latest is not None:
            result["state"] = latest["state"]
            result["model_contact_state"] = latest["model_contact_state"]
        return result

    def list_supervisor_v4_jobs(self, *, limit: int = 10_000) -> list[dict[str, Any]]:
        if not 1 <= limit <= 100_000:
            raise ValueError("Supervisor v4 job limit is invalid")
        with self.session() as connection:
            rows = connection.execute(
                "SELECT id FROM supervisor_v4_jobs ORDER BY created_at ASC, id ASC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            job
            for row in rows
            if (job := self.get_supervisor_v4_job(str(row["id"]))) is not None
        ]

    def list_supervisor_v4_job_transitions(self, job_id: str) -> list[dict[str, Any]]:
        with self.session() as connection:
            exists = connection.execute(
                "SELECT 1 FROM supervisor_v4_jobs WHERE id = ?", (job_id,)
            ).fetchone()
            if exists is None:
                raise KeyError(f"Supervisor v4 job not found: {job_id}")
            rows = connection.execute(
                """
                SELECT * FROM supervisor_v4_job_transitions
                WHERE job_id = ? ORDER BY job_sequence ASC
                """,
                (job_id,),
            ).fetchall()
        return [self._supervisor_v4_row(row) for row in rows]  # type: ignore[misc]

    def transition_supervisor_v4_offline_job(
        self,
        job_id: str,
        *,
        state: str,
        model_contact_state: str | None = None,
        worker_identity: dict[str, Any] | None = None,
        details: dict[str, Any] | None = None,
        recorded_at: str | None = None,
    ) -> dict[str, Any]:
        """Append one validated offline transition; never start or resume work."""

        if state not in _SUPERVISOR_V4_OFFLINE_TRANSITIONS:
            raise ValueError("Supervisor v4 offline transition target is invalid")
        observed_at = recorded_at or utc_now()
        _supervisor_v4_parse_timestamp(observed_at)
        identity = dict(worker_identity or {})
        identity_fields = {
            "worker_id",
            "worker_pid",
            "worker_start_token",
            "process_group_id",
            "process_group_start_token",
            "executable_sha256",
        }
        if set(identity) - identity_fields:
            raise ValueError("Supervisor v4 worker identity contains unknown fields")
        if identity and set(identity) != identity_fields:
            raise ValueError("Supervisor v4 worker identity must be complete")
        if state == "offline_qualifying" and set(identity) != identity_fields:
            raise ValueError(
                "Supervisor v4 active offline work requires complete reconciliation identity"
            )
        if identity:
            self._supervisor_v4_label(
                str(identity["worker_id"]), field="worker identity", maximum=160
            )
            for field in ("worker_pid", "process_group_id"):
                value = identity[field]
                if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                    raise ValueError(f"Supervisor v4 {field} is invalid")
            for field in ("worker_start_token", "process_group_start_token"):
                value = identity[field]
                if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 256:
                    raise ValueError(f"Supervisor v4 {field} is invalid")
            if not re.fullmatch(r"[0-9a-f]{64}", str(identity["executable_sha256"])):
                raise ValueError("Supervisor v4 executable digest is invalid")
        details_json, details_sha256 = _supervisor_v4_content(details)
        with self.session() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                """
                SELECT * FROM supervisor_v4_job_transitions
                WHERE job_id = ? ORDER BY job_sequence DESC LIMIT 1
                """,
                (job_id,),
            ).fetchone()
            if current is None:
                exists = connection.execute(
                    "SELECT 1 FROM supervisor_v4_jobs WHERE id = ?", (job_id,)
                ).fetchone()
                if exists is None:
                    raise KeyError(f"Supervisor v4 job not found: {job_id}")
                raise ValueError("Supervisor v4 job has no initial transition")
            current_state = str(current["state"])
            if state not in _SUPERVISOR_V4_OFFLINE_TRANSITIONS[current_state]:
                raise ValueError(
                    f"Invalid Supervisor v4 offline transition: {current_state} -> {state}"
                )
            current_contact = str(current["model_contact_state"])
            next_contact = model_contact_state or current_contact
            if next_contact not in _SUPERVISOR_V4_MODEL_CONTACT_RANK:
                raise ValueError("Supervisor v4 model-contact state is invalid")
            if (
                _SUPERVISOR_V4_MODEL_CONTACT_RANK[next_contact]
                < _SUPERVISOR_V4_MODEL_CONTACT_RANK[current_contact]
            ):
                raise ValueError("Supervisor v4 model-contact state cannot move backward")
            sequence = int(current["job_sequence"]) + 1
            connection.execute(
                """
                INSERT INTO supervisor_v4_job_transitions(
                    job_id, job_sequence, state, model_contact_state,
                    worker_id, worker_pid, worker_start_token,
                    process_group_id, process_group_start_token,
                    executable_sha256, details_json, details_sha256, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    job_id,
                    sequence,
                    state,
                    next_contact,
                    identity.get("worker_id"),
                    identity.get("worker_pid"),
                    identity.get("worker_start_token"),
                    identity.get("process_group_id"),
                    identity.get("process_group_start_token"),
                    identity.get("executable_sha256"),
                    details_json,
                    details_sha256,
                    observed_at,
                ),
            )
            row = connection.execute(
                """
                SELECT * FROM supervisor_v4_job_transitions
                WHERE job_id = ? AND job_sequence = ?
                """,
                (job_id, sequence),
            ).fetchone()
        return self._supervisor_v4_row(row)  # type: ignore[return-value]

    def supervisor_v4_reconciliation_candidates(self) -> list[dict[str, Any]]:
        """Return active offline process identities without mutating their state."""

        with self.session() as connection:
            rows = connection.execute(
                """
                SELECT
                    j.id AS job_id, j.kind, j.qualification_id,
                    t.job_sequence, t.state, t.model_contact_state,
                    t.worker_id, t.worker_pid, t.worker_start_token,
                    t.process_group_id, t.process_group_start_token,
                    t.executable_sha256, t.recorded_at
                FROM supervisor_v4_jobs AS j
                JOIN supervisor_v4_job_transitions AS t ON t.job_id = j.id
                WHERE t.job_sequence = (
                    SELECT MAX(latest.job_sequence)
                    FROM supervisor_v4_job_transitions AS latest
                    WHERE latest.job_id = j.id
                ) AND t.state = 'offline_qualifying'
                ORDER BY t.recorded_at ASC, j.id ASC
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def record_supervisor_v4_capability_nonce(
        self,
        *,
        nonce: str,
        capability: str,
        scope: dict[str, Any],
        verified_envelope_sha256: str,
        envelope_issued_at: str,
        envelope_expires_at: str,
        recorded_at: str | None = None,
    ) -> dict[str, Any]:
        """Record an externally verified nonce as inert, offline evidence only."""

        nonce_sha256 = _supervisor_v4_nonce_digest(nonce)
        self._supervisor_v4_label(capability, field="capability", maximum=128)
        if capability != "offline.qualification.claim":
            raise ValueError("Supervisor v4 capability must remain offline-only")
        if not isinstance(scope, dict):
            raise ValueError("Supervisor v4 capability scope must be an object")
        _supervisor_v4_digest(
            verified_envelope_sha256, field="verified envelope digest"
        )
        issued = _supervisor_v4_parse_timestamp(envelope_issued_at)
        expires = _supervisor_v4_parse_timestamp(envelope_expires_at)
        if expires <= issued:
            raise ValueError("Supervisor v4 envelope expiry must follow issuance")
        observed_at = recorded_at or utc_now()
        _supervisor_v4_parse_timestamp(observed_at)
        scope_json = canonical_json(scope)
        scope_sha256 = hashlib.sha256(scope_json.encode("utf-8")).hexdigest()
        capability_id = str(uuid.uuid4())
        try:
            with self.session() as connection:
                connection.execute(
                    """
                    INSERT INTO supervisor_v4_capabilities(
                        id, nonce_sha256, capability, scope_json, scope_sha256,
                        verified_envelope_sha256, authority_state,
                        authority_granted, envelope_issued_at,
                        envelope_expires_at, recorded_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 'inert_offline', 0, ?, ?, ?)
                    """,
                    (
                        capability_id,
                        nonce_sha256,
                        capability,
                        scope_json,
                        scope_sha256,
                        verified_envelope_sha256,
                        envelope_issued_at,
                        envelope_expires_at,
                        observed_at,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ValueError("Supervisor v4 capability nonce was already recorded") from exc
        with self.session() as connection:
            row = connection.execute(
                "SELECT * FROM supervisor_v4_capabilities WHERE id = ?",
                (capability_id,),
            ).fetchone()
        return self._supervisor_v4_row(row)  # type: ignore[return-value]

    def consume_supervisor_v4_capability_nonce(
        self,
        *,
        nonce: str,
        capability: str,
        scope: dict[str, Any],
        verified_envelope_sha256: str,
        job_id: str | None = None,
        consumed_at: str | None = None,
    ) -> dict[str, Any]:
        """Record one exact-bound nonce consumption; this grants no authority."""

        nonce_sha256 = _supervisor_v4_nonce_digest(nonce)
        self._supervisor_v4_label(capability, field="capability", maximum=128)
        if capability != "offline.qualification.claim":
            raise ValueError("Supervisor v4 capability must remain offline-only")
        if not isinstance(scope, dict):
            raise ValueError("Supervisor v4 capability scope must be an object")
        _supervisor_v4_digest(
            verified_envelope_sha256, field="verified envelope digest"
        )
        observed_at = consumed_at or utc_now()
        consumed = _supervisor_v4_parse_timestamp(observed_at)
        scope_json = canonical_json(scope)
        scope_sha256 = hashlib.sha256(scope_json.encode("utf-8")).hexdigest()
        consumption_id = str(uuid.uuid4())
        with self.session() as connection:
            connection.execute("BEGIN IMMEDIATE")
            record = connection.execute(
                "SELECT * FROM supervisor_v4_capabilities WHERE nonce_sha256 = ?",
                (nonce_sha256,),
            ).fetchone()
            if record is None:
                raise ValueError("Supervisor v4 capability nonce is invalid")
            if (
                record["capability"] != capability
                or record["scope_sha256"] != scope_sha256
                or not secrets.compare_digest(str(record["scope_json"]), scope_json)
                or not secrets.compare_digest(
                    str(record["verified_envelope_sha256"]),
                    verified_envelope_sha256,
                )
            ):
                raise ValueError("Supervisor v4 capability binding does not match")
            if str(record["authority_state"]) != "inert_offline" or int(
                record["authority_granted"]
            ) != 0:
                raise ValueError("Supervisor v4 capability record is not inert")
            if consumed < _supervisor_v4_parse_timestamp(
                str(record["envelope_issued_at"])
            ):
                raise ValueError("Supervisor v4 capability nonce is not yet valid")
            if consumed >= _supervisor_v4_parse_timestamp(
                str(record["envelope_expires_at"])
            ):
                raise ValueError("Supervisor v4 capability nonce expired")
            if job_id is not None:
                job = connection.execute(
                    "SELECT 1 FROM supervisor_v4_jobs WHERE id = ?", (job_id,)
                ).fetchone()
                if job is None:
                    raise KeyError(f"Supervisor v4 job not found: {job_id}")
            try:
                connection.execute(
                    """
                    INSERT INTO supervisor_v4_capability_consumptions(
                        id, capability_id, job_id, action, scope_sha256,
                        verified_envelope_sha256, authority_granted, consumed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 0, ?)
                    """,
                    (
                        consumption_id,
                        record["id"],
                        job_id,
                        capability,
                        scope_sha256,
                        verified_envelope_sha256,
                        observed_at,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("Supervisor v4 capability nonce was already consumed") from exc
            row = connection.execute(
                "SELECT * FROM supervisor_v4_capability_consumptions WHERE id = ?",
                (consumption_id,),
            ).fetchone()
        return dict(row)  # type: ignore[arg-type]

    def list_supervisor_v4_capabilities(
        self, *, limit: int = 10_000
    ) -> list[dict[str, Any]]:
        if not 1 <= limit <= 100_000:
            raise ValueError("Supervisor v4 capability limit is invalid")
        with self.session() as connection:
            rows = connection.execute(
                """
                SELECT * FROM supervisor_v4_capabilities
                ORDER BY recorded_at ASC, id ASC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [self._supervisor_v4_row(row) for row in rows]  # type: ignore[misc]

    def list_supervisor_v4_capability_consumptions(
        self, *, limit: int = 10_000
    ) -> list[dict[str, Any]]:
        if not 1 <= limit <= 100_000:
            raise ValueError("Supervisor v4 capability-consumption limit is invalid")
        with self.session() as connection:
            rows = connection.execute(
                """
                SELECT * FROM supervisor_v4_capability_consumptions
                ORDER BY consumed_at ASC, id ASC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    @classmethod
    def _supervisor_v4_signature_algorithm(cls, value: str) -> str:
        cls._supervisor_v4_label(value, field="signature algorithm", maximum=128)
        lowered = value.lower()
        if any(marker in lowered for marker in ("hmac", "shared-secret", "symmetric")):
            raise ValueError(
                "Supervisor v4 receipts require an external public-key verifier"
            )
        return value

    def prepare_supervisor_v4_receipt(
        self,
        *,
        receipt_kind: str,
        subject_id: str,
        content: dict[str, Any] | None,
        signer_key_id: str,
        signature_algorithm: str,
        public_metadata: dict[str, Any],
        receipt_id: str | None = None,
        recorded_at: str | None = None,
    ) -> dict[str, Any]:
        """Prepare a read-only envelope for an external public-key signer."""

        self._supervisor_v4_label(receipt_kind, field="receipt kind", maximum=128)
        self._supervisor_v4_label(subject_id, field="receipt subject", maximum=160)
        self._supervisor_v4_label(signer_key_id, field="signer key id", maximum=128)
        self._supervisor_v4_signature_algorithm(signature_algorithm)
        identifier = receipt_id or str(uuid.uuid4())
        try:
            if str(uuid.UUID(identifier)) != identifier:
                raise ValueError
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError("Supervisor v4 receipt id must be a canonical UUID") from exc
        observed_at = recorded_at or utc_now()
        _supervisor_v4_parse_timestamp(observed_at)
        content_json, content_sha256 = _supervisor_v4_content(content)
        public_metadata_json, public_metadata_sha256 = _supervisor_v4_public_metadata(
            public_metadata
        )
        with self.session() as connection:
            previous = connection.execute(
                """
                SELECT sequence, chain_sha256 FROM supervisor_v4_receipts
                ORDER BY sequence DESC LIMIT 1
                """
            ).fetchone()
        sequence = 1 if previous is None else int(previous["sequence"]) + 1
        previous_chain = (
            _SUPERVISOR_V4_ZERO_DIGEST
            if previous is None
            else str(previous["chain_sha256"])
        )
        signed_document = {
            "format": "atlas-supervisor-v4-receipt-v1",
            "sequence": sequence,
            "id": identifier,
            "receipt_kind": receipt_kind,
            "subject_id": subject_id,
            "content_sha256": content_sha256,
            "previous_chain_sha256": previous_chain,
            "signer_key_id": signer_key_id,
            "signature_algorithm": signature_algorithm,
            "public_metadata_sha256": public_metadata_sha256,
            "authority_granted": False,
            "recorded_at": observed_at,
        }
        signing_payload = canonical_json(signed_document)
        return {
            "content": json.loads(content_json),
            "public_metadata": json.loads(public_metadata_json),
            "signed_document": signed_document,
            "signing_payload": signing_payload,
        }

    def append_supervisor_v4_receipt(
        self,
        *,
        prepared_envelope: dict[str, Any],
        signature: str,
        signature_verifier: Callable[[bytes, str, dict[str, Any]], bool],
    ) -> dict[str, Any]:
        """Append externally signed evidence; never accept or retain a signing secret."""

        if not isinstance(prepared_envelope, dict) or set(prepared_envelope) != {
            "content",
            "public_metadata",
            "signed_document",
            "signing_payload",
        }:
            raise ValueError("Supervisor v4 prepared receipt envelope is invalid")
        if not isinstance(signature, str) or not signature or len(signature) > 65_536:
            raise ValueError("Supervisor v4 receipt signature is invalid")
        if not callable(signature_verifier):
            raise ValueError("Supervisor v4 receipt signature verifier is required")
        content = prepared_envelope["content"]
        public_metadata = prepared_envelope["public_metadata"]
        signed_document = prepared_envelope["signed_document"]
        signing_payload = prepared_envelope["signing_payload"]
        if not isinstance(content, dict) or not isinstance(signed_document, dict):
            raise ValueError("Supervisor v4 prepared receipt envelope is invalid")
        required_document_fields = {
            "format",
            "sequence",
            "id",
            "receipt_kind",
            "subject_id",
            "content_sha256",
            "previous_chain_sha256",
            "signer_key_id",
            "signature_algorithm",
            "public_metadata_sha256",
            "authority_granted",
            "recorded_at",
        }
        if set(signed_document) != required_document_fields:
            raise ValueError("Supervisor v4 signed receipt document is invalid")
        if signed_document["format"] != "atlas-supervisor-v4-receipt-v1":
            raise ValueError("Supervisor v4 receipt format is invalid")
        sequence = signed_document["sequence"]
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence <= 0:
            raise ValueError("Supervisor v4 receipt sequence is invalid")
        identifier = signed_document["id"]
        try:
            if str(uuid.UUID(identifier)) != identifier:
                raise ValueError
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError("Supervisor v4 receipt id must be a canonical UUID") from exc
        receipt_kind = signed_document["receipt_kind"]
        subject_id = signed_document["subject_id"]
        signer_key_id = signed_document["signer_key_id"]
        signature_algorithm = signed_document["signature_algorithm"]
        self._supervisor_v4_label(receipt_kind, field="receipt kind", maximum=128)
        self._supervisor_v4_label(subject_id, field="receipt subject", maximum=160)
        self._supervisor_v4_label(signer_key_id, field="signer key id", maximum=128)
        self._supervisor_v4_signature_algorithm(signature_algorithm)
        receipt_recorded_at = signed_document["recorded_at"]
        if not isinstance(receipt_recorded_at, str):
            raise ValueError("Supervisor v4 receipt timestamp is invalid")
        _supervisor_v4_parse_timestamp(receipt_recorded_at)
        if signed_document["authority_granted"] is not False:
            raise ValueError("Supervisor v4 receipt authority must remain false")
        content_json, content_sha256 = _supervisor_v4_content(content)
        public_metadata_json, public_metadata_sha256 = _supervisor_v4_public_metadata(
            public_metadata
        )
        if not secrets.compare_digest(
            str(signed_document["content_sha256"]), content_sha256
        ) or not secrets.compare_digest(
            str(signed_document["public_metadata_sha256"]), public_metadata_sha256
        ):
            raise ValueError("Supervisor v4 prepared receipt digest is invalid")
        canonical_payload = canonical_json(signed_document)
        if not isinstance(signing_payload, str) or not secrets.compare_digest(
            signing_payload, canonical_payload
        ):
            raise ValueError("Supervisor v4 prepared signing payload is invalid")
        try:
            signature_valid = bool(
                signature_verifier(
                    canonical_payload.encode("utf-8"),
                    signature,
                    json.loads(public_metadata_json),
                )
            )
        except Exception as exc:
            raise ValueError("Supervisor v4 receipt signature verification failed") from exc
        if not signature_valid:
            raise ValueError("Supervisor v4 receipt signature is invalid")

        chain_sha256 = hashlib.sha256(
            canonical_json(
                {
                    "signed_document": signed_document,
                    "signature": signature,
                    "public_metadata": json.loads(public_metadata_json),
                }
            ).encode("utf-8")
        ).hexdigest()
        with self.session() as connection:
            connection.execute("BEGIN IMMEDIATE")
            previous = connection.execute(
                """
                SELECT sequence, chain_sha256 FROM supervisor_v4_receipts
                ORDER BY sequence DESC LIMIT 1
                """
            ).fetchone()
            expected_sequence = 1 if previous is None else int(previous["sequence"]) + 1
            expected_previous_chain = (
                _SUPERVISOR_V4_ZERO_DIGEST
                if previous is None
                else str(previous["chain_sha256"])
            )
            if sequence != expected_sequence or not secrets.compare_digest(
                str(signed_document["previous_chain_sha256"]),
                expected_previous_chain,
            ):
                raise ValueError("Supervisor v4 prepared receipt envelope is stale")
            try:
                connection.execute(
                    """
                    INSERT INTO supervisor_v4_receipts(
                        sequence, id, receipt_kind, subject_id, content_json,
                        content_sha256, previous_chain_sha256, signer_key_id,
                        signature_algorithm, public_metadata_json,
                        public_metadata_sha256, signature_text, chain_sha256,
                        authority_granted, recorded_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
                    """,
                    (
                        sequence,
                        identifier,
                        receipt_kind,
                        subject_id,
                        content_json,
                        content_sha256,
                        expected_previous_chain,
                        signer_key_id,
                        signature_algorithm,
                        public_metadata_json,
                        public_metadata_sha256,
                        signature,
                        chain_sha256,
                        signed_document["recorded_at"],
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("Supervisor v4 receipt could not be appended") from exc
            row = connection.execute(
                "SELECT * FROM supervisor_v4_receipts WHERE sequence = ?", (sequence,)
            ).fetchone()
        return self._supervisor_v4_row(row)  # type: ignore[return-value]

    def list_supervisor_v4_receipts(self, *, limit: int = 1_000) -> list[dict[str, Any]]:
        if not 1 <= limit <= 100_000:
            raise ValueError("Supervisor v4 receipt limit is invalid")
        with self.session() as connection:
            rows = connection.execute(
                "SELECT * FROM supervisor_v4_receipts ORDER BY sequence ASC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._supervisor_v4_row(row) for row in rows]  # type: ignore[misc]

    def verify_supervisor_v4_receipt_chain(
        self,
        *,
        signature_verifier: Callable[[bytes, str, dict[str, Any]], bool],
        expected_receipt_count: int,
        expected_head_sha256: str,
    ) -> dict[str, Any]:
        """Verify the complete ledger against an externally retained count and head."""

        if (
            not isinstance(expected_receipt_count, int)
            or isinstance(expected_receipt_count, bool)
            or expected_receipt_count < 0
        ):
            raise ValueError("Supervisor v4 expected receipt count is invalid")
        _supervisor_v4_digest(
            expected_head_sha256,
            field="expected receipt-chain head",
            allow_zero=True,
        )
        if expected_receipt_count > 0 and expected_head_sha256 == _SUPERVISOR_V4_ZERO_DIGEST:
            raise ValueError("Supervisor v4 non-empty receipt chain requires a nonzero head")
        if not callable(signature_verifier):
            raise ValueError("Supervisor v4 receipt signature verifier is required")
        with self.session() as connection:
            rows = connection.execute(
                "SELECT * FROM supervisor_v4_receipts ORDER BY sequence ASC"
            ).fetchall()
        previous_chain = _SUPERVISOR_V4_ZERO_DIGEST
        if len(rows) != expected_receipt_count:
            return {
                "valid": False,
                "receipt_count": len(rows),
                "head_chain_sha256": previous_chain,
                "error": "receipt_count_mismatch",
            }
        for expected_sequence, row in enumerate(rows, start=1):
            receipt = dict(row)
            try:
                content = json.loads(str(receipt["content_json"]))
                public_metadata = json.loads(str(receipt["public_metadata_json"]))
            except json.JSONDecodeError:
                content = None
                public_metadata = None
            if not isinstance(content, dict) or not isinstance(public_metadata, dict):
                return {
                    "valid": False,
                    "receipt_count": len(rows),
                    "head_chain_sha256": previous_chain,
                    "error": "content_or_public_metadata_invalid",
                    "invalid_sequence": expected_sequence,
                }
            try:
                self._supervisor_v4_label(
                    str(receipt["receipt_kind"]), field="receipt kind", maximum=128
                )
                self._supervisor_v4_label(
                    str(receipt["subject_id"]), field="receipt subject", maximum=160
                )
                self._supervisor_v4_label(
                    str(receipt["signer_key_id"]), field="signer key id", maximum=128
                )
                self._supervisor_v4_signature_algorithm(
                    str(receipt["signature_algorithm"])
                )
                _supervisor_v4_parse_timestamp(str(receipt["recorded_at"]))
                content_json, content_sha256 = _supervisor_v4_content(content)
                public_metadata_json, public_metadata_sha256 = (
                    _supervisor_v4_public_metadata(public_metadata)
                )
            except (TypeError, ValueError):
                return {
                    "valid": False,
                    "receipt_count": len(rows),
                    "head_chain_sha256": previous_chain,
                    "error": "receipt_metadata_invalid",
                    "invalid_sequence": expected_sequence,
                }
            if (
                int(receipt["sequence"]) != expected_sequence
                or int(receipt["authority_granted"]) != 0
                or not secrets.compare_digest(
                    str(receipt["previous_chain_sha256"]), previous_chain
                )
                or not secrets.compare_digest(str(receipt["content_json"]), content_json)
                or not secrets.compare_digest(
                    str(receipt["content_sha256"]), content_sha256
                )
                or not secrets.compare_digest(
                    str(receipt["public_metadata_json"]), public_metadata_json
                )
                or not secrets.compare_digest(
                    str(receipt["public_metadata_sha256"]), public_metadata_sha256
                )
            ):
                return {
                    "valid": False,
                    "receipt_count": len(rows),
                    "head_chain_sha256": previous_chain,
                    "error": "digest_or_chain_mismatch",
                    "invalid_sequence": expected_sequence,
                }
            signed_document = {
                "format": "atlas-supervisor-v4-receipt-v1",
                "sequence": expected_sequence,
                "id": receipt["id"],
                "receipt_kind": receipt["receipt_kind"],
                "subject_id": receipt["subject_id"],
                "content_sha256": content_sha256,
                "previous_chain_sha256": previous_chain,
                "signer_key_id": receipt["signer_key_id"],
                "signature_algorithm": receipt["signature_algorithm"],
                "public_metadata_sha256": public_metadata_sha256,
                "authority_granted": False,
                "recorded_at": receipt["recorded_at"],
            }
            signing_payload = canonical_json(signed_document).encode("utf-8")
            try:
                signature_valid = bool(
                    signature_verifier(
                        signing_payload,
                        str(receipt["signature_text"]),
                        public_metadata,
                    )
                )
            except Exception:
                signature_valid = False
            if not signature_valid:
                return {
                    "valid": False,
                    "receipt_count": len(rows),
                    "head_chain_sha256": previous_chain,
                    "error": "signature_mismatch",
                    "invalid_sequence": expected_sequence,
                }
            expected_chain = hashlib.sha256(
                canonical_json(
                    {
                        "signed_document": signed_document,
                        "signature": receipt["signature_text"],
                        "public_metadata": public_metadata,
                    }
                ).encode("utf-8")
            ).hexdigest()
            if not secrets.compare_digest(str(receipt["chain_sha256"]), expected_chain):
                return {
                    "valid": False,
                    "receipt_count": len(rows),
                    "head_chain_sha256": previous_chain,
                    "error": "digest_or_chain_mismatch",
                    "invalid_sequence": expected_sequence,
                }
            previous_chain = expected_chain
        if not secrets.compare_digest(previous_chain, expected_head_sha256):
            return {
                "valid": False,
                "receipt_count": len(rows),
                "head_chain_sha256": previous_chain,
                "error": "receipt_head_mismatch",
            }
        return {
            "valid": True,
            "receipt_count": len(rows),
            "head_chain_sha256": previous_chain,
            "error": None,
        }

    def stats(self) -> dict[str, int]:
        tables = [
            "conversations",
            "messages",
            "memories",
            "projects",
            "approvals",
            "runs",
            "audit_events",
            "import_jobs",
            "supervisor_tasks",
            "supervisor_v2_tasks",
            "supervisor_v3_tasks",
            "supervisor_v4_qualifications",
            "supervisor_v4_jobs",
            "supervisor_v4_job_transitions",
            "supervisor_v4_capabilities",
            "supervisor_v4_capability_consumptions",
            "supervisor_v4_receipts",
        ]
        with self.session() as connection:
            return {
                table: int(connection.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"])
                for table in tables
            }
