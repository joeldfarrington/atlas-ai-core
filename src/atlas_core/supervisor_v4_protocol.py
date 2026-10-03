from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence


ZERO_DIGEST = "0" * 64
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
METHOD_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9]*(?:/[A-Za-z][A-Za-z0-9]*)*$")
CASE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")

EVENT_CLASS_NAMES = frozenset(
    {
        "lifecycle-observed",
        "action-prohibited",
        "passive-observed",
        "content-discarded",
        "capability-status-observed",
        "capability-prohibited",
    }
)
COMMAND_SOURCES = (
    "agent",
    "unifiedExecStartup",
    "unifiedExecInteraction",
    "userShell",
)
COMMAND_SOURCE_CODES = {
    "agent": "command_source_agent_prohibited",
    "unifiedExecStartup": "command_source_unified_exec_startup_prohibited",
    "unifiedExecInteraction": "command_source_unified_exec_interaction_prohibited",
    "userShell": "command_source_user_shell_prohibited",
}
OBSERVED_ITEM_TYPES = frozenset({"userMessage", "agentMessage", "reasoning"})
CURRENT_ITEM_TYPES = frozenset(
    {
        "userMessage",
        "agentMessage",
        "reasoning",
        "hookPrompt",
        "plan",
        "commandExecution",
        "fileChange",
        "mcpToolCall",
        "dynamicToolCall",
        "collabAgentToolCall",
        "subAgentActivity",
        "webSearch",
        "imageView",
        "sleep",
        "imageGeneration",
        "enteredReviewMode",
        "exitedReviewMode",
        "contextCompaction",
    }
)

EVENT_KEYS = frozenset(
    {
        "method",
        "server_request",
        "schema_valid",
        "correlation",
        "payload",
        "truncated",
    }
)
CORRELATION_KEYS = frozenset({"task", "thread", "turn", "item"})
PAYLOAD_KEYS = frozenset(
    {
        "item_type",
        "source",
        "source_defaulted",
        "status",
        "message_phase",
        "proposal",
        "typed_result_status",
        "result_proposal_sha256",
        "readers_joined",
        "queue_drained",
        "late_event_count",
        "reader_error_count",
        "items",
    }
)
PROPOSAL_KEYS = frozenset(
    {
        "schema_version",
        "operation",
        "baseline_sha256",
        "path",
        "original_sha256",
        "replacement",
    }
)
KNOWN_STRUCTURAL_KEYS = EVENT_KEYS | CORRELATION_KEYS | PAYLOAD_KEYS | PROPOSAL_KEYS

SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"(?i)\b(?:api[_-]?key|access[_-]?token|password)\s*[:=]\s*[^\s]{8,}"),
)


class ProtocolViolation(RuntimeError):
    """A privacy-safe, fail-closed compatibility or replay violation."""

    def __init__(self, code: str, *, diagnostic_digest: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.diagnostic_digest = diagnostic_digest


class NormalizedEventKind(str, Enum):
    LIFECYCLE_OBSERVED = "LifecycleObserved"
    ACTION_PROPOSED = "ActionProposed"
    ACTION_STARTED = "ActionStarted"
    ACTION_COMPLETED = "ActionCompleted"
    APPROVAL_REQUESTED = "ApprovalRequested"
    CAPABILITY_STATUS_OBSERVED = "CapabilityStatusObserved"
    TURN_TERMINAL = "TurnTerminal"
    COMPATIBILITY_VIOLATION = "CompatibilityViolation"


class DecisionTreatment(str, Enum):
    OBSERVE = "observe"
    PROPOSAL_ELIGIBLE = "proposal_eligible"
    PROHIBITED = "prohibited"
    COMPATIBILITY_VIOLATION = "compatibility_violation"


@dataclass(frozen=True, slots=True)
class CapabilityDecision:
    treatment: DecisionTreatment
    code: str

    @property
    def grants_execution_authority(self) -> bool:
        """The proposal-only Phase A/B contract never grants execution authority."""

        return False

    @property
    def candidate_materialization_eligible(self) -> bool:
        return self.treatment is DecisionTreatment.PROPOSAL_ELIGIBLE


@dataclass(frozen=True, slots=True)
class StructuralLimits:
    max_depth: int = 6
    max_collection_items: int = 32
    max_nodes: int = 256
    max_string_bytes: int = 256
    max_key_bytes: int = 128
    max_event_bytes: int = 262_144
    max_events: int = 32


DEFAULT_LIMITS = StructuralLimits()


@dataclass(slots=True)
class _StructuralBudget:
    limits: StructuralLimits
    nodes: int = 0
    bytes_seen: int = 0

    def consume(self) -> None:
        self.nodes += 1
        if self.nodes > self.limits.max_nodes:
            raise ProtocolViolation("input_node_limit_exceeded")

    def consume_bytes(self, size: int) -> None:
        self.bytes_seen += size
        if self.bytes_seen > self.limits.max_event_bytes:
            raise ProtocolViolation("input_event_byte_limit_exceeded")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _validate_sha256(value: str, *, field_name: str) -> None:
    if not SHA256_PATTERN.fullmatch(value):
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")


def _digest_name(value: object, *, salt_sha256: str) -> str:
    if isinstance(value, str):
        encoded = value.encode("utf-8", errors="replace")
    else:
        encoded = f"<{type(value).__name__}>".encode("ascii", errors="replace")
    return hmac.new(
        bytes.fromhex(salt_sha256),
        b"atlas-supervisor-v4-diagnostic-v1\x00" + encoded,
        hashlib.sha256,
    ).hexdigest()


def _read_regular_file(path: Path, *, max_bytes: int = 2_000_000) -> bytes:
    """Read a stable regular file without following any path component."""

    absolute = path.expanduser().absolute()
    if not absolute.is_absolute() or ".." in absolute.parts or absolute.name in {"", "."}:
        raise ProtocolViolation("snapshot_file_path_invalid")
    base_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    directory_flags = (
        base_flags
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    directory_fd: int | None = None
    file_fd: int | None = None
    try:
        directory_fd = os.open(absolute.anchor, directory_flags)
        for component in absolute.parts[1:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(
            absolute.name,
            base_flags | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
        metadata = os.fstat(file_fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size < 0
            or metadata.st_size > max_bytes
        ):
            raise ProtocolViolation("snapshot_file_invalid")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(file_fd, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) > max_bytes:
            raise ProtocolViolation("snapshot_file_too_large")
        after = os.fstat(file_fd)
        if len(content) != metadata.st_size or (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ProtocolViolation("snapshot_file_changed_during_read")
        return content
    except OSError as exc:
        raise ProtocolViolation("snapshot_file_unavailable") from exc
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if directory_fd is not None:
            os.close(directory_fd)


def _decode_utf8(content: bytes) -> str:
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProtocolViolation("snapshot_file_not_utf8") from exc


def _json_reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolViolation("duplicate_json_key")
        result[key] = value
    return result


def _length_bucket(length: int) -> str:
    if length == 0:
        return "0"
    for ceiling in (15, 63, 255):
        if length <= ceiling:
            return f"1-{ceiling}"
    return "256+"


def bounded_structural_shape(
    value: Any,
    *,
    diagnostic_salt_sha256: str,
    known_keys: frozenset[str] = KNOWN_STRUCTURAL_KEYS,
    limits: StructuralLimits = DEFAULT_LIMITS,
    replacement_string_limit: int | None = None,
) -> Any:
    """Return a bounded, scalar-free shape with every unknown key hashed.

    Collection, depth, node, key, and string limits are enforced before the
    returned shape is serialized. No scalar payload value is copied into the
    shape.
    """

    budget = _StructuralBudget(limits)

    def visit(item: Any, depth: int, *, parent_key: str | None = None) -> Any:
        if depth > limits.max_depth:
            raise ProtocolViolation("input_depth_limit_exceeded")
        budget.consume()
        if item is None:
            budget.consume_bytes(4)
            return {"type": "null"}
        if isinstance(item, bool):
            budget.consume_bytes(5)
            return {"type": "boolean"}
        if isinstance(item, int) and not isinstance(item, bool):
            budget.consume_bytes(len(str(item)))
            return {"type": "integer"}
        if isinstance(item, float):
            budget.consume_bytes(len(repr(item)))
            return {"type": "number"}
        if isinstance(item, str):
            length = len(item.encode("utf-8"))
            string_limit = (
                replacement_string_limit
                if parent_key == "replacement" and replacement_string_limit is not None
                else limits.max_string_bytes
            )
            if length > string_limit:
                raise ProtocolViolation("input_string_limit_exceeded")
            budget.consume_bytes(length)
            return {"type": "string", "length": _length_bucket(length)}
        if isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            if len(item) > limits.max_collection_items:
                raise ProtocolViolation("input_collection_limit_exceeded")
            return {
                "type": "array",
                "count": len(item),
                "items": [visit(child, depth + 1) for child in item],
            }
        if isinstance(item, Mapping):
            if len(item) > limits.max_collection_items:
                raise ProtocolViolation("input_collection_limit_exceeded")
            entries: list[dict[str, Any]] = []
            sortable: list[tuple[str, object, Any]] = []
            for raw_key, child in item.items():
                key_text = raw_key if isinstance(raw_key, str) else f"<{type(raw_key).__name__}>"
                key_bytes = key_text.encode("utf-8", errors="replace")
                if len(key_bytes) > limits.max_key_bytes:
                    raise ProtocolViolation("input_key_limit_exceeded")
                budget.consume_bytes(len(key_bytes))
                stored_key = (
                    key_text
                    if key_text in known_keys
                    else f"hmac-sha256:{_digest_name(key_text, salt_sha256=diagnostic_salt_sha256)}"
                )
                sortable.append((stored_key, raw_key, child))
            for stored_key, _raw_key, child in sorted(sortable, key=lambda row: row[0]):
                parent_key = (
                    _raw_key
                    if isinstance(_raw_key, str)
                    else f"<{type(_raw_key).__name__}>"
                )
                entries.append(
                    {
                        "key": stored_key,
                        "value": visit(child, depth + 1, parent_key=parent_key),
                    }
                )
            return {"type": "object", "count": len(item), "entries": entries}
        return {"type": type(item).__name__[:32]}

    return visit(value, 0)


@dataclass(frozen=True, slots=True)
class ProtocolInventory:
    version: int
    sdk_version: str
    stable_method_count: int
    classifications: dict[str, str]
    server_requests: frozenset[str]
    item_treatments: dict[str, str]
    command_source_codes: dict[str, str]
    replay_corpus_sha256: str
    diagnostic_salt_sha256: str
    proposal_schema_version: int
    proposal_operation: str
    proposal_baseline_sha256: str
    proposal_path: str
    proposal_original_sha256: str
    proposal_max_files: int
    proposal_max_lines: int
    proposal_max_replacement_bytes: int
    limits: StructuralLimits

    @classmethod
    def load(cls, path: Path) -> "ProtocolInventory":
        import yaml

        class UniqueKeyLoader(yaml.SafeLoader):
            pass

        def construct_unique_mapping(loader, node, deep=False):
            mapping: dict[Any, Any] = {}
            for key_node, value_node in node.value:
                key = loader.construct_object(key_node, deep=deep)
                if key in mapping:
                    raise ProtocolViolation("duplicate_yaml_key")
                mapping[key] = loader.construct_object(value_node, deep=deep)
            return mapping

        UniqueKeyLoader.add_constructor(
            yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
            construct_unique_mapping,
        )
        raw = yaml.load(
            _decode_utf8(_read_regular_file(path)), Loader=UniqueKeyLoader
        ) or {}
        expected_top_level = {
            "version",
            "sdk_version",
            "stable_method_count",
            "event_classes",
            "server_requests",
            "item_types",
            "command_sources",
            "limits",
            "diagnostic_salt_sha256",
            "proposal_contract",
            "replay_corpus_sha256",
        }
        if (
            not isinstance(raw, dict)
            or set(raw) != expected_top_level
            or raw.get("version") != 1
            or raw.get("sdk_version") != "0.147.0"
            or raw.get("stable_method_count") != 70
            or not isinstance(raw.get("event_classes"), dict)
        ):
            raise ProtocolViolation("protocol_inventory_format_invalid")
        classes = raw["event_classes"]
        if set(classes) != EVENT_CLASS_NAMES:
            raise ProtocolViolation("protocol_event_classes_drifted")
        classifications: dict[str, str] = {}
        duplicates: set[str] = set()
        for class_name in sorted(EVENT_CLASS_NAMES):
            methods = classes[class_name]
            if not isinstance(methods, list) or any(
                not isinstance(method, str) or not METHOD_PATTERN.fullmatch(method)
                for method in methods
            ):
                raise ProtocolViolation("protocol_method_inventory_invalid")
            for method in methods:
                if method in classifications:
                    duplicates.add(method)
                classifications[method] = class_name
        if duplicates:
            raise ProtocolViolation("protocol_method_inventory_duplicated")
        stable_method_count = raw.get("stable_method_count")
        if stable_method_count != len(classifications):
            raise ProtocolViolation("protocol_method_count_drifted")

        server_requests = raw.get("server_requests")
        if not isinstance(server_requests, list) or any(
            not isinstance(method, str) or not METHOD_PATTERN.fullmatch(method)
            for method in server_requests
        ):
            raise ProtocolViolation("protocol_server_request_inventory_invalid")
        request_set = frozenset(server_requests)
        if len(request_set) != len(server_requests) or len(request_set) != 10:
            raise ProtocolViolation("protocol_server_request_inventory_duplicated")

        items = raw.get("item_types")
        if not isinstance(items, dict) or any(
            not isinstance(name, str) or treatment not in {"observe", "prohibit"}
            for name, treatment in items.items()
        ):
            raise ProtocolViolation("protocol_item_inventory_invalid")
        if set(items) != CURRENT_ITEM_TYPES:
            raise ProtocolViolation("protocol_item_inventory_incomplete")
        if {name for name, treatment in items.items() if treatment == "observe"} != set(
            OBSERVED_ITEM_TYPES
        ):
            raise ProtocolViolation("protocol_observed_item_inventory_drifted")

        sources = raw.get("command_sources")
        if not isinstance(sources, dict) or set(sources) != set(COMMAND_SOURCES):
            raise ProtocolViolation("protocol_command_source_inventory_drifted")
        if any(sources.get(source) != COMMAND_SOURCE_CODES[source] for source in COMMAND_SOURCES):
            raise ProtocolViolation("protocol_command_source_decision_drifted")
        if len(set(sources.values())) != len(COMMAND_SOURCES):
            raise ProtocolViolation("protocol_command_source_decisions_not_distinct")

        replay_digest = raw.get("replay_corpus_sha256")
        if not isinstance(replay_digest, str) or not SHA256_PATTERN.fullmatch(replay_digest):
            raise ProtocolViolation("protocol_replay_digest_invalid")
        diagnostic_salt = raw.get("diagnostic_salt_sha256")
        if not isinstance(diagnostic_salt, str) or not SHA256_PATTERN.fullmatch(
            diagnostic_salt
        ):
            raise ProtocolViolation("protocol_diagnostic_salt_invalid")
        proposal = raw.get("proposal_contract")
        if not isinstance(proposal, dict) or set(proposal) != {
            "schema_version",
            "operation",
            "baseline_sha256",
            "path",
            "original_sha256",
            "max_files",
            "max_lines",
            "max_replacement_bytes",
        }:
            raise ProtocolViolation("protocol_proposal_contract_invalid")
        if (
            proposal.get("schema_version") != 1
            or proposal.get("operation") != "replace_existing_file"
            or not isinstance(proposal.get("path"), str)
            or not proposal["path"]
            or Path(proposal["path"]).is_absolute()
            or ".." in Path(proposal["path"]).parts
            or proposal.get("max_files") != 1
            or not isinstance(proposal.get("max_lines"), int)
            or not 1 <= proposal["max_lines"] <= 100
            or not isinstance(proposal.get("max_replacement_bytes"), int)
            or not 1 <= proposal["max_replacement_bytes"] <= 65_536
        ):
            raise ProtocolViolation("protocol_proposal_contract_invalid")
        for digest_field in ("baseline_sha256", "original_sha256"):
            if not isinstance(proposal.get(digest_field), str) or not SHA256_PATTERN.fullmatch(
                proposal[digest_field]
            ):
                raise ProtocolViolation("protocol_proposal_contract_invalid")
        raw_limits = raw.get("limits")
        if not isinstance(raw_limits, dict) or set(raw_limits) != {
            "max_depth",
            "max_collection_items",
            "max_nodes",
            "max_string_bytes",
            "max_key_bytes",
            "max_event_bytes",
            "max_events",
        }:
            raise ProtocolViolation("protocol_limits_invalid")
        try:
            limits = StructuralLimits(
                max_depth=int(raw_limits["max_depth"]),
                max_collection_items=int(raw_limits["max_collection_items"]),
                max_nodes=int(raw_limits["max_nodes"]),
                max_string_bytes=int(raw_limits["max_string_bytes"]),
                max_key_bytes=int(raw_limits["max_key_bytes"]),
                max_event_bytes=int(raw_limits["max_event_bytes"]),
                max_events=int(raw_limits["max_events"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ProtocolViolation("protocol_limits_invalid") from exc
        if any(
            value <= 0
            for value in (
                limits.max_depth,
                limits.max_collection_items,
                limits.max_nodes,
                limits.max_string_bytes,
                limits.max_key_bytes,
                limits.max_event_bytes,
                limits.max_events,
            )
        ):
            raise ProtocolViolation("protocol_limits_invalid")

        return cls(
            version=1,
            sdk_version=str(raw.get("sdk_version") or ""),
            stable_method_count=int(stable_method_count),
            classifications=classifications,
            server_requests=request_set,
            item_treatments=dict(items),
            command_source_codes=dict(sources),
            replay_corpus_sha256=replay_digest,
            diagnostic_salt_sha256=diagnostic_salt,
            proposal_schema_version=1,
            proposal_operation="replace_existing_file",
            proposal_baseline_sha256=proposal["baseline_sha256"],
            proposal_path=proposal["path"],
            proposal_original_sha256=proposal["original_sha256"],
            proposal_max_files=1,
            proposal_max_lines=int(proposal["max_lines"]),
            proposal_max_replacement_bytes=int(proposal["max_replacement_bytes"]),
            limits=limits,
        )

    def classify(self, method: str) -> str | None:
        return self.classifications.get(method)


@dataclass(frozen=True, slots=True)
class CapabilityBindings:
    """Exact non-secret bindings covered by a future owner-side signature."""

    capability_version: int
    capability_id_sha256: str
    task_sha256: str
    job_sha256: str
    project_sha256: str
    nonce_sha256: str
    audience: str
    provider: str
    sdk_version: str
    signing_key_id: str
    one_use: bool
    issued_at: str
    expires_at: str
    max_ttl_seconds: int
    source_baseline_sha256: str
    policy_bundle_sha256: str
    replay_corpus_sha256: str
    adapter_sha256: str
    model: str
    reasoning_effort: str
    runtime_sha256: str
    sandbox: str
    sandbox_profile_sha256: str
    network_access: bool
    budgets_sha256: str
    attempt_limit: int
    process_limit: int
    timeout_seconds: int
    max_output_bytes: int
    max_changed_files: int
    max_changed_lines: int
    max_patch_bytes: int
    pause_channel_sha256: str
    operation: str
    result_type: str
    path_sha256: str
    expected_original_sha256: str
    verification_recipe_sha256: str
    data_egress_class: str
    data_egress_manifest_sha256: str
    credential_scope_sha256: str
    credential_delivery_channel_sha256: str
    receipt_chain_id_sha256: str
    receipt_predecessor_sha256: str
    receipt_predecessor_count: int
    kill_switch_channel_sha256: str

    def __post_init__(self) -> None:
        for field_name in (
            "capability_id_sha256",
            "task_sha256",
            "job_sha256",
            "project_sha256",
            "nonce_sha256",
            "source_baseline_sha256",
            "policy_bundle_sha256",
            "replay_corpus_sha256",
            "adapter_sha256",
            "runtime_sha256",
            "sandbox_profile_sha256",
            "budgets_sha256",
            "pause_channel_sha256",
            "path_sha256",
            "expected_original_sha256",
            "verification_recipe_sha256",
            "data_egress_manifest_sha256",
            "credential_scope_sha256",
            "credential_delivery_channel_sha256",
            "receipt_chain_id_sha256",
            "receipt_predecessor_sha256",
            "kill_switch_channel_sha256",
        ):
            _validate_sha256(getattr(self, field_name), field_name=field_name)
        try:
            issued = datetime.fromisoformat(self.issued_at.replace("Z", "+00:00"))
            expiry = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("capability expiry must be an ISO-8601 timestamp") from exc
        integer_limits = (
            self.max_ttl_seconds,
            self.attempt_limit,
            self.process_limit,
            self.timeout_seconds,
            self.max_output_bytes,
            self.max_changed_files,
            self.max_changed_lines,
            self.max_patch_bytes,
            self.receipt_predecessor_count,
        )
        if any(not isinstance(value, int) or isinstance(value, bool) for value in integer_limits):
            raise ValueError("capability budgets must be integers")
        if (
            self.capability_version != 4
            or not self.audience
            or not self.provider
            or not self.sdk_version
            or not self.signing_key_id
            or self.one_use is not True
            or issued.tzinfo is None
            or expiry.tzinfo is None
            or not 1 <= self.max_ttl_seconds <= 300
            or not 0 < (expiry - issued).total_seconds() <= self.max_ttl_seconds
            or not self.model
            or not self.reasoning_effort
            or self.sandbox != "read_only_empty_root"
            or self.network_access
            or self.attempt_limit != 1
            or self.process_limit != 1
            or not 1 <= self.timeout_seconds <= 180
            or not 1 <= self.max_output_bytes <= 262_144
            or self.max_changed_files != 1
            or not 1 <= self.max_changed_lines <= 20
            or not 1 <= self.max_patch_bytes <= 16_384
            or self.operation != "replace_existing_file"
            or self.result_type != "structured_replacement_proposal"
            or self.data_egress_class != "synthetic_fictional_bounded"
            or self.receipt_predecessor_count < 0
            or (
                self.receipt_predecessor_count == 0
                and self.receipt_predecessor_sha256 != ZERO_DIGEST
            )
            or (
                self.receipt_predecessor_count > 0
                and self.receipt_predecessor_sha256 == ZERO_DIGEST
            )
        ):
            raise ValueError("invalid proposal-only capability bindings")

    @property
    def sha256(self) -> str:
        """Canonical digest of the complete externally signed work order."""

        return hashlib.sha256(canonical_json(asdict(self)).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class SignedCapabilityEnvelope:
    """Interface-only signed capability; it never contains a signing key."""

    version: int
    key_id: str
    capability_sha256: str
    signature: str
    nonce_sha256: str
    bindings: CapabilityBindings
    one_use: bool = True

    def __post_init__(self) -> None:
        _validate_sha256(self.capability_sha256, field_name="capability_sha256")
        _validate_sha256(self.nonce_sha256, field_name="nonce_sha256")
        if (
            self.version != 1
            or not self.key_id
            or not self.signature
            or self.one_use is not True
            or self.key_id != self.bindings.signing_key_id
            or self.nonce_sha256 != self.bindings.nonce_sha256
            or self.one_use != self.bindings.one_use
            or self.capability_sha256 != self.bindings.sha256
        ):
            raise ValueError("invalid inactive signed-capability envelope")


@dataclass(frozen=True, slots=True)
class ImmutablePolicyBundle:
    version: int
    policy_sha256: str
    protocol_sha256: str
    sdk_lock_sha256: str
    replay_corpus_sha256: str

    def __post_init__(self) -> None:
        if self.version != 1:
            raise ValueError("invalid immutable policy-bundle version")
        for field_name in (
            "policy_sha256",
            "protocol_sha256",
            "sdk_lock_sha256",
            "replay_corpus_sha256",
        ):
            _validate_sha256(getattr(self, field_name), field_name=field_name)

    @property
    def sha256(self) -> str:
        """Canonical digest bound into every capability for this bundle."""

        return hashlib.sha256(canonical_json(asdict(self)).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class SignedReceiptLink:
    version: int
    predecessor_sha256: str
    receipt_sha256: str
    key_id: str
    signature: str

    def __post_init__(self) -> None:
        if self.version != 1 or not self.key_id or not self.signature:
            raise ValueError("invalid signed-receipt link")
        _validate_sha256(self.predecessor_sha256, field_name="predecessor_sha256")
        _validate_sha256(self.receipt_sha256, field_name="receipt_sha256")


class PolicyBroker(Protocol):
    def issue_capability(
        self, bundle: ImmutablePolicyBundle, bindings: CapabilityBindings
    ) -> SignedCapabilityEnvelope: ...


class ReceiptSigner(Protocol):
    def sign_receipt(self, receipt_sha256: str, predecessor_sha256: str) -> SignedReceiptLink: ...


@dataclass(frozen=True, slots=True)
class NormalizedEvent:
    kind: NormalizedEventKind
    classification: str
    method: str | None
    method_digest: str | None
    public_value: str | None
    value_digest: str | None
    structural_shape_sha256: str
    correlation_valid: bool
    decision: CapabilityDecision

    def envelope(self, sequence: int) -> dict[str, Any]:
        return {
            "sequence": sequence,
            "kind": self.kind.value,
            "classification": self.classification,
            "method": self.method,
            "method_digest": self.method_digest,
            "public_value": self.public_value,
            "value_digest": self.value_digest,
            "structural_shape_sha256": self.structural_shape_sha256,
            "correlation_valid": self.correlation_valid,
            "treatment": self.decision.treatment.value,
            "code": self.decision.code,
        }


@dataclass(frozen=True, slots=True)
class ReplayReceipt:
    case_id: str
    outcome: str
    decision_code: str
    event_count: int
    event_chain_sha256: str
    final_phase: str
    known_method_counts: dict[str, int]
    diagnostic_public_value: str | None
    diagnostic_digest: str | None
    final_agent_message_count: int
    validated_proposal_sha256: str | None
    terminal_readers_joined: bool
    terminal_queue_drained: bool
    terminal_late_event_count: int | None
    terminal_reader_error_count: int | None
    typed_result_consistent: bool
    raw_protocol_persisted: bool = False
    prompt_persisted: bool = False
    response_persisted: bool = False
    reasoning_persisted: bool = False
    command_output_persisted: bool = False

    def to_dict(self) -> dict[str, Any]:
        content = {
            "version": 1,
            "case_id": self.case_id,
            "stage": "proposal_only",
            "outcome": self.outcome,
            "decision_code": self.decision_code,
            "event_count": self.event_count,
            "event_chain_sha256": self.event_chain_sha256,
            "final_phase": self.final_phase,
            "known_method_counts": dict(sorted(self.known_method_counts.items())),
            "diagnostic_public_value": self.diagnostic_public_value,
            "diagnostic_digest": self.diagnostic_digest,
            "final_agent_message_count": self.final_agent_message_count,
            "validated_proposal_sha256": self.validated_proposal_sha256,
            "terminal_readers_joined": self.terminal_readers_joined,
            "terminal_queue_drained": self.terminal_queue_drained,
            "terminal_late_event_count": self.terminal_late_event_count,
            "terminal_reader_error_count": self.terminal_reader_error_count,
            "typed_result_consistent": self.typed_result_consistent,
            "grants_execution_authority": False,
            "candidate_integrated": False,
            "model_contacted": False,
            "raw_protocol_persisted": self.raw_protocol_persisted,
            "prompt_persisted": self.prompt_persisted,
            "response_persisted": self.response_persisted,
            "reasoning_persisted": self.reasoning_persisted,
            "command_output_persisted": self.command_output_persisted,
        }
        content["decision_sha256"] = sha256_bytes(canonical_json(content).encode("utf-8"))
        return content


@dataclass(slots=True)
class ProposalReplayMachine:
    inventory: ProtocolInventory
    phase: str = "awaiting_thread"
    open_item_type: str | None = None
    event_chain_sha256: str = ZERO_DIGEST
    event_count: int = 0
    known_method_counts: Counter[str] = field(default_factory=Counter)
    final_agent_message_count: int = 0
    validated_proposal_sha256: str | None = None
    terminal_readers_joined: bool = False
    terminal_queue_drained: bool = False
    terminal_late_event_count: int | None = None
    terminal_reader_error_count: int | None = None
    typed_result_consistent: bool = False

    def _record(self, event: NormalizedEvent) -> None:
        self.event_count += 1
        envelope = event.envelope(self.event_count)
        self.event_chain_sha256 = sha256_bytes(
            self.event_chain_sha256.encode("ascii")
            + canonical_json(envelope).encode("utf-8")
        )
        if event.method is not None:
            self.known_method_counts[event.method] += 1

    def _failure_event(
        self,
        raw_event: object,
        violation: ProtocolViolation,
        *,
        shape_sha256: str = ZERO_DIGEST,
    ) -> NormalizedEvent:
        method: str | None = None
        method_digest: str | None = None
        classification = "unknown-or-malformed"
        if isinstance(raw_event, Mapping):
            candidate = raw_event.get("method")
            if isinstance(candidate, str) and candidate in self.inventory.classifications:
                method = candidate
                classification = self.inventory.classifications[candidate]
            elif isinstance(candidate, str) and candidate in self.inventory.server_requests:
                method = candidate
                classification = "server-request"
            else:
                method_digest = _digest_name(
                    candidate, salt_sha256=self.inventory.diagnostic_salt_sha256
                )
        return NormalizedEvent(
            kind=NormalizedEventKind.COMPATIBILITY_VIOLATION,
            classification=classification,
            method=method,
            method_digest=method_digest,
            public_value=None,
            value_digest=violation.diagnostic_digest,
            structural_shape_sha256=shape_sha256,
            correlation_valid=False,
            decision=CapabilityDecision(
                DecisionTreatment.COMPATIBILITY_VIOLATION, violation.code
            ),
        )

    def observe(self, raw_event: object) -> NormalizedEvent:
        shape_sha256 = ZERO_DIGEST
        try:
            shape = bounded_structural_shape(
                raw_event,
                diagnostic_salt_sha256=self.inventory.diagnostic_salt_sha256,
                limits=self.inventory.limits,
                replacement_string_limit=self.inventory.proposal_max_replacement_bytes,
            )
            shape_sha256 = sha256_bytes(canonical_json(shape).encode("utf-8"))
            event = self._validate_event(raw_event)
            normalized = self._evaluate(event, shape_sha256=shape_sha256)
        except ProtocolViolation as exc:
            normalized = self._failure_event(
                raw_event, exc, shape_sha256=shape_sha256
            )
        self._record(normalized)
        return normalized

    def _validate_event(self, raw_event: object) -> Mapping[str, Any]:
        if not isinstance(raw_event, Mapping):
            raise ProtocolViolation("event_not_object")
        unexpected = sorted(str(key) for key in set(raw_event) - EVENT_KEYS)
        if unexpected:
            raise ProtocolViolation(
                "unknown_event_key",
                diagnostic_digest=_digest_name(
                    unexpected[0], salt_sha256=self.inventory.diagnostic_salt_sha256
                ),
            )
        if raw_event.get("truncated") is True:
            raise ProtocolViolation("input_truncated")
        if raw_event.get("schema_valid") is not True:
            raise ProtocolViolation("schema_invalid")
        server_request = raw_event.get("server_request", False)
        if not isinstance(server_request, bool):
            raise ProtocolViolation("server_request_marker_invalid")
        method = raw_event.get("method")
        if not isinstance(method, str) or not METHOD_PATTERN.fullmatch(method):
            raise ProtocolViolation(
                "method_malformed",
                diagnostic_digest=_digest_name(
                    method, salt_sha256=self.inventory.diagnostic_salt_sha256
                ),
            )
        correlation = raw_event.get("correlation", {})
        if not isinstance(correlation, Mapping):
            raise ProtocolViolation("correlation_malformed")
        unknown_correlations = sorted(str(key) for key in set(correlation) - CORRELATION_KEYS)
        if unknown_correlations:
            raise ProtocolViolation(
                "unknown_correlation_key",
                diagnostic_digest=_digest_name(
                    unknown_correlations[0],
                    salt_sha256=self.inventory.diagnostic_salt_sha256,
                ),
            )
        if set(correlation) != CORRELATION_KEYS:
            raise ProtocolViolation("correlation_incomplete")
        if any(not isinstance(value, bool) for value in correlation.values()):
            raise ProtocolViolation("correlation_malformed")
        if any(value is False for value in correlation.values()):
            raise ProtocolViolation("correlation_mismatch")
        payload = raw_event.get("payload", {})
        if not isinstance(payload, Mapping):
            raise ProtocolViolation("payload_malformed")
        unknown_payload = sorted(str(key) for key in set(payload) - PAYLOAD_KEYS)
        if unknown_payload:
            raise ProtocolViolation(
                "unknown_payload_key",
                diagnostic_digest=_digest_name(
                    unknown_payload[0],
                    salt_sha256=self.inventory.diagnostic_salt_sha256,
                ),
            )
        return raw_event

    def _evaluate(
        self, event: Mapping[str, Any], *, shape_sha256: str
    ) -> NormalizedEvent:
        method = str(event["method"])
        server_request = bool(event.get("server_request", False))
        if self.phase == "terminal":
            raise ProtocolViolation("terminal_barrier_violation")
        if server_request:
            if method not in self.inventory.server_requests:
                raise ProtocolViolation(
                    "unknown_server_request",
                    diagnostic_digest=_digest_name(
                        method, salt_sha256=self.inventory.diagnostic_salt_sha256
                    ),
                )
            return self._normalized(
                kind=NormalizedEventKind.APPROVAL_REQUESTED,
                classification="server-request",
                method=method,
                shape_sha256=shape_sha256,
                treatment=DecisionTreatment.PROHIBITED,
                code=(
                    "unexpected_approval_request"
                    if "Approval" in method or method in {"execCommandApproval", "applyPatchApproval"}
                    else "server_request_prohibited"
                ),
            )
        classification = self.inventory.classify(method)
        if classification is None:
            raise ProtocolViolation(
                "unknown_method",
                diagnostic_digest=_digest_name(
                    method, salt_sha256=self.inventory.diagnostic_salt_sha256
                ),
            )
        if classification == "action-prohibited":
            return self._normalized(
                kind=(
                    NormalizedEventKind.ACTION_PROPOSED
                    if "patchUpdated" in method or method == "turn/diff/updated"
                    else NormalizedEventKind.ACTION_STARTED
                ),
                classification=classification,
                method=method,
                shape_sha256=shape_sha256,
                treatment=DecisionTreatment.PROHIBITED,
                code=(
                    "file_change_event_prohibited"
                    if "fileChange" in method or method == "turn/diff/updated"
                    else "command_event_prohibited"
                ),
            )
        if classification == "capability-prohibited":
            return self._normalized(
                kind=NormalizedEventKind.ACTION_PROPOSED,
                classification=classification,
                method=method,
                shape_sha256=shape_sha256,
                treatment=DecisionTreatment.PROHIBITED,
                code="capability_event_prohibited",
            )
        if classification == "capability-status-observed":
            payload = event.get("payload", {})
            if payload.get("status") != "disabled":
                raise ProtocolViolation(
                    "capability_status_not_disabled",
                    diagnostic_digest=_digest_name(
                        payload.get("status"),
                        salt_sha256=self.inventory.diagnostic_salt_sha256,
                    ),
                )
            return self._normalized(
                kind=NormalizedEventKind.CAPABILITY_STATUS_OBSERVED,
                classification=classification,
                method=method,
                shape_sha256=shape_sha256,
                treatment=DecisionTreatment.OBSERVE,
                code="capability_disabled_observed",
            )
        if classification in {"passive-observed", "content-discarded"}:
            if self.phase not in {"thread", "turn", "item"}:
                raise ProtocolViolation("event_out_of_phase")
            return self._normalized(
                kind=NormalizedEventKind.LIFECYCLE_OBSERVED,
                classification=classification,
                method=method,
                shape_sha256=shape_sha256,
                treatment=DecisionTreatment.OBSERVE,
                code=(
                    "content_discarded"
                    if classification == "content-discarded"
                    else "metadata_observed"
                ),
            )
        return self._evaluate_lifecycle(event, method=method, shape_sha256=shape_sha256)

    def _evaluate_lifecycle(
        self, event: Mapping[str, Any], *, method: str, shape_sha256: str
    ) -> NormalizedEvent:
        payload = event.get("payload", {})
        if method == "error":
            raise ProtocolViolation("app_server_error")
        if method == "thread/started":
            if self.phase != "awaiting_thread":
                raise ProtocolViolation("thread_started_duplicate_or_reordered")
            self.phase = "thread"
            return self._observe_lifecycle(method, shape_sha256, "thread_started")
        if method == "turn/started":
            if self.phase != "thread":
                raise ProtocolViolation("turn_started_reordered")
            self.phase = "turn"
            return self._observe_lifecycle(method, shape_sha256, "turn_started")
        if method in {"thread/status/changed", "thread/tokenUsage/updated"}:
            if self.phase not in {"thread", "turn", "item"}:
                raise ProtocolViolation("event_out_of_phase")
            return self._observe_lifecycle(method, shape_sha256, "lifecycle_metadata_observed")
        if method == "item/started":
            if self.phase != "turn" or self.open_item_type is not None:
                raise ProtocolViolation("item_started_duplicate_or_reordered")
            return self._evaluate_item(
                payload, method=method, shape_sha256=shape_sha256, completed=False
            )
        if method == "item/completed":
            if self.phase != "item" or self.open_item_type is None:
                raise ProtocolViolation("item_completed_reordered")
            return self._evaluate_item(
                payload, method=method, shape_sha256=shape_sha256, completed=True
            )
        if method == "turn/completed":
            if self.phase != "turn" or self.open_item_type is not None:
                raise ProtocolViolation("turn_completed_reordered")
            self.phase = "terminal"
            status = payload.get("status")
            typed_status = payload.get("typed_result_status")
            self.typed_result_consistent = status == "completed" and typed_status == status
            self.terminal_readers_joined = payload.get("readers_joined") is True
            self.terminal_queue_drained = payload.get("queue_drained") is True
            late_count = payload.get("late_event_count")
            reader_error_count = payload.get("reader_error_count")
            self.terminal_late_event_count = (
                late_count if isinstance(late_count, int) and not isinstance(late_count, bool) else None
            )
            self.terminal_reader_error_count = (
                reader_error_count
                if isinstance(reader_error_count, int) and not isinstance(reader_error_count, bool)
                else None
            )
            if status != "completed" or typed_status != status:
                return self._normalized(
                    kind=NormalizedEventKind.TURN_TERMINAL,
                    classification="lifecycle-observed",
                    method=method,
                    shape_sha256=shape_sha256,
                    treatment=DecisionTreatment.COMPATIBILITY_VIOLATION,
                    code="turn_terminal_not_completed",
                )
            if (
                not self.terminal_readers_joined
                or not self.terminal_queue_drained
                or self.terminal_late_event_count != 0
                or self.terminal_reader_error_count != 0
            ):
                return self._normalized(
                    kind=NormalizedEventKind.TURN_TERMINAL,
                    classification="lifecycle-observed",
                    method=method,
                    shape_sha256=shape_sha256,
                    treatment=DecisionTreatment.COMPATIBILITY_VIOLATION,
                    code="terminal_barrier_incomplete",
                )
            if (
                self.final_agent_message_count != 1
                or self.validated_proposal_sha256 is None
                or payload.get("result_proposal_sha256")
                != self.validated_proposal_sha256
            ):
                return self._normalized(
                    kind=NormalizedEventKind.TURN_TERMINAL,
                    classification="lifecycle-observed",
                    method=method,
                    shape_sha256=shape_sha256,
                    treatment=DecisionTreatment.COMPATIBILITY_VIOLATION,
                    code="typed_result_proposal_mismatch",
                )
            return self._normalized(
                kind=NormalizedEventKind.TURN_TERMINAL,
                classification="lifecycle-observed",
                method=method,
                shape_sha256=shape_sha256,
                treatment=DecisionTreatment.PROPOSAL_ELIGIBLE,
                code="proposal_schema_eligible",
            )
        raise ProtocolViolation("lifecycle_method_unhandled")

    def _evaluate_item(
        self,
        payload: Mapping[str, Any],
        *,
        method: str,
        shape_sha256: str,
        completed: bool,
    ) -> NormalizedEvent:
        item_type = payload.get("item_type")
        if not isinstance(item_type, str):
            raise ProtocolViolation("item_type_missing_or_malformed")
        treatment = self.inventory.item_treatments.get(item_type)
        if treatment is None:
            raise ProtocolViolation(
                "item_type_unknown",
                diagnostic_digest=_digest_name(
                    item_type, salt_sha256=self.inventory.diagnostic_salt_sha256
                ),
            )
        if treatment == "prohibit":
            if item_type == "commandExecution":
                source = payload.get("source")
                if source is None:
                    raise ProtocolViolation("command_source_missing")
                if not isinstance(source, str):
                    raise ProtocolViolation("command_source_malformed")
                code = self.inventory.command_source_codes.get(source)
                if code is None:
                    raise ProtocolViolation(
                        "command_source_unknown",
                        diagnostic_digest=_digest_name(
                            source, salt_sha256=self.inventory.diagnostic_salt_sha256
                        ),
                    )
                return self._normalized(
                    kind=(
                        NormalizedEventKind.ACTION_COMPLETED
                        if completed
                        else NormalizedEventKind.ACTION_STARTED
                    ),
                    classification="action-prohibited",
                    method=method,
                    shape_sha256=shape_sha256,
                    treatment=DecisionTreatment.PROHIBITED,
                    code=code,
                    public_value=source,
                )
            return self._normalized(
                kind=(
                    NormalizedEventKind.ACTION_COMPLETED
                    if completed
                    else NormalizedEventKind.ACTION_STARTED
                ),
                classification="action-prohibited",
                method=method,
                shape_sha256=shape_sha256,
                treatment=DecisionTreatment.PROHIBITED,
                code=(
                    "file_change_event_prohibited"
                    if item_type == "fileChange"
                    else "action_item_prohibited"
                ),
                public_value=item_type,
            )
        if completed:
            if item_type != self.open_item_type:
                raise ProtocolViolation("item_completed_type_mismatch")
            if item_type == "agentMessage":
                if payload.get("message_phase") != "final_answer":
                    raise ProtocolViolation(
                        "final_agent_message_phase_invalid",
                        diagnostic_digest=_digest_name(
                            payload.get("message_phase"),
                            salt_sha256=self.inventory.diagnostic_salt_sha256,
                        ),
                    )
                proposal = payload.get("proposal")
                proposal_sha256 = self._validate_proposal(proposal)
                if self.final_agent_message_count != 0:
                    raise ProtocolViolation("multiple_final_agent_messages")
                self.final_agent_message_count = 1
                self.validated_proposal_sha256 = proposal_sha256
            self.open_item_type = None
            self.phase = "turn"
            kind = NormalizedEventKind.ACTION_COMPLETED
            code = "non_action_item_completed"
        else:
            self.open_item_type = item_type
            self.phase = "item"
            kind = NormalizedEventKind.ACTION_STARTED
            code = "non_action_item_started"
        return self._normalized(
            kind=kind,
            classification="lifecycle-observed",
            method=method,
            shape_sha256=shape_sha256,
            treatment=DecisionTreatment.OBSERVE,
            code=code,
            public_value=item_type,
        )

    def _validate_proposal(self, proposal: object) -> str:
        return validate_structured_proposal(proposal, self.inventory)

    def _observe_lifecycle(
        self, method: str, shape_sha256: str, code: str
    ) -> NormalizedEvent:
        return self._normalized(
            kind=NormalizedEventKind.LIFECYCLE_OBSERVED,
            classification="lifecycle-observed",
            method=method,
            shape_sha256=shape_sha256,
            treatment=DecisionTreatment.OBSERVE,
            code=code,
        )

    @staticmethod
    def _normalized(
        *,
        kind: NormalizedEventKind,
        classification: str,
        method: str,
        shape_sha256: str,
        treatment: DecisionTreatment,
        code: str,
        public_value: str | None = None,
    ) -> NormalizedEvent:
        return NormalizedEvent(
            kind=kind,
            classification=classification,
            method=method,
            method_digest=None,
            public_value=public_value,
            value_digest=None,
            structural_shape_sha256=shape_sha256,
            correlation_valid=True,
            decision=CapabilityDecision(treatment, code),
        )


def validate_structured_proposal(
    proposal: object, inventory: ProtocolInventory
) -> str:
    """Validate one exact transient proposal and return only its canonical digest."""

    if not isinstance(proposal, Mapping):
        raise ProtocolViolation("proposal_missing_or_malformed")
    unknown = sorted(str(key) for key in set(proposal) - PROPOSAL_KEYS)
    if unknown:
        raise ProtocolViolation(
            "proposal_unknown_key",
            diagnostic_digest=_digest_name(
                unknown[0], salt_sha256=inventory.diagnostic_salt_sha256
            ),
        )
    if set(proposal) != PROPOSAL_KEYS:
        raise ProtocolViolation("proposal_schema_incomplete")
    if proposal.get("schema_version") != inventory.proposal_schema_version:
        raise ProtocolViolation("proposal_schema_version_mismatch")
    if proposal.get("operation") != inventory.proposal_operation:
        raise ProtocolViolation(
            "proposal_operation_not_allowed",
            diagnostic_digest=_digest_name(
                proposal.get("operation"),
                salt_sha256=inventory.diagnostic_salt_sha256,
            ),
        )
    if proposal.get("baseline_sha256") != inventory.proposal_baseline_sha256:
        raise ProtocolViolation("proposal_baseline_mismatch")
    if proposal.get("path") != inventory.proposal_path:
        raise ProtocolViolation("proposal_path_not_allowed")
    if proposal.get("original_sha256") != inventory.proposal_original_sha256:
        raise ProtocolViolation("proposal_original_digest_mismatch")
    replacement = proposal.get("replacement")
    if not isinstance(replacement, str) or "\x00" in replacement:
        raise ProtocolViolation("proposal_replacement_not_utf8_text")
    try:
        replacement_bytes = replacement.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ProtocolViolation("proposal_replacement_not_utf8_text") from exc
    if len(replacement_bytes) > inventory.proposal_max_replacement_bytes:
        raise ProtocolViolation("proposal_replacement_byte_budget_exceeded")
    line_count = len(replacement.splitlines())
    if line_count > inventory.proposal_max_lines:
        raise ProtocolViolation("proposal_replacement_line_budget_exceeded")
    if any(pattern.search(replacement) for pattern in SECRET_PATTERNS):
        raise ProtocolViolation("proposal_secret_like_content")
    return sha256_bytes(canonical_json(dict(proposal)).encode("utf-8"))


def run_replay_case(
    case: Mapping[str, Any], inventory: ProtocolInventory
) -> ReplayReceipt:
    case_id = case.get("id")
    if not isinstance(case_id, str) or not CASE_ID_PATTERN.fullmatch(case_id):
        raise ProtocolViolation("replay_case_id_invalid")
    events = case.get("events")
    if not isinstance(events, list):
        raise ProtocolViolation("replay_case_events_invalid")
    if len(events) > inventory.limits.max_events:
        events = events[: inventory.limits.max_events]
        overflow = True
    else:
        overflow = False

    machine = ProposalReplayMachine(inventory)
    terminal: NormalizedEvent | None = None
    for raw_event in events:
        normalized = machine.observe(raw_event)
        terminal = normalized
        if normalized.decision.treatment in {
            DecisionTreatment.PROHIBITED,
            DecisionTreatment.COMPATIBILITY_VIOLATION,
        }:
            break
    if overflow and (
        terminal is None
        or terminal.decision.treatment
        not in {DecisionTreatment.PROHIBITED, DecisionTreatment.COMPATIBILITY_VIOLATION}
    ):
        terminal = machine._failure_event(
            {}, ProtocolViolation("event_limit_exceeded")
        )
        machine._record(terminal)
    if terminal is None or terminal.decision.treatment is DecisionTreatment.OBSERVE:
        terminal = machine._failure_event(
            {}, ProtocolViolation("sequence_incomplete")
        )
        machine._record(terminal)

    return ReplayReceipt(
        case_id=case_id,
        outcome=terminal.decision.treatment.value,
        decision_code=terminal.decision.code,
        event_count=machine.event_count,
        event_chain_sha256=machine.event_chain_sha256,
        final_phase=machine.phase,
        known_method_counts=dict(machine.known_method_counts),
        diagnostic_public_value=terminal.public_value,
        diagnostic_digest=terminal.value_digest,
        final_agent_message_count=machine.final_agent_message_count,
        validated_proposal_sha256=machine.validated_proposal_sha256,
        terminal_readers_joined=machine.terminal_readers_joined,
        terminal_queue_drained=machine.terminal_queue_drained,
        terminal_late_event_count=machine.terminal_late_event_count,
        terminal_reader_error_count=machine.terminal_reader_error_count,
        typed_result_consistent=machine.typed_result_consistent,
    )


def load_replay_corpus(path: Path) -> dict[str, Any]:
    raw = json.loads(
        _decode_utf8(_read_regular_file(path)),
        object_pairs_hook=_json_reject_duplicate_pairs,
    )
    if (
        not isinstance(raw, dict)
        or set(raw) != {"format", "version", "cases"}
        or raw.get("format") != "atlas-supervisor-v4-replays"
    ):
        raise ProtocolViolation("replay_corpus_format_invalid")
    if raw.get("version") != 1 or not isinstance(raw.get("cases"), list):
        raise ProtocolViolation("replay_corpus_format_invalid")
    ids: list[str] = []
    for case in raw["cases"]:
        if (
            not isinstance(case, dict)
            or set(case) != {"id", "events", "expected"}
            or not isinstance(case.get("id"), str)
            or not CASE_ID_PATTERN.fullmatch(case["id"])
            or not isinstance(case.get("events"), list)
            or not isinstance(case.get("expected"), dict)
            or set(case["expected"]) != {"outcome", "decision_code"}
            or case["expected"].get("outcome")
            not in {
                DecisionTreatment.PROPOSAL_ELIGIBLE.value,
                DecisionTreatment.PROHIBITED.value,
                DecisionTreatment.COMPATIBILITY_VIOLATION.value,
            }
            or not isinstance(case["expected"].get("decision_code"), str)
        ):
            raise ProtocolViolation("replay_case_format_invalid")
        ids.append(case["id"])
    if len(ids) != len(set(ids)):
        raise ProtocolViolation("replay_case_id_duplicated")
    return raw


def replay_corpus_sha256(corpus: Mapping[str, Any]) -> str:
    return sha256_bytes(canonical_json(corpus).encode("utf-8"))


__all__ = [
    "CapabilityBindings",
    "CapabilityDecision",
    "COMMAND_SOURCES",
    "DecisionTreatment",
    "ImmutablePolicyBundle",
    "NormalizedEvent",
    "NormalizedEventKind",
    "PolicyBroker",
    "ProposalReplayMachine",
    "ProtocolInventory",
    "ProtocolViolation",
    "ReceiptSigner",
    "ReplayReceipt",
    "SignedCapabilityEnvelope",
    "SignedReceiptLink",
    "StructuralLimits",
    "bounded_structural_shape",
    "canonical_json",
    "load_replay_corpus",
    "replay_corpus_sha256",
    "run_replay_case",
    "validate_structured_proposal",
]
