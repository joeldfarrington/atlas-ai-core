from __future__ import annotations

import hashlib
import json
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


CLASS_NAMES = (
    "lifecycle-critical",
    "action-critical",
    "passive-metadata",
    "content-stream",
    "disabled-capability-status",
    "prohibited-capability",
    "unknown-or-unclassified",
)
METHOD_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9]*(?:/[A-Za-z][A-Za-z0-9]*)*$")
ZERO_DIGEST = "0" * 64
V3_DISABLED_FEATURES = (
    "apps",
    "auth_elicitation",
    "browser_use",
    "browser_use_external",
    "browser_use_full_cdp_access",
    "computer_use",
    "goals",
    "hooks",
    "image_generation",
    "in_app_browser",
    "memories",
    "multi_agent",
    "multi_agent_v2",
    "plugins",
    "realtime_conversation",
    "remote_control",
    "remote_plugin",
    "request_permissions_tool",
    "shell_snapshot",
    "skill_mcp_dependency_install",
    "skill_search",
    "tool_suggest",
    "view_image",
    "workspace_dependencies",
)
V3_SHELL_ENV_KEYS = (
    "CI",
    "GIT_OPTIONAL_LOCKS",
    "LANG",
    "NO_UPDATE_NOTIFIER",
    "PATH",
    "PYTHONDONTWRITEBYTECODE",
    "TMPDIR",
)
V3_ALL_STAGES = frozenset(
    {
        "canary",
        "successor_canary",
        "fixture",
        "recovery_canary",
        "recovery_fixture",
    }
)
V3_READ_ONLY_STAGES = frozenset({"canary", "successor_canary"})
V3_RESPONSE_CANARY_STAGES = frozenset(
    {"canary", "successor_canary", "recovery_canary"}
)
V3_EDIT_STAGES = frozenset({"fixture", "recovery_fixture"})
V3_PROJECT_STAGES = frozenset({"fixture", "recovery_canary", "recovery_fixture"})
V3_DISABLED_STATUS_STAGES = frozenset(
    {"successor_canary", "recovery_canary", "recovery_fixture"}
)


class ProtocolViolation(RuntimeError):
    """A fail-closed protocol, phase, size, or capability violation."""


def supervisor_v3_permission_profile(stage: str) -> tuple[str, dict[str, Any]]:
    """Return the one reviewed named permission profile for a v3 stage."""

    if stage not in V3_ALL_STAGES:
        raise ProtocolViolation("permission_profile_stage_invalid")
    profile_name = f"atlas_v3_{stage}"
    access = "read" if stage in V3_READ_ONLY_STAGES else "write"
    return profile_name, {
        "filesystem": {
            ":root": "deny",
            ":minimal": "read",
            ":workspace_roots": {".": access},
        },
        "network": {"enabled": False},
    }


def supervisor_v3_permission_profile_toml(stage: str) -> str:
    profile_name, profile = supervisor_v3_permission_profile(stage)
    access = profile["filesystem"][":workspace_roots"]["."]
    return (
        f'permissions={{ {profile_name} = {{ filesystem = {{ ":root" = "deny", '
        f'":minimal" = "read", ":workspace_roots" = {{ "." = "{access}" }} }}, '
        "network = { enabled = false } } }"
    )


def supervisor_v3_permission_profile_sha256(stage: str) -> str:
    profile_name, profile = supervisor_v3_permission_profile(stage)
    payload = {"stage": stage, "id": profile_name, "profile": profile}
    return _digest(_canonical_json(payload).encode("utf-8"))


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _string_length_bucket(length: int) -> str:
    if length == 0:
        return "0"
    for ceiling in (15, 63, 255, 1_023, 4_095, 16_383, 65_535):
        if length <= ceiling:
            return f"1-{ceiling}"
    return "65536+"


def redacted_structural_shape(value: Any, *, unknown_keys: bool = False) -> Any:
    """Return types, bounded sizes, and keys without retaining scalar values."""

    if value is None:
        return {"type": "null"}
    if isinstance(value, bool):
        return {"type": "boolean"}
    if isinstance(value, int) and not isinstance(value, bool):
        return {"type": "integer"}
    if isinstance(value, float):
        return {"type": "number"}
    if isinstance(value, str):
        return {"type": "string", "length": _string_length_bucket(len(value))}
    if isinstance(value, list):
        return {
            "type": "array",
            "count": len(value),
            "items": [
                redacted_structural_shape(item, unknown_keys=unknown_keys)
                for item in value[:64]
            ],
            "truncated": len(value) > 64,
        }
    if isinstance(value, dict):
        entries: list[dict[str, Any]] = []
        for raw_key in sorted(str(key) for key in value)[:128]:
            stored_key = (
                _digest(raw_key.encode("utf-8"))[:16] if unknown_keys else raw_key[:128]
            )
            entries.append(
                {
                    "key": stored_key,
                    "value": redacted_structural_shape(
                        value.get(raw_key), unknown_keys=unknown_keys
                    ),
                }
            )
        return {
            "type": "object",
            "count": len(value),
            "entries": entries,
            "truncated": len(value) > 128,
        }
    return {"type": type(value).__name__[:64]}


@dataclass(frozen=True, slots=True)
class NotificationPolicy:
    version: int
    sdk_version: str
    stable_method_count: int
    classifications: dict[str, str]
    server_requests: frozenset[str]
    opt_out_notification_methods: tuple[str, ...]

    @classmethod
    def load(
        cls,
        path: Path,
        *,
        expected_notifications: Iterable[str] | None = None,
        expected_server_requests: Iterable[str] | None = None,
    ) -> "NotificationPolicy":
        import yaml

        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if raw.get("version") != 1 or not isinstance(raw.get("classes"), dict):
            raise ProtocolViolation("Supervisor v3 classifier format is invalid")
        classes = raw["classes"]
        if set(classes) != set(CLASS_NAMES):
            raise ProtocolViolation("Supervisor v3 classifier classes drifted")
        classifications: dict[str, str] = {}
        duplicates: set[str] = set()
        for class_name in CLASS_NAMES:
            methods = classes[class_name]
            if not isinstance(methods, list) or any(not isinstance(item, str) for item in methods):
                raise ProtocolViolation("Supervisor v3 classifier contains malformed methods")
            for method in methods:
                if method in classifications:
                    duplicates.add(method)
                classifications[method] = class_name
        if duplicates:
            raise ProtocolViolation("Supervisor v3 classifier contains duplicate methods")
        declared_count = raw.get("stable_method_count")
        if declared_count != len(classifications):
            raise ProtocolViolation("Supervisor v3 classifier count is inconsistent")
        if classes["unknown-or-unclassified"]:
            raise ProtocolViolation("Known methods cannot use the unknown classifier bucket")
        expected = set(expected_notifications or classifications)
        if set(classifications) != expected:
            raise ProtocolViolation("Supervisor v3 stable notification coverage drifted")
        requests = raw.get("server_requests")
        if not isinstance(requests, list) or any(not isinstance(item, str) for item in requests):
            raise ProtocolViolation("Supervisor v3 server-request inventory is invalid")
        request_set = frozenset(requests)
        if len(request_set) != len(requests):
            raise ProtocolViolation("Supervisor v3 server-request inventory has duplicates")
        if expected_server_requests is not None and request_set != set(expected_server_requests):
            raise ProtocolViolation("Supervisor v3 stable server-request coverage drifted")
        opt_out = raw.get("opt_out_notification_methods", [])
        if not isinstance(opt_out, list) or any(item not in classifications for item in opt_out):
            raise ProtocolViolation("Supervisor v3 opt-out notification list is invalid")
        return cls(
            version=1,
            sdk_version=str(raw.get("sdk_version") or ""),
            stable_method_count=int(declared_count),
            classifications=classifications,
            server_requests=request_set,
            opt_out_notification_methods=tuple(opt_out),
        )

    def classify(self, method: str) -> str:
        return self.classifications.get(method, "unknown-or-unclassified")


@dataclass(slots=True)
class EnvelopeChain:
    max_line_bytes: int
    max_events: int
    sequence: int = 0
    chain_sha256: str = ZERO_DIGEST
    class_counts: Counter[str] = field(default_factory=Counter)
    method_counts: Counter[str] = field(default_factory=Counter)

    def record(
        self,
        *,
        direction: str,
        phase: str,
        method: object,
        classification: str,
        payload: Any,
        schema_sha256: str | None,
        schema_valid: bool,
        request_id: object = None,
        expected_request_id: object = None,
        correlations: dict[str, bool | None] | None = None,
    ) -> dict[str, Any]:
        encoded = _canonical_json(payload).encode("utf-8")
        if len(encoded) > self.max_line_bytes:
            raise ProtocolViolation("protocol_line_too_large")
        if self.sequence >= self.max_events:
            raise ProtocolViolation("protocol_event_limit_exceeded")
        self.sequence += 1
        known_method = isinstance(method, str) and bool(METHOD_PATTERN.fullmatch(method))
        method_label = method if known_method else None
        method_digest = None if known_method else _digest(str(method).encode("utf-8"))[:16]
        request_id_type = "none" if request_id is None else type(request_id).__name__[:32]
        expected_match = None
        if expected_request_id is not None:
            expected_match = type(request_id) is type(expected_request_id) and request_id == expected_request_id
        shape = redacted_structural_shape(payload, unknown_keys=not known_method)
        envelope: dict[str, Any] = {
            "sequence": self.sequence,
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "monotonic_ns": time.monotonic_ns(),
            "direction": direction[:16],
            "phase": phase[:32],
            "method": method_label,
            "method_digest": method_digest,
            "classification": classification,
            "request_id_type": request_id_type,
            "expected_request_id_match": expected_match,
            "byte_length": len(encoded),
            "top_level_collection_size": len(payload) if isinstance(payload, (dict, list)) else None,
            "schema_sha256": schema_sha256,
            "schema_valid": bool(schema_valid),
            "shape_sha256": _digest(_canonical_json(shape).encode("utf-8")),
            "correlations": dict(correlations or {}),
        }
        self.chain_sha256 = _digest(
            self.chain_sha256.encode("ascii") + _canonical_json(envelope).encode("utf-8")
        )
        self.class_counts[classification] += 1
        self.method_counts[str(method_label or f"digest:{method_digest}")] += 1
        return envelope

    def summary(self) -> dict[str, Any]:
        return {
            "envelope_count": self.sequence,
            "envelope_chain_sha256": self.chain_sha256,
            "classification_counts": dict(sorted(self.class_counts.items())),
            "method_counts": dict(sorted(self.method_counts.items())),
            "raw_protocol_persisted": False,
            "prompt_persisted": False,
            "response_persisted": False,
            "reasoning_persisted": False,
            "command_output_persisted": False,
        }


@dataclass(slots=True)
class ProtocolState:
    """Small, explicit lifecycle validator used by real and fake SDK drivers."""

    stage: str
    phase: str = "initialize"
    thread_started: bool = False
    turn_started: bool = False
    turn_completed: bool = False
    open_items: dict[str, str] = field(default_factory=dict)

    def open_item_type(self, item_id: object) -> str | None:
        return self.open_items.get(item_id) if isinstance(item_id, str) else None

    def observe(self, method: str, payload: dict[str, Any], classification: str) -> None:
        if classification in {"prohibited-capability", "unknown-or-unclassified"}:
            raise ProtocolViolation(f"prohibited_notification:{method}")
        if method == "error":
            raise ProtocolViolation("app_server_error_notification")
        if self.turn_completed and method not in {
            "thread/status/changed",
            "thread/tokenUsage/updated",
            "account/rateLimits/updated",
        }:
            raise ProtocolViolation(f"notification_after_terminal:{method}")
        if method == "thread/started":
            if self.thread_started or self.turn_started:
                raise ProtocolViolation("thread_started_wrong_phase")
            self.thread_started = True
            self.phase = "thread"
        elif method == "turn/started":
            if not self.thread_started or self.turn_started:
                raise ProtocolViolation("turn_started_wrong_phase")
            self.turn_started = True
            self.phase = "turn"
        elif method == "item/started":
            if not self.turn_started or self.turn_completed:
                raise ProtocolViolation("item_started_wrong_phase")
            item = payload.get("item")
            item_id = item.get("id") if isinstance(item, dict) else None
            item_type = item.get("type") if isinstance(item, dict) else None
            if not isinstance(item_id, str) or not isinstance(item_type, str):
                raise ProtocolViolation("item_started_missing_identity")
            allowed = {"userMessage", "agentMessage", "reasoning"}
            if self.stage in V3_EDIT_STAGES:
                allowed |= {"commandExecution", "fileChange", "plan"}
            if item_type not in allowed:
                raise ProtocolViolation(f"item_type_not_allowed:{item_type[:64]}")
            if item_id in self.open_items:
                raise ProtocolViolation("item_started_duplicate_identity")
            self.open_items[item_id] = item_type
        elif method == "item/completed":
            item = payload.get("item")
            item_id = item.get("id") if isinstance(item, dict) else None
            item_type = item.get("type") if isinstance(item, dict) else None
            if not isinstance(item_id, str) or item_id not in self.open_items:
                raise ProtocolViolation("item_completed_without_start")
            if item_type != self.open_items[item_id]:
                raise ProtocolViolation("item_completed_type_mismatch")
            del self.open_items[item_id]
        elif method == "turn/completed":
            if not self.turn_started or self.turn_completed or self.open_items:
                raise ProtocolViolation("turn_completed_wrong_phase")
            turn = payload.get("turn")
            status = turn.get("status") if isinstance(turn, dict) else None
            if status != "completed":
                raise ProtocolViolation("turn_terminal_status_not_completed")
            self.turn_completed = True
            self.phase = "terminal"


def validate_disabled_capability_status(
    *,
    stage: str,
    method: str,
    payload: dict[str, Any],
    effective_config_verified: bool,
    prior_count: int,
) -> None:
    """Accept only reviewed stages' exact proof that remote control is off."""

    if stage not in V3_DISABLED_STATUS_STAGES or method != "remoteControl/status/changed":
        raise ProtocolViolation(f"prohibited_notification:{method}")
    if not effective_config_verified:
        raise ProtocolViolation("remote_control_status_before_config_verification")
    if prior_count != 0:
        raise ProtocolViolation("remote_control_status_repeated")
    if set(payload) not in (
        {"installationId", "serverName", "status"},
        {"environmentId", "installationId", "serverName", "status"},
    ):
        raise ProtocolViolation("remote_control_status_shape_invalid")
    if payload.get("environmentId") is not None:
        raise ProtocolViolation("remote_control_environment_present")
    if payload.get("status") != "disabled":
        raise ProtocolViolation("remote_control_status_not_disabled")
    for field in ("installationId", "serverName"):
        value = payload.get(field)
        if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 512:
            raise ProtocolViolation("remote_control_status_identity_invalid")


__all__ = [
    "CLASS_NAMES",
    "EnvelopeChain",
    "NotificationPolicy",
    "ProtocolState",
    "ProtocolViolation",
    "V3_DISABLED_FEATURES",
    "V3_ALL_STAGES",
    "V3_DISABLED_STATUS_STAGES",
    "V3_EDIT_STAGES",
    "V3_PROJECT_STAGES",
    "V3_READ_ONLY_STAGES",
    "V3_RESPONSE_CANARY_STAGES",
    "V3_SHELL_ENV_KEYS",
    "redacted_structural_shape",
    "supervisor_v3_permission_profile",
    "supervisor_v3_permission_profile_sha256",
    "supervisor_v3_permission_profile_toml",
    "validate_disabled_capability_status",
]
