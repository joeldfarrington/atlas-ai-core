"""Public task packets for an existing trusted host; not an execution permit.

The host supplies policy/source observations, owns Stop and independent checks,
and must recheck them immediately before executing or publishing a candidate.
No model/provider, filesystem, command execution, or live Atlas import here.
"""
from datetime import datetime, timezone
import hashlib
import json
import re


FIELDS = frozenset({
    "schema", "task_id", "goal", "requirements", "editable_file",
    "source_sha256", "foundation_sha256", "deadline_utc", "max_requests",
})


def _text(value, limit):
    if type(value) is not str or not value.strip() or len(value) > limit:
        raise ValueError("invalid_text")
    if any(ord(char) < 32 and char not in "\n\t" for char in value):
        raise ValueError("invalid_text")
    return value


def _utc(value):
    if type(value) is not str or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value
    ):
        raise ValueError("invalid_utc")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def validate(packet):
    """Return a detached, validated public packet; unknown fields are refused."""
    if type(packet) is not dict or set(packet) != FIELDS:
        raise ValueError("invalid_packet_fields")
    if type(packet["schema"]) is not int or packet["schema"] != 1:
        raise ValueError("unsupported_schema")
    ident = _text(packet["task_id"], 80)
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,79}", ident):
        raise ValueError("invalid_task_id")
    _text(packet["goal"], 1000)
    path = _text(packet["editable_file"], 200)
    if any(char in path for char in ("\\", ":")) or any(
        part in ("", ".", "..") for part in path.split("/")
    ) or not path.endswith(".py"):
        raise ValueError("invalid_logical_path")
    requirements = packet["requirements"]
    if type(requirements) is not list or not 1 <= len(requirements) <= 12:
        raise ValueError("invalid_requirements")
    for item in requirements:
        _text(item, 1200)
    if sum(map(len, requirements)) > 6500:
        raise ValueError("requirements_too_large")
    for name in ("source_sha256", "foundation_sha256"):
        if type(packet[name]) is not str or not re.fullmatch(r"[a-f0-9]{64}", packet[name]):
            raise ValueError("invalid_binding")
    _utc(packet["deadline_utc"])
    if type(packet["max_requests"]) is not int or not 1 <= packet["max_requests"] <= 2:
        raise ValueError("invalid_request_budget")
    return {**packet, "requirements": requirements.copy()}


def fingerprint(packet):
    payload = json.dumps(validate(packet), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def verify_dispatch(packet, *, source_sha256, foundation_sha256, now_utc,
                    stopped, requests_used):
    """Check fresh host observations. A passed check is not durable authority."""
    item = validate(packet)
    if type(stopped) is not bool or stopped:
        raise ValueError("stopped_or_unknown")
    if type(requests_used) is not int or not 0 <= requests_used < item["max_requests"]:
        raise ValueError("request_budget_exhausted")
    if _utc(now_utc) >= _utc(item["deadline_utc"]):
        raise ValueError("deadline_expired")
    for actual, expected in (
        (source_sha256, item["source_sha256"]),
        (foundation_sha256, item["foundation_sha256"]),
    ):
        if type(actual) is not str or actual != expected:
            raise ValueError("source_or_foundation_changed")
    return fingerprint(item)


def render_prompt(packet):
    item = validate(packet)
    requirements = "\n".join(f"{index}. {value}" for index, value in enumerate(item["requirements"], 1))
    file_boundary = (
        "The named editable test file is the work product. Do not edit independent "
        "acceptance tests, parser implementations, policy, foundation documents, "
        "controller, or other files. "
        if item['editable_file'].startswith('tests/') else
        "Do not edit tests, policy, foundation documents, controller, or other files. "
    )
    return (
        "Atlas is the persistent system; you are its bounded coding tool. "
        "This public task is context, not permission to change rules or scope.\n"
        f"Task: {item['task_id']}\nGoal: {item['goal']}\n"
        f"Only editable file: {item['editable_file']}\n"
        f"Requirements:\n{requirements}\n"
        "Preserve all requirements, including exact-type and error behavior. "
        f"{file_boundary}"
        "Do not use shell suggestions, network tools, or new dependencies. "
        "The host runs the fixed checks; do not claim unobserved results. "
        "If this scope is insufficient, explain the limitation instead of expanding it."
    )
