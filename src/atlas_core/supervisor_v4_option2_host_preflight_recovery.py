"""Predecessor-bound recovery for the Option 2 identity host preflight.

This module is inert unless a caller supplies the exact owner phrase bound to
the terminal original claim.  Its only live-capable operation repeats the same
network-denied, read-only local-directory inventory used by the original
preflight.  It has no account, group, filesystem, Keychain, launchd, model, or
provider mutation operation.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import plistlib
import re
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping
from uuid import UUID

from atlas_core.supervisor_v4_option2_host_preflight import (
    OPTION2_HOST_INVENTORY_MAX_ENTITIES,
    OPTION2_HOST_NUMERIC_ID_RANGE,
    OPTION2_HOST_PREFLIGHT_CLAIM_SUBJECT,
    OPTION2_HOST_PREFLIGHT_NEXT_GATE,
    OPTION2_HOST_QUERY_COUNT,
    OPTION2_LOCAL_DIRECTORY_NODE,
    Option2HostPreflightViolation,
    _run_dscl_listing,
    build_option2_host_candidate,
    validate_option2_host_candidate,
)
from atlas_core.supervisor_v4_option2_identity_candidate import (
    OPTION2_IDENTITY_CANDIDATE_AUTHORITY_FIELDS,
    OPTION2_IDENTITY_CANDIDATE_MAX_VALIDITY_SECONDS,
    OPTION2_SERVICE_IDENTITIES,
)
from atlas_core.supervisor_v4_process import (
    SupervisedCompletedProcess,
    run_supervised,
)


OPTION2_HOST_PREFLIGHT_RECOVERY_VERSION = 1
OPTION2_HOST_PREFLIGHT_RECOVERY_STATE = "recovery_implemented_inactive"
OPTION2_HOST_PREFLIGHT_RECOVERY_CLAIM_STATE = (
    "read_only_recovery_preflight_claimed_inactive"
)
OPTION2_HOST_PREFLIGHT_RECOVERY_CANDIDATE_STATE = (
    "recovery_candidate_generated_inactive"
)
OPTION2_HOST_PREFLIGHT_RECOVERY_CLAIM_SUBJECT = (
    "option2.identity-only-host-preflight.recovery-claim.v1"
)
OPTION2_HOST_PREFLIGHT_RECOVERY_CANDIDATE_SUBJECT = (
    "option2.identity-only-host-preflight.recovery-candidate.v1"
)
OPTION2_HOST_PREFLIGHT_RECOVERY_AUTHORIZATION_GATE = (
    "owner_authorize_option2_identity_only_host_preflight_recovery"
)
OPTION2_HOST_PREFLIGHT_RECOVERY_RESULT_GATE = (
    "owner_review_option2_identity_only_host_preflight_recovery_result"
)
OPTION2_HOST_PREFLIGHT_RECOVERY_CONFIRMATION_PREFIX = (
    "AUTHORIZE OPTION2 ONE-SHOT IDENTITY HOST PREFLIGHT RECOVERY"
)
OPTION2_HOST_PREFLIGHT_RECOVERY_FAILURE_CONTEXT = (
    "option2_host_inventory_record_schema_invalid"
)

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_UUID4_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)
_SHORT_KEYS = {
    "name": "RecordName",
    "uid": "UniqueID",
    "gid": "PrimaryGroupID",
}
_STANDARD_KEYS = {
    "name": "dsAttrTypeStandard:RecordName",
    "uid": "dsAttrTypeStandard:UniqueID",
    "gid": "dsAttrTypeStandard:PrimaryGroupID",
}
_BINDING_FIELDS = {
    "reviewed_manifest_sha256",
    "manifest_review_content_sha256",
    "fixture_qualification_content_sha256",
    "sdk_lock_sha256",
    "policy_sha256",
    "host_preflight_source_sha256",
    "host_instance_sha256",
    "dscl_sha256",
    "sandbox_exec_sha256",
    "sandbox_profile_sha256",
}

HostRunner = Callable[..., SupervisedCompletedProcess]


def _canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _sha256(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _validated_sha256(value: object, *, code: str) -> str:
    if (
        not isinstance(value, str)
        or _SHA256_PATTERN.fullmatch(value) is None
        or value == "0" * 64
    ):
        raise Option2HostPreflightViolation(code)
    return value


def _validated_uuid4(value: object, *, code: str) -> str:
    if not isinstance(value, str) or _UUID4_PATTERN.fullmatch(value) is None:
        raise Option2HostPreflightViolation(code)
    try:
        parsed = UUID(value)
    except ValueError as error:
        raise Option2HostPreflightViolation(code) from error
    if parsed.version != 4 or str(parsed) != value:
        raise Option2HostPreflightViolation(code)
    return value


def _canonical_window(issued_at: object, expires_at: object) -> tuple[str, str]:
    parsed: list[datetime] = []
    for value, code in (
        (issued_at, "option2_host_recovery_issued_at_invalid"),
        (expires_at, "option2_host_recovery_expires_at_invalid"),
    ):
        if not isinstance(value, str) or not value:
            raise Option2HostPreflightViolation(code)
        candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
        try:
            moment = datetime.fromisoformat(candidate)
        except ValueError as error:
            raise Option2HostPreflightViolation(code) from error
        if moment.tzinfo is None or moment.utcoffset() is None or moment.microsecond:
            raise Option2HostPreflightViolation(code)
        parsed.append(moment.astimezone(timezone.utc))
    lifetime = (parsed[1] - parsed[0]).total_seconds()
    if lifetime <= 0 or lifetime > OPTION2_IDENTITY_CANDIDATE_MAX_VALIDITY_SECONDS:
        raise Option2HostPreflightViolation(
            "option2_host_recovery_validity_window_invalid"
        )
    return tuple(
        moment.strftime("%Y-%m-%dT%H:%M:%SZ") for moment in parsed
    )  # type: ignore[return-value]


def _validated_bindings(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != _BINDING_FIELDS:
        raise Option2HostPreflightViolation(
            "option2_host_recovery_bindings_invalid"
        )
    return {
        field: _validated_sha256(
            value.get(field), code=f"option2_host_recovery_{field}_invalid"
        )
        for field in sorted(_BINDING_FIELDS)
    }


def build_option2_host_preflight_recovery_authorization_phrase(
    *,
    predecessor_claim_id: str,
    predecessor_claim_content_sha256: str,
) -> str:
    """Build the only phrase that may authorize the recovery inventory read."""

    claim_id = _validated_uuid4(
        predecessor_claim_id,
        code="option2_host_recovery_predecessor_claim_id_invalid",
    )
    content_sha256 = _validated_sha256(
        predecessor_claim_content_sha256,
        code="option2_host_recovery_predecessor_content_digest_invalid",
    )
    return (
        f"{OPTION2_HOST_PREFLIGHT_RECOVERY_CONFIRMATION_PREFIX} "
        f"{claim_id} {content_sha256}"
    )


def parse_option2_dscl_plist_projection_recovery(
    output: str,
    *,
    numeric_field: str,
) -> dict[str, object]:
    """Parse only one of two explicit dscl attribute-key projections.

    A complete inventory must use either unqualified keys or the standard
    Directory Services prefix consistently.  Unknown, extra, native, or mixed
    keys fail closed.  Unrelated identity names are discarded after collision
    detection and never appear in the returned projection.
    """

    if numeric_field not in {"uid", "gid"}:
        raise Option2HostPreflightViolation(
            "option2_host_recovery_inventory_numeric_field_invalid"
        )
    if not isinstance(output, str) or not output or "\ufffd" in output:
        raise Option2HostPreflightViolation(
            "option2_host_recovery_inventory_output_invalid"
        )
    try:
        records = plistlib.loads(output.encode("utf-8"))
    except (ValueError, plistlib.InvalidFileException) as error:
        raise Option2HostPreflightViolation(
            "option2_host_recovery_inventory_plist_invalid"
        ) from error
    if (
        not isinstance(records, list)
        or not records
        or len(records) > OPTION2_HOST_INVENTORY_MAX_ENTITIES
    ):
        raise Option2HostPreflightViolation(
            "option2_host_recovery_inventory_record_count_invalid"
        )

    expected_styles = {
        "short": {_SHORT_KEYS["name"], _SHORT_KEYS[numeric_field]},
        "standard": {_STANDARD_KEYS["name"], _STANDARD_KEYS[numeric_field]},
    }
    selected_style: str | None = None
    target_names = {name.casefold(): name for name in OPTION2_SERVICE_IDENTITIES}
    present_targets: set[str] = set()
    occupied_in_band: set[int] = set()
    observed_aliases: set[str] = set()
    observed_numeric: set[int] = set()

    for record in records:
        if not isinstance(record, Mapping):
            raise Option2HostPreflightViolation(
                "option2_host_recovery_inventory_record_schema_invalid"
            )
        matching_styles = [
            style for style, keys in expected_styles.items() if set(record) == keys
        ]
        if len(matching_styles) != 1:
            raise Option2HostPreflightViolation(
                "option2_host_recovery_inventory_record_schema_invalid"
            )
        record_style = matching_styles[0]
        if selected_style is None:
            selected_style = record_style
        elif record_style != selected_style:
            raise Option2HostPreflightViolation(
                "option2_host_recovery_inventory_key_style_mixed"
            )
        keys = _SHORT_KEYS if record_style == "short" else _STANDARD_KEYS
        aliases = record.get(keys["name"])
        numeric_values = record.get(keys[numeric_field])
        if (
            not isinstance(aliases, list)
            or not aliases
            or len(aliases) > 16
            or not isinstance(numeric_values, list)
            or len(numeric_values) != 1
        ):
            raise Option2HostPreflightViolation(
                "option2_host_recovery_inventory_record_values_invalid"
            )
        numeric_text = numeric_values[0]
        if (
            not isinstance(numeric_text, str)
            or not numeric_text.isascii()
            or re.fullmatch(r"-?[0-9]{1,10}", numeric_text) is None
        ):
            raise Option2HostPreflightViolation(
                "option2_host_recovery_inventory_numeric_identity_invalid"
            )
        numeric_value = int(numeric_text)
        if (
            numeric_value < -2_147_483_648
            or numeric_value > 2_147_483_647
            or numeric_value in observed_numeric
        ):
            raise Option2HostPreflightViolation(
                "option2_host_recovery_inventory_numeric_identity_invalid"
            )
        observed_numeric.add(numeric_value)
        if OPTION2_HOST_NUMERIC_ID_RANGE[0] <= numeric_value <= OPTION2_HOST_NUMERIC_ID_RANGE[1]:
            occupied_in_band.add(numeric_value)
        for alias in aliases:
            if (
                not isinstance(alias, str)
                or not alias
                or len(alias.encode("utf-8")) > 255
                or any(ord(character) < 32 or ord(character) == 127 for character in alias)
                or "/" in alias
            ):
                raise Option2HostPreflightViolation(
                    "option2_host_recovery_inventory_record_name_invalid"
                )
            folded = alias.casefold()
            if folded in observed_aliases:
                raise Option2HostPreflightViolation(
                    "option2_host_recovery_inventory_alias_duplicate"
                )
            observed_aliases.add(folded)
            if folded in target_names:
                present_targets.add(target_names[folded])

    return {
        "target_names_present": sorted(
            present_targets, key=OPTION2_SERVICE_IDENTITIES.index
        ),
        "occupied_numeric_ids": sorted(occupied_in_band),
    }


def _recovery_claim_body(
    *,
    predecessor_claim_id: str,
    predecessor_claim_content_sha256: str,
    predecessor_claim_sha256: str,
    bindings: Mapping[str, str],
    authorization_confirmation_sha256: str,
    authorization_challenge_sha256: str,
    issued_at: str,
    expires_at: str,
) -> dict[str, object]:
    return {
        "version": OPTION2_HOST_PREFLIGHT_RECOVERY_VERSION,
        "classification": "option2_identity_only_host_preflight_recovery_one_use_claim",
        "recovery_claim_state": OPTION2_HOST_PREFLIGHT_RECOVERY_CLAIM_STATE,
        "predecessor": {
            "subject": OPTION2_HOST_PREFLIGHT_CLAIM_SUBJECT,
            "claim_id": predecessor_claim_id,
            "content_sha256": predecessor_claim_content_sha256,
            "claim_sha256": predecessor_claim_sha256,
            "observed_state": "preflight_consumed_incomplete",
            "reviewed_failure_context": OPTION2_HOST_PREFLIGHT_RECOVERY_FAILURE_CONTEXT,
        },
        "bindings": dict(bindings),
        "authorization_confirmation_sha256": authorization_confirmation_sha256,
        "authorization_challenge_sha256": authorization_challenge_sha256,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "max_validity_seconds": OPTION2_IDENTITY_CANDIDATE_MAX_VALIDITY_SECONDS,
        "recovery_attempt_limit": 1,
        "inventory_snapshot_limit": 2,
        "directory_query_limit": OPTION2_HOST_QUERY_COUNT,
        "candidate_limit": 1,
        "local_directory_node": OPTION2_LOCAL_DIRECTORY_NODE,
        "accepted_attribute_key_styles": ["short", "dsAttrTypeStandard"],
        "original_claim_reopened": False,
        "original_command_reusable": False,
        "host_inventory_read_authorized": True,
        "identity_mutation_authorized": False,
        "raw_inventory_persisted": False,
        "raw_inventory_returned": False,
        "authorization_challenge_persisted": False,
        "ordinary_or_http_route_present": False,
        "authority": {
            field: False for field in OPTION2_IDENTITY_CANDIDATE_AUTHORITY_FIELDS
        },
        "ready": False,
        "ready_offline": False,
        "ready_live": False,
        "next_internal_milestone": "option2_identity_only_host_preflight_recovery",
    }


def build_option2_host_preflight_recovery_claim(
    *,
    confirmation: str,
    authorization_challenge: str,
    predecessor_claim_id: str,
    predecessor_claim_content_sha256: str,
    predecessor_claim_sha256: str,
    bindings: Mapping[str, str],
    issued_at: str,
    expires_at: str,
) -> dict[str, object]:
    """Build the separate one-use claim after exact owner authorization."""

    expected = build_option2_host_preflight_recovery_authorization_phrase(
        predecessor_claim_id=predecessor_claim_id,
        predecessor_claim_content_sha256=predecessor_claim_content_sha256,
    )
    if not isinstance(confirmation, str) or not hmac.compare_digest(
        confirmation, expected
    ):
        raise Option2HostPreflightViolation(
            "option2_host_recovery_confirmation_invalid"
        )
    if (
        not isinstance(authorization_challenge, str)
        or re.fullmatch(r"[0-9a-f]{32}", authorization_challenge) is None
    ):
        raise Option2HostPreflightViolation(
            "option2_host_recovery_authorization_challenge_invalid"
        )
    issued, expires = _canonical_window(issued_at, expires_at)
    body = _recovery_claim_body(
        predecessor_claim_id=_validated_uuid4(
            predecessor_claim_id,
            code="option2_host_recovery_predecessor_claim_id_invalid",
        ),
        predecessor_claim_content_sha256=_validated_sha256(
            predecessor_claim_content_sha256,
            code="option2_host_recovery_predecessor_content_digest_invalid",
        ),
        predecessor_claim_sha256=_validated_sha256(
            predecessor_claim_sha256,
            code="option2_host_recovery_predecessor_claim_digest_invalid",
        ),
        bindings=_validated_bindings(bindings),
        authorization_confirmation_sha256=hashlib.sha256(
            confirmation.encode("utf-8")
        ).hexdigest(),
        authorization_challenge_sha256=hashlib.sha256(
            authorization_challenge.encode("ascii")
        ).hexdigest(),
        issued_at=issued,
        expires_at=expires,
    )
    claim = {**body, "recovery_claim_sha256": _sha256(body)}
    validate_option2_host_preflight_recovery_claim(claim)
    return claim


def validate_option2_host_preflight_recovery_claim(
    claim: Mapping[str, Any],
) -> None:
    """Validate the immutable recovery claim without inspecting the host."""

    if not isinstance(claim, Mapping):
        raise Option2HostPreflightViolation("option2_host_recovery_claim_invalid")
    body = {
        key: deepcopy(value)
        for key, value in claim.items()
        if key != "recovery_claim_sha256"
    }
    if claim.get("recovery_claim_sha256") != _sha256(body):
        raise Option2HostPreflightViolation(
            "option2_host_recovery_claim_digest_invalid"
        )
    predecessor = body.get("predecessor")
    if not isinstance(predecessor, Mapping):
        raise Option2HostPreflightViolation(
            "option2_host_recovery_predecessor_invalid"
        )
    issued, expires = _canonical_window(body.get("issued_at"), body.get("expires_at"))
    expected = _recovery_claim_body(
        predecessor_claim_id=_validated_uuid4(
            predecessor.get("claim_id"),
            code="option2_host_recovery_predecessor_claim_id_invalid",
        ),
        predecessor_claim_content_sha256=_validated_sha256(
            predecessor.get("content_sha256"),
            code="option2_host_recovery_predecessor_content_digest_invalid",
        ),
        predecessor_claim_sha256=_validated_sha256(
            predecessor.get("claim_sha256"),
            code="option2_host_recovery_predecessor_claim_digest_invalid",
        ),
        bindings=_validated_bindings(body.get("bindings")),
        authorization_confirmation_sha256=_validated_sha256(
            body.get("authorization_confirmation_sha256"),
            code="option2_host_recovery_confirmation_digest_invalid",
        ),
        authorization_challenge_sha256=_validated_sha256(
            body.get("authorization_challenge_sha256"),
            code="option2_host_recovery_challenge_digest_invalid",
        ),
        issued_at=issued,
        expires_at=expires,
    )
    if body != expected:
        raise Option2HostPreflightViolation(
            "option2_host_recovery_claim_contract_invalid"
        )


def perform_option2_identity_only_host_preflight_recovery(
    *,
    authorization_challenge: str,
    preflight_claim_id: str,
    preflight_claim_sha256: str,
    issued_at: str,
    expires_at: str,
    bindings: Mapping[str, str],
    sandbox_exec_path: Path = Path("/usr/bin/sandbox-exec"),
    dscl_path: Path = Path("/usr/bin/dscl"),
    cwd: Path = Path("/var/empty"),
    pause_file: Path | None = None,
    runner: HostRunner = run_supervised,
) -> dict[str, object]:
    """Run the separately claimed read-only recovery inventory exactly once."""

    normalized_bindings = _validated_bindings(bindings)
    snapshots: list[tuple[dict[str, object], dict[str, object]]] = []
    for _index in range(2):
        users = parse_option2_dscl_plist_projection_recovery(
            _run_dscl_listing(
                record_path="/Users",
                attribute="UniqueID",
                sandbox_exec_path=sandbox_exec_path,
                dscl_path=dscl_path,
                cwd=cwd,
                pause_file=pause_file,
                runner=runner,
            ),
            numeric_field="uid",
        )
        groups = parse_option2_dscl_plist_projection_recovery(
            _run_dscl_listing(
                record_path="/Groups",
                attribute="PrimaryGroupID",
                sandbox_exec_path=sandbox_exec_path,
                dscl_path=dscl_path,
                cwd=cwd,
                pause_file=pause_file,
                runner=runner,
            ),
            numeric_field="gid",
        )
        snapshots.append((users, groups))
    if snapshots[0] != snapshots[1]:
        raise Option2HostPreflightViolation(
            "option2_host_recovery_inventory_changed_during_preflight"
        )
    user_projection, group_projection = snapshots[1]
    candidate = build_option2_host_candidate(
        user_projection=user_projection,
        group_projection=group_projection,
        authorization_challenge=authorization_challenge,
        preflight_claim_id=preflight_claim_id,
        preflight_claim_sha256=preflight_claim_sha256,
        issued_at=issued_at,
        expires_at=expires_at,
        generation=1,
        previous_candidate_sha256=None,
        supersession_reason="initial",
        **normalized_bindings,
    )
    validate_option2_host_candidate(candidate)
    snapshots.clear()
    user_projection.clear()
    group_projection.clear()
    return candidate


__all__ = [
    "OPTION2_HOST_PREFLIGHT_RECOVERY_AUTHORIZATION_GATE",
    "OPTION2_HOST_PREFLIGHT_RECOVERY_CANDIDATE_STATE",
    "OPTION2_HOST_PREFLIGHT_RECOVERY_CANDIDATE_SUBJECT",
    "OPTION2_HOST_PREFLIGHT_RECOVERY_CLAIM_STATE",
    "OPTION2_HOST_PREFLIGHT_RECOVERY_CLAIM_SUBJECT",
    "OPTION2_HOST_PREFLIGHT_RECOVERY_CONFIRMATION_PREFIX",
    "OPTION2_HOST_PREFLIGHT_RECOVERY_RESULT_GATE",
    "OPTION2_HOST_PREFLIGHT_RECOVERY_STATE",
    "Option2HostPreflightViolation",
    "build_option2_host_preflight_recovery_authorization_phrase",
    "build_option2_host_preflight_recovery_claim",
    "parse_option2_dscl_plist_projection_recovery",
    "perform_option2_identity_only_host_preflight_recovery",
    "validate_option2_host_preflight_recovery_claim",
]
