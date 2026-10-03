from __future__ import annotations

import ctypes
import difflib
import hashlib
import hmac
import importlib.metadata
import importlib.util
import json
import os
import pwd
import re
import secrets
import shlex
import socket
import stat
import sys
import tempfile
import yaml
from copy import deepcopy
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Sequence
from uuid import UUID, uuid4

from atlas_core.config import AtlasConfig, SupervisorV4PolicyConfig
from atlas_core.errors import SupervisorError
from atlas_core.memory.database import Database, canonical_json
from atlas_core.supervisor_v4_option2_plan import (
    OPTION2_PLAN_NEXT_GATE,
    OPTION2_PLAN_STATE,
    Option2PlanViolation,
    build_option2_service_identity_and_vault_plan,
    review_option2_service_identity_and_vault_plan,
)
from atlas_core.supervisor_v4_option2_manifest_review import (
    OPTION2_MANIFEST_REVIEW_NEXT_INTERNAL_MILESTONE,
    OPTION2_MANIFEST_REVIEW_STATE,
    Option2ManifestReviewViolation,
    build_option2_service_identity_provisioning_manifest_review_content,
)
from atlas_core.supervisor_v4_option2_identity_candidate import (
    OPTION2_IDENTITY_CANDIDATE_AUTHORITY_FIELDS,
    OPTION2_IDENTITY_CANDIDATE_CREATION_STAGE_IDS,
    OPTION2_IDENTITY_CANDIDATE_EFFECT_FIELDS,
    OPTION2_IDENTITY_CANDIDATE_MAX_VALIDITY_SECONDS,
    OPTION2_IDENTITY_CANDIDATE_NEXT_GATE,
    OPTION2_IDENTITY_CANDIDATE_RESOLVER_STATE,
    OPTION2_IDENTITY_CANDIDATE_TRANSACTION_STAGE_IDS,
    OPTION2_IDENTITY_CANDIDATE_VERSION,
    OPTION2_SERVICE_IDENTITIES,
    OPTION2_SYNTHETIC_INVENTORY_CLASSIFICATION,
    Option2IdentityCandidateViolation,
    qualify_option2_identity_candidate_resolver,
)
from atlas_core.supervisor_v4_option2_host_preflight import (
    OPTION2_HOST_PREFLIGHT_CLAIM_SUBJECT,
    OPTION2_HOST_PREFLIGHT_RECOVERY_GATE,
    OPTION2_HOST_SANDBOX_PROFILE_SHA256,
    OPTION2_HOST_PREFLIGHT_STATE,
    OPTION2_HOST_PREFLIGHT_SUBJECT,
    Option2HostPreflightViolation,
    build_option2_host_preflight_claim,
    perform_option2_identity_only_host_preflight,
    validate_option2_host_candidate,
    validate_option2_host_preflight_claim,
)
from atlas_core.supervisor_v4_option2_host_preflight_recovery import (
    OPTION2_HOST_PREFLIGHT_RECOVERY_AUTHORIZATION_GATE,
    OPTION2_HOST_PREFLIGHT_RECOVERY_CANDIDATE_STATE,
    OPTION2_HOST_PREFLIGHT_RECOVERY_CANDIDATE_SUBJECT,
    OPTION2_HOST_PREFLIGHT_RECOVERY_CLAIM_SUBJECT,
    OPTION2_HOST_PREFLIGHT_RECOVERY_RESULT_GATE,
    OPTION2_HOST_PREFLIGHT_RECOVERY_STATE,
    build_option2_host_preflight_recovery_authorization_phrase,
    build_option2_host_preflight_recovery_claim,
    perform_option2_identity_only_host_preflight_recovery,
    validate_option2_host_preflight_recovery_claim,
)
from atlas_core.supervisor_v4_option2_provisioner import (
    OPTION2_PROVISIONER_NEXT_GATE,
    OPTION2_PROVISIONER_QUALIFICATION_STATE,
    OPTION2_PROVISIONER_STATE,
    Option2ProvisionerViolation,
    PRODUCTION_CONFIGURATION_FIELDS,
    build_option2_plan_review_content,
    build_option2_provisioner_manifest,
    review_option2_provisioner_contract,
)
from atlas_core.supervisor_v4_option2_point_action import (
    OPTION2_POINT_ACTION_AUTHORITY_FIELDS,
    OPTION2_POINT_ACTION_EFFECT_FIELDS,
    OPTION2_POINT_ACTION_NEXT_GATE,
    OPTION2_POINT_ACTION_POSTMUTATION_QUARANTINE_CASE_IDS,
    OPTION2_POINT_ACTION_PREMUTATION_REJECTION_CASE_IDS,
    OPTION2_POINT_ACTION_QUALIFICATION_STATE,
    OPTION2_POINT_ACTION_REJECTION_CASE_IDS,
    OPTION2_POINT_ACTION_STATE,
    Option2PointActionViolation,
    build_option2_point_action_contract,
    qualify_option2_point_action_contract,
)
from atlas_core.supervisor_v4_option2_native_preflight import (
    OPTION2_NATIVE_PREFLIGHT_NEXT_GATE,
    OPTION2_NATIVE_PREFLIGHT_QUALIFICATION_STATE,
    OPTION2_NATIVE_PREFLIGHT_QUARANTINE_GATE,
    OPTION2_NATIVE_PREFLIGHT_SOURCE_PATHS,
    OPTION2_NATIVE_PREFLIGHT_STATE,
    Option2NativePreflightViolation,
    build_option2_native_preflight_contract,
    qualify_option2_native_preflight_contract,
    validate_native_fixture_report,
    validate_native_source_texts,
)
from atlas_core.supervisor_v4_process import (
    ProcessSupervisionError,
    SupervisedCompletedProcess,
    run_supervised,
)


_MAX_BUNDLE_FILE_BYTES = 4 * 1024 * 1024
_MAX_RUNTIME_FILE_BYTES = 300 * 1024 * 1024
_V4_PROFILE_ID = "atlas_v4_proposal_read_only"
_V4_PERMISSION_PROFILE = {
    "filesystem": {
        ":root": "deny",
        ":minimal": "read",
        ":workspace_roots": {".": "read"},
    },
    "network": {"enabled": False},
}
_V4_PERMISSION_PROFILE_TOML = (
    'permissions={ atlas_v4_proposal_read_only = { filesystem = { ":root" = '
    '"deny", ":minimal" = "read", ":workspace_roots" = { "." = "read" } }, '
    "network = { enabled = false } } }"
)
_V4_QUALIFICATION_PROFILE_ID = "atlas_v4_qualification_no_network"
_V4_QUALIFICATION_PROFILE_TOML = (
    'permissions={ atlas_v4_qualification_no_network = { filesystem = { ":root" = '
    '"deny", ":minimal" = "read", ":workspace_roots" = { "." = "write" } }, '
    "network = { enabled = false } } }"
)
_OPTION1_RECOVERY_RESULT_REVIEW_SUBJECT = (
    "option1.recovery-canary.result-review.v1"
)
_OPTION2_PLAN_REVIEW_SUBJECT = "option2.service-identity-vault-plan.review.v1"
_OPTION2_PROVISIONER_QUALIFICATION_SUBJECT = (
    "option2.service-identity-provisioner.fixture-qualification.v1"
)
_OPTION2_PROVISIONER_MANIFEST_REVIEW_SUBJECT = (
    "option2.service-identity-provisioning-manifest.review.v1"
)
_OPTION2_IDENTITY_CANDIDATE_QUALIFICATION_SUBJECT = (
    "option2.identity-candidate-resolver.fixture-qualification.v1"
)
_OPTION2_HOST_PREFLIGHT_RECOVERY_RESULT_REVIEW_SUBJECT = (
    "option2.identity-only-host-preflight.recovery-result-review.v1"
)
_OPTION2_POINT_ACTION_QUALIFICATION_SUBJECT = (
    "option2.identity-only-provisioning.point-of-action-design.qualification.v1"
)
_OPTION2_NATIVE_PREFLIGHT_QUALIFICATION_SUBJECT = (
    "option2.identity-only-native-preflight-and-claim-ledger.qualification.v1"
)
_OPTION2_HOST_RECOVERY_RESULT_QUARANTINE_GATE = (
    "owner_review_option2_identity_only_host_preflight_recovery_result_quarantine"
)
_OPTION2_POINT_ACTION_QUALIFICATION_QUARANTINE_GATE = (
    "owner_review_option2_point_action_qualification_quarantine"
)
_OPTION2_LEGACY_HOST_CANDIDATE_REVIEW_GATE = (
    "owner_review_option2_legacy_identity_candidate_non_authorizing"
)
_OPTION2_HOST_DSCL_PATH = Path("/usr/bin/dscl")
_OPTION2_HOST_PREFLIGHT_CWD = Path("/var/empty")
_TRUSTED_PLATFORM_TOOL_PATHS = MappingProxyType(
    {
        "git": Path("/usr/bin/git"),
        "sandbox_exec": Path("/usr/bin/sandbox-exec"),
        "cmp": Path("/usr/bin/cmp"),
        "nc": Path("/usr/bin/nc"),
        "install_name_tool": Path("/usr/bin/install_name_tool"),
        "codesign": Path("/usr/bin/codesign"),
    }
)
_RUNTIME_BUNDLE_SOURCE_PINS = MappingProxyType(
    {
        "service_source": "src/atlas_core/supervisor_v4.py",
        "database_source": "src/atlas_core/memory/database.py",
        "adapter_source": "src/atlas_core/supervisor_v4_protocol.py",
        "live_contract_source": "src/atlas_core/supervisor_v4_live_contract.py",
        "offline_source": "src/atlas_core/supervisor_v4_offline.py",
        "offline_audit_source": "src/atlas_core/supervisor_v4_offline_audit.py",
        "offline_broker_qualification_source": (
            "src/atlas_core/supervisor_v4_offline_broker_qualification.py"
        ),
        "offline_credential_broker_source": (
            "src/atlas_core/supervisor_v4_offline_credential_broker.py"
        ),
        "offline_crypto_source": "src/atlas_core/supervisor_v4_offline_crypto.py",
        "offline_external_broker_source": (
            "src/atlas_core/supervisor_v4_offline_external_broker.py"
        ),
        "offline_policy_broker_source": (
            "src/atlas_core/supervisor_v4_offline_policy_broker.py"
        ),
        "process_source": "src/atlas_core/supervisor_v4_process.py",
        "option1_canary_source": (
            "src/atlas_core/supervisor_v4_option1_canary.py"
        ),
        "option1_canary_runner_source": "scripts/option1_on_demand_canary.py",
        "option1_recovery_canary_source": (
            "src/atlas_core/supervisor_v4_option1_recovery_canary.py"
        ),
        "option1_recovery_canary_runner_source": (
            "scripts/option1_on_demand_recovery_canary.py"
        ),
        "option2_plan_source": (
            "src/atlas_core/supervisor_v4_option2_plan.py"
        ),
        "option2_provisioner_source": (
            "src/atlas_core/supervisor_v4_option2_provisioner.py"
        ),
        "option2_manifest_review_source": (
            "src/atlas_core/supervisor_v4_option2_manifest_review.py"
        ),
        "option2_identity_candidate_source": (
            "src/atlas_core/supervisor_v4_option2_identity_candidate.py"
        ),
        "option2_host_preflight_source": (
            "src/atlas_core/supervisor_v4_option2_host_preflight.py"
        ),
        "option2_host_preflight_recovery_source": (
            "src/atlas_core/supervisor_v4_option2_host_preflight_recovery.py"
        ),
        "option2_point_action_source": (
            "src/atlas_core/supervisor_v4_option2_point_action.py"
        ),
        "option2_native_preflight_source": (
            "src/atlas_core/supervisor_v4_option2_native_preflight.py"
        ),
        "option2_native_bound_request_source": (
            "native/option2_identity_preflight/BoundRequest.swift"
        ),
        "option2_native_canonical_json_source": (
            "native/option2_identity_preflight/CanonicalJSON.swift"
        ),
        "option2_native_claim_ledger_source": (
            "native/option2_identity_preflight/ClaimLedger.swift"
        ),
        "option2_native_offline_fixtures_source": (
            "native/option2_identity_preflight/OfflineFixtures.swift"
        ),
        "option2_native_fixture_main_source": (
            "native/option2_identity_preflight/Option2FixtureMain.swift"
        ),
        "option2_native_preflight_evaluator_source": (
            "native/option2_identity_preflight/PreflightEvaluator.swift"
        ),
        "option2_native_fixture_report": (
            "src/atlas_core/resources/"
            "supervisor_v4_option2_native_preflight_qualification.json"
        ),
        "same_user_broker_source": (
            "src/atlas_core/supervisor_v4_same_user_broker.py"
        ),
        "same_user_connector_source": (
            "src/atlas_core/supervisor_v4_same_user_connector.py"
        ),
        "same_user_qualification_source": (
            "src/atlas_core/supervisor_v4_same_user_qualification.py"
        ),
        "same_user_state_source": (
            "src/atlas_core/supervisor_v4_same_user_state.py"
        ),
        "same_user_probe_source": "scripts/supervisor_v4_same_user_probe.py",
        "sdk_probe_source": "scripts/supervisor_v4_sdk_probe.py",
    }
)
_SAME_USER_STAGED_MODULES = MappingProxyType(
    {
        "supervisor_v4_live_contract.py": "live_contract_source",
        "supervisor_v4_offline_credential_broker.py": (
            "offline_credential_broker_source"
        ),
        "supervisor_v4_offline_crypto.py": "offline_crypto_source",
        "supervisor_v4_offline_policy_broker.py": "offline_policy_broker_source",
        "supervisor_v4_protocol.py": "adapter_source",
        "supervisor_v4_same_user_broker.py": "same_user_broker_source",
        "supervisor_v4_same_user_qualification.py": (
            "same_user_qualification_source"
        ),
        "supervisor_v4_same_user_state.py": "same_user_state_source",
    }
)
_OPENAI_CODEX_DESIGNATED_REQUIREMENT = (
    'identifier "codex" and anchor apple generic and '
    'certificate 1[field.1.2.840.113635.100.6.2.6] exists and '
    'certificate leaf[field.1.2.840.113635.100.6.1.13] exists and '
    'certificate leaf[subject.OU] = "2DC432GLL2"'
)
_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:github_pat_|ghp_|sk-(?:live|proj)-)[A-Za-z0-9_-]{8,}\b"),
    re.compile(
        r"(?i)\b(?:api[_-]?key|access[_-]?token|secret|password)\s*[:=]\s*[^\s]{8,}"
    ),
)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_canonical_uuid4(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = UUID(value)
    except ValueError:
        return False
    return parsed.version == 4 and str(parsed) == value


def _active_venv_python_executable(project_root: Path) -> Path:
    """Return the active venv interpreter path without following its symlink."""

    candidate = Path(sys.executable)
    environment = Path(sys.prefix)
    expected_environment = project_root / ".venv"
    expected_bin = expected_environment / "bin"
    try:
        if (
            not candidate.is_absolute()
            or not environment.is_absolute()
            or candidate.parent != expected_bin
            or not candidate.name.startswith("python")
            or environment.resolve(strict=True)
            != expected_environment.resolve(strict=True)
        ):
            raise OSError("active virtual environment mismatch")
        for directory in (expected_environment, expected_bin):
            metadata = directory.lstat()
            if (
                directory.is_symlink()
                or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                raise OSError("active virtual environment is unsafe")
        lexical_metadata = candidate.lstat()
        target = candidate.resolve(strict=True)
        target_metadata = target.stat()
        if (
            not (
                stat.S_ISLNK(lexical_metadata.st_mode)
                or stat.S_ISREG(lexical_metadata.st_mode)
            )
            or lexical_metadata.st_uid not in {0, os.getuid()}
            or not stat.S_ISREG(target_metadata.st_mode)
            or target_metadata.st_uid not in {0, os.getuid()}
            or stat.S_IMODE(target_metadata.st_mode) & 0o022
            or not os.access(candidate, os.X_OK)
        ):
            raise OSError("active virtual environment interpreter is unsafe")
    except OSError as exc:
        raise SupervisorError("option1_canary_python_runtime_invalid") from exc
    return candidate


def _validated_option1_canary_child_report(
    completed: SupervisedCompletedProcess,
) -> dict[str, object]:
    """Validate one child result without exposing its captured output."""

    from atlas_core.supervisor_v4_option1_canary import (
        Option1CanaryViolation,
        canonical_json as canary_canonical_json,
        validate_canary_receipt,
    )

    if completed.process_group_reaped is not True:
        raise SupervisorError("option1_canary_child_process_group_not_reaped")
    captured = (completed.stdout, completed.stderr)
    if any("atlas-option1-synthetic-v1_" in value for value in captured):
        raise SupervisorError("option1_canary_child_material_detected")
    if any(pattern.search(value) for value in captured for pattern in _SECRET_PATTERNS):
        raise SupervisorError("option1_canary_child_secret_pattern_detected")
    if completed.stderr != "":
        raise SupervisorError("option1_canary_child_stderr_present")
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError:
        # JSONDecodeError retains the raw document. Do not chain it into a
        # parent-facing exception or any later traceback.
        raise SupervisorError("option1_canary_child_output_invalid") from None
    if (
        not isinstance(report, dict)
        or canary_canonical_json(report).decode("utf-8") != completed.stdout
    ):
        raise SupervisorError("option1_canary_child_output_invalid")
    if completed.returncode != 0:
        code = report.get("failure_code")
        if not isinstance(code, str) or not re.fullmatch(
            r"option1_canary_[a-z0-9_]{1,80}", code
        ):
            code = "option1_canary_child_failed"
        raise SupervisorError(code)
    try:
        validate_canary_receipt(report)
    except Option1CanaryViolation as exc:
        raise SupervisorError("option1_canary_child_receipt_invalid") from exc
    if report.get("status") != "passed":
        raise SupervisorError("option1_canary_child_failed")
    return report


def _validated_option1_recovery_canary_child_report(
    completed: SupervisedCompletedProcess,
) -> dict[str, object]:
    """Validate one recovery child result without exposing captured output."""

    from atlas_core.supervisor_v4_option1_recovery_canary import (
        Option1RecoveryCanaryViolation,
        canonical_json as recovery_canonical_json,
        validate_recovery_canary_child_result,
    )

    if completed.process_group_reaped is not True:
        raise SupervisorError(
            "option1_recovery_canary_child_process_group_not_reaped"
        )
    captured = (completed.stdout, completed.stderr)
    if any("atlas-option1-synthetic-v1_" in value for value in captured):
        raise SupervisorError("option1_recovery_canary_child_material_detected")
    if any(pattern.search(value) for value in captured for pattern in _SECRET_PATTERNS):
        raise SupervisorError(
            "option1_recovery_canary_child_secret_pattern_detected"
        )
    if completed.stderr != "":
        raise SupervisorError("option1_recovery_canary_child_stderr_present")
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError:
        raise SupervisorError(
            "option1_recovery_canary_child_output_invalid"
        ) from None
    if (
        not isinstance(report, dict)
        or recovery_canonical_json(report).decode("utf-8") != completed.stdout
    ):
        raise SupervisorError("option1_recovery_canary_child_output_invalid")
    try:
        validate_recovery_canary_child_result(report)
    except Option1RecoveryCanaryViolation as exc:
        raise SupervisorError(
            "option1_recovery_canary_child_receipt_invalid"
        ) from exc
    if completed.returncode != 0:
        code = report.get("failure_code")
        if not isinstance(code, str) or not re.fullmatch(
            r"option1_recovery_canary_[a-z0-9_]{1,80}", code
        ):
            code = "option1_recovery_canary_child_failed"
        raise SupervisorError(code)
    if report.get("status") != "passed":
        raise SupervisorError("option1_recovery_canary_child_failed")
    return report


def _resolved_module_source(module_name: str) -> Path:
    """Locate one Python source module without importing its executable code."""

    spec = importlib.util.find_spec(module_name)
    if spec is None or not isinstance(spec.origin, str):
        raise SupervisorError("Supervisor v4 module source is unavailable")
    path = Path(spec.origin).resolve()
    if path.suffix != ".py":
        raise SupervisorError("Supervisor v4 module source is not inspectable")
    return path


def _copy_verified_regular(
    source: Path,
    destination: Path,
    *,
    expected_sha256: str,
    expected_uid: int | None = None,
    require_single_link: bool = True,
) -> None:
    """Copy one already pinned executable through no-follow descriptors."""

    absolute = source.expanduser().absolute()
    base_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    directory_flags = (
        base_flags | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    directory_descriptor = os.open(absolute.anchor, directory_flags)
    source_descriptor: int | None = None
    try:
        for component in absolute.parts[1:-1]:
            next_descriptor = os.open(
                component, directory_flags, dir_fd=directory_descriptor
            )
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        source_descriptor = os.open(
            absolute.name,
            base_flags | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_descriptor,
        )
        before = os.fstat(source_descriptor)
        owner_uid = os.getuid() if expected_uid is None else expected_uid
        if (
            not stat.S_ISREG(before.st_mode)
            or (require_single_link and before.st_nlink != 1)
            or before.st_uid != owner_uid
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_size > _MAX_RUNTIME_FILE_BYTES
        ):
            raise SupervisorError("Pinned Supervisor v4 runtime file is unsafe")
        output_descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o500,
        )
        digest = hashlib.sha256()
        copied = 0
        try:
            while chunk := os.read(source_descriptor, 1024 * 1024):
                copied += len(chunk)
                if copied > _MAX_RUNTIME_FILE_BYTES:
                    raise SupervisorError("Pinned Supervisor v4 runtime file is too large")
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    view = view[os.write(output_descriptor, view) :]
            os.fsync(output_descriptor)
        finally:
            os.close(output_descriptor)
        after = os.fstat(source_descriptor)
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or copied != before.st_size
            or digest.hexdigest() != expected_sha256
            or _sha256_file(destination) != expected_sha256
        ):
            destination.unlink(missing_ok=True)
            raise SupervisorError("Pinned Supervisor v4 runtime changed while staging")
    finally:
        if source_descriptor is not None:
            os.close(source_descriptor)
        os.close(directory_descriptor)


def _write_private_snapshot(path: Path, content: bytes, *, mode: int) -> None:
    """Create one private immutable snapshot member and verify its bytes."""

    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        view = memoryview(content)
        while view:
            view = view[os.write(descriptor, view) :]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(path, mode)
    if _sha256_file(path) != _sha256_bytes(content):
        raise SupervisorError("Supervisor v4 private snapshot write drifted")


def _clear_codesign_detritus(path: Path) -> None:
    """Remove only known non-content xattrs through a no-follow descriptor."""

    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        original_mode = stat.S_IMODE(before.st_mode)
        os.fchmod(descriptor, original_mode | stat.S_IWUSR)
        libc = ctypes.CDLL(None, use_errno=True)
        remove = getattr(libc, "fremovexattr", None)
        if remove is None:
            raise SupervisorError("Supervisor v4 xattr cleanup is unavailable")
        remove.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
        remove.restype = ctypes.c_int
        for name in (
            b"com.apple.provenance",
            b"com.apple.ResourceFork",
            b"com.apple.FinderInfo",
            b"com.apple.fileprovider.fpfs#P",
        ):
            ctypes.set_errno(0)
            if remove(descriptor, name, 0) != 0 and ctypes.get_errno() not in {
                2,
                93,
            }:
                raise SupervisorError("Supervisor v4 xattr cleanup failed")
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise SupervisorError("Supervisor v4 staged executable identity changed")
    finally:
        try:
            os.fchmod(descriptor, original_mode)
        except (OSError, UnboundLocalError):
            pass
        os.close(descriptor)


def _clear_codesign_tree_detritus(root: Path) -> None:
    for path in (root, *sorted(root.rglob("*"))):
        if path.is_symlink():
            continue
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode):
            _clear_codesign_detritus(path)


def _site_packages_manifest(
    root: Path,
    *,
    max_files: int = 10_000,
) -> tuple[int, str]:
    """Hash the complete importable venv tree, excluding generated bytecode."""

    if not root.is_dir() or root.is_symlink():
        raise SupervisorError("Supervisor v4 site-packages root is unsafe")
    entries: list[str] = []
    for path in sorted(root.rglob("*")):
        if path.is_dir():
            if path.is_symlink():
                raise SupervisorError("Supervisor v4 site-packages contains a symlink")
            continue
        relative = path.relative_to(root)
        if "__pycache__" in relative.parts or path.suffix == ".pyc":
            continue
        if len(entries) >= max_files:
            raise SupervisorError("Supervisor v4 site-packages file count is unbounded")
        content = _read_regular_no_follow(path, max_bytes=_MAX_RUNTIME_FILE_BYTES)
        entries.append(
            f"{_sha256_bytes(content)} {len(content)} {relative.as_posix()}\n"
        )
    manifest = "".join(entries).encode("utf-8")
    return len(entries), _sha256_bytes(manifest)


def _runtime_tree_manifest(
    root: Path,
    *,
    max_files: int = 10_000,
) -> tuple[int, str]:
    """Hash a runtime tree, binding only internal symlinks as metadata."""

    absolute = root.expanduser().resolve(strict=True)
    if not absolute.is_dir() or root.is_symlink():
        raise SupervisorError("Supervisor v4 runtime base is unsafe")
    entries: list[str] = []
    for path in sorted(absolute.rglob("*")):
        relative = path.relative_to(absolute)
        if "__pycache__" in relative.parts or path.suffix == ".pyc":
            continue
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if len(entries) >= max_files:
            raise SupervisorError("Supervisor v4 runtime base file count is unbounded")
        if stat.S_ISLNK(metadata.st_mode):
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(absolute):
                raise SupervisorError("Supervisor v4 runtime symlink escapes its base")
            entries.append(
                f"L {relative.as_posix()} {os.readlink(path)} "
                f"{resolved.relative_to(absolute).as_posix()}\n"
            )
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise SupervisorError("Supervisor v4 runtime base has a special file")
        content = _read_regular_no_follow(path, max_bytes=_MAX_RUNTIME_FILE_BYTES)
        entries.append(
            f"F {_sha256_bytes(content)} {len(content)} {relative.as_posix()}\n"
        )
    manifest = "".join(entries).encode("utf-8")
    return len(entries), _sha256_bytes(manifest)


def _copy_runtime_snapshot_tree(
    source: Path,
    destination: Path,
    *,
    allow_internal_symlinks: bool,
    max_files: int = 10_000,
) -> None:
    """Copy an attested runtime tree into a private, read-only snapshot."""

    source_root = source.expanduser().resolve(strict=True)
    if not source_root.is_dir() or source.is_symlink():
        raise SupervisorError("Supervisor v4 runtime snapshot source is unsafe")
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    copied = 0
    for path in sorted(source_root.rglob("*")):
        relative = path.relative_to(source_root)
        if "__pycache__" in relative.parts or path.suffix == ".pyc":
            continue
        metadata = path.lstat()
        target = destination / relative
        if stat.S_ISDIR(metadata.st_mode):
            if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o022:
                raise SupervisorError("Supervisor v4 runtime directory is unsafe")
            target.mkdir(mode=0o700, parents=True, exist_ok=False)
            continue
        copied += 1
        if copied > max_files:
            raise SupervisorError("Supervisor v4 runtime snapshot file count is unbounded")
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if stat.S_ISLNK(metadata.st_mode):
            if not allow_internal_symlinks:
                raise SupervisorError("Supervisor v4 runtime snapshot contains a symlink")
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(source_root):
                raise SupervisorError("Supervisor v4 runtime symlink escapes its source")
            link_target = os.readlink(path)
            if Path(link_target).is_absolute():
                raise SupervisorError("Supervisor v4 runtime symlink is absolute")
            os.symlink(link_target, target)
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise SupervisorError("Supervisor v4 runtime snapshot has a special file")
        content = _read_regular_no_follow(path, max_bytes=_MAX_RUNTIME_FILE_BYTES)
        mode = 0o500 if stat.S_IMODE(metadata.st_mode) & 0o111 else 0o400
        descriptor = os.open(
            target,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            mode,
        )
        try:
            view = memoryview(content)
            while view:
                view = view[os.write(descriptor, view) :]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


@dataclass(frozen=True, slots=True)
class StagedPythonRuntime:
    python: Path
    dyld_root: Path
    base_root: Path
    site_packages: Path
    base_file_count: int
    base_manifest_sha256: str
    site_packages_file_count: int
    site_packages_manifest_sha256: str


@dataclass(frozen=True, slots=True)
class StagedOption1Dependencies:
    site_packages: Path
    cryptography_version: str
    cryptography_file_count: int
    cryptography_manifest_sha256: str
    cffi_version: str
    cffi_backend_filename: str
    cffi_backend_sha256: str


@dataclass(frozen=True, slots=True)
class StagedLocalTools:
    git: Path
    sandbox_exec: Path
    cmp: Path
    nc: Path
    install_name_tool: Path
    codesign: Path


def _unique_yaml(content: bytes) -> object:
    class UniqueKeyLoader(yaml.SafeLoader):
        pass

    def construct_mapping(loader: yaml.SafeLoader, node: yaml.MappingNode, deep: bool = False):
        mapping: dict[object, object] = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in mapping:
                raise SupervisorError("Supervisor v4 contract has a duplicate YAML key")
            mapping[key] = loader.construct_object(value_node, deep=deep)
        return mapping

    UniqueKeyLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping
    )
    try:
        return yaml.load(content.decode("utf-8", errors="strict"), Loader=UniqueKeyLoader)
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise SupervisorError("Supervisor v4 contract is not canonical YAML") from exc


def _run(
    argv: Sequence[str],
    *,
    cwd: Path,
    timeout: float,
    env: Mapping[str, str],
    pause_file: Path,
    max_output_bytes: int = 1_048_576,
) -> SupervisedCompletedProcess:
    return run_supervised(
        argv,
        cwd=cwd,
        timeout=timeout,
        env=env,
        pause_file=pause_file,
        max_output_bytes=max_output_bytes,
    )


def _verify_openai_codex_signature(
    binary: Path,
    *,
    codesign_binary: Path,
    pause_file: Path,
    mismatches: list[str],
) -> bool:
    """Verify the staged sandbox binary with a fixed platform trust root."""

    if codesign_binary != _TRUSTED_PLATFORM_TOOL_PATHS["codesign"]:
        mismatches.append("pinned code-signing verifier path drifted")
        return False
    try:
        completed = _run(
            [
                str(codesign_binary),
                "--verify",
                "--strict",
                "--verbose=2",
                f"-R={_OPENAI_CODEX_DESIGNATED_REQUIREMENT}",
                str(binary),
            ],
            cwd=binary.parent,
            timeout=15,
            env={
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "HOME": str(binary.parent),
                "TMPDIR": str(binary.parent),
                "LANG": "C.UTF-8",
            },
            pause_file=pause_file,
            max_output_bytes=65_536,
        )
    except (OSError, ProcessSupervisionError):
        mismatches.append("pinned Codex code-signing verification failed")
        return False
    if completed.returncode != 0:
        mismatches.append("pinned Codex code-signing identity drifted")
        return False
    return True


@dataclass(frozen=True, slots=True)
class SealedBundleMember:
    label: str
    path: str
    sha256: str
    size_bytes: int
    content: bytes


@dataclass(frozen=True, slots=True)
class ImmutablePolicyBundle:
    members: tuple[SealedBundleMember, ...]
    sha256: str

    def member(self, label: str) -> SealedBundleMember:
        for member in self.members:
            if member.label == label:
                return member
        raise KeyError(label)

    def public_binding(self) -> dict[str, Any]:
        return {
            "sha256": self.sha256,
            "members": [
                {
                    "label": member.label,
                    "sha256": member.sha256,
                    "size_bytes": member.size_bytes,
                }
                for member in self.members
            ],
        }


def _read_regular_no_follow(path: Path, *, max_bytes: int) -> bytes:
    absolute = path.expanduser().absolute()
    if not absolute.is_absolute() or ".." in absolute.parts or absolute.name in {"", "."}:
        raise SupervisorError("Unsafe Supervisor v4 bundle path")
    base_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    directory_flags = (
        base_flags
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    directory_descriptor = os.open(absolute.anchor, directory_flags)
    descriptor: int | None = None
    try:
        for component in absolute.parts[1:-1]:
            next_descriptor = os.open(
                component,
                directory_flags,
                dir_fd=directory_descriptor,
            )
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        descriptor = os.open(
            absolute.name,
            base_flags | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_descriptor,
        )
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory_descriptor)
        raise SupervisorError(f"Unsafe Supervisor v4 bundle member: {path.name}") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) & 0o022
        ):
            raise SupervisorError(
                f"Supervisor v4 bundle member ownership or mode is unsafe: "
                f"{path.name}"
            )
        if before.st_size < 0 or before.st_size > max_bytes:
            raise SupervisorError(f"Supervisor v4 bundle member is too large: {path.name}")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) > max_bytes:
            raise SupervisorError(f"Supervisor v4 bundle member is too large: {path.name}")
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        if identity_before != identity_after or len(content) != before.st_size:
            raise SupervisorError(
                f"Supervisor v4 bundle member changed while sealing: {path.name}"
            )
        return content
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory_descriptor)


def _sha256_root_owned_platform_tool(path: Path) -> str:
    """Hash one fixed root-owned platform binary through a no-follow handle."""

    if not path.is_absolute() or path.parent != Path("/usr/bin"):
        raise SupervisorError("Option 2 host preflight tool path is invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SupervisorError(
            "Option 2 host preflight tool is unavailable"
        ) from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_size <= 0
            or before.st_size > _MAX_RUNTIME_FILE_BYTES
        ):
            raise SupervisorError(
                "Option 2 host preflight tool provenance is unsafe"
            )
        digest = hashlib.sha256()
        copied = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            copied += len(chunk)
            if copied > _MAX_RUNTIME_FILE_BYTES:
                raise SupervisorError(
                    "Option 2 host preflight tool is too large"
                )
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or copied != before.st_size
        ):
            raise SupervisorError(
                "Option 2 host preflight tool changed during attestation"
            )
        result = digest.hexdigest()
        if result == "0" * 64:
            raise SupervisorError(
                "Option 2 host preflight tool digest is invalid"
            )
        return result
    finally:
        os.close(descriptor)


def _option2_host_instance_sha256(
    *, database_path: Path, project_root: Path
) -> str:
    """Bind a candidate to this local Atlas installation without retaining raw IDs."""

    descriptors: list[int] = []
    try:
        database_descriptor = os.open(
            database_path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        descriptors.append(database_descriptor)
        database_parent_descriptor = os.open(
            database_path.parent,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_DIRECTORY", 0),
        )
        descriptors.append(database_parent_descriptor)
        project_descriptor = os.open(
            project_root,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_DIRECTORY", 0),
        )
        descriptors.append(project_descriptor)
        database_state = os.fstat(database_descriptor)
        database_parent_state = os.fstat(database_parent_descriptor)
        project_state = os.fstat(project_descriptor)
        node_name = os.uname().nodename
        if (
            not stat.S_ISREG(database_state.st_mode)
            or database_state.st_uid != os.geteuid()
            or stat.S_IMODE(database_state.st_mode) & 0o022
            or not stat.S_ISDIR(database_parent_state.st_mode)
            or database_parent_state.st_uid != os.geteuid()
            or stat.S_IMODE(database_parent_state.st_mode) & 0o022
            or not stat.S_ISDIR(project_state.st_mode)
            or project_state.st_uid != os.geteuid()
            or stat.S_IMODE(project_state.st_mode) & 0o022
            or not isinstance(node_name, str)
            or not node_name
            or len(node_name.encode("utf-8")) > 255
            or any(ord(character) < 32 for character in node_name)
        ):
            raise SupervisorError(
                "Option 2 host instance binding is unavailable"
            )
        binding = {
            "version": 1,
            "node_name": node_name,
            "owner_uid": os.geteuid(),
            "owner_gid": os.getegid(),
            "database_device": database_state.st_dev,
            "database_inode": database_state.st_ino,
            "database_parent_device": database_parent_state.st_dev,
            "database_parent_inode": database_parent_state.st_ino,
            "project_device": project_state.st_dev,
            "project_inode": project_state.st_ino,
        }
        return _sha256_bytes(canonical_json(binding).encode("utf-8"))
    except OSError as error:
        raise SupervisorError(
            "Option 2 host instance binding is unavailable"
        ) from error
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def seal_policy_bundle(paths: Mapping[str, Path]) -> ImmutablePolicyBundle:
    members: list[SealedBundleMember] = []
    for label, path in sorted(paths.items()):
        content = _read_regular_no_follow(path, max_bytes=_MAX_BUNDLE_FILE_BYTES)
        members.append(
            SealedBundleMember(
                label=label,
                path=str(path),
                sha256=_sha256_bytes(content),
                size_bytes=len(content),
                content=content,
            )
        )
    binding = [
        {
            "label": member.label,
            "sha256": member.sha256,
            "size_bytes": member.size_bytes,
        }
        for member in members
    ]
    return ImmutablePolicyBundle(
        members=tuple(members),
        sha256=_sha256_bytes(canonical_json(binding).encode("utf-8")),
    )


@dataclass(frozen=True, slots=True)
class SupervisorV4Capability:
    """Exact one-use work-order authority; no prompt or credential is included."""

    version: int
    capability_id: str
    task_id: str
    job_id: str
    nonce: str
    audience: str
    provider: str
    issued_at: str
    project_slug: str
    source_baseline_sha256: str
    policy_bundle_sha256: str
    replay_corpus_sha256: str
    adapter_sha256: str
    sdk_version: str
    runtime_sha256: str
    model: str
    reasoning_effort: str
    sandbox_profile_sha256: str
    command_network_access: bool
    pause_control_sha256: str
    allowed_operation: str
    allowed_result_type: str
    allowed_path: str
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
    attempt_limit: int
    process_limit: int
    timeout_seconds: int
    max_output_bytes: int
    max_changed_files: int
    max_changed_lines: int
    max_patch_bytes: int
    expires_at: str
    signing_key_id: str

    def payload(self) -> bytes:
        return canonical_json(asdict(self)).encode("utf-8")

    def protocol_bindings(self) -> object:
        """Project this exact work order into the externally signed protocol shape."""

        from atlas_core.supervisor_v4_protocol import CapabilityBindings

        return CapabilityBindings(
            capability_version=self.version,
            capability_id_sha256=_sha256_bytes(self.capability_id.encode("utf-8")),
            task_sha256=_sha256_bytes(self.task_id.encode("utf-8")),
            job_sha256=_sha256_bytes(self.job_id.encode("utf-8")),
            project_sha256=_sha256_bytes(self.project_slug.encode("utf-8")),
            nonce_sha256=_sha256_bytes(self.nonce.encode("utf-8")),
            audience=self.audience,
            provider=self.provider,
            sdk_version=self.sdk_version,
            signing_key_id=self.signing_key_id,
            one_use=True,
            issued_at=self.issued_at,
            expires_at=self.expires_at,
            max_ttl_seconds=300,
            source_baseline_sha256=self.source_baseline_sha256,
            policy_bundle_sha256=self.policy_bundle_sha256,
            replay_corpus_sha256=self.replay_corpus_sha256,
            adapter_sha256=self.adapter_sha256,
            model=self.model,
            reasoning_effort=self.reasoning_effort,
            runtime_sha256=self.runtime_sha256,
            sandbox="read_only_empty_root",
            sandbox_profile_sha256=self.sandbox_profile_sha256,
            network_access=self.command_network_access,
            budgets_sha256=_sha256_bytes(
                canonical_json(
                    {
                        "attempt_limit": self.attempt_limit,
                        "process_limit": self.process_limit,
                        "timeout_seconds": self.timeout_seconds,
                        "max_output_bytes": self.max_output_bytes,
                        "max_changed_files": self.max_changed_files,
                        "max_changed_lines": self.max_changed_lines,
                        "max_patch_bytes": self.max_patch_bytes,
                    }
                ).encode("utf-8")
            ),
            attempt_limit=self.attempt_limit,
            process_limit=self.process_limit,
            timeout_seconds=self.timeout_seconds,
            max_output_bytes=self.max_output_bytes,
            max_changed_files=self.max_changed_files,
            max_changed_lines=self.max_changed_lines,
            max_patch_bytes=self.max_patch_bytes,
            pause_channel_sha256=self.pause_control_sha256,
            operation=self.allowed_operation,
            result_type=self.allowed_result_type,
            path_sha256=_sha256_bytes(self.allowed_path.encode("utf-8")),
            expected_original_sha256=self.expected_original_sha256,
            verification_recipe_sha256=self.verification_recipe_sha256,
            data_egress_class=self.data_egress_class,
            data_egress_manifest_sha256=self.data_egress_manifest_sha256,
            credential_scope_sha256=self.credential_scope_sha256,
            credential_delivery_channel_sha256=self.credential_delivery_channel_sha256,
            receipt_chain_id_sha256=self.receipt_chain_id_sha256,
            receipt_predecessor_sha256=self.receipt_predecessor_sha256,
            receipt_predecessor_count=self.receipt_predecessor_count,
            kill_switch_channel_sha256=self.kill_switch_channel_sha256,
        )

    def validate_inactive_contract(self, *, now: datetime) -> None:
        if self.version != 4 or self.audience != "atlas-supervisor-v4-proposal-worker":
            raise SupervisorError("Supervisor v4 capability audience is invalid")
        if not self.provider or self.sdk_version != "0.147.0" or not self.signing_key_id:
            raise SupervisorError("Supervisor v4 capability trust identity is invalid")
        if self.command_network_access or self.attempt_limit != 1:
            raise SupervisorError("Supervisor v4 capability widens inactive authority")
        if self.allowed_operation != "replace_existing_file" or self.allowed_result_type != (
            "structured_replacement_proposal"
        ):
            raise SupervisorError("Supervisor v4 capability operation is invalid")
        relative = Path(self.allowed_path)
        if relative.is_absolute() or ".." in relative.parts or relative.as_posix() != self.allowed_path:
            raise SupervisorError("Supervisor v4 capability path is invalid")
        for value in (
            self.source_baseline_sha256,
            self.policy_bundle_sha256,
            self.replay_corpus_sha256,
            self.adapter_sha256,
            self.runtime_sha256,
            self.sandbox_profile_sha256,
            self.pause_control_sha256,
            self.expected_original_sha256,
            self.verification_recipe_sha256,
            self.data_egress_manifest_sha256,
            self.credential_scope_sha256,
            self.credential_delivery_channel_sha256,
            self.receipt_chain_id_sha256,
            self.receipt_predecessor_sha256,
            self.kill_switch_channel_sha256,
        ):
            if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
                raise SupervisorError("Supervisor v4 capability digest is invalid")
        issued = datetime.fromisoformat(self.issued_at.replace("Z", "+00:00"))
        expiry = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        if (
            issued.tzinfo is None
            or expiry.tzinfo is None
            or not 0 < (expiry - issued).total_seconds() <= 300
            or now < issued
            or now >= expiry
            or not isinstance(self.receipt_predecessor_count, int)
            or isinstance(self.receipt_predecessor_count, bool)
            or self.receipt_predecessor_count < 0
            or (
                self.receipt_predecessor_count == 0
                and self.receipt_predecessor_sha256 != "0" * 64
            )
            or (
                self.receipt_predecessor_count > 0
                and self.receipt_predecessor_sha256 == "0" * 64
            )
        ):
            raise SupervisorError("Supervisor v4 capability expiry is invalid")


class ModelContactTracker:
    """Monotonic contact state that can never be downgraded after process launch."""

    _ORDER = {"not_dispatched": 0, "contact_possible": 1, "contacted": 2}

    def __init__(self, state: str = "not_dispatched") -> None:
        if state not in self._ORDER:
            raise ValueError("Unknown Supervisor v4 model-contact state")
        self._state = state

    @property
    def state(self) -> str:
        return self._state

    def advance(self, state: str) -> str:
        if state not in self._ORDER or self._ORDER[state] < self._ORDER[self._state]:
            raise SupervisorError("Supervisor v4 model-contact state cannot move backward")
        self._state = state
        return state


@dataclass(frozen=True, slots=True)
class ValidatedReplacementProposal:
    relative_path: str
    replacement_content: str
    replacement_sha256: str
    replacement_bytes: int
    changed_lines: int

    def durable_receipt(self) -> dict[str, Any]:
        return {
            "operation": "replace_existing_file",
            "relative_path": self.relative_path,
            "replacement_sha256": self.replacement_sha256,
            "replacement_bytes": self.replacement_bytes,
            "changed_lines": self.changed_lines,
            "raw_response_persisted": False,
            "replacement_content_persisted": False,
            "candidate_integrated": False,
        }


def validate_structured_proposal(
    payload: object,
    *,
    capability: SupervisorV4Capability,
    original_content: str,
) -> ValidatedReplacementProposal:
    """Validate the exact proposal contract before Atlas may materialize bytes."""

    required_keys = {
        "schema_version",
        "operation",
        "baseline_sha256",
        "path",
        "original_sha256",
        "replacement",
    }
    if not isinstance(payload, dict) or set(payload) != required_keys:
        raise SupervisorError("Supervisor v4 proposal schema is not exact")
    expected_scalars = {
        "schema_version": 1,
        "operation": "replace_existing_file",
        "baseline_sha256": capability.source_baseline_sha256,
        "path": capability.allowed_path,
        "original_sha256": capability.expected_original_sha256,
    }
    if any(payload.get(key) != value for key, value in expected_scalars.items()):
        raise SupervisorError("Supervisor v4 proposal binding is invalid")
    original_bytes = original_content.encode("utf-8")
    if _sha256_bytes(original_bytes) != capability.expected_original_sha256:
        raise SupervisorError("Supervisor v4 original file digest drifted")
    replacement = payload.get("replacement")
    if not isinstance(replacement, str) or "\x00" in replacement:
        raise SupervisorError("Supervisor v4 replacement is not bounded UTF-8 text")
    try:
        replacement_bytes = replacement.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise SupervisorError("Supervisor v4 replacement is not valid UTF-8") from exc
    if len(replacement_bytes) > capability.max_patch_bytes:
        raise SupervisorError("Supervisor v4 replacement exceeds its byte budget")
    if any(pattern.search(replacement) for pattern in _SECRET_PATTERNS):
        raise SupervisorError("Supervisor v4 replacement resembles secret material")
    original_lines = original_content.splitlines()
    replacement_lines = replacement.splitlines()
    changed_lines = sum(
        1
        for line in difflib.ndiff(original_lines, replacement_lines)
        if line.startswith(("+ ", "- "))
    )
    if capability.max_changed_files != 1 or changed_lines > capability.max_changed_lines:
        raise SupervisorError("Supervisor v4 replacement exceeds its change budget")
    if replacement == original_content:
        raise SupervisorError("Supervisor v4 proposal makes no change")
    return ValidatedReplacementProposal(
        relative_path=capability.allowed_path,
        replacement_content=replacement,
        replacement_sha256=_sha256_bytes(replacement_bytes),
        replacement_bytes=len(replacement_bytes),
        changed_lines=changed_lines,
    )


def _extract_schema_methods(document: dict[str, Any]) -> set[str]:
    methods: set[str] = set()

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            properties = value.get("properties")
            method = properties.get("method") if isinstance(properties, dict) else None
            if isinstance(method, dict):
                constant = method.get("const")
                choices = method.get("enum")
                if isinstance(constant, str):
                    methods.add(constant)
                if (
                    isinstance(choices, list)
                    and len(choices) == 1
                    and isinstance(choices[0], str)
                ):
                    methods.add(choices[0])
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(document)
    return methods


class SupervisorV4Service:
    """Offline-only Supervisor v4 qualification and status surface."""

    def __init__(self, *, config: AtlasConfig, database: Database | None) -> None:
        self.config = config
        self.database = database

    @property
    def enabled(self) -> bool:
        return self.config.supervisor_v4.enabled and self.config.supervisor_v4_policy is not None

    def _option1_canary_accounting(self) -> dict[str, object]:
        """Inspect only owner-private canary receipts; never query Keychain."""

        from atlas_core.supervisor_v4_option1_canary import (
            Option1CanaryViolation,
            inspect_canary_accounting,
        )

        owner_home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True)
        runtime_root = (
            owner_home
            / "Library/Application Support/Atlas Core/runtime/supervisor-v4-option1"
        )
        if not os.path.lexists(runtime_root):
            return {
                "canary_launch_state": "runtime_unavailable",
                "canary_accounting_origin": None,
                "canary_launch_evidence_sha256": None,
                "canary_parent_error_code": None,
                "canary_attempt_state": "not_attempted",
                "canary_evidence_sha256": None,
                "canary_keychain_query_performed": False,
                "canary_synthetic_delivery_started": False,
                "failed_preclaim_no_keychain_query_or_delivery_verified": False,
            }
        try:
            return inspect_canary_accounting(runtime_root)
        except Option1CanaryViolation:
            return {
                "canary_launch_state": "invalid",
                "canary_accounting_origin": None,
                "canary_launch_evidence_sha256": None,
                "canary_parent_error_code": "option1_canary_accounting_invalid",
                "canary_attempt_state": "invalid",
                "canary_evidence_sha256": None,
                "canary_keychain_query_performed": None,
                "canary_synthetic_delivery_started": None,
                "failed_preclaim_no_keychain_query_or_delivery_verified": False,
            }

    def _option1_recovery_canary_accounting(self) -> dict[str, object]:
        """Inspect the separate recovery lineage without querying Keychain."""

        from atlas_core.supervisor_v4_option1_recovery_canary import (
            Option1RecoveryCanaryViolation,
            inspect_recovery_canary_accounting,
        )

        owner_home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True)
        runtime_root = (
            owner_home
            / "Library/Application Support/Atlas Core/runtime/supervisor-v4-option1"
        )
        unavailable = {
            "recovery_canary_predecessor_verified": False,
            "recovery_canary_predecessor_launch_id": None,
            "recovery_canary_predecessor_evidence_sha256": None,
            "recovery_canary_launch_state": "runtime_unavailable",
            "recovery_canary_launch_evidence_sha256": None,
            "recovery_canary_parent_error_code": None,
            "recovery_canary_attempt_state": "not_attempted",
            "recovery_canary_evidence_sha256": None,
            "recovery_canary_keychain_query_performed": False,
            "recovery_canary_synthetic_delivery_started": False,
            "recovery_canary_launches_used": 0,
            "recovery_canary_attempts_used": 0,
        }
        if not os.path.lexists(runtime_root):
            return unavailable
        try:
            return inspect_recovery_canary_accounting(runtime_root)
        except Option1RecoveryCanaryViolation:
            return {
                **unavailable,
                "recovery_canary_launch_state": "invalid",
                "recovery_canary_attempt_state": "invalid",
                "recovery_canary_parent_error_code": (
                    "option1_recovery_canary_accounting_invalid"
                ),
                "recovery_canary_keychain_query_performed": None,
                "recovery_canary_synthetic_delivery_started": None,
            }

    @staticmethod
    def _option1_canary_status_projection(
        accounting: Mapping[str, object],
    ) -> tuple[str, str | None]:
        launch_state = accounting.get("canary_launch_state")
        attempt_state = accounting.get("canary_attempt_state")
        parent_error = accounting.get("canary_parent_error_code")
        if (
            launch_state == "child_completed"
            and attempt_state == "passed"
            and parent_error is None
        ):
            return "completed_inactive", None
        if launch_state == "not_launched" and attempt_state == "not_attempted":
            return (
                "implemented_inactive",
                "option1_synthetic_integration_canary_not_run",
            )
        if launch_state == "failed_preclaim" and attempt_state == "failed_preclaim":
            return (
                "failed_preclaim_recovery_review_required",
                "option1_synthetic_integration_canary_failed_preclaim",
            )
        if launch_state == "runtime_unavailable":
            return (
                "runtime_review_required",
                "option1_vault_or_runtime_unavailable",
            )
        if launch_state == "invalid" or attempt_state == "invalid":
            return (
                "state_review_required",
                "option1_synthetic_integration_canary_state_invalid",
            )
        return (
            "recovery_review_required",
            "option1_synthetic_integration_canary_recovery_required",
        )

    @staticmethod
    def _option1_canary_next_gate(accounting: Mapping[str, object]) -> str:
        if (
            accounting.get("canary_launch_state") == "not_launched"
            and accounting.get("canary_attempt_state") == "not_attempted"
        ):
            return "owner_authorize_option1_on_demand_synthetic_integration_canary"
        if (
            accounting.get("canary_launch_state") == "child_completed"
            and accounting.get("canary_attempt_state") == "passed"
            and accounting.get("canary_parent_error_code") is None
        ):
            return "owner_review_option1_synthetic_integration_canary_result"
        if accounting.get("canary_launch_state") == "runtime_unavailable":
            return "owner_review_option1_vault_and_runtime_state"
        return "owner_review_option1_synthetic_integration_canary_recovery"

    @staticmethod
    def _option1_recovery_canary_status_projection(
        accounting: Mapping[str, object],
    ) -> tuple[str, str | None]:
        launch_state = accounting.get("recovery_canary_launch_state")
        attempt_state = accounting.get("recovery_canary_attempt_state")
        parent_error = accounting.get("recovery_canary_parent_error_code")
        predecessor_verified = accounting.get(
            "recovery_canary_predecessor_verified"
        )
        if (
            predecessor_verified is True
            and launch_state == "child_completed"
            and attempt_state == "passed"
            and parent_error is None
        ):
            return "completed_inactive", None
        if (
            predecessor_verified is True
            and launch_state == "not_launched"
            and attempt_state == "not_attempted"
        ):
            return (
                "option1_synthetic_integration_recovery_canary_implemented_inactive",
                "option1_synthetic_integration_recovery_canary_owner_authorization_absent",
            )
        if launch_state == "runtime_unavailable":
            return "runtime_review_required", "option1_vault_or_runtime_unavailable"
        if (
            predecessor_verified is not True
            or launch_state == "invalid"
            or attempt_state == "invalid"
        ):
            return (
                "state_review_required",
                "option1_synthetic_integration_recovery_canary_state_invalid",
            )
        return (
            "result_review_required",
            "option1_synthetic_integration_recovery_canary_result_review_required",
        )

    @staticmethod
    def _option1_recovery_result_review_content(
        original: Mapping[str, object],
        recovery: Mapping[str, object],
    ) -> dict[str, object]:
        """Bind a non-authorizing review to the exact exhausted canary lineage."""

        digest_fields = (
            original.get("canary_launch_evidence_sha256"),
            recovery.get("recovery_canary_predecessor_evidence_sha256"),
            recovery.get("recovery_canary_launch_evidence_sha256"),
            recovery.get("recovery_canary_evidence_sha256"),
        )
        if (
            original.get("canary_launch_state") != "failed_preclaim"
            or original.get("canary_attempt_state") != "failed_preclaim"
            or original.get("canary_accounting_origin")
            != "postflight_reconciliation"
            or not isinstance(original.get("canary_parent_error_code"), str)
            or original.get("failed_preclaim_no_keychain_query_or_delivery_verified")
            is not True
            or original.get("canary_keychain_query_performed") is not False
            or original.get("canary_synthetic_delivery_started") is not False
            or recovery.get("recovery_canary_predecessor_verified") is not True
            or recovery.get("recovery_canary_launch_state") != "child_completed"
            or recovery.get("recovery_canary_attempt_state") != "passed"
            or recovery.get("recovery_canary_parent_error_code") is not None
            or recovery.get("recovery_canary_keychain_query_performed") is not True
            or recovery.get("recovery_canary_synthetic_delivery_started") is not True
            or recovery.get("recovery_canary_launches_used") != 1
            or recovery.get("recovery_canary_attempts_used") != 1
            or not _is_canonical_uuid4(
                recovery.get("recovery_canary_predecessor_launch_id")
            )
            or any(
                not isinstance(value, str)
                or re.fullmatch(r"[0-9a-f]{64}", value) is None
                or value == "0" * 64
                for value in digest_fields
            )
            or recovery.get("recovery_canary_predecessor_evidence_sha256")
            != original.get("canary_launch_evidence_sha256")
        ):
            raise SupervisorError(
                "Option 1 recovery result is not an exact completed synthetic lineage"
            )
        return {
            "version": 1,
            "classification": (
                "option1_synthetic_integration_recovery_canary_result_review"
            ),
            "status": "reviewed_inactive",
            "original_canary_accounting_origin": "postflight_reconciliation",
            "original_canary_launch_state": "failed_preclaim",
            "original_canary_attempt_state": "failed_preclaim",
            "original_canary_parent_error_code": original[
                "canary_parent_error_code"
            ],
            "original_canary_launch_evidence_sha256": digest_fields[0],
            "recovery_canary_predecessor_launch_id": recovery[
                "recovery_canary_predecessor_launch_id"
            ],
            "recovery_canary_predecessor_evidence_sha256": digest_fields[1],
            "recovery_canary_launch_state": "child_completed",
            "recovery_canary_attempt_state": "passed",
            "recovery_canary_launch_evidence_sha256": digest_fields[2],
            "recovery_canary_evidence_sha256": digest_fields[3],
            "recovery_canary_launches_used": 1,
            "recovery_canary_attempts_used": 1,
            "synthetic_keychain_only": True,
            "authority_granted": False,
            "credential_use_authorized": False,
            "private_data_transmission_authorized": False,
            "model_contact_authorized": False,
            "network_access_authorized": False,
            "service_identity_provisioning_authorized": False,
            "vault_provisioning_authorized": False,
            "access_change_authorized": False,
            "background_execution_authorized": False,
            "deployment_authorized": False,
            "live_execution_authorized": False,
        }

    def _option1_recovery_result_review_state(
        self,
        original: Mapping[str, object],
        recovery: Mapping[str, object],
    ) -> tuple[str, bool, str | None]:
        try:
            expected = self._option1_recovery_result_review_content(
                original, recovery
            )
        except SupervisorError:
            return "not_applicable", False, None
        if self.database is None or not hasattr(
            self.database, "list_supervisor_v4_qualifications"
        ):
            return (
                "review_storage_unavailable",
                False,
                "option1_recovery_canary_result_review_storage_unavailable",
            )
        records = self.database.list_supervisor_v4_qualifications(
            subject=_OPTION1_RECOVERY_RESULT_REVIEW_SUBJECT,
            limit=3,
        )
        if not records:
            return (
                "review_required",
                False,
                "option1_synthetic_integration_recovery_canary_result_review_required",
            )
        expected_json = canonical_json(expected)
        expected_sha256 = _sha256_bytes(expected_json.encode("utf-8"))
        if len(records) != 1:
            return (
                "review_invalid",
                False,
                "option1_recovery_canary_result_review_duplicate_evidence",
            )
        record = records[0]
        if (
            record.get("status") != "inactive"
            or record.get("content") != expected
            or record.get("content_sha256") != expected_sha256
            or int(record.get("authority_granted", 1)) != 0
        ):
            return (
                "review_invalid",
                False,
                "option1_recovery_canary_result_review_evidence_mismatch",
            )
        return "reviewed_inactive", True, None

    def record_option1_recovery_canary_result_review(self) -> dict[str, object]:
        """Record one exact acknowledgement without granting any authority."""

        if self.database is None or not hasattr(
            self.database, "record_supervisor_v4_qualification_once"
        ):
            raise SupervisorError("Supervisor v4 review ledger is unavailable")
        original = self._option1_canary_accounting()
        recovery = self._option1_recovery_canary_accounting()
        content = self._option1_recovery_result_review_content(original, recovery)
        record = self.database.record_supervisor_v4_qualification_once(
            subject=_OPTION1_RECOVERY_RESULT_REVIEW_SUBJECT,
            status="inactive",
            content=content,
        )
        state, reviewed, blocker = self._option1_recovery_result_review_state(
            original, recovery
        )
        if state != "reviewed_inactive" or reviewed is not True or blocker is not None:
            raise SupervisorError(
                "Option 1 recovery result review evidence did not verify"
            )
        return {
            "classification": content["classification"],
            "result_review_state": state,
            "qualification_id": record["id"],
            "qualification_sha256": record["content_sha256"],
            "authority_granted": False,
            "credential_use_authorized": False,
            "private_data_transmission_authorized": False,
            "model_contact_authorized": False,
            "network_access_authorized": False,
            "service_identity_provisioning_authorized": False,
            "vault_provisioning_authorized": False,
            "access_change_authorized": False,
            "background_execution_authorized": False,
            "deployment_authorized": False,
            "live_execution_authorized": False,
            "next_gate": OPTION2_PLAN_NEXT_GATE,
        }

    def review_option2_service_identity_and_vault_offline_plan(
        self,
    ) -> dict[str, object]:
        """Validate the inactive design after the recovery result is reviewed."""

        original = self._option1_canary_accounting()
        recovery = self._option1_recovery_canary_accounting()
        state, reviewed, blocker = self._option1_recovery_result_review_state(
            original, recovery
        )
        if state != "reviewed_inactive" or reviewed is not True or blocker is not None:
            raise SupervisorError(
                "Option 1 recovery result review must verify before Option 2 review"
            )
        return review_option2_service_identity_and_vault_plan()

    def _option2_production_paths_are_null(self) -> bool:
        return self._option2_production_paths_configured_count() == 0

    def _option2_production_paths_configured_count(self) -> int:
        return sum(
            getattr(self.config.supervisor_v4, field) is not None
            for field in PRODUCTION_CONFIGURATION_FIELDS
        )

    def _option2_plan_review_content(
        self,
        original: Mapping[str, object],
        recovery: Mapping[str, object],
    ) -> dict[str, object]:
        predecessor = self._option1_recovery_result_review_content(
            original, recovery
        )
        predecessor_sha256 = _sha256_bytes(
            canonical_json(predecessor).encode("utf-8")
        )
        return build_option2_plan_review_content(
            predecessor_option1_result_review_sha256=predecessor_sha256
        )

    def _option2_plan_review_state(
        self,
        original: Mapping[str, object],
        recovery: Mapping[str, object],
    ) -> tuple[str, bool, str | None]:
        option1_state, option1_reviewed, _option1_blocker = (
            self._option1_recovery_result_review_state(original, recovery)
        )
        if option1_state != "reviewed_inactive" or option1_reviewed is not True:
            return "not_applicable", False, None
        if not self._option2_production_paths_are_null():
            return (
                "review_invalid",
                False,
                "option2_plan_review_production_configuration_present",
            )
        if self.database is None or not hasattr(
            self.database, "list_supervisor_v4_qualifications"
        ):
            return (
                "review_storage_unavailable",
                False,
                "option2_plan_review_storage_unavailable",
            )
        try:
            expected = self._option2_plan_review_content(original, recovery)
        except (Option2PlanViolation, Option2ProvisionerViolation, KeyError, TypeError):
            return (
                "review_invalid",
                False,
                "option2_plan_review_contract_drift",
            )
        records = self.database.list_supervisor_v4_qualifications(
            subject=_OPTION2_PLAN_REVIEW_SUBJECT,
            limit=3,
        )
        if not records:
            return (
                "review_required",
                False,
                "option2_service_identity_and_vault_offline_plan_review_required",
            )
        if len(records) != 1:
            return (
                "review_invalid",
                False,
                "option2_plan_review_duplicate_evidence",
            )
        expected_json = canonical_json(expected)
        expected_sha256 = _sha256_bytes(expected_json.encode("utf-8"))
        record = records[0]
        if (
            record.get("status") != "inactive"
            or record.get("content") != expected
            or record.get("content_sha256") != expected_sha256
            or int(record.get("authority_granted", 1)) != 0
        ):
            return (
                "review_invalid",
                False,
                "option2_plan_review_evidence_mismatch",
            )
        return "reviewed_inactive", True, None

    def record_option2_service_identity_and_vault_plan_review(
        self,
    ) -> dict[str, object]:
        """Record the owner's exact plan review without granting provisioning authority."""

        if self.database is None or not hasattr(
            self.database, "record_supervisor_v4_qualification_once"
        ):
            raise SupervisorError("Supervisor v4 review ledger is unavailable")
        original = self._option1_canary_accounting()
        recovery = self._option1_recovery_canary_accounting()
        option1_state, option1_reviewed, option1_blocker = (
            self._option1_recovery_result_review_state(original, recovery)
        )
        if (
            option1_state != "reviewed_inactive"
            or option1_reviewed is not True
            or option1_blocker is not None
        ):
            raise SupervisorError(
                "Option 1 recovery result review must verify before Option 2 review"
            )
        if not self._option2_production_paths_are_null():
            raise SupervisorError(
                "Option 2 production configuration must remain null during review"
            )
        content = self._option2_plan_review_content(original, recovery)
        record = self.database.record_supervisor_v4_qualification_once(
            subject=_OPTION2_PLAN_REVIEW_SUBJECT,
            status="inactive",
            content=content,
        )
        state, reviewed, blocker = self._option2_plan_review_state(
            original, recovery
        )
        if state != "reviewed_inactive" or reviewed is not True or blocker is not None:
            raise SupervisorError("Option 2 plan review evidence did not verify")
        return {
            "classification": content["classification"],
            "plan_review_state": state,
            "qualification_id": record["id"],
            "qualification_sha256": record["content_sha256"],
            "plan_sha256": content["plan_sha256"],
            "authority_granted": False,
            "provisioning_authorized": False,
            "service_identity_creation_authorized": False,
            "service_identity_provisioning_authorized": False,
            "vault_provisioning_authorized": False,
            "credential_use_authorized": False,
            "private_data_transmission_authorized": False,
            "model_contact_authorized": False,
            "network_access_authorized": False,
            "access_change_authorized": False,
            "background_execution_authorized": False,
            "deployment_authorized": False,
            "live_execution_authorized": False,
            "next_gate": "option2_provisioner_fixture_qualification",
        }

    def _option2_provisioner_qualification_content(
        self,
        original: Mapping[str, object],
        recovery: Mapping[str, object],
    ) -> dict[str, object]:
        plan_review = self._option2_plan_review_content(original, recovery)
        plan_review_sha256 = _sha256_bytes(
            canonical_json(plan_review).encode("utf-8")
        )
        report = review_option2_provisioner_contract(
            service_verified_plan_review_content_sha256=plan_review_sha256
        )
        manifest = build_option2_provisioner_manifest()
        expected_report_keys = {
            "all_declared_fixture_conflict_cases_rejected",
            "all_virtual_post_stage_snapshot_rollbacks_covered",
            "all_virtual_rollback_failures_quarantined",
            "authority",
            "classification",
            "declared_fixture_preflight_rejection_case_count",
            "declared_fixture_preflight_rejection_case_sha256",
            "fixture_engine_account_api_called",
            "fixture_engine_filesystem_read",
            "fixture_engine_filesystem_written",
            "fixture_engine_host_inspected",
            "fixture_engine_keychain_queried",
            "fixture_engine_launchd_contacted",
            "fixture_engine_model_contacted",
            "fixture_engine_network_accessed",
            "fixture_engine_provider_contacted",
            "fixture_engine_socket_opened",
            "fixture_engine_subprocess_started",
            "fixture_engine_temporary_files_written",
            "host_apply_present",
            "in_memory_fixture_engine_only",
            "manifest_sha256",
            "next_gate",
            "post_stage_rollback_cases",
            "production_configuration",
            "production_manifest_complete",
            "production_preflight_qualified",
            "production_rollback_qualified",
            "qualification_sha256",
            "ready",
            "ready_live",
            "ready_offline",
            "reviewed_plan_sha256",
            "service_verified_plan_review_content_sha256",
            "state",
            "success_simulation_sha256",
            "virtual_post_stage_rollback_case_count",
            "virtual_rollback_uncertainty_case_count",
            "virtual_rollback_uncertainty_case_sha256",
            "virtual_success_invariants",
        }
        stage_ids = {
            str(stage["id"]) for stage in manifest["transaction_stages"]
        }
        rejection_case_ids = {
            "group_collision",
            "identity_collision",
            "directory_collision",
            "artifact_collision",
            "service_definition_collision",
            "symlink_target",
            "acl_drift",
            "code_signing_drift",
            "production_path_configured",
            "service_loaded",
            "socket_active",
            "key_present",
            "vault_item_present",
            "owner_pause_unlatched",
        }
        expected_success_invariant_ids = {
            "manifest_attested",
            "preflight_verified",
            "future_authorization_contract_attested",
            "six_groups_projected",
            "six_identities_projected",
            "six_disjoint_roots_projected",
            "six_synthetic_artifacts_projected",
            "six_inert_service_definitions_projected",
            "no_service_loaded",
            "no_socket_active",
            "no_key_present",
            "no_vault_item_present",
            "owner_pause_latched",
            "inactive_postflight_verified",
            "one_non_authorizing_receipt_projected",
            "production_configuration_null",
        }
        false_fields = {
            "fixture_engine_account_api_called",
            "fixture_engine_filesystem_read",
            "fixture_engine_filesystem_written",
            "fixture_engine_host_inspected",
            "fixture_engine_keychain_queried",
            "fixture_engine_launchd_contacted",
            "fixture_engine_model_contacted",
            "fixture_engine_network_accessed",
            "fixture_engine_provider_contacted",
            "fixture_engine_socket_opened",
            "fixture_engine_subprocess_started",
            "fixture_engine_temporary_files_written",
            "host_apply_present",
            "production_manifest_complete",
            "production_preflight_qualified",
            "production_rollback_qualified",
            "ready",
            "ready_live",
            "ready_offline",
        }
        report_body = {
            key: value
            for key, value in report.items()
            if key != "qualification_sha256"
        }
        post_stage_cases = report.get("post_stage_rollback_cases")
        rejection_cases = report.get(
            "declared_fixture_preflight_rejection_case_sha256"
        )
        uncertainty_cases = report.get(
            "virtual_rollback_uncertainty_case_sha256"
        )
        success_invariants = report.get("virtual_success_invariants")
        if (
            set(report) != expected_report_keys
            or report.get("classification")
            != "option2_provisioner_offline_fixture_qualification"
            or report.get("state") != OPTION2_PROVISIONER_QUALIFICATION_STATE
            or report.get("service_verified_plan_review_content_sha256")
            != plan_review_sha256
            or report.get("reviewed_plan_sha256")
            != manifest["reviewed_plan_sha256"]
            or report.get("manifest_sha256") != manifest["manifest_sha256"]
            or report.get("next_gate") != OPTION2_PROVISIONER_NEXT_GATE
            or report.get("qualification_sha256")
            != _sha256_bytes(canonical_json(report_body).encode("utf-8"))
            or report.get("in_memory_fixture_engine_only") is not True
            or report.get(
                "all_virtual_post_stage_snapshot_rollbacks_covered"
            )
            is not True
            or report.get("all_declared_fixture_conflict_cases_rejected")
            is not True
            or report.get("all_virtual_rollback_failures_quarantined")
            is not True
            or any(report.get(field) is not False for field in false_fields)
            or report.get("authority") != manifest["authority"]
            or report.get("production_configuration")
            != manifest["production_configuration"]
            or not isinstance(success_invariants, Mapping)
            or set(success_invariants) != expected_success_invariant_ids
            or any(value is not True for value in success_invariants.values())
            or not isinstance(report.get("success_simulation_sha256"), str)
            or re.fullmatch(
                r"[0-9a-f]{64}", str(report["success_simulation_sha256"])
            )
            is None
            or not isinstance(post_stage_cases, Mapping)
            or set(post_stage_cases) != stage_ids
            or report.get("virtual_post_stage_rollback_case_count")
            != len(stage_ids)
            or any(
                not isinstance(case, Mapping)
                or set(case)
                != {
                    "simulation_sha256",
                    "outcome",
                    "restored_to_preflight_snapshot",
                    "rollback_complete",
                }
                or case.get("outcome") != "rolled_back_inactive"
                or case.get("restored_to_preflight_snapshot") is not True
                or case.get("rollback_complete") is not True
                or not isinstance(case.get("simulation_sha256"), str)
                or re.fullmatch(
                    r"[0-9a-f]{64}", str(case.get("simulation_sha256"))
                )
                is None
                for case in post_stage_cases.values()
            )
            or not isinstance(rejection_cases, Mapping)
            or set(rejection_cases) != rejection_case_ids
            or report.get("declared_fixture_preflight_rejection_case_count")
            != len(rejection_case_ids)
            or any(
                not isinstance(value, str)
                or re.fullmatch(r"[0-9a-f]{64}", value) is None
                for value in rejection_cases.values()
            )
            or not isinstance(uncertainty_cases, Mapping)
            or set(uncertainty_cases) != stage_ids
            or report.get("virtual_rollback_uncertainty_case_count")
            != len(stage_ids)
            or any(
                not isinstance(value, str)
                or re.fullmatch(r"[0-9a-f]{64}", value) is None
                for value in uncertainty_cases.values()
            )
        ):
            raise SupervisorError(
                "Option 2 provisioner fixture qualification was not exact"
            )
        return {
            "version": 1,
            "classification": (
                "option2_service_identity_provisioner_fixture_qualification"
            ),
            "status": OPTION2_PROVISIONER_QUALIFICATION_STATE,
            "predecessor_plan_review_sha256": plan_review_sha256,
            "reviewed_plan_sha256": report["reviewed_plan_sha256"],
            "manifest_sha256": report["manifest_sha256"],
            "fixture_qualification_sha256": report["qualification_sha256"],
            "all_virtual_post_stage_snapshot_rollbacks_covered": True,
            "all_declared_fixture_conflict_cases_rejected": True,
            "all_virtual_rollback_failures_quarantined": True,
            "production_preflight_qualified": False,
            "production_rollback_qualified": False,
            "production_manifest_complete": False,
            "host_apply_present": False,
            "production_paths_configured": 0,
            "fixture_engine_host_inspected": False,
            "fixture_engine_filesystem_read": False,
            "fixture_engine_filesystem_written": False,
            "fixture_engine_temporary_files_written": False,
            "fixture_engine_subprocess_started": False,
            "fixture_engine_account_api_called": False,
            "fixture_engine_keychain_queried": False,
            "fixture_engine_socket_opened": False,
            "fixture_engine_launchd_contacted": False,
            "fixture_engine_network_accessed": False,
            "fixture_engine_model_contacted": False,
            "fixture_engine_provider_contacted": False,
            "authority_granted": False,
            "provisioning_authorized": False,
            "service_identity_creation_authorized": False,
            "service_identity_provisioning_authorized": False,
            "vault_provisioning_authorized": False,
            "credential_use_authorized": False,
            "private_data_transmission_authorized": False,
            "model_contact_authorized": False,
            "network_access_authorized": False,
            "access_change_authorized": False,
            "background_execution_authorized": False,
            "deployment_authorized": False,
            "live_execution_authorized": False,
            "ready": False,
            "ready_offline": False,
            "ready_live": False,
        }

    def _option2_provisioner_qualification_state(
        self,
        original: Mapping[str, object],
        recovery: Mapping[str, object],
    ) -> tuple[str, bool, str | None]:
        plan_state, plan_reviewed, _plan_blocker = self._option2_plan_review_state(
            original, recovery
        )
        if plan_state != "reviewed_inactive" or plan_reviewed is not True:
            return "not_applicable", False, None
        if not self._option2_production_paths_are_null():
            return (
                "qualification_invalid",
                False,
                "option2_provisioner_production_configuration_present",
            )
        if self.database is None or not hasattr(
            self.database, "list_supervisor_v4_qualifications"
        ):
            return (
                "qualification_storage_unavailable",
                False,
                "option2_provisioner_qualification_storage_unavailable",
            )
        try:
            expected = self._option2_provisioner_qualification_content(
                original, recovery
            )
        except (
            Option2PlanViolation,
            Option2ProvisionerViolation,
            SupervisorError,
            KeyError,
            TypeError,
        ):
            return (
                "qualification_invalid",
                False,
                "option2_provisioner_contract_drift",
            )
        records = self.database.list_supervisor_v4_qualifications(
            subject=_OPTION2_PROVISIONER_QUALIFICATION_SUBJECT,
            limit=3,
        )
        if not records:
            return (
                "qualification_required",
                False,
                "option2_provisioner_fixture_qualification_required",
            )
        if len(records) != 1:
            return (
                "qualification_invalid",
                False,
                "option2_provisioner_qualification_duplicate_evidence",
            )
        expected_json = canonical_json(expected)
        expected_sha256 = _sha256_bytes(expected_json.encode("utf-8"))
        record = records[0]
        if (
            record.get("status") != "inactive"
            or record.get("content") != expected
            or record.get("content_sha256") != expected_sha256
            or int(record.get("authority_granted", 1)) != 0
        ):
            return (
                "qualification_invalid",
                False,
                "option2_provisioner_qualification_evidence_mismatch",
            )
        return OPTION2_PROVISIONER_QUALIFICATION_STATE, True, None

    def record_option2_provisioner_fixture_qualification(
        self,
    ) -> dict[str, object]:
        """Persist the pure engine result; perform no provisioning or host probe."""

        if self.database is None or not hasattr(
            self.database, "record_supervisor_v4_qualification_once"
        ):
            raise SupervisorError("Supervisor v4 review ledger is unavailable")
        original = self._option1_canary_accounting()
        recovery = self._option1_recovery_canary_accounting()
        plan_state, plan_reviewed, plan_blocker = self._option2_plan_review_state(
            original, recovery
        )
        if (
            plan_state != "reviewed_inactive"
            or plan_reviewed is not True
            or plan_blocker is not None
        ):
            raise SupervisorError(
                "Option 2 plan review must verify before fixture qualification"
            )
        content = self._option2_provisioner_qualification_content(
            original, recovery
        )
        record = self.database.record_supervisor_v4_qualification_once(
            subject=_OPTION2_PROVISIONER_QUALIFICATION_SUBJECT,
            status="inactive",
            content=content,
        )
        state, qualified, blocker = self._option2_provisioner_qualification_state(
            original, recovery
        )
        if (
            state != OPTION2_PROVISIONER_QUALIFICATION_STATE
            or qualified is not True
            or blocker is not None
        ):
            raise SupervisorError(
                "Option 2 provisioner fixture qualification evidence did not verify"
            )
        return {
            "classification": content["classification"],
            "qualification_state": state,
            "qualification_id": record["id"],
            "qualification_sha256": record["content_sha256"],
            "qualification_record_persisted": True,
            "manifest_sha256": content["manifest_sha256"],
            "production_manifest_complete": False,
            "host_apply_present": False,
            "authority_granted": False,
            "provisioning_authorized": False,
            "service_identity_creation_authorized": False,
            "service_identity_provisioning_authorized": False,
            "vault_provisioning_authorized": False,
            "credential_use_authorized": False,
            "private_data_transmission_authorized": False,
            "model_contact_authorized": False,
            "network_access_authorized": False,
            "access_change_authorized": False,
            "background_execution_authorized": False,
            "deployment_authorized": False,
            "live_execution_authorized": False,
            "ready": False,
            "ready_offline": False,
            "ready_live": False,
            "next_gate": OPTION2_PROVISIONER_NEXT_GATE,
        }

    def _option2_provisioner_manifest_review_content(
        self,
        original: Mapping[str, object],
        recovery: Mapping[str, object],
    ) -> dict[str, object]:
        plan_review = self._option2_plan_review_content(original, recovery)
        plan_review_sha256 = _sha256_bytes(
            canonical_json(plan_review).encode("utf-8")
        )
        fixture_qualification = self._option2_provisioner_qualification_content(
            original, recovery
        )
        fixture_qualification_sha256 = _sha256_bytes(
            canonical_json(fixture_qualification).encode("utf-8")
        )
        return build_option2_service_identity_provisioning_manifest_review_content(
            plan_review_content_sha256=plan_review_sha256,
            fixture_qualification_content_sha256=(
                fixture_qualification_sha256
            ),
            reviewed_plan_sha256=str(
                fixture_qualification["reviewed_plan_sha256"]
            ),
            manifest_sha256=str(fixture_qualification["manifest_sha256"]),
            fixture_qualification_sha256=str(
                fixture_qualification["fixture_qualification_sha256"]
            ),
        )

    def _option2_provisioner_manifest_review_state(
        self,
        original: Mapping[str, object],
        recovery: Mapping[str, object],
    ) -> tuple[str, bool, str | None]:
        if not self._option2_production_paths_are_null():
            return (
                "review_invalid",
                False,
                "option2_manifest_review_production_configuration_present",
            )
        qualification_state, qualified, _qualification_blocker = (
            self._option2_provisioner_qualification_state(original, recovery)
        )
        if (
            qualification_state != OPTION2_PROVISIONER_QUALIFICATION_STATE
            or qualified is not True
        ):
            return "not_applicable", False, None
        if self.database is None or not hasattr(
            self.database, "list_supervisor_v4_qualifications"
        ):
            return (
                "review_storage_unavailable",
                False,
                "option2_manifest_review_storage_unavailable",
            )
        try:
            expected = self._option2_provisioner_manifest_review_content(
                original, recovery
            )
        except (
            Option2ManifestReviewViolation,
            Option2PlanViolation,
            Option2ProvisionerViolation,
            SupervisorError,
            KeyError,
            TypeError,
        ):
            return (
                "review_invalid",
                False,
                "option2_manifest_review_contract_drift",
            )
        records = self.database.list_supervisor_v4_qualifications(
            subject=_OPTION2_PROVISIONER_MANIFEST_REVIEW_SUBJECT,
            limit=3,
        )
        if not records:
            return (
                "review_required",
                False,
                "option2_service_identity_provisioning_manifest_review_required",
            )
        if len(records) != 1:
            return (
                "review_invalid",
                False,
                "option2_manifest_review_duplicate_evidence",
            )
        expected_json = canonical_json(expected)
        expected_sha256 = _sha256_bytes(expected_json.encode("utf-8"))
        record = records[0]
        if (
            record.get("status") != "inactive"
            or record.get("content") != expected
            or record.get("content_sha256") != expected_sha256
            or int(record.get("authority_granted", 1)) != 0
        ):
            return (
                "review_invalid",
                False,
                "option2_manifest_review_evidence_mismatch",
            )
        return OPTION2_MANIFEST_REVIEW_STATE, True, None

    def record_option2_service_identity_provisioning_manifest_review(
        self,
    ) -> dict[str, object]:
        """Record review of the incomplete manifest without host authority."""

        if self.database is None or not hasattr(
            self.database, "record_supervisor_v4_qualification_once"
        ):
            raise SupervisorError("Supervisor v4 review ledger is unavailable")
        original = self._option1_canary_accounting()
        recovery = self._option1_recovery_canary_accounting()
        if not self._option2_production_paths_are_null():
            raise SupervisorError(
                "Option 2 production configuration must remain null during review"
            )
        qualification_state, qualified, qualification_blocker = (
            self._option2_provisioner_qualification_state(original, recovery)
        )
        if (
            qualification_state != OPTION2_PROVISIONER_QUALIFICATION_STATE
            or qualified is not True
            or qualification_blocker is not None
        ):
            raise SupervisorError(
                "Option 2 fixture qualification must verify before manifest review"
            )
        content = self._option2_provisioner_manifest_review_content(
            original, recovery
        )
        record = self.database.record_supervisor_v4_qualification_once(
            subject=_OPTION2_PROVISIONER_MANIFEST_REVIEW_SUBJECT,
            status="inactive",
            content=content,
        )
        state, reviewed, blocker = self._option2_provisioner_manifest_review_state(
            original, recovery
        )
        if (
            state != OPTION2_MANIFEST_REVIEW_STATE
            or reviewed is not True
            or blocker is not None
        ):
            raise SupervisorError(
                "Option 2 provisioning manifest review evidence did not verify"
            )
        return {
            "classification": content["classification"],
            "manifest_review_state": state,
            "qualification_id": record["id"],
            "qualification_sha256": record["content_sha256"],
            "manifest_sha256": content["manifest_sha256"],
            "production_manifest_complete": False,
            "production_artifact_bindings_present": False,
            "production_preflight_qualified": False,
            "production_rollback_qualified": False,
            "host_apply_present": False,
            "authority_granted": False,
            "provisioning_authorized": False,
            "service_identity_creation_authorized": False,
            "service_identity_provisioning_authorized": False,
            "vault_provisioning_authorized": False,
            "credential_use_authorized": False,
            "private_data_transmission_authorized": False,
            "model_contact_authorized": False,
            "network_access_authorized": False,
            "access_change_authorized": False,
            "background_execution_authorized": False,
            "deployment_authorized": False,
            "live_execution_authorized": False,
            "ready": False,
            "ready_offline": False,
            "ready_live": False,
            "next_gate": OPTION2_MANIFEST_REVIEW_NEXT_INTERNAL_MILESTONE,
        }

    @staticmethod
    def _option2_identity_candidate_fixture_inputs() -> tuple[
        dict[str, object], dict[str, dict[str, object]]
    ]:
        inventory: dict[str, object] = {
            "version": 1,
            "classification": OPTION2_SYNTHETIC_INVENTORY_CLASSIFICATION,
            "synthetic_only": True,
            "owner_pause_latched": True,
            "users": [
                {
                    "name": "fixture:unrelated-alice",
                    "uid": 101,
                    "synthetic": True,
                },
                {
                    "name": "fixture:unrelated-bob",
                    "uid": 102,
                    "synthetic": True,
                },
            ],
            "groups": [
                {
                    "name": "fixture:unrelated-team",
                    "gid": 201,
                    "synthetic": True,
                },
                {
                    "name": "fixture:unrelated-staff",
                    "gid": 202,
                    "synthetic": True,
                },
            ],
            "production_configuration": {
                field: None for field in PRODUCTION_CONFIGURATION_FIELDS
            },
        }
        assignments = {
            name: {
                "uid": 5_000 + index,
                "gid": 6_000 + index,
                "password_state": "locked",
                "hidden_account": True,
                "login_shell": "/usr/bin/false",
                "home_directory": "/var/empty",
                "supplementary_groups": [],
            }
            for index, name in enumerate(OPTION2_SERVICE_IDENTITIES)
        }
        return inventory, assignments

    def _option2_identity_candidate_qualification_content(
        self,
        original: Mapping[str, object],
        recovery: Mapping[str, object],
    ) -> dict[str, object]:
        manifest_review = self._option2_provisioner_manifest_review_content(
            original, recovery
        )
        manifest_review_sha256 = _sha256_bytes(
            canonical_json(manifest_review).encode("utf-8")
        )
        inventory, assignments = self._option2_identity_candidate_fixture_inputs()
        report = qualify_option2_identity_candidate_resolver(
            synthetic_inventory=inventory,
            proposed_assignments=assignments,
            manifest_review_content=manifest_review,
            service_verified_manifest_review_content_sha256=(
                manifest_review_sha256
            ),
            issued_at="2026-08-30T14:00:00Z",
            expires_at="2026-08-30T14:10:00Z",
            observed_at="2026-08-30T14:01:00Z",
        )
        expected_keys = {
            "authority",
            "candidate_sha256",
            "classification",
            "effects",
            "host_apply_present",
            "host_preflight_performed",
            "manifest_review_content_sha256",
            "next_gate",
            "owner_pause_latched",
            "partial_failure_case_sha256",
            "partial_stage_count",
            "partial_stages_all_covered",
            "preexisting_entity_preservation_verified",
            "production_configuration",
            "production_manifest_complete",
            "qualification_sha256",
            "ready",
            "ready_live",
            "ready_offline",
            "resolver_state",
            "reverse_rollback_verified",
            "reviewed_manifest_sha256",
            "rollback_only_transaction_created_entities_verified",
            "rollback_uncertainty_case_sha256",
            "rollback_uncertainty_quarantine_verified",
            "success_case_sha256",
            "synthetic_inventory_sha256",
            "synthetic_only",
            "version",
        }
        digest_fields = {
            "candidate_sha256",
            "manifest_review_content_sha256",
            "qualification_sha256",
            "reviewed_manifest_sha256",
            "success_case_sha256",
            "synthetic_inventory_sha256",
        }
        partial_failures = report.get("partial_failure_case_sha256")
        rollback_uncertainty = report.get(
            "rollback_uncertainty_case_sha256"
        )
        authority = report.get("authority")
        effects = report.get("effects")
        production = report.get("production_configuration")
        report_body = {
            key: value
            for key, value in report.items()
            if key != "qualification_sha256"
        }
        if (
            set(report) != expected_keys
            or report.get("version") != OPTION2_IDENTITY_CANDIDATE_VERSION
            or report.get("classification")
            != "option2_identity_candidate_resolver_fixture_qualification"
            or report.get("resolver_state")
            != OPTION2_IDENTITY_CANDIDATE_RESOLVER_STATE
            or report.get("synthetic_only") is not True
            or report.get("manifest_review_content_sha256")
            != manifest_review_sha256
            or report.get("reviewed_manifest_sha256")
            != manifest_review["manifest_sha256"]
            or report.get("next_gate") != OPTION2_IDENTITY_CANDIDATE_NEXT_GATE
            or report.get("owner_pause_latched") is not True
            or report.get("partial_stage_count")
            != len(OPTION2_IDENTITY_CANDIDATE_TRANSACTION_STAGE_IDS)
            or report.get("partial_stages_all_covered") is not True
            or report.get("reverse_rollback_verified") is not True
            or report.get(
                "rollback_only_transaction_created_entities_verified"
            )
            is not True
            or report.get("preexisting_entity_preservation_verified") is not True
            or report.get("rollback_uncertainty_quarantine_verified") is not True
            or report.get("production_manifest_complete") is not False
            or report.get("host_preflight_performed") is not False
            or report.get("host_apply_present") is not False
            or report.get("ready") is not False
            or report.get("ready_offline") is not False
            or report.get("ready_live") is not False
            or not isinstance(production, Mapping)
            or set(production) != set(PRODUCTION_CONFIGURATION_FIELDS)
            or any(
                production[field] is not None
                for field in PRODUCTION_CONFIGURATION_FIELDS
            )
            or not isinstance(authority, Mapping)
            or set(authority) != set(
                OPTION2_IDENTITY_CANDIDATE_AUTHORITY_FIELDS
            )
            or any(value is not False for value in authority.values())
            or not isinstance(effects, Mapping)
            or set(effects) != set(OPTION2_IDENTITY_CANDIDATE_EFFECT_FIELDS)
            or any(value is not False for value in effects.values())
            or any(
                not isinstance(report.get(field), str)
                or re.fullmatch(r"[0-9a-f]{64}", str(report.get(field))) is None
                or report.get(field) == "0" * 64
                for field in digest_fields
            )
            or report.get("qualification_sha256")
            != _sha256_bytes(canonical_json(report_body).encode("utf-8"))
            or not isinstance(partial_failures, Mapping)
            or set(partial_failures)
            != set(OPTION2_IDENTITY_CANDIDATE_TRANSACTION_STAGE_IDS)
            or any(
                not isinstance(value, str)
                or re.fullmatch(r"[0-9a-f]{64}", value) is None
                or value == "0" * 64
                for value in partial_failures.values()
            )
            or not isinstance(rollback_uncertainty, Mapping)
            or set(rollback_uncertainty)
            != set(OPTION2_IDENTITY_CANDIDATE_CREATION_STAGE_IDS)
            or any(
                not isinstance(value, str)
                or re.fullmatch(r"[0-9a-f]{64}", value) is None
                or value == "0" * 64
                for value in rollback_uncertainty.values()
            )
        ):
            raise SupervisorError(
                "Option 2 identity candidate fixture qualification was not exact"
            )
        return {
            "version": 1,
            "classification": (
                "option2_identity_candidate_resolver_fixture_qualification"
            ),
            "status": OPTION2_IDENTITY_CANDIDATE_RESOLVER_STATE,
            "predecessor_manifest_review_sha256": manifest_review_sha256,
            "reviewed_manifest_sha256": report["reviewed_manifest_sha256"],
            "candidate_sha256": report["candidate_sha256"],
            "synthetic_inventory_sha256": report[
                "synthetic_inventory_sha256"
            ],
            "fixture_qualification_sha256": report["qualification_sha256"],
            "partial_stage_count": report["partial_stage_count"],
            "partial_stages_all_covered": True,
            "reverse_rollback_verified": True,
            "rollback_only_transaction_created_entities_verified": True,
            "preexisting_entity_preservation_verified": True,
            "rollback_uncertainty_quarantine_verified": True,
            "synthetic_only": True,
            "production_manifest_complete": False,
            "host_preflight_performed": False,
            "host_apply_present": False,
            "authority_granted": False,
            "provisioning_authorized": False,
            "service_identity_creation_authorized": False,
            "service_identity_provisioning_authorized": False,
            "vault_provisioning_authorized": False,
            "credential_use_authorized": False,
            "private_data_transmission_authorized": False,
            "model_contact_authorized": False,
            "network_access_authorized": False,
            "access_change_authorized": False,
            "background_execution_authorized": False,
            "deployment_authorized": False,
            "live_execution_authorized": False,
            "ready": False,
            "ready_offline": False,
            "ready_live": False,
            "next_gate": OPTION2_IDENTITY_CANDIDATE_NEXT_GATE,
        }

    def _option2_identity_candidate_qualification_state(
        self,
        original: Mapping[str, object],
        recovery: Mapping[str, object],
    ) -> tuple[str, bool, str | None]:
        manifest_state, manifest_reviewed, _manifest_blocker = (
            self._option2_provisioner_manifest_review_state(original, recovery)
        )
        if (
            manifest_state != OPTION2_MANIFEST_REVIEW_STATE
            or manifest_reviewed is not True
        ):
            return "not_applicable", False, None
        if not self._option2_production_paths_are_null():
            return (
                "qualification_invalid",
                False,
                "option2_identity_candidate_production_configuration_present",
            )
        if self.database is None or not hasattr(
            self.database, "list_supervisor_v4_qualifications"
        ):
            return (
                "qualification_storage_unavailable",
                False,
                "option2_identity_candidate_qualification_storage_unavailable",
            )
        try:
            expected = self._option2_identity_candidate_qualification_content(
                original, recovery
            )
        except (
            Option2IdentityCandidateViolation,
            Option2ManifestReviewViolation,
            Option2PlanViolation,
            Option2ProvisionerViolation,
            SupervisorError,
            KeyError,
            TypeError,
        ):
            return (
                "qualification_invalid",
                False,
                "option2_identity_candidate_contract_drift",
            )
        records = self.database.list_supervisor_v4_qualifications(
            subject=_OPTION2_IDENTITY_CANDIDATE_QUALIFICATION_SUBJECT,
            limit=3,
        )
        if not records:
            return (
                "qualification_required",
                False,
                "option2_identity_candidate_fixture_qualification_required",
            )
        if len(records) != 1:
            return (
                "qualification_invalid",
                False,
                "option2_identity_candidate_qualification_duplicate_evidence",
            )
        expected_json = canonical_json(expected)
        expected_sha256 = _sha256_bytes(expected_json.encode("utf-8"))
        record = records[0]
        if (
            record.get("status") != "inactive"
            or record.get("content") != expected
            or record.get("content_sha256") != expected_sha256
            or int(record.get("authority_granted", 1)) != 0
        ):
            return (
                "qualification_invalid",
                False,
                "option2_identity_candidate_qualification_evidence_mismatch",
            )
        return OPTION2_IDENTITY_CANDIDATE_RESOLVER_STATE, True, None

    def record_option2_identity_candidate_fixture_qualification(
        self,
    ) -> dict[str, object]:
        """Persist only the pure synthetic identity-candidate qualification."""

        if self.database is None or not hasattr(
            self.database, "record_supervisor_v4_qualification_once"
        ):
            raise SupervisorError("Supervisor v4 review ledger is unavailable")
        original = self._option1_canary_accounting()
        recovery = self._option1_recovery_canary_accounting()
        manifest_state, manifest_reviewed, manifest_blocker = (
            self._option2_provisioner_manifest_review_state(original, recovery)
        )
        if (
            manifest_state != OPTION2_MANIFEST_REVIEW_STATE
            or manifest_reviewed is not True
            or manifest_blocker is not None
        ):
            raise SupervisorError(
                "Option 2 manifest review must verify before identity fixture qualification"
            )
        content = self._option2_identity_candidate_qualification_content(
            original, recovery
        )
        record = self.database.record_supervisor_v4_qualification_once(
            subject=_OPTION2_IDENTITY_CANDIDATE_QUALIFICATION_SUBJECT,
            status="inactive",
            content=content,
        )
        state, qualified, blocker = (
            self._option2_identity_candidate_qualification_state(
                original, recovery
            )
        )
        if (
            state != OPTION2_IDENTITY_CANDIDATE_RESOLVER_STATE
            or qualified is not True
            or blocker is not None
        ):
            raise SupervisorError(
                "Option 2 identity candidate qualification evidence did not verify"
            )
        return {
            "classification": content["classification"],
            "qualification_state": state,
            "qualification_id": record["id"],
            "qualification_sha256": record["content_sha256"],
            "candidate_sha256": content["candidate_sha256"],
            "synthetic_inventory_sha256": content[
                "synthetic_inventory_sha256"
            ],
            "synthetic_only": True,
            "production_manifest_complete": False,
            "host_preflight_performed": False,
            "host_apply_present": False,
            "authority_granted": False,
            "provisioning_authorized": False,
            "service_identity_creation_authorized": False,
            "service_identity_provisioning_authorized": False,
            "vault_provisioning_authorized": False,
            "credential_use_authorized": False,
            "private_data_transmission_authorized": False,
            "model_contact_authorized": False,
            "network_access_authorized": False,
            "access_change_authorized": False,
            "background_execution_authorized": False,
            "deployment_authorized": False,
            "live_execution_authorized": False,
            "ready": False,
            "ready_offline": False,
            "ready_live": False,
            "next_gate": OPTION2_IDENTITY_CANDIDATE_NEXT_GATE,
        }

    def _option2_host_preflight_current_bindings(
        self,
        original: Mapping[str, object],
        recovery: Mapping[str, object],
    ) -> dict[str, str]:
        """Resolve current source, ledger, and fixed platform-tool bindings."""

        mismatches: list[str] = []
        bundle = self._seal_runtime_bundle()
        policy = self._sealed_policy(bundle, mismatches)
        if policy is None:
            raise SupervisorError(
                "Option 2 host preflight policy binding is unavailable"
            )
        if bundle.member("protocol").sha256 != policy.protocol_inventory_sha256:
            mismatches.append("Option 2 host preflight protocol binding drifted")
        if bundle.member("sdk_lock").sha256 != policy.sdk_lock_sha256:
            mismatches.append("Option 2 host preflight SDK lock binding drifted")
        lock = self._load_lock(bundle.member("sdk_lock"), mismatches)
        self._inspect_source_pins(lock, mismatches)
        self._inspect_loaded_source_bindings(bundle, lock, mismatches)
        host_contract = lock.get("option2_host_preflight")
        expected_host_contract_keys = {
            "directory_node",
            "numeric_identity_range",
            "allocation_order",
            "matching_uid_gid",
            "sandbox_profile_sha256",
            "dscl",
        }
        if (
            not isinstance(host_contract, Mapping)
            or set(host_contract) != expected_host_contract_keys
            or host_contract.get("directory_node") != "/Local/Default"
            or host_contract.get("numeric_identity_range") != [400, 499]
            or host_contract.get("allocation_order") != "descending"
            or host_contract.get("matching_uid_gid") is not True
            or host_contract.get("sandbox_profile_sha256")
            != OPTION2_HOST_SANDBOX_PROFILE_SHA256
        ):
            mismatches.append("Option 2 host preflight lock contract is invalid")
            host_contract = {}
        dscl = host_contract.get("dscl") if isinstance(host_contract, Mapping) else None
        if (
            not isinstance(dscl, Mapping)
            or set(dscl) != {"path", "sha256", "owner_uid"}
            or dscl.get("path") != str(_OPTION2_HOST_DSCL_PATH)
            or dscl.get("owner_uid") != 0
            or not isinstance(dscl.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", str(dscl.get("sha256"))) is None
            or dscl.get("sha256") == "0" * 64
        ):
            mismatches.append("Option 2 dscl lock binding is invalid")
        local_tools = lock.get("local_tools")
        sandbox = (
            local_tools.get("sandbox_exec")
            if isinstance(local_tools, Mapping)
            else None
        )
        if (
            not isinstance(sandbox, Mapping)
            or sandbox.get("path")
            != str(_TRUSTED_PLATFORM_TOOL_PATHS["sandbox_exec"])
            or sandbox.get("owner_uid") != 0
            or not isinstance(sandbox.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", str(sandbox.get("sha256"))) is None
            or sandbox.get("sha256") == "0" * 64
        ):
            mismatches.append("Option 2 sandbox-exec lock binding is invalid")
        try:
            observed_dscl_sha256 = _sha256_root_owned_platform_tool(
                _OPTION2_HOST_DSCL_PATH
            )
            observed_sandbox_sha256 = _sha256_root_owned_platform_tool(
                _TRUSTED_PLATFORM_TOOL_PATHS["sandbox_exec"]
            )
            if self.database is None:
                raise SupervisorError(
                    "Option 2 host preflight ledger is unavailable"
                )
            host_instance_sha256 = _option2_host_instance_sha256(
                database_path=self.database.path,
                project_root=self.config.project_root,
            )
        except SupervisorError:
            mismatches.append("Option 2 host preflight tool attestation failed")
            observed_dscl_sha256 = None
            observed_sandbox_sha256 = None
            host_instance_sha256 = None
        if isinstance(dscl, Mapping) and observed_dscl_sha256 != dscl.get("sha256"):
            mismatches.append("Option 2 dscl binary drifted")
        if (
            isinstance(sandbox, Mapping)
            and observed_sandbox_sha256 != sandbox.get("sha256")
        ):
            mismatches.append("Option 2 sandbox-exec binary drifted")

        manifest_review = self._option2_provisioner_manifest_review_content(
            original, recovery
        )
        manifest_review_sha256 = _sha256_bytes(
            canonical_json(manifest_review).encode("utf-8")
        )
        if self.database is None:
            raise SupervisorError("Option 2 host preflight ledger is unavailable")
        fixture_records = self.database.list_supervisor_v4_qualifications(
            subject=_OPTION2_IDENTITY_CANDIDATE_QUALIFICATION_SUBJECT,
            limit=3,
        )
        if len(fixture_records) != 1:
            mismatches.append(
                "Option 2 identity fixture qualification binding is unavailable"
            )
            fixture_content_sha256 = None
        else:
            fixture_content_sha256 = fixture_records[0].get("content_sha256")
        if (
            not isinstance(fixture_content_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", fixture_content_sha256) is None
            or fixture_content_sha256 == "0" * 64
        ):
            mismatches.append(
                "Option 2 identity fixture qualification digest is invalid"
            )
        if mismatches:
            raise SupervisorError(
                "Option 2 host preflight attestation failed: "
                + "; ".join(mismatches[:6])
            )
        return {
            "reviewed_manifest_sha256": str(manifest_review["manifest_sha256"]),
            "manifest_review_content_sha256": manifest_review_sha256,
            "fixture_qualification_content_sha256": str(
                fixture_content_sha256
            ),
            "sdk_lock_sha256": bundle.member("sdk_lock").sha256,
            "policy_sha256": bundle.member("contract").sha256,
            "host_preflight_source_sha256": bundle.member(
                "option2_host_preflight_source"
            ).sha256,
            "host_instance_sha256": str(host_instance_sha256),
            "dscl_sha256": str(observed_dscl_sha256),
            "sandbox_exec_sha256": str(observed_sandbox_sha256),
            "sandbox_profile_sha256": OPTION2_HOST_SANDBOX_PROFILE_SHA256,
        }

    def _option2_host_preflight_candidate_state(
        self,
        original: Mapping[str, object],
        recovery: Mapping[str, object],
        *,
        observed_at: datetime | None = None,
    ) -> tuple[str, bool, str | None, dict[str, Any] | None]:
        """Validate the complete claim/candidate lineage without a host query."""

        identity_state, identity_qualified, _identity_blocker = (
            self._option2_identity_candidate_qualification_state(
                original, recovery
            )
        )
        if (
            identity_state != OPTION2_IDENTITY_CANDIDATE_RESOLVER_STATE
            or identity_qualified is not True
        ):
            return "not_performed", False, None, None
        if self.database is None:
            return (
                "candidate_storage_unavailable",
                False,
                "option2_host_candidate_storage_unavailable",
                None,
            )
        candidate_records = self.database.list_supervisor_v4_qualifications(
            subject=OPTION2_HOST_PREFLIGHT_SUBJECT,
            limit=10_000,
        )
        claim_records = self.database.list_supervisor_v4_qualifications(
            subject=OPTION2_HOST_PREFLIGHT_CLAIM_SUBJECT,
            limit=10_000,
        )
        if not candidate_records and not claim_records:
            return "not_performed", False, None, None
        if (
            len(candidate_records) >= 10_000
            or len(claim_records) >= 10_000
            or len(claim_records)
            not in {len(candidate_records), len(candidate_records) + 1}
        ):
            return (
                "candidate_invalid_quarantined",
                False,
                "option2_host_candidate_lineage_cardinality_invalid",
                None,
            )

        candidates = list(reversed(candidate_records))
        claims = list(reversed(claim_records))
        previous_candidate: Mapping[str, object] | None = None
        latest_candidate_record: dict[str, Any] | None = None
        for index, claim_record in enumerate(claims, start=1):
            claim = claim_record.get("content")
            if (
                claim_record.get("status") != "inactive"
                or claim_record.get("authority_granted") != 0
                or not isinstance(claim, Mapping)
                or claim_record.get("content_sha256")
                != _sha256_bytes(canonical_json(claim).encode("utf-8"))
            ):
                return (
                    "candidate_invalid_quarantined",
                    False,
                    "option2_host_claim_ledger_invalid",
                    None,
                )
            try:
                validate_option2_host_preflight_claim(claim)
            except Option2HostPreflightViolation:
                return (
                    "candidate_invalid_quarantined",
                    False,
                    "option2_host_claim_contract_invalid",
                    None,
                )
            lineage = claim.get("lineage")
            previous_sha256 = (
                previous_candidate.get("candidate_sha256")
                if isinstance(previous_candidate, Mapping)
                else None
            )
            if (
                not isinstance(lineage, Mapping)
                or lineage.get("generation") != index
                or lineage.get("previous_candidate_sha256")
                != previous_sha256
            ):
                return (
                    "candidate_invalid_quarantined",
                    False,
                    "option2_host_candidate_lineage_invalid",
                    None,
                )
            if index == 1 and lineage.get("supersession_reason") != "initial":
                return (
                    "candidate_invalid_quarantined",
                    False,
                    "option2_host_candidate_lineage_invalid",
                    None,
                )
            if index > 1:
                reason = lineage.get("supersession_reason")
                try:
                    previous_issue = datetime.fromisoformat(
                        str(previous_candidate.get("issued_at")).replace(
                            "Z", "+00:00"
                        )
                    )
                    previous_expiry = datetime.fromisoformat(
                        str(previous_candidate.get("expires_at")).replace(
                            "Z", "+00:00"
                        )
                    )
                    claim_issue = datetime.fromisoformat(
                        str(claim.get("issued_at")).replace("Z", "+00:00")
                    )
                except (ValueError, AttributeError):
                    return (
                        "candidate_invalid_quarantined",
                        False,
                        "option2_host_candidate_lineage_invalid",
                        None,
                    )
                if claim_issue < previous_issue:
                    return (
                        "candidate_invalid_quarantined",
                        False,
                        "option2_host_candidate_lineage_invalid",
                        None,
                    )
                if reason == "expired":
                    if claim_issue < previous_expiry:
                        return (
                            "candidate_invalid_quarantined",
                            False,
                            "option2_host_candidate_lineage_invalid",
                            None,
                        )
                elif (
                    reason != "stale"
                    or claim.get("bindings") == previous_candidate.get("bindings")
                ):
                    return (
                        "candidate_invalid_quarantined",
                        False,
                        "option2_host_candidate_lineage_invalid",
                        None,
                    )
            if index > len(candidates):
                return (
                    "preflight_consumed_incomplete",
                    False,
                    "option2_host_preflight_claim_consumed_incomplete",
                    None,
                )
            candidate_record = candidates[index - 1]
            candidate = candidate_record.get("content")
            if (
                candidate_record.get("status") != "inactive"
                or candidate_record.get("authority_granted") != 0
                or not isinstance(candidate, Mapping)
                or candidate_record.get("content_sha256")
                != _sha256_bytes(canonical_json(candidate).encode("utf-8"))
            ):
                return (
                    "candidate_invalid_quarantined",
                    False,
                    "option2_host_candidate_ledger_invalid",
                    None,
                )
            try:
                validate_option2_host_candidate(candidate)
            except Option2HostPreflightViolation:
                return (
                    "candidate_invalid_quarantined",
                    False,
                    "option2_host_candidate_contract_invalid",
                    None,
                )
            if (
                candidate.get("lineage") != claim.get("lineage")
                or candidate.get("bindings") != claim.get("bindings")
                or candidate.get("issued_at") != claim.get("issued_at")
                or candidate.get("expires_at") != claim.get("expires_at")
                or candidate.get("authorization_challenge_sha256")
                != claim.get("authorization_challenge_sha256")
                or candidate.get("preflight_claim_id") != claim_record.get("id")
                or candidate.get("preflight_claim_sha256")
                != claim_record.get("content_sha256")
            ):
                return (
                    "candidate_invalid_quarantined",
                    False,
                    "option2_host_candidate_claim_binding_invalid",
                    None,
                )
            previous_candidate = candidate
            latest_candidate_record = candidate_record

        if latest_candidate_record is None or not isinstance(
            previous_candidate, Mapping
        ):
            return (
                "candidate_invalid_quarantined",
                False,
                "option2_host_candidate_lineage_invalid",
                None,
            )
        now = (observed_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
        now = now.replace(microsecond=0)
        try:
            issued = datetime.fromisoformat(
                str(previous_candidate.get("issued_at")).replace("Z", "+00:00")
            ).astimezone(timezone.utc)
            expires = datetime.fromisoformat(
                str(previous_candidate.get("expires_at")).replace("Z", "+00:00")
            ).astimezone(timezone.utc)
        except ValueError:
            return (
                "candidate_invalid_quarantined",
                False,
                "option2_host_candidate_timestamp_invalid",
                None,
            )
        if now < issued:
            return (
                "candidate_invalid_quarantined",
                False,
                "option2_host_candidate_clock_anomaly",
                latest_candidate_record,
            )
        try:
            current_bindings = self._option2_host_preflight_current_bindings(
                original, recovery
            )
        except SupervisorError:
            return (
                "candidate_stale_inactive",
                False,
                "option2_host_candidate_current_binding_unavailable",
                latest_candidate_record,
            )
        if previous_candidate.get("bindings") != current_bindings:
            return (
                "candidate_stale_inactive",
                False,
                "option2_host_candidate_binding_drift",
                latest_candidate_record,
            )
        if now >= expires:
            return (
                "candidate_expired_inactive",
                False,
                "option2_host_candidate_expired",
                latest_candidate_record,
            )
        return OPTION2_HOST_PREFLIGHT_STATE, True, None, latest_candidate_record

    def _option2_host_preflight_recovery_current_bindings(
        self,
        original: Mapping[str, object],
        recovery: Mapping[str, object],
    ) -> dict[str, str]:
        """Bind a recovery candidate to its separate attested implementation."""

        bindings = self._option2_host_preflight_current_bindings(
            original, recovery
        )
        bundle = self._seal_runtime_bundle()
        return {
            **bindings,
            "host_preflight_source_sha256": bundle.member(
                "option2_host_preflight_recovery_source"
            ).sha256,
        }

    def _option2_host_preflight_recovery_state(
        self,
        original: Mapping[str, object],
        recovery: Mapping[str, object],
        *,
        observed_at: datetime | None = None,
    ) -> tuple[
        str,
        bool,
        str | None,
        dict[str, Any] | None,
        dict[str, Any] | None,
    ]:
        """Validate the distinct, at-most-once recovery lineage without a query."""

        (
            original_state,
            _original_active,
            original_blocker,
            _original_candidate,
        ) = self._option2_host_preflight_candidate_state(original, recovery)
        if original_state != "preflight_consumed_incomplete":
            return "not_applicable", False, original_blocker, None, None
        if self.database is None:
            return (
                "recovery_storage_unavailable",
                False,
                "option2_host_recovery_storage_unavailable",
                None,
                None,
            )
        predecessor_records = self.database.list_supervisor_v4_qualifications(
            subject=OPTION2_HOST_PREFLIGHT_CLAIM_SUBJECT,
            limit=2,
        )
        original_candidates = self.database.list_supervisor_v4_qualifications(
            subject=OPTION2_HOST_PREFLIGHT_SUBJECT,
            limit=1,
        )
        if len(predecessor_records) != 1 or original_candidates:
            return (
                "recovery_invalid_quarantined",
                False,
                "option2_host_recovery_predecessor_cardinality_invalid",
                None,
                None,
            )
        predecessor_record = predecessor_records[0]
        predecessor = predecessor_record.get("content")
        if not isinstance(predecessor, Mapping):
            return (
                "recovery_invalid_quarantined",
                False,
                "option2_host_recovery_predecessor_invalid",
                None,
                predecessor_record,
            )

        claim_records = self.database.list_supervisor_v4_qualifications(
            subject=OPTION2_HOST_PREFLIGHT_RECOVERY_CLAIM_SUBJECT,
            limit=3,
        )
        candidate_records = self.database.list_supervisor_v4_qualifications(
            subject=OPTION2_HOST_PREFLIGHT_RECOVERY_CANDIDATE_SUBJECT,
            limit=3,
        )
        if not claim_records and not candidate_records:
            return (
                OPTION2_HOST_PREFLIGHT_RECOVERY_STATE,
                False,
                None,
                None,
                predecessor_record,
            )
        if (
            len(claim_records) != 1
            or len(candidate_records) not in {0, 1}
            or len(claim_records) >= 3
            or len(candidate_records) >= 3
        ):
            return (
                "recovery_invalid_quarantined",
                False,
                "option2_host_recovery_lineage_cardinality_invalid",
                None,
                predecessor_record,
            )
        claim_record = claim_records[0]
        claim = claim_record.get("content")
        if (
            claim_record.get("status") != "inactive"
            or claim_record.get("authority_granted") != 0
            or not isinstance(claim, Mapping)
            or claim_record.get("content_sha256")
            != _sha256_bytes(canonical_json(claim).encode("utf-8"))
        ):
            return (
                "recovery_invalid_quarantined",
                False,
                "option2_host_recovery_claim_ledger_invalid",
                None,
                predecessor_record,
            )
        try:
            validate_option2_host_preflight_recovery_claim(claim)
        except Option2HostPreflightViolation:
            return (
                "recovery_invalid_quarantined",
                False,
                "option2_host_recovery_claim_contract_invalid",
                None,
                predecessor_record,
            )
        predecessor_binding = claim.get("predecessor")
        expected_phrase = build_option2_host_preflight_recovery_authorization_phrase(
            predecessor_claim_id=str(predecessor_record.get("id")),
            predecessor_claim_content_sha256=str(
                predecessor_record.get("content_sha256")
            ),
        )
        if (
            not isinstance(predecessor_binding, Mapping)
            or predecessor_binding.get("claim_id") != predecessor_record.get("id")
            or predecessor_binding.get("content_sha256")
            != predecessor_record.get("content_sha256")
            or predecessor_binding.get("claim_sha256")
            != predecessor.get("claim_sha256")
            or claim.get("authorization_confirmation_sha256")
            != _sha256_bytes(expected_phrase.encode("utf-8"))
        ):
            return (
                "recovery_invalid_quarantined",
                False,
                "option2_host_recovery_predecessor_binding_invalid",
                None,
                predecessor_record,
            )
        if not candidate_records:
            return (
                "recovery_preflight_consumed_incomplete",
                False,
                "option2_host_recovery_claim_consumed_incomplete",
                None,
                predecessor_record,
            )

        candidate_record = candidate_records[0]
        candidate = candidate_record.get("content")
        if (
            candidate_record.get("status") != "inactive"
            or candidate_record.get("authority_granted") != 0
            or not isinstance(candidate, Mapping)
            or candidate_record.get("content_sha256")
            != _sha256_bytes(canonical_json(candidate).encode("utf-8"))
        ):
            return (
                "recovery_invalid_quarantined",
                False,
                "option2_host_recovery_candidate_ledger_invalid",
                candidate_record,
                predecessor_record,
            )
        try:
            validate_option2_host_candidate(candidate)
        except Option2HostPreflightViolation:
            return (
                "recovery_invalid_quarantined",
                False,
                "option2_host_recovery_candidate_contract_invalid",
                candidate_record,
                predecessor_record,
            )
        if (
            candidate.get("preflight_claim_id") != claim_record.get("id")
            or candidate.get("preflight_claim_sha256")
            != claim_record.get("content_sha256")
            or candidate.get("bindings") != claim.get("bindings")
            or candidate.get("issued_at") != claim.get("issued_at")
            or candidate.get("expires_at") != claim.get("expires_at")
            or candidate.get("authorization_challenge_sha256")
            != claim.get("authorization_challenge_sha256")
            or candidate.get("lineage")
            != {
                "generation": 1,
                "previous_candidate_sha256": None,
                "supersession_reason": "initial",
            }
        ):
            return (
                "recovery_invalid_quarantined",
                False,
                "option2_host_recovery_candidate_claim_binding_invalid",
                candidate_record,
                predecessor_record,
            )

        now = (observed_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
        now = now.replace(microsecond=0)
        try:
            issued = datetime.fromisoformat(
                str(candidate.get("issued_at")).replace("Z", "+00:00")
            ).astimezone(timezone.utc)
            expires = datetime.fromisoformat(
                str(candidate.get("expires_at")).replace("Z", "+00:00")
            ).astimezone(timezone.utc)
        except (ValueError, AttributeError):
            return (
                "recovery_invalid_quarantined",
                False,
                "option2_host_recovery_candidate_timestamp_invalid",
                candidate_record,
                predecessor_record,
            )
        if now < issued:
            return (
                "recovery_invalid_quarantined",
                False,
                "option2_host_recovery_candidate_clock_anomaly",
                candidate_record,
                predecessor_record,
            )
        try:
            current_bindings = self._option2_host_preflight_recovery_current_bindings(
                original, recovery
            )
        except SupervisorError:
            return (
                "recovery_candidate_stale_inactive",
                False,
                "option2_host_recovery_current_binding_unavailable",
                candidate_record,
                predecessor_record,
            )
        if candidate.get("bindings") != current_bindings:
            return (
                "recovery_candidate_stale_inactive",
                False,
                "option2_host_recovery_candidate_binding_drift",
                candidate_record,
                predecessor_record,
            )
        if now >= expires:
            return (
                "recovery_candidate_expired_inactive",
                False,
                "option2_host_recovery_candidate_expired",
                candidate_record,
                predecessor_record,
            )
        return (
            OPTION2_HOST_PREFLIGHT_RECOVERY_CANDIDATE_STATE,
            True,
            None,
            candidate_record,
            predecessor_record,
        )

    @staticmethod
    def _option2_inactive_ledger_record_content(
        record: Mapping[str, object], *, code: str
    ) -> Mapping[str, object]:
        content = record.get("content")
        if (
            record.get("status") != "inactive"
            or record.get("authority_granted") != 0
            or not isinstance(content, Mapping)
            or record.get("content_sha256")
            != _sha256_bytes(canonical_json(content).encode("utf-8"))
        ):
            raise SupervisorError(code)
        return content

    def _option2_host_preflight_recovery_result_review_content(
        self,
        *,
        observed_at: datetime | None = None,
    ) -> dict[str, object]:
        """Bind the exact expired lineage without refreshing its host bindings.

        Resealing this source intentionally makes the historical candidate
        stale against the current source bundle.  Result review therefore
        validates the immutable record lineage, internal digests, expiry, and
        zero-authority envelope directly.  It never asks whether the candidate
        is current and can never revive it.
        """

        if self.database is None or not hasattr(
            self.database, "list_supervisor_v4_qualifications"
        ):
            raise SupervisorError(
                "option2_host_recovery_result_review_storage_unavailable"
            )
        original_claims = self.database.list_supervisor_v4_qualifications(
            subject=OPTION2_HOST_PREFLIGHT_CLAIM_SUBJECT,
            limit=3,
        )
        original_candidates = self.database.list_supervisor_v4_qualifications(
            subject=OPTION2_HOST_PREFLIGHT_SUBJECT,
            limit=3,
        )
        recovery_claims = self.database.list_supervisor_v4_qualifications(
            subject=OPTION2_HOST_PREFLIGHT_RECOVERY_CLAIM_SUBJECT,
            limit=3,
        )
        recovery_candidates = self.database.list_supervisor_v4_qualifications(
            subject=OPTION2_HOST_PREFLIGHT_RECOVERY_CANDIDATE_SUBJECT,
            limit=3,
        )
        if (
            len(original_claims) != 1
            or original_candidates
            or len(recovery_claims) != 1
            or len(recovery_candidates) != 1
        ):
            raise SupervisorError(
                "option2_host_recovery_result_review_lineage_cardinality_invalid"
            )
        original_record = original_claims[0]
        recovery_claim_record = recovery_claims[0]
        recovery_candidate_record = recovery_candidates[0]
        original_claim = self._option2_inactive_ledger_record_content(
            original_record,
            code="option2_host_recovery_result_review_original_claim_invalid",
        )
        recovery_claim = self._option2_inactive_ledger_record_content(
            recovery_claim_record,
            code="option2_host_recovery_result_review_recovery_claim_invalid",
        )
        recovery_candidate = self._option2_inactive_ledger_record_content(
            recovery_candidate_record,
            code="option2_host_recovery_result_review_candidate_invalid",
        )
        try:
            validate_option2_host_preflight_claim(original_claim)
            validate_option2_host_preflight_recovery_claim(recovery_claim)
            validate_option2_host_candidate(recovery_candidate)
        except Option2HostPreflightViolation as error:
            raise SupervisorError(
                "option2_host_recovery_result_review_contract_invalid"
            ) from error

        predecessor = recovery_claim.get("predecessor")
        expected_confirmation = (
            build_option2_host_preflight_recovery_authorization_phrase(
                predecessor_claim_id=str(original_record.get("id")),
                predecessor_claim_content_sha256=str(
                    original_record.get("content_sha256")
                ),
            )
        )
        if (
            not isinstance(predecessor, Mapping)
            or predecessor.get("claim_id") != original_record.get("id")
            or predecessor.get("content_sha256")
            != original_record.get("content_sha256")
            or predecessor.get("claim_sha256")
            != original_claim.get("claim_sha256")
            or predecessor.get("observed_state")
            != "preflight_consumed_incomplete"
            or recovery_claim.get("authorization_confirmation_sha256")
            != _sha256_bytes(expected_confirmation.encode("utf-8"))
            or recovery_claim.get("original_claim_reopened") is not False
            or recovery_claim.get("original_command_reusable") is not False
            or recovery_claim.get("authorization_challenge_persisted") is not False
        ):
            raise SupervisorError(
                "option2_host_recovery_result_review_predecessor_binding_invalid"
            )
        if (
            recovery_candidate.get("preflight_claim_id")
            != recovery_claim_record.get("id")
            or recovery_candidate.get("preflight_claim_sha256")
            != recovery_claim_record.get("content_sha256")
            or recovery_candidate.get("bindings") != recovery_claim.get("bindings")
            or recovery_candidate.get("issued_at") != recovery_claim.get("issued_at")
            or recovery_candidate.get("expires_at") != recovery_claim.get("expires_at")
            or recovery_candidate.get("authorization_challenge_sha256")
            != recovery_claim.get("authorization_challenge_sha256")
            or recovery_candidate.get("authorization_challenge_persisted") is not False
            or recovery_candidate.get("candidate_complete_for_host_mutation")
            is not False
            or recovery_candidate.get(
                "effective_search_path_collision_check_performed"
            )
            is not False
            or recovery_candidate.get("filesystem_ownership_reuse_check_performed")
            is not False
            or recovery_candidate.get("host_apply_present") is not False
            or recovery_candidate.get("ready") is not False
            or recovery_candidate.get("ready_offline") is not False
            or recovery_candidate.get("ready_live") is not False
        ):
            raise SupervisorError(
                "option2_host_recovery_result_review_candidate_binding_invalid"
            )
        authority = recovery_candidate.get("authority")
        if not isinstance(authority, Mapping) or any(
            value is not False for value in authority.values()
        ):
            raise SupervisorError(
                "option2_host_recovery_result_review_candidate_authority_invalid"
            )
        try:
            issued = datetime.fromisoformat(
                str(recovery_candidate.get("issued_at")).replace("Z", "+00:00")
            ).astimezone(timezone.utc)
            expires = datetime.fromisoformat(
                str(recovery_candidate.get("expires_at")).replace("Z", "+00:00")
            ).astimezone(timezone.utc)
        except (ValueError, AttributeError) as error:
            raise SupervisorError(
                "option2_host_recovery_result_review_timestamp_invalid"
            ) from error
        now = (observed_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
        now = now.replace(microsecond=0)
        if now < issued or now < expires:
            raise SupervisorError(
                "option2_host_recovery_result_review_candidate_not_expired"
            )

        bindings = recovery_candidate.get("bindings")
        if not isinstance(bindings, Mapping):
            raise SupervisorError(
                "option2_host_recovery_result_review_bindings_invalid"
            )
        return {
            "version": 1,
            "classification": (
                "option2_identity_only_host_preflight_recovery_result_review"
            ),
            "status": "recovery_result_reviewed_inactive",
            "original_claim": {
                "id": original_record["id"],
                "content_sha256": original_record["content_sha256"],
                "claim_sha256": original_claim["claim_sha256"],
                "terminal_state": "preflight_consumed_incomplete",
            },
            "recovery_claim": {
                "id": recovery_claim_record["id"],
                "content_sha256": recovery_claim_record["content_sha256"],
                "recovery_claim_sha256": recovery_claim[
                    "recovery_claim_sha256"
                ],
                "consumed": True,
            },
            "recovery_candidate": {
                "id": recovery_candidate_record["id"],
                "content_sha256": recovery_candidate_record["content_sha256"],
                "candidate_sha256": recovery_candidate["candidate_sha256"],
                "inventory_sha256": recovery_candidate["inventory_sha256"],
                "bindings_sha256": _sha256_bytes(
                    canonical_json(bindings).encode("utf-8")
                ),
                "issued_at": recovery_candidate["issued_at"],
                "expires_at": recovery_candidate["expires_at"],
                "terminal_state": "recovery_candidate_expired_inactive",
                "active": False,
                "complete_for_host_mutation": False,
            },
            "historical_host_inventory_read_performed": True,
            "historical_directory_query_count": recovery_candidate[
                "query_count"
            ],
            "raw_inventory_persisted": False,
            "raw_inventory_returned": False,
            "raw_authorization_challenge_persisted": False,
            "expired_candidate_reusable": False,
            "original_claim_reopened": False,
            "recovery_claim_reusable": False,
            "host_query_performed_by_review": False,
            "administrator_prompt_displayed_by_review": False,
            "host_apply_performed_by_review": False,
            "authority_granted": False,
            "provisioning_authorized": False,
            "service_identity_creation_authorized": False,
            "service_identity_provisioning_authorized": False,
            "vault_provisioning_authorized": False,
            "credential_use_authorized": False,
            "private_data_transmission_authorized": False,
            "model_contact_authorized": False,
            "network_access_authorized": False,
            "access_change_authorized": False,
            "background_execution_authorized": False,
            "deployment_authorized": False,
            "live_execution_authorized": False,
            "ready": False,
            "ready_offline": False,
            "ready_live": False,
        }

    def _option2_host_preflight_recovery_result_review_state(
        self,
    ) -> tuple[str, bool, str | None]:
        if self.database is None or not hasattr(
            self.database, "list_supervisor_v4_qualifications"
        ):
            return (
                "review_storage_unavailable",
                False,
                "option2_host_recovery_result_review_storage_unavailable",
            )
        records = self.database.list_supervisor_v4_qualifications(
            subject=_OPTION2_HOST_PREFLIGHT_RECOVERY_RESULT_REVIEW_SUBJECT,
            limit=3,
        )
        try:
            review_observed_at = None
            if records:
                review_observed_at = datetime.fromisoformat(
                    str(records[-1].get("created_at")).replace("Z", "+00:00")
                ).astimezone(timezone.utc)
            expected = self._option2_host_preflight_recovery_result_review_content(
                observed_at=review_observed_at
            )
        except (SupervisorError, ValueError, AttributeError):
            return (
                "review_invalid" if records else "review_required",
                False,
                "option2_host_recovery_result_review_lineage_invalid",
            )
        if not records:
            return (
                "review_required",
                False,
                "option2_identity_only_host_preflight_recovery_result_review_required",
            )
        if len(records) != 1:
            return (
                "review_invalid",
                False,
                "option2_host_recovery_result_review_duplicate_evidence",
            )
        record = records[0]
        expected_sha256 = _sha256_bytes(
            canonical_json(expected).encode("utf-8")
        )
        if (
            record.get("status") != "inactive"
            or record.get("authority_granted") != 0
            or record.get("content") != expected
            or record.get("content_sha256") != expected_sha256
        ):
            return (
                "review_invalid",
                False,
                "option2_host_recovery_result_review_evidence_mismatch",
            )
        return "recovery_result_reviewed_inactive", True, None

    def record_option2_host_preflight_recovery_result_review(
        self,
    ) -> dict[str, object]:
        """Record one exact historical review with no live authorization."""

        if self.database is None or not hasattr(
            self.database, "record_supervisor_v4_qualification_once_if_heads"
        ):
            raise SupervisorError(
                "Option 2 recovery result review ledger is unavailable"
            )
        content = self._option2_host_preflight_recovery_result_review_content()
        original_records = self.database.list_supervisor_v4_qualifications(
            subject=OPTION2_HOST_PREFLIGHT_CLAIM_SUBJECT,
            limit=1,
        )
        recovery_claim_records = self.database.list_supervisor_v4_qualifications(
            subject=OPTION2_HOST_PREFLIGHT_RECOVERY_CLAIM_SUBJECT,
            limit=1,
        )
        recovery_candidate_records = (
            self.database.list_supervisor_v4_qualifications(
                subject=OPTION2_HOST_PREFLIGHT_RECOVERY_CANDIDATE_SUBJECT,
                limit=1,
            )
        )
        record = self.database.record_supervisor_v4_qualification_once_if_heads(
            subject=_OPTION2_HOST_PREFLIGHT_RECOVERY_RESULT_REVIEW_SUBJECT,
            status="inactive",
            content=content,
            expected_heads={
                OPTION2_HOST_PREFLIGHT_CLAIM_SUBJECT: str(
                    original_records[0]["id"]
                ),
                OPTION2_HOST_PREFLIGHT_SUBJECT: None,
                OPTION2_HOST_PREFLIGHT_RECOVERY_CLAIM_SUBJECT: str(
                    recovery_claim_records[0]["id"]
                ),
                OPTION2_HOST_PREFLIGHT_RECOVERY_CANDIDATE_SUBJECT: str(
                    recovery_candidate_records[0]["id"]
                ),
            },
        )
        state, reviewed, blocker = (
            self._option2_host_preflight_recovery_result_review_state()
        )
        if state != "recovery_result_reviewed_inactive" or not reviewed or blocker:
            raise SupervisorError(
                "Option 2 recovery result review evidence did not verify"
            )
        return {
            "classification": content["classification"],
            "result_review_state": state,
            "qualification_id": record["id"],
            "qualification_sha256": record["content_sha256"],
            "expired_candidate_reused": False,
            "host_query_performed": False,
            "administrator_prompt_displayed": False,
            "host_apply_performed": False,
            "authority_granted": False,
            "provisioning_authorized": False,
            "service_identity_creation_authorized": False,
            "service_identity_provisioning_authorized": False,
            "vault_provisioning_authorized": False,
            "credential_use_authorized": False,
            "private_data_transmission_authorized": False,
            "model_contact_authorized": False,
            "network_access_authorized": False,
            "access_change_authorized": False,
            "background_execution_authorized": False,
            "deployment_authorized": False,
            "live_execution_authorized": False,
            "ready": False,
            "ready_offline": False,
            "ready_live": False,
            "next_gate": "option2_point_action_fixture_qualification",
        }

    def _option2_point_action_current_bindings(self) -> dict[str, str]:
        """Bind the offline design receipt to the sealed implementation."""

        mismatches: list[str] = []
        bundle = self._seal_runtime_bundle()
        policy = self._sealed_policy(bundle, mismatches)
        if policy is None:
            raise SupervisorError(
                "Option 2 point-action policy binding is unavailable"
            )
        if bundle.member("protocol").sha256 != policy.protocol_inventory_sha256:
            mismatches.append("Option 2 point-action protocol binding drifted")
        if bundle.member("sdk_lock").sha256 != policy.sdk_lock_sha256:
            mismatches.append("Option 2 point-action SDK lock binding drifted")
        lock = self._load_lock(bundle.member("sdk_lock"), mismatches)
        self._inspect_source_pins(lock, mismatches)
        self._inspect_loaded_source_bindings(bundle, lock, mismatches)
        if mismatches:
            raise SupervisorError(
                "Option 2 point-action source attestation failed: "
                + "; ".join(mismatches[:6])
            )
        return {
            "runtime_bundle_sha256": bundle.sha256,
            "sdk_lock_sha256": bundle.member("sdk_lock").sha256,
            "policy_sha256": bundle.member("contract").sha256,
            "service_source_sha256": bundle.member("service_source").sha256,
            "database_source_sha256": bundle.member("database_source").sha256,
            "point_action_source_sha256": bundle.member(
                "option2_point_action_source"
            ).sha256,
        }

    def _option2_point_action_qualification_content(
        self,
        *,
        recorded_historical_content: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        review_state, reviewed, review_blocker = (
            self._option2_host_preflight_recovery_result_review_state()
        )
        if (
            review_state != "recovery_result_reviewed_inactive"
            or reviewed is not True
            or review_blocker is not None
        ):
            raise SupervisorError(
                "Option 2 recovery result review must verify first"
            )
        if recorded_historical_content is None:
            review_content = (
                self._option2_host_preflight_recovery_result_review_content()
            )
            review_sha256 = _sha256_bytes(
                canonical_json(review_content).encode("utf-8")
            )
            implementation_bindings = (
                self._option2_point_action_current_bindings()
            )
        else:
            review_sha256 = str(
                recorded_historical_content.get(
                    "predecessor_recovery_result_review_content_sha256", ""
                )
            )
            stored_bindings = recorded_historical_content.get(
                "implementation_bindings"
            )
            if not isinstance(stored_bindings, Mapping):
                raise SupervisorError(
                    "Option 2 historical point-action bindings are invalid"
                )
            implementation_bindings = {
                str(key): str(value) for key, value in stored_bindings.items()
            }
        report = qualify_option2_point_action_contract(
            recovery_result_review_content_sha256=review_sha256
        )
        contract = build_option2_point_action_contract(
            recovery_result_review_content_sha256=review_sha256
        )
        authority = report.get("authority")
        effects = report.get("effects")
        rejection_cases = report.get("rejection_case_sha256")
        expected_binding_fields = {
            "runtime_bundle_sha256",
            "sdk_lock_sha256",
            "policy_sha256",
            "service_source_sha256",
            "database_source_sha256",
            "point_action_source_sha256",
        }
        report_body = {
            key: value
            for key, value in report.items()
            if key != "qualification_sha256"
        }
        if (
            report.get("state") != OPTION2_POINT_ACTION_QUALIFICATION_STATE
            or report.get("contract_sha256") != contract["contract_sha256"]
            or report.get(
                "predecessor_recovery_result_review_content_sha256"
            )
            != review_sha256
            or report.get("next_gate") != OPTION2_POINT_ACTION_NEXT_GATE
            or report.get("qualification_sha256")
            != _sha256_bytes(canonical_json(report_body).encode("utf-8"))
            or report.get("rejection_case_count")
            != len(OPTION2_POINT_ACTION_REJECTION_CASE_IDS)
            or report.get("premutation_rejection_case_count")
            != len(OPTION2_POINT_ACTION_PREMUTATION_REJECTION_CASE_IDS)
            or report.get("postmutation_quarantine_case_count")
            != len(OPTION2_POINT_ACTION_POSTMUTATION_QUARANTINE_CASE_IDS)
            or report.get(
                "all_premutation_rejections_stop_before_first_mutation"
            )
            is not True
            or report.get(
                "all_postmutation_rollback_uncertainties_quarantine"
            )
            is not True
            or report.get("postmutation_residual_entity_risk_explicit")
            is not True
            or not isinstance(rejection_cases, Mapping)
            or set(rejection_cases) != set(OPTION2_POINT_ACTION_REJECTION_CASE_IDS)
            or any(
                not isinstance(value, str)
                or re.fullmatch(r"[0-9a-f]{64}", value) is None
                or value == "0" * 64
                for value in rejection_cases.values()
            )
            or not isinstance(authority, Mapping)
            or set(authority) != set(OPTION2_POINT_ACTION_AUTHORITY_FIELDS)
            or any(value is not False for value in authority.values())
            or not isinstance(effects, Mapping)
            or set(effects) != set(OPTION2_POINT_ACTION_EFFECT_FIELDS)
            or any(value is not False for value in effects.values())
            or set(implementation_bindings) != expected_binding_fields
            or any(
                re.fullmatch(r"[0-9a-f]{64}", value) is None
                or value == "0" * 64
                for value in implementation_bindings.values()
            )
            or any(
                report.get(field) is not False
                for field in (
                    "host_query_present",
                    "host_apply_present",
                    "administrator_prompt_present",
                    "future_preflight_implementation_present",
                    "future_provisioning_implementation_present",
                    "production_preflight_qualified",
                    "production_rollback_qualified",
                    "ordinary_startup_wired",
                    "http_route_present",
                    "ui_action_present",
                    "ready",
                    "ready_offline",
                    "ready_live",
                )
            )
        ):
            raise SupervisorError(
                "Option 2 point-action fixture qualification was not exact"
            )
        return {
            "version": 1,
            "classification": (
                "option2_identity_only_point_action_design_qualification"
            ),
            "status": OPTION2_POINT_ACTION_QUALIFICATION_STATE,
            "predecessor_recovery_result_review_content_sha256": review_sha256,
            "contract_state": OPTION2_POINT_ACTION_STATE,
            "contract_sha256": report["contract_sha256"],
            "implementation_bindings": implementation_bindings,
            "fixture_qualification_sha256": report["qualification_sha256"],
            "rejection_case_count": report["rejection_case_count"],
            "premutation_rejection_case_count": report[
                "premutation_rejection_case_count"
            ],
            "postmutation_quarantine_case_count": report[
                "postmutation_quarantine_case_count"
            ],
            "all_premutation_rejections_stop_before_first_mutation": True,
            "all_postmutation_rollback_uncertainties_quarantine": True,
            "postmutation_residual_entity_risk_explicit": True,
            "two_distinct_owner_gates_verified": True,
            "preflight_candidate_grants_no_mutation_authority": True,
            "expired_recovery_candidate_reused": False,
            "host_query_present": False,
            "host_apply_present": False,
            "administrator_prompt_present": False,
            "future_preflight_implementation_present": False,
            "future_provisioning_implementation_present": False,
            "production_preflight_qualified": False,
            "production_rollback_qualified": False,
            "ordinary_startup_wired": False,
            "http_route_present": False,
            "ui_action_present": False,
            "authority_granted": False,
            "provisioning_authorized": False,
            "service_identity_creation_authorized": False,
            "service_identity_provisioning_authorized": False,
            "vault_provisioning_authorized": False,
            "credential_use_authorized": False,
            "private_data_transmission_authorized": False,
            "model_contact_authorized": False,
            "network_access_authorized": False,
            "access_change_authorized": False,
            "background_execution_authorized": False,
            "deployment_authorized": False,
            "live_execution_authorized": False,
            "ready": False,
            "ready_offline": False,
            "ready_live": False,
            "next_gate": OPTION2_POINT_ACTION_NEXT_GATE,
        }

    def _option2_point_action_qualification_state(
        self,
    ) -> tuple[str, bool, str | None]:
        review_state, reviewed, _review_blocker = (
            self._option2_host_preflight_recovery_result_review_state()
        )
        if review_state != "recovery_result_reviewed_inactive" or not reviewed:
            return "not_applicable", False, None
        if self.database is None or not hasattr(
            self.database, "list_supervisor_v4_qualifications"
        ):
            return (
                "qualification_storage_unavailable",
                False,
                "option2_point_action_qualification_storage_unavailable",
            )
        records = self.database.list_supervisor_v4_qualifications(
            subject=_OPTION2_POINT_ACTION_QUALIFICATION_SUBJECT,
            limit=3,
        )
        if not records:
            return (
                "qualification_required",
                False,
                "option2_point_action_fixture_qualification_required",
            )
        if len(records) != 1:
            return (
                "qualification_invalid",
                False,
                "option2_point_action_qualification_duplicate_evidence",
            )
        record = records[0]
        content = record.get("content")
        try:
            if not isinstance(content, Mapping):
                raise SupervisorError(
                    "Option 2 historical point-action content is invalid"
                )
            review_records = self.database.list_supervisor_v4_qualifications(
                subject=_OPTION2_HOST_PREFLIGHT_RECOVERY_RESULT_REVIEW_SUBJECT,
                limit=3,
            )
            if (
                len(review_records) != 1
                or content.get(
                    "predecessor_recovery_result_review_content_sha256"
                )
                != review_records[0].get("content_sha256")
            ):
                raise SupervisorError(
                    "Option 2 historical point-action predecessor is invalid"
                )
            expected = self._option2_point_action_qualification_content(
                recorded_historical_content=content
            )
        except (Option2PointActionViolation, SupervisorError, KeyError, TypeError):
            return (
                "qualification_invalid",
                False,
                "option2_point_action_contract_or_lineage_invalid",
            )
        expected_sha256 = _sha256_bytes(
            canonical_json(expected).encode("utf-8")
        )
        if (
            record.get("status") != "inactive"
            or record.get("authority_granted") != 0
            or record.get("content") != expected
            or record.get("content_sha256") != expected_sha256
        ):
            return (
                "qualification_invalid",
                False,
                "option2_point_action_qualification_evidence_mismatch",
            )
        return OPTION2_POINT_ACTION_QUALIFICATION_STATE, True, None

    def record_option2_point_action_fixture_qualification(
        self,
    ) -> dict[str, object]:
        """Record the pure design qualification without a live route."""

        if self.database is None or not hasattr(
            self.database, "record_supervisor_v4_qualification_once_if_heads"
        ):
            raise SupervisorError(
                "Option 2 point-action qualification ledger is unavailable"
            )
        content = self._option2_point_action_qualification_content()
        result_review_records = self.database.list_supervisor_v4_qualifications(
            subject=_OPTION2_HOST_PREFLIGHT_RECOVERY_RESULT_REVIEW_SUBJECT,
            limit=1,
        )
        original_records = self.database.list_supervisor_v4_qualifications(
            subject=OPTION2_HOST_PREFLIGHT_CLAIM_SUBJECT,
            limit=1,
        )
        recovery_claim_records = self.database.list_supervisor_v4_qualifications(
            subject=OPTION2_HOST_PREFLIGHT_RECOVERY_CLAIM_SUBJECT,
            limit=1,
        )
        recovery_candidate_records = (
            self.database.list_supervisor_v4_qualifications(
                subject=OPTION2_HOST_PREFLIGHT_RECOVERY_CANDIDATE_SUBJECT,
                limit=1,
            )
        )
        record = self.database.record_supervisor_v4_qualification_once_if_heads(
            subject=_OPTION2_POINT_ACTION_QUALIFICATION_SUBJECT,
            status="inactive",
            content=content,
            expected_heads={
                OPTION2_HOST_PREFLIGHT_CLAIM_SUBJECT: str(
                    original_records[0]["id"]
                ),
                OPTION2_HOST_PREFLIGHT_SUBJECT: None,
                OPTION2_HOST_PREFLIGHT_RECOVERY_CLAIM_SUBJECT: str(
                    recovery_claim_records[0]["id"]
                ),
                OPTION2_HOST_PREFLIGHT_RECOVERY_CANDIDATE_SUBJECT: str(
                    recovery_candidate_records[0]["id"]
                ),
                _OPTION2_HOST_PREFLIGHT_RECOVERY_RESULT_REVIEW_SUBJECT: str(
                    result_review_records[0]["id"]
                ),
            },
        )
        state, qualified, blocker = self._option2_point_action_qualification_state()
        if (
            state != OPTION2_POINT_ACTION_QUALIFICATION_STATE
            or qualified is not True
            or blocker is not None
        ):
            raise SupervisorError(
                "Option 2 point-action fixture evidence did not verify"
            )
        return {
            "classification": content["classification"],
            "qualification_state": state,
            "qualification_id": record["id"],
            "qualification_sha256": record["content_sha256"],
            "contract_sha256": content["contract_sha256"],
            "expired_recovery_candidate_reused": False,
            "host_query_performed": False,
            "administrator_prompt_displayed": False,
            "host_apply_performed": False,
            "authority_granted": False,
            "provisioning_authorized": False,
            "service_identity_creation_authorized": False,
            "service_identity_provisioning_authorized": False,
            "vault_provisioning_authorized": False,
            "credential_use_authorized": False,
            "private_data_transmission_authorized": False,
            "model_contact_authorized": False,
            "network_access_authorized": False,
            "access_change_authorized": False,
            "background_execution_authorized": False,
            "deployment_authorized": False,
            "live_execution_authorized": False,
            "ready": False,
            "ready_offline": False,
            "ready_live": False,
            "next_gate": OPTION2_POINT_ACTION_NEXT_GATE,
        }

    @staticmethod
    def _option2_native_source_member_keys() -> dict[str, str]:
        return {
            "native/option2_identity_preflight/BoundRequest.swift": (
                "option2_native_bound_request_source"
            ),
            "native/option2_identity_preflight/CanonicalJSON.swift": (
                "option2_native_canonical_json_source"
            ),
            "native/option2_identity_preflight/ClaimLedger.swift": (
                "option2_native_claim_ledger_source"
            ),
            "native/option2_identity_preflight/OfflineFixtures.swift": (
                "option2_native_offline_fixtures_source"
            ),
            "native/option2_identity_preflight/Option2FixtureMain.swift": (
                "option2_native_fixture_main_source"
            ),
            "native/option2_identity_preflight/PreflightEvaluator.swift": (
                "option2_native_preflight_evaluator_source"
            ),
        }

    def _option2_native_preflight_current_bindings(
        self,
    ) -> tuple[dict[str, str], dict[str, str]]:
        """Bind the native fixture receipt to the current sealed sources."""

        mismatches: list[str] = []
        bundle = self._seal_runtime_bundle()
        policy = self._sealed_policy(bundle, mismatches)
        if policy is None:
            raise SupervisorError(
                "Option 2 native preflight policy binding is unavailable"
            )
        if bundle.member("protocol").sha256 != policy.protocol_inventory_sha256:
            mismatches.append("Option 2 native preflight protocol binding drifted")
        if bundle.member("sdk_lock").sha256 != policy.sdk_lock_sha256:
            mismatches.append("Option 2 native preflight SDK lock binding drifted")
        lock = self._load_lock(bundle.member("sdk_lock"), mismatches)
        self._inspect_source_pins(lock, mismatches)
        self._inspect_loaded_source_bindings(bundle, lock, mismatches)
        member_keys = self._option2_native_source_member_keys()
        source_sha256 = {
            path: bundle.member(member_keys[path]).sha256
            for path in OPTION2_NATIVE_PREFLIGHT_SOURCE_PATHS
        }
        try:
            validate_native_source_texts(
                {
                    path: bundle.member(member_keys[path]).content.decode(
                        "utf-8", errors="strict"
                    )
                    for path in OPTION2_NATIVE_PREFLIGHT_SOURCE_PATHS
                }
            )
        except (UnicodeDecodeError, Option2NativePreflightViolation) as exc:
            mismatches.append(f"Option 2 native source validation failed: {exc}")
        native_fixture_report: Mapping[str, object] | None = None
        try:
            parsed_report = json.loads(
                bundle.member("option2_native_fixture_report").content.decode(
                    "utf-8", errors="strict"
                )
            )
            if not isinstance(parsed_report, Mapping):
                raise Option2NativePreflightViolation(
                    "option2_native_fixture_report_not_mapping"
                )
            validate_native_fixture_report(parsed_report)
            native_fixture_report = parsed_report
        except (
            json.JSONDecodeError,
            UnicodeDecodeError,
            Option2NativePreflightViolation,
        ) as exc:
            mismatches.append(
                f"Option 2 native fixture report validation failed: {exc}"
            )
        if mismatches:
            raise SupervisorError(
                "Option 2 native preflight source attestation failed: "
                + "; ".join(mismatches[:6])
            )
        return (
            {
                "runtime_bundle_sha256": bundle.sha256,
                "sdk_lock_sha256": bundle.member("sdk_lock").sha256,
                "policy_sha256": bundle.member("contract").sha256,
                "service_source_sha256": bundle.member("service_source").sha256,
                "database_source_sha256": bundle.member("database_source").sha256,
                "native_preflight_source_sha256": bundle.member(
                    "option2_native_preflight_source"
                ).sha256,
                "native_fixture_report_file_sha256": bundle.member(
                    "option2_native_fixture_report"
                ).sha256,
                "native_fixture_qualification_sha256": str(
                    (native_fixture_report or {}).get(
                        "qualification_sha256", ""
                    )
                ),
            },
            source_sha256,
        )

    def _option2_native_preflight_qualification_content(
        self,
        *,
        recorded_historical_content: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        point_state, point_qualified, point_blocker = (
            self._option2_point_action_qualification_state()
        )
        if (
            point_state != OPTION2_POINT_ACTION_QUALIFICATION_STATE
            or point_qualified is not True
            or point_blocker is not None
        ):
            raise SupervisorError(
                "Option 2 point-action qualification must verify first"
            )
        if self.database is None:
            raise SupervisorError(
                "Option 2 native preflight qualification ledger is unavailable"
            )
        point_records = self.database.list_supervisor_v4_qualifications(
            subject=_OPTION2_POINT_ACTION_QUALIFICATION_SUBJECT,
            limit=3,
        )
        if len(point_records) != 1:
            raise SupervisorError(
                "Option 2 point-action qualification cardinality is invalid"
            )
        point_record = point_records[0]
        point_content = self._option2_inactive_ledger_record_content(
            point_record,
            code="option2_native_preflight_point_action_receipt_invalid",
        )
        point_contract_sha256 = str(point_content.get("contract_sha256", ""))
        if recorded_historical_content is None:
            implementation_bindings, source_sha256 = (
                self._option2_native_preflight_current_bindings()
            )
        else:
            stored_bindings = recorded_historical_content.get(
                "implementation_bindings"
            )
            stored_source_sha256 = recorded_historical_content.get(
                "native_source_sha256"
            )
            if not isinstance(stored_bindings, Mapping) or not isinstance(
                stored_source_sha256, Mapping
            ):
                raise SupervisorError(
                    "Option 2 historical native preflight bindings are invalid"
                )
            implementation_bindings = {
                str(key): str(value) for key, value in stored_bindings.items()
            }
            source_sha256 = {
                str(key): str(value)
                for key, value in stored_source_sha256.items()
            }
        contract = build_option2_native_preflight_contract(
            point_action_qualification_id=str(point_record["id"]),
            point_action_qualification_content_sha256=str(
                point_record["content_sha256"]
            ),
            point_action_contract_sha256=point_contract_sha256,
            source_sha256=source_sha256,
        )
        report = qualify_option2_native_preflight_contract(
            point_action_qualification_id=str(point_record["id"]),
            point_action_qualification_content_sha256=str(
                point_record["content_sha256"]
            ),
            point_action_contract_sha256=point_contract_sha256,
            source_sha256=source_sha256,
        )
        expected_binding_fields = {
            "runtime_bundle_sha256",
            "sdk_lock_sha256",
            "policy_sha256",
            "service_source_sha256",
            "database_source_sha256",
            "native_preflight_source_sha256",
            "native_fixture_report_file_sha256",
            "native_fixture_qualification_sha256",
        }
        report_body = {
            key: value
            for key, value in report.items()
            if key != "qualification_sha256"
        }
        if (
            report.get("state")
            != OPTION2_NATIVE_PREFLIGHT_QUALIFICATION_STATE
            or report.get("contract_sha256") != contract["contract_sha256"]
            or report.get("predecessor_point_action_qualification_id")
            != point_record["id"]
            or report.get(
                "predecessor_point_action_qualification_content_sha256"
            )
            != point_record["content_sha256"]
            or report.get("qualification_sha256")
            != _sha256_bytes(canonical_json(report_body).encode("utf-8"))
            or set(implementation_bindings) != expected_binding_fields
            or any(
                re.fullmatch(r"[0-9a-f]{64}", value) is None
                or value == "0" * 64
                for value in implementation_bindings.values()
            )
            or set(source_sha256) != set(OPTION2_NATIVE_PREFLIGHT_SOURCE_PATHS)
            or any(
                re.fullmatch(r"[0-9a-f]{64}", value) is None
                or value == "0" * 64
                for value in source_sha256.values()
            )
            or any(
                report.get(field) is not False
                for field in (
                    "whole_host_snapshot_rollback_resistance_qualified",
                    "durable_filesystem_io_verified",
                    "independent_anchor_verified",
                    "production_host_adapter_present",
                    "production_durable_ledger_adapter_present",
                    "production_anti_rollback_anchor_present",
                    "root_owned_installation_present",
                    "separately_signed_installation_present",
                    "administrator_prompt_present",
                    "point_action_host_query_present",
                    "identity_mutation_present",
                    "network_route_present",
                    "atlas_to_native_execution_route_present",
                    "ordinary_startup_wired",
                    "http_route_present",
                    "ui_action_present",
                    "production_preflight_qualified",
                    "production_rollback_qualified",
                    "authority_granted",
                    "ready",
                    "ready_offline",
                    "ready_live",
                )
            )
            or report.get("next_gate") != OPTION2_NATIVE_PREFLIGHT_NEXT_GATE
        ):
            raise SupervisorError(
                "Option 2 native preflight qualification was not exact"
            )
        return {
            "version": 1,
            "classification": (
                "option2_native_preflight_and_claim_ledger_offline_qualification"
            ),
            "status": OPTION2_NATIVE_PREFLIGHT_QUALIFICATION_STATE,
            "predecessor_point_action_qualification_id": point_record["id"],
            "predecessor_point_action_qualification_content_sha256": (
                point_record["content_sha256"]
            ),
            "predecessor_point_action_contract_sha256": point_contract_sha256,
            "contract_state": OPTION2_NATIVE_PREFLIGHT_STATE,
            "contract_sha256": contract["contract_sha256"],
            "implementation_bindings": implementation_bindings,
            "native_source_sha256": dict(sorted(source_sha256.items())),
            "native_source_manifest_sha256": contract[
                "native_source_manifest_sha256"
            ],
            "fixture_qualification_sha256": report["qualification_sha256"],
            "native_fixture_report_file_sha256": implementation_bindings[
                "native_fixture_report_file_sha256"
            ],
            "native_fixture_report_qualification_sha256": (
                implementation_bindings[
                    "native_fixture_qualification_sha256"
                ]
            ),
            "native_fixture_case_count": report["native_fixture_case_count"],
            "required_binding_field_count": report[
                "required_binding_field_count"
            ],
            "native_core_implemented": True,
            "authorization_claim_ledger_core_implemented": True,
            "native_fixture_qualified": True,
            "authorization_claim_ledger_crash_fixture_qualified": True,
            "claim_durability_order_projection_qualified": True,
            "durable_filesystem_io_verified": False,
            "independent_anchor_verified": False,
            "historical_point_action_receipt_recomputed_against_current_source": False,
            "atlas_database_restore_replay_rejected_in_fixture": True,
            "whole_host_snapshot_rollback_resistance_qualified": False,
            "production_host_adapter_present": False,
            "production_durable_ledger_adapter_present": False,
            "production_anti_rollback_anchor_present": False,
            "root_owned_installation_present": False,
            "separately_signed_installation_present": False,
            "administrator_prompt_present": False,
            "point_action_host_query_present": False,
            "identity_mutation_present": False,
            "network_route_present": False,
            "atlas_to_native_execution_route_present": False,
            "ordinary_startup_wired": False,
            "http_route_present": False,
            "ui_action_present": False,
            "production_preflight_qualified": False,
            "production_rollback_qualified": False,
            "authority_granted": False,
            "ready": False,
            "ready_offline": False,
            "ready_live": False,
            "next_gate": OPTION2_NATIVE_PREFLIGHT_NEXT_GATE,
        }

    def _option2_native_preflight_qualification_state(
        self,
    ) -> tuple[str, bool, str | None]:
        point_state, point_qualified, _point_blocker = (
            self._option2_point_action_qualification_state()
        )
        if point_state != OPTION2_POINT_ACTION_QUALIFICATION_STATE or not point_qualified:
            return "not_applicable", False, None
        if self.database is None:
            return (
                "qualification_storage_unavailable",
                False,
                "option2_native_preflight_qualification_storage_unavailable",
            )
        records = self.database.list_supervisor_v4_qualifications(
            subject=_OPTION2_NATIVE_PREFLIGHT_QUALIFICATION_SUBJECT,
            limit=3,
        )
        if not records:
            return (
                "qualification_required",
                False,
                "option2_native_preflight_fixture_qualification_required",
            )
        if len(records) != 1:
            return (
                "qualification_invalid",
                False,
                "option2_native_preflight_qualification_duplicate_evidence",
            )
        record = records[0]
        content = record.get("content")
        try:
            if not isinstance(content, Mapping):
                raise SupervisorError(
                    "Option 2 native preflight qualification content is invalid"
                )
            expected = self._option2_native_preflight_qualification_content(
                recorded_historical_content=content
            )
        except (
            Option2NativePreflightViolation,
            Option2PointActionViolation,
            SupervisorError,
            KeyError,
            TypeError,
        ):
            return (
                "qualification_invalid",
                False,
                "option2_native_preflight_contract_or_lineage_invalid",
            )
        expected_sha256 = _sha256_bytes(
            canonical_json(expected).encode("utf-8")
        )
        if (
            record.get("status") != "inactive"
            or record.get("authority_granted") != 0
            or record.get("content") != expected
            or record.get("content_sha256") != expected_sha256
        ):
            return (
                "qualification_invalid",
                False,
                "option2_native_preflight_qualification_evidence_mismatch",
            )
        return OPTION2_NATIVE_PREFLIGHT_QUALIFICATION_STATE, True, None

    def record_option2_native_preflight_fixture_qualification(
        self,
    ) -> dict[str, object]:
        """Record the already validated, sealed native fixture report."""

        if self.database is None or not hasattr(
            self.database, "record_supervisor_v4_qualification_once_if_heads"
        ):
            raise SupervisorError(
                "Option 2 native preflight qualification ledger is unavailable"
            )
        content = self._option2_native_preflight_qualification_content()
        point_records = self.database.list_supervisor_v4_qualifications(
            subject=_OPTION2_POINT_ACTION_QUALIFICATION_SUBJECT,
            limit=1,
        )
        record = self.database.record_supervisor_v4_qualification_once_if_heads(
            subject=_OPTION2_NATIVE_PREFLIGHT_QUALIFICATION_SUBJECT,
            status="inactive",
            content=content,
            expected_heads={
                _OPTION2_POINT_ACTION_QUALIFICATION_SUBJECT: str(
                    point_records[0]["id"]
                ),
            },
        )
        state, qualified, blocker = (
            self._option2_native_preflight_qualification_state()
        )
        if (
            state != OPTION2_NATIVE_PREFLIGHT_QUALIFICATION_STATE
            or qualified is not True
            or blocker is not None
        ):
            raise SupervisorError(
                "Option 2 native preflight qualification did not verify"
            )
        return {
            "classification": content["classification"],
            "qualification_state": state,
            "qualification_id": record["id"],
            "qualification_sha256": record["content_sha256"],
            "contract_sha256": content["contract_sha256"],
            "native_fixture_case_count": content[
                "native_fixture_case_count"
            ],
            "root_owned_installation_present": False,
            "separately_signed_installation_present": False,
            "production_host_adapter_present": False,
            "production_anti_rollback_anchor_present": False,
            "administrator_prompt_displayed": False,
            "host_query_performed": False,
            "identity_mutation_performed": False,
            "authority_granted": False,
            "ready": False,
            "ready_offline": False,
            "ready_live": False,
            "next_gate": OPTION2_NATIVE_PREFLIGHT_NEXT_GATE,
        }

    @contextmanager
    def _option2_host_preflight_execution_lock(self):
        """Serialize the owner-initiated query through the existing ledger file."""

        if self.database is None:
            raise SupervisorError("Option 2 host preflight ledger is unavailable")
        lock_path = self.database.path.with_name(
            f".{self.database.path.name}.option2-host-preflight.lock"
        )
        try:
            import fcntl

            descriptor = os.open(
                lock_path,
                os.O_RDWR
                | os.O_CREAT
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
        except (ImportError, OSError) as error:
            raise SupervisorError(
                "Option 2 host preflight execution lock is unavailable"
            ) from error
        locked = False
        try:
            metadata = os.fstat(descriptor)
            path_metadata = lock_path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) & 0o077
                or (
                    metadata.st_dev,
                    metadata.st_ino,
                )
                != (
                    path_metadata.st_dev,
                    path_metadata.st_ino,
                )
            ):
                raise SupervisorError(
                    "Option 2 host preflight execution lock is unsafe"
                )
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
            except BlockingIOError as error:
                raise SupervisorError(
                    "Option 2 host preflight is already in progress"
                ) from error
            yield
        finally:
            if locked:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def record_option2_identity_only_host_preflight_candidate(
        self,
    ) -> dict[str, object]:
        """Run one serialized owner-reviewed local-only inventory query."""

        if sys.platform != "darwin":
            raise SupervisorError("Option 2 host preflight requires macOS")
        if os.geteuid() == 0 or os.getuid() != os.geteuid():
            raise SupervisorError(
                "Option 2 host preflight refuses root or changed user identity"
            )
        if os.getgid() != os.getegid():
            raise SupervisorError(
                "Option 2 host preflight refuses changed group identity"
            )
        if self.database is None:
            raise SupervisorError("Option 2 host preflight ledger is unavailable")
        with self._option2_host_preflight_execution_lock():
            return self._record_option2_identity_only_host_preflight_candidate_locked()

    def _record_option2_identity_only_host_preflight_candidate_locked(
        self,
    ) -> dict[str, object]:
        """Run the owner-reviewed local-only query and persist no raw inventory."""

        if sys.platform != "darwin":
            raise SupervisorError("Option 2 host preflight requires macOS")
        if os.geteuid() == 0 or os.getuid() != os.geteuid():
            raise SupervisorError(
                "Option 2 host preflight refuses root or changed user identity"
            )
        if os.getgid() != os.getegid():
            raise SupervisorError(
                "Option 2 host preflight refuses changed group identity"
            )
        if self.database is None or not hasattr(
            self.database, "record_supervisor_v4_qualification_if_heads"
        ):
            raise SupervisorError("Option 2 host preflight ledger is unavailable")
        if self.config.supervisor_v4.pause_file.exists():
            raise SupervisorError("Supervisor v4 is paused")
        try:
            cwd_state = _OPTION2_HOST_PREFLIGHT_CWD.stat()
        except OSError as error:
            raise SupervisorError(
                "Option 2 host preflight working directory is unavailable"
            ) from error
        if (
            not stat.S_ISDIR(cwd_state.st_mode)
            or cwd_state.st_uid != 0
            or stat.S_IMODE(cwd_state.st_mode) & 0o022
        ):
            raise SupervisorError(
                "Option 2 host preflight working directory is unsafe"
            )
        original = self._option1_canary_accounting()
        recovery = self._option1_recovery_canary_accounting()
        identity_state, identity_qualified, identity_blocker = (
            self._option2_identity_candidate_qualification_state(
                original, recovery
            )
        )
        if (
            identity_state != OPTION2_IDENTITY_CANDIDATE_RESOLVER_STATE
            or identity_qualified is not True
            or identity_blocker is not None
            or not self._option2_production_paths_are_null()
        ):
            raise SupervisorError(
                "Option 2 identity fixture must remain qualified and inactive"
            )
        existing_state, existing_active, existing_blocker, existing_record = (
            self._option2_host_preflight_candidate_state(original, recovery)
        )
        if existing_active:
            raise SupervisorError(
                "An active Option 2 host candidate already exists; use its original review phrase"
            )
        if existing_state in {
            "candidate_invalid_quarantined",
            "preflight_consumed_incomplete",
            "candidate_storage_unavailable",
        }:
            raise SupervisorError(
                existing_blocker or "Option 2 host candidate lineage is quarantined"
            )
        if existing_state not in {
            "not_performed",
            "candidate_expired_inactive",
            "candidate_stale_inactive",
        }:
            raise SupervisorError("Option 2 host preflight state is not eligible")
        bindings = self._option2_host_preflight_current_bindings(
            original, recovery
        )
        existing_candidate = (
            existing_record.get("content")
            if isinstance(existing_record, Mapping)
            else None
        )
        if isinstance(existing_candidate, Mapping):
            previous_lineage = existing_candidate.get("lineage")
            if not isinstance(previous_lineage, Mapping):
                raise SupervisorError(
                    "Option 2 host candidate lineage is unavailable"
                )
            generation = int(previous_lineage["generation"]) + 1
            previous_candidate_sha256 = str(
                existing_candidate["candidate_sha256"]
            )
            supersession_reason = (
                "expired"
                if existing_state == "candidate_expired_inactive"
                else "stale"
            )
        else:
            generation = 1
            previous_candidate_sha256 = None
            supersession_reason = "initial"
        issued = datetime.now(timezone.utc).replace(microsecond=0)
        expires = issued + timedelta(
            seconds=OPTION2_IDENTITY_CANDIDATE_MAX_VALIDITY_SECONDS
        )
        authorization_challenge = secrets.token_hex(16)
        claim = build_option2_host_preflight_claim(
            authorization_challenge=authorization_challenge,
            issued_at=issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
            expires_at=expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
            generation=generation,
            previous_candidate_sha256=previous_candidate_sha256,
            supersession_reason=supersession_reason,
            **bindings,
        )
        previous_claim_records = (
            self.database.list_supervisor_v4_qualifications(
                subject=OPTION2_HOST_PREFLIGHT_CLAIM_SUBJECT,
                limit=1,
            )
        )
        previous_claim_id = (
            str(previous_claim_records[0]["id"])
            if previous_claim_records
            else None
        )
        previous_candidate_id = (
            str(existing_record["id"])
            if isinstance(existing_record, Mapping)
            else None
        )
        try:
            claim_record = (
                self.database.record_supervisor_v4_qualification_if_heads(
                    subject=OPTION2_HOST_PREFLIGHT_CLAIM_SUBJECT,
                    status="inactive",
                    content=claim,
                    expected_heads={
                        OPTION2_HOST_PREFLIGHT_CLAIM_SUBJECT: previous_claim_id,
                        OPTION2_HOST_PREFLIGHT_SUBJECT: previous_candidate_id,
                    },
                )
            )
        except ValueError as error:
            raise SupervisorError(
                "Option 2 host preflight claim could not be recorded atomically"
            ) from error
        try:
            candidate = perform_option2_identity_only_host_preflight(
                authorization_challenge=authorization_challenge,
                issued_at=issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
                expires_at=expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
                sandbox_exec_path=_TRUSTED_PLATFORM_TOOL_PATHS["sandbox_exec"],
                dscl_path=_OPTION2_HOST_DSCL_PATH,
                cwd=_OPTION2_HOST_PREFLIGHT_CWD,
                pause_file=self.config.supervisor_v4.pause_file,
                preflight_claim_id=str(claim_record["id"]),
                preflight_claim_sha256=str(claim_record["content_sha256"]),
                generation=generation,
                previous_candidate_sha256=previous_candidate_sha256,
                supersession_reason=supersession_reason,
                **bindings,
            )
        except Option2HostPreflightViolation as error:
            code = str(error).split(":", 1)[0]
            if re.fullmatch(r"option2_host_[a-z0-9_]{1,120}", code) is None:
                code = "option2_host_preflight_failed_closed"
            raise SupervisorError(code) from error
        if self.config.supervisor_v4.pause_file.exists():
            raise SupervisorError(
                "Option 2 host preflight paused after inventory; claim consumed without candidate"
            )
        try:
            record = self.database.record_supervisor_v4_qualification_if_heads(
                subject=OPTION2_HOST_PREFLIGHT_SUBJECT,
                status="inactive",
                content=candidate,
                expected_heads={
                    OPTION2_HOST_PREFLIGHT_CLAIM_SUBJECT: str(
                        claim_record["id"]
                    ),
                    OPTION2_HOST_PREFLIGHT_SUBJECT: previous_candidate_id,
                },
            )
        except ValueError as error:
            raise SupervisorError(
                "Option 2 host preflight candidate could not be recorded atomically"
            ) from error
        completed = datetime.now(timezone.utc).replace(microsecond=0)
        state, active, blocker, verified_record = (
            self._option2_host_preflight_candidate_state(
                original, recovery, observed_at=completed
            )
        )
        if (
            state != OPTION2_HOST_PREFLIGHT_STATE
            or active is not True
            or blocker is not None
            or verified_record is None
            or verified_record.get("id") != record.get("id")
        ):
            raise SupervisorError(
                "Option 2 host preflight candidate evidence did not verify"
            )
        return {
            "classification": candidate["classification"],
            "preflight_state": state,
            "preflight_claim_id": claim_record["id"],
            "preflight_claim_sha256": claim_record["content_sha256"],
            "qualification_id": record["id"],
            "qualification_sha256": record["content_sha256"],
            "candidate_sha256": candidate["candidate_sha256"],
            "inventory_sha256": candidate["inventory_sha256"],
            "host_binding_sha256": candidate["host_binding_sha256"],
            "host_binding_scope": candidate["host_binding_scope"],
            "issued_at": candidate["issued_at"],
            "expires_at": candidate["expires_at"],
            "assignments": deepcopy(candidate["assignments"]),
            "authorization_phrase_generated": False,
            "legacy_authorization_gate_retired": True,
            "authorization_challenge_persisted": False,
            "raw_inventory_persisted": False,
            "raw_inventory_returned": False,
            "private_identity_data_transiently_present": True,
            "preflight_lock_file_used": True,
            "preflight_claim_ledger_written": True,
            "candidate_ledger_written": True,
            "local_orchestration_filesystem_written": True,
            "host_inspected": True,
            "accounts_created": False,
            "groups_created": False,
            "service_identity_provisioning_authorized": False,
            "candidate_complete_for_host_mutation": False,
            "effective_search_path_collision_check_performed": False,
            "filesystem_ownership_reuse_check_performed": False,
            "ready": False,
            "ready_offline": False,
            "ready_live": False,
            "next_gate": _OPTION2_LEGACY_HOST_CANDIDATE_REVIEW_GATE,
        }

    def record_option2_identity_only_host_preflight_recovery_candidate(
        self,
        *,
        confirmation: str,
    ) -> dict[str, object]:
        """Run only the separately authorized, predecessor-bound recovery read."""

        if sys.platform != "darwin":
            raise SupervisorError("Option 2 host preflight recovery requires macOS")
        if os.geteuid() == 0 or os.getuid() != os.geteuid():
            raise SupervisorError(
                "Option 2 host preflight recovery refuses root or changed user identity"
            )
        if os.getgid() != os.getegid():
            raise SupervisorError(
                "Option 2 host preflight recovery refuses changed group identity"
            )
        if self.database is None:
            raise SupervisorError(
                "Option 2 host preflight recovery ledger is unavailable"
            )
        with self._option2_host_preflight_execution_lock():
            return self._record_option2_identity_only_host_preflight_recovery_candidate_locked(
                confirmation=confirmation
            )

    def _record_option2_identity_only_host_preflight_recovery_candidate_locked(
        self,
        *,
        confirmation: str,
    ) -> dict[str, object]:
        """Consume the separate recovery claim before any directory query."""

        if self.database is None or not hasattr(
            self.database, "record_supervisor_v4_qualification_if_heads"
        ):
            raise SupervisorError(
                "Option 2 host preflight recovery ledger is unavailable"
            )
        if self.config.supervisor_v4.pause_file.exists():
            raise SupervisorError("Supervisor v4 is paused")
        try:
            cwd_state = _OPTION2_HOST_PREFLIGHT_CWD.stat()
        except OSError as error:
            raise SupervisorError(
                "Option 2 host preflight recovery working directory is unavailable"
            ) from error
        if (
            not stat.S_ISDIR(cwd_state.st_mode)
            or cwd_state.st_uid != 0
            or stat.S_IMODE(cwd_state.st_mode) & 0o022
        ):
            raise SupervisorError(
                "Option 2 host preflight recovery working directory is unsafe"
            )
        original = self._option1_canary_accounting()
        recovery = self._option1_recovery_canary_accounting()
        (
            recovery_state,
            recovery_active,
            recovery_blocker,
            _recovery_candidate,
            predecessor_record,
        ) = self._option2_host_preflight_recovery_state(original, recovery)
        if recovery_active or recovery_state != OPTION2_HOST_PREFLIGHT_RECOVERY_STATE:
            raise SupervisorError(
                recovery_blocker
                or "Option 2 host preflight recovery is not eligible"
            )
        if not isinstance(predecessor_record, Mapping):
            raise SupervisorError(
                "Option 2 host preflight recovery predecessor is unavailable"
            )
        predecessor = predecessor_record.get("content")
        if not isinstance(predecessor, Mapping):
            raise SupervisorError(
                "Option 2 host preflight recovery predecessor is invalid"
            )
        expected_confirmation = (
            build_option2_host_preflight_recovery_authorization_phrase(
                predecessor_claim_id=str(predecessor_record["id"]),
                predecessor_claim_content_sha256=str(
                    predecessor_record["content_sha256"]
                ),
            )
        )
        if not isinstance(confirmation, str) or not hmac.compare_digest(
            confirmation, expected_confirmation
        ):
            raise SupervisorError("option2_host_recovery_confirmation_invalid")

        bindings = self._option2_host_preflight_recovery_current_bindings(
            original, recovery
        )
        issued = datetime.now(timezone.utc).replace(microsecond=0)
        expires = issued + timedelta(
            seconds=OPTION2_IDENTITY_CANDIDATE_MAX_VALIDITY_SECONDS
        )
        authorization_challenge = secrets.token_hex(16)
        claim = build_option2_host_preflight_recovery_claim(
            confirmation=confirmation,
            authorization_challenge=authorization_challenge,
            predecessor_claim_id=str(predecessor_record["id"]),
            predecessor_claim_content_sha256=str(
                predecessor_record["content_sha256"]
            ),
            predecessor_claim_sha256=str(predecessor["claim_sha256"]),
            bindings=bindings,
            issued_at=issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
            expires_at=expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        try:
            claim_record = self.database.record_supervisor_v4_qualification_if_heads(
                subject=OPTION2_HOST_PREFLIGHT_RECOVERY_CLAIM_SUBJECT,
                status="inactive",
                content=claim,
                expected_heads={
                    OPTION2_HOST_PREFLIGHT_CLAIM_SUBJECT: str(
                        predecessor_record["id"]
                    ),
                    OPTION2_HOST_PREFLIGHT_SUBJECT: None,
                    OPTION2_HOST_PREFLIGHT_RECOVERY_CLAIM_SUBJECT: None,
                    OPTION2_HOST_PREFLIGHT_RECOVERY_CANDIDATE_SUBJECT: None,
                },
            )
        except ValueError as error:
            raise SupervisorError(
                "Option 2 host preflight recovery claim could not be recorded atomically"
            ) from error
        try:
            candidate = perform_option2_identity_only_host_preflight_recovery(
                authorization_challenge=authorization_challenge,
                preflight_claim_id=str(claim_record["id"]),
                preflight_claim_sha256=str(claim_record["content_sha256"]),
                issued_at=issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
                expires_at=expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
                bindings=bindings,
                sandbox_exec_path=_TRUSTED_PLATFORM_TOOL_PATHS["sandbox_exec"],
                dscl_path=_OPTION2_HOST_DSCL_PATH,
                cwd=_OPTION2_HOST_PREFLIGHT_CWD,
                pause_file=self.config.supervisor_v4.pause_file,
            )
        except Option2HostPreflightViolation as error:
            code = str(error).split(":", 1)[0]
            if re.fullmatch(r"option2_host_recovery_[a-z0-9_]{1,120}", code) is None:
                code = "option2_host_recovery_failed_closed"
            raise SupervisorError(code) from error
        if self.config.supervisor_v4.pause_file.exists():
            raise SupervisorError(
                "Option 2 host preflight recovery paused after inventory; claim consumed without candidate"
            )
        try:
            record = self.database.record_supervisor_v4_qualification_if_heads(
                subject=OPTION2_HOST_PREFLIGHT_RECOVERY_CANDIDATE_SUBJECT,
                status="inactive",
                content=candidate,
                expected_heads={
                    OPTION2_HOST_PREFLIGHT_CLAIM_SUBJECT: str(
                        predecessor_record["id"]
                    ),
                    OPTION2_HOST_PREFLIGHT_SUBJECT: None,
                    OPTION2_HOST_PREFLIGHT_RECOVERY_CLAIM_SUBJECT: str(
                        claim_record["id"]
                    ),
                    OPTION2_HOST_PREFLIGHT_RECOVERY_CANDIDATE_SUBJECT: None,
                },
            )
        except ValueError as error:
            raise SupervisorError(
                "Option 2 host preflight recovery candidate could not be recorded atomically"
            ) from error
        completed = datetime.now(timezone.utc).replace(microsecond=0)
        (
            verified_state,
            verified_active,
            verified_blocker,
            verified_record,
            _verified_predecessor,
        ) = self._option2_host_preflight_recovery_state(
            original, recovery, observed_at=completed
        )
        if (
            verified_state != OPTION2_HOST_PREFLIGHT_RECOVERY_CANDIDATE_STATE
            or verified_active is not True
            or verified_blocker is not None
            or verified_record is None
            or verified_record.get("id") != record.get("id")
        ):
            raise SupervisorError(
                "Option 2 host preflight recovery evidence did not verify"
            )
        return {
            "classification": (
                "option2_identity_only_local_host_preflight_recovery_candidate"
            ),
            "recovery_state": verified_state,
            "predecessor_claim_id": predecessor_record["id"],
            "predecessor_claim_sha256": predecessor_record["content_sha256"],
            "recovery_claim_id": claim_record["id"],
            "recovery_claim_sha256": claim_record["content_sha256"],
            "qualification_id": record["id"],
            "qualification_sha256": record["content_sha256"],
            "candidate_sha256": candidate["candidate_sha256"],
            "inventory_sha256": candidate["inventory_sha256"],
            "host_binding_sha256": candidate["host_binding_sha256"],
            "issued_at": candidate["issued_at"],
            "expires_at": candidate["expires_at"],
            "authorization_phrase_generated": False,
            "legacy_authorization_gate_retired": True,
            "original_claim_reopened": False,
            "recovery_claim_ledger_written": True,
            "candidate_ledger_written": True,
            "host_inspected": True,
            "accounts_created": False,
            "groups_created": False,
            "service_identity_provisioning_authorized": False,
            "candidate_complete_for_host_mutation": False,
            "ready": False,
            "ready_offline": False,
            "ready_live": False,
            "next_gate": _OPTION2_LEGACY_HOST_CANDIDATE_REVIEW_GATE,
        }

    @staticmethod
    def _option1_combined_next_gate(
        original: Mapping[str, object],
        recovery: Mapping[str, object],
        *,
        recovery_result_reviewed: bool = False,
        option2_plan_reviewed: bool = False,
        option2_provisioner_qualified: bool = False,
        option2_manifest_reviewed: bool = False,
        option2_identity_candidate_qualified: bool = False,
        option2_host_candidate_active: bool = False,
        option2_host_candidate_state: str = "not_performed",
        option2_host_recovery_state: str = "not_applicable",
        option2_host_recovery_result_review_state: str = "review_required",
        option2_host_recovery_result_reviewed: bool = False,
        option2_point_action_qualification_state: str = "not_applicable",
        option2_point_action_qualified: bool = False,
        option2_native_preflight_qualification_state: str = "not_applicable",
        option2_native_preflight_qualified: bool = False,
    ) -> str:
        if option2_host_recovery_result_review_state == "review_invalid":
            return _OPTION2_HOST_RECOVERY_RESULT_QUARANTINE_GATE
        if option2_point_action_qualification_state == "qualification_invalid":
            return _OPTION2_POINT_ACTION_QUALIFICATION_QUARANTINE_GATE
        if option2_native_preflight_qualification_state == "qualification_invalid":
            return OPTION2_NATIVE_PREFLIGHT_QUARANTINE_GATE
        if (
            original.get("canary_launch_state") == "failed_preclaim"
            and original.get("canary_attempt_state") == "failed_preclaim"
            and original.get(
                "failed_preclaim_no_keychain_query_or_delivery_verified"
            )
            is True
        ):
            if recovery.get("recovery_canary_predecessor_verified") is not True:
                return "owner_review_option1_synthetic_integration_canary_recovery"
            if (
                recovery.get("recovery_canary_launch_state") == "not_launched"
                and recovery.get("recovery_canary_attempt_state") == "not_attempted"
            ):
                return "owner_authorize_option1_synthetic_integration_recovery_canary"
            if recovery_result_reviewed:
                if not option2_plan_reviewed:
                    return OPTION2_PLAN_NEXT_GATE
                if not option2_provisioner_qualified:
                    return "option2_provisioner_fixture_qualification"
                if not option2_manifest_reviewed:
                    return OPTION2_PROVISIONER_NEXT_GATE
                if not option2_identity_candidate_qualified:
                    return OPTION2_MANIFEST_REVIEW_NEXT_INTERNAL_MILESTONE
                if option2_host_recovery_result_reviewed:
                    if option2_point_action_qualified:
                        if option2_native_preflight_qualified:
                            return OPTION2_NATIVE_PREFLIGHT_NEXT_GATE
                        return "option2_native_preflight_fixture_qualification"
                    return "option2_point_action_fixture_qualification"
                if option2_host_candidate_active:
                    return _OPTION2_LEGACY_HOST_CANDIDATE_REVIEW_GATE
                if option2_host_candidate_state == "preflight_consumed_incomplete":
                    if (
                        option2_host_recovery_state
                        == OPTION2_HOST_PREFLIGHT_RECOVERY_STATE
                    ):
                        return OPTION2_HOST_PREFLIGHT_RECOVERY_AUTHORIZATION_GATE
                    if option2_host_recovery_state in {
                        "recovery_preflight_consumed_incomplete",
                        "recovery_invalid_quarantined",
                        "recovery_storage_unavailable",
                        "recovery_candidate_stale_inactive",
                        "recovery_candidate_expired_inactive",
                    }:
                        return OPTION2_HOST_PREFLIGHT_RECOVERY_RESULT_GATE
                    return OPTION2_HOST_PREFLIGHT_RECOVERY_GATE
                if option2_host_candidate_state in {
                    "candidate_invalid_quarantined",
                    "candidate_storage_unavailable",
                }:
                    return OPTION2_HOST_PREFLIGHT_RECOVERY_GATE
                return OPTION2_IDENTITY_CANDIDATE_NEXT_GATE
            return "owner_review_option1_synthetic_integration_recovery_canary_result"
        return SupervisorV4Service._option1_canary_next_gate(original)

    def status(self) -> dict[str, Any]:
        canary_accounting = self._option1_canary_accounting()
        canary_implementation_state, canary_blocker = (
            self._option1_canary_status_projection(canary_accounting)
        )
        recovery_accounting = self._option1_recovery_canary_accounting()
        recovery_implementation_state, recovery_blocker = (
            self._option1_recovery_canary_status_projection(recovery_accounting)
        )
        recovery_review_completed = (
            canary_accounting.get("canary_launch_state") == "failed_preclaim"
            and canary_accounting.get("canary_attempt_state") == "failed_preclaim"
            and recovery_accounting.get("recovery_canary_predecessor_verified")
            is True
        )
        if recovery_review_completed:
            canary_implementation_state = "failed_preclaim_terminal"
            canary_blocker = "option1_synthetic_integration_canary_failed_preclaim_terminal"
        (
            recovery_result_review_state,
            recovery_result_reviewed,
            recovery_result_review_blocker,
        ) = self._option1_recovery_result_review_state(
            canary_accounting, recovery_accounting
        )
        try:
            option2_plan = build_option2_service_identity_and_vault_plan()
            option2_plan_contract_state = OPTION2_PLAN_STATE
        except (Option2PlanViolation, Option2ProvisionerViolation, KeyError, TypeError):
            option2_plan = {"plan_sha256": None}
            option2_plan_contract_state = "contract_invalid"
        (
            option2_plan_review_state,
            option2_plan_reviewed,
            option2_plan_review_blocker,
        ) = self._option2_plan_review_state(
            canary_accounting, recovery_accounting
        )
        (
            option2_provisioner_qualification_state,
            option2_provisioner_qualified,
            option2_provisioner_qualification_blocker,
        ) = self._option2_provisioner_qualification_state(
            canary_accounting, recovery_accounting
        )
        (
            option2_manifest_review_state,
            option2_manifest_reviewed,
            option2_manifest_review_blocker,
        ) = self._option2_provisioner_manifest_review_state(
            canary_accounting, recovery_accounting
        )
        (
            option2_identity_candidate_state,
            option2_identity_candidate_qualified,
            option2_identity_candidate_blocker,
        ) = self._option2_identity_candidate_qualification_state(
            canary_accounting, recovery_accounting
        )
        (
            option2_host_candidate_state,
            option2_host_candidate_active,
            option2_host_candidate_blocker,
            option2_host_candidate_record,
        ) = self._option2_host_preflight_candidate_state(
            canary_accounting, recovery_accounting
        )
        (
            option2_host_recovery_state,
            option2_host_recovery_candidate_active,
            option2_host_recovery_blocker,
            option2_host_recovery_candidate_record,
            option2_host_recovery_predecessor_record,
        ) = self._option2_host_preflight_recovery_state(
            canary_accounting, recovery_accounting
        )
        (
            option2_host_recovery_result_review_state,
            option2_host_recovery_result_reviewed,
            option2_host_recovery_result_review_blocker,
        ) = self._option2_host_preflight_recovery_result_review_state()
        (
            option2_point_action_qualification_state,
            option2_point_action_qualified,
            option2_point_action_qualification_blocker,
        ) = self._option2_point_action_qualification_state()
        (
            option2_native_preflight_qualification_state,
            option2_native_preflight_qualified,
            option2_native_preflight_qualification_blocker,
        ) = self._option2_native_preflight_qualification_state()
        option2_native_preflight_records = (
            self.database.list_supervisor_v4_qualifications(
                subject=_OPTION2_NATIVE_PREFLIGHT_QUALIFICATION_SUBJECT,
                limit=1,
            )
            if hasattr(self.database, "list_supervisor_v4_qualifications")
            else []
        )
        option2_native_preflight_content = (
            option2_native_preflight_records[0].get("content")
            if option2_native_preflight_records
            else None
        )
        try:
            option2_recovery_review_content = (
                self._option2_host_preflight_recovery_result_review_content()
            )
            option2_recovery_review_content_sha256 = _sha256_bytes(
                canonical_json(option2_recovery_review_content).encode("utf-8")
            )
            option2_point_action_contract = build_option2_point_action_contract(
                recovery_result_review_content_sha256=(
                    option2_recovery_review_content_sha256
                )
            )
            option2_point_action_contract_state = OPTION2_POINT_ACTION_STATE
        except (Option2PointActionViolation, SupervisorError, KeyError, TypeError):
            option2_point_action_contract = {"contract_sha256": None}
            option2_point_action_contract_state = "not_applicable"
        if option2_host_recovery_result_reviewed:
            option2_host_recovery_candidate_active = False
        option2_host_candidate_active = bool(
            option2_host_candidate_active
            or option2_host_recovery_candidate_active
        )
        if option2_host_recovery_candidate_active:
            option2_host_candidate_record = option2_host_recovery_candidate_record
        option2_host_candidate_content = (
            option2_host_candidate_record.get("content")
            if isinstance(option2_host_candidate_record, Mapping)
            else None
        )
        try:
            option2_manifest = build_option2_provisioner_manifest()
            option2_manifest_contract_state = OPTION2_PROVISIONER_STATE
        except (Option2PlanViolation, Option2ProvisionerViolation, KeyError, TypeError):
            option2_manifest = {"manifest_sha256": None}
            option2_manifest_contract_state = "contract_invalid"
        latest = None
        if hasattr(self.database, "list_supervisor_v4_qualifications"):
            records = self.database.list_supervisor_v4_qualifications(
                subject="offline-runtime-v4", limit=1
            )
            record = records[0] if records else None
            if record is not None:
                # A qualification row is diagnostic evidence, not authority.  Do
                # not expose its free-form body and do not let a caller-created
                # row become a readiness grant.
                latest = {
                    "id": record["id"],
                    "subject": record["subject"],
                    "status": record["status"],
                    "content_sha256": record["content_sha256"],
                    "created_at": record["created_at"],
                }
        return {
            "enabled": self.enabled,
            "implementation_state": "implemented_inactive" if self.enabled else "disabled",
            "offline_qualification_enabled": bool(
                self.config.supervisor_v4.offline_qualification_enabled
            ),
            "offline_ready": False,
            "offline_readiness_requires_external_anchor": True,
            "ready_live": False,
            "live_execution_route_present": False,
            "plan_route_present": False,
            "canonical_mutations": False,
            "candidate_application": False,
            "background_execution": False,
            "model_contact_state": "not_dispatched",
            "model_contacted": False,
            "latest_qualification": latest,
            "live_canary_contracts_defined": True,
            "live_canary_design_reviewed": True,
            "offline_broker_implementation_authorized": True,
            "offline_broker_implementation_state": "implemented_inactive",
            "production_broker_externalization_reviewed": True,
            "offline_external_broker_transport_state": "implemented_inactive",
            "same_user_broker_mode": self.config.supervisor_v4.same_user_broker_mode,
            "same_user_broker_qualification_enabled": bool(
                self.config.supervisor_v4.same_user_broker_qualification_enabled
            ),
            "same_user_broker_implementation_state": (
                "implemented_inactive"
                if self.config.supervisor_v4.same_user_broker_qualification_enabled
                else "disabled"
            ),
            "ordinary_startup_wired": False,
            "option1_canary_implementation_state": canary_implementation_state,
            **canary_accounting,
            "option1_recovery_review_completed": recovery_review_completed,
            "option1_recovery_canary_implementation_state": (
                recovery_implementation_state
            ),
            "option1_recovery_canary_owner_authorized": False,
            "option1_recovery_canary_authorization_state": (
                "consumed"
                if recovery_accounting.get("recovery_canary_launches_used") == 1
                else "absent"
            ),
            "option1_recovery_canary_launch_limit": 1,
            "option1_recovery_canary_attempt_limit": 1,
            "option1_recovery_canary_exact_confirmation_cli_present": True,
            "option1_recovery_canary_ordinary_or_http_launch_route_present": False,
            **recovery_accounting,
            "option1_recovery_canary_result_review_state": (
                recovery_result_review_state
            ),
            "option1_recovery_canary_result_reviewed": (
                recovery_result_reviewed
            ),
            "option2_service_identity_and_vault_plan_state": (
                option2_plan_contract_state
            ),
            "option2_service_identity_and_vault_plan_sha256": option2_plan[
                "plan_sha256"
            ],
            "option2_plan_owner_review_state": option2_plan_review_state,
            "option2_plan_owner_reviewed": option2_plan_reviewed,
            "option2_provisioner_contract_state": option2_manifest_contract_state,
            "option2_provisioner_dry_run_state": (
                option2_provisioner_qualification_state
            ),
            "option2_provisioner_dry_run_qualified": (
                option2_provisioner_qualified
            ),
            "option2_provisioning_manifest_review_state": (
                option2_manifest_review_state
            ),
            "option2_provisioning_manifest_owner_reviewed": (
                option2_manifest_reviewed
            ),
            "option2_identity_candidate_resolver_state": (
                option2_identity_candidate_state
            ),
            "option2_identity_candidate_fixture_qualified": (
                option2_identity_candidate_qualified
            ),
            "option2_identity_candidate_host_preflight_state": (
                option2_host_candidate_state
            ),
            "option2_identity_candidate_host_preflight_recovery_state": (
                option2_host_recovery_state
            ),
            "option2_host_preflight_recovery_design_reviewed": True,
            "option2_host_preflight_recovery_implementation_state": (
                OPTION2_HOST_PREFLIGHT_RECOVERY_STATE
            ),
            "option2_host_preflight_recovery_owner_authorized": False,
            "option2_host_preflight_recovery_authorization_state": (
                "absent"
                if option2_host_recovery_state
                == OPTION2_HOST_PREFLIGHT_RECOVERY_STATE
                else "consumed"
            ),
            "option2_host_preflight_recovery_claim_limit": 1,
            "option2_host_preflight_recovery_candidate_limit": 1,
            "option2_host_preflight_recovery_exact_confirmation_cli_present": True,
            "option2_host_preflight_recovery_ordinary_or_http_route_present": False,
            "option2_host_preflight_recovery_predecessor_claim_id": (
                option2_host_recovery_predecessor_record.get("id")
                if isinstance(option2_host_recovery_predecessor_record, Mapping)
                else None
            ),
            "option2_host_preflight_recovery_predecessor_claim_sha256": (
                option2_host_recovery_predecessor_record.get("content_sha256")
                if isinstance(option2_host_recovery_predecessor_record, Mapping)
                else None
            ),
            "option2_host_preflight_recovery_original_claim_reopened": False,
            "option2_host_preflight_recovery_raw_inventory_persisted": False,
            "option2_host_preflight_recovery_raw_inventory_returned": False,
            "option2_host_preflight_recovery_result_review_state": (
                option2_host_recovery_result_review_state
            ),
            "option2_host_preflight_recovery_result_reviewed": (
                option2_host_recovery_result_reviewed
            ),
            "option2_point_action_contract_state": (
                option2_point_action_contract_state
            ),
            "option2_point_action_contract_sha256": (
                option2_point_action_contract["contract_sha256"]
            ),
            "option2_point_action_qualification_state": (
                option2_point_action_qualification_state
            ),
            "option2_point_action_fixture_qualified": (
                option2_point_action_qualified
            ),
            "option2_point_action_expired_candidate_reused": False,
            "option2_point_action_host_query_present": False,
            "option2_point_action_host_apply_present": False,
            "option2_point_action_administrator_prompt_present": False,
            "option2_point_action_future_preflight_implementation_present": False,
            "option2_point_action_future_provisioning_implementation_present": False,
            "option2_point_action_production_preflight_qualified": False,
            "option2_point_action_production_rollback_qualified": False,
            "option2_point_action_ordinary_or_http_route_present": False,
            "option2_native_preflight_contract_state": (
                OPTION2_NATIVE_PREFLIGHT_STATE
                if option2_point_action_qualified
                else "not_applicable"
            ),
            "option2_native_preflight_contract_sha256": (
                option2_native_preflight_content.get("contract_sha256")
                if isinstance(option2_native_preflight_content, Mapping)
                else None
            ),
            "option2_native_preflight_qualification_state": (
                option2_native_preflight_qualification_state
            ),
            "option2_native_preflight_fixture_qualified": (
                option2_native_preflight_qualified
            ),
            "option2_native_preflight_fixture_case_count": (
                option2_native_preflight_content.get(
                    "native_fixture_case_count"
                )
                if isinstance(option2_native_preflight_content, Mapping)
                else 0
            ),
            "option2_native_claim_ledger_core_implemented": True,
            "option2_native_claim_ledger_crash_fixture_qualified": (
                option2_native_preflight_qualified
            ),
            "option2_native_claim_durability_order_projection_qualified": (
                option2_native_preflight_qualified
            ),
            "option2_native_durable_filesystem_io_verified": False,
            "option2_native_independent_anchor_verified": False,
            "option2_native_whole_host_snapshot_rollback_resistance_qualified": False,
            "option2_native_production_host_adapter_present": False,
            "option2_native_production_durable_ledger_adapter_present": False,
            "option2_native_production_anti_rollback_anchor_present": False,
            "option2_native_root_owned_installation_present": False,
            "option2_native_separately_signed_installation_present": False,
            "option2_native_administrator_prompt_present": False,
            "option2_native_point_action_host_query_present": False,
            "option2_native_identity_mutation_present": False,
            "option2_native_network_route_present": False,
            "option2_native_atlas_execution_route_present": False,
            "option2_native_production_preflight_qualified": False,
            "option2_native_production_rollback_qualified": False,
            "option2_native_ordinary_or_http_route_present": False,
            "option2_identity_candidate_host_inspected": bool(
                isinstance(option2_host_candidate_content, Mapping)
                and option2_host_candidate_content.get("host_preflight_performed")
                is True
            ),
            "option2_host_candidate_active": option2_host_candidate_active,
            "option2_host_candidate_sha256": (
                option2_host_candidate_content.get("candidate_sha256")
                if isinstance(option2_host_candidate_content, Mapping)
                else None
            ),
            "option2_host_inventory_sha256": (
                option2_host_candidate_content.get("inventory_sha256")
                if isinstance(option2_host_candidate_content, Mapping)
                else None
            ),
            "option2_host_candidate_expires_at": (
                option2_host_candidate_content.get("expires_at")
                if isinstance(option2_host_candidate_content, Mapping)
                else None
            ),
            "option2_host_raw_inventory_persisted": False,
            "option2_host_raw_inventory_returned": False,
            "option2_service_identity_provisioning_manifest_state": (
                option2_manifest_contract_state
            ),
            "option2_service_identity_provisioning_manifest_sha256": (
                option2_manifest["manifest_sha256"]
            ),
            "option2_production_manifest_complete": False,
            "option2_host_apply_present": False,
            "option2_production_paths_configured": (
                self._option2_production_paths_configured_count()
            ),
            "option2_service_identity_state": "not_provisioned",
            "option2_vault_state": "not_provisioned",
            "option2_key_custody_state": "absent",
            "option2_access_change_state": "not_performed",
            "option2_background_service_state": "not_installed",
            "option2_provisioning_authorized": False,
            "option2_service_identity_gate_satisfied": False,
            "live_owner_authorized": False,
            "next_gate": self._option1_combined_next_gate(
                canary_accounting,
                recovery_accounting,
                recovery_result_reviewed=recovery_result_reviewed,
                option2_plan_reviewed=option2_plan_reviewed,
                option2_provisioner_qualified=option2_provisioner_qualified,
                option2_manifest_reviewed=option2_manifest_reviewed,
                option2_identity_candidate_qualified=(
                    option2_identity_candidate_qualified
                ),
                option2_host_candidate_active=option2_host_candidate_active,
                option2_host_candidate_state=option2_host_candidate_state,
                option2_host_recovery_state=option2_host_recovery_state,
                option2_host_recovery_result_review_state=(
                    option2_host_recovery_result_review_state
                ),
                option2_host_recovery_result_reviewed=(
                    option2_host_recovery_result_reviewed
                ),
                option2_point_action_qualification_state=(
                    option2_point_action_qualification_state
                ),
                option2_point_action_qualified=option2_point_action_qualified,
                option2_native_preflight_qualification_state=(
                    option2_native_preflight_qualification_state
                ),
                option2_native_preflight_qualified=(
                    option2_native_preflight_qualified
                ),
            ),
            "live_blockers": [
                *([canary_blocker] if canary_blocker is not None else []),
                *([recovery_blocker] if recovery_blocker is not None else []),
                *(
                    [recovery_result_review_blocker]
                    if recovery_result_review_blocker is not None
                    else []
                ),
                *(
                    [option2_plan_review_blocker]
                    if option2_plan_review_blocker is not None
                    else []
                ),
                *(
                    [option2_provisioner_qualification_blocker]
                    if option2_provisioner_qualification_blocker is not None
                    else []
                ),
                *(
                    [option2_manifest_review_blocker]
                    if option2_manifest_review_blocker is not None
                    else []
                ),
                *(
                    [option2_identity_candidate_blocker]
                    if option2_identity_candidate_blocker is not None
                    else []
                ),
                *(
                    [option2_host_candidate_blocker]
                    if option2_host_candidate_blocker is not None
                    else []
                ),
                *(
                    [option2_host_recovery_blocker]
                    if option2_host_recovery_blocker is not None
                    and not option2_host_recovery_result_reviewed
                    else []
                ),
                *(
                    [option2_host_recovery_result_review_blocker]
                    if option2_host_recovery_result_review_blocker is not None
                    else []
                ),
                *(
                    [option2_point_action_qualification_blocker]
                    if option2_point_action_qualification_blocker is not None
                    else []
                ),
                *(
                    [option2_native_preflight_qualification_blocker]
                    if option2_native_preflight_qualification_blocker is not None
                    else []
                ),
                *(
                    [
                        "option2_identity_only_host_preflight_recovery_owner_authorization_required"
                    ]
                    if option2_identity_candidate_qualified
                    and not option2_host_candidate_active
                    and option2_host_recovery_state
                    == OPTION2_HOST_PREFLIGHT_RECOVERY_STATE
                    else []
                ),
                *(
                    ["option2_identity_only_host_preflight_owner_review_required"]
                    if option2_identity_candidate_qualified
                    and not option2_host_candidate_active
                    and option2_host_recovery_state
                    != OPTION2_HOST_PREFLIGHT_RECOVERY_STATE
                    and not option2_host_recovery_result_reviewed
                    else []
                ),
                *(
                    ["option2_native_preflight_installation_and_signing_plan_owner_review_required"]
                    if option2_native_preflight_qualified
                    else []
                ),
                *(
                    ["option2_legacy_identity_candidate_non_authorizing_review_required"]
                    if option2_host_candidate_active
                    else []
                ),
                "owner_controlled_service_identity_not_provisioned",
                "durable_broker_state_not_configured",
                "vault_adapter_not_connected",
                "live_owner_authorization_absent",
                "owner_policy_broker_not_configured",
                "owner_policy_verification_key_not_configured",
                "short_lived_credential_broker_not_configured",
                "credential_broker_verification_key_not_configured",
                "receipt_verification_key_not_configured",
                "external_receipt_anchor_not_configured",
                "owner_kill_switch_not_configured",
                "live_execution_structurally_absent",
            ],
        }

    def run_option1_synthetic_integration_canary(
        self,
        *,
        confirmation: str,
    ) -> dict[str, object]:
        """Launch the separately gated one-shot synthetic canary.

        No ordinary startup, HTTP route, background service, model/provider
        client, or caller-selected credential target reaches this method.
        """

        from atlas_core.supervisor_v4_option1_canary import (
            CANARY_CONFIRMATION,
            Option1CanaryViolation,
            claim_canary_launch,
            finalize_canary_launch,
        )

        if not isinstance(confirmation, str) or not hmac.compare_digest(
            confirmation, CANARY_CONFIRMATION
        ):
            raise SupervisorError("option1_canary_confirmation_invalid")
        if sys.platform != "darwin":
            raise SupervisorError("option1_canary_platform_unsupported")
        if (
            not self.enabled
            or not self.config.supervisor_v4.offline_qualification_enabled
            or not self.config.supervisor_v4.same_user_broker_qualification_enabled
            or self.config.supervisor_v4.same_user_broker_mode
            != "offline_synthetic_qualification"
            or self.config.supervisor_v4.pause_file.exists()
        ):
            raise SupervisorError("option1_canary_supervisor_state_invalid")
        policy_projection = self.config.supervisor_v4_policy
        if policy_projection is None:
            raise SupervisorError("option1_canary_policy_unavailable")
        action_flags = (
            "background_execution",
            "live_model_execution",
            "live_canary_execution",
            "canonical_mutations",
            "candidate_application",
            "external_actions",
            "command_network_access",
            "model_side_commands",
            "model_side_file_changes",
            "model_side_tools",
            "approval_requests",
            "experimental_api",
        )
        if any(getattr(policy_projection, field) is not False for field in action_flags):
            raise SupervisorError("option1_canary_live_control_open")
        trust_fields = (
            "owner_policy_broker_socket",
            "owner_policy_verification_key_file",
            "credential_broker_socket",
            "credential_broker_verification_key_file",
            "receipt_verification_key_file",
            "receipt_anchor_broker_socket",
            "receipt_anchor_verification_key_file",
            "owner_kill_switch_socket",
            "owner_kill_switch_verification_key_file",
        )
        if any(
            getattr(self.config.supervisor_v4, field) is not None
            for field in trust_fields
        ):
            raise SupervisorError("option1_canary_production_trust_present")

        mismatches: list[str] = []
        bundle = self._seal_runtime_bundle()
        sealed_policy = self._sealed_policy(bundle, mismatches)
        if sealed_policy is None:
            raise SupervisorError("option1_canary_policy_unavailable")
        if bundle.member("protocol").sha256 != sealed_policy.protocol_inventory_sha256:
            mismatches.append("contract-bound protocol inventory digest drifted")
        if bundle.member("sdk_lock").sha256 != sealed_policy.sdk_lock_sha256:
            mismatches.append("contract-bound SDK lock digest drifted")
        lock = self._load_lock(bundle.member("sdk_lock"), mismatches)
        self._inspect_source_pins(lock, mismatches)
        self._inspect_loaded_source_bindings(bundle, lock, mismatches)
        expected_registry = (
            ((lock.get("executor") or {}).get("source_sha256") or {}).get(
                "config/supervisor_v4_same_user_registry.json"
            )
        )
        if (
            not isinstance(expected_registry, str)
            or expected_registry == "0" * 64
            or bundle.member("same_user_registry").sha256 != expected_registry
        ):
            mismatches.append("loaded Supervisor v4 same-user registry drifted")

        sandbox_exec = _TRUSTED_PLATFORM_TOOL_PATHS["sandbox_exec"]
        sandbox_pin = (lock.get("local_tools") or {}).get("sandbox_exec") or {}
        try:
            sandbox_metadata = sandbox_exec.lstat()
            sandbox_valid = (
                sandbox_exec.resolve(strict=True) == sandbox_exec
                and stat.S_ISREG(sandbox_metadata.st_mode)
                and sandbox_metadata.st_nlink == 1
                and sandbox_metadata.st_uid == 0
                and not stat.S_IMODE(sandbox_metadata.st_mode) & 0o022
                and os.access(sandbox_exec, os.X_OK)
                and sandbox_pin.get("path") == str(sandbox_exec)
                and sandbox_pin.get("owner_uid") == 0
                and _sha256_file(sandbox_exec) == sandbox_pin.get("sha256")
            )
        except OSError:
            sandbox_valid = False
        if not sandbox_valid:
            mismatches.append("pinned Option 1 canary sandbox drifted")

        runner = self.config.project_root / "scripts" / "option1_on_demand_canary.py"
        if mismatches:
            raise SupervisorError("option1_canary_source_attestation_failed")
        python_executable = _active_venv_python_executable(self.config.project_root)

        owner_home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True)
        runtime_root = (
            owner_home
            / "Library/Application Support/Atlas Core/runtime/supervisor-v4-option1"
        )
        try:
            launch_path, launch_claim = claim_canary_launch(
                runtime_root,
                confirmation=confirmation,
            )
        except Option1CanaryViolation as exc:
            raise SupervisorError(exc.code) from None

        def finalize_launch(
            *,
            parent_error_code: str | None,
            child_process_started: bool,
            child_process_completed: bool,
        ) -> dict[str, object]:
            try:
                return finalize_canary_launch(
                    launch_path,
                    launch_claim,
                    parent_error_code=parent_error_code,
                    child_process_started=child_process_started,
                    child_process_completed=child_process_completed,
                )
            except Option1CanaryViolation:
                raise SupervisorError(
                    "option1_canary_launch_receipt_finalize_failed"
                ) from None

        environment = {
            "HOME": str(owner_home),
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "TMPDIR": "/tmp",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONSAFEPATH": "1",
        }
        try:
            completed = run_supervised(
                [
                    str(python_executable),
                    "-I",
                    "-B",
                    str(runner),
                    "--root",
                    str(self.config.project_root),
                    "--confirm",
                    confirmation,
                    "--parent-pid",
                    str(os.getpid()),
                ],
                cwd=self.config.project_root,
                timeout=60.0,
                env=environment,
                pause_file=self.config.supervisor_v4.pause_file,
                max_output_bytes=64 * 1024,
            )
        except ProcessSupervisionError as exc:
            parent_error = "option1_canary_supervised_child_stopped_" + exc.code
            finalize_launch(
                parent_error_code=parent_error,
                child_process_started=exc.process_id is not None,
                child_process_completed=False,
            )
            raise SupervisorError(parent_error) from None
        except OSError:
            parent_error = "option1_canary_supervised_child_start_failed"
            finalize_launch(
                parent_error_code=parent_error,
                child_process_started=False,
                child_process_completed=False,
            )
            raise SupervisorError(parent_error) from None

        try:
            report = _validated_option1_canary_child_report(completed)
        except SupervisorError as exc:
            parent_error = str(exc)
            finalize_launch(
                parent_error_code=parent_error,
                child_process_started=True,
                child_process_completed=True,
            )
            raise SupervisorError(parent_error) from None
        launch_receipt = finalize_launch(
            parent_error_code=None,
            child_process_started=True,
            child_process_completed=True,
        )
        return {
            "version": 1,
            "classification": (
                "option1_atlas_facing_synthetic_integration_canary_supervised_result"
            ),
            "status": "passed",
            "canary_launch_receipt": launch_receipt,
            "canary_launch_evidence_sha256": launch_receipt["evidence_sha256"],
            "canary_receipt": report,
            "canary_evidence_sha256": report["evidence_sha256"],
            "broker_process_environment_scrubbed": True,
            "broker_process_network_guard_armed": True,
            "broker_process_os_network_sandboxed": False,
            "keychain_helper_os_network_sandboxed": True,
            "connector_os_network_sandboxed": True,
            "broker_process_group_reaped": True,
            "real_credential_used": False,
            "private_data_present": False,
            "network_accessed": False,
            "model_contacted": False,
            "provider_contacted": False,
            "background_service_enrolled": False,
            "ordinary_startup_wired": False,
            "live_authority_granted": False,
            "ready": False,
            "ready_offline": False,
            "ready_live": False,
        }

    def run_option1_synthetic_integration_recovery_canary(
        self,
        *,
        confirmation: str,
    ) -> dict[str, object]:
        """Launch only the separately gated, predecessor-bound recovery canary."""

        from atlas_core.supervisor_v4_option1_recovery_canary import (
            RECOVERY_CANARY_CONFIRMATION,
            Option1RecoveryCanaryViolation,
            attest_recovery_runtime_dependencies,
            claim_recovery_canary_launch,
            finalize_recovery_canary_launch,
        )

        if not isinstance(confirmation, str) or not hmac.compare_digest(
            confirmation, RECOVERY_CANARY_CONFIRMATION
        ):
            raise SupervisorError("option1_recovery_canary_confirmation_invalid")
        if sys.platform != "darwin":
            raise SupervisorError("option1_recovery_canary_platform_unsupported")
        if (
            not self.enabled
            or not self.config.supervisor_v4.offline_qualification_enabled
            or not self.config.supervisor_v4.same_user_broker_qualification_enabled
            or self.config.supervisor_v4.same_user_broker_mode
            != "offline_synthetic_qualification"
            or self.config.supervisor_v4.pause_file.exists()
        ):
            raise SupervisorError("option1_recovery_canary_supervisor_state_invalid")
        policy_projection = self.config.supervisor_v4_policy
        if policy_projection is None:
            raise SupervisorError("option1_recovery_canary_policy_unavailable")
        action_flags = (
            "background_execution",
            "live_model_execution",
            "live_canary_execution",
            "canonical_mutations",
            "candidate_application",
            "external_actions",
            "command_network_access",
            "model_side_commands",
            "model_side_file_changes",
            "model_side_tools",
            "approval_requests",
            "experimental_api",
        )
        if any(getattr(policy_projection, field) is not False for field in action_flags):
            raise SupervisorError("option1_recovery_canary_live_control_open")
        trust_fields = (
            "owner_policy_broker_socket",
            "owner_policy_verification_key_file",
            "credential_broker_socket",
            "credential_broker_verification_key_file",
            "receipt_verification_key_file",
            "receipt_anchor_broker_socket",
            "receipt_anchor_verification_key_file",
            "owner_kill_switch_socket",
            "owner_kill_switch_verification_key_file",
        )
        if any(
            getattr(self.config.supervisor_v4, field) is not None
            for field in trust_fields
        ):
            raise SupervisorError("option1_recovery_canary_production_trust_present")

        mismatches: list[str] = []
        bundle = self._seal_runtime_bundle()
        sealed_policy = self._sealed_policy(bundle, mismatches)
        if sealed_policy is None:
            raise SupervisorError("option1_recovery_canary_policy_unavailable")
        if bundle.member("protocol").sha256 != sealed_policy.protocol_inventory_sha256:
            mismatches.append("contract-bound protocol inventory digest drifted")
        if bundle.member("sdk_lock").sha256 != sealed_policy.sdk_lock_sha256:
            mismatches.append("contract-bound SDK lock digest drifted")
        lock = self._load_lock(bundle.member("sdk_lock"), mismatches)
        self._inspect_source_pins(lock, mismatches)
        self._inspect_loaded_source_bindings(bundle, lock, mismatches)
        expected_registry = (
            ((lock.get("executor") or {}).get("source_sha256") or {}).get(
                "config/supervisor_v4_same_user_registry.json"
            )
        )
        if (
            not isinstance(expected_registry, str)
            or expected_registry == "0" * 64
            or bundle.member("same_user_registry").sha256 != expected_registry
        ):
            mismatches.append("loaded Supervisor v4 same-user registry drifted")

        sandbox_exec = _TRUSTED_PLATFORM_TOOL_PATHS["sandbox_exec"]
        sandbox_pin = (lock.get("local_tools") or {}).get("sandbox_exec") or {}
        try:
            sandbox_metadata = sandbox_exec.lstat()
            sandbox_valid = (
                sandbox_exec.resolve(strict=True) == sandbox_exec
                and stat.S_ISREG(sandbox_metadata.st_mode)
                and sandbox_metadata.st_nlink == 1
                and sandbox_metadata.st_uid == 0
                and not stat.S_IMODE(sandbox_metadata.st_mode) & 0o022
                and os.access(sandbox_exec, os.X_OK)
                and sandbox_pin.get("path") == str(sandbox_exec)
                and sandbox_pin.get("owner_uid") == 0
                and _sha256_file(sandbox_exec) == sandbox_pin.get("sha256")
            )
        except OSError:
            sandbox_valid = False
        if not sandbox_valid:
            mismatches.append("pinned Option 1 recovery canary sandbox drifted")

        runner = (
            self.config.project_root
            / "scripts"
            / "option1_on_demand_recovery_canary.py"
        )
        if mismatches:
            raise SupervisorError("option1_recovery_canary_source_attestation_failed")
        python_executable = _active_venv_python_executable(self.config.project_root)
        try:
            attest_recovery_runtime_dependencies(
                lock,
                expected_python_executable=python_executable,
            )
        except Option1RecoveryCanaryViolation as exc:
            raise SupervisorError(exc.code) from None

        owner_home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True)
        runtime_root = (
            owner_home
            / "Library/Application Support/Atlas Core/runtime/supervisor-v4-option1"
        )
        try:
            launch_path, launch_claim = claim_recovery_canary_launch(
                runtime_root,
                confirmation=confirmation,
            )
        except Option1RecoveryCanaryViolation as exc:
            raise SupervisorError(exc.code) from None

        def finalize_launch(
            *,
            parent_error_code: str | None,
            child_process_started: bool,
            child_process_completed: bool,
        ) -> dict[str, object]:
            try:
                return finalize_recovery_canary_launch(
                    launch_path,
                    launch_claim,
                    parent_error_code=parent_error_code,
                    child_process_started=child_process_started,
                    child_process_completed=child_process_completed,
                )
            except Option1RecoveryCanaryViolation:
                raise SupervisorError(
                    "option1_recovery_canary_launch_receipt_finalize_failed"
                ) from None

        environment = {
            "HOME": str(owner_home),
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "TMPDIR": "/tmp",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONSAFEPATH": "1",
        }
        try:
            completed = run_supervised(
                [
                    str(python_executable),
                    "-I",
                    "-B",
                    str(runner),
                    "--root",
                    str(self.config.project_root),
                    "--confirm",
                    confirmation,
                    "--parent-pid",
                    str(os.getpid()),
                ],
                cwd=self.config.project_root,
                timeout=60.0,
                env=environment,
                pause_file=self.config.supervisor_v4.pause_file,
                max_output_bytes=64 * 1024,
            )
        except ProcessSupervisionError as exc:
            parent_error = (
                "option1_recovery_canary_supervised_child_stopped_" + exc.code
            )
            finalize_launch(
                parent_error_code=parent_error,
                child_process_started=exc.process_id is not None,
                child_process_completed=False,
            )
            raise SupervisorError(parent_error) from None
        except OSError:
            parent_error = "option1_recovery_canary_supervised_child_start_failed"
            finalize_launch(
                parent_error_code=parent_error,
                child_process_started=False,
                child_process_completed=False,
            )
            raise SupervisorError(parent_error) from None

        try:
            report = _validated_option1_recovery_canary_child_report(completed)
        except SupervisorError as exc:
            parent_error = str(exc)
            finalize_launch(
                parent_error_code=parent_error,
                child_process_started=True,
                child_process_completed=True,
            )
            raise SupervisorError(parent_error) from None
        launch_receipt = finalize_launch(
            parent_error_code=None,
            child_process_started=True,
            child_process_completed=True,
        )
        return {
            "version": 1,
            "classification": (
                "option1_atlas_facing_synthetic_integration_recovery_canary_supervised_result"
            ),
            "status": "passed",
            "recovery_canary_launch_receipt": launch_receipt,
            "recovery_canary_launch_evidence_sha256": launch_receipt[
                "evidence_sha256"
            ],
            "recovery_canary_receipt": report,
            "recovery_canary_evidence_sha256": report["evidence_sha256"],
            "broker_process_environment_scrubbed": True,
            "broker_process_network_guard_armed": True,
            "broker_process_os_network_sandboxed": False,
            "keychain_helper_os_network_sandboxed": True,
            "connector_os_network_sandboxed": True,
            "broker_process_group_reaped": True,
            "real_credential_used": False,
            "private_data_present": False,
            "network_accessed": False,
            "model_contacted": False,
            "provider_contacted": False,
            "background_service_enrolled": False,
            "ordinary_startup_wired": False,
            "live_authority_granted": False,
            "ready": False,
            "ready_offline": False,
            "ready_live": False,
        }

    def _seal_runtime_bundle(self) -> ImmutablePolicyBundle:
        probe = self.config.project_root / "scripts" / "supervisor_v4_sdk_probe.py"
        same_user_probe = (
            self.config.project_root / "scripts" / "supervisor_v4_same_user_probe.py"
        )
        members = {
            "contract": self.config.app.supervisor_v4_contract_file,
            "protocol": self.config.app.supervisor_v4_protocol_file,
            "sdk_lock": self.config.app.supervisor_v4_lock_file,
            "replays": self.config.app.supervisor_v4_replay_file,
            "service_source": Path(__file__).resolve(),
            "database_source": _resolved_module_source(
                "atlas_core.memory.database"
            ),
            "adapter_source": _resolved_module_source(
                "atlas_core.supervisor_v4_protocol"
            ),
            "live_contract_source": _resolved_module_source(
                "atlas_core.supervisor_v4_live_contract"
            ),
            "offline_source": _resolved_module_source(
                "atlas_core.supervisor_v4_offline"
            ),
            "offline_audit_source": _resolved_module_source(
                "atlas_core.supervisor_v4_offline_audit"
            ),
            "offline_broker_qualification_source": _resolved_module_source(
                "atlas_core.supervisor_v4_offline_broker_qualification"
            ),
            "offline_credential_broker_source": _resolved_module_source(
                "atlas_core.supervisor_v4_offline_credential_broker"
            ),
            "offline_crypto_source": _resolved_module_source(
                "atlas_core.supervisor_v4_offline_crypto"
            ),
            "offline_external_broker_source": _resolved_module_source(
                "atlas_core.supervisor_v4_offline_external_broker"
            ),
            "offline_policy_broker_source": _resolved_module_source(
                "atlas_core.supervisor_v4_offline_policy_broker"
            ),
            "process_source": _resolved_module_source(
                "atlas_core.supervisor_v4_process"
            ),
            "option1_canary_source": _resolved_module_source(
                "atlas_core.supervisor_v4_option1_canary"
            ),
            "option1_canary_runner_source": (
                self.config.project_root / "scripts" / "option1_on_demand_canary.py"
            ),
            "option1_recovery_canary_source": _resolved_module_source(
                "atlas_core.supervisor_v4_option1_recovery_canary"
            ),
            "option1_recovery_canary_runner_source": (
                self.config.project_root
                / "scripts"
                / "option1_on_demand_recovery_canary.py"
            ),
            "option2_plan_source": _resolved_module_source(
                "atlas_core.supervisor_v4_option2_plan"
            ),
            "option2_provisioner_source": _resolved_module_source(
                "atlas_core.supervisor_v4_option2_provisioner"
            ),
            "option2_manifest_review_source": _resolved_module_source(
                "atlas_core.supervisor_v4_option2_manifest_review"
            ),
            "option2_identity_candidate_source": _resolved_module_source(
                "atlas_core.supervisor_v4_option2_identity_candidate"
            ),
            "option2_host_preflight_source": _resolved_module_source(
                "atlas_core.supervisor_v4_option2_host_preflight"
            ),
            "option2_host_preflight_recovery_source": _resolved_module_source(
                "atlas_core.supervisor_v4_option2_host_preflight_recovery"
            ),
            "option2_point_action_source": _resolved_module_source(
                "atlas_core.supervisor_v4_option2_point_action"
            ),
            "option2_native_preflight_source": _resolved_module_source(
                "atlas_core.supervisor_v4_option2_native_preflight"
            ),
            "option2_native_bound_request_source": (
                self.config.project_root
                / "native"
                / "option2_identity_preflight"
                / "BoundRequest.swift"
            ),
            "option2_native_canonical_json_source": (
                self.config.project_root
                / "native"
                / "option2_identity_preflight"
                / "CanonicalJSON.swift"
            ),
            "option2_native_claim_ledger_source": (
                self.config.project_root
                / "native"
                / "option2_identity_preflight"
                / "ClaimLedger.swift"
            ),
            "option2_native_offline_fixtures_source": (
                self.config.project_root
                / "native"
                / "option2_identity_preflight"
                / "OfflineFixtures.swift"
            ),
            "option2_native_fixture_main_source": (
                self.config.project_root
                / "native"
                / "option2_identity_preflight"
                / "Option2FixtureMain.swift"
            ),
            "option2_native_preflight_evaluator_source": (
                self.config.project_root
                / "native"
                / "option2_identity_preflight"
                / "PreflightEvaluator.swift"
            ),
            "option2_native_fixture_report": (
                self.config.project_root
                / "src"
                / "atlas_core"
                / "resources"
                / "supervisor_v4_option2_native_preflight_qualification.json"
            ),
            "same_user_broker_source": _resolved_module_source(
                "atlas_core.supervisor_v4_same_user_broker"
            ),
            "same_user_connector_source": _resolved_module_source(
                "atlas_core.supervisor_v4_same_user_connector"
            ),
            "same_user_qualification_source": _resolved_module_source(
                "atlas_core.supervisor_v4_same_user_qualification"
            ),
            "same_user_state_source": _resolved_module_source(
                "atlas_core.supervisor_v4_same_user_state"
            ),
            "same_user_probe_source": same_user_probe,
            "sdk_probe_source": probe,
        }
        if self.config.supervisor_v4.same_user_broker_qualification_enabled:
            members["same_user_registry"] = (
                self.config.app.supervisor_v4_same_user_registry_file
            )
        return seal_policy_bundle(members)

    def _sealed_policy(
        self,
        bundle: ImmutablePolicyBundle,
        mismatches: list[str],
    ) -> SupervisorV4PolicyConfig | None:
        """Parse and resolve only the contract bytes in the sealed snapshot."""

        try:
            raw = _unique_yaml(bundle.member("contract").content)
            policy = SupervisorV4PolicyConfig.model_validate(raw)
        except (SupervisorError, ValueError) as exc:
            mismatches.append(f"sealed Supervisor v4 contract is invalid: {str(exc)[:160]}")
            return None
        pin = policy.protocol_pin
        for field in ("binary_path", "sdk_python_path", "artifact_dir"):
            value = Path(getattr(pin, field))
            setattr(
                pin,
                field,
                value if value.is_absolute() else (self.config.project_root / value).resolve(),
            )
        loaded = self.config.supervisor_v4_policy
        if loaded is None or policy.model_dump(mode="json") != loaded.model_dump(mode="json"):
            mismatches.append("sealed Supervisor v4 contract differs from startup projection")
        return policy

    @staticmethod
    def _load_lock(member: SealedBundleMember, mismatches: list[str]) -> dict[str, Any]:
        def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            value: dict[str, Any] = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError("duplicate SDK lock key")
                value[key] = item
            return value

        try:
            lock = json.loads(member.content, object_pairs_hook=unique_object)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            mismatches.append("SDK lock is unreadable")
            return {}
        if not isinstance(lock, dict) or lock.get("format") != "atlas-supervisor-v4-sdk-lock":
            mismatches.append("SDK lock format drifted")
            return {}
        return lock

    def _inspect_artifacts(
        self,
        policy: SupervisorV4PolicyConfig,
        mismatches: list[str],
    ) -> dict[str, dict[str, Any]]:
        results: dict[str, dict[str, Any]] = {}
        for name, pin in sorted(policy.protocol_pin.artifacts.items()):
            path = policy.protocol_pin.artifact_dir / pin.filename
            try:
                actual = _sha256_bytes(
                    _read_regular_no_follow(path, max_bytes=_MAX_RUNTIME_FILE_BYTES)
                )
            except (OSError, SupervisorError):
                actual = None
            results[name] = {
                "version": pin.version,
                "filename": pin.filename,
                "sha256": actual,
                "matches": actual == pin.sha256,
            }
            if actual != pin.sha256:
                mismatches.append(f"SDK artifact drifted: {name}")
        return results

    def _inspect_runtime_files(
        self,
        policy: SupervisorV4PolicyConfig,
        lock: Mapping[str, Any],
        mismatches: list[str],
    ) -> dict[str, Any]:
        pin = policy.protocol_pin
        binary = pin.binary_path
        python = pin.sdk_python_path
        result: dict[str, Any] = {}
        for path, label, expected in (
            (binary, "Codex binary", pin.binary_sha256),
            (python, "SDK Python", str((lock.get("python") or {}).get("executable_sha256") or "")),
            (
                python.parent.parent / "pyvenv.cfg",
                "SDK pyvenv configuration",
                str((lock.get("python") or {}).get("pyvenv_sha256") or ""),
            ),
        ):
            try:
                content = _read_regular_no_follow(path, max_bytes=_MAX_RUNTIME_FILE_BYTES)
                observed = _sha256_bytes(content)
            except (OSError, SupervisorError):
                observed = None
            result[label] = {"sha256": observed, "matches": observed == expected}
            if not expected or observed != expected:
                mismatches.append(f"pinned {label} drifted")

        version_parts = policy.protocol_pin.python_version.split(".")
        site_packages = (
            python.parent.parent
            / "lib"
            / f"python{version_parts[0]}.{version_parts[1]}"
            / "site-packages"
        )
        expected_count = (lock.get("python") or {}).get("site_packages_file_count")
        expected_manifest = (lock.get("python") or {}).get(
            "site_packages_manifest_sha256"
        )
        try:
            observed_count, observed_manifest = _site_packages_manifest(site_packages)
        except (OSError, SupervisorError):
            observed_count, observed_manifest = 0, None
        result["site_packages"] = {
            "file_count": observed_count,
            "manifest_sha256": observed_manifest,
            "matches": observed_count == expected_count
            and observed_manifest == expected_manifest,
        }
        if not expected_manifest or not result["site_packages"]["matches"]:
            mismatches.append("pinned SDK site-packages tree drifted")
        base_root_text = (lock.get("python") or {}).get("base_readable_root")
        expected_base_count = (lock.get("python") or {}).get("base_file_count")
        expected_base_manifest = (lock.get("python") or {}).get(
            "base_manifest_sha256"
        )
        base_root = Path(str(base_root_text)) if base_root_text else Path()
        try:
            if not base_root.is_absolute():
                raise SupervisorError("Supervisor v4 Python base root is not absolute")
            base_count, base_manifest = _runtime_tree_manifest(base_root)
        except (OSError, SupervisorError):
            base_count, base_manifest = 0, None
        result["python_base"] = {
            "root": str(base_root) if base_root_text else None,
            "file_count": base_count,
            "manifest_sha256": base_manifest,
            "matches": base_count == expected_base_count
            and base_manifest == expected_base_manifest,
        }
        if not expected_base_manifest or not result["python_base"]["matches"]:
            mismatches.append("pinned Python base runtime drifted")
        return result

    def _stage_python_runtime(
        self,
        policy: SupervisorV4PolicyConfig,
        lock: Mapping[str, Any],
        destination: Path,
        mismatches: list[str],
    ) -> StagedPythonRuntime | None:
        """Create and re-attest the exact Python/import tree used by the probe."""

        python_lock = lock.get("python") or {}
        if not isinstance(python_lock, Mapping):
            mismatches.append("SDK lock Python snapshot metadata is invalid")
            return None
        base_source_text = python_lock.get("base_readable_root")
        base_relative_text = python_lock.get("base_python_relative")
        if not isinstance(base_source_text, str) or not isinstance(
            base_relative_text, str
        ):
            mismatches.append("SDK lock Python snapshot path is unavailable")
            return None
        base_source = Path(base_source_text)
        base_relative = Path(base_relative_text)
        if (
            not base_source.is_absolute()
            or base_relative.is_absolute()
            or ".." in base_relative.parts
            or not base_relative.parts
        ):
            mismatches.append("SDK lock Python snapshot path is unsafe")
            return None
        version_parts = policy.protocol_pin.python_version.split(".")
        site_source = (
            policy.protocol_pin.sdk_python_path.parent.parent
            / "lib"
            / f"python{version_parts[0]}.{version_parts[1]}"
            / "site-packages"
        )
        dyld_root = destination / "dyld-root"
        base_snapshot = dyld_root / base_source.relative_to(base_source.anchor)
        site_snapshot = destination / "site-packages"
        try:
            _copy_runtime_snapshot_tree(
                base_source,
                base_snapshot,
                allow_internal_symlinks=True,
            )
            _copy_runtime_snapshot_tree(
                site_source,
                site_snapshot,
                allow_internal_symlinks=False,
            )
            base_count, base_manifest = _runtime_tree_manifest(base_snapshot)
            site_count, site_manifest = _site_packages_manifest(site_snapshot)
            staged_python = base_snapshot / base_relative
            _read_regular_no_follow(
                staged_python, max_bytes=_MAX_RUNTIME_FILE_BYTES
            )
        except (OSError, SupervisorError):
            mismatches.append("private Python runtime snapshot failed")
            return None
        if (
            base_count != python_lock.get("base_file_count")
            or base_manifest != python_lock.get("base_manifest_sha256")
            or site_count != python_lock.get("site_packages_file_count")
            or site_manifest != python_lock.get("site_packages_manifest_sha256")
        ):
            mismatches.append("private Python runtime snapshot drifted")
            return None
        return StagedPythonRuntime(
            python=staged_python,
            dyld_root=dyld_root,
            base_root=base_snapshot,
            site_packages=site_snapshot,
            base_file_count=base_count,
            base_manifest_sha256=base_manifest,
            site_packages_file_count=site_count,
            site_packages_manifest_sha256=site_manifest,
        )

    def _stage_option1_dependencies(
        self,
        lock: Mapping[str, Any],
        destination: Path,
        mismatches: list[str],
    ) -> StagedOption1Dependencies | None:
        """Privately stage the exact non-SDK imports used by Option 1."""

        configured = lock.get("option1_crypto_dependencies") or {}
        if not isinstance(configured, Mapping):
            mismatches.append("Option 1 dependency lock metadata is invalid")
            return None
        cryptography_version = configured.get("cryptography_version")
        cryptography_file_count = configured.get("cryptography_file_count")
        cryptography_manifest = configured.get("cryptography_manifest_sha256")
        cffi_version = configured.get("cffi_version")
        cffi_backend_filename = configured.get("cffi_backend_filename")
        cffi_backend_sha256 = configured.get("cffi_backend_sha256")
        if (
            not isinstance(cryptography_version, str)
            or type(cryptography_file_count) is not int
            or not isinstance(cryptography_manifest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", cryptography_manifest)
            or not isinstance(cffi_version, str)
            or not isinstance(cffi_backend_filename, str)
            or not re.fullmatch(
                r"_cffi_backend\.[A-Za-z0-9_.-]{1,80}\.so",
                cffi_backend_filename,
            )
            or not isinstance(cffi_backend_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", cffi_backend_sha256)
        ):
            mismatches.append("Option 1 dependency lock metadata is invalid")
            return None
        try:
            observed_cryptography_version = importlib.metadata.version("cryptography")
            observed_cffi_version = importlib.metadata.version("cffi")
            cryptography_spec = importlib.util.find_spec("cryptography")
            cffi_backend_spec = importlib.util.find_spec("_cffi_backend")
            locations = tuple(
                cryptography_spec.submodule_search_locations or ()
            ) if cryptography_spec is not None else ()
            if (
                len(locations) != 1
                or cffi_backend_spec is None
                or not isinstance(cffi_backend_spec.origin, str)
            ):
                raise SupervisorError("Option 1 dependency source is unavailable")
            cryptography_candidate = Path(locations[0])
            cffi_backend_candidate = Path(cffi_backend_spec.origin)
            if cryptography_candidate.is_symlink() or cffi_backend_candidate.is_symlink():
                raise SupervisorError("Option 1 dependency source is unsafe")
            cryptography_source = cryptography_candidate.resolve(strict=True)
            cffi_backend_source = cffi_backend_candidate.resolve(strict=True)
            if (
                cryptography_source.name != "cryptography"
                or cffi_backend_source.name != cffi_backend_filename
                or cffi_backend_source.parent != cryptography_source.parent
            ):
                raise SupervisorError("Option 1 dependency source is unsafe")
            observed_count, observed_manifest = _site_packages_manifest(
                cryptography_source,
                max_files=1_000,
            )
            observed_backend_sha256 = _sha256_bytes(
                _read_regular_no_follow(
                    cffi_backend_source,
                    max_bytes=_MAX_RUNTIME_FILE_BYTES,
                )
            )
        except (
            OSError,
            SupervisorError,
            importlib.metadata.PackageNotFoundError,
        ):
            mismatches.append("Option 1 dependency attestation failed")
            return None
        if (
            observed_cryptography_version != cryptography_version
            or observed_cffi_version != cffi_version
            or observed_count != cryptography_file_count
            or observed_manifest != cryptography_manifest
            or observed_backend_sha256 != cffi_backend_sha256
        ):
            mismatches.append("pinned Option 1 dependency snapshot drifted")
            return None
        try:
            destination.mkdir(mode=0o700, parents=True, exist_ok=False)
            staged_cryptography = destination / "cryptography"
            _copy_runtime_snapshot_tree(
                cryptography_source,
                staged_cryptography,
                allow_internal_symlinks=False,
                max_files=1_000,
            )
            staged_backend = destination / cffi_backend_filename
            _copy_verified_regular(
                cffi_backend_source,
                staged_backend,
                expected_sha256=cffi_backend_sha256,
            )
            staged_count, staged_manifest = _site_packages_manifest(
                staged_cryptography,
                max_files=1_000,
            )
        except (OSError, SupervisorError):
            mismatches.append("private Option 1 dependency staging failed")
            return None
        if (
            staged_count != cryptography_file_count
            or staged_manifest != cryptography_manifest
            or _sha256_file(staged_backend) != cffi_backend_sha256
        ):
            mismatches.append("private Option 1 dependency staging drifted")
            return None
        return StagedOption1Dependencies(
            site_packages=destination,
            cryptography_version=cryptography_version,
            cryptography_file_count=cryptography_file_count,
            cryptography_manifest_sha256=cryptography_manifest,
            cffi_version=cffi_version,
            cffi_backend_filename=cffi_backend_filename,
            cffi_backend_sha256=cffi_backend_sha256,
        )

    def _stage_local_tools(
        self,
        lock: Mapping[str, Any],
        destination: Path,
        mismatches: list[str],
    ) -> StagedLocalTools | None:
        """Attest and privately stage every executable used by qualification."""

        configured = lock.get("local_tools") or {}
        if not isinstance(configured, Mapping):
            mismatches.append("SDK lock local-tool metadata is invalid")
            return None
        try:
            destination.mkdir(mode=0o700, parents=True, exist_ok=False)
        except OSError:
            mismatches.append("private local-tool staging directory failed")
            return None
        staged: dict[str, Path] = {}
        sources: dict[str, Path] = {}
        names = (
            "git",
            "sandbox_exec",
            "cmp",
            "nc",
            "install_name_tool",
            "codesign",
        )
        for name in names:
            item = configured.get(name)
            if not isinstance(item, Mapping):
                mismatches.append(f"SDK lock local tool is unavailable: {name}")
                continue
            source_text = item.get("path")
            digest = item.get("sha256")
            owner_uid = item.get("owner_uid")
            trusted_source = _TRUSTED_PLATFORM_TOOL_PATHS[name]
            if (
                not isinstance(source_text, str)
                or source_text != trusted_source.as_posix()
                or not isinstance(digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", digest)
                or type(owner_uid) is not int
                or owner_uid != 0
            ):
                mismatches.append(f"SDK lock local tool metadata is unsafe: {name}")
                continue
            target = destination / name
            try:
                _copy_verified_regular(
                    trusted_source,
                    target,
                    expected_sha256=digest,
                    expected_uid=0,
                    require_single_link=False,
                )
            except (OSError, SupervisorError):
                mismatches.append(f"pinned local tool failed private staging: {name}")
                continue
            staged[name] = target
            sources[name] = trusted_source
        if set(staged) != set(names):
            return None
        bootstrap_environment = {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": str(destination),
            "TMPDIR": str(destination),
            "LANG": "C.UTF-8",
        }
        for name in names:
            if name == "nc":
                continue
            item = configured[name]
            expected_staged = item.get("staged_sha256")
            if not isinstance(expected_staged, str) or not re.fullmatch(
                r"[0-9a-f]{64}", expected_staged
            ):
                mismatches.append(f"SDK lock staged local tool is invalid: {name}")
                continue
            try:
                completed = _run(
                    [
                        str(sources["sandbox_exec"]),
                        "-p",
                        '(version 1)(allow default)(deny network*)',
                        str(sources["codesign"]),
                        "--force",
                        "--sign",
                        "-",
                        "--timestamp=none",
                        "--preserve-metadata=entitlements,requirements,flags,runtime",
                        str(staged[name]),
                    ],
                    cwd=destination,
                    timeout=15,
                    env=bootstrap_environment,
                    pause_file=self.config.supervisor_v4.pause_file,
                    max_output_bytes=65_536,
                )
            except ProcessSupervisionError as exc:
                mismatches.append(
                    "private local-tool signing stopped: "
                    f"{name}:{exc.code}; process_group_reaped="
                    f"{str(exc.process_group_reaped).lower()}"
                )
                continue
            if (
                completed.returncode != 0
                or _sha256_file(staged[name]) != expected_staged
            ):
                mismatches.append(f"private local-tool signing drifted: {name}")
        if mismatches:
            return None
        return StagedLocalTools(
            git=staged["git"],
            sandbox_exec=staged["sandbox_exec"],
            cmp=staged["cmp"],
            # Apple's nc platform binary cannot retain its launch trust after
            # copying. Its exact root-owned original is attested above and used
            # only for the loopback-connect sandbox probe.
            nc=sources["nc"],
            install_name_tool=staged["install_name_tool"],
            # codesign is a platform security tool and is killed when launched
            # from an ad-hoc copied path. Its root-owned original was descriptor-
            # attested before this exact-path use.
            codesign=sources["codesign"],
        )

    def _prepare_staged_python_runtime(
        self,
        staged: StagedPythonRuntime,
        tools: StagedLocalTools,
        lock: Mapping[str, Any],
        mismatches: list[str],
    ) -> StagedPythonRuntime | None:
        """Bind the copied interpreter to its copied framework, then re-attest it."""

        python_lock = lock.get("python") or {}
        if not isinstance(python_lock, Mapping):
            mismatches.append("SDK lock staged-Python metadata is invalid")
            return None
        original_name = python_lock.get("original_library_install_name")
        staged_name = python_lock.get("staged_library_install_name")
        staged_app_name = python_lock.get("staged_app_library_install_name")
        app_relative_text = python_lock.get("base_python_app_relative")
        expected_python = python_lock.get("staged_python_executable_sha256")
        expected_app = python_lock.get("staged_python_app_sha256")
        expected_count = python_lock.get("staged_base_file_count")
        expected_manifest = python_lock.get("staged_base_manifest_sha256")
        if not all(
            isinstance(item, str) and item
            for item in (
                original_name,
                staged_name,
                staged_app_name,
                app_relative_text,
                expected_python,
                expected_app,
                expected_manifest,
            )
        ) or not isinstance(expected_count, int):
            mismatches.append("SDK lock staged-Python metadata is unavailable")
            return None
        app_relative = Path(str(app_relative_text))
        if app_relative.is_absolute() or ".." in app_relative.parts:
            mismatches.append("SDK lock staged Python.app path is unsafe")
            return None
        app_python = staged.base_root / app_relative
        environment = {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": str(staged.base_root),
            "TMPDIR": str(staged.base_root),
            "LANG": "C.UTF-8",
        }
        try:
            for executable, replacement_name in (
                (staged.python, str(staged_name)),
                (app_python, str(staged_app_name)),
            ):
                changed = _run(
                    [
                        str(tools.sandbox_exec),
                        "-p",
                        '(version 1)(allow default)(deny network*)',
                        str(tools.install_name_tool),
                        "-change",
                        str(original_name),
                        replacement_name,
                        str(executable),
                    ],
                    cwd=staged.base_root,
                    timeout=15,
                    env=environment,
                    pause_file=self.config.supervisor_v4.pause_file,
                    max_output_bytes=65_536,
                )
                if changed.returncode != 0:
                    mismatches.append("private Python runtime rebinding failed")
                    return None
                if executable == app_python:
                    _clear_codesign_tree_detritus(app_python.parents[2])
                else:
                    _clear_codesign_detritus(executable)
                signed = _run(
                    [
                        str(tools.sandbox_exec),
                        "-p",
                        '(version 1)(allow default)(deny network*)',
                        str(tools.codesign),
                        "--force",
                        "--sign",
                        "-",
                        "--timestamp=none",
                        str(executable),
                    ],
                    cwd=staged.base_root,
                    timeout=15,
                    env=environment,
                    pause_file=self.config.supervisor_v4.pause_file,
                    max_output_bytes=65_536,
                )
                if signed.returncode != 0:
                    mismatches.append("private Python runtime rebinding failed")
                    return None
        except ProcessSupervisionError as exc:
            mismatches.append(
                "private Python runtime rebinding stopped: "
                f"{exc.code}; process_group_reaped="
                f"{str(exc.process_group_reaped).lower()}"
            )
            return None
        except (OSError, SupervisorError):
            mismatches.append("private Python runtime rebinding cleanup failed")
            return None
        try:
            base_count, base_manifest = _runtime_tree_manifest(staged.base_root)
            python_sha256 = _sha256_file(staged.python)
            app_sha256 = _sha256_file(app_python)
        except (OSError, SupervisorError):
            mismatches.append("private Python runtime rebinding attestation failed")
            return None
        if (
            base_count != expected_count
            or base_manifest != expected_manifest
            or python_sha256 != expected_python
            or app_sha256 != expected_app
        ):
            mismatches.append("private Python runtime rebinding drifted")
            return None
        return StagedPythonRuntime(
            python=staged.python,
            dyld_root=staged.dyld_root,
            base_root=staged.base_root,
            site_packages=staged.site_packages,
            base_file_count=base_count,
            base_manifest_sha256=base_manifest,
            site_packages_file_count=staged.site_packages_file_count,
            site_packages_manifest_sha256=staged.site_packages_manifest_sha256,
        )

    @staticmethod
    def _verify_staged_python_runtime(
        staged: StagedPythonRuntime,
        mismatches: list[str],
    ) -> bool:
        try:
            base_count, base_manifest = _runtime_tree_manifest(staged.base_root)
            site_count, site_manifest = _site_packages_manifest(staged.site_packages)
        except (OSError, SupervisorError):
            mismatches.append("private Python runtime snapshot became unsafe")
            return False
        okay = (
            base_count == staged.base_file_count
            and base_manifest == staged.base_manifest_sha256
            and site_count == staged.site_packages_file_count
            and site_manifest == staged.site_packages_manifest_sha256
        )
        if not okay:
            mismatches.append("private Python runtime snapshot changed during use")
        return okay

    def _inspect_sdk_probe(
        self,
        policy: SupervisorV4PolicyConfig,
        bundle: ImmutablePolicyBundle,
        lock: Mapping[str, Any],
        staged_python: StagedPythonRuntime,
        sandbox_binary: Path,
        mismatches: list[str],
    ) -> dict[str, Any]:
        python = staged_python.python
        python_runtime_root = str(staged_python.dyld_root)
        if not self._verify_staged_python_runtime(staged_python, mismatches):
            return {"ready": False, "model_contacted": False}
        runtime_root = self.config.supervisor_v4.runtime_dir
        runtime_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="atlas-v4-sdk-probe-", dir=runtime_root
        ) as temporary:
            probe = Path(temporary) / "supervisor_v4_sdk_probe.py"
            probe.write_bytes(bundle.member("sdk_probe_source").content)
            probe.chmod(0o500)
            home = Path(temporary) / "empty-home"
            codex_home = Path(temporary) / "empty-codex-home"
            home.mkdir(mode=0o700)
            codex_home.mkdir(mode=0o700)
            completed = _run(
                [
                    str(sandbox_binary),
                    "sandbox",
                    "-C",
                    str(self.config.project_root),
                    "-P",
                    _V4_PROFILE_ID,
                    "-c",
                    _V4_PERMISSION_PROFILE_TOML,
                    "--sandbox-state-readable-root",
                    python_runtime_root,
                    "--",
                    str(python),
                    "-S",
                    str(probe),
                ],
                cwd=self.config.project_root,
                timeout=20,
                pause_file=self.config.supervisor_v4.pause_file,
                max_output_bytes=1_048_576,
                env={
                    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                    "LANG": "C.UTF-8",
                    "HOME": str(home),
                    "CODEX_HOME": str(codex_home),
                    "TMPDIR": str(temporary),
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "PYTHONHOME": str(staged_python.python.parent.parent),
                    "PYTHONNOUSERSITE": "1",
                    "PYTHONSAFEPATH": "1",
                    "PYTHONHASHSEED": "0",
                    "ATLAS_V4_SDK_SITE_PACKAGES": str(
                        staged_python.site_packages
                    ),
                    "ATLAS_V4_PYTHON_BASE": str(staged_python.base_root),
                    "CI": "1",
                },
            )
        self._verify_staged_python_runtime(staged_python, mismatches)
        try:
            result = json.loads(completed.stdout) if completed.returncode == 0 else {}
        except json.JSONDecodeError:
            result = {}
        required = {
            "format": "atlas-supervisor-v4-sdk-probe",
            "sdk_version": policy.protocol_pin.sdk_version,
            "runtime_package_version": policy.protocol_pin.runtime_package_version,
            "codex_constructed": False,
            "codex_client_constructed": False,
            "client_started": False,
            "model_contacted": False,
            "experimental_api": False,
            "approval_handler_parameter_available": True,
            "default_handler_is_permissive": True,
            "process_spawned": False,
            "socket_opened": False,
            "network_accessed": False,
            "active_operation_traps_armed": True,
            "active_operation_trap_calls": 0,
            "runtime_snapshot_verified": True,
            "sdk_modules_from_snapshot": True,
            "stdlib_modules_from_snapshot": True,
            "sys_path_from_snapshot": True,
            "approval_mode": "deny_all",
            "approval_policy": "never",
            "read_only_sandbox": "read-only",
            "thread_run_has_output_schema": True,
            "turn_stream_available": True,
            "turn_interrupt_available": True,
            "typed_turn_result": True,
        }
        for field, expected in required.items():
            if result.get(field) != expected:
                mismatches.append(f"SDK probe control drifted: {field}")
        reject_samples = result.get("reject_all_handler_samples") or {}
        if not reject_samples or any(
            sample != {"decision": "decline"}
            for sample in reject_samples.values()
        ):
            mismatches.append("explicit reject-all handler behavior drifted")
        expected_sources = {
            "agent",
            "unifiedExecStartup",
            "unifiedExecInteraction",
            "userShell",
        }
        if set(result.get("command_execution_sources") or []) != expected_sources:
            mismatches.append("SDK command-source inventory drifted")
        return result

    @staticmethod
    def _schema_snapshot(root: Path, selected: Mapping[str, str]) -> dict[str, Any]:
        files = sorted(path for path in root.rglob("*") if path.is_file())
        manifest = "".join(
            f"{_sha256_file(path)}  {path.relative_to(root).as_posix()}\n"
            for path in files
        ).encode("utf-8")
        return {
            "file_count": len(files),
            "manifest_sha256": _sha256_bytes(manifest),
            "selected_schema_sha256": {
                name: _sha256_file(root / name) if (root / name).is_file() else None
                for name in selected
            },
        }

    def _inspect_runtime_and_protocol(
        self,
        policy: SupervisorV4PolicyConfig,
        bundle: ImmutablePolicyBundle,
        lock: Mapping[str, Any],
        sdk_probe: Mapping[str, Any],
        sandbox_binary: Path,
        mismatches: list[str],
    ) -> dict[str, Any]:
        from atlas_core.supervisor_v4_protocol import (
            ProtocolInventory,
            ProtocolViolation,
            load_replay_corpus,
            replay_corpus_sha256,
            run_replay_case,
        )

        pin = policy.protocol_pin
        binary_hash = _sha256_file(sandbox_binary)
        runtime_root = self.config.supervisor_v4.runtime_dir
        runtime_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="atlas-v4-runtime-version-", dir=runtime_root
        ) as version_temporary:
            version_home = Path(version_temporary) / "home"
            version_codex_home = Path(version_temporary) / "codex-home"
            version_home.mkdir(mode=0o700)
            version_codex_home.mkdir(mode=0o700)
            version = _run(
                [
                    str(sandbox_binary),
                    "sandbox",
                    "-C",
                    str(version_temporary),
                    "-P",
                    _V4_QUALIFICATION_PROFILE_ID,
                    "-c",
                    _V4_QUALIFICATION_PROFILE_TOML,
                    "--",
                    str(sandbox_binary),
                    "--version",
                ],
                cwd=Path(version_temporary),
                timeout=10,
                pause_file=self.config.supervisor_v4.pause_file,
                max_output_bytes=65_536,
                env={
                    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                    "LANG": "C.UTF-8",
                    "HOME": str(version_home),
                    "CODEX_HOME": str(version_codex_home),
                    "TMPDIR": str(version_temporary),
                },
            )
        cli_version = version.stdout.strip()
        if version.returncode != 0 or cli_version != pin.cli_version:
            mismatches.append("pinned SDK Codex binary version drifted")
            return {
                "binary_sha256": binary_hash,
                "cli_version": cli_version,
                "model_contacted": False,
            }

        with tempfile.TemporaryDirectory(
            prefix="atlas-v4-runtime-", dir=runtime_root
        ) as temporary:
            root = Path(temporary)
            home = root / "home"
            codex_home = root / "codex-home"
            home.mkdir(mode=0o700)
            codex_home.mkdir(mode=0o700)
            schema_root = root / "schema"
            schema_root.mkdir()
            generated = _run(
                [
                    str(sandbox_binary),
                    "sandbox",
                    "-C",
                    str(root),
                    "-P",
                    _V4_QUALIFICATION_PROFILE_ID,
                    "-c",
                    _V4_QUALIFICATION_PROFILE_TOML,
                    "--",
                    str(sandbox_binary),
                    "app-server",
                    "generate-json-schema",
                    "--out",
                    str(schema_root),
                ],
                cwd=root,
                timeout=60,
                pause_file=self.config.supervisor_v4.pause_file,
                max_output_bytes=1_048_576,
                env={
                    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                    "LANG": "C.UTF-8",
                    "HOME": str(home),
                    "CODEX_HOME": str(codex_home),
                    "TMPDIR": str(root),
                    "CI": "1",
                },
            )
            if generated.returncode != 0:
                mismatches.append("stable App Server schema generation failed")
                return {
                    "binary_sha256": binary_hash,
                    "cli_version": cli_version,
                    "model_contacted": False,
                }
            snapshot = self._schema_snapshot(schema_root, pin.selected_schema_sha256)
            notifications = _extract_schema_methods(
                json.loads((schema_root / "ServerNotification.json").read_text(encoding="utf-8"))
            )
            requests = _extract_schema_methods(
                json.loads((schema_root / "ServerRequest.json").read_text(encoding="utf-8"))
            )
            protocol_copy = root / "protocol.yaml"
            protocol_copy.write_bytes(bundle.member("protocol").content)
            replay_copy = root / "replays.json"
            replay_copy.write_bytes(bundle.member("replays").content)
            try:
                inventory = ProtocolInventory.load(protocol_copy)
                corpus = load_replay_corpus(replay_copy)
                corpus_digest = replay_corpus_sha256(corpus)
            except (OSError, ProtocolViolation, json.JSONDecodeError) as exc:
                mismatches.append(f"protocol replay inventory failed: {str(exc)[:160]}")
                return {
                    "binary_sha256": binary_hash,
                    "cli_version": cli_version,
                    **snapshot,
                    "model_contacted": False,
                }

        if snapshot["file_count"] != pin.schema_file_count:
            mismatches.append("stable schema file count drifted")
        if snapshot["manifest_sha256"] != pin.schema_manifest_sha256:
            mismatches.append("stable schema manifest SHA-256 drifted")
        for name, expected in pin.selected_schema_sha256.items():
            if snapshot["selected_schema_sha256"].get(name) != expected:
                mismatches.append(f"selected stable schema drifted: {name}")
        if notifications != set(inventory.classifications):
            mismatches.append("protocol notification classification is incomplete")
        if requests != set(inventory.server_requests):
            mismatches.append("protocol server-request classification is incomplete")
        if set(sdk_probe.get("notification_methods") or []) != notifications:
            mismatches.append("SDK notification registry does not match stable schema")
        if inventory.sdk_version != pin.sdk_version:
            mismatches.append("protocol SDK version drifted")
        if corpus_digest != inventory.replay_corpus_sha256:
            mismatches.append("protocol-bound replay corpus digest drifted")
        if corpus_digest != policy.replay_corpus_sha256:
            mismatches.append("contract-bound replay corpus digest drifted")

        receipts = [run_replay_case(case, inventory).to_dict() for case in corpus["cases"]]
        replay_failures: list[str] = []
        for case, receipt in zip(corpus["cases"], receipts, strict=True):
            expected = case.get("expected") or {}
            if receipt["outcome"] != expected.get("outcome"):
                replay_failures.append(f"{case['id']}:outcome")
            if receipt["decision_code"] != expected.get("decision_code"):
                replay_failures.append(f"{case['id']}:decision")
            if receipt["grants_execution_authority"] is not False:
                replay_failures.append(f"{case['id']}:authority")
        if replay_failures:
            mismatches.append(
                "adversarial replay mismatch: " + ", ".join(replay_failures[:8])
            )
        command_source_codes = {
            receipt["diagnostic_public_value"]: receipt["decision_code"]
            for receipt in receipts
            if receipt.get("diagnostic_public_value")
            in {
                "agent",
                "unifiedExecStartup",
                "unifiedExecInteraction",
                "userShell",
            }
        }
        if command_source_codes != inventory.command_source_codes:
            mismatches.append("command-source adversarial replay coverage drifted")
        return {
            "binary_sha256": binary_hash,
            "cli_version": cli_version,
            **snapshot,
            "notification_method_count": len(notifications),
            "server_request_method_count": len(requests),
            "classified_notification_count": len(inventory.classifications),
            "classified_server_request_count": len(inventory.server_requests),
            "replay_case_count": len(receipts),
            "replay_corpus_sha256": corpus_digest,
            "replay_decision_sha256": _sha256_bytes(
                canonical_json(receipts).encode("utf-8")
            ),
            "command_source_decisions": command_source_codes,
            "all_commands_prohibited": True,
            "all_server_requests_prohibited": True,
            "raw_protocol_persisted": False,
            "model_contacted": False,
        }

    def _inspect_source_pins(
        self, lock: Mapping[str, Any], mismatches: list[str]
    ) -> dict[str, str | None]:
        expected = (lock.get("executor") or {}).get("source_sha256", {})
        if not isinstance(expected, dict) or not expected:
            mismatches.append("SDK lock has no v4 source pins")
            return {}
        observed: dict[str, str | None] = {}
        for relative, digest in sorted(expected.items()):
            path = self.config.project_root / str(relative)
            try:
                actual = _sha256_bytes(
                    _read_regular_no_follow(path, max_bytes=_MAX_BUNDLE_FILE_BYTES)
                )
            except (OSError, SupervisorError):
                actual = None
            observed[str(relative)] = actual
            if not isinstance(digest, str) or digest == "0" * 64 or actual != digest:
                mismatches.append(f"Supervisor v4 source drifted: {relative}")
        return observed

    @staticmethod
    def _inspect_loaded_source_bindings(
        bundle: ImmutablePolicyBundle,
        lock: Mapping[str, Any],
        mismatches: list[str],
    ) -> dict[str, str | None]:
        """Bind every executed bundle module to its canonical source lock.

        A regular wheel install may live separately from the canonical project
        tree.  Source-pin inspection protects that tree; this second comparison
        proves that the already imported implementation is byte-identical to
        the same lock before any broker or later qualification child starts.
        """

        expected = (lock.get("executor") or {}).get("source_sha256", {})
        observed: dict[str, str | None] = {}
        if not isinstance(expected, dict):
            mismatches.append("SDK lock has no loaded-source bindings")
            return observed
        for label, relative in _RUNTIME_BUNDLE_SOURCE_PINS.items():
            expected_digest = expected.get(relative)
            try:
                actual = bundle.member(label).sha256
            except KeyError:
                actual = None
            observed[relative] = actual
            if (
                not isinstance(expected_digest, str)
                or expected_digest == "0" * 64
                or actual != expected_digest
            ):
                mismatches.append(
                    f"loaded Supervisor v4 source drifted: {relative}"
                )
        return observed

    def _inspect_static_replays(
        self,
        policy: SupervisorV4PolicyConfig,
        bundle: ImmutablePolicyBundle,
        mismatches: list[str],
    ) -> dict[str, Any]:
        """Replay the packaged corpus before any external process can start."""

        from atlas_core.supervisor_v4_protocol import (
            ProtocolInventory,
            ProtocolViolation,
            load_replay_corpus,
            replay_corpus_sha256,
            run_replay_case,
        )

        runtime_root = self.config.supervisor_v4.runtime_dir
        runtime_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            with tempfile.TemporaryDirectory(
                prefix="atlas-v4-static-replay-", dir=runtime_root
            ) as temporary:
                root = Path(temporary)
                protocol_path = root / "protocol.yaml"
                corpus_path = root / "replays.json"
                protocol_path.write_bytes(bundle.member("protocol").content)
                corpus_path.write_bytes(bundle.member("replays").content)
                inventory = ProtocolInventory.load(protocol_path)
                corpus = load_replay_corpus(corpus_path)
                corpus_digest = replay_corpus_sha256(corpus)
                receipts = [
                    run_replay_case(case, inventory).to_dict()
                    for case in corpus["cases"]
                ]
        except (OSError, ProtocolViolation, json.JSONDecodeError, KeyError) as exc:
            mismatches.append(f"static adversarial replay failed: {str(exc)[:160]}")
            return {"ready": False, "model_contacted": False}
        if corpus_digest != inventory.replay_corpus_sha256:
            mismatches.append("protocol-bound static replay digest drifted")
        if corpus_digest != policy.replay_corpus_sha256:
            mismatches.append("contract-bound static replay digest drifted")
        failures: list[str] = []
        for case, receipt in zip(corpus["cases"], receipts, strict=True):
            expected = case.get("expected") or {}
            if receipt.get("outcome") != expected.get("outcome"):
                failures.append(f"{case.get('id')}:outcome")
            if receipt.get("decision_code") != expected.get("decision_code"):
                failures.append(f"{case.get('id')}:decision")
            if receipt.get("grants_execution_authority") is not False:
                failures.append(f"{case.get('id')}:authority")
        if failures:
            mismatches.append("static replay expectation drifted: " + ", ".join(failures[:8]))
        return {
            "ready": not failures,
            "case_count": len(receipts),
            "replay_corpus_sha256": corpus_digest,
            "decision_sha256": _sha256_bytes(canonical_json(receipts).encode("utf-8")),
            "model_contacted": False,
            "raw_protocol_persisted": False,
        }

    def _profile_probe(
        self,
        policy: SupervisorV4PolicyConfig,
        sandbox_binary: Path,
        nc_binary: Path,
        mismatches: list[str],
    ) -> dict[str, Any]:
        if os.uname().sysname != "Darwin":
            mismatches.append("Supervisor v4 reviewed sandbox requires macOS Seatbelt")
            return {"ready": False, "model_contacted": False}
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(0.2)
        port = int(listener.getsockname()[1])
        try:
            with tempfile.TemporaryDirectory(prefix="atlas-v4-sandbox-") as temporary:
                outer = Path(temporary)
                root = outer / "proposal-root"
                root.mkdir(mode=0o700)
                inside = root / "inside.txt"
                inside.write_text("unchanged\n", encoding="utf-8")
                outside = outer / "outside.txt"
                outside.write_text("unchanged\n", encoding="utf-8")
                protected = self.config.app.supervisor_v4_contract_file
                command = "; ".join(
                    (
                        "ulimit -t 5",
                        "ulimit -n 64",
                        f"if /bin/cat {shlex.quote(str(inside))} >/dev/null 2>&1; then echo read=allowed; else echo read=denied; fi",
                        f"if /usr/bin/printf changed > {shlex.quote(str(inside))} 2>/dev/null; then echo write=allowed; else echo write=denied; fi",
                        f"if /usr/bin/printf changed > {shlex.quote(str(outside))} 2>/dev/null; then echo outside=allowed; else echo outside=denied; fi",
                        f"if /bin/cat {shlex.quote(str(protected))} >/dev/null 2>&1; then echo protected=allowed; else echo protected=denied; fi",
                        f"if {shlex.quote(str(nc_binary))} -z -w 1 127.0.0.1 {port} >/dev/null 2>&1; then echo network=allowed; else echo network=denied; fi",
                    )
                )
                completed = _run(
                    [
                        str(sandbox_binary),
                        "sandbox",
                        "-C",
                        str(root),
                        "-P",
                        _V4_PROFILE_ID,
                        "-c",
                        _V4_PERMISSION_PROFILE_TOML,
                        "--sandbox-state-readable-root",
                        str(nc_binary.parent),
                        "--",
                        "/bin/zsh",
                        "-f",
                        "-c",
                        command,
                    ],
                    cwd=root,
                    timeout=15,
                    pause_file=self.config.supervisor_v4.pause_file,
                    max_output_bytes=65_536,
                    env={
                        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                        "LANG": "C.UTF-8",
                        "PYTHONDONTWRITEBYTECODE": "1",
                        "TMPDIR": str(root),
                    },
                )
                flags = dict(
                    line.split("=", 1)
                    for line in completed.stdout.splitlines()
                    if "=" in line
                )
                connection_observed = False
                try:
                    accepted, _address = listener.accept()
                except TimeoutError:
                    pass
                else:
                    connection_observed = True
                    accepted.close()
                network_allowed = (
                    flags.get("network") == "allowed" or connection_observed
                )
                okay = (
                    completed.returncode == 0
                    and flags.get("read") == "allowed"
                    and flags.get("write") == "denied"
                    and flags.get("outside") == "denied"
                    and flags.get("protected") == "denied"
                    and not network_allowed
                    and inside.read_text(encoding="utf-8") == "unchanged\n"
                    and outside.read_text(encoding="utf-8") == "unchanged\n"
                )
                if not okay:
                    mismatches.append("proposal/readiness sandbox probe failed")
                return {
                    "ready": okay,
                    "profile_id": _V4_PROFILE_ID,
                    "profile_sha256": _sha256_bytes(
                        canonical_json(_V4_PERMISSION_PROFILE).encode("utf-8")
                    ),
                    "read_allowed": flags.get("read") == "allowed",
                    "write_denied": flags.get("write") == "denied",
                    "outside_write_denied": flags.get("outside") == "denied",
                    "protected_read_denied": flags.get("protected") == "denied",
                    "network_denied": not network_allowed,
                    "loopback_connection_observed": connection_observed,
                    "resource_quotas_applied": completed.returncode == 0,
                    "model_contacted": False,
                }
        finally:
            listener.close()

    @staticmethod
    def _capability_contract_probe() -> dict[str, Any]:
        from atlas_core.supervisor_v4_protocol import (
            ImmutablePolicyBundle as CapabilityPolicyBundle,
            PolicyBroker,
            SignedCapabilityEnvelope,
        )
        from atlas_core.supervisor_v4_live_contract import (
            CapabilityVerifier,
            CredentialBroker,
            CredentialLeaseVerifier,
            OwnerKillSwitchOracle,
            ReceiptAnchorBroker,
            ReceiptVerifier,
        )

        now = datetime.now(timezone.utc)
        bundle = CapabilityPolicyBundle(
            version=1,
            policy_sha256="1" * 64,
            protocol_sha256="2" * 64,
            sdk_lock_sha256="3" * 64,
            replay_corpus_sha256="4" * 64,
        )
        capability = SupervisorV4Capability(
            version=4,
            capability_id=str(uuid4()),
            task_id=str(uuid4()),
            job_id=str(uuid4()),
            nonce=str(uuid4()),
            audience="atlas-supervisor-v4-proposal-worker",
            provider="openai",
            issued_at=now.isoformat(),
            project_slug="supervisor-fixture",
            source_baseline_sha256="1" * 64,
            policy_bundle_sha256=bundle.sha256,
            replay_corpus_sha256="3" * 64,
            adapter_sha256="4" * 64,
            sdk_version="0.147.0",
            runtime_sha256="5" * 64,
            model="gpt-5.6-sol",
            reasoning_effort="low",
            sandbox_profile_sha256="6" * 64,
            command_network_access=False,
            pause_control_sha256="7" * 64,
            allowed_operation="replace_existing_file",
            allowed_result_type="structured_replacement_proposal",
            allowed_path="src/word_counter.py",
            expected_original_sha256="8" * 64,
            verification_recipe_sha256="9" * 64,
            data_egress_class="synthetic_fictional_bounded",
            data_egress_manifest_sha256="a" * 64,
            credential_scope_sha256="b" * 64,
            credential_delivery_channel_sha256="c" * 64,
            receipt_chain_id_sha256="d" * 64,
            receipt_predecessor_sha256="0" * 64,
            receipt_predecessor_count=0,
            kill_switch_channel_sha256="e" * 64,
            attempt_limit=1,
            process_limit=1,
            timeout_seconds=180,
            max_output_bytes=262_144,
            max_changed_files=1,
            max_changed_lines=20,
            max_patch_bytes=16_384,
            expires_at=(now + timedelta(minutes=5)).isoformat(),
            signing_key_id="offline-test-key",
        )
        bindings = capability.protocol_bindings()
        envelope = SignedCapabilityEnvelope(
            version=1,
            key_id="offline-test-key",
            capability_sha256=bindings.sha256,
            signature="external-signature-not-a-secret",
            nonce_sha256=_sha256_bytes(capability.nonce.encode("utf-8")),
            bindings=bindings,
        )
        capability.validate_inactive_contract(now=now)
        return {
            "capability_binding_complete": set(asdict(capability))
            == {
                "version",
                "capability_id",
                "task_id",
                "job_id",
                "nonce",
                "audience",
                "provider",
                "issued_at",
                "project_slug",
                "source_baseline_sha256",
                "policy_bundle_sha256",
                "replay_corpus_sha256",
                "adapter_sha256",
                "sdk_version",
                "runtime_sha256",
                "model",
                "reasoning_effort",
                "sandbox_profile_sha256",
                "command_network_access",
                "pause_control_sha256",
                "allowed_operation",
                "allowed_result_type",
                "allowed_path",
                "expected_original_sha256",
                "verification_recipe_sha256",
                "data_egress_class",
                "data_egress_manifest_sha256",
                "credential_scope_sha256",
                "credential_delivery_channel_sha256",
                "receipt_chain_id_sha256",
                "receipt_predecessor_sha256",
                "receipt_predecessor_count",
                "kill_switch_channel_sha256",
                "attempt_limit",
                "process_limit",
                "timeout_seconds",
                "max_output_bytes",
                "max_changed_files",
                "max_changed_lines",
                "max_patch_bytes",
                "expires_at",
                "signing_key_id",
            },
            "policy_broker_interface_defined": hasattr(PolicyBroker, "issue_capability"),
            "signed_envelope_interface_defined": envelope.one_use,
            "immutable_bundle_interface_defined": bundle.version == 1,
            "canonical_capability_projection_defined": (
                envelope.bindings == bindings
                and envelope.capability_sha256 == bindings.sha256
                and bindings.policy_bundle_sha256 == bundle.sha256
                and bindings.provider == capability.provider
                and bindings.sdk_version == capability.sdk_version
                and bindings.signing_key_id == envelope.key_id
            ),
            "one_use_nonce_bound": envelope.nonce_sha256
            == _sha256_bytes(capability.nonce.encode("utf-8")),
            "capability_verifier_interface_defined": hasattr(
                CapabilityVerifier, "verify_capability"
            ),
            "credential_broker_interface_defined": all(
                hasattr(CredentialBroker, name) for name in ("issue_lease", "revoke_lease")
            ),
            "credential_lease_verifier_interface_defined": hasattr(
                CredentialLeaseVerifier, "verify_lease"
            ),
            "receipt_verifier_interface_defined": hasattr(
                ReceiptVerifier, "verify_receipt"
            ),
            "receipt_anchor_interface_defined": all(
                hasattr(ReceiptAnchorBroker, name)
                for name in ("read_anchor", "compare_and_append")
            ),
            "owner_kill_switch_interface_defined": hasattr(
                OwnerKillSwitchOracle, "read_state"
            ),
            "worker_received_signing_key": False,
            "credential_material_present": False,
            "signing_implementation_present": False,
            "production_broker_configured": False,
            "model_contacted": False,
        }

    @staticmethod
    def _offline_broker_qualification_probe() -> dict[str, object]:
        """Run only the in-process, synthetic, non-authorizing broker harness."""

        try:
            from atlas_core.supervisor_v4_offline_broker_qualification import (
                run_offline_broker_qualification,
            )

            return run_offline_broker_qualification()
        except Exception:
            # Never expose exception bodies from a trust-boundary probe. The
            # exact failure is exercised in focused tests; readiness needs only
            # a privacy-safe fail-closed result.
            return {
                "qualified": False,
                "cryptographic_implementation_present": False,
                "credential_material_present": False,
                "credential_material_persisted": False,
                "private_data_present": False,
                "network_accessed": False,
                "model_contacted": False,
                "live_authority_granted": False,
                "production_broker_configured": False,
            }

    @staticmethod
    def _offline_external_broker_qualification_probe() -> dict[str, object]:
        """Run the synthetic, attestation-only external-process transport."""

        failed: dict[str, object] = {
            "qualified": False,
            "broker_process_count": 0,
            "process_teardown_verified": False,
            "credential_material_present": False,
            "private_data_present": False,
            "network_accessed": False,
            "model_contacted": False,
            "live_authority_granted": False,
            "production_broker_configured": False,
        }
        try:
            from atlas_core.supervisor_v4_offline_external_broker import (
                run_offline_external_broker_qualification,
            )

            report = run_offline_external_broker_qualification()
        except Exception:
            return failed
        expected_keys = {
            "transport",
            "protocol",
            "broker_process_count",
            "broker_roles_complete",
            "role_attestations_valid",
            "distinct_processes",
            "distinct_transport_identities",
            "owner_only_socket_permissions",
            "owner_only_root_permissions",
            "peer_uid_verified",
            "launcher_bound_session_verified",
            "parent_watchdog_verified",
            "canonical_json_required",
            "bounded_length_prefix_required",
            "one_request_per_connection",
            "signed_responses_verified",
            "signed_requests_verified",
            "request_digest_and_nonce_bound",
            "request_replay_rejected",
            "concurrent_replay_rejected",
            "response_substitution_rejected",
            "untrusted_client_rejected",
            "oversized_frame_rejected",
            "partial_frame_rejected",
            "trailing_bytes_rejected",
            "noncanonical_json_rejected",
            "duplicate_json_keys_rejected",
            "deep_json_rejected",
            "lone_surrogate_rejected",
            "oversized_integer_rejected",
            "absolute_frame_deadline_enforced",
            "boolean_version_rejected",
            "malformed_input_survived",
            "concurrent_requests_serialized",
            "crashed_broker_failed_closed",
            "attestation_only_surface",
            "child_environment_scrubbed",
            "process_teardown_verified",
            "private_signing_keys_exported",
            "credential_material_present",
            "private_data_present",
            "network_accessed",
            "model_contacted",
            "live_authority_granted",
            "production_broker_configured",
            "durable_replay_state_present",
            "vault_adapter_connected",
            "distinct_os_service_accounts",
            "qualified",
        }
        if (
            not isinstance(report, dict)
            or set(report) != expected_keys
            or report.get("transport") != "unix_domain_socket"
            or report.get("protocol")
            != "atlas-supervisor-v4-external-broker-fixture"
            or type(report.get("broker_process_count")) is not int
            or report.get("broker_process_count") != 5
            or any(
                not isinstance(report[key], bool)
                for key in expected_keys
                - {"transport", "protocol", "broker_process_count"}
            )
        ):
            return failed
        safety_false = (
            "private_signing_keys_exported",
            "credential_material_present",
            "private_data_present",
            "network_accessed",
            "model_contacted",
            "live_authority_granted",
            "production_broker_configured",
            "durable_replay_state_present",
            "vault_adapter_connected",
            "distinct_os_service_accounts",
        )
        if report["qualified"] is True and (
            report["process_teardown_verified"] is not True
            or report["attestation_only_surface"] is not True
            or any(report[key] is not False for key in safety_false)
        ):
            report = dict(report)
            report["qualified"] = False
        return report

    def _same_user_broker_qualification_probe(
        self,
        bundle: ImmutablePolicyBundle,
        *,
        lock: Mapping[str, Any],
        staged_python: StagedPythonRuntime,
        staged_tools: StagedLocalTools,
    ) -> dict[str, object]:
        """Run Option 1 in a sealed, pinned, network-denied broker child."""

        failed: dict[str, object] = {
            "qualified": False,
            "mode": "guarded_same_user_offline_synthetic",
            "broker_process_environment_scrubbed": False,
            "broker_process_connector_launches_bounded": False,
            "broker_process_from_staged_runtime": False,
            "broker_process_network_guard_armed": False,
            "broker_process_os_network_sandboxed": False,
            "broker_process_source_snapshot_verified": False,
            "broker_process_subprocess_allowlist_armed": False,
            "broker_process_teardown_verified": False,
            "synthetic_material_present_in_broker_process": False,
            "synthetic_material_present_in_qualification_process": False,
            "synthetic_material_present_in_atlas_worker": False,
            "credential_material_persisted": False,
            "private_data_present": False,
            "network_accessed": False,
            "model_contacted": False,
            "provider_contacted": False,
            "live_authority_granted": False,
            "production_broker_configured": False,
            "operating_system_service_installed": False,
            "deployment_performed": False,
            "production_ready": False,
            "option2_service_identity_gate_satisfied": False,
            "ordinary_startup_wired": False,
        }
        expected_keys = {
            "qualified",
            "mode",
            "registry_bound",
            "registry_source_pinned",
            "caller_selectable_vault_item_field_present",
            "caller_selectable_destination_field_present",
            "request_replay_rejected",
            "vault_lock_rejected",
            "connector_environment_scrubbed",
            "connector_network_blocked",
            "connector_filesystem_write_blocked",
            "connector_process_fork_blocked",
            "connector_teardown_verified",
            "connector_material_not_returned",
            "connector_material_not_persisted",
            "connector_working_buffer_cleared",
            "delivery_signature_verified",
            "sentinel_absent_from_state",
            "vault_item_consumed",
            "request_replay_rejected_after_restart",
            "delivery_replay_rejected_after_restart",
            "revocation_survived_restart",
            "pause_survived_restart",
            "sentinel_absent_after_restart",
            "receipt_continuity_preserved",
            "state_generation_monotonic",
            "state_quarantined",
            "same_uid_residual_risk",
            "broker_process_environment_scrubbed",
            "broker_process_connector_launches_bounded",
            "broker_process_from_staged_runtime",
            "broker_process_network_guard_armed",
            "broker_process_os_network_sandboxed",
            "broker_process_source_snapshot_verified",
            "broker_process_subprocess_allowlist_armed",
            "broker_process_teardown_verified",
            "synthetic_material_present_in_broker_process",
            "synthetic_material_present_in_qualification_process",
            "synthetic_material_present_in_atlas_worker",
            "credential_material_persisted",
            "private_data_present",
            "network_accessed",
            "model_contacted",
            "provider_contacted",
            "live_authority_granted",
            "production_broker_configured",
            "operating_system_service_installed",
            "deployment_performed",
            "production_ready",
            "option2_service_identity_gate_satisfied",
            "ordinary_startup_wired",
            "connector_interface_host_portable",
            "evidence_sha256",
        }
        required_true = {
            "qualified",
            "registry_bound",
            "registry_source_pinned",
            "request_replay_rejected",
            "vault_lock_rejected",
            "connector_environment_scrubbed",
            "connector_network_blocked",
            "connector_filesystem_write_blocked",
            "connector_process_fork_blocked",
            "connector_teardown_verified",
            "connector_material_not_returned",
            "connector_material_not_persisted",
            "connector_working_buffer_cleared",
            "delivery_signature_verified",
            "sentinel_absent_from_state",
            "vault_item_consumed",
            "request_replay_rejected_after_restart",
            "delivery_replay_rejected_after_restart",
            "revocation_survived_restart",
            "pause_survived_restart",
            "sentinel_absent_after_restart",
            "receipt_continuity_preserved",
            "state_generation_monotonic",
            "same_uid_residual_risk",
            "connector_interface_host_portable",
            "broker_process_environment_scrubbed",
            "broker_process_connector_launches_bounded",
            "broker_process_from_staged_runtime",
            "broker_process_network_guard_armed",
            "broker_process_source_snapshot_verified",
            "broker_process_subprocess_allowlist_armed",
            "broker_process_teardown_verified",
            "synthetic_material_present_in_broker_process",
            "synthetic_material_present_in_qualification_process",
        }
        required_false = {
            "caller_selectable_vault_item_field_present",
            "caller_selectable_destination_field_present",
            "state_quarantined",
            "broker_process_os_network_sandboxed",
            "synthetic_material_present_in_atlas_worker",
            "credential_material_persisted",
            "private_data_present",
            "network_accessed",
            "model_contacted",
            "provider_contacted",
            "live_authority_granted",
            "production_broker_configured",
            "operating_system_service_installed",
            "deployment_performed",
            "production_ready",
            "option2_service_identity_gate_satisfied",
            "ordinary_startup_wired",
        }
        try:
            runtime_root = self.config.supervisor_v4.same_user_broker_runtime_dir
            runtime_root.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(runtime_root, 0o700)
            runtime_root = runtime_root.resolve(strict=True)
            with tempfile.TemporaryDirectory(
                prefix="atlas-option1-sealed-", dir=runtime_root
            ) as temporary:
                staged_root = Path(temporary).resolve(strict=True)
                package_root = staged_root / "packages"
                atlas_package = package_root / "atlas_core"
                atlas_package.mkdir(mode=0o700, parents=True)
                registry_file = staged_root / "registry.json"
                connector_source = staged_root / "connector.py"
                probe_source = staged_root / "same_user_probe.py"
                source_manifest = staged_root / "source-manifest.json"
                dependency_mismatches: list[str] = []
                staged_option1_dependencies = self._stage_option1_dependencies(
                    lock,
                    staged_root / "option1-site-packages",
                    dependency_mismatches,
                )
                if staged_option1_dependencies is None or dependency_mismatches:
                    stopped = dict(failed)
                    stopped["failure_code"] = "same_user_dependency_staging_failed"
                    return stopped
                _write_private_snapshot(
                    registry_file,
                    bundle.member("same_user_registry").content,
                    mode=0o400,
                )
                _write_private_snapshot(
                    connector_source,
                    bundle.member("same_user_connector_source").content,
                    mode=0o400,
                )
                _write_private_snapshot(
                    probe_source,
                    bundle.member("same_user_probe_source").content,
                    mode=0o500,
                )
                module_manifest = {
                    "__init__.py": _sha256_bytes(b""),
                }
                _write_private_snapshot(
                    atlas_package / "__init__.py", b"", mode=0o400
                )
                for filename, label in _SAME_USER_STAGED_MODULES.items():
                    member = bundle.member(label)
                    _write_private_snapshot(
                        atlas_package / filename, member.content, mode=0o400
                    )
                    module_manifest[filename] = member.sha256
                _write_private_snapshot(
                    source_manifest,
                    canonical_json(module_manifest).encode("utf-8"),
                    mode=0o400,
                )
                empty_home = staged_root / "empty-home"
                empty_home.mkdir(mode=0o700)
                completed = _run(
                    [
                        str(staged_python.python),
                        "-S",
                        "-B",
                        str(probe_source),
                        "--runtime-root",
                        str(staged_root),
                        "--registry-file",
                        str(registry_file),
                        "--connector-source",
                        str(connector_source),
                        "--python-executable",
                        str(staged_python.python),
                        "--sandbox-exec",
                        str(staged_tools.sandbox_exec),
                        "--package-root",
                        str(package_root),
                        "--site-packages",
                        str(staged_python.site_packages),
                        "--option1-site-packages",
                        str(staged_option1_dependencies.site_packages),
                        "--option1-cryptography-file-count",
                        str(staged_option1_dependencies.cryptography_file_count),
                        "--option1-cryptography-manifest-sha256",
                        staged_option1_dependencies.cryptography_manifest_sha256,
                        "--option1-cffi-backend-filename",
                        staged_option1_dependencies.cffi_backend_filename,
                        "--option1-cffi-backend-sha256",
                        staged_option1_dependencies.cffi_backend_sha256,
                        "--python-base",
                        str(staged_python.base_root),
                        "--source-manifest",
                        str(source_manifest),
                        "--probe-sha256",
                        bundle.member("same_user_probe_source").sha256,
                        "--parent-pid",
                        str(os.getpid()),
                    ],
                    cwd=staged_root,
                    timeout=30,
                    env={
                        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                        "LANG": "C.UTF-8",
                        "HOME": str(empty_home),
                        "TMPDIR": str(staged_root),
                        "PYTHONDONTWRITEBYTECODE": "1",
                        "PYTHONHOME": str(staged_python.python.parent.parent),
                        "PYTHONNOUSERSITE": "1",
                        "PYTHONSAFEPATH": "1",
                        "PYTHONHASHSEED": "0",
                    },
                    pause_file=self.config.supervisor_v4.pause_file,
                    max_output_bytes=65_536,
                )
            if (
                completed.returncode != 0
                or completed.stderr != ""
                or completed.process_group_reaped is not True
            ):
                stopped = dict(failed)
                error_code = completed.stderr.strip()
                stopped["failure_code"] = (
                    error_code
                    if re.fullmatch(r"(?:same_user|connector)_[a-z0-9_]{1,80}", error_code)
                    else "same_user_broker_child_failed"
                )
                return stopped
            report = json.loads(completed.stdout)
            if canonical_json(report) != completed.stdout:
                return failed
        except (OSError, ProcessSupervisionError, SupervisorError, ValueError):
            return failed
        child_expected_keys = expected_keys - {"broker_process_teardown_verified"}
        if (
            not isinstance(report, dict)
            or set(report) != child_expected_keys
            or report.get("mode") != "guarded_same_user_offline_synthetic"
            or any(
                not isinstance(report[key], bool)
                for key in child_expected_keys - {"mode", "evidence_sha256"}
            )
            or not isinstance(report.get("evidence_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", str(report["evidence_sha256"]))
        ):
            return failed
        evidence = dict(report)
        evidence_sha256 = str(evidence.pop("evidence_sha256"))
        if _sha256_bytes(canonical_json(evidence).encode("utf-8")) != evidence_sha256:
            return failed
        report = dict(report)
        report["broker_process_teardown_verified"] = True
        report.pop("evidence_sha256")
        report["evidence_sha256"] = _sha256_bytes(
            canonical_json(report).encode("utf-8")
        )
        if any(report[key] is not True for key in required_true) or any(
            report[key] is not False for key in required_false
        ):
            report = dict(report)
            report["qualified"] = False
        return report

    def readiness(self) -> dict[str, Any]:
        if self.database is None:
            raise SupervisorError("Supervisor v4 qualification database is unavailable")
        if not self.enabled or not self.config.supervisor_v4.offline_qualification_enabled:
            raise SupervisorError("Supervisor v4 offline qualification is disabled")
        if self.config.supervisor_v4.pause_file.exists():
            raise SupervisorError("Supervisor v4 is paused")
        canary_accounting = self._option1_canary_accounting()
        canary_implementation_state, _canary_blocker = (
            self._option1_canary_status_projection(canary_accounting)
        )
        recovery_accounting = self._option1_recovery_canary_accounting()
        recovery_implementation_state, _recovery_blocker = (
            self._option1_recovery_canary_status_projection(recovery_accounting)
        )
        recovery_review_completed = (
            canary_accounting.get("canary_launch_state") == "failed_preclaim"
            and canary_accounting.get("canary_attempt_state") == "failed_preclaim"
            and recovery_accounting.get("recovery_canary_predecessor_verified")
            is True
        )
        if recovery_review_completed:
            canary_implementation_state = "failed_preclaim_terminal"
        (
            recovery_result_review_state,
            recovery_result_reviewed,
            _recovery_result_review_blocker,
        ) = self._option1_recovery_result_review_state(
            canary_accounting, recovery_accounting
        )
        try:
            option2_plan = build_option2_service_identity_and_vault_plan()
            option2_plan_contract_state = OPTION2_PLAN_STATE
        except (Option2PlanViolation, Option2ProvisionerViolation, KeyError, TypeError):
            option2_plan = {"plan_sha256": None}
            option2_plan_contract_state = "contract_invalid"
        (
            option2_plan_review_state,
            option2_plan_reviewed,
            _option2_plan_review_blocker,
        ) = self._option2_plan_review_state(
            canary_accounting, recovery_accounting
        )
        (
            option2_provisioner_qualification_state,
            option2_provisioner_qualified,
            _option2_provisioner_qualification_blocker,
        ) = self._option2_provisioner_qualification_state(
            canary_accounting, recovery_accounting
        )
        (
            option2_manifest_review_state,
            option2_manifest_reviewed,
            _option2_manifest_review_blocker,
        ) = self._option2_provisioner_manifest_review_state(
            canary_accounting, recovery_accounting
        )
        (
            option2_identity_candidate_state,
            option2_identity_candidate_qualified,
            _option2_identity_candidate_blocker,
        ) = self._option2_identity_candidate_qualification_state(
            canary_accounting, recovery_accounting
        )
        (
            option2_host_candidate_state,
            option2_host_candidate_active,
            option2_host_candidate_blocker,
            option2_host_candidate_record,
        ) = self._option2_host_preflight_candidate_state(
            canary_accounting, recovery_accounting
        )
        (
            option2_host_recovery_state,
            option2_host_recovery_candidate_active,
            option2_host_recovery_blocker,
            option2_host_recovery_candidate_record,
            option2_host_recovery_predecessor_record,
        ) = self._option2_host_preflight_recovery_state(
            canary_accounting, recovery_accounting
        )
        (
            option2_host_recovery_result_review_state,
            option2_host_recovery_result_reviewed,
            _option2_host_recovery_result_review_blocker,
        ) = self._option2_host_preflight_recovery_result_review_state()
        (
            option2_point_action_qualification_state,
            option2_point_action_qualified,
            _option2_point_action_qualification_blocker,
        ) = self._option2_point_action_qualification_state()
        (
            option2_native_preflight_qualification_state,
            option2_native_preflight_qualified,
            _option2_native_preflight_qualification_blocker,
        ) = self._option2_native_preflight_qualification_state()
        option2_native_preflight_records = (
            self.database.list_supervisor_v4_qualifications(
                subject=_OPTION2_NATIVE_PREFLIGHT_QUALIFICATION_SUBJECT,
                limit=1,
            )
            if hasattr(self.database, "list_supervisor_v4_qualifications")
            else []
        )
        option2_native_preflight_content = (
            option2_native_preflight_records[0].get("content")
            if option2_native_preflight_records
            else None
        )
        try:
            option2_recovery_review_content = (
                self._option2_host_preflight_recovery_result_review_content()
            )
            option2_recovery_review_content_sha256 = _sha256_bytes(
                canonical_json(option2_recovery_review_content).encode("utf-8")
            )
            option2_point_action_contract = build_option2_point_action_contract(
                recovery_result_review_content_sha256=(
                    option2_recovery_review_content_sha256
                )
            )
            option2_point_action_contract_state = OPTION2_POINT_ACTION_STATE
        except (Option2PointActionViolation, SupervisorError, KeyError, TypeError):
            option2_point_action_contract = {"contract_sha256": None}
            option2_point_action_contract_state = "not_applicable"
        if option2_host_recovery_result_reviewed:
            option2_host_recovery_candidate_active = False
        option2_host_candidate_active = bool(
            option2_host_candidate_active
            or option2_host_recovery_candidate_active
        )
        if option2_host_recovery_candidate_active:
            option2_host_candidate_record = option2_host_recovery_candidate_record
        option2_host_candidate_content = (
            option2_host_candidate_record.get("content")
            if isinstance(option2_host_candidate_record, Mapping)
            else None
        )
        try:
            option2_manifest = build_option2_provisioner_manifest()
            option2_manifest_contract_state = OPTION2_PROVISIONER_STATE
        except (Option2PlanViolation, Option2ProvisionerViolation, KeyError, TypeError):
            option2_manifest = {"manifest_sha256": None}
            option2_manifest_contract_state = "contract_invalid"
        mismatches: list[str] = []
        if option2_plan_contract_state == "contract_invalid":
            mismatches.append("Option 2 plan contract invalid")
        if option2_manifest_contract_state == "contract_invalid":
            mismatches.append("Option 2 provisioner manifest contract invalid")
        if option2_plan_review_state == "review_invalid":
            mismatches.append("Option 2 plan review evidence invalid")
        if option2_provisioner_qualification_state == "qualification_invalid":
            mismatches.append("Option 2 provisioner fixture evidence invalid")
        if option2_manifest_review_state == "review_invalid":
            mismatches.append("Option 2 provisioning manifest review evidence invalid")
        if option2_identity_candidate_state == "qualification_invalid":
            mismatches.append("Option 2 identity candidate evidence invalid")
        if option2_host_candidate_state == "candidate_invalid_quarantined":
            mismatches.append("Option 2 host candidate evidence invalid")
        if (
            option2_host_candidate_state == "preflight_consumed_incomplete"
            and option2_host_recovery_state
            not in {
                OPTION2_HOST_PREFLIGHT_RECOVERY_STATE,
                OPTION2_HOST_PREFLIGHT_RECOVERY_CANDIDATE_STATE,
                "recovery_candidate_stale_inactive",
                "recovery_candidate_expired_inactive",
            }
        ):
            mismatches.append("Option 2 host preflight claim is incomplete")
        if option2_host_candidate_blocker == "option2_host_candidate_clock_anomaly":
            mismatches.append("Option 2 host candidate clock anomaly")
        if option2_host_recovery_state in {
            "recovery_invalid_quarantined",
            "recovery_preflight_consumed_incomplete",
            "recovery_storage_unavailable",
        }:
            mismatches.append("Option 2 host preflight recovery evidence incomplete")
        if (
            option2_host_recovery_state
            in {
                "recovery_candidate_stale_inactive",
                "recovery_candidate_expired_inactive",
            }
            and not option2_host_recovery_result_reviewed
        ):
            mismatches.append(
                "Option 2 host preflight recovery result is unreviewed"
            )
        if option2_host_recovery_result_review_state == "review_invalid":
            mismatches.append("Option 2 host recovery result review evidence invalid")
        if option2_point_action_qualification_state == "qualification_invalid":
            mismatches.append("Option 2 point-action qualification evidence invalid")
        if option2_native_preflight_qualification_state == "qualification_invalid":
            mismatches.append(
                "Option 2 native preflight qualification evidence invalid"
            )
        if option2_host_recovery_blocker == "option2_host_recovery_candidate_clock_anomaly":
            mismatches.append("Option 2 host recovery candidate clock anomaly")
        bundle = self._seal_runtime_bundle()
        policy = self._sealed_policy(bundle, mismatches)
        if policy is None:
            raise SupervisorError("Supervisor v4 sealed offline contract is unavailable")
        if bundle.member("protocol").sha256 != policy.protocol_inventory_sha256:
            mismatches.append("contract-bound protocol inventory digest drifted")
        if bundle.member("sdk_lock").sha256 != policy.sdk_lock_sha256:
            mismatches.append("contract-bound SDK lock digest drifted")
        lock = self._load_lock(bundle.member("sdk_lock"), mismatches)
        artifacts = self._inspect_artifacts(policy, mismatches)
        runtime_files = self._inspect_runtime_files(policy, lock, mismatches)
        source_pins = self._inspect_source_pins(lock, mismatches)
        loaded_source_pins = self._inspect_loaded_source_bindings(
            bundle, lock, mismatches
        )
        loaded_same_user_registry_sha256: str | None = None
        if self.config.supervisor_v4.same_user_broker_qualification_enabled:
            registry_relative = "config/supervisor_v4_same_user_registry.json"
            expected_registry_sha256 = (
                ((lock.get("executor") or {}).get("source_sha256", {})) or {}
            ).get(registry_relative)
            try:
                loaded_same_user_registry_sha256 = bundle.member(
                    "same_user_registry"
                ).sha256
            except KeyError:
                loaded_same_user_registry_sha256 = None
            if (
                not isinstance(expected_registry_sha256, str)
                or expected_registry_sha256 == "0" * 64
                or loaded_same_user_registry_sha256 != expected_registry_sha256
            ):
                mismatches.append("loaded Supervisor v4 same-user registry drifted")
        static_replay: dict[str, Any] = {
            "ready": False,
            "skipped": "source attestation not complete",
            "model_contacted": False,
        }
        offline_broker_qualification: dict[str, object] = {
            "qualified": False,
            "skipped": "source attestation not complete",
            "credential_material_present": False,
            "private_data_present": False,
            "network_accessed": False,
            "model_contacted": False,
            "live_authority_granted": False,
            "production_broker_configured": False,
        }
        if not mismatches:
            static_replay = self._inspect_static_replays(policy, bundle, mismatches)
        if not mismatches:
            offline_broker_qualification = self._offline_broker_qualification_probe()
            if offline_broker_qualification.get("qualified") is not True:
                mismatches.append("offline broker qualification failed")

        offline_external_broker_qualification: dict[str, object] = {
            "qualified": False,
            "skipped": "pre-child attestation not complete",
            "credential_material_present": False,
            "private_data_present": False,
            "network_accessed": False,
            "model_contacted": False,
            "live_authority_granted": False,
            "production_broker_configured": False,
        }
        if not mismatches:
            offline_external_broker_qualification = (
                self._offline_external_broker_qualification_probe()
            )
            if offline_external_broker_qualification.get("qualified") is not True:
                mismatches.append("offline external broker qualification failed")

        same_user_broker_qualification: dict[str, object] = {
            "qualified": False,
            "skipped": (
                "pre-child attestation not complete"
                if self.config.supervisor_v4.same_user_broker_qualification_enabled
                else "same-user qualification disabled"
            ),
            "synthetic_material_present_in_atlas_worker": False,
            "synthetic_material_present_in_broker_process": False,
            "credential_material_persisted": False,
            "private_data_present": False,
            "network_accessed": False,
            "model_contacted": False,
            "provider_contacted": False,
            "live_authority_granted": False,
            "production_broker_configured": False,
            "operating_system_service_installed": False,
            "deployment_performed": False,
            "production_ready": False,
            "option2_service_identity_gate_satisfied": False,
            "ordinary_startup_wired": False,
        }

        skipped = {
            "ready": False,
            "skipped": "qualification phase did not run",
            "model_contacted": False,
        }
        sdk_probe: dict[str, Any] = dict(skipped)
        runtime: dict[str, Any] = dict(skipped)
        sandbox: dict[str, Any] = dict(skipped)
        phase_c: dict[str, Any] = dict(skipped)
        if mismatches:
            for result in (sdk_probe, runtime, sandbox, phase_c):
                result["skipped"] = "static attestation failed before child process"
        else:
            from atlas_core.supervisor_v4_offline import (
                OfflineHarnessViolation,
                run_offline_self_qualification,
            )

            runtime_root = self.config.supervisor_v4.runtime_dir
            runtime_root.mkdir(mode=0o700, parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(
                prefix="atlas-v4-sealed-runtime-", dir=runtime_root
            ) as temporary:
                sealed_root = Path(temporary)
                sandbox_binary = sealed_root / "codex"
                staged_python: StagedPythonRuntime | None = None
                staged_tools: StagedLocalTools | None = None
                try:
                    _copy_verified_regular(
                        policy.protocol_pin.binary_path,
                        sandbox_binary,
                        expected_sha256=policy.protocol_pin.binary_sha256,
                    )
                    staged_tools = self._stage_local_tools(
                        lock, sealed_root / "tools", mismatches
                    )
                    signature_valid = False
                    if staged_tools is not None:
                        signature_valid = _verify_openai_codex_signature(
                            sandbox_binary,
                            codesign_binary=staged_tools.codesign,
                            pause_file=self.config.supervisor_v4.pause_file,
                            mismatches=mismatches,
                        )
                    runtime_files["Codex code-signing identity"] = {
                        "requirement": _OPENAI_CODEX_DESIGNATED_REQUIREMENT,
                        "matches": signature_valid,
                    }
                    if signature_valid and staged_tools is not None:
                        staged_python = self._stage_python_runtime(
                            policy, lock, sealed_root / "python", mismatches
                        )
                        if staged_python is not None and staged_tools is not None:
                            staged_python = self._prepare_staged_python_runtime(
                                staged_python, staged_tools, lock, mismatches
                            )
                except (OSError, SupervisorError) as exc:
                    mismatches.append(
                        "private runtime staging failed: "
                        + _sha256_bytes(str(exc).encode("utf-8"))[:16]
                    )
                if (
                    not mismatches
                    and staged_python is not None
                    and staged_tools is not None
                    and self.config.supervisor_v4.same_user_broker_qualification_enabled
                ):
                    same_user_broker_qualification = (
                        self._same_user_broker_qualification_probe(
                            bundle,
                            lock=lock,
                            staged_python=staged_python,
                            staged_tools=staged_tools,
                        )
                    )
                    if same_user_broker_qualification.get("qualified") is not True:
                        mismatches.append("same-user broker qualification failed")
                if mismatches or staged_python is None or staged_tools is None:
                    for result in (sdk_probe, runtime, sandbox, phase_c):
                        result["skipped"] = (
                            "private runtime or same-user broker attestation failed"
                        )
                else:
                    try:
                        phase_c = run_offline_self_qualification(
                            self.database,
                            runtime_root=runtime_root,
                            git_binary=staged_tools.git,
                            sandbox_exec_binary=staged_tools.sandbox_exec,
                            cmp_binary=staged_tools.cmp,
                            pause_file=self.config.supervisor_v4.pause_file,
                        )
                    except (
                        OSError,
                        OfflineHarnessViolation,
                        ProcessSupervisionError,
                    ) as exc:
                        mismatches.append(
                            f"Phase C offline fixture failed: {str(exc)[:160]}"
                        )
                        phase_c = {
                            "ready": False,
                            "failure_code_sha256": _sha256_bytes(
                                str(exc).encode("utf-8")
                            ),
                            "model_contacted": False,
                        }
                    if mismatches:
                        for result in (sdk_probe, runtime, sandbox):
                            result["skipped"] = (
                                "Phase C failed before SDK/runtime execution"
                            )
                    else:
                        try:
                            sdk_probe = self._inspect_sdk_probe(
                                policy,
                                bundle,
                                lock,
                                staged_python,
                                sandbox_binary,
                                mismatches,
                            )
                            if not mismatches:
                                runtime = self._inspect_runtime_and_protocol(
                                    policy,
                                    bundle,
                                    lock,
                                    sdk_probe,
                                    sandbox_binary,
                                    mismatches,
                                )
                            else:
                                runtime["skipped"] = (
                                    "SDK probe failed before runtime protocol"
                                )
                            if not mismatches:
                                sandbox = self._profile_probe(
                                    policy,
                                    sandbox_binary,
                                    staged_tools.nc,
                                    mismatches,
                                )
                            else:
                                sandbox["skipped"] = (
                                    "runtime protocol failed before sandbox probe"
                                )
                        except ProcessSupervisionError as exc:
                            mismatches.append(
                                "supervised qualification child stopped: "
                                f"{exc.code}; process_group_reaped="
                                f"{str(exc.process_group_reaped).lower()}"
                            )
                        self._verify_staged_python_runtime(
                            staged_python, mismatches
                        )
        capability_contract = self._capability_contract_probe()
        if not all(
            capability_contract[key]
            for key in (
                "capability_binding_complete",
                "policy_broker_interface_defined",
                "signed_envelope_interface_defined",
                "immutable_bundle_interface_defined",
                "canonical_capability_projection_defined",
                "one_use_nonce_bound",
                "capability_verifier_interface_defined",
                "credential_broker_interface_defined",
                "credential_lease_verifier_interface_defined",
                "receipt_verifier_interface_defined",
                "receipt_anchor_interface_defined",
                "owner_kill_switch_interface_defined",
            )
        ):
            mismatches.append("external capability contract probe failed")
        control_flags = {
            "background_execution": policy.background_execution,
            "live_model_execution": policy.live_model_execution,
            "live_canary_execution": policy.live_canary_execution,
            "canonical_mutations": policy.canonical_mutations,
            "candidate_application": policy.candidate_application,
            "external_actions": policy.external_actions,
            "command_network_access": policy.command_network_access,
            "model_side_commands": policy.model_side_commands,
            "model_side_file_changes": policy.model_side_file_changes,
            "model_side_tools": policy.model_side_tools,
            "approval_requests": policy.approval_requests,
            "experimental_api": policy.experimental_api,
        }
        if any(control_flags.values()):
            mismatches.append("one or more v4 live/action controls are open")
        if policy.approval_mode != "deny_all":
            mismatches.append("v4 approval mode is not deny-all")
        if self.config.supervisor_v4.pause_file.exists():
            mismatches.append("Supervisor v4 pause was requested during qualification")

        checks_passed = not mismatches
        report = {
            # Production readiness remains false until an owner-controlled
            # verifier and externally retained chain anchor exist. This command
            # qualifies the inactive implementation; it never grants authority.
            "ready": False,
            "ready_offline": False,
            "offline_qualification_checks_passed": checks_passed,
            "ready_live": False,
            "implementation_state": "implemented_inactive",
            "mismatches": mismatches,
            "runtime_bundle": bundle.public_binding(),
            "artifacts": artifacts,
            "runtime_files": runtime_files,
            "static_replay": static_replay,
            "phase_c_fake_sdk": phase_c,
            "sdk_probe": sdk_probe,
            "runtime_protocol": runtime,
            "source_sha256": source_pins,
            "loaded_source_sha256": loaded_source_pins,
            "loaded_same_user_registry_sha256": (
                loaded_same_user_registry_sha256
            ),
            "sandbox": sandbox,
            "capability_contract": capability_contract,
            "offline_broker_qualification": offline_broker_qualification,
            "offline_external_broker_qualification": (
                offline_external_broker_qualification
            ),
            "same_user_broker_qualification": same_user_broker_qualification,
            "control_flags": control_flags,
            "owner_policy_broker_configured": False,
            "owner_policy_verification_key_configured": False,
            "short_lived_credential_broker_configured": False,
            "credential_broker_verification_key_configured": False,
            "receipt_verification_key_configured": False,
            "external_receipt_anchor_configured": False,
            "receipt_anchor_verification_key_configured": False,
            "owner_kill_switch_configured": False,
            "owner_kill_switch_verification_key_configured": False,
            "live_execution_route_present": False,
            "plan_route_present": False,
            "model_contact_state": "not_dispatched",
            "model_contacted": False,
            "canonical_source_mutated": False,
            "live_canary_contracts_defined": checks_passed,
            "live_canary_design_reviewed": True,
            "offline_broker_implementation_authorized": True,
            "offline_broker_implementation_state": "implemented_inactive",
            "production_broker_externalization_reviewed": True,
            "offline_external_broker_transport_state": "implemented_inactive",
            "same_user_broker_mode": self.config.supervisor_v4.same_user_broker_mode,
            "same_user_broker_implementation_state": "qualified_inactive"
            if same_user_broker_qualification.get("qualified") is True
            else "implemented_inactive",
            "ordinary_startup_wired": False,
            "option1_canary_implementation_state": canary_implementation_state,
            **canary_accounting,
            "option1_recovery_review_completed": recovery_review_completed,
            "option1_recovery_canary_implementation_state": (
                recovery_implementation_state
            ),
            "option1_recovery_canary_owner_authorized": False,
            "option1_recovery_canary_authorization_state": (
                "consumed"
                if recovery_accounting.get("recovery_canary_launches_used") == 1
                else "absent"
            ),
            "option1_recovery_canary_launch_limit": 1,
            "option1_recovery_canary_attempt_limit": 1,
            "option1_recovery_canary_exact_confirmation_cli_present": True,
            "option1_recovery_canary_ordinary_or_http_launch_route_present": False,
            **recovery_accounting,
            "option1_recovery_canary_result_review_state": (
                recovery_result_review_state
            ),
            "option1_recovery_canary_result_reviewed": (
                recovery_result_reviewed
            ),
            "option2_service_identity_and_vault_plan_state": (
                option2_plan_contract_state
            ),
            "option2_service_identity_and_vault_plan_sha256": option2_plan[
                "plan_sha256"
            ],
            "option2_plan_owner_review_state": option2_plan_review_state,
            "option2_plan_owner_reviewed": option2_plan_reviewed,
            "option2_provisioner_contract_state": option2_manifest_contract_state,
            "option2_provisioner_dry_run_state": (
                option2_provisioner_qualification_state
            ),
            "option2_provisioner_dry_run_qualified": (
                option2_provisioner_qualified
            ),
            "option2_provisioning_manifest_review_state": (
                option2_manifest_review_state
            ),
            "option2_provisioning_manifest_owner_reviewed": (
                option2_manifest_reviewed
            ),
            "option2_identity_candidate_resolver_state": (
                option2_identity_candidate_state
            ),
            "option2_identity_candidate_fixture_qualified": (
                option2_identity_candidate_qualified
            ),
            "option2_identity_candidate_host_preflight_state": (
                option2_host_candidate_state
            ),
            "option2_identity_candidate_host_preflight_recovery_state": (
                option2_host_recovery_state
            ),
            "option2_host_preflight_recovery_design_reviewed": True,
            "option2_host_preflight_recovery_implementation_state": (
                OPTION2_HOST_PREFLIGHT_RECOVERY_STATE
            ),
            "option2_host_preflight_recovery_owner_authorized": False,
            "option2_host_preflight_recovery_authorization_state": (
                "absent"
                if option2_host_recovery_state
                == OPTION2_HOST_PREFLIGHT_RECOVERY_STATE
                else "consumed"
            ),
            "option2_host_preflight_recovery_claim_limit": 1,
            "option2_host_preflight_recovery_candidate_limit": 1,
            "option2_host_preflight_recovery_exact_confirmation_cli_present": True,
            "option2_host_preflight_recovery_ordinary_or_http_route_present": False,
            "option2_host_preflight_recovery_predecessor_claim_id": (
                option2_host_recovery_predecessor_record.get("id")
                if isinstance(option2_host_recovery_predecessor_record, Mapping)
                else None
            ),
            "option2_host_preflight_recovery_predecessor_claim_sha256": (
                option2_host_recovery_predecessor_record.get("content_sha256")
                if isinstance(option2_host_recovery_predecessor_record, Mapping)
                else None
            ),
            "option2_host_preflight_recovery_original_claim_reopened": False,
            "option2_host_preflight_recovery_raw_inventory_persisted": False,
            "option2_host_preflight_recovery_raw_inventory_returned": False,
            "option2_host_preflight_recovery_result_review_state": (
                option2_host_recovery_result_review_state
            ),
            "option2_host_preflight_recovery_result_reviewed": (
                option2_host_recovery_result_reviewed
            ),
            "option2_point_action_contract_state": (
                option2_point_action_contract_state
            ),
            "option2_point_action_contract_sha256": (
                option2_point_action_contract["contract_sha256"]
            ),
            "option2_point_action_qualification_state": (
                option2_point_action_qualification_state
            ),
            "option2_point_action_fixture_qualified": (
                option2_point_action_qualified
            ),
            "option2_point_action_expired_candidate_reused": False,
            "option2_point_action_host_query_present": False,
            "option2_point_action_host_apply_present": False,
            "option2_point_action_administrator_prompt_present": False,
            "option2_point_action_future_preflight_implementation_present": False,
            "option2_point_action_future_provisioning_implementation_present": False,
            "option2_point_action_production_preflight_qualified": False,
            "option2_point_action_production_rollback_qualified": False,
            "option2_point_action_ordinary_or_http_route_present": False,
            "option2_native_preflight_contract_state": (
                OPTION2_NATIVE_PREFLIGHT_STATE
                if option2_point_action_qualified
                else "not_applicable"
            ),
            "option2_native_preflight_contract_sha256": (
                option2_native_preflight_content.get("contract_sha256")
                if isinstance(option2_native_preflight_content, Mapping)
                else None
            ),
            "option2_native_preflight_qualification_state": (
                option2_native_preflight_qualification_state
            ),
            "option2_native_preflight_fixture_qualified": (
                option2_native_preflight_qualified
            ),
            "option2_native_preflight_fixture_case_count": (
                option2_native_preflight_content.get(
                    "native_fixture_case_count"
                )
                if isinstance(option2_native_preflight_content, Mapping)
                else 0
            ),
            "option2_native_claim_ledger_core_implemented": True,
            "option2_native_claim_ledger_crash_fixture_qualified": (
                option2_native_preflight_qualified
            ),
            "option2_native_claim_durability_order_projection_qualified": (
                option2_native_preflight_qualified
            ),
            "option2_native_durable_filesystem_io_verified": False,
            "option2_native_independent_anchor_verified": False,
            "option2_native_whole_host_snapshot_rollback_resistance_qualified": False,
            "option2_native_production_host_adapter_present": False,
            "option2_native_production_durable_ledger_adapter_present": False,
            "option2_native_production_anti_rollback_anchor_present": False,
            "option2_native_root_owned_installation_present": False,
            "option2_native_separately_signed_installation_present": False,
            "option2_native_administrator_prompt_present": False,
            "option2_native_point_action_host_query_present": False,
            "option2_native_identity_mutation_present": False,
            "option2_native_network_route_present": False,
            "option2_native_atlas_execution_route_present": False,
            "option2_native_production_preflight_qualified": False,
            "option2_native_production_rollback_qualified": False,
            "option2_native_ordinary_or_http_route_present": False,
            "option2_identity_candidate_host_inspected": bool(
                isinstance(option2_host_candidate_content, Mapping)
                and option2_host_candidate_content.get("host_preflight_performed")
                is True
            ),
            "option2_host_candidate_active": option2_host_candidate_active,
            "option2_host_candidate_sha256": (
                option2_host_candidate_content.get("candidate_sha256")
                if isinstance(option2_host_candidate_content, Mapping)
                else None
            ),
            "option2_host_inventory_sha256": (
                option2_host_candidate_content.get("inventory_sha256")
                if isinstance(option2_host_candidate_content, Mapping)
                else None
            ),
            "option2_host_candidate_expires_at": (
                option2_host_candidate_content.get("expires_at")
                if isinstance(option2_host_candidate_content, Mapping)
                else None
            ),
            "option2_host_raw_inventory_persisted": False,
            "option2_host_raw_inventory_returned": False,
            "option2_service_identity_provisioning_manifest_state": (
                option2_manifest_contract_state
            ),
            "option2_service_identity_provisioning_manifest_sha256": (
                option2_manifest["manifest_sha256"]
            ),
            "option2_production_manifest_complete": False,
            "option2_host_apply_present": False,
            "option2_production_paths_configured": (
                self._option2_production_paths_configured_count()
            ),
            "option2_service_identity_state": "not_provisioned",
            "option2_vault_state": "not_provisioned",
            "option2_key_custody_state": "absent",
            "option2_access_change_state": "not_performed",
            "option2_background_service_state": "not_installed",
            "option2_provisioning_authorized": False,
            "option2_service_identity_gate_satisfied": False,
            "live_owner_authorized": False,
            "next_gate": self._option1_combined_next_gate(
                canary_accounting,
                recovery_accounting,
                recovery_result_reviewed=recovery_result_reviewed,
                option2_plan_reviewed=option2_plan_reviewed,
                option2_provisioner_qualified=option2_provisioner_qualified,
                option2_manifest_reviewed=option2_manifest_reviewed,
                option2_identity_candidate_qualified=(
                    option2_identity_candidate_qualified
                ),
                option2_host_candidate_active=option2_host_candidate_active,
                option2_host_candidate_state=option2_host_candidate_state,
                option2_host_recovery_state=option2_host_recovery_state,
                option2_host_recovery_result_review_state=(
                    option2_host_recovery_result_review_state
                ),
                option2_host_recovery_result_reviewed=(
                    option2_host_recovery_result_reviewed
                ),
                option2_point_action_qualification_state=(
                    option2_point_action_qualification_state
                ),
                option2_point_action_qualified=option2_point_action_qualified,
                option2_native_preflight_qualification_state=(
                    option2_native_preflight_qualification_state
                ),
                option2_native_preflight_qualified=(
                    option2_native_preflight_qualified
                ),
            ),
        }
        qualification = self.database.record_supervisor_v4_qualification(
            subject="offline-runtime-v4",
            status="inactive" if checks_passed else "offline_failed",
            content={
                "implementation_state": report["implementation_state"],
                "runtime_bundle_sha256": bundle.sha256,
                "sdk_version": sdk_probe.get("sdk_version"),
                "runtime_package_version": sdk_probe.get("runtime_package_version"),
                "schema_manifest_sha256": runtime.get("manifest_sha256"),
                "replay_corpus_sha256": static_replay.get("replay_corpus_sha256"),
                "replay_decision_sha256": runtime.get("replay_decision_sha256"),
                "replay_case_count": runtime.get("replay_case_count"),
                "sandbox_profile_sha256": sandbox.get("profile_sha256"),
                "phase_c_evidence_sha256": phase_c.get("evidence_sha256"),
                "control_flags": control_flags,
                "model_contact_state": "not_dispatched",
                "model_contacted": False,
                "ready_live": False,
                "ready_offline": False,
                "offline_qualification_checks_passed": checks_passed,
                "offline_broker_qualification_passed": (
                    offline_broker_qualification.get("qualified") is True
                ),
                "offline_external_broker_qualification_passed": (
                    offline_external_broker_qualification.get("qualified") is True
                ),
                "offline_external_broker_evidence_sha256": _sha256_bytes(
                    canonical_json(offline_external_broker_qualification).encode(
                        "utf-8"
                    )
                ),
                "same_user_broker_qualification_passed": (
                    same_user_broker_qualification.get("qualified") is True
                ),
                "same_user_broker_evidence_sha256": _sha256_bytes(
                    canonical_json(same_user_broker_qualification).encode("utf-8")
                ),
                "mismatch_codes": [
                    _sha256_bytes(item.encode("utf-8"))[:16] for item in mismatches
                ],
                "raw_protocol_persisted": False,
                "prompt_persisted": False,
                "response_persisted": False,
                "reasoning_persisted": False,
                "command_output_persisted": False,
            },
        )
        report["qualification_id"] = qualification["id"]
        return report
