"""Deterministic TEST-ONLY Supervisor v4 offline qualification harness.

This module is intentionally disconnected from Atlas services, API routes, the
OpenAI SDK, credentials, and every model-contact path.  It accepts only a Git
repository carrying an explicit synthetic-fixture marker, replays a fabricated
lifecycle through :mod:`atlas_core.supervisor_v4_protocol`, and may materialize
one eligible replacement in an independent, non-integrated clone.

Candidate verification uses one fixed byte comparison in a separate macOS
Seatbelt process with network denied. Git is used only to create and inspect
the local synthetic clone, with the allowed transport restricted to ``file``
and all credential prompting disabled.
"""

from __future__ import annotations

import ctypes
import difflib
import hashlib
import os
import re
import shutil
import stat
import sys
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from atlas_core.memory.database import Database
from atlas_core.supervisor_v4_protocol import (
    COMMAND_SOURCE_CODES,
    DecisionTreatment,
    ProtocolInventory,
    ReplayReceipt,
    StructuralLimits,
    canonical_json,
    run_replay_case,
    sha256_bytes,
    validate_structured_proposal,
)
from atlas_core.supervisor_v4_process import (
    ProcessSupervisionError,
    SupervisedCompletedProcess,
    run_supervised,
)


TEST_ONLY_ACKNOWLEDGEMENT = "ATLAS_SUPERVISOR_V4_OFFLINE_FAKE_SDK_TEST_ONLY"
SYNTHETIC_FIXTURE_MARKER = ".atlas-supervisor-v4-synthetic-fixture"
SYNTHETIC_FIXTURE_MARKER_CONTENT = "atlas-supervisor-v4-test-only\n"

_MAX_SYNTHETIC_FILES = 256
_MAX_SYNTHETIC_FILE_BYTES = 2 * 1024 * 1024
_FAKE_WORKER_SHA256 = sha256_bytes(b"atlas-supervisor-v4-fake-sdk-worker-v1")
_DEFAULT_GIT_BINARY = Path("/usr/bin/git")
_DEFAULT_SANDBOX_EXEC_BINARY = Path("/usr/bin/sandbox-exec")
_DEFAULT_CMP_BINARY = Path("/usr/bin/cmp")
_GIT_NETWORK_DENY_PROFILE = '(version 1)(allow default)(deny network*)'


class OfflineHarnessViolation(RuntimeError):
    """Fail-closed test-harness violation with a non-sensitive reason code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class FakeSdkScenario(str, Enum):
    SUCCESS = "success"
    PAUSED = "paused"
    TIMEOUT = "timeout"
    READER_ERROR = "reader_error"
    LATE_EVENT = "late_event"
    CORRELATION_FAILURE = "correlation_failure"


@dataclass(frozen=True, slots=True)
class FakeSdkTranscript:
    scenario: FakeSdkScenario
    events: tuple[dict[str, Any], ...]
    stop_code: str | None
    elapsed_ticks: int
    deadline_ticks: int
    pause_observed: bool
    model_contacted: bool = False
    sdk_imported: bool = False
    network_accessed: bool = False
    credential_accessed: bool = False
    process_started: bool = False


@dataclass(frozen=True, slots=True)
class CandidateEvidence:
    candidate_root: Path
    patch_path: Path
    changed_path: str
    proposal_sha256: str
    source_baseline_sha256: str
    source_snapshot_sha256: str
    candidate_snapshot_sha256: str
    replacement_sha256: str
    patch_sha256: str
    candidate_head: str
    source_unchanged: bool
    remotes_present: bool
    hooks_present: bool
    alternates_present: bool
    shared_hardlinks_present: bool
    candidate_integrated: bool
    verification_mode: str
    verification_process_started: bool
    os_sandbox_enforced: bool
    network_capability_exercised: bool
    command_executed_during_verification: bool

    def public_receipt(self) -> dict[str, Any]:
        receipt = asdict(self)
        receipt.pop("candidate_root")
        receipt.pop("patch_path")
        return receipt


@dataclass(frozen=True, slots=True)
class OfflineQualificationResult:
    scenario: FakeSdkScenario
    status: str
    stop_code: str
    initial_qualification_id: str
    final_qualification_id: str
    job_id: str
    protocol_receipt: dict[str, Any]
    candidate: CandidateEvidence | None
    model_contact_state: str
    authority_granted: bool = False
    model_contacted: bool = False
    candidate_integrated: bool = False


def _read_regular_bytes(
    path: Path, *, maximum: int = _MAX_SYNTHETIC_FILE_BYTES
) -> bytes:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise OfflineHarnessViolation("synthetic_file_invalid") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 0
            or before.st_size > maximum
        ):
            raise OfflineHarnessViolation("synthetic_file_invalid")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(content) > maximum
            or len(content) != before.st_size
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        ):
            raise OfflineHarnessViolation("synthetic_file_changed_during_read")
        return content
    finally:
        os.close(descriptor)


def _sha256_file(path: Path, *, maximum: int = _MAX_SYNTHETIC_FILE_BYTES) -> str:
    digest = hashlib.sha256()
    digest.update(_read_regular_bytes(path, maximum=maximum))
    return digest.hexdigest()


def _private_git_environment(home: Path) -> dict[str, str]:
    home.mkdir(mode=0o700, parents=True, exist_ok=False)
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / "xdg"),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/usr/bin/false",
        "SSH_ASKPASS": "/usr/bin/false",
        "GIT_ALLOW_PROTOCOL": "file",
        "GIT_EXEC_PATH": "/usr/libexec/git-core",
        "LC_ALL": "C",
        "LANG": "C",
    }


def _run_git(
    arguments: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    git_binary: Path = _DEFAULT_GIT_BINARY,
    sandbox_exec_binary: Path = _DEFAULT_SANDBOX_EXEC_BINARY,
    pause_file: Path | None = None,
    allowed_returncodes: frozenset[int] = frozenset({0}),
) -> SupervisedCompletedProcess:
    if not git_binary.is_file() or not sandbox_exec_binary.is_file():
        raise OfflineHarnessViolation("git_unavailable")
    try:
        completed = run_supervised(
            [
                str(sandbox_exec_binary),
                "-p",
                _GIT_NETWORK_DENY_PROFILE,
                str(git_binary),
                *arguments,
            ],
            cwd=cwd,
            env=dict(env),
            timeout=20,
            pause_file=pause_file,
            max_output_bytes=262_144,
        )
    except ProcessSupervisionError as exc:
        if not exc.process_group_reaped and exc.process_id is not None:
            raise OfflineHarnessViolation("local_git_process_group_not_reaped") from exc
        raise OfflineHarnessViolation(f"local_git_{exc.code}") from exc
    if completed.returncode not in allowed_returncodes:
        raise OfflineHarnessViolation("local_git_operation_failed")
    return completed


def synthetic_git_baseline_sha256(
    source_repo: Path,
    *,
    git_binary: Path = _DEFAULT_GIT_BINARY,
    sandbox_exec_binary: Path = _DEFAULT_SANDBOX_EXEC_BINARY,
    pause_file: Path | None = None,
) -> str:
    """Bind an explicit synthetic repository to its current commit."""

    source = source_repo.expanduser().resolve(strict=True)
    _require_synthetic_source(source)
    with tempfile.TemporaryDirectory(prefix="atlas-v4-git-home-") as temporary:
        env = _private_git_environment(Path(temporary) / "home")
        head = _run_git(
            ["rev-parse", "--verify", "HEAD"],
            cwd=source,
            env=env,
            git_binary=git_binary,
            sandbox_exec_binary=sandbox_exec_binary,
            pause_file=pause_file,
        ).stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40,64}", head):
        raise OfflineHarnessViolation("synthetic_head_invalid")
    return sha256_bytes(b"atlas-supervisor-v4-git-head-v1\0" + head.encode("ascii"))


def _require_synthetic_source(source: Path) -> None:
    if not source.is_dir() or source.is_symlink():
        raise OfflineHarnessViolation("synthetic_source_invalid")
    marker = source / SYNTHETIC_FIXTURE_MARKER
    try:
        content = _read_regular_bytes(marker, maximum=128).decode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise OfflineHarnessViolation("synthetic_fixture_marker_missing") from exc
    except OfflineHarnessViolation as exc:
        raise OfflineHarnessViolation("synthetic_fixture_marker_missing") from exc
    if content != SYNTHETIC_FIXTURE_MARKER_CONTENT:
        raise OfflineHarnessViolation("synthetic_fixture_marker_invalid")


def _snapshot_worktree(root: Path) -> str:
    entries: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if relative.parts and relative.parts[0] == ".git":
            continue
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            raise OfflineHarnessViolation("synthetic_source_special_file")
        entries.append(
            {
                "path": relative.as_posix(),
                "mode": stat.S_IMODE(metadata.st_mode),
                "size": metadata.st_size,
                "sha256": _sha256_file(path),
            }
        )
        if len(entries) > _MAX_SYNTHETIC_FILES:
            raise OfflineHarnessViolation("synthetic_file_count_exceeded")
    return sha256_bytes(canonical_json(entries).encode("utf-8"))


def _event(method: str, payload: Mapping[str, Any] | None = None) -> dict[str, Any]:
    return {
        "method": method,
        "server_request": False,
        "schema_valid": True,
        "correlation": {"task": True, "thread": True, "turn": True, "item": True},
        "payload": dict(payload or {}),
        "truncated": False,
    }


def strict_synthetic_proposal(
    inventory: ProtocolInventory, *, replacement: str
) -> dict[str, Any]:
    proposal = {
        "schema_version": inventory.proposal_schema_version,
        "operation": inventory.proposal_operation,
        "baseline_sha256": inventory.proposal_baseline_sha256,
        "path": inventory.proposal_path,
        "original_sha256": inventory.proposal_original_sha256,
        "replacement": replacement,
    }
    validate_structured_proposal(proposal, inventory)
    return proposal


def fabricate_sdk_transcript(
    inventory: ProtocolInventory,
    *,
    proposal: Mapping[str, Any],
    scenario: FakeSdkScenario,
) -> FakeSdkTranscript:
    """Create a synthetic SDK lifecycle without importing or starting an SDK."""

    proposal_sha256 = validate_structured_proposal(proposal, inventory)
    events = [
        _event("thread/started"),
        _event("turn/started"),
        _event("item/started", {"item_type": "agentMessage"}),
        _event(
            "item/completed",
            {
                "item_type": "agentMessage",
                "message_phase": "final_answer",
                "proposal": dict(proposal),
            },
        ),
        _event(
            "turn/completed",
            {
                "status": "completed",
                "typed_result_status": "completed",
                "result_proposal_sha256": proposal_sha256,
                "readers_joined": True,
                "queue_drained": True,
                "late_event_count": 0,
                "reader_error_count": 0,
            },
        ),
    ]
    stop_code: str | None = None
    elapsed_ticks = len(events)
    deadline_ticks = 10
    pause_observed = False
    if scenario is FakeSdkScenario.PAUSED:
        events = events[:2]
        stop_code = "pause_requested"
        pause_observed = True
    elif scenario is FakeSdkScenario.TIMEOUT:
        events = events[:3]
        stop_code = "deadline_exceeded"
        elapsed_ticks = deadline_ticks + 1
    elif scenario is FakeSdkScenario.READER_ERROR:
        events[-1]["payload"]["reader_error_count"] = 1
        stop_code = "reader_error_observed"
    elif scenario is FakeSdkScenario.LATE_EVENT:
        # Feed an actual post-terminal event so the adapter's terminal barrier,
        # rather than an orchestration-side counter alone, proves the stop.
        events.append(_event("thread/status/changed"))
        stop_code = "late_event_observed"
    elif scenario is FakeSdkScenario.CORRELATION_FAILURE:
        events[1]["correlation"]["turn"] = False
        stop_code = "correlation_mismatch"
    elif scenario is not FakeSdkScenario.SUCCESS:
        raise OfflineHarnessViolation("fake_sdk_scenario_unknown")
    return FakeSdkTranscript(
        scenario=scenario,
        events=tuple(events),
        stop_code=stop_code,
        elapsed_ticks=elapsed_ticks,
        deadline_ticks=deadline_ticks,
        pause_observed=pause_observed,
    )


def replay_fake_sdk_transcript(
    inventory: ProtocolInventory, transcript: FakeSdkTranscript
) -> ReplayReceipt:
    case = {
        "id": f"fake-sdk-{transcript.scenario.value.replace('_', '-')}",
        "events": [dict(event) for event in transcript.events],
    }
    return run_replay_case(case, inventory)


def _regular_file_identities(root: Path) -> set[tuple[int, int]]:
    identities: set[tuple[int, int]] = set()
    for path in root.rglob("*"):
        metadata = path.lstat()
        if stat.S_ISREG(metadata.st_mode):
            if metadata.st_nlink != 1:
                raise OfflineHarnessViolation("candidate_hardlink_detected")
            identities.add((metadata.st_dev, metadata.st_ino))
    return identities


def _assert_git_isolation(
    *,
    source: Path,
    candidate: Path,
    env: Mapping[str, str],
    git_binary: Path,
    sandbox_exec_binary: Path,
    pause_file: Path | None,
) -> str:
    git_options = {
        "git_binary": git_binary,
        "sandbox_exec_binary": sandbox_exec_binary,
        "pause_file": pause_file,
    }
    remote_output = _run_git(
        ["remote"], cwd=candidate, env=env, **git_options
    ).stdout.strip()
    if remote_output:
        raise OfflineHarnessViolation("candidate_remote_present")
    remote_config = _run_git(
        ["config", "--local", "--get-regexp", r"^remote\."],
        cwd=candidate,
        env=env,
        **git_options,
        allowed_returncodes=frozenset({0, 1}),
    )
    if remote_config.returncode == 0 and remote_config.stdout.strip():
        raise OfflineHarnessViolation("candidate_remote_config_present")
    hooks = candidate / ".git" / "hooks"
    if hooks.exists() and any(hooks.iterdir()):
        raise OfflineHarnessViolation("candidate_hook_present")
    alternates = candidate / ".git" / "objects" / "info" / "alternates"
    if alternates.exists() and alternates.read_bytes().strip():
        raise OfflineHarnessViolation("candidate_alternates_present")
    remotes = candidate / ".git" / "refs" / "remotes"
    if remotes.exists() and any(remotes.rglob("*")):
        raise OfflineHarnessViolation("candidate_remote_ref_present")
    packed_refs = candidate / ".git" / "packed-refs"
    if packed_refs.exists() and b"refs/remotes/" in packed_refs.read_bytes():
        raise OfflineHarnessViolation("candidate_remote_ref_present")
    source_ids = _regular_file_identities(source)
    candidate_ids = _regular_file_identities(candidate)
    if source_ids.intersection(candidate_ids):
        raise OfflineHarnessViolation("candidate_shared_hardlink_detected")
    head = (candidate / ".git" / "HEAD").read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{40,64}", head):
        raise OfflineHarnessViolation("candidate_not_detached")
    return head


def _write_private(path: Path, content: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        offset = 0
        while offset < len(content):
            offset += os.write(descriptor, content[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _directory_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_uid,
    )


def _regular_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


@dataclass(slots=True)
class _CandidateTargetHandle:
    root: Path
    relative: Path
    directory_descriptors: list[int]
    directory_components: tuple[str, ...]
    directory_identities: tuple[tuple[int, int, int, int], ...]
    target_descriptor: int
    target_identity: tuple[int, int, int, int, int, int, int, int]

    @property
    def parent_descriptor(self) -> int:
        return self.directory_descriptors[-1]

    @property
    def target_name(self) -> str:
        return self.relative.parts[-1]

    @property
    def path(self) -> Path:
        return self.root / self.relative

    def close(self) -> None:
        if self.target_descriptor >= 0:
            os.close(self.target_descriptor)
            self.target_descriptor = -1
        for descriptor in reversed(self.directory_descriptors):
            os.close(descriptor)
        self.directory_descriptors.clear()


def _open_candidate_target(root: Path, relative_text: str) -> _CandidateTargetHandle:
    relative = Path(relative_text)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise OfflineHarnessViolation("candidate_path_invalid")

    root_path = root.expanduser().absolute()
    read_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    directory_flags = (
        read_flags
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        root_descriptor = os.open(root_path, directory_flags)
    except OSError as exc:
        raise OfflineHarnessViolation("candidate_parent_invalid") from exc
    descriptors = [root_descriptor]
    identities = [_directory_identity(os.fstat(root_descriptor))]
    components: list[str] = []
    try:
        for component in relative.parts[:-1]:
            try:
                descriptor = os.open(
                    component,
                    directory_flags,
                    dir_fd=descriptors[-1],
                )
            except OSError as exc:
                raise OfflineHarnessViolation("candidate_parent_invalid") from exc
            metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                os.close(descriptor)
                raise OfflineHarnessViolation("candidate_parent_invalid")
            descriptors.append(descriptor)
            identities.append(_directory_identity(metadata))
            components.append(component)

        try:
            target_descriptor = os.open(
                relative.parts[-1],
                os.O_RDWR
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptors[-1],
            )
        except OSError as exc:
            raise OfflineHarnessViolation("candidate_target_invalid") from exc
        target_metadata = os.fstat(target_descriptor)
        if (
            not stat.S_ISREG(target_metadata.st_mode)
            or target_metadata.st_nlink != 1
        ):
            os.close(target_descriptor)
            raise OfflineHarnessViolation("candidate_target_invalid")
        return _CandidateTargetHandle(
            root=root_path,
            relative=relative,
            directory_descriptors=descriptors,
            directory_components=tuple(components),
            directory_identities=tuple(identities),
            target_descriptor=target_descriptor,
            target_identity=_regular_identity(target_metadata),
        )
    except Exception:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise


def _verify_candidate_parent_chain(handle: _CandidateTargetHandle) -> None:
    try:
        root_metadata = os.stat(handle.root, follow_symlinks=False)
    except OSError as exc:
        raise OfflineHarnessViolation("candidate_parent_changed") from exc
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or _directory_identity(root_metadata) != handle.directory_identities[0]
        or _directory_identity(os.fstat(handle.directory_descriptors[0]))
        != handle.directory_identities[0]
    ):
        raise OfflineHarnessViolation("candidate_parent_changed")

    for index, component in enumerate(handle.directory_components):
        parent_descriptor = handle.directory_descriptors[index]
        child_descriptor = handle.directory_descriptors[index + 1]
        expected = handle.directory_identities[index + 1]
        try:
            named_metadata = os.stat(
                component,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise OfflineHarnessViolation("candidate_parent_changed") from exc
        if (
            not stat.S_ISDIR(named_metadata.st_mode)
            or _directory_identity(named_metadata) != expected
            or _directory_identity(os.fstat(child_descriptor)) != expected
        ):
            raise OfflineHarnessViolation("candidate_parent_changed")


def _verify_candidate_target_binding(handle: _CandidateTargetHandle) -> None:
    try:
        named_metadata = os.stat(
            handle.target_name,
            dir_fd=handle.parent_descriptor,
            follow_symlinks=False,
        )
        opened_metadata = os.fstat(handle.target_descriptor)
    except OSError as exc:
        raise OfflineHarnessViolation("candidate_target_changed") from exc
    if (
        not stat.S_ISREG(named_metadata.st_mode)
        or _regular_identity(named_metadata) != handle.target_identity
        or _regular_identity(opened_metadata) != handle.target_identity
    ):
        raise OfflineHarnessViolation("candidate_target_changed")


def _read_candidate_target(
    handle: _CandidateTargetHandle,
    *,
    maximum: int = _MAX_SYNTHETIC_FILE_BYTES,
) -> bytes:
    _verify_candidate_parent_chain(handle)
    _verify_candidate_target_binding(handle)
    before = os.fstat(handle.target_descriptor)
    if before.st_size < 0 or before.st_size > maximum:
        raise OfflineHarnessViolation("candidate_target_invalid")
    chunks: list[bytes] = []
    offset = 0
    while offset <= maximum:
        chunk = os.pread(
            handle.target_descriptor,
            min(65_536, maximum + 1 - offset),
            offset,
        )
        if not chunk:
            break
        chunks.append(chunk)
        offset += len(chunk)
    content = b"".join(chunks)
    after = os.fstat(handle.target_descriptor)
    if (
        len(content) > maximum
        or len(content) != before.st_size
        or _regular_identity(before) != _regular_identity(after)
    ):
        raise OfflineHarnessViolation("candidate_target_changed")
    _verify_candidate_target_binding(handle)
    return content


def _atomic_private_replace(
    handle: _CandidateTargetHandle,
    replacement: bytes,
) -> None:
    """Rewrite only the already-open candidate inode under frozen parents.

    Darwin's user-immutable directory flag prevents every directory in the
    descriptor-bound parent chain from being renamed while the target is
    changed. The content write never reopens a pathname and therefore cannot
    be redirected outside the disposable clone by a parent-swap race.
    """

    _verify_candidate_parent_chain(handle)
    _verify_candidate_target_binding(handle)
    immutable = getattr(stat, "UF_IMMUTABLE", None)
    if sys.platform != "darwin" or not isinstance(immutable, int):
        raise OfflineHarnessViolation("candidate_parent_freeze_unavailable")
    libc = ctypes.CDLL(None, use_errno=True)
    fchflags = getattr(libc, "fchflags", None)
    if fchflags is None:
        raise OfflineHarnessViolation("candidate_parent_freeze_unavailable")
    fchflags.argtypes = [ctypes.c_int, ctypes.c_uint]
    fchflags.restype = ctypes.c_int
    frozen: list[tuple[int, int]] = []

    def set_flags(descriptor: int, flags: int) -> None:
        ctypes.set_errno(0)
        if fchflags(descriptor, flags) != 0:
            raise OSError(ctypes.get_errno(), "fchflags")

    try:
        for descriptor in handle.directory_descriptors:
            original_flags = int(os.fstat(descriptor).st_flags)
            set_flags(descriptor, original_flags | immutable)
            if not int(os.fstat(descriptor).st_flags) & immutable:
                raise OfflineHarnessViolation("candidate_parent_freeze_failed")
            frozen.append((descriptor, original_flags))

        _verify_candidate_parent_chain(handle)
        _verify_candidate_target_binding(handle)
        before = os.fstat(handle.target_descriptor)
        os.fchmod(handle.target_descriptor, 0o600)
        os.ftruncate(handle.target_descriptor, 0)
        offset = 0
        while offset < len(replacement):
            offset += os.pwrite(
                handle.target_descriptor,
                replacement[offset:],
                offset,
            )
        os.fsync(handle.target_descriptor)
        replacement_metadata = os.fstat(handle.target_descriptor)
        if (
            not stat.S_ISREG(replacement_metadata.st_mode)
            or replacement_metadata.st_nlink != 1
            or replacement_metadata.st_uid != os.getuid()
            or stat.S_IMODE(replacement_metadata.st_mode) != 0o600
            or replacement_metadata.st_size != len(replacement)
            or (before.st_dev, before.st_ino)
            != (replacement_metadata.st_dev, replacement_metadata.st_ino)
            or os.pread(handle.target_descriptor, len(replacement) + 1, 0)
            != replacement
        ):
            raise OfflineHarnessViolation("candidate_target_changed")
        handle.target_identity = _regular_identity(replacement_metadata)
        _verify_candidate_parent_chain(handle)
        _verify_candidate_target_binding(handle)
    except OSError as exc:
        raise OfflineHarnessViolation("candidate_replacement_failed") from exc
    finally:
        unfreeze_failed = False
        for descriptor, original_flags in reversed(frozen):
            try:
                set_flags(descriptor, original_flags)
            except OSError:
                unfreeze_failed = True
        if unfreeze_failed:
            raise OfflineHarnessViolation("candidate_parent_unfreeze_failed")


def _materialize_and_verify_candidate(
    *,
    source: Path,
    workspace_root: Path,
    proposal: Mapping[str, Any],
    proposal_sha256: str,
    expected_source_baseline_sha256: str,
    git_binary: Path,
    sandbox_exec_binary: Path,
    cmp_binary: Path,
    pause_file: Path | None,
) -> CandidateEvidence:
    source_snapshot_before = _snapshot_worktree(source)
    actual_baseline = synthetic_git_baseline_sha256(
        source,
        git_binary=git_binary,
        sandbox_exec_binary=sandbox_exec_binary,
        pause_file=pause_file,
    )
    if actual_baseline != expected_source_baseline_sha256:
        raise OfflineHarnessViolation("synthetic_baseline_mismatch")

    candidate = workspace_root / f"candidate-{proposal_sha256[:16]}"
    artifacts = workspace_root / f"artifacts-{proposal_sha256[:16]}"
    if candidate.exists() or candidate.is_symlink() or artifacts.exists():
        raise OfflineHarnessViolation("candidate_output_already_exists")
    artifacts.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(
        prefix=".git-home-", dir=workspace_root
    ) as temporary:
        env = _private_git_environment(Path(temporary) / "home")
        git_options = {
            "git_binary": git_binary,
            "sandbox_exec_binary": sandbox_exec_binary,
            "pause_file": pause_file,
        }
        clean = _run_git(
            ["status", "--porcelain=v1", "--untracked-files=all"],
            cwd=source,
            env=env,
            **git_options,
        ).stdout
        if clean.strip():
            raise OfflineHarnessViolation("synthetic_source_not_clean")
        source_head = _run_git(
            ["rev-parse", "--verify", "HEAD"],
            cwd=source,
            env=env,
            **git_options,
        ).stdout.strip()
        _run_git(
            [
                "clone",
                "--no-local",
                "--no-hardlinks",
                "--no-checkout",
                "--config",
                "core.hooksPath=/dev/null",
                "--",
                str(source),
                str(candidate),
            ],
            cwd=workspace_root,
            env=env,
            **git_options,
        )
        hooks = candidate / ".git" / "hooks"
        if hooks.exists():
            shutil.rmtree(hooks)
        _run_git(
            ["remote", "remove", "origin"],
            cwd=candidate,
            env=env,
            **git_options,
        )
        _run_git(
            ["-c", "core.hooksPath=/dev/null", "checkout", "--detach", "--force", "HEAD"],
            cwd=candidate,
            env=env,
            **git_options,
        )
        candidate_head = _assert_git_isolation(
            source=source,
            candidate=candidate,
            env=env,
            git_binary=git_binary,
            sandbox_exec_binary=sandbox_exec_binary,
            pause_file=pause_file,
        )
        if candidate_head != source_head:
            raise OfflineHarnessViolation("candidate_head_mismatch")

    target_handle = _open_candidate_target(candidate, str(proposal["path"]))
    try:
        target = target_handle.path
        original = _read_candidate_target(target_handle)
        if sha256_bytes(original) != proposal["original_sha256"]:
            raise OfflineHarnessViolation("candidate_original_digest_mismatch")
        replacement = str(proposal["replacement"]).encode("utf-8")
        _atomic_private_replace(target_handle, replacement)
        patch_content = "".join(
            difflib.unified_diff(
                original.decode("utf-8").splitlines(keepends=True),
                replacement.decode("utf-8").splitlines(keepends=True),
                fromfile=f"a/{proposal['path']}",
                tofile=f"b/{proposal['path']}",
            )
        ).encode("utf-8")
        patch_path = artifacts / "candidate.patch"
        _write_private(patch_path, patch_content)

        # The independent check is a fixed byte comparison in a separate macOS
        # Seatbelt process. The profile permits only reads of the disposable
        # candidate and one transient expected-value file; network stays denied.
        if (
            sys.platform != "darwin"
            or not sandbox_exec_binary.is_file()
            or not cmp_binary.is_file()
        ):
            raise OfflineHarnessViolation("candidate_os_sandbox_unavailable")
        expected = artifacts / ".expected-replacement"
        observed = artifacts / ".observed-replacement"
        _write_private(expected, replacement)
        _write_private(observed, _read_candidate_target(target_handle))
        artifacts_real = artifacts.resolve(strict=True)
        cmp_real = cmp_binary.resolve(strict=True)
        profile = (
            '(version 1)(deny default)(import "system.sb")(deny network*)'
            f'(allow file-read* (subpath "{artifacts_real}"))'
            f'(allow file-read* (literal "{cmp_real}"))'
            f'(allow process-exec (literal "{cmp_real}"))'
        )
        _verify_candidate_parent_chain(target_handle)
        _verify_candidate_target_binding(target_handle)
        try:
            try:
                checked = run_supervised(
                    [
                        str(sandbox_exec_binary),
                        "-p",
                        profile,
                        str(cmp_real),
                        str(observed.resolve(strict=True)),
                        str(expected.resolve(strict=True)),
                    ],
                    cwd=artifacts_real,
                    env={
                        "PATH": "/usr/bin:/bin",
                        "HOME": str(artifacts_real),
                        "TMPDIR": str(artifacts_real),
                        "LC_ALL": "C",
                        "LANG": "C",
                    },
                    timeout=10,
                    pause_file=pause_file,
                    max_output_bytes=8_192,
                )
            except ProcessSupervisionError as exc:
                if not exc.process_group_reaped and exc.process_id is not None:
                    raise OfflineHarnessViolation(
                        "candidate_process_group_not_reaped"
                    ) from exc
                raise OfflineHarnessViolation(
                    f"candidate_check_{exc.code}"
                ) from exc
            if checked.returncode != 0:
                raise OfflineHarnessViolation("candidate_sandboxed_check_failed")
        finally:
            expected.unlink(missing_ok=True)
            observed.unlink(missing_ok=True)

        _verify_candidate_parent_chain(target_handle)
        _verify_candidate_target_binding(target_handle)
        if _read_candidate_target(target_handle) != replacement:
            raise OfflineHarnessViolation("candidate_replacement_verification_failed")
        target_metadata = os.fstat(target_handle.target_descriptor)
        if (
            stat.S_IMODE(target_metadata.st_mode) != 0o600
            or target_metadata.st_nlink != 1
        ):
            raise OfflineHarnessViolation("candidate_replacement_mode_invalid")
        if stat.S_IMODE(patch_path.lstat().st_mode) != 0o600:
            raise OfflineHarnessViolation("candidate_patch_mode_invalid")
    finally:
        target_handle.close()
    source_snapshot_after = _snapshot_worktree(source)
    if source_snapshot_after != source_snapshot_before:
        raise OfflineHarnessViolation("synthetic_source_changed")
    if _sha256_file(source / str(proposal["path"])) != proposal["original_sha256"]:
        raise OfflineHarnessViolation("synthetic_source_target_changed")
    source_ids = _regular_file_identities(source)
    candidate_ids = _regular_file_identities(candidate)
    if source_ids.intersection(candidate_ids):
        raise OfflineHarnessViolation("candidate_shared_hardlink_detected")
    head_after = (candidate / ".git" / "HEAD").read_text(encoding="ascii").strip()
    if head_after != candidate_head:
        raise OfflineHarnessViolation("candidate_head_changed")
    config_text = (candidate / ".git" / "config").read_text(encoding="utf-8")
    if re.search(r"(?mi)^\s*\[remote\s+", config_text):
        raise OfflineHarnessViolation("candidate_remote_config_present")
    hooks = candidate / ".git" / "hooks"
    hooks_present = hooks.exists() and any(hooks.iterdir())
    alternates = candidate / ".git" / "objects" / "info" / "alternates"
    alternates_present = alternates.exists() and bool(alternates.read_bytes().strip())
    if hooks_present or alternates_present:
        raise OfflineHarnessViolation("candidate_isolation_changed")
    return CandidateEvidence(
        candidate_root=candidate,
        patch_path=patch_path,
        changed_path=str(proposal["path"]),
        proposal_sha256=proposal_sha256,
        source_baseline_sha256=actual_baseline,
        source_snapshot_sha256=source_snapshot_before,
        candidate_snapshot_sha256=_snapshot_worktree(candidate),
        replacement_sha256=sha256_bytes(replacement),
        patch_sha256=_sha256_file(patch_path),
        candidate_head=candidate_head,
        source_unchanged=True,
        remotes_present=False,
        hooks_present=False,
        alternates_present=False,
        shared_hardlinks_present=False,
        candidate_integrated=False,
        verification_mode="macos_seatbelt_deterministic_cmp",
        verification_process_started=True,
        os_sandbox_enforced=True,
        network_capability_exercised=False,
        command_executed_during_verification=True,
    )


def _time_sequence(base: str | None) -> tuple[str, ...]:
    if base is None:
        start = datetime.now(timezone.utc)
    else:
        try:
            start = datetime.fromisoformat(base.replace("Z", "+00:00"))
        except ValueError as exc:
            raise OfflineHarnessViolation("qualification_timestamp_invalid") from exc
        if start.tzinfo is None:
            raise OfflineHarnessViolation("qualification_timestamp_invalid")
        start = start.astimezone(timezone.utc)
    return tuple((start + timedelta(seconds=index)).isoformat() for index in range(6))


def _fake_worker_identity() -> dict[str, Any]:
    return {
        "worker_id": "fake-sdk-test-only",
        "worker_pid": 42420,
        "worker_start_token": "fictional-worker-start-token",
        "process_group_id": 42420,
        "process_group_start_token": "fictional-process-group-start-token",
        "executable_sha256": _FAKE_WORKER_SHA256,
    }


class DeterministicOfflineHarness:
    """Explicitly armed fake-SDK runner with no runtime integration surface."""

    def __init__(
        self,
        *,
        database: Database,
        inventory: ProtocolInventory,
        workspace_root: Path,
        test_only_acknowledgement: str,
        git_binary: Path = _DEFAULT_GIT_BINARY,
        sandbox_exec_binary: Path = _DEFAULT_SANDBOX_EXEC_BINARY,
        cmp_binary: Path = _DEFAULT_CMP_BINARY,
        pause_file: Path | None = None,
    ) -> None:
        if test_only_acknowledgement != TEST_ONLY_ACKNOWLEDGEMENT:
            raise OfflineHarnessViolation("test_only_acknowledgement_required")
        self.database = database
        self.inventory = inventory
        self.git_binary = git_binary.expanduser().absolute()
        self.sandbox_exec_binary = sandbox_exec_binary.expanduser().absolute()
        self.cmp_binary = cmp_binary.expanduser().absolute()
        self.pause_file = pause_file.expanduser().absolute() if pause_file else None
        self.workspace_root = workspace_root.expanduser().absolute()
        if self.workspace_root.exists() or self.workspace_root.is_symlink():
            raise OfflineHarnessViolation("offline_workspace_must_not_exist")
        self.workspace_root.mkdir(mode=0o700, parents=True)

    def qualify(
        self,
        *,
        source_repo: Path,
        replacement: str,
        scenario: FakeSdkScenario = FakeSdkScenario.SUCCESS,
        observed_at: str | None = None,
    ) -> OfflineQualificationResult:
        source = source_repo.expanduser().resolve(strict=True)
        _require_synthetic_source(source)
        if self.workspace_root == source or self.workspace_root.is_relative_to(source):
            raise OfflineHarnessViolation("offline_workspace_overlaps_source")
        proposal = strict_synthetic_proposal(self.inventory, replacement=replacement)
        proposal_sha256 = validate_structured_proposal(proposal, self.inventory)
        timestamps = _time_sequence(observed_at)
        initial = self.database.record_supervisor_v4_qualification(
            subject="fake_sdk.offline",
            status="inactive",
            content={
                "scenario": scenario.value,
                "proposal_sha256": proposal_sha256,
                "authority_granted": False,
                "model_contacted": False,
            },
            created_at=timestamps[0],
        )
        job = self.database.create_supervisor_v4_offline_job(
            qualification_id=str(initial["id"]),
            definition={
                "fixture": "synthetic",
                "scenario": scenario.value,
                "proposal_sha256": proposal_sha256,
                "model_contact_allowed": False,
                "authority_granted": False,
            },
            created_at=timestamps[1],
        )
        self.database.transition_supervisor_v4_offline_job(
            str(job["id"]),
            state="offline_qualifying",
            model_contact_state="not_dispatched",
            worker_identity=_fake_worker_identity(),
            details={"phase": "fabricated_protocol_replay", "scenario": scenario.value},
            recorded_at=timestamps[2],
        )
        transcript = fabricate_sdk_transcript(
            self.inventory, proposal=proposal, scenario=scenario
        )
        replay = replay_fake_sdk_transcript(self.inventory, transcript)
        public_replay = replay.to_dict()
        if any(
            (
                transcript.model_contacted,
                transcript.sdk_imported,
                transcript.network_accessed,
                transcript.credential_accessed,
                transcript.process_started,
            )
        ):
            raise OfflineHarnessViolation("fake_sdk_contact_boundary_violated")
        if (
            scenario is FakeSdkScenario.PAUSED
            and not transcript.pause_observed
        ) or (
            scenario is FakeSdkScenario.TIMEOUT
            and transcript.elapsed_ticks <= transcript.deadline_ticks
        ):
            raise OfflineHarnessViolation("fake_sdk_stop_evidence_invalid")

        eligible = (
            scenario is FakeSdkScenario.SUCCESS
            and replay.outcome == DecisionTreatment.PROPOSAL_ELIGIBLE.value
            and replay.decision_code == "proposal_schema_eligible"
        )
        candidate: CandidateEvidence | None = None
        if eligible:
            try:
                candidate = _materialize_and_verify_candidate(
                    source=source,
                    workspace_root=self.workspace_root,
                    proposal=proposal,
                    proposal_sha256=proposal_sha256,
                    expected_source_baseline_sha256=self.inventory.proposal_baseline_sha256,
                    git_binary=self.git_binary,
                    sandbox_exec_binary=self.sandbox_exec_binary,
                    cmp_binary=self.cmp_binary,
                    pause_file=self.pause_file,
                )
            except OfflineHarnessViolation as exc:
                status = "offline_failed"
                stop_code = exc.code
            else:
                status = "offline_qualified"
                stop_code = "offline_fixture_qualified"
        else:
            status = "offline_failed"
            stop_code = transcript.stop_code or replay.decision_code

        self.database.transition_supervisor_v4_offline_job(
            str(job["id"]),
            state=status,
            model_contact_state="not_dispatched",
            details={
                "stop_code": stop_code,
                "event_chain_sha256": replay.event_chain_sha256,
                "proposal_sha256": replay.validated_proposal_sha256,
                "candidate_integrated": False,
                "model_contacted": False,
                "authority_granted": False,
            },
            recorded_at=timestamps[3],
        )
        final = self.database.record_supervisor_v4_qualification(
            subject="fake_sdk.offline",
            status=status,
            content={
                "scenario": scenario.value,
                "stop_code": stop_code,
                "protocol_receipt_sha256": sha256_bytes(
                    canonical_json(public_replay).encode("utf-8")
                ),
                "candidate_receipt_sha256": (
                    sha256_bytes(
                        canonical_json(candidate.public_receipt()).encode("utf-8")
                    )
                    if candidate is not None
                    else None
                ),
                "candidate_integrated": False,
                "model_contacted": False,
                "authority_granted": False,
            },
            created_at=timestamps[4],
        )
        return OfflineQualificationResult(
            scenario=scenario,
            status=status,
            stop_code=stop_code,
            initial_qualification_id=str(initial["id"]),
            final_qualification_id=str(final["id"]),
            job_id=str(job["id"]),
            protocol_receipt=public_replay,
            candidate=candidate,
            model_contact_state="not_dispatched",
        )


def reconcile_orphaned_offline_jobs(
    database: Database,
    *,
    identity_is_live: Callable[[dict[str, Any]], bool],
    test_only_acknowledgement: str,
    recorded_at: str | None = None,
) -> list[dict[str, Any]]:
    """Close dead fake workers without starting, resuming, or killing a process."""

    if test_only_acknowledgement != TEST_ONLY_ACKNOWLEDGEMENT:
        raise OfflineHarnessViolation("test_only_acknowledgement_required")
    if not callable(identity_is_live):
        raise OfflineHarnessViolation("identity_probe_required")
    results: list[dict[str, Any]] = []
    for candidate in database.supervisor_v4_reconciliation_candidates():
        try:
            is_live = bool(identity_is_live(dict(candidate)))
        except Exception as exc:
            raise OfflineHarnessViolation("identity_probe_failed") from exc
        if is_live:
            results.append(
                {
                    "job_id": candidate["job_id"],
                    "outcome": "active_unchanged",
                    "model_contact_state": candidate["model_contact_state"],
                }
            )
            continue
        terminal = database.transition_supervisor_v4_offline_job(
            str(candidate["job_id"]),
            state="interrupted",
            model_contact_state=str(candidate["model_contact_state"]),
            details={
                "reconciliation": "dead_identity_closed",
                "process_started": False,
                "process_killed": False,
                "process_resumed": False,
                "authority_granted": False,
            },
            recorded_at=recorded_at,
        )
        results.append(
            {
                "job_id": candidate["job_id"],
                "outcome": "interrupted",
                "model_contact_state": terminal["model_contact_state"],
            }
        )
    return results


def run_offline_self_qualification(
    database: Database,
    *,
    runtime_root: Path,
    git_binary: Path = _DEFAULT_GIT_BINARY,
    sandbox_exec_binary: Path = _DEFAULT_SANDBOX_EXEC_BINARY,
    cmp_binary: Path = _DEFAULT_CMP_BINARY,
    pause_file: Path | None = None,
) -> dict[str, Any]:
    """Run Phase C against a newly created fictional repository, then erase it."""

    root = runtime_root.expanduser().absolute()
    if root.is_symlink():
        raise OfflineHarnessViolation("offline_runtime_root_invalid")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="phase-c-", dir=root) as temporary:
        qualification_root = Path(temporary)
        source = qualification_root / "synthetic-source"
        source.mkdir(mode=0o700)
        marker = source / SYNTHETIC_FIXTURE_MARKER
        fixture = source / "fixture.txt"
        _write_private(marker, SYNTHETIC_FIXTURE_MARKER_CONTENT.encode("utf-8"))
        _write_private(fixture, b"old synthetic value\n")
        env = _private_git_environment(qualification_root / "git-home")
        env = dict(env) | {
            "GIT_AUTHOR_DATE": "2026-08-28T00:00:00+00:00",
            "GIT_COMMITTER_DATE": "2026-08-28T00:00:00+00:00",
        }
        git_options = {
            "git_binary": git_binary,
            "sandbox_exec_binary": sandbox_exec_binary,
            "pause_file": pause_file,
        }
        _run_git(
            ["init", "--initial-branch=main"],
            cwd=source,
            env=env,
            **git_options,
        )
        _run_git(
            ["add", "--", SYNTHETIC_FIXTURE_MARKER, "fixture.txt"],
            cwd=source,
            env=env,
            **git_options,
        )
        _run_git(
            [
                "-c",
                "user.name=Atlas Offline Fixture",
                "-c",
                "user.email=atlas-offline.invalid@example.invalid",
                "commit",
                "-m",
                "deterministic synthetic fixture",
            ],
            cwd=source,
            env=env,
            **git_options,
        )
        classifications = {
            "thread/started": "lifecycle-observed",
            "turn/started": "lifecycle-observed",
            "item/started": "lifecycle-observed",
            "item/completed": "lifecycle-observed",
            "turn/completed": "lifecycle-observed",
        }
        inventory = ProtocolInventory(
            version=1,
            sdk_version="0.147.0",
            stable_method_count=len(classifications),
            classifications=classifications,
            server_requests=frozenset(),
            item_treatments={"agentMessage": "observe"},
            command_source_codes=dict(COMMAND_SOURCE_CODES),
            replay_corpus_sha256="1" * 64,
            diagnostic_salt_sha256="2" * 64,
            proposal_schema_version=1,
            proposal_operation="replace_existing_file",
            proposal_baseline_sha256=synthetic_git_baseline_sha256(
                source, **git_options
            ),
            proposal_path="fixture.txt",
            proposal_original_sha256=sha256_bytes(b"old synthetic value\n"),
            proposal_max_files=1,
            proposal_max_lines=8,
            proposal_max_replacement_bytes=1_024,
            limits=StructuralLimits(max_events=16),
        )
        harness = DeterministicOfflineHarness(
            database=database,
            inventory=inventory,
            workspace_root=qualification_root / "offline-workspace",
            test_only_acknowledgement=TEST_ONLY_ACKNOWLEDGEMENT,
            git_binary=git_binary,
            sandbox_exec_binary=sandbox_exec_binary,
            cmp_binary=cmp_binary,
            pause_file=pause_file,
        )
        result = harness.qualify(
            source_repo=source,
            replacement="new synthetic value\n",
            scenario=FakeSdkScenario.SUCCESS,
        )
        candidate = result.candidate
        if (
            result.status != "offline_qualified"
            or result.model_contacted
            or result.authority_granted
            or result.candidate_integrated
            or candidate is None
            or not candidate.source_unchanged
            or candidate.shared_hardlinks_present
            or candidate.remotes_present
            or candidate.hooks_present
            or candidate.alternates_present
            or not candidate.os_sandbox_enforced
            or not candidate.verification_process_started
            or not candidate.command_executed_during_verification
        ):
            raise OfflineHarnessViolation("phase_c_acceptance_failed")
        if database.supervisor_v4_reconciliation_candidates():
            raise OfflineHarnessViolation("phase_c_reconciliation_incomplete")
        public = {
            "status": result.status,
            "qualification_scope": "semantic_test_only_dynamic_fixture",
            "pinned_policy_fixture_binding": False,
            "stop_code": result.stop_code,
            "protocol_decision_code": result.protocol_receipt["decision_code"],
            "source_unchanged": candidate.source_unchanged,
            "candidate_integrated": candidate.candidate_integrated,
            "independent_clone": not candidate.shared_hardlinks_present,
            "remotes_present": candidate.remotes_present,
            "hooks_present": candidate.hooks_present,
            "alternates_present": candidate.alternates_present,
            "os_sandbox_enforced": candidate.os_sandbox_enforced,
            "network_denied_by_profile": True,
            "model_contact_state": result.model_contact_state,
            "model_contacted": result.model_contacted,
            "authority_granted": result.authority_granted,
            "raw_response_persisted": False,
            "candidate_cleanup_on_return": True,
        }
        public["evidence_sha256"] = sha256_bytes(
            canonical_json(public).encode("utf-8")
        )
        return public


__all__ = [
    "CandidateEvidence",
    "DeterministicOfflineHarness",
    "FakeSdkScenario",
    "FakeSdkTranscript",
    "OfflineHarnessViolation",
    "OfflineQualificationResult",
    "SYNTHETIC_FIXTURE_MARKER",
    "SYNTHETIC_FIXTURE_MARKER_CONTENT",
    "TEST_ONLY_ACKNOWLEDGEMENT",
    "fabricate_sdk_transcript",
    "reconcile_orphaned_offline_jobs",
    "replay_fake_sdk_transcript",
    "strict_synthetic_proposal",
    "synthetic_git_baseline_sha256",
]
