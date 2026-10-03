"""One bounded, resumable backup transfer. No model or service initialization.

An injected transport must implement remote idempotency for ``snapshot_id``:
retrying an upload after a lost response must return the original remote file.
This module supplies no production Drive transport or credential access. Its
local lock coordinates ordinary writers; it is not protection from a malicious
process running as the same operating-system user.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Iterable, Protocol
import uuid

from atlas_core.recovery_snapshots import (
    create_snapshot, restore_snapshot, verify_snapshot,
)

_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,79}\Z")
_REMOTE_ID = re.compile(r"[A-Za-z0-9_-]{1,160}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_PHASES = ("created", "uploaded", "downloaded", "verified")
_STATE_LIMIT = 32768
_MAX_ATTEMPTS = 5
_MAX_RETAINED_BYTES = 1024**3
_MAX_RETAINED_ENTRIES = 8192
# One maximum-sized snapshot, download and restore, with a little headroom.
_RESERVED_BYTES = 224 * 1024**2
_STATE_KEYS = {"version", "operation_id", "plan_sha256", "phase", "snapshot",
               "file_id", "download_name", "restore", "failure", "attempts"}
_SNAPSHOT_KEYS = {"format_version", "snapshot_id", "archive_name", "archive_sha256",
                  "archive_bytes", "manifest_sha256", "files", "source_bytes",
                  "created_at_utc"}


class BackupMaintenanceError(ValueError):
    """A local plan, path or durable receipt could not be trusted."""


class _RecoveryBudgetExceeded(BackupMaintenanceError):
    pass


class BackupTransport(Protocol):
    destination_id: str

    def upload(self, path: Path, *, snapshot_id: str, archive_sha256: str,
               archive_bytes: int) -> str:
        """Create once or recover the same upload, including response loss."""

    def download(self, file_id: str) -> Iterable[bytes]:
        """Yield bounded chunks of the actual remote object's bytes."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def _hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _require(value: bool) -> None:
    if not value:
        raise BackupMaintenanceError("Invalid backup plan or recovery state")


def _absolute(value: Any) -> Path:
    _require(isinstance(value, (str, os.PathLike)))
    path = Path(value)
    _require(path.is_absolute() and ".." not in path.parts)
    _require(not any(ord(char) < 32 or ord(char) == 127 for char in str(path)))
    return path


def _directory(path: Path, *, create_leaf: bool = False, owned: bool = False) -> int:
    """Open every component relative to its parent without following links."""
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for index, part in enumerate(path.parts[1:]):
            if create_leaf and index == len(path.parts) - 2:
                try:
                    os.mkdir(part, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                            os.O_CLOEXEC, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        _require(not owned or (info.st_uid == os.geteuid() and info.st_mode & 0o077 == 0))
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _regular(descriptor: int) -> os.stat_result:
    info = os.fstat(descriptor)
    _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
             info.st_uid == os.geteuid() and info.st_mode & 0o077 == 0)
    return info


def _identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _same_directory(path: Path, pinned: int) -> None:
    current = _directory(path, owned=True)
    try:
        a, b = os.fstat(current), os.fstat(pinned)
        _require((a.st_dev, a.st_ino) == (b.st_dev, b.st_ino))
    finally:
        os.close(current)


def _budget(root: int) -> None:
    """Count a bounded private tree without following any alias or deleting it."""
    total, entries = 0, 0

    def walk(descriptor: int, depth: int) -> None:
        nonlocal total, entries
        if depth > 64:
            raise _RecoveryBudgetExceeded("Recovery tree needs review")
        with os.scandir(descriptor) as scan:
            for entry in scan:
                entries += 1
                if entries > _MAX_RETAINED_ENTRIES:
                    raise _RecoveryBudgetExceeded("Recovery entry budget reached")
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY |
                                    os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
                    try:
                        opened = os.fstat(child)
                        _require(opened.st_uid == os.geteuid() and opened.st_mode & 0o077 == 0)
                        _require((info.st_dev, info.st_ino) == (opened.st_dev, opened.st_ino))
                        walk(child, depth + 1)
                    finally:
                        os.close(child)
                else:
                    _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                             info.st_uid == os.geteuid() and info.st_mode & 0o077 == 0)
                    total += info.st_size
                    if total + _RESERVED_BYTES > _MAX_RETAINED_BYTES:
                        raise _RecoveryBudgetExceeded("Recovery byte budget reached")
    walk(root, 0)
    space = os.fstatvfs(root)
    if total + _RESERVED_BYTES > _MAX_RETAINED_BYTES or space.f_bavail * space.f_frsize < _RESERVED_BYTES:
        raise _RecoveryBudgetExceeded("Recovery storage headroom unavailable")


def _verify_restored(path: Path, manifest: dict[str, Any]) -> None:
    root = _directory(path, owned=True)
    try:
        for item in manifest["files"]:
            selected = path / item["path"]
            parent = _directory(selected.parent, owned=True)
            try:
                data = _read_at(parent, selected.name, item["size_bytes"])
                _require(len(data) == item["size_bytes"] and _hash(data) == item["sha256"])
            finally:
                os.close(parent)
        _same_directory(path, root)
    finally:
        os.close(root)


def _read_at(directory: int, name: str, maximum: int) -> bytes:
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC |
                         os.O_NONBLOCK, dir_fd=directory)
    try:
        before = _regular(descriptor)
        _require(before.st_size <= maximum)
        parts = []
        count = 0
        while chunk := os.read(descriptor, min(65536, maximum + 1 - count)):
            parts.append(chunk)
            count += len(chunk)
            _require(count <= maximum)
        _require(_identity(before) == _identity(_regular(descriptor)))
        return b"".join(parts)
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        count = os.write(descriptor, view)
        _require(count > 0)
        view = view[count:]


def _save(directory: int, state: dict[str, Any]) -> None:
    payload = _canonical(state)
    data = _canonical({"payload": state, "sha256": _hash(payload)})
    _require(len(data) <= _STATE_LIMIT)
    name = ".state-" + uuid.uuid4().hex
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                         os.O_CLOEXEC, 0o600, dir_fd=directory)
    try:
        _write_all(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        # Do not replace an unexpected alias or object at the receipt name.
        try:
            existing = os.open("state.json", os.O_RDONLY | os.O_NOFOLLOW |
                               os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError:
            pass
        else:
            try:
                _regular(existing)
            finally:
                os.close(existing)
        os.replace(name, "state.json", src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        try:
            os.unlink(name, dir_fd=directory)
        except FileNotFoundError:
            pass


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        _require(key not in result)
        result[key] = value
    return result


def _snapshot(value: Any, operation_id: str) -> dict[str, Any]:
    _require(isinstance(value, dict) and set(value) == _SNAPSHOT_KEYS)
    _require(type(value["format_version"]) is int and value["format_version"] == 1)
    _require(value["snapshot_id"] == operation_id and value["archive_name"] == operation_id + ".zip")
    for key in ("archive_sha256", "manifest_sha256"):
        _require(isinstance(value[key], str) and _HASH.fullmatch(value[key]) is not None)
    for key in ("archive_bytes", "files"):
        _require(type(value[key]) is int and 0 < value[key] <= 2 * 1024**3)
    _require(type(value["source_bytes"]) is int and 0 <= value["source_bytes"] <= 2 * 1024**3)
    _require(isinstance(value["created_at_utc"], str) and len(value["created_at_utc"]) <= 80 and
             not any(ord(char) < 32 or ord(char) == 127 for char in value["created_at_utc"]))
    return value


def _load(directory: int, operation_id: str, plan_hash: str) -> dict[str, Any] | None:
    try:
        data = _read_at(directory, "state.json", _STATE_LIMIT)
    except FileNotFoundError:
        return None
    envelope = json.loads(data, object_pairs_hook=_unique_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(BackupMaintenanceError("Invalid recovery state")))
    _require(isinstance(envelope, dict) and set(envelope) == {"payload", "sha256"})
    state = envelope["payload"]
    _require(envelope["sha256"] == _hash(_canonical(state)))
    _require(isinstance(state, dict) and set(state) == _STATE_KEYS)
    _require(type(state["version"]) is int and state["version"] == 1)
    _require(state["operation_id"] == operation_id and state["plan_sha256"] == plan_hash)
    _require(state["phase"] in _PHASES and type(state["attempts"]) is int and 0 <= state["attempts"] < 1000000)
    _snapshot(state["snapshot"], operation_id)
    _require(state["failure"] in (None, "drive_connection_required", "transfer_failed", "verification_failed", "interrupted", "retry_limit_reached", "recovery_budget_exceeded"))
    rank = _PHASES.index(state["phase"])
    _require((rank == 0 and state["file_id"] is None) or
             (rank > 0 and isinstance(state["file_id"], str) and _REMOTE_ID.fullmatch(state["file_id"]) is not None))
    _require((rank < 2 and state["download_name"] is None) or
             (rank >= 2 and isinstance(state["download_name"], str) and re.fullmatch(r"download-[a-f0-9]{32}\.zip", state["download_name"]) is not None))
    if rank < 3:
        _require(state["restore"] is None)
    else:
        proof = state["restore"]
        _require(isinstance(proof, dict) and set(proof) == {"directory_name", "archive_sha256", "receipt_sha256", "files"})
        _require(isinstance(proof["directory_name"], str) and re.fullmatch(r"restore-[a-f0-9]{32}", proof["directory_name"]) is not None)
        _require(proof["archive_sha256"] == state["snapshot"]["archive_sha256"] and proof["files"] == state["snapshot"]["files"])
        _require(isinstance(proof["receipt_sha256"], str) and _HASH.fullmatch(proof["receipt_sha256"]) is not None)
    return state


def _result(state: dict[str, Any]) -> dict[str, Any]:
    return {"operation_id": state["operation_id"], "status": state["failure"] or state["phase"],
            "phase": state["phase"], "snapshot": state["snapshot"],
            "file_id": state["file_id"], "restore": state["restore"],
            "local_snapshot_preserved": True, "attempts": state["attempts"]}


def run_once(plan: dict[str, Any], transport: BackupTransport | None = None) -> dict[str, Any]:
    """Run one attempt; rerun the exact plan and operation ID to resume it.

    ``plan`` has exactly source_root, selection, recovery_root, operation_id and
    destination_id. Paths are explicit absolute paths. The recovery root's parent
    must exist; all output directories are private and no previous backup is
    deleted. An uploaded file ID is reused after any interrupted download.
    """
    _require(isinstance(plan, dict) and set(plan) == {"source_root", "selection", "recovery_root", "operation_id", "destination_id"})
    operation_id, destination_id = plan["operation_id"], plan["destination_id"]
    _require(isinstance(operation_id, str) and _ID.fullmatch(operation_id) is not None)
    _require(isinstance(destination_id, str) and _REMOTE_ID.fullmatch(destination_id) is not None)
    source = _absolute(plan["source_root"])
    recovery = _absolute(plan["recovery_root"])
    selection = plan["selection"]
    _require(isinstance(selection, list) and 0 < len(selection) <= 10000 and all(isinstance(item, str) for item in selection))
    _require(len(set(selection)) == len(selection))
    _require(all(0 < len(item) <= 2048 and not Path(item).is_absolute() and
                 ".." not in Path(item).parts and
                 not any(ord(char) < 32 or ord(char) == 127 for char in item)
                 for item in selection))
    plan_hash = _hash(_canonical({"source_root": str(source), "selection": selection,
                                  "recovery_root": str(recovery), "destination_id": destination_id}))
    if transport is not None:
        _require(transport.destination_id == destination_id)
    descriptors = []
    lock = None
    state = None
    try:
        for path in (recovery, recovery / "outbox", recovery / "snapshots",
                     recovery / "outbox" / operation_id, recovery / "snapshots" / operation_id):
            descriptors.append(_directory(path, create_leaf=True, owned=True))
        directory = descriptors[3]
        job = recovery / "outbox" / operation_id
        snapshot_root = recovery / "snapshots" / operation_id
        lock = os.open(".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC |
                       os.O_NONBLOCK, 0o600, dir_fd=directory)
        _regular(lock)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {"operation_id": operation_id, "status": "busy"}
        state = _load(directory, operation_id, plan_hash)
        if state is None:
            _budget(descriptors[0])
            _same_directory(job, directory)
            _same_directory(snapshot_root, descriptors[4])
            snapshot = _snapshot(create_snapshot(source, selection, snapshot_root,
                                                   snapshot_id=operation_id), operation_id)
            state = {"version": 1, "operation_id": operation_id, "plan_sha256": plan_hash,
                     "phase": "created", "snapshot": snapshot, "file_id": None,
                     "download_name": None, "restore": None, "failure": None, "attempts": 0}
            _save(directory, state)
        archive = snapshot_root / state["snapshot"]["archive_name"]
        _same_directory(job, directory)
        _same_directory(snapshot_root, descriptors[4])
        verify_snapshot(archive, state["snapshot"])
        if state["phase"] == "verified":
            manifest = verify_snapshot(job / state["download_name"], state["snapshot"])
            _verify_restored(job / state["restore"]["directory_name"], manifest)
            if state["failure"] is not None:
                state["failure"] = None
                _save(directory, state)
            return _result(state)
        if transport is None:
            state["failure"] = "drive_connection_required"
            _save(directory, state)
            return _result(state)
        if state["attempts"] >= _MAX_ATTEMPTS:
            state["failure"] = "retry_limit_reached"
            _save(directory, state)
            return _result(state)
        _budget(descriptors[0])
        state["attempts"] += 1
        state["failure"] = None
        _save(directory, state)
        if state["phase"] == "created":
            file_id = transport.upload(archive, snapshot_id=operation_id,
                                       archive_sha256=state["snapshot"]["archive_sha256"],
                                       archive_bytes=state["snapshot"]["archive_bytes"])
            _require(isinstance(file_id, str) and _REMOTE_ID.fullmatch(file_id) is not None)
            state.update(phase="uploaded", file_id=file_id)
            _save(directory, state)
        if state["phase"] == "uploaded":
            _same_directory(job, directory)
            name = "download-" + uuid.uuid4().hex + ".zip"
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
            size = 0
            digest = hashlib.sha256()
            try:
                for chunk in transport.download(state["file_id"]):
                    _require(isinstance(chunk, bytes) and 0 < len(chunk) <= 1024**2)
                    size += len(chunk)
                    _require(size <= state["snapshot"]["archive_bytes"])
                    _write_all(descriptor, chunk)
                    digest.update(chunk)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            _require(size == state["snapshot"]["archive_bytes"] and digest.hexdigest() == state["snapshot"]["archive_sha256"])
            verify_snapshot(job / name, state["snapshot"])
            state.update(phase="downloaded", download_name=name)
            _save(directory, state)
        if state["phase"] == "downloaded":
            _same_directory(job, directory)
            manifest = verify_snapshot(job / state["download_name"], state["snapshot"])
            name = "restore-" + uuid.uuid4().hex
            proof = restore_snapshot(job / state["download_name"], state["snapshot"], job / name)
            _require(isinstance(proof, dict) and proof.get("verified") is True and
                     proof.get("snapshot_id") == operation_id and
                     type(proof.get("restored_files")) is int and proof["restored_files"] == state["snapshot"]["files"] and
                     proof.get("archive_sha256") == state["snapshot"]["archive_sha256"])
            _verify_restored(job / name, manifest)
            state.update(phase="verified", restore={"directory_name": name,
                         "archive_sha256": state["snapshot"]["archive_sha256"],
                         "receipt_sha256": _hash(_canonical(proof)), "files": state["snapshot"]["files"]})
            _save(directory, state)
        _same_directory(job, directory)
        return _result(state)
    except BaseException as exc:
        if state is None:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            if isinstance(exc, _RecoveryBudgetExceeded):
                return {"operation_id": operation_id, "status": "recovery_budget_exceeded"}
            raise BackupMaintenanceError("Backup plan or local snapshot could not be prepared") from None
        state["failure"] = ("recovery_budget_exceeded" if isinstance(exc, _RecoveryBudgetExceeded) else
                            "interrupted" if isinstance(exc, (KeyboardInterrupt, SystemExit)) else
                            "verification_failed" if state["phase"] in ("downloaded", "verified") or isinstance(exc, ValueError) else "transfer_failed")
        try:
            _save(descriptors[3], state)
        except Exception:
            raise BackupMaintenanceError("Backup failed and recovery receipt could not be saved") from None
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        return _result(state)
    finally:
        if lock is not None:
            os.close(lock)
        for descriptor in reversed(descriptors):
            os.close(descriptor)
