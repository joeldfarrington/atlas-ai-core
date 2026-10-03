"""Deterministic, explicitly selected source/evidence snapshots. No network or models.

The caller chooses one authorized root and every selected relative file. This is
not a full-state backup: private configuration, databases and credentials are
excluded by name. Name exclusions are not a content-classification system.
Receipts prove byte integrity, not the authenticity or authority of their author.
Directories must have quiescent, trusted same-user owners; descriptor-relative
operations prevent symlink traversal but do not establish an OS sandbox.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import uuid
import zipfile
import zlib


class SnapshotError(ValueError):
    """A selected source, archive, receipt or destination failed validation."""


@dataclass(frozen=True)
class SnapshotLimits:
    max_files: int = 512
    max_file_bytes: int = 8 * 1024 * 1024
    max_total_bytes: int = 64 * 1024 * 1024
    max_archive_bytes: int = 72 * 1024 * 1024
    max_manifest_bytes: int = 512 * 1024
    max_compression_ratio: int = 200

    def __post_init__(self):
        for value in vars(self).values():
            if type(value) is not int or value <= 0:
                raise SnapshotError("Snapshot limits must be positive integers")


_MANIFEST = "BACKUP_MANIFEST.json"
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,79}\Z")
_BLOCKED_PARTS = frozenset({
    "config", "configuration", "identity", "data", "logs", "private",
    "private-adoption", "installation-private", "credentials", "secrets",
    "handbook", "node_modules", "venv", "__pycache__", "auth",
})
_BLOCKED_SUFFIXES = (".db", ".sqlite", ".sqlite3", ".db-wal", ".db-shm", ".pem",
                     ".key", ".p12", ".pfx", ".bak", ".log", ".zip", ".yaml", ".yml")
_SENSITIVE = re.compile(r"(?:^|[-_.])(?:credentials?|secrets?|passwords?|tokens?|api[-_]?keys?|private[-_]?keys?|handbook)(?:[-_.]|$)", re.I)
_CREDENTIAL_VALUES = re.compile(
    rb"(?:sk-(?:proj|svcacct)-[A-Za-z0-9_-]{30,}|github_pat_[A-Za-z0-9_]{50,}|"
    rb"ghp_[A-Za-z0-9]{36,}|AKIA[0-9A-Z]{16}|AIzaSy[A-Za-z0-9_-]{33}|"
    rb"xox[baprs]-[A-Za-z0-9-]{30,}|"
    rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----(?:\s|\\n)+[A-Za-z0-9+/=]{40,})"
)


def _check_content(data):
    # Deliberately require credential-shaped values, not marker names or short
    # examples in source. This catches high-confidence forms, not every secret.
    if _CREDENTIAL_VALUES.search(data):
        raise SnapshotError("Selected content contains a credential-shaped value")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_bytes(value) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def _decode_json(data: bytes):
    # Python versions differ in their decoder recursion behavior. Bound nesting
    # explicitly, while ignoring delimiters inside escaped JSON strings.
    depth, in_string, escaped = 0, False, False
    for byte in data:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                in_string = False
        elif byte == 34:
            in_string = True
        elif byte in (91, 123):
            depth += 1
            if depth > 16:
                raise SnapshotError("Snapshot JSON exceeds nesting limit")
        elif byte in (93, 125):
            depth -= 1
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise SnapshotError("Duplicate JSON keys")
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=unique)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise SnapshotError("Invalid snapshot JSON") from exc


def _safe_name(name: str) -> str:
    if (not isinstance(name, str) or not 0 < len(name) <= 512
            or not re.fullmatch(r"[A-Za-z0-9_./-]+", name)):
        raise SnapshotError("Unsafe selected relative path")
    parts = name.split("/")
    if any(not part or part in {".", ".."} or len(part) > 255 for part in parts):
        raise SnapshotError("Unsafe selected path component")
    for part in parts:
        lowered = part.casefold()
        if (part.startswith(".") or lowered in _BLOCKED_PARTS or _SENSITIVE.search(part)
                or lowered.endswith(_BLOCKED_SUFFIXES)
                or lowered.split(".")[0] in {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}):
            raise SnapshotError("Sensitive or unsupported selected path")
    if name.casefold() == _MANIFEST.casefold():
        raise SnapshotError("Reserved manifest path")
    return name


def _paths(selection, limits):
    if not isinstance(selection, list) or not 1 <= len(selection) <= limits.max_files:
        raise SnapshotError("Selection must be a bounded nonempty list")
    names = [_safe_name(name) for name in selection]
    folded = [name.casefold() for name in names]
    if len(folded) != len(set(folded)):
        raise SnapshotError("Duplicate or case-colliding selected paths")
    for name in folded:
        if any(name.startswith(other + "/") for other in folded if other != name):
            raise SnapshotError("Selected file/directory collision")
    return sorted(names)


def _flags():
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise SnapshotError("Descriptor-safe snapshots require POSIX nofollow support")
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


@contextmanager
def _directory(path):
    """Anchor every absolute ancestor without following a symlink."""
    absolute = Path(os.path.abspath(os.fspath(path)))
    fd = os.open(absolute.anchor, _flags())
    try:
        for part in absolute.parts[1:]:
            child = os.open(part, _flags(), dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    except OSError as exc:
        raise SnapshotError("Unsafe or unavailable directory") from exc
    finally:
        os.close(fd)


def _signature(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def _read_at(root_fd, name, maximum):
    parts = name.split("/")
    current = os.dup(root_fd)
    fd = None
    try:
        for part in parts[:-1]:
            child = os.open(part, _flags(), dir_fd=current)
            os.close(current)
            current = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=current)
        before = os.fstat(fd)
        if before.st_nlink != 1:
            raise SnapshotError("Multiple links: source is unsafe or interrupted snapshot staging needs review")
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise SnapshotError("Source must be a bounded regular file with one link")
        data = bytearray()
        while True:
            chunk = os.read(fd, min(65536, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > maximum:
                raise SnapshotError("Source exceeds byte limit")
        after = os.fstat(fd)
        named = os.stat(parts[-1], dir_fd=current, follow_symlinks=False)
        if _signature(before) != _signature(after) or _signature(after) != _signature(named) or len(data) != before.st_size:
            raise SnapshotError("Source changed while reading")
        return bytes(data)
    except OSError as exc:
        raise SnapshotError("Unsafe or unavailable regular file") from exc
    finally:
        if fd is not None:
            os.close(fd)
        os.close(current)


def _read_path(path, maximum):
    path = Path(os.path.abspath(os.fspath(path)))
    with _directory(path.parent) as parent:
        return _read_at(parent, path.name, maximum)


def _write_at(directory, name, data):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("Snapshot write made no progress")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _receipt(manifest, archive, manifest_bytes):
    return {"format_version": 1, "snapshot_id": manifest["snapshot_id"],
            "archive_name": manifest["snapshot_id"] + ".zip", "archive_sha256": _digest(archive),
            "archive_bytes": len(archive), "manifest_sha256": _digest(manifest_bytes),
            "files": len(manifest["files"]), "source_bytes": manifest["source_bytes"],
            "created_at_utc": manifest["created_at_utc"]}


def _inspect(archive_bytes, limits):
    if len(archive_bytes) > limits.max_archive_bytes or not archive_bytes.startswith(b"PK\x03\x04"):
        raise SnapshotError("Archive size or header is invalid")
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            entries = archive.infolist()
            names = [entry.filename for entry in entries]
            if (not 2 <= len(entries) <= limits.max_files + 1 or names.count(_MANIFEST) != 1
                    or len(set(names)) != len(names) or archive.comment):
                raise SnapshotError("Archive has missing, duplicate or excessive members")
            _paths([name for name in names if name != _MANIFEST], limits)
            total = 0
            for entry in entries:
                maximum = limits.max_manifest_bytes if entry.filename == _MANIFEST else limits.max_file_bytes
                mode = entry.external_attr >> 16
                if (entry.is_dir() or entry.flag_bits & 1 or entry.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                        or stat.S_IFMT(mode) not in {0, stat.S_IFREG} or entry.file_size > maximum
                        or entry.file_size > max(1, entry.compress_size) * limits.max_compression_ratio):
                    raise SnapshotError("Unsafe, oversized or overcompressed archive member")
                total += entry.file_size
                if total > limits.max_total_bytes + limits.max_manifest_bytes:
                    raise SnapshotError("Expanded archive exceeds total limit")
            manifest_bytes = archive.read(_MANIFEST)
            manifest = _decode_json(manifest_bytes)
            if (not isinstance(manifest, dict) or set(manifest) != {"format_version", "snapshot_id", "created_at_utc", "files", "source_bytes"}
                    or type(manifest["format_version"]) is not int or manifest["format_version"] != 1
                    or not isinstance(manifest["snapshot_id"], str) or not _ID.fullmatch(manifest["snapshot_id"])
                    or not isinstance(manifest["created_at_utc"], str) or len(manifest["created_at_utc"]) > 40
                    or type(manifest["source_bytes"]) is not int or not 0 <= manifest["source_bytes"] <= limits.max_total_bytes
                    or not isinstance(manifest["files"], list)):
                raise SnapshotError("Invalid snapshot manifest")
            selected = manifest["files"]
            if any(not isinstance(item, dict) or set(item) != {"path", "size_bytes", "sha256"}
                   or type(item["size_bytes"]) is not int or not 0 <= item["size_bytes"] <= limits.max_file_bytes
                   or not isinstance(item["sha256"], str) or not _HASH.fullmatch(item["sha256"]) for item in selected):
                raise SnapshotError("Invalid selected-file manifest")
            selected_names = _paths([item["path"] for item in selected], limits)
            if set(names) != set(selected_names) | {_MANIFEST}:
                raise SnapshotError("Archive members differ from explicit manifest")
            verified = []
            for item in selected:
                data = archive.read(item["path"])
                _check_content(data)
                if len(data) != item["size_bytes"] or _digest(data) != item["sha256"]:
                    raise SnapshotError("Archived file fingerprint mismatch")
                verified.append((item["path"], data))
            if sum(len(data) for _, data in verified) != manifest["source_bytes"]:
                raise SnapshotError("Manifest total byte count mismatch")
            return manifest, manifest_bytes, verified
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, EOFError, KeyError, zlib.error) as exc:
        raise SnapshotError("Invalid or unreadable ZIP archive") from exc


def _verify_bytes(data, receipt, limits):
    if not isinstance(receipt, dict) or receipt.get("archive_sha256") != _digest(data) or type(receipt.get("archive_bytes")) is not int or receipt["archive_bytes"] != len(data):
        raise SnapshotError("Archive does not match its receipt")
    manifest, manifest_bytes, verified = _inspect(data, limits)
    if receipt != _receipt(manifest, data, manifest_bytes):
        raise SnapshotError("Receipt does not match archive manifest")
    return manifest, verified


def verify_snapshot(zip_path, receipt, *, limits=None):
    """Verify actual bytes and every member. A downloaded ZIP may have any basename."""
    limits = limits or SnapshotLimits()
    data = _read_path(zip_path, limits.max_archive_bytes)
    manifest, _ = _verify_bytes(data, receipt, limits)
    return manifest


def _publish(directory, stage, name):
    # Hard-link creation is an atomic, no-overwrite publication of verified bytes.
    # Removing the private staging link leaves one public link before the receipt.
    os.link(name, name, src_dir_fd=stage, dst_dir_fd=directory, follow_symlinks=False)
    os.unlink(name, dir_fd=stage)
    os.fsync(directory)


def _verify_restored_tree(root, selected):
    """Check the exact expected namespace without following directory links."""
    children = {"": set()}
    for name, _ in selected:
        parts = name.split("/")
        for index, part in enumerate(parts):
            parent = "/".join(parts[:index])
            children.setdefault(parent, set()).add(part)
    for parent, expected in children.items():
        current = os.dup(root)
        try:
            for part in parent.split("/") if parent else []:
                child = os.open(part, _flags(), dir_fd=current)
                os.close(current)
                current = child
            actual = set()
            with os.scandir(current) as entries:
                for entry in entries:
                    actual.add(entry.name)
                    if len(actual) > len(expected):
                        raise SnapshotError("Unexpected restored namespace entry")
            if actual != expected:
                raise SnapshotError("Restored namespace differs from selected paths")
        finally:
            os.close(current)


def create_snapshot(source_root, selection: list[str], snapshot_root, *, snapshot_id=None, limits=None):
    """Create <id>.zip and <id>.receipt.json in an existing owned directory.

    Reusing an explicit ID with identical selected contents is idempotent. A ZIP
    published before interruption can be verified and completed without rewrite.
    A differing selection/content under that ID is an error; older files survive.
    """
    limits = limits or SnapshotLimits()
    names = _paths(selection, limits)
    snapshot_id = ("snapshot-" + uuid.uuid4().hex) if snapshot_id is None else snapshot_id
    if not isinstance(snapshot_id, str) or not _ID.fullmatch(snapshot_id):
        raise SnapshotError("Invalid snapshot ID")
    selected, total = [], 0
    with _directory(source_root) as source:
        for name in names:
            data = _read_at(source, name, limits.max_file_bytes)
            _check_content(data)
            total += len(data)
            if total > limits.max_total_bytes:
                raise SnapshotError("Selection exceeds total byte limit")
            selected.append((name, data))
    files = [{"path": name, "size_bytes": len(data), "sha256": _digest(data)} for name, data in selected]
    archive_name, receipt_name = snapshot_id + ".zip", snapshot_id + ".receipt.json"
    with _directory(snapshot_root) as target:
        existing = set(os.listdir(target))
        if receipt_name in existing:
            receipt = _decode_json(_read_at(target, receipt_name, limits.max_manifest_bytes))
            manifest, _ = _verify_bytes(_read_at(target, archive_name, limits.max_archive_bytes), receipt, limits)
            if manifest["snapshot_id"] != snapshot_id or manifest["files"] != files:
                raise SnapshotError("Snapshot ID already names different selected contents")
            return receipt
        if archive_name in existing:
            data = _read_at(target, archive_name, limits.max_archive_bytes)
            manifest, manifest_bytes, _ = _inspect(data, limits)
            if manifest["snapshot_id"] != snapshot_id or manifest["files"] != files:
                raise SnapshotError("Interrupted snapshot differs from selected contents")
        else:
            manifest = {"format_version": 1, "snapshot_id": snapshot_id,
                        "created_at_utc": datetime.now(timezone.utc).isoformat(), "files": files, "source_bytes": total}
            manifest_bytes = _json_bytes(manifest)
            if len(manifest_bytes) > limits.max_manifest_bytes:
                raise SnapshotError("Manifest exceeds byte limit")
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr(_MANIFEST, manifest_bytes)
                for name, content in selected:
                    archive.writestr(name, content)
            data = output.getvalue()
        receipt = _receipt(manifest, data, manifest_bytes)
        _verify_bytes(data, receipt, limits)
        stage_name = ".snapshot-stage-" + uuid.uuid4().hex
        os.mkdir(stage_name, 0o700, dir_fd=target)
        stage = os.open(stage_name, _flags(), dir_fd=target)
        complete = False
        try:
            if archive_name not in existing:
                _write_at(stage, archive_name, data)
                _verify_bytes(_read_at(stage, archive_name, limits.max_archive_bytes), receipt, limits)
                _publish(target, stage, archive_name)
            _verify_bytes(_read_at(target, archive_name, limits.max_archive_bytes), receipt, limits)
            _write_at(stage, receipt_name, _json_bytes(receipt))
            _publish(target, stage, receipt_name)
            complete = True
        except BaseException as exc:
            # Do not delete a staging entry that a concurrent writer could have
            # replaced. A kill between link/unlink may leave two links; reads
            # explicitly refuse that incomplete state instead of weakening the
            # one-link requirement or guessing which name should be removed.
            exc.add_note("Private snapshot staging preserved for review: " + stage_name)
            raise
        finally:
            os.close(stage)
            if complete:
                os.rmdir(stage_name, dir_fd=target)
        return receipt


def restore_snapshot(zip_path, receipt, destination, *, limits=None):
    """Validate before creating a new private destination; never merge/overwrite.

    Destination reservation is exclusive. Each file is written privately and
    rehashed; the destination is returned only after all selected files pass.
    Interrupted restores preserve the partial private destination for review.
    No failure cleanup deletes files that another same-user writer could replace.
    This is not an atomic rename of an entire directory or a concurrent-writer CAS.
    """
    limits = limits or SnapshotLimits()
    data = _read_path(zip_path, limits.max_archive_bytes)
    manifest, selected = _verify_bytes(data, receipt, limits)
    destination = Path(os.path.abspath(os.fspath(destination)))
    if destination.name in {"", ".", ".."}:
        raise SnapshotError("Restore requires a new named destination")
    with _directory(destination.parent) as parent:
        try:
            os.mkdir(destination.name, 0o700, dir_fd=parent)
        except FileExistsError as exc:
            raise SnapshotError("Restore destination already exists") from exc
        root = os.open(destination.name, _flags(), dir_fd=parent)
        try:
            for name, content in selected:
                parts = name.split("/")
                current = os.dup(root)
                try:
                    for index, part in enumerate(parts[:-1]):
                        try:
                            os.mkdir(part, 0o700, dir_fd=current)
                        except FileExistsError:
                            pass
                        child = os.open(part, _flags(), dir_fd=current)
                        os.close(current)
                        current = child
                    _write_at(current, parts[-1], content)
                    if _read_at(current, parts[-1], limits.max_file_bytes) != content:
                        raise SnapshotError("Restored file readback mismatch")
                finally:
                    os.close(current)
            # Recheck the paths that will be returned, not only descriptors used
            # during writes. A replaced parent or published root cannot pass.
            for name, content in selected:
                if _read_at(root, name, limits.max_file_bytes) != content:
                    raise SnapshotError("Restored namespace changed during verification")
            _verify_restored_tree(root, selected)
            current_root = os.stat(destination.name, dir_fd=parent, follow_symlinks=False)
            pinned_root = os.fstat(root)
            if ((current_root.st_dev, current_root.st_ino) != (pinned_root.st_dev, pinned_root.st_ino)
                    or not stat.S_ISDIR(current_root.st_mode) or stat.S_IMODE(current_root.st_mode) != 0o700):
                raise SnapshotError("Restore destination changed during verification")
            os.fsync(root)
        except BaseException as exc:
            note = "Restore failed; partial private destination preserved for review: " + str(destination)
            if isinstance(exc, Exception):
                raise SnapshotError(note) from exc
            exc.add_note(note)
            raise
        finally:
            os.close(root)
    return {"verified": True, "snapshot_id": manifest["snapshot_id"], "restored_files": len(selected),
            "restored_bytes": manifest["source_bytes"], "archive_sha256": receipt["archive_sha256"],
            "destination": str(destination)}
