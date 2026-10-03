"""Explicit private settings loading for the isolated release candidate.

This module never discovers credential stores or migrates existing data. The
caller supplies an owner file outside the repository. Only allowlisted settings
and secret names are supported. Diagnostics never contain file contents.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
from typing import Mapping, MutableMapping

_PACKAGE_PARENT = Path(__file__).resolve().parent.parent
REPOSITORY_ROOT = _PACKAGE_PARENT.parent if _PACKAGE_PARENT.name == "src" else _PACKAGE_PARENT
SECRET_NAMES = frozenset({
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "ATLAS_API_TOKEN", "ATLAS_LOCAL_API_KEY"
})
SETTING_NAMES = {
    "private_root": "ATLAS_PRIVATE_ROOT",
    "google_expected_account": "ATLAS_GOOGLE_EXPECTED_ACCOUNT",
    "google_time_zone": "ATLAS_GOOGLE_TIME_ZONE",
}
MAX_BYTES = 65536


class PrivateOwnerError(ValueError):
    """A categorical error; the offending value is never included."""


def _outside_repository(path: Path, repository_root: Path) -> Path:
    if not path.is_absolute() or ".." in path.parts:
        raise PrivateOwnerError("private_path_must_be_absolute")
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise PrivateOwnerError("private_path_symlink_refused")
    resolved = path.resolve()
    root = repository_root.resolve()
    if resolved == root or root in resolved.parents:
        raise PrivateOwnerError("private_path_inside_repository_refused")
    return resolved


def _unique_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise PrivateOwnerError("private_file_duplicate_key")
        value[key] = item
    return value


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def load_owner_file(path: str | Path, *, repository_root: Path = REPOSITORY_ROOT) -> dict[str, str]:
    """Read an explicitly selected, POSIX owner-only regular JSON file.

    Returns only allowlisted environment entries. Never log or serialize this
    result. Empty fields are missing, not credentials. Unknown fields fail closed.
    """
    target = _outside_repository(Path(path), repository_root)
    try:
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        raise PrivateOwnerError("private_file_unavailable") from None
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) not in (0o600, 0o400)
                or not 0 < before.st_size <= MAX_BYTES):
            raise PrivateOwnerError("private_file_identity_or_permissions_refused")
        chunks = []
        remaining = before.st_size + 1
        while remaining:
            part = os.read(fd, remaining)
            if not part:
                break
            chunks.append(part)
            remaining -= len(part)
        raw = b"".join(chunks)
        after = os.fstat(fd)
        if (len(raw) != before.st_size or _identity(before) != _identity(after)
                or _identity(after) != _identity(target.stat(follow_symlinks=False))):
            raise PrivateOwnerError("private_file_changed_during_read")
        try:
            document = json.loads(raw, object_pairs_hook=_unique_pairs)
        except (UnicodeError, json.JSONDecodeError):
            raise PrivateOwnerError("private_file_invalid_json") from None
    finally:
        os.close(fd)
    if not isinstance(document, dict) or set(document) != {"settings", "secrets"}:
        raise PrivateOwnerError("private_file_schema_refused")
    settings, secrets = document["settings"], document["secrets"]
    if (not isinstance(settings, dict) or not isinstance(secrets, dict)
            or set(settings) - SETTING_NAMES.keys() or set(secrets) - SECRET_NAMES):
        raise PrivateOwnerError("private_file_fields_refused")
    result = {}
    for section, names in ((settings, SETTING_NAMES), (secrets, {n: n for n in SECRET_NAMES})):
        for key, value in section.items():
            if not isinstance(value, str) or len(value) > 8192 or "\x00" in value or "\n" in value or "\r" in value:
                raise PrivateOwnerError("private_file_value_type_refused")
            if value:
                result[names[key]] = value
    if "ATLAS_PRIVATE_ROOT" in result:
        result["ATLAS_PRIVATE_ROOT"] = str(_outside_repository(
            Path(result["ATLAS_PRIVATE_ROOT"]), repository_root))
        state_root = Path(result["ATLAS_PRIVATE_ROOT"])
        if target == state_root or state_root in target.parents:
            raise PrivateOwnerError("private_file_inside_state_refused")
    return result


def configure_owner_environment(*, environment: MutableMapping[str, str] | None = None,
                                repository_root: Path = REPOSITORY_ROOT) -> None:
    """Opt in with ATLAS_OWNER_FILE; never discover a file automatically.

    The compatibility adapters consume process environment entries. They remain
    in this process; do not pass them to child tools. Conflicting values fail
    before any mutation. An OS-vault adapter is a future reviewed alternative.
    """
    target = os.environ if environment is None else environment
    selected = target.get("ATLAS_OWNER_FILE")
    if not selected:
        return
    entries = load_owner_file(selected, repository_root=repository_root)
    state_selection = entries.get("ATLAS_PRIVATE_ROOT") or target.get("ATLAS_PRIVATE_ROOT")
    if state_selection:
        state_root = _outside_repository(Path(state_selection), repository_root)
        owner_path = _outside_repository(Path(selected), repository_root)
        if owner_path == state_root or state_root in owner_path.parents:
            raise PrivateOwnerError("private_file_inside_state_refused")
    if any(key in target and target[key] != value for key, value in entries.items()):
        raise PrivateOwnerError("private_file_environment_conflict")
    target.update(entries)


def require_secret(name: str, *, environment: Mapping[str, str] | None = None) -> str:
    if name not in SECRET_NAMES:
        raise PrivateOwnerError("secret_name_not_supported")
    selected = os.environ if environment is None else environment
    value = selected.get(name, "")
    if not value.strip():
        raise PrivateOwnerError("required_secret_missing")
    return value


def prepare_private_state(root: str | Path, *, repository_root: Path = REPOSITORY_ROOT) -> Path:
    """Create only the explicitly selected empty candidate state, never migrate.

    Existing owner data/identity is never overwritten. This is separate from the
    actual Atlas migration plan, which still needs owner review and approval.
    """
    target = _outside_repository(Path(root), repository_root)
    if target == Path.home().resolve():
        raise PrivateOwnerError("private_state_home_root_refused")
    target.mkdir(mode=0o700, parents=False, exist_ok=True)
    info = target.stat(follow_symlinks=False)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o077):
        raise PrivateOwnerError("private_state_permissions_refused")
    for name in ("data", "identity", "workspace"):
        sub = target / name
        _outside_repository(sub, repository_root)
        sub.mkdir(mode=0o700, exist_ok=True)
        child = sub.stat(follow_symlinks=False)
        if child.st_uid != os.getuid() or stat.S_IMODE(child.st_mode) & 0o077:
            raise PrivateOwnerError("private_state_permissions_refused")
    for template in sorted((repository_root / "identity").glob("*.md")):
        if template.name == "README.md":
            continue
        try:
            fd = os.open(target / "identity" / template.name,
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            continue
        with os.fdopen(fd, "wb") as stream:
            stream.write(template.read_bytes())
    return target
