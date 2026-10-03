from __future__ import annotations

import json
import os
import re
import sqlite3
import stat
import shutil
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from atlas_core import __version__
from atlas_core.config import AtlasConfig
from atlas_core.identity import IdentityStore
from atlas_core.memory.database import Database


_SECRET_MARKERS = (
    b"-----BEGIN " b"PRIVATE KEY-----",
    b"-----BEGIN RSA " b"PRIVATE KEY-----",
    b"-----BEGIN OPENSSH " b"PRIVATE KEY-----",
    b"github_pat_",
    b"ghp_",
    b"sk-live-",
    b"sk-proj-",
    b"GOCSPX-",
    b"AIzaSy",
    b"xoxb-",
    b"xoxp-",
)

_MAX_BACKUP_MEMBER_BYTES = 512 * 1024 * 1024
_MAX_BACKUP_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
_MAX_PORTABLE_CONFIG_BYTES = 4 * 1024 * 1024

_SAFE_CREDENTIAL_METADATA_KEYS = frozenset(
    {
        "api_key_env",
        "credential_broker_socket",
        "credential_mode",
        "keyring_service",
    }
)
_CREDENTIAL_KEY_PARTS = frozenset(
    {
        "authorization",
        "credential",
        "credentials",
        "passwd",
        "password",
        "secret",
        "token",
    }
)
_V4_EXTERNAL_CONTROL_KEYS = frozenset(
    {
        "owner_policy_broker_socket",
        "owner_policy_verification_key_file",
        "credential_broker_socket",
        "credential_broker_verification_key_file",
        "receipt_verification_key_file",
        "receipt_anchor_broker_socket",
        "receipt_anchor_verification_key_file",
        "owner_kill_switch_socket",
        "owner_kill_switch_verification_key_file",
    }
)


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that refuses ambiguous duplicate mappings."""


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _normalized_config_key(key: str) -> str:
    snake_case = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key)
    return re.sub(r"[^a-z0-9]+", "_", snake_case.casefold()).strip("_")


def _credential_bearing_key(key: str) -> bool:
    normalized = _normalized_config_key(key)
    if normalized in _SAFE_CREDENTIAL_METADATA_KEYS:
        return False
    parts = normalized.split("_")
    if _CREDENTIAL_KEY_PARTS.intersection(parts):
        return True
    return ("api" in parts and "key" in parts) or (
        "private" in parts and "key" in parts
    )


def _read_private_regular_file(source: Path, *, maximum_bytes: int) -> bytes:
    descriptor = os.open(
        source,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"Backup source is not a regular file: {source.name}")
        if before.st_nlink != 1:
            raise ValueError(f"Backup source cannot be a hard link: {source.name}")
        if before.st_size > maximum_bytes:
            raise ValueError(f"Backup source is too large: {source.name}")
        content = bytearray()
        while chunk := os.read(descriptor, min(1024 * 1024, maximum_bytes + 1)):
            content.extend(chunk)
            if len(content) > maximum_bytes:
                raise ValueError(f"Backup source is too large: {source.name}")
        after = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or len(content) != before.st_size
        ):
            raise ValueError(f"Backup source changed while reading: {source.name}")
        return bytes(content)
    finally:
        os.close(descriptor)


def _write_private_file(destination: Path, content: bytes) -> None:
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        view = memoryview(content)
        while view:
            view = view[os.write(descriptor, view) :]
    finally:
        os.close(descriptor)


def _redact_portable_config_value(
    value: Any,
    *,
    path: tuple[str, ...] = (),
    active_containers: frozenset[int] = frozenset(),
) -> Any:
    if len(path) > 64:
        raise ValueError("Active configuration nesting is too deep for backup")
    if isinstance(value, dict):
        identity = id(value)
        if identity in active_containers:
            raise ValueError("Active configuration contains a recursive YAML alias")
        descendants = active_containers | {identity}
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("Active configuration mapping keys must be strings")
            normalized = _normalized_config_key(key)
            if path == ("supervisor_v4",) and normalized in _V4_EXTERNAL_CONTROL_KEYS:
                redacted[key] = None
                continue
            if normalized == "api_token":
                if path == ("app",):
                    redacted["api_token"] = None
                continue
            if _credential_bearing_key(key):
                continue
            redacted[key] = _redact_portable_config_value(
                item,
                path=path + (normalized,),
                active_containers=descendants,
            )
        return redacted
    if isinstance(value, list):
        identity = id(value)
        if identity in active_containers:
            raise ValueError("Active configuration contains a recursive YAML alias")
        descendants = active_containers | {identity}
        return [
            _redact_portable_config_value(
                item,
                path=path + (str(index),),
                active_containers=descendants,
            )
            for index, item in enumerate(value)
        ]
    if value is None or isinstance(value, (str, bool, int, float)):
        if isinstance(value, str):
            encoded = value.encode("utf-8")
            if any(marker in encoded for marker in _SECRET_MARKERS):
                raise ValueError("Active configuration contains secret-like material")
            if "://" in value or value.startswith("//"):
                try:
                    parsed = urlsplit(value)
                except ValueError as exc:
                    raise ValueError(
                        "Active configuration contains an invalid URL value"
                    ) from exc
                if parsed.username is not None or parsed.password is not None:
                    raise ValueError("Active configuration contains URL credentials")
        return value
    raise ValueError("Active configuration must contain portable YAML values only")


def _validate_portable_config(value: Any, *, path: tuple[str, ...] = ()) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = _normalized_config_key(key)
            if normalized == "api_token" and path == ("app",) and item is None:
                continue
            if (
                path == ("supervisor_v4",)
                and normalized in _V4_EXTERNAL_CONTROL_KEYS
                and item is None
            ):
                continue
            if _credential_bearing_key(key):
                raise ValueError(
                    "Portable configuration still contains a credential-bearing field"
                )
            _validate_portable_config(item, path=path + (normalized,))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _validate_portable_config(item, path=path + (str(index),))


def _portable_config_projection(source: Path) -> bytes:
    content = _read_private_regular_file(
        source,
        maximum_bytes=_MAX_PORTABLE_CONFIG_BYTES,
    )
    try:
        parsed = yaml.load(content.decode("utf-8"), Loader=_UniqueKeySafeLoader)
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValueError("Active configuration is not valid UTF-8 YAML") from exc
    if parsed is None:
        parsed = {}
    if not isinstance(parsed, dict):
        raise ValueError("Active configuration must be a YAML mapping")
    portable = _redact_portable_config_value(parsed)
    app = portable.get("app")
    if app is None:
        app = {}
        portable["app"] = app
    if not isinstance(app, dict):
        raise ValueError("Active configuration app section must be a mapping")
    app["api_token"] = None
    _validate_portable_config(portable)
    rendered = yaml.safe_dump(
        portable,
        allow_unicode=True,
        sort_keys=False,
    ).encode("utf-8")
    try:
        round_tripped = yaml.load(rendered.decode("utf-8"), Loader=_UniqueKeySafeLoader)
    except yaml.YAMLError as exc:
        raise ValueError("Portable configuration could not be validated") from exc
    if round_tripped != portable:
        raise ValueError("Portable configuration did not round-trip safely")
    _validate_portable_config(round_tripped)
    return rendered


def _reject_symlinks(root: Path) -> None:
    if root.is_symlink():
        raise ValueError(f"Backup source cannot be a symbolic link: {root.name}")
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError(
                f"Backup source contains a symbolic link: {path.relative_to(root)}"
            )


def _copy_regular_no_follow(source: Path, destination: Path) -> None:
    descriptor = os.open(
        source,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"Backup source is not a regular file: {source.name}")
        if metadata.st_nlink != 1:
            raise ValueError(f"Backup source cannot be a hard link: {source.name}")
        if metadata.st_size > _MAX_BACKUP_MEMBER_BYTES:
            raise ValueError(f"Backup source is too large: {source.name}")
        destination_descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        try:
            copied = 0
            while chunk := os.read(descriptor, 1024 * 1024):
                copied += len(chunk)
                if copied > _MAX_BACKUP_MEMBER_BYTES:
                    raise ValueError(f"Backup source is too large: {source.name}")
                view = memoryview(chunk)
                while view:
                    view = view[os.write(destination_descriptor, view) :]
            after = os.fstat(descriptor)
            if (
                (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or copied != metadata.st_size
            ):
                raise ValueError(f"Backup source changed while copying: {source.name}")
        finally:
            os.close(destination_descriptor)
    finally:
        os.close(descriptor)


def _copy_tree_no_follow(
    source: Path,
    destination: Path,
    *,
    ignored_names: frozenset[str] = frozenset(),
) -> None:
    """Copy a bounded tree through opened directory descriptors only."""

    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    root_descriptor = os.open(source, directory_flags)
    destination.mkdir(mode=0o700)
    total = 0

    def walk(directory_descriptor: int, output: Path) -> None:
        nonlocal total
        for name in sorted(os.listdir(directory_descriptor)):
            if name in ignored_names or name in {".", ".."} or "/" in name:
                continue
            before = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode):
                raise ValueError(f"Backup source contains a symbolic link: {name}")
            target = output / name
            if stat.S_ISDIR(before.st_mode):
                child = os.open(name, directory_flags, dir_fd=directory_descriptor)
                try:
                    opened = os.fstat(child)
                    if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                        raise ValueError(f"Backup directory changed while opening: {name}")
                    target.mkdir(mode=0o700)
                    walk(child, target)
                finally:
                    os.close(child)
                continue
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise ValueError(f"Backup source is not a private regular file: {name}")
            if before.st_size > _MAX_BACKUP_MEMBER_BYTES:
                raise ValueError(f"Backup source is too large: {name}")
            child = os.open(name, file_flags, dir_fd=directory_descriptor)
            try:
                opened = os.fstat(child)
                if (
                    (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                    != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                    or not stat.S_ISREG(opened.st_mode)
                    or opened.st_nlink != 1
                ):
                    raise ValueError(f"Backup file changed while opening: {name}")
                output_descriptor = os.open(
                    target,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                )
                try:
                    copied = 0
                    while chunk := os.read(child, 1024 * 1024):
                        copied += len(chunk)
                        total += len(chunk)
                        if total > _MAX_BACKUP_TOTAL_BYTES:
                            raise ValueError("Backup source trees exceed the total byte limit")
                        view = memoryview(chunk)
                        while view:
                            view = view[os.write(output_descriptor, view) :]
                finally:
                    os.close(output_descriptor)
                after = os.fstat(child)
                if (
                    (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                    != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                    or copied != opened.st_size
                ):
                    raise ValueError(f"Backup file changed while copying: {name}")
            finally:
                os.close(child)

    try:
        walk(root_descriptor, destination)
    finally:
        os.close(root_descriptor)


def _redact_v4_from_database_copy(path: Path) -> None:
    """Keep authority-bearing v4 records out of the raw recovery database."""

    tables = (
        "supervisor_v4_capability_consumptions",
        "supervisor_v4_job_transitions",
        "supervisor_v4_receipts",
        "supervisor_v4_capabilities",
        "supervisor_v4_jobs",
        "supervisor_v4_qualifications",
    )
    connection = sqlite3.connect(path)
    try:
        # DELETE alone leaves prior payload bytes recoverable from SQLite free
        # pages. This is a disposable copy, so overwrite and compact it before
        # it is admitted to the owner-private archive.
        connection.execute("PRAGMA secure_delete = ON")
        connection.execute("PRAGMA foreign_keys = OFF")
        trigger_rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'trigger' AND name LIKE 'supervisor_v4_%'"
        ).fetchall()
        for (name,) in trigger_rows:
            if not str(name).replace("_", "").isalnum():
                raise ValueError("Unexpected Supervisor v4 trigger name")
            connection.execute(f'DROP TRIGGER "{name}"')
        for table in tables:
            connection.execute(f'DELETE FROM "{table}"')
        connection.commit()
        connection.execute("VACUUM")
    finally:
        connection.close()
    # Re-opening through Database restores the current validation triggers.
    Database(path)
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")


def _verify_secret_free_tree(root: Path) -> None:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        content = path.read_bytes()
        if any(marker in content for marker in _SECRET_MARKERS):
            raise ValueError(
                f"Backup stopped because secret-like material was found in {path.name}"
            )


def _verify_secret_free_archive(path: Path) -> None:
    total = 0
    longest = max(len(marker) for marker in _SECRET_MARKERS)
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            member = Path(info.filename)
            if member.is_absolute() or ".." in member.parts or info.file_size > _MAX_BACKUP_MEMBER_BYTES:
                raise ValueError("Backup archive contains an unsafe member")
            total += info.file_size
            if total > _MAX_BACKUP_TOTAL_BYTES:
                raise ValueError("Backup archive exceeds the total byte limit")
            tail = b""
            with archive.open(info) as handle:
                while chunk := handle.read(1024 * 1024):
                    window = tail + chunk
                    if any(marker in window for marker in _SECRET_MARKERS):
                        raise ValueError(
                            f"Backup stopped because secret-like material was found in {member.name}"
                        )
                    tail = window[-longest:]


class BackupService:
    """Create portable, secret-free Atlas backups."""

    def __init__(
        self,
        *,
        config: AtlasConfig,
        database: Database,
        identity: IdentityStore,
    ) -> None:
        self.config = config
        self.database = database
        self.identity = identity

    def _portable_data(self) -> dict[str, Any]:
        conversations = [
            *self.database.list_conversations(archived=False, limit=100_000),
            *self.database.list_conversations(archived=True, limit=100_000),
        ]
        portable_conversations: list[dict[str, Any]] = []
        for conversation in conversations:
            portable_conversations.append(
                {
                    key: value
                    for key, value in conversation.items()
                    if key not in {"last_message", "message_count"}
                }
                | {
                    "messages": self.database.list_messages(
                        conversation["id"], limit=1_000_000
                    )
                }
            )
        return {
            "format": "atlas-core-portable-data",
            "version": 1,
            "atlas_version": __version__,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "projects": self.database.list_projects(limit=100_000),
            "memories": self.database.list_memories(limit=1_000_000),
            "conversations": portable_conversations,
            "supervisor_tasks": self.database.list_supervisor_tasks(limit=1_000_000),
            # Privacy-minimized receipts only. Runtime clones and patch artifacts
            # live under data/supervisor-v2 and are never copied into this export.
            "supervisor_v2_tasks": self.database.list_supervisor_v2_tasks(
                limit=1_000_000
            ),
            # V3 exports only redacted plan bindings, counters, envelope digests,
            # and terminal outcomes. Its SDK, homes, clones, and patches stay in
            # ignored data/supervisor-v3 and are never copied.
            "supervisor_v3_tasks": self.database.list_supervisor_v3_tasks(
                limit=1_000_000
            ),
            # V4 exports historical, non-authoritative evidence only. Free-form
            # bodies, scopes, nonces, signatures, process identities, active jobs,
            # and capability-consumption state deliberately stay out of portable
            # backups and cannot be restored as authority.
            "supervisor_v4_qualifications": [
                {
                    key: item[key]
                    for key in ("id", "subject", "status", "content_sha256", "created_at")
                }
                for item in self.database.list_supervisor_v4_qualifications(limit=10_000)
            ],
            "supervisor_v4_jobs": [
                {
                    "id": item["id"],
                    "kind": item["kind"],
                    "definition_sha256": item["definition_sha256"],
                    "qualification_id": item["qualification_id"],
                    "created_at": item["created_at"],
                    "terminal_state": item.get("state")
                    if item.get("state")
                    in {"offline_qualified", "offline_failed", "stopped", "interrupted", "cancelled"}
                    else "quarantined_historical",
                    "authority_granted": False,
                }
                for item in self.database.list_supervisor_v4_jobs(limit=10_000)
            ],
            "supervisor_v4_capabilities": [],
            "supervisor_v4_capability_consumptions": [],
            "supervisor_v4_receipts": [
                {
                    key: item[key]
                    for key in (
                        "sequence",
                        "id",
                        "receipt_kind",
                        "subject_id",
                        "content_sha256",
                        "previous_chain_sha256",
                        "signer_key_id",
                        "signature_algorithm",
                        "public_metadata_sha256",
                        "chain_sha256",
                        "authority_granted",
                        "recorded_at",
                    )
                }
                for item in self.database.list_supervisor_v4_receipts(limit=100_000)
            ],
        }

    def create_backup(
        self,
        destination: str | Path | None = None,
        *,
        include_workspace: bool | None = None,
    ) -> Path:
        include = (
            self.config.backups.include_workspace_by_default
            if include_workspace is None
            else include_workspace
        )
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        target = (
            Path(destination).expanduser().resolve()
            if destination
            else (self.config.app.data_dir / f"atlas-backup-{timestamp}.zip").resolve()
        )
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_symlink():
            raise ValueError("Backup destination cannot be a symbolic link")
        with tempfile.TemporaryDirectory(prefix="atlas-backup-") as temporary:
            root = Path(temporary) / "atlas-backup"
            root.mkdir()
            self.database.backup_to(root / "atlas.db")
            _redact_v4_from_database_copy(root / "atlas.db")
            (root / "atlas_data.json").write_text(
                json.dumps(self._portable_data(), indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            _copy_tree_no_follow(self.config.app.identity_dir, root / "identity")
            config_dir = root / "config"
            config_dir.mkdir()
            portable_config = _portable_config_projection(self.config.config_path)
            _write_private_file(
                config_dir / self.config.config_path.name,
                portable_config,
            )
            for path in (
                self.config.app.permissions_file,
                self.config.app.agents_file,
                self.config.app.development_projects_file,
                self.config.app.supervisor_policy_file,
                self.config.app.supervisor_v2_policy_file,
                self.config.app.supervisor_v3_policy_file,
                self.config.app.supervisor_v3_classifier_file,
                self.config.app.supervisor_v3_lock_file,
                self.config.app.supervisor_v4_contract_file,
                self.config.app.supervisor_v4_protocol_file,
                self.config.app.supervisor_v4_lock_file,
                self.config.app.supervisor_v4_replay_file,
                self.config.app.supervisor_v4_same_user_registry_file,
            ):
                if path.exists():
                    _copy_regular_no_follow(path, config_dir / path.name)
            if include and self.config.app.workspace_dir.exists():
                _copy_tree_no_follow(
                    self.config.app.workspace_dir,
                    root / "workspace",
                    ignored_names=frozenset({".atlas_home", ".atlas_tmp"}),
                )
            # Only attest that secrets are excluded after every source has been
            # copied and the active configuration has been structurally redacted.
            _verify_secret_free_tree(root)
            manifest: dict[str, Any] = {
                "format": "atlas-core-backup",
                "version": 1,
                "atlas_version": __version__,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "identity_fingerprint": self.identity.fingerprint(),
                "database_stats": self.database.stats(),
                "workspace_included": include,
                "portable_data_included": True,
                "secrets_included": False,
                "contains_private_owner_data": True,
                "encrypted": False,
                "file_mode": "0600",
                "redaction_profile": "atlas-portable-v4-historical-v1",
                "v4_active_authority_included": False,
                "v4_raw_content_included": False,
            }
            (root / "manifest.json").write_text(
                json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
            )
            _verify_secret_free_tree(root)
            descriptor, temporary_archive_name = tempfile.mkstemp(
                prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
            )
            temporary_archive = Path(temporary_archive_name)
            try:
                os.fchmod(descriptor, 0o600)
                os.close(descriptor)
                descriptor = -1
                with zipfile.ZipFile(
                    temporary_archive,
                    "w",
                    compression=zipfile.ZIP_DEFLATED,
                    compresslevel=6,
                ) as archive:
                    for path in sorted(root.rglob("*")):
                        if path.is_file():
                            archive.write(
                                path, Path("atlas-backup") / path.relative_to(root)
                            )
                _verify_secret_free_archive(temporary_archive)
                with temporary_archive.open("rb") as handle:
                    os.fsync(handle.fileno())
                os.replace(temporary_archive, target)
                os.chmod(target, 0o600)
                directory_descriptor = os.open(
                    target.parent,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
                )
                try:
                    os.fsync(directory_descriptor)
                finally:
                    os.close(directory_descriptor)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
                temporary_archive.unlink(missing_ok=True)
        return target

    def create_backup_bytes(
        self, *, include_workspace: bool | None = None
    ) -> bytes:
        """Create a portable backup without leaving a temporary archive behind."""
        with tempfile.TemporaryDirectory(prefix="atlas-export-") as temporary:
            path = self.create_backup(
                Path(temporary) / "atlas-core-backup.zip",
                include_workspace=include_workspace,
            )
            return path.read_bytes()
