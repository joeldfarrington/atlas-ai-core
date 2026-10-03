from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from atlas_core.config import MacInboxConfig
from atlas_core.errors import ToolError
from atlas_core.tools.base import Tool


class MacInboxTool(Tool):
    """Operate one owner-approved Mac folder without broad computer access."""

    name = "mac_inbox"
    _OPERATIONS = {
        "create_folder",
        "move",
        "trash",
        "restore",
        "reveal",
        "open",
    }
    _PREVIEW_ID = re.compile(r"[0-9a-f]{32}")
    _RECOVERY_ID = re.compile(r"[0-9a-f]{32}")
    _BLOCKED_BUNDLE_SUFFIXES = {
        ".app",
        ".bundle",
        ".framework",
        ".plugin",
        ".prefpane",
        ".qlgenerator",
        ".saver",
        ".workflow",
    }

    def __init__(self, config: MacInboxConfig) -> None:
        self.config = config
        self.root = config.root.expanduser().resolve()
        self.recovery_root = config.recovery_dir.expanduser().resolve()
        self.preview_root = config.preview_dir.expanduser().resolve()
        self.pause_file = config.pause_file.expanduser().resolve()
        self.safe_open_extensions = set(config.safe_open_extensions)
        if config.enabled:
            self.root.mkdir(parents=True, exist_ok=True)
            self.recovery_root.mkdir(parents=True, exist_ok=True)
            self.preview_root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, ensure_ascii=False, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)

    def _require_active(self) -> None:
        if not self.config.enabled:
            raise ToolError("The Atlas Inbox Mac operator is disabled")
        if self.pause_file.exists():
            raise ToolError(
                "The Atlas Inbox Mac operator is paused by the owner stop control"
            )

    def pause(self) -> dict[str, Any]:
        if not self.config.enabled:
            raise ToolError("The Atlas Inbox Mac operator is disabled")
        if self.pause_file.is_symlink():
            raise ToolError("The Mac operator pause control is not a regular file")
        self._write_json_atomic(
            self.pause_file,
            {"paused_at": self._now().isoformat(), "scope": "mac_inbox"},
        )
        return self.status({})

    def resume(self) -> dict[str, Any]:
        if self.pause_file.is_symlink():
            raise ToolError("The Mac operator pause control is not a regular file")
        self.pause_file.unlink(missing_ok=True)
        return self.status({})

    @staticmethod
    def _parts(path: Path) -> tuple[str, ...]:
        return tuple(part for part in path.parts if part not in {"", "."})

    def _resolve(self, supplied: Any, *, allow_root: bool = False) -> Path:
        if not isinstance(supplied, str) or not supplied.strip():
            if allow_root:
                supplied = "."
            else:
                raise ToolError("A non-empty Atlas-Inbox-relative path is required")
        relative = Path(supplied)
        if relative.is_absolute() or ".." in relative.parts:
            raise ToolError("Path escapes the approved Atlas Inbox")
        parts = self._parts(relative)
        if any(part.startswith(".") for part in parts):
            raise ToolError("Hidden paths are outside the initial Atlas Inbox gate")

        cursor = self.root
        for part in parts:
            cursor = cursor / part
            if cursor.is_symlink():
                raise ToolError("Symbolic links are outside the Atlas Inbox gate")

        candidate = (self.root / relative).resolve()
        if candidate != self.root and self.root not in candidate.parents:
            raise ToolError("Path escapes the approved Atlas Inbox")
        if not allow_root and candidate == self.root:
            raise ToolError("This action cannot target the Atlas Inbox root")
        return candidate

    def _display(self, path: Path) -> str:
        return str(path.relative_to(self.root)) if path != self.root else "."

    def _require_existing(self, path: Path) -> None:
        if not path.exists():
            raise ToolError(f"Atlas Inbox item not found: {self._display(path)}")
        if path.is_symlink():
            raise ToolError("Symbolic links are outside the Atlas Inbox gate")

    def _require_destination(self, path: Path) -> None:
        if path.exists() or path.is_symlink():
            raise ToolError(
                f"Atlas Inbox destination already exists: {self._display(path)}"
            )
        parent = path.parent
        if not parent.exists() or not parent.is_dir() or parent.is_symlink():
            raise ToolError(
                f"Atlas Inbox destination parent is unavailable: {self._display(parent)}"
            )

    @staticmethod
    def _metadata(path: Path) -> dict[str, Any]:
        if path.is_dir():
            item_type = "directory"
        elif path.is_file():
            item_type = "file"
        else:
            raise ToolError(
                "Only regular files and folders are inside the Atlas Inbox gate"
            )
        details = path.lstat()
        return {
            "name": path.name,
            "type": item_type,
            "size": details.st_size,
            "mtime_ns": details.st_mtime_ns,
            "mode": stat.S_IMODE(details.st_mode),
            "inode": details.st_ino,
        }

    def _fingerprint(self, path: Path) -> dict[str, Any]:
        self._require_existing(path)
        records: list[dict[str, Any]] = []
        total_size = 0

        def add(item: Path, relative: str) -> None:
            nonlocal total_size
            if item.is_symlink():
                raise ToolError("Symbolic links are outside the Atlas Inbox gate")
            if relative != "." and any(
                part.startswith(".") for part in Path(relative).parts
            ):
                raise ToolError("Hidden paths are outside the initial Atlas Inbox gate")
            metadata = self._metadata(item)
            metadata["relative"] = relative
            records.append(metadata)
            if metadata["type"] == "file":
                total_size += int(metadata["size"])
            if len(records) > self.config.max_entries:
                raise ToolError(
                    f"Item exceeds the {self.config.max_entries}-entry Atlas Inbox gate"
                )

        add(path, ".")
        if path.is_dir():
            for child in sorted(path.rglob("*"), key=lambda item: str(item)):
                add(child, str(child.relative_to(path)))
        encoded = json.dumps(
            records, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return {
            "sha256": hashlib.sha256(encoded).hexdigest(),
            "type": "directory" if path.is_dir() else "file",
            "entries": len(records),
            "total_size": total_size,
        }

    def _validate_open(self, path: Path) -> None:
        self._require_existing(path)
        if path.is_dir():
            if path.suffix.lower() in self._BLOCKED_BUNDLE_SUFFIXES:
                raise ToolError(
                    "Application and automation bundles are outside the Atlas Inbox open gate"
                )
            return
        mode = path.stat().st_mode
        if mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
            raise ToolError("Executable files are outside the Atlas Inbox open gate")
        if path.suffix.lower() not in self.safe_open_extensions:
            raise ToolError(
                f"Opening {path.suffix or 'extensionless files'} is outside the safe document gate"
            )

    def _recovery_dir(self, recovery_id: str) -> Path:
        if not self._RECOVERY_ID.fullmatch(recovery_id):
            raise ToolError("Invalid Atlas Inbox recovery ID")
        return self.recovery_root / recovery_id

    def _receipt(self, recovery_id: str) -> dict[str, Any]:
        receipt_path = self._recovery_dir(recovery_id) / "receipt.json"
        if not receipt_path.is_file() or receipt_path.is_symlink():
            raise ToolError(f"Recovery record not found: {recovery_id}")
        try:
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ToolError(f"Recovery record is unreadable: {recovery_id}") from exc
        if receipt.get("recovery_id") != recovery_id:
            raise ToolError("Recovery record identifier mismatch")
        return receipt

    def _operation_state(
        self, operation: str, arguments: dict[str, Any]
    ) -> tuple[dict[str, Any], dict[str, str], str]:
        if operation not in self._OPERATIONS:
            raise ToolError(f"Unsupported Atlas Inbox preview operation: {operation}")

        if operation == "create_folder":
            path = self._resolve(arguments.get("path"))
            self._require_destination(path)
            normalized = {"path": self._display(path)}
            state = {"destination_absent": True, "parent": self._display(path.parent)}
            summary = f"Create folder '{normalized['path']}' inside Atlas Inbox."
            return state, normalized, summary

        if operation == "move":
            source = self._resolve(arguments.get("source"))
            destination = self._resolve(arguments.get("destination"))
            self._require_existing(source)
            self._require_destination(destination)
            if source.is_dir() and source in destination.parents:
                raise ToolError("A folder cannot be moved inside itself")
            normalized = {
                "source": self._display(source),
                "destination": self._display(destination),
            }
            state = {
                "source": self._fingerprint(source),
                "destination_absent": True,
            }
            summary = (
                f"Move '{normalized['source']}' to '{normalized['destination']}' "
                "inside Atlas Inbox."
            )
            return state, normalized, summary

        if operation == "trash":
            path = self._resolve(arguments.get("path"))
            normalized = {"path": self._display(path)}
            state = {"source": self._fingerprint(path)}
            summary = (
                f"Move '{normalized['path']}' out of Atlas Inbox into recoverable "
                "Atlas storage; no permanent deletion."
            )
            return state, normalized, summary

        if operation == "restore":
            recovery_id = arguments.get("recovery_id")
            if not isinstance(recovery_id, str):
                raise ToolError("A recovery_id is required")
            receipt = self._receipt(recovery_id)
            if receipt.get("status") != "trashed":
                raise ToolError(f"Recovery record is {receipt.get('status')}, not trashed")
            original = self._resolve(receipt.get("original_path"))
            self._require_destination(original)
            payload = self._recovery_dir(recovery_id) / "payload"
            if not payload.exists() or payload.is_symlink():
                raise ToolError(f"Recovery payload is unavailable: {recovery_id}")
            normalized = {"recovery_id": recovery_id}
            state = {
                "payload": self._fingerprint(payload),
                "destination_absent": True,
                "original_path": self._display(original),
            }
            summary = f"Restore '{self._display(original)}' to Atlas Inbox."
            return state, normalized, summary

        path = self._resolve(arguments.get("path"))
        self._require_existing(path)
        if operation == "open":
            self._validate_open(path)
        normalized = {"path": self._display(path)}
        state = {"source": self._fingerprint(path)}
        verb = "Open" if operation == "open" else "Reveal in Finder"
        summary = f"{verb} '{normalized['path']}' from Atlas Inbox."
        return state, normalized, summary

    def _plan_path(self, preview_id: str) -> Path:
        if not self._PREVIEW_ID.fullmatch(preview_id):
            raise ToolError("Invalid Atlas Inbox preview ID")
        return self.preview_root / f"{preview_id}.json"

    def _load_plan(
        self, operation: str, arguments: dict[str, Any]
    ) -> tuple[Path, dict[str, Any], dict[str, str]]:
        preview_id = arguments.get("preview_id")
        if not isinstance(preview_id, str):
            raise ToolError("An exact preview_id is required")
        plan_path = self._plan_path(preview_id)
        if not plan_path.is_file() or plan_path.is_symlink():
            raise ToolError(f"Preview not found: {preview_id}")
        try:
            plan = json.loads(plan_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ToolError(f"Preview is unreadable: {preview_id}") from exc
        if plan.get("operation") != operation:
            raise ToolError("Preview operation does not match the requested action")
        if plan.get("consumed_at"):
            raise ToolError("Preview has already been used")
        try:
            expires_at = datetime.fromisoformat(str(plan.get("expires_at")))
        except ValueError as exc:
            raise ToolError("Preview expiration record is invalid") from exc
        if self._now() > expires_at:
            raise ToolError("Preview expired; create a new preview")

        supplied = {key: value for key, value in arguments.items() if key != "preview_id"}
        current_state, normalized, _ = self._operation_state(operation, supplied)
        if normalized != plan.get("execution_arguments"):
            raise ToolError("Action arguments do not match the exact preview")
        if current_state != plan.get("state"):
            raise ToolError("Atlas Inbox changed after preview; create a new preview")
        return plan_path, plan, normalized

    def _consume_plan(
        self, plan_path: Path, plan: dict[str, Any], result: dict[str, Any]
    ) -> None:
        plan["consumed_at"] = self._now().isoformat()
        plan["outcome"] = "success"
        plan["result"] = result
        self._write_json_atomic(plan_path, plan)

    def status(self, arguments: dict[str, Any]) -> dict[str, Any]:
        if arguments:
            raise ToolError("mac_inbox.status does not accept arguments")
        paused = self.pause_file.exists()
        return {
            "enabled": self.config.enabled,
            "paused": paused,
            "ready": self.config.enabled and not paused and self.root.is_dir(),
            "platform": sys.platform,
            "task_family": "bounded-mac-file-and-finder-operator",
            "root": str(self.root),
            "root_exists": self.root.is_dir(),
            "root_writable": self.root.is_dir() and os.access(self.root, os.W_OK),
            "required_permissions": [
                "filesystem access to this exact Atlas Inbox folder",
                "standard macOS open/Finder access for open and reveal",
            ],
            "not_required": ["Full Disk Access", "Accessibility control", "administrator access"],
            "supported_actions": sorted(self._OPERATIONS | {"list", "list_recovery", "preview"}),
            "safe_open_extensions": sorted(self.safe_open_extensions),
            "stop_controls": [
                "turn off Allow agent tools for the active Atlas chat",
                "run Pause Atlas Mac Operator.command",
                "stop the local Atlas service",
            ],
        }

    def list_directory(self, arguments: dict[str, Any]) -> dict[str, Any]:
        self._require_active()
        path = self._resolve(arguments.get("path", "."), allow_root=True)
        if not path.exists() or not path.is_dir() or path.is_symlink():
            raise ToolError("path must be a real directory inside Atlas Inbox")
        entries: list[dict[str, Any]] = []
        hidden_omitted = 0
        for child in sorted(path.iterdir(), key=lambda item: item.name.lower()):
            if child.name.startswith("."):
                hidden_omitted += 1
                continue
            if child.is_symlink():
                entry_type = "blocked-symlink"
            elif not child.is_dir() and not child.is_file():
                entry_type = "blocked-special"
            else:
                entry_type = "directory" if child.is_dir() else "file"
            details = child.lstat()
            entries.append(
                {
                    "name": child.name,
                    "path": self._display(child),
                    "type": entry_type,
                    "size": details.st_size,
                }
            )
            if len(entries) >= self.config.max_entries:
                break
        return {
            "path": self._display(path),
            "entries": entries,
            "entry_count": len(entries),
            "hidden_entries_omitted": hidden_omitted,
            "truncated": len(entries) >= self.config.max_entries,
        }

    def preview(self, arguments: dict[str, Any]) -> dict[str, Any]:
        self._require_active()
        operation = arguments.get("operation")
        if not isinstance(operation, str):
            raise ToolError("A preview operation is required")
        supplied = {key: value for key, value in arguments.items() if key != "operation"}
        state, normalized, summary = self._operation_state(operation, supplied)
        preview_id = uuid.uuid4().hex
        now = self._now()
        plan = {
            "preview_id": preview_id,
            "operation": operation,
            "summary": summary,
            "execution_arguments": normalized,
            "state": state,
            "created_at": now.isoformat(),
            "expires_at": (
                now + timedelta(seconds=self.config.preview_ttl_seconds)
            ).isoformat(),
            "consumed_at": None,
        }
        self._write_json_atomic(self._plan_path(preview_id), plan)
        return {
            "preview_id": preview_id,
            "operation": operation,
            "summary": summary,
            "expires_at": plan["expires_at"],
            "execution_arguments": normalized | {"preview_id": preview_id},
            "will_permanently_delete": False,
        }

    def create_folder(self, arguments: dict[str, Any]) -> dict[str, Any]:
        self._require_active()
        plan_path, plan, normalized = self._load_plan("create_folder", arguments)
        path = self._resolve(normalized["path"])
        path.mkdir()
        result = {"created": True, "path": self._display(path), "verified": path.is_dir()}
        self._consume_plan(plan_path, plan, result)
        return result

    def move(self, arguments: dict[str, Any]) -> dict[str, Any]:
        self._require_active()
        plan_path, plan, normalized = self._load_plan("move", arguments)
        source = self._resolve(normalized["source"])
        destination = self._resolve(normalized["destination"])
        os.rename(source, destination)
        result = {
            "moved": True,
            "source": normalized["source"],
            "destination": normalized["destination"],
            "verified": destination.exists() and not source.exists(),
        }
        self._consume_plan(plan_path, plan, result)
        return result

    def trash(self, arguments: dict[str, Any]) -> dict[str, Any]:
        self._require_active()
        plan_path, plan, normalized = self._load_plan("trash", arguments)
        source = self._resolve(normalized["path"])
        recovery_id = uuid.uuid4().hex
        recovery_dir = self._recovery_dir(recovery_id)
        payload = recovery_dir / "payload"
        recovery_dir.mkdir(parents=True)
        receipt = {
            "recovery_id": recovery_id,
            "original_path": normalized["path"],
            "status": "trashed",
            "trashed_at": self._now().isoformat(),
            "restored_at": None,
            "fingerprint": plan["state"]["source"],
        }
        try:
            shutil.move(str(source), str(payload))
            self._write_json_atomic(recovery_dir / "receipt.json", receipt)
        except Exception:
            if payload.exists() and not source.exists():
                shutil.move(str(payload), str(source))
            shutil.rmtree(recovery_dir, ignore_errors=True)
            raise
        result = {
            "trashed": True,
            "path": normalized["path"],
            "recovery_id": recovery_id,
            "permanent": False,
            "verified": payload.exists() and not source.exists(),
        }
        self._consume_plan(plan_path, plan, result)
        return result

    def restore(self, arguments: dict[str, Any]) -> dict[str, Any]:
        self._require_active()
        plan_path, plan, normalized = self._load_plan("restore", arguments)
        recovery_id = normalized["recovery_id"]
        recovery_dir = self._recovery_dir(recovery_id)
        receipt = self._receipt(recovery_id)
        destination = self._resolve(receipt["original_path"])
        payload = recovery_dir / "payload"
        shutil.move(str(payload), str(destination))
        receipt["status"] = "restored"
        receipt["restored_at"] = self._now().isoformat()
        self._write_json_atomic(recovery_dir / "receipt.json", receipt)
        result = {
            "restored": True,
            "path": self._display(destination),
            "recovery_id": recovery_id,
            "verified": destination.exists() and not payload.exists(),
        }
        self._consume_plan(plan_path, plan, result)
        return result

    def list_recovery(self, arguments: dict[str, Any]) -> dict[str, Any]:
        self._require_active()
        if arguments:
            raise ToolError("mac_inbox.list_recovery does not accept arguments")
        receipts: list[dict[str, Any]] = []
        for receipt_path in sorted(
            self.recovery_root.glob("*/receipt.json"), reverse=True
        ):
            try:
                receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            receipts.append(
                {
                    "recovery_id": receipt.get("recovery_id"),
                    "original_path": receipt.get("original_path"),
                    "status": receipt.get("status"),
                    "trashed_at": receipt.get("trashed_at"),
                    "restored_at": receipt.get("restored_at"),
                }
            )
            if len(receipts) >= 200:
                break
        return {"receipts": receipts, "receipt_count": len(receipts)}

    @staticmethod
    def _run_open(path: Path, *, reveal: bool) -> dict[str, Any]:
        if sys.platform != "darwin":
            raise ToolError("Finder open and reveal are available only on macOS")
        argv = ["/usr/bin/open", "-R", str(path)] if reveal else ["/usr/bin/open", str(path)]
        try:
            completed = subprocess.run(
                argv,
                shell=False,
                env={
                    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                    "HOME": str(Path.home()),
                    "LANG": os.getenv("LANG", "C.UTF-8"),
                },
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ToolError("macOS did not complete the open request") from exc
        if completed.returncode != 0:
            detail = completed.stderr.strip()[-500:] or "unknown macOS open error"
            raise ToolError(f"macOS open request failed: {detail}")
        return {"argv": argv, "returncode": completed.returncode}

    def reveal(self, arguments: dict[str, Any]) -> dict[str, Any]:
        self._require_active()
        plan_path, plan, normalized = self._load_plan("reveal", arguments)
        path = self._resolve(normalized["path"])
        self._run_open(path, reveal=True)
        result = {"revealed": True, "path": normalized["path"], "verified": path.exists()}
        self._consume_plan(plan_path, plan, result)
        return result

    def open_item(self, arguments: dict[str, Any]) -> dict[str, Any]:
        self._require_active()
        plan_path, plan, normalized = self._load_plan("open", arguments)
        path = self._resolve(normalized["path"])
        self._run_open(path, reveal=False)
        result = {"opened": True, "path": normalized["path"], "verified": path.exists()}
        self._consume_plan(plan_path, plan, result)
        return result

    def execute(self, action: str, arguments: dict[str, Any]) -> dict[str, Any]:
        actions = {
            "status": self.status,
            "list": self.list_directory,
            "preview": self.preview,
            "create_folder": self.create_folder,
            "move": self.move,
            "trash": self.trash,
            "restore": self.restore,
            "list_recovery": self.list_recovery,
            "reveal": self.reveal,
            "open": self.open_item,
        }
        handler = actions.get(action)
        if handler is None:
            raise ToolError(f"Unsupported Mac Inbox action: {action}")
        return handler(arguments)

    def audit_result(self, action: str, result: dict[str, Any]) -> dict[str, Any]:
        if action == "list":
            return {
                "path": result.get("path"),
                "entry_count": result.get("entry_count"),
                "hidden_entries_omitted": result.get("hidden_entries_omitted"),
                "truncated": result.get("truncated"),
            }
        if action == "list_recovery":
            return {"receipt_count": result.get("receipt_count")}
        return result

    def describe(self) -> dict[str, Any]:
        path_schema = {
            "type": "string",
            "description": "Path relative to the single approved Atlas Inbox folder.",
        }
        preview_id = {
            "type": "string",
            "pattern": "^[0-9a-f]{32}$",
            "description": "Unexpired one-use preview ID returned by mac_inbox.preview.",
        }
        return {
            "name": self.name,
            "description": (
                "Operate only the owner-approved Atlas Inbox on this Mac. Hidden paths, "
                "symbolic links, executables, permanent deletion, and paths outside the "
                "inbox are blocked. Every mutation, open, or Finder reveal requires an "
                "exact fresh preview."
            ),
            "root": str(self.root),
            "actions": {
                "status": {
                    "description": "Show the exact Mac Inbox scope, readiness, and stop controls.",
                    "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
                },
                "list": {
                    "description": "List names and metadata in one Atlas Inbox directory without reading file contents.",
                    "parameters": {
                        "type": "object",
                        "properties": {"path": path_schema},
                        "additionalProperties": False,
                    },
                },
                "preview": {
                    "description": "Validate and preview one exact Mac Inbox action before it can execute.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "operation": {"type": "string", "enum": sorted(self._OPERATIONS)},
                            "path": path_schema,
                            "source": path_schema,
                            "destination": path_schema,
                            "recovery_id": {"type": "string", "pattern": "^[0-9a-f]{32}$"},
                        },
                        "required": ["operation"],
                        "additionalProperties": False,
                    },
                },
                "create_folder": {
                    "description": "Create the folder from an exact unexpired preview.",
                    "parameters": {
                        "type": "object",
                        "properties": {"path": path_schema, "preview_id": preview_id},
                        "required": ["path", "preview_id"],
                        "additionalProperties": False,
                    },
                },
                "move": {
                    "description": "Move or rename an item within Atlas Inbox from an exact unexpired preview.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "source": path_schema,
                            "destination": path_schema,
                            "preview_id": preview_id,
                        },
                        "required": ["source", "destination", "preview_id"],
                        "additionalProperties": False,
                    },
                },
                "trash": {
                    "description": "Move an item into Atlas recovery storage from an exact preview; never permanently delete it.",
                    "parameters": {
                        "type": "object",
                        "properties": {"path": path_schema, "preview_id": preview_id},
                        "required": ["path", "preview_id"],
                        "additionalProperties": False,
                    },
                },
                "restore": {
                    "description": "Restore a recoverably trashed item to its original Atlas Inbox path.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "recovery_id": {"type": "string", "pattern": "^[0-9a-f]{32}$"},
                            "preview_id": preview_id,
                        },
                        "required": ["recovery_id", "preview_id"],
                        "additionalProperties": False,
                    },
                },
                "list_recovery": {
                    "description": "List local Atlas Inbox recovery receipts and restoration status.",
                    "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
                },
                "reveal": {
                    "description": "Reveal an existing Atlas Inbox item in Finder after an exact preview.",
                    "parameters": {
                        "type": "object",
                        "properties": {"path": path_schema, "preview_id": preview_id},
                        "required": ["path", "preview_id"],
                        "additionalProperties": False,
                    },
                },
                "open": {
                    "description": "Open an approved non-executable document or folder after an exact preview.",
                    "parameters": {
                        "type": "object",
                        "properties": {"path": path_schema, "preview_id": preview_id},
                        "required": ["path", "preview_id"],
                        "additionalProperties": False,
                    },
                },
            },
        }
