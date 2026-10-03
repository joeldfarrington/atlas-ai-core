from __future__ import annotations

import os
import shutil
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from atlas_core.errors import ToolError
from atlas_core.tools.base import Tool


class FilesystemTool(Tool):
    name = "filesystem"
    _CONTROL_DIRS = {".atlas_development_control", ".atlas_versions", ".atlas_trash", ".atlas_home", ".atlas_tmp"}

    def __init__(self, workspace_root: str | Path, max_file_bytes: int) -> None:
        self.root = Path(workspace_root).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.max_file_bytes = max_file_bytes
        (self.root / ".atlas_versions").mkdir(exist_ok=True)
        (self.root / ".atlas_trash").mkdir(exist_ok=True)

    def _resolve(self, supplied: Any, *, allow_root: bool = False) -> Path:
        if not isinstance(supplied, str) or not supplied.strip():
            if allow_root:
                return self.root
            raise ToolError("A non-empty relative path is required")
        relative = Path(supplied)
        candidate = relative.resolve() if relative.is_absolute() else (self.root / relative).resolve()
        if candidate != self.root and self.root not in candidate.parents:
            raise ToolError("Path escapes the Atlas workspace")
        if not allow_root and candidate == self.root:
            raise ToolError("This action cannot target the workspace root")
        try:
            relative_to_root = candidate.relative_to(self.root)
        except ValueError as exc:
            raise ToolError("Path escapes the Atlas workspace") from exc
        if candidate.exists() and candidate.is_file() and candidate.stat().st_nlink != 1:
            raise ToolError("Hard-linked files cannot be accessed through this tool")
        if any(part in self._CONTROL_DIRS for part in relative_to_root.parts):
            raise ToolError("Atlas control directories cannot be accessed through this tool")
        return candidate

    def _display(self, path: Path) -> str:
        return str(path.relative_to(self.root)) if path != self.root else "."

    def _require_regular_file(self, path: Path) -> None:
        if not path.exists():
            raise ToolError(f"File not found: {self._display(path)}")
        if path.is_symlink():
            raise ToolError("Symbolic links are not supported")
        if not path.is_file():
            raise ToolError(f"Not a regular file: {self._display(path)}")

    def _write_atomic(self, path: Path, content: str) -> None:
        encoded = content.encode("utf-8")
        if len(encoded) > self.max_file_bytes:
            raise ToolError(f"Content exceeds the {self.max_file_bytes}-byte workspace limit")
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, path)
        finally:
            temporary_path.unlink(missing_ok=True)

    def _backup(self, path: Path) -> Path:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        relative = path.relative_to(self.root)
        backup_dir = self.root / ".atlas_versions" / relative.parent
        backup_dir.mkdir(parents=True, exist_ok=True)
        backup_path = backup_dir / f"{relative.name}.{timestamp}.{uuid.uuid4().hex[:8]}.bak"
        shutil.copy2(path, backup_path)
        return backup_path

    def list_directory(self, arguments: dict[str, Any]) -> dict[str, Any]:
        path = self._resolve(arguments.get("path", "."), allow_root=True)
        if not path.exists():
            raise ToolError(f"Directory not found: {self._display(path)}")
        if path.is_symlink() or not path.is_dir():
            raise ToolError(f"Not a directory: {self._display(path)}")
        entries: list[dict[str, Any]] = []
        for child in sorted(path.iterdir(), key=lambda item: item.name.lower()):
            if child.name in self._CONTROL_DIRS:
                continue
            stat = child.lstat()
            entries.append(
                {
                    "name": child.name,
                    "path": self._display(child),
                    "type": "symlink" if child.is_symlink() else "directory" if child.is_dir() else "file",
                    "size": stat.st_size,
                }
            )
        return {"path": self._display(path), "entries": entries[:1_000]}

    def read_file(self, arguments: dict[str, Any]) -> dict[str, Any]:
        path = self._resolve(arguments.get("path"))
        self._require_regular_file(path)
        size = path.stat().st_size
        if size > self.max_file_bytes:
            raise ToolError(f"File is {size} bytes; limit is {self.max_file_bytes} bytes")
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise ToolError("Only UTF-8 text files are supported") from exc
        return {"path": self._display(path), "size": size, "content": content}

    def search_files(self, arguments: dict[str, Any]) -> dict[str, Any]:
        query = arguments.get("query")
        if not isinstance(query, str) or not query:
            raise ToolError("query must be a non-empty string")
        start = self._resolve(arguments.get("path", "."), allow_root=True)
        if not start.exists() or not start.is_dir() or start.is_symlink():
            raise ToolError("path must be a workspace directory")
        limit = min(max(int(arguments.get("limit", 50)), 1), 200)
        matches: list[dict[str, Any]] = []
        for path in start.rglob("*"):
            if len(matches) >= limit:
                break
            if path.is_symlink() or not path.is_file():
                continue
            relative = path.relative_to(self.root)
            if any(part in self._CONTROL_DIRS for part in relative.parts):
                continue
            try:
                if path.stat().st_size > self.max_file_bytes:
                    continue
                lines = path.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError):
                continue
            for number, line in enumerate(lines, start=1):
                if query.lower() in line.lower():
                    matches.append(
                        {
                            "path": str(relative),
                            "line": number,
                            "text": line[:500],
                        }
                    )
                    if len(matches) >= limit:
                        break
        return {"query": query, "path": self._display(start), "matches": matches}

    def create_file(self, arguments: dict[str, Any]) -> dict[str, Any]:
        path = self._resolve(arguments.get("path"))
        if path.exists():
            raise ToolError(f"Path already exists: {self._display(path)}")
        content = arguments.get("content", "")
        if not isinstance(content, str):
            raise ToolError("content must be a string")
        self._write_atomic(path, content)
        return {"path": self._display(path), "created": True, "size": path.stat().st_size}

    def modify_file(self, arguments: dict[str, Any]) -> dict[str, Any]:
        path = self._resolve(arguments.get("path"))
        self._require_regular_file(path)
        content = arguments.get("content")
        if not isinstance(content, str):
            raise ToolError("content must be a string")
        backup_path = self._backup(path)
        self._write_atomic(path, content)
        return {
            "path": self._display(path),
            "modified": True,
            "size": path.stat().st_size,
            "backup": str(backup_path.relative_to(self.root)),
        }

    def delete_path(self, arguments: dict[str, Any]) -> dict[str, Any]:
        path = self._resolve(arguments.get("path"))
        if not path.exists():
            raise ToolError(f"Path not found: {self._display(path)}")
        if path.is_symlink():
            raise ToolError("Symbolic links are not supported")
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        relative = path.relative_to(self.root)
        trash_path = self.root / ".atlas_trash" / timestamp / relative
        trash_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(path), str(trash_path))
        return {
            "path": str(relative),
            "deleted": True,
            "recoverable_from": str(trash_path.relative_to(self.root)),
        }

    def execute(self, action: str, arguments: dict[str, Any]) -> dict[str, Any]:
        actions = {
            "list": self.list_directory,
            "read": self.read_file,
            "search": self.search_files,
            "create": self.create_file,
            "modify": self.modify_file,
            "delete": self.delete_path,
        }
        handler = actions.get(action)
        if handler is None:
            raise ToolError(f"Unsupported filesystem action: {action}")
        return handler(arguments)

    def describe(self) -> dict[str, Any]:
        path_schema = {"type": "string", "description": "Path relative to the Atlas workspace."}
        return {
            "name": self.name,
            "description": "Read and manage files inside the owner-controlled Atlas workspace.",
            "workspace_root": str(self.root),
            "max_file_bytes": self.max_file_bytes,
            "actions": {
                "list": {
                    "description": "List a workspace directory.",
                    "parameters": {"type": "object", "properties": {"path": path_schema}, "additionalProperties": False},
                },
                "read": {
                    "description": "Read a UTF-8 text file from the workspace.",
                    "parameters": {"type": "object", "properties": {"path": path_schema}, "required": ["path"], "additionalProperties": False},
                },
                "search": {
                    "description": "Search UTF-8 workspace files for a text phrase.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string"},
                            "path": path_schema,
                            "limit": {"type": "integer", "minimum": 1, "maximum": 200},
                        },
                        "required": ["query"],
                        "additionalProperties": False,
                    },
                },
                "create": {
                    "description": "Create a new UTF-8 text file in the workspace.",
                    "parameters": {
                        "type": "object",
                        "properties": {"path": path_schema, "content": {"type": "string"}},
                        "required": ["path", "content"],
                        "additionalProperties": False,
                    },
                },
                "modify": {
                    "description": "Replace a workspace file, preserving a version backup.",
                    "parameters": {
                        "type": "object",
                        "properties": {"path": path_schema, "content": {"type": "string"}},
                        "required": ["path", "content"],
                        "additionalProperties": False,
                    },
                },
                "delete": {
                    "description": "Move a workspace path to recoverable Atlas trash.",
                    "parameters": {"type": "object", "properties": {"path": path_schema}, "required": ["path"], "additionalProperties": False},
                },
            },
        }
