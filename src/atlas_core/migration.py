from __future__ import annotations

import json
import stat
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from atlas_core.errors import ImportFormatError
from atlas_core.memory.database import Database


def _iso_time(value: Any) -> str | None:
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc).isoformat(
                timespec="milliseconds"
            )
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if not isinstance(content, dict):
        return str(content or "")
    parts = content.get("parts")
    if isinstance(parts, list):
        output: list[str] = []
        for part in parts:
            if isinstance(part, str):
                output.append(part)
            elif isinstance(part, dict):
                if isinstance(part.get("text"), str):
                    output.append(part["text"])
                elif isinstance(part.get("content"), str):
                    output.append(part["content"])
        if output:
            return "\n".join(output)
    for key in ("text", "content", "result"):
        if isinstance(content.get(key), str):
            return content[key]
    return ""


class ImportService:
    """Merge portable Atlas data, ChatGPT exports, or explicit memories."""

    def __init__(self, database: Database, *, max_upload_bytes: int = 209_715_200) -> None:
        self.database = database
        self.max_upload_bytes = int(max_upload_bytes)

    def import_bytes(
        self,
        *,
        filename: str,
        data: bytes,
        source: str = "auto",
        project_slug: str | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        if len(data) > self.max_upload_bytes:
            raise ImportFormatError(
                f"Import is {len(data)} bytes; configured maximum is "
                f"{self.max_upload_bytes} bytes"
            )
        safe_name = Path(filename).name or "atlas-import.bin"
        with tempfile.TemporaryDirectory(prefix="atlas-upload-") as temporary:
            path = Path(temporary) / safe_name
            path.write_bytes(data)
            return self.import_path(
                path,
                source=source,
                project_slug=project_slug,
                dry_run=dry_run,
            )

    def import_path(
        self,
        path: str | Path,
        *,
        source: str = "auto",
        project_slug: str | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        file_path = Path(path).expanduser().resolve()
        if not file_path.exists() or not file_path.is_file():
            raise ImportFormatError(f"Import file not found: {file_path}")
        if file_path.stat().st_size > self.max_upload_bytes:
            raise ImportFormatError(
                f"Import is {file_path.stat().st_size} bytes; configured maximum is "
                f"{self.max_upload_bytes} bytes"
            )

        job = self.database.create_import_job(source, file_path.name)
        stats: dict[str, Any] = {
            "conversations_seen": 0,
            "conversations_imported": 0,
            "conversations_skipped": 0,
            "messages_imported": 0,
            "memories_imported": 0,
            "projects_imported": 0,
            "files_examined": [],
            "project_override": project_slug,
            "dry_run": dry_run,
        }
        try:
            if zipfile.is_zipfile(file_path):
                with zipfile.ZipFile(file_path) as archive, tempfile.TemporaryDirectory(
                    prefix="atlas-import-"
                ) as temporary:
                    candidates = self._safe_extract(archive, Path(temporary))
                    self._import_candidates(
                        candidates,
                        source=source,
                        project_slug=project_slug,
                        dry_run=dry_run,
                        stats=stats,
                    )
            else:
                self._import_candidates(
                    [file_path],
                    source=source,
                    project_slug=project_slug,
                    dry_run=dry_run,
                    stats=stats,
                )
            result = self.database.finish_import_job(
                job["id"], status="completed", stats=stats
            )
            self.database.audit(
                event_type="import",
                actor="operator",
                action="import.complete",
                resource=job["id"],
                outcome="success",
                details=stats,
            )
            return result
        except Exception as exc:
            self.database.finish_import_job(
                job["id"], status="failed", stats=stats, error=str(exc)
            )
            self.database.audit(
                event_type="import",
                actor="operator",
                action="import.complete",
                resource=job["id"],
                outcome="failed",
                details={"error": str(exc), **stats},
            )
            if isinstance(exc, ImportFormatError):
                raise
            raise ImportFormatError(str(exc)) from exc

    def _safe_extract(
        self, archive: zipfile.ZipFile, destination: Path
    ) -> list[Path]:
        files: list[Path] = []
        expanded_limit = min(self.max_upload_bytes * 4, 2_000_000_000)
        expanded_total = 0
        for info in archive.infolist():
            if info.is_dir():
                continue
            member = Path(info.filename)
            if member.is_absolute() or ".." in member.parts:
                raise ImportFormatError(
                    f"Unsafe path in import archive: {info.filename}"
                )
            unix_mode = info.external_attr >> 16
            if unix_mode and stat.S_ISLNK(unix_mode):
                raise ImportFormatError(
                    f"Symbolic links are not accepted in import archives: {info.filename}"
                )
            expanded_total += int(info.file_size)
            if expanded_total > expanded_limit:
                raise ImportFormatError(
                    "Import archive expands beyond the configured safety limit"
                )
            target = (destination / member).resolve()
            if destination.resolve() not in target.parents:
                raise ImportFormatError(
                    f"Unsafe path in import archive: {info.filename}"
                )
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, target.open("wb") as output:
                while chunk := source.read(1024 * 1024):
                    output.write(chunk)
            files.append(target)
        return files

    def _import_candidates(
        self,
        candidates: list[Path],
        *,
        source: str,
        project_slug: str | None,
        dry_run: bool,
        stats: dict[str, Any],
    ) -> None:
        relevant = sorted(
            candidates,
            key=lambda path: (
                0 if path.name.lower() == "atlas_data.json" else 1,
                0 if path.name.lower() == "conversations.json" else 1,
                path.name.lower(),
            ),
        )
        handled = False
        for path in relevant:
            name = path.name.lower()
            if path.suffix.lower() == ".json":
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue

                if self._looks_like_atlas_data(data):
                    stats["files_examined"].append(path.name)
                    self._import_atlas_data(
                        data,
                        dry_run=dry_run,
                        stats=stats,
                        project_slug=project_slug,
                    )
                    handled = True
                    continue

                if name == "conversations.json" or source == "chatgpt":
                    if isinstance(data, list) and any(
                        isinstance(item, dict) and "mapping" in item
                        for item in data[:10]
                    ):
                        stats["files_examined"].append(path.name)
                        self._import_chatgpt_conversations(
                            data,
                            dry_run=dry_run,
                            stats=stats,
                            project_slug=project_slug,
                        )
                        handled = True
                        continue

                if "memory" in name or source in {"memory", "memories"}:
                    stats["files_examined"].append(path.name)
                    self._import_memories(
                        data,
                        dry_run=dry_run,
                        stats=stats,
                        source=source,
                    )
                    handled = True
                    continue

                if self._looks_like_generic_conversations(data):
                    stats["files_examined"].append(path.name)
                    self._import_generic_conversations(
                        data,
                        dry_run=dry_run,
                        stats=stats,
                        source=source,
                        project_slug=project_slug,
                    )
                    handled = True
            elif path.suffix.lower() in {".md", ".txt"} and source in {
                "memory",
                "memories",
            }:
                stats["files_examined"].append(path.name)
                content = path.read_text(encoding="utf-8")
                if not dry_run:
                    self.database.upsert_memory(
                        namespace="imported",
                        kind="document",
                        key=path.stem[:200],
                        content=content,
                        importance=5,
                        metadata={"source": source, "filename": path.name},
                    )
                stats["memories_imported"] += 1
                handled = True
        if not handled:
            raise ImportFormatError(
                "No supported portable Atlas data, ChatGPT conversations, or explicit "
                "memory files were found. A ChatGPT export should contain "
                "conversations.json."
            )

    @staticmethod
    def _looks_like_atlas_data(data: Any) -> bool:
        return isinstance(data, dict) and (
            data.get("format") == "atlas-core-portable-data"
            or (
                isinstance(data.get("conversations"), list)
                and isinstance(data.get("memories"), list)
                and isinstance(data.get("projects"), list)
            )
        )

    @staticmethod
    def _looks_like_generic_conversations(data: Any) -> bool:
        items = data.get("conversations") if isinstance(data, dict) else data
        return isinstance(items, list) and bool(items) and any(
            isinstance(item, dict) and isinstance(item.get("messages"), list)
            for item in items[:10]
        )

    def _import_atlas_data(
        self,
        data: dict[str, Any],
        *,
        dry_run: bool,
        stats: dict[str, Any],
        project_slug: str | None,
    ) -> None:
        for project in data.get("projects") or []:
            if not isinstance(project, dict):
                continue
            slug = str(project.get("slug") or "").strip()
            name = str(project.get("name") or "").strip()
            if not slug or not name:
                continue
            if not dry_run:
                self.database.upsert_project(
                    slug=slug,
                    name=name,
                    status=str(project.get("status") or "active"),
                    summary=str(project.get("summary") or ""),
                    next_action=str(project.get("next_action") or ""),
                    metadata=dict(project.get("metadata") or {}),
                )
            stats["projects_imported"] += 1

        for memory in data.get("memories") or []:
            if not isinstance(memory, dict):
                continue
            content = str(memory.get("content") or "").strip()
            key = str(memory.get("key") or "").strip()
            if not content or not key:
                continue
            if not dry_run:
                self.database.upsert_memory(
                    namespace=str(memory.get("namespace") or "imported"),
                    kind=str(memory.get("kind") or "note"),
                    key=key[:200],
                    content=content,
                    importance=max(1, min(int(memory.get("importance") or 5), 10)),
                    metadata=dict(memory.get("metadata") or {}),
                )
            stats["memories_imported"] += 1

        self._import_generic_conversations(
            {"conversations": data.get("conversations") or []},
            dry_run=dry_run,
            stats=stats,
            source="atlas",
            project_slug=project_slug,
        )

    def _import_chatgpt_conversations(
        self,
        conversations: list[Any],
        *,
        dry_run: bool,
        stats: dict[str, Any],
        project_slug: str | None,
    ) -> None:
        for raw in conversations:
            if not isinstance(raw, dict):
                continue
            stats["conversations_seen"] += 1
            external_id = str(raw.get("id") or raw.get("conversation_id") or "")
            if not external_id:
                external_id = f"chatgpt-{stats['conversations_seen']}"
            existing = self.database.find_conversation_by_external(
                "chatgpt", external_id
            )
            messages = self._chatgpt_messages(raw)
            if dry_run:
                stats["conversations_imported"] += 1 if not existing else 0
                stats["conversations_skipped"] += 1 if existing else 0
                stats["messages_imported"] += len(messages) if not existing else 0
                continue
            if existing:
                conversation = existing
                stats["conversations_skipped"] += 1
                if project_slug:
                    conversation = self.database.update_conversation(
                        conversation["id"], project_slug=project_slug
                    )
            else:
                conversation = self.database.create_conversation(
                    title=str(
                        raw.get("title") or "Imported ChatGPT conversation"
                    )[:500],
                    project_slug=project_slug,
                    agent_slug="atlas",
                    external_source="chatgpt",
                    external_id=external_id,
                    created_at=_iso_time(raw.get("create_time")),
                    updated_at=_iso_time(raw.get("update_time")),
                )
                stats["conversations_imported"] += 1
            for item in messages:
                external_message_id = item.get("external_id")
                if external_message_id and self.database.message_exists_external(
                    conversation["id"], external_message_id
                ):
                    continue
                self.database.add_message(
                    conversation["id"],
                    item["role"],
                    item["content"],
                    metadata=item.get("metadata"),
                    external_id=external_message_id,
                    created_at=item.get("created_at"),
                )
                stats["messages_imported"] += 1

    @staticmethod
    def _chatgpt_messages(raw: dict[str, Any]) -> list[dict[str, Any]]:
        mapping = raw.get("mapping") or {}
        if not isinstance(mapping, dict):
            return []
        ordered_nodes: list[dict[str, Any]] = []
        current = raw.get("current_node")
        visited: set[str] = set()
        while isinstance(current, str) and current in mapping and current not in visited:
            visited.add(current)
            node = mapping[current]
            if isinstance(node, dict):
                ordered_nodes.append(node)
                current = node.get("parent")
            else:
                break
        if ordered_nodes:
            ordered_nodes.reverse()
        else:
            ordered_nodes = [node for node in mapping.values() if isinstance(node, dict)]
            ordered_nodes.sort(
                key=lambda node: ((node.get("message") or {}).get("create_time") or 0)
            )
        output: list[dict[str, Any]] = []
        for node in ordered_nodes:
            message = node.get("message")
            if not isinstance(message, dict):
                continue
            metadata = message.get("metadata") or {}
            if metadata.get("is_visually_hidden_from_conversation"):
                continue
            author = message.get("author") or {}
            role = str(author.get("role") or "user")
            if role not in {"user", "assistant", "system", "tool"}:
                continue
            text = _content_text(message.get("content"))
            if not text and role != "tool":
                continue
            output.append(
                {
                    "external_id": str(message.get("id") or node.get("id") or "")
                    or None,
                    "role": role,
                    "content": text,
                    "created_at": _iso_time(message.get("create_time")),
                    "metadata": {
                        "imported_from": "chatgpt",
                        "original_model": metadata.get("model_slug"),
                        "content_type": (
                            (message.get("content") or {}).get("content_type")
                            if isinstance(message.get("content"), dict)
                            else None
                        ),
                    },
                }
            )
        return output

    def _import_generic_conversations(
        self,
        data: Any,
        *,
        dry_run: bool,
        stats: dict[str, Any],
        source: str,
        project_slug: str | None,
    ) -> None:
        items = data.get("conversations") if isinstance(data, dict) else data
        for index, item in enumerate(items or []):
            if not isinstance(item, dict):
                continue
            stats["conversations_seen"] += 1
            external_id = str(item.get("external_id") or item.get("id") or f"generic-{index}")
            source_name = source if source != "auto" else "generic"
            existing = self.database.find_conversation_by_external(
                source_name, external_id
            )
            messages = [m for m in item.get("messages") or [] if isinstance(m, dict)]
            if dry_run:
                stats["conversations_imported"] += 1 if not existing else 0
                stats["conversations_skipped"] += 1 if existing else 0
                stats["messages_imported"] += len(messages) if not existing else 0
                continue

            chosen_project = project_slug
            if chosen_project is None:
                raw_project = item.get("project_slug")
                chosen_project = str(raw_project) if raw_project else None
            if existing:
                conversation = existing
                stats["conversations_skipped"] += 1
                if chosen_project:
                    conversation = self.database.update_conversation(
                        conversation["id"], project_slug=chosen_project
                    )
            else:
                conversation = self.database.create_conversation(
                    title=str(item.get("title") or "Imported conversation")[:500],
                    project_slug=chosen_project,
                    agent_slug=str(item.get("agent_slug") or "atlas"),
                    external_source=source_name,
                    external_id=external_id,
                    created_at=_iso_time(item.get("created_at")),
                    updated_at=_iso_time(item.get("updated_at")),
                )
                stats["conversations_imported"] += 1
            for message_index, message in enumerate(messages):
                role = str(message.get("role") or "user")
                if role not in {"user", "assistant", "system", "tool"}:
                    continue
                message_external_id = str(
                    message.get("external_id")
                    or message.get("id")
                    or f"{external_id}-{message_index}"
                )
                if self.database.message_exists_external(
                    conversation["id"], message_external_id
                ):
                    continue
                self.database.add_message(
                    conversation["id"],
                    role,
                    _content_text(message.get("content")),
                    provider=(str(message.get("provider")) if message.get("provider") else None),
                    model=(str(message.get("model")) if message.get("model") else None),
                    external_id=message_external_id,
                    created_at=_iso_time(message.get("created_at")),
                    metadata={
                        **dict(message.get("metadata") or {}),
                        "imported_from": source_name,
                    },
                )
                stats["messages_imported"] += 1

    def _import_memories(
        self,
        data: Any,
        *,
        dry_run: bool,
        stats: dict[str, Any],
        source: str,
    ) -> None:
        if isinstance(data, dict):
            items = data.get("memories") or data.get("memory") or data.get("items")
            if items is None:
                items = [data]
        else:
            items = data
        if not isinstance(items, list):
            raise ImportFormatError("Memory JSON must contain a list or a memories list")
        for index, item in enumerate(items):
            if isinstance(item, str):
                key, content = f"imported-memory-{index + 1}", item
                namespace, kind, importance = "imported", "imported", 5
                metadata: dict[str, Any] = {}
            elif isinstance(item, dict):
                content = next(
                    (
                        str(item[key])
                        for key in ("content", "text", "value", "memory")
                        if isinstance(item.get(key), str)
                    ),
                    "",
                )
                key = next(
                    (
                        str(item[name])
                        for name in ("key", "title", "name")
                        if isinstance(item.get(name), str)
                    ),
                    f"imported-memory-{index + 1}",
                )
                namespace = str(item.get("namespace") or "imported")
                kind = str(item.get("kind") or "imported")
                importance = max(1, min(int(item.get("importance") or 5), 10))
                metadata = {"original": item}
            else:
                continue
            if not content.strip():
                continue
            if not dry_run:
                self.database.upsert_memory(
                    namespace=namespace,
                    kind=kind,
                    key=key[:200],
                    content=content,
                    importance=importance,
                    metadata={"source": source, **metadata},
                )
            stats["memories_imported"] += 1
