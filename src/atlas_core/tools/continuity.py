"""Read-only growth context, scoped to owner-registered development projects."""
from __future__ import annotations

import re
import uuid
from typing import Any, Iterable

from atlas_core.continuity import ProjectContinuity, _evidence
from atlas_core.errors import ToolError
from atlas_core.memory.database import Database
from atlas_core.tools.base import Tool


class ContinuityTool(Tool):
    name = "continuity"
    ACTIONS = frozenset({"project_context", "reviewed_lessons", "recent_experience", "task_status"})

    def __init__(self, database: Database, *, allowed_projects: Iterable[str]) -> None:
        self.continuity = ProjectContinuity(database)
        self.allowed_projects = frozenset(allowed_projects)
        if any(not self._slug(slug) for slug in self.allowed_projects):
            raise ValueError("Invalid registered project slug")

    @staticmethod
    def _slug(value: Any) -> bool:
        return isinstance(value, str) and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?", value) is not None

    @staticmethod
    def _revision(value: Any) -> str | None:
        return value if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) else None

    @staticmethod
    def _bounded(value: Any, limit: int) -> str:
        if not isinstance(value, str):
            raise ValueError("Invalid stored text")
        return value[:limit]

    def execute(self, action: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if action not in self.ACTIONS or not isinstance(arguments, dict):
            raise ToolError("Unsupported continuity action or arguments")
        allowed = {"project_slug"}
        required = {"project_slug"}
        if action in {"reviewed_lessons", "recent_experience"}:
            allowed.add("limit")
        if action == "task_status":
            allowed.add("task_id")
            required.add("task_id")
        if not required.issubset(arguments) or set(arguments) - allowed:
            raise ToolError("Invalid continuity argument fields")
        slug = arguments["project_slug"]
        if not self._slug(slug) or slug not in self.allowed_projects:
            raise ToolError("Project is not registered for continuity reads")
        limit = arguments.get("limit", 10)
        if type(limit) is not int or not 1 <= limit <= 20:
            raise ToolError("Lesson limit must be an integer from 1 through 20")
        try:
            if action == "project_context":
                project = self.continuity._project(slug)
                bounds = {"slug": 64, "name": 200, "status": 100, "summary": 3200, "next_action": 3200, "updated_at": 64}
                return {"project": {key: self._bounded(project[key], bound) for key, bound in bounds.items()},
                    "recent_experience": self.continuity.experiences(slug, limit=5),
                    "truncated": any(len(project[key]) > bound for key, bound in bounds.items()),
                    "source_revision": self._revision(project["metadata"].get("source_revision")),
                    "read_only": True, "execution_authority": False}
            if action == "recent_experience":
                return {"project": slug, "experiences": self.continuity.experiences(slug, limit=limit),
                    "read_only": True, "execution_authority": False}
            if action == "reviewed_lessons":
                rows = self.continuity._lessons(slug, approved_only=True)
                lessons = []
                for row in rows[:limit]:
                    metadata = row["metadata"]
                    evidence = metadata.get("evidence", {})
                    if not _evidence(evidence):
                        raise ValueError("Invalid reviewed lesson evidence")
                    lessons.append({"id": row["id"], "key": self._bounded(row["key"], 160), "content": self._bounded(row["content"], 3200),
                        "truncated": len(row["key"]) > 160 or len(row["content"]) > 3200,
                        "review_state": metadata["review_state"],
                        "source_revision": self._revision(metadata.get("source_revision")),
                        "evidence": {key: evidence[key] for key in
                            ("origin", "passed", "artifact_sha256", "check") if key in evidence}})
                return {"project": slug, "lessons": lessons, "has_more": len(rows) > limit,
                    "read_only": True, "execution_authority": False}
            task_id = arguments["task_id"]
            if not isinstance(task_id, str) or str(uuid.UUID(task_id)) != task_id:
                raise ValueError("Invalid task ID")
            view = self.continuity.view(slug, task_id)
            return {"task": {key: view[key] for key in
                ("task_id", "project", "state", "stale", "last_activity", "age_seconds",
                 "attempts", "cleanup_required", "evidence_origin", "next_action", "review_state")},
                "read_only": True, "execution_authority": False}
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise ToolError("Continuity record is unavailable or invalid") from exc

    def audit_arguments(self, action: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return {"read_only": True}

    def audit_result(self, action: str, result: dict[str, Any]) -> dict[str, Any]:
        return {"read_only": True}

    def audit_error(self, action: str, error: Exception) -> str:
        return "Continuity read failed"

    def describe(self) -> dict[str, Any]:
        project = {"type": "string", "pattern": "^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$"}
        actions = {}
        descriptions = {
            "project_context": "Read selected status and next action for one registered project.",
            "reviewed_lessons": "Read bounded lessons with stored owner-review labels, not independent verification; imported unverified knowledge is excluded.",
            "recent_experience": "Recall automatically recorded task outcomes and evidence; no lesson review is required. These observations do not authorize actions or prove general conclusions.",
            "task_status": "Read recorded task progress and stale or cleanup state; this does not execute work.",
        }
        for action, description in descriptions.items():
            properties = {"project_slug": dict(project)}
            required = ["project_slug"]
            if action in {"reviewed_lessons", "recent_experience"}:
                properties["limit"] = {"type": "integer", "minimum": 1, "maximum": 20, "default": 10}
            if action == "task_status":
                properties["task_id"] = {"type": "string", "format": "uuid", "minLength": 36, "maxLength": 36}
                required.append("task_id")
            actions[action] = {"description": description, "parameters": {"type": "object",
                "properties": properties, "required": required, "additionalProperties": False}}
        return {"name": self.name, "description": "Read evidence-linked project knowledge without changing authority.",
            "actions": actions}
