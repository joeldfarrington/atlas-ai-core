from __future__ import annotations

from typing import Any

from atlas_core.errors import ToolError
from atlas_core.memory.database import Database
from atlas_core.tools.base import Tool


class ProjectsTool(Tool):
    name = "projects"

    def __init__(self, database: Database) -> None:
        self.database = database

    def execute(self, action: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if action == "list":
            return {"projects": self.database.list_projects(limit=min(max(int(arguments.get("limit", 100)), 1), 200))}
        if action == "get":
            slug = str(arguments.get("slug") or "")
            project = self.database.get_project(slug)
            if project is None:
                raise ToolError(f"Project not found: {slug}")
            return project
        if action == "upsert":
            slug = str(arguments.get("slug") or "")
            name = str(arguments.get("name") or "")
            if not slug or not name:
                raise ToolError("slug and name are required")
            return self.database.upsert_project(
                slug=slug,
                name=name,
                status=str(arguments.get("status") or "active"),
                summary=str(arguments.get("summary") or ""),
                next_action=str(arguments.get("next_action") or ""),
                metadata=dict(arguments.get("metadata") or {}),
            )
        if action == "delete":
            slug = str(arguments.get("slug") or "")
            if not self.database.delete_project(slug):
                raise ToolError(f"Project not found: {slug}")
            return {"deleted": True, "slug": slug}
        raise ToolError(f"Unsupported projects action: {action}")

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": "Read and maintain durable project status records.",
            "actions": {
                "list": {
                    "description": "List projects.",
                    "parameters": {"type": "object", "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 200}}, "additionalProperties": False},
                },
                "get": {
                    "description": "Get a project by slug.",
                    "parameters": {"type": "object", "properties": {"slug": {"type": "string"}}, "required": ["slug"], "additionalProperties": False},
                },
                "upsert": {
                    "description": "Create or update inspectable project state.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "slug": {"type": "string", "pattern": "^[a-z0-9][a-z0-9-]{0,99}$"},
                            "name": {"type": "string"},
                            "status": {"type": "string"},
                            "summary": {"type": "string"},
                            "next_action": {"type": "string"},
                            "metadata": {"type": "object"},
                        },
                        "required": ["slug", "name"],
                        "additionalProperties": False,
                    },
                },
                "delete": {
                    "description": "Delete a project status record with an audit record.",
                    "parameters": {"type": "object", "properties": {"slug": {"type": "string"}}, "required": ["slug"], "additionalProperties": False},
                },
            },
        }
