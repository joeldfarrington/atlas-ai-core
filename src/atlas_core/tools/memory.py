from __future__ import annotations

from typing import Any

from atlas_core.errors import ToolError
from atlas_core.memory.database import Database
from atlas_core.tools.base import Tool


class MemoryTool(Tool):
    name = "memory"

    def __init__(self, database: Database) -> None:
        self.database = database

    def execute(self, action: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if action == "list":
            return {
                "memories": self.database.list_memories(
                    namespace=arguments.get("namespace"),
                    limit=min(max(int(arguments.get("limit", 50)), 1), 200),
                    exclude_research=True,
                )
            }
        if action == "get":
            memory = self.database.get_memory(int(arguments.get("id")))
            if memory is None or memory["namespace"].startswith("research:"):
                raise ToolError(f"Memory not found: {arguments.get('id')}")
            return memory
        if action == "search":
            query = arguments.get("query")
            if not isinstance(query, str) or not query.strip():
                raise ToolError("query must be a non-empty string")
            return {
                "memories": self.database.search_memories(
                    query,
                    namespace=arguments.get("namespace"),
                    limit=min(max(int(arguments.get("limit", 8)), 1), 50),
                    exclude_research=True,
                )
            }
        if action == "remember":
            namespace = str(arguments.get("namespace") or "global")
            if namespace.startswith("research:"):
                raise ToolError("Research source receipts require the project-scoped research tool")
            required = ("key", "content")
            if any(not isinstance(arguments.get(item), str) or not arguments[item].strip() for item in required):
                raise ToolError("key and content must be non-empty strings")
            return self.database.upsert_memory(
                namespace=namespace,
                kind=str(arguments.get("kind") or "note"),
                key=str(arguments["key"]),
                content=str(arguments["content"]),
                importance=min(max(int(arguments.get("importance", 5)), 1), 10),
                metadata=dict(arguments.get("metadata") or {}),
            )
        if action == "forget":
            memory_id = int(arguments.get("id"))
            if not self.database.delete_memory(memory_id, exclude_research=True):
                raise ToolError(f"Memory not found: {memory_id}")
            return {"deleted": True, "id": memory_id}
        raise ToolError(f"Unsupported memory action: {action}")

    def describe(self) -> dict[str, Any]:
        namespace = {"type": "string", "description": "Memory namespace, such as global or project:slug."}
        return {
            "name": self.name,
            "description": "Search and maintain explicit, inspectable Atlas memories.",
            "actions": {
                "list": {
                    "description": "List stored memories.",
                    "parameters": {"type": "object", "properties": {"namespace": namespace, "limit": {"type": "integer", "minimum": 1, "maximum": 200}}, "additionalProperties": False},
                },
                "get": {
                    "description": "Get one memory by numeric ID.",
                    "parameters": {"type": "object", "properties": {"id": {"type": "integer"}}, "required": ["id"], "additionalProperties": False},
                },
                "search": {
                    "description": "Search memory content and keys.",
                    "parameters": {
                        "type": "object",
                        "properties": {"query": {"type": "string"}, "namespace": namespace, "limit": {"type": "integer", "minimum": 1, "maximum": 50}},
                        "required": ["query"],
                        "additionalProperties": False,
                    },
                },
                "remember": {
                    "description": "Create or replace an inspectable, audit-recorded memory.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "namespace": namespace,
                            "kind": {"type": "string"},
                            "key": {"type": "string"},
                            "content": {"type": "string"},
                            "importance": {"type": "integer", "minimum": 1, "maximum": 10},
                            "metadata": {"type": "object"},
                        },
                        "required": ["key", "content"],
                        "additionalProperties": False,
                    },
                },
                "forget": {
                    "description": "Delete a memory by ID with an audit record.",
                    "parameters": {"type": "object", "properties": {"id": {"type": "integer"}}, "required": ["id"], "additionalProperties": False},
                },
            },
        }
