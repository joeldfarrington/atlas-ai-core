from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Literal

Role = Literal["system", "user", "assistant", "tool"]


@dataclass(slots=True)
class ToolDefinition:
    name: str
    description: str
    parameters: dict[str, Any]
    tool: str
    action: str

    def for_openai_chat(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }

    def for_openai_responses(self) -> dict[str, Any]:
        return {
            "type": "function",
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
            "strict": False,
        }

    def for_anthropic(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.parameters,
        }


@dataclass(slots=True)
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "arguments": self.arguments}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ToolCall":
        return cls(
            id=str(value.get("id") or ""),
            name=str(value.get("name") or ""),
            arguments=dict(value.get("arguments") or {}),
        )


@dataclass(slots=True)
class ChatMessage:
    role: Role
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_call_id: str | None = None
    name: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "content": self.content,
            "tool_calls": [call.as_dict() for call in self.tool_calls],
            "tool_call_id": self.tool_call_id,
            "name": self.name,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ChatMessage":
        role = str(value.get("role") or "user")
        if role not in {"system", "user", "assistant", "tool"}:
            role = "user"
        return cls(
            role=role,  # type: ignore[arg-type]
            content=str(value.get("content") or ""),
            tool_calls=[ToolCall.from_dict(item) for item in value.get("tool_calls") or []],
            tool_call_id=value.get("tool_call_id"),
            name=value.get("name"),
        )

    def for_openai_chat(self) -> dict[str, Any]:
        result: dict[str, Any] = {"role": self.role, "content": self.content}
        if self.role == "assistant" and self.tool_calls:
            result["tool_calls"] = [
                {
                    "id": call.id,
                    "type": "function",
                    "function": {
                        "name": call.name,
                        "arguments": _json_string(call.arguments),
                    },
                }
                for call in self.tool_calls
            ]
        if self.role == "tool":
            result["tool_call_id"] = self.tool_call_id
            if self.name:
                result["name"] = self.name
        return result


@dataclass(slots=True)
class ModelResponse:
    content: str
    provider: str
    model: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    usage: dict[str, Any] = field(default_factory=dict)
    stop_reason: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


class ModelProvider(ABC):
    def __init__(
        self,
        *,
        name: str,
        model: str,
        local: bool,
        enabled: bool,
        api_key_env: str | None = None,
    ) -> None:
        self.name = name
        self.model = model
        self.local = local
        self.enabled = enabled
        self.api_key_env = api_key_env

    @abstractmethod
    async def generate(
        self,
        messages: list[ChatMessage],
        *,
        tools: list[ToolDefinition] | None = None,
        model: str | None = None,
        temperature: float = 0.2,
        max_tokens: int | None = None,
    ) -> ModelResponse:
        raise NotImplementedError

    @abstractmethod
    async def health(self) -> dict[str, Any]:
        raise NotImplementedError


def _json_string(value: Any) -> str:
    import json

    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
