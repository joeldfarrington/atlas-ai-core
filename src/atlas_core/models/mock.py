from __future__ import annotations

import json
import re
import uuid
from typing import Any

from atlas_core.models.base import (
    ChatMessage,
    ModelProvider,
    ModelResponse,
    ToolCall,
    ToolDefinition,
)

_TOOL_PATTERN = re.compile(r"^TOOL\s+([A-Za-z0-9_]+)\s*(\{.*\})?$", re.DOTALL)


class MockProvider(ModelProvider):
    """Deterministic offline provider used for diagnostics and integration tests."""

    async def generate(
        self,
        messages: list[ChatMessage],
        *,
        tools: list[ToolDefinition] | None = None,
        model: str | None = None,
        temperature: float = 0.2,
        max_tokens: int | None = None,
    ) -> ModelResponse:
        del temperature, max_tokens
        last = messages[-1] if messages else ChatMessage(role="user", content="")
        if last.role == "tool":
            content = f"Tool result received and verified: {last.content}"
            return ModelResponse(
                content=content,
                provider=self.name,
                model=model or self.model,
                usage={"input_messages": len(messages)},
            )
        latest_user = next(
            (message.content for message in reversed(messages) if message.role == "user"),
            "",
        )
        match = _TOOL_PATTERN.match(latest_user.strip())
        if match and tools:
            name = match.group(1)
            available = {tool.name for tool in tools}
            if name in available:
                raw = match.group(2) or "{}"
                try:
                    arguments = json.loads(raw)
                except json.JSONDecodeError:
                    arguments = {"_raw": raw}
                return ModelResponse(
                    content="",
                    provider=self.name,
                    model=model or self.model,
                    tool_calls=[
                        ToolCall(
                            id=f"call_{uuid.uuid4().hex}",
                            name=name,
                            arguments=arguments,
                        )
                    ],
                    stop_reason="tool_calls",
                    usage={"input_messages": len(messages)},
                )
        return ModelResponse(
            content=(
                "Atlas Core mock provider is running. "
                f"The latest operator message was: {latest_user}"
            ),
            provider=self.name,
            model=model or self.model,
            usage={"input_messages": len(messages)},
        )

    async def health(self) -> dict[str, Any]:
        return {
            "ok": True,
            "configured": True,
            "provider": self.name,
            "kind": "mock",
            "model": self.model,
            "local": self.local,
            "enabled": self.enabled,
        }
