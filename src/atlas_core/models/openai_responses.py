from __future__ import annotations

import json
import os
import uuid
from typing import Any

import httpx

from atlas_core.errors import ProviderError
from atlas_core.models.base import (
    ChatMessage,
    ModelProvider,
    ModelResponse,
    ToolCall,
    ToolDefinition,
)


class OpenAIResponsesProvider(ModelProvider):
    """OpenAI Responses API adapter with portable function-tool state."""

    def __init__(
        self,
        *,
        name: str,
        model: str,
        local: bool,
        enabled: bool,
        base_url: str,
        api_key_env: str | None,
        timeout_seconds: float,
    ) -> None:
        super().__init__(
            name=name,
            model=model,
            local=local,
            enabled=enabled,
            api_key_env=api_key_env,
        )
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    def _api_key(self) -> str | None:
        return os.getenv(self.api_key_env) if self.api_key_env else None

    def _headers(self) -> dict[str, str]:
        key = self._api_key()
        headers = {"Content-Type": "application/json"}
        if key:
            headers["Authorization"] = f"Bearer {key}"
        return headers

    @staticmethod
    def _input(messages: list[ChatMessage]) -> tuple[str, list[dict[str, Any]]]:
        instructions = "\n\n".join(
            message.content for message in messages if message.role == "system" and message.content
        )
        items: list[dict[str, Any]] = []
        for message in messages:
            if message.role == "system":
                continue
            if message.role == "tool":
                items.append(
                    {
                        "type": "function_call_output",
                        "call_id": message.tool_call_id,
                        "output": message.content,
                    }
                )
                continue
            if message.content:
                items.append({"role": message.role, "content": message.content})
            if message.role == "assistant":
                for call in message.tool_calls:
                    items.append(
                        {
                            "type": "function_call",
                            "call_id": call.id,
                            "name": call.name,
                            "arguments": json.dumps(
                                call.arguments,
                                ensure_ascii=False,
                                separators=(",", ":"),
                            ),
                        }
                    )
        return instructions, items

    async def generate(
        self,
        messages: list[ChatMessage],
        *,
        tools: list[ToolDefinition] | None = None,
        model: str | None = None,
        temperature: float = 0.2,
        max_tokens: int | None = None,
    ) -> ModelResponse:
        del temperature  # Current reasoning models may not accept sampling controls.
        if not self.enabled:
            raise ProviderError(f"Provider '{self.name}' is disabled")
        if not self._api_key():
            raise ProviderError(
                f"Provider '{self.name}' requires environment variable {self.api_key_env}"
            )
        selected_model = model or self.model
        instructions, input_items = self._input(messages)
        payload: dict[str, Any] = {
            "model": selected_model,
            "input": input_items,
            "store": False,
        }
        if instructions:
            payload["instructions"] = instructions
        if tools:
            payload["tools"] = [tool.for_openai_responses() for tool in tools]
            payload["tool_choice"] = "auto"
            payload["parallel_tool_calls"] = False
        if max_tokens is not None:
            payload["max_output_tokens"] = max_tokens

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.post(
                    f"{self.base_url}/responses",
                    headers=self._headers(),
                    json=payload,
                )
                response.raise_for_status()
                data = response.json()
        except httpx.HTTPStatusError as exc:
            raise ProviderError(
                f"Provider '{self.name}' returned HTTP {exc.response.status_code}: "
                f"{exc.response.text[:2_000]}"
            ) from exc
        except (httpx.HTTPError, ValueError) as exc:
            raise ProviderError(f"Provider '{self.name}' request failed: {exc}") from exc

        text_parts: list[str] = []
        calls: list[ToolCall] = []
        for item in data.get("output") or []:
            if not isinstance(item, dict):
                continue
            item_type = item.get("type")
            if item_type == "function_call":
                raw_arguments = item.get("arguments") or "{}"
                try:
                    arguments = json.loads(raw_arguments) if isinstance(raw_arguments, str) else dict(raw_arguments)
                except (json.JSONDecodeError, TypeError, ValueError):
                    arguments = {"_raw": str(raw_arguments)}
                calls.append(
                    ToolCall(
                        id=str(item.get("call_id") or item.get("id") or f"call_{uuid.uuid4().hex}"),
                        name=str(item.get("name") or ""),
                        arguments=arguments,
                    )
                )
            elif item_type == "message":
                for block in item.get("content") or []:
                    if isinstance(block, dict) and block.get("type") in {"output_text", "text"}:
                        text_parts.append(str(block.get("text") or ""))
        content = "".join(text_parts).strip()
        if not content and isinstance(data.get("output_text"), str):
            content = data["output_text"].strip()
        usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
        return ModelResponse(
            content=content,
            provider=self.name,
            model=str(data.get("model") or selected_model),
            tool_calls=calls,
            usage=usage,
            stop_reason=str(data.get("status") or "") or None,
            raw=data,
        )

    async def health(self) -> dict[str, Any]:
        key = self._api_key()
        base = {
            "provider": self.name,
            "kind": "openai_responses",
            "base_url": self.base_url,
            "model": self.model,
            "local": self.local,
            "enabled": self.enabled,
        }
        if not self.enabled:
            return {**base, "ok": False, "configured": False, "error": "Provider is disabled"}
        if not key:
            return {
                **base,
                "ok": False,
                "configured": False,
                "error": f"Missing {self.api_key_env}",
            }
        try:
            async with httpx.AsyncClient(timeout=min(self.timeout_seconds, 10.0)) as client:
                response = await client.get(f"{self.base_url}/models", headers=self._headers())
                response.raise_for_status()
            return {**base, "ok": True, "configured": True}
        except Exception as exc:
            return {**base, "ok": False, "configured": True, "error": str(exc)}
