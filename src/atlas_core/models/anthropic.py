from __future__ import annotations

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


class AnthropicProvider(ModelProvider):
    """Anthropic Messages API adapter with native tool-use conversion."""

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
        headers = {
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
        }
        if self._api_key():
            headers["x-api-key"] = self._api_key() or ""
        return headers

    @staticmethod
    def _messages(messages: list[ChatMessage]) -> tuple[str, list[dict[str, Any]]]:
        system = "\n\n".join(
            message.content for message in messages if message.role == "system" and message.content
        )
        converted: list[dict[str, Any]] = []
        for message in messages:
            if message.role == "system":
                continue
            if message.role == "tool":
                converted.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": message.tool_call_id,
                                "content": message.content,
                            }
                        ],
                    }
                )
                continue
            blocks: list[dict[str, Any]] = []
            if message.content:
                blocks.append({"type": "text", "text": message.content})
            if message.role == "assistant":
                blocks.extend(
                    {
                        "type": "tool_use",
                        "id": call.id,
                        "name": call.name,
                        "input": call.arguments,
                    }
                    for call in message.tool_calls
                )
            converted.append({"role": message.role, "content": blocks or ""})
        return system, converted

    async def generate(
        self,
        messages: list[ChatMessage],
        *,
        tools: list[ToolDefinition] | None = None,
        model: str | None = None,
        temperature: float = 0.2,
        max_tokens: int | None = None,
    ) -> ModelResponse:
        del temperature  # Sonnet 5 rejects non-default sampling parameters.
        if not self.enabled:
            raise ProviderError(f"Provider '{self.name}' is disabled")
        if not self._api_key():
            raise ProviderError(
                f"Provider '{self.name}' requires environment variable {self.api_key_env}"
            )
        selected_model = model or self.model
        system, converted = self._messages(messages)
        payload: dict[str, Any] = {
            "model": selected_model,
            "max_tokens": max_tokens or 8_192,
            "messages": converted,
        }
        if system:
            payload["system"] = system
        if tools:
            payload["tools"] = [tool.for_anthropic() for tool in tools]
            payload["tool_choice"] = {"type": "auto"}

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.post(
                    f"{self.base_url}/v1/messages",
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
        for block in data.get("content") or []:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "text":
                text_parts.append(str(block.get("text") or ""))
            elif block.get("type") == "tool_use":
                raw_input = block.get("input")
                calls.append(
                    ToolCall(
                        id=str(block.get("id") or f"call_{uuid.uuid4().hex}"),
                        name=str(block.get("name") or ""),
                        arguments=dict(raw_input) if isinstance(raw_input, dict) else {"_raw": raw_input},
                    )
                )
        usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
        return ModelResponse(
            content="".join(text_parts).strip(),
            provider=self.name,
            model=str(data.get("model") or selected_model),
            tool_calls=calls,
            usage=usage,
            stop_reason=str(data.get("stop_reason") or "") or None,
            raw=data,
        )

    async def health(self) -> dict[str, Any]:
        base = {
            "provider": self.name,
            "kind": "anthropic",
            "base_url": self.base_url,
            "model": self.model,
            "local": self.local,
            "enabled": self.enabled,
        }
        if not self.enabled:
            return {**base, "ok": False, "configured": False, "error": "Provider is disabled"}
        if not self._api_key():
            return {
                **base,
                "ok": False,
                "configured": False,
                "error": f"Missing {self.api_key_env}",
            }
        try:
            async with httpx.AsyncClient(timeout=min(self.timeout_seconds, 10.0)) as client:
                response = await client.get(
                    f"{self.base_url}/v1/models?limit=1", headers=self._headers()
                )
                response.raise_for_status()
            return {**base, "ok": True, "configured": True}
        except Exception as exc:
            return {**base, "ok": False, "configured": True, "error": str(exc)}
