from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from atlas_core.errors import ToolError
from atlas_core.models import ChatMessage, ToolCall
from atlas_core.models.anthropic import AnthropicProvider
from atlas_core.models.openai_compatible import OpenAICompatibleProvider
from atlas_core.models.openai_responses import OpenAIResponsesProvider
from atlas_core.services import AtlasServices
from atlas_core.tools.web import WebFetchTool


def test_identity_and_permission_updates_are_versioned(services: AtlasServices) -> None:
    services.identity.update("atlas.md", "# Atlas\n\nUpdated identity.")
    identity_versions = list((services.config.app.identity_dir / ".versions").glob("atlas.md.*.bak"))
    assert identity_versions

    original = services.permissions.raw()
    services.permissions.update(original.replace("modify: ask", "modify: deny"))
    policy_versions = list((services.config.app.permissions_file.parent / ".versions").glob("permissions.yaml.*.bak"))
    assert policy_versions
    assert services.permissions.decision("filesystem", "modify").value == "deny"


def test_web_fetch_blocks_loopback_and_non_http() -> None:
    tool = WebFetchTool()
    with pytest.raises(ToolError):
        tool.fetch({"url": "http://127.0.0.1:8742"})
    with pytest.raises(ToolError):
        tool.fetch({"url": "file:///etc/passwd"})


def test_provider_message_converters_preserve_tool_state(monkeypatch: pytest.MonkeyPatch) -> None:
    messages = [
        ChatMessage(role="system", content="System rules"),
        ChatMessage(role="user", content="Use a tool"),
        ChatMessage(
            role="assistant",
            content="",
            tool_calls=[ToolCall(id="call-1", name="filesystem__read", arguments={"path": "a.txt"})],
        ),
        ChatMessage(role="tool", content='{"content":"hello"}', tool_call_id="call-1", name="filesystem__read"),
    ]

    instructions, response_items = OpenAIResponsesProvider._input(messages)
    assert instructions == "System rules"
    assert any(item.get("type") == "function_call" for item in response_items)
    assert any(item.get("type") == "function_call_output" for item in response_items)

    system, anthropic_messages = AnthropicProvider._messages(messages)
    assert system == "System rules"
    assistant = next(item for item in anthropic_messages if item["role"] == "assistant")
    assert any(block.get("type") == "tool_use" for block in assistant["content"])
    tool_result = anthropic_messages[-1]
    assert tool_result["content"][0]["type"] == "tool_result"


def test_openai_compatible_health_handles_an_empty_ollama_model_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeResponse:
        @staticmethod
        def raise_for_status() -> None:
            return None

        @staticmethod
        def json() -> dict[str, object | None]:
            return {"object": "list", "data": None}

    class FakeAsyncClient:
        def __init__(self, **_: object) -> None:
            pass

        async def __aenter__(self) -> "FakeAsyncClient":
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def get(self, *_: object, **__: object) -> FakeResponse:
            return FakeResponse()

    monkeypatch.setattr(
        "atlas_core.models.openai_compatible.httpx.AsyncClient", FakeAsyncClient
    )
    provider = OpenAICompatibleProvider(
        name="local",
        model="qwen3.5:9b",
        local=True,
        enabled=True,
        base_url="http://127.0.0.1:11434/v1",
        api_key_env=None,
        timeout_seconds=5,
    )

    result = asyncio.run(provider.health())

    assert result["ok"] is True
    assert result["configured"] is True
    assert result["available_models"] == []
    assert result["model_available"] is False
    assert "error" not in result


def test_openai_compatible_retries_a_reasoning_only_final_as_visible_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    responses = [
        {
            "model": "qwen3.5:9b",
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "reasoning": "There is 1 visible entry: .gitkeep.",
                    },
                }
            ],
            "usage": {"completion_tokens": 12},
        },
        {
            "model": "qwen3.5:9b",
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {
                        "role": "assistant",
                        "content": "There is 1 visible entry: `.gitkeep`.",
                    },
                }
            ],
            "usage": {"completion_tokens": 12},
        },
    ]

    class FakeResponse:
        def __init__(self, payload: dict[str, object]) -> None:
            self.payload = payload

        @staticmethod
        def raise_for_status() -> None:
            return None

        def json(self) -> dict[str, object]:
            return self.payload

    class FakeAsyncClient:
        payloads: list[dict[str, object]] = []

        def __init__(self, **_: object) -> None:
            pass

        async def __aenter__(self) -> "FakeAsyncClient":
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def post(self, *_: object, **kwargs: object) -> FakeResponse:
            self.payloads.append(dict(kwargs["json"]))  # type: ignore[arg-type]
            return FakeResponse(responses.pop(0))

    monkeypatch.setattr(
        "atlas_core.models.openai_compatible.httpx.AsyncClient", FakeAsyncClient
    )
    provider = OpenAICompatibleProvider(
        name="local",
        model="qwen3.5:9b",
        local=True,
        enabled=True,
        base_url="http://127.0.0.1:11434/v1",
        api_key_env=None,
        timeout_seconds=5,
    )
    messages = [
        ChatMessage(role="user", content="List the workspace."),
        ChatMessage(
            role="assistant",
            tool_calls=[
                ToolCall(id="call-1", name="filesystem__list", arguments={"path": ""})
            ],
        ),
        ChatMessage(
            role="tool",
            content='{"entries":[{"name":".gitkeep"}]}',
            tool_call_id="call-1",
            name="filesystem__list",
        ),
    ]

    result = asyncio.run(provider.generate(messages))

    assert result.content == "There is 1 visible entry: `.gitkeep`."
    assert len(FakeAsyncClient.payloads) == 2
    assert "reasoning_effort" not in FakeAsyncClient.payloads[0]
    assert FakeAsyncClient.payloads[1]["reasoning_effort"] == "none"
