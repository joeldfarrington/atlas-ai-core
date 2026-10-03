from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from atlas_core.errors import ApprovalError, ProviderError
from atlas_core.models import ChatMessage, ModelResponse
from atlas_core.runtime import MODEL_TOOL_CONTEXT_CHARS, AtlasRuntime
from atlas_core.services import AtlasServices


def test_model_tool_call_pauses_and_resumes_after_approval(
    services: AtlasServices,
) -> None:
    services.tools.execute(
        tool_name="filesystem",
        action="create",
        arguments={"path": "approval.txt", "content": "before"},
    )
    result = asyncio.run(
        services.runtime.chat(
            message='TOOL filesystem__modify {"path":"approval.txt","content":"after"}',
            provider="mock",
        )
    )
    assert result["status"] == "awaiting_approval"
    approval = result["approval"]
    assert approval["status"] == "pending"
    assert approval["run_id"] == result["run_id"]

    services.tools.decide_approval(approval["id"], "approved")
    completed = asyncio.run(services.runtime.resume(result["run_id"]))
    assert completed["status"] == "completed"
    assert "Tool result received and verified" in completed["content"]
    assert (services.config.app.workspace_dir / "approval.txt").read_text() == "after"
    assert services.database.get_approval(approval["id"])["status"] == "executed"


def test_rejected_tool_call_returns_result_to_model_without_modifying_file(
    services: AtlasServices,
) -> None:
    services.tools.execute(
        tool_name="filesystem",
        action="create",
        arguments={"path": "reject.txt", "content": "before"},
    )
    result = asyncio.run(
        services.runtime.chat(
            message='TOOL filesystem__modify {"path":"reject.txt","content":"after"}',
            provider="mock",
        )
    )
    approval = result["approval"]
    services.tools.decide_approval(approval["id"], "rejected")
    completed = asyncio.run(services.runtime.resume(result["run_id"]))
    assert completed["status"] == "completed"
    assert "owner rejected" in completed["content"].lower()
    assert (services.config.app.workspace_dir / "reject.txt").read_text() == "before"
    assert services.database.get_approval(approval["id"])["status"] == "rejected"


def test_tools_can_be_disabled_per_chat(services: AtlasServices) -> None:
    result = asyncio.run(
        services.runtime.chat(
            message='TOOL filesystem__create {"path":"disabled.txt","content":"no"}',
            provider="mock",
            tools_enabled=False,
        )
    )
    assert result["status"] == "completed"
    assert not (services.config.app.workspace_dir / "disabled.txt").exists()


def test_run_bound_approval_cannot_be_replayed_without_run_context(
    services: AtlasServices,
) -> None:
    services.tools.execute(
        tool_name="filesystem",
        action="create",
        arguments={"path": "bound.txt", "content": "one"},
    )
    arguments = {"path": "bound.txt", "content": "two"}
    approval = services.database.create_approval(
        "filesystem",
        "modify",
        arguments,
        run_id="run-one",
        call_id="call-one",
    )
    services.database.decide_approval(approval["id"], "approved")
    with pytest.raises(ApprovalError):
        services.tools.execute(
            tool_name="filesystem",
            action="modify",
            arguments=arguments,
            approval_id=approval["id"],
        )


def test_runtime_emits_structured_events(services: AtlasServices) -> None:
    events: list[dict] = []

    async def callback(event: dict) -> None:
        events.append(event)

    result = asyncio.run(
        services.runtime.chat(
            message="Event test",
            provider="mock",
            event_callback=callback,
        )
    )
    assert result["status"] == "completed"
    names = [event["event"] for event in events]
    assert names[0] == "run.started"
    assert "model.started" in names
    assert "model.completed" in names
    assert "text.delta" in names
    assert names[-1] == "run.completed"


def test_model_tool_evidence_is_compacted_without_changing_run_messages() -> None:
    search_result = {
        "bounded": True,
        "count": 25,
        "result_size_estimate": 25,
        "messages": [
            {
                "id": f"message-{index}",
                "thread_id": f"thread-{index}",
                "label_ids": ["UNREAD", "INBOX"],
                "date": "Thu, 27 Aug 2026 12:00:00 -0400",
                "from": "Sender Name <sender@example.com>",
                "to": "owner@example.com",
                "cc": "",
                "subject": f"Potentially important message {index}",
                "snippet": "x" * 500,
            }
            for index in range(25)
        ],
    }
    read_result = {
        "id": "message-1",
        "thread_id": "thread-1",
        "label_ids": ["UNREAD", "INBOX"],
        "from": "Sender Name <sender@example.com>",
        "to": "owner@example.com",
        "subject": "Long message",
        "date": "Thu, 27 Aug 2026 12:00:00 -0400",
        "snippet": "Important opening",
        "body": "body " * 8_000,
        "body_truncated": False,
        "attachments_fetched": False,
    }
    calendar_result = {
        "bounded": True,
        "calendar": "primary",
        "time_zone": "America/New_York",
        "count": 20,
        "events": [
            {
                "id": f"event-{index}",
                "status": "confirmed",
                "summary": f"Event {index}",
                "description": "details " * 1_000,
                "location": "Office",
                "start": {"dateTime": "2026-08-27T12:00:00-04:00"},
                "end": {"dateTime": "2026-08-27T13:00:00-04:00"},
                "attendees": [],
            }
            for index in range(20)
        ],
    }
    messages = [
        ChatMessage(role="user", content="Prepare my brief"),
        ChatMessage(
            role="tool",
            content=json.dumps(search_result),
            tool_call_id="search-call",
            name="gmail__search",
        ),
        ChatMessage(
            role="tool",
            content=json.dumps(read_result),
            tool_call_id="read-call",
            name="gmail__read",
        ),
        ChatMessage(
            role="tool",
            content=json.dumps(calendar_result),
            tool_call_id="calendar-call",
            name="calendar__list_events",
        ),
    ]

    prepared = AtlasRuntime._messages_for_model(messages)

    assert messages[1].content == json.dumps(search_result)
    assert sum(len(item.content) for item in prepared if item.role == "tool") <= (
        MODEL_TOOL_CONTEXT_CHARS
    )
    assert [item.tool_call_id for item in prepared[1:]] == [
        "search-call",
        "read-call",
        "calendar-call",
    ]
    for item in prepared[1:]:
        payload = json.loads(item.content)
        assert payload["model_view_compacted"] is True


def test_empty_model_response_fails_instead_of_claiming_completion(
    services: AtlasServices, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def empty_generate(*args: object, **kwargs: object) -> ModelResponse:
        del args, kwargs
        return ModelResponse(
            content="",
            provider="mock",
            model="atlas-mock",
            usage={"total_tokens": 8_192},
            stop_reason="length",
        )

    monkeypatch.setattr(services.router, "generate", empty_generate)

    with pytest.raises(ProviderError, match="no visible text or tool call"):
        asyncio.run(services.runtime.chat(message="Return a brief", provider="mock"))
