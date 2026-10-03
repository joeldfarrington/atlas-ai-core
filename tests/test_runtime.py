from __future__ import annotations

import asyncio

from atlas_core.services import AtlasServices


def test_runtime_chat_persists_conversation_and_retrieves_memory(
    services: AtlasServices,
) -> None:
    memory = services.database.upsert_memory(
        namespace="global",
        kind="preference",
        key="response-style",
        content="Use direct, practical explanations.",
        importance=9,
    )
    first = asyncio.run(
        services.runtime.chat(
            message="Please use a practical response style.",
            provider="mock",
        )
    )
    assert first["provider"] == "mock"
    assert memory["id"] in first["memory_ids"]

    second = asyncio.run(
        services.runtime.chat(
            message="Continue the same conversation.",
            conversation_id=first["conversation_id"],
            provider="mock",
        )
    )
    assert second["conversation_id"] == first["conversation_id"]
    messages = services.database.recent_messages(first["conversation_id"], limit=10)
    assert [message["role"] for message in messages] == [
        "user",
        "assistant",
        "user",
        "assistant",
    ]


def test_router_blocks_non_local_provider_in_local_only_mode(
    services: AtlasServices,
) -> None:
    from atlas_core.errors import ProviderError

    services.router.providers["mock"].local = False
    try:
        services.router.get("mock", local_only=True)
    except ProviderError as exc:
        assert "local_only" in str(exc)
    else:
        raise AssertionError("Expected local-only routing to block a non-local provider")
