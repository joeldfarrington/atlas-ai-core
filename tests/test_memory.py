from __future__ import annotations

from atlas_core.services import AtlasServices


def test_memory_upsert_search_and_delete(services: AtlasServices) -> None:
    first = services.database.upsert_memory(
        namespace="global",
        kind="preference",
        key="communication-style",
        content="the owner prefers direct and practical explanations.",
        importance=8,
    )
    updated = services.database.upsert_memory(
        namespace="global",
        kind="preference",
        key="communication-style",
        content="the owner prefers direct, practical, candid explanations.",
        importance=9,
    )
    assert updated["id"] == first["id"]
    results = services.database.search_memories("practical candid", namespace="global")
    assert results
    assert results[0]["key"] == "communication-style"
    assert services.database.delete_memory(first["id"]) is True
    assert services.database.get_memory(first["id"]) is None


def test_project_state_round_trip(services: AtlasServices) -> None:
    project = services.database.upsert_project(
        slug="atlas-core",
        name="Atlas Core",
        status="active",
        summary="Build a local-first core.",
        next_action="Connect a local model.",
    )
    assert project["slug"] == "atlas-core"
    loaded = services.database.get_project("atlas-core")
    assert loaded is not None
    assert loaded["next_action"] == "Connect a local model."
