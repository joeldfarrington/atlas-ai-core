from __future__ import annotations

import json
import zipfile
from pathlib import Path

from atlas_core.memory import Database
from atlas_core.migration import ImportService
from atlas_core.services import AtlasServices


def _chatgpt_export() -> list[dict[str, object]]:
    return [
        {
            "id": "chatgpt-conversation-1",
            "title": "Imported conversation",
            "create_time": 1_700_000_000,
            "update_time": 1_700_000_100,
            "current_node": "node-2",
            "mapping": {
                "node-1": {
                    "id": "node-1",
                    "parent": None,
                    "message": {
                        "id": "message-1",
                        "author": {"role": "user"},
                        "content": {"content_type": "text", "parts": ["Hello Atlas"]},
                        "create_time": 1_700_000_000,
                        "metadata": {},
                    },
                },
                "node-2": {
                    "id": "node-2",
                    "parent": "node-1",
                    "message": {
                        "id": "message-2",
                        "author": {"role": "assistant"},
                        "content": {"content_type": "text", "parts": ["Hello the owner"]},
                        "create_time": 1_700_000_010,
                        "metadata": {"model_slug": "test-model"},
                    },
                },
            },
        }
    ]


def test_chatgpt_import_is_idempotent_and_can_assign_project(
    services: AtlasServices, tmp_path: Path
) -> None:
    export = tmp_path / "conversations.json"
    export.write_text(json.dumps(_chatgpt_export()), encoding="utf-8")

    first = services.imports.import_path(
        export, source="chatgpt", project_slug="atlas-core"
    )
    assert first["status"] == "completed"
    assert first["stats"]["conversations_imported"] == 1
    assert first["stats"]["messages_imported"] == 2
    conversation = services.database.find_conversation_by_external(
        "chatgpt", "chatgpt-conversation-1"
    )
    assert conversation is not None
    assert conversation["project_slug"] == "atlas-core"

    second = services.imports.import_path(export, source="chatgpt")
    assert second["stats"]["conversations_skipped"] == 1
    assert second["stats"]["messages_imported"] == 0


def test_portable_backup_contains_merge_data_and_round_trips(
    services: AtlasServices, tmp_path: Path
) -> None:
    services.database.upsert_memory(
        namespace="global",
        kind="note",
        key="backup-memory",
        content="This survives a portable backup.",
        importance=7,
    )
    services.database.upsert_project(
        slug="backup-project",
        name="Backup Project",
        status="active",
        summary="Round-trip test",
        next_action="Restore it",
    )
    conversation = services.database.create_conversation(
        "Backup conversation", project_slug="backup-project"
    )
    services.database.add_message(conversation["id"], "user", "Keep this")
    services.database.add_message(conversation["id"], "assistant", "Stored")

    archive = services.backups.create_backup(tmp_path / "backup.zip")
    with zipfile.ZipFile(archive) as bundle:
        names = set(bundle.namelist())
        assert "atlas-backup/manifest.json" in names
        assert "atlas-backup/atlas_data.json" in names
        manifest = json.loads(bundle.read("atlas-backup/manifest.json"))
        assert manifest["secrets_included"] is False
        assert manifest["portable_data_included"] is True

    restored_db = Database(tmp_path / "restored.db")
    importer = ImportService(restored_db)
    imported = importer.import_path(archive, source="atlas")
    assert imported["status"] == "completed"
    assert restored_db.get_project("backup-project") is not None
    memories = restored_db.search_memories("portable backup")
    assert any(item["key"] == "backup-memory" for item in memories)
    restored = restored_db.find_conversation_by_external("atlas", conversation["id"])
    assert restored is not None
    assert len(restored_db.list_messages(restored["id"])) == 2


def test_backup_imports_into_a_separate_fresh_database(
    services: AtlasServices, tmp_path: Path
) -> None:
    """A portable archive must merge cleanly into an unrelated installation."""
    services.database.upsert_memory(
        namespace="global",
        kind="preference",
        key="portable-owner-preference",
        content="Keep durable state model-independent.",
        importance=9,
    )
    services.database.upsert_project(
        slug="portable-project",
        name="Portable Project",
        status="active",
        summary="Created in installation A",
        next_action="Restore in installation B",
    )
    source_conversation = services.database.create_conversation(
        "Portable second-install test", project_slug="portable-project"
    )
    services.database.add_message(
        source_conversation["id"], "user", "This originated in installation A."
    )
    services.database.add_message(
        source_conversation["id"], "assistant", "It should appear in installation B."
    )

    archive = services.backups.create_backup(tmp_path / "portable.zip")

    destination_db = Database(tmp_path / "installation-b" / "atlas.db")
    destination_importer = ImportService(destination_db)
    result = destination_importer.import_path(archive, source="auto")

    assert result["status"] == "completed"
    assert destination_db.get_project("portable-project") is not None
    assert any(
        memory["key"] == "portable-owner-preference"
        for memory in destination_db.list_memories(limit=100)
    )
    restored = destination_db.find_conversation_by_external(
        "atlas", source_conversation["id"]
    )
    assert restored is not None
    assert [
        message["content"] for message in destination_db.list_messages(restored["id"])
    ] == [
        "This originated in installation A.",
        "It should appear in installation B.",
    ]
