from __future__ import annotations

from pathlib import Path

import pytest

from atlas_core.services import AtlasServices, build_services


@pytest.fixture()
def config_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "atlas"
    (root / "config").mkdir(parents=True)
    (root / "identity").mkdir()
    (root / "workspace").mkdir()
    (root / "data").mkdir()
    (root / "identity" / "atlas.md").write_text(
        "# Atlas\n\nYou are Atlas, a portable assistant.", encoding="utf-8"
    )
    (root / "identity" / "behavior.md").write_text(
        "# Behavior\n\nRespect owner-controlled permissions.", encoding="utf-8"
    )
    (root / "config" / "permissions.yaml").write_text(
        """default: deny

tools:
  filesystem:
    list: allow
    read: allow
    create: allow
    modify: ask
    delete: ask
  mac_inbox:
    status: allow
    list: allow
    preview: allow
    create_folder: allow
    move: allow
    trash: ask
    restore: allow
    list_recovery: allow
    reveal: allow
    open: allow
  phone_companion:
    status: allow
""",
        encoding="utf-8",
    )
    (root / "config" / "agents.yaml").write_text(
        """default_agent: atlas
agents:
  atlas:
    name: Atlas
    description: Test agent
    instructions: Use tools safely.
    tools:
      - filesystem.list
      - filesystem.read
      - filesystem.create
      - filesystem.modify
      - mac_inbox.*
      - phone_companion.status
      - memory.search
      - projects.get
    max_steps: 6
    local_only: true
  developer:
    name: Developer
    description: Test developer
    instructions: Test code.
    tools:
      - filesystem.list
      - filesystem.read
      - filesystem.create
      - filesystem.modify
    max_steps: 6
    local_only: true
  general-operator:
    name: General Operator
    description: Test Mac operator
    instructions: Preview first.
    tools:
      - mac_inbox.*
      - phone_companion.status
    max_steps: 6
    local_only: true
""",
        encoding="utf-8",
    )
    config = root / "config" / "atlas.yaml"
    config.write_text(
        """app:
  root_dir: ..
  data_dir: data
  identity_dir: identity
  workspace_dir: workspace
  permissions_file: config/permissions.yaml
  agents_file: config/agents.yaml
  database_name: test.db
  memory_top_k: 6
  recent_message_limit: 16
  max_file_bytes: 100000

providers:
  mock:
    kind: mock
    model: atlas-mock
    local: true
    timeout_seconds: 5

routing:
  default_provider: mock

mac_inbox:
  enabled: true
  root: mac-inbox
  recovery_dir: workspace/.atlas_trash/mac_inbox
  preview_dir: workspace/.atlas_tmp/mac_inbox
  pause_file: data/mac-inbox.paused
  preview_ttl_seconds: 900
  max_entries: 100

phone_companion:
  enabled: true
  state_file: data/phone-companion-state.json
  pause_file: data/phone-companion.paused
  bridge_port: 8743
  pairing_ttl_seconds: 600
  session_ttl_seconds: 43200
  status_max_age_seconds: 300
  max_pairing_attempts: 5
""",
        encoding="utf-8",
    )
    monkeypatch.delenv("ATLAS_DEFAULT_PROVIDER", raising=False)
    monkeypatch.delenv("ATLAS_API_TOKEN", raising=False)
    return config


@pytest.fixture()
def services(config_path: Path) -> AtlasServices:
    return build_services(config_path)
