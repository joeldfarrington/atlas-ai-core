from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from atlas_core.errors import ConfigurationError, ProviderError
from atlas_core.private_owner import (
    PrivateOwnerError, REPOSITORY_ROOT, configure_owner_environment, load_owner_file,
    prepare_private_state, require_secret,
)


def owner_file(tmp_path: Path, document=None) -> Path:
    path = tmp_path / "owner.json"
    payload = {"settings": {}, "secrets": {}} if document is None else document
    path.write_text(json.dumps(payload), encoding="utf-8")
    path.chmod(0o600)
    return path


def test_empty_secrets_are_missing(tmp_path):
    file = owner_file(tmp_path, {"settings": {}, "secrets": {"OPENAI_API_KEY": ""}})
    assert load_owner_file(file) == {}
    with pytest.raises(PrivateOwnerError, match="required_secret_missing"):
        require_secret("OPENAI_API_KEY", environment={})


def test_explicit_synthetic_owner_settings(tmp_path):
    root = tmp_path / "private-state"
    file = owner_file(tmp_path, {
        "settings": {"private_root": str(root), "google_time_zone": "UTC"},
        "secrets": {"OPENAI_API_KEY": "unit-only-synthetic-value"},
    })
    environment = {"ATLAS_OWNER_FILE": str(file)}
    configure_owner_environment(environment=environment)
    assert environment["ATLAS_PRIVATE_ROOT"] == str(root)
    assert require_secret("OPENAI_API_KEY", environment=environment) == "unit-only-synthetic-value"


def test_no_automatic_file_discovery():
    environment = {}
    configure_owner_environment(environment=environment)
    assert environment == {}


def test_repository_file_is_refused_without_reading(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    file = owner_file(repository)
    with pytest.raises(PrivateOwnerError, match="inside_repository_refused"):
        load_owner_file(file, repository_root=repository)


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o660, 0o700])
def test_non_private_file_permissions_are_refused(tmp_path, mode):
    file = owner_file(tmp_path)
    file.chmod(mode)
    with pytest.raises(PrivateOwnerError, match="identity_or_permissions_refused"):
        load_owner_file(file)


def test_symlink_is_refused(tmp_path):
    file = owner_file(tmp_path)
    alias = tmp_path / "alias.json"
    alias.symlink_to(file)
    with pytest.raises(PrivateOwnerError, match="symlink_refused"):
        load_owner_file(alias)


def test_hardlink_is_refused(tmp_path):
    file = owner_file(tmp_path)
    os.link(file, tmp_path / "alias.json")
    with pytest.raises(PrivateOwnerError, match="identity_or_permissions_refused"):
        load_owner_file(file)


@pytest.mark.parametrize("payload", [
    {"settings": {}, "secrets": {}, "unexpected": "unit-only-marker"},
    {"settings": {}, "secrets": {"UNSUPPORTED_KEY": "unit-only-marker"}},
    {"settings": {"permission_grant": "unit-only-marker"}, "secrets": {}},
    {"settings": {}, "secrets": {"OPENAI_API_KEY": ["unit-only-marker"]}},
])
def test_invalid_schema_does_not_echo_values(tmp_path, payload):
    file = owner_file(tmp_path, payload)
    with pytest.raises(PrivateOwnerError) as caught:
        load_owner_file(file)
    assert "unit-only-marker" not in str(caught.value)


def test_bad_json_and_duplicates_do_not_echo_values(tmp_path):
    file = owner_file(tmp_path)
    for content in [
        '{"unit-only-marker":',
        '{"settings": {}, "secrets": {}, "secrets": {}}',
    ]:
        file.write_text(content)
        with pytest.raises(PrivateOwnerError) as caught:
            load_owner_file(file)
        assert "unit-only-marker" not in str(caught.value)


def test_environment_conflict_is_atomic(tmp_path):
    file = owner_file(tmp_path, {"settings": {"google_time_zone": "UTC"},
                              "secrets": {"OPENAI_API_KEY": "unit-only-synthetic-value"}})
    environment = {"ATLAS_OWNER_FILE": str(file), "OPENAI_API_KEY": "other-unit-only-value"}
    before = dict(environment)
    with pytest.raises(PrivateOwnerError, match="environment_conflict"):
        configure_owner_environment(environment=environment)
    assert environment == before


def test_missing_or_oversized_file_is_refused(tmp_path):
    with pytest.raises(PrivateOwnerError, match="private_file_unavailable"):
        load_owner_file(tmp_path / "absent.json")
    file = owner_file(tmp_path)
    file.write_text(" " * 65537)
    with pytest.raises(PrivateOwnerError, match="identity_or_permissions_refused"):
        load_owner_file(file)


def test_private_state_does_not_overwrite_identity(tmp_path):
    state = prepare_private_state(tmp_path / "state")
    identity = state / "identity" / "user.md"
    identity.write_text("# Synthetic retained context\n")
    prepare_private_state(state)
    assert identity.read_text() == "# Synthetic retained context\n"
    assert state != REPOSITORY_ROOT and REPOSITORY_ROOT not in state.parents


def test_private_state_rejects_repo_and_symlink(tmp_path):
    with pytest.raises(PrivateOwnerError, match="inside_repository_refused"):
        prepare_private_state(REPOSITORY_ROOT / "should-not-exist")
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    (root / "data").symlink_to(tmp_path)
    with pytest.raises(PrivateOwnerError, match="symlink_refused"):
        prepare_private_state(root)


def test_credential_file_cannot_live_in_application_state(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    file = owner_file(state, {"settings": {"private_root": str(state)}, "secrets": {}})
    with pytest.raises(PrivateOwnerError, match="private_file_inside_state_refused"):
        load_owner_file(file)
    file = owner_file(state)
    environment = {"ATLAS_OWNER_FILE": str(file), "ATLAS_PRIVATE_ROOT": str(state)}
    with pytest.raises(PrivateOwnerError, match="private_file_inside_state_refused"):
        configure_owner_environment(environment=environment)


def test_release_sample_requires_explicit_external_state():
    from atlas_core.config import load_config
    with pytest.raises(ConfigurationError, match="private_state_root_required"):
        load_config(REPOSITORY_ROOT / "config" / "atlas.yaml", environment={})


def test_private_setting_validation_does_not_echo_input(tmp_path):
    from atlas_core.config import load_config
    environment = {"ATLAS_PRIVATE_ROOT": str(tmp_path / "private-state"),
                   "ATLAS_GOOGLE_EXPECTED_ACCOUNT": "unit-only-invalid-value"}
    with pytest.raises(ConfigurationError, match="configuration_validation_failed") as caught:
        load_config(REPOSITORY_ROOT / "config" / "atlas.yaml", environment=environment)
    assert "unit-only-invalid-value" not in str(caught.value)


def test_release_sample_is_offline_and_missing_cloud_secret_fails_before_request(tmp_path, monkeypatch):
    from atlas_core.services import build_services
    state = tmp_path / "state"
    monkeypatch.setenv("ATLAS_PRIVATE_ROOT", str(state))
    for name in ("ATLAS_OWNER_FILE", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "ATLAS_DEFAULT_PROVIDER"):
        monkeypatch.delenv(name, raising=False)
    services = build_services(REPOSITORY_ROOT / "config" / "atlas.yaml")
    assert services.config.routing.default_provider == "mock"
    assert not services.config.development.projects
    assert services.google is None and services.mac_inbox is None and services.phone_companion is None
    assert not any((services.config.supervisor.enabled, services.config.supervisor_v2.enabled,
                    services.config.supervisor_v3.enabled, services.config.supervisor_v4.enabled))
    assert services.constitution.status()["owner_adopted"] is False
    assert services.config.app.data_dir == state / "data"
    services.router.providers["openai"].enabled = True
    with pytest.raises(ProviderError, match="requires environment variable"):
        services.router.get("openai", local_only=False)
