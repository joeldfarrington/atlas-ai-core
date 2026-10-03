from __future__ import annotations

import os
import pwd
import re
import stat
from pathlib import Path
from typing import Any, Literal, Mapping

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from atlas_core.errors import ConfigurationError

_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


class AppConfig(BaseModel):
    root_dir: Path = Path("..")
    data_dir: Path = Path("data")
    identity_dir: Path = Path("identity")
    workspace_dir: Path = Path("workspace")
    permissions_file: Path = Path("config/permissions.yaml")
    agents_file: Path = Path("config/agents.yaml")
    development_projects_file: Path = Path("config/development_projects.yaml")
    supervisor_policy_file: Path = Path("config/supervisor_policy.yaml")
    supervisor_v2_policy_file: Path = Path("config/supervisor_v2_policy.yaml")
    supervisor_v3_policy_file: Path = Path("config/supervisor_v3_policy.yaml")
    supervisor_v3_classifier_file: Path = Path(
        "config/supervisor_v3_notifications.yaml"
    )
    supervisor_v3_lock_file: Path = Path("config/supervisor_v3_sdk.lock.json")
    supervisor_v4_contract_file: Path = Path("config/supervisor_v4_policy.yaml")
    supervisor_v4_protocol_file: Path = Path("config/supervisor_v4_protocol.yaml")
    supervisor_v4_lock_file: Path = Path("config/supervisor_v4_sdk.lock.json")
    supervisor_v4_replay_file: Path = Path(
        "src/atlas_core/resources/supervisor_v4_replays.json"
    )
    supervisor_v4_same_user_registry_file: Path = Path(
        "config/supervisor_v4_same_user_registry.json"
    )
    database_name: str = "atlas.db"
    memory_top_k: int = Field(default=8, ge=1, le=50)
    recent_message_limit: int = Field(default=30, ge=2, le=200)
    max_file_bytes: int = Field(default=2_097_152, ge=1_024, le=100_000_000)
    max_tool_steps: int = Field(default=12, ge=1, le=100)
    web_fetch_max_bytes: int = Field(default=750_000, ge=10_000, le=20_000_000)
    terminal_timeout_seconds: float = Field(default=30.0, ge=1, le=120)
    api_token: str | None = None


class ProviderConfig(BaseModel):
    kind: Literal["openai_compatible", "openai_responses", "anthropic", "mock"]
    base_url: str | None = None
    model: str
    api_key_env: str | None = None
    local: bool = True
    enabled: bool = True
    timeout_seconds: float = Field(default=180.0, gt=0, le=1_800)
    reasoning_effort: Literal["none"] | None = None
    # An optional provider ceiling also applies when the caller has no budget.
    max_tokens: int | None = Field(default=None, strict=True, ge=1, le=32_768)

    @model_validator(mode="after")
    def require_local_response_options(self) -> "ProviderConfig":
        if (self.reasoning_effort is not None or self.max_tokens is not None) and (
            self.kind != "openai_compatible" or not self.local
        ):
            raise ValueError("explicit response options require a local openai_compatible provider")
        return self

    @field_validator("base_url")
    @classmethod
    def normalize_base_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.rstrip("/")


class RoutingConfig(BaseModel):
    default_provider: str = "local"
    fallback_providers: list[str] = Field(default_factory=list)


class ImportsConfig(BaseModel):
    max_upload_bytes: int = Field(default=209_715_200, ge=1_024, le=2_000_000_000)


class BackupsConfig(BaseModel):
    include_workspace_by_default: bool = True


DEFAULT_MAC_INBOX_OPEN_EXTENSIONS = [
    ".csv",
    ".gif",
    ".heic",
    ".jpeg",
    ".jpg",
    ".json",
    ".md",
    ".pdf",
    ".png",
    ".rtf",
    ".txt",
    ".webp",
]


class MacInboxConfig(BaseModel):
    """Owner-controlled boundary for Atlas's first Mac task family."""

    enabled: bool = False
    root: Path = Path("~/Documents/Atlas Inbox")
    recovery_dir: Path = Path("workspace/.atlas_trash/mac_inbox")
    preview_dir: Path = Path("workspace/.atlas_tmp/mac_inbox")
    pause_file: Path = Path("data/mac-inbox.paused")
    preview_ttl_seconds: int = Field(default=900, ge=30, le=3_600)
    max_entries: int = Field(default=5_000, ge=10, le=100_000)
    safe_open_extensions: list[str] = Field(
        default_factory=lambda: list(DEFAULT_MAC_INBOX_OPEN_EXTENSIONS)
    )

    @field_validator("safe_open_extensions")
    @classmethod
    def validate_safe_open_extensions(cls, value: list[str]) -> list[str]:
        normalized: list[str] = []
        for item in value:
            extension = item.strip().lower()
            if not re.fullmatch(r"\.[a-z0-9]{1,12}", extension):
                raise ValueError(
                    "safe_open_extensions must contain simple lowercase extensions"
                )
            if extension not in normalized:
                normalized.append(extension)
        if not normalized:
            raise ValueError("safe_open_extensions cannot be empty")
        return normalized


class PhoneCompanionConfig(BaseModel):
    """Owner-controlled boundary for Atlas's first native phone bridge."""

    enabled: bool = False
    state_file: Path = Path("data/phone-companion-state.json")
    pause_file: Path = Path("data/phone-companion.paused")
    bridge_port: int = Field(default=8743, ge=1_024, le=65_535)
    pairing_ttl_seconds: int = Field(default=600, ge=60, le=1_800)
    session_ttl_seconds: int = Field(default=43_200, ge=300, le=86_400)
    status_max_age_seconds: int = Field(default=300, ge=30, le=3_600)
    max_pairing_attempts: int = Field(default=5, ge=1, le=10)

    @model_validator(mode="after")
    def require_distinct_control_files(self) -> "PhoneCompanionConfig":
        if self.state_file == self.pause_file:
            raise ValueError("phone companion state and pause files must differ")
        return self


DEVELOPMENT_ACTIONS = {
    "status",
    "list",
    "read",
    "search",
    "create",
    "modify",
    "delete",
    "run_check",
    "selfdev_context",
    "selfdev_apply",
}


class DevelopmentCheckConfig(BaseModel):
    """An owner-configured check with no model-supplied command surface."""

    description: str = ""
    argv: list[str] = Field(min_length=1, max_length=64)
    cwd: Path = Path(".")
    timeout_seconds: float = Field(default=120.0, ge=1, le=1_800)
    covered_paths: list[str] = Field(default_factory=list, max_length=128)

    @field_validator("covered_paths")
    @classmethod
    def validate_covered_paths(cls, value: list[str]) -> list[str]:
        """Declare exact project files; never infer coverage from a check name."""

        normalized: list[str] = []
        for item in value:
            path = Path(item)
            if (
                not item or item != item.strip()
                or any(character in item for character in "\\\x00*?[]:")
                or path.is_absolute() or ".." in path.parts
                or not path.parts
            ):
                raise ValueError("check covered_paths must contain exact relative file paths")
            text = path.as_posix()
            if text not in normalized:
                normalized.append(text)
        return normalized

    @field_validator("argv")
    @classmethod
    def validate_argv(cls, value: list[str]) -> list[str]:
        if any(not item.strip() for item in value):
            raise ValueError("check argv entries must be non-empty strings")
        if sum(len(item) for item in value) > 20_000:
            raise ValueError("check argv is too large")
        if value[0] in {"sudo", "su", "doas", "shutdown", "reboot", "halt"}:
            raise ValueError(f"blocked check executable: {value[0]}")
        return value

    @field_validator("cwd")
    @classmethod
    def validate_cwd(cls, value: Path) -> Path:
        if value.is_absolute() or ".." in value.parts:
            raise ValueError("check cwd must stay relative to the registered project")
        return value


class RegisteredDevelopmentProjectConfig(BaseModel):
    """Owner-controlled boundary for one local software project."""

    name: str
    root: Path
    action_tier: Literal["tier_0_observe", "tier_2_reversible_local"] = (
        "tier_0_observe"
    )
    allowed_actions: list[str] = Field(
        default_factory=lambda: ["status", "list", "read", "search"]
    )
    checks: dict[str, DevelopmentCheckConfig] = Field(default_factory=dict)
    blocked_paths: list[str] = Field(default_factory=list)
    self_development: bool = False
    selfdev_editable_paths: list[str] = Field(default_factory=list)
    selfdev_require_check_coverage: bool = Field(default=False, strict=True)
    baseline: dict[str, Any] = Field(default_factory=dict)
    pause_conditions: list[str] = Field(default_factory=list)

    @field_validator("allowed_actions")
    @classmethod
    def validate_allowed_actions(cls, value: list[str]) -> list[str]:
        unknown = sorted(set(value) - DEVELOPMENT_ACTIONS)
        if unknown:
            raise ValueError(f"unknown development actions: {', '.join(unknown)}")
        if len(value) != len(set(value)):
            raise ValueError("development allowed_actions must not contain duplicates")
        return value

    @field_validator("blocked_paths")
    @classmethod
    def validate_blocked_paths(cls, value: list[str]) -> list[str]:
        for item in value:
            path = Path(item)
            normalized_parts = tuple(
                part for part in path.parts if part not in {"", "."}
            )
            if (
                not item.strip()
                or not normalized_parts
                or path.is_absolute()
                or ".." in path.parts
            ):
                raise ValueError("blocked_paths entries must be non-empty relative paths")
        return value

    @field_validator("selfdev_editable_paths")
    @classmethod
    def validate_selfdev_editable_paths(cls, value: list[str]) -> list[str]:
        normalized: list[str] = []
        for item in value:
            path = Path(item)
            if (
                not item.strip()
                or path.is_absolute()
                or ".." in path.parts
                or not tuple(part for part in path.parts if part not in {"", "."})
            ):
                raise ValueError(
                    "selfdev_editable_paths entries must be non-empty relative paths"
                )
            text = path.as_posix().rstrip("/")
            if text not in normalized:
                normalized.append(text)
        return normalized

    @model_validator(mode="after")
    def enforce_action_tier(self) -> "RegisteredDevelopmentProjectConfig":
        if self.action_tier == "tier_0_observe":
            disallowed = set(self.allowed_actions) - {
                "status",
                "list",
                "read",
                "search",
            }
            if disallowed:
                raise ValueError(
                    "tier_0_observe projects cannot enable local mutation or checks"
                )
        if self.self_development:
            if self.action_tier != "tier_2_reversible_local":
                raise ValueError(
                    "self-development projects require tier_2_reversible_local"
                )
            required_actions = {"selfdev_context", "selfdev_apply"}
            if set(self.allowed_actions) != required_actions:
                raise ValueError(
                    "self-development projects may enable only selfdev_context and "
                    "selfdev_apply"
                )
            if not self.selfdev_editable_paths:
                raise ValueError(
                    "self-development projects require owner-approved editable paths"
                )
            blocked = {
                tuple(part for part in Path(item).parts if part not in {"", "."})
                for item in self.blocked_paths
            }
            required_blocked = {
                (".git",),
                ("config",),
                ("data",),
                ("identity",),
                ("workspace",),
            }
            if not required_blocked.issubset(blocked):
                raise ValueError(
                    "self-development projects must block .git, config, data, "
                    "identity, and workspace"
                )
        return self


class DevelopmentRegistryConfig(BaseModel):
    """Portable registry of software projects Atlas may operate inside."""

    version: Literal[1] = 1
    projects: dict[str, RegisteredDevelopmentProjectConfig] = Field(
        default_factory=dict
    )

    @field_validator("projects")
    @classmethod
    def validate_project_slugs(
        cls, value: dict[str, RegisteredDevelopmentProjectConfig]
    ) -> dict[str, RegisteredDevelopmentProjectConfig]:
        for slug in value:
            if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?", slug):
                raise ValueError(f"invalid registered project slug: {slug}")
        return value


class GrowthConfig(BaseModel):
    """Owner-scoped research tools and automatic outcome observations."""

    model_config = {"extra": "forbid"}
    enabled: bool = Field(default=False, strict=True)
    projects: list[str] = Field(default_factory=list, max_length=32)
    allowed_agents: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("projects", "allowed_agents")
    @classmethod
    def validate_scope(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value) or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?", item) for item in value
        ):
            raise ValueError("Invalid or duplicate growth scope")
        return value

    @model_validator(mode="after")
    def explicit_scope(self) -> "GrowthConfig":
        if self.enabled and (not self.projects or not self.allowed_agents):
            raise ValueError("Enabled growth needs explicit projects and allowed_agents")
        return self


class ResearchJournalConfig(BaseModel):
    """Owner-bound research context. No model-supplied directory selection."""

    model_config = {"extra": "forbid"}
    enabled: bool = Field(default=False, strict=True)
    projects: dict[str, Path] = Field(default_factory=dict, max_length=32)
    allowed_agents: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("projects")
    @classmethod
    def validate_directories(cls, value: dict[str, Path]) -> dict[str, Path]:
        for slug, directory in value.items():
            if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?", slug):
                raise ValueError("invalid research journal project slug")
            if not directory.is_absolute() or ".." in directory.parts or len(directory.parts) < 3:
                raise ValueError("research journal requires a specific absolute directory")
        if len(set(value.values())) != len(value):
            raise ValueError("each research project requires a distinct journal directory")
        return value

    @field_validator("allowed_agents")
    @classmethod
    def validate_agents(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value) or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?", item)
            for item in value
        ):
            raise ValueError("invalid research journal agent list")
        return value

    @model_validator(mode="after")
    def require_explicit_scope(self) -> "ResearchJournalConfig":
        if self.enabled and (not self.projects or not self.allowed_agents):
            raise ValueError("enabled research journal requires projects and allowed_agents")
        return self


class SupervisorProjectPolicyConfig(BaseModel):
    """Owner-selected Supervisor actions for one registered project."""

    allow_status: bool = True
    allowed_checks: list[str] = Field(default_factory=list)

    @field_validator("allowed_checks")
    @classmethod
    def validate_allowed_checks(cls, value: list[str]) -> list[str]:
        normalized = [item.strip() for item in value]
        if any(not item for item in normalized):
            raise ValueError("supervisor allowed_checks entries must be non-empty")
        if len(normalized) != len(set(normalized)):
            raise ValueError("supervisor allowed_checks must not contain duplicates")
        return normalized


class SupervisorPolicyConfig(BaseModel):
    """Immutable-at-runtime owner policy for the first bounded Supervisor."""

    version: Literal[1] = 1
    background_execution: Literal[False] = False
    allow_mutations: Literal[False] = False
    require_exact_confirmation: Literal[True] = True
    max_attempts_per_task: int = Field(default=1, ge=1, le=1)
    projects: dict[str, SupervisorProjectPolicyConfig] = Field(default_factory=dict)


class SupervisorConfig(BaseModel):
    """Runtime controls for the manual, on-demand Supervisor."""

    enabled: bool = False
    pause_file: Path = Path("data/supervisor.paused")
    max_tasks: int = Field(default=10_000, ge=100, le=1_000_000)


class SupervisorV2ProtocolPinConfig(BaseModel):
    """Owner-reviewed local Codex App Server protocol snapshot."""

    cli_version: str = Field(min_length=1, max_length=200)
    binary_path: Path
    binary_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    schema_file_count: int = Field(ge=1, le=10_000)
    schema_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    selected_schema_sha256: dict[str, str] = Field(default_factory=dict)

    @field_validator("selected_schema_sha256")
    @classmethod
    def validate_selected_schema_hashes(cls, value: dict[str, str]) -> dict[str, str]:
        if not value:
            raise ValueError("at least one selected App Server schema hash is required")
        for name, digest in value.items():
            path = Path(name)
            if (
                not name.strip()
                or path.is_absolute()
                or ".." in path.parts
                or not re.fullmatch(r"[0-9a-f]{64}", digest)
            ):
                raise ValueError("selected App Server schema hashes must be named SHA-256 values")
        return value


class SupervisorV2RecipeConfig(BaseModel):
    """One fixed, owner-written candidate-generation recipe."""

    version: int = Field(default=1, ge=1, le=1)
    project: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")
    task_statement: str = Field(min_length=1, max_length=20_000)
    allowed_paths: list[str] = Field(min_length=1, max_length=16)
    blocked_paths: list[str] = Field(default_factory=list, max_length=64)
    verification_checks: list[str] = Field(min_length=1, max_length=8)
    max_changed_files: int = Field(default=4, ge=1, le=4)
    max_changed_lines: int = Field(default=200, ge=1, le=200)
    max_patch_bytes: int = Field(default=131_072, ge=1, le=131_072)

    @field_validator("allowed_paths", "blocked_paths")
    @classmethod
    def validate_recipe_paths(cls, value: list[str]) -> list[str]:
        normalized: list[str] = []
        for item in value:
            path = Path(item)
            parts = tuple(part for part in path.parts if part not in {"", "."})
            if not item.strip() or not parts or path.is_absolute() or ".." in path.parts:
                raise ValueError("Supervisor v2 paths must be non-empty relative paths")
            text = path.as_posix().rstrip("/")
            if text not in normalized:
                normalized.append(text)
        return normalized

    @field_validator("allowed_paths")
    @classmethod
    def prohibit_git_authority(cls, value: list[str]) -> list[str]:
        if any(item == ".git" or item.startswith(".git/") for item in value):
            raise ValueError("Supervisor v2 cannot authorize Git metadata")
        return value

    @field_validator("verification_checks")
    @classmethod
    def validate_verification_checks(cls, value: list[str]) -> list[str]:
        normalized = [item.strip() for item in value]
        if any(not item for item in normalized) or len(normalized) != len(set(normalized)):
            raise ValueError("verification checks must be non-empty and unique")
        return normalized


class SupervisorV2PolicyConfig(BaseModel):
    """Fail-closed authority for the one-shot reversible-change pilot."""

    version: Literal[2] = 2
    background_execution: Literal[False] = False
    live_codex_execution: Literal[True] = True
    canonical_mutations: Literal[False] = False
    command_network_access: Literal[False] = False
    experimental_api: Literal[False] = False
    permission_profile_beta: Literal[True] = True
    permission_profile: Literal["atlas_fixture"] = "atlas_fixture"
    model: Literal["gpt-5.6-sol"] = "gpt-5.6-sol"
    reasoning_effort: Literal["low"] = "low"
    max_attempts_per_task: int = Field(default=1, ge=1, le=1)
    max_live_attempts_total: int = Field(default=1, ge=1, le=1)
    turn_timeout_seconds: int = Field(default=180, ge=180, le=180)
    plan_ttl_seconds: int = Field(default=1_800, ge=60, le=3_600)
    protocol_pin: SupervisorV2ProtocolPinConfig | None = None
    recipes: dict[str, SupervisorV2RecipeConfig] = Field(default_factory=dict)

    @field_validator("recipes")
    @classmethod
    def validate_recipe_slugs(
        cls, value: dict[str, SupervisorV2RecipeConfig]
    ) -> dict[str, SupervisorV2RecipeConfig]:
        for slug in value:
            if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?", slug):
                raise ValueError(f"invalid Supervisor v2 recipe slug: {slug}")
        return value


class SupervisorV2Config(BaseModel):
    """On-demand controls for one owner-confirmed fixture candidate."""

    enabled: bool = False
    runtime_dir: Path = Path("data/supervisor-v2")
    max_tasks: int = Field(default=10_000, ge=100, le=1_000_000)


class SupervisorV3ArtifactPinConfig(BaseModel):
    """One exact wheel in the isolated Supervisor v3 dependency set."""

    version: str = Field(min_length=1, max_length=100)
    filename: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}\.whl$")
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class SupervisorV3ProtocolPinConfig(SupervisorV2ProtocolPinConfig):
    """Exact stable SDK, Python, runtime, and schema selection for v3."""

    sdk_version: Literal["0.147.0"] = "0.147.0"
    runtime_package_version: Literal["0.147.0"] = "0.147.0"
    python_version: str = Field(pattern=r"^3\.(?:1[0-9]|[2-9][0-9])\.[0-9]+$")
    sdk_python_path: Path
    artifact_dir: Path
    artifacts: dict[str, SupervisorV3ArtifactPinConfig] = Field(min_length=1)

    @field_validator("artifacts")
    @classmethod
    def validate_artifacts(
        cls, value: dict[str, SupervisorV3ArtifactPinConfig]
    ) -> dict[str, SupervisorV3ArtifactPinConfig]:
        if len(value) != len({artifact.filename for artifact in value.values()}):
            raise ValueError("Supervisor v3 artifact filenames must be unique")
        return value


class SupervisorV3SuccessorPredecessorConfig(BaseModel):
    """Exact failed v3 canary receipt that the successor is allowed to address."""

    task_id: str = Field(
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    )
    plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    envelope_chain_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    failure_method: Literal["remoteControl/status/changed"] = (
        "remoteControl/status/changed"
    )


class SupervisorV3RecoveryPredecessorConfig(BaseModel):
    """Exact failed fixture receipt that the recovery lineage may address."""

    task_id: str = Field(
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    )
    plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    envelope_chain_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    failure_method: Literal["remoteControl/status/changed"] = (
        "remoteControl/status/changed"
    )


class SupervisorV3PolicyConfig(BaseModel):
    """Fail-closed authority for the separately commissioned v3 pilot."""

    version: Literal[3] = 3
    background_execution: Literal[False] = False
    live_canary_execution: bool = False
    live_successor_canary_execution: bool = False
    live_fixture_execution: bool = False
    live_recovery_canary_execution: bool = False
    live_recovery_fixture_execution: bool = False
    canonical_mutations: Literal[False] = False
    command_network_access: Literal[False] = False
    experimental_api: Literal[False] = False
    driver: Literal["python_sdk"] = "python_sdk"
    model: Literal["gpt-5.6-sol"] = "gpt-5.6-sol"
    reasoning_effort: Literal["low"] = "low"
    max_attempts_per_stage: int = Field(default=1, ge=1, le=1)
    canary_attempts_total: int = Field(default=1, ge=1, le=1)
    successor_canary_attempts_total: int = Field(default=1, ge=1, le=1)
    fixture_attempts_total: int = Field(default=1, ge=1, le=1)
    recovery_canary_attempts_total: int = Field(default=1, ge=1, le=1)
    recovery_fixture_attempts_total: int = Field(default=1, ge=1, le=1)
    turn_timeout_seconds: int = Field(default=180, ge=30, le=180)
    plan_ttl_seconds: int = Field(default=1_800, ge=60, le=3_600)
    max_protocol_line_bytes: int = Field(default=1_048_576, ge=1_024, le=1_048_576)
    max_protocol_events: int = Field(default=10_000, ge=100, le=10_000)
    canary_prompt: Literal[
        "Reply with exactly ATLAS_V3_CANARY_OK. Do not inspect files, run commands, "
        "use tools, or make changes."
    ] = (
        "Reply with exactly ATLAS_V3_CANARY_OK. Do not inspect files, run commands, "
        "use tools, or make changes."
    )
    canary_expected_response: Literal["ATLAS_V3_CANARY_OK"] = "ATLAS_V3_CANARY_OK"
    successor_canary_prompt: Literal[
        "Reply with exactly ATLAS_V3_SUCCESSOR_CANARY_OK. Do not inspect files, run "
        "commands, use tools, or make changes."
    ] = (
        "Reply with exactly ATLAS_V3_SUCCESSOR_CANARY_OK. Do not inspect files, run "
        "commands, use tools, or make changes."
    )
    successor_canary_expected_response: Literal["ATLAS_V3_SUCCESSOR_CANARY_OK"] = (
        "ATLAS_V3_SUCCESSOR_CANARY_OK"
    )
    recovery_canary_prompt: Literal[
        "Reply with exactly ATLAS_V3_RECOVERY_CANARY_OK. Do not inspect files, run "
        "commands, use tools, or make changes."
    ] = (
        "Reply with exactly ATLAS_V3_RECOVERY_CANARY_OK. Do not inspect files, run "
        "commands, use tools, or make changes."
    )
    recovery_canary_expected_response: Literal["ATLAS_V3_RECOVERY_CANARY_OK"] = (
        "ATLAS_V3_RECOVERY_CANARY_OK"
    )
    successor_predecessor: SupervisorV3SuccessorPredecessorConfig
    recovery_predecessor: SupervisorV3RecoveryPredecessorConfig
    classifier_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    sdk_lock_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    protocol_pin: SupervisorV3ProtocolPinConfig
    recipes: dict[str, SupervisorV2RecipeConfig] = Field(default_factory=dict)

    @model_validator(mode="after")
    def require_fixed_stages_and_recipe(self) -> "SupervisorV3PolicyConfig":
        if set(self.recipes) != {"fixture-small-bugfix"}:
            raise ValueError("Supervisor v3 requires exactly the fixed fixture recipe")
        if self.live_canary_execution and self.live_successor_canary_execution:
            raise ValueError("Original and successor canary gates cannot be open together")
        if self.live_fixture_execution and not self.live_successor_canary_execution:
            raise ValueError("Supervisor v3 fixture execution requires the successor gate")
        if self.live_recovery_canary_execution and self.live_recovery_fixture_execution:
            raise ValueError("Recovery canary and recovery fixture gates cannot be open together")
        if self.live_fixture_execution and (
            self.live_recovery_canary_execution or self.live_recovery_fixture_execution
        ):
            raise ValueError("Legacy and recovery fixture gates cannot be open together")
        return self


class SupervisorV3Config(BaseModel):
    """Control-plane owner authority for separately authorized v3 stages."""

    enabled: bool = False
    fixture_owner_authorized: bool = False
    recovery_canary_owner_authorized: bool = False
    recovery_fixture_owner_authorized: bool = False
    runtime_dir: Path = Path("data/supervisor-v3")
    max_tasks: int = Field(default=10_000, ge=100, le=1_000_000)


class SupervisorV4ArtifactPinConfig(BaseModel):
    """One exact artifact used by the offline Supervisor v4 qualification."""

    version: str = Field(min_length=1, max_length=100)
    filename: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}\.whl$")
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class SupervisorV4ProtocolPinConfig(SupervisorV2ProtocolPinConfig):
    """Exact public SDK/runtime/schema surface inspected without a model turn."""

    sdk_version: Literal["0.147.0"] = "0.147.0"
    runtime_package_version: Literal["0.147.0"] = "0.147.0"
    python_version: str = Field(pattern=r"^3\.(?:1[0-9]|[2-9][0-9])\.[0-9]+$")
    sdk_python_path: Path
    artifact_dir: Path
    artifacts: dict[str, SupervisorV4ArtifactPinConfig] = Field(min_length=1)

    @field_validator("artifacts")
    @classmethod
    def validate_artifacts(
        cls, value: dict[str, SupervisorV4ArtifactPinConfig]
    ) -> dict[str, SupervisorV4ArtifactPinConfig]:
        if len(value) != len({artifact.filename for artifact in value.values()}):
            raise ValueError("Supervisor v4 artifact filenames must be unique")
        return value


class SupervisorV4PolicyConfig(BaseModel):
    """Non-live contract for the proposal-only Supervisor v4 implementation."""

    version: Literal[4] = 4
    implementation_state: Literal["implemented_inactive"] = "implemented_inactive"
    background_execution: Literal[False] = False
    live_model_execution: Literal[False] = False
    live_canary_execution: Literal[False] = False
    canonical_mutations: Literal[False] = False
    candidate_application: Literal[False] = False
    external_actions: Literal[False] = False
    command_network_access: Literal[False] = False
    model_side_commands: Literal[False] = False
    model_side_file_changes: Literal[False] = False
    model_side_tools: Literal[False] = False
    approval_requests: Literal[False] = False
    experimental_api: Literal[False] = False
    driver: Literal["python_sdk"] = "python_sdk"
    approval_mode: Literal["deny_all"] = "deny_all"
    proposal_sandbox: Literal["read_only_empty_root"] = "read_only_empty_root"
    candidate_mode: Literal["atlas_materialized_not_integrated"] = (
        "atlas_materialized_not_integrated"
    )
    data_egress_class: Literal["synthetic_fictional_bounded"] = (
        "synthetic_fictional_bounded"
    )
    credential_mode: Literal["brokered_short_lived_required"] = (
        "brokered_short_lived_required"
    )
    owner_policy_broker_required: Literal[True] = True
    trusted_platform_bootstrap_required: Literal[True] = True
    openai_codex_designated_requirement_required: Literal[True] = True
    capability_public_key_verification_required: Literal[True] = True
    exact_data_egress_manifest_required: Literal[True] = True
    credential_lease_signature_required: Literal[True] = True
    credential_revocation_required: Literal[True] = True
    signed_receipts_required: Literal[True] = True
    external_receipt_anchor_required: Literal[True] = True
    owner_kill_switch_required: Literal[True] = True
    max_event_depth: int = Field(default=8, ge=2, le=16)
    max_event_collection_items: int = Field(default=256, ge=16, le=2_048)
    max_event_bytes: int = Field(default=262_144, ge=1_024, le=1_048_576)
    max_changed_files: int = Field(default=1, ge=1, le=1)
    max_changed_lines: int = Field(default=20, ge=1, le=100)
    max_patch_bytes: int = Field(default=16_384, ge=1_024, le=65_536)
    protocol_inventory_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    sdk_lock_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    replay_corpus_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    protocol_pin: SupervisorV4ProtocolPinConfig


class SupervisorV4Config(BaseModel):
    """Status-only v4 controls; no live planning or execution switch exists."""

    enabled: bool = False
    offline_qualification_enabled: bool = False
    runtime_dir: Path = Path("data/supervisor-v4")
    pause_file: Path = Path("data/supervisor-v4.paused")
    same_user_broker_mode: Literal[
        "disabled", "offline_synthetic_qualification"
    ] = "disabled"
    same_user_broker_qualification_enabled: bool = False
    same_user_broker_runtime_dir: Path = Path("data/supervisor-v4-option1")
    owner_policy_broker_socket: Path | None = None
    owner_policy_verification_key_file: Path | None = None
    credential_broker_socket: Path | None = None
    credential_broker_verification_key_file: Path | None = None
    receipt_verification_key_file: Path | None = None
    receipt_anchor_broker_socket: Path | None = None
    receipt_anchor_verification_key_file: Path | None = None
    owner_kill_switch_socket: Path | None = None
    owner_kill_switch_verification_key_file: Path | None = None

    @model_validator(mode="after")
    def validate_same_user_broker_mode(self) -> SupervisorV4Config:
        expected_mode = (
            "offline_synthetic_qualification"
            if self.same_user_broker_qualification_enabled
            else "disabled"
        )
        if self.same_user_broker_mode != expected_mode:
            raise ValueError(
                "same_user_broker_mode must exactly match its qualification switch"
            )
        if self.same_user_broker_qualification_enabled and (
            not self.enabled or not self.offline_qualification_enabled
        ):
            raise ValueError(
                "same-user broker qualification requires Supervisor v4 offline qualification"
            )
        return self


GMAIL_MODIFY_SCOPE = "https://www.googleapis.com/auth/gmail.modify"
CALENDAR_OWNED_EVENTS_SCOPE = (
    "https://www.googleapis.com/auth/calendar.events.owned"
)
GOOGLE_WORKSPACE_SCOPES = [GMAIL_MODIFY_SCOPE, CALENDAR_OWNED_EVENTS_SCOPE]


class GoogleWorkspaceConfig(BaseModel):
    """Narrow Google Workspace connection for Atlas's first Day Manager gate."""

    enabled: bool = False
    expected_account: str | None = None
    calendar_id: str = "primary"
    time_zone: str = "America/New_York"
    keyring_service: str = "com.atlas.core.google-workspace"
    scopes: list[str] = Field(default_factory=lambda: list(GOOGLE_WORKSPACE_SCOPES))
    timeout_seconds: float = Field(default=30.0, ge=5, le=120)
    authorization_timeout_seconds: int = Field(default=300, ge=30, le=900)

    @field_validator("expected_account")
    @classmethod
    def validate_expected_account(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().lower()
        if "@" not in normalized or normalized.startswith("@") or normalized.endswith("@"):
            raise ValueError("expected_account must be a valid email address")
        return normalized

    @field_validator("calendar_id")
    @classmethod
    def require_primary_calendar(cls, value: str) -> str:
        if value != "primary":
            raise ValueError("The initial Google Workspace gate only supports the primary calendar")
        return value

    @field_validator("scopes")
    @classmethod
    def require_bounded_scopes(cls, value: list[str]) -> list[str]:
        if set(value) != set(GOOGLE_WORKSPACE_SCOPES) or len(value) != len(
            GOOGLE_WORKSPACE_SCOPES
        ):
            raise ValueError(
                "Google Workspace scopes must be exactly gmail.modify and calendar.events.owned"
            )
        return list(GOOGLE_WORKSPACE_SCOPES)


class PracticeConfig(BaseModel):
    """Explicit owner workspace; absent/disabled means no tools or filesystem changes."""
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    root: Path | None = None
    project: str = "atlas-selfdev"
    agent: str = "atlas-practice"
    background_enabled: bool = False

    @model_validator(mode="after")
    def require_explicit_root(self):
        if self.background_enabled and not self.enabled:
            raise ValueError("Background work requires enabled owner Practice")
        if self.enabled and (self.root is None or not self.root.is_absolute()):
            raise ValueError("Practice requires an explicit absolute owner workspace")
        return self


class AtlasConfig(BaseModel):
    app: AppConfig
    providers: dict[str, ProviderConfig]
    routing: RoutingConfig
    imports: ImportsConfig = Field(default_factory=ImportsConfig)
    backups: BackupsConfig = Field(default_factory=BackupsConfig)
    mac_inbox: MacInboxConfig = Field(default_factory=MacInboxConfig)
    phone_companion: PhoneCompanionConfig = Field(
        default_factory=PhoneCompanionConfig
    )
    development: DevelopmentRegistryConfig = Field(
        default_factory=DevelopmentRegistryConfig
    )
    research_journal: ResearchJournalConfig = Field(default_factory=ResearchJournalConfig)
    growth: GrowthConfig = Field(default_factory=GrowthConfig)
    practice: PracticeConfig = Field(default_factory=PracticeConfig)
    supervisor: SupervisorConfig = Field(default_factory=SupervisorConfig)
    supervisor_policy: SupervisorPolicyConfig = Field(
        default_factory=SupervisorPolicyConfig
    )
    supervisor_v2: SupervisorV2Config = Field(default_factory=SupervisorV2Config)
    supervisor_v2_policy: SupervisorV2PolicyConfig = Field(
        default_factory=SupervisorV2PolicyConfig
    )
    supervisor_v3: SupervisorV3Config = Field(default_factory=SupervisorV3Config)
    supervisor_v3_policy: SupervisorV3PolicyConfig | None = None
    supervisor_v4: SupervisorV4Config = Field(default_factory=SupervisorV4Config)
    supervisor_v4_policy: SupervisorV4PolicyConfig | None = None
    google_workspace: GoogleWorkspaceConfig = Field(
        default_factory=GoogleWorkspaceConfig
    )
    config_path: Path
    project_root: Path

    @property
    def database_path(self) -> Path:
        return self.app.data_dir / self.app.database_name


def _load_dotenv(path: Path) -> None:
    """Load a predictable subset of .env syntax without overriding the process."""
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _expand_env_string(
    value: str,
    *,
    environment: Mapping[str, str] | None = None,
) -> str:
    def replace(match: re.Match[str]) -> str:
        name, default = match.group(1), match.group(2)
        current = os.getenv(name) if environment is None else environment.get(name)
        if current is not None and current != "":
            return current
        return "" if default is None else default

    return _ENV_PATTERN.sub(replace, value)


def _expand_env(
    value: Any,
    *,
    environment: Mapping[str, str] | None = None,
) -> Any:
    if isinstance(value, str):
        return _expand_env_string(value, environment=environment)
    if isinstance(value, list):
        return [_expand_env(item, environment=environment) for item in value]
    if isinstance(value, dict):
        return {
            key: _expand_env(item, environment=environment)
            for key, item in value.items()
        }
    return value


def _expand_user_path(value: Path, *, allow_ambient_home: bool) -> Path:
    if str(value).startswith("~") and not allow_ambient_home:
        raise ConfigurationError(
            "Environment-isolated configuration cannot use home-directory expansion"
        )
    return value.expanduser()


def _resolve_path(
    root: Path,
    value: Path,
    *,
    allow_ambient_home: bool = True,
) -> Path:
    expanded = _expand_user_path(value, allow_ambient_home=allow_ambient_home)
    return expanded.resolve() if expanded.is_absolute() else (root / expanded).resolve()


def _resolve_no_symlink_components(
    root: Path,
    value: Path,
    *,
    label: str,
    allow_ambient_home: bool = True,
) -> Path:
    """Resolve a control path only after rejecting every existing symlink component."""

    expanded = _expand_user_path(value, allow_ambient_home=allow_ambient_home)
    if ".." in expanded.parts:
        raise ConfigurationError(f"{label} cannot contain parent traversal")
    candidate = expanded if expanded.is_absolute() else root / expanded
    absolute = candidate.absolute()
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current = current / component
        try:
            mode = os.lstat(current).st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode):
            raise ConfigurationError(f"{label} cannot contain a symbolic-link component")
    return absolute.resolve()


def _read_control_text_no_follow(path: Path, *, label: str) -> str:
    base_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    directory_flags = (
        base_flags
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    directory_descriptor = os.open(path.anchor, directory_flags)
    descriptor: int | None = None
    try:
        for component in path.parts[1:-1]:
            next_descriptor = os.open(
                component,
                directory_flags,
                dir_fd=directory_descriptor,
            )
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        descriptor = os.open(
            path.name,
            base_flags | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_descriptor,
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or metadata.st_size > 4 * 1024 * 1024
        ):
            raise ConfigurationError(f"{label} ownership, mode, or size is unsafe")
        content = bytearray()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            content.extend(chunk)
            if len(content) > 4 * 1024 * 1024:
                raise ConfigurationError(f"{label} is too large")
        return bytes(content).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigurationError(f"{label} is unavailable or invalid") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory_descriptor)


def load_config(
    config_path: str | Path = "config/atlas.yaml",
    *,
    load_dotenv_file: bool = False,
    environment: Mapping[str, str] | None = None,
) -> AtlasConfig:
    """Load Atlas configuration.

    Ordinary callers retain process-environment behavior. Repository dotenv is disabled. A caller
    that supplies an explicit environment and disables dotenv receives a
    deterministic configuration projection without ambient environment reads.
    """

    candidate_path = Path(config_path)
    if environment is not None and str(candidate_path).startswith("~"):
        raise ConfigurationError(
            "Environment-isolated configuration path cannot use home-directory expansion"
        )
    path = candidate_path.expanduser().resolve()
    if not path.exists():
        raise ConfigurationError(f"Config file not found: {path}")

    tentative_root = path.parent.parent if path.parent.name == "config" else path.parent
    from atlas_core.private_owner import (
        REPOSITORY_ROOT, PrivateOwnerError, configure_owner_environment, prepare_private_state,
    )
    try:
        if environment is None:
            configure_owner_environment(repository_root=tentative_root)
    except PrivateOwnerError as exc:
        raise ConfigurationError(str(exc)) from None
    if load_dotenv_file:
        raise ConfigurationError("Repository-local credential loading is disabled; select an external owner file.")

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"Invalid YAML in {path}: {exc}") from exc

    if raw.get("release_candidate_public_template") is True:
        selected_environment = os.environ if environment is None else environment
        state_root = selected_environment.get("ATLAS_PRIVATE_ROOT", "")
        try:
            if not state_root:
                raise PrivateOwnerError("private_state_root_required")
            prepare_private_state(state_root, repository_root=tentative_root)
        except PrivateOwnerError as exc:
            raise ConfigurationError(str(exc)) from None
    expanded = _expand_env(raw, environment=environment)
    if isinstance(expanded.get("google_workspace"), dict) and expanded["google_workspace"].get("expected_account") == "":
        expanded["google_workspace"]["expected_account"] = None
    try:
        app = AppConfig.model_validate(expanded.get("app", {}))
        providers = {
            name: ProviderConfig.model_validate(provider)
            for name, provider in expanded.get("providers", {}).items()
        }
        routing = RoutingConfig.model_validate(expanded.get("routing", {}))
        imports = ImportsConfig.model_validate(expanded.get("imports", {}))
        backups = BackupsConfig.model_validate(expanded.get("backups", {}))
        mac_inbox = MacInboxConfig.model_validate(expanded.get("mac_inbox", {}))
        phone_companion = PhoneCompanionConfig.model_validate(
            expanded.get("phone_companion", {})
        )
        growth = GrowthConfig.model_validate(expanded.get("growth", {}))
        practice = PracticeConfig.model_validate(expanded.get("practice", {}))
        research_journal = ResearchJournalConfig.model_validate(
            expanded.get("research_journal", {})
        )
        supervisor = SupervisorConfig.model_validate(expanded.get("supervisor", {}))
        supervisor_v2 = SupervisorV2Config.model_validate(
            expanded.get("supervisor_v2", {})
        )
        supervisor_v3 = SupervisorV3Config.model_validate(
            expanded.get("supervisor_v3", {})
        )
        supervisor_v4 = SupervisorV4Config.model_validate(
            expanded.get("supervisor_v4", {})
        )
        google_workspace = GoogleWorkspaceConfig.model_validate(
            expanded.get("google_workspace", {})
        )
    except ValidationError:
        raise ConfigurationError("configuration_validation_failed; private input values withheld") from None

    allow_ambient_home = environment is None
    owner_home = (
        Path.home().resolve()
        if allow_ambient_home
        else Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True)
    )

    project_root = _resolve_path(
        path.parent,
        app.root_dir,
        allow_ambient_home=allow_ambient_home,
    )
    app.root_dir = project_root
    app.data_dir = _resolve_path(
        project_root, app.data_dir, allow_ambient_home=allow_ambient_home
    )
    app.identity_dir = _resolve_path(
        project_root, app.identity_dir, allow_ambient_home=allow_ambient_home
    )
    app.workspace_dir = _resolve_path(
        project_root, app.workspace_dir, allow_ambient_home=allow_ambient_home
    )
    app.permissions_file = _resolve_path(
        project_root, app.permissions_file, allow_ambient_home=allow_ambient_home
    )
    app.agents_file = _resolve_path(
        project_root, app.agents_file, allow_ambient_home=allow_ambient_home
    )
    app.development_projects_file = _resolve_path(
        project_root,
        app.development_projects_file,
        allow_ambient_home=allow_ambient_home,
    )
    app.supervisor_policy_file = _resolve_path(
        project_root,
        app.supervisor_policy_file,
        allow_ambient_home=allow_ambient_home,
    )
    app.supervisor_v2_policy_file = _resolve_path(
        project_root,
        app.supervisor_v2_policy_file,
        allow_ambient_home=allow_ambient_home,
    )
    app.supervisor_v3_policy_file = _resolve_path(
        project_root,
        app.supervisor_v3_policy_file,
        allow_ambient_home=allow_ambient_home,
    )
    app.supervisor_v3_classifier_file = _resolve_path(
        project_root,
        app.supervisor_v3_classifier_file,
        allow_ambient_home=allow_ambient_home,
    )
    app.supervisor_v3_lock_file = _resolve_path(
        project_root,
        app.supervisor_v3_lock_file,
        allow_ambient_home=allow_ambient_home,
    )
    app.supervisor_v4_contract_file = _resolve_no_symlink_components(
        project_root,
        app.supervisor_v4_contract_file,
        label="Supervisor v4 contract",
        allow_ambient_home=allow_ambient_home,
    )
    app.supervisor_v4_protocol_file = _resolve_no_symlink_components(
        project_root,
        app.supervisor_v4_protocol_file,
        label="Supervisor v4 protocol",
        allow_ambient_home=allow_ambient_home,
    )
    app.supervisor_v4_lock_file = _resolve_no_symlink_components(
        project_root,
        app.supervisor_v4_lock_file,
        label="Supervisor v4 SDK lock",
        allow_ambient_home=allow_ambient_home,
    )
    app.supervisor_v4_replay_file = _resolve_no_symlink_components(
        project_root,
        app.supervisor_v4_replay_file,
        label="Supervisor v4 replay corpus",
        allow_ambient_home=allow_ambient_home,
    )
    app.supervisor_v4_same_user_registry_file = _resolve_no_symlink_components(
        project_root,
        app.supervisor_v4_same_user_registry_file,
        label="Supervisor v4 same-user registry",
        allow_ambient_home=allow_ambient_home,
    )
    api_token = (
        os.getenv("ATLAS_API_TOKEN")
        if environment is None
        else environment.get("ATLAS_API_TOKEN")
    )
    app.api_token = api_token or app.api_token

    mac_inbox.root = _resolve_path(
        project_root, mac_inbox.root, allow_ambient_home=allow_ambient_home
    )
    mac_inbox.recovery_dir = _resolve_path(
        project_root, mac_inbox.recovery_dir, allow_ambient_home=allow_ambient_home
    )
    mac_inbox.preview_dir = _resolve_path(
        project_root, mac_inbox.preview_dir, allow_ambient_home=allow_ambient_home
    )
    mac_inbox.pause_file = _resolve_path(
        project_root, mac_inbox.pause_file, allow_ambient_home=allow_ambient_home
    )
    if mac_inbox.enabled:
        home = owner_home
        filesystem_root = Path(mac_inbox.root.anchor).resolve()
        documents = (home / "Documents").resolve()
        if mac_inbox.root in {filesystem_root, home, documents, project_root}:
            raise ConfigurationError(
                f"Mac Inbox root is too broad: {mac_inbox.root}"
            )
        for control_path in (
            mac_inbox.recovery_dir,
            mac_inbox.preview_dir,
            mac_inbox.pause_file,
        ):
            if (
                control_path == mac_inbox.root
                or control_path in mac_inbox.root.parents
                or mac_inbox.root in control_path.parents
            ):
                raise ConfigurationError(
                    "Mac Inbox control paths must remain outside the approved inbox root"
                )

    phone_companion.state_file = _resolve_path(
        project_root,
        phone_companion.state_file,
        allow_ambient_home=allow_ambient_home,
    )
    phone_companion.pause_file = _resolve_path(
        project_root,
        phone_companion.pause_file,
        allow_ambient_home=allow_ambient_home,
    )
    if phone_companion.enabled:
        for control_path in (
            phone_companion.state_file,
            phone_companion.pause_file,
        ):
            if control_path == app.workspace_dir or app.workspace_dir in control_path.parents:
                raise ConfigurationError(
                    "Phone companion controls must remain outside the model-writable workspace"
                )
            if control_path == app.identity_dir or app.identity_dir in control_path.parents:
                raise ConfigurationError(
                    "Phone companion controls must remain outside portable identity files"
                )

    development = DevelopmentRegistryConfig()
    if app.development_projects_file.exists():
        try:
            raw_development = (
                yaml.safe_load(
                    app.development_projects_file.read_text(encoding="utf-8")
                )
                or {}
            )
            development = DevelopmentRegistryConfig.model_validate(
                _expand_env(raw_development, environment=environment)
            )
        except (OSError, yaml.YAMLError, ValidationError) as exc:
            raise ConfigurationError(
                f"Invalid development project registry in "
                f"{app.development_projects_file}: {exc}"
            ) from exc
        roots: dict[Path, str] = {}
        for slug, registered in development.projects.items():
            registered.root = _resolve_path(
                app.development_projects_file.parent,
                registered.root,
                allow_ambient_home=allow_ambient_home,
            )
            if registered.root in {
                Path(registered.root.anchor).resolve(),
                owner_home,
            }:
                raise ConfigurationError(
                    f"Registered project '{slug}' root is too broad: {registered.root}"
                )
            duplicate = roots.get(registered.root)
            if duplicate is not None:
                raise ConfigurationError(
                    f"Registered projects '{duplicate}' and '{slug}' use the same root"
                )
            roots[registered.root] = slug

    for slug, directory in research_journal.projects.items():
        if slug not in development.projects:
            raise ConfigurationError("Research journal project must be registered")
        if directory == owner_home:
            raise ConfigurationError("Research journal directory must not be the owner home")
        # Preserve the literal path: the reader opens every component without
        # following links. Resolving here would erase evidence of a symlink.

    supervisor.pause_file = _resolve_path(
        project_root,
        supervisor.pause_file,
        allow_ambient_home=allow_ambient_home,
    )
    supervisor_policy = SupervisorPolicyConfig()
    if supervisor.enabled:
        if not app.supervisor_policy_file.exists():
            raise ConfigurationError(
                f"Supervisor policy file not found: {app.supervisor_policy_file}"
            )
        try:
            raw_supervisor_policy = (
                yaml.safe_load(
                    app.supervisor_policy_file.read_text(encoding="utf-8")
                )
                or {}
            )
            supervisor_policy = SupervisorPolicyConfig.model_validate(
                _expand_env(raw_supervisor_policy, environment=environment)
            )
        except (OSError, yaml.YAMLError, ValidationError) as exc:
            raise ConfigurationError(
                f"Invalid Supervisor policy in {app.supervisor_policy_file}: {exc}"
            ) from exc

        for control_path, label in (
            (app.supervisor_policy_file, "policy"),
            (supervisor.pause_file, "pause control"),
        ):
            for protected_root, protected_label in (
                (app.workspace_dir, "model-writable workspace"),
                (app.identity_dir, "portable identity"),
            ):
                if control_path == protected_root or protected_root in control_path.parents:
                    raise ConfigurationError(
                        f"Supervisor {label} must remain outside the {protected_label}"
                    )
            for slug, registered in development.projects.items():
                if control_path == registered.root or registered.root in control_path.parents:
                    raise ConfigurationError(
                        f"Supervisor {label} must remain outside registered project '{slug}'"
                    )

        for slug, project_policy in supervisor_policy.projects.items():
            registered = development.projects.get(slug)
            if registered is None:
                raise ConfigurationError(
                    f"Supervisor project is not in the development registry: {slug}"
                )
            if project_policy.allow_status and "status" not in registered.allowed_actions:
                raise ConfigurationError(
                    f"Supervisor status is not enabled in the development registry: {slug}"
                )
            unknown_checks = sorted(
                set(project_policy.allowed_checks) - set(registered.checks)
            )
            if unknown_checks:
                raise ConfigurationError(
                    f"Supervisor policy has unknown checks for {slug}: "
                    f"{', '.join(unknown_checks)}"
                )
            if project_policy.allowed_checks and "run_check" not in registered.allowed_actions:
                raise ConfigurationError(
                    f"Supervisor checks are not enabled in the development registry: {slug}"
                )

    supervisor_v2.runtime_dir = _resolve_path(
        project_root,
        supervisor_v2.runtime_dir,
        allow_ambient_home=allow_ambient_home,
    )
    supervisor_v2_policy = SupervisorV2PolicyConfig()
    if supervisor_v2.enabled:
        if not app.supervisor_v2_policy_file.exists():
            raise ConfigurationError(
                f"Supervisor v2 policy file not found: {app.supervisor_v2_policy_file}"
            )
        try:
            raw_supervisor_v2_policy = (
                yaml.safe_load(
                    app.supervisor_v2_policy_file.read_text(encoding="utf-8")
                )
                or {}
            )
            supervisor_v2_policy = SupervisorV2PolicyConfig.model_validate(
                _expand_env(raw_supervisor_v2_policy, environment=environment)
            )
        except (OSError, yaml.YAMLError, ValidationError) as exc:
            raise ConfigurationError(
                f"Invalid Supervisor v2 policy in "
                f"{app.supervisor_v2_policy_file}: {exc}"
            ) from exc

        if supervisor_v2_policy.protocol_pin is None:
            raise ConfigurationError("Supervisor v2 requires a pinned App Server protocol")
        supervisor_v2_policy.protocol_pin.binary_path = _resolve_path(
            project_root,
            supervisor_v2_policy.protocol_pin.binary_path,
            allow_ambient_home=allow_ambient_home,
        )

        for control_path, label in (
            (app.supervisor_v2_policy_file, "policy"),
            (supervisor_v2.runtime_dir, "runtime"),
        ):
            for protected_root, protected_label in (
                (app.workspace_dir, "model-writable workspace"),
                (app.identity_dir, "portable identity"),
            ):
                if control_path == protected_root or protected_root in control_path.parents:
                    raise ConfigurationError(
                        f"Supervisor v2 {label} must remain outside the {protected_label}"
                    )
            for slug, registered in development.projects.items():
                if control_path == registered.root or registered.root in control_path.parents:
                    raise ConfigurationError(
                        f"Supervisor v2 {label} must remain outside registered project '{slug}'"
                    )

        for slug, recipe in supervisor_v2_policy.recipes.items():
            registered = development.projects.get(recipe.project)
            if registered is None:
                raise ConfigurationError(
                    f"Supervisor v2 recipe '{slug}' project is not registered: "
                    f"{recipe.project}"
                )
            unknown_checks = sorted(set(recipe.verification_checks) - set(registered.checks))
            if unknown_checks:
                raise ConfigurationError(
                    f"Supervisor v2 recipe '{slug}' has unknown checks: "
                    f"{', '.join(unknown_checks)}"
                )
            if "run_check" not in registered.allowed_actions:
                raise ConfigurationError(
                    f"Supervisor v2 checks are not enabled for project: {recipe.project}"
                )

    supervisor_v3.runtime_dir = _resolve_path(
        project_root,
        supervisor_v3.runtime_dir,
        allow_ambient_home=allow_ambient_home,
    )
    supervisor_v3_policy: SupervisorV3PolicyConfig | None = None
    if supervisor_v3.enabled:
        for required, label in (
            (app.supervisor_v3_policy_file, "policy"),
            (app.supervisor_v3_classifier_file, "notification classifier"),
            (app.supervisor_v3_lock_file, "SDK lock"),
        ):
            if not required.is_file() or required.is_symlink():
                raise ConfigurationError(f"Supervisor v3 {label} file is unavailable: {required}")
        try:
            raw_supervisor_v3_policy = (
                yaml.safe_load(
                    app.supervisor_v3_policy_file.read_text(encoding="utf-8")
                )
                or {}
            )
            # Owner authority is deliberately separate from the integrity-sealed
            # runtime policy. Opening a later stage must not rewrite the policy
            # bytes already bound into the successful predecessor canary.
            raw_supervisor_v3_policy["live_fixture_execution"] = (
                supervisor_v3.fixture_owner_authorized
            )
            raw_supervisor_v3_policy["live_recovery_canary_execution"] = (
                supervisor_v3.recovery_canary_owner_authorized
            )
            raw_supervisor_v3_policy["live_recovery_fixture_execution"] = (
                supervisor_v3.recovery_fixture_owner_authorized
            )
            supervisor_v3_policy = SupervisorV3PolicyConfig.model_validate(
                _expand_env(raw_supervisor_v3_policy, environment=environment)
            )
        except (OSError, yaml.YAMLError, ValidationError) as exc:
            raise ConfigurationError(
                f"Invalid Supervisor v3 policy in {app.supervisor_v3_policy_file}: {exc}"
            ) from exc

        pin = supervisor_v3_policy.protocol_pin
        pin.binary_path = _resolve_path(
            project_root, pin.binary_path, allow_ambient_home=allow_ambient_home
        )
        pin.sdk_python_path = _resolve_path(
            project_root, pin.sdk_python_path, allow_ambient_home=allow_ambient_home
        )
        pin.artifact_dir = _resolve_path(
            project_root, pin.artifact_dir, allow_ambient_home=allow_ambient_home
        )
        for control_path, label in (
            (app.supervisor_v3_policy_file, "policy"),
            (app.supervisor_v3_classifier_file, "classifier"),
            (app.supervisor_v3_lock_file, "SDK lock"),
            (supervisor_v3.runtime_dir, "runtime"),
        ):
            for protected_root, protected_label in (
                (app.workspace_dir, "model-writable workspace"),
                (app.identity_dir, "portable identity"),
            ):
                if control_path == protected_root or protected_root in control_path.parents:
                    raise ConfigurationError(
                        f"Supervisor v3 {label} must remain outside the {protected_label}"
                    )
            for slug, registered in development.projects.items():
                if control_path == registered.root or registered.root in control_path.parents:
                    raise ConfigurationError(
                        f"Supervisor v3 {label} must remain outside registered project '{slug}'"
                    )
        for slug, recipe in supervisor_v3_policy.recipes.items():
            registered = development.projects.get(recipe.project)
            if registered is None:
                raise ConfigurationError(
                    f"Supervisor v3 recipe '{slug}' project is not registered: {recipe.project}"
                )
            unknown_checks = sorted(set(recipe.verification_checks) - set(registered.checks))
            if unknown_checks or "run_check" not in registered.allowed_actions:
                raise ConfigurationError(
                    f"Supervisor v3 recipe '{slug}' has an invalid verification binding"
                )

    supervisor_v4.runtime_dir = _resolve_no_symlink_components(
        project_root,
        supervisor_v4.runtime_dir,
        label="Supervisor v4 runtime",
        allow_ambient_home=allow_ambient_home,
    )
    supervisor_v4.pause_file = _resolve_no_symlink_components(
        project_root,
        supervisor_v4.pause_file,
        label="Supervisor v4 pause control",
        allow_ambient_home=allow_ambient_home,
    )
    supervisor_v4.same_user_broker_runtime_dir = _resolve_no_symlink_components(
        project_root,
        supervisor_v4.same_user_broker_runtime_dir,
        label="Supervisor v4 same-user broker runtime",
        allow_ambient_home=allow_ambient_home,
    )
    supervisor_v4_policy: SupervisorV4PolicyConfig | None = None
    if supervisor_v4.enabled:
        required_v4_files = [
            (app.supervisor_v4_contract_file, "offline contract"),
            (app.supervisor_v4_protocol_file, "protocol inventory"),
            (app.supervisor_v4_lock_file, "SDK lock"),
            (app.supervisor_v4_replay_file, "replay corpus"),
        ]
        if supervisor_v4.same_user_broker_qualification_enabled:
            required_v4_files.append(
                (
                    app.supervisor_v4_same_user_registry_file,
                    "same-user task registry",
                )
            )
        for required, label in required_v4_files:
            if not required.is_file() or required.is_symlink():
                raise ConfigurationError(
                    f"Supervisor v4 {label} file is unavailable: {required}"
                )
        try:
            raw_supervisor_v4_policy = (
                yaml.safe_load(
                    _read_control_text_no_follow(
                        app.supervisor_v4_contract_file,
                        label="Supervisor v4 offline contract",
                    )
                )
                or {}
            )
            supervisor_v4_policy = SupervisorV4PolicyConfig.model_validate(
                _expand_env(raw_supervisor_v4_policy, environment=environment)
            )
        except (OSError, yaml.YAMLError, ValidationError) as exc:
            raise ConfigurationError(
                f"Invalid Supervisor v4 offline contract in "
                f"{app.supervisor_v4_contract_file}: {exc}"
            ) from exc

        pin = supervisor_v4_policy.protocol_pin
        pin.binary_path = _resolve_path(
            project_root, pin.binary_path, allow_ambient_home=allow_ambient_home
        )
        pin.sdk_python_path = _resolve_path(
            project_root, pin.sdk_python_path, allow_ambient_home=allow_ambient_home
        )
        pin.artifact_dir = _resolve_path(
            project_root, pin.artifact_dir, allow_ambient_home=allow_ambient_home
        )

        protected_controls = [
            (app.supervisor_v4_contract_file, "offline contract"),
            (app.supervisor_v4_protocol_file, "protocol inventory"),
            (app.supervisor_v4_lock_file, "SDK lock"),
            (app.supervisor_v4_replay_file, "replay corpus"),
            (supervisor_v4.runtime_dir, "runtime"),
            (supervisor_v4.pause_file, "pause control"),
        ]
        if supervisor_v4.same_user_broker_qualification_enabled:
            protected_controls.extend(
                [
                    (
                        app.supervisor_v4_same_user_registry_file,
                        "same-user task registry",
                    ),
                    (
                        supervisor_v4.same_user_broker_runtime_dir,
                        "same-user broker runtime",
                    ),
                ]
            )
        for control_path, label in protected_controls:
            for protected_root, protected_label in (
                (app.workspace_dir, "model-writable workspace"),
                (app.identity_dir, "portable identity"),
            ):
                if control_path == protected_root or protected_root in control_path.parents:
                    raise ConfigurationError(
                        f"Supervisor v4 {label} must remain outside the "
                        f"{protected_label}"
                    )
            for slug, registered in development.projects.items():
                if control_path == registered.root or registered.root in control_path.parents:
                    raise ConfigurationError(
                        f"Supervisor v4 {label} must remain outside registered "
                        f"project '{slug}'"
                    )

        external_controls = (
            (
                "owner_policy_broker_socket",
                supervisor_v4.owner_policy_broker_socket,
                "owner policy broker",
            ),
            (
                "owner_policy_verification_key_file",
                supervisor_v4.owner_policy_verification_key_file,
                "owner policy verification key",
            ),
            (
                "credential_broker_socket",
                supervisor_v4.credential_broker_socket,
                "credential broker",
            ),
            (
                "credential_broker_verification_key_file",
                supervisor_v4.credential_broker_verification_key_file,
                "credential broker verification key",
            ),
            (
                "receipt_verification_key_file",
                supervisor_v4.receipt_verification_key_file,
                "receipt verification key",
            ),
            (
                "receipt_anchor_broker_socket",
                supervisor_v4.receipt_anchor_broker_socket,
                "receipt anchor broker",
            ),
            (
                "receipt_anchor_verification_key_file",
                supervisor_v4.receipt_anchor_verification_key_file,
                "receipt anchor verification key",
            ),
            (
                "owner_kill_switch_socket",
                supervisor_v4.owner_kill_switch_socket,
                "owner kill-switch oracle",
            ),
            (
                "owner_kill_switch_verification_key_file",
                supervisor_v4.owner_kill_switch_verification_key_file,
                "owner kill-switch verification key",
            ),
        )
        for attribute, external_path, label in external_controls:
            if external_path is None:
                continue
            if not external_path.is_absolute():
                raise ConfigurationError(
                    f"Supervisor v4 {label} must use an absolute external path"
                )
            unresolved_external = _expand_user_path(
                external_path,
                allow_ambient_home=allow_ambient_home,
            )
            resolved = _resolve_no_symlink_components(
                Path(unresolved_external.anchor),
                unresolved_external,
                label=f"Supervisor v4 {label}",
                allow_ambient_home=allow_ambient_home,
            )
            if resolved == project_root or project_root in resolved.parents:
                raise ConfigurationError(
                    f"Supervisor v4 {label} must remain outside the Atlas checkout"
                )
            for slug, registered in development.projects.items():
                if resolved == registered.root or registered.root in resolved.parents:
                    raise ConfigurationError(
                        f"Supervisor v4 {label} must remain outside registered "
                        f"project '{slug}'"
                    )
            setattr(supervisor_v4, attribute, resolved)

    if not providers:
        raise ConfigurationError("At least one model provider must be configured")
    if routing.default_provider not in providers:
        raise ConfigurationError(
            f"Default provider '{routing.default_provider}' is not configured"
        )
    for name in routing.fallback_providers:
        if name not in providers:
            raise ConfigurationError(f"Fallback provider '{name}' is not configured")
    for name, provider in providers.items():
        if provider.kind != "mock" and not provider.base_url:
            raise ConfigurationError(f"Provider '{name}' requires base_url")

    app.data_dir.mkdir(parents=True, exist_ok=True)
    app.identity_dir.mkdir(parents=True, exist_ok=True)
    app.workspace_dir.mkdir(parents=True, exist_ok=True)

    return AtlasConfig(
        app=app,
        providers=providers,
        routing=routing,
        imports=imports,
        backups=backups,
        mac_inbox=mac_inbox,
        phone_companion=phone_companion,
        development=development,
        research_journal=research_journal,
        growth=growth,
        practice=practice,
        supervisor=supervisor,
        supervisor_policy=supervisor_policy,
        supervisor_v2=supervisor_v2,
        supervisor_v2_policy=supervisor_v2_policy,
        supervisor_v3=supervisor_v3,
        supervisor_v3_policy=supervisor_v3_policy,
        supervisor_v4=supervisor_v4,
        supervisor_v4_policy=supervisor_v4_policy,
        google_workspace=google_workspace,
        config_path=path,
        project_root=project_root,
    )


def load_config_without_environment(
    config_path: str | Path = "config/atlas.yaml",
) -> AtlasConfig:
    """Load fixed-file configuration without dotenv or ambient environment input."""

    return load_config(
        config_path,
        load_dotenv_file=False,
        environment={},
    )
