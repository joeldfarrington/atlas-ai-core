from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from atlas_core.errors import ConfigurationError


@dataclass(frozen=True, slots=True)
class AgentProfile:
    """Portable agent profile loaded from config/agents.yaml."""

    slug: str
    name: str
    description: str
    instructions: str
    allowed_tools: tuple[str, ...]
    allowed_actions: tuple[str, ...]
    max_steps: int
    temperature: float
    provider: str | None = None
    model: str | None = None
    local_only: bool = False

    @property
    def id(self) -> str:
        """Compatibility alias used by older Atlas Core clients."""
        return self.slug

    @property
    def tools(self) -> tuple[str, ...]:
        """Human-readable combined scope used by API clients."""
        if self.allowed_actions:
            return self.allowed_actions
        return tuple(f"{name}.*" for name in self.allowed_tools)

    def allows(self, tool: str, action: str) -> bool:
        target = f"{tool}.{action}"
        if "*" in self.allowed_actions or target in self.allowed_actions:
            return True
        if f"{tool}.*" in self.allowed_actions:
            return True
        return "*" in self.allowed_tools or tool in self.allowed_tools

    def as_dict(self, *, default: bool = False) -> dict[str, Any]:
        return {
            "slug": self.slug,
            "id": self.slug,
            "name": self.name,
            "description": self.description,
            "instructions": self.instructions,
            "allowed_tools": list(self.allowed_tools),
            "allowed_actions": list(self.allowed_actions),
            "tools": list(self.tools),
            "max_steps": self.max_steps,
            "temperature": self.temperature,
            "provider": self.provider,
            "model": self.model,
            "local_only": self.local_only,
            "default": default,
        }


class AgentStore:
    """Loads inspectable, model-independent agent profiles from YAML."""

    def __init__(self, path: str | Path, *, global_max_steps: int = 12) -> None:
        self.path = Path(path).expanduser().resolve()
        self.global_max_steps = max(1, min(int(global_max_steps), 100))
        self.default_agent = "atlas"
        self._agents: dict[str, AgentProfile] = {}
        self.reload()

    def reload(self) -> None:
        if not self.path.exists():
            raise ConfigurationError(f"Agent configuration not found: {self.path}")
        try:
            raw = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ConfigurationError(f"Invalid agent YAML in {self.path}: {exc}") from exc

        if not isinstance(raw, dict):
            raise ConfigurationError("Agent configuration must be a YAML mapping")
        default_agent = str(raw.get("default_agent") or "atlas")
        raw_agents = raw.get("agents") or {}
        if not isinstance(raw_agents, dict) or not raw_agents:
            raise ConfigurationError("At least one agent profile must be configured")

        agents: dict[str, AgentProfile] = {}
        for raw_slug, value in raw_agents.items():
            slug = str(raw_slug)
            if not isinstance(value, dict):
                raise ConfigurationError(f"Agent '{slug}' must be a mapping")

            configured_steps = int(value.get("max_steps", self.global_max_steps))
            if configured_steps < 1 or configured_steps > 100:
                raise ConfigurationError(
                    f"Agent '{slug}' max_steps must be between 1 and 100"
                )
            temperature = float(value.get("temperature", 0.2))
            if not 0 <= temperature <= 2:
                raise ConfigurationError(
                    f"Agent '{slug}' temperature must be between 0 and 2"
                )

            explicit_tools = value.get("allowed_tools")
            legacy_tools = value.get("tools") if explicit_tools is None else None
            allowed_tools = explicit_tools if explicit_tools is not None else []
            allowed_actions = list(value.get("allowed_actions") or [])
            # v0.1 profiles used `tools` for both `filesystem` and
            # `filesystem.read` style entries. Preserve both forms.
            if legacy_tools is not None:
                if not isinstance(legacy_tools, list):
                    raise ConfigurationError(f"Agent '{slug}' tools must be an array")
                for item in legacy_tools:
                    text = str(item)
                    if "." in text:
                        allowed_actions.append(text)
                    else:
                        allowed_tools.append(text)
            if not isinstance(allowed_tools, list) or not isinstance(allowed_actions, list):
                raise ConfigurationError(
                    f"Agent '{slug}' allowed_tools and allowed_actions must be arrays"
                )

            agents[slug] = AgentProfile(
                slug=slug,
                name=str(value.get("name") or slug),
                description=str(value.get("description") or ""),
                instructions=str(value.get("instructions") or "").strip(),
                allowed_tools=tuple(str(item) for item in allowed_tools),
                allowed_actions=tuple(str(item) for item in allowed_actions),
                max_steps=min(configured_steps, self.global_max_steps),
                temperature=temperature,
                provider=(str(value["provider"]) if value.get("provider") else None),
                model=(str(value["model"]) if value.get("model") else None),
                local_only=bool(value.get("local_only", False)),
            )

        if default_agent not in agents:
            raise ConfigurationError(
                f"Default agent '{default_agent}' is not configured"
            )
        self.default_agent = default_agent
        self._agents = agents

    def get(self, slug: str | None = None) -> AgentProfile:
        selected = slug or self.default_agent
        try:
            return self._agents[selected]
        except KeyError as exc:
            raise KeyError(f"Agent not found: {selected}") from exc

    def list(self) -> list[dict[str, Any]]:
        return [
            profile.as_dict(default=profile.slug == self.default_agent)
            for profile in self._agents.values()
        ]


# Compatibility name retained for v0.1 integrations.
AgentRegistry = AgentStore
