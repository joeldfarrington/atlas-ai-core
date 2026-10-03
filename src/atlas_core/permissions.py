from __future__ import annotations

import shutil
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

from atlas_core.errors import ConfigurationError


class PermissionDecision(str, Enum):
    ALLOW = "allow"
    ASK = "ask"
    DENY = "deny"


class PermissionEngine:
    def __init__(self, policy_path: str | Path) -> None:
        self.policy_path = Path(policy_path).expanduser().resolve()
        self.default = PermissionDecision.DENY
        self.rules: dict[str, dict[str, PermissionDecision]] = {}
        self.reload()

    @staticmethod
    def _parse(text: str) -> tuple[PermissionDecision, dict[str, dict[str, PermissionDecision]]]:
        try:
            raw = yaml.safe_load(text) or {}
        except yaml.YAMLError as exc:
            raise ConfigurationError(f"Invalid permission YAML: {exc}") from exc
        try:
            default = PermissionDecision(str(raw.get("default", "deny")))
            rules: dict[str, dict[str, PermissionDecision]] = {}
            for tool, actions in (raw.get("tools") or {}).items():
                if not isinstance(actions, dict):
                    raise ValueError(f"Rules for tool '{tool}' must be a mapping")
                rules[str(tool)] = {
                    str(action): PermissionDecision(str(decision))
                    for action, decision in actions.items()
                }
        except (TypeError, ValueError) as exc:
            raise ConfigurationError(f"Invalid permission policy: {exc}") from exc
        return default, rules

    def reload(self) -> None:
        if not self.policy_path.exists():
            raise ConfigurationError(f"Permission policy not found: {self.policy_path}")
        self.default, self.rules = self._parse(
            self.policy_path.read_text(encoding="utf-8")
        )

    def raw(self) -> str:
        return self.policy_path.read_text(encoding="utf-8")

    def update(self, text: str) -> dict[str, Any]:
        default, rules = self._parse(text)
        backup_dir = self.policy_path.parent / ".versions"
        backup_dir.mkdir(exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        shutil.copy2(
            self.policy_path,
            backup_dir / f"{self.policy_path.name}.{timestamp}.bak",
        )
        temporary = self.policy_path.with_suffix(self.policy_path.suffix + ".tmp")
        temporary.write_text(text, encoding="utf-8")
        temporary.replace(self.policy_path)
        self.default, self.rules = default, rules
        return self.snapshot()

    def decision(self, tool: str, action: str) -> PermissionDecision:
        tool_rules = self.rules.get(tool, {})
        return tool_rules.get(action, tool_rules.get("*", self.default))

    def snapshot(self) -> dict[str, Any]:
        return {
            "policy_path": str(self.policy_path),
            "default": self.default.value,
            "tools": {
                tool: {action: decision.value for action, decision in actions.items()}
                for tool, actions in self.rules.items()
            },
        }
