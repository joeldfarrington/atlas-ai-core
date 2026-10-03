from __future__ import annotations

from typing import Any

from atlas_core.config import PhoneCompanionConfig
from atlas_core.errors import ToolError
from atlas_core.phone_companion import PhoneCompanionStateStore
from atlas_core.tools.base import Tool


class PhoneCompanionTool(Tool):
    """Read only a status receipt from the explicitly paired native phone bridge."""

    name = "phone_companion"

    def __init__(self, config: PhoneCompanionConfig) -> None:
        self.config = config
        self.store = PhoneCompanionStateStore(config)

    def status(self, arguments: dict[str, Any]) -> dict[str, Any]:
        if arguments:
            raise ToolError("phone_companion.status does not accept arguments")
        try:
            return self.store.status()
        except ValueError as exc:
            raise ToolError(str(exc)) from exc

    def execute(self, action: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if action != "status":
            raise ToolError(f"Unsupported phone companion action: {action}")
        return self.status(arguments)

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": (
                "Report only the latest read-only status receipt from Atlas's explicitly "
                "paired native iPhone companion. This tool cannot control the phone, open "
                "apps, read personal data, or perform a phone mutation."
            ),
            "actions": {
                "status": {
                    "description": (
                        "Report bridge, pairing, operating-system, app, and battery status "
                        "without changing the phone."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {},
                        "additionalProperties": False,
                    },
                }
            },
        }

    def audit_result(self, action: str, result: dict[str, Any]) -> dict[str, Any]:
        del action
        return {
            "bridge_active": result.get("bridge_active"),
            "device_connected": result.get("device_connected"),
            "device_model": result.get("device_model"),
            "os_name": result.get("os_name"),
            "os_version": result.get("os_version"),
            "app_version": result.get("app_version"),
            "status_fresh": result.get("status_fresh"),
        }
