from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class AtlasError(Exception):
    """Base exception for expected Atlas Core failures."""


class ConfigurationError(AtlasError):
    pass


class ProviderError(AtlasError):
    pass


class ConnectorError(AtlasError):
    pass


class RunStateError(AtlasError):
    pass


class ImportFormatError(AtlasError):
    pass


class PermissionDenied(AtlasError):
    def __init__(self, tool: str, action: str, message: str | None = None) -> None:
        self.tool = tool
        self.action = action
        super().__init__(message or f"Permission denied for {tool}.{action}")


@dataclass(slots=True)
class ApprovalRequired(AtlasError):
    approval_id: str
    tool: str
    action: str
    arguments: dict[str, Any]

    def __str__(self) -> str:
        return f"Approval required for {self.tool}.{self.action} (approval_id={self.approval_id})"


class ApprovalError(AtlasError):
    pass


class ToolError(AtlasError):
    pass


class SupervisorError(AtlasError):
    pass
