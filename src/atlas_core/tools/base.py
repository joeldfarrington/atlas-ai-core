from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class Tool(ABC):
    name: str

    @abstractmethod
    def execute(self, action: str, arguments: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def describe(self) -> dict[str, Any]:
        """Return name, description, and per-action JSON Schemas."""
        raise NotImplementedError

    def audit_arguments(self, action: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Return the non-secret argument summary safe for the general audit trail."""
        del action
        return arguments

    def audit_result(self, action: str, result: dict[str, Any]) -> dict[str, Any]:
        """Return the non-secret result summary safe for the general audit trail."""
        del action
        return result

    def audit_error(self, action: str, error: Exception) -> str:
        """Return a non-secret error summary safe for the general audit trail."""
        del action
        return str(error)
