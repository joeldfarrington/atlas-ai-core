from __future__ import annotations

from typing import Any

from atlas_core.errors import ApprovalError, ApprovalRequired, PermissionDenied, ToolError
from atlas_core.memory.database import Database, arguments_digest
from atlas_core.models import ToolDefinition
from atlas_core.permissions import PermissionDecision, PermissionEngine
from atlas_core.tools.base import Tool


class ToolManager:
    def __init__(
        self,
        *,
        database: Database,
        permissions: PermissionEngine,
        tools: list[Tool],
        constitution: Any | None = None,
    ) -> None:
        self.constitution = constitution
        self.database = database
        self.permissions = permissions
        self.tools = {tool.name: tool for tool in tools}
        self._function_map: dict[str, tuple[str, str]] = {}
        for tool in tools:
            for action in tool.describe().get("actions", {}):
                self._function_map[self.function_name(tool.name, action)] = (tool.name, action)

    @staticmethod
    def function_name(tool: str, action: str) -> str:
        return f"{tool}__{action}"

    def resolve_function(self, name: str) -> tuple[str, str]:
        resolved = self._function_map.get(name)
        if resolved is None:
            raise ToolError(f"Unknown model tool function: {name}")
        return resolved

    def model_tools(self, *, allows: Any | None = None) -> list[ToolDefinition]:
        definitions: list[ToolDefinition] = []
        for tool_name, tool in self.tools.items():
            description = tool.describe()
            for action, action_description in description.get("actions", {}).items():
                if allows is not None and not allows(tool_name, action):
                    continue
                if self.permissions.decision(tool_name, action) is PermissionDecision.DENY:
                    continue
                definitions.append(
                    ToolDefinition(
                        name=self.function_name(tool_name, action),
                        description=str(action_description.get("description") or f"{tool_name}.{action}"),
                        parameters=dict(action_description.get("parameters") or {"type": "object", "properties": {}}),
                        tool=tool_name,
                        action=action,
                    )
                )
        return definitions

    def describe(self) -> list[dict[str, Any]]:
        descriptions: list[dict[str, Any]] = []
        for name, tool in self.tools.items():
            description = tool.describe()
            for action, value in description.get("actions", {}).items():
                value["permission"] = self.permissions.decision(name, action).value
                value["function_name"] = self.function_name(name, action)
            descriptions.append(description)
        return descriptions

    def execute(
        self,
        *,
        tool_name: str,
        action: str,
        arguments: dict[str, Any],
        approval_id: str | None = None,
        actor: str = "operator",
        run_id: str | None = None,
        call_id: str | None = None,
        allows: Any | None = None,
    ) -> dict[str, Any]:
        if self.constitution is not None:
            self.constitution.check_current()
        self.permissions.reload()
        tool = self.tools.get(tool_name)
        if tool is None:
            raise ToolError(f"Unknown tool: {tool_name}")
        if allows is not None and not allows(tool_name, action):
            audit_arguments = tool.audit_arguments(action, arguments)
            self.database.audit(
                event_type="tool",
                actor=actor,
                action=f"{tool_name}.{action}",
                resource=tool_name,
                outcome="agent_scope_denied",
                details={"arguments": audit_arguments, "run_id": run_id},
            )
            raise PermissionDenied(tool_name, action, "Agent profile does not allow this tool action")

        decision = self.permissions.decision(tool_name, action)
        if decision is PermissionDecision.DENY:
            audit_arguments = tool.audit_arguments(action, arguments)
            self.database.audit(
                event_type="tool",
                actor=actor,
                action=f"{tool_name}.{action}",
                resource=tool_name,
                outcome="denied",
                details={"arguments": audit_arguments, "run_id": run_id},
            )
            raise PermissionDenied(tool_name, action)

        consumed_approval: str | None = None
        if decision is PermissionDecision.ASK:
            if not approval_id:
                approval = self.database.create_approval(
                    tool_name,
                    action,
                    arguments,
                    run_id=run_id,
                    call_id=call_id,
                )
                self.database.audit(
                    event_type="approval",
                    actor=actor,
                    action=f"request:{tool_name}.{action}",
                    resource=approval["id"],
                    outcome="pending",
                    details={
                        "arguments": tool.audit_arguments(action, arguments),
                        "run_id": run_id,
                        "call_id": call_id,
                    },
                )
                raise ApprovalRequired(
                    approval_id=approval["id"],
                    tool=tool_name,
                    action=action,
                    arguments=arguments,
                )
            approval = self.database.get_approval(approval_id)
            if approval is None:
                raise ApprovalError(f"Approval not found: {approval_id}")
            if approval["status"] != "approved":
                raise ApprovalError(f"Approval {approval_id} is {approval['status']}, not approved")
            if approval["tool"] != tool_name or approval["action"] != action:
                raise ApprovalError("Approval does not match the requested tool action")
            if approval["arguments_digest"] != arguments_digest(arguments):
                raise ApprovalError("Approval arguments do not match the requested arguments")
            if approval.get("run_id") != run_id:
                raise ApprovalError("Approval belongs to a different agent run")
            if approval.get("call_id") != call_id:
                raise ApprovalError("Approval belongs to a different tool call")
            consumed_approval = approval_id

        try:
            if self.constitution is not None:
                self.constitution.check_current()
            result = tool.execute(action, arguments)
        except Exception as exc:
            self.database.audit(
                event_type="tool",
                actor=actor,
                action=f"{tool_name}.{action}",
                resource=tool_name,
                outcome="failed",
                details={
                    "arguments": tool.audit_arguments(action, arguments),
                    "error": tool.audit_error(action, exc),
                    "run_id": run_id,
                },
            )
            raise

        if consumed_approval:
            self.database.mark_approval_executed(consumed_approval)
        self.database.audit(
            event_type="tool",
            actor=actor,
            action=f"{tool_name}.{action}",
            resource=tool_name,
            outcome="success",
            details={
                "arguments": tool.audit_arguments(action, arguments),
                "result": tool.audit_result(action, result),
                "run_id": run_id,
            },
        )
        return result

    def decide_approval(
        self, approval_id: str, decision: str, note: str | None = None
    ) -> dict[str, Any]:
        approval = self.database.decide_approval(approval_id, decision, note)
        self.database.audit(
            event_type="approval",
            actor="operator",
            action=f"decision:{approval['tool']}.{approval['action']}",
            resource=approval_id,
            outcome=decision,
            details={"note": note, "run_id": approval.get("run_id")},
        )
        return approval
