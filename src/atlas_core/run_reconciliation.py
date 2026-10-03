"""Read-only projections of durable receipts. These functions never execute work.

Execution status, verification and response delivery are separate facts. A saved
model answer is not proof that coding work passed independent acceptance.
"""
from __future__ import annotations


def reconcile_run(database, run, *, active=False):
    state = run.get("state") or {}
    status = run["status"]
    lifecycle = {
        "running": "RUNNING" if active else "OUTCOME_UNKNOWN",
        "unconfirmed": "OUTCOME_UNKNOWN", "awaiting_approval": "WAITING_FOR_HUMAN",
        "interrupted": "INTERRUPTED", "stopped": "INTERRUPTED", "cancelled": "INTERRUPTED",
        "cleanup_required": "BLOCKED", "failed": "FAILED", "rolled_back": "ROLLED_BACK",
    }.get(status, "OUTCOME_UNKNOWN")
    result = None
    verification = "not_applicable" if state.get("tools_enabled") is False else "unconfirmed"
    receipt = state.get("practice_verification") or {}
    if receipt.get("status") in {"passed", "failed"}:
        verification = receipt["status"]
    if status == "completed":
        message = database.get_message(state.get("last_message_id") or "")
        coherent = (message is not None and message["conversation_id"] == run["conversation_id"]
                    and message["role"] == "assistant"
                    and (message.get("metadata") or {}).get("run_id") == run["id"]
                    and not (message.get("metadata") or {}).get("tool_calls")
                    and state.get("pending_calls") == [] and not state.get("cleanup_required"))
        if coherent:
            result = {"run_id": run["id"], "status": status,
                      "conversation_id": run["conversation_id"], "message_id": message["id"],
                      "content": message["content"] or "The model returned no text.",
                      "agent_slug": run["agent_slug"], "project_slug": run.get("project_slug"),
                      "provider": run.get("provider"), "model": run.get("model"),
                      "memory_ids": state.get("memory_ids") or [],
                      "research_journal": state.get("research_journal") or {"status": "disabled", "notes": []},
                      "learning": state.get("learning") or {"status": "disabled", "outcome_count": 0},
                      "approval": None, "error": run.get("error")}
            lifecycle = "COMPLETE" if verification in {"passed", "not_applicable"} else (
                "FAILED" if verification == "failed" else "VERIFYING")
        else:
            lifecycle = "OUTCOME_UNKNOWN"
    terminal = status in {"completed", "failed", "interrupted", "stopped", "cancelled", "rolled_back"}
    can_continue = (terminal and lifecycle != "OUTCOME_UNKNOWN" and state.get("pending_calls") == []
                    and not state.get("cleanup_required")
                    and not (state.get("interruption") or {}).get("cleanup_required"))
    return {"lifecycle": lifecycle, "verification": verification, "result": result,
            "result_available": result is not None, "can_continue": can_continue,
            "replay_allowed": False, "observed_updated_at": run.get("updated_at")}
