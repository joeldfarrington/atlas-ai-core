from __future__ import annotations

from typing import Any, Literal

from pydantic import AliasChoices, BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class ChatRequest(StrictModel):
    request_id: str | None = Field(default=None, min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
    message: str = Field(min_length=1, max_length=200_000)
    conversation_id: str | None = None
    provider: str | None = None
    model: str | None = None
    project_slug: str | None = None
    agent_slug: str | None = Field(
        default=None,
        validation_alias=AliasChoices("agent_slug", "agent_id"),
    )
    local_only: bool = True
    tools_enabled: bool = True


class ResearchJournalNoteReceipt(StrictModel):
    filename: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}(?:-[A-Za-z0-9][A-Za-z0-9_-]{0,79})?\.json$", max_length=96)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ResearchJournalReceipt(StrictModel):
    status: Literal["disabled", "out_of_scope", "loaded", "empty", "unavailable", "invalid"] = "disabled"
    notes: list[ResearchJournalNoteReceipt] = Field(default_factory=list, max_length=5)


class LearningReceipt(StrictModel):
    status: Literal["disabled", "out_of_scope", "loaded", "empty"] = "disabled"
    outcome_count: int = Field(default=0, ge=0, le=5, strict=True)


class ChatResponse(StrictModel):
    run_id: str
    status: str
    conversation_id: str
    message_id: str | None = None
    content: str = ""
    provider: str | None = None
    model: str | None = None
    agent_slug: str
    project_slug: str | None = None
    memory_ids: list[int] = Field(default_factory=list)
    research_journal: ResearchJournalReceipt = Field(default_factory=ResearchJournalReceipt)
    learning: LearningReceipt = Field(default_factory=LearningReceipt)
    approval: dict[str, Any] | None = None
    error: str | None = None


class ConversationCreate(StrictModel):
    title: str | None = Field(default=None, max_length=500)
    project_slug: str | None = None
    agent_slug: str = Field(default="atlas", min_length=1, max_length=100)


class ConversationUpdate(StrictModel):
    title: str | None = Field(default=None, max_length=500)
    project_slug: str | None = None
    agent_slug: str | None = Field(default=None, min_length=1, max_length=100)
    archived: bool | None = None


# Retained for clients that used the preview name.
ConversationPatch = ConversationUpdate


class MemoryCreate(StrictModel):
    namespace: str = Field(default="global", min_length=1, max_length=100)
    kind: str = Field(default="note", min_length=1, max_length=100)
    key: str = Field(min_length=1, max_length=200)
    content: str = Field(min_length=1, max_length=500_000)
    importance: int = Field(default=5, ge=1, le=10)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProjectUpsert(StrictModel):
    slug: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,99}$")
    name: str = Field(min_length=1, max_length=200)
    status: str = Field(default="active", min_length=1, max_length=100)
    summary: str = Field(default="", max_length=200_000)
    next_action: str = Field(default="", max_length=50_000)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ToolExecuteRequest(StrictModel):
    tool: str = Field(min_length=1, max_length=100)
    action: str = Field(min_length=1, max_length=100)
    arguments: dict[str, Any] = Field(default_factory=dict)
    approval_id: str | None = None


class ApprovalDecisionRequest(StrictModel):
    decision: Literal["approved", "rejected"]
    note: str | None = Field(default=None, max_length=5_000)
    resume_run: bool = True


class BackupRequest(StrictModel):
    include_workspace: bool | None = None


class IdentityUpdate(StrictModel):
    content: str = Field(max_length=1_000_000)


class PermissionUpdate(StrictModel):
    content: str = Field(min_length=1, max_length=500_000)


class SupervisorPlanRequest(StrictModel):
    project: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")
    action: Literal["status", "run_check"]
    check: str | None = Field(default=None, min_length=1, max_length=100)


class SupervisorRunRequest(StrictModel):
    confirmation: Literal["RUN"]


class SupervisorRecoverRequest(StrictModel):
    confirmation: Literal["RECOVER"]


class SupervisorV2PlanRequest(StrictModel):
    # The API intentionally cannot supply a project, prompt, path, command,
    # model, or policy override. Expansion requires an owner-edited policy.
    recipe: Literal["fixture-small-bugfix"]


class SupervisorV2RunRequest(StrictModel):
    confirmation: str = Field(
        min_length=27,
        max_length=27,
        pattern=r"^APPLY [0-9a-f]{8} [0-9a-f]{12}$",
    )


class SupervisorV3RunRequest(StrictModel):
    confirmation: str = Field(
        min_length=30,
        max_length=32,
        pattern=(
            r"^(?:CANARY-V3(?:S|R)? [0-9a-f]{8} [0-9a-f]{12}|"
            r"APPLY-V3R? [0-9a-f]{8} [0-9a-f]{12})$"
        ),
    )


class ImportRequest(StrictModel):
    filename: str = Field(min_length=1, max_length=500)
    data_base64: str = Field(min_length=1)
    source: Literal["auto", "chatgpt", "atlas", "memory", "memories"] = "auto"
    project_slug: str | None = None
    dry_run: bool = False
