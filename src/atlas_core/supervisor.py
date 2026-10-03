from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from atlas_core.config import AtlasConfig, RegisteredDevelopmentProjectConfig
from atlas_core.errors import SupervisorError
from atlas_core.memory.database import Database, utc_now
from atlas_core.permissions import PermissionDecision, PermissionEngine
from atlas_core.tools.development import DevelopmentTool


class SupervisorService:
    """Manual, persistent execution for narrowly registered development checks."""

    RUN_CONFIRMATION = "RUN"
    RECOVER_CONFIRMATION = "RECOVER"
    TASK_KINDS = {"development.status", "development.run_check"}

    def __init__(
        self,
        *,
        config: AtlasConfig,
        database: Database,
        permissions: PermissionEngine,
        development: DevelopmentTool,
    ) -> None:
        self.config = config
        self.database = database
        self.permissions = permissions
        self.development = development
        self.pause_file = config.supervisor.pause_file

    @property
    def enabled(self) -> bool:
        return self.config.supervisor.enabled

    @property
    def paused(self) -> bool:
        return self.pause_file.exists()

    def _require_enabled(self) -> None:
        if not self.enabled:
            raise SupervisorError("Atlas Supervisor is disabled")

    def _require_ready(self) -> None:
        self._require_enabled()
        if self.paused:
            raise SupervisorError(
                "Atlas Supervisor is paused; resume it before running a task"
            )

    def _validate_action(
        self,
        *,
        project_slug: str,
        action: str,
        check_name: str | None,
    ) -> RegisteredDevelopmentProjectConfig:
        self._require_enabled()
        if action not in {"status", "run_check"}:
            raise SupervisorError(
                "Supervisor v1 only supports development status and registered checks"
            )
        project_policy = self.config.supervisor_policy.projects.get(project_slug)
        if project_policy is None:
            raise SupervisorError(
                f"Project is not enabled in the Supervisor policy: {project_slug}"
            )
        registered = self.config.development.projects.get(project_slug)
        if registered is None:
            raise SupervisorError(
                f"Project is not in the development registry: {project_slug}"
            )
        if self.permissions.decision("development", action) is not PermissionDecision.ALLOW:
            raise SupervisorError(
                f"Supervisor requires an explicit allow permission for development.{action}"
            )
        if action == "status":
            if not project_policy.allow_status:
                raise SupervisorError(
                    f"Status is not enabled in the Supervisor policy: {project_slug}"
                )
            if check_name is not None:
                raise SupervisorError("A status task cannot include a check name")
        else:
            if not check_name:
                raise SupervisorError("A registered check name is required")
            if check_name not in project_policy.allowed_checks:
                raise SupervisorError(
                    f"Check is not enabled in the Supervisor policy for "
                    f"{project_slug}: {check_name}"
                )
            if check_name not in registered.checks:
                raise SupervisorError(
                    f"Check is not in the development registry for "
                    f"{project_slug}: {check_name}"
                )
        return registered

    @staticmethod
    def _baseline_snapshot(
        project: RegisteredDevelopmentProjectConfig,
    ) -> dict[str, Any]:
        allowed = {"branch", "upstream", "commit", "repository_clean"}
        return {
            key: value for key, value in project.baseline.items() if key in allowed
        }

    def _action_digest(
        self,
        *,
        project_slug: str,
        action: str,
        check_name: str | None,
        project: RegisteredDevelopmentProjectConfig,
    ) -> str:
        check: dict[str, Any] | None = None
        if check_name is not None:
            configured = project.checks[check_name]
            check = {
                "name": check_name,
                "argv": list(configured.argv),
                "cwd": str(configured.cwd),
                "timeout_seconds": configured.timeout_seconds,
            }
        bound_action = {
            "policy_version": self.config.supervisor_policy.version,
            "project": project_slug,
            "project_root": str(project.root),
            "action": action,
            "check": check,
            "baseline": self._baseline_snapshot(project),
            "background_execution": False,
            "mutations_allowed": False,
        }
        encoded = json.dumps(
            bound_action, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @classmethod
    def _baseline_mismatches(
        cls,
        project: RegisteredDevelopmentProjectConfig,
        status: dict[str, Any],
    ) -> list[str]:
        baseline = cls._baseline_snapshot(project)
        mismatches: list[str] = []
        if baseline and not status.get("repository"):
            return ["registered project is not an available Git repository"]
        comparisons = {
            "branch": status.get("branch"),
            "upstream": status.get("upstream"),
            "commit": status.get("head"),
        }
        for key, actual in comparisons.items():
            expected = baseline.get(key)
            if expected is not None and actual != expected:
                mismatches.append(f"{key} differs from the registered baseline")
        if baseline.get("repository_clean") is True and not status.get("clean"):
            mismatches.append("repository has uncommitted or untracked changes")
        return mismatches

    @classmethod
    def _safe_status_result(
        cls,
        project: RegisteredDevelopmentProjectConfig,
        result: dict[str, Any],
    ) -> dict[str, Any]:
        mismatches = cls._baseline_mismatches(project, result)
        return {
            "project": result.get("project"),
            "repository": bool(result.get("repository")),
            "branch": result.get("branch"),
            "head": result.get("head"),
            "upstream": result.get("upstream"),
            "clean": bool(result.get("clean")),
            "change_count": len(result.get("changes") or []),
            "changes_truncated": bool(result.get("changes_truncated")),
            "baseline_match": not mismatches,
            "baseline_mismatches": mismatches,
        }

    @staticmethod
    def _safe_check_result(result: dict[str, Any]) -> dict[str, Any]:
        stdout = str(result.get("stdout") or "").encode("utf-8")
        stderr = str(result.get("stderr") or "").encode("utf-8")
        return {
            "project": result.get("project"),
            "check": result.get("check"),
            "returncode": result.get("returncode"),
            "stdout_bytes": int(result.get("stdout_bytes") or len(stdout)),
            "stderr_bytes": int(result.get("stderr_bytes") or len(stderr)),
            "stdout_sha256": result.get("stdout_sha256")
            or hashlib.sha256(stdout).hexdigest(),
            "stderr_sha256": result.get("stderr_sha256")
            or hashlib.sha256(stderr).hexdigest(),
            "output_truncated": bool(result.get("output_truncated")),
            "stopped": bool(result.get("stopped")),
        }

    def status(self) -> dict[str, Any]:
        counts = self.database.supervisor_task_counts()
        latest = self.database.list_supervisor_tasks(limit=1)
        allowed_projects = {
            slug: {
                "status": project.allow_status,
                "checks": list(project.allowed_checks),
            }
            for slug, project in self.config.supervisor_policy.projects.items()
        }
        return {
            "enabled": self.enabled,
            "paused": self.paused,
            "ready": self.enabled and not self.paused,
            "background_execution": False,
            "mutations_allowed": False,
            "exact_run_confirmation": self.RUN_CONFIRMATION,
            "allowed_projects": allowed_projects,
            "task_counts": counts,
            "latest_task": latest[0] if latest else None,
        }

    def plan(
        self,
        *,
        project_slug: str,
        action: str,
        check_name: str | None = None,
    ) -> dict[str, Any]:
        project = self._validate_action(
            project_slug=project_slug,
            action=action,
            check_name=check_name,
        )
        task_count = sum(self.database.supervisor_task_counts().values())
        if task_count >= self.config.supervisor.max_tasks:
            raise SupervisorError(
                "Supervisor task limit reached; archive strategy requires owner review"
            )
        kind = f"development.{action}"
        plan = {
            "kind": kind,
            "project": project_slug,
            "check": check_name,
            "dry_run": True,
            "requires_confirmation": self.RUN_CONFIRMATION,
            "background_execution": False,
            "mutations_allowed": False,
            "policy_version": self.config.supervisor_policy.version,
            "baseline": self._baseline_snapshot(project),
            "action_sha256": self._action_digest(
                project_slug=project_slug,
                action=action,
                check_name=check_name,
                project=project,
            ),
        }
        task = self.database.create_supervisor_task(
            kind=kind,
            project_slug=project_slug,
            check_name=check_name,
            plan=plan,
        )
        self.database.audit(
            event_type="supervisor",
            actor="operator",
            action="supervisor.plan",
            resource=task["id"],
            outcome="planned",
            details={"kind": kind, "project": project_slug, "check": check_name},
        )
        return task

    def get_task(self, task_id: str) -> dict[str, Any]:
        task = self.database.get_supervisor_task(task_id)
        if task is None:
            raise KeyError(f"Supervisor task not found: {task_id}")
        return task

    def list_tasks(
        self, *, status: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        return self.database.list_supervisor_tasks(status=status, limit=limit)

    def _validate_task(
        self, task: dict[str, Any]
    ) -> RegisteredDevelopmentProjectConfig:
        kind = str(task.get("kind") or "")
        if kind not in self.TASK_KINDS:
            raise SupervisorError(f"Unsupported Supervisor task kind: {kind}")
        action = kind.removeprefix("development.")
        project = self._validate_action(
            project_slug=str(task["project_slug"]),
            action=action,
            check_name=task.get("check_name"),
        )
        expected = self._action_digest(
            project_slug=str(task["project_slug"]),
            action=action,
            check_name=task.get("check_name"),
            project=project,
        )
        if task.get("plan", {}).get("action_sha256") != expected:
            raise SupervisorError(
                "Supervisor policy or registered action changed after planning; "
                "cancel this task and create a new plan"
            )
        return project

    def _finish(
        self,
        task_id: str,
        *,
        status: str,
        result: dict[str, Any],
        error: str | None = None,
    ) -> dict[str, Any]:
        task = self.database.finish_supervisor_task(
            task_id, status=status, result=result, error=error
        )
        self.database.audit(
            event_type="supervisor",
            actor="supervisor",
            action="supervisor.run",
            resource=task_id,
            outcome=status,
            details={
                "kind": task["kind"],
                "project": task["project_slug"],
                "check": task.get("check_name"),
                "result": result,
                "error": error,
            },
        )
        return task

    def run_task(self, task_id: str, *, confirmation: str) -> dict[str, Any]:
        if confirmation != self.RUN_CONFIRMATION:
            self.database.audit(
                event_type="supervisor",
                actor="operator",
                action="supervisor.run",
                resource=task_id,
                outcome="confirmation_denied",
                details={},
            )
            raise SupervisorError(
                f"Exact confirmation {self.RUN_CONFIRMATION!r} is required"
            )
        self._require_ready()
        task = self.get_task(task_id)
        project = self._validate_task(task)
        task = self.database.claim_supervisor_task(
            task_id,
            max_attempts=self.config.supervisor_policy.max_attempts_per_task,
            runner_pid=os.getpid(),
        )
        self.database.audit(
            event_type="supervisor",
            actor="operator",
            action="supervisor.run",
            resource=task_id,
            outcome="started",
            details={
                "kind": task["kind"],
                "project": task["project_slug"],
                "check": task.get("check_name"),
            },
        )

        try:
            arguments = {"project": task["project_slug"]}
            status_result = self.development.status(arguments)
            safe_status = self._safe_status_result(project, status_result)
            if task["kind"] == "development.status":
                return self._finish(
                    task_id, status="succeeded", result=safe_status
                )

            if not safe_status["baseline_match"]:
                return self._finish(
                    task_id,
                    status="stopped",
                    result={"preflight": safe_status},
                    error="Registered project baseline does not match",
                )
            if self.paused:
                return self._finish(
                    task_id,
                    status="stopped",
                    result={"preflight": safe_status},
                    error="Atlas Supervisor was paused before check execution",
                )
            arguments["check"] = task["check_name"]
            check_result = self.development.run_check_interruptible(
                arguments, should_stop=lambda: self.paused
            )
            safe_check = self._safe_check_result(check_result)
            result = {"preflight": safe_status, "check": safe_check}
            if safe_check["stopped"]:
                return self._finish(
                    task_id,
                    status="stopped",
                    result=result,
                    error="Atlas Supervisor pause control stopped the check",
                )
            terminal = "succeeded" if safe_check["returncode"] == 0 else "failed"
            error = None if terminal == "succeeded" else "Registered check failed"
            return self._finish(
                task_id, status=terminal, result=result, error=error
            )
        except KeyboardInterrupt:
            self._finish(
                task_id,
                status="interrupted",
                result={},
                error="Supervisor runner was interrupted",
            )
            raise
        except Exception as exc:
            error = str(exc)[:2_000]
            return self._finish(
                task_id, status="failed", result={}, error=error
            )

    def cancel_task(self, task_id: str) -> dict[str, Any]:
        self._require_enabled()
        task = self.database.cancel_supervisor_task(task_id)
        self.database.audit(
            event_type="supervisor",
            actor="operator",
            action="supervisor.cancel",
            resource=task_id,
            outcome="cancelled",
            details={"kind": task["kind"], "project": task["project_slug"]},
        )
        return task

    def pause(self) -> dict[str, Any]:
        self._require_enabled()
        self.pause_file.parent.mkdir(parents=True, exist_ok=True)
        already_paused = self.paused
        if not already_paused:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{self.pause_file.name}.",
                suffix=".tmp",
                dir=self.pause_file.parent,
            )
            temporary = Path(temporary_name)
            try:
                os.fchmod(descriptor, 0o600)
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    json.dump(
                        {"paused": True, "created_at": utc_now(), "actor": "operator"},
                        handle,
                        sort_keys=True,
                    )
                    handle.write("\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, self.pause_file)
            finally:
                temporary.unlink(missing_ok=True)
        self.database.audit(
            event_type="supervisor",
            actor="operator",
            action="supervisor.pause",
            resource="supervisor",
            outcome="already_paused" if already_paused else "paused",
            details={},
        )
        return self.status()

    def resume(self) -> dict[str, Any]:
        self._require_enabled()
        was_paused = self.paused
        self.pause_file.unlink(missing_ok=True)
        self.database.audit(
            event_type="supervisor",
            actor="operator",
            action="supervisor.resume",
            resource="supervisor",
            outcome="resumed" if was_paused else "already_ready",
            details={},
        )
        return self.status()

    def recover_task(self, task_id: str, *, confirmation: str) -> dict[str, Any]:
        self._require_enabled()
        if not self.paused:
            raise SupervisorError(
                "Pause Atlas Supervisor before recovering an interrupted task"
            )
        if confirmation != self.RECOVER_CONFIRMATION:
            raise SupervisorError(
                f"Exact confirmation {self.RECOVER_CONFIRMATION!r} is required"
            )
        task = self.database.recover_supervisor_task(task_id)
        self.database.audit(
            event_type="supervisor",
            actor="operator",
            action="supervisor.recover",
            resource=task_id,
            outcome="interrupted",
            details={"kind": task["kind"], "project": task["project_slug"]},
        )
        return task
