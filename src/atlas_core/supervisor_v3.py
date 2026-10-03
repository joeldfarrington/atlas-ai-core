from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Sequence

from atlas_core import __version__
from atlas_core.config import (
    AtlasConfig,
    RegisteredDevelopmentProjectConfig,
    SupervisorV2RecipeConfig,
    SupervisorV3ProtocolPinConfig,
)
from atlas_core.errors import SupervisorError
from atlas_core.memory.database import Database, canonical_json
from atlas_core.permissions import PermissionDecision, PermissionEngine
from atlas_core.supervisor_v3_protocol import (
    NotificationPolicy,
    ProtocolViolation,
    V3_DISABLED_STATUS_STAGES,
    V3_EDIT_STAGES,
    V3_PROJECT_STAGES,
    V3_READ_ONLY_STAGES,
    V3_RESPONSE_CANARY_STAGES,
    supervisor_v3_permission_profile,
    supervisor_v3_permission_profile_sha256,
    supervisor_v3_permission_profile_toml,
)


ACTIVE_V3_STATUSES = {
    "approved",
    "preparing",
    "contacting",
    "executing",
    "validating",
    "verifying",
}
TERMINAL_V3_STATUSES = {
    "canary_passed",
    "candidate_ready",
    "stopped",
    "failed",
    "interrupted",
    "cancelled",
    "expired",
}
CANARY_CONFIRMATION = "CANARY-V3 <task-id-prefix> <plan-hash-prefix>"
SUCCESSOR_CANARY_CONFIRMATION = "CANARY-V3S <task-id-prefix> <plan-hash-prefix>"
FIXTURE_CONFIRMATION = "APPLY-V3 <task-id-prefix> <plan-hash-prefix>"
RECOVERY_CANARY_CONFIRMATION = "CANARY-V3R <task-id-prefix> <plan-hash-prefix>"
RECOVERY_FIXTURE_CONFIRMATION = "APPLY-V3R <task-id-prefix> <plan-hash-prefix>"
KNOWN_LIMITATIONS = (
    "The pinned macOS sandbox can permit writes to shared system temporary paths. "
    "Atlas supplies a private TMPDIR, denies command network, validates events, and "
    "independently inspects final state, but this is not full process isolation.",
)
SECRET_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"(?i)(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"\s]{16,}"),
    re.compile(r"(?:ghp|github_pat)_[A-Za-z0-9_]{20,}"),
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
)
INSTRUCTION_NAMES = {
    "AGENTS.md",
    "CLAUDE.md",
    "GEMINI.md",
    ".cursorrules",
    ".windsurfrules",
}


class _WorkerLifecycleError(SupervisorError):
    def __init__(self, message: str, *, process_group_terminated: bool) -> None:
        super().__init__(message)
        self.process_group_terminated = process_group_terminated


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run(
    argv: Sequence[str],
    *,
    cwd: Path,
    timeout: float = 30,
    env: dict[str, str] | None = None,
    text: bool = True,
) -> subprocess.CompletedProcess[Any]:
    try:
        return subprocess.run(
            list(argv),
            cwd=cwd,
            env=env,
            shell=False,
            capture_output=True,
            text=text,
            timeout=timeout,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise SupervisorError("A bounded Supervisor v3 offline subprocess failed") from exc


def _process_group_exists(group_id: int) -> bool:
    try:
        os.killpg(group_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _terminate_process_group(
    process: subprocess.Popen[str], group_id: int, *, timeout: float = 2.0
) -> bool:
    """Terminate only the worker's dedicated session and prove it is gone."""

    if _process_group_exists(group_id):
        try:
            os.killpg(group_id, signal.SIGTERM)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + timeout
        while _process_group_exists(group_id) and time.monotonic() < deadline:
            process.poll()
            time.sleep(0.05)
    if _process_group_exists(group_id):
        try:
            os.killpg(group_id, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except PermissionError:
            return False
        deadline = time.monotonic() + timeout
        while _process_group_exists(group_id) and time.monotonic() < deadline:
            process.poll()
            time.sleep(0.05)
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        return False
    return process.poll() is not None and not _process_group_exists(group_id)


def _communicate_with_pause(
    process: subprocess.Popen[str],
    payload: str,
    *,
    timeout: float,
    should_stop: Any,
    poll_interval: float = 0.1,
) -> tuple[str, str, str | None]:
    """Exchange one request while polling the authoritative pause marker."""

    deadline = time.monotonic() + timeout
    pending_input: str | None = payload
    while True:
        if should_stop():
            return "", "", "paused"
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return "", "", "timeout"
        try:
            stdout, stderr = process.communicate(
                pending_input,
                timeout=min(poll_interval, remaining),
            )
            return stdout, stderr, None
        except subprocess.TimeoutExpired:
            pending_input = None


def _git(root: Path, *arguments: str, timeout: float = 30) -> str:
    completed = _run(
        ["git", "-c", "core.hooksPath=/dev/null", *arguments],
        cwd=root,
        timeout=timeout,
    )
    if completed.returncode != 0:
        raise SupervisorError(f"Supervisor v3 Git operation failed: {arguments[0]}")
    return str(completed.stdout).strip()


def _extract_schema_methods(document: dict[str, Any]) -> set[str]:
    methods: set[str] = set()

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            properties = value.get("properties")
            method = properties.get("method") if isinstance(properties, dict) else None
            if isinstance(method, dict):
                constant = method.get("const")
                choices = method.get("enum")
                if isinstance(constant, str):
                    methods.add(constant)
                if (
                    isinstance(choices, list)
                    and len(choices) == 1
                    and isinstance(choices[0], str)
                ):
                    methods.add(choices[0])
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(document)
    return methods


class SupervisorV3ReadinessInspector:
    """Verify the complete SDK/runtime/schema/classifier pin without a model."""

    def __init__(self, config: AtlasConfig) -> None:
        self.config = config
        if config.supervisor_v3_policy is None:
            raise SupervisorError("Supervisor v3 policy is unavailable")
        self.policy = config.supervisor_v3_policy
        self.pin = self.policy.protocol_pin

    @staticmethod
    def _schema_snapshot(root: Path, selected: dict[str, str]) -> dict[str, Any]:
        files = sorted(path for path in root.rglob("*") if path.is_file())
        manifest = "".join(
            f"{_sha256_file(path)}  {path.relative_to(root).as_posix()}\n"
            for path in files
        ).encode("utf-8")
        return {
            "schema_file_count": len(files),
            "schema_manifest_sha256": _sha256_bytes(manifest),
            "selected_schema_sha256": {
                name: _sha256_file(root / name) if (root / name).is_file() else None
                for name in selected
            },
        }

    def _load_lock(self, mismatches: list[str]) -> dict[str, Any]:
        lock_path = self.config.app.supervisor_v3_lock_file
        try:
            lock = json.loads(lock_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            mismatches.append("SDK lock is unreadable")
            return {}
        if not isinstance(lock, dict) or lock.get("format") != "atlas-supervisor-v3-sdk-lock":
            mismatches.append("SDK lock format drifted")
            return {}
        return lock

    def _inspect_packages(self, lock: dict[str, Any], mismatches: list[str]) -> dict[str, Any]:
        artifact_results: dict[str, Any] = {}
        for name, pin in sorted(self.pin.artifacts.items()):
            artifact = self.pin.artifact_dir / pin.filename
            actual = _sha256_file(artifact) if artifact.is_file() and not artifact.is_symlink() else None
            artifact_results[name] = {
                "version": pin.version,
                "filename": pin.filename,
                "sha256": actual,
                "matches": actual == pin.sha256,
            }
            if actual != pin.sha256:
                mismatches.append(f"SDK artifact drifted: {name}")

        python = self.pin.sdk_python_path
        if not python.exists():
            mismatches.append("isolated SDK Python is unavailable")
            return {"artifacts": artifact_results}
        script = (
            "import importlib.metadata as m,json,platform;"
            "from openai_codex.generated.notification_registry import NOTIFICATION_MODELS;"
            "from codex_cli_bin import bundled_codex_path;"
            "print(json.dumps({'python':platform.python_version(),"
            "'sdk':m.version('openai-codex'),'runtime':m.version('openai-codex-cli-bin'),"
            "'binary':str(bundled_codex_path()),'notifications':sorted(NOTIFICATION_MODELS)}))"
        )
        environment = {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "LANG": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        completed = _run(
            [str(python), "-I", "-c", script],
            cwd=self.config.project_root,
            timeout=20,
            env=environment,
        )
        try:
            metadata = json.loads(str(completed.stdout)) if completed.returncode == 0 else {}
        except json.JSONDecodeError:
            metadata = {}
        expected = {
            "python": self.pin.python_version,
            "sdk": self.pin.sdk_version,
            "runtime": self.pin.runtime_package_version,
            "binary": str(self.pin.binary_path),
        }
        for field, value in expected.items():
            if metadata.get(field) != value:
                mismatches.append(f"isolated SDK {field} drifted")
        return {"artifacts": artifact_results, "metadata": metadata}

    def _inspect_runtime(
        self, package: dict[str, Any], mismatches: list[str]
    ) -> dict[str, Any]:
        binary = self.pin.binary_path
        if not binary.is_file() or binary.is_symlink():
            mismatches.append("pinned SDK Codex binary is unavailable or unsafe")
            return {}
        binary_hash = _sha256_file(binary)
        if binary_hash != self.pin.binary_sha256:
            mismatches.append("pinned SDK Codex binary SHA-256 drifted")
            return {"binary_sha256": binary_hash}
        version = _run([str(binary), "--version"], cwd=binary.parent, timeout=10)
        actual_version = str(version.stdout).strip()
        if version.returncode != 0 or actual_version != self.pin.cli_version:
            mismatches.append("pinned SDK Codex binary version drifted")
        with tempfile.TemporaryDirectory(prefix="atlas-v3-schema-") as temporary:
            schema_root = Path(temporary)
            generated = _run(
                [
                    str(binary),
                    "app-server",
                    "generate-json-schema",
                    "--out",
                    str(schema_root),
                ],
                cwd=binary.parent,
                timeout=60,
                env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8"},
            )
            if generated.returncode != 0:
                mismatches.append("stable App Server schema generation failed")
                return {"binary_sha256": binary_hash, "cli_version": actual_version}
            snapshot = self._schema_snapshot(schema_root, self.pin.selected_schema_sha256)
            server_notifications = _extract_schema_methods(
                json.loads((schema_root / "ServerNotification.json").read_text(encoding="utf-8"))
            )
            server_requests = _extract_schema_methods(
                json.loads((schema_root / "ServerRequest.json").read_text(encoding="utf-8"))
            )
        if snapshot["schema_file_count"] != self.pin.schema_file_count:
            mismatches.append("stable schema file count drifted")
        if snapshot["schema_manifest_sha256"] != self.pin.schema_manifest_sha256:
            mismatches.append("stable schema manifest SHA-256 drifted")
        for name, expected in self.pin.selected_schema_sha256.items():
            if snapshot["selected_schema_sha256"].get(name) != expected:
                mismatches.append(f"selected stable schema drifted: {name}")
        sdk_notifications = set((package.get("metadata") or {}).get("notifications") or [])
        if sdk_notifications != server_notifications:
            mismatches.append("SDK notification registry does not match generated stable schema")
        try:
            classifier = NotificationPolicy.load(
                self.config.app.supervisor_v3_classifier_file,
                expected_notifications=server_notifications,
                expected_server_requests=server_requests,
            )
        except (OSError, ProtocolViolation) as exc:
            mismatches.append(f"notification classifier failed: {str(exc)[:160]}")
            classifier = None
        return {
            "binary_sha256": binary_hash,
            "cli_version": actual_version,
            **snapshot,
            "notification_method_count": len(server_notifications),
            "server_request_method_count": len(server_requests),
            "classifier_coverage": classifier.stable_method_count if classifier else 0,
            "experimental_api": False,
        }

    def _inspect_sources(self, lock: dict[str, Any], mismatches: list[str]) -> dict[str, Any]:
        expected = lock.get("executor", {}).get("source_sha256", {}) if isinstance(lock, dict) else {}
        actual: dict[str, str | None] = {}
        if not isinstance(expected, dict) or not expected:
            mismatches.append("SDK lock has no executor source pins")
            return actual
        for relative, digest in sorted(expected.items()):
            path = self.config.project_root / str(relative)
            observed = _sha256_file(path) if path.is_file() and not path.is_symlink() else None
            actual[str(relative)] = observed
            if observed != digest:
                mismatches.append(f"Supervisor v3 executor source drifted: {relative}")
        worker = self.config.project_root / "scripts" / "supervisor_v3_sdk_worker.py"
        source = worker.read_text(encoding="utf-8") if worker.is_file() else ""
        required_markers = (
            "experimental_api=False",
            "approval_handler=",
            '"approvalPolicy": "never"',
            '"config/read"',
            "default_permissions",
            "unknown-or-unclassified",
            "ALLOWED_ENVIRONMENT_KEYS",
        )
        if any(marker not in source for marker in required_markers):
            mismatches.append("Supervisor v3 SDK worker control markers drifted")
        service_source = Path(__file__).read_text(encoding="utf-8")
        if "start_new_session=True" not in service_source or "os.killpg" not in service_source:
            mismatches.append("Supervisor v3 process-group controls drifted")
        return actual

    def _profile_probe(self, mismatches: list[str]) -> dict[str, Any]:
        """Exercise every named command profile locally without App Server."""

        if sys_platform() != "darwin":
            mismatches.append("Supervisor v3 reviewed profiles require macOS Seatbelt")
            return {"ready": False, "model_contacted": False}
        results: dict[str, Any] = {}
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        listener.settimeout(0.2)
        port = int(listener.getsockname()[1])
        try:
            with tempfile.TemporaryDirectory(prefix="atlas-v3-profile-") as temporary:
                outer = Path(temporary)
                for stage, access in (
                    ("canary", "read"),
                    ("successor_canary", "read"),
                    ("fixture", "write"),
                    ("recovery_canary", "write"),
                    ("recovery_fixture", "write"),
                ):
                    root = outer / stage
                    root.mkdir(mode=0o700)
                    inside = root / "inside.txt"
                    inside.write_text("unchanged\n", encoding="utf-8")
                    outside = outer / f"outside-{stage}.txt"
                    outside.write_text("unchanged\n", encoding="utf-8")
                    profile_name, profile_data = supervisor_v3_permission_profile(stage)
                    if profile_data["filesystem"][":workspace_roots"]["."] != access:
                        raise SupervisorError("Supervisor v3 permission profile access drifted")
                    profile = supervisor_v3_permission_profile_toml(stage)
                    command = "; ".join(
                        (
                            f"if /bin/cat {shlex.quote(str(inside))} >/dev/null 2>&1; then echo read=allowed; else echo read=denied; fi",
                            f"if /usr/bin/printf changed > {shlex.quote(str(inside))} 2>/dev/null; then echo write=allowed; else echo write=denied; fi",
                            f"if /usr/bin/printf changed > {shlex.quote(str(outside))} 2>/dev/null; then echo outside=allowed; else echo outside=denied; fi",
                            f"if /bin/cat {shlex.quote(str(self.config.app.supervisor_v3_policy_file))} >/dev/null 2>&1; then echo protected=allowed; else echo protected=denied; fi",
                            f"if /usr/bin/curl --connect-timeout 1 --max-time 1 -sS http://127.0.0.1:{port}/ >/dev/null 2>&1; then echo network=allowed; else echo network=denied; fi",
                        )
                    )
                    completed = _run(
                        [
                            str(self.pin.binary_path),
                            "sandbox",
                            "-C",
                            str(root),
                            "-P",
                            profile_name,
                            "-c",
                            profile,
                            "--",
                            "/bin/zsh",
                            "-f",
                            "-c",
                            command,
                        ],
                        cwd=root,
                        timeout=15,
                        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8"},
                    )
                    flags = dict(
                        line.split("=", 1)
                        for line in str(completed.stdout).splitlines()
                        if "=" in line
                    )
                    expected_write = (
                        "denied" if stage in V3_READ_ONLY_STAGES else "allowed"
                    )
                    okay = (
                        completed.returncode == 0
                        and flags.get("read") == "allowed"
                        and flags.get("write") == expected_write
                        and flags.get("outside") == "denied"
                        and flags.get("protected") == "denied"
                        and flags.get("network") == "denied"
                        and outside.read_text(encoding="utf-8") == "unchanged\n"
                    )
                    results[stage] = {
                        "ready": okay,
                        "permission_profile_id": profile_name,
                        "permission_profile_sha256": supervisor_v3_permission_profile_sha256(
                            stage
                        ),
                        "read_allowed": flags.get("read") == "allowed",
                        "write_allowed": flags.get("write") == "allowed",
                        "outside_write_denied": flags.get("outside") == "denied",
                        "protected_read_denied": flags.get("protected") == "denied",
                        "command_network_denied": flags.get("network") == "denied",
                    }
                    if not okay:
                        mismatches.append(f"{stage} sandbox profile probe failed")
        finally:
            listener.close()
        return {
            **results,
            "model_contacted": False,
            "known_limitations": list(KNOWN_LIMITATIONS),
        }

    def inspect(self) -> dict[str, Any]:
        mismatches: list[str] = []
        classifier_hash = _sha256_file(self.config.app.supervisor_v3_classifier_file)
        lock_hash = _sha256_file(self.config.app.supervisor_v3_lock_file)
        if classifier_hash != self.policy.classifier_sha256:
            mismatches.append("notification classifier SHA-256 drifted")
        if lock_hash != self.policy.sdk_lock_sha256:
            mismatches.append("SDK lock SHA-256 drifted")
        lock = self._load_lock(mismatches)
        packages = self._inspect_packages(lock, mismatches)
        runtime = self._inspect_runtime(packages, mismatches)
        sources = self._inspect_sources(lock, mismatches)
        profiles = self._profile_probe(mismatches) if not mismatches else {
            "ready": False,
            "skipped": "earlier pin mismatch",
            "model_contacted": False,
        }
        return {
            "ready": not mismatches,
            "mismatches": mismatches,
            "driver": "python_sdk",
            "packages": packages,
            "runtime": runtime,
            "executor_source_sha256": sources,
            "sandbox_profiles": profiles,
            "classifier_sha256": classifier_hash,
            "sdk_lock_sha256": lock_hash,
            "experimental_api": False,
            "model_contacted": False,
            "fake_driver_only": True,
        }


def sys_platform() -> str:
    import sys

    return sys.platform


class SupervisorV3Service:
    """Five lineage-bound stages with independent, non-resettable one-shot gates."""

    def __init__(
        self,
        *,
        config: AtlasConfig,
        database: Database,
        permissions: PermissionEngine,
    ) -> None:
        self.config = config
        self.database = database
        self.permissions = permissions
        interrupted = database.interrupt_active_supervisor_v3_tasks(
            reason="Recovered at startup; Supervisor v3 never resumes a claimed stage"
        )
        if interrupted:
            database.audit(
                event_type="supervisor_v3",
                actor="supervisor",
                action="supervisor_v3.reconcile",
                resource="supervisor_v3",
                outcome="interrupted",
                details={"task_count": interrupted, "automatic_resume": False},
            )

    @property
    def enabled(self) -> bool:
        return self.config.supervisor_v3.enabled and self.config.supervisor_v3_policy is not None

    @property
    def paused(self) -> bool:
        return self.config.supervisor.pause_file.exists()

    @property
    def policy(self):
        if self.config.supervisor_v3_policy is None:
            raise SupervisorError("Supervisor v3 policy is unavailable")
        return self.config.supervisor_v3_policy

    def _require_enabled(self) -> None:
        if not self.enabled:
            raise SupervisorError("Atlas Supervisor v3 is disabled")

    @staticmethod
    def _predecessor_receipt(task: dict[str, Any]) -> dict[str, Any]:
        plan = task.get("plan") if isinstance(task.get("plan"), dict) else {}
        result = task.get("result") if isinstance(task.get("result"), dict) else {}
        return {
            "task_id": task.get("id"),
            "stage": task.get("stage"),
            "status": task.get("status"),
            "stop_code": task.get("stop_code"),
            "attempt_count": task.get("attempt_count"),
            "model_contacted": task.get("model_contacted"),
            "envelope_count": task.get("envelope_count"),
            "envelope_chain_sha256": task.get("envelope_chain_sha256"),
            "plan_sha256": plan.get("plan_sha256"),
            "process_group_terminated": result.get("process_group_terminated"),
            "credential_staging_removed": result.get("credential_staging_removed"),
            "raw_output_persisted": result.get("raw_output_persisted"),
            "disposable_root_verified": result.get("disposable_root_verified"),
        }

    def _validated_successor_predecessor(self) -> dict[str, Any]:
        expected = self.policy.successor_predecessor
        task = self.database.get_supervisor_v3_task(expected.task_id)
        if task is None:
            raise SupervisorError("Supervisor v3 successor predecessor is unavailable")
        receipt = self._predecessor_receipt(task)
        required = {
            "task_id": expected.task_id,
            "stage": "canary",
            "status": "failed",
            "stop_code": "stage_failed",
            "attempt_count": 1,
            "model_contacted": True,
            "envelope_count": 5,
            "envelope_chain_sha256": expected.envelope_chain_sha256,
            "plan_sha256": expected.plan_sha256,
            "process_group_terminated": True,
            "credential_staging_removed": True,
            "raw_output_persisted": False,
            "disposable_root_verified": True,
        }
        if receipt != required or not str(task.get("error") or "").endswith(
            f"prohibited_notification:{expected.failure_method}"
        ):
            raise SupervisorError("Supervisor v3 successor predecessor receipt drifted")
        return receipt

    def _successor_predecessor_available(self) -> bool:
        try:
            self._validated_successor_predecessor()
        except SupervisorError:
            return False
        return True

    def _validated_recovery_predecessor(self) -> dict[str, Any]:
        expected = self.policy.recovery_predecessor
        task = self.database.get_supervisor_v3_task(expected.task_id)
        if task is None:
            raise SupervisorError("Supervisor v3 recovery predecessor is unavailable")
        receipt = self._predecessor_receipt(task)
        required = {
            "task_id": expected.task_id,
            "stage": "fixture",
            "status": "failed",
            "stop_code": "stage_failed",
            "attempt_count": 1,
            "model_contacted": True,
            "envelope_count": 5,
            "envelope_chain_sha256": expected.envelope_chain_sha256,
            "plan_sha256": expected.plan_sha256,
            "process_group_terminated": True,
            "credential_staging_removed": True,
            "raw_output_persisted": False,
            "disposable_root_verified": True,
        }
        result = task.get("result") if isinstance(task.get("result"), dict) else {}
        if (
            receipt != required
            or result.get("candidate_integrated") is not False
            or result.get("canonical_source_unchanged") is not True
            or result.get("auth_source_unchanged") is not True
            or not str(task.get("error") or "").endswith(
                f"prohibited_notification:{expected.failure_method}"
            )
        ):
            raise SupervisorError("Supervisor v3 recovery predecessor receipt drifted")
        return receipt

    def _recovery_predecessor_available(self) -> bool:
        try:
            self._validated_recovery_predecessor()
        except SupervisorError:
            return False
        return True

    def status(self) -> dict[str, Any]:
        self.database.expire_supervisor_v3_tasks()
        latest = self.database.list_supervisor_v3_tasks(limit=1)
        canary_used = self.database.supervisor_v3_stage_attempts("canary")
        successor_used = self.database.supervisor_v3_stage_attempts(
            "successor_canary"
        )
        fixture_used = self.database.supervisor_v3_stage_attempts("fixture")
        recovery_canary_used = self.database.supervisor_v3_stage_attempts(
            "recovery_canary"
        )
        recovery_fixture_used = self.database.supervisor_v3_stage_attempts(
            "recovery_fixture"
        )
        policy = self.config.supervisor_v3_policy
        canary_enabled = bool(policy and policy.live_canary_execution)
        successor_enabled = bool(
            policy and policy.live_successor_canary_execution
        )
        fixture_enabled = bool(policy and policy.live_fixture_execution)
        recovery_canary_enabled = bool(
            policy and policy.live_recovery_canary_execution
        )
        recovery_fixture_enabled = bool(
            policy and policy.live_recovery_fixture_execution
        )
        successor_passed = (
            self.database.latest_supervisor_v3_successor_canary_pass() is not None
        )
        recovery_canary_passed = (
            self.database.latest_supervisor_v3_recovery_canary_pass() is not None
        )
        active_plans = {
            stage: self.database.active_supervisor_v3_plan(stage)
            for stage in (
                "canary",
                "successor_canary",
                "fixture",
                "recovery_canary",
                "recovery_fixture",
            )
        }
        successor_predecessor_available = self._successor_predecessor_available()
        recovery_predecessor_available = self._recovery_predecessor_available()
        if fixture_used >= 1 and recovery_predecessor_available:
            if recovery_canary_passed:
                if recovery_fixture_used >= 1:
                    if (
                        latest
                        and latest[0].get("stage") == "recovery_fixture"
                        and latest[0].get("status") == "candidate_ready"
                    ):
                        next_gate = "recovery_candidate_owner_review"
                    else:
                        next_gate = "recovery_fixture_attempt_exhausted"
                elif not recovery_fixture_enabled:
                    next_gate = "recovery_fixture_owner_authorization"
                elif (
                    latest
                    and latest[0].get("stage") == "recovery_fixture"
                    and latest[0].get("status") == "planned"
                ):
                    next_gate = "recovery_fixture_exact_confirmation"
                else:
                    next_gate = "recovery_fixture_plan"
            elif recovery_canary_used >= 1:
                next_gate = "recovery_canary_attempt_exhausted"
            elif not recovery_canary_enabled:
                next_gate = "recovery_canary_owner_authorization"
            elif (
                latest
                and latest[0].get("stage") == "recovery_canary"
                and latest[0].get("status") == "planned"
            ):
                next_gate = "recovery_canary_exact_confirmation"
            else:
                next_gate = "recovery_canary_plan"
        elif fixture_used >= 1:
            next_gate = "fixture_attempt_exhausted"
        elif successor_passed:
            if fixture_used >= 1:
                next_gate = "fixture_attempt_exhausted"
            elif not fixture_enabled:
                next_gate = "fixture_owner_authorization"
            elif latest and latest[0].get("stage") == "fixture" and latest[0].get(
                "status"
            ) == "planned":
                next_gate = "fixture_exact_confirmation"
            else:
                next_gate = "fixture_plan"
        elif successor_used >= 1:
            next_gate = "successor_canary_attempt_exhausted"
        elif not successor_predecessor_available:
            next_gate = "successor_canary_predecessor_unavailable"
        elif not successor_enabled:
            next_gate = "successor_canary_owner_authorization"
        elif latest and latest[0].get("stage") == "successor_canary" and latest[0].get(
            "status"
        ) == "planned":
            next_gate = "successor_canary_exact_confirmation"
        else:
            next_gate = "successor_canary_plan"
        return {
            "enabled": self.enabled,
            "paused": self.paused,
            "mode": "staged_sdk_fixture_recovery_pilot",
            "offline_implementation_complete": True,
            "driver": "python_sdk",
            "sdk_version": policy.protocol_pin.sdk_version if policy else None,
            "model": policy.model if policy else None,
            "reasoning_effort": policy.reasoning_effort if policy else None,
            "live_canary_execution": canary_enabled,
            "live_successor_canary_execution": successor_enabled,
            "live_fixture_execution": fixture_enabled,
            "live_recovery_canary_execution": recovery_canary_enabled,
            "live_recovery_fixture_execution": recovery_fixture_enabled,
            "canary_attempts_used": canary_used,
            "canary_attempt_cap": 1,
            "successor_canary_attempts_used": successor_used,
            "successor_canary_attempt_cap": 1,
            "fixture_attempts_used": fixture_used,
            "fixture_attempt_cap": 1,
            "recovery_canary_attempts_used": recovery_canary_used,
            "recovery_canary_attempt_cap": 1,
            "recovery_fixture_attempts_used": recovery_fixture_used,
            "recovery_fixture_attempt_cap": 1,
            "canary_plan_available": (
                self.enabled
                and canary_enabled
                and not self.paused
                and canary_used == 0
                and active_plans["canary"] is None
            ),
            "successor_canary_plan_available": (
                self.enabled
                and successor_enabled
                and not self.paused
                and successor_used == 0
                and successor_predecessor_available
                and active_plans["successor_canary"] is None
            ),
            "fixture_plan_available": (
                self.enabled
                and fixture_enabled
                and not self.paused
                and fixture_used == 0
                and self.database.latest_supervisor_v3_successor_canary_pass()
                is not None
                and active_plans["fixture"] is None
            ),
            "recovery_canary_plan_available": (
                self.enabled
                and recovery_canary_enabled
                and not self.paused
                and recovery_canary_used == 0
                and fixture_used == 1
                and recovery_predecessor_available
                and active_plans["recovery_canary"] is None
            ),
            "recovery_fixture_plan_available": (
                self.enabled
                and recovery_fixture_enabled
                and not self.paused
                and recovery_fixture_used == 0
                and self.database.latest_supervisor_v3_recovery_canary_pass()
                is not None
                and active_plans["recovery_fixture"] is None
            ),
            "canonical_mutations": False,
            "background_execution": False,
            "experimental_api": False,
            "model_contacted": self.database.supervisor_v3_any_model_contacted(),
            "confirmations": {
                "canary": CANARY_CONFIRMATION,
                "successor_canary": SUCCESSOR_CANARY_CONFIRMATION,
                "fixture": FIXTURE_CONFIRMATION,
                "recovery_canary": RECOVERY_CANARY_CONFIRMATION,
                "recovery_fixture": RECOVERY_FIXTURE_CONFIRMATION,
            },
            "task_counts": self.database.supervisor_v3_task_counts(),
            "latest_task": latest[0] if latest else None,
            "next_gate": next_gate,
        }

    def readiness(self) -> dict[str, Any]:
        self._require_enabled()
        inspected = SupervisorV3ReadinessInspector(self.config).inspect()
        canary_used = self.database.supervisor_v3_stage_attempts("canary")
        successor_used = self.database.supervisor_v3_stage_attempts(
            "successor_canary"
        )
        fixture_used = self.database.supervisor_v3_stage_attempts("fixture")
        recovery_canary_used = self.database.supervisor_v3_stage_attempts(
            "recovery_canary"
        )
        recovery_fixture_used = self.database.supervisor_v3_stage_attempts(
            "recovery_fixture"
        )
        mismatches = list(inspected["mismatches"])
        if not self._successor_predecessor_available():
            mismatches.append("the exact failed-canary predecessor receipt drifted")
        if fixture_used >= 1 and not self._recovery_predecessor_available():
            mismatches.append("the exact failed-fixture recovery predecessor receipt drifted")
        if self.paused:
            mismatches.append("the authoritative Supervisor pause marker is set")
        return {
            **inspected,
            "ready": not mismatches,
            "mismatches": mismatches,
            "paused": self.paused,
            "live_canary_execution": self.policy.live_canary_execution,
            "live_successor_canary_execution": (
                self.policy.live_successor_canary_execution
            ),
            "live_fixture_execution": self.policy.live_fixture_execution,
            "live_recovery_canary_execution": (
                self.policy.live_recovery_canary_execution
            ),
            "live_recovery_fixture_execution": (
                self.policy.live_recovery_fixture_execution
            ),
            "canary_attempts_used": canary_used,
            "canary_attempt_cap": 1,
            "successor_canary_attempts_used": successor_used,
            "successor_canary_attempt_cap": 1,
            "fixture_attempts_used": fixture_used,
            "fixture_attempt_cap": 1,
            "recovery_canary_attempts_used": recovery_canary_used,
            "recovery_canary_attempt_cap": 1,
            "recovery_fixture_attempts_used": recovery_fixture_used,
            "recovery_fixture_attempt_cap": 1,
            "model_contacted": self.database.supervisor_v3_any_model_contacted(),
            "readiness_check_contacted_model": False,
            "local_fake_driver_pass_is_not_live_canary": True,
        }

    @staticmethod
    def _plan_digest(plan: dict[str, Any]) -> str:
        digestable = dict(plan)
        digestable.pop("plan_sha256", None)
        return _sha256_bytes(canonical_json(digestable).encode("utf-8"))

    @staticmethod
    def _required_confirmation(task: dict[str, Any]) -> str:
        plan_hash = str((task.get("plan") or {}).get("plan_sha256") or "")
        prefixes = {
            "canary": "CANARY-V3",
            "successor_canary": "CANARY-V3S",
            "fixture": "APPLY-V3",
            "recovery_canary": "CANARY-V3R",
            "recovery_fixture": "APPLY-V3R",
        }
        prefix = prefixes.get(str(task.get("stage")), "INVALID-V3")
        return f"{prefix} {str(task['id'])[:8]} {plan_hash[:12]}"

    def _binding(self) -> dict[str, Any]:
        lock = json.loads(self.config.app.supervisor_v3_lock_file.read_text(encoding="utf-8"))
        return {
            "policy_sha256": _sha256_file(self.config.app.supervisor_v3_policy_file),
            "classifier_sha256": self.policy.classifier_sha256,
            "sdk_lock_sha256": self.policy.sdk_lock_sha256,
            "driver": self.policy.driver,
            "sdk_version": self.policy.protocol_pin.sdk_version,
            "runtime_version": self.policy.protocol_pin.cli_version,
            "runtime_sha256": self.policy.protocol_pin.binary_sha256,
            "schema_manifest_sha256": self.policy.protocol_pin.schema_manifest_sha256,
            "executor_source_sha256": lock.get("executor", {}).get("source_sha256", {}),
            "permission_profiles": {
                stage: {
                    "id": supervisor_v3_permission_profile(stage)[0],
                    "sha256": supervisor_v3_permission_profile_sha256(stage),
                }
                for stage in (
                    "canary",
                    "successor_canary",
                    "fixture",
                    "recovery_canary",
                    "recovery_fixture",
                )
            },
            "model": self.policy.model,
            "reasoning_effort": self.policy.reasoning_effort,
            "experimental_api": False,
            "command_network_access": False,
            "canonical_mutations": False,
        }

    def _require_planning_authority(self, stage: str) -> None:
        self._require_enabled()
        if self.paused:
            raise SupervisorError("Atlas Supervisor is paused")
        enabled = {
            "canary": self.policy.live_canary_execution,
            "successor_canary": self.policy.live_successor_canary_execution,
            "fixture": self.policy.live_fixture_execution,
            "recovery_canary": self.policy.live_recovery_canary_execution,
            "recovery_fixture": self.policy.live_recovery_fixture_execution,
        }.get(stage, False)
        if not enabled:
            raise SupervisorError(
                f"Supervisor v3 {stage} is implemented offline but its live owner gate is disabled"
            )
        action = {
            "canary": "plan_canary",
            "successor_canary": "plan_successor_canary",
            "fixture": "plan_fixture",
            "recovery_canary": "plan_recovery_canary",
            "recovery_fixture": "plan_recovery_fixture",
        }.get(stage, "invalid")
        if self.permissions.decision("supervisor_v3", action) is not PermissionDecision.ALLOW:
            raise SupervisorError(f"Supervisor v3 permission denied: {action}")
        readiness = self.readiness()
        if not readiness["ready"]:
            raise SupervisorError("Supervisor v3 offline readiness failed")

    def plan_canary(self) -> dict[str, Any]:
        self._require_planning_authority("canary")
        if self.database.supervisor_v3_stage_attempts("canary") >= 1:
            raise SupervisorError("Supervisor v3 canary lifetime attempt is exhausted")
        created = datetime.now(timezone.utc)
        expires = created + timedelta(seconds=self.policy.plan_ttl_seconds)
        binding = self._binding()
        plan = {
            "kind": "codex.protocol_canary.v3",
            "stage": "canary",
            "binding": binding,
            "binding_sha256": _sha256_bytes(canonical_json(binding).encode("utf-8")),
            "sandbox": "read-only",
            "permission_profile": {
                "id": supervisor_v3_permission_profile("canary")[0],
                "sha256": supervisor_v3_permission_profile_sha256("canary"),
            },
            "empty_root": True,
            "model": self.policy.model,
            "reasoning_effort": self.policy.reasoning_effort,
            "canonical_mutations": False,
            "background_execution": False,
            "experimental_api": False,
            "command_network_access": False,
            "created_at": created.isoformat(timespec="milliseconds"),
            "expires_at": expires.isoformat(timespec="milliseconds"),
            "confirmation_format": CANARY_CONFIRMATION,
        }
        plan["plan_sha256"] = self._plan_digest(plan)
        task = self.database.create_supervisor_v3_task(
            stage="canary",
            recipe_slug=None,
            project_slug=None,
            plan=plan,
            expires_at=plan["expires_at"],
        )
        task["required_confirmation"] = self._required_confirmation(task)
        return task

    def plan_successor_canary(self) -> dict[str, Any]:
        self._require_planning_authority("successor_canary")
        if self.database.supervisor_v3_stage_attempts("canary") != 1:
            raise SupervisorError(
                "Supervisor v3 successor requires the one exhausted original canary"
            )
        if self.database.supervisor_v3_stage_attempts("successor_canary") >= 1:
            raise SupervisorError("Supervisor v3 successor canary attempt is exhausted")
        predecessor = self._validated_successor_predecessor()
        created = datetime.now(timezone.utc)
        expires = created + timedelta(seconds=self.policy.plan_ttl_seconds)
        binding = self._binding()
        plan = {
            "kind": "codex.protocol_canary.v3.successor",
            "stage": "successor_canary",
            "binding": binding,
            "binding_sha256": _sha256_bytes(canonical_json(binding).encode("utf-8")),
            "predecessor_receipt_sha256": _sha256_bytes(
                canonical_json(predecessor).encode("utf-8")
            ),
            "predecessor_task_id": predecessor["task_id"],
            "sandbox": "read-only",
            "permission_profile": {
                "id": supervisor_v3_permission_profile("successor_canary")[0],
                "sha256": supervisor_v3_permission_profile_sha256(
                    "successor_canary"
                ),
            },
            "empty_root": True,
            "required_remote_control_status": "disabled",
            "required_remote_control_status_count": 1,
            "model": self.policy.model,
            "reasoning_effort": self.policy.reasoning_effort,
            "canonical_mutations": False,
            "background_execution": False,
            "experimental_api": False,
            "command_network_access": False,
            "created_at": created.isoformat(timespec="milliseconds"),
            "expires_at": expires.isoformat(timespec="milliseconds"),
            "confirmation_format": SUCCESSOR_CANARY_CONFIRMATION,
        }
        plan["plan_sha256"] = self._plan_digest(plan)
        task = self.database.create_supervisor_v3_task(
            stage="successor_canary",
            recipe_slug=None,
            project_slug=None,
            plan=plan,
            expires_at=plan["expires_at"],
        )
        task["required_confirmation"] = self._required_confirmation(task)
        return task

    @staticmethod
    def _source_snapshot(project: RegisteredDevelopmentProjectConfig) -> dict[str, Any]:
        return {
            "head": _git(project.root, "rev-parse", "HEAD"),
            "status": _git(project.root, "status", "--porcelain=v1", "--untracked-files=all"),
            "branch": _git(project.root, "branch", "--show-current"),
            "remotes": _git(project.root, "remote"),
        }

    def plan_fixture(self) -> dict[str, Any]:
        self._require_planning_authority("fixture")
        if self.database.supervisor_v3_stage_attempts("fixture") >= 1:
            raise SupervisorError("Supervisor v3 fixture lifetime attempt is exhausted")
        canary = self.database.latest_supervisor_v3_successor_canary_pass()
        if canary is None:
            raise SupervisorError(
                "Supervisor v3 fixture requires a passed successor canary"
            )
        binding = self._binding()
        if (canary.get("plan") or {}).get("binding") != binding:
            raise SupervisorError("Supervisor v3 canary-bound implementation drifted")
        recipe = self.policy.recipes["fixture-small-bugfix"]
        project = self.config.development.projects[recipe.project]
        source = self._source_snapshot(project)
        if (
            source["head"] != project.baseline.get("commit")
            or source["status"]
            or source["remotes"]
        ):
            raise SupervisorError("Supervisor v3 canonical fixture baseline drifted")
        created = datetime.now(timezone.utc)
        expires = created + timedelta(seconds=self.policy.plan_ttl_seconds)
        plan = {
            "kind": "codex.fixture_candidate.v3",
            "stage": "fixture",
            "recipe": "fixture-small-bugfix",
            "project": recipe.project,
            "binding": binding,
            "binding_sha256": _sha256_bytes(canonical_json(binding).encode("utf-8")),
            "successor_canary_task_sha256": _sha256_bytes(
                str(canary["id"]).encode("utf-8")
            ),
            "source_snapshot_sha256": _sha256_bytes(canonical_json(source).encode("utf-8")),
            "sandbox": "workspace-write",
            "permission_profile": {
                "id": supervisor_v3_permission_profile("fixture")[0],
                "sha256": supervisor_v3_permission_profile_sha256("fixture"),
            },
            "canonical_mutations": False,
            "background_execution": False,
            "experimental_api": False,
            "command_network_access": False,
            "created_at": created.isoformat(timespec="milliseconds"),
            "expires_at": expires.isoformat(timespec="milliseconds"),
            "confirmation_format": FIXTURE_CONFIRMATION,
        }
        plan["plan_sha256"] = self._plan_digest(plan)
        task = self.database.create_supervisor_v3_task(
            stage="fixture",
            recipe_slug="fixture-small-bugfix",
            project_slug=recipe.project,
            plan=plan,
            expires_at=plan["expires_at"],
        )
        task["required_confirmation"] = self._required_confirmation(task)
        return task

    def plan_recovery_canary(self) -> dict[str, Any]:
        self._require_planning_authority("recovery_canary")
        if self.database.supervisor_v3_stage_attempts("fixture") != 1:
            raise SupervisorError(
                "Supervisor v3 recovery canary requires the exhausted fixture attempt"
            )
        if self.database.supervisor_v3_stage_attempts("recovery_canary") >= 1:
            raise SupervisorError("Supervisor v3 recovery canary attempt is exhausted")
        predecessor = self._validated_recovery_predecessor()
        recipe = self.policy.recipes["fixture-small-bugfix"]
        project = self.config.development.projects[recipe.project]
        source = self._source_snapshot(project)
        if (
            source["head"] != project.baseline.get("commit")
            or source["status"]
            or source["remotes"]
        ):
            raise SupervisorError("Supervisor v3 canonical fixture baseline drifted")
        created = datetime.now(timezone.utc)
        expires = created + timedelta(seconds=self.policy.plan_ttl_seconds)
        binding = self._binding()
        plan = {
            "kind": "codex.fixture_recovery_canary.v3",
            "stage": "recovery_canary",
            "recipe": "fixture-small-bugfix",
            "project": recipe.project,
            "binding": binding,
            "binding_sha256": _sha256_bytes(canonical_json(binding).encode("utf-8")),
            "predecessor_receipt_sha256": _sha256_bytes(
                canonical_json(predecessor).encode("utf-8")
            ),
            "predecessor_task_id": predecessor["task_id"],
            "source_snapshot_sha256": _sha256_bytes(
                canonical_json(source).encode("utf-8")
            ),
            "sandbox": "workspace-write",
            "permission_profile": {
                "id": supervisor_v3_permission_profile("recovery_canary")[0],
                "sha256": supervisor_v3_permission_profile_sha256(
                    "recovery_canary"
                ),
            },
            "fixture_clone_required": True,
            "candidate_actions_allowed": False,
            "required_remote_control_status": "disabled",
            "required_remote_control_status_count": 1,
            "model": self.policy.model,
            "reasoning_effort": self.policy.reasoning_effort,
            "canonical_mutations": False,
            "background_execution": False,
            "experimental_api": False,
            "command_network_access": False,
            "created_at": created.isoformat(timespec="milliseconds"),
            "expires_at": expires.isoformat(timespec="milliseconds"),
            "confirmation_format": RECOVERY_CANARY_CONFIRMATION,
        }
        plan["plan_sha256"] = self._plan_digest(plan)
        task = self.database.create_supervisor_v3_task(
            stage="recovery_canary",
            recipe_slug="fixture-small-bugfix",
            project_slug=recipe.project,
            plan=plan,
            expires_at=plan["expires_at"],
        )
        task["required_confirmation"] = self._required_confirmation(task)
        return task

    def _validated_recovery_canary_pass(self) -> dict[str, Any]:
        task = self.database.latest_supervisor_v3_recovery_canary_pass()
        if task is None:
            raise SupervisorError("Supervisor v3 recovery fixture requires a passed canary")
        receipt = self._predecessor_receipt(task)
        result = task.get("result") if isinstance(task.get("result"), dict) else {}
        protocol = result.get("protocol") if isinstance(result.get("protocol"), dict) else {}
        if (
            receipt.get("stage") != "recovery_canary"
            or receipt.get("status") != "canary_passed"
            or receipt.get("attempt_count") != 1
            or receipt.get("model_contacted") is not True
            or receipt.get("process_group_terminated") is not True
            or receipt.get("credential_staging_removed") is not True
            or receipt.get("raw_output_persisted") is not False
            or receipt.get("disposable_root_verified") is not True
            or result.get("canonical_source_mutated") is not False
            or result.get("candidate_integrated") is not False
            or result.get("canonical_source_unchanged") is not True
            or protocol.get("exact_response_match") is not True
            or protocol.get("remote_control_disabled_status_count") != 1
        ):
            raise SupervisorError("Supervisor v3 recovery canary receipt drifted")
        return receipt

    def plan_recovery_fixture(self) -> dict[str, Any]:
        self._require_planning_authority("recovery_fixture")
        if self.database.supervisor_v3_stage_attempts("recovery_fixture") >= 1:
            raise SupervisorError("Supervisor v3 recovery fixture attempt is exhausted")
        canary_receipt = self._validated_recovery_canary_pass()
        canary = self.database.get_supervisor_v3_task(str(canary_receipt["task_id"]))
        if canary is None:
            raise SupervisorError("Supervisor v3 recovery canary disappeared")
        binding = self._binding()
        if (canary.get("plan") or {}).get("binding") != binding:
            raise SupervisorError("Supervisor v3 recovery-canary implementation drifted")
        recipe = self.policy.recipes["fixture-small-bugfix"]
        project = self.config.development.projects[recipe.project]
        source = self._source_snapshot(project)
        if (
            source["head"] != project.baseline.get("commit")
            or source["status"]
            or source["remotes"]
        ):
            raise SupervisorError("Supervisor v3 canonical fixture baseline drifted")
        created = datetime.now(timezone.utc)
        expires = created + timedelta(seconds=self.policy.plan_ttl_seconds)
        plan = {
            "kind": "codex.fixture_recovery_candidate.v3",
            "stage": "recovery_fixture",
            "recipe": "fixture-small-bugfix",
            "project": recipe.project,
            "binding": binding,
            "binding_sha256": _sha256_bytes(canonical_json(binding).encode("utf-8")),
            "recovery_canary_receipt_sha256": _sha256_bytes(
                canonical_json(canary_receipt).encode("utf-8")
            ),
            "recovery_canary_task_id": canary_receipt["task_id"],
            "source_snapshot_sha256": _sha256_bytes(
                canonical_json(source).encode("utf-8")
            ),
            "sandbox": "workspace-write",
            "permission_profile": {
                "id": supervisor_v3_permission_profile("recovery_fixture")[0],
                "sha256": supervisor_v3_permission_profile_sha256(
                    "recovery_fixture"
                ),
            },
            "required_remote_control_status": "disabled",
            "required_remote_control_status_count": 1,
            "canonical_mutations": False,
            "background_execution": False,
            "experimental_api": False,
            "command_network_access": False,
            "created_at": created.isoformat(timespec="milliseconds"),
            "expires_at": expires.isoformat(timespec="milliseconds"),
            "confirmation_format": RECOVERY_FIXTURE_CONFIRMATION,
        }
        plan["plan_sha256"] = self._plan_digest(plan)
        task = self.database.create_supervisor_v3_task(
            stage="recovery_fixture",
            recipe_slug="fixture-small-bugfix",
            project_slug=recipe.project,
            plan=plan,
            expires_at=plan["expires_at"],
        )
        task["required_confirmation"] = self._required_confirmation(task)
        return task

    def get_task(self, task_id: str) -> dict[str, Any]:
        self.database.expire_supervisor_v3_tasks()
        task = self.database.get_supervisor_v3_task(task_id)
        if task is None:
            raise KeyError(f"Supervisor v3 task not found: {task_id}")
        return task

    def list_tasks(
        self, *, status: str | None = None, stage: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        self.database.expire_supervisor_v3_tasks()
        return self.database.list_supervisor_v3_tasks(
            status=status, stage=stage, limit=limit
        )

    def cancel_task(self, task_id: str) -> dict[str, Any]:
        self._require_enabled()
        return self.database.cancel_supervisor_v3_task(task_id)

    def _validate_plan(self, task: dict[str, Any]) -> None:
        if task.get("status") != "planned":
            raise SupervisorError(f"Supervisor v3 task is {task.get('status')}, not planned")
        plan = task.get("plan")
        if not isinstance(plan, dict):
            raise SupervisorError("Supervisor v3 plan is malformed")
        plan_hash = plan.get("plan_sha256")
        if not isinstance(plan_hash, str) or not secrets.compare_digest(
            plan_hash, self._plan_digest(plan)
        ):
            raise SupervisorError("Supervisor v3 plan integrity check failed")
        if plan.get("binding") != self._binding():
            raise SupervisorError("Supervisor v3 implementation changed after planning")
        stage = str(task.get("stage"))
        if stage == "successor_canary":
            predecessor = self._validated_successor_predecessor()
            expected_predecessor_digest = _sha256_bytes(
                canonical_json(predecessor).encode("utf-8")
            )
            if (
                plan.get("predecessor_task_id") != predecessor["task_id"]
                or plan.get("predecessor_receipt_sha256")
                != expected_predecessor_digest
                or plan.get("required_remote_control_status") != "disabled"
                or plan.get("required_remote_control_status_count") != 1
            ):
                raise SupervisorError(
                    "Supervisor v3 successor predecessor binding drifted"
                )
        elif stage == "recovery_canary":
            predecessor = self._validated_recovery_predecessor()
            expected_predecessor_digest = _sha256_bytes(
                canonical_json(predecessor).encode("utf-8")
            )
            if (
                plan.get("predecessor_task_id") != predecessor["task_id"]
                or plan.get("predecessor_receipt_sha256")
                != expected_predecessor_digest
                or plan.get("required_remote_control_status") != "disabled"
                or plan.get("required_remote_control_status_count") != 1
                or plan.get("fixture_clone_required") is not True
                or plan.get("candidate_actions_allowed") is not False
            ):
                raise SupervisorError(
                    "Supervisor v3 recovery predecessor binding drifted"
                )
        elif stage == "recovery_fixture":
            canary_receipt = self._validated_recovery_canary_pass()
            expected_canary_digest = _sha256_bytes(
                canonical_json(canary_receipt).encode("utf-8")
            )
            if (
                plan.get("recovery_canary_task_id") != canary_receipt["task_id"]
                or plan.get("recovery_canary_receipt_sha256")
                != expected_canary_digest
                or plan.get("required_remote_control_status") != "disabled"
                or plan.get("required_remote_control_status_count") != 1
            ):
                raise SupervisorError(
                    "Supervisor v3 recovery-canary binding drifted"
                )
        if stage in V3_PROJECT_STAGES:
            recipe = self.policy.recipes["fixture-small-bugfix"]
            project = self.config.development.projects[recipe.project]
            source = self._source_snapshot(project)
            expected_source_digest = _sha256_bytes(
                canonical_json(source).encode("utf-8")
            )
            if (
                task.get("recipe_slug") != "fixture-small-bugfix"
                or task.get("project_slug") != recipe.project
                or plan.get("recipe") != "fixture-small-bugfix"
                or plan.get("project") != recipe.project
                or plan.get("source_snapshot_sha256") != expected_source_digest
                or source["head"] != project.baseline.get("commit")
                or source["status"]
                or source["remotes"]
            ):
                raise SupervisorError("Supervisor v3 fixture source binding drifted")
        expected_profile = {
            "id": supervisor_v3_permission_profile(stage)[0],
            "sha256": supervisor_v3_permission_profile_sha256(stage),
        }
        if plan.get("permission_profile") != expected_profile:
            raise SupervisorError("Supervisor v3 plan permission profile drifted")
        expected_sandbox = (
            "read-only" if stage in V3_READ_ONLY_STAGES else "workspace-write"
        )
        if plan.get("sandbox") != expected_sandbox:
            raise SupervisorError("Supervisor v3 plan sandbox drifted")
        for field in (
            "canonical_mutations",
            "background_execution",
            "experimental_api",
            "command_network_access",
        ):
            if plan.get(field) is not False:
                raise SupervisorError(f"Supervisor v3 plan broadened {field}")

    @staticmethod
    def _auth_path() -> Path:
        return Path.home().resolve() / ".codex" / "auth.json"

    def _stage_auth(self, codex_home: Path) -> tuple[int, int, int, int]:
        source = self._auth_path()
        if not source.is_file() or source.is_symlink():
            raise SupervisorError("Codex authentication source is unavailable or unsafe")
        target = codex_home / "auth.json"
        source_fd = os.open(
            source,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            before = os.fstat(source_fd)
            if not stat.S_ISREG(before.st_mode) or not (0 < before.st_size <= 1_048_576):
                raise SupervisorError("Codex authentication source size or type is unsafe")
            target_fd = os.open(
                target,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                while True:
                    chunk = os.read(source_fd, 65_536)
                    if not chunk:
                        break
                    view = memoryview(chunk)
                    while view:
                        written = os.write(target_fd, view)
                        if written <= 0:
                            raise SupervisorError("Codex authentication staging write failed")
                        view = view[written:]
                os.fsync(target_fd)
            finally:
                os.close(target_fd)
            after = os.fstat(source_fd)
        finally:
            os.close(source_fd)
        identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        if identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise SupervisorError("Codex authentication source changed while staging")
        target_stat = target.stat(follow_symlinks=False)
        if target_stat.st_size != before.st_size or stat.S_IMODE(target_stat.st_mode) != 0o600:
            raise SupervisorError("Codex authentication staging result was unsafe")
        return identity

    def _build_fixture_clone(
        self, task_root: Path, project: RegisteredDevelopmentProjectConfig
    ) -> Path:
        clone = task_root / "clone"
        completed = _run(
            [
                "git",
                "clone",
                "--no-local",
                "--no-hardlinks",
                "--no-checkout",
                str(project.root),
                str(clone),
            ],
            cwd=task_root,
            timeout=60,
        )
        if completed.returncode != 0:
            raise SupervisorError("Supervisor v3 could not create an independent clone")
        commit = str(project.baseline["commit"])
        _git(clone, "checkout", "--detach", commit)
        for remote in _git(clone, "remote").splitlines():
            if remote:
                _git(clone, "remote", "remove", remote)
        for reference in _git(clone, "for-each-ref", "--format=%(refname)").splitlines():
            if reference:
                _git(clone, "update-ref", "-d", reference)
        hooks = clone / ".git" / "hooks"
        if hooks.is_symlink():
            hooks.unlink()
        elif hooks.exists():
            shutil.rmtree(hooks)
        hooks.mkdir(mode=0o700)
        _git(clone, "config", "core.hooksPath", "/dev/null")
        if (clone / ".git" / "objects" / "info" / "alternates").exists():
            raise SupervisorError("Supervisor v3 clone shares Git objects")
        if (clone / ".gitmodules").exists():
            raise SupervisorError("Supervisor v3 fixture cannot contain submodules")
        for path in clone.rglob("*"):
            relative = path.relative_to(clone)
            if ".git" in relative.parts:
                continue
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode) or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                raise SupervisorError("Supervisor v3 fixture contains a link or special file")
            if path.name in INSTRUCTION_NAMES:
                raise SupervisorError("Supervisor v3 fixture contains inherited instructions")
        self._validate_fixture_git_metadata(clone, commit)
        return clone

    @staticmethod
    def _validate_fixture_git_metadata(clone: Path, baseline_commit: str) -> None:
        git_directory = clone / ".git"
        if not git_directory.is_dir() or git_directory.is_symlink():
            raise SupervisorError("Supervisor v3 fixture Git directory is unsafe")
        if _git(clone, "rev-parse", "HEAD") != baseline_commit:
            raise SupervisorError("Supervisor v3 fixture HEAD drifted")
        if _git(clone, "branch", "--show-current"):
            raise SupervisorError("Supervisor v3 fixture is no longer detached")
        if _git(clone, "remote"):
            raise SupervisorError("Supervisor v3 fixture acquired a Git remote")
        if _git(clone, "for-each-ref", "--format=%(refname)"):
            raise SupervisorError("Supervisor v3 fixture contains a Git ref or stash")
        hooks = git_directory / "hooks"
        if not hooks.is_dir() or hooks.is_symlink() or any(hooks.iterdir()):
            raise SupervisorError("Supervisor v3 fixture contains a Git hook")
        config_read = _run(
            [
                "git",
                "config",
                "--file",
                str(git_directory / "config"),
                "--get",
                "core.hooksPath",
            ],
            cwd=clone,
            timeout=10,
        )
        if config_read.returncode != 0 or str(config_read.stdout).strip() != "/dev/null":
            raise SupervisorError("Supervisor v3 fixture hook configuration drifted")

    def _run_worker(
        self,
        *,
        stage: str,
        root: Path,
        codex_home: Path,
        task_tmp: Path,
        prompt: str,
        expected_response: str | None,
    ) -> dict[str, Any]:
        classifier = NotificationPolicy.load(self.config.app.supervisor_v3_classifier_file)
        profile_id, _profile = supervisor_v3_permission_profile(stage)
        allowed_paths = (
            list(self.policy.recipes["fixture-small-bugfix"].allowed_paths)
            if stage in V3_EDIT_STAGES
            else []
        )
        protected_paths = [
            str(self._auth_path()),
            str(self.config.app.supervisor_v3_policy_file),
            str(self.config.app.supervisor_v3_classifier_file),
            str(self.config.app.supervisor_v3_lock_file),
        ]
        if stage in V3_PROJECT_STAGES:
            recipe = self.policy.recipes["fixture-small-bugfix"]
            protected_paths.append(str(self.config.development.projects[recipe.project].root))
        request = {
            "stage": stage,
            "root": str(root),
            "allowed_paths": allowed_paths,
            "protected_paths": protected_paths,
            "model": self.policy.model,
            "reasoning_effort": self.policy.reasoning_effort,
            "sandbox": (
                "read-only" if stage in V3_READ_ONLY_STAGES else "workspace-write"
            ),
            "permission_profile_id": profile_id,
            "permission_profile_sha256": supervisor_v3_permission_profile_sha256(stage),
            "prompt": prompt,
            "expected_response": expected_response,
            "codex_binary": str(self.policy.protocol_pin.binary_path),
            "classifications": classifier.classifications,
            "server_notification_schema_sha256": self.policy.protocol_pin.selected_schema_sha256[
                "ServerNotification.json"
            ],
            "max_protocol_line_bytes": self.policy.max_protocol_line_bytes,
            "max_protocol_events": self.policy.max_protocol_events,
        }
        worker = self.config.project_root / "scripts" / "supervisor_v3_sdk_worker.py"
        environment = {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "LANG": "C.UTF-8",
            "CODEX_HOME": str(codex_home),
            "TMPDIR": str(task_tmp),
            "CI": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "NO_UPDATE_NOTIFIER": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        process = subprocess.Popen(
            [str(self.policy.protocol_pin.sdk_python_path), str(worker), "--mode", "live"],
            cwd=root,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            start_new_session=True,
        )
        group_id = process.pid
        stop_reason: str | None = None
        group_terminated = False
        try:
            stdout, _discarded_stderr, stop_reason = _communicate_with_pause(
                process,
                canonical_json(request) + "\n",
                timeout=self.policy.turn_timeout_seconds,
                should_stop=lambda: self.paused,
            )
        finally:
            group_terminated = _terminate_process_group(process, group_id)
        if not group_terminated:
            raise _WorkerLifecycleError(
                "Supervisor v3 could not prove the SDK worker process group terminated",
                process_group_terminated=False,
            )
        if stop_reason == "paused":
            raise _WorkerLifecycleError(
                "Supervisor v3 stopped by the pause marker",
                process_group_terminated=True,
            )
        if stop_reason == "timeout":
            raise _WorkerLifecycleError(
                "Supervisor v3 SDK worker timed out",
                process_group_terminated=True,
            )
        if len(stdout.encode("utf-8")) > 65_536 or stdout.count("\n") != 1:
            raise _WorkerLifecycleError(
                "Supervisor v3 SDK worker receipt was malformed",
                process_group_terminated=True,
            )
        try:
            receipt = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise _WorkerLifecycleError(
                "Supervisor v3 SDK worker receipt was invalid",
                process_group_terminated=True,
            ) from exc
        if not isinstance(receipt, dict):
            raise _WorkerLifecycleError(
                "Supervisor v3 SDK worker receipt was invalid",
                process_group_terminated=True,
            )
        receipt["process_group_terminated"] = group_terminated
        return receipt

    def _validate_candidate(
        self,
        *,
        clone: Path,
        task_root: Path,
        project: RegisteredDevelopmentProjectConfig,
        recipe: SupervisorV2RecipeConfig,
    ) -> dict[str, Any]:
        baseline_commit = str(project.baseline["commit"])
        self._validate_fixture_git_metadata(clone, baseline_commit)
        status = _git(clone, "status", "--porcelain=v1", "--untracked-files=all")
        if not status:
            raise SupervisorError("Supervisor v3 fixture produced no candidate change")
        untracked = [line[3:] for line in status.splitlines() if line.startswith("?? ")]
        if untracked:
            raise SupervisorError("Supervisor v3 fixture produced untracked files")
        changed = [line for line in _git(clone, "diff", "--name-only", "--").splitlines() if line]
        if changed != recipe.allowed_paths or len(changed) > recipe.max_changed_files:
            raise SupervisorError("Supervisor v3 candidate changed an unauthorized path")
        for path in changed:
            target = clone / path
            if not target.is_file() or target.is_symlink():
                raise SupervisorError("Supervisor v3 candidate changed an unsafe file type")
            text = target.read_text(encoding="utf-8")
            if any(pattern.search(text) for pattern in SECRET_PATTERNS):
                raise SupervisorError("Supervisor v3 candidate contains secret-like material")
        numstat = _git(clone, "diff", "--numstat", "--")
        changed_lines = 0
        for line in numstat.splitlines():
            added, deleted, _path = line.split("\t", 2)
            if not added.isdigit() or not deleted.isdigit():
                raise SupervisorError("Supervisor v3 candidate includes a binary change")
            changed_lines += int(added) + int(deleted)
        patch = _run(
            ["git", "diff", "--binary", "--no-ext-diff", "--"],
            cwd=clone,
            timeout=30,
            text=False,
        ).stdout
        if not isinstance(patch, bytes):
            raise SupervisorError("Supervisor v3 candidate patch was unavailable")
        if changed_lines > recipe.max_changed_lines or len(patch) > recipe.max_patch_bytes:
            raise SupervisorError("Supervisor v3 candidate exceeded its fixed budget")
        for check_name in recipe.verification_checks:
            check = project.checks[check_name]
            relative_cwd = check.cwd.relative_to(project.root)
            completed = _run(
                list(check.argv),
                cwd=clone / relative_cwd,
                timeout=check.timeout_seconds,
                env={
                    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                    "LANG": "C.UTF-8",
                    "CI": "1",
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
            )
            if completed.returncode != 0:
                raise SupervisorError("Supervisor v3 fixed candidate check failed")
        self._validate_fixture_git_metadata(clone, baseline_commit)
        artifact = task_root / "candidate.patch"
        artifact.write_bytes(patch)
        os.chmod(artifact, 0o600)
        return {
            "changed_paths": changed,
            "changed_lines": changed_lines,
            "patch_bytes": len(patch),
            "patch_sha256": _sha256_bytes(patch),
            "artifact": str(artifact),
            "candidate_integrated": False,
            "git_metadata_verified": True,
        }

    def run_task(self, task_id: str, *, confirmation: str) -> dict[str, Any]:
        self._require_enabled()
        task = self.get_task(task_id)
        stage = str(task.get("stage"))
        live_enabled = {
            "canary": self.policy.live_canary_execution,
            "successor_canary": self.policy.live_successor_canary_execution,
            "fixture": self.policy.live_fixture_execution,
            "recovery_canary": self.policy.live_recovery_canary_execution,
            "recovery_fixture": self.policy.live_recovery_fixture_execution,
        }.get(stage, False)
        if not live_enabled:
            raise SupervisorError(f"Supervisor v3 {stage} live owner gate is disabled")
        required = self._required_confirmation(task)
        if len(confirmation) > 128 or not secrets.compare_digest(confirmation, required):
            raise SupervisorError(f"Exact confirmation {required!r} is required")
        action = {
            "canary": "run_canary",
            "successor_canary": "run_successor_canary",
            "fixture": "run_fixture",
            "recovery_canary": "run_recovery_canary",
            "recovery_fixture": "run_recovery_fixture",
        }.get(stage, "invalid")
        if self.permissions.decision("supervisor_v3", action) is not PermissionDecision.ALLOW:
            raise SupervisorError(f"Supervisor v3 permission denied: {action}")
        readiness = self.readiness()
        if not readiness["ready"]:
            raise SupervisorError("Supervisor v3 readiness changed after planning")
        self._validate_plan(task)
        max_total = {
            "canary": self.policy.canary_attempts_total,
            "successor_canary": self.policy.successor_canary_attempts_total,
            "fixture": self.policy.fixture_attempts_total,
            "recovery_canary": self.policy.recovery_canary_attempts_total,
            "recovery_fixture": self.policy.recovery_fixture_attempts_total,
        }.get(stage, 0)
        if max_total != 1:
            raise SupervisorError("Supervisor v3 stage attempt policy is invalid")
        task = self.database.claim_supervisor_v3_task(
            task_id,
            max_attempts_per_stage=self.policy.max_attempts_per_stage,
            max_total_attempts=max_total,
            runner_pid=os.getpid(),
        )
        task_root = self.config.supervisor_v3.runtime_dir / "tasks" / task_id
        task_root.mkdir(parents=True, mode=0o700)
        os.chmod(task_root, 0o700)
        source_before: dict[str, Any] | None = None
        project: RegisteredDevelopmentProjectConfig | None = None
        root = task_root / f"empty-{stage.replace('_', '-')}-root"
        model_contact_state = "not_dispatched"
        process_group_terminated: bool | None = None
        session_root: Path | None = None
        credential_staging_removed: bool | None = None
        auth_identity: tuple[int, int, int, int] | None = None
        auth_source_unchanged: bool | None = None
        try:
            self.database.transition_supervisor_v3_task(
                task_id, expected_statuses={"approved"}, status="preparing"
            )
            if stage in V3_PROJECT_STAGES:
                recipe = self.policy.recipes["fixture-small-bugfix"]
                project = self.config.development.projects[recipe.project]
                source_before = self._source_snapshot(project)
                root = self._build_fixture_clone(task_root, project)
            else:
                root.mkdir(mode=0o700)
            if stage in V3_RESPONSE_CANARY_STAGES:
                if stage == "successor_canary":
                    prompt = self.policy.successor_canary_prompt
                    expected = self.policy.successor_canary_expected_response
                elif stage == "recovery_canary":
                    prompt = self.policy.recovery_canary_prompt
                    expected = self.policy.recovery_canary_expected_response
                else:
                    prompt = self.policy.canary_prompt
                    expected = self.policy.canary_expected_response
            else:
                recipe = self.policy.recipes["fixture-small-bugfix"]
                prompt = recipe.task_statement
                expected = None
            with tempfile.TemporaryDirectory(
                prefix=".sdk-session-", dir=task_root
            ) as temporary:
                session_root = Path(temporary).resolve()
                os.chmod(session_root, 0o700)
                codex_home = session_root / "codex-home"
                task_tmp = session_root / "private-tmp"
                codex_home.mkdir(mode=0o700)
                task_tmp.mkdir(mode=0o700)
                auth_identity = self._stage_auth(codex_home)
                next_status = (
                    "contacting" if stage in V3_RESPONSE_CANARY_STAGES else "executing"
                )
                self.database.transition_supervisor_v3_task(
                    task_id, expected_statuses={"preparing"}, status=next_status
                )
                # If the isolated worker fails before returning its bounded receipt,
                # Atlas cannot prove whether the turn dispatch crossed the boundary.
                model_contact_state = "unknown"
                receipt = self._run_worker(
                    stage=stage,
                    root=root,
                    codex_home=codex_home,
                    task_tmp=task_tmp,
                    prompt=prompt,
                    expected_response=expected,
                )
                process_group_terminated = bool(receipt.get("process_group_terminated"))
                model_contact_state = (
                    "confirmed_contacted"
                    if receipt.get("model_contact_dispatched")
                    else "confirmed_not_contacted"
                )
                self.database.record_supervisor_v3_protocol_receipt(
                    task_id,
                    expected_statuses={next_status},
                    model_contacted=bool(receipt.get("model_contact_dispatched")),
                    envelope_count=int(receipt.get("envelope_count") or 0),
                    envelope_chain_sha256=receipt.get("envelope_chain_sha256"),
                )
                expected_profile_id = supervisor_v3_permission_profile(stage)[0]
                if (
                    receipt.get("permission_profile_id") != expected_profile_id
                    or receipt.get("permission_profile_sha256")
                    != supervisor_v3_permission_profile_sha256(stage)
                    or receipt.get("concrete_action_validation") is not True
                    or receipt.get("effective_config_verified") is not True
                    or receipt.get("thread_projection_verified") is not True
                    or (
                        stage in V3_DISABLED_STATUS_STAGES
                        and receipt.get("remote_control_disabled_status_count") != 1
                    )
                ):
                    raise SupervisorError("Supervisor v3 SDK worker policy receipt drifted")
                if self.paused:
                    raise SupervisorError("Supervisor v3 stopped by the pause marker")
                if not receipt.get("ok"):
                    raise SupervisorError(
                        f"Supervisor v3 worker stopped: {receipt.get('stop_code')}"
                    )
                source_auth = self._auth_path().stat(follow_symlinks=False)
                auth_source_unchanged = auth_identity == (
                    source_auth.st_dev,
                    source_auth.st_ino,
                    source_auth.st_size,
                    source_auth.st_mtime_ns,
                )
                if not auth_source_unchanged:
                    raise SupervisorError("Codex authentication source changed during the stage")
            credential_staging_removed = session_root is not None and not session_root.exists()
            if not credential_staging_removed:
                raise SupervisorError("Supervisor v3 credential staging cleanup failed")
            self.database.transition_supervisor_v3_task(
                task_id,
                expected_statuses={next_status},
                status="validating",
                model_contacted=bool(receipt.get("model_contact_dispatched")),
                envelope_count=int(receipt.get("envelope_count") or 0),
                envelope_chain_sha256=receipt.get("envelope_chain_sha256"),
            )
            result: dict[str, Any] = {
                "attempt_consumed": True,
                "model_contacted": bool(receipt.get("model_contact_dispatched")),
                "model_contact_state": model_contact_state,
                "protocol": receipt,
                "canonical_source_mutated": False,
                "candidate_integrated": False,
                "raw_output_persisted": False,
                "process_group_terminated": process_group_terminated,
                "permission_profile_verified": True,
                "auth_source_unchanged": auth_source_unchanged,
                "credential_staging_removed": credential_staging_removed,
                "plan_binding_verified": True,
                "disposable_root_verified": root.is_dir() and not root.is_symlink(),
            }
            terminal: str
            if stage in V3_RESPONSE_CANARY_STAGES:
                if receipt.get("exact_response_match") is not True:
                    raise SupervisorError("Supervisor v3 canary post-state validation failed")
                if stage in V3_READ_ONLY_STAGES:
                    if any(root.iterdir()):
                        raise SupervisorError(
                            "Supervisor v3 canary post-state validation failed"
                        )
                else:
                    if project is None or source_before is None:
                        raise SupervisorError(
                            "Supervisor v3 recovery canary context disappeared"
                        )
                    baseline = str(project.baseline["commit"])
                    self._validate_fixture_git_metadata(root, baseline)
                    if _git(
                        root, "status", "--porcelain=v1", "--untracked-files=all"
                    ):
                        raise SupervisorError(
                            "Supervisor v3 recovery canary changed its disposable clone"
                        )
                    canonical_unchanged = self._source_snapshot(project) == source_before
                    if not canonical_unchanged:
                        raise SupervisorError(
                            "Supervisor v3 canonical fixture changed during recovery canary"
                        )
                    result["canonical_source_unchanged"] = True
                    result["git_metadata_verified"] = True
                terminal = "canary_passed"
            else:
                if project is None or source_before is None:
                    raise SupervisorError("Supervisor v3 fixture context disappeared")
                self.database.transition_supervisor_v3_task(
                    task_id,
                    expected_statuses={"validating"},
                    status="verifying",
                    model_contacted=bool(receipt.get("model_contact_dispatched")),
                    envelope_count=int(receipt.get("envelope_count") or 0),
                    envelope_chain_sha256=receipt.get("envelope_chain_sha256"),
                )
                recipe = self.policy.recipes["fixture-small-bugfix"]
                result["candidate"] = self._validate_candidate(
                    clone=root,
                    task_root=task_root,
                    project=project,
                    recipe=recipe,
                )
                if self._source_snapshot(project) != source_before:
                    raise SupervisorError("Supervisor v3 canonical fixture changed")
                terminal = "candidate_ready"
            expected_status = (
                {"validating"}
                if stage in V3_RESPONSE_CANARY_STAGES
                else {"verifying"}
            )
            return self.database.transition_supervisor_v3_task(
                task_id,
                expected_statuses=expected_status,
                status=terminal,
                result=result,
                model_contacted=bool(receipt.get("model_contact_dispatched")),
                envelope_count=int(receipt.get("envelope_count") or 0),
                envelope_chain_sha256=receipt.get("envelope_chain_sha256"),
            )
        except KeyboardInterrupt:
            credential_staging_removed = (
                None if session_root is None else not session_root.exists()
            )
            current = self.database.get_supervisor_v3_task(task_id)
            if current and current["status"] in ACTIVE_V3_STATUSES:
                self.database.transition_supervisor_v3_task(
                    task_id,
                    expected_statuses={current["status"]},
                    status="interrupted",
                    result={
                        "attempt_consumed": True,
                        "candidate_integrated": False,
                        "credential_staging_removed": credential_staging_removed,
                        "process_group_terminated": process_group_terminated,
                    },
                    error="Supervisor v3 runner was interrupted",
                    stop_code="interrupted",
                    model_contacted=bool(current.get("model_contacted")),
                )
            raise
        except Exception as exc:
            if isinstance(exc, _WorkerLifecycleError):
                process_group_terminated = exc.process_group_terminated
            credential_staging_removed = (
                None if session_root is None else not session_root.exists()
            )
            if auth_identity is not None:
                try:
                    source_auth = self._auth_path().stat(follow_symlinks=False)
                    auth_source_unchanged = auth_identity == (
                        source_auth.st_dev,
                        source_auth.st_ino,
                        source_auth.st_size,
                        source_auth.st_mtime_ns,
                    )
                except OSError:
                    auth_source_unchanged = None
            current = self.database.get_supervisor_v3_task(task_id)
            if current is None or current["status"] not in ACTIVE_V3_STATUSES:
                raise
            source_state: bool | None = None
            if project is not None and source_before is not None:
                try:
                    source_state = self._source_snapshot(project) == source_before
                except Exception:
                    source_state = None
            stopped = self.paused or "pause" in str(exc).lower()
            return self.database.transition_supervisor_v3_task(
                task_id,
                expected_statuses={current["status"]},
                status="stopped" if stopped else "failed",
                result={
                    "attempt_consumed": True,
                    "model_contacted": bool(current.get("model_contacted")),
                    "model_contact_state": model_contact_state,
                    "canonical_source_unchanged": source_state,
                    "candidate_integrated": False,
                    "raw_output_persisted": False,
                    "process_group_terminated": process_group_terminated,
                    "auth_source_unchanged": auth_source_unchanged,
                    "credential_staging_removed": credential_staging_removed,
                    "plan_binding_verified": True,
                    "disposable_root_verified": root.is_dir() and not root.is_symlink(),
                },
                error=str(exc)[:500] or exc.__class__.__name__,
                stop_code="paused" if stopped else "stage_failed",
                model_contacted=bool(current.get("model_contacted")),
                envelope_count=int(current.get("envelope_count") or 0),
                envelope_chain_sha256=current.get("envelope_chain_sha256"),
            )


__all__ = [
    "SupervisorV3ReadinessInspector",
    "SupervisorV3Service",
]
