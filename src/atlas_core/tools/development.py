from __future__ import annotations

import hashlib
import os
import selectors
import signal
import shutil
import stat
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timezone
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable

from atlas_core.config import (
    DevelopmentRegistryConfig,
    RegisteredDevelopmentProjectConfig,
)
from atlas_core.errors import ToolError
from atlas_core.development_control import DevelopmentControl, DevelopmentStopped
from atlas_core.tools.base import Tool


class _SelfdevCleanupError(ToolError):
    """Cleanup could not be verified; the project must remain paused."""


class _SelfdevWriteError(ToolError):
    def __init__(self, message: str, *, replaced: bool):
        super().__init__(message)
        self.replaced = replaced


class DevelopmentTool(Tool):
    """Operate only inside owner-registered software projects."""

    name = "development"
    _SELFDEV_CONTEXT_MAX_FILES = 6
    _SELFDEV_CONTEXT_MAX_TERMS = 8
    _SELFDEV_CONTEXT_MAX_CHARS = 3_200
    _SELFDEV_MAX_EDITS = 3
    _SELFDEV_MAX_REPLACEMENTS_PER_FILE = 8
    _CHECK_MAX_OUTPUT_BYTES = 8 * 1024 * 1024
    _CONTROL_NAMES = {
        ".atlas_development_control",
        ".atlas_home",
        ".atlas_tmp",
        ".atlas_trash",
        ".atlas_versions",
        ".git",
        ".next",
        ".wrangler",
        "dist",
        "node_modules",
    }

    def __init__(
        self,
        registry: DevelopmentRegistryConfig,
        *,
        control_root: str | Path,
        max_file_bytes: int,
    ) -> None:
        self.constitution = None
        self.projects = dict(registry.projects)
        self.control_root = Path(control_root).expanduser().resolve()
        self.control_root.mkdir(parents=True, exist_ok=True)
        self.control = DevelopmentControl(self.control_root, [slug for slug, project in self.projects.items() if project.self_development])
        self.max_file_bytes = max_file_bytes
        self.versions_root = self.control_root / ".atlas_versions" / "development"
        self.trash_root = self.control_root / ".atlas_trash" / "development"
        self.home_root = self.control_root / ".atlas_home" / "development"
        self.tmp_root = self.control_root / ".atlas_tmp" / "development"
        for path in (
            self.versions_root,
            self.trash_root,
            self.home_root,
            self.tmp_root,
        ):
            path.mkdir(parents=True, exist_ok=True)

    def _registered(
        self, arguments: dict[str, Any], *, action: str
    ) -> tuple[str, RegisteredDevelopmentProjectConfig]:
        if self.constitution is not None:
            self.constitution.check_current()
        slug = arguments.get("project")
        if not isinstance(slug, str) or not slug.strip():
            raise ToolError("A registered project slug is required")
        project = self.projects.get(slug)
        if project is None:
            raise ToolError(f"Project is not registered for development: {slug}")
        if action not in project.allowed_actions:
            raise ToolError(f"Action {action} is not enabled for registered project {slug}")
        if not project.root.exists() or not project.root.is_dir():
            raise ToolError(f"Registered project root is unavailable: {slug}")
        return slug, project

    def _selfdev_registered(
        self, arguments: dict[str, Any], *, action: str
    ) -> tuple[str, RegisteredDevelopmentProjectConfig]:
        """Resolve the one separately registered, isolated selfdev target."""

        slug, project = self._registered(arguments, action=action)
        if not project.self_development:
            raise ToolError(
                "Self-development orchestration is not enabled for registered "
                f"project {slug}"
            )
        return slug, project

    def _require_selfdev_editable(
        self, project: RegisteredDevelopmentProjectConfig, path: Path
    ) -> None:
        """Limit self-development writes to owner-approved low-risk subtrees."""

        if self._is_foundational(path.relative_to(project.root)) or self._is_blocked(project, path.relative_to(project.root)):
            raise ToolError("Foundational controls require an owner-reviewed installation; self-development edits remain limited to owner-approved writable paths")
        relative = self._display(project, path)
        if not any(
            relative == prefix or relative.startswith(f"{prefix.rstrip('/')}/")
            for prefix in project.selfdev_editable_paths
        ):
            raise ToolError(
                "Self-development edits are limited to owner-approved writable paths"
            )

    @staticmethod
    def _content_sha256(content: str) -> str:
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    @staticmethod
    def _relative_parts(path: Path) -> tuple[str, ...]:
        return tuple(part for part in path.parts if part not in {"", "."})

    def _is_foundational(self, relative: Path) -> bool:
        parts = self._relative_parts(relative)
        # A model-generated source edit cannot amend its own authority. The
        # owner release path is separate and retains versioned rollback.
        protected = (
            "src/atlas_core/governance", "src/atlas_core/resources/constitution",
            "src/atlas_core/services.py", "src/atlas_core/permissions.py",
            "src/atlas_core/tools/manager.py", "src/atlas_core/tools/development.py",
            "src/atlas_core/development_control.py", "src/atlas_core/runtime.py",
            "src/atlas_core/api.py",
            "src/atlas_core/coding_connection", "src/atlas_core/coding_owner.py",
            "src/atlas_core/coding_preparation.py", "src/atlas_core/coding_execution.py",
            "src/atlas_core/coding_aider.py", "src/atlas_core/worker_lifetime.py",
            "src/atlas_core/worker_peer.py", "src/atlas_core/worker_peer_client.py",
        )
        return self.constitution is not None and any(
            parts[:len(Path(name).parts)] == Path(name).parts
            or Path(name).parts[:len(parts)] == parts for name in protected)

    def _is_blocked(
        self, project: RegisteredDevelopmentProjectConfig, relative: Path
    ) -> bool:
        parts = self._relative_parts(relative)
        if any(
            part in self._CONTROL_NAMES
            or part.startswith(".env")
            for part in parts
        ):
            return True
        for configured in project.blocked_paths:
            blocked = self._relative_parts(Path(configured))
            if parts[: len(blocked)] == blocked:
                return True
        return False

    def _resolve(
        self,
        project: RegisteredDevelopmentProjectConfig,
        supplied: Any,
        *,
        allow_root: bool = False,
        for_write: bool = False,
    ) -> Path:
        if not isinstance(supplied, str) or not supplied.strip():
            if allow_root:
                supplied = "."
            else:
                raise ToolError("A non-empty project-relative path is required")
        relative = Path(supplied)
        if relative.is_absolute() or ".." in relative.parts:
            raise ToolError("Path escapes the registered project")
        if for_write and self._is_foundational(relative):
            raise ToolError("Foundational controls require an owner-reviewed installation; self-development edits remain limited to owner-approved writable paths")
        if self._is_blocked(project, relative):
            raise ToolError("Registered project control or sensitive paths are blocked")

        cursor = project.root
        for part in self._relative_parts(relative):
            cursor = cursor / part
            if cursor.is_symlink():
                raise ToolError("Symbolic links are not supported")

        candidate = (project.root / relative).resolve()
        if candidate != project.root and project.root not in candidate.parents:
            raise ToolError("Path escapes the registered project")
        if not allow_root and candidate == project.root:
            raise ToolError("This action cannot target the registered project root")
        return candidate

    @staticmethod
    def _display(project: RegisteredDevelopmentProjectConfig, path: Path) -> str:
        return str(path.relative_to(project.root)) if path != project.root else "."

    def _require_regular_file(
        self, project: RegisteredDevelopmentProjectConfig, path: Path
    ) -> None:
        if not path.exists():
            raise ToolError(f"File not found: {self._display(project, path)}")
        if path.is_symlink():
            raise ToolError("Symbolic links are not supported")
        if not path.is_file():
            raise ToolError(f"Not a regular file: {self._display(project, path)}")

    def _write_atomic(self, path: Path, content: str) -> None:
        encoded = content.encode("utf-8")
        if len(encoded) > self.max_file_bytes:
            raise ToolError(
                f"Content exceeds the {self.max_file_bytes}-byte registered-project limit"
            )
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, path)
        finally:
            temporary_path.unlink(missing_ok=True)

    def _backup(self, slug: str, project: RegisteredDevelopmentProjectConfig, path: Path) -> Path:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        relative = path.relative_to(project.root)
        backup_dir = self.versions_root / slug / relative.parent
        backup_dir.mkdir(parents=True, exist_ok=True)
        backup = backup_dir / (
            f"{relative.name}.{timestamp}.{uuid.uuid4().hex[:8]}.bak"
        )
        shutil.copy2(path, backup)
        return backup

    @staticmethod
    @contextmanager
    def _selfdev_directory(directory: Path):
        """Pin an absolute directory without following any link component."""
        if not directory.is_absolute() or ".." in directory.parts:
            raise ToolError("Unsafe selfdev directory")
        descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in directory.parts[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            yield descriptor
        except OSError as exc:
            raise ToolError("Selfdev path is unavailable or unsafe") from exc
        finally:
            os.close(descriptor)

    @staticmethod
    def _selfdev_signature(value):
        return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
                value.st_ctime_ns, value.st_mode, value.st_nlink)

    def _selfdev_snapshot(self, path: Path, *, parent_fd=None) -> tuple[bytes, int]:
        if parent_fd is None:
            with self._selfdev_directory(path.parent) as parent:
                return self._selfdev_snapshot(path, parent_fd=parent)
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=parent_fd)
            try:
                before = os.fstat(fd)
                if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                    raise ToolError("Selfdev requires a regular single-link file")
                if before.st_uid != os.getuid():
                    raise ToolError("Selfdev requires an owner-owned file")
                if before.st_size > self.max_file_bytes:
                    raise ToolError("Selfdev original exceeds the configured file limit")
                with os.fdopen(os.dup(fd), "rb") as stream:
                    content = stream.read(self.max_file_bytes + 1)
                after = os.fstat(fd)
                current = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
                if (len(content) > self.max_file_bytes or
                    self._selfdev_signature(before) != self._selfdev_signature(after) or
                    self._selfdev_signature(after) != self._selfdev_signature(current)):
                    raise ToolError("Selfdev file changed while being inspected")
                return content, stat.S_IMODE(before.st_mode)
            finally:
                os.close(fd)
        except OSError as exc:
            raise ToolError("Selfdev file is unavailable or unsafe") from exc

    def _selfdev_replace(self, path: Path, expected: bytes, replacement: bytes, mode: int) -> None:
        """Conditional replacement, requiring a quiescent development copy.

        Descriptor anchoring and repeated checks detect ordinary drift; they are
        not an atomic compare-and-swap or a malicious same-user sandbox.
        """
        if len(replacement) > self.max_file_bytes:
            raise ToolError("Selfdev replacement exceeds the configured file limit")
        replaced = False
        try:
            with self._selfdev_directory(path.parent) as parent:
                if self._selfdev_snapshot(path, parent_fd=parent) != (expected, mode):
                    raise ToolError("Selfdev evidence is stale before replacement")
                temporary = f".atlas-selfdev-{uuid.uuid4().hex}.tmp"
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=parent)
                try:
                    with os.fdopen(fd, "wb") as stream:
                        stream.write(replacement)
                        stream.flush()
                        os.fchmod(stream.fileno(), mode)
                        os.fsync(stream.fileno())
                    if self._selfdev_snapshot(path, parent_fd=parent) != (expected, mode):
                        raise ToolError("Selfdev evidence is stale before replacement")
                    with self._selfdev_directory(path.parent) as current:
                        a, b = os.fstat(parent), os.fstat(current)
                        if (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino):
                            raise ToolError("Selfdev parent directory changed")
                    os.replace(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent)
                    replaced = True
                    os.fsync(parent)
                finally:
                    try:
                        os.unlink(temporary, dir_fd=parent)
                    except FileNotFoundError:
                        pass
        except Exception as exc:
            # Include temporary-file and parent-descriptor cleanup failures.
            # A completed rename remains ours even when finalization fails.
            raise _SelfdevWriteError("Selfdev replacement failed", replaced=replaced) from exc

    def _selfdev_backup(self, slug: str, item: dict[str, Any]) -> Path:
        directory = self.versions_root / slug
        directory.mkdir(exist_ok=True)
        path = directory / f"selfdev-{uuid.uuid4().hex}.bak"
        with self._selfdev_directory(directory) as parent:
            fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=parent)
            with os.fdopen(fd, "wb") as stream:
                stream.write(item["original_bytes"])
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(parent)
        return path

    def _selfdev_rollback(self, items: list[dict[str, Any]]) -> dict[str, Any]:
        restored, unresolved = [], []
        for item in reversed(items):
            try:
                current = self._selfdev_snapshot(item["path"])
                if current == (item["original_bytes"], item["mode"]):
                    restored.append(item["display_path"])
                    continue
                self._selfdev_replace(item["path"], item["updated_bytes"],
                                      item["original_bytes"], item["mode"])
                restored.append(item["display_path"])
            except Exception:
                unresolved.append(item["display_path"])
        return {"status": "incomplete" if unresolved else "completed",
                "restored": restored, "unresolved": unresolved}

    def _selfdev_recover(self, items: list[dict[str, Any]]) -> dict[str, Any]:
        """Never report complete recovery when the recovery routine itself fails."""
        try:
            return self._selfdev_rollback(items)
        except BaseException:
            # Interrupted recovery is incomplete; it cannot inherit the
            # successful cleanup status of an earlier operation.
            return {"status": "incomplete", "restored": [],
                    "unresolved": [item["display_path"] for item in items]}

    @staticmethod
    def _stop_selfdev_process(process) -> None:
        # A successful leader exit does not establish that its children exited.
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(process.pid, sig)
            except ProcessLookupError:
                break
            if sig == signal.SIGTERM:
                # Reap a terminated leader before signaling the group again.
                # macOS can return EPERM when the only group member is a zombie.
                try:
                    process.wait(timeout=0.1)
                except subprocess.TimeoutExpired:
                    pass
        process.wait(timeout=3)
        deadline = time.monotonic() + 1
        while True:
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                return
            if time.monotonic() >= deadline:
                raise _SelfdevCleanupError("Configured check process group is still present")
            time.sleep(0.05)

    def _checkpoint(self, slug):
        self.control.checkpoint(slug, self.control.epoch(slug))

    def _run_selfdev_check(self, slug, project, check_name) -> dict[str, Any]:
        """Bounded pipe capture for the one fixed self-development check."""
        if os.name != "posix":
            raise ToolError("Bounded selfdev checks require POSIX process groups")
        check = project.checks[check_name]
        cwd = self._resolve(project, str(check.cwd), allow_root=True)
        argv = list(check.argv)
        captures = {name: {"tail": bytearray(), "bytes": 0, "hash": hashlib.sha256()}
                    for name in ("stdout", "stderr")}
        process = None
        try:
            with self._selfdev_directory(cwd):
                pass
            self._checkpoint(slug)
            process = subprocess.Popen(argv, cwd=cwd, env=self._process_env(slug),
                                       shell=False, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       start_new_session=True)
            deadline = time.monotonic() + check.timeout_seconds
            with selectors.DefaultSelector() as selector:
                for name in captures:
                    pipe = getattr(process, name)
                    os.set_blocking(pipe.fileno(), False)
                    selector.register(pipe, selectors.EVENT_READ, name)
                while selector.get_map() or process.poll() is None:
                    self._checkpoint(slug)
                    if time.monotonic() >= deadline:
                        raise ToolError(f"Configured check timed out after {check.timeout_seconds} seconds")
                    for key, _ in selector.select(timeout=0.05):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        capture = captures[key.data]
                        capture["bytes"] += len(chunk)
                        if capture["bytes"] > self._CHECK_MAX_OUTPUT_BYTES:
                            raise ToolError("Configured check exceeded the output limit")
                        capture["hash"].update(chunk)
                        capture["tail"].extend(chunk)
                        del capture["tail"][:-100_000]
            returncode = process.wait()
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                pass
            else:
                raise ToolError("Configured check left child processes running")
        except OSError as exc:
            raise ToolError("Configured selfdev executable or directory is unavailable") from exc
        finally:
            if process is not None:
                cleanup_error = None
                try:
                    self._stop_selfdev_process(process)
                except BaseException as exc:
                    # An interruption during cleanup cannot prove quiescence.
                    cleanup_error = exc
                finally:
                    for pipe in (process.stdout, process.stderr):
                        try:
                            pipe.close()
                        except BaseException as exc:
                            cleanup_error = cleanup_error or exc
                if cleanup_error is not None:
                    raise _SelfdevCleanupError("Configured check cleanup could not be verified") from cleanup_error
        result = {"project": slug, "check": check_name, "description": check.description,
                  "cwd": self._display(project, cwd), "argv": argv, "returncode": returncode,
                  "output_truncated": any(value["bytes"] > 100_000 for value in captures.values())}
        for name, capture in captures.items():
            result[name] = bytes(capture["tail"]).decode("utf-8", errors="replace")
            result[name + "_bytes"] = capture["bytes"]
            result[name + "_sha256"] = capture["hash"].hexdigest()
        return result

    def _process_env(self, slug: str) -> dict[str, str]:
        home = self.home_root / slug
        temporary = self.tmp_root / slug
        package_store = temporary / "pnpm-store"
        home.mkdir(parents=True, exist_ok=True)
        temporary.mkdir(parents=True, exist_ok=True)
        package_store.mkdir(parents=True, exist_ok=True)
        return {
            "PATH": os.getenv("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"),
            "HOME": str(home),
            "TMPDIR": str(temporary),
            "LANG": os.getenv("LANG", "C.UTF-8"),
            "CI": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "NEXT_TELEMETRY_DISABLED": "1",
            "NO_UPDATE_NOTIFIER": "1",
            "COREPACK_ENABLE_DOWNLOAD_PROMPT": "0",
            # Package-manager checks must use already available dependencies.
            # This prevents an ordinary registered check from silently turning
            # into dependency installation or registry access.
            "npm_config_offline": "true",
            "pnpm_config_offline": "true",
            "npm_config_store_dir": str(package_store),
            "pnpm_config_store_dir": str(package_store),
        }

    def _run_process(
        self,
        *,
        slug: str,
        argv: list[str],
        cwd: Path,
        timeout_seconds: float,
    ) -> dict[str, Any]:
        try:
            completed = subprocess.run(
                argv,
                cwd=cwd,
                env=self._process_env(slug),
                shell=False,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except FileNotFoundError as exc:
            raise ToolError(f"Configured executable not found: {argv[0]}") from exc
        except subprocess.TimeoutExpired as exc:
            raise ToolError(
                f"Configured check timed out after {timeout_seconds} seconds"
            ) from exc
        return {
            "argv": argv,
            "returncode": completed.returncode,
            "stdout": completed.stdout[-100_000:],
            "stderr": completed.stderr[-100_000:],
            "output_truncated": len(completed.stdout) > 100_000
            or len(completed.stderr) > 100_000,
        }

    @staticmethod
    def _terminate_process(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGTERM)
            else:
                process.terminate()
            process.wait(timeout=3)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            if process.poll() is None:
                try:
                    if os.name == "posix":
                        os.killpg(process.pid, signal.SIGKILL)
                    else:
                        process.kill()
                except ProcessLookupError:
                    pass
                process.wait(timeout=3)

    def _run_process_interruptible(
        self,
        *,
        slug: str,
        argv: list[str],
        cwd: Path,
        timeout_seconds: float,
        should_stop: Callable[[], bool],
    ) -> dict[str, Any]:
        """Run a fixed check while polling an out-of-band Supervisor stop control."""

        with tempfile.TemporaryFile(mode="w+b") as stdout_file, tempfile.TemporaryFile(
            mode="w+b"
        ) as stderr_file:
            try:
                process = subprocess.Popen(
                    argv,
                    cwd=cwd,
                    env=self._process_env(slug),
                    shell=False,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    start_new_session=os.name == "posix",
                )
            except FileNotFoundError as exc:
                raise ToolError(f"Configured executable not found: {argv[0]}") from exc

            stopped = False
            deadline = time.monotonic() + timeout_seconds
            try:
                while process.poll() is None:
                    if should_stop():
                        stopped = True
                        self._terminate_process(process)
                        break
                    if time.monotonic() >= deadline:
                        self._terminate_process(process)
                        raise ToolError(
                            f"Configured check timed out after {timeout_seconds} seconds"
                        )
                    time.sleep(0.1)
            except BaseException:
                self._terminate_process(process)
                raise

            returncode = process.wait()

            def captured(handle) -> tuple[str, int, str]:
                handle.flush()
                size = handle.tell()
                handle.seek(0)
                digest = hashlib.sha256()
                while chunk := handle.read(1024 * 1024):
                    digest.update(chunk)
                handle.seek(max(0, size - 100_000))
                return (
                    handle.read().decode("utf-8", errors="replace"),
                    size,
                    digest.hexdigest(),
                )

            stdout, stdout_bytes, stdout_sha256 = captured(stdout_file)
            stderr, stderr_bytes, stderr_sha256 = captured(stderr_file)
            return {
                "argv": argv,
                "returncode": returncode,
                "stdout": stdout,
                "stderr": stderr,
                "stdout_bytes": stdout_bytes,
                "stderr_bytes": stderr_bytes,
                "stdout_sha256": stdout_sha256,
                "stderr_sha256": stderr_sha256,
                "output_truncated": stdout_bytes > 100_000 or stderr_bytes > 100_000,
                "stopped": stopped,
            }

    def status(self, arguments: dict[str, Any]) -> dict[str, Any]:
        slug, project = self._registered(arguments, action="status")
        base = {
            "project": slug,
            "name": project.name,
            "root": str(project.root),
            "action_tier": project.action_tier,
            "allowed_actions": list(project.allowed_actions),
            "checks": sorted(project.checks),
            "baseline": dict(project.baseline),
            "pause_conditions": list(project.pause_conditions),
        }
        inside = self._run_process(
            slug=slug,
            argv=["git", "rev-parse", "--is-inside-work-tree"],
            cwd=project.root,
            timeout_seconds=30,
        )
        if inside["returncode"] != 0 or inside["stdout"].strip() != "true":
            return base | {
                "repository": False,
                "branch": None,
                "head": None,
                "upstream": None,
                "clean": False,
                "changes": [],
            }

        def git_output(argv: list[str]) -> tuple[int, str]:
            result = self._run_process(
                slug=slug, argv=argv, cwd=project.root, timeout_seconds=30
            )
            return int(result["returncode"]), str(result["stdout"]).strip()

        _, branch = git_output(["git", "branch", "--show-current"])
        head_code, head = git_output(["git", "rev-parse", "HEAD"])
        upstream_code, upstream = git_output(
            ["git", "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"]
        )
        _, porcelain = git_output(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"]
        )
        changes = porcelain.splitlines() if porcelain else []
        return base | {
            "repository": True,
            "branch": branch or None,
            "head": head if head_code == 0 else None,
            "upstream": upstream if upstream_code == 0 else None,
            "clean": not changes,
            "changes": changes[:1_000],
            "changes_truncated": len(changes) > 1_000,
        }

    def list_directory(self, arguments: dict[str, Any]) -> dict[str, Any]:
        slug, project = self._registered(arguments, action="list")
        path = self._resolve(
            project, arguments.get("path", "."), allow_root=True
        )
        if not path.exists() or not path.is_dir() or path.is_symlink():
            raise ToolError("path must be a registered project directory")
        entries: list[dict[str, Any]] = []
        for child in sorted(path.iterdir(), key=lambda item: item.name.lower()):
            relative = child.relative_to(project.root)
            if self._is_blocked(project, relative):
                continue
            stat = child.lstat()
            entries.append(
                {
                    "name": child.name,
                    "path": str(relative),
                    "type": "symlink"
                    if child.is_symlink()
                    else "directory"
                    if child.is_dir()
                    else "file",
                    "size": stat.st_size,
                }
            )
            if len(entries) >= 1_000:
                break
        return {
            "project": slug,
            "path": self._display(project, path),
            "entries": entries,
        }

    def read_file(self, arguments: dict[str, Any]) -> dict[str, Any]:
        slug, project = self._registered(arguments, action="read")
        path = self._resolve(project, arguments.get("path"))
        self._require_regular_file(project, path)
        size = path.stat().st_size
        if size > self.max_file_bytes:
            raise ToolError(f"File is {size} bytes; limit is {self.max_file_bytes} bytes")
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise ToolError("Only UTF-8 text files are supported") from exc
        return {
            "project": slug,
            "path": self._display(project, path),
            "size": size,
            "content": content,
        }

    def search_files(self, arguments: dict[str, Any]) -> dict[str, Any]:
        slug, project = self._registered(arguments, action="search")
        query = arguments.get("query")
        if not isinstance(query, str) or not query:
            raise ToolError("query must be a non-empty string")
        start = self._resolve(
            project, arguments.get("path", "."), allow_root=True
        )
        if not start.exists() or not start.is_dir() or start.is_symlink():
            raise ToolError("path must be a registered project directory")
        try:
            limit = min(max(int(arguments.get("limit", 50)), 1), 200)
        except (TypeError, ValueError) as exc:
            raise ToolError("limit must be an integer") from exc
        matches: list[dict[str, Any]] = []
        lowered = query.lower()
        for current, directories, filenames in os.walk(start, followlinks=False):
            current_path = Path(current)
            directories[:] = [
                name
                for name in directories
                if not (current_path / name).is_symlink()
                and not self._is_blocked(
                    project, (current_path / name).relative_to(project.root)
                )
            ]
            for filename in filenames:
                path = current_path / filename
                relative = path.relative_to(project.root)
                if path.is_symlink() or self._is_blocked(project, relative):
                    continue
                try:
                    if path.stat().st_size > self.max_file_bytes:
                        continue
                    lines = path.read_text(encoding="utf-8").splitlines()
                except (OSError, UnicodeDecodeError):
                    continue
                for number, line in enumerate(lines, start=1):
                    if lowered in line.lower():
                        matches.append(
                            {
                                "path": str(relative),
                                "line": number,
                                "text": line[:500],
                            }
                        )
                        if len(matches) >= limit:
                            return {
                                "project": slug,
                                "query": query,
                                "path": self._display(project, start),
                                "matches": matches,
                            }
        return {
            "project": slug,
            "query": query,
            "path": self._display(project, start),
            "matches": matches,
        }

    def create_file(self, arguments: dict[str, Any]) -> dict[str, Any]:
        slug, project = self._registered(arguments, action="create")
        path = self._resolve(project, arguments.get("path"), for_write=True)
        if path.exists() or path.is_symlink():
            raise ToolError(f"Path already exists: {self._display(project, path)}")
        content = arguments.get("content", "")
        if not isinstance(content, str):
            raise ToolError("content must be a string")
        self._write_atomic(path, content)
        return {
            "project": slug,
            "path": self._display(project, path),
            "created": True,
            "size": path.stat().st_size,
        }

    def modify_file(self, arguments: dict[str, Any]) -> dict[str, Any]:
        slug, project = self._registered(arguments, action="modify")
        path = self._resolve(project, arguments.get("path"), for_write=True)
        self._require_regular_file(project, path)
        content = arguments.get("content")
        if not isinstance(content, str):
            raise ToolError("content must be a string")
        backup = self._backup(slug, project, path)
        self._write_atomic(path, content)
        return {
            "project": slug,
            "path": self._display(project, path),
            "modified": True,
            "size": path.stat().st_size,
            "backup": str(backup.relative_to(self.control_root)),
        }

    def delete_path(self, arguments: dict[str, Any]) -> dict[str, Any]:
        slug, project = self._registered(arguments, action="delete")
        path = self._resolve(project, arguments.get("path"), for_write=True)
        if not path.exists():
            raise ToolError(f"Path not found: {self._display(project, path)}")
        if path.is_symlink():
            raise ToolError("Symbolic links are not supported")
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        relative = path.relative_to(project.root)
        trash = self.trash_root / slug / f"{timestamp}-{uuid.uuid4().hex[:8]}" / relative
        trash.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(path), str(trash))
        return {
            "project": slug,
            "path": str(relative),
            "deleted": True,
            "recoverable_from": str(trash.relative_to(self.control_root)),
        }

    def _run_registered_check(
        self,
        slug: str,
        project: RegisteredDevelopmentProjectConfig,
        check_name: Any,
    ) -> dict[str, Any]:
        if not isinstance(check_name, str) or not check_name.strip():
            raise ToolError("A configured check name is required")
        check = project.checks.get(check_name)
        if check is None:
            raise ToolError(f"Check is not registered for {slug}: {check_name}")
        cwd = self._resolve(project, str(check.cwd), allow_root=True)
        if not cwd.exists() or not cwd.is_dir() or cwd.is_symlink():
            raise ToolError(f"Configured check directory is unavailable: {check.cwd}")
        result = self._run_process(
            slug=slug,
            argv=list(check.argv),
            cwd=cwd,
            timeout_seconds=check.timeout_seconds,
        )
        return {
            "project": slug,
            "check": check_name,
            "description": check.description,
            "cwd": self._display(project, cwd),
        } | result

    def run_check(self, arguments: dict[str, Any]) -> dict[str, Any]:
        slug, project = self._registered(arguments, action="run_check")
        return self._run_registered_check(slug, project, arguments.get("check"))

    def run_check_interruptible(
        self,
        arguments: dict[str, Any],
        *,
        should_stop: Callable[[], bool],
    ) -> dict[str, Any]:
        """Run only a registered check with an external, non-model stop callback."""

        slug, project = self._registered(arguments, action="run_check")
        check_name = arguments.get("check")
        if not isinstance(check_name, str) or not check_name.strip():
            raise ToolError("A configured check name is required")
        check = project.checks.get(check_name)
        if check is None:
            raise ToolError(f"Check is not registered for {slug}: {check_name}")
        cwd = self._resolve(project, str(check.cwd), allow_root=True)
        if not cwd.exists() or not cwd.is_dir() or cwd.is_symlink():
            raise ToolError(f"Configured check directory is unavailable: {check.cwd}")
        result = self._run_process_interruptible(
            slug=slug,
            argv=list(check.argv),
            cwd=cwd,
            timeout_seconds=check.timeout_seconds,
            should_stop=should_stop,
        )
        return {
            "project": slug,
            "check": check_name,
            "description": check.description,
            "cwd": self._display(project, cwd),
        } | result

    @staticmethod
    def _selfdev_excerpt(
        content: str, terms: list[str], *, maximum_chars: int
    ) -> tuple[str, int]:
        """Return a compact, line-numbered evidence view for a small model."""

        lines = content.splitlines()
        if not lines:
            return "", 0
        normalized_terms = [term.lower() for term in terms]
        matched = [
            index
            for index, line in enumerate(lines, start=1)
            if not normalized_terms
            or any(term in line.lower() for term in normalized_terms)
        ]
        if maximum_chars <= 0:
            return "", len(matched)
        selected: set[int] = set()
        if matched:
            for line_number in matched[:24]:
                selected.update(
                    range(max(1, line_number - 1), min(len(lines), line_number + 1) + 1)
                )
        else:
            selected.update(range(1, min(len(lines), 32) + 1))

        rendered: list[str] = []
        used = 0
        for line_number in sorted(selected):
            line = lines[line_number - 1]
            item = f"{line_number}: {line}"
            if len(item) > 700:
                item = item[:699] + "…"
            additional = len(item) + (1 if rendered else 0)
            if rendered and used + additional > maximum_chars:
                break
            if not rendered and additional > maximum_chars:
                item = item[: max(0, maximum_chars - 1)] + "…"
                additional = len(item)
            rendered.append(item)
            used += additional
        return "\n".join(rendered), len(matched)

    @staticmethod
    def _selfdev_source_view(
        content: str,
        terms: list[str],
        *,
        maximum_chars: int,
        start_line: int | None = None,
        end_line: int | None = None,
    ) -> dict[str, Any]:
        """Return one whole bounded slice without rewriting source characters."""

        lines = content.splitlines(keepends=True)
        explicit = start_line is not None
        selected_by = "explicit_range" if explicit else "file_start"
        if explicit:
            if end_line is None or end_line > len(lines):
                raise ToolError("selfdev_context line range exceeds the file's line count")
            first, last = start_line, end_line
        elif not lines:
            return {
                "text": "", "start_line": None, "end_line": None,
                "complete": True, "selected_by": selected_by,
                "note": "Empty file; no source lines are available.",
            }
        else:
            normalized_terms = [term.lower() for term in terms]
            match = next((index for index, line in enumerate(lines, start=1)
                          if normalized_terms
                          and any(term in line.lower() for term in normalized_terms)), None)
            if match is not None:
                first, last = max(1, match - 8), min(len(lines), match + 8)
                selected_by = "first_term_neighborhood"
            else:
                first, last = 1, min(len(lines), 17)
        text = "".join(lines[first - 1:last])
        if len(text) > maximum_chars:
            if explicit:
                raise ToolError("selfdev_context source slice exceeds the 3,200 character limit")
            return {
                "text": "", "start_line": first, "end_line": last,
                "complete": False, "selected_by": selected_by,
                "note": (
                    "Source window unavailable: the whole selected slice exceeds the "
                    "remaining context character limit. Request a smaller explicit line range."
                ),
            }
        return {
            "text": text, "start_line": first, "end_line": last,
            "complete": True, "selected_by": selected_by,
            "note": "Complete selected slice; not guaranteed to contain a whole function.",
        }

    def selfdev_context(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """Return bounded evidence for an isolated plan before any edit occurs."""

        slug, project = self._selfdev_registered(arguments, action="selfdev_context")
        paths = arguments.get("paths")
        if (
            not isinstance(paths, list)
            or not paths
            or len(paths) > self._SELFDEV_CONTEXT_MAX_FILES
            or any(not isinstance(path, str) or not path.strip() for path in paths)
        ):
            raise ToolError(
                "selfdev_context requires 1 to "
                f"{self._SELFDEV_CONTEXT_MAX_FILES} non-empty project-relative paths"
            )
        if len(paths) != len(set(paths)):
            raise ToolError("selfdev_context paths must not contain duplicates")

        has_start = "start_line" in arguments
        has_end = "end_line" in arguments
        if has_start != has_end:
            raise ToolError("selfdev_context start_line and end_line must appear together")
        start_line = arguments.get("start_line")
        end_line = arguments.get("end_line")
        if has_start:
            if len(paths) != 1:
                raise ToolError("selfdev_context explicit line ranges require exactly one path")
            if type(start_line) is not int or type(end_line) is not int:
                raise ToolError("selfdev_context line ranges require integers, excluding booleans")
            if start_line < 1 or end_line < start_line:
                raise ToolError("selfdev_context line range must satisfy 1 <= start_line <= end_line")
            if end_line - start_line + 1 > 80:
                raise ToolError("selfdev_context explicit line range exceeds the 80 line limit")

        terms = arguments.get("terms", [])
        if (
            not isinstance(terms, list)
            or len(terms) > self._SELFDEV_CONTEXT_MAX_TERMS
            or any(
                not isinstance(term, str)
                or not term.strip()
                or len(term) > 160
                for term in terms
            )
        ):
            raise ToolError(
                "selfdev_context terms must contain at most "
                f"{self._SELFDEV_CONTEXT_MAX_TERMS} short non-empty strings"
            )

        files: list[dict[str, Any]] = []
        remaining = self._SELFDEV_CONTEXT_MAX_CHARS
        for index, supplied in enumerate(paths):
            path = self._resolve(project, supplied)
            self._require_regular_file(project, path)
            raw, _ = self._selfdev_snapshot(path)
            try:
                content = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ToolError("Only UTF-8 text files are supported") from exc
            files_left = len(paths) - index
            budget = max(0, remaining // files_left)
            source_view = self._selfdev_source_view(
                content, list(terms), maximum_chars=budget,
                start_line=start_line, end_line=end_line,
            )
            source_chars = len(source_view["text"])
            excerpt, match_count = self._selfdev_excerpt(
                content, list(terms), maximum_chars=budget - source_chars,
            )
            remaining = max(0, remaining - source_chars - len(excerpt))
            files.append(
                {
                    "path": self._display(project, path),
                    "sha256": self._content_sha256(content),
                    "line_count": len(content.splitlines()),
                    "match_count": match_count,
                    "excerpt": excerpt,
                    "source_view": source_view,
                }
            )

        return {
            "project": slug,
            "phase": "inspect",
            "files": files,
            "checks": sorted(project.checks),
            "check_coverage": {
                name: list(check.covered_paths) for name, check in project.checks.items()
            },
            "check_coverage_required": project.selfdev_require_check_coverage,
            "required_next_phase": "plan_then_selfdev_apply",
            "promotion": "manual_owner_approval_required",
            "prohibited": [
                "push",
                "merge",
                "deploy",
                "secrets",
                "authority_changes",
            ],
        }

    @staticmethod
    def _selfdev_apply_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
        """Map one explicit flat edit to the unchanged transaction contract."""
        if not isinstance(arguments, dict):
            raise ToolError("selfdev_apply arguments must be an object")
        flat = {"path", "expected_sha256", "find", "replace", "expected_count"}
        if flat.intersection(arguments):
            required = flat | {"project", "plan", "check"}
            if set(arguments) != required:
                raise ToolError("Flat selfdev_apply requires all eight fields and no edits or unknown fields")
            if (any(not isinstance(arguments[key], str) for key in required - {"expected_count"})
                    or type(arguments["expected_count"]) is not int):
                raise ToolError("Flat selfdev_apply requires literal strings and an integer expected_count")
            return {"project": arguments["project"], "plan": arguments["plan"], "check": arguments["check"],
                    "edits": [{"path": arguments["path"], "expected_sha256": arguments["expected_sha256"],
                               "replacements": [{"find": arguments["find"], "replace": arguments["replace"],
                                                  "expected_count": arguments["expected_count"]}]}]}
        return arguments

    def selfdev_apply(self, arguments: dict[str, Any]) -> dict[str, Any]:
        slug, _ = self._selfdev_registered(arguments, action="selfdev_apply")
        epoch = self.control.epoch(slug)
        with self.control.transaction(slug, epoch), self.control.bind(slug, epoch):
            try:
                result = self._selfdev_apply(arguments)
            except _SelfdevCleanupError:
                self.control.mark_cleanup(slug)
                raise
            if result.get("cleanup_required"):
                self.control.mark_cleanup(slug)
            return result

    def _selfdev_apply(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """Apply a small evidence-bound plan and run exactly one fixed local check."""

        arguments = self._selfdev_apply_arguments(arguments)
        slug, project = self._selfdev_registered(arguments, action="selfdev_apply")
        plan = arguments.get("plan")
        if (
            not isinstance(plan, str)
            or not plan.strip()
            or len(plan.encode("utf-8")) > 4_000
        ):
            raise ToolError("selfdev_apply requires a non-empty plan of at most 4,000 bytes")
        check_name = arguments.get("check")
        if not isinstance(check_name, str) or check_name not in project.checks:
            raise ToolError("selfdev_apply requires one owner-configured check")
        edits = arguments.get("edits")
        if (
            not isinstance(edits, list)
            or not edits
            or len(edits) > self._SELFDEV_MAX_EDITS
        ):
            raise ToolError(
                "selfdev_apply requires 1 to "
                f"{self._SELFDEV_MAX_EDITS} evidence-bound file edits"
            )

        prepared: list[dict[str, Any]] = []
        seen_paths: set[str] = set()
        for edit in edits:
            if not isinstance(edit, dict) or set(edit) != {
                "path",
                "expected_sha256",
                "replacements",
            }:
                raise ToolError(
                    "Each selfdev edit must contain only path, expected_sha256, and replacements"
                )
            supplied = edit["path"]
            if not isinstance(supplied, str) or not supplied.strip():
                raise ToolError("selfdev edit paths must be non-empty and unique")
            path = self._resolve(project, supplied)
            canonical = self._display(project, path)
            if canonical in seen_paths:
                raise ToolError("selfdev edit paths must be non-empty and unique")
            seen_paths.add(canonical)
            self._require_regular_file(project, path)
            self._require_selfdev_editable(project, path)
            expected_sha256 = edit["expected_sha256"]
            if (
                not isinstance(expected_sha256, str)
                or len(expected_sha256) != 64
                or any(character not in "0123456789abcdef" for character in expected_sha256)
            ):
                raise ToolError("selfdev expected_sha256 must be a lowercase SHA-256 digest")
            original_bytes, mode = self._selfdev_snapshot(path)
            try:
                original = original_bytes.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ToolError("Only UTF-8 text files are supported") from exc
            if self._content_sha256(original) != expected_sha256:
                raise ToolError(
                    "selfdev evidence is stale for "
                    f"{self._display(project, path)}; inspect it again before editing"
                )

            replacements = edit["replacements"]
            if (
                not isinstance(replacements, list)
                or not replacements
                or len(replacements) > self._SELFDEV_MAX_REPLACEMENTS_PER_FILE
            ):
                raise ToolError(
                    "Each selfdev edit requires 1 to "
                    f"{self._SELFDEV_MAX_REPLACEMENTS_PER_FILE} exact replacements"
                )
            updated = original
            replacement_report: list[dict[str, Any]] = []
            for replacement in replacements:
                if not isinstance(replacement, dict) or set(replacement) != {
                    "find",
                    "replace",
                    "expected_count",
                }:
                    raise ToolError(
                        "Each selfdev replacement must contain only find, replace, and expected_count"
                    )
                find = replacement["find"]
                replace = replacement["replace"]
                expected_count = replacement["expected_count"]
                if (
                    not isinstance(find, str)
                    or not find
                    or not isinstance(replace, str)
                    or isinstance(expected_count, bool)
                    or not isinstance(expected_count, int)
                    or not 1 <= expected_count <= 32
                ):
                    raise ToolError("selfdev replacements must use non-empty exact text and a count")
                if find == replace:
                    raise ToolError("selfdev replacement must change the selected text")
                actual_count = updated.count(find)
                if actual_count != expected_count:
                    raise ToolError(
                        "selfdev replacement count did not match the inspected evidence for "
                        f"{self._display(project, path)}"
                    )
                projected_bytes = (len(updated.encode("utf-8")) + actual_count *
                                   (len(replace.encode("utf-8")) - len(find.encode("utf-8"))))
                if projected_bytes > self.max_file_bytes:
                    raise ToolError("Selfdev replacement exceeds the configured file limit")
                updated = updated.replace(find, replace)
                replacement_report.append(
                    {
                        "find_sha256": self._content_sha256(find),
                        "replace_sha256": self._content_sha256(replace),
                        "count": expected_count,
                    }
                )
            if len(updated.encode("utf-8")) > self.max_file_bytes:
                raise ToolError(
                    f"Content exceeds the {self.max_file_bytes}-byte registered-project limit"
                )
            if updated == original:
                raise ToolError("selfdev replacements must produce a net file change")
            prepared.append(
                {
                    "path": path,
                    "display_path": self._display(project, path),
                    "original": original,
                    "updated": updated,
                    "original_bytes": original_bytes,
                    "updated_bytes": updated.encode("utf-8"),
                    "mode": mode,
                    "before_sha256": self._content_sha256(original),
                    "after_sha256": self._content_sha256(updated),
                    "replacements": replacement_report,
                }
            )

        if project.selfdev_require_check_coverage:
            # Owner declarations are exact files, resolved through the same
            # traversal, blocked-path and symlink checks as proposed edits.
            # Declared coverage is not proof that a check is a useful oracle;
            # the owner must independently qualify the registered command.
            covered: set[str] = set()
            for supplied in project.checks[check_name].covered_paths:
                checked_path = self._resolve(project, supplied)
                self._require_regular_file(project, checked_path)
                covered.add(self._display(project, checked_path))
            uncovered = sorted(seen_paths - covered)
            if uncovered:
                raise ToolError(
                    "Configured check does not declare coverage for every edited file: "
                    + ", ".join(uncovered)
                )

        self._checkpoint(slug)
        # Validate the whole transaction again before producing backups or edits.
        for item in prepared:
            if self._selfdev_snapshot(item["path"]) != (item["original_bytes"], item["mode"]):
                raise ToolError("Selfdev evidence is stale before applying the plan")
        for item in prepared:
            item["backup"] = self._selfdev_backup(slug, item)
        attempted = []
        apply_failed = False
        check_result = {"project": slug, "check": check_name, "returncode": None,
                        "stopped": False, "timed_out": False}
        try:
            for item in prepared:
                try:
                    self._checkpoint(slug)
                    self._selfdev_replace(item["path"], item["original_bytes"],
                                          item["updated_bytes"], item["mode"])
                except _SelfdevWriteError as exc:
                    if exc.replaced:
                        attempted.append(item)
                    raise
                except (ToolError, OSError):
                    # Known refusal before a reported replacement is not proof
                    # that matching bytes belong to this transaction.
                    raise
                except Exception:
                    # Replacement may have completed before bookkeeping failed.
                    # Include the in-flight path, but never untouched later edits.
                    attempted.append(item)
                    raise
                attempted.append(item)
                self._checkpoint(slug)
        except Exception as exc:
            check_result["stopped"] = isinstance(exc, DevelopmentStopped)
            apply_failed = True
            check_result["error"] = "Selfdev apply failed; conditional recovery attempted"
        except (KeyboardInterrupt, SystemExit) as exc:
            # An interrupt can arrive immediately after replace, before the
            # successful item is appended. Inspect every prepared path and
            # restore only bytes still matching this transaction's output.
            recovery = self._selfdev_recover(prepared)
            if recovery["status"] != "completed":
                raise _SelfdevCleanupError("Interrupted selfdev needs recovery") from exc
            raise
        if not apply_failed:
            try:
                self._checkpoint(slug)
                check_result.update(self._run_selfdev_check(slug, project, check_name))
                self._checkpoint(slug)
                for item in prepared:
                    if self._selfdev_snapshot(item["path"]) != (item["updated_bytes"], item["mode"]):
                        raise ToolError("Selfdev file changed during its configured check")
            except Exception as exc:
                check_result["returncode"] = None
                check_result["stopped"] = isinstance(exc, DevelopmentStopped)
                check_result["error"] = str(exc) if isinstance(exc, ToolError) else "Configured check failed safely"
                check_result["timed_out"] = (isinstance(exc, subprocess.TimeoutExpired)
                                             or isinstance(exc, ToolError) and "timed out" in str(exc))
                check_result["cleanup_required"] = isinstance(exc, _SelfdevCleanupError)
            except (KeyboardInterrupt, SystemExit) as exc:
                recovery = self._selfdev_recover(prepared)
                if recovery["status"] != "completed":
                    raise _SelfdevCleanupError("Interrupted selfdev needs recovery") from exc
                raise
        code = check_result.get("returncode")
        check_passed = type(code) is int and code == 0
        rollback = ({"status": "not_needed", "restored": [], "unresolved": []}
                    if check_passed else self._selfdev_recover(attempted))
        cleanup_required = rollback["status"] == "incomplete" or bool(check_result.get("cleanup_required"))
        files = [
            {
                "path": item["display_path"],
                "before_sha256": item["before_sha256"],
                "after_sha256": item["after_sha256"],
                "backup": str(item["backup"].relative_to(self.control_root)),
                "replacements": item["replacements"],
            }
            for item in prepared
        ]
        return {
            "project": slug,
            "status": ("cleanup_required" if cleanup_required else "completed" if check_passed
                       else "stopped" if check_result.get("stopped")
                       else "apply_failed" if apply_failed else "check_failed"),
            "execution_receipt_version": 1,
            "cleanup_required": cleanup_required,
            "rolled_back": not check_passed and rollback["status"] == "completed",
            "rollback": rollback,
            "phase": "report",
            "plan_sha256": self._content_sha256(plan),
            "files": files,
            "check": check_result,
            "report": {
                "files_changed": ([item["path"] for item in files] if check_passed
                                  else list(rollback["unresolved"])),
                "targeted_check_passed": check_passed,
                "quiescent_copy_required": True,
                "compare_and_swap_protection": False,
                "promotion": "manual_owner_approval_required",
                "automatic_live_change": False,
                "prohibited": [
                    "push",
                    "merge",
                    "deploy",
                    "secrets",
                    "authority_changes",
                ],
            },
        }

    def execute(self, action: str, arguments: dict[str, Any]) -> dict[str, Any]:
        actions = {
            "status": self.status,
            "list": self.list_directory,
            "read": self.read_file,
            "search": self.search_files,
            "create": self.create_file,
            "modify": self.modify_file,
            "delete": self.delete_path,
            "run_check": self.run_check,
            "selfdev_context": self.selfdev_context,
            "selfdev_apply": self.selfdev_apply,
        }
        handler = actions.get(action)
        if handler is None:
            raise ToolError(f"Unsupported development action: {action}")
        return handler(arguments)

    def audit_arguments(
        self, action: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        if action == "selfdev_apply":
            # Log bounded metadata only, including for refused calls. A malformed
            # tool call must not make failure auditing throw or expose edit text.
            invalid: dict[str, Any] = {"invalid_arguments": True}
            if isinstance(arguments, dict):
                project = arguments.get("project")
                if isinstance(project, str) and project in self.projects:
                    invalid["project"] = project
                    check = arguments.get("check")
                    if isinstance(check, str) and check in self.projects[project].checks:
                        invalid["check"] = check
            try:
                normalized = self._selfdev_apply_arguments(arguments)
                plan = normalized.get("plan")
                edits = normalized.get("edits")
                if not isinstance(plan, str) or not isinstance(edits, list) or not 1 <= len(edits) <= 3:
                    return invalid
                encoded = plan.encode("utf-8")
                summary = {key: value for key, value in invalid.items() if key != "invalid_arguments"} | {
                    "plan_bytes": len(encoded), "plan_sha256": hashlib.sha256(encoded).hexdigest(), "edits": []}
                for edit in edits:
                    if not isinstance(edit, dict):
                        return invalid
                    path, expected, replacements = edit.get("path"), edit.get("expected_sha256"), edit.get("replacements")
                    if not isinstance(path, str) or not isinstance(expected, str) or not isinstance(replacements, list):
                        return invalid
                    summary["edits"].append({"path": path[:1024], "expected_sha256": expected[:64],
                                              "replacement_count": len(replacements)})
                return summary
            except (ToolError, TypeError, ValueError, UnicodeError):
                return invalid
        summary = {
            key: arguments[key]
            for key in ("project", "path", "check", "limit")
            if key in arguments
        }
        if "query" in arguments:
            encoded = str(arguments["query"]).encode("utf-8")
            summary["query_bytes"] = len(encoded)
            summary["query_sha256"] = hashlib.sha256(encoded).hexdigest()
        if action in {"create", "modify"} and "content" in arguments:
            encoded = str(arguments["content"]).encode("utf-8")
            summary["content_bytes"] = len(encoded)
            summary["content_sha256"] = hashlib.sha256(encoded).hexdigest()
        if action == "selfdev_context":
            paths = arguments.get("paths")
            terms = arguments.get("terms")
            paths = paths if isinstance(paths, list) else []
            terms = terms if isinstance(terms, list) else []
            summary["paths"] = [str(path) for path in paths]
            summary["term_count"] = len(terms)
            summary["term_sha256"] = [
                self._content_sha256(str(term)) for term in terms
            ]
        return summary

    def audit_result(self, action: str, result: dict[str, Any]) -> dict[str, Any]:
        safe_keys = {
            "project",
            "path",
            "created",
            "modified",
            "deleted",
            "size",
            "backup",
            "recoverable_from",
            "check",
            "returncode",
            "output_truncated",
            "repository",
            "branch",
            "head",
            "upstream",
            "clean",
            "stopped",
        }
        summary = {key: value for key, value in result.items() if key in safe_keys}
        if action == "list":
            summary["entry_count"] = len(result.get("entries", []))
        if action == "search":
            summary["match_count"] = len(result.get("matches", []))
        if action == "read":
            summary["content_bytes"] = len(
                str(result.get("content", "")).encode("utf-8")
            )
        if action == "run_check":
            summary["stdout_bytes"] = int(
                result.get("stdout_bytes")
                or len(str(result.get("stdout", "")).encode("utf-8"))
            )
            summary["stderr_bytes"] = int(
                result.get("stderr_bytes")
                or len(str(result.get("stderr", "")).encode("utf-8"))
            )
        if action == "selfdev_context":
            summary["file_count"] = len(result.get("files", []))
            summary["paths"] = [
                str(item.get("path") or "")
                for item in result.get("files", [])
                if isinstance(item, dict)
            ]
        if action == "selfdev_apply":
            check = result.get("check") or {}
            summary = {
                "project": result.get("project"),
                "status": result.get("status"),
                "execution_receipt_version": result.get("execution_receipt_version"),
                "cleanup_required": result.get("cleanup_required"),
                "rolled_back": result.get("rolled_back"),
                "files": [
                    {
                        "path": item.get("path"),
                        "before_sha256": item.get("before_sha256"),
                        "after_sha256": item.get("after_sha256"),
                        "backup": item.get("backup"),
                    }
                    for item in result.get("files", [])
                    if isinstance(item, dict)
                ],
                "check": {
                    "name": check.get("check"),
                    "returncode": check.get("returncode"),
                    "error": check.get("error"),
                    "stopped": check.get("stopped", False),
                    "timed_out": check.get("timed_out", False),
                },
                "promotion": "manual_owner_approval_required",
            }
        return summary

    def describe(self) -> dict[str, Any]:
        slugs = sorted(self.projects)
        checks = sorted(
            {name for project in self.projects.values() for name in project.checks}
        )
        project_schema = {
            "type": "string",
            "enum": slugs,
            "description": "Owner-registered local project slug.",
        }
        path_schema = {
            "type": "string",
            "description": "Path relative to the selected registered project.",
        }
        project_property = {"project": project_schema}
        registered = {
            slug: {
                "name": project.name,
                "action_tier": project.action_tier,
                "allowed_actions": list(project.allowed_actions),
                "checks": sorted(project.checks),
                "selfdev_editable_paths": list(project.selfdev_editable_paths),
                "check_coverage_required": project.selfdev_require_check_coverage,
                "check_coverage": {
                    name: list(check.covered_paths)
                    for name, check in project.checks.items()
                },
                "pause_conditions": list(project.pause_conditions),
            }
            for slug, project in self.projects.items()
        }
        description = {
            "name": self.name,
            "description": (
                "Read and make recoverable local changes only inside owner-registered "
                "software projects. Generic terminal commands, pushes, deployments, "
                "production data, and external actions are not provided."
            ),
            "registered_projects": registered,
            "max_file_bytes": self.max_file_bytes,
            "actions": {
                "status": {
                    "description": "Inspect registration policy and read-only Git status.",
                    "parameters": {
                        "type": "object",
                        "properties": project_property,
                        "required": ["project"],
                        "additionalProperties": False,
                    },
                },
                "list": {
                    "description": "List a directory inside a registered project.",
                    "parameters": {
                        "type": "object",
                        "properties": project_property | {"path": path_schema},
                        "required": ["project"],
                        "additionalProperties": False,
                    },
                },
                "read": {
                    "description": "Read a UTF-8 file inside a registered project.",
                    "parameters": {
                        "type": "object",
                        "properties": project_property | {"path": path_schema},
                        "required": ["project", "path"],
                        "additionalProperties": False,
                    },
                },
                "search": {
                    "description": "Search UTF-8 files inside a registered project.",
                    "parameters": {
                        "type": "object",
                        "properties": project_property
                        | {
                            "query": {"type": "string"},
                            "path": path_schema,
                            "limit": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": 200,
                            },
                        },
                        "required": ["project", "query"],
                        "additionalProperties": False,
                    },
                },
                "create": {
                    "description": "Create a UTF-8 file inside a registered project.",
                    "parameters": {
                        "type": "object",
                        "properties": project_property
                        | {"path": path_schema, "content": {"type": "string"}},
                        "required": ["project", "path", "content"],
                        "additionalProperties": False,
                    },
                },
                "modify": {
                    "description": (
                        "Replace a registered-project file after preserving a recovery copy."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": project_property
                        | {"path": path_schema, "content": {"type": "string"}},
                        "required": ["project", "path", "content"],
                        "additionalProperties": False,
                    },
                },
                "delete": {
                    "description": (
                        "Move a registered-project path to recoverable Atlas storage."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": project_property | {"path": path_schema},
                        "required": ["project", "path"],
                        "additionalProperties": False,
                    },
                },
                "run_check": {
                    "description": (
                        "Run one owner-configured project check. The model cannot supply argv."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": project_property
                        | {
                            "check": {
                                "type": "string",
                                "enum": checks,
                                "description": "Owner-configured check name.",
                            }
                        },
                        "required": ["project", "check"],
                        "additionalProperties": False,
                    },
                },
            },
        }
        selfdev_slugs = sorted(
            slug for slug, project in self.projects.items() if project.self_development
        )
        if selfdev_slugs:
            selfdev_project_property = {
                "project": {
                    "type": "string",
                    "enum": selfdev_slugs,
                    "description": "The separately registered isolated self-development target.",
                }
            }
            description["actions"]["selfdev_context"] = {
                "description": (
                    "Inspect a small, focused set of files in the isolated self-development "
                    "target. Returns hash-bound source_view text with original source characters, "
                    "separate from legacy line-numbered excerpts. Only a source_view marked "
                    "complete is the whole selected slice; it need not contain a whole function. "
                    "Use start_line and end_line together for one file, at most 80 lines and "
                    "3,200 total source/excerpt characters. Never copy line numbers or ellipses "
                    "from an excerpt into a replacement."
                ),
                "parameters": {
                    "type": "object",
                    "properties": selfdev_project_property
                    | {
                        "paths": {
                            "type": "array",
                            "items": path_schema,
                            "minItems": 1,
                            "maxItems": self._SELFDEV_CONTEXT_MAX_FILES,
                        },
                        "terms": {
                            "type": "array",
                            "items": {"type": "string", "minLength": 1, "maxLength": 160},
                            "maxItems": self._SELFDEV_CONTEXT_MAX_TERMS,
                            "default": [],
                        },
                        "start_line": {
                            "type": "integer", "minimum": 1,
                            "description": "First source line, inclusive. Requires end_line and exactly one path.",
                        },
                        "end_line": {
                            "type": "integer", "minimum": 1,
                            "description": "Last source line, inclusive. Requires start_line; at most 80 lines.",
                        },
                    },
                    "required": ["project", "paths"],
                    "additionalProperties": False,
                },
            }
            description["actions"]["selfdev_apply"] = {
                "description": (
                    "Apply exactly one evidence-bound replacement in one inspected file, run "
                    "one fixed check, and return a recovery-aware receipt. Supply eight simple "
                    "sibling fields: project, plan, check, path, expected_sha256, find, replace, "
                    "expected_count. Copy the observed path and sha256 from selfdev_context. "
                    "find and replace are literal text; expected_count is an integer. "
                    "Do not send an edits field, JSON-encoded objects, shell commands, or argv. "
                    "This operation never promotes changes to the live tree."
                ),
                "parameters": {
                    "type": "object",
                    "properties": selfdev_project_property | {
                        "plan": {"type": "string", "minLength": 1, "maxLength": 4000},
                        "check": {"type": "string", "enum": sorted({name for slug in selfdev_slugs for name in self.projects[slug].checks}),
                                  "description": "The top-level fixed check name returned by selfdev_context."},
                        "path": path_schema,
                        "expected_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$",
                                            "description": "The observed 64-character sha256 returned for this path."},
                        "find": {"type": "string", "minLength": 1, "description": "Exact literal text from the inspected file."},
                        "replace": {"type": "string", "description": "Your replacement literal text, not an encoded edit object."},
                        "expected_count": {"type": "integer", "minimum": 1, "maximum": 32},
                    },
                    "required": ["project", "plan", "check", "path", "expected_sha256", "find", "replace", "expected_count"],
                    "additionalProperties": False,
                },
            }
        return description
