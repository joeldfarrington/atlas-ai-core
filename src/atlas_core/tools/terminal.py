from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

from atlas_core.errors import ToolError
from atlas_core.tools.base import Tool


class TerminalTool(Tool):
    name = "terminal"

    def __init__(
        self, workspace_root: str | Path, *, default_timeout_seconds: float = 30.0
    ) -> None:
        self.root = Path(workspace_root).expanduser().resolve()
        self.default_timeout_seconds = min(
            max(float(default_timeout_seconds), 1.0), 120.0
        )
        self.home = self.root / ".atlas_home"
        self.tmp = self.root / ".atlas_tmp"
        self.home.mkdir(exist_ok=True)
        self.tmp.mkdir(exist_ok=True)

    def _cwd(self, supplied: Any) -> Path:
        value = str(supplied or ".")
        candidate = (self.root / value).resolve()
        if candidate != self.root and self.root not in candidate.parents:
            raise ToolError("Terminal working directory escapes the Atlas workspace")
        if not candidate.exists() or not candidate.is_dir():
            raise ToolError("Terminal working directory does not exist")
        return candidate

    def run(self, arguments: dict[str, Any]) -> dict[str, Any]:
        argv = arguments.get("argv")
        if not isinstance(argv, list) or not argv or any(not isinstance(item, str) for item in argv):
            raise ToolError("argv must be a non-empty array of strings")
        if len(argv) > 64 or sum(len(item) for item in argv) > 20_000:
            raise ToolError("Command is too large")
        if argv[0] in {"sudo", "su", "doas", "shutdown", "reboot", "halt"}:
            raise ToolError(f"Blocked executable: {argv[0]}")
        timeout = min(
            max(
                float(
                    arguments.get(
                        "timeout_seconds", self.default_timeout_seconds
                    )
                ),
                1,
            ),
            120,
        )
        cwd = self._cwd(arguments.get("cwd", "."))
        env = {
            "PATH": os.getenv("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"),
            "HOME": str(self.home),
            "TMPDIR": str(self.tmp),
            "LANG": os.getenv("LANG", "C.UTF-8"),
        }
        try:
            completed = subprocess.run(
                argv,
                cwd=cwd,
                env=env,
                shell=False,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError as exc:
            raise ToolError(f"Executable not found: {argv[0]}") from exc
        except subprocess.TimeoutExpired as exc:
            raise ToolError(f"Command timed out after {timeout} seconds") from exc
        return {
            "argv": argv,
            "cwd": str(cwd.relative_to(self.root)) or ".",
            "returncode": completed.returncode,
            "stdout": completed.stdout[-100_000:],
            "stderr": completed.stderr[-100_000:],
            "output_truncated": len(completed.stdout) > 100_000 or len(completed.stderr) > 100_000,
        }

    def execute(self, action: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if action != "run":
            raise ToolError(f"Unsupported terminal action: {action}")
        return self.run(arguments)

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": "Run a process with no shell and a workspace working directory. This is not an operating-system sandbox and is disabled by default.",
            "actions": {
                "run": {
                    "description": "Run an argv-style process. Requires explicit policy permission and normally owner approval.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "argv": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 64},
                            "cwd": {"type": "string"},
                            "timeout_seconds": {"type": "number", "minimum": 1, "maximum": 120},
                        },
                        "required": ["argv"],
                        "additionalProperties": False,
                    },
                }
            },
        }
