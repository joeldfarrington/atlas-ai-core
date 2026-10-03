from __future__ import annotations

"""Inactive synthetic-only macOS Keychain seam for Option 1 provisioning.

The stable native helper owns the fixed Keychain selector and writes material
directly to an already-open connector descriptor. This Python adapter never
receives the material. It is not wired into ordinary Atlas startup and cannot
carry a real credential or private payload.
"""

import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
from pathlib import Path


SYNTHETIC_PREFIX = b"atlas-option1-synthetic-v1_"
VAULT_SELECTOR = (
    "atlas-option1-vault-selector-v1:macos-keychain-generic-password:"
    "com.atlas.core.supervisor-v4.option1.synthetic:sentinel-v1"
)
VAULT_ITEM_LABEL_SHA256 = hashlib.sha256(VAULT_SELECTOR.encode("utf-8")).hexdigest()
KEYCHAIN_HELPER_SOURCE_SHA256 = (
    "bc4daec87de5c86e188663901746c9e2239942a19329714ff5225e4cdfbeff40"
)
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_ERROR_PATTERN = re.compile(r"^option1_keychain_[a-z0-9_]{1,71}$")
_MAX_HELPER_OUTPUT_BYTES = 8_192
_PINNED_SANDBOX_EXEC = Path("/usr/bin/sandbox-exec")
_NETWORK_DENIAL_PROFILE = "(version 1)(allow default)(deny network*)"


class Option1KeychainViolation(ValueError):
    """Privacy-safe failure from the inactive Option 1 Keychain seam."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise Option1KeychainViolation("option1_keychain_report_invalid") from exc


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise Option1KeychainViolation("option1_keychain_helper_unavailable") from exc
    return digest.hexdigest()


def _terminate_process(
    process: subprocess.Popen[bytes],
    *,
    owns_process_group: bool,
) -> None:
    if process.poll() is not None:
        return
    try:
        if owns_process_group:
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
        process.wait(timeout=1.0)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        if process.poll() is None:
            try:
                if owns_process_group:
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            except ProcessLookupError:
                pass
            process.wait(timeout=2.0)


class MacOSKeychainSyntheticVaultAdapter:
    """Fixed-selector native helper adapter; synthetic material only."""

    def __init__(
        self,
        *,
        helper_path: Path,
        helper_sha256: str,
        timeout_seconds: float = 5.0,
        join_current_process_group: bool = False,
        use_network_sandbox: bool = False,
    ) -> None:
        if sys.platform != "darwin":
            raise Option1KeychainViolation("option1_keychain_platform_unsupported")
        if type(join_current_process_group) is not bool:
            raise Option1KeychainViolation("option1_keychain_process_group_mode_invalid")
        if type(use_network_sandbox) is not bool:
            raise Option1KeychainViolation("option1_keychain_sandbox_mode_invalid")
        if not _DIGEST_PATTERN.fullmatch(helper_sha256) or helper_sha256 == "0" * 64:
            raise Option1KeychainViolation("option1_keychain_helper_digest_invalid")
        if not isinstance(timeout_seconds, (int, float)) or isinstance(
            timeout_seconds, bool
        ) or not 0.5 <= float(timeout_seconds) <= 30:
            raise Option1KeychainViolation("option1_keychain_timeout_invalid")
        if not helper_path.is_absolute() or helper_path.is_symlink():
            raise Option1KeychainViolation("option1_keychain_helper_path_invalid")
        try:
            resolved = helper_path.resolve(strict=True)
            metadata = resolved.stat()
        except OSError as exc:
            raise Option1KeychainViolation("option1_keychain_helper_unavailable") from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o277
            or not os.access(resolved, os.X_OK)
        ):
            raise Option1KeychainViolation("option1_keychain_helper_permissions_invalid")
        if _sha256_file(resolved) != helper_sha256:
            raise Option1KeychainViolation("option1_keychain_helper_digest_mismatch")
        sandbox_exec: Path | None = None
        if use_network_sandbox:
            try:
                sandbox_metadata = _PINNED_SANDBOX_EXEC.lstat()
                sandbox_resolved = _PINNED_SANDBOX_EXEC.resolve(strict=True)
            except OSError as exc:
                raise Option1KeychainViolation(
                    "option1_keychain_sandbox_invalid"
                ) from exc
            if (
                sandbox_resolved != _PINNED_SANDBOX_EXEC
                or not stat.S_ISREG(sandbox_metadata.st_mode)
                or sandbox_metadata.st_nlink != 1
                or sandbox_metadata.st_uid != 0
                or stat.S_IMODE(sandbox_metadata.st_mode) & 0o022
                or not os.access(sandbox_resolved, os.X_OK)
            ):
                raise Option1KeychainViolation("option1_keychain_sandbox_invalid")
            sandbox_exec = sandbox_resolved
        self.helper_path = resolved
        self.helper_sha256 = helper_sha256
        self.timeout_seconds = float(timeout_seconds)
        self.join_current_process_group = join_current_process_group
        self.sandbox_exec = sandbox_exec
        self.profile_id = "darwin-keychain-synthetic-connector-v1"

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(helper_sha256={self.helper_sha256!r}, "
            "material='<unavailable-to-adapter>', synthetic_only=True)"
        )

    def _run(
        self,
        arguments: list[str],
        *,
        pass_descriptor: int | None = None,
    ) -> dict[str, object]:
        if pass_descriptor is not None and (
            not isinstance(pass_descriptor, int) or pass_descriptor < 3
        ):
            raise Option1KeychainViolation("option1_keychain_descriptor_invalid")
        process: subprocess.Popen[bytes] | None = None
        command = [str(self.helper_path), *arguments]
        if self.sandbox_exec is not None:
            command = [
                str(self.sandbox_exec),
                "-p",
                _NETWORK_DENIAL_PROFILE,
                *command,
            ]
        try:
            process = subprocess.Popen(
                command,
                cwd=self.helper_path.parent,
                env={},
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                pass_fds=(() if pass_descriptor is None else (pass_descriptor,)),
                start_new_session=not self.join_current_process_group,
            )
            try:
                stdout, stderr = process.communicate(timeout=self.timeout_seconds)
            except subprocess.TimeoutExpired as exc:
                _terminate_process(
                    process,
                    owns_process_group=not self.join_current_process_group,
                )
                raise Option1KeychainViolation("option1_keychain_helper_timeout") from exc
            if len(stdout) + len(stderr) > _MAX_HELPER_OUTPUT_BYTES:
                raise Option1KeychainViolation("option1_keychain_helper_output_too_large")
            if SYNTHETIC_PREFIX in stdout or SYNTHETIC_PREFIX in stderr:
                raise Option1KeychainViolation("option1_keychain_material_returned")
            if process.returncode != 0:
                try:
                    code = stderr.decode("utf-8", errors="strict")
                except UnicodeDecodeError:
                    code = ""
                if _ERROR_PATTERN.fullmatch(code):
                    raise Option1KeychainViolation(code)
                raise Option1KeychainViolation("option1_keychain_helper_failed")
            if stderr:
                raise Option1KeychainViolation("option1_keychain_helper_stderr_present")
            try:
                report = json.loads(stdout.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise Option1KeychainViolation("option1_keychain_report_invalid") from exc
            if not isinstance(report, dict) or _canonical_json(report) != stdout:
                raise Option1KeychainViolation("option1_keychain_report_noncanonical")
            return report
        finally:
            if process is not None:
                _terminate_process(
                    process,
                    owns_process_group=not self.join_current_process_group,
                )

    def status(self) -> dict[str, object]:
        report = self._run(["status"])
        if set(report) != {
            "version",
            "present",
            "synthetic_only",
            "secret_read",
            "secret_returned",
        } or any(
            report[key] is not expected
            for key, expected in {
                "version": 1,
                "synthetic_only": True,
                "secret_read": False,
                "secret_returned": False,
            }.items()
        ) or type(report["present"]) is not bool:
            raise Option1KeychainViolation("option1_keychain_status_mismatch")
        return report

    def consume_to_descriptor(self, item_label_sha256: str, descriptor: int) -> None:
        if item_label_sha256 != VAULT_ITEM_LABEL_SHA256:
            raise Option1KeychainViolation("option1_keychain_item_binding_mismatch")
        report = self._run(
            [
                "deliver-synthetic",
                "--material-fd",
                str(descriptor),
                "--parent-pid",
                str(os.getpid()),
            ],
            pass_descriptor=descriptor,
        )
        expected = {
            "version": 1,
            "delivered": True,
            "synthetic_only": True,
            "secret_returned": False,
            "secret_stdout_allowed": False,
            "real_credential_supported": False,
            "parent_verified": True,
        }
        if report != expected:
            raise Option1KeychainViolation("option1_keychain_delivery_report_mismatch")

    @staticmethod
    def contains_known_material(value: bytes) -> bool:
        if not isinstance(value, bytes):
            raise Option1KeychainViolation("option1_keychain_leak_scan_input_invalid")
        return SYNTHETIC_PREFIX in value


__all__ = [
    "MacOSKeychainSyntheticVaultAdapter",
    "KEYCHAIN_HELPER_SOURCE_SHA256",
    "Option1KeychainViolation",
    "SYNTHETIC_PREFIX",
    "VAULT_ITEM_LABEL_SHA256",
    "VAULT_SELECTOR",
]
