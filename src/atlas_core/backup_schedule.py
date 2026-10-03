"""A small clock-driven backup routine. No model, app session, or scheduler API.

The host may call this at startup and periodically. It creates at most one local
snapshot per due date and transfers at most one pending snapshot per invocation.
Missed days coalesce to the most recent 3 AM; old snapshots are never deleted.
"""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
from zoneinfo import ZoneInfo

from atlas_core import backup_maintenance as maintenance
from atlas_core.backup_maintenance import run_once, BackupMaintenanceError
import os


def due_date(now: datetime) -> str:
    if now.tzinfo is None or now.utcoffset() is None:
        raise BackupMaintenanceError("Backup clock must include a timezone")
    local = now.astimezone(ZoneInfo("America/New_York"))
    day = local.date() if local.hour >= 3 else local.date() - timedelta(days=1)
    return day.strftime("%Y%m%d")


def run_daily(base_plan: dict, *, now: datetime | None = None, transport=None) -> dict:
    if not isinstance(base_plan, dict) or set(base_plan) != {
        "source_root", "selection", "recovery_root", "destination_id"
    }:
        raise BackupMaintenanceError("Daily backup needs one explicit selection and destination")
    day = due_date(now or datetime.now(timezone.utc))
    current = {**base_plan, "operation_id": "daily-" + day}
    # Always preserve today's selected local bytes even when remote login fails.
    local = run_once(current)
    result = {"schedule": "03:00 America/New_York with catch-up", "due_date": day,
              "local": local, "cloud": None, "status": local["status"],
              "blocked_operations": []}
    if transport is None:
        return result
    pending = []
    plan_hash = maintenance._hash(maintenance._canonical({
        "source_root": str(maintenance._absolute(base_plan["source_root"])),
        "selection": base_plan["selection"],
        "recovery_root": str(maintenance._absolute(base_plan["recovery_root"])),
        "destination_id": base_plan["destination_id"],
    }))
    directory = maintenance._directory(Path(base_plan["recovery_root"]) / "outbox", owned=True)
    try:
        names = os.listdir(directory)
        if len(names) > 512:
            raise BackupMaintenanceError("Backup queue requires inspection before more transfers")
        for name in sorted(names):
            if not re.fullmatch(r"daily-[0-9]{8}", name) or name > current["operation_id"]:
                continue
            # A phase is meaningful only inside the checked, plan-bound state.
            # Open each private operation directory relative to the pinned queue.
            job = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                          os.O_CLOEXEC, dir_fd=directory)
            try:
                info = os.fstat(job)
                if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                    raise BackupMaintenanceError("Backup queue directory is not private")
                try:
                    state = maintenance._load(job, name, plan_hash)
                except RecursionError:
                    raise BackupMaintenanceError("Backup queue state is invalid") from None
            finally:
                os.close(job)
            if state is None:
                result["blocked_operations"].append({"operation_id": name, "reason": "incomplete_state"})
            elif state["phase"] == "verified":
                if state["failure"] is not None:
                    result["blocked_operations"].append({"operation_id": name, "reason": state["failure"]})
            elif state["attempts"] >= maintenance._MAX_ATTEMPTS:
                result["blocked_operations"].append({"operation_id": name, "reason": "retry_limit_reached"})
            else:
                pending.append(name)
    finally:
        os.close(directory)
    if pending:
        cloud = run_once({**base_plan, "operation_id": pending[0]}, transport)
        result.update(cloud=cloud, status=cloud["status"])
        if cloud["status"] == "verified" and (len(pending) > 1 or (
            pending[0] != current["operation_id"] and local["status"] != "verified"
        )):
            result["status"] = "cloud_pending"
    if result["blocked_operations"]:
        result["status"] = "attention_required"
    return result
