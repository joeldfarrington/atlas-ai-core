from __future__ import annotations

import json
import os
import plistlib
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Sequence

from atlas_core.config import AtlasConfig, load_config
from atlas_core.memory import Database
from atlas_core.phone_companion import PhoneCompanionStateStore


PHONE_BUNDLE_ID = "net.atlaswithin.atlascompanion"
PHONE_TEST_BUNDLE_ID = "net.atlaswithin.atlascompanion.tests"
PHONE_SIGNING_TEAM = "J3PWB7RXTU"
PHONE_SCHEME = "AtlasCompanion"
PHONE_PROJECT = Path("companion/ios/AtlasCompanion.xcodeproj")
REFRESH_RECEIPT = Path("data/phone-companion-refresh-receipt.json")

EXPECTED_SIGNED_ENTITLEMENTS = {
    "application-identifier",
    "com.apple.developer.team-identifier",
    "get-task-allow",
}
FORBIDDEN_INFO_KEYS = {
    "NSAppleEventsUsageDescription",
    "NSBluetoothAlwaysUsageDescription",
    "NSBluetoothPeripheralUsageDescription",
    "NSCalendarsFullAccessUsageDescription",
    "NSCalendarsUsageDescription",
    "NSCalendarsWriteOnlyAccessUsageDescription",
    "NSCameraUsageDescription",
    "NSContactsUsageDescription",
    "NSFaceIDUsageDescription",
    "NSHealthClinicalHealthRecordsShareUsageDescription",
    "NSHealthShareUsageDescription",
    "NSHealthUpdateUsageDescription",
    "NSHomeKitUsageDescription",
    "NSLocationAlwaysAndWhenInUseUsageDescription",
    "NSLocationAlwaysUsageDescription",
    "NSLocationUsageDescription",
    "NSLocationWhenInUseUsageDescription",
    "NSMicrophoneUsageDescription",
    "NSMotionUsageDescription",
    "NSNearbyInteractionUsageDescription",
    "NSPhotoLibraryAddUsageDescription",
    "NSPhotoLibraryUsageDescription",
    "NSRemindersFullAccessUsageDescription",
    "NSRemindersUsageDescription",
    "NSSiriUsageDescription",
    "NSSpeechRecognitionUsageDescription",
    "NSUserTrackingUsageDescription",
    "UIBackgroundModes",
}
FORBIDDEN_RECEIPT_MARKERS = {
    "certificate",
    "device_identifier",
    "device_name",
    "private_key",
    "provisioning_uuid",
    "serial_number",
    "session_token",
    "pairing_code",
    "udid",
}
_SETTING = re.compile(r"^\s*([A-Z][A-Z0-9_]*)\s*=\s*(.*?)\s*$")
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")


class PhoneRefreshError(RuntimeError):
    """A bounded, owner-actionable phone refresh failure."""


@dataclass(frozen=True)
class PhoneDevice:
    identifier: str
    udid: str
    name: str
    marketing_name: str
    os_version: str
    platform: str
    device_type: str
    pairing_state: str

    @property
    def safe_label(self) -> str:
        return f"{self.marketing_name} · iOS {self.os_version}"


def _clean_text(value: Any, *, fallback: str, limit: int = 200) -> str:
    if not isinstance(value, str):
        return fallback
    cleaned = value.strip()
    if not cleaned or len(cleaned) > limit or _CONTROL_CHARACTERS.search(cleaned):
        return fallback
    return cleaned


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _run(
    arguments: Sequence[str],
    *,
    failure: str,
    env: dict[str, str] | None = None,
    binary: bool = False,
) -> bytes | str:
    completed = subprocess.run(
        list(arguments),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=not binary,
        env=env,
        check=False,
    )
    if completed.returncode != 0:
        raw = completed.stderr if completed.stderr else completed.stdout
        lowered = (
            raw.decode("utf-8", errors="replace").lower()
            if isinstance(raw, bytes)
            else str(raw).lower()
        )
        if "locked" in lowered or "passcode" in lowered:
            raise PhoneRefreshError(
                "The iPhone is locked. Unlock it and run Refresh Atlas Companion again."
            )
        if "developer mode" in lowered:
            raise PhoneRefreshError(
                "The paired iPhone is not available for development. Enable Developer Mode in iOS and try again."
            )
        if "account" in lowered and "xcode" in lowered:
            raise PhoneRefreshError(
                "Xcode could not use the saved Apple developer account. Open Xcode > Settings > Accounts and confirm the account."
            )
        raise PhoneRefreshError(failure)
    return completed.stdout


def _require_tools() -> None:
    missing = [
        command
        for command in ("codesign", "security", "xcodebuild", "xcrun")
        if shutil.which(command) is None
    ]
    if missing:
        raise PhoneRefreshError(
            "The complete Xcode command-line toolchain is required before Atlas Companion can be refreshed."
        )


def _config(config_path: str | Path) -> AtlasConfig:
    try:
        return load_config(config_path)
    except Exception as exc:
        raise PhoneRefreshError("Atlas could not read its local configuration.") from exc


def _project_paths(config: AtlasConfig) -> tuple[Path, Path]:
    project = (config.project_root / PHONE_PROJECT).resolve()
    receipt = (config.project_root / REFRESH_RECEIPT).resolve()
    if project.is_symlink() or not project.is_dir():
        raise PhoneRefreshError("The canonical Atlas Companion Xcode project is missing.")
    if config.project_root not in project.parents:
        raise PhoneRefreshError("The Atlas Companion Xcode project escaped the canonical source root.")
    if config.app.data_dir != receipt.parent:
        raise PhoneRefreshError("The phone refresh receipt path is outside Atlas's configured data directory.")
    return project, receipt


def _device_from_payload(payload: dict[str, Any]) -> PhoneDevice:
    connection = payload.get("connectionProperties")
    hardware = payload.get("hardwareProperties")
    properties = payload.get("deviceProperties")
    if not isinstance(connection, dict) or not isinstance(hardware, dict) or not isinstance(properties, dict):
        raise PhoneRefreshError("Xcode returned an unreadable paired-device record.")
    identifier = _clean_text(payload.get("identifier"), fallback="")
    udid = _clean_text(hardware.get("udid"), fallback="")
    name = _clean_text(properties.get("name"), fallback="")
    if not identifier or not udid or not name:
        raise PhoneRefreshError("Xcode returned an incomplete paired-device record.")
    return PhoneDevice(
        identifier=identifier,
        udid=udid,
        name=name,
        marketing_name=_clean_text(hardware.get("marketingName"), fallback="iPhone"),
        os_version=_clean_text(properties.get("osVersionNumber"), fallback="unknown"),
        platform=_clean_text(hardware.get("platform"), fallback="unknown"),
        device_type=_clean_text(hardware.get("deviceType"), fallback="unknown"),
        pairing_state=_clean_text(connection.get("pairingState"), fallback="unknown"),
    )


def select_phone_device(
    raw_devices: Sequence[dict[str, Any]], selector: str | None = None
) -> PhoneDevice:
    candidates: list[PhoneDevice] = []
    for raw in raw_devices:
        try:
            device = _device_from_payload(raw)
        except PhoneRefreshError:
            continue
        if (
            device.platform == "iOS"
            and device.device_type == "iPhone"
            and device.pairing_state == "paired"
        ):
            candidates.append(device)
    if selector:
        matches = [
            device
            for device in candidates
            if selector in {device.identifier, device.udid, device.name}
        ]
        if len(matches) != 1:
            raise PhoneRefreshError(
                "The requested paired iPhone was not found uniquely. Connect the intended iPhone and try again."
            )
        return matches[0]
    if not candidates:
        raise PhoneRefreshError(
            "No paired iPhone is available. Connect the intended iPhone to Xcode and try again."
        )
    if len(candidates) != 1:
        labels = ", ".join(sorted({device.marketing_name for device in candidates}))
        raise PhoneRefreshError(
            f"More than one paired iPhone is available ({labels}). Run the terminal command with an exact --device selector."
        )
    return candidates[0]


def _devicectl_json(
    temporary: Path,
    filename: str,
    arguments: Sequence[str],
    *,
    failure: str,
) -> dict[str, Any]:
    output = temporary / filename
    _run(
        [
            "xcrun",
            "devicectl",
            *arguments,
            "--timeout",
            "120",
            "--json-output",
            str(output),
            "--quiet",
        ],
        failure=failure,
    )
    try:
        payload = json.loads(output.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PhoneRefreshError("Xcode returned unreadable device verification output.") from exc
    if not isinstance(payload, dict):
        raise PhoneRefreshError("Xcode returned an invalid device verification result.")
    return payload


def _list_devices(temporary: Path) -> list[dict[str, Any]]:
    payload = _devicectl_json(
        temporary,
        "devices.json",
        ["list", "devices"],
        failure="Xcode could not list paired devices.",
    )
    devices = (payload.get("result") or {}).get("devices")
    if not isinstance(devices, list):
        raise PhoneRefreshError("Xcode did not return a paired-device list.")
    return [item for item in devices if isinstance(item, dict)]


def _installed_app(temporary: Path, device: PhoneDevice) -> dict[str, str] | None:
    payload = _devicectl_json(
        temporary,
        "installed-app.json",
        [
            "device",
            "info",
            "apps",
            "--device",
            device.udid,
            "--bundle-id",
            PHONE_BUNDLE_ID,
        ],
        failure="Xcode could not inspect Atlas Companion on the paired iPhone.",
    )
    apps = (payload.get("result") or {}).get("apps")
    if not isinstance(apps, list):
        raise PhoneRefreshError("Xcode returned an invalid installed-app result.")
    matches = [
        item
        for item in apps
        if isinstance(item, dict) and item.get("bundleIdentifier") == PHONE_BUNDLE_ID
    ]
    if not matches:
        return None
    if len(matches) != 1:
        raise PhoneRefreshError("Xcode returned more than one Atlas Companion installation.")
    return {
        "bundle_id": PHONE_BUNDLE_ID,
        "version": _clean_text(matches[0].get("version"), fallback="unknown"),
        "build": _clean_text(matches[0].get("bundleVersion"), fallback="unknown"),
    }


def _install_signed_app(temporary: Path, device: PhoneDevice, app_path: Path) -> None:
    arguments = ["device", "install", "app", "--device", device.udid, str(app_path)]
    failure = "Xcode built the app, but could not install it on the paired iPhone."
    try:
        _devicectl_json(
            temporary,
            "install.json",
            arguments,
            failure=failure,
        )
    except PhoneRefreshError as first_error:
        # CoreDevice can occasionally leave a stale tunnel after a signed build.
        # A single idempotent retry recovered the real paired-device gate during
        # acceptance. Human-actionable failures remain immediate stop conditions.
        if str(first_error).startswith(
            (
                "The iPhone is locked.",
                "The paired iPhone is not available for development.",
                "Xcode could not use the saved Apple developer account.",
            )
        ):
            raise
        _devicectl_json(
            temporary,
            "install-retry.json",
            arguments,
            failure=failure,
        )


def parse_build_settings(output: str) -> dict[str, str]:
    settings: dict[str, str] = {}
    for line in output.splitlines():
        match = _SETTING.match(line)
        if match:
            settings[match.group(1)] = match.group(2)
    return settings


def validate_build_settings(settings: dict[str, str]) -> dict[str, str]:
    expected = {
        "CODE_SIGN_STYLE": "Automatic",
        "DEVELOPMENT_TEAM": PHONE_SIGNING_TEAM,
        "PRODUCT_BUNDLE_IDENTIFIER": PHONE_BUNDLE_ID,
    }
    for key, value in expected.items():
        if settings.get(key) != value:
            raise PhoneRefreshError(
                "The Xcode signing boundary no longer matches the approved Atlas Companion project."
            )
    version = _clean_text(settings.get("MARKETING_VERSION"), fallback="")
    build = _clean_text(settings.get("CURRENT_PROJECT_VERSION"), fallback="")
    if not version or not build:
        raise PhoneRefreshError("The Atlas Companion version settings are incomplete.")
    return {"version": version, "build": build}


def _build_settings(project: Path, device: PhoneDevice) -> dict[str, str]:
    output = _run(
        [
            "xcodebuild",
            "-project",
            str(project),
            "-scheme",
            PHONE_SCHEME,
            "-configuration",
            "Debug",
            "-sdk",
            "iphoneos",
            "-destination",
            f"platform=iOS,id={device.udid}",
            "-showBuildSettings",
        ],
        failure="Xcode could not read the Atlas Companion signing settings.",
    )
    assert isinstance(output, str)
    return validate_build_settings(parse_build_settings(output))


def validate_app_boundary(
    info: dict[str, Any],
    profile: dict[str, Any],
    entitlements: dict[str, Any],
    *,
    device_udid: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    if info.get("CFBundleIdentifier") != PHONE_BUNDLE_ID:
        raise PhoneRefreshError("The signed app bundle identifier changed unexpectedly.")
    version = _clean_text(info.get("CFBundleShortVersionString"), fallback="")
    build = _clean_text(info.get("CFBundleVersion"), fallback="")
    if not version or not build:
        raise PhoneRefreshError("The signed app version is incomplete.")
    local_network = info.get("NSLocalNetworkUsageDescription")
    if not isinstance(local_network, str) or not local_network.strip():
        raise PhoneRefreshError("The signed app lost its Local Network explanation.")
    forbidden = sorted(FORBIDDEN_INFO_KEYS.intersection(info))
    if forbidden:
        raise PhoneRefreshError(
            "The signed app unexpectedly requests a broader privacy or background capability."
        )
    if set(entitlements) != EXPECTED_SIGNED_ENTITLEMENTS:
        raise PhoneRefreshError("The signed app entitlements changed beyond the approved boundary.")
    application_identifier = f"{PHONE_SIGNING_TEAM}.{PHONE_BUNDLE_ID}"
    if entitlements.get("application-identifier") != application_identifier:
        raise PhoneRefreshError("The signed app identifier does not match the approved signing team.")
    if entitlements.get("com.apple.developer.team-identifier") != PHONE_SIGNING_TEAM:
        raise PhoneRefreshError("The signed app team identifier changed unexpectedly.")
    if entitlements.get("get-task-allow") is not True:
        raise PhoneRefreshError("The signed app is not the expected owner-development build.")

    profile_entitlements = profile.get("Entitlements")
    if not isinstance(profile_entitlements, dict):
        raise PhoneRefreshError("The development profile entitlements are unreadable.")
    if profile_entitlements.get("application-identifier") != application_identifier:
        raise PhoneRefreshError("The development profile is for a different app.")
    teams = profile.get("TeamIdentifier")
    if not isinstance(teams, list) or PHONE_SIGNING_TEAM not in teams:
        raise PhoneRefreshError("The development profile is for a different team.")
    devices = profile.get("ProvisionedDevices")
    if not isinstance(devices, list) or device_udid not in devices:
        raise PhoneRefreshError("The development profile does not include the selected iPhone.")
    expiration = profile.get("ExpirationDate")
    if not isinstance(expiration, datetime):
        raise PhoneRefreshError("The development profile expiration is unreadable.")
    expires_at = _utc(expiration)
    current = _utc(now or datetime.now(timezone.utc))
    if expires_at <= current:
        raise PhoneRefreshError("Xcode produced an expired development profile.")
    profile_name = _clean_text(profile.get("Name"), fallback="")
    if PHONE_BUNDLE_ID not in profile_name:
        raise PhoneRefreshError("Xcode selected an unexpected development profile.")
    return {
        "app_version": version,
        "app_build": build,
        "profile_name": profile_name,
        "profile_expires_at": expires_at.isoformat(),
        "refresh_recommended_by": (expires_at - timedelta(days=1)).isoformat(),
    }


def _inspect_signed_app(app_path: Path, device: PhoneDevice) -> dict[str, Any]:
    if app_path.is_symlink() or not app_path.is_dir():
        raise PhoneRefreshError("Xcode did not produce the expected Atlas Companion app.")
    _run(
        ["codesign", "--verify", "--deep", "--strict", str(app_path)],
        failure="The refreshed Atlas Companion code signature did not verify.",
    )
    try:
        with (app_path / "Info.plist").open("rb") as handle:
            info = plistlib.load(handle)
    except (OSError, plistlib.InvalidFileException) as exc:
        raise PhoneRefreshError("The refreshed Atlas Companion Info.plist is unreadable.") from exc
    if not isinstance(info, dict):
        raise PhoneRefreshError("The refreshed Atlas Companion Info.plist is invalid.")

    profile_output = _run(
        ["security", "cms", "-D", "-i", str(app_path / "embedded.mobileprovision")],
        failure="The refreshed Atlas Companion development profile is unreadable.",
        binary=True,
    )
    entitlement_output = _run(
        ["codesign", "-d", "--entitlements", ":-", str(app_path)],
        failure="The refreshed Atlas Companion entitlements are unreadable.",
        binary=True,
    )
    assert isinstance(profile_output, bytes)
    assert isinstance(entitlement_output, bytes)
    try:
        profile = plistlib.loads(profile_output)
        entitlements = plistlib.loads(entitlement_output)
    except plistlib.InvalidFileException as exc:
        raise PhoneRefreshError("The refreshed signing evidence is invalid.") from exc
    if not isinstance(profile, dict) or not isinstance(entitlements, dict):
        raise PhoneRefreshError("The refreshed signing evidence has an invalid format.")
    return validate_app_boundary(
        info,
        profile,
        entitlements,
        device_udid=device.udid,
    )


def _read_receipt(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        raise PhoneRefreshError("The phone refresh receipt must be a regular owner file.")
    if path.stat().st_mode & 0o077:
        raise PhoneRefreshError("The phone refresh receipt is not owner-only.")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PhoneRefreshError("The phone refresh receipt is unreadable.") from exc
    if not isinstance(payload, dict):
        raise PhoneRefreshError("The phone refresh receipt has an invalid format.")
    serialized = json.dumps(payload, sort_keys=True).lower()
    if any(marker in serialized for marker in FORBIDDEN_RECEIPT_MARKERS):
        raise PhoneRefreshError("The phone refresh receipt contains a forbidden identifier or secret field.")
    return payload


def write_refresh_receipt(path: Path, payload: dict[str, Any]) -> None:
    serialized = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    lowered = serialized.lower()
    if any(marker in lowered for marker in FORBIDDEN_RECEIPT_MARKERS):
        raise PhoneRefreshError("Refusing to persist a phone identifier or secret in the refresh receipt.")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)


def _preflight(
    config_path: str | Path,
    selector: str | None,
    temporary: Path,
) -> tuple[AtlasConfig, Path, Path, PhoneDevice, dict[str, Any]]:
    _require_tools()
    config = _config(config_path)
    project, receipt = _project_paths(config)
    device = select_phone_device(_list_devices(temporary), selector)
    version = _build_settings(project, device)
    phone_status = PhoneCompanionStateStore(config.phone_companion).status()
    installed = _installed_app(temporary, device)
    return config, project, receipt, device, {
        "status": "blocked" if phone_status.get("bridge_active") else "ready",
        "mode": "check",
        "bundle_id": PHONE_BUNDLE_ID,
        "signing_team": PHONE_SIGNING_TEAM,
        "project_version": version["version"],
        "project_build": version["build"],
        "device_model": device.marketing_name,
        "device_os": device.os_version,
        "paired": True,
        "installed": installed is not None,
        "installed_version": installed.get("version") if installed else None,
        "installed_build": installed.get("build") if installed else None,
        "bridge_active": bool(phone_status.get("bridge_active")),
        "paused": bool(phone_status.get("paused")),
        "existing_refresh_receipt": _read_receipt(receipt),
        "will_request": ["Xcode automatic provisioning updates", "install on the selected paired iPhone"],
        "will_not": [
            "start the Atlas phone bridge",
            "launch Atlas Companion",
            "grant an iOS permission",
            "add a phone action or background mode",
            "persist a device identifier or signing secret",
        ],
    }


def check_phone_refresh(
    config_path: str | Path = "config/atlas.yaml",
    *,
    selector: str | None = None,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(
        prefix="atlas-phone-refresh-check.", dir="/private/tmp"
    ) as temporary_name:
        _, _, _, _, result = _preflight(config_path, selector, Path(temporary_name))
        return result


def install_phone_refresh(
    config_path: str | Path = "config/atlas.yaml",
    *,
    selector: str | None = None,
    confirmation: str,
) -> dict[str, Any]:
    if confirmation != "REFRESH":
        raise PhoneRefreshError("The exact REFRESH confirmation is required before installation.")
    with tempfile.TemporaryDirectory(
        prefix="atlas-phone-refresh-install.", dir="/private/tmp"
    ) as temporary_name:
        temporary = Path(temporary_name)
        config, project, receipt_path, device, preflight = _preflight(
            config_path, selector, temporary
        )
        if preflight["bridge_active"]:
            raise PhoneRefreshError(
                "Stop the separate Atlas Phone Bridge before refreshing the app. The main Atlas service may remain running."
            )
        derived = temporary / "DerivedData"
        environment = dict(os.environ)
        environment["COPYFILE_DISABLE"] = "1"
        _run(
            [
                "xcodebuild",
                "-quiet",
                "-project",
                str(project),
                "-scheme",
                PHONE_SCHEME,
                "-configuration",
                "Debug",
                "-sdk",
                "iphoneos",
                "-destination",
                f"platform=iOS,id={device.udid}",
                "-destination-timeout",
                "60",
                "-derivedDataPath",
                str(derived),
                "-allowProvisioningUpdates",
                "-allowProvisioningDeviceRegistration",
                "build",
            ],
            failure=(
                "Xcode could not create the signed refresh build. Open Xcode > Settings > Accounts, "
                "confirm the Personal Team, and try again."
            ),
            env=environment,
        )
        app_path = derived / "Build/Products/Debug-iphoneos/AtlasCompanion.app"
        signing = _inspect_signed_app(app_path, device)
        _install_signed_app(temporary, device, app_path)
        installed = _installed_app(temporary, device)
        if not installed:
            raise PhoneRefreshError("Atlas Companion was not present after the installation request.")
        if (
            installed.get("version") != signing["app_version"]
            or installed.get("build") != signing["app_build"]
        ):
            raise PhoneRefreshError("The installed Atlas Companion version did not match the signed build.")

        completed_at = datetime.now(timezone.utc).isoformat()
        receipt = {
            "format": "atlas-phone-companion-refresh-receipt",
            "version": 1,
            "completed_at": completed_at,
            "bundle_id": PHONE_BUNDLE_ID,
            "app_version": signing["app_version"],
            "app_build": signing["app_build"],
            "signing_team": PHONE_SIGNING_TEAM,
            "profile_name": signing["profile_name"],
            "profile_expires_at": signing["profile_expires_at"],
            "refresh_recommended_by": signing["refresh_recommended_by"],
            "device_model": device.marketing_name,
            "device_os": device.os_version,
            "code_signature_verified": True,
            "installed_version_verified": True,
            "bridge_started": False,
            "permissions": ["Local Network while the bridge is running"],
            "broader_permissions_granted": False,
            "phone_mutation_added": False,
            "secrets_included": False,
        }
        write_refresh_receipt(receipt_path, receipt)
        Database(config.database_path).audit(
            event_type="maintenance",
            actor="operator",
            action="phone_companion.refresh_install",
            resource="phone_companion",
            outcome="success",
            details={
                "bundle_id": PHONE_BUNDLE_ID,
                "app_version": signing["app_version"],
                "app_build": signing["app_build"],
                "profile_expires_at": signing["profile_expires_at"],
                "signing_team": PHONE_SIGNING_TEAM,
                "bridge_started": False,
            },
        )
        return {
            "status": "installed",
            "mode": "refresh",
            "bundle_id": PHONE_BUNDLE_ID,
            "app_version": signing["app_version"],
            "app_build": signing["app_build"],
            "device_model": device.marketing_name,
            "device_os": device.os_version,
            "profile_name": signing["profile_name"],
            "profile_expires_at": signing["profile_expires_at"],
            "refresh_recommended_by": signing["refresh_recommended_by"],
            "code_signature_verified": True,
            "installed_version_verified": True,
            "bridge_active": False,
            "receipt": str(receipt_path),
            "secrets_included": False,
        }
