from __future__ import annotations

import asyncio
import hmac
import json
import os
import secrets
import threading
import webbrowser
from pathlib import Path
from typing import Any

import typer
import uvicorn

from atlas_core import __version__
from atlas_core.api import create_app
from atlas_core.errors import ApprovalRequired, AtlasError
from atlas_core.phone_companion import (
    create_phone_bridge_app,
    ephemeral_tls_material,
    validate_bridge_host,
)
from atlas_core.phone_refresh import (
    PhoneRefreshError,
    check_phone_refresh,
    install_phone_refresh,
)
from atlas_core.services import (
    AtlasServices,
    build_services,
    build_supervisor_v4_only,
    build_supervisor_v4_review_only,
)

app = typer.Typer(
    name="atlas",
    help="Atlas Core local-first, model-independent AI runtime.",
    no_args_is_help=True,
)

DEFAULT_CONFIG = Path("config/atlas.yaml")
GOOGLE_PRIVACY_POLICY_URL = "https://atlaswithin.net/privacy"


def _services(config: Path) -> AtlasServices:
    return build_services(config)


def _print_json(value: Any) -> None:
    typer.echo(json.dumps(value, indent=2, ensure_ascii=False, default=str))


def _run(coro):
    return asyncio.run(coro)


def _check_bind_security(config: Path, host: str) -> None:
    if host in {"127.0.0.1", "localhost", "::1"}:
        return
    svc = _services(config)
    if not svc.config.app.api_token:
        raise typer.BadParameter(
            "Refusing to expose Atlas beyond localhost without ATLAS_API_TOKEN",
            param_hint="--host",
        )
    typer.echo(
        "Warning: Atlas is bound beyond localhost. Keep a firewall or private network boundary in place.",
        err=True,
    )


def _print_chat_result(result: dict[str, Any]) -> None:
    content = str(result.get("content") or "")
    if content:
        typer.echo(content)
    if result.get("status") == "awaiting_approval":
        approval = result.get("approval") or {}
        typer.echo(
            f"\nApproval required: {approval.get('tool')}.{approval.get('action')}"
        )
        typer.echo(f"Approval ID: {approval.get('id')}")
        typer.echo(json.dumps(approval.get("arguments") or {}, indent=2, ensure_ascii=False))
    elif result.get("error"):
        typer.echo(f"\nRun error: {result['error']}", err=True)


def _resolve_approvals_interactively(
    svc: AtlasServices, result: dict[str, Any]
) -> dict[str, Any]:
    while result.get("status") == "awaiting_approval":
        approval = result.get("approval") or {}
        typer.echo(
            f"\nAtlas requests {approval.get('tool')}.{approval.get('action')}:"
        )
        typer.echo(json.dumps(approval.get("arguments") or {}, indent=2, ensure_ascii=False))
        decision = "approved" if typer.confirm("Approve this exact action once?") else "rejected"
        svc.tools.decide_approval(str(approval["id"]), decision)
        result = _run(svc.runtime.resume(str(result["run_id"])))
        _print_chat_result(result)
    return result


@app.command()
def version() -> None:
    """Print the Atlas Core version."""
    typer.echo(__version__)


@app.command()
def doctor(
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Check identity, storage, policy, agents, and model connectivity."""
    svc = _services(config)
    typer.echo(f"Atlas Core {__version__}")
    typer.echo(f"Config:       {svc.config.config_path}")
    typer.echo(f"Database:     {svc.config.database_path}")
    typer.echo(f"Workspace:    {svc.config.app.workspace_dir}")
    typer.echo(f"Identity:     {svc.identity.fingerprint()} ({len(svc.identity.documents())} files)")
    typer.echo(f"Permissions:  {svc.config.app.permissions_file}")
    typer.echo(f"Agents:       {len(svc.agents.list())} ({svc.agents.default_agent} default)")
    typer.echo(f"Default model: {svc.config.routing.default_provider}")
    typer.echo(f"Records:      {json.dumps(svc.database.stats(), sort_keys=True)}")
    typer.echo("\nMac operator:")
    if svc.mac_inbox is None:
        typer.echo("  [--] Atlas Inbox disabled")
    else:
        mac_status = svc.mac_inbox.status({})
        marker = "OK" if mac_status["ready"] else "PAUSED"
        typer.echo(
            f"  [{marker}] Atlas Inbox · {mac_status['root']} · "
            f"{'ready' if mac_status['ready'] else 'paused'}"
        )
    typer.echo("\nPhone companion:")
    if svc.phone_companion is None:
        typer.echo("  [--] native phone bridge disabled")
    else:
        phone_status = svc.phone_companion.status({})
        if phone_status.get("device_connected"):
            marker, label = "OK", "device connected"
        elif phone_status.get("bridge_active"):
            marker, label = "--", "bridge waiting for phone"
        elif phone_status.get("paused"):
            marker, label = "PAUSED", "paused"
        else:
            marker, label = "--", "bridge stopped"
        typer.echo(
            f"  [{marker}] Native iPhone companion · {label} · read-only status"
        )
    typer.echo("\nSupervisor:")
    supervisor_status = svc.supervisor.status()
    if not supervisor_status["enabled"]:
        typer.echo("  [--] disabled")
    else:
        marker = "PAUSED" if supervisor_status["paused"] else "OK"
        label = "paused" if supervisor_status["paused"] else "ready on demand"
        task_count = sum(supervisor_status["task_counts"].values())
        typer.echo(
            f"  [{marker}] Software Development · {label} · "
            f"manual only · {task_count} task receipts"
        )
        typer.echo("       No background execution, project mutation, push, or deploy.")
    v2_status = svc.supervisor_v2.status()
    v2_count = sum(v2_status["task_counts"].values())
    typer.echo("\nSupervisor v2 fixture gate:")
    if not v2_status["enabled"]:
        v2_marker, v2_label = "--", "disabled"
    elif v2_status["paused"]:
        v2_marker, v2_label = "PAUSED", "paused"
    elif v2_status["candidate_execution_available"]:
        v2_marker, v2_label = "OK", "ready for one owner-confirmed attempt"
    else:
        v2_marker, v2_label = "--", "lifetime attempt cap exhausted"
    typer.echo(
        f"  [{v2_marker}] {v2_label} · {v2_status['attempts_used']}/"
        f"{v2_status['attempt_cap']} live attempts used · {v2_count} task receipts"
    )
    typer.echo(
        "       Authenticated Codex model service required; command network disabled; "
        "canonical project unchanged."
    )
    v3_status = svc.supervisor_v3.status()
    v3_count = sum(v3_status["task_counts"].values())
    typer.echo("\nSupervisor v3 staged SDK pilot:")
    if not v3_status["enabled"]:
        v3_marker, v3_label = "--", "disabled"
    elif v3_status["paused"]:
        v3_marker, v3_label = "PAUSED", "paused"
    elif v3_status["next_gate"] == "successor_canary_attempt_exhausted":
        v3_marker, v3_label = "--", "successor attempt exhausted; stopped safely"
    elif v3_status["next_gate"] == "successor_canary_exact_confirmation":
        v3_marker, v3_label = "OK", "successor plan awaits its exact phrase"
    elif v3_status["successor_canary_plan_available"]:
        v3_marker, v3_label = "OK", "successor canary ready to plan"
    else:
        v3_marker, v3_label = "--", f"waiting at {v3_status['next_gate']}"
    typer.echo(
        f"  [{v3_marker}] {v3_label} · {v3_status['canary_attempts_used']}/1 "
        f"original, {v3_status['successor_canary_attempts_used']}/1 successor, "
        f"{v3_status['fixture_attempts_used']}/1 fixture, "
        f"{v3_status['recovery_canary_attempts_used']}/1 recovery canary, and "
        f"{v3_status['recovery_fixture_attempts_used']}/1 recovery fixture attempts used · "
        f"{v3_count} task receipts"
    )
    typer.echo(
        "       Pinned Python SDK and runtime; no model contact from offline readiness; "
        "no canonical mutation."
    )
    v4_status = svc.supervisor_v4.status()
    typer.echo("\nSupervisor v4 proposal-only core:")
    if not v4_status["enabled"]:
        v4_marker, v4_label = "--", "disabled"
    elif v4_status.get("next_gate") in {
        "owner_review_option2_identity_only_host_preflight_recovery_result_quarantine",
        "owner_review_option2_point_action_qualification_quarantine",
        "owner_review_option2_native_preflight_offline_qualification_quarantine",
    }:
        v4_marker, v4_label = (
            "STOP",
            "Option 2 review evidence is quarantined; exact owner review required",
        )
    elif (
        v4_status.get("option2_identity_candidate_host_preflight_recovery_state")
        == "recovery_candidate_generated_inactive"
        and v4_status.get("option2_host_candidate_active") is True
        and v4_status.get("next_gate")
        == "owner_review_option2_legacy_identity_candidate_non_authorizing"
    ):
        v4_marker, v4_label = (
            "STOP",
            "Option 2 legacy recovery candidate is non-authorizing; owner review required",
        )
    elif (
        v4_status.get("option2_native_preflight_qualification_state")
        == "native_preflight_and_claim_ledger_fixture_qualified_inactive"
        and v4_status.get("option2_native_preflight_fixture_qualified") is True
        and v4_status.get("next_gate")
        == "owner_review_option2_native_preflight_installation_and_signing_plan"
    ):
        v4_marker, v4_label = (
            "STOP",
            "Option 2 native fixture qualified inactive; installation, signing, and anchor plan requires owner review",
        )
    elif (
        v4_status.get("option2_point_action_qualification_state")
        == "qualified_inactive"
        and v4_status.get("option2_point_action_fixture_qualified") is True
        and v4_status.get("option2_native_preflight_qualification_state")
        == "qualification_required"
        and v4_status.get("next_gate")
        == "option2_native_preflight_fixture_qualification"
    ):
        v4_marker, v4_label = (
            "OK",
            "Option 2 point-of-action design qualified inactive; native fixture qualification pending",
        )
    elif (
        v4_status.get("option2_host_preflight_recovery_result_review_state")
        == "recovery_result_reviewed_inactive"
        and v4_status.get("next_gate")
        == "option2_point_action_fixture_qualification"
    ):
        v4_marker, v4_label = (
            "OK",
            "Option 2 expired recovery result reviewed; offline design qualification pending",
        )
    elif (
        v4_status.get(
            "option2_identity_candidate_host_preflight_recovery_state"
        )
        in {"recovery_candidate_expired_inactive", "recovery_candidate_stale_inactive"}
        and v4_status.get("next_gate")
        == "owner_review_option2_identity_only_host_preflight_recovery_result"
    ):
        v4_marker, v4_label = (
            "STOP",
            "Option 2 recovery candidate is historical only; result review required",
        )
    elif (
        v4_status.get("option2_identity_candidate_host_preflight_state")
        == "preflight_consumed_incomplete"
        and v4_status.get(
            "option2_identity_candidate_host_preflight_recovery_state"
        )
        == "recovery_implemented_inactive"
        and v4_status.get("next_gate")
        == "owner_authorize_option2_identity_only_host_preflight_recovery"
    ):
        v4_marker, v4_label = (
            "STOP",
            "Option 2 read-only recovery is ready; exact owner authorization required",
        )
    elif v4_status.get("option2_identity_candidate_host_preflight_state") in {
        "candidate_invalid_quarantined",
        "preflight_consumed_incomplete",
        "candidate_storage_unavailable",
    }:
        v4_marker, v4_label = (
            "STOP",
            "Option 2 host preflight quarantined; owner recovery review required",
        )
    elif (
        v4_status.get("option2_identity_candidate_host_preflight_state")
        == "candidate_generated_inactive"
        and v4_status.get("option2_host_candidate_active") is True
        and v4_status.get("next_gate")
        == "owner_review_option2_legacy_identity_candidate_non_authorizing"
    ):
        v4_marker, v4_label = (
            "STOP",
            "Option 2 legacy host candidate is non-authorizing; owner review required",
        )
    elif v4_status.get("option2_identity_candidate_host_preflight_state") in {
        "candidate_expired_inactive",
        "candidate_stale_inactive",
    }:
        v4_marker, v4_label = (
            "--",
            "Option 2 host candidate expired or drifted; fresh review required",
        )
    elif (
        v4_status.get("option2_identity_candidate_resolver_state")
        == "qualified_inactive"
        and v4_status.get("option2_identity_candidate_fixture_qualified") is True
        and v4_status.get("option2_identity_candidate_host_preflight_state")
        == "not_performed"
        and v4_status.get("next_gate")
        == "owner_review_option2_identity_only_host_preflight"
    ):
        v4_marker, v4_label = (
            "OK",
            "Option 2 identity candidate qualified inactive; host-preflight review required",
        )
    elif (
        v4_status.get("option2_provisioning_manifest_review_state")
        == "reviewed_inactive"
        and v4_status.get("option2_provisioning_manifest_owner_reviewed") is True
        and v4_status.get("next_gate")
        == "option2_identity_candidate_resolver_offline_implementation"
    ):
        v4_marker, v4_label = (
            "OK",
            "Option 2 incomplete manifest reviewed; identity candidate work pending",
        )
    elif (
        v4_status.get("option2_plan_owner_review_state") == "reviewed_inactive"
        and v4_status.get("option2_provisioner_dry_run_state")
        == "qualified_inactive"
        and v4_status.get("next_gate")
        == "owner_review_option2_service_identity_provisioning_manifest"
    ):
        v4_marker, v4_label = (
            "OK",
            "Option 2 inactive manifest contract ready for owner review",
        )
    elif (
        v4_status.get("option1_recovery_canary_result_review_state")
        == "reviewed_inactive"
        and v4_status.get("option2_service_identity_and_vault_plan_state")
        == "implemented_inactive"
        and v4_status.get("next_gate")
        == "owner_review_option2_service_identity_and_vault_offline_plan"
    ):
        v4_marker, v4_label = "OK", "Option 2 offline plan ready for owner review"
    elif v4_status.get("option1_recovery_canary_implementation_state") == (
        "completed_inactive"
    ):
        v4_marker, v4_label = "OK", "recovery canary passed; result review required"
    elif v4_status.get("option1_recovery_canary_implementation_state") == (
        "option1_synthetic_integration_recovery_canary_implemented_inactive"
    ):
        v4_marker, v4_label = "OK", "recovery canary implemented; authorization pending"
    elif v4_status["option1_canary_implementation_state"] == (
        "failed_preclaim_recovery_review_required"
    ):
        v4_marker, v4_label = "--", "synthetic canary recovery review required"
    elif v4_status["offline_ready"]:
        v4_marker, v4_label = "OK", "offline qualification passed; inactive"
    else:
        v4_marker, v4_label = "--", "implemented inactive; qualification pending"
    typer.echo(f"  [{v4_marker}] {v4_label} · live readiness false")
    typer.echo(
        "       Structured proposals only · every model action prohibited · "
        "no ordinary/API run, credential, canonical-application, or model-contact route · "
        f"next gate: {v4_status['next_gate']}."
    )
    typer.echo("\nProviders:")
    results = _run(svc.router.health())
    for result in results:
        marker = "OK" if result.get("ok") else "--"
        configured = "configured" if result.get("configured") else "not configured"
        location = "local" if result.get("local") else "cloud"
        typer.echo(
            f"  [{marker}] {result.get('provider')} · {result.get('model')} · {location} · {configured}"
        )
        if result.get("error"):
            typer.echo(f"       {result['error']}")
        if result.get("model_available") is False:
            typer.echo("       Server is reachable, but the configured model was not listed.")
    default_result = next(
        (item for item in results if item.get("provider") == svc.config.routing.default_provider),
        None,
    )
    if default_result and not default_result.get("ok"):
        provider = svc.config.providers[svc.config.routing.default_provider]
        if provider.kind == "openai_compatible" and provider.local:
            typer.echo(
                f"\nConfigured local model: {provider.model}\n"
                "For the bundled default, run: ./scripts/setup-ollama.sh\n"
                "Then make sure Ollama is running and repeat: atlas doctor"
            )
    typer.echo("\nGoogle Workspace:")
    if svc.google is None:
        typer.echo("  [--] disabled")
    else:
        try:
            google_status = svc.google.status()
            client_marker = "configured" if google_status["client_configured"] else "not configured"
            connection_marker = "connected" if google_status["connected"] else "not connected"
            typer.echo(
                f"  [{'OK' if google_status['connected'] else '--'}] "
                f"{google_status['expected_account']} · OAuth client {client_marker} · {connection_marker}"
            )
            typer.echo("       Gmail send and permanent deletion are unavailable.")
            typer.echo("       Calendar mutations are confined to the primary calendar.")
        except AtlasError as exc:
            typer.echo(f"  [--] status unavailable: {exc}")


@app.command()
def chat(
    message: str | None = typer.Argument(None, help="Message; omit for interactive mode."),
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
    provider: str | None = typer.Option(None, help="Configured provider name."),
    model: str | None = typer.Option(None, help="Override the provider's default model."),
    agent: str | None = typer.Option(None, help="Agent profile slug."),
    project: str | None = typer.Option(None, help="Active project slug."),
    allow_cloud: bool = typer.Option(False, help="Permit a provider not marked local."),
    tools: bool = typer.Option(True, "--tools/--no-tools", help="Expose policy-approved tools to the model."),
    approvals: bool = typer.Option(True, "--approvals/--no-approvals", help="Prompt for requested tool approvals."),
) -> None:
    """Chat with Atlas in one-shot or interactive terminal mode."""
    svc = _services(config)

    def ask(text: str, conversation_id: str | None) -> dict[str, Any]:
        result = _run(
            svc.runtime.chat(
                message=text,
                conversation_id=conversation_id,
                provider=provider,
                model=model,
                project_slug=project,
                agent_slug=agent,
                local_only=not allow_cloud,
                tools_enabled=tools,
            )
        )
        _print_chat_result(result)
        if approvals:
            result = _resolve_approvals_interactively(svc, result)
        return result

    if message is not None:
        result = ask(message, None)
        typer.echo(f"\n[conversation: {result['conversation_id']}; run: {result['run_id']}]")
        return

    typer.echo("Interactive Atlas session. Enter /quit to exit or /new to start over.")
    conversation_id: str | None = None
    while True:
        try:
            user_message = typer.prompt("You")
        except (EOFError, KeyboardInterrupt):
            typer.echo()
            break
        command = user_message.strip().lower()
        if command in {"/quit", "/exit"}:
            break
        if command == "/new":
            conversation_id = None
            typer.echo("Started a new conversation.")
            continue
        result = ask(user_message, conversation_id)
        conversation_id = result["conversation_id"]


@app.command()
def resume(
    run_id: str,
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
    approvals: bool = typer.Option(True, "--approvals/--no-approvals"),
) -> None:
    """Resume an agent run after its pending approval was decided."""
    svc = _services(config)
    result = _run(svc.runtime.resume(run_id))
    _print_chat_result(result)
    if approvals:
        _resolve_approvals_interactively(svc, result)


@app.command()
def agents(
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """List configured portable agent profiles."""
    _print_json(_services(config).agents.list())


@app.command()
def providers(
    health: bool = typer.Option(False, help="Perform connectivity checks."),
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """List model providers or test their connectivity."""
    svc = _services(config)
    _print_json(_run(svc.router.health()) if health else svc.router.describe())


def _mac_inbox_operator(svc: AtlasServices):
    if svc.mac_inbox is None:
        raise typer.BadParameter("The Atlas Inbox Mac operator is disabled")
    return svc.mac_inbox


@app.command("mac-inbox-status")
def mac_inbox_status(
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Show the exact Atlas Inbox scope and stop-control state."""
    _print_json(_mac_inbox_operator(_services(config)).status({}))


@app.command("mac-inbox-pause")
def mac_inbox_pause(
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Immediately pause all Atlas Inbox actions until the owner resumes them."""
    svc = _services(config)
    result = _mac_inbox_operator(svc).pause()
    svc.database.audit(
        event_type="control",
        actor="operator",
        action="mac_inbox.pause",
        resource="mac_inbox",
        outcome="success",
        details={"root": result["root"]},
    )
    _print_json(result)


@app.command("mac-inbox-resume")
def mac_inbox_resume(
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Resume the owner-approved Atlas Inbox task family."""
    svc = _services(config)
    result = _mac_inbox_operator(svc).resume()
    svc.database.audit(
        event_type="control",
        actor="operator",
        action="mac_inbox.resume",
        resource="mac_inbox",
        outcome="success",
        details={"root": result["root"]},
    )
    _print_json(result)


def _phone_operator(svc: AtlasServices):
    if svc.phone_companion is None:
        raise typer.BadParameter("The native Atlas phone companion is disabled")
    return svc.phone_companion


@app.command("phone-companion-status")
def phone_companion_status(
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Show the read-only native phone bridge and device status."""
    _print_json(_phone_operator(_services(config)).status({}))


@app.command("phone-companion-pause")
def phone_companion_pause(
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Immediately block phone pairing and status updates."""
    svc = _services(config)
    operator = _phone_operator(svc)
    result = operator.store.pause()
    svc.database.audit(
        event_type="control",
        actor="operator",
        action="phone_companion.pause",
        resource="phone_companion",
        outcome="success",
        details={},
    )
    _print_json(result)


@app.command("phone-companion-resume")
def phone_companion_resume(
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Resume the already-approved read-only phone companion gate."""
    svc = _services(config)
    operator = _phone_operator(svc)
    result = operator.store.resume()
    svc.database.audit(
        event_type="control",
        actor="operator",
        action="phone_companion.resume",
        resource="phone_companion",
        outcome="success",
        details={},
    )
    _print_json(result)


@app.command("phone-companion-refresh")
def phone_companion_refresh(
    install: bool = typer.Option(
        False,
        "--install",
        help="Build, verify, and reinstall the status-only app on the paired iPhone.",
    ),
    confirm: str = typer.Option(
        "",
        "--confirm",
        help="Exact REFRESH confirmation required with --install.",
    ),
    device: str | None = typer.Option(
        None,
        "--device",
        help="Exact paired-device name or identifier; omit when one paired iPhone exists.",
    ),
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Check or refresh the owner-signed native Atlas Companion installation."""
    try:
        result = (
            install_phone_refresh(
                config,
                selector=device,
                confirmation=confirm,
            )
            if install
            else check_phone_refresh(config, selector=device)
        )
    except PhoneRefreshError as exc:
        typer.echo(f"Atlas Companion refresh stopped: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    _print_json(result)


@app.command("phone-bridge")
def phone_bridge(
    host: str = typer.Option(..., help="One exact private IPv4 address on this Mac."),
    port: int | None = typer.Option(None, min=1_024, max=65_535),
    hide_pairing_code: bool = typer.Option(False, hidden=True),
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Run the separate ephemeral-TLS native iPhone bridge on demand."""
    validated_host = validate_bridge_host(host)
    svc = _services(config)
    _phone_operator(svc)
    selected_port = port or svc.config.phone_companion.bridge_port
    pairing_code = f"{secrets.randbelow(1_000_000):06d}"
    with ephemeral_tls_material(validated_host) as tls:
        typer.echo("Atlas Native Phone Bridge")
        typer.echo(f"Address: https://{validated_host}:{selected_port}")
        typer.echo(f"Certificate code: {tls.confirmation_code}")
        if hide_pairing_code:
            typer.echo("Pairing code: hidden for automated verification")
        else:
            typer.echo(f"Pairing code: {pairing_code}")
        typer.echo(
            "Scope: one explicitly paired device; read-only device status only."
        )
        typer.echo(
            "Stop: press Control-C, run Pause Atlas Phone Companion.command, "
            "or disconnect in the iPhone app."
        )
        typer.echo("The certificate, private key, pairing code, and session expire with this process.")
        bridge_app = create_phone_bridge_app(
            config,
            host=validated_host,
            port=selected_port,
            pairing_code=pairing_code,
        )
        uvicorn.run(
            bridge_app,
            host=validated_host,
            port=selected_port,
            ssl_keyfile=str(tls.private_key_path),
            ssl_certfile=str(tls.certificate_path),
        )


def _google_connector(svc: AtlasServices):
    if svc.google is None:
        raise typer.BadParameter("Google Workspace is disabled in Atlas configuration")
    return svc.google


def _confirm_google_workspace_access(expected_account: str | None) -> None:
    account = expected_account or "the Google account configured in Atlas"
    typer.echo("\nGOOGLE WORKSPACE ACCESS DISCLOSURE\n")
    typer.echo(f"Account: {account}")
    typer.echo(
        "\nAtlas will ask Google for two permissions:\n"
        "- Gmail Modify: read and search mail; change labels or recoverable Trash "
        "state; and create, replace, or delete unsent drafts. Google's permission "
        "is broad enough to send mail, but this Atlas build exposes no send or "
        "permanent-delete action.\n"
        "- Calendar owned events: see, create, change, and delete events on calendars "
        "you own. Atlas confines its tools to the primary calendar and refuses to "
        "change events that have attendees."
    )
    typer.echo(
        "\nPurpose: help you manage email and your schedule. Email and calendar "
        "changes require an exact one-time approval. The sole exception is an "
        "optional connector self-test that creates, verifies, and immediately deletes "
        "only its own owner-addressed unsent draft."
    )
    typer.echo(
        "\nStorage and use: the OAuth client credential and refresh token stay in "
        "macOS Keychain; short-lived access tokens stay in process memory. Requested "
        "tool results and conversations may be retained in Atlas's local database. "
        "Atlas does not sell Google data, use it for advertising, or use it to train "
        "a generalized or shared AI model."
    )
    typer.echo(f"\nPrivacy policy: {GOOGLE_PRIVACY_POLICY_URL}\n")
    if not typer.confirm("Continue and open Google's consent screen?"):
        raise typer.Abort()


@app.command("google-status")
def google_status(
    verify: bool = typer.Option(False, help="Perform a live non-mutating account check."),
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Show the Google Workspace connection without revealing credentials."""
    svc = _services(config)
    connector = _google_connector(svc)
    result = connector.status()
    if verify and result.get("connected"):
        result["live_verification"] = connector.verify_connection()
    _print_json(result)


@app.command("google-import-client")
def google_import_client(
    path: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Import a Google Desktop OAuth client JSON file into macOS Keychain."""
    svc = _services(config)
    connector = _google_connector(svc)
    result = connector.import_client_file(path)
    svc.database.audit(
        event_type="connector",
        actor="operator",
        action="google.oauth_client.import",
        resource="google-workspace",
        outcome="success",
        details={
            "client_type": result["client_type"],
            "client_fingerprint": result["client_fingerprint"],
        },
    )
    _print_json(result)
    typer.echo("The client credential is stored in macOS Keychain; the source file was not deleted.")


@app.command("google-connect")
def google_connect(
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Connect the configured Google account through the system browser."""
    svc = _services(config)
    connector = _google_connector(svc)
    _confirm_google_workspace_access(connector.config.expected_account)
    result = connector.authorize_interactive()
    svc.database.audit(
        event_type="connector",
        actor="operator",
        action="google.connect",
        resource="google-workspace",
        outcome="success",
        details={
            "account": result.get("connected_account"),
            "calendar": result.get("calendar"),
            "scopes": result.get("scopes"),
        },
    )
    _print_json(result)


@app.command("google-disconnect")
def google_disconnect(
    yes: bool = typer.Option(False, "--yes", help="Confirm revocation without prompting."),
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Revoke Atlas's Google token and remove it from macOS Keychain."""
    svc = _services(config)
    connector = _google_connector(svc)
    if not yes and not typer.confirm("Revoke Atlas's Google Workspace access?"):
        raise typer.Abort()
    result = connector.disconnect()
    svc.database.audit(
        event_type="connector",
        actor="operator",
        action="google.disconnect",
        resource="google-workspace",
        outcome="success",
        details=result,
    )
    _print_json(result)


@app.command()
def remember(
    key: str,
    content: str,
    namespace: str = typer.Option("global"),
    kind: str = typer.Option("note"),
    importance: int = typer.Option(5, min=1, max=10),
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Create or replace an explicit long-term memory."""
    svc = _services(config)
    memory = svc.database.upsert_memory(
        namespace=namespace,
        kind=kind,
        key=key,
        content=content,
        importance=importance,
    )
    svc.database.audit(
        event_type="memory",
        actor="operator",
        action="memory.upsert",
        resource=str(memory["id"]),
        outcome="success",
        details={"namespace": namespace, "key": key},
    )
    _print_json(memory)


@app.command("memories")
def list_memories(
    query: str | None = typer.Option(None, "--query", "-q"),
    namespace: str | None = typer.Option(None),
    limit: int = typer.Option(50, min=1, max=500),
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Inspect stored memories."""
    svc = _services(config)
    rows = (
        svc.database.search_memories(query, namespace=namespace, limit=limit)
        if query
        else svc.database.list_memories(namespace=namespace, limit=limit)
    )
    _print_json(rows)


@app.command("forget")
def forget_memory(
    memory_id: int,
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Delete an explicit memory by ID."""
    svc = _services(config)
    if not svc.database.delete_memory(memory_id):
        raise typer.BadParameter(f"Memory not found: {memory_id}")
    typer.echo(f"Deleted memory {memory_id}")


@app.command("project-set")
def project_set(
    slug: str,
    name: str,
    status: str = typer.Option("active"),
    summary: str = typer.Option(""),
    next_action: str = typer.Option(""),
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Create or update a durable project-state record."""
    _print_json(
        _services(config).database.upsert_project(
            slug=slug,
            name=name,
            status=status,
            summary=summary,
            next_action=next_action,
        )
    )


@app.command("projects")
def projects(
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """List durable project records."""
    _print_json(_services(config).database.list_projects())


@app.command()
def tool(
    tool_name: str,
    action: str,
    arguments_json: str = typer.Argument("{}"),
    approval_id: str | None = typer.Option(None),
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Execute a registered tool action through the permission engine."""
    try:
        arguments = json.loads(arguments_json)
        if not isinstance(arguments, dict):
            raise ValueError("arguments_json must decode to an object")
    except (json.JSONDecodeError, ValueError) as exc:
        raise typer.BadParameter(str(exc), param_hint="arguments_json") from exc
    svc = _services(config)
    try:
        result = svc.tools.execute(
            tool_name=tool_name,
            action=action,
            arguments=arguments,
            approval_id=approval_id,
        )
        _print_json({"status": "executed", "result": result})
    except ApprovalRequired as exc:
        _print_json(
            {
                "status": "approval_required",
                "approval_id": exc.approval_id,
                "tool": exc.tool,
                "action": exc.action,
                "arguments": exc.arguments,
            }
        )
        raise typer.Exit(code=2)
    except AtlasError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1)


@app.command()
def approve(
    approval_id: str,
    reject: bool = typer.Option(False, help="Reject instead of approve."),
    note: str | None = typer.Option(None),
    resume_run: bool = typer.Option(True, "--resume/--no-resume"),
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Approve or reject a pending action and optionally resume its run."""
    svc = _services(config)
    decision = "rejected" if reject else "approved"
    approval = svc.tools.decide_approval(approval_id, decision, note)
    _print_json(approval)
    if resume_run and approval.get("run_id"):
        result = _run(svc.runtime.resume(str(approval["run_id"])))
        _print_chat_result(result)


@app.command()
def approvals(
    status: str | None = typer.Option(None),
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """List tool approvals."""
    _print_json(_services(config).database.list_approvals(status=status))


@app.command("import-file")
def import_file(
    path: Path = typer.Argument(..., exists=True, dir_okay=False),
    source: str = typer.Option(
        "auto", help="auto, chatgpt, atlas, memories, or generic"
    ),
    project: str | None = typer.Option(
        None, help="Assign imported conversations to this project slug."
    ),
    dry_run: bool = typer.Option(False),
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Import ChatGPT conversations or explicit memory files."""
    _print_json(
        _services(config).imports.import_path(
            path, source=source, project_slug=project, dry_run=dry_run
        )
    )


@app.command()
def backup(
    destination: Path | None = typer.Argument(None),
    workspace: bool = typer.Option(True, "--workspace/--no-workspace"),
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Create a portable Atlas backup ZIP without API secrets."""
    path = _services(config).backups.create_backup(destination, include_workspace=workspace)
    typer.echo(path)


def _backup_json_file(path: Path) -> dict[str, Any]:
    # The backup commands do not load runtime services, models or owner data.
    from atlas_core.recovery_snapshots import _decode_json, _read_path, SnapshotError

    value = _decode_json(_read_path(path, 64 * 1024))
    if not isinstance(value, dict):
        raise SnapshotError("Backup input must be a JSON object")
    return value


@app.command("backup-maintain")
def backup_maintain(plan: Path = typer.Argument(...)) -> None:
    """Create or resume an explicitly selected recovery snapshot without a model.

    The standalone command leaves cloud transfer pending until Atlas has its own
    qualified Drive connection. It never borrows another app's credentials.
    """
    from atlas_core.backup_maintenance import run_once

    try:
        result = run_once(_backup_json_file(plan))
    except (ValueError, OSError):
        _print_json({"status": "failed", "reason": "backup_input_or_storage_error"})
        raise typer.Exit(1)
    _print_json(result)
    if result.get("status") == "drive_connection_required":
        raise typer.Exit(3)
    if result.get("status") != "verified":
        raise typer.Exit(1)


@app.command("backup-verify")
def backup_verify(
    archive: Path = typer.Argument(...),
    receipt: Path = typer.Argument(...),
) -> None:
    """Check archive bytes and every selected file without extracting or running it."""
    from atlas_core.recovery_snapshots import verify_snapshot

    try:
        manifest = verify_snapshot(archive, _backup_json_file(receipt))
    except (ValueError, OSError):
        _print_json({"status": "failed", "reason": "backup_verification_failed"})
        raise typer.Exit(1)
    _print_json({"status": "verified", "snapshot_id": manifest["snapshot_id"],
                 "files": len(manifest["files"]), "source_bytes": manifest["source_bytes"]})


@app.command("backup-daily")
def backup_daily(
    plan: Path = typer.Argument(...),
    drive_profile: Path | None = typer.Option(None),
) -> None:
    """Run the due 3 AM backup or catch up, using Atlas's own connection if bound."""
    from atlas_core.backup_schedule import run_daily
    from atlas_core.errors import ConnectorError

    transport = None
    try:
        selected = _backup_json_file(plan)
        result = run_daily(selected)
        # No credential lookup occurs when an owner has not created a profile.
        if drive_profile is not None and drive_profile.exists():
            from atlas_core.backup_drive_connection import build_drive_backup_transport
            try:
                transport = build_drive_backup_transport(drive_profile)
            except ConnectorError:
                result["cloud"] = {"status": "authorization_unavailable"}
                result["status"] = "drive_connection_required"
            else:
                result = run_daily(selected, transport=transport)
    except (ValueError, OSError, ConnectorError):
        _print_json({"status": "failed", "reason": "scheduled_backup_failed"})
        raise typer.Exit(1)
    finally:
        if transport is not None:
            transport.close()
    _print_json(result)
    if result.get("status") in {"drive_connection_required", "cloud_pending"}:
        raise typer.Exit(3)
    if result.get("status") != "verified":
        raise typer.Exit(1)


@app.command("backup-connect")
def backup_connect(
    account: str = typer.Option(..., help="Your Google account; never a password or key."),
    folder_id: str = typer.Option(...),
    profile: Path = typer.Option(...),
    state_dir: Path = typer.Option(...),
    client_json: Path | None = typer.Option(None),
    reuse_existing_client: bool = typer.Option(False),
) -> None:
    """Open one-time Google consent for Atlas's separate, folder-bound backups."""
    from atlas_core.backup_drive_connection import connect_drive_backup
    from atlas_core.errors import ConnectorError

    typer.echo("Atlas will request Drive file access for the selected backup folder. "
               "Backup credentials stay in a separate local Keychain record.")
    try:
        result = connect_drive_backup(expected_account=account, folder_id=folder_id,
            profile_path=profile, state_dir=state_dir, client_json=client_json,
            reuse_existing_client=reuse_existing_client)
    except ConnectorError as exc:
        typer.echo("Atlas backup connection did not complete: " + str(exc).splitlines()[0][:300], err=True)
        raise typer.Exit(1)
    except (ValueError, OSError):
        typer.echo("Atlas backup connection did not complete because a selected local input is unavailable or invalid.", err=True)
        raise typer.Exit(1)
    _print_json({"connected": True, "folder_id": result["folder_id"]})


@app.command("backup-restore")
def backup_restore(
    archive: Path = typer.Argument(...),
    receipt: Path = typer.Argument(...),
    destination: Path = typer.Argument(...),
) -> None:
    """Restore selected files into a new directory, preserving existing files."""
    from atlas_core.recovery_snapshots import restore_snapshot

    try:
        result = restore_snapshot(archive, _backup_json_file(receipt), destination)
    except (ValueError, OSError):
        _print_json({"status": "failed", "reason": "backup_restore_failed"})
        raise typer.Exit(1)
    _print_json(result)


@app.command("supervisor-status")
def supervisor_status(
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Inspect the manual Supervisor, its stop control, and its latest task."""
    _print_json(_services(config).supervisor.status())


@app.command("supervisor-plan")
def supervisor_plan(
    project: str = typer.Argument(..., help="Owner-registered project slug."),
    action: str = typer.Option(
        "status", help="status or run_check; no other actions are supported."
    ),
    check: str | None = typer.Option(
        None, help="Fixed registered check name for run_check."
    ),
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Create a persistent dry-run task without executing it."""
    _print_json(
        _services(config).supervisor.plan(
            project_slug=project, action=action, check_name=check
        )
    )


@app.command("supervisor-tasks")
def supervisor_tasks(
    status: str | None = typer.Option(None, help="Optional task status filter."),
    limit: int = typer.Option(100, min=1, max=5_000),
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """List persistent Supervisor task receipts."""
    _print_json(_services(config).supervisor.list_tasks(status=status, limit=limit))


@app.command("supervisor-run")
def supervisor_run(
    task_id: str = typer.Argument(...),
    confirm: str = typer.Option(..., "--confirm", help="Must be exactly RUN."),
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Run one planned task once after exact operator confirmation."""
    _print_json(
        _services(config).supervisor.run_task(task_id, confirmation=confirm)
    )


@app.command("supervisor-cancel")
def supervisor_cancel(
    task_id: str = typer.Argument(...),
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Cancel a task that has not started."""
    _print_json(_services(config).supervisor.cancel_task(task_id))


@app.command("supervisor-pause")
def supervisor_pause(
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Set the out-of-band Supervisor stop control."""
    _print_json(_services(config).supervisor.pause())


@app.command("supervisor-resume")
def supervisor_resume(
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Clear the Supervisor stop control."""
    _print_json(_services(config).supervisor.resume())


@app.command("supervisor-recover")
def supervisor_recover(
    task_id: str = typer.Argument(...),
    confirm: str = typer.Option(..., "--confirm", help="Must be exactly RECOVER."),
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Mark a stale running receipt interrupted while the Supervisor is paused."""
    _print_json(
        _services(config).supervisor.recover_task(
            task_id, confirmation=confirm
        )
    )


@app.command("supervisor-v2-status")
def supervisor_v2_status(
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Inspect the one-shot disposable-fixture Supervisor v2 gate."""
    _print_json(_services(config).supervisor_v2.status())


@app.command("supervisor-v2-readiness")
def supervisor_v2_readiness(
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Verify the protocol pin and permission profile without a model run."""
    _print_json(_services(config).supervisor_v2.readiness())


@app.command("supervisor-v2-plan")
def supervisor_v2_plan(
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Create a fresh bound plan for the one fixed fixture recipe."""
    _print_json(
        _services(config).supervisor_v2.plan(
            recipe_slug="fixture-small-bugfix"
        )
    )


@app.command("supervisor-v2-tasks")
def supervisor_v2_tasks(
    status: str | None = typer.Option(None, help="Optional task status filter."),
    limit: int = typer.Option(100, min=1, max=5_000),
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """List privacy-minimized Supervisor v2 task receipts."""
    _print_json(
        _services(config).supervisor_v2.list_tasks(status=status, limit=limit)
    )


@app.command("supervisor-v2-cancel")
def supervisor_v2_cancel(
    task_id: str = typer.Argument(...),
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Cancel a fixture plan that has not started."""
    _print_json(_services(config).supervisor_v2.cancel_task(task_id))


@app.command("supervisor-v2-run")
def supervisor_v2_run(
    task_id: str = typer.Argument(...),
    confirm: str = typer.Option(
        ...,
        "--confirm",
        help="Exact task-and-plan-bound APPLY confirmation from the fresh plan.",
    ),
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Run the single owner-confirmed disposable-fixture candidate attempt."""
    _print_json(
        _services(config).supervisor_v2.run_task(
            task_id,
            confirmation=confirm,
        )
    )


@app.command("supervisor-v3-status")
def supervisor_v3_status(
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Inspect the separately gated Supervisor v3 SDK pilot."""
    _print_json(_services(config).supervisor_v3.status())


@app.command("supervisor-v3-readiness")
def supervisor_v3_readiness(
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Verify all v3 offline pins and controls without contacting a model."""
    _print_json(_services(config).supervisor_v3.readiness())


@app.command("supervisor-v3-plan-canary")
def supervisor_v3_plan_canary(
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Create a canary plan only after its separate live gate is enabled."""
    _print_json(_services(config).supervisor_v3.plan_canary())


@app.command("supervisor-v3-plan-fixture")
def supervisor_v3_plan_fixture(
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Create a fixture plan only after a passed canary and owner gate."""
    _print_json(_services(config).supervisor_v3.plan_fixture())


@app.command("supervisor-v3-plan-successor-canary")
def supervisor_v3_plan_successor_canary(
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Create the predecessor-bound successor plan without contacting a model."""
    _print_json(_services(config).supervisor_v3.plan_successor_canary())


@app.command("supervisor-v3-plan-recovery-canary")
def supervisor_v3_plan_recovery_canary(
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Plan the failed-fixture-bound recovery canary after owner authorization."""
    _print_json(_services(config).supervisor_v3.plan_recovery_canary())


@app.command("supervisor-v3-plan-recovery-fixture")
def supervisor_v3_plan_recovery_fixture(
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Plan one recovery fixture after its canary and separate owner gate."""
    _print_json(_services(config).supervisor_v3.plan_recovery_fixture())


@app.command("supervisor-v3-tasks")
def supervisor_v3_tasks(
    status: str | None = typer.Option(None, help="Optional task status filter."),
    stage: str | None = typer.Option(
        None,
        help=(
            "Optional canary, successor_canary, fixture, recovery_canary, "
            "or recovery_fixture stage."
        ),
    ),
    limit: int = typer.Option(100, min=1, max=5_000),
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """List privacy-minimized Supervisor v3 receipts."""
    _print_json(
        _services(config).supervisor_v3.list_tasks(
            status=status, stage=stage, limit=limit
        )
    )


@app.command("supervisor-v3-cancel")
def supervisor_v3_cancel(
    task_id: str = typer.Argument(...),
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Cancel an unclaimed v3 plan."""
    _print_json(_services(config).supervisor_v3.cancel_task(task_id))


@app.command("supervisor-v3-run")
def supervisor_v3_run(
    task_id: str = typer.Argument(...),
    confirm: str = typer.Option(
        ...,
        "--confirm",
        help="Exact stage-specific confirmation from a fresh v3 plan.",
    ),
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Run one claimed v3 stage after its separate live authorization."""
    _print_json(
        _services(config).supervisor_v3.run_task(
            task_id,
            confirmation=confirm,
        )
    )


@app.command("supervisor-v4-status")
def supervisor_v4_status(
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Inspect the inactive Supervisor v4 proposal-only implementation."""

    _print_json(_services(config).supervisor_v4.status())


@app.command("supervisor-v4-readiness")
def supervisor_v4_readiness(
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Run the no-model v4 replay and runtime qualification."""

    _print_json(_services(config).supervisor_v4.readiness())


@app.command("supervisor-v4-option1-canary")
def supervisor_v4_option1_canary(
    confirm: str = typer.Option(..., "--confirm"),
) -> None:
    """Run the separately authorized one-shot synthetic Option 1 canary."""

    # Validate before loading configuration, opening the Atlas database, or
    # constructing any service.  The service and child repeat this check.
    from atlas_core.supervisor_v4_option1_canary import CANARY_CONFIRMATION

    if not hmac.compare_digest(confirm, CANARY_CONFIRMATION):
        raise typer.BadParameter(
            "Exact owner confirmation is required",
            param_hint="--confirm",
        )
    _print_json(
        build_supervisor_v4_only().run_option1_synthetic_integration_canary(
            confirmation=confirm
        )
    )


@app.command("supervisor-v4-option1-recovery-canary")
def supervisor_v4_option1_recovery_canary(
    confirm: str = typer.Option(..., "--confirm"),
) -> None:
    """Run only the separately authorized, predecessor-bound recovery canary."""

    # Reject generic approval and the exhausted original phrase before loading
    # configuration, opening the database, or inspecting the runtime.
    from atlas_core.supervisor_v4_option1_recovery_canary import (
        RECOVERY_CANARY_CONFIRMATION,
    )

    if not hmac.compare_digest(confirm, RECOVERY_CANARY_CONFIRMATION):
        raise typer.BadParameter(
            "Exact recovery owner confirmation is required",
            param_hint="--confirm",
        )
    _print_json(
        build_supervisor_v4_only(
            isolated_environment=True
        ).run_option1_synthetic_integration_recovery_canary(
            confirmation=confirm
        )
    )


@app.command("supervisor-v4-acknowledge-option1-recovery-result")
def supervisor_v4_acknowledge_option1_recovery_result() -> None:
    """Record one non-authorizing review of the exhausted synthetic result."""

    _print_json(
        build_supervisor_v4_review_only().record_option1_recovery_canary_result_review()
    )


@app.command("supervisor-v4-option2-plan-review")
def supervisor_v4_option2_plan_review() -> None:
    """Validate the inactive Option 2 design without provisioning anything."""

    _print_json(
        build_supervisor_v4_review_only().review_option2_service_identity_and_vault_offline_plan()
    )


@app.command("supervisor-v4-acknowledge-option2-plan")
def supervisor_v4_acknowledge_option2_plan() -> None:
    """Record one non-authorizing review of the inactive Option 2 plan."""

    _print_json(
        build_supervisor_v4_review_only().record_option2_service_identity_and_vault_plan_review()
    )


@app.command("supervisor-v4-qualify-option2-provisioner")
def supervisor_v4_qualify_option2_provisioner() -> None:
    """Record the pure in-memory provisioner fixture qualification."""

    _print_json(
        build_supervisor_v4_review_only().record_option2_provisioner_fixture_qualification()
    )


@app.command("supervisor-v4-acknowledge-option2-provisioning-manifest")
def supervisor_v4_acknowledge_option2_provisioning_manifest() -> None:
    """Record review of the incomplete inactive Option 2 manifest."""

    _print_json(
        build_supervisor_v4_review_only()
        .record_option2_service_identity_provisioning_manifest_review()
    )


@app.command("supervisor-v4-qualify-option2-identity-candidate")
def supervisor_v4_qualify_option2_identity_candidate() -> None:
    """Record the pure synthetic identity-candidate fixture qualification."""

    _print_json(
        build_supervisor_v4_review_only()
        .record_option2_identity_candidate_fixture_qualification()
    )


@app.command("supervisor-v4-option2-identity-host-preflight")
def supervisor_v4_option2_identity_host_preflight() -> None:
    """Reject the retired legacy host-query entry point."""

    raise typer.BadParameter(
        "Legacy Option 2 host preflight is retired; no host query was performed",
        param_hint="command",
    )


@app.command("supervisor-v4-option2-identity-host-preflight-recovery")
def supervisor_v4_option2_identity_host_preflight_recovery(
    confirm: str = typer.Option(..., "--confirm"),
) -> None:
    """Reject the retired legacy recovery host-query entry point."""

    del confirm
    raise typer.BadParameter(
        "Legacy Option 2 recovery preflight is retired; no host query was performed",
        param_hint="command",
    )


@app.command(
    "supervisor-v4-acknowledge-option2-host-preflight-recovery-result"
)
def supervisor_v4_acknowledge_option2_host_preflight_recovery_result() -> None:
    """Record the expired recovery result without another host query."""

    _print_json(
        build_supervisor_v4_review_only()
        .record_option2_host_preflight_recovery_result_review()
    )


@app.command("supervisor-v4-qualify-option2-point-action")
def supervisor_v4_qualify_option2_point_action() -> None:
    """Record the pure offline point-of-action design qualification."""

    _print_json(
        build_supervisor_v4_review_only()
        .record_option2_point_action_fixture_qualification()
    )


@app.command("supervisor-v4-qualify-option2-native-preflight")
def supervisor_v4_qualify_option2_native_preflight() -> None:
    """Record the sealed offline native fixture qualification."""

    _print_json(
        build_supervisor_v4_review_only()
        .record_option2_native_preflight_fixture_qualification()
    )


@app.command()
def audit(
    limit: int = typer.Option(100, min=1, max=5_000),
    event_type: str | None = typer.Option(None),
    outcome: str | None = typer.Option(None),
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
) -> None:
    """Inspect the local audit trail."""
    _print_json(
        _services(config).database.list_audit(
            limit=limit, event_type=event_type, outcome=outcome
        )
    )


@app.command()
def serve(
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
    host: str = typer.Option("127.0.0.1"),
    port: int = typer.Option(8742, min=1, max=65535),
    reload: bool = typer.Option(False),
) -> None:
    """Run the Atlas local API and browser application."""
    _check_bind_security(config, host)
    if reload:
        os.environ["ATLAS_CONFIG"] = str(config.expanduser().resolve())
        uvicorn.run("atlas_core.api:app", host=host, port=port, reload=True)
    else:
        uvicorn.run(create_app(config), host=host, port=port)


@app.command()
def start(
    config: Path = typer.Option(DEFAULT_CONFIG, exists=True, dir_okay=False),
    host: str = typer.Option("127.0.0.1"),
    port: int = typer.Option(8742, min=1, max=65535),
    no_browser: bool = typer.Option(False, help="Do not open the local browser window."),
    mock: bool = typer.Option(False, help="Use the offline diagnostic model for this launch."),
) -> None:
    """Launch Atlas and open its private local chat interface."""
    if mock:
        os.environ["ATLAS_DEFAULT_PROVIDER"] = "mock"
    _check_bind_security(config, host)
    url = f"http://{host}:{port}"
    if not no_browser:
        timer = threading.Timer(1.0, lambda: webbrowser.open(url))
        timer.daemon = True
        timer.start()
    typer.echo(f"Atlas Core is opening at {url}")
    typer.echo("Press Ctrl+C in this terminal to stop the local service.")
    uvicorn.run(create_app(config), host=host, port=port)


if __name__ == "__main__":
    app()
