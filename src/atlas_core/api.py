from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import secrets
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any, AsyncIterator, Awaitable, Callable, Literal
from urllib.parse import urlsplit

import httpx
import anyio
from pydantic import Field
from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    Header,
    HTTPException,
    Query,
    Request,
    UploadFile,
    status,
)
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from atlas_core import __version__
from atlas_core.errors import (
    ApprovalError,
    ApprovalRequired,
    AtlasError,
    ConnectorError,
    ImportFormatError,
    PermissionDenied,
    ProviderError,
    RunStateError,
    SupervisorError,
    ToolError,
)
from atlas_core.schemas import (
    ApprovalDecisionRequest,
    BackupRequest,
    ChatRequest,
    ChatResponse,
    ConversationCreate,
    ConversationPatch,
    IdentityUpdate,
    MemoryCreate,
    PermissionUpdate,
    ProjectUpsert,
    StrictModel,
    SupervisorPlanRequest,
    SupervisorRecoverRequest,
    SupervisorRunRequest,
    SupervisorV2PlanRequest,
    SupervisorV2RunRequest,
    SupervisorV3RunRequest,
    ToolExecuteRequest,
)
from atlas_core.services import AtlasServices, build_services


class ObjectiveSubmission(StrictModel):
    request_id: Annotated[str, Field(strict=True, min_length=36, max_length=36)]
    conversation_id: Annotated[str, Field(strict=True, min_length=36, max_length=36)]
    run_id: Annotated[str, Field(strict=True, min_length=36, max_length=36)]
    project: Annotated[str, Field(strict=True, min_length=1, max_length=80)]
    objective: Annotated[str, Field(strict=True, min_length=1, max_length=1000)]


class ObjectiveCancellation(StrictModel):
    expected_sha256: Annotated[str, Field(strict=True, pattern=r"^[0-9a-f]{64}$")]


class DevelopmentResumeRequest(StrictModel):
    confirmation: Literal["Resume Atlas development"]
    expected_epoch: Annotated[int, Field(strict=True, ge=0)]


EventOperation = Callable[[Callable[[dict[str, Any]], Awaitable[None]]], Awaitable[dict[str, Any]]]


def _is_loopback_authority(authority: str) -> bool:
    """Return whether an HTTP Host authority names this loopback installation."""

    if not authority:
        return False
    try:
        parsed = urlsplit(f"//{authority}")
        hostname = parsed.hostname
    except ValueError:
        return False
    if (
        not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
    ):
        return False
    normalized = hostname.rstrip(".").lower()
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def create_app(config_path: str | Path = "config/atlas.yaml", *, coding_owner_factory=None, model_admission_factory=None,
               work_startup_selection=None, objective_activation_factory=None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.services = build_services(config_path)
        app.state.work_startup_error = None
        app.state.objective_activation = None
        app.state.objective_activation_error = None
        if objective_activation_factory is not None:
            try:
                from atlas_core.objective_activation import ObjectiveActivation
                import inspect
                if not callable(objective_activation_factory):
                    raise ValueError("trusted_activation_factory_required")
                activation = objective_activation_factory(app.state.services.database)
                if inspect.isawaitable(activation):
                    if inspect.iscoroutine(activation):
                        activation.close()
                    raise ValueError("synchronous_activation_factory_required")
                if type(activation) is not ObjectiveActivation or activation.database is not app.state.services.database:
                    raise ValueError("exact_activation_binding_required")
                app.state.objective_activation = activation
            except Exception:
                # Optional activation cannot disable ordinary Chat or durable
                # request storage. Never fall back to a grant or another engine.
                app.state.objective_activation_error = "activation_unavailable"
        if work_startup_selection is not None:
            try:
                app.state.services.select_work_startup(work_startup_selection)
            except Exception:
                # Optional Work custody must not disable ordinary Chat/Practice.
                # No fallback grant, record creation, Resume or automatic retry.
                app.state.work_startup_error = "work_startup_unavailable"
        from atlas_core.models.host import selected_model_host
        async with selected_model_host(app.state.services, model_admission_factory) as model_host:
            app.state.model_admission_host = model_host
            heartbeat = app.state.services.heartbeat
            if heartbeat is not None:
                await heartbeat.start()
            svc = app.state.services
            if svc.config.practice.background_enabled:
                try:
                    from atlas_core.practice.improvement import AtlasImprovement
                    svc.improvement = AtlasImprovement(svc)
                    svc.runtime.improvement = svc.improvement
                    await svc.improvement.start()
                except Exception:
                    svc.improvement_error = "improvement_unavailable"
            app.state.coding_owner_error = None
            owner = None
            try:
                owner = app.state.services.initialize_coding_owner()
                if coding_owner_factory is not None:
                    from atlas_core.coding_owner import CodingOwnerRefused
                    if not callable(coding_owner_factory):
                        raise CodingOwnerRefused("trusted_factory_required")
                    # Explicit trusted Python callback only. No settings/JSON import
                    # and no automatic preparation or saved-admission recovery.
                    binding = coding_owner_factory(app.state.services.development.control)
                    import inspect
                    if inspect.isawaitable(binding):
                        if inspect.iscoroutine(binding):
                            binding.close()
                        raise CodingOwnerRefused("synchronous_factory_required")
                    if binding is not None:
                        await app.state.services.attach_prepared_coding_binding(binding)
            except Exception:
                # The optional coding connection cannot disable the ordinary app.
                app.state.coding_owner_error = "coding_owner_unavailable"
            try:
                yield
            finally:
                if model_host is not None:
                    model_host.stop()
                try:
                    app.state.coding_owner_cleanup_confirmed = True if owner is None else await owner.aclose()
                finally:
                    try:
                        if app.state.services.improvement is not None:
                            await app.state.services.improvement.close()
                    finally:
                        if heartbeat is not None:
                            await heartbeat.close()
        app.state.model_admission_cleanup_confirmed = model_host is None or model_host.cleanup_confirmed

    app = FastAPI(
        title="Atlas Core",
        version=__version__,
        description="Local-first personal AI with inspectable memory, portable agents, and owner-controlled approvals.",
        lifespan=lifespan,
    )
    ui_dir = Path(__file__).parent / "ui"
    if ui_dir.is_dir():
        app.mount("/static", StaticFiles(directory=ui_dir), name="static")

    def services(request: Request) -> AtlasServices:
        return request.app.state.services

    def authorize(
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
    ) -> None:
        configured = services(request).config.app.api_token
        if not configured:
            return
        expected = f"Bearer {configured}"
        if authorization is None or not secrets.compare_digest(authorization, expected):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing bearer token",
            )

    protected = Depends(authorize)

    @app.get("/v1/work/readiness", dependencies=[protected])
    async def work_readiness(request: Request) -> dict[str, Any]:
        from atlas_core.governance.work_startup import WorkStartup, IncrementWorkCodeStartup, unavailable
        from atlas_core.governance.work_first_install import FirstWorkCodeStartup
        selected = services(request).coding_work_startup
        if type(selected) in (WorkStartup, FirstWorkCodeStartup, IncrementWorkCodeStartup):
            return await asyncio.to_thread(selected.status)
        state = "unavailable" if request.app.state.work_startup_error else "not_configured"
        return unavailable(state)

    def objective_store(request: Request):
        # A development objective requires configured owner authentication even
        # where ordinary local Chat intentionally permits tokenless access.
        svc = services(request)
        if not svc.config.app.api_token:
            raise HTTPException(status_code=503, detail="Objective submission requires owner authentication")
        from atlas_core.objective_requests import ObjectiveRequests
        return ObjectiveRequests(svc.database)

    async def objective_operation(operation, *args, **kwargs):
        from atlas_core.objective_requests import ObjectiveRequestError
        try:
            return await asyncio.to_thread(operation, *args, **kwargs)
        except ObjectiveRequestError as error:
            code = 404 if str(error) == "request_not_found" else 409
            raise HTTPException(status_code=code, detail=str(error)) from None

    @app.post("/v1/work/objectives", dependencies=[protected])
    async def submit_objective(request: Request, body: ObjectiveSubmission):
        from atlas_core.objective_requests import ObjectiveRequest
        store = objective_store(request)
        if body.project not in services(request).config.development.projects:
            raise HTTPException(status_code=403, detail="Project is not configured for development")
        saved = await objective_operation(store.submit, ObjectiveRequest(**body.model_dump()))
        activation = request.app.state.objective_activation
        if activation is not None:
            try:
                notice = await asyncio.to_thread(activation.notify, saved["request_id"],
                                                expected_sha256=saved["request_sha256"])
            except Exception:
                # Persistence already succeeded. Unknown notification outcome
                # is not permission to retry or claim that execution succeeded.
                notice = {"state": "requires_reconciliation", "execution_authority": False,
                          "coding_success": False}
            return {**saved, "activation": notice}
        if request.app.state.objective_activation_error:
            return {**saved, "activation": {"state": "unavailable", "execution_authority": False,
                                            "coding_success": False}}
        return saved

    @app.get("/v1/work/objectives/{request_id}", dependencies=[protected])
    async def objective_status(request: Request, request_id: str):
        return await objective_operation(objective_store(request).get, request_id)

    @app.post("/v1/work/objectives/{request_id}/cancel", dependencies=[protected])
    async def cancel_objective(request: Request, request_id: str, body: ObjectiveCancellation):
        return await objective_operation(objective_store(request).cancel, request_id,
                                         expected_sha256=body.expected_sha256)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        # Localhost services are still reachable by a browser visiting a malicious
        # website. Reject cross-site/mismatched origins and require an actual
        # loopback Host for browser-shaped requests when bearer auth is disabled.
        response: Response
        if request.url.path.startswith("/v1/"):
            fetch_site = (request.headers.get("sec-fetch-site") or "").lower()
            origin = request.headers.get("origin")
            request_authority = (request.headers.get("host") or "").lower()
            browser_shaped = bool(
                fetch_site
                or origin
                or request.headers.get("sec-fetch-mode")
                or request.headers.get("sec-fetch-dest")
            )
            rejection_error: str | None = None
            if fetch_site == "cross-site":
                rejection_error = "cross_site_request_blocked"
            if origin:
                parsed = urlsplit(origin)
                origin_authority = parsed.netloc.lower()
                if not origin_authority or origin_authority != request_authority:
                    rejection_error = "cross_site_request_blocked"
            if (
                rejection_error is None
                and browser_shaped
                and not services(request).config.app.api_token
                and not _is_loopback_authority(request_authority)
            ):
                rejection_error = "untrusted_host"
            if rejection_error:
                response = JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={
                        "error": rejection_error,
                        "detail": "Atlas API requests must originate from this Atlas installation.",
                    },
                )
            else:
                response = await call_next(request)
        else:
            response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
            "base-uri 'none'; form-action 'self'",
        )
        return response

    @app.exception_handler(PermissionDenied)
    async def permission_denied_handler(
        request: Request, exc: PermissionDenied
    ) -> JSONResponse:
        del request
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error": "permission_denied", "detail": str(exc)},
        )

    @app.exception_handler(ProviderError)
    async def provider_error_handler(request: Request, exc: ProviderError) -> JSONResponse:
        del request
        return JSONResponse(
            status_code=status.HTTP_502_BAD_GATEWAY,
            content={"error": "provider_error", "detail": str(exc)},
        )

    async def atlas_error_handler(request: Request, exc: Exception) -> JSONResponse:
        del request
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": exc.__class__.__name__, "detail": str(exc)},
        )

    for error_type in (
        ApprovalError,
        RunStateError,
        ToolError,
        ImportFormatError,
        ConnectorError,
        SupervisorError,
        ValueError,
    ):
        app.add_exception_handler(error_type, atlas_error_handler)

    @app.exception_handler(KeyError)
    async def key_error_handler(request: Request, exc: KeyError) -> JSONResponse:
        del request
        detail = exc.args[0] if exc.args else str(exc)
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"error": "not_found", "detail": str(detail)},
        )

    @app.get("/", include_in_schema=False)
    async def root() -> Response:
        index = ui_dir / "index.html"
        if index.is_file():
            return FileResponse(index)
        return JSONResponse({"name": "Atlas Core", "version": __version__})

    @app.get("/health")
    async def health(request: Request) -> dict[str, Any]:
        svc = services(request)
        return {
            "ok": True,
            "version": __version__,
            "identity_fingerprint": svc.identity.fingerprint(),
            "chat_request_receipts": True,
            "default_provider": svc.config.routing.default_provider,
            "default_agent": svc.agents.default_agent,
            "api_token_required": bool(svc.config.app.api_token),
            "constitution": svc.constitution.status() if svc.constitution is not None else {"installed": False},
            "heartbeat": svc.heartbeat.status() if svc.heartbeat is not None else {"running": False},
        }

    @app.get("/v1/improvement", dependencies=[protected])
    async def improvement_status(request: Request) -> dict[str, Any]:
        svc = services(request)
        return svc.improvement.status() if svc.improvement is not None else {
            "enabled": False, "state": "unavailable" if svc.improvement_error else "disabled",
            "reason": svc.improvement_error}

    @app.post("/v1/improvement/{action}", dependencies=[protected])
    async def improvement_control(action: str, request: Request) -> dict[str, Any]:
        svc = services(request)
        if svc.improvement is None or action not in {"pause", "resume"}:
            raise HTTPException(status_code=409, detail="Background control unavailable")
        return await svc.improvement.set_paused(action == "pause")

    @app.get("/v1/settings", dependencies=[protected])
    async def settings(request: Request) -> dict[str, Any]:
        svc = services(request)
        return {
            "version": __version__,
            "project_root": str(svc.config.project_root),
            "database": str(svc.config.database_path),
            "workspace": str(svc.config.app.workspace_dir),
            "identity": str(svc.config.app.identity_dir),
            "permissions_file": str(svc.config.app.permissions_file),
            "agents_file": str(svc.config.app.agents_file),
            "default_provider": svc.config.routing.default_provider,
            "default_agent": svc.agents.default_agent,
            "default_local_only": True,
            "api_token_required": bool(svc.config.app.api_token),
            "mac_inbox": (
                svc.mac_inbox.status({})
                if svc.mac_inbox is not None
                else {"enabled": False, "paused": False, "ready": False}
            ),
            "phone_companion": (
                svc.phone_companion.status({})
                if svc.phone_companion is not None
                else {
                    "enabled": False,
                    "paused": False,
                    "ready": False,
                    "bridge_active": False,
                    "device_connected": False,
                }
            ),
            "supervisor": svc.supervisor.status(),
            "supervisor_v2": svc.supervisor_v2.status(),
            "supervisor_v3": svc.supervisor_v3.status(),
            "supervisor_v4": svc.supervisor_v4.status(),
            "stats": svc.database.stats(),
        }

    @app.get("/v1/supervisor-v2", dependencies=[protected])
    async def supervisor_v2_status(request: Request) -> dict[str, Any]:
        return services(request).supervisor_v2.status()

    @app.post("/v1/supervisor-v2/readiness", dependencies=[protected])
    async def supervisor_v2_readiness(request: Request) -> dict[str, Any]:
        # Regenerates local stable schemas only. It does not start App Server or
        # consume model usage.
        return await asyncio.to_thread(services(request).supervisor_v2.readiness)

    @app.post("/v1/supervisor-v2/plan", dependencies=[protected])
    async def supervisor_v2_plan(
        request: Request, payload: SupervisorV2PlanRequest
    ) -> dict[str, Any]:
        return await asyncio.to_thread(
            services(request).supervisor_v2.plan,
            recipe_slug=payload.recipe,
        )

    @app.get("/v1/supervisor-v2/tasks", dependencies=[protected])
    async def supervisor_v2_tasks(
        request: Request,
        task_status: str | None = None,
        limit: Annotated[int, Query(ge=1, le=5_000)] = 100,
    ) -> list[dict[str, Any]]:
        return services(request).supervisor_v2.list_tasks(
            status=task_status, limit=limit
        )

    @app.get("/v1/supervisor-v2/tasks/{task_id}", dependencies=[protected])
    async def supervisor_v2_task(request: Request, task_id: str) -> dict[str, Any]:
        return services(request).supervisor_v2.get_task(task_id)

    @app.post("/v1/supervisor-v2/tasks/{task_id}/cancel", dependencies=[protected])
    async def supervisor_v2_cancel(request: Request, task_id: str) -> dict[str, Any]:
        return services(request).supervisor_v2.cancel_task(task_id)

    @app.post("/v1/supervisor-v2/tasks/{task_id}/run", dependencies=[protected])
    async def supervisor_v2_run(
        request: Request,
        task_id: str,
        payload: SupervisorV2RunRequest,
    ) -> dict[str, Any]:
        # Synchronous and one-shot by design. The request returns only after the
        # model turn and independent candidate validation reach a terminal state.
        return await asyncio.to_thread(
            services(request).supervisor_v2.run_task,
            task_id,
            confirmation=payload.confirmation,
        )

    @app.get("/v1/supervisor-v3", dependencies=[protected])
    async def supervisor_v3_status(request: Request) -> dict[str, Any]:
        return services(request).supervisor_v3.status()

    @app.post("/v1/supervisor-v3/readiness", dependencies=[protected])
    async def supervisor_v3_readiness(request: Request) -> dict[str, Any]:
        # Package, runtime, schemas, sandbox profiles, and fake-driver controls
        # only. This route never starts App Server and never contacts a model.
        return await asyncio.to_thread(services(request).supervisor_v3.readiness)

    @app.post("/v1/supervisor-v3/plan/canary", dependencies=[protected])
    async def supervisor_v3_plan_canary(request: Request) -> dict[str, Any]:
        return await asyncio.to_thread(services(request).supervisor_v3.plan_canary)

    @app.post("/v1/supervisor-v3/plan/successor-canary", dependencies=[protected])
    async def supervisor_v3_plan_successor_canary(request: Request) -> dict[str, Any]:
        return await asyncio.to_thread(
            services(request).supervisor_v3.plan_successor_canary
        )

    @app.post("/v1/supervisor-v3/plan/fixture", dependencies=[protected])
    async def supervisor_v3_plan_fixture(request: Request) -> dict[str, Any]:
        return await asyncio.to_thread(services(request).supervisor_v3.plan_fixture)

    @app.post("/v1/supervisor-v3/plan/recovery-canary", dependencies=[protected])
    async def supervisor_v3_plan_recovery_canary(request: Request) -> dict[str, Any]:
        return await asyncio.to_thread(
            services(request).supervisor_v3.plan_recovery_canary
        )

    @app.post("/v1/supervisor-v3/plan/recovery-fixture", dependencies=[protected])
    async def supervisor_v3_plan_recovery_fixture(request: Request) -> dict[str, Any]:
        return await asyncio.to_thread(
            services(request).supervisor_v3.plan_recovery_fixture
        )

    @app.get("/v1/supervisor-v3/tasks", dependencies=[protected])
    async def supervisor_v3_tasks(
        request: Request,
        task_status: str | None = None,
        stage: str | None = None,
        limit: Annotated[int, Query(ge=1, le=5_000)] = 100,
    ) -> list[dict[str, Any]]:
        return services(request).supervisor_v3.list_tasks(
            status=task_status, stage=stage, limit=limit
        )

    @app.get("/v1/supervisor-v3/tasks/{task_id}", dependencies=[protected])
    async def supervisor_v3_task(request: Request, task_id: str) -> dict[str, Any]:
        return services(request).supervisor_v3.get_task(task_id)

    @app.post("/v1/supervisor-v3/tasks/{task_id}/cancel", dependencies=[protected])
    async def supervisor_v3_cancel(request: Request, task_id: str) -> dict[str, Any]:
        return services(request).supervisor_v3.cancel_task(task_id)

    @app.post("/v1/supervisor-v3/tasks/{task_id}/run", dependencies=[protected])
    async def supervisor_v3_run(
        request: Request,
        task_id: str,
        payload: SupervisorV3RunRequest,
    ) -> dict[str, Any]:
        return await asyncio.to_thread(
            services(request).supervisor_v3.run_task,
            task_id,
            confirmation=payload.confirmation,
        )

    @app.get("/v1/supervisor-v4", dependencies=[protected])
    async def supervisor_v4_status(request: Request) -> dict[str, Any]:
        """Report the inactive v4 implementation; no plan or run route exists."""

        return services(request).supervisor_v4.status()

    def development_control(request: Request, project: str):
        development = services(request).development
        if not isinstance(project, str) or not project:
            raise ToolError("A registered development project is required")
        registered = development.projects.get(project)
        if registered is None or not registered.self_development:
            raise HTTPException(status_code=404, detail="Development control is unavailable for this project")
        return development.control

    @app.get("/v1/development-control", dependencies=[protected])
    async def development_control_status(request: Request, project: str) -> dict[str, Any]:
        registered = services(request).development.projects.get(project)
        if registered is None or not registered.self_development:
            return {"project": project, "available": False, "stopped": True}
        return await asyncio.to_thread(development_control(request, project).status, project)

    @app.post("/v1/development-control/stop", dependencies=[protected])
    async def development_control_stop(request: Request, project: str) -> dict[str, Any]:
        return await asyncio.to_thread(development_control(request, project).stop, project)

    @app.post("/v1/development-control/resume", dependencies=[protected])
    async def development_control_resume(
        request: Request, payload: DevelopmentResumeRequest, project: str
    ) -> dict[str, Any]:
        return await asyncio.to_thread(
            development_control(request, project).resume,
            project,
            expected_epoch=payload.expected_epoch,
        )

    @app.get("/v1/supervisor", dependencies=[protected])
    async def supervisor_status(request: Request) -> dict[str, Any]:
        return services(request).supervisor.status()

    @app.post("/v1/supervisor/plan", dependencies=[protected])
    async def supervisor_plan(
        request: Request, payload: SupervisorPlanRequest
    ) -> dict[str, Any]:
        return services(request).supervisor.plan(
            project_slug=payload.project,
            action=payload.action,
            check_name=payload.check,
        )

    @app.get("/v1/supervisor/tasks", dependencies=[protected])
    async def supervisor_tasks(
        request: Request,
        task_status: str | None = None,
        limit: Annotated[int, Query(ge=1, le=5_000)] = 100,
    ) -> list[dict[str, Any]]:
        return services(request).supervisor.list_tasks(
            status=task_status, limit=limit
        )

    @app.post("/v1/supervisor/pause", dependencies=[protected])
    async def supervisor_pause(request: Request) -> dict[str, Any]:
        return services(request).supervisor.pause()

    @app.post("/v1/supervisor/resume", dependencies=[protected])
    async def supervisor_resume(request: Request) -> dict[str, Any]:
        return services(request).supervisor.resume()

    @app.get("/v1/supervisor/tasks/{task_id}", dependencies=[protected])
    async def supervisor_task(request: Request, task_id: str) -> dict[str, Any]:
        return services(request).supervisor.get_task(task_id)

    @app.post("/v1/supervisor/tasks/{task_id}/run", dependencies=[protected])
    async def supervisor_run(
        request: Request, task_id: str, payload: SupervisorRunRequest
    ) -> dict[str, Any]:
        supervisor = services(request).supervisor
        return await asyncio.to_thread(
            supervisor.run_task,
            task_id,
            confirmation=payload.confirmation,
        )

    @app.post("/v1/supervisor/tasks/{task_id}/cancel", dependencies=[protected])
    async def supervisor_cancel(request: Request, task_id: str) -> dict[str, Any]:
        return services(request).supervisor.cancel_task(task_id)

    @app.post("/v1/supervisor/tasks/{task_id}/recover", dependencies=[protected])
    async def supervisor_recover(
        request: Request, task_id: str, payload: SupervisorRecoverRequest
    ) -> dict[str, Any]:
        return services(request).supervisor.recover_task(
            task_id, confirmation=payload.confirmation
        )

    @app.get("/v1/identity", dependencies=[protected])
    async def get_identity(request: Request) -> dict[str, Any]:
        identity = services(request).identity
        return {
            "fingerprint": identity.fingerprint(),
            "documents": identity.documents(),
        }

    @app.put("/v1/identity/{name}", dependencies=[protected])
    async def update_identity(
        request: Request, name: str, payload: IdentityUpdate
    ) -> dict[str, Any]:
        svc = services(request)
        document = svc.identity.update(name, payload.content)
        svc.database.audit(
            event_type="identity",
            actor="operator",
            action="identity.update",
            resource=name,
            outcome="success",
            details={"fingerprint": svc.identity.fingerprint()},
        )
        return {"document": document, "fingerprint": svc.identity.fingerprint()}

    @app.get("/v1/permissions", dependencies=[protected])
    async def get_permissions(request: Request) -> dict[str, Any]:
        svc = services(request)
        return {"content": svc.permissions.raw(), "snapshot": svc.permissions.snapshot()}

    @app.put("/v1/permissions", dependencies=[protected])
    async def update_permissions(
        request: Request, payload: PermissionUpdate
    ) -> dict[str, Any]:
        svc = services(request)
        snapshot = svc.permissions.update(payload.content)
        svc.database.audit(
            event_type="permissions",
            actor="operator",
            action="permissions.update",
            resource=str(svc.config.app.permissions_file),
            outcome="success",
            details=snapshot,
        )
        return {"content": svc.permissions.raw(), "snapshot": snapshot}

    @app.get("/v1/providers", dependencies=[protected])
    async def get_providers(request: Request) -> list[dict[str, Any]]:
        return services(request).router.describe()

    @app.get("/v1/providers/health", dependencies=[protected])
    async def providers_health(request: Request) -> list[dict[str, Any]]:
        return await services(request).router.health()

    @app.get("/v1/agents", dependencies=[protected])
    async def list_agents(request: Request) -> list[dict[str, Any]]:
        return services(request).agents.list()

    async def stream_operation(operation: EventOperation) -> StreamingResponse:
        queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue()

        async def callback(event: dict[str, Any]) -> None:
            await queue.put(event)

        async def worker() -> None:
            try:
                result = await operation(callback)
                await queue.put({"event": "stream.result", "result": result})
            except Exception as exc:  # Serialized because response headers are already sent.
                await queue.put(
                    {
                        "event": "stream.error",
                        "error": exc.__class__.__name__,
                        "detail": str(exc),
                    }
                )
            finally:
                await queue.put(None)

        task = asyncio.create_task(worker())

        async def events() -> AsyncIterator[bytes]:
            while True:
                event = await queue.get()
                if event is None:
                    break
                yield (json.dumps(event, ensure_ascii=False, default=str) + "\n").encode(
                    "utf-8"
                )

        class OwnedStreamingResponse(StreamingResponse):
            async def __call__(self, scope, receive, send):
                try:
                    await super().__call__(scope, receive, send)
                finally:
                    # Own the producer even if the connection disappears before
                    # the body iterator starts; generator-finally alone misses it.
                    if not task.done():
                        task.cancel()
                        try:
                            with anyio.CancelScope(shield=True):
                                await asyncio.wait({task}, timeout=4.0)
                        except asyncio.CancelledError:
                            pass

        return OwnedStreamingResponse(
            events(),
            media_type="application/x-ndjson",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

    @app.post("/v1/chat", response_model=ChatResponse, dependencies=[protected])
    async def chat(request: Request, payload: ChatRequest) -> dict[str, Any]:
        return await services(request).runtime.chat(**payload.model_dump())

    @app.post("/v1/chat/stream", dependencies=[protected])
    async def chat_stream(request: Request, payload: ChatRequest) -> StreamingResponse:
        svc = services(request)

        async def operation(callback):
            return await svc.runtime.chat(
                **payload.model_dump(), event_callback=callback
            )

        return await stream_operation(operation)

    @app.get("/v1/chat/requests/{request_id}", dependencies=[protected])
    async def chat_request_receipt(request: Request, request_id: str) -> dict[str, Any]:
        return services(request).runtime.chat_request_view(request_id)

    @app.get("/v1/runs", dependencies=[protected])
    async def list_runs(
        request: Request,
        conversation_id: str | None = None,
        run_status: str | None = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ) -> list[dict[str, Any]]:
        svc=services(request)
        rows=svc.database.list_runs(conversation_id=conversation_id,
            status='running' if run_status=='unconfirmed' else run_status, limit=limit)
        views=[svc.runtime.run_status_view(row) for row in rows]
        return [row for row in views if run_status is None or row['status']==run_status]

    @app.get("/v1/runs/{run_id}", dependencies=[protected])
    async def get_run(request: Request, run_id: str) -> dict[str, Any]:
        run = services(request).database.get_run(run_id)
        if run is None:
            raise KeyError(f"Run not found: {run_id}")
        return services(request).runtime.run_status_view(run)

    @app.post("/v1/runs/{run_id}/resume", response_model=ChatResponse, dependencies=[protected])
    async def resume_run(request: Request, run_id: str) -> dict[str, Any]:
        return await services(request).runtime.resume(run_id)

    @app.post("/v1/runs/{run_id}/resume/stream", dependencies=[protected])
    async def resume_run_stream(request: Request, run_id: str) -> StreamingResponse:
        svc = services(request)

        async def operation(callback):
            return await svc.runtime.resume(run_id, event_callback=callback)

        return await stream_operation(operation)

    @app.get("/v1/conversations", dependencies=[protected])
    async def list_conversations(
        request: Request,
        q: str | None = None,
        limit: Annotated[int, Query(ge=1, le=1000)] = 200,
        archived: bool = False,
    ) -> list[dict[str, Any]]:
        return services(request).database.list_conversations(
            search=q, limit=limit, archived=archived
        )

    @app.post("/v1/conversations", dependencies=[protected])
    async def create_conversation(
        request: Request, payload: ConversationCreate
    ) -> dict[str, Any]:
        svc = services(request)
        svc.agents.get(payload.agent_slug)
        return svc.database.create_conversation(**payload.model_dump())

    @app.get("/v1/conversations/{conversation_id}", dependencies=[protected])
    async def get_conversation(
        request: Request, conversation_id: str
    ) -> dict[str, Any]:
        database = services(request).database
        conversation = database.get_conversation(conversation_id)
        if conversation is None:
            raise KeyError(f"Conversation not found: {conversation_id}")
        conversation["messages"] = database.list_messages(conversation_id, limit=10_000)
        conversation["runs"] = database.list_runs(conversation_id=conversation_id, limit=100)
        return conversation

    @app.patch("/v1/conversations/{conversation_id}", dependencies=[protected])
    async def update_conversation(
        request: Request, conversation_id: str, payload: ConversationPatch
    ) -> dict[str, Any]:
        svc = services(request)
        changes = payload.model_dump(exclude_unset=True)
        if changes.get("agent_slug"):
            svc.agents.get(changes["agent_slug"])
        return svc.database.update_conversation(conversation_id, **changes)

    @app.delete("/v1/conversations/{conversation_id}", dependencies=[protected])
    async def delete_conversation(
        request: Request, conversation_id: str
    ) -> dict[str, Any]:
        if not services(request).database.delete_conversation(conversation_id):
            raise KeyError(f"Conversation not found: {conversation_id}")
        return {"deleted": True, "id": conversation_id}

    @app.post("/v1/memories", dependencies=[protected])
    async def create_memory(request: Request, payload: MemoryCreate) -> dict[str, Any]:
        svc = services(request)
        memory = svc.database.upsert_memory(**payload.model_dump())
        svc.database.audit(
            event_type="memory",
            actor="operator",
            action="memory.upsert",
            resource=str(memory["id"]),
            outcome="success",
            details={"namespace": memory["namespace"], "key": memory["key"]},
        )
        return memory

    @app.put("/v1/memories/{memory_id}", dependencies=[protected])
    async def update_memory(
        request: Request, memory_id: int, payload: MemoryCreate
    ) -> dict[str, Any]:
        svc = services(request)
        memory = svc.database.update_memory(memory_id, **payload.model_dump())
        svc.database.audit(
            event_type="memory",
            actor="operator",
            action="memory.update",
            resource=str(memory_id),
            outcome="success",
        )
        return memory

    @app.get("/v1/memories", dependencies=[protected])
    async def get_memories(
        request: Request,
        q: str | None = None,
        namespace: str | None = None,
        limit: Annotated[int, Query(ge=1, le=1000)] = 200,
    ) -> list[dict[str, Any]]:
        database = services(request).database
        return (
            database.search_memories(q, namespace=namespace, limit=limit)
            if q
            else database.list_memories(namespace=namespace, limit=limit)
        )

    @app.delete("/v1/memories/{memory_id}", dependencies=[protected])
    async def delete_memory(request: Request, memory_id: int) -> dict[str, Any]:
        database = services(request).database
        if not database.delete_memory(memory_id):
            raise KeyError(f"Memory not found: {memory_id}")
        database.audit(
            event_type="memory",
            actor="operator",
            action="memory.delete",
            resource=str(memory_id),
            outcome="success",
        )
        return {"deleted": True, "id": memory_id}

    @app.post("/v1/projects", dependencies=[protected])
    async def upsert_project(request: Request, payload: ProjectUpsert) -> dict[str, Any]:
        svc = services(request)
        project = svc.database.upsert_project(**payload.model_dump())
        svc.database.audit(
            event_type="project",
            actor="operator",
            action="project.upsert",
            resource=project["slug"],
            outcome="success",
        )
        return project

    @app.get("/v1/projects", dependencies=[protected])
    async def list_projects(request: Request) -> list[dict[str, Any]]:
        return services(request).database.list_projects()

    @app.get("/v1/projects/{slug}", dependencies=[protected])
    async def get_project(request: Request, slug: str) -> dict[str, Any]:
        project = services(request).database.get_project(slug)
        if project is None:
            raise KeyError(f"Project not found: {slug}")
        return project

    @app.delete("/v1/projects/{slug}", dependencies=[protected])
    async def delete_project(request: Request, slug: str) -> dict[str, Any]:
        svc = services(request)
        if not svc.database.delete_project(slug):
            raise KeyError(f"Project not found: {slug}")
        svc.database.audit(
            event_type="project",
            actor="operator",
            action="project.delete",
            resource=slug,
            outcome="success",
        )
        return {"deleted": True, "slug": slug}

    @app.get("/v1/tools", dependencies=[protected])
    async def get_tools(request: Request) -> list[dict[str, Any]]:
        return services(request).tools.describe()

    @app.get("/v1/connectors/google", dependencies=[protected])
    async def google_connector_status(request: Request) -> dict[str, Any]:
        svc = services(request)
        if svc.google is None:
            return {
                "enabled": False,
                "client_configured": False,
                "connected": False,
            }
        return svc.google.status()

    @app.get("/v1/connectors/google/health", dependencies=[protected])
    async def google_connector_health(request: Request) -> dict[str, Any]:
        """Perform a live, non-mutating Google account and token check."""
        svc = services(request)
        if svc.google is None:
            return {
                "enabled": False,
                "client_configured": False,
                "connected": False,
                "healthy": False,
                "state": "not_enabled",
                "reconnect_required": False,
                "message": "Google Workspace is not enabled for this Atlas installation.",
                "reconnect_launcher": "Connect Google.command",
            }

        stored = svc.google.status()
        if not stored.get("enabled"):
            state = "not_enabled"
            message = "Google Workspace is turned off in Atlas configuration."
            reconnect_required = False
        elif not stored.get("client_configured"):
            state = "setup_required"
            message = "Atlas needs its Google Desktop app credential before it can connect."
            reconnect_required = False
        elif not stored.get("connected"):
            state = "reconnect_required"
            message = "Google needs to be connected again before Atlas can use Gmail or Calendar."
            reconnect_required = True
        else:
            try:
                live = await asyncio.to_thread(svc.google.verify_connection)
            except (ConnectorError, httpx.HTTPError):
                return {
                    **stored,
                    "healthy": False,
                    "state": "reconnect_required",
                    "reconnect_required": True,
                    "message": "Google rejected the saved connection. Reconnect Atlas to restore access.",
                    "reconnect_launcher": "Connect Google.command",
                }
            return {
                **stored,
                "healthy": True,
                "state": "ready",
                "reconnect_required": False,
                "message": "Google verified the saved Atlas connection.",
                "account": live.get("account"),
                "calendar": live.get("calendar"),
                "scopes": live.get("scopes") or stored.get("scopes") or [],
                "reconnect_launcher": "Connect Google.command",
            }

        return {
            **stored,
            "healthy": False,
            "state": state,
            "reconnect_required": reconnect_required,
            "message": message,
            "reconnect_launcher": "Connect Google.command",
        }

    @app.post("/v1/tools/execute", dependencies=[protected], response_model=None)
    async def execute_tool(request: Request, payload: ToolExecuteRequest) -> Any:
        try:
            svc = services(request)
            execute_arguments = dict(
                tool_name=payload.tool,
                action=payload.action,
                arguments=payload.arguments,
                approval_id=payload.approval_id,
            )
            if payload.tool == "development" and payload.action == "selfdev_apply":
                project = payload.arguments.get("project")
                control = development_control(request, project)
                epoch = control.admit(project)
                with control.bind(project, epoch):
                    result = await asyncio.to_thread(svc.tools.execute, **execute_arguments)
            else:
                result = svc.tools.execute(**execute_arguments)
            return {"status": "executed", "result": result}
        except ApprovalRequired as exc:
            return JSONResponse(
                status_code=status.HTTP_202_ACCEPTED,
                content={
                    "status": "approval_required",
                    "approval_id": exc.approval_id,
                    "tool": exc.tool,
                    "action": exc.action,
                    "arguments": exc.arguments,
                },
            )

    @app.get("/v1/approvals", dependencies=[protected])
    async def list_approvals(
        request: Request,
        approval_status: str | None = None,
        limit: Annotated[int, Query(ge=1, le=1000)] = 200,
    ) -> list[dict[str, Any]]:
        return services(request).database.list_approvals(
            status=approval_status, limit=limit
        )

    @app.post("/v1/approvals/{approval_id}", dependencies=[protected])
    async def decide_approval(
        request: Request,
        approval_id: str,
        payload: ApprovalDecisionRequest,
    ) -> dict[str, Any]:
        svc = services(request)
        approval = svc.tools.decide_approval(
            approval_id, payload.decision, payload.note
        )
        run_result: dict[str, Any] | None = None
        resume_error: str | None = None
        run_id = approval.get("run_id")
        if payload.resume_run and run_id:
            try:
                run_result = await svc.runtime.resume(str(run_id))
            except (RunStateError, ApprovalError, ProviderError) as exc:
                resume_error = str(exc)
        return {
            "approval": approval,
            "run": run_result,
            "resume_error": resume_error,
        }

    @app.get("/v1/audit", dependencies=[protected])
    async def get_audit(
        request: Request,
        limit: Annotated[int, Query(ge=1, le=5000)] = 200,
        event_type: str | None = None,
        outcome: str | None = None,
    ) -> list[dict[str, Any]]:
        return services(request).database.list_audit(
            limit=limit, event_type=event_type, outcome=outcome
        )

    @app.post("/v1/import", dependencies=[protected])
    async def import_data(
        request: Request,
        file: UploadFile = File(...),
        source: str = Form("auto"),
        project_slug: str | None = Form(None),
        dry_run: bool = Form(False),
    ) -> dict[str, Any]:
        svc = services(request)
        suffix = Path(file.filename or "import.bin").suffix
        total = 0
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                prefix="atlas-import-", suffix=suffix, delete=False
            ) as temporary:
                temporary_path = Path(temporary.name)
                while True:
                    chunk = await file.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > svc.config.imports.max_upload_bytes:
                        raise HTTPException(
                            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            detail=(
                                "Import exceeds the configured "
                                f"{svc.config.imports.max_upload_bytes}-byte limit"
                            ),
                        )
                    temporary.write(chunk)
            return await asyncio.to_thread(
                svc.imports.import_path,
                temporary_path,
                source=source,
                project_slug=project_slug,
                dry_run=dry_run,
            )
        finally:
            await file.close()
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

    @app.get("/v1/imports", dependencies=[protected])
    async def list_imports(
        request: Request,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ) -> list[dict[str, Any]]:
        return services(request).database.list_import_jobs(limit=limit)

    @app.post("/v1/backups", dependencies=[protected])
    async def create_backup(request: Request, payload: BackupRequest) -> Response:
        path = await asyncio.to_thread(
            services(request).backups.create_backup,
            include_workspace=payload.include_workspace,
        )
        return FileResponse(
            path,
            media_type="application/zip",
            filename=path.name,
        )

    @app.get("/v1/backups", dependencies=[protected])
    async def list_backups(request: Request) -> list[dict[str, Any]]:
        data_dir = services(request).config.app.data_dir
        return [
            {
                "name": path.name,
                "size": path.stat().st_size,
                "modified_at": path.stat().st_mtime,
            }
            for path in sorted(data_dir.glob("atlas-backup-*.zip"), reverse=True)[:100]
        ]

    # Backwards-compatible export endpoint used by early Atlas clients.
    @app.get("/v1/export", dependencies=[protected])
    async def export_data(request: Request) -> Response:
        path = await asyncio.to_thread(services(request).backups.create_backup)
        return FileResponse(path, media_type="application/zip", filename=path.name)

    return app


app = create_app(os.getenv("ATLAS_CONFIG", "config/atlas.yaml"))
