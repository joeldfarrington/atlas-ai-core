from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

from atlas_core.agents import AgentStore
from atlas_core.governance.live_constitution import LiveConstitution
from atlas_core.governance.heartbeat import AtlasHeartbeat
from atlas_core.backup import BackupService
from atlas_core.config import (
    AtlasConfig,
    load_config,
    load_config_without_environment,
)
from atlas_core.connectors import GoogleWorkspaceConnector
from atlas_core.identity import IdentityStore
from atlas_core.memory import Database
from atlas_core.migration import ImportService
from atlas_core.models import ModelRouter
from atlas_core.permissions import PermissionEngine
from atlas_core.runtime import AtlasRuntime
from atlas_core.tools.continuity import ContinuityTool
from atlas_core.tools.research import ResearchTool
from atlas_core.supervisor import SupervisorService
from atlas_core.supervisor_v2 import SupervisorV2Service
from atlas_core.supervisor_v3 import SupervisorV3Service
from atlas_core.supervisor_v4 import SupervisorV4Service
from atlas_core.tools import (
    DevelopmentTool,
    FilesystemTool,
    GmailTool,
    GoogleCalendarTool,
    MacInboxTool,
    MemoryTool,
    PhoneCompanionTool,
    ProjectsTool,
    TerminalTool,
    ToolManager,
    WebFetchTool,
)


@dataclass(slots=True)
class AtlasServices:
    config: AtlasConfig
    database: Database
    identity: IdentityStore
    router: ModelRouter
    permissions: PermissionEngine
    agents: AgentStore
    tools: ToolManager
    runtime: AtlasRuntime
    imports: ImportService
    backups: BackupService
    development: DevelopmentTool
    supervisor: SupervisorService
    supervisor_v2: SupervisorV2Service
    supervisor_v3: SupervisorV3Service
    supervisor_v4: SupervisorV4Service
    google: GoogleWorkspaceConnector | None = None
    mac_inbox: MacInboxTool | None = None
    phone_companion: PhoneCompanionTool | None = None

    constitution: LiveConstitution | None = None
    heartbeat: AtlasHeartbeat | None = None
    improvement: object | None = None
    improvement_error: str | None = None

    coding_owner: object | None = None
    coding_preparation: object | None = None
    # Trusted host adoption only. This is not populated from model or HTTP data.
    coding_constitution: object | None = None
    coding_foundation: object | None = None
    coding_action_observation: object | None = None
    coding_work_controls: object | None = None
    coding_work_startup: object | None = None

    def publish_verified_coding_resolution(self, selection, *, resolution, aggregate, audit):
        """Trusted owner delivery only; not a model tool or HTTP operation.

        Caller must select independently verified receipts and their original
        conversation/run binding. Selection grants no task or source authority.
        """
        from atlas_core.coding_goal_delivery import publish_goal_resolution
        return publish_goal_resolution(self.database, selection, resolution=resolution,
                                       aggregate=aggregate, audit=audit)

    def select_work_startup(self, selection):
        """Explicit host-selected readiness; no authority or task dispatch."""
        from atlas_core.governance.work_startup import select_for_services
        return select_for_services(self, selection)

    def prepare_first_work_install(self, selection, *, project):
        """Prepare first code installation; never provision task authority."""
        from atlas_core.governance.work_first_install import FirstWorkInstall
        return FirstWorkInstall(self, selection, project=project)

    def prepare_work_state_transition(self, selection):
        """Owner-host preparation; no migration, authority or resume by itself."""
        from atlas_core.governance.work_state_transition import WorkStateTransition
        return WorkStateTransition(self, selection)

    def select_prepared_work_controls(self, prepared, selection):
        """Select already-provisioned owner records; never generate permission."""
        from atlas_core.governance.owner_work import select_for_services
        return select_for_services(self, prepared, selection)

    def bind_prepared_work_observation(self, prepared, *, resources_ok):
        """Bind current Work state for the independent boundary; grant nothing."""
        from atlas_core.governance.prepared_work_state import bind_for_services
        return bind_for_services(self, prepared, resources_ok=resources_ok)

    def select_coding_constitution(self, selection):
        """Explicit trusted-host selection; never discovered from config or task data."""
        from atlas_core.governance.owner_foundation import select_for_services
        return select_for_services(self, selection)

    def prepare_work_release(self, work_selection, release_selection):
        """Trusted host only: prepare source/state release without activation."""
        from atlas_core.governance.work_release import WorkRelease
        return WorkRelease(self.prepare_work_state_transition(work_selection),release_selection)

    async def prepare_registered_coding_task(self, plan):
        """Trusted fixed-task preparation; no public transport or dispatch."""
        from atlas_core.coding_preparation import FreshTaskPreparation, FreshPreparationRefused
        if self.coding_preparation is None:
            self.coding_preparation = FreshTaskPreparation(self)
        elif (type(self.coding_preparation) is not FreshTaskPreparation
              or self.coding_preparation.services is not self):
            raise FreshPreparationRefused('existing_preparation_required')
        return await self.coding_preparation.prepare(plan)

    def initialize_coding_owner(self):
        """Keep optional hosting in this exact already-built services lifetime."""
        from atlas_core.coding_owner import CodingOwner, CodingOwnerRefused
        if self.coding_owner is None:
            self.coding_owner = CodingOwner(self.development.control)
        elif type(self.coding_owner) is not CodingOwner or self.coding_owner.control is not self.development.control:
            raise CodingOwnerRefused("existing_control_required")
        return self.coding_owner

    async def attach_prepared_coding_binding(self, binding):
        """Trusted owner entry; caller separately prepares a current task.

        This is not an HTTP tool, and cannot recreate saved admission authority.
        """
        owner = self.initialize_coding_owner()
        return await owner.attach(binding)

    async def close_coding_owner(self):
        if self.coding_owner is None:
            return True
        return await self.coding_owner.aclose()

    # Compatibility properties for early v1 previews.
    @property
    def migration(self) -> ImportService:
        return self.imports



def build_services(config_path: str | Path = "config/atlas.yaml") -> AtlasServices:
    config = load_config(config_path)
    constitution = LiveConstitution()
    database = Database(config.database_path)
    identity = IdentityStore(config.app.identity_dir)
    router = ModelRouter(config)
    permissions = PermissionEngine(config.app.permissions_file)
    agents = AgentStore(
        config.app.agents_file,
        global_max_steps=config.app.max_tool_steps,
    )
    google: GoogleWorkspaceConnector | None = None
    mac_inbox: MacInboxTool | None = None
    phone_companion: PhoneCompanionTool | None = None
    development = DevelopmentTool(
        config.development,
        control_root=config.app.workspace_dir,
        max_file_bytes=config.app.max_file_bytes,
    )
    development.constitution = constitution
    heartbeat = AtlasHeartbeat(constitution, development)
    growth_projects = set(config.growth.projects) & set(config.development.projects) if config.growth.enabled else set()
    registered_tools = [
        ContinuityTool(database, allowed_projects=growth_projects),
        ResearchTool(database, allowed_projects=growth_projects,
                     fetcher=WebFetchTool(max_bytes=config.app.web_fetch_max_bytes)),
        development,
        FilesystemTool(
            config.app.workspace_dir,
            max_file_bytes=config.app.max_file_bytes,
        ),
        MemoryTool(database),
        ProjectsTool(database),
        WebFetchTool(max_bytes=config.app.web_fetch_max_bytes),
        TerminalTool(
            config.app.workspace_dir,
            default_timeout_seconds=config.app.terminal_timeout_seconds,
        ),
    ]
    if config.mac_inbox.enabled:
        mac_inbox = MacInboxTool(config.mac_inbox)
        registered_tools.append(mac_inbox)
    if config.phone_companion.enabled:
        phone_companion = PhoneCompanionTool(config.phone_companion)
        registered_tools.append(phone_companion)
    if config.google_workspace.enabled:
        google = GoogleWorkspaceConnector(config.google_workspace)
        registered_tools.extend([GmailTool(google), GoogleCalendarTool(google)])
    if config.practice.enabled:
        from atlas_core.practice.host import PracticeHost
        practice_host = PracticeHost(config=config, control=development.control,
                                     constitution=constitution, permissions=permissions, agents=agents)
        registered_tools.extend(practice_host.tools())
    tools = ToolManager(
        database=database,
        permissions=permissions,
        tools=registered_tools,
        constitution=constitution,
    )
    supervisor = SupervisorService(
        config=config,
        database=database,
        permissions=permissions,
        development=development,
    )
    supervisor_v2 = SupervisorV2Service(
        config=config,
        database=database,
        permissions=permissions,
    )
    supervisor_v3 = SupervisorV3Service(
        config=config,
        database=database,
        permissions=permissions,
    )
    supervisor_v4 = SupervisorV4Service(
        config=config,
        database=database,
    )
    runtime = AtlasRuntime(
        config=config,
        database=database,
        identity=identity,
        router=router,
        agents=agents,
        tools=tools,
    )
    imports = ImportService(
        database, max_upload_bytes=config.imports.max_upload_bytes
    )
    backups = BackupService(config=config, database=database, identity=identity)
    return AtlasServices(
        config=config,
        database=database,
        identity=identity,
        router=router,
        permissions=permissions,
        agents=agents,
        tools=tools,
        runtime=runtime,
        imports=imports,
        backups=backups,
        development=development,
        supervisor=supervisor,
        supervisor_v2=supervisor_v2,
        supervisor_v3=supervisor_v3,
        supervisor_v4=supervisor_v4,
        google=google,
        mac_inbox=mac_inbox,
        phone_companion=phone_companion,
        constitution=constitution,
        heartbeat=heartbeat,
    )


def _canonical_supervisor_v4_config(*, isolated_environment: bool) -> AtlasConfig:
    """Load the active checkout's v4 config without constructing Atlas runtime."""

    environment_root = Path(sys.prefix)
    if not environment_root.is_absolute():
        raise RuntimeError("Option 1 canary runtime is not absolute")
    environment_root = environment_root.resolve(strict=True)
    project_root = environment_root.parent
    expected_environment = project_root / ".venv"
    if (
        environment_root != expected_environment.resolve(strict=True)
        or not project_root.is_dir()
    ):
        raise RuntimeError(
            "Option 1 canary runtime is not the canonical Atlas environment"
        )
    config_path = project_root / "config" / "atlas.yaml"
    if config_path.is_symlink() or not config_path.is_file():
        raise RuntimeError("Option 1 canary configuration is unavailable")
    config_loader = (
        load_config_without_environment if isolated_environment else load_config
    )
    config = config_loader(config_path.resolve(strict=True))
    if config.project_root != project_root.resolve(strict=True):
        raise RuntimeError("Option 1 canary configuration root is not canonical")
    return config


def build_supervisor_v4_only(
    *,
    isolated_environment: bool = False,
) -> SupervisorV4Service:
    """Build only the local Supervisor v4 control surface.

    The explicit Option 1 canary must not initialize model routers, external
    connectors, tools, the Atlas database, or the ordinary Atlas runtime before
    its owner gate is checked. Its configuration is hard-bound to the Atlas
    checkout that owns the active ``.venv`` rather than caller input.
    """

    config = _canonical_supervisor_v4_config(
        isolated_environment=isolated_environment
    )
    return SupervisorV4Service(config=config, database=None)


def build_supervisor_v4_review_only() -> SupervisorV4Service:
    """Build the isolated v4 review ledger without models, tools, or connectors."""

    config = _canonical_supervisor_v4_config(isolated_environment=True)
    return SupervisorV4Service(config=config, database=Database(config.database_path))


def build_supervisor_v4_host_preflight_only() -> SupervisorV4Service:
    """Build only the local, read-only Option 2 identity preflight surface."""

    config = _canonical_supervisor_v4_config(isolated_environment=True)
    return SupervisorV4Service(config=config, database=Database(config.database_path))
