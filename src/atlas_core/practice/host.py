"""Scoped host connection for the explicit practice agent; no automatic grants."""
from contextlib import contextmanager, nullcontext
import contextvars
import os
import json
from pathlib import Path
import stat
import uuid

from atlas_core.errors import ToolError
from atlas_core.development_control import DevelopmentStopped
from . import PracticeWorkspace, PracticeNotebook, PracticeTool, NotebookTool, PracticeRefused
from .workspace import regular
from .continuity import read_lesson_snapshot

SCOPES = frozenset({('practice','read'),('practice','write'),('practice','check'),
                    ('notebook','read'),('notebook','save')})


def private_directory(path):
    path = Path(path).absolute()
    if any(p.is_symlink() for p in (path,*path.parents)):
        raise ToolError('Practice directory must not use symlinks')
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ToolError('Practice requires a private owner-prepared directory')
    return (info.st_dev, info.st_ino)


class PracticeHost:
    def __init__(self, *, config, control, constitution, permissions, agents):
        self.config = config
        self.root = Path(config.practice.root).absolute()
        self.control, self.constitution = control, constitution
        self.permissions, self.agents = permissions, agents
        self._bound = contextvars.ContextVar('atlas_practice_request', default=None)
        project = config.development.projects.get(config.practice.project)
        if control is None or constitution is None or project is None or not project.self_development:
            raise ToolError('Practice requires the registered owner-controlled development project')
        roots = [config.app.workspace_dir, *[p.root for p in config.development.projects.values()]]
        if any(self.root == Path(p) or self.root in Path(p).parents or Path(p) in self.root.parents for p in roots):
            raise ToolError('Practice must be separate from general tool and source roots')
        self._identities = {p:private_directory(p) for p in [self.root, self.root/'notes', self.root/'experiments']}
        self._package = Path(__file__).parent

    def tools(self):
        return [BoundPracticeTool(self), BoundNotebookTool(self)]

    def lesson_context(self, *, project):
        """Read-only context for ordinary local Chat; creates no tool authority."""
        if project != self.config.practice.project:
            return {'status': 'out_of_scope', 'notes': []}
        try:
            self.constitution.check_current()
            for path, expected in self._identities.items():
                if private_directory(path) != expected:
                    raise ToolError('Practice directory identity changed')
            if os.path.lexists(self.root/'STOP'):
                raise ToolError('Workspace stopped')
            self.permissions.reload()
            if self.permissions.decision('notebook', 'read').value != 'allow':
                raise ToolError('Notebook read is not permitted')
            result = read_lesson_snapshot(self.root)
            for path, expected in self._identities.items():
                if private_directory(path) != expected:
                    raise ToolError('Practice directory identity changed')
            self.constitution.check_current()
            self.permissions.reload()
            if os.path.lexists(self.root/'STOP') or self.permissions.decision('notebook', 'read').value != 'allow':
                raise ToolError('Notebook context permission changed')
            return result
        except (OSError, ValueError, ToolError, DevelopmentStopped):
            # Do not leak paths or note bytes in exception text.
            return {'status': 'unavailable', 'notes': []}

    def _current(self):
        scope = self._bound.get()
        if scope is None:
            raise ToolError('Practice tools require an admitted practice Chat request')
        if scope.get('request_control') is not None:
            scope['request_control'].check(scope['tool']+'.'+scope['action'])
        self.check_request(scope['project'], scope['epoch'])
        profile = self.agents.get(self.config.practice.agent)
        if (not profile.allows(scope['tool'],scope['action'])
                or self.permissions.decision(scope['tool'],scope['action']).value == 'deny'):
            raise ToolError('Practice permission or agent scope was revoked')
        return scope

    def check_request(self, project, epoch):
        from .improvement import current_checkpoint
        current_checkpoint()
        if project != self.config.practice.project:
            raise ToolError('Practice project does not match its request')
        for path, expected in self._identities.items():
            if private_directory(path) != expected: raise ToolError('Practice directory identity changed')
        if os.path.lexists(self.root/'STOP'): raise DevelopmentStopped('Practice workspace is stopped')
        self.constitution.check_current()
        self.control.checkpoint(project, epoch)
        self.permissions.reload(); self.agents.reload()
        profile = self.agents.get(self.config.practice.agent)
        if not any(profile.allows(t,a) and self.permissions.decision(t,a).value != 'deny' for t,a in SCOPES):
            raise ToolError('Practice scope has no permitted actions')

    def _authorize(self, action):
        self._current()
        return True

    @contextmanager
    def bind(self, *, run_id, conversation_id, project, epoch, tool, action, request_control=None):
        if project != self.config.practice.project or (tool,action) not in SCOPES:
            raise ToolError('Tool is outside the practice request scope')
        for identifier in [run_id,conversation_id]:
            try:
                if type(identifier) is not str or str(uuid.UUID(identifier)) != identifier: raise ValueError()
            except (ValueError,TypeError,AttributeError): raise ToolError('Invalid practice request identity') from None
        token = self._bound.set({'run_id':run_id,'conversation_id':conversation_id,'project':project,
                                 'epoch':epoch,'tool':tool,'action':action,'request_control':request_control})
        try:
            self._current()
            yield
        finally:
            self._bound.reset(token)

    def execute(self, tool, action, arguments):
        scope = self._current()
        if (scope['tool'],scope['action']) != (tool,action): raise ToolError('Practice action does not match its request')
        # The existing owner control accounts for this foreground operation.
        # Stop changes its epoch; every checker poll also rechecks this authority.
        try:
            with self.control.transaction(scope['project'],scope['epoch']):
                self._current()
                if tool == 'notebook':
                    notebook = PracticeNotebook(self.root/'notes', authorize=self._authorize)
                    self._order_writes(notebook, scope, {'NOTEBOOK.md','IDEAS.md','LESSONS.md'})
                    target = NotebookTool(notebook)
                else:
                    directory = self.root/'experiments'/scope['conversation_id']
                    if not os.path.lexists(directory):
                        workspace = PracticeWorkspace.create(directory, checker=self._package/'checker.py',
                            tests=[self._package/'protected_tests/test_parse.py', self._package/'protected_tests/test_contract.py'],
                            authorize=self._authorize, seed=(self._package/'starter.txt').read_text())
                    else:
                        workspace = PracticeWorkspace(directory, authorize=self._authorize)
                    self._order_writes(workspace, scope, {'solution.py'})
                    target = PracticeTool(workspace)
                result = target.execute(action,arguments)
                if tool == 'practice' and action == 'check' and workspace._state()['in_flight']:
                    self.control.mark_cleanup(scope['project'])
                self._current()
                return result
        except PracticeRefused as exc:
            raise ToolError(str(exc)) from exc

    def _order_writes(self, target, scope, names):
        original = target._atomic
        def atomic(name, raw):
            if name in names:
                # Order the actual model-content write against durable owner Stop.
                # This body must not reenter the control database.
                request = scope.get('request_control')
                with request.publication() if request is not None else nullcontext():
                    with self.control.publication_guard(scope['project'], scope['epoch']):
                        original(name, raw)
            else:
                original(name, raw)  # operational state/cleanup receipts may persist after Stop
        target._atomic = atomic

    def verification(self, *, conversation_id, project, epoch):
        """Host evidence for the current source, never inferred from model prose."""
        self.check_request(project, epoch)
        if str(uuid.UUID(conversation_id)) != conversation_id:
            raise ToolError('Invalid practice conversation identity')
        directory = self.root/'experiments'/conversation_id
        if not os.path.lexists(directory):
            return {'status':'not_checked','tests_run':0}
        def authorize(action):
            self.check_request(project, epoch)
            return True
        workspace = PracticeWorkspace(directory, authorize=authorize)
        with workspace._locked('host_verification') as state:
            result = state.get('last_result')
            if not result:
                return {'status':'not_checked','tests_run':0,'source_sha256':state['source_sha256']}
            receipt = json.loads(regular(directory/('check-'+str(state['checks'])+'.json')))
            if receipt['result'] != result or result['source_sha256'] != state['source_sha256']:
                raise ToolError('Practice result receipt does not match current source')
            status = 'passed' if result.get('passed') is True else 'failed' if result.get('complete') is True else 'unconfirmed'
            return {'status':status,'tests_run':result.get('tests_run',0),
                    'source_sha256':state['source_sha256'],'checked_at':receipt['utc']}


class BoundPracticeTool(PracticeTool):
    def __init__(self, host): self.host = host
    def execute(self, action, arguments): return self.host.execute(self.name,action,arguments)


class BoundNotebookTool(NotebookTool):
    def __init__(self, host): self.host = host
    def execute(self, action, arguments): return self.host.execute(self.name,action,arguments)
