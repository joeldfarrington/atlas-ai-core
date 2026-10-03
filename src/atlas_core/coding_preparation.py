"""Trusted one-shot preparation for a fixed registered maintenance task.

No HTTP/model tool, source selector, resume, dispatch, or saved admission loader.
The caller supplies a frozen plan to the existing services lifetime. Failed intent
is retained permanently; preparing a second plan does not renew or replay it.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, asdict
from pathlib import Path
import os
import stat
import json


class FreshPreparationRefused(ValueError):
    pass


def _need(ok, reason):
    if not ok:
        raise FreshPreparationRefused(reason)


@dataclass(frozen=True)
class FreshTaskPlan:
    task_id: str
    project: str
    run_id: str
    created_utc: str
    dispatch_utc: str
    acceptance_utc: str
    close_utc: str
    expected_epoch: int
    approval_ref: str


@dataclass(frozen=True)
class FreshPreparedTask:
    plan: FreshTaskPlan
    session: object
    binding: object
    source_path: Path
    owner_status: dict


def _private_directory(path):
    _need(not any(p.is_symlink() for p in (path, *path.parents)), 'directory_symlink')
    info = path.lstat()
    _need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
          and stat.S_IMODE(info.st_mode) == 0o700, 'private_directory_required')
    return info.st_dev, info.st_ino


class FreshTaskPreparation:
    def __init__(self, services):
        from atlas_core.services import AtlasServices
        from atlas_core.development_control import DevelopmentControl
        _need(type(services) is AtlasServices
              and type(services.development.control) is DevelopmentControl, 'existing_services_required')
        self.services = services
        self.control = services.development.control
        self._prepared = None
        self._pid = os.getpid()
        self._lock = asyncio.Lock()
        self._loop = None
        from atlas_core.governance.constitution_policy import ConstitutionGate
        from atlas_core.governance.owner_foundation import OwnerFoundation
        self._owner_foundation_type = OwnerFoundation
        self._owner_foundation = services.coding_foundation
        _need(type(self._owner_foundation) is OwnerFoundation
              and self._owner_foundation.services is services, 'owner_foundation_required')
        self._constitution_type = ConstitutionGate
        self._constitution = services.coding_constitution
        _need(type(self._constitution) is ConstitutionGate, 'owner_foundation_required')
        _need(self._owner_foundation.gate is self._constitution, 'owner_foundation_required')
        try:
            ConstitutionGate(self._constitution.document,self._constitution.adoption)
        except Exception:
            raise FreshPreparationRefused('owner_foundation_required') from None
        self._foundation_selection = self._foundation_snapshot()
        self._foundation_failed = False
        self._foundation_record = None
        self._check_foundation()

    def _foundation_snapshot(self):
        gate = self._constitution
        return json.dumps({'document':str(Path(gate.document).absolute()),
            'adoption':gate.adoption},sort_keys=True,separators=(',',':'),allow_nan=False)

    def _check_foundation(self):
        try:
            _need(not self._foundation_failed, 'foundation_stopped')
            _need(self.services.coding_foundation is self._owner_foundation,
                  'foundation_owner_changed')
            self._owner_foundation_type.check_current(self._owner_foundation)
            _need(self.services.coding_constitution is self._constitution
                  and self._foundation_snapshot() == self._foundation_selection,
                  'foundation_selection_changed')
            self._constitution_type.check_foundation(self._constitution)
            if self._foundation_record is not None:
                cs,path,expected = self._foundation_record
                _need(cs.regular(path, 4096) == expected, 'foundation_record_changed')
        except Exception:
            self._foundation_failed = True
            raise FreshPreparationRefused('foundation_stopped') from None

    def _foundation_receipt(self):
        self._check_foundation()
        adopted = json.loads(self._foundation_selection)['adoption']
        return {'version':adopted['version'],'document_sha256':adopted['document_sha256'],
                'context':adopted['context'],'permission_to_execute':False}

    def _same_owner(self):
        _need(os.getpid() == self._pid and self.services.development.control is self.control,
              'existing_control_required')
        self._check_foundation()

    def _source(self, cs, source, digest):
        cs.safe_path(str(source))
        _private_directory(source.parent)
        info = source.lstat()
        _need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
              and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
              'private_source_required')
        raw = cs.regular(source, 32768)
        _need(cs.sha(raw) == digest, 'source_changed')
        return raw

    def _state(self, plan, *, idle=False):
        self._same_owner()
        state = self.control.status(plan.project)
        _need(type(plan.expected_epoch) is int and state['epoch'] == plan.expected_epoch
              and not state['stopped'] and not state['cleanup_required'], 'stale_or_stopped')
        if idle:
            _need(state['active_operations'] == 0, 'competing_work')
        return state

    def _build(self, plan):
        from atlas_core.coding_connection import load_session
        cs = load_session()
        _need(type(plan) is FreshTaskPlan, 'trusted_plan_required')
        _need(type(plan.approval_ref) is str and 0 < len(plan.approval_ref.encode()) <= 120
              and all(32 <= ord(c) < 127 for c in plan.approval_ref), 'approval_reference_required')
        metadata = cs.fresh_task_contract(plan.task_id)
        _, project = self.services.development._selfdev_registered(
            {'project': plan.project}, action='selfdev_context')
        _need(project.action_tier == 'tier_2_reversible_local'
              and 'selfdev_apply' in project.allowed_actions, 'project_not_eligible')
        project_root = cs.safe_path(str(project.root))
        source = cs.safe_path(str(project_root / metadata['path']))
        _need(source.is_relative_to(project_root)
              and not self.services.development._is_blocked(project, Path(metadata['path'])),
              'source_scope_refused')
        self.services.development._require_selfdev_editable(project, source)
        raw = self._source(cs, source, metadata['source_sha256'])
        self._state(plan, idle=True)
        parent = project_root / '.atlas_coding_runs'
        # Validate all plan fields and deadlines before creating any run state.
        # Session's spec requires an existing parent; use the existing project
        # root for side-effect-free validation, then derive the fixed run parent.
        validation_spec = cs.make_fresh_spec(project_root, project=plan.project,
            task_id=plan.task_id, run_id=plan.run_id, created_utc=plan.created_utc,
            dispatch_utc=plan.dispatch_utc, acceptance_utc=plan.acceptance_utc,
            close_utc=plan.close_utc)
        probe = cs.Session(validation_spec)
        probe._gate(dispatch=True)
        _need(not parent.is_symlink(), 'runtime_symlink')
        if parent.exists():
            _private_directory(parent)
            _need(not (parent / ('INTENT.' + plan.task_id + '.json')).exists()
                  and not (parent / ('INTENT.' + plan.task_id + '.json')).is_symlink(),
                  'registration_already_reserved')
        return cs, metadata, source, raw, parent

    def _prepare(self, plan):
        from atlas_core.coding_connection import create_binding
        cs, metadata, source, raw, parent = self._build(plan)
        self._state(plan, idle=True)
        epoch = self.control.admit(plan.project)
        _need(epoch == plan.expected_epoch, 'stale_or_stopped')
        self._source(cs, source, metadata['source_sha256'])
        # Do not call a control/Session hook while holding this DB guard.
        with self.control.publication_guard(plan.project, epoch):
            foundation = self._foundation_receipt()
            if not parent.exists():
                parent.mkdir(mode=0o700)
            _private_directory(parent)
            cs.exclusive(parent / ('INTENT.' + plan.task_id + '.json'), cs.encoded({
                'schema': 1, 'plan': asdict(plan), 'source_sha256': metadata['source_sha256'],
                'constitution': foundation,
                'permission_to_execute': False, 'automatic_retry': False}))
        self._state(plan)
        self._source(cs, source, metadata['source_sha256'])
        spec = cs.make_fresh_spec(parent, project=plan.project, task_id=plan.task_id,
            run_id=plan.run_id, created_utc=plan.created_utc, dispatch_utc=plan.dispatch_utc,
            acceptance_utc=plan.acceptance_utc, close_utc=plan.close_utc)

        def stopped():
            try:
                self._state(plan)
                return False
            except Exception:
                return True

        session = cs.Session(spec, should_stop=stopped,
            publication_guard=lambda: self.control.publication_guard(plan.project, epoch),
            validate_invariants=self._check_foundation)
        session.initialize()
        self._state(plan)
        foundation_record = cs.encoded({'task_id':plan.task_id,'run_id':plan.run_id,
            'project':plan.project,'epoch':epoch,'constitution':self._foundation_receipt()})
        with self.control.publication_guard(plan.project, epoch):
            self._check_foundation()
            path = session.root / 'CONSTITUTION.json'
            cs.exclusive(path,foundation_record)
            self._foundation_record = (cs,path,foundation_record)
        self._state(plan)
        raw = self._source(cs, source, metadata['source_sha256'])
        session.prepare_public_request(raw)
        self._state(plan)
        self._source(cs, source, metadata['source_sha256'])
        binding_root = parent / ('binding-' + plan.run_id)
        binding_root.mkdir(mode=0o700)
        binding = create_binding(binding_root, session, self.control, epoch=epoch,
            approval_ref=plan.approval_ref, source_path=source)
        binding.prepare()
        self._state(plan)
        self._source(cs, source, metadata['source_sha256'])
        return session, binding, source

    async def prepare(self, plan):
        from atlas_core.coding_owner import _drain
        self._same_owner()
        loop = asyncio.get_running_loop()
        _need(self._loop is None or self._loop is loop, 'wrong_event_loop')
        self._loop = loop
        _need(not self._lock.locked(), 'preparation_busy')
        async with self._lock:
            owner = self.services.initialize_coding_owner()
            _need(owner.status()['status'] == 'disabled', 'owner_unavailable')
            # Keep the lock until an owned preparation thread has really ended,
            # even if the caller cancels its await. No second prep may race it.
            pending = asyncio.create_task(asyncio.to_thread(self._prepare, plan))
            try:
                session, binding, source = await _drain(pending)
            except Exception as error:
                if isinstance(error, FreshPreparationRefused):
                    raise
                raise FreshPreparationRefused('fresh_preparation_failed') from None
            self._state(plan)
            self._source(binding.cs, source, session.spec['task']['source_sha256'])
            status = await self.services.attach_prepared_coding_binding(binding)
            self._prepared = FreshPreparedTask(plan, session, binding, source, status)
            return self._prepared
