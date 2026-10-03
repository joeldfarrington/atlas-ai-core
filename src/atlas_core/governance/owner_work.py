"""Explicit host custody for one prepared Work task, not an authority issuer.

The owner provisions fixed private records before selection. Task/model inputs
cannot select paths, issue grants or reset ledgers. No public route, automatic
worker dispatch, credential access or production adoption is provided here.
Files and host objects are not a defence against a hostile OS administrator.
"""
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import threading

from .action_boundary import ActionBoundary, digest, identifier, need, private_identity, sha
from .attention_pipeline import AttentionPipeline
from .cognitive_state import CognitiveJournal, digest as state_digest
from .independent_checker import IndependentChecker
from .owner_foundation import _open_directory, _read_file, _unique_pairs
from .prepared_work_state import PreparedWorkObservation
from .work_admission import SharedWorkAdmission, admission_status
from .work_state_format import stored_version


@dataclass(frozen=True)
class WorkControlSelection:
    adoption_sha256: str


def _root(services):
    root=Path(services.config.app.identity_dir)/'coding-work'
    need(root.is_absolute() and '..' not in root.parts, 'work_custody_path')
    prohibited=[services.config.app.workspace_dir, services.config.app.data_dir]
    prohibited += [p.root for p in services.development.projects.values()]
    for item in prohibited:
        other=Path(item)
        need(other.is_absolute() and '..' not in other.parts
             and not any(p.is_symlink() for p in (other,*other.parents)), 'work_scope_path')
        need(not root.is_relative_to(other) and not other.is_relative_to(root), 'work_custody_overlaps_tools')
    return root


class OwnerWorkControls:
    def __init__(self, services, prepared, selection):
        from atlas_core.services import AtlasServices
        from .heartbeat import AtlasHeartbeat
        need(type(services) is AtlasServices and type(selection) is WorkControlSelection
             and sha(selection.adoption_sha256), 'explicit_work_selection_required')
        observer=services.coding_action_observation
        need(type(observer) is PreparedWorkObservation and observer.services is services
             and observer.prepared is prepared, 'prepared_observer_required')
        need(type(services.heartbeat) is AtlasHeartbeat and services.heartbeat.attention is None,
             'existing_unbound_heartbeat_required')
        self.services,self.prepared,self.observer=services,prepared,observer
        self.selection=selection;self.root=_root(services);self._root=self.root
        self._pid=os.getpid();self._failed=False;self._attached=False
        self._mutex=threading.RLock();self._guard_local=threading.local()
        self._selected=selection;self._runner=None
        self._heartbeat=services.heartbeat
        self.record,self._identities,self._raw=self._read()
        record=self.record
        need(set(record)=={'schema','context','owner_reference','atlas_id','run_id','task_id',
             'project','expected_epoch','constitution_sha256','actions_policy_sha256',
             'worker_policy_sha256','checker_sha256'}, 'work_adoption_schema')
        need(type(record['schema']) is int and record['schema']==1
             and record['context']=='isolated_development'
             and all(identifier(record[k]) for k in ('owner_reference','atlas_id','run_id','task_id','project')),
             'owner_work_adoption')
        need(record['run_id']==prepared.plan.run_id and record['task_id']==prepared.plan.task_id
             and record['project']==prepared.plan.project
             and type(record['expected_epoch']) is int and record['expected_epoch']==prepared.plan.expected_epoch
             and record['constitution_sha256']==observer._foundation, 'work_adoption_task_binding')
        identity={'atlas_id':record['atlas_id'],'constitution_sha256':record['constitution_sha256'],
                  'permission_scope_sha256':state_digest({'actions':record['actions_policy_sha256'],
                                                         'worker':record['worker_policy_sha256']})}
        # Never create a journal/ledger during binding: a missing store is a
        # recovery problem, not an empty budget or a new developmental history.
        for name in ('journal','actions','scratch'):
            private_identity(self.root/name, True)
        private_identity(self.root/'actions/actions.sqlite3')
        self.journal=CognitiveJournal(self.root/'journal',expected_identity=identity)
        self.attention=AttentionPipeline(self.journal,custody_check=self.check_current)
        self.checker=IndependentChecker(self.root/'checker.json',record['checker_sha256'],self.root/'scratch')
        self._state_version=stored_version(self.root/'actions/actions.sqlite3')
        from .work_release import enforce_release_for_services
        enforce_release_for_services(services,self.root,self._state_version)
        self.boundary=ActionBoundary(self.root/'actions',policy_path=self.root/'actions-policy.json',
            policy_sha256=record['actions_policy_sha256'],constitution_sha256=record['constitution_sha256'],
            observe=self.observe,checker=self.checker,publication_guard=self.publication_guard,
            policy_guard=self.guard,state_version=self._state_version)
        self.admission=SharedWorkAdmission(journal=self.journal,run_id=record['run_id'],
            lock_path=self.root/'worker-policy.json',lock_identity=self._identities['worker-policy.json'],
            custody_check=self.check_current,inspect=self._work_available,confirm=self._work_outcome)
        self.boundary.work_admission=self.admission
        self._objects=(self.journal,self.attention,self.boundary,self.checker,self.observer,self.admission)
        self.check_current()
        current=self.observer(prepared.plan.task_id)
        from atlas_core.coding_execution import registered_task_packet
        # Validate the exact worker grant before attaching anything to services.
        # Reading a grant is not spending it or invoking a model.
        services.coding_constitution.assess(registered_task_packet(services,prepared),
            operation='check_candidate',authority=self.read(),observations={
                'now_utc':datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                'source_sha256':current['source_sha256'],'project':prepared.plan.project,
                'control_epoch':current['epoch'],'stopped':current['stopped'],
                'resources_ok':current['resources_ok']})

    def _read(self):
        handle,root_identity=_open_directory(self.root)
        try:
            adoption,adoption_id=_read_file(handle,'adoption.json',8192)
            need(digest(adoption)==self.selection.adoption_sha256,'work_adoption_changed')
            record=json.loads(adoption,object_pairs_hook=_unique_pairs)
            need(type(record) is dict,'work_adoption_schema')
            ids={'root':root_identity,'adoption':adoption_id};raw={'adoption':adoption}
            for name,key in [('actions-policy.json','actions_policy_sha256'),
                             ('worker-policy.json','worker_policy_sha256'),
                             ('checker.json','checker_sha256')]:
                data,ident=_read_file(handle,name,32768)
                need(sha(record.get(key)) and digest(data)==record[key], 'work_selected_file_changed')
                ids[name]=ident;raw[name]=data
        finally:os.close(handle)
        ids['lock']=private_identity(self.root/'policy.lock')
        return record,ids,raw

    def check_current(self):
        try:
            need(not self._failed and os.getpid()==self._pid and self.selection is self._selected
                 and self.root==self._root and _root(self.services)==self._root, 'work_custody_stopped')
            need(not (self.root/'REVOKED').exists() and not (self.root/'REVOKED').is_symlink(), 'work_revoked')
            record,identities,raw=self._read()
            need(record==self.record and identities==self._identities and raw==self._raw,'work_custody_changed')
            need(self.services.coding_action_observation is self.observer
                 and self.services.heartbeat is self._heartbeat, 'work_host_changed')
            if self._attached:
                need(self.services.coding_work_controls is self
                     and self._heartbeat.attention is self.attention
                     and self._objects==(self.journal,self.attention,self.boundary,self.checker,self.observer,self.admission)
                     and self.attention.journal is self.journal
                     and self.boundary.work_admission is self.admission
                     and self.boundary.state_version == self._state_version
                     and self.boundary.checker is self.checker
                     and self.boundary.policy_path==self.root/'actions-policy.json'
                     and self.boundary.policy_sha256==record['actions_policy_sha256'], 'work_binding_changed')
            self.services.coding_foundation.check_current()
            from .work_release import enforce_release_for_services
            enforce_release_for_services(self.services,self.root,self._state_version)
        except Exception:
            self._failed=True
            raise ValueError('work_custody_stopped') from None

    def read(self):
        """Fixed worker policy for the existing RegisteredCodingExecution."""
        with self._mutex:
            self.check_current()
            return json.loads(self._raw['worker-policy.json'],object_pairs_hook=_unique_pairs)

    @contextmanager
    def guard(self):
        # All supported revocation uses this lock. Direct file replacement is
        # detected and latched; a hostile host writer is outside this boundary.
        with self._mutex:
            need(not getattr(self._guard_local,'held',False),'nested_work_policy_guard')
            fd=os.open(self.root/'policy.lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            try:
                need((os.fstat(fd).st_dev,os.fstat(fd).st_ino)==self._identities['lock'],'work_lock_changed')
                fcntl.flock(fd,fcntl.LOCK_SH|fcntl.LOCK_NB)
                self.check_current();self._guard_local.held=True
                try:yield
                finally:self._guard_local.held=False
            finally:os.close(fd)

    def revoke(self):
        """Reduce this selected authority; no renewal or grant method exists."""
        with self._mutex:
            need(not getattr(self._guard_local,'held',False),'revocation_during_publication')
            self.check_current()
            fd=os.open(self.root/'policy.lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            try:
                need((os.fstat(fd).st_dev,os.fstat(fd).st_ino)==self._identities['lock'],'work_lock_changed')
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                marker=os.open(self.root/'REVOKED',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(marker,'wb') as stream:
                    stream.write(b'Owner revoked this task. No automatic resume.\n');stream.flush();os.fsync(stream.fileno())
                self._failed=True
            finally:os.close(fd)

    def observe(self, task_id):
        self.check_current()
        return self.observer(task_id)

    @contextmanager
    def publication_guard(self, task_id):
        with self.guard():
            with self.observer.publication_guard(task_id):
                yield

    def execution(self):
        """Bind the existing registered worker; never invoke it automatically."""
        from atlas_core.coding_execution import RegisteredCodingExecution
        with self._mutex:
            self.check_current()
            need(self._runner is None,'work_execution_already_bound')
            runner=RegisteredCodingExecution(self.services,self.prepared,journal=self.journal,
                owner_policy=self,resources_ok=self.observer.resources_ok,work_admission=self.admission)
            runner.loop.authorize('check_candidate')
            self._runner=runner
            return runner

    def _registered_outcome(self):
        from atlas_core.coding_execution import registered_task_packet, recover_registered_execution
        return recover_registered_execution(self.prepared.session,
            registered_task_packet(self.services,self.prepared),self.journal)

    def _work_available(self):
        # Inspect both pre-existing ledgers as well as the new admission journal.
        # A missing coding journal event cannot erase a preserved worker intent.
        actions=self.boundary.status()
        if actions['requires_recovery'] or actions['safe_mode']:return False
        registered=self._registered_outcome()
        if registered['state'] in ('accepted','failed'):return True
        session=self.prepared.session
        markers=('WORKER_INTENT.json','WORKER_REQUEST.json','WORKER_RETURN.json',
                 'WORKER_SOURCE.bin','WORKER_VERIFICATION.json','ACCEPT_INTENT.json','RESULT.json')
        return registered['state']=='not_started' and not any(session._has(name) for name in markers)

    def _work_outcome(self, lane, request_id):
        # Pure historical verification after publication: an owner Stop/revoke
        # ordered after a completed commit must not erase that completed outcome.
        if lane=='supplemental':
            result=self.boundary.status()
            rows=[r for r in result['actions'] if r['id']==request_id]
            need(not result['requires_recovery'] and len(rows)==1
                 and rows[0]['state'] in ('verified','failed'),'work_outcome_unconfirmed')
            state=rows[0]['state']
        else:
            need(request_id=='coding-'+self.record['run_id'],'work_outcome_task')
            result=self._registered_outcome();state=result['state']
            need(state in ('accepted','failed'),'work_outcome_unconfirmed')
        return dict(lane=lane,state=state,record_sha256=state_digest(result))

    def summary(self):
        self.check_current()
        return {'run_id':self.record['run_id'],'task_id':self.record['task_id'],
            'context':'isolated_development','journal':self.journal.checkpoint(),
            'action_status':self.boundary.status(),'heartbeat_mode':self._heartbeat.status()['mode'],
            'work_admission':admission_status(self.journal),
            'model_calls':0,'creates_authority':False,'automatic_dispatch':False,'installed':False}


def select_for_services(services, prepared, selection):
    from atlas_core.services import AtlasServices
    need(type(services) is AtlasServices and services.coding_work_controls is None,
         'work_controls_already_selected')
    controls=OwnerWorkControls(services,prepared,selection)
    controls.summary()
    services.coding_work_controls=controls
    services.heartbeat.attention=controls.attention
    controls._attached=True
    return controls
