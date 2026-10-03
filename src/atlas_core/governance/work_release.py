"""Stopped-host source/state release; no activation, grants, shell or network.

The coordinator runs from the separately verified package, never imports files
while replacing them, and does not restore database snapshots. Owner-host only.
Private custody protects against worker access, not a hostile administrator.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
from types import MappingProxyType

from .action_boundary import identifier, private_identity, sha
from .cognitive_state import digest, encoded, need
from .owner_foundation import _unique_pairs
from .work_state_transition import WorkStateTransition, WorkTransitionRequest


@dataclass(frozen=True)
class ReleaseSelection:
    package_root: Path
    manifest_sha256: str


def _file(path,maximum=1048576):
    need(not any(p.is_symlink() for p in (path,*path.parents)),'release_symlink')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and st.st_nlink==1
             and 0<=st.st_size<=maximum and not st.st_mode & 0o022,'release_file_identity')
        # A regular-file read may legally return fewer bytes than requested.
        # Bound the total to the observed size plus one byte to detect growth.
        chunks=[];remaining=st.st_size+1
        while remaining:
            chunk=os.read(fd,remaining)
            if not chunk:break
            chunks.append(chunk);remaining-=len(chunk)
        raw=b''.join(chunks)
        end=os.fstat(fd)
        need(len(raw)==st.st_size and (st.st_ino,st.st_mtime_ns,st.st_ctime_ns,st.st_size)==
             (end.st_ino,end.st_mtime_ns,end.st_ctime_ns,end.st_size),'release_file_changed')
        return raw
    finally:os.close(fd)


def _stable_file(path, maximum=1048576):
    # Discard an unstable snapshot and take at most one fresh strict snapshot.
    # Never retry identity/symlink refusals or parse partial bytes. This is a
    # read only retry: all caller hash, receipt and lineage checks still apply.
    try:
        return _file(path, maximum)
    except ValueError as error:
        if str(error) != 'release_file_changed':
            raise
        return _file(path, maximum)


def _sha(path):
    return hashlib.sha256(_stable_file(path)).hexdigest()


def _sync_dir(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def _atomic(path,raw,mode=0o600):
    temp=path.with_name(path.name+'.atlas-release-part')
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    try:
        with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
        os.replace(temp,path);_sync_dir(path.parent)
    finally:
        if temp.exists():temp.unlink()


# Exact versioned, non-executable public exercise requirements. These are
# package data, never authority or instructions to the release operator.
PUBLIC_EXERCISE_DATA = MappingProxyType({'src/atlas_core/coding_connection/session-code/trusted_baseline/public/quantity-test-repair/PROBLEM.md': '802b71185d890d6533a324ee19851d27d86e8da036f9791c5dc1eec353157497', 'src/atlas_core/coding_connection/session-code/trusted_baseline/public/ready-jobs-feature/PROBLEM.md': 'c8fff7a44a4a08c0bf7d1b4e7dbcc1c1d52afa95faa68868b4da07f8c16bf7fb', 'src/atlas_core/coding_connection/session-code/trusted_baseline/public/terminal-count-refactor/PROBLEM.md': '9d2cc37340d7b349f0bbdacdfc7076b8b1b883f2b13d0a61a491a9085bc64fda', 'src/atlas_core/coding_connection/session-code/trusted_deadline/public/review-deadline-budget/PROBLEM.md': '0438ebb22133cd4f1cd7046ab5b2fa09ca7373685f516e3a9d5c66fc2c5f374c', 'src/atlas_core/coding_connection/session-code/trusted_deadline/public/review-deadline-budget/PROVENANCE.json': '5bfd010e26c129c0ebb4827dce12ed6dc64c82520e7abe0650d0c27884c56920'})


def _rows(manifest):
    need(type(manifest) is dict and set(manifest)=={'schema','release_id','owner_reference','files'},'release_manifest')
    need(type(manifest['schema']) is int and manifest['schema']==1 and identifier(manifest['release_id'])
         and type(manifest['owner_reference']) is str and 0<len(manifest['owner_reference'].strip())<=512,
         'release_identity')
    rows=manifest['files'];need(type(rows) is list and 0<len(rows)<=64,'release_size');seen=set()
    for row in rows:
        need(type(row) is dict and set(row)=={'path','before_sha256','after_sha256'},'release_row')
        name=row['path'];need(type(name) is str,'release_path')
        path=Path(name)
        need(path.as_posix()==name and not path.is_absolute() and '..' not in path.parts
             and len(path.parts)>=3 and path.parts[:2]==('src','atlas_core')
             and (path.suffix=='.py' or name in PUBLIC_EXERCISE_DATA)
             and name not in seen and not any(part in {'resources','__pycache__'} for part in path.parts),
             'release_path')
        need((row['before_sha256'] is None or sha(row['before_sha256'])) and sha(row['after_sha256'])
             and row['before_sha256']!=row['after_sha256'],'release_hashes')
        if name in PUBLIC_EXERCISE_DATA:
            need(row['after_sha256']==PUBLIC_EXERCISE_DATA[name], 'release_public_data_version')
        seen.add(name)
    return rows


def _receipt(root):
    private_identity(root,True);path=root/'receipt.json';private_identity(path)
    value=json.loads(_stable_file(path,262144),object_pairs_hook=_unique_pairs)
    need(type(value) is dict and set(value)=={'schema','release_id','manifest_sha256','target_root',
        'manifest','initial_state','events'},'release_receipt')
    need(value['schema']==1 and sha(value['manifest_sha256']) and
         digest(value['manifest'])==value['manifest_sha256'],'release_receipt_binding')
    _rows(value['manifest']);need(value['release_id']==value['manifest']['release_id'],'release_receipt_binding')
    head=digest({k:v for k,v in value.items() if k!='events'});events=value['events']
    need(type(events) is list and 0<len(events)<=32,'release_event_count')
    stages=[]
    for event in events:
        need(type(event) is dict and set(event)=={'stage','previous','hash'},'release_event')
        stage=event['stage'];need(stage in {'prepared','source_installed','installed','rollback_started','rolled_back'},'release_stage')
        need(event['previous']==head and event['hash']==digest({'previous':head,'stage':stage}),'release_event_chain')
        stages.append(stage);head=event['hash']
    allowed=[['prepared'],['prepared','source_installed'],['prepared','source_installed','installed']]
    need(stages in allowed or (stages[-1:] in (['rollback_started'],['rolled_back']) and
         (stages[:-1] in allowed or stages[-2:]==['rollback_started','rolled_back'] and stages[:-2] in allowed)),
         'release_stage_order')
    return value


def release_gate(work_root,source_root,generation,*,required=False):
    """Installed Work calls this before attaching and on every authority read.

    A present release marker must validate; its removal is not a supported
    recovery operation. Legacy isolated fixtures have no release installation.
    """
    root=work_root/'release'
    if not root.exists() and not root.is_symlink() and not required:return
    record=_receipt(root)
    need(record['events'][-1]['stage']=='installed' and generation==2,'release_not_ready')
    need(Path(record['target_root'])==source_root,'release_target_changed')
    for row in _rows(record['manifest']):
        need(_sha(source_root/row['path'])==row['after_sha256'],'release_source_changed')


def enforce_release_for_services(services,work_root,generation):
    # Actual installed source must have a verified release record. Legacy
    # isolated fixtures import from a different, pinned development tree.
    source_root=Path(services.config.project_root)
    installed_here=Path(__file__).resolve().parents[3]==source_root
    release_gate(work_root,source_root,generation,required=installed_here)


class WorkRelease:
    def __init__(self,transition,selection):
        need(type(transition) is WorkStateTransition and type(selection) is ReleaseSelection
             and isinstance(selection.package_root,Path) and sha(selection.manifest_sha256),'trusted_release_selection')
        self.transition=transition;self.selection=selection
        self.target=Path(transition.services.config.project_root)
        self.target_id=private_identity(self.target,True)
        self.root=transition.root/'release'
        self.package=selection.package_root
        private_identity(self.package,True)
        need(not self.package.is_relative_to(self.target) and not self.target.is_relative_to(self.package),
             'release_package_compartment')
        raw=_file(self.package/'manifest.json',65536)
        self.manifest=json.loads(raw,object_pairs_hook=_unique_pairs)
        need(digest(self.manifest)==selection.manifest_sha256,'release_manifest_changed')
        self.rows=_rows(self.manifest);self._id=self.manifest['release_id']
        self._check_package()

    def _target_identity(self):
        return private_identity(self.target,True)

    def _check_package(self):
        need(self._target_identity()==self.target_id,'release_target_replaced')
        need(digest(json.loads(_file(self.package/'manifest.json'),object_pairs_hook=_unique_pairs))==
             self.selection.manifest_sha256,'release_manifest_changed')
        for row in self.rows:
            for side in ('before','after'):
                expected=row[side+'_sha256']
                if expected is not None:need(_sha(self.package/side/row['path'])==expected,'release_package_changed')

    def _sources(self,which):
        for row in self.rows:
            target=self.target/row['path']
            need(not any(p.is_symlink() for p in (target,*target.parents)),'release_symlink')
            actual=_sha(target) if target.exists() else None
            expected={row[x+'_sha256'] for x in which}
            need(actual in expected,'release_source_drift')

    def _read(self):
        record=_receipt(self.root)
        need(record['manifest_sha256']==self.selection.manifest_sha256 and record['manifest']==self.manifest
             and record['target_root']==str(self.target),'release_receipt_binding')
        return record

    def _event(self,record,stage):
        need(len(record['events'])<32,'release_event_count')
        head=record['events'][-1]['hash'] if record['events'] else digest({k:v for k,v in record.items() if k!='events'})
        record['events'].append({'stage':stage,'previous':head,'hash':digest({'previous':head,'stage':stage})})
        _atomic(self.root/'receipt.json',encoded(record).encode())

    def _prepare(self,before):
        need(not self.root.exists() and not self.root.is_symlink(),'release_already_exists')
        self.root.mkdir(mode=0o700);_sync_dir(self.root.parent)
        record={'schema':1,'release_id':self._id,'manifest_sha256':self.selection.manifest_sha256,
            'target_root':str(self.target),'manifest':self.manifest,'initial_state':before,'events':[]}
        self._event(record,'prepared');return record

    def _replace(self,side):
        for index,row in enumerate(self.rows):
            self._check_package();self._sources(('before','after'))
            target=self.target/row['path'];expected=row[side+'_sha256']
            actual=_sha(target) if target.exists() else None
            if actual!=expected:
                if expected is None:
                    target.unlink();_sync_dir(target.parent)
                else:
                    target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
                    need(not any(x.is_symlink() for x in (target,*target.parents)),'release_symlink')
                    mode=stat.S_IMODE(target.stat().st_mode) if target.exists() else 0o600
                    _atomic(target,_file(self.package/side/row['path']),mode)
            self._stage(side+':'+str(index))

    def _transition(self,db,jdb,journal,to,checkpoint):
        if checkpoint['generation']==to:return checkpoint
        request=WorkTransitionRequest(self._id+('-upgrade' if to==2 else '-rollback'),
            self.manifest['owner_reference'],checkpoint['generation'],to,checkpoint['checkpoint_sha256'])
        return self.transition._apply_locked(request,db,jdb,journal)

    def install(self,*,stopped_epoch):
        self._check_package()
        with self.transition._state(stopped_epoch) as (db,jdb,journal):
            before=self.transition._snapshot(db,jdb,journal)
            self._sources(('before',));record=self._prepare(before)
            self._stage('prepared');self._replace('after');self._sources(('after',))
            self._event(record,'source_installed');self._stage('source_installed')
            after=self._transition(db,jdb,journal,2,before)
            self._stage('before_state_commit')
        self._stage('after_state_commit')
        # No readiness claim is persisted until the state transaction commits.
        with self.transition._state(stopped_epoch) as (db,jdb,journal):
            current=self.transition._snapshot(db,jdb,journal)
            need(current['generation']==2 and current['preserved_data_sha256']==before['preserved_data_sha256'],
                 'release_state_changed')
            self._sources(('after',));self._event(self._read(),'installed')
        return self.status(stopped_epoch=stopped_epoch)

    def rollback(self,*,stopped_epoch):
        self._check_package()
        with self.transition._state(stopped_epoch,recover=True) as (db,jdb,journal):
            current=self.transition._snapshot(db,jdb,journal);record=self._read()
            need(record['events'][-1]['stage']!='rolled_back','release_already_rolled_back')
            self._sources(('before','after'))
            need(not current['has_shared_admission_history'],'downgrade_would_ignore_shared_work')
            # A newer pending budget/history is never replaced by initial_state.
            self._transition(db,jdb,journal,1,current)
            if record['events'][-1]['stage']!='rollback_started':self._event(record,'rollback_started')
            self._stage('rollback_started');self._replace('before');self._sources(('before',))
        self._stage('after_rollback_state_commit')
        with self.transition._state(stopped_epoch) as (db,jdb,journal):
            self._sources(('before',));need(self.transition._snapshot(db,jdb,journal)['generation']==1,'rollback_state')
            self._event(self._read(),'rolled_back')
        return self.status(stopped_epoch=stopped_epoch)

    def recover(self,*,stopped_epoch):
        """Only finish verification of committed install; otherwise stay blocked.

        Finishing or reversing partially replaced source requires explicit host
        rollback. Recovery never repeats installation writes or any Work task.
        """
        self._check_package()
        with self.transition._state(stopped_epoch,recover=True) as (db,jdb,journal):
            state=self.transition._snapshot(db,jdb,journal);record=self._read()
            stage=record['events'][-1]['stage'];self._sources(('before','after'))
            if stage=='source_installed' and state['generation']==2:
                self._sources(('after',))
                need(state['preserved_data_sha256']==record['initial_state']['preserved_data_sha256'],'release_state_changed')
                self._event(record,'installed')
            elif stage=='rollback_started' and state['generation']==1:
                self._sources(('before',));self._event(record,'rolled_back')
        return self.status(stopped_epoch=stopped_epoch)

    def status(self,*,stopped_epoch):
        with self.transition._state(stopped_epoch) as (db,jdb,journal):
            state=self.transition._snapshot(db,jdb,journal);record=self._read()
            stage=record['events'][-1]['stage'];self._check_package();self._sources(('before','after'))
            ready=stage=='installed' and state['generation']==2
            if ready:self._sources(('after',))
            return {'release_id':self._id,'stage':stage,'installation_verified':ready,
                'work_available':False,
                'requires_owner_reconciliation':any(state[k] for k in ('requires_recovery','revoked','safe_mode')),
                'state':state,'execution_authority':False,'task_replayed':False,'service_restarted':False}

    @staticmethod
    def _stage(name):
        """Independent fixture fault-injection seam; never a model callback."""
