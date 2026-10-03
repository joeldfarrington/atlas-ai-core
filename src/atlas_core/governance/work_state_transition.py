"""Host-only, stopped-state Work format transition with no authority migration.

Only the action-ledger reader generation and its transition history change.
Owner policy, foundation, identity, budgets, journal and uncertainty stay intact.
There is no model/HTTP entry point, grant, resume, service restart or task replay.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sqlite3

from .action_boundary import ActionBoundary, identifier, private_identity, sha
from .cognitive_state import CognitiveJournal, digest, encoded, need
from .independent_checker import IndependentChecker
from .owner_foundation import OwnerFoundation, _open_directory, _read_file, _unique_pairs
from .work_admission import PREFIX, admission_status
from .work_state_format import stored_version, validate_format


@dataclass(frozen=True)
class WorkTransitionRequest:
    request_id: str
    owner_reference: str
    from_version: int
    to_version: int
    checkpoint_sha256: str


class WorkStateTransition:
    def __init__(self, services, selection):
        from atlas_core.services import AtlasServices
        from atlas_core.development_control import DevelopmentControl
        from atlas_core import development_control
        from .owner_work import WorkControlSelection, _root
        need(type(services) is AtlasServices and type(selection) is WorkControlSelection,
             'trusted_transition_selection_required')
        need(type(services.development.control) is DevelopmentControl
             and hashlib.sha256(Path(development_control.__file__).read_bytes()).hexdigest()==
             'd7546cd64c795676b7cdef3df502abbc9712cf8f32b067391f2d106499606fe2',
             'original_control_required')
        need(type(services.coding_foundation) is OwnerFoundation,'adopted_foundation_required')
        self.services,self.selection=services,selection
        self.root=_root(services);self.control=services.development.control
        self.foundation=services.coding_foundation;self._pid=os.getpid()
        self.record,self._files,self._ids=self._read()
        self._project=self.record['project']
        need(self._project in self.control.projects,'transition_project')
        self._root_id=private_identity(self.root,True)
        self._actions_id=private_identity(self.root/'actions',True)
        self._ledger_id=private_identity(self.root/'actions/actions.sqlite3')
        self._policy_lock_id=private_identity(self.root/'policy.lock')
        self._journal_id=private_identity(self.root/'journal/cognition.sqlite3')

    def _read(self):
        self.foundation.check_current()
        fd,root_id=_open_directory(self.root)
        try:
            raw,ident=_read_file(fd,'adoption.json',8192)
            need(hashlib.sha256(raw).hexdigest()==self.selection.adoption_sha256,'transition_selection_changed')
            record=json.loads(raw,object_pairs_hook=_unique_pairs)
            keys={'schema','context','owner_reference','atlas_id','run_id','task_id','project',
                  'expected_epoch','constitution_sha256','actions_policy_sha256','worker_policy_sha256','checker_sha256'}
            need(type(record) is dict and set(record)==keys and type(record['schema']) is int
                 and record['schema']==1 and record['context']=='isolated_development'
                 and all(identifier(record[k]) for k in ('owner_reference','atlas_id','run_id','task_id','project'))
                 and type(record['expected_epoch']) is int and record['expected_epoch']>=0
                 and record['constitution_sha256']==self.foundation.selection.document_sha256,
                 'transition_owner_record')
            files={'adoption.json':raw};ids={'root':root_id,'adoption.json':ident}
            for name,key in [('actions-policy.json','actions_policy_sha256'),
                             ('worker-policy.json','worker_policy_sha256'),('checker.json','checker_sha256')]:
                raw,ident=_read_file(fd,name,32768)
                need(sha(record[key]) and hashlib.sha256(raw).hexdigest()==record[key],'transition_policy_changed')
                files[name]=raw;ids[name]=ident
            marker=self.root/'REVOKED'
            if marker.exists() or marker.is_symlink():
                files['REVOKED'],ids['REVOKED']=_read_file(fd,'REVOKED',8192)
        finally:os.close(fd)
        return record,files,ids

    def _current(self):
        from .owner_work import _root
        need(os.getpid()==self._pid and self.services.development.control is self.control
             and self.services.coding_foundation is self.foundation and _root(self.services)==self.root,
             'transition_host_changed')
        record,files,ids=self._read()
        need(record==self.record and files==self._files and ids==self._ids,'transition_custody_changed')
        need(private_identity(self.root,True)==self._root_id
             and private_identity(self.root/'actions',True)==self._actions_id
             and private_identity(self.root/'actions/actions.sqlite3')==self._ledger_id
             and private_identity(self.root/'journal/cognition.sqlite3')==self._journal_id,
             'transition_store_replaced')

    @contextmanager
    def _locks(self,stopped_epoch):
        self._current();handles=[]
        try:
            for name,expected in [('worker-policy.json',self._ids['worker-policy.json'][:2]),
                                  ('policy.lock',self._policy_lock_id)]:
                handle=os.open(self.root/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);handles.append(handle)
                info=os.fstat(handle)
                need((info.st_dev,info.st_ino)==tuple(expected),'transition_lock_changed')
                try:fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
                except BlockingIOError:raise ValueError('transition_work_active') from None
            self._current()
            # Existing canonical DB, not a replacement control. Holding its
            # writer transaction orders the transition against Stop and Resume.
            # No other control method/connection is called while it is held.
            with self.control._db() as control_db:
                control_db.execute('BEGIN IMMEDIATE')
                row=control_db.execute('SELECT epoch,stopped,cleanup,active_write FROM controls WHERE project=?',
                                       (self._project,)).fetchone()
                with self.control._mutex:active=self.control._active.get(self._project,0)
                durable=control_db.execute('SELECT COUNT(*) FROM activities WHERE project=?',(self._project,)).fetchone()[0]
                need(type(stopped_epoch) is int and row==(stopped_epoch,1,0,0)
                     and active==0 and durable==0,'transition_requires_current_stopped_idle_state')
                yield
        finally:
            for handle in reversed(handles):os.close(handle)

    def _sidecars(self):
        # Prevent SQLite from opening a caller-chosen journal/WAL destination.
        for base in (self.root/'actions/actions.sqlite3',self.root/'journal/cognition.sqlite3'):
            for suffix in ('-journal','-wal','-shm'):
                path=Path(str(base)+suffix)
                if path.exists() or path.is_symlink():private_identity(path)

    def _reader(self):
        self._sidecars()
        version=stored_version(self.root/'actions/actions.sqlite3')
        checker=IndependentChecker(self.root/'checker.json',self.record['checker_sha256'],self.root/'scratch')
        reader=ActionBoundary(self.root/'actions',policy_path=self.root/'actions-policy.json',
            policy_sha256=self.record['actions_policy_sha256'],constitution_sha256=self.record['constitution_sha256'],
            observe=lambda _:None,checker=checker,state_version=version)
        identity={'atlas_id':self.record['atlas_id'],'constitution_sha256':self.record['constitution_sha256'],
            'permission_scope_sha256':digest({'actions':self.record['actions_policy_sha256'],
                                             'worker':self.record['worker_policy_sha256']})}
        journal=CognitiveJournal(self.root/'journal',expected_identity=identity)
        return reader,journal

    def _snapshot(self,db,jdb,journal):
        events,head=journal._read(jdb)
        admission=admission_status(journal)
        generation=validate_format(db)
        marker=self.root/'actions/STOP';stop=None
        if marker.exists() or marker.is_symlink():
            handle,_=_open_directory(self.root/'actions')
            try:stop=hashlib.sha256(_read_file(handle,'STOP',8192)[0]).hexdigest()
            finally:os.close(handle)
        rows=db.execute('SELECT id,fingerprint,domain,capability,state,units,result FROM actions ORDER BY id').fetchall()
        audit=db.execute('SELECT seq,body,previous,hash FROM audit ORDER BY seq').fetchall()
        data={'owner_files':{k:hashlib.sha256(v).hexdigest() for k,v in self._files.items()},
            'identity':journal.identity,'journal_head':head,'journal_events':len(events),
            'actions':rows,'audit':audit,'safe_mode_sha256':stop}
        table=db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='state_transitions'").fetchone()
        history=[] if table is None else db.execute('SELECT seq,body,previous,hash FROM state_transitions ORDER BY seq').fetchall()
        checkpoint=digest({'data':data,'generation':generation,'transitions':history})
        return {'generation':generation,'checkpoint_sha256':checkpoint,'preserved_data_sha256':digest(data),
            'journal_events':len(events),'journal_head':head,'actions':len(rows),'units_spent':sum(r[5] for r in rows),
            'requires_recovery':admission['requires_recovery'] or any(r[4] in ('reserved','uncertain') for r in rows),
            'has_shared_admission_history':any(e['subject'].startswith(PREFIX) for e in events),
            'revoked':'REVOKED' in self._files,'safe_mode':stop is not None,'transition_count':len(history),
            'execution_authority':False}

    @contextmanager
    def _state(self,stopped_epoch,*,recover=False):
        with self._locks(stopped_epoch):
            self._sidecars()
            if recover:
                # Explicit owner-host recovery may let SQLite undo its own
                # interrupted transaction. It never restores a stale backup.
                for path in (self.root/'actions/actions.sqlite3',self.root/'journal/cognition.sqlite3'):
                    db=sqlite3.connect(path.as_uri()+'?mode=rw',uri=True,timeout=1)
                    try:need(db.execute('PRAGMA quick_check').fetchall()==[('ok',)],'state_recovery_failed')
                    finally:db.close()
            reader,journal=self._reader()
            with reader._tx() as db:
                with journal._db() as jdb:
                    jdb.execute('BEGIN IMMEDIATE')
                    yield db,jdb,journal
            self._current()

    def inspect(self,*,stopped_epoch):
        with self._state(stopped_epoch) as (db,jdb,journal):
            return self._snapshot(db,jdb,journal)

    def recover(self,*,stopped_epoch):
        with self._state(stopped_epoch,recover=True) as (db,jdb,journal):
            return dict(self._snapshot(db,jdb,journal),sqlite_recovery_checked=True,task_replayed=False)

    def apply(self,request,*,stopped_epoch):
        need(type(request) is WorkTransitionRequest and identifier(request.request_id)
             and type(request.owner_reference) is str and 0<len(request.owner_reference.strip())<=512
             and type(request.from_version) is int and type(request.to_version) is int
             and (request.from_version,request.to_version) in ((1,2),(2,1))
             and sha(request.checkpoint_sha256),'explicit_transition_request_required')
        with self._state(stopped_epoch) as (db,jdb,journal):
            after=self._apply_locked(request,db,jdb,journal)
        self._stage('after_commit')
        return after

    def _apply_locked(self,request,db,jdb,journal):
        """Trusted coordinator only; caller holds the original _state context."""
        need(type(request) is WorkTransitionRequest and identifier(request.request_id)
             and type(request.owner_reference) is str and 0<len(request.owner_reference.strip())<=512
             and type(request.from_version) is int and type(request.to_version) is int
             and (request.from_version,request.to_version) in ((1,2),(2,1))
             and sha(request.checkpoint_sha256),'explicit_transition_request_required')
        before=self._snapshot(db,jdb,journal)
        need(before['generation']==request.from_version and before['checkpoint_sha256']==request.checkpoint_sha256,
             'transition_checkpoint_changed')
        need(request.to_version==2 or not before['has_shared_admission_history'],
             'downgrade_would_ignore_shared_work')
        self._stage('before_write')
        db.execute('CREATE TABLE IF NOT EXISTS state_transitions (seq INTEGER PRIMARY KEY,body TEXT NOT NULL,previous TEXT NOT NULL,hash TEXT NOT NULL)')
        rows=db.execute('SELECT seq,body,previous,hash FROM state_transitions ORDER BY seq').fetchall()
        need(len(rows)<64 and request.request_id not in {json.loads(row[1])['request_id'] for row in rows},
             'transition_duplicate_or_capacity')
        head=rows[-1][3] if rows else digest({'policy':self.record['actions_policy_sha256'],
            'foundation':self.record['constitution_sha256'],'format':1})
        event={'request_id':request.request_id,'owner_reference':request.owner_reference,
            'from':request.from_version,'to':request.to_version,'checkpoint_sha256':request.checkpoint_sha256}
        db.execute('INSERT INTO state_transitions VALUES (?,?,?,?)',
            (len(rows)+1,encoded(event),head,digest({'previous':head,'event':event})))
        db.execute('UPDATE meta SET schema=?',(request.to_version,))
        after=self._snapshot(db,jdb,journal)
        need(after['preserved_data_sha256']==before['preserved_data_sha256'],'transition_data_changed')
        self._current();self._stage('before_commit')
        return after

    @staticmethod
    def _stage(name):
        """Fault-injection seam used only by independent development tests."""
