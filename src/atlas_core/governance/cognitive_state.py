"""Small persistent development-state layer; no model, tool or authority issuer.

The existing execution host owns permissions and worker lifetimes. This journal
adds continuity/provenance around those operations; it is not another job queue.
"""
from contextlib import contextmanager, closing
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time

KINDS = {'observation','belief','goal','plan','critique','prediction','action',
         'verification','reflection','skill_candidate','capability','model_change'}
BASES = {'observed','user_provided','inference','model_output','tested','hypothesis'}
ORIGINS = {'user_assigned','standing_responsibility','atlas_generated'}
STATES = {'open','waiting','completed','cancelled','blocked'}
MAX_EVENTS = 1000

def need(ok, reason):
    if not ok: raise ValueError(reason)

def encoded(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)

def digest(value): return hashlib.sha256(encoded(value).encode()).hexdigest()

def identifier(value):
    return type(value) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}',value)

def timestamp(value): return type(value) is int and 0 <= value < 10**11

def validate_event(value):
    need(type(value) is dict and set(value) == {'id','kind','basis','subject','occurred_at',
        'recorded_at','verified_at','expires_at','evidence','supersedes','value'},'event_schema')
    need(identifier(value['id']) and identifier(value['subject']),'event_identity')
    need(type(value['kind']) is str and value['kind'] in KINDS and
         type(value['basis']) is str and value['basis'] in BASES,'event_classification')
    need(timestamp(value['occurred_at']) and timestamp(value['recorded_at']) and
         value['occurred_at'] <= value['recorded_at'],'event_time')
    verified,expiry = value['verified_at'],value['expires_at']
    need(verified is None or timestamp(verified) and value['occurred_at'] <= verified <= value['recorded_at'],
         'verification_time')
    need(expiry is None or timestamp(expiry) and expiry >= value['occurred_at'],'expiry_time')
    evidence = value['evidence']
    need(type(evidence) is list and len(evidence) <= 12 and all(type(x) is str and
         re.fullmatch(r'sha256:[0-9a-f]{64}',x) for x in evidence),'evidence_refs')
    need(value['basis'] != 'tested' or verified is not None and evidence,'tested_needs_evidence')
    need(value['kind'] != 'verification' or value['basis'] == 'tested' and
         verified is not None and evidence,'verification_needs_tested_evidence')
    need(value['supersedes'] is None or identifier(value['supersedes']),'revision_identity')
    raw = encoded(value)
    need(len(raw.encode()) <= 8192,'event_size')
    if value['kind'] == 'goal':
        item = value['value']
        need(type(item) is dict and set(item) == {'origin','status','priority','not_before','expires_at'},'goal_schema')
        need(type(item['origin']) is str and item['origin'] in ORIGINS and
             type(item['status']) is str and item['status'] in STATES,'goal_classification')
        need(type(item['priority']) is int and 0 <= item['priority'] <= 100 and
             timestamp(item['not_before']) and (item['expires_at'] is None or
             timestamp(item['expires_at']) and item['expires_at'] >= item['not_before']), 'goal_bounds')
    return json.loads(raw)


class CognitiveJournal:
    """Append-only, bounded local evidence with explicit identity and revisions."""
    @classmethod
    def create(cls, root, identity):
        need(type(identity) is dict and set(identity) == {'atlas_id','constitution_sha256',
             'permission_scope_sha256'},'identity_schema')
        need(identifier(identity['atlas_id']) and all(type(identity[k]) is str and
             re.fullmatch(r'[0-9a-f]{64}',identity[k]) for k in
             ('constitution_sha256','permission_scope_sha256')),'identity_fields')
        root = Path(root).absolute()
        need(not any(p.is_symlink() for p in (root,*root.parents)),'state_symlink')
        root.mkdir(mode=0o700,exist_ok=False)
        path = root/'cognition.sqlite3'
        fd = os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600); os.close(fd)
        with closing(sqlite3.connect(path)) as db:
            with db:
                db.execute('CREATE TABLE identity (value TEXT NOT NULL)')
                db.execute('INSERT INTO identity VALUES (?)',(encoded(identity),))
                db.execute('CREATE TABLE events (seq INTEGER PRIMARY KEY, id TEXT UNIQUE NOT NULL, body TEXT NOT NULL, previous TEXT NOT NULL, hash TEXT NOT NULL)')
        return cls(root,expected_identity=identity)

    def __init__(self, root, *, expected_identity=None, read_only=False):
        self.root = Path(root).absolute(); self.path = self.root/'cognition.sqlite3'
        self.read_only = read_only
        self._root_id = self._identity(self.root,True)
        self._file_id = self._identity(self.path,False)
        with self._db() as db:
            rows = db.execute('SELECT value FROM identity').fetchall()
        need(len(rows) == 1,'identity_record')
        self.identity = json.loads(rows[0][0])
        need(expected_identity is None or self.identity == expected_identity,'identity_changed')
        self.identity_hash = digest(self.identity)

    @staticmethod
    def _identity(path, directory):
        need(not any(p.is_symlink() for p in (path,*path.parents)),'state_symlink')
        info = path.lstat()
        need((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)) and
             info.st_uid == os.getuid() and info.st_mode & 0o077 == 0 and
             (directory or info.st_nlink == 1),'state_private_identity')
        return info.st_dev,info.st_ino

    @contextmanager
    def _db(self):
        need(self._identity(self.root,True) == self._root_id and
             self._identity(self.path,False) == self._file_id,'state_replaced')
        db = sqlite3.connect(self.path.as_uri()+('?mode=ro' if self.read_only else '?mode=rw'),uri=True,timeout=1)
        try:
            with db: yield db
        finally: db.close()

    def _read(self, db):
        identity = db.execute('SELECT value FROM identity').fetchall()
        need(len(identity) == 1 and digest(json.loads(identity[0][0])) == self.identity_hash,'identity_changed')
        rows = db.execute('SELECT seq,id,body,previous,hash FROM events ORDER BY seq LIMIT ?',
                          (MAX_EVENTS+1,)).fetchall()
        need(len(rows) <= MAX_EVENTS,'event_capacity')
        result,head = [],self.identity_hash
        for index,(seq,event_id,raw,previous,stored_hash) in enumerate(rows,1):
            item = validate_event(json.loads(raw))
            need(seq == index and item['id'] == event_id and previous == head and
                 digest({'previous':head,'event':item}) == stored_hash,'event_chain_changed')
            result.append(item); head = stored_hash
        return result,head

    def events(self):
        with self._db() as db: return self._read(db)[0]

    def append(self, event):
        need(not self.read_only,'read_only_journal')
        item = validate_event(event)
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            events,head = self._read(db)
            prior = {x['id']:x for x in events}
            if item['id'] in prior:
                need(item == prior[item['id']],'conflicting_event_identity')
                return False
            need(len(events) < MAX_EVENTS,'event_capacity')
            need(not events or item['recorded_at'] >= events[-1]['recorded_at'],'recording_time_reversed')
            if item['supersedes'] is not None:
                old = prior.get(item['supersedes'])
                need(old is not None and old['subject'] == item['subject'] and old['kind'] == item['kind'],
                     'invalid_revision')
                need(item['supersedes'] not in {x['supersedes'] for x in events},'revision_branch')
            db.execute('INSERT INTO events VALUES (?,?,?,?,?)',(len(events)+1,item['id'],encoded(item),
                head,digest({'previous':head,'event':item})))
        return True

    def checkpoint(self):
        with self._db() as db: events,head = self._read(db)
        return {'identity_sha256':self.identity_hash,'events':len(events),'history_sha256':head,
                'execution_authority':False}

    def belief(self, subject, now):
        need(timestamp(now),'observation_time')
        events = [x for x in self.events() if x['recorded_at'] <= now]
        replaced = {x['supersedes'] for x in events}
        claims = [x for x in events if x['subject'] == subject and x['kind'] in ('belief','observation')
            and x['id'] not in replaced and x['occurred_at'] <= now and
            (x['expires_at'] is None or now < x['expires_at'])
            and (x['kind'] != 'observation' or now < x['recorded_at']+300)]
        if not claims: return {'state':'unknown','claims':[]}
        if len({encoded(x['value']) for x in claims}) > 1:
            return {'state':'contradicted','claims':claims}
        verified = all(x['basis'] in ('observed','tested') and x['verified_at'] is not None
                       and x['verified_at'] <= now and x['evidence'] for x in claims)
        return {'state':'verified' if verified else 'unverified','claims':claims}


def attention_tick(journal, now, *, selector, resources_ok=True):
    """Cheap observation only. It cannot call a model, execute work or notify."""
    need(timestamp(now) and type(resources_ok) is bool,'tick_observation')
    events = [x for x in journal.events() if x['recorded_at'] <= now]
    replaced = {x['supersedes'] for x in events}
    current = [x for x in events if x['id'] not in replaced and x['recorded_at'] <= now]
    unresolved = {x['subject'] for x in current if x['kind'] == 'action'} - {
        x['subject'] for x in current if x['kind'] == 'verification' and type(x['value']) is dict
        and (x['value'].get('response_complete') is True or x['value'].get('cleanup_verified') is True)}
    base = {'execution_authority':False,'model_invoked':False,'notify':False}
    if unresolved:
        return dict(base,state='reconcile',subjects=sorted(unresolved),reason='Recorded work has no verified outcome; do not replay.')
    if not resources_ok:
        return dict(base,state='quiet',reason='Resources are reserved or unavailable.')
    goals = [dict(x['value'],id=x['subject']) for x in current if x['kind'] == 'goal']
    need(len({x['id'] for x in goals}) == len(goals),'conflicting_goal_versions')
    selected = selector(goals,now)
    need(selected is None or type(selected) is str and selected in {x['id'] for x in goals},'unknown_selected_goal')
    if selected is None: return dict(base,state='quiet',reason='Nothing eligible needs attention.')
    goal = next(x for x in goals if x['id'] == selected)
    need(goal['status'] == 'open' and goal['not_before'] <= now and
         (goal['expires_at'] is None or now < goal['expires_at']),'ineligible_selected_goal')
    return dict(base,state='consider',goal_id=selected,origin=goal['origin'],
                reason='Eligible goal; planning is separate from permission to act.')


def observe_heartbeat(journal, *, selector, ticks=1, interval=1.0, clock=time.time):
    """Foreground bounded driver. Existing scheduler/service integration is separate."""
    need(type(ticks) is int and 1 <= ticks <= 60 and type(interval) in (int,float)
         and 0 <= interval <= 5,'heartbeat_limits')
    for index in range(ticks):
        yield attention_tick(journal,int(clock()),selector=selector)
        if index+1 < ticks: time.sleep(interval)
