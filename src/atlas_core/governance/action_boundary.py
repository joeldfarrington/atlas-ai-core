"""Trusted-host action boundary. Models submit proposals, never policies.

Development integration: the owner binds an immutable policy and an independent
checker. The broker has no grant, shell, credential, network or promotion API.
Its private directory must remain outside every worker's OS write/read scope.
Hash chains detect corruption, not a hostile administrator rewriting the DB.
"""
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time


class Refused(ValueError):
    pass


def need(condition, reason):
    if not condition:
        raise Refused(reason)


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def identifier(value):
    return type(value) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}', value)


def sha(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value)


def private_identity(path, directory=False):
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'symlink')
    info = path.lstat()
    need((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
         and info.st_uid == os.getuid() and not info.st_mode & 0o077
         and (directory or info.st_nlink == 1), 'private_identity')
    return info.st_dev, info.st_ino


def read_policy(path, expected):
    private_identity(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(0 < before.st_size <= 32768, 'policy_size')
        raw = os.read(fd, 32769)
        after = os.fstat(fd)
        need((before.st_ino, before.st_mtime_ns, before.st_ctime_ns, before.st_size)
             == (after.st_ino, after.st_mtime_ns, after.st_ctime_ns, after.st_size), 'policy_changed')
        need(sha(expected) and digest(raw) == expected, 'policy_changed')
        def unique(pairs):
            result={}
            for key,value in pairs:
                need(key not in result, 'duplicate_policy_key')
                result[key]=value
            return result
        return json.loads(raw,object_pairs_hook=unique)
    finally:
        os.close(fd)


@dataclass(frozen=True)
class Proposal:
    request_id: str
    task_id: str
    domain: str
    capability: str
    origin: str
    source_sha256: str
    candidate_sha256: str
    units: int = 1


class ActionBoundary:
    """One serial action; authority and checker selected by the trusted owner.

    Candidate testing is the only admitted capability in this increment. A pass
    earns evidence for that domain, never permission to publish or self-expand.
    The checker callback is trusted host infrastructure, never task/model input.
    Full process-isolated broker wiring remains a separate integration gate.
    """
    def __init__(self, root, *, policy_path, policy_sha256, constitution_sha256,
                 observe, checker, clock=time.time, publication_guard=None, policy_guard=None,
                 work_admission=None, state_version=1):
        self.root = Path(root).absolute()
        self.policy_path = Path(policy_path).absolute()
        need(not self.policy_path.is_relative_to(self.root), 'policy_compartment')
        self.policy_sha256 = policy_sha256
        self.constitution_sha256 = constitution_sha256
        need(sha(constitution_sha256), 'constitution_digest')
        from .independent_checker import IndependentChecker
        self.observe, self.checker, self.clock = observe, checker, clock
        need(callable(observe) and type(checker) is IndependentChecker, 'trusted_host_interfaces')
        need(publication_guard is None or callable(publication_guard), 'trusted_publication_guard')
        self.publication_guard = publication_guard
        need(policy_guard is None or callable(policy_guard), 'trusted_policy_guard')
        self.policy_guard = policy_guard
        self.work_admission = work_admission
        need(type(state_version) is int and state_version in (1,2), 'unsupported_work_state')
        self.state_version = state_version
        self.root_id = private_identity(self.root, True)
        self.path = self.root/'actions.sqlite3'
        if not self.path.exists():
            need(state_version == 1, 'work_state_migration_required')
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            os.close(fd)
            with sqlite3.connect(self.path) as db:
                db.executescript('''
                  CREATE TABLE meta (schema INTEGER, policy TEXT, foundation TEXT);
                  CREATE TABLE actions (id TEXT PRIMARY KEY, fingerprint TEXT, domain TEXT,
                    capability TEXT, state TEXT, units INTEGER, result TEXT);
                  CREATE TABLE audit (seq INTEGER PRIMARY KEY, body TEXT, previous TEXT, hash TEXT);
                ''')
                db.execute('INSERT INTO meta VALUES (1,?,?)', (policy_sha256, constitution_sha256))
        self.file_id = private_identity(self.path)
        self.policy = self._policy(fresh=False)
        with self._tx() as db:
            self._history(db)

    def _policy(self, fresh=True):
        value = read_policy(self.policy_path, self.policy_sha256)
        need(type(value) is dict and set(value) == {'schema','authority','owner_reference',
             'constitution_sha256','checker_sha256','expires_at','capabilities'}, 'policy_schema')
        need(type(value['schema']) is int and value['schema'] == 1
             and value['authority'] == 'owner_adopted' and identifier(value['owner_reference']), 'owner_policy')
        need(value['constitution_sha256'] == self.constitution_sha256, 'foundation_binding')
        need(type(value['expires_at']) is int and (not fresh or self.clock() < value['expires_at']), 'policy_expired')
        need(sha(value['checker_sha256']) and value['checker_sha256'] == self.checker.checker_sha256, 'checker_binding')
        capabilities = value['capabilities']
        need(type(capabilities) is list and 0 < len(capabilities) <= 32, 'registry_size')
        seen = set()
        for c in capabilities:
            need(type(c) is dict and set(c) == {'id','domain','operation','tasks','origins',
                 'max_actions','max_units','minimum_successes','epoch','evidence_max_age'}, 'capability_schema')
            need(identifier(c['id']) and identifier(c['domain']) and c['id'] not in seen, 'capability_identity')
            seen.add(c['id'])
            need(c['operation'] == 'test_candidate', 'unsupported_consequence')
            need(type(c['tasks']) is list and 0 < len(c['tasks']) <= 32 and all(identifier(x) for x in c['tasks']), 'task_scope')
            need(type(c['origins']) is list and c['origins'] and all(x in
                 ('user_assigned','standing_responsibility','atlas_generated') for x in c['origins']), 'goal_origins')
            for key, low, high in [('max_actions',1,100),('max_units',1,100),
                    ('minimum_successes',0,100),('epoch',0,1000000),('evidence_max_age',1,300)]:
                need(type(c[key]) is int and low <= c[key] <= high, 'capability_budget')
        return value

    @contextmanager
    def _tx(self, *, read_only=False):
        need(private_identity(self.root, True) == self.root_id and
             private_identity(self.path) == self.file_id, 'ledger_replaced')
        db = sqlite3.connect(self.path.as_uri()+('?mode=ro' if read_only else '?mode=rw'), uri=True, timeout=2)
        try:
            db.execute('BEGIN' if read_only else 'BEGIN IMMEDIATE')
            need(db.execute('SELECT * FROM meta').fetchall() ==
                 [(self.state_version,self.policy_sha256,self.constitution_sha256)], 'migration_or_identity_required')
            from .work_state_format import validate_format
            validate_format(db)
            self._history(db)
            self._projection(db)
            yield db
            self._projection(db)
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def _history(self, db):
        rows = db.execute('SELECT seq,body,previous,hash FROM audit ORDER BY seq LIMIT 1025').fetchall()
        need(len(rows) <= 1024, 'ledger_capacity')
        head = digest((self.policy_sha256+self.constitution_sha256).encode())
        previous_time = 0
        for index, (seq, body, prev, item_hash) in enumerate(rows, 1):
            item = json.loads(body)
            need(seq == index and prev == head and digest((prev+body).encode()) == item_hash, 'ledger_corrupt')
            need(type(item['at']) is int and item['at'] >= previous_time, 'ledger_time_reversal')
            previous_time = item['at']; head = item_hash
        return rows, head, previous_time

    def _projection(self, db):
        expected = {}
        rows, _, _ = self._history(db)
        for _, body, _, _ in rows:
            item=json.loads(body);key=item['request_id'];details=item['details'];kind=item['kind']
            if kind=='reserved':
                need(key not in expected, 'duplicate_history')
                expected[key]=[key,details['fingerprint'],details['domain'],details['capability'],'reserved',details['units'],None]
            else:
                if kind == 'publication_uncertain':
                    need(key in expected and expected[key][4] in ('verified','failed'), 'invalid_action_transition')
                    expected[key][4]='uncertain'; expected[key][6]=None
                else:
                    need(kind in ('verified','failed','uncertain') and key in expected and expected[key][4]=='reserved','invalid_action_transition')
                    expected[key][4]=kind
                    expected[key][6]=None if kind=='uncertain' else encode(details)
        actual=db.execute('SELECT id,fingerprint,domain,capability,state,units,result FROM actions ORDER BY id').fetchall()
        need(actual==[tuple(expected[k]) for k in sorted(expected)],'action_projection_corrupt')

    def _event(self, db, kind, request_id, details):
        rows, head, last = self._history(db)
        now = int(self.clock())
        need(now >= last and len(rows) < 1024, 'clock_or_capacity')
        body = encode(dict(kind=kind, request_id=request_id, at=now, details=details))
        need(len(body) <= 4096, 'receipt_size')
        db.execute('INSERT INTO audit VALUES (?,?,?,?)',
                   (len(rows)+1,body,head,digest((head+body).encode())))

    def _gate(self, proposal):
        need(type(proposal) is Proposal and all(identifier(x) for x in
             (proposal.request_id,proposal.task_id,proposal.domain,proposal.capability)), 'proposal_identity')
        need(proposal.origin in ('user_assigned','standing_responsibility','atlas_generated')
             and sha(proposal.source_sha256) and sha(proposal.candidate_sha256)
             and type(proposal.units) is int and proposal.units == 1, 'proposal_fields')
        need(not (self.root/'STOP').exists() and not (self.root/'STOP').is_symlink(), 'safe_mode')
        policy = self._policy()
        selected = [c for c in policy['capabilities'] if c['id'] == proposal.capability]
        need(len(selected) == 1, 'unregistered_capability')
        c = selected[0]
        need(c['domain'] == proposal.domain and proposal.task_id in c['tasks']
             and proposal.origin in c['origins'], 'grant_scope')
        state = self.observe(proposal.task_id)
        need(type(state) is dict and set(state) == {'stopped','epoch','resources_ok',
             'source_sha256','observed_at','constitution_sha256'}, 'independent_observation')
        need(state['stopped'] is False and state['resources_ok'] is True, 'stopped_or_resource_loss')
        need(type(state['epoch']) is int and state['epoch'] == c['epoch'], 'revoked_epoch')
        need(type(state['observed_at']) is int and 0 <= self.clock()-state['observed_at'] <= c['evidence_max_age'], 'stale_state')
        need(state['source_sha256'] == proposal.source_sha256
             and state['constitution_sha256'] == self.constitution_sha256, 'state_drift')
        return c

    def reserve(self, proposal):
        need(type(proposal) is Proposal, 'proposal_identity')
        need(self.state_version == 1 or self.work_admission is not None, 'shared_work_reader_required')
        guard = (nullcontext() if self.work_admission is None else
                 self.work_admission.guard('supplemental', proposal.request_id, reservation_only=True))
        with guard:
            self._reserve_with_policy(proposal)

    def _reserve_with_policy(self, proposal):
        # The selected owner lock precedes every action-ledger writer that
        # consults policy. Final publication uses the same ordering, avoiding
        # a reserve-versus-publish lock inversion.
        with nullcontext() if self.policy_guard is None else self.policy_guard():
            self._reserve(proposal)

    def _reserve(self, proposal):
        c = self._gate(proposal)
        fingerprint = digest(encode(proposal.__dict__).encode())
        with self._tx() as db:
            self._gate(proposal)
            need(not db.execute('SELECT 1 FROM actions WHERE id=?',(proposal.request_id,)).fetchone(), 'duplicate_no_replay')
            need(not db.execute("SELECT 1 FROM actions WHERE state IN ('reserved','uncertain')").fetchone(), 'recovery_required')
            count, units = db.execute('SELECT count(*),coalesce(sum(units),0) FROM actions WHERE capability=?', (c['id'],)).fetchone()
            need(count < c['max_actions'] and units+proposal.units <= c['max_units'], 'budget_exhausted')
            success = db.execute("SELECT count(*) FROM actions WHERE domain=? AND capability=? AND state='verified'", (c['domain'],c['id'])).fetchone()[0]
            failure = db.execute("SELECT count(*) FROM actions WHERE domain=? AND capability=? AND state!='verified'", (c['domain'],c['id'])).fetchone()[0]
            need(max(0,success-failure) >= c['minimum_successes'], 'insufficient_domain_evidence')
            db.execute('INSERT INTO actions VALUES (?,?,?,?,?,?,?)',
                       (proposal.request_id,fingerprint,c['domain'],c['id'],'reserved',proposal.units,None))
            self._event(db,'reserved',proposal.request_id,dict(fingerprint=fingerprint,
                policy=self.policy_sha256,domain=c['domain'],capability=c['id'],units=proposal.units,origin=proposal.origin,creates_authority=False))

    def test_candidate(self, proposal, candidate):
        need(type(proposal) is Proposal, 'proposal_identity')
        need(self.state_version == 1 or self.work_admission is not None, 'shared_work_reader_required')
        need(type(candidate) is bytes and 0 < len(candidate) <= 32768 and
             digest(candidate) == proposal.candidate_sha256, 'candidate_binding')
        guard = (nullcontext() if self.work_admission is None else
                 self.work_admission.guard('supplemental', proposal.request_id))
        with guard:
            return self._test_candidate(proposal, candidate)

    def _test_candidate(self, proposal, candidate):
        self._reserve_with_policy(proposal)
        try:
            self._gate(proposal)
            # Only the trusted host invokes the independently selected checker.
            # Model-provided `passed`, advice, or claimed tests are not accepted.
            receipt = self.checker(candidate)
            need(type(receipt) is dict and set(receipt) == {'candidate_sha256',
                 'checker_sha256','exit_code','cleanup_verified'}, 'independent_receipt')
            need(receipt['candidate_sha256'] == proposal.candidate_sha256 and
                 receipt['checker_sha256'] == self.checker.checker_sha256 and type(receipt['exit_code']) is int
                 and receipt['cleanup_verified'] is True, 'unconfirmed_check')
            self._gate(proposal)
            state = 'verified' if receipt['exit_code'] == 0 else 'failed'
            guard = (nullcontext() if self.publication_guard is None
                     else self.publication_guard(proposal.task_id))
            # Hold owner policy and original Stop ordering through ledger commit.
            # The prepared observer uses the held control epoch without DB re-entry.
            with guard:
                with self._tx() as db:
                    self._gate(proposal)
                    need(db.execute('SELECT state FROM actions WHERE id=?',(proposal.request_id,)).fetchone() == ('reserved',), 'reservation_changed')
                    db.execute('UPDATE actions SET state=?,result=? WHERE id=?',
                               (state,encode(receipt),proposal.request_id))
                    self._event(db,state,proposal.request_id,receipt)
            return dict(state=state,request_id=proposal.request_id,execution_authority=False,
                        source_applied=False,receipt=receipt)
        except BaseException:
            with self._tx() as db:
                row=db.execute('SELECT state FROM actions WHERE id=?',(proposal.request_id,)).fetchone()
                if row and row[0] in ('reserved','verified','failed'):
                    db.execute("UPDATE actions SET state='uncertain',result=NULL WHERE id=?",(proposal.request_id,))
                    kind='uncertain' if row[0]=='reserved' else 'publication_uncertain'
                    self._event(db,kind,proposal.request_id,dict(automatic_retry=False))
            raise

    def enter_safe_mode(self):
        """Any trusted monitor may reduce authority. This module cannot clear it."""
        try:
            fd=os.open(self.root/'STOP',os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
        except FileExistsError:
            return
        with os.fdopen(fd,'w') as stream:
            stream.write('Owner reconciliation required. No automatic resume.\n')
            stream.flush();os.fsync(stream.fileno())

    def trust(self, domain, capability):
        need(identifier(domain) and identifier(capability), 'trust_scope')
        with self._tx() as db:
            rows=db.execute('SELECT state FROM actions WHERE domain=? AND capability=?',
                            (domain,capability)).fetchall()
        counts={state:sum(row[0]==state for row in rows) for state in
                ('verified','failed','reserved','uncertain')}
        return dict(domain=domain,capability=capability,counts=counts,
            evidence_score=max(0,counts['verified']-counts['failed']-counts['uncertain']),
            qualification='candidate_checks_only',creates_authority=False)

    def status(self):
        with self._tx(read_only=True) as db:
            rows = db.execute('SELECT id,domain,capability,state,units FROM actions ORDER BY rowid').fetchall()
            events, head, _ = self._history(db)
        return dict(actions=[dict(zip(('id','domain','capability','state','units'),row)) for row in rows],
            history_sha256=head,events=len(events),requires_recovery=any(r[3] in ('reserved','uncertain') for r in rows),
            safe_mode=(self.root/'STOP').exists(),execution_authority=False)
