"""Shared foreground admission; no queue, permission issuer or recovery replay.

The host supplies fixed custody and independently recovered outcomes. An OS
lock prevents overlap; an append-only journal reservation survives process loss.
Neither a model's success claim nor a released process lock settles that record.
This coordinates trusted host paths, not a hostile same-user administrator.
"""
from contextlib import contextmanager
import fcntl
import os
import stat
import threading
import time
import uuid

from .cognitive_state import digest, identifier, need

PREFIX = 'work-admission:'
LANES = {'supplemental', 'registered'}


def admission_status(journal):
    """Read-only historical recovery; never clear, replay or reconstruct a host."""
    pending = {}
    settled = 0
    seen = set()
    for event in journal.events():
        if not event['subject'].startswith(PREFIX):
            continue
        value = event['value']
        need(type(value) is dict and value.get('schema') == 1
             and type(value['schema']) is int and value.get('lane') in LANES
             and all(identifier(value.get(k)) for k in ('token', 'run_id', 'request_id'))
             and event['subject'] == PREFIX + value['token']
             and event['supersedes'] is None, 'work_admission_corrupt')
        token = value['token']
        base = {'schema', 'lane', 'run_id', 'request_id', 'token', 'state'}
        if value['state'] == 'reserved':
            need(set(value) == base and token not in seen and not pending
                 and event['kind'] == 'action' and event['basis'] == 'observed',
                 'work_admission_transition')
            seen.add(token)
            pending[token] = event
        else:
            need(set(value) == base | {'outcome', 'cleanup_verified'}
                 and value['state'] == 'settled' and value['cleanup_verified'] is True
                 and token in pending and event['kind'] == 'verification'
                 and event['basis'] == 'tested', 'work_admission_transition')
            prior = pending[token]
            need(all(value[k] == prior['value'][k] for k in base - {'state'})
                 and event['evidence'] == ['sha256:' + digest(prior),
                                          'sha256:' + digest(value['outcome'])],
                 'work_admission_receipt')
            _outcome(value['outcome'], value['lane'])
            del pending[token]
            settled += 1
    return {'pending': [v['value'] for v in pending.values()], 'settled': settled,
            'requires_recovery': bool(pending), 'execution_authority': False}


def _outcome(value, lane):
    need(type(value) is dict and set(value) == {'lane', 'state', 'record_sha256'}
         and value['lane'] == lane
         and value['state'] in ({'verified', 'failed'} if lane == 'supplemental'
                                else {'accepted', 'failed'})
         and type(value['record_sha256']) is str and len(value['record_sha256']) == 64
         and all(c in '0123456789abcdef' for c in value['record_sha256']),
         'work_outcome_unconfirmed')


class SharedWorkAdmission:
    def __init__(self, *, journal, run_id, lock_path, lock_identity,
                 custody_check, inspect, confirm):
        need(identifier(run_id) and all(callable(c) for c in
             (custody_check, inspect, confirm)), 'work_host_required')
        self.journal, self.run_id = journal, run_id
        self.lock_path, self.lock_identity = lock_path, tuple(lock_identity[:2])
        self.custody_check, self.inspect, self.confirm = custody_check, inspect, confirm
        self._mutex = threading.Lock()
        self._pid = os.getpid()

    @contextmanager
    def guard(self, lane, request_id, *, reservation_only=False):
        need(lane in LANES and identifier(request_id) and os.getpid() == self._pid,
             'work_admission_scope')
        need(type(reservation_only) is bool and
             (not reservation_only or lane == 'supplemental'), 'work_admission_scope')
        need(self._mutex.acquire(blocking=False), 'work_already_active')
        fd = None
        try:
            self.custody_check()
            fd = os.open(self.lock_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            info = os.fstat(fd)
            need((info.st_dev, info.st_ino) == self.lock_identity
                 and stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                 and info.st_mode & 0o077 == 0 and info.st_nlink == 1,
                 'work_admission_lock_changed')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError('work_already_active') from None
            self.custody_check()
            need(not admission_status(self.journal)['requires_recovery'], 'work_recovery_required')
            # Includes unresolved records predating this shared admission layer.
            need(self.inspect() is True, 'work_recovery_required')
            token = uuid.uuid4().hex
            value = dict(schema=1, lane=lane, run_id=self.run_id,
                         request_id=request_id, token=token, state='reserved')
            event = self._event(value, 'action', [])
            self.journal.append(event)
            # Exceptions and process loss intentionally leave the reservation
            # unresolved, even when no worker return can be recovered.
            yield
            if not reservation_only:
                outcome = self.confirm(lane, request_id)
                _outcome(outcome, lane)
                self.journal.append(self._event(dict(value, state='settled',
                    outcome=outcome, cleanup_verified=True), 'verification',
                    ['sha256:' + digest(event), 'sha256:' + digest(outcome)]))
        finally:
            if fd is not None:
                os.close(fd)
            self._mutex.release()

    @staticmethod
    def _event(value, kind, evidence):
        now = int(time.time())
        return dict(id='work-' + uuid.uuid4().hex, kind=kind,
            basis='tested' if kind == 'verification' else 'observed',
            subject=PREFIX + value['token'], occurred_at=now, recorded_at=now,
            verified_at=now if evidence else None, expires_at=None,
            evidence=evidence, supersedes=None, value=value)
