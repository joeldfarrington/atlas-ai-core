"""Owner-owned, finite, at-most-once improvement queue. Never a model tool."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
import stat
import time
import uuid

INTERVAL = 10800
DAILY_LIMIT = 8
MAX_JOBS = 2048


class QueueRefused(RuntimeError):
    pass


class ImprovementQueue:
    def __init__(self, root, *, clock=time.time):
        self.root = Path(root).absolute()
        self.clock = clock
        self._fd = None
        if any(p.is_symlink() for p in (self.root, *self.root.parents)):
            raise QueueRefused('Queue symlink refused')
        self.root.mkdir(mode=0o700, exist_ok=True)
        self._identity = self._directory()
        self.path = self.root/'queue.sqlite3'
        fresh = not os.path.lexists(self.path)
        if fresh:
            fd = os.open(self.path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
            os.close(fd)
        self._file_identity = self._file(self.path)
        self.lease = self.root/'owner.lock'
        if fresh:
            fd = os.open(self.lease, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
            os.close(fd)
        self._lease_identity = self._file(self.lease)
        # This lifetime lease prevents a second process from declaring a live
        # claimant orphaned. Expiry alone never causes an uncertain job replay.
        self._fd = os.open(self.lease, os.O_RDONLY|os.O_NOFOLLOW)
        try:
            fcntl.flock(self._fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BaseException:
            os.close(self._fd); self._fd = None
            raise QueueRefused('Another improvement owner holds the lease') from None
        try:
            with self.db() as db:
                if fresh:
                    db.executescript('''
                    CREATE TABLE meta (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL,
                      paused INTEGER NOT NULL, next_due REAL NOT NULL, last_clock REAL NOT NULL);
                    CREATE TABLE jobs (key TEXT PRIMARY KEY, kind TEXT NOT NULL, payload TEXT NOT NULL,
                      status TEXT NOT NULL, created REAL NOT NULL, claimed REAL, finished REAL,
                      claim TEXT, generations INTEGER NOT NULL DEFAULT 0, tools INTEGER NOT NULL DEFAULT 0,
                      result TEXT, run_id TEXT, conversation_id TEXT);
                    ''')
                    db.execute('INSERT INTO meta VALUES (1,1,0,?,?)', (clock(), clock()))
                row = db.execute('SELECT version FROM meta WHERE id=1').fetchone()
                if row is None or row[0] != 1:
                    raise QueueRefused('Unknown queue schema; owner migration required')
                db.execute("UPDATE jobs SET status='unconfirmed', finished=?, result=? WHERE status='claimed'",
                           (clock(), json.dumps({'reason':'service_interrupted_no_replay'})))
        except BaseException:
            self.close(); raise

    def _directory(self):
        s = self.root.lstat()
        if (not stat.S_ISDIR(s.st_mode) or s.st_uid != os.getuid() or s.st_mode & 0o077
                or any(p.is_symlink() for p in self.root.parents)):
            raise QueueRefused('Queue directory changed or is not private')
        return s.st_dev, s.st_ino

    def _file(self, path):
        s = path.lstat()
        if not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid() or s.st_nlink != 1 or s.st_mode & 0o077:
            raise QueueRefused('Queue file is not private and regular')
        return s.st_dev, s.st_ino

    @contextmanager
    def db(self):
        if self._fd is None or self._directory() != self._identity or self._file(self.path) != self._file_identity or self._file(self.lease) != self._lease_identity:
            raise QueueRefused('Queue owner or file identity changed')
        db = sqlite3.connect(self.path.as_uri()+'?mode=rw', uri=True, timeout=2)
        db.row_factory = sqlite3.Row
        try:
            with db:
                db.execute('BEGIN IMMEDIATE')
                yield db
        finally:
            db.close()

    def _time(self, db):
        now = self.clock()
        previous = db.execute('SELECT last_clock FROM meta WHERE id=1').fetchone()[0]
        if type(now) not in (int, float) or not math.isfinite(now) or now < previous:
            raise QueueRefused('Clock moved backward or is unknown; defer')
        db.execute('UPDATE meta SET last_clock=? WHERE id=1', (now,))
        return now

    def enqueue(self, key, kind, payload):
        if (type(key) is not str or not 1 <= len(key) <= 180 or kind not in {'review', 'exercise'}
                or type(payload) is not dict):
            raise QueueRefused('Invalid fixed job')
        raw = json.dumps(payload, sort_keys=True, allow_nan=False)
        if len(raw.encode()) > 12000:
            raise QueueRefused('Job evidence too large')
        with self.db() as db:
            now = self._time(db)
            if db.execute('SELECT 1 FROM jobs WHERE key=?', (key,)).fetchone():
                return False
            if db.execute('SELECT count(*) FROM jobs').fetchone()[0] >= MAX_JOBS:
                raise QueueRefused('Queue history full; owner archival required')
            db.execute('INSERT INTO jobs (key,kind,payload,status,created) VALUES (?,?,?,\'pending\',?)',
                       (key, kind, raw, now))
            return True

    def paused(self, value):
        if type(value) is not bool:
            raise QueueRefused('Explicit pause boolean required')
        with self.db() as db:
            self._time(db)
            db.execute('UPDATE meta SET paused=? WHERE id=1', (int(value),))

    def claim(self):
        with self.db() as db:
            now = self._time(db)
            meta = db.execute('SELECT * FROM meta').fetchone()
            if meta['paused'] or now < meta['next_due']:
                return None
            if db.execute("SELECT 1 FROM jobs WHERE status='claimed'").fetchone():
                return None
            if db.execute('SELECT count(*) FROM jobs WHERE claimed>=?', (now-86400,)).fetchone()[0] >= DAILY_LIMIT:
                return None
            row = db.execute("SELECT * FROM jobs WHERE status='pending' ORDER BY created,key LIMIT 1").fetchone()
            if row is None:
                return None
            token = str(uuid.uuid4())
            db.execute("UPDATE jobs SET status='claimed',claimed=?,claim=? WHERE key=? AND status='pending'",
                       (now, token, row['key']))
            # Coalesce missed slots: one job now; no catch-up burst.
            db.execute('UPDATE meta SET next_due=? WHERE id=1', (now+INTERVAL,))
            return {**dict(row), 'payload':json.loads(row['payload']), 'claim':token, 'claimed':now}

    def charge(self, job, field):
        limits = {'generations':11, 'tools':10}
        if field not in limits:
            raise QueueRefused('Unknown budget')
        with self.db() as db:
            now = self._time(db)
            row = db.execute('SELECT * FROM jobs WHERE key=?', (job['key'],)).fetchone()
            if (row is None or row['status'] != 'claimed' or row['claim'] != job['claim']
                    or now-row['claimed'] >= 600 or row[field] >= limits[field]
                    or db.execute('SELECT paused FROM meta').fetchone()[0]):
                raise QueueRefused('Claim, pause or cycle budget refused')
            db.execute('UPDATE jobs SET '+field+'='+field+'+1 WHERE key=?', (job['key'],))

    def bind_run(self, job, run_id, conversation_id):
        with self.db() as db:
            updated = db.execute("UPDATE jobs SET run_id=?,conversation_id=? WHERE key=? AND claim=? AND status='claimed'",
                                 (run_id, conversation_id, job['key'], job['claim']))
            if updated.rowcount != 1:
                raise QueueRefused('Claim lost')

    def finish(self, job, status, result):
        if status not in {'completed', 'failed', 'cancelled', 'unconfirmed'}:
            raise QueueRefused('Unknown terminal status')
        raw = json.dumps(result, sort_keys=True, allow_nan=False)
        if len(raw.encode()) > 16000:
            raise QueueRefused('Outcome too large')
        with self.db() as db:
            # Closing uncertainty must remain possible even after a clock fault.
            changed = db.execute("UPDATE jobs SET status=?,finished=?,result=? WHERE key=? AND claim=? AND status='claimed'",
                (status, self.clock(), raw, job['key'], job['claim']))
            if changed.rowcount != 1:
                raise QueueRefused('Terminal job cannot be replayed or overwritten')

    def snapshot(self):
        with self.db() as db:
            meta = dict(db.execute('SELECT * FROM meta').fetchone())
            last = db.execute('SELECT key,kind,status,claimed,finished,generations,tools,result,run_id,conversation_id FROM jobs WHERE claimed IS NOT NULL ORDER BY claimed DESC LIMIT 1').fetchone()
            return {'paused':bool(meta['paused']), 'next_due':meta['next_due'],
                    'pending':db.execute("SELECT count(*) FROM jobs WHERE status='pending'").fetchone()[0],
                    'cycles_last_24h':db.execute('SELECT count(*) FROM jobs WHERE claimed>=?', (self.clock()-86400,)).fetchone()[0],
                    'last_outcome':None if last is None else {**dict(last), 'result':json.loads(last['result'] or '{}')},
                    'schema_version':meta['version']}

    def close(self):
        if self._fd is not None:
            os.close(self._fd); self._fd = None
