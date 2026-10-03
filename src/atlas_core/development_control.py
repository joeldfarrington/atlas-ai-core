"""Owner-only durable stop state. This object is deliberately not a model tool."""
from __future__ import annotations
import contextvars
import fcntl
import hashlib
import os
import sqlite3
import stat
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path
from atlas_core.errors import ToolError


class DevelopmentStopped(ToolError):
    pass


class DevelopmentControl:
    def __init__(self, root: Path, projects):
        self.projects = frozenset(projects)
        self.root = Path(root) / '.atlas_development_control'
        self.path = self.root / 'state.sqlite3'
        self._bound = contextvars.ContextVar('development_epoch', default=None)
        self._active = {}; self._mutex = threading.Lock()
        self._error = None
        self._root_identity = None
        self._state_identity = None
        try:
            fresh = not self.root.exists()
            if self.root.is_symlink():
                raise ValueError('Control directory is a symlink')
            self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
            info=self.root.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ValueError('Control directory is not private')
            self._root_identity=(info.st_dev,info.st_ino)
            if any(parent.is_symlink() for parent in self.root.parents):
                raise ValueError('Control parent cannot be a symlink')
            if fresh:
                fd=os.open(self.path, os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_NOFOLLOW, 0o600)
                os.close(fd)
            elif not self.path.exists():
                raise ValueError('Existing control state is missing')
            info=self.path.lstat()
            self._state_identity=(info.st_dev,info.st_ino)
            with self._db() as db:
                if fresh:
                    db.execute('CREATE TABLE controls (project TEXT PRIMARY KEY, epoch INTEGER NOT NULL, stopped INTEGER NOT NULL, cleanup INTEGER NOT NULL, active_write INTEGER NOT NULL)')
                    db.execute('CREATE TABLE activities (token TEXT PRIMARY KEY, project TEXT NOT NULL)')
                rows=db.execute('SELECT epoch,stopped,cleanup,active_write FROM controls').fetchall()
                if any(type(row[0]) is not int or row[0]<0 or type(row[1]) is not int or row[1] not in (0,1) or type(row[2]) is not int or row[2] not in (0,1) or type(row[3]) is not int or row[3] not in (0,1) for row in rows):
                    raise ValueError('Invalid saved control state')
                saved_projects={row[0] for row in db.execute('SELECT project FROM controls')}
                active_projects={row[0] for row in db.execute('SELECT project FROM activities')}
                if not fresh and not self.projects.issubset(saved_projects):
                    raise ValueError('Registered development control row is missing')
                for project in self.projects:
                    if fresh:
                        db.execute('INSERT INTO controls VALUES (?,0,0,0,0)', (project,))
                    # A new service instance cannot replay an old saved model/tool run.
                    db.execute('UPDATE controls SET epoch=epoch+1, stopped=MAX(stopped,active_write,?), cleanup=MAX(cleanup,active_write,?) WHERE project=?', (int(project in active_projects),int(project in active_projects),project))
        except (OSError, sqlite3.Error, ValueError, DevelopmentStopped):
            # Failure is scoped to development; ordinary Atlas chat remains usable.
            self._error = 'Development control state unavailable; owner repair required'

    @contextmanager
    def _db(self):
        if self._error:
            raise DevelopmentStopped('Development control state unavailable')
        try:
            directory=self.root.lstat()
            info=self.path.lstat()
            if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.getuid()
                    or directory.st_mode & 0o077
                    or (directory.st_dev,directory.st_ino) != self._root_identity
                    or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.getuid() or info.st_mode & 0o077
                    or (info.st_dev,info.st_ino) != self._state_identity
                    or any(parent.is_symlink() for parent in self.root.parents)):
                raise DevelopmentStopped('Development control identity or private permissions changed')
            connection=sqlite3.connect(self.path.as_uri()+'?mode=rw', uri=True, timeout=2)
        except OSError as exc:
            raise DevelopmentStopped('Development control state unavailable') from exc
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def status(self, project):
        if project not in self.projects:
            raise ToolError('Project is not registered for self-development')
        try:
            with self._db() as db:
                row = db.execute('SELECT epoch,stopped,cleanup,active_write FROM controls WHERE project=?',(project,)).fetchone()
                durable_active=db.execute('SELECT COUNT(*) FROM activities WHERE project=?',(project,)).fetchone()[0]
            if row is None or type(row[0]) is not int or row[0]<0 or type(row[1]) is not int or row[1] not in (0,1) or type(row[2]) is not int or row[2] not in (0,1) or type(row[3]) is not int or row[3] not in (0,1):
                raise ValueError('Invalid control state')
        except (OSError,sqlite3.Error,ValueError) as exc:
            raise DevelopmentStopped('Development control state is unavailable; admission stopped') from exc
        with self._mutex: active=self._active.get(project,0)
        return {'available':True,'project':project,'epoch':row[0],'stopped':bool(row[1]),'cleanup_required':bool(row[2]),'active_operations':max(active,row[3],durable_active)}

    def _change(self, project, stopped, cleanup=False, expected_epoch=None):
        self.status(project)
        try:
            with self._db() as db:
                db.execute('BEGIN IMMEDIATE')
                row=db.execute('SELECT cleanup,epoch,stopped,active_write FROM controls WHERE project=?',(project,)).fetchone()
                with self._mutex: active=self._active.get(project,0)
                active=max(active,db.execute('SELECT COUNT(*) FROM activities WHERE project=?',(project,)).fetchone()[0])
                if not stopped and (row is None or row[0] or row[3] or active or not row[2] or type(expected_epoch) is not int or row[1]!=expected_epoch):
                    raise ToolError('Resume requires current stopped epoch, no active work and verified cleanup')
                db.execute('UPDATE controls SET epoch=epoch+1, stopped=?,cleanup=MAX(cleanup,?) WHERE project=?',(int(stopped),int(cleanup),project))
        except sqlite3.Error as exc:
            raise DevelopmentStopped('Development control could not be persisted') from exc
        return self.status(project)

    def stop(self, project): return self._change(project, True)
    def resume(self, project, *, expected_epoch): return self._change(project, False, expected_epoch=expected_epoch)
    def mark_cleanup(self, project): return self._change(project, True, True)

    @contextmanager
    def publication_guard(self, project, epoch):
        """Order one bounded publication against STOP on this owner's database.

        Caller holds its Session/coordinator locks before entering. Do not call
        another control method or open a second control DB connection inside.
        The guard never admits, renews or reconstructs an owner's epoch.
        """
        if project not in self.projects:
            raise ToolError('Project is not registered for self-development')
        try:
            with self._db() as db:
                db.execute('BEGIN IMMEDIATE')
                row = db.execute('SELECT epoch,stopped,cleanup,active_write FROM controls WHERE project=?',
                                 (project,)).fetchone()
                if (row is None or len(row) != 4 or type(row[0]) is not int or row[0] < 0
                        or any(type(v) is not int or v not in (0, 1) for v in row[1:])
                        or type(epoch) is not int or row[0] != epoch or row[1] or row[2]):
                    raise DevelopmentStopped('Publication refused for stale or stopped development epoch')
                yield
        except sqlite3.Error as exc:
            raise DevelopmentStopped('Development publication guard unavailable') from exc

    def admit(self, project):
        state=self.status(project)
        if state['stopped'] or state['cleanup_required']:
            raise DevelopmentStopped('Atlas development is stopped by the owner')
        return state['epoch']

    def checkpoint(self, project, epoch):
        state=self.status(project)
        if type(epoch) is not int or state['stopped'] or state['cleanup_required'] or state['epoch']!=epoch:
            raise DevelopmentStopped('Atlas development stopped; this run cannot resume')

    @contextmanager
    def bind(self, project, epoch):
        token=self._bound.set((project,epoch))
        try:
            self.checkpoint(project,epoch)
            yield
        finally: self._bound.reset(token)

    def epoch(self, project):
        bound=self._bound.get()
        if bound is not None:
            if bound[0]!=project: raise DevelopmentStopped('Development project does not match admitted run')
            self.checkpoint(project,bound[1]); return bound[1]
        return self.admit(project)

    @contextmanager
    def active(self, project):
        self.status(project)
        token=uuid.uuid4().hex
        with self._db() as db:
            db.execute('INSERT INTO activities VALUES (?,?)',(token,project))
        with self._mutex: self._active[project]=self._active.get(project,0)+1
        try: yield
        finally:
            with self._mutex: self._active[project]-=1
            with self._db() as db:
                db.execute('DELETE FROM activities WHERE token=?',(token,))

    @contextmanager
    def transaction(self, project, epoch):
        lock=self.root / (hashlib.sha256(project.encode()).hexdigest()+'.lock')
        fd=os.open(lock,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError as exc: raise DevelopmentStopped('Another development transaction is active') from exc
            self.checkpoint(project,epoch)
            with self._db() as db:
                db.execute('UPDATE controls SET active_write=1 WHERE project=?',(project,))
            try:
                self.checkpoint(project,epoch)
                with self.active(project): yield
            finally:
                with self._db() as db:
                    db.execute('UPDATE controls SET active_write=0 WHERE project=?',(project,))
        finally:
            os.close(fd)
