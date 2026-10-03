"""Optional owner-side guidance hosting; trusted in-process callers only.

This service never admits, resumes, prepares, consumes, or reconstructs a task.
The caller must supply a current prepared binding from this services lifetime.
"""
from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import stat
import threading

import anyio


class CodingOwnerRefused(ValueError):
    pass


def _need(condition, code):
    if not condition:
        raise CodingOwnerRefused(code)


def _metadata(st):
    return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode),
            st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _private_directory(path):
    _need(path.is_absolute() and path == Path(os.path.abspath(path)), 'private_directory_required')
    for part in [path, *path.parents]:
        _need(not part.is_symlink(), 'private_directory_required')
    st = path.lstat()
    _need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid()
          and stat.S_IMODE(st.st_mode) == 0o700, 'private_directory_required')
    return st.st_dev, st.st_ino


async def _drain(future):
    cancelled = False
    with anyio.CancelScope(shield=True):
        while not future.done():
            try:
                await asyncio.wait({future})
            except asyncio.CancelledError:
                cancelled = True
        try:
            result = future.result()
        except BaseException:
            if cancelled:
                raise asyncio.CancelledError from None
            raise
    if cancelled:
        raise asyncio.CancelledError
    return result


class CodingOwner:
    """One optional task host attached to an existing canonical control object."""
    def __init__(self, control, *, endpoint=None, descriptor_path=None):
        self.control = control
        self._pid = os.getpid()
        installation_root = Path(__file__).resolve().parents[2]
        installation_id = hashlib.sha256(str(installation_root).encode('utf-8')).hexdigest()[:16]
        # Fixed per-installation transient state; deriving names starts nothing.
        private_root = Path('/private/tmp') / f'atlas-guidance-{os.getuid()}-{installation_id}'
        self.endpoint = Path(endpoint) if endpoint is not None else private_root / 'owner.sock'
        self.descriptor_path = Path(descriptor_path) if descriptor_path is not None else private_root / 'guidance-owner.json'
        self.cleanup_confirmed = None
        self._state = 'disabled'
        self._host = None
        self._server = None
        self._publication = None
        self._closing = threading.Event()
        self._mutex = threading.RLock()
        self._executor = None
        self._inflight = None
        self._close_task = None
        self._loop = None

    def status(self):
        return {'status': self._state, 'cleanup_confirmed': self.cleanup_confirmed,
                'task_preparation_available': False, 'model_dispatched': False}

    def _event_loop(self):
        _need(os.getpid() == self._pid, "owning_process_required")
        loop = asyncio.get_running_loop()
        if self._loop is None:
            self._loop = loop
        _need(self._loop is loop, 'wrong_event_loop')
        return loop

    def _publish(self, descriptor):
        raw = json.dumps({'schema': 1, 'endpoint': str(self.endpoint), 'descriptor': descriptor},
                         ensure_ascii=True, allow_nan=False, sort_keys=True,
                         separators=(',', ':')).encode('ascii')
        _need(len(raw) <= 8192, 'descriptor_too_large')
        parent_id = _private_directory(self.descriptor_path.parent)
        directory = os.open(self.descriptor_path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            _need((os.fstat(directory).st_dev, os.fstat(directory).st_ino) == parent_id, 'descriptor_parent_changed')
            fd = os.open(self.descriptor_path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            try:
                st = os.fstat(fd)
                self._publication = (parent_id, _metadata(st), b'')
                os.fchmod(fd, 0o600)
                self._publication = (parent_id, _metadata(os.fstat(fd)), b'')
                view = memoryview(raw)
                offset = 0
                while view:
                    written = os.write(fd, view)
                    _need(written > 0, 'descriptor_write_failed')
                    offset += written
                    view = view[written:]
                    self._publication = (parent_id, _metadata(os.fstat(fd)), raw[:offset])
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(directory)
        finally:
            os.close(directory)

    def _unpublish(self):
        if self._publication is None:
            return True
        parent_id, metadata, raw = self._publication
        try:
            _need(_private_directory(self.descriptor_path.parent) == parent_id, 'descriptor_parent_changed')
            directory = os.open(self.descriptor_path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                _need((os.fstat(directory).st_dev, os.fstat(directory).st_ino) == parent_id, 'descriptor_parent_changed')
                fd = os.open(self.descriptor_path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                try:
                    st = os.fstat(fd)
                    _need(stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and st.st_nlink == 1
                          and _metadata(st) == metadata, 'descriptor_changed')
                    current = bytearray()
                    while len(current) <= 8192:
                        chunk = os.read(fd, 8193 - len(current))
                        if not chunk:
                            break
                        current.extend(chunk)
                    _need(bytes(current) == raw and _metadata(os.fstat(fd)) == metadata, 'descriptor_changed')
                finally:
                    os.close(fd)
                _need(_metadata(os.stat(self.descriptor_path.name, dir_fd=directory, follow_symlinks=False)) == metadata,
                      'descriptor_changed')
                os.unlink(self.descriptor_path.name, dir_fd=directory)
                os.fsync(directory)
            finally:
                os.close(directory)
            self._publication = None
            return True
        except Exception:
            return False

    def _attach(self, binding):
        with self._mutex:
            _need(not self._closing.is_set() and self._server is None, 'owner_unavailable')
            from atlas_core.development_control import DevelopmentControl
            from atlas_core.coding_connection import load_components
            components = load_components()
            _need(type(self.control) is DevelopmentControl and type(binding) is components['TaskGuidanceBinding']
                  and binding.control is self.control, 'current_prepared_binding_required')
            host = components['OwnedTaskHost'](binding)
            # Known invalid bindings are rejected before filesystem publication.
            _need(self.endpoint.is_absolute() and len(os.fsencode(self.endpoint)) <= 100, 'invalid_endpoint')
            if not self.endpoint.parent.exists():
                self.endpoint.parent.mkdir(mode=0o700)
            _private_directory(self.endpoint.parent)
            _private_directory(self.descriptor_path.parent)
            _need(not self.descriptor_path.exists() and not self.descriptor_path.is_symlink(), 'descriptor_exists')
            self._host = host
            self._server = components['OwnerGuidanceServer'](host, self.endpoint)
            try:
                descriptor = self._server.start()
                _need(not self._closing.is_set(), 'owner_closing')
                self._publish(descriptor)
                _need(not self._closing.is_set(), 'owner_closing')
                self._state = 'attached'
                return self.status()
            except BaseException:
                host.revoke()
                removed = self._unpublish()
                try:
                    closed = self._server.close(timeout=5.0) is True
                except Exception:
                    closed = False
                self.cleanup_confirmed = removed and closed
                self._state = 'refused' if self.cleanup_confirmed else 'cleanup_unconfirmed'
                raise CodingOwnerRefused('owner_start_refused') from None

    async def attach(self, binding):
        loop = self._event_loop()
        _need(not self._closing.is_set() and self._server is None
              and (self._inflight is None or self._inflight.done()), 'owner_unavailable')
        if self._executor is None:
            self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='atlas-coding-owner')
        self._inflight = asyncio.wrap_future(self._executor.submit(self._attach, binding), loop=loop)
        try:
            return await _drain(self._inflight)
        except asyncio.CancelledError:
            await self.aclose()
            raise
        except Exception:
            if self._state == 'disabled':
                self._state = 'refused'
            raise CodingOwnerRefused('owner_start_refused') from None

    def _close(self):
        with self._mutex:
            removed = self._unpublish()
            try:
                closed = self._server is None or self._server.close(timeout=5.0) is True
            except Exception:
                closed = False
            self.cleanup_confirmed = removed and closed
            self._state = 'closed' if self.cleanup_confirmed else 'cleanup_unconfirmed'
            return self.cleanup_confirmed

    async def _cleanup(self):
        with anyio.CancelScope(shield=True):
            if self._inflight is not None:
                try:
                    await _drain(self._inflight)
                except BaseException:
                    pass
            if self._executor is None:
                self.cleanup_confirmed = True
                self._state = 'closed'
                return True
            future = asyncio.wrap_future(self._executor.submit(self._close))
            try:
                return await _drain(future)
            finally:
                self._executor.shutdown(wait=True, cancel_futures=True)

    async def aclose(self):
        loop = self._event_loop()
        self._closing.set()
        if self._host is not None:
            self._host.revoke()
        if self._close_task is None:
            self._close_task = loop.create_task(self._cleanup())
        return await _drain(self._close_task)
