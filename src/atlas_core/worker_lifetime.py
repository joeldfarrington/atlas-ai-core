"""Fixed launcher infrastructure: supervision inside the existing sandbox.

The guardian's pipe is a lifetime signal, not a command channel. Its child does
not inherit either guardian descriptor. The parent reports the actual workload
PID, and a clean result requires both the child group and guardian to be gone.
"""
import json
import os
import selectors
import signal
import subprocess
import time


GUARDIAN_CODE = r'''
import json,os,selectors,signal,subprocess,sys,time
spec=json.loads(sys.argv[1]);life=spec['life'];status=spec['status']
interrupted=False
def interrupt(signum,frame):
 global interrupted
 interrupted=True
signal.signal(signal.SIGTERM,interrupt)
def emit(value):
 try:os.write(status,json.dumps(value).encode()+b'\n')
 except BrokenPipeError:pass
def group_exists(pid):
 try:os.killpg(pid,0);return True
 except ProcessLookupError:return False
 except PermissionError:return True
def cleanup(child):
 for sig,grace in ((signal.SIGTERM,1.0),(signal.SIGKILL,1.0)):
  # Reap our child before probing or signalling its group. A rapidly exiting
  # sandboxed child can cease to be a signalable descendant before waitpid.
  child.poll()
  if not group_exists(child.pid):break
  try:os.killpg(child.pid,sig)
  except ProcessLookupError:break
  except PermissionError:
   # Denial is not cleanup evidence. Wait only for our own child, then require
   # an independent group-absence check; a live or inaccessible group fails.
   try:child.wait(timeout=grace)
   except subprocess.TimeoutExpired:pass
   continue
  until=time.monotonic()+grace
  while time.monotonic()<until:
   child.poll()
   if not group_exists(child.pid):break
   time.sleep(.025)
  if not group_exists(child.pid):break
 try:child.wait(timeout=.5)
 except subprocess.TimeoutExpired:pass
 return child.poll() is not None and not group_exists(child.pid)
child=None;reason='completed';clean=False
try:
 child=subprocess.Popen(spec['argv'],start_new_session=True,close_fds=True,
                        pass_fds=tuple(spec['pass_fds']))
 for fd in spec['pass_fds']:os.close(fd)
 emit({'event':'started','pid':child.pid,'guardian_pid':os.getpid()})
 selector=selectors.DefaultSelector();selector.register(life,selectors.EVENT_READ)
 deadline=time.monotonic()+spec['seconds']
 while child.poll() is None:
  if interrupted:reason='guardian_termination';break
  if time.monotonic()>=deadline:reason='fixed_deadline';break
  if selector.select(.025):
   data=os.read(life,1)
   reason='launcher_lost' if not data else 'invalid_lifetime_data'
   break
finally:
 if child is not None:
  clean=cleanup(child)
  emit({'event':'finished','pid':child.pid,'returncode':child.returncode,
        'process_group_empty':clean,'reason':reason})
 os.close(life);os.close(status)
if not clean:sys.exit(125)
rc=child.returncode
sys.exit(rc if rc>=0 else 128-rc)
'''


def group_exists(pid):
    try:
        os.killpg(pid, 0)
        return True
    except ProcessLookupError:
        return False


class ConfinedLifetime:
    """Popen-like handle; only trusted parent creates this fixed wrapper."""

    def __init__(self, argv, *, cwd, env, stdout, stderr, seconds, pass_fds=()):
        assert argv[:2] == ['/usr/bin/sandbox-exec', '-f']
        assert 1 <= seconds <= 180
        life_read, self.life_write = os.pipe()
        self.status_read, status_write = os.pipe()
        self.buffer = b''
        self.started = None
        self.finished = None
        self.returncode = None
        self.args = argv
        self.pid = None
        spec = {'argv': argv[3:], 'life': life_read, 'status': status_write,
                'pass_fds': list(pass_fds), 'seconds': seconds}
        # Code is embedded from this trusted file, never read from worker-writable
        # scratch, and runs after applying the exact existing frozen profile.
        self.guardian_argv = [*argv[:3], argv[3], '-I', '-S', '-B', '-c',
                              GUARDIAN_CODE, json.dumps(spec)]
        try:
            self.guardian = subprocess.Popen(
                self.guardian_argv, cwd=cwd, env=env, stdout=stdout, stderr=stderr,
                pass_fds=(life_read, status_write, *pass_fds),
                start_new_session=True, close_fds=True)
        except BaseException:
            os.close(self.life_write)
            os.close(self.status_read)
            self.life_write = self.status_read = None
            raise
        finally:
            os.close(life_read)
            os.close(status_write)
        os.set_blocking(self.status_read, False)
        try:
            until = time.monotonic() + 3
            while self.started is None and time.monotonic() < until:
                self._read()
                if self.guardian.poll() is not None:
                    # Exit may become visible just after the preceding read.
                    # Drain final receipts before deciding startup was absent.
                    self._read()
                    break
                time.sleep(.01)
            if self.started is None:
                raise RuntimeError('Confined guardian did not identify workload')
        except BaseException:
            self.cleanup_group()
            raise
        self.pid = self.started['pid']

    def _read(self):
        if self.status_read is None:
            return
        while True:
            try:
                chunk = os.read(self.status_read, 4096)
            except BlockingIOError:
                break
            if not chunk:
                break
            self.buffer += chunk
            if len(self.buffer) > 16384:
                raise RuntimeError('Lifetime receipt exceeds fixed bound')
            while b'\n' in self.buffer:
                raw, self.buffer = self.buffer.split(b'\n', 1)
                event = json.loads(raw)
                if event['event'] == 'started':
                    if self.started is not None:
                        raise RuntimeError('Duplicate lifetime start')
                    self.started = event
                    self.pid = event['pid']
                elif event['event'] == 'finished':
                    if self.finished is not None or event['pid'] != self.pid:
                        raise RuntimeError('Invalid lifetime completion')
                    self.finished = event
                else:
                    raise RuntimeError('Unknown lifetime receipt')

    def poll(self):
        self._read()
        code = self.guardian.poll()
        if code is not None:
            self._read()
            self.returncode = (self.finished['returncode'] if self.finished and
                               self.finished['process_group_empty'] else 125)
        return self.returncode

    def wait(self, timeout=None):
        self.guardian.wait(timeout=timeout)
        return self.poll()

    def communicate(self, timeout=None):
        value = self.guardian.communicate(timeout=timeout)
        self.poll()
        return value

    def cleanup_group(self):
        if self.life_write is not None:
            os.close(self.life_write)
            self.life_write = None
        try:
            self.wait(timeout=3)
        except subprocess.TimeoutExpired:
            # If the guardian is unresponsive, the trusted launcher still has
            # its previous authority to clean its own exact recorded processes.
            self.guardian.terminate()
            try:
                self.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.guardian.kill()
                self.guardian.wait(timeout=1)
        if self.pid is not None and group_exists(self.pid):
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(self.pid, sig)
                except ProcessLookupError:
                    break
                until = time.monotonic()+1
                while group_exists(self.pid) and time.monotonic() < until:
                    time.sleep(.025)
        self.poll()
        clean = (self.pid is None or not group_exists(self.pid)) and self.guardian.poll() is not None
        if self.status_read is not None:
            os.close(self.status_read)
            self.status_read = None
        for stream in (self.guardian.stdin, self.guardian.stdout, self.guardian.stderr):
            if stream is not None:
                stream.close()
        return clean
