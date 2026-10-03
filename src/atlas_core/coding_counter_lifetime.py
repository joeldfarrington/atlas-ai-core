"""Trusted host guardian for a separately sandboxed native prompt counter.

The existing frozen native profile still confines the helper. This guardian is
trusted host infrastructure, like its calling Python host, not a sandbox for
arbitrary code. Its lifetime pipe carries no commands and is never inherited by
the counter. Losing the host closes that pipe even if the counter is stopped.
"""
import json
import os
import subprocess
import time

from atlas_core.worker_lifetime import ConfinedLifetime, GUARDIAN_CODE


class NativeCounterLifetime(ConfinedLifetime):
    def __init__(self, argv, *, cwd, env, seconds):
        if (type(argv) is not list or len(argv) != 6
                or argv[:2] != ['/usr/bin/sandbox-exec', '-f']
                or not all(type(value) is str for value in argv)
                or type(seconds) is not int or not 1 <= seconds <= 8):
            raise ValueError('fixed_native_counter_command_required')
        life_read, self.life_write = os.pipe()
        self.status_read, status_write = os.pipe()
        self.buffer = b''
        self.started = self.finished = self.returncode = self.pid = None
        self.args = argv
        spec = {'argv': argv, 'life': life_read, 'status': status_write,
                'pass_fds': [], 'seconds': seconds}
        # The helper still starts through sandbox-exec with the exact pinned
        # profile. No Python runtime or broader access is added to that profile.
        self.guardian_argv = ['/usr/bin/python3', '-I', '-S', '-B', '-c',
                              GUARDIAN_CODE, json.dumps(spec)]
        try:
            self.guardian = subprocess.Popen(self.guardian_argv, cwd=cwd, env=env,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                pass_fds=(life_read, status_write), start_new_session=True, close_fds=True)
        except BaseException:
            os.close(self.life_write); os.close(self.status_read)
            self.life_write = self.status_read = None
            raise
        finally:
            os.close(life_read); os.close(status_write)
        os.set_blocking(self.status_read, False)
        try:
            until = time.monotonic() + 3
            while self.started is None and time.monotonic() < until:
                self._read()
                if self.guardian.poll() is not None:
                    break
                time.sleep(.01)
            if self.started is None:
                raise RuntimeError('Counter guardian did not identify helper')
            self.pid = self.started['pid']
        except BaseException:
            self.cleanup_group()
            raise

    def communicate(self, input=None, timeout=None):
        value = self.guardian.communicate(input=input, timeout=timeout)
        self.poll()
        return value
