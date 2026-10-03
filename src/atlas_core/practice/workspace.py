"""Fixed-file practice tools with persistent budgets and confined checking.

The trusted host must supply a current authority/Stop callback. This module does
not create a grant, enable a model, register itself, or change the live Atlas.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import threading
import time
import uuid
from .catalog import exercise

CHECK_PYTHON = '/Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9/Resources/Python.app/Contents/MacOS/Python'
PYTHON_ROOT = '/Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9'
MAX_SOURCE = 16384
MAX_OUTPUT = 32768
CONTRACT = ('Implement only def parse_quantity(value). Accept exact built-in int or str. '
            'Strip surrounding whitespace; strings must then contain only ASCII digits 0-9. '
            'Leading zeros are allowed. Return an exact int from 1 through 100. '
            'Other types, including bool and subclasses, raise TypeError. '
            'Malformed strings and out-of-range values raise ValueError. '
            'Use no imports, test code, helper functions, I/O or external libraries. '
            'Pure built-ins: type, int, str, bool, isinstance, len, all, any, ord, TypeError, ValueError. '
            'String methods: strip, isdigit, isascii. Use comparisons and single-iterator generators; '
            'general loops, arithmetic and custom format widths are outside this first exercise. '
            'The original and independent tests are protected.')


class PracticeRefused(ValueError):
    pass


def need(value, message):
    if not value:
        raise PracticeRefused(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def regular(path, maximum=65536):
    path = Path(path).absolute()
    need(not any(item.is_symlink() for item in (path, *path.parents)), 'Symlink paths are refused.')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
             and before.st_nlink == 1 and before.st_size <= maximum, 'Invalid file identity or size.')
        raw = os.read(fd, maximum + 1)
        after = os.fstat(fd)
        need(len(raw) == before.st_size == after.st_size
             and before.st_mtime_ns == after.st_mtime_ns, 'File changed during read.')
        return raw
    finally:
        os.close(fd)


def sandbox_profile(read_paths):
    # The historical Aider pilot uses the same OS mechanism. This checker has
    # fewer capabilities: no writes except /dev/null and no network exceptions.
    lines = ['(version 1)', '(allow default)', '(deny file-read-data)',
             '(deny file-write*)', '(deny network*)', '(deny appleevent-send)', '(deny process-exec)']
    trees = ['/System', '/usr/lib', '/usr/share', '/private/var/db/dyld', PYTHON_ROOT]
    for path in trees:
        lines.append('(allow file-read-data (subpath ' + json.dumps(path) + '))')
    executable = str(Path(CHECK_PYTHON).resolve())
    literals = [CHECK_PYTHON, executable, '/dev/null', '/dev/urandom', '/dev/random', *map(str, read_paths)]
    ancestors = {str(parent) for path in trees + literals for parent in Path(path).parents}
    for path in sorted(set(literals) | ancestors):
        lines.append('(allow file-read-data (literal ' + json.dumps(path) + '))')
    lines += ['(allow file-write* (literal "/dev/null"))',
              '(allow process-exec (literal ' + json.dumps(CHECK_PYTHON) + ') (literal ' + json.dumps(executable) + '))']
    return '\n'.join(lines) + '\n'


class PracticeWorkspace:
    @classmethod
    def create_exercise(cls, root, *, exercise_id, authorize):
        """Trusted host entry only; no model tool or public request selects assets."""
        spec = exercise(exercise_id)
        package = Path(__file__).parent
        return cls.create(root, checker=package/'catalog_checker.py',
            tests=[package/'protected_tests'/exercise_id/'test_parse.py',
                   package/'protected_tests'/exercise_id/'test_contract.py'],
            authorize=authorize, seed=spec['seed'], exercise_id=exercise_id)

    @classmethod
    def create(cls, root, *, checker, tests, authorize, seed, exercise_id='quantity-v1'):
        root = Path(root).absolute()
        need(not any(p.is_symlink() for p in (root, *root.parents)), 'Symlink roots are refused.')
        need(callable(authorize) and authorize('create') is True, 'Current owner authority is required.')
        need(type(seed) is str and 0 < len(seed.encode()) <= MAX_SOURCE, 'Seed size refused.')
        need(type(exercise_id) is str, 'Exact exercise ID required.')
        if exercise_id != 'quantity-v1':
            exercise(exercise_id)  # Only the trusted host selects a fixed task.
        tests = list(map(lambda p: Path(p).absolute(), tests))
        need(len(tests) == 2 and [p.name for p in tests] == ['test_parse.py', 'test_contract.py'], 'Fixed test suite required.')
        checker = Path(checker).absolute()
        helpers = []
        if exercise_id != 'quantity-v1':
            package = Path(__file__).parent
            need(checker == package/'catalog_checker.py' and tests == [
                package/'protected_tests'/exercise_id/'test_parse.py',
                package/'protected_tests'/exercise_id/'test_contract.py'], 'Fixed catalog assets required.')
            helpers = [package/'catalog.py', package/'checker.py']
        pins = {str(p): sha(regular(p)) for p in [checker, *tests, *helpers]}
        root.mkdir(mode=0o700)
        state = {'schema': 1, 'contract': exercise_id, 'writes': 0, 'checks': 0,
                 'in_flight': False, 'last_result': None, 'pins': pins,
                 'expires_at': time.time() + 1800, 'source_sha256': sha(seed.encode()),
                 'checker': str(checker), 'tests': list(map(str, tests))}
        for name, raw in [('solution.py', seed.encode()), ('state.json', json.dumps(state).encode()), ('lock', b'')]:
            fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as handle:
                handle.write(raw); handle.flush(); os.fsync(handle.fileno())
        return cls(root, authorize=authorize)

    def __init__(self, root, *, authorize):
        self.root = Path(root).absolute()
        need(callable(authorize), 'A live host authority callback is required.')
        self.authorize = authorize
        self._mutex = threading.Lock()
        self._identity = self._directory_identity()
        self._gate('open')
        self._state()

    def _directory_identity(self):
        need(not any(p.is_symlink() for p in (self.root, *self.root.parents)), 'Symlink roots are refused.')
        info = self.root.stat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
             and stat.S_IMODE(info.st_mode) == 0o700, 'Private owner directory required.')
        return info.st_dev, info.st_ino

    def _gate(self, action):
        need(self._directory_identity() == self._identity, 'Workspace directory changed.')
        need(not os.path.lexists(self.root / 'STOP'), 'Practice is stopped.')
        try: allowed = self.authorize(action)
        except Exception as exc: raise PracticeRefused('Owner authority is unavailable.') from exc
        need(allowed is True, 'Owner authority or Stop gate is closed.')

    def _state(self):
        state = json.loads(regular(self.root / 'state.json'))
        need(state['schema'] == 1, 'Unknown workspace state.')
        if state['contract'] != 'quantity-v1':
            exercise(state['contract'])
            package = Path(__file__).parent
            expected = [package/'catalog_checker.py',
                package/'protected_tests'/state['contract']/'test_parse.py',
                package/'protected_tests'/state['contract']/'test_contract.py',
                package/'catalog.py', package/'checker.py']
            need(state['checker'] == str(expected[0]) and state['tests'] == list(map(str,expected[1:3]))
                 and set(state['pins']) == set(map(str,expected)), 'Catalog identity changed.')
        need(type(state['writes']) is int and 0 <= state['writes'] <= 2
             and type(state['checks']) is int and 0 <= state['checks'] <= 3, 'Invalid budgets.')
        need(time.time() < state['expires_at'], 'Practice session expired.')
        for path, digest in state['pins'].items():
            need(sha(regular(path)) == digest, 'Protected checker or tests changed.')
        need(sha(regular(self.root / 'solution.py', MAX_SOURCE)) == state['source_sha256'], 'Unreviewed source change.')
        return state

    def _atomic(self, name, raw):
        temporary = self.root / ('.' + uuid.uuid4().hex + '.tmp')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'wb') as handle:
                handle.write(raw); handle.flush(); os.fsync(handle.fileno())
            os.replace(temporary, self.root / name)
        finally:
            if temporary.exists(): temporary.unlink()

    def _save(self, state):
        self._atomic('state.json', json.dumps(state, sort_keys=True).encode())

    @contextmanager
    def _locked(self, action):
        with self._mutex:
            self._gate(action)
            fd = os.open(self.root / 'lock', os.O_RDONLY | os.O_NOFOLLOW)
            try:
                info = os.fstat(fd)
                need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'Invalid lock.')
                try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as exc: raise PracticeRefused('Another practice operation is active.') from exc
                state = self._state()
                need(state['in_flight'] is False, 'Previous operation is unresolved; owner review is required.')
                yield state
            finally:
                os.close(fd)

    def read(self):
        with self._locked('read') as state:
            return {'path': 'solution.py', 'content': regular(self.root / 'solution.py', MAX_SOURCE).decode(),
                    'source_sha256': state['source_sha256'],
                    'contract': CONTRACT if state['contract'] == 'quantity-v1' else exercise(state['contract'])['contract'],
                    'exercise': state['contract'],
                    'repairs_remaining': 2 - state['writes'], 'checks_remaining': 3 - state['checks']}

    def write(self, *, content, expected_sha256):
        need(type(content) is str and 0 < len(content.encode()) <= MAX_SOURCE, 'Content must contain 1..16384 UTF-8 bytes.')
        need(type(expected_sha256) is str, 'Expected source hash is required.')
        with self._locked('write') as state:
            need(state['writes'] < 2, 'Two-repair limit reached.')
            need(expected_sha256 == state['source_sha256'], 'Stale edit; read the current file first.')
            raw = content.encode()
            need(sha(raw) != state['source_sha256'], 'Unchanged retry refused.')
            # Reserve before mutation. An interrupted replacement stays closed.
            state['writes'] += 1; state['in_flight'] = True; self._save(state)
            self._gate('write')
            self._atomic('solution.py', raw)
            state['source_sha256'] = sha(raw); state['last_result'] = None; state['in_flight'] = False
            self._save(state)
            return {'written': True, 'path': 'solution.py', 'source_sha256': state['source_sha256'],
                    'repairs_remaining': 2 - state['writes']}

    @staticmethod
    def _cleanup(child):
        for sig in [signal.SIGTERM, signal.SIGKILL]:
            try: os.killpg(child.pid, sig)
            except ProcessLookupError: pass
            try: child.wait(timeout=1)
            except subprocess.TimeoutExpired: continue
        try: os.killpg(child.pid, 0); return False
        except ProcessLookupError: return child.poll() is not None

    def _run(self, argv):
        child = subprocess.Popen(argv, cwd=self.root, env={'PATH': '/usr/bin:/bin', 'LANG': 'C'},
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        started = time.monotonic(); reason = None; chunks = {1: bytearray(), 2: bytearray()}
        next_sample = started; peak_rss_kib = 0
        selector = selectors.DefaultSelector()
        for index, stream in [(1, child.stdout), (2, child.stderr)]:
            os.set_blocking(stream.fileno(), False); selector.register(stream, selectors.EVENT_READ, index)
        try:
            while selector.get_map():
                try: self._gate('check_poll')
                except PracticeRefused: reason = 'stopped'; break
                if time.monotonic() - started > 5: reason = 'timeout'; break
                if time.monotonic() >= next_sample and child.poll() is None:
                    sample = subprocess.run(['/bin/ps', '-o', 'rss=', '-p', str(child.pid)],
                        env={'PATH': '/usr/bin:/bin', 'LANG': 'C'}, capture_output=True, text=True, timeout=1)
                    reading = sample.stdout.strip()
                    if sample.returncode == 0 and reading.isdigit():
                        peak_rss_kib = max(peak_rss_kib, int(reading))
                        if int(reading) > 196608: reason = 'memory_watchdog'; break
                    elif child.poll() is None:
                        reason = 'memory_observation_unavailable'; break
                    next_sample = time.monotonic() + 0.1
                for key, _ in selector.select(0.03):
                    data = os.read(key.fileobj.fileno(), 4096)
                    if not data: selector.unregister(key.fileobj); continue
                    chunks[key.data].extend(data)
                    if sum(map(len, chunks.values())) > MAX_OUTPUT: reason = 'output_limit'; break
                if reason: break
            if not reason:
                try: child.wait(timeout=max(0.1, 5 - (time.monotonic() - started)))
                except subprocess.TimeoutExpired: reason = 'timeout'
        finally:
            cleanup = self._cleanup(child)
            selector.close(); child.stdout.close(); child.stderr.close()
        return {'exit_code': child.returncode, 'stop_reason': reason, 'cleanup_verified': cleanup,
                'seconds': round(time.monotonic() - started, 4), 'observed_peak_rss_kib': peak_rss_kib,
                'stdout': bytes(chunks[1])[:MAX_OUTPUT].decode('utf-8', errors='replace'),
                'stderr': bytes(chunks[2])[:MAX_OUTPUT].decode('utf-8', errors='replace')}

    def check(self):
        with self._locked('check') as state:
            if state['last_result']:
                return dict(state['last_result'], cached=True)
            need(state['checks'] < 3, 'Check budget exhausted.')
            state['checks'] += 1; state['in_flight'] = True; self._save(state)
            paths = [self.root / 'solution.py', *map(Path, state['pins'])]
            profile = self.root / ('check-' + str(state['checks']) + '.sb')
            self._atomic(profile.name, sandbox_profile(paths).encode())
            argv = ['/usr/bin/sandbox-exec', '-f', str(profile), CHECK_PYTHON, '-I', '-B',
                    state['checker'], str(self.root / 'solution.py'), *state['tests']]
            run = self._run(argv)
            result = {'complete': False, 'passed': False, 'source_sha256': state['source_sha256'],
                      'stage': 'execution', 'feedback': run['stop_reason'] or run['stderr'][:1000],
                      'tests_run': 0, 'cached': False}
            if run['exit_code'] == 0 and run['cleanup_verified'] and run['stop_reason'] is None:
                try:
                    observed = json.loads(run['stdout'])
                    expected_count = 13 if state['contract'] == 'quantity-v1' else exercise(state['contract'])['tests_run']
                    need(type(observed) is dict, 'Invalid checker receipt.')
                    need(state['contract'] == 'quantity-v1' or observed.get('exercise') == state['contract'], 'Wrong exercise receipt.')
                    need(type(observed) is dict and observed['source_sha256'] == state['source_sha256']
                         and type(observed['complete']) is bool and type(observed['passed']) is bool
                         and type(observed['tests_run']) is int and observed['tests_run'] in [0, expected_count], 'Invalid checker receipt.')
                    need(not observed['passed'] or observed['complete'] and observed['tests_run'] == expected_count, 'Incomplete pass refused.')
                    result.update(observed)
                except (ValueError, KeyError, TypeError):
                    result['feedback'] = 'Checker did not return a valid complete receipt.'
            # Recheck source/tests and owner gate before publishing any success.
            self._state()
            try: self._gate('check_publish')
            except PracticeRefused:
                result.update(complete=False, passed=False, feedback='Practice stopped before publication.')
            state['in_flight'] = not run['cleanup_verified']
            state['last_result'] = result
            self._save(state)
            record = {'command': argv, 'utc': datetime.now(timezone.utc).isoformat(), 'run': run, 'result': result}
            self._atomic('check-' + str(state['checks']) + '.json', json.dumps(record, indent=2).encode())
            return result

    def stop(self):
        # Trusted owner/host control. There is deliberately no model Resume tool.
        need(self._directory_identity() == self._identity, 'Workspace changed.')
        fd = os.open(self.root / 'STOP', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
