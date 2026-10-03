"""Confined foreground Aider for an existing registered execution.

Trusted host API, not a model tool or an exposed shell/provider endpoint. The
host supplies an already qualified runtime and a bounded, cancellation-aware
completion callback. That callback's provider/account authority must be checked
separately. Scripted callbacks prove workflow only, never model competence.
"""
from __future__ import annotations

from datetime import datetime, timezone
import ast
import hashlib
import http.server
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import threading
import time

from atlas_core.coding_execution import RegisteredCodingExecution
from atlas_core.coding_request_budget import AiderRequestBudget
from atlas_core.governance.cognitive_state import need

SETTINGS = ('empty-config.yml', 'empty-env', 'model-settings.yml', 'model-metadata.json')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def regular(path, maximum=32768):
    """Do not follow candidate symlinks or accept shared/oversized files."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and before.st_uid == os.getuid() and before.st_size <= maximum,
             'aider_file_shape')
        raw = os.read(fd, maximum + 1)
        after = os.fstat(fd)
        need(len(raw) <= maximum and (before.st_size,before.st_mtime_ns,before.st_ino)
             == (after.st_size,after.st_mtime_ns,after.st_ino), 'aider_file_changed')
        return raw
    finally:
        os.close(fd)


def preserve_capsule_terminal_blank(candidate, baseline, task):
    """Restore one protected blank line for the exact registered repair capsules.

    The model's function bytes are unchanged. No substantive exterior change,
    unknown task, invalid syntax or changed baseline is repaired here. The
    independent checker still owns all syntax and behavioral acceptance.
    """
    if type(candidate) is not bytes or type(baseline) is not bytes or type(task) is not dict:
        return candidate
    descriptor=task.get('checker')
    if type(descriptor) is not dict or set(descriptor)!={'id'} or type(descriptor.get('id')) is not str:
        return candidate
    # Exact registry bindings only. This repairs framing, never task behavior.
    capsules={
        'practice_stop_marker_v1': ('stop-marker','require_running','092d1833d4261af3e014fde1bab4f6c93e6a442fb704e178dc20e8742a1dbfeb'),
        'practice_artifact_path_v1': ('artifact-path','relative','574c2984434bcbe051bcc42e0e387ad6067a0bbb79a6e9fa8d3538225f44a1cf'),
        'practice_json_overflow_v1': ('json-overflow','decode','c906345a3fd29c63c4c61cda9b224c2b5836e8b57c11e2c584828298b58d7a79'),
    }
    binding=capsules.get(descriptor['id'])
    if binding is None:return candidate
    task_id,function_name,expected=binding
    if (task.get('source_sha256') != expected or sha(baseline) != expected
            or task.get('path') != 'public/'+task_id+'/candidate.py'
            or not 0<len(candidate)<32768 or not candidate.endswith(b'\n')):
        return candidate
    def parts(raw):
        tree=ast.parse(raw.decode('utf-8'))
        found=[n for n in tree.body if type(n) is ast.FunctionDef and n.name==function_name]
        if len(found)!=1:raise ValueError('one_selected_function')
        node=found[0];lines=raw.splitlines(keepends=True)
        return node,b''.join(lines[:node.lineno-1]),b''.join(lines[node.end_lineno:])
    try:
        original,before,after=parts(baseline)
        function,prefix,suffix=parts(candidate)
    except (ValueError,SyntaxError,UnicodeDecodeError,RecursionError):
        return candidate
    if (prefix != before or after != b'\n' or suffix != b''
            or function.decorator_list or function.returns or function.type_comment
            or ast.dump(function.args) != ast.dump(original.args)):
        return candidate
    return candidate+b'\n'


class AiderProcessWorker:
    def __init__(self, execution, *, guard, runtime_pins, completion,
                 provider_label, port=0, timeout_seconds=175, request_budget=None):
        need(type(execution) is RegisteredCodingExecution, 'registered_execution_required')
        need(callable(completion) and type(provider_label) is str and
             0 < len(provider_label) <= 128, 'trusted_completion_required')
        need(type(port) is int and (port == 0 or 1024 < port < 65536), 'fixture_port')
        need(type(timeout_seconds) is int and 1 <= timeout_seconds <= 175, 'aider_deadline')
        self.execution, self.guard, self.completion = execution, guard, completion
        self.label, self.port, self.timeout = provider_label, port, timeout_seconds
        # An absent host-qualified counter is deliberately fail-closed at the
        # assembled request boundary, before reservation or provider execution.
        need(request_budget is None or type(request_budget) is AiderRequestBudget,
             'aider_context_admission_required')
        self.request_budget = request_budget
        self.pins = dict(runtime_pins)
        required = [Path(guard.__file__), *(guard.ROOT/'control'/name for name in SETTINGS)]
        need(set(self.pins) == {str(p) for p in required}, 'qualified_runtime_pins_required')
        self._check_runtime()
        if self.request_budget is not None:
            self.request_budget.verify_metadata(json.loads(regular(
                guard.ROOT/'control/model-metadata.json')))
        self.root = execution.session.root/'aider-worker'
        need(not self.root.exists() and not self.root.is_symlink(), 'aider_worker_already_created')
        self.root.mkdir(mode=0o700)
        self.case, self.scratch = self.root/'case', self.root/'scratch'
        self.case.mkdir(mode=0o700); self.scratch.mkdir(mode=0o700)
        guard.prepare_scratch(self.scratch)
        self.relative = execution.session.spec['task']['path']
        self.source = self.case/self.relative
        self.source.parent.mkdir(parents=True, mode=0o700)
        self.source.write_bytes(regular(execution.prepared.source_path));self.source.chmod(0o600)
        self.cancel = threading.Event()
        self.request_started = threading.Event()
        self._request_lock = threading.Lock()
        self._used = False
        self._requests = 0
        self._errors = []
        self.receipt = None
        self.child_pid = None

    def _check_runtime(self):
        need(all(sha(regular(Path(name), 131072)) == value for name,value in self.pins.items()),
             'qualified_runtime_changed')

    def _gate(self):
        need(not self.cancel.is_set(), 'aider_stopped')
        self._check_runtime()
        self.execution.loop.authorize('local_model')

    def _save(self, name, value):
        # Evidence is outside every child-write path; preserve first receipt.
        with (self.root/name).open('x') as handle:
            json.dump(value, handle, indent=2); handle.write('\n')

    def _handler(self, reserve):
        worker = self
        class Proxy(http.server.BaseHTTPRequestHandler):
            def setup(self):
                super().setup();self.connection.settimeout(2)
            def do_POST(self):
                if self.path != '/v1/chat/completions':return self.send_error(403)
                try:
                    length = int(self.headers.get('Content-Length','0'))
                    need(0 < length <= 150000, 'bounded_request_required')
                    body = json.loads(self.rfile.read(length))
                    need(body.get('model') == 'atlas-local' and body.get('stream',False) is False,
                         'fixed_nonstream_model_required')
                    messages = body.get('messages')
                    need(type(messages) is list and 0 < len(messages) <= 100, 'messages_required')
                    normalized=[]
                    for item in messages:
                        need(type(item) is dict and item.get('role') in ('system','user','assistant'),
                             'message_role')
                        text=item.get('content')
                        if type(text) is list and all(type(part) is dict and part.get('type') == 'text'
                                and type(part.get('text')) is str for part in text):
                            text=''.join(part['text'] for part in text)
                        need(type(text) is str, 'text_content_required')
                        normalized.append({'role':item['role'],'content':text})
                    with worker._request_lock:
                        worker._gate()
                        need(worker._requests == 0, 'single_request_exhausted')
                        budget = worker.request_budget
                        need(type(budget) is AiderRequestBudget, 'aider_context_admission_required')
                        admission = budget.admit(normalized, worker.label)
                        worker._gate()  # Stop/revocation may change while counting.
                        number = reserve()
                        need(number == 1, 'registered_single_request_required')
                        worker._requests = 1
                        worker._save('REQUEST.json',{'provider':worker.label,'number':number,
                            'messages':normalized, 'input_admission':admission,
                            'requested_utc':datetime.now(timezone.utc).isoformat()})
                        worker.request_started.set()
                    content=worker.completion(normalized,worker.cancel)
                    worker._gate()
                    need(type(content) is str and len(content.encode()) <= 65536, 'bounded_reply_required')
                    worker._save('REPLY.json',{'provider':worker.label,'content':content,
                        'reply_utc':datetime.now(timezone.utc).isoformat()})
                    result={'id':'atlas-scoped-worker','object':'chat.completion',
                        'created':int(time.time()),'model':'atlas-local',
                        'choices':[{'index':0,'message':{'role':'assistant','content':content},
                            'finish_reason':'stop'}],
                        'usage':{'prompt_tokens':0,'completion_tokens':0,'total_tokens':0}}
                    raw=json.dumps(result).encode()
                    self.send_response(200);self.send_header('Content-Type','application/json')
                    self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
                except (BrokenPipeError,ConnectionResetError):pass
                except Exception as error:
                    worker._errors.append(type(error).__name__+': '+str(error)[:160])
                    worker.cancel.set()
                    try:self.send_error(400,'Scoped request refused')
                    except (BrokenPipeError,ConnectionResetError):pass
            def do_GET(self):self.send_error(403)
            def log_message(self,*args):pass
        return Proxy

    def _launch(self, prompt, port):
        guard=self.guard
        launcher=self.root/'launcher.py'
        launcher.write_text('import os,sys\nos.environ["OPENAI_API_KEY"]="local-trial-placeholder"\n'
            'os.environ["OPENAI_API_BASE"]='+repr(f'http://127.0.0.1:{port}/v1')+
            '\nos.execv(sys.executable,[sys.executable,"-m","aider",*sys.argv[1:]])\n')
        settings=[guard.ROOT/'control'/name for name in SETTINGS]
        policy=self.root/'worker.sb'
        policy.write_text(guard.profile([self.source,self.scratch,launcher,guard.ROOT/'token-cache',*settings],
            [self.source,self.scratch],port))
        args=['--model','openai/atlas-local','--config',settings[0],'--env-file',settings[1],
            '--model-settings-file',settings[2],'--model-metadata-file',settings[3],
            '--no-check-update','--no-show-release-notes','--no-analytics','--no-auto-commits',
            '--no-dirty-commits','--no-gitignore','--no-add-gitignore-files','--no-suggest-shell-commands',
            '--no-detect-urls','--disable-playwright','--no-stream','--no-pretty','--no-fancy-input',
            '--no-auto-lint','--no-auto-test','--no-git','--map-tokens','0','--timeout',str(self.timeout),
            '--input-history-file',self.scratch/'input.history','--chat-history-file',self.scratch/'chat.md',
            '--yes-always','--max-chat-history-tokens','4096','--no-restore-chat-history',
            '--message',prompt,self.relative]
        return guard.argv(policy,[guard.PYTHON,'-I','-B',launcher,*args])

    @staticmethod
    def _cleanup(child):
        if child is None:return True
        # A separately confined sibling must be reaped by its owning parent.
        # The fixed peer handle can only affect that parent's recorded child.
        peer_cleanup = getattr(child, 'cleanup_group', None)
        if peer_cleanup is not None:
            try:return peer_cleanup() is True
            except Exception:return False
        # Kill descendants even if the leader already exited. Only our own PGID.
        for sig, wait in ((signal.SIGTERM,1.5),(signal.SIGKILL,1.5)):
            try:os.killpg(child.pid,sig)
            except ProcessLookupError:break
            until=time.monotonic()+wait
            while time.monotonic()<until:
                child.poll()
                try:os.killpg(child.pid,0)
                except ProcessLookupError:break
                time.sleep(.05)
            else:continue
            break
        try:child.wait(timeout=.5)
        except subprocess.TimeoutExpired:return False
        try:os.killpg(child.pid,0);return False
        except ProcessLookupError:return True

    def __call__(self, prompt, reserve):
        need(not self._used, 'aider_attempt_consumed');self._used=True
        self._gate()
        started=time.monotonic();utc=datetime.now(timezone.utc).isoformat()
        server=thread=None;child=None;argv=[];stop_reason=None;proxy_clean=True;cleanup=False
        try:
            class Server(http.server.HTTPServer):allow_reuse_address=True
            server=Server(('127.0.0.1',self.port),self._handler(reserve))
            server.timeout=.1
            # No detached worker: own server thread is joined before publication.
            def serve():
                while not self.cancel.is_set():server.handle_request()
            thread=threading.Thread(target=serve,name='atlas-aider-fixture-proxy',daemon=True)
            thread.start()
            argv=self._launch(prompt,server.server_port)
            self._gate()
            with (self.root/'OUTPUT.txt').open('xb') as output:
                child=subprocess.Popen(argv,cwd=self.case,env=self.guard.clean_env(self.scratch),
                    stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
                self.child_pid=child.pid
                while child.poll() is None:
                    self._gate()
                    need(time.monotonic()-started < self.timeout, 'aider_process_deadline')
                    need((self.root/'OUTPUT.txt').stat().st_size <= 131072, 'aider_output_limit')
                    time.sleep(.1)
                self._gate()
        except Exception as error:
            stop_reason=type(error).__name__+': '+str(error)[:200]
        finally:
            self.cancel.set()
            cleanup=self._cleanup(child)
            if thread is not None:
                thread.join(timeout=3);proxy_clean=not thread.is_alive()
            if server is not None:server.server_close()
        candidate=b'';framing=None
        launch_status='not_started'
        if child is not None:
            launch_status='exited' if child.returncode == 0 else 'process_failed'
            if child.returncode == 71 and (self.root/'OUTPUT.txt').read_bytes().startswith(
                    b'sandbox-exec: sandbox_apply: Operation not permitted'):
                launch_status='sandbox_refused'
                stop_reason='sandbox_refused: required child confinement could not be applied'
            elif child.returncode != 0 and stop_reason is None:
                stop_reason='process_failed: exit '+str(child.returncode)
        complete=child is not None and child.returncode == 0 and stop_reason is None and not self._errors
        complete=complete and self._requests == 1 and proxy_clean and cleanup
        if complete:
            try:
                raw=regular(self.source)
                candidate=preserve_capsule_terminal_blank(raw,regular(self.execution.prepared.source_path),
                    self.execution.session.spec['task'])
                framing={'schema':1,'raw_candidate_sha256':sha(raw),'returned_candidate_sha256':sha(candidate),
                    'terminal_blank_restored':candidate!=raw,'function_bytes_changed':False,
                    'raw_source_preserved':True,'acceptance_claim':False}
            except Exception as error:complete=False;stop_reason=type(error).__name__+': '+str(error)[:200]
        self.receipt={'started_utc':utc,'completed_utc':datetime.now(timezone.utc).isoformat(),
            'argv':list(map(str,argv)),'pid':self.child_pid,'exit_code':child.returncode if child else None,
            'seconds':round(time.monotonic()-started,3),'stop_reason':stop_reason,'proxy_errors':self._errors,
            'launch_status':launch_status,'reserved_requests':self._requests,'provider':self.label,'proxy_joined':proxy_clean,
            'process_group_empty':cleanup,'cleanup_verified':cleanup and proxy_clean,
            'complete':bool(complete),'candidate_sha256':sha(candidate),'runtime_pins':self.pins,
            'candidate_framing':framing,
            'supported_chatgpt_return_qualified':False,'installed':False,
            'token_counts':'not inferred from compatibility envelope; provider receipt required'}
        self._save('PROCESS.json',self.receipt)
        return {'complete':bool(complete),'cleanup_verified':cleanup and proxy_clean,'candidate':candidate}
