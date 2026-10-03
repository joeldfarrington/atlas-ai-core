"""Independently adjudicated, bounded function-output acceptance.

The trusted host parses a pinned declarative contract, never candidate Python.
Only public call inputs reach the confined child. Output is untrusted data;
the host checks every case and expected value before issuing an acceptance code.
This qualifies observable outputs for registered calls, not arbitrary Python
program structure, honesty, or resistance to a compromised host administrator.
"""
import ast
import hashlib
import json
import math
import os
from pathlib import Path
import re
import selectors
import shutil
import stat
import subprocess
import sys
import tempfile
import time

from atlas_core.worker_lifetime import ConfinedLifetime

PYTHON = sys.executable
MAX_OUTPUT = 65536
BOOTSTRAP = '''import json,resource,runpy,sys
resource.setrlimit(resource.RLIMIT_NPROC,(0,0))
resource.setrlimit(resource.RLIMIT_FSIZE,(0,0))
resource.setrlimit(resource.RLIMIT_CPU,(3,3))
resource.setrlimit(resource.RLIMIT_NOFILE,(64,64))
source=sys.argv[1]
calls=json.loads(sys.argv[2])
module=runpy.run_path(source)
results=[]
for index,call in enumerate(calls):
    result=module[call['function']](*call['args'])
    results.append({'case':index,'value':result})
print(json.dumps({'version':1,'results':results},allow_nan=False,separators=(',',':')),flush=True)
'''


def _unique(pairs):
    result={}
    for key,value in pairs:
        if key in result:
            raise ValueError('duplicate_key')
        result[key]=value
    return result


def _decode(raw):
    def invalid(value):
        raise ValueError('non_finite_json')
    return json.loads(raw,object_pairs_hook=_unique,parse_constant=invalid)


def _value(value,depth=0):
    if depth>8:
        raise ValueError('value_depth')
    kind=type(value)
    if value is None or kind is bool:
        return
    if kind is int and -(2**63)<=value<2**63:
        return
    if kind is float and math.isfinite(value):
        return
    if kind is str and len(value)<=4096:
        return
    if kind is list and len(value)<=128:
        for item in value:_value(item,depth+1)
        return
    if kind is dict and len(value)<=128 and all(type(k) is str and len(k)<=128 for k in value):
        for item in value.values():_value(item,depth+1)
        return
    raise ValueError('value_type_or_size')


def _same(actual,expected):
    # Python's True == 1 and 6.0 == 6 do not erase the specified output type.
    if type(actual) is not type(expected):return False
    if type(actual) is list:
        return len(actual)==len(expected) and all(_same(a,b) for a,b in zip(actual,expected))
    if type(actual) is dict:
        return actual.keys()==expected.keys() and all(_same(actual[k],expected[k]) for k in expected)
    return actual==expected


def _contract(raw):
    """Accept JSON cases or the exact existing literal-assert fixture dialect.

    The compatibility path parses AST only. It does not run the Python checker
    or evaluate arbitrary expressions. Unsupported checkers fail closed.
    """
    try:
        if raw.lstrip().startswith(b'{'):
            value=_decode(raw)
            if type(value) is not dict or set(value)!={'schema','cases'} or type(value['schema']) is not int or value['schema']!=1:
                raise ValueError('contract_schema')
            cases=value['cases']
        else:
            tree=ast.parse(raw)
            prefix=ast.parse('import runpy,sys\nm=runpy.run_path(sys.argv[1])\n').body
            if len(tree.body)<3 or any(ast.dump(a)!=ast.dump(b) for a,b in zip(tree.body[:2],prefix)):
                raise ValueError('checker_prefix')
            cases=[]
            for statement in tree.body[2:]:
                if not isinstance(statement,ast.Assert) or statement.msg is not None:
                    raise ValueError('checker_statement')
                expression=statement.test
                if not isinstance(expression,ast.Compare) or len(expression.ops)!=1 or not isinstance(expression.ops[0],ast.Eq) or len(expression.comparators)!=1:
                    raise ValueError('checker_comparison')
                call=expression.left
                if not isinstance(call,ast.Call) or call.keywords or not isinstance(call.func,ast.Subscript):
                    raise ValueError('checker_call')
                lookup=call.func
                if not isinstance(lookup.value,ast.Name) or lookup.value.id!='m':
                    raise ValueError('checker_module')
                cases.append({'function':ast.literal_eval(lookup.slice),
                    'args':[ast.literal_eval(arg) for arg in call.args],
                    'expected':ast.literal_eval(expression.comparators[0])})
        if type(cases) is not list or not 1<=len(cases)<=32:
            raise ValueError('case_count')
        for case in cases:
            if type(case) is not dict or set(case)!={'function','args','expected'}:
                raise ValueError('case_schema')
            if type(case['function']) is not str or not re.fullmatch('[A-Za-z][A-Za-z0-9_]{0,63}',case['function']):
                raise ValueError('entrypoint')
            if type(case['args']) is not list or len(case['args'])>8:
                raise ValueError('arguments')
            _value(case['args']);_value(case['expected'])
        if len(json.dumps(cases,allow_nan=False).encode())>32768:
            raise ValueError('contract_size')
        return cases
    except (ValueError,TypeError,KeyError,SyntaxError,RecursionError,UnicodeError) as error:
        raise ValueError('unsupported_checker') from error


def _adjudicate(raw,cases):
    try:
        response=_decode(raw)
        if type(response) is not dict or set(response)!={'version','results'} or type(response['version']) is not int or response['version']!=1:
            return False,'response_schema',0
        results=response['results']
        if type(results) is not list or len(results)!=len(cases):
            return False,'incomplete_cases',0
        for index,(actual,case) in enumerate(zip(results,cases)):
            if type(actual) is not dict or set(actual)!={'case','value'} or type(actual['case']) is not int or actual['case']!=index:
                return False,'case_identity',index
            _value(actual['value'])
            if not _same(actual['value'],case['expected']):
                return False,'wrong_output',index
        return True,'all_registered_outputs_matched',len(cases)
    except (ValueError,TypeError,KeyError,RecursionError,UnicodeError):
        return False,'invalid_response',0


class IndependentChecker:
    def __init__(self,script,expected_sha256,scratch_root):
        self.script=Path(script).absolute()
        self.scratch_root=Path(scratch_root).absolute()
        self.checker_sha256=expected_sha256
        self.last_observation=None
        self._verify()

    def _verify(self):
        for path in (self.script,self.scratch_root):
            if any(p.is_symlink() for p in (path,*path.parents)):
                raise ValueError('checker_symlink')
            info=path.lstat()
            if info.st_uid!=os.getuid() or info.st_mode & 0o077:
                raise ValueError('checker_private_identity')
        if not stat.S_ISDIR(self.scratch_root.lstat().st_mode):
            raise ValueError('checker_scratch')
        fd=os.open(self.script,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            before=os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or not 0<before.st_size<=32768:
                raise ValueError('checker_file')
            raw=os.read(fd,32769);after=os.fstat(fd)
            fields=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
            if fields(before)!=fields(after) or hashlib.sha256(raw).hexdigest()!=self.checker_sha256:
                raise ValueError('checker_changed')
            return raw
        finally:os.close(fd)

    def __call__(self,candidate):
        self.last_observation=None
        cases=_contract(self._verify())
        if type(candidate) is not bytes or not 0<len(candidate)<=32768:
            raise ValueError('candidate_bound')
        # Expected outputs and private checker contents never enter the child.
        calls=[{'function':c['function'],'args':c['args']} for c in cases]
        root=Path(tempfile.mkdtemp(prefix='check-',dir=self.scratch_root))
        source=root/'candidate.py';source.write_bytes(candidate);source.chmod(0o600)
        profile=root/'checker.sb'
        reads=['/System','/usr/lib','/usr/share','/opt/homebrew',
               '/private/var/db/dyld',str(Path(PYTHON).parent.parent)]
        literal=[str(source),'/dev/null','/dev/urandom','/dev/random']
        quote=lambda s:'"'+s.replace('\\','\\\\').replace('"','\\"')+'"'
        rules=['(version 1)','(allow default)','(deny file-read-data)',
               '(deny file-write*)','(deny network*)','(deny appleevent-send)',
               '(deny process-exec)']
        rules+=['(allow file-read-data (subpath '+quote(p)+'))' for p in reads]
        rules+=['(allow file-read-data (literal '+quote(p)+'))' for p in literal]
        ancestors={str(q) for f in (source,Path(PYTHON)) for q in f.parents}
        rules+=['(allow file-read-data (literal '+quote(p)+'))' for p in sorted(ancestors)]
        rules+=['(allow process-exec (literal '+quote(p)+'))' for p in
                (PYTHON,str(Path(PYTHON).resolve()),'/opt/homebrew/Cellar/python@3.14/3.14.7/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python')]
        profile.write_text('\n'.join(rules)+'\n');profile.chmod(0o600)
        child=None
        try:
            child=ConfinedLifetime(['/usr/bin/sandbox-exec','-f',str(profile),PYTHON,
                '-I','-S','-B','-c',BOOTSTRAP,str(source),json.dumps(calls,allow_nan=False)],
                cwd=root,env={'PATH':'/usr/bin:/bin','PYTHONDONTWRITEBYTECODE':'1'},
                stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,seconds=6)
            output=bytearray();reason=None;eof=False;observed_bytes=0
            fd=child.guardian.stdout.fileno();os.set_blocking(fd,False)
            deadline=time.monotonic()+8
            with selectors.DefaultSelector() as selector:
                selector.register(fd,selectors.EVENT_READ)
                while not (eof and child.poll() is not None):
                    if time.monotonic()>=deadline:
                        reason='output_deadline';break
                    for key,_ in selector.select(.05):
                        chunk=os.read(key.fd,4096)
                        if not chunk:
                            eof=True;selector.unregister(key.fd)
                        else:
                            observed_bytes+=len(chunk)
                            output.extend(chunk[:max(0,MAX_OUTPUT+1-len(output))])
                            if observed_bytes>MAX_OUTPUT and reason is None:
                                reason='output_limit'
                                # Signal the qualified guardian through its
                                # owned lifetime pipe, then keep draining. A
                                # blocking wait with unread pipe data can hide
                                # the guardian's final cleanup receipt.
                                if child.life_write is not None:
                                    os.close(child.life_write)
                                    child.life_write=None
            clean=child.cleanup_group()
            self._verify()
            if not clean or child.finished is None or not child.finished['process_group_empty']:
                raise RuntimeError('checker_cleanup_unconfirmed')
            code=child.returncode
            passed=False;matched=0
            if reason is None and code!=0:reason='candidate_process_failed'
            if reason is None:passed,reason,matched=_adjudicate(bytes(output),cases)
            self.last_observation={'candidate_pid':child.pid,'guardian_pid':child.guardian.pid,
                'candidate_exit_code':code,'adjudication':reason,'registered_cases':len(cases),
                'matched_cases':matched,'output_bytes':observed_bytes,
                'retained_output_bytes':len(output),
                'output_sha256':hashlib.sha256(output).hexdigest(),'cleanup_verified':clean,
                'candidate_executed_in_host':False,'expected_values_shared_with_child':False}
            # Compatibility field: acceptance exit code, not merely child exit.
            return {'candidate_sha256':hashlib.sha256(candidate).hexdigest(),
                    'checker_sha256':self.checker_sha256,'exit_code':0 if passed else 1,
                    'cleanup_verified':clean}
        finally:
            if child is not None and not child.cleanup_group():
                raise RuntimeError('checker_cleanup_unconfirmed')
            shutil.rmtree(root)
