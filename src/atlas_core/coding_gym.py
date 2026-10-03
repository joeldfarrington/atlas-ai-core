"""Disposable, fixed-exercise coding gym built on the existing Practice engine.

Builder and Reviewer are trusted host-supplied async data ports, not executable
plugins or model tools. They receive explicit projections, never verifier files.
Candidate code runs only inside PracticeWorkspace's protected checker. This
module grants no model/provider access and installs nothing. A real provider
also needs separately qualified shared admission and cancellation controls.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import difflib
import json
import math
import os
from pathlib import Path
import shutil
import time
import uuid

from atlas_core.coding_backends import select_backend
from atlas_core.practice.workspace import PracticeWorkspace, need, regular, sha


ARTIFACTS = ('INTENT.json', 'OBSERVATION.json', 'REPRODUCTION.json',
             'BUILDER_DISPATCH.json', 'BUILD.json', 'REVIEW.json', 'VERIFY.json', 'COMPLETION.json', 'CLEANUP.json')


class NotReproduced(ValueError):
    pass


def save(root, name, value):
    raw = (json.dumps(value, sort_keys=True, allow_nan=False, indent=2)+'\n').encode()
    need(len(raw) <= 65536, 'Gym evidence too large.')
    fd = os.open(root/name, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(raw); out.flush(); os.fsync(out.fileno())


def read(root, name):
    return json.loads(regular(root/name))


def grade(reproduction, review, verification, *, interrupted, cleanup):
    reproduced = reproduction.get('complete') is True and reproduction.get('passed') is False
    verified = verification.get('complete') is True and verification.get('passed') is True
    reviewed = review.get('approved') is True
    if interrupted or not cleanup:
        return 'outcome_unconfirmed'
    if not reproduced:
        return 'not_reproduced'
    return 'accepted' if verified and reviewed else 'not_accepted'


class CodingGym:
    """One disposable training attempt; restart reads evidence, never replays."""
    def __init__(self, root, *, exercise_id, authorize, deadline_utc,
                 builder_id, reviewer_id, model_id, evidence_kind='scripted_fixture'):
        need(evidence_kind == 'scripted_fixture',
             'Actual-model Gym admission and cancellation are not qualified yet.')
        need(callable(authorize) and authorize('gym_create') is True, 'Owner authority required.')
        need(type(builder_id) is str and type(reviewer_id) is str and
             builder_id != reviewer_id and 0 < len(builder_id) <= 128 and
             0 < len(reviewer_id) <= 128, 'Distinct bounded role identities required.')
        need(type(model_id) is str and 0 < len(model_id) <= 128, 'Model identity required.')
        deadline = datetime.fromisoformat(deadline_utc)
        need(deadline.tzinfo is not None, 'UTC-aware deadline required.')
        remaining = (deadline-datetime.now(timezone.utc)).total_seconds()
        need(0 < remaining <= 300, 'Bounded Gym deadline required.')
        self.root = Path(root).absolute()
        need(not any(p.is_symlink() for p in (self.root,*self.root.parents)), 'Symlink root refused.')
        self.root.mkdir(mode=0o700)
        self._identity=(self.root.stat().st_dev,self.root.stat().st_ino)
        self.authorize=authorize; self.deadline=time.monotonic()+remaining
        self._used=False; self._pending_port=None
        self.backend=select_backend('practice-tools',task_kind='catalog_pure_function')
        self.intent={'schema':1,'run_id':str(uuid.uuid4()),'exercise':exercise_id,
            'backend':self.backend.identifier,'backend_version':self.backend.version,
            'builder':builder_id,'reviewer':reviewer_id,'verifier':'practice-protected-checker',
            'model':model_id,'evidence_kind':evidence_kind,'attempts_max':1,
            'deadline_utc':deadline_utc,'authority_reference':'current_host_callback',
            'execution_authority':False,'deployment_authority':False,'held_out':False}
        save(self.root,'INTENT.json',self.intent)
        if exercise_id=='quantity-v1':
            package=Path(__file__).parent/'practice'
            self.workspace=PracticeWorkspace.create(self.root/'workspace',checker=package/'checker.py',
                tests=[package/'protected_tests/test_parse.py',package/'protected_tests/test_contract.py'],
                seed=regular(package/'starter.txt').decode(),authorize=lambda action:self._gate(action))
        else:
            self.workspace=PracticeWorkspace.create_exercise(self.root/'workspace',
                exercise_id=exercise_id,authorize=lambda action:self._gate(action))

    def _gate(self, action):
        need(not self.root.is_symlink() and
             (self.root.stat().st_dev,self.root.stat().st_ino)==self._identity, 'Gym root changed.')
        need(time.monotonic()<self.deadline, 'Gym deadline expired.')
        need(not os.path.lexists(self.root/'STOP'), 'Gym stopped.')
        need(self.authorize(action) is True, 'Gym authority unavailable.')
        return True

    def stop(self):
        # Owner control; no Resume operation and no policy update.
        save(self.root,'STOP',{'stopped':True})

    async def _call(self, port, payload, stage):
        self._gate(stage)
        need(callable(port), 'Trusted async role port required.')
        # A cancellation-aware provider is still required for any future real
        # model admission. This bounds supported asynchronous fixture ports.
        task=asyncio.create_task(port(payload));self._pending_port=task
        try:
            while not task.done():
                self._gate(stage+'_poll')
                await asyncio.wait({task},timeout=min(.05,max(.001,self.deadline-time.monotonic())))
            result=task.result()
            self._gate(stage+'_returned')
            return result
        finally:
            if not task.done():
                task.cancel()
                await asyncio.wait({task},timeout=.25)
            if task.done():self._pending_port=None

    async def run(self, *, builder, reviewer):
        need(not self._used and builder is not reviewer, 'One attempt and separate role ports required.')
        self._used=True
        started=time.monotonic(); reproduction={};review={};verification={};built={}
        interrupted=False;failure=None;cleanup=False
        try:
            observed=self.workspace.read();save(self.root,'OBSERVATION.json',observed)
            reproduction=self.workspace.check();save(self.root,'REPRODUCTION.json',reproduction)
            if not (reproduction['complete'] is True and reproduction['passed'] is False):
                raise NotReproduced('Failure not reproduced; investigate instead of claiming a repair.')
            public={'exercise':observed['exercise'],'problem':observed['contract'],
                'source':observed['content'],'source_sha256':observed['source_sha256'],
                'reproduction':{'complete':reproduction['complete'],'passed':reproduction['passed']},
                'requirements':'Return source, strategy, confidence, claimed_success. No hidden tests, tools, grants or known solutions.'}
            self._gate('builder_dispatch')
            save(self.root,'BUILDER_DISPATCH.json',{'attempt':1,'builder':self.intent['builder'],
                'utc':datetime.now(timezone.utc).isoformat(),'model_calls':0,'fixture':True})
            proposal=await self._call(builder,public,'builder')
            need(type(proposal) is dict and set(proposal)=={'source','strategy','confidence','claimed_success'},
                 'Builder result shape refused.')
            need(type(proposal['source']) is str and 0<len(proposal['source'].encode())<=16384 and
                 type(proposal['strategy']) is str and 0<len(proposal['strategy'])<=2048 and
                 type(proposal['confidence']) in (int,float) and math.isfinite(proposal['confidence']) and
                 0<=proposal['confidence']<=1 and type(proposal['claimed_success']) is bool,
                 'Bounded Builder data required.')
            built=dict(proposal)
            save(self.root,'BUILD.json',built)
            # Reviewer never receives Builder strategy, confidence or success claim.
            review_input={'exercise':observed['exercise'],'problem':observed['contract'],
                'base_source':observed['content'],'candidate_source':built['source'],
                'diff':''.join(difflib.unified_diff(observed['content'].splitlines(True),
                    built['source'].splitlines(True),fromfile='before/solution.py',tofile='after/solution.py'))}
            critique=await self._call(reviewer,review_input,'reviewer')
            need(type(critique) is dict and set(critique)=={'approved','findings'} and
                 type(critique['approved']) is bool and type(critique['findings']) is list and
                 len(critique['findings'])<=16 and all(type(s) is str and 0<len(s)<=512 for s in critique['findings']),
                 'Bounded independent review required.')
            review=dict(critique)
            save(self.root,'REVIEW.json',review)
            # Reuse the existing transactional writer and protected AST/OS checker.
            self.workspace.write(content=built['source'],expected_sha256=observed['source_sha256'])
            verification=self.workspace.check();save(self.root,'VERIFY.json',verification)
            current=self.workspace.read()
            need(verification['source_sha256']==current['source_sha256']==sha(built['source'].encode()),
                 'Verifier source identity changed.')
            self._gate('publish')
        except NotReproduced as exc:
            failure=type(exc).__name__
        except (Exception, asyncio.CancelledError) as exc:
            interrupted=True;failure=type(exc).__name__
        finally:
            save(self.root,'COMPLETION.json',{'interrupted':interrupted,'failure_mode':failure})
            cleanup=self._dispose()
            save(self.root,'CLEANUP.json',{'workspace_discarded':cleanup,'production_changed':False})
        state=grade(reproduction,review,verification,interrupted=interrupted,cleanup=cleanup)
        record={'schema':1,'run_id':self.intent['run_id'],'exercise':self.intent['exercise'],
            'task_class':'pure_function_bug','backend':self.intent['backend'],
            'model':self.intent['model'],'evidence_kind':self.intent['evidence_kind'],
            'outcome':state,'interrupted':interrupted,'failure_mode':failure,
            'reproduced':reproduction.get('complete') is True and reproduction.get('passed') is False,
            'review_approved':review.get('approved') is True,'reviewer_findings':review.get('findings',[]),
            'verifier_complete':verification.get('complete') is True,
            'verifier_passed':verification.get('passed') is True,
            'tests_run':verification.get('tests_run',0),'cleanup_verified':cleanup,
            'claimed_success':built.get('claimed_success') is True,
            'confidence':built.get('confidence'),'attempts':int((self.root/'BUILDER_DISPATCH.json').exists()),
            'elapsed_seconds':time.monotonic()-started,'compute_cost':None,'api_cost':None,
            'human_interventions':None,'unauthorized_actions_observed':None,
            'regression_result':None,'recovery_result':None,'rollback_result':None,
            'authority_change':False,'installed':False,'reliability_qualified':False}
        evidence={name:sha(regular(self.root/name)) for name in ARTIFACTS if (self.root/name).exists()}
        record['evidence']=evidence
        save(self.root,'RESULT.json',record)
        # Strategies are data, not trusted skills or authority. No answer text or
        # hidden-test artifacts enter this reusable strategy projection.
        save(self.root,'STRATEGY.json',{'schema':1,'run_id':record['run_id'],
            'task_class':record['task_class'],'backend':record['backend'],'model':record['model'],
            'result_sha256':sha(regular(self.root/'RESULT.json')),
            'outcome':state,'confidence':record['confidence'],'attempts':record['attempts'],
            'tests_run':record['tests_run'],'elapsed_seconds':record['elapsed_seconds'],
            'tools_with_completed_evidence':(['practice.read'] if 'OBSERVATION.json' in record['evidence'] else [])+
                (['practice.write'] if 'VERIFY.json' in record['evidence'] else [])+
                (['practice.check'] if 'REPRODUCTION.json' in record['evidence'] else []),
            'strategy_class':'reproduce_then_bounded_edit_then_independent_check',
            'private_attempt_artifact':record['evidence'].get('BUILD.json'),
            'reviewer_findings_count':len(record['reviewer_findings']),
            'failure_mode':record['failure_mode'],'cleanup_verified':cleanup,
            'lesson':('Independent checks and review agreed.' if state=='accepted' else
                      'Retain the observed failure; investigate before changing strategy.'),
            'skill_status':'proposed_not_adopted','execution_authority':False,
            'benchmark_solution_included':False})
        return recover_gym(self.root)

    def _dispose(self):
        path=self.root/'workspace'
        try:
            need(self._pending_port is None, 'Provider cleanup unconfirmed; preserve workspace.')
            # Only this constructor's private workspace may be discarded. The
            # retained checker verifies its own child cleanup before publication.
            need(self.workspace.root==path and self.workspace._directory_identity()==self.workspace._identity,
                 'Disposable workspace identity changed.')
            state=self.workspace._state()
            need(state['in_flight'] is False, 'Unconfirmed operation requires recovery; preserve files.')
            archive=self.root/'execution-evidence';archive.mkdir(mode=0o700)
            for f in path.iterdir():
                need(not f.is_symlink() and f.is_file(), 'Unexpected disposable entry.')
                raw=regular(f)
                target=archive/f.name
                fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'wb') as out:out.write(raw)
            shutil.rmtree(path)
            return not path.exists()
        except (OSError,ValueError):return False


def recover_gym(root):
    """Validate durable evidence and return it; never reconstruct or dispatch."""
    root=Path(root).absolute();intent=read(root,'INTENT.json')
    if not (root/'RESULT.json').exists():
        return {'run_id':intent['run_id'],'outcome':'outcome_unconfirmed','replayed':False}
    result=read(root,'RESULT.json')
    present={name for name in ARTIFACTS if (root/name).exists()}
    need(intent['evidence_kind']=='scripted_fixture' and intent['attempts_max']==1 and
         type(result['schema']) is int and result['schema']==1 and
         result['run_id']==intent['run_id'] and type(result['evidence']) is dict and
         set(result['evidence'])==present and
         {'INTENT.json','COMPLETION.json','CLEANUP.json'}<=present, 'Gym result identity refused.')
    for name,pin in result['evidence'].items():
        need(sha(regular(root/name))==pin, 'Gym evidence changed.')
    get=lambda n:read(root,n) if n in result['evidence'] else {}
    completion=get('COMPLETION.json'); cleanup=get('CLEANUP.json')
    need(type(completion['interrupted']) is bool and
         result['interrupted'] is completion['interrupted'] and
         result['failure_mode']==completion['failure_mode'], 'Completion identity changed.')
    expected=grade(get('REPRODUCTION.json'),get('REVIEW.json'),get('VERIFY.json'),
        interrupted=completion['interrupted'],cleanup=cleanup.get('workspace_discarded') is True)
    need(expected==result['outcome'], 'Gym outcome conflicts with evidence.')
    for key in ('exercise','backend','model','evidence_kind'):
        need(result[key]==intent[key], 'Gym role identity changed.')
    need(result['task_class']=='pure_function_bug', 'Task classification changed.')
    rep=get('REPRODUCTION.json'); review=get('REVIEW.json'); verify=get('VERIFY.json'); build=get('BUILD.json')
    derived={'reproduced':rep.get('complete') is True and rep.get('passed') is False,
        'review_approved':review.get('approved') is True,'reviewer_findings':review.get('findings',[]),
        'verifier_complete':verify.get('complete') is True,'verifier_passed':verify.get('passed') is True,
        'tests_run':verify.get('tests_run',0),'cleanup_verified':cleanup.get('workspace_discarded') is True,
        'claimed_success':build.get('claimed_success') is True,'confidence':build.get('confidence'),
        'attempts':int('BUILDER_DISPATCH.json' in present)}
    need(all(type(result[k]) is type(v) and result[k]==v for k,v in derived.items()),
         'Gym metrics conflict with evidence.')
    if expected=='accepted':
        need(present==set(ARTIFACTS) and verify['source_sha256']==sha(build['source'].encode()) and
             rep['source_sha256']==get('OBSERVATION.json')['source_sha256'], 'Acceptance source mismatch.')
    need(not cleanup['workspace_discarded'] or not (root/'workspace').exists(), 'Cleanup claim is false.')
    need(result['authority_change'] is False and result['installed'] is False and
         result['reliability_qualified'] is False, 'Gym cannot grant authority or claim installation.')
    return dict(result,replayed=False)
