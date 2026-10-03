"""Repository exercise wrapper around the retained governed coding engine.

This host-only composition creates no grant or model connection. Aider keeps its
existing admission, isolated editing, request counter and cleanup. The retained
registered checker owns objective verification. The separate reviewer receives
requirements and source/diff only; its opinion cannot override failing tests.
Host reviewer callbacks must be cancellation-cooperative. They are not plugins
or a route to model access; any model-based reviewer needs its own authorization.
"""
import asyncio
from datetime import datetime, timezone
import difflib
import inspect
import json
import math
import os
from pathlib import Path
import shutil
import stat
import time

from atlas_core.coding_gym import save, read
from atlas_core.coding_reviewer import decode_review_context, validate_precheck
from atlas_core.practice.workspace import regular, sha
from atlas_core.governance.cognitive_state import digest, need
from atlas_core.governance.action_boundary import private_identity
from atlas_core.coding_edit_feedback import public_edit_feedback, lesson_for_attempt, CATALOG_PROTOCOL, LEGACY_PROTOCOL

ARTIFACTS = ('INTENT.json','BASE.bin','REPRODUCTION.json','REPRODUCTION_RECEIPT.json',
    'BUILD.bin','REVIEW_INPUT.json','REVIEW.json','ENGINE.json','CLEANUP.json','WORKSPACE_EVIDENCE.json')
OPTIONAL_ARTIFACTS = ('MODEL_REVIEW.json','PRECHECK_RECEIPT.json','PRECHECK.json','PUBLIC_EDIT_FEEDBACK.json','REVIEW_SKIPPED.json')


def scope_review_skip(feedback):
    return dict(schema=1,protocol='public-catalog-v1',reason='public_scope_refusal',
        feedback_sha256=digest(feedback),source_sha256=feedback['source_sha256'],
        candidate_sha256=feedback['candidate_sha256'],model_requests=0,
        semantic_review_performed=False,behavioral_acceptance=False,execution_authority=False)


def scope_review_decision():
    return dict(approved=False,findings=['Public interpreter scope refused the candidate; semantic review was not requested.'])


def summarize_precheck(receipt,intent,source):
    """Expose aggregate evidence only; hidden cases stay in protected host storage."""
    need(type(receipt) is dict and receipt.get('complete') is True
         and receipt.get('cleanup_verified') is True and receipt.get('timed_out') is False
         and receipt.get('stopped') is False and type(receipt.get('exit_code')) is int
         and receipt['exit_code']==0,'gym_precheck_incomplete')
    result=receipt['result']
    stdout=receipt['stdout']
    if type(stdout) is str:stdout=bytes.fromhex(stdout)
    need(type(stdout) is bytes and json.loads(stdout)==result
         and result['source_sha256']==sha(source)
         and result['checker_sha256']==intent['checker_sha256']
         and result['source_bound'] is True and result['source_unchanged'] is True
         and type(result['errors']) is int and result['errors']==0
         and type(result['expected_cases']) is int
         and result['expected_cases']==intent['expected_cases']
         and result['counts']['cases']==intent['expected_cases'],'gym_precheck_identity')
    return validate_precheck({'source_sha256':sha(source),'checker_sha256':result['checker_sha256'],
        'status':result['status'],**{k:result['counts'][k] for k in ('cases','passed','failed')}},sha(source))


def task_class_for(execution):
    metadata = execution.session.modules['session_checker'].descriptor_contract(
        execution.session.spec['task']['checker'])
    kind = metadata.get('task_class', 'bug_fix')
    need(type(kind) is str and kind in ('bug_fix','feature','test_repair','refactoring'),
         'gym_task_class')
    return kind


def review_task_context(kind, *, prechecked=False):
    contexts = {
        'bug_fix': 'The original source failed independent reproduction before this '
            'change. This is a bug repair, not a request to preserve the defective behavior. ',
        'feature': 'The original source did not implement the required new feature. '
            'Assess the requested feature and its permitted pure behavior. ',
        'test_repair': 'The editable work product is the test suite. Independent acceptance '
            'requires it to pass a correct implementation and detect faulty implementations. '
            'Removing coverage or failing every implementation does not qualify. ',
        'refactoring': 'The original behavior is already correct; a separate refactoring '
            'requirement is unmet. Preserve behavior while meeting that requirement. ',
    }
    need(type(kind) is str and kind in contexts, 'gym_task_class')
    return contexts[kind] + 'Assess the candidate independently; ' + (
        'a separate protected-checker summary is available as bounded evidence.' if prechecked
        else 'no candidate test result is supplied here.')


def grade_engine(reproduced, reviewed, engine_state, cleanup, interrupted):
    need(all(type(x) is bool for x in (reproduced,reviewed,cleanup,interrupted)),
         'gym_exact_outcome_flags')
    if interrupted or not cleanup:
        return 'outcome_unconfirmed'
    if not reproduced:
        return 'not_reproduced'
    if engine_state not in ('accepted','failed'):
        return 'outcome_unconfirmed'
    return 'accepted' if reviewed and engine_state == 'accepted' else 'not_accepted'


def _bytes(root,name,value):
    need(type(value) is bytes and 0 < len(value) <= 32768,'gym_source_size')
    fd=os.open(root/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as out:
        out.write(value);out.flush();os.fsync(out.fileno())


def review_budget(seconds, transport_seconds=None, *, reasoning=False):
    """Use one outer ceiling; never silently truncate a selected transport."""
    need(type(reasoning) is bool,'gym_review_reasoning_mode')
    limit=105 if reasoning else 15
    if transport_seconds is not None:
        need(type(transport_seconds) in (int,float) and 0 < transport_seconds <= limit,
             'gym_review_transport_budget')
    if seconds is None:
        seconds = max(5, transport_seconds or 0)
    need(type(seconds) in (int,float) and 0 < seconds <= limit, 'gym_review_budget')
    need(transport_seconds is None or seconds >= transport_seconds,
         'gym_review_budget_shorter_than_transport')
    return seconds


class EngineCodingGym:
    def __init__(self,root,execution,backend,*,reviewer,reviewer_id,
                 reviewer_kind,review_seconds=None,scope_preflight=False):
        from atlas_core.coding_execution import RegisteredCodingExecution
        from atlas_core.coding_backends import AiderBackend
        need(type(execution) is RegisteredCodingExecution and type(backend) is AiderBackend
             and backend.execution is execution,'gym_registered_engine_required')
        backend.validate(execution)
        need(type(scope_preflight) is bool,'gym_scope_preflight_selection')
        need(inspect.iscoroutinefunction(reviewer),'gym_async_host_reviewer_required')
        need(type(reviewer_id) is str and 0 < len(reviewer_id) <= 128
             and reviewer_id != backend.description()['provider_declared'],'gym_distinct_reviewer')
        need(reviewer_kind in ('scripted_fixture','independent_host'),'gym_reviewer_provenance')
        execution.loop.authorize('check_candidate')
        self.root=Path(root).absolute()
        need('..' not in self.root.parts and not any(p.is_symlink() for p in (self.root,*self.root.parents)),
             'gym_root')
        project=execution.services.development.projects[execution.prepared.plan.project].root
        need(not self.root.is_relative_to(project) and not project.is_relative_to(self.root),
             'gym_evidence_outside_task_repository')
        from atlas_core.coding_reviewer import LocalCodingReviewer
        owner=getattr(reviewer,'__self__',None)
        self._review_port=owner if type(owner) is LocalCodingReviewer else None
        review_seconds=review_budget(review_seconds,
            owner.provider.timeout_seconds if self._review_port is not None else None,
            reasoning=bool(self._review_port and owner.provider._review_reasoning_counter_identity))
        if self._review_port is not None:
            need(backend._shared_completion and reviewer_kind=='independent_host'
                 and reviewer_id==owner.intent['provider'],'gym_review_transport_identity')
            owner.require_shared_admission(backend._completion.admission)
            need(not owner.root.is_relative_to(project) and not project.is_relative_to(owner.root),
                 'gym_reviewer_evidence_outside_task_repository')
        self.root.mkdir(mode=0o700)
        self._identity=private_identity(self.root,True)
        self.execution=self._execution=execution
        self.backend=self._backend=backend
        self.reviewer=self._reviewer=reviewer
        self._pid=os.getpid();self._used=False;self._pending_review=False
        self.review_seconds=review_seconds
        self._workspace_ids={p:private_identity(p,True) for p in (backend.worker.case,backend.worker.scratch)}
        self.base=regular(execution.prepared.source_path,32768)
        self.intent={'schema':1,'task_class':task_class_for(execution),'task_id':execution.packet['task_id'],
            'task_fingerprint':digest(execution.packet),'source_sha256':sha(self.base),
            'backend':backend.description(),'reviewer':reviewer_id,'reviewer_kind':reviewer_kind,
            'deadline_utc':execution.packet['deadline_utc'],'review_seconds':review_seconds,
            'checker_sha256':execution.session.spec['task']['checker_sha256'],
            'expected_cases':execution.session.spec['task']['expected_cases'],
            'attempts_max':1,'automatic_retry':False,'held_out':False,
            'authority_change':False,'installed':False}
        self.intent['edit_feedback_protocol']=CATALOG_PROTOCOL
        if scope_preflight:self.intent['scope_preflight']='public-catalog-v1'
        if self._review_port is not None:
            self.intent['review_transport']=dict(self._review_port.intent)
        save(self.root,'INTENT.json',self.intent);_bytes(self.root,'BASE.bin',self.base)

    def validate(self,execution):
        need(self.intent.get('edit_feedback_protocol')==CATALOG_PROTOCOL,'gym_edit_feedback_protocol_changed')
        need(self.execution is self._execution is execution and self.backend is self._backend
             and self.reviewer is self._reviewer and self._pid == os.getpid()
             and private_identity(self.root,True)==self._identity,'gym_binding_changed')
        need(read(self.root,'INTENT.json') == self.intent and regular(self.root/'BASE.bin') == self.base,
             'gym_input_changed')
        execution._local_invariants()
        if self._review_port is not None:
            self._review_port.require_shared_admission(self.backend._completion.admission)

    def _gate(self):
        self.validate(self.execution)
        self.execution.loop.authorize('check_candidate')

    def _reproduce(self):
        self._gate();session=self.execution.session
        remaining=(datetime.fromisoformat(self.intent['deadline_utc'])-datetime.now(timezone.utc)).total_seconds()
        budget=min(session.spec['limits']['checker_seconds'],remaining)
        need(budget>0,'gym_deadline')
        receipt=session.modules['session_checker'].run_check(self.base,session.spec['task']['checker'],
            timeout_seconds=budget,max_output_bytes=session.spec['limits']['checker_output_bytes'],
            should_stop=session._stop_requested,scratch_parent=self.root)
        receipt['budget_seconds']=budget
        save(self.root,'REPRODUCTION_RECEIPT.json',
             {k:v.hex() if type(v) is bytes else v for k,v in receipt.items()})
        result=session._validate_child(receipt,self.base)
        reproduced=result['status']=='behavior_fail' and result['counts']['failed']>0
        save(self.root,'REPRODUCTION.json',{'reproduced':reproduced,
            'source_sha256':sha(self.base),'checker_sha256':result['checker_sha256'],
            'cases':result['counts']['cases']})
        self._gate()
        return reproduced

    def review_candidate(self,source):
        self._gate()
        need(not (self.root/'BUILD.bin').exists(),'gym_one_review')
        _bytes(self.root,'BUILD.bin',source)
        feedback=public_edit_feedback(self.base,source,protocol=self.intent['edit_feedback_protocol'])
        save(self.root,'PUBLIC_EDIT_FEEDBACK.json',feedback)
        # A selected, source-bound public grammar refusal is sufficient to skip
        # semantic review, never sufficient to accept a candidate. The protected
        # checker still runs and the original failed proposal remains retained.
        if (self.intent.get('scope_preflight')=='public-catalog-v1'
                and feedback.get('protocol')==CATALOG_PROTOCOL
                and feedback['basis']=='public_interpreter_scope'
                and feedback['status']=='outside_boundary'):
            save(self.root,'REVIEW_SKIPPED.json',scope_review_skip(feedback))
            save(self.root,'REVIEW.json',scope_review_decision())
            self._gate()
            return
        verification=None
        if self._review_port is not None and self._review_port.intent.get('independent_precheck') is True:
            session=self.execution.session
            remaining=(datetime.fromisoformat(self.intent['deadline_utc'])-datetime.now(timezone.utc)).total_seconds()
            budget=min(session.spec['limits']['checker_seconds'],remaining)
            need(budget>0,'gym_deadline')
            receipt=session.modules['session_checker'].run_check(source,session.spec['task']['checker'],
                timeout_seconds=budget,max_output_bytes=session.spec['limits']['checker_output_bytes'],
                should_stop=session._stop_requested,scratch_parent=self.root)
            receipt['budget_seconds']=budget
            save(self.root,'PRECHECK_RECEIPT.json',
                 {k:v.hex() if type(v) is bytes else v for k,v in receipt.items()})
            session._validate_child(receipt,source)
            verification=summarize_precheck(receipt,self.intent,source)
            save(self.root,'PRECHECK.json',verification)
            self._gate()
        from atlas_core.coding_backends import public_execution_constraints
        requirements=list(self.execution.packet['requirements'])
        constraints=public_execution_constraints(self.execution.session.spec['task'])
        if constraints: requirements.append(constraints)
        if feedback['findings']:
            requirements.append('Host public edit-boundary observation (not behavioral acceptance): '
                +' '.join(feedback['findings']))
        need(task_class_for(self.execution) == self.intent['task_class'],'gym_task_class_changed')
        requirements.append(review_task_context(self.intent['task_class'],prechecked=verification is not None))
        payload={'task_id':self.intent['task_id'],'requirements':requirements,
            'base_source':self.base.decode(),'candidate_source':source.decode(),
            'diff':''.join(difflib.unified_diff(self.base.decode().splitlines(True),
                source.decode().splitlines(True),fromfile='before',tofile='candidate'))}
        save(self.root,'REVIEW_INPUT.json',payload)
        async def call():
            call_review=(self.reviewer(payload,verification=verification)
                         if verification is not None else self.reviewer(payload))
            task=asyncio.create_task(call_review);self._pending_review=True
            deadline=time.monotonic()+self.review_seconds
            try:
                while not task.done():
                    self._gate();need(time.monotonic()<deadline,'gym_review_timeout')
                    await asyncio.wait({task},timeout=.02)
                result=task.result();self._gate()
                need(type(result) is dict and set(result)=={'approved','findings'}
                     and type(result['approved']) is bool and type(result['findings']) is list
                     and len(result['findings'])<=16 and all(type(x) is str and 0<len(x)<=512
                         for x in result['findings']),'gym_review_shape')
                return result
            finally:
                if not task.done():
                    task.cancel();await asyncio.wait({task},timeout=.25)
                self._pending_review=not task.done()
        try:
            result=asyncio.run(call())
        finally:
            if self._review_port is not None:
                save(self.root,'MODEL_REVIEW.json',self._review_port.snapshot())
        save(self.root,'REVIEW.json',result)

    def _dispose(self):
        """Remove only the two identity-pinned disposable Aider directories."""
        worker=self.backend.worker
        try:
            need(not self._pending_review,'gym_review_cleanup_unknown')
            need(worker.child_pid is None or type(worker.receipt) is dict
                 and worker.receipt.get('cleanup_verified') is True,'gym_worker_cleanup_unknown')
            if self.backend._shared_completion:
                need(not self.backend._completion.admission.status()['requires_recovery'],
                     'gym_model_outcome_unknown')
            archive=self.root/'workspace-evidence';archive.mkdir(mode=0o700)
            inventory={};total=0
            for directory,identity in self._workspace_ids.items():
                need(private_identity(directory,True)==identity,'gym_workspace_replaced')
                for path in sorted(directory.rglob('*')):
                    need(not path.is_symlink(),'gym_unexpected_link')
                    info=path.lstat();need(info.st_uid==os.getuid(),'gym_workspace_owner')
                    relative=directory.name+'/'+str(path.relative_to(directory))
                    dest=archive/relative
                    if stat.S_ISDIR(info.st_mode):
                        dest.mkdir(parents=True,exist_ok=True,mode=0o700);continue
                    need(stat.S_ISREG(info.st_mode) and info.st_nlink==1,'gym_unexpected_node')
                    raw=regular(path,1048576);total+=len(raw)
                    need(total<=2097152 and len(inventory)<512,'gym_archive_bound')
                    dest.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
                    fd=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                    with os.fdopen(fd,'wb') as out:out.write(raw)
                    need(sha(regular(dest,1048576))==sha(raw),'gym_archive_changed')
                    inventory[relative]=sha(raw)
            save(self.root,'WORKSPACE_EVIDENCE.json',inventory)
            for directory,identity in self._workspace_ids.items():
                need(private_identity(directory,True)==identity,'gym_workspace_replaced')
                shutil.rmtree(directory)
            return True
        except (OSError,ValueError):
            return False

    def run(self,*,critique):
        need(not self._used,'gym_attempt_consumed');self._used=True
        started=time.monotonic();reproduced=False;engine={};failure=None
        try:
            self._gate();reproduced=self._reproduce()
            if reproduced:
                self.backend.bind_candidate_review(self)
                engine=self.execution.execute_backend(self.backend,critique=critique)
                self._gate()
        except Exception as error:
            failure=type(error).__name__
            engine=self.execution.recover()
        backend=(self.execution.session._read('BACKEND_OUTCOME.json')
                 if self.execution.session._has('BACKEND_OUTCOME.json') else {})
        checker=(self.execution.session._read('CHECKER_RECEIPT.json')
                 if self.execution.session._has('CHECKER_RECEIPT.json') else {})
        save(self.root,'ENGINE.json',{'result':engine,'backend':backend,'checker':checker,
            'failure':failure,'elapsed_seconds':time.monotonic()-started})
        cleanup=self._dispose()
        save(self.root,'CLEANUP.json',{'workspace_discarded':cleanup,
            'original_source_unchanged':regular(self.execution.prepared.source_path,32768)==self.base})
        review=read(self.root,'REVIEW.json') if (self.root/'REVIEW.json').exists() else {}
        complete=checker.get('complete') is True and checker.get('cleanup_verified') is True
        outcome=grade_engine(reproduced,review.get('approved') is True,engine.get('state'),cleanup,failure is not None)
        result={'schema':1,'record_kind':'engine_gym','task_class':self.intent['task_class'],'task_id':self.intent['task_id'],
            'task_fingerprint':self.intent['task_fingerprint'],'backend':self.intent['backend']['backend'],
            'model':self.intent['backend']['provider_declared'],
            'evidence_kind':self.intent['backend']['evidence_kind'],'reviewer_kind':self.intent['reviewer_kind'],
            'outcome':outcome,'reproduced':reproduced,'review_approved':review.get('approved') is True,
            'verifier_complete':complete,'verifier_passed':complete and engine.get('state')=='accepted',
            'tests_run':checker.get('result',{}).get('counts',{}).get('cases',0) if complete else 0,
            'attempts':backend.get('attempts',0),'requests':backend.get('requests',0),
            'workspace_discarded':cleanup,'elapsed_seconds':time.monotonic()-started,
            'model_reliability_observation':self.intent['backend']['evidence_kind']=='local_model'
                and self.intent['reviewer_kind']=='independent_host',
            'cost':None,'human_interventions':None,'installed':False,'authority_change':False,
            'reliability_qualified':False,'held_out':False,
            'requests_scope':'builder_only; separate model review is retained in MODEL_REVIEW.json',
            'evidence':{n:sha(regular(self.root/n)) for n in ARTIFACTS+OPTIONAL_ARTIFACTS if (self.root/n).exists()}}
        save(self.root,'RESULT.json',result)
        save(self.root,'STRATEGY.json',{'schema':1,'task_id':result['task_id'],
            'result_sha256':sha(regular(self.root/'RESULT.json')),'task_class':self.intent['task_class'],
            'backend':result['backend'],'model':result['model'],'outcome':outcome,
            'attempts':result['attempts'],'tests_run':result['tests_run'],
            'strategy_class':'reproduce_aider_edit_separate_review_fixed_verification',
            'lesson':lesson_for_attempt(outcome,result['tests_run'],
                read(self.root,'PUBLIC_EDIT_FEEDBACK.json') if (self.root/'PUBLIC_EDIT_FEEDBACK.json').exists() else None),
            'skill_status':'proposed_not_adopted','execution_authority':False,
            'benchmark_solution_included':False})
        return recover_engine_gym(self.root)


def recover_engine_gym(root):
    """Private immutable evidence only; never reconstruct a job or provider."""
    root=Path(root).absolute();private_identity(root,True)
    intent=read(root,'INTENT.json')
    if not (root/'RESULT.json').exists() or not (root/'STRATEGY.json').exists():
        return {'task_id':intent['task_id'],'outcome':'outcome_unconfirmed','replayed':False}
    result=read(root,'RESULT.json')
    present={n for n in ARTIFACTS+OPTIONAL_ARTIFACTS if (root/n).exists()}
    need(set(result['evidence'])==present and {'INTENT.json','BASE.bin','ENGINE.json','CLEANUP.json'}<=present,
         'gym_evidence_missing')
    for name,pin in result['evidence'].items():
        need(sha(regular(root/name))==pin,'gym_evidence_changed')
    engine=read(root,'ENGINE.json');cleanup=read(root,'CLEANUP.json')
    rep=read(root,'REPRODUCTION.json') if 'REPRODUCTION.json' in present else {}
    review=read(root,'REVIEW.json') if 'REVIEW.json' in present else {}
    reproduced=rep.get('reproduced') is True
    expected=grade_engine(reproduced,review.get('approved') is True,engine['result'].get('state'),
                          cleanup['workspace_discarded'],engine['failure'] is not None)
    need(result['task_id']==intent['task_id'] and result['task_fingerprint']==intent['task_fingerprint']
         and result['outcome']==expected and result['reproduced'] is reproduced
         and result['review_approved'] is (review.get('approved') is True)
         and result['workspace_discarded'] is cleanup['workspace_discarded']
         and cleanup['original_source_unchanged'] is True,'gym_result_conflict')
    need(sha(regular(root/'BASE.bin'))==intent['source_sha256'],'gym_base_changed')
    if reproduced:
        need(rep['source_sha256']==intent['source_sha256']
             and rep['checker_sha256']==intent['checker_sha256']
             and rep['cases']==intent['expected_cases'],'gym_reproduction_identity')
        receipt=read(root,'REPRODUCTION_RECEIPT.json')
        need(receipt['complete'] is True and receipt['cleanup_verified'] is True
             and receipt['timed_out'] is False and receipt['stopped'] is False
             and type(receipt['exit_code']) is int and receipt['exit_code']==0
             and json.loads(bytes.fromhex(receipt['stdout']))==receipt['result']
             and receipt['result']['status']=='behavior_fail'
             and receipt['result']['counts']['failed']>0
             and receipt['result']['source_sha256']==intent['source_sha256']
             and receipt['result']['checker_sha256']==intent['checker_sha256'],
             'gym_reproduction_receipt_changed')
    checker=engine['checker'];backend=engine['backend']
    complete=checker.get('complete') is True and checker.get('cleanup_verified') is True
    observed=engine['result'].get('state')
    derived={'backend':intent['backend']['backend'],'model':intent['backend']['provider_declared'],
        'evidence_kind':intent['backend']['evidence_kind'],'reviewer_kind':intent['reviewer_kind'],
        'verifier_complete':complete,'verifier_passed':complete and observed=='accepted',
        'tests_run':checker.get('result',{}).get('counts',{}).get('cases',0) if complete else 0,
        'attempts':backend.get('attempts',0),'requests':backend.get('requests',0),
        'model_reliability_observation':intent['backend']['evidence_kind']=='local_model'
            and intent['reviewer_kind']=='independent_host'}
    if 'task_class' in intent:
        need(type(intent['task_class']) is str and intent['task_class'] in
            ('bug_fix','feature','test_repair','refactoring'),'gym_task_class')
        derived['task_class'] = intent['task_class']
    need(all(type(result.get(k)) is type(v) and result.get(k)==v for k,v in derived.items()),
         'gym_metrics_conflict_with_evidence')
    need(type(result['elapsed_seconds']) in (int,float) and math.isfinite(result['elapsed_seconds'])
         and result['elapsed_seconds']>=engine['elapsed_seconds']>=0,'gym_elapsed')
    if backend:
        need(all(backend.get(k)==intent['backend'].get(k) for k in ('backend','provider_declared',
            'evidence_kind','task_fingerprint','runtime_pins_sha256')),'gym_backend_evidence_changed')
    if complete:
        need(json.loads(bytes.fromhex(checker['stdout']))==checker['result']
             and checker['result']['source_sha256']==sha(regular(root/'BUILD.bin'))
             and checker['result']['checker_sha256']==intent['checker_sha256']
             and checker['result']['expected_cases']==intent['expected_cases'],
             'gym_verifier_identity_changed')
    if 'REVIEW_INPUT.json' in present:
        payload=read(root,'REVIEW_INPUT.json')
        need(payload['task_id']==intent['task_id']
             and payload['base_source'].encode()==regular(root/'BASE.bin')
             and payload['candidate_source'].encode()==regular(root/'BUILD.bin'),
             'gym_review_source_changed')
    if 'PUBLIC_EDIT_FEEDBACK.json' in present:
        need(read(root,'PUBLIC_EDIT_FEEDBACK.json')==public_edit_feedback(
            regular(root/'BASE.bin'),regular(root/'BUILD.bin'),
            protocol=intent.get('edit_feedback_protocol',LEGACY_PROTOCOL)),'gym_public_edit_feedback_changed')
    selected_scope=intent.get('scope_preflight')
    need(selected_scope in (None,'public-catalog-v1'),'gym_scope_preflight_version')
    if 'REVIEW_SKIPPED.json' in present:
        feedback=public_edit_feedback(regular(root/'BASE.bin'),regular(root/'BUILD.bin'),
            protocol=intent.get('edit_feedback_protocol',LEGACY_PROTOCOL))
        need(selected_scope=='public-catalog-v1' and feedback.get('protocol')==CATALOG_PROTOCOL
             and feedback['basis']=='public_interpreter_scope' and feedback['status']=='outside_boundary'
             and digest(read(root,'REVIEW_SKIPPED.json'))==digest(scope_review_skip(feedback))
             and digest(review)==digest(scope_review_decision())
             and not {'MODEL_REVIEW.json','REVIEW_INPUT.json','PRECHECK.json','PRECHECK_RECEIPT.json'}&present,
             'gym_scope_review_skip_invalid')
    elif selected_scope=='public-catalog-v1' and 'PUBLIC_EDIT_FEEDBACK.json' in present:
        feedback=read(root,'PUBLIC_EDIT_FEEDBACK.json')
        if (feedback.get('protocol')==CATALOG_PROTOCOL and feedback['basis']=='public_interpreter_scope'
                and feedback['status']=='outside_boundary' and review):
            need(False,'gym_scope_review_skip_missing')
    selected_precheck=intent.get('review_transport',{}).get('independent_precheck') is True
    if selected_precheck and 'REVIEW_INPUT.json' in present:
        need({'PRECHECK.json','PRECHECK_RECEIPT.json'}<=present,'gym_precheck_missing')
        summary=summarize_precheck(read(root,'PRECHECK_RECEIPT.json'),intent,regular(root/'BUILD.bin'))
        need(read(root,'PRECHECK.json')==summary,'gym_precheck_changed')
    elif not selected_precheck:
        need(not {'PRECHECK.json','PRECHECK_RECEIPT.json'}&present,'gym_precheck_unselected')
    if 'review_transport' in intent and 'REVIEW_INPUT.json' in present:
        need('MODEL_REVIEW.json' in present,'gym_model_review_missing')
        model_review=read(root,'MODEL_REVIEW.json')
        need(model_review['intent']==intent['review_transport'],'gym_model_review_identity')
        if selected_precheck and model_review.get('request'):
            need(model_review['request'].get('independent_precheck')==summary,
                 'gym_model_precheck_conflict')
        if review:
            need(model_review['outcome']=='review_received' and model_review['decision']==review
                 and model_review['authority_change'] is False and model_review['coding_success'] is False
                 and decode_review_context(model_review['request']['messages'][1]['content'])==payload,
                 'gym_model_review_conflict')
    if cleanup['workspace_discarded']:
        need('WORKSPACE_EVIDENCE.json' in present,'gym_workspace_archive_missing')
        inventory=read(root,'WORKSPACE_EVIDENCE.json')
        need(type(inventory) is dict and len(inventory)<=512,'gym_workspace_archive_bound')
        for name,pin in inventory.items():
            path=Path(name)
            need(type(name) is str and path.as_posix()==name and not path.is_absolute()
                 and '..' not in path.parts and len(path.parts)>1
                 and path.parts[0] in ('case','scratch'),'gym_workspace_archive_path')
            need(sha(regular(root/'workspace-evidence'/path,1048576))==pin,
                 'gym_workspace_archive_changed')
    if expected=='accepted':
        need(set(ARTIFACTS)<=present and engine['backend'].get('independent_accepted') is True
             and engine['checker'].get('complete') is True
             and engine['checker'].get('cleanup_verified') is True
             and engine['result']['candidate_sha256']==sha(regular(root/'BUILD.bin')),
             'gym_acceptance_incomplete')
    need(result['installed'] is False and result['authority_change'] is False
         and result['reliability_qualified'] is False,'gym_authority_claim')
    strategy=read(root,'STRATEGY.json')
    if 'task_class' in intent:
        need(strategy.get('task_class') == intent['task_class'],'gym_strategy_class_conflict')
    need(strategy['result_sha256']==sha(regular(root/'RESULT.json'))
         and strategy['execution_authority'] is False and strategy['benchmark_solution_included'] is False,
         'gym_strategy_binding')
    if 'PUBLIC_EDIT_FEEDBACK.json' in present:
        need(strategy['lesson']==lesson_for_attempt(result['outcome'],result['tests_run'],
            read(root,'PUBLIC_EDIT_FEEDBACK.json')),'gym_strategy_lesson_conflict')
    return result
