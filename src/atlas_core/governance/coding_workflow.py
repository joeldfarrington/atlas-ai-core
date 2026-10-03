"""Constitution checks around the existing worker and DevelopmentControl.

The host supplies fixed worker/checker functions, owner policy and observations.
This is a foreground association, not a replacement service or model tool.
"""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import time

from .cognitive_state import digest,need
from .task_contract import validate,fingerprint,render_prompt
from .correction_review import review_attempt
from atlas_core.coding_connection import CONTROL_SHA256

class CodingWorkflow:
    def __init__(self,packet,*,gate,journal,control_module,control,project,epoch,
                 owner_policy,observe,checker_pins,invariant_check=None):
        need(hashlib.sha256(Path(control_module.__file__).read_bytes()).hexdigest()==CONTROL_SHA256,
             'control_version_changed')
        need(type(control) is control_module.DevelopmentControl,'existing_control_required')
        need(type(epoch) is int and epoch>=0,'invalid_epoch')
        need(type(checker_pins) is dict and set(checker_pins)=={'public','independent'}
             and all(type(v) is str and len(v)==64 for v in checker_pins.values()),'checker_binding')
        self.packet=validate(packet);self.fp=fingerprint(self.packet)
        self.gate=gate;self.journal=journal;self.control=control
        self.project=project;self.epoch=epoch;self.policy=owner_policy;self.observe=observe
        self.pins=deepcopy(checker_pins);self.subject=self.packet['task_id']
        self._stage=None;self._inside=False;self._inflight=False
        need(invariant_check is None or callable(invariant_check), 'invalid_invariant_check')
        self._invariant_check=invariant_check

    def records(self):
        return [x for x in self.journal.events() if x['subject']==self.subject]

    def _emit(self,kind,value,*,basis='observed',refs=()):
        events=self.journal.events();now=max(int(time.time()),events[-1]['recorded_at'] if events else 0)
        event={'id':self.subject+'-'+str(len(events)+1),'kind':kind,'basis':basis,
            'subject':self.subject,'occurred_at':now,'recorded_at':now,
            'verified_at':now if basis=='tested' else None,'expires_at':None,
            'evidence':['sha256:'+v for v in refs],'supersedes':None,'value':value}
        self.journal.append(event);return event['id']

    def authorize(self,operation):
        # No second control read inside its publication writer transaction.
        if not self._inside:self.control.checkpoint(self.project,self.epoch)
        if self._invariant_check is not None:self._invariant_check()
        observation=self.observe()
        need(type(observation) is dict,'host_observation')
        current=dict(observation,project=self.project,control_epoch=self.epoch,
                     stopped=False if self._inside else self.control.status(self.project)['stopped'])
        return self.gate.assess(self.packet,operation=operation,
            authority=self.policy.read(),observations=current)

    @contextmanager
    def publication(self):
        with self.policy.guard():
            with self.control.publication_guard(self.project,self.epoch):
                self._inside=True
                try:
                    self.authorize('check_candidate');yield;self.authorize('check_candidate')
                finally:self._inside=False

    def reserve_request(self):
        need(self._stage in (1,2),'generation_not_active')
        self.authorize('local_model')
        records=self.records()
        requests=[x for x in records if x['kind']=='action' and x['value'].get('type')=='model_request']
        need(len(requests)<self.packet['max_requests'],'request_budget_exhausted')
        # One model request per generation. Auxiliary summaries cannot spend the correction.
        need(not any(x['value'].get('attempt')==self._stage for x in requests),'one_request_per_attempt')
        self._emit('action',{'type':'model_request','attempt':self._stage,
            'request':len(requests)+1,'task_fingerprint':self.fp},refs=(self.fp,))
        return len(requests)+1

    def execute(self,worker,check,*,changed_hypothesis,critique):
        need(not self.records(),'task_consumed_no_replay')
        need(callable(changed_hypothesis) or type(changed_hypothesis) is str and 0<len(changed_hypothesis.strip())<=1200,
             'bounded_correction_hypothesis_required')
        need(type(critique) is dict and set(critique)=={'risks','alternative','proceed'}
             and critique['proceed'] is True and type(critique['risks']) is list
             and critique['risks'] and type(critique['alternative']) is str,'plan_critique_required')
        self.authorize('local_model')
        with self.control.transaction(self.project,self.epoch):
            # Check again after the exclusive project reservation.
            need(not self.records(),'task_consumed_no_replay')
            self._emit('plan',{'task_fingerprint':self.fp,'steps':['observe','plan','critique','generate',
                'independent_check','reflect','report'],'goal_origin':'user_assigned',
                'controller_authorship':'Codex','execution_authority':False},basis='inference',refs=(self.fp,))
            self._emit('critique',critique,basis='inference',refs=(digest(critique),))
            final=None;feedback=''
            try:
                for attempt in (1,2):
                    self.authorize('local_model')
                    self._stage=attempt
                    self._emit('action',{'type':'worker','attempt':attempt,'task_fingerprint':self.fp},refs=(self.fp,))
                    prompt=render_prompt(self.packet)
                    if attempt==2:
                        prompt+='\nOne correction within the same task: '+feedback
                    self._inflight=True
                    outcome=worker(prompt,self.reserve_request)
                    self._stage=None
                    need(type(outcome) is dict and set(outcome)=={'complete','cleanup_verified','candidate'},'worker_receipt')
                    need(type(outcome['complete']) is bool and type(outcome['cleanup_verified']) is bool,'worker_receipt')
                    if outcome['cleanup_verified'] is not True:
                        self.control.mark_cleanup(self.project)
                    need(outcome['complete'] is True and outcome['cleanup_verified'] is True,'worker_outcome_unconfirmed')
                    self._inflight=False
                    source=outcome['candidate'];need(type(source) is bytes and 0<len(source)<=32768,'candidate_size')
                    requests=[x for x in self.records() if x['kind']=='action' and x['value'].get('type')=='model_request']
                    need(any(x['value']['attempt']==attempt for x in requests),'model_request_missing')
                    self.authorize('check_candidate')
                    self._inflight=True
                    receipt=check(source,attempt)
                    need(type(receipt) is dict and set(receipt)=={'task_fingerprint','candidate_sha256',
                        'checker_pins','public_passed','independent_passed','cleanup_verified'},'checker_receipt')
                    need(receipt['task_fingerprint']==self.fp and receipt['candidate_sha256']==hashlib.sha256(source).hexdigest()
                         and receipt['checker_pins']==self.pins,'checker_receipt_binding')
                    state=self.gate.outcome(**{k:receipt[k] for k in ('public_passed','independent_passed','cleanup_verified')})
                    if not receipt['cleanup_verified']:self.control.mark_cleanup(self.project)
                    self._inflight=not receipt['cleanup_verified']
                    self._emit('verification',dict(receipt,type='attempt',attempt=attempt,state=state),
                        basis='tested',refs=(digest(receipt),))
                    feedback=(changed_hypothesis(deepcopy(receipt)) if callable(changed_hypothesis)
                              else changed_hypothesis) if state=='failed' and attempt==1 else ''
                    need(type(feedback) is str and len(feedback.encode())<=1200,'bounded_feedback_required')
                    decision=review_attempt(self.packet,task_fingerprint=self.fp,state=state,closed=False,
                        stopped=False,now_utc=self.observe()['now_utc'],requests_used=len(requests),
                        correction_used=attempt==2,changed_hypothesis=feedback)
                    self._emit('reflection',{'type':'correction_review','attempt':attempt,'decision':decision,
                        'feedback_exposure':'published requirements only; private cases not supplied'},basis='inference',refs=(digest(receipt),))
                    final={'type':'terminal','state':state,'candidate_sha256':receipt['candidate_sha256'],
                        'task_fingerprint':self.fp,'attempts':attempt,'model_requests':len(requests),
                        'installed':False,'model_weights_trained':False,'execution_authority':False}
                    if decision['next_step']!='propose_one_correction':break
                    self.authorize('local_model')
                with self.publication():
                    terminal_id=self._emit('verification',final,basis='tested',refs=(digest(final),))
                # Guard return is separately witnessed; a saved terminal alone is insufficient.
                self._emit('verification',{'type':'publication_exit','terminal_id':terminal_id,
                    'terminal_sha256':digest(final),'cleanup_verified':True,'task_fingerprint':self.fp},
                    basis='tested',refs=(digest(final),))
            except Exception as error:
                self._stage=None
                if self._inflight:self.control.mark_cleanup(self.project)
                self._emit('reflection',{'type':'interrupted','reason':type(error).__name__,
                    'automatic_retry':False,'outcome':'unknown'},basis='inference',refs=(self.fp,))
                raise
        return self.recover()

    def recover(self):
        return recover_task(self.packet,self.journal)

def recover_task(packet,journal):
    """Read only; no control reconstruction, authority callback or worker call."""
    item=validate(packet);fp=fingerprint(item)
    records=[x for x in journal.events() if x['subject']==item['task_id']]
    base={'task_id':item['task_id'],'installed':False,'execution_authority':False,'automatic_retry':False}
    if not records:return dict(base,state='not_started')
    terminals=[x for x in records if x['kind']=='verification' and x['value'].get('type')=='terminal']
    witnesses=[x for x in records if x['kind']=='verification' and x['value'].get('type')=='publication_exit']
    if len(terminals)!=1 or len(witnesses)!=1:return dict(base,state='outcome_unconfirmed')
    terminal,witness=terminals[0],witnesses[0]
    need(terminal['value']['task_fingerprint']==fp and witness['value']['task_fingerprint']==fp
         and witness['value']['terminal_id']==terminal['id']
         and witness['value']['terminal_sha256']==digest(terminal['value'])
         and records.index(witness)>records.index(terminal),'completion_binding')
    return dict(base,**{k:terminal['value'][k] for k in ('state','candidate_sha256','attempts','model_requests')})
