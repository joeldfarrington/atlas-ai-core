"""Shared local inference reservation using Atlas's existing work ledger/lock.

This is a trusted host integration, not a permission issuer or model tool. All
cooperating native and external callers must bind the same journal and lock.
An idle observation, vanished PID or expired deadline never clears a request.
Forced cancellation leaves the durable reservation unresolved: closing an HTTP client
does not prove that a separate inference server stopped computing.
"""
import asyncio
from dataclasses import dataclass
import math
import os
import threading
import time
import uuid
from urllib.parse import urlsplit

from atlas_core.errors import ProviderError
from atlas_core.governance.cognitive_state import CognitiveJournal, digest, need
from atlas_core.governance.work_admission import SharedWorkAdmission, admission_status
from atlas_core.models.base import ModelResponse


class ModelAdmissionRefused(ProviderError):
    """No provider fallback or unchanged retry is permitted for this condition."""


class ModelAdmissionDrained(ModelAdmissionRefused):
    """Transport settled after host cancellation; output must not be used."""


@dataclass(frozen=True)
class LocalModelProfile:
    base_url: str
    model: str
    max_tokens: int

    def validate(self):
        need(type(self.base_url) is str,'fixed_local_model_endpoint_required')
        parsed=urlsplit(self.base_url)
        need(type(self.base_url) is str and parsed.scheme=='http' and parsed.hostname=='127.0.0.1'
             and parsed.port is not None and 1024<=parsed.port<=65535 and parsed.path=='/v1'
             and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment,
             'fixed_local_model_endpoint_required')
        need(type(self.model) is str and 0<len(self.model)<=128 and
             type(self.max_tokens) is int and 1<=self.max_tokens<=4096,'bounded_model_profile_required')


class LocalModelAdmission:
    """Finite host-selected resource scope, separate from action authority."""
    def __init__(self, *, journal, lock_path, lock_identity, profile, deadline,
                 max_requests, custody_check, authority_check, resources_check, drain_check=None):
        need(type(journal) is CognitiveJournal and type(profile) is LocalModelProfile,
             'qualified_journal_and_profile_required')
        profile.validate()
        need(type(deadline) in (int,float) and math.isfinite(deadline) and
             time.time()<deadline<=time.time()+2700,'bounded_admission_deadline_required')
        need(type(max_requests) is int and 1<=max_requests<=6,'bounded_request_budget_required')
        need(all(callable(c) for c in (custody_check,authority_check,resources_check)),
             'current_host_checks_required')
        self.journal=self._journal=journal;self.profile=profile;self.deadline=deadline;self.max_requests=max_requests
        self._profile=profile;self._deadline=deadline;self._max_requests=max_requests
        self._custody=custody_check;self._authority=authority_check;self._resources=resources_check
        need(drain_check is None or callable(drain_check),'host_drain_observer_required')
        self._drain_check=self._original_drain_check=drain_check
        self._drain_signal=threading.Event()
        self._pid=os.getpid();self._confirmed={}
        self._stop_signal=threading.Event();self._transport_lock=threading.Lock();self._transports=set()
        self._scope=digest({'profile':profile.__dict__,'deadline':deadline,'max_requests':max_requests,
                           'identity':journal.identity_hash})
        self.shared=self._shared=SharedWorkAdmission(journal=journal,run_id='model-'+self._scope[:32],
            lock_path=lock_path,lock_identity=lock_identity,custody_check=self.checkpoint,
            inspect=lambda:self._eligible(),confirm=self._confirm)

    def _reservations(self):
        return [e for e in self.journal.events() if e['subject'].startswith('work-admission:')
                and e['value'].get('state')=='reserved']

    def _eligible(self):
        need(len(self._reservations())<self.max_requests,'model_request_budget_exhausted')
        # Every cooperating process must retain exactly the same scope. A new
        # host object cannot silently reset the deadline, budget or model.
        for event in self.journal.events():
            if event['subject']=='model-resource-scope':
                need(event['value']=={'scope':self._scope},'model_resource_scope_changed')
        return True

    def checkpoint(self):
        need(os.getpid()==self._pid and self.profile==self._profile and
             self.journal is self._journal and self.shared is self._shared and
             self.deadline==self._deadline and self.max_requests==self._max_requests
             and self._drain_check is self._original_drain_check,
             'model_host_binding_changed')
        self._custody()
        need(not self._stop_signal.is_set() and not self._durable_stop(),'model_admission_stopped')
        need(time.time()<self.deadline,'model_admission_deadline')
        need(self._authority() is True,'model_authority_unavailable')
        need(self._resources() is True,'model_resources_unavailable')

    def _event(self, *, subject, kind, value, evidence=None):
        now=int(time.time());evidence=evidence or []
        return dict(id='inference-'+uuid.uuid4().hex,kind=kind,
            basis='tested' if evidence else 'observed',subject=subject,
            occurred_at=now,recorded_at=now,verified_at=now if evidence else None,
            expires_at=None,evidence=evidence,supersedes=None,value=value)

    def _confirm(self,lane,request_id):
        receipt=self._confirmed.pop((lane,request_id),None)
        need(receipt is not None,'inference_completion_unconfirmed')
        events=[e for e in self.journal.events() if e['subject']=='model-response:'+request_id]
        need(len(events)==1 and events[0]['value']==receipt,'inference_receipt_changed')
        return {'lane':lane,'state':'verified' if lane=='supplemental' else 'accepted',
                'record_sha256':digest(events[0])}

    def status(self):
        state=admission_status(self.journal)
        return {'schema':1,'scope_sha256':self._scope,'pending':len(state['pending']),
            'requires_recovery':state['requires_recovery'],'requests_used':len(self._reservations()),
            'max_requests':self.max_requests,'deadline':self.deadline,
            'execution_authority':False,'server_cancellation_qualified':False,
            'stopped':self._stop_signal.is_set() or self._durable_stop(),
            'local_transports_active':self._transport_count(),
            'draining':self._durable_drain() or self._drain_signal.is_set()}

    def _durable_drain(self):
        events=[e for e in self.journal.events() if e['subject']=='model-admission-drain']
        for event in events:
            need(event['kind']=='observation' and digest(event['value'])==digest({
                'scope_sha256':self._scope,'draining':True}), 'model_drain_record_changed')
        return bool(events)

    def drain(self):
        """Stop new admission/output; let one admitted transport settle normally.

        This grants no extra deadline or resources. Authority/custody loss and
        emergency stop still abort immediately and retain uncertain outcomes.
        """
        self.checkpoint()
        self._drain_signal.set()
        if not self._durable_drain():
            self.journal.append(self._event(subject='model-admission-drain',kind='observation',
                value={'scope_sha256':self._scope,'draining':True}))

    def _observe_drain(self):
        if self._drain_check is not None:
            requested=self._drain_check()
            need(type(requested) is bool,'host_drain_observation_unknown')
            if requested:self.drain()
        return self._durable_drain() or self._drain_signal.is_set()

    def _durable_stop(self):
        events=[e for e in self.journal.events() if e['subject']=='model-admission-stop']
        for event in events:
            need(event['kind']=='observation' and event['value']=={
                'scope_sha256':self._scope,'stopped':True},'model_stop_record_changed')
        return bool(events)

    def stop(self):
        """Host stop is durable and irreversible in this finite allocation."""
        self._stop_signal.set()
        self._custody()
        if not self._durable_stop():
            self.journal.append(self._event(subject='model-admission-stop',kind='observation',
                value={'scope_sha256':self._scope,'stopped':True}))

    def _transport_count(self):
        with self._transport_lock:
            return sum(not task.done() for task in self._transports)

    def _transport_done(self,task):
        # Retrieve orphaned errors without displaying server bodies. The owning
        # caller still receives its result/exception through task.result().
        if not task.cancelled():task.exception()
        with self._transport_lock:self._transports.discard(task)

    async def aclose(self, *, timeout=3.0):
        """Stop admission, drain local transport, retain unconfirmed server work."""
        need(type(timeout) in (int,float) and math.isfinite(timeout) and 0<timeout<=3,
             'bounded_close_timeout_required')
        self.stop()
        until=time.monotonic()+timeout
        while self._transport_count() and time.monotonic()<until:
            await asyncio.sleep(.02)
        state=self.status()
        return self._durable_stop() and not state['local_transports_active'] and not state['requires_recovery']

    async def run(self, request, *, lane='supplemental'):
        """One native-provider or external-worker request, no implicit retry."""
        task=None;request_id=uuid.uuid4().hex;started=time.monotonic()
        try:
            need(lane in {'supplemental','registered'} and callable(request),'model_request_scope')
            self.checkpoint()
            need(not self._observe_drain(),'model_admission_draining')
            with self.shared.guard(lane,request_id):
                if not any(e['subject']=='model-resource-scope' for e in self.journal.events()):
                    self.journal.append(self._event(subject='model-resource-scope',kind='observation',
                        value={'scope':self._scope}))
                self.checkpoint()
                need(not self._observe_drain(),'model_admission_draining')
                task=asyncio.create_task(request())
                with self._transport_lock:self._transports.add(task)
                task.add_done_callback(self._transport_done)
                while not task.done():
                    self.checkpoint()
                    self._observe_drain()
                    await asyncio.wait({task},timeout=.05)
                response=task.result()
                # The trusted transport adapter, not model prose, supplies this
                # result after the whole HTTP response and client close.
                need(type(response) is ModelResponse and response.model==self.profile.model,
                     'unexpected_model_response_identity')
                need(response.stop_reason in {'stop','length','tool_calls'},'incomplete_model_response')
                receipt={'request_id':request_id,'scope_sha256':self._scope,'lane':lane,
                    'response_received':True,'transport_finished':True,
                    'elapsed_seconds':time.monotonic()-started,'coding_success':False,
                    'model':response.model,'stop_reason':response.stop_reason}
                self.journal.append(self._event(subject='model-response:'+request_id,kind='verification',
                    value=receipt,evidence=['sha256:'+digest(receipt)]))
                self._confirmed[(lane,request_id)]=receipt
            # An owner Stop after a completed transport cannot publish output,
            # but neither should it relabel that completed transport as active.
            self.checkpoint()
            if self._observe_drain():
                raise ModelAdmissionDrained('Host cancellation drained the admitted transport; output withheld.')
            return response
        except (asyncio.CancelledError,ModelAdmissionDrained):
            raise
        except (ValueError,ProviderError):
            # Do not copy server error bodies, prompts or credential-bearing
            # diagnostics into the coordination error path.
            raise ModelAdmissionRefused('Local model admission refused or outcome unconfirmed; inspect its durable status.') from None
        finally:
            if task is not None and not task.done():
                task.cancel()
                await asyncio.wait({task},timeout=.25)
            # There is deliberately no clear, resume, expiry-based unlock or
            # model-provided settlement operation. Uncertain requests stay held.
