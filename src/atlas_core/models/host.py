"""Explicit finite model allocation inside the existing Core service lifespan.

No scheduler, environment loader, model-facing factory or permission issuer.
Deployment must retain its exact trusted factory on every startup. Missing or
changed deployment selection is a separate release/installation failure, not
something this module can infer or authorize from saved data.
"""
from contextlib import asynccontextmanager
import inspect
import os
import uuid

from atlas_core.governance.cognitive_state import need
from atlas_core.models.admission import LocalModelAdmission


class ModelAdmissionHost:
    def __init__(self,services,admission):
        from atlas_core.services import AtlasServices
        from atlas_core.models.router import ModelRouter
        need(type(services) is AtlasServices and type(services.router) is ModelRouter
             and type(admission) is LocalModelAdmission,'current_model_host_required')
        need(not services.runtime._active_runs and services.improvement is None,
             'model_binding_must_precede_background_start')
        need(services.router._local_admission_provider is None,'model_host_already_bound')
        self.services=services;self.router=services.router;self.admission=admission
        self._pid=os.getpid();self.started=False;self.claimed=False;self.cleanup_confirmed=None
        self._providers=dict(self.router.providers)
        self._native_provider=self._providers.get('local')
        self._routing=self.router.config.routing.model_dump()
        self.released_to_native=False;self._return_attempted=False

    def start(self):
        need(os.getpid()==self._pid and not self.started and self.services.router is self.router,
             'current_model_host_required')
        self.admission.checkpoint()
        events=self.admission.journal.events()
        need(not any(e['subject']=='model-host-lifetime' for e in events),
             'model_host_restart_requires_new_owner_preparation')
        need(not self.admission.status()['requires_recovery'],'model_host_outcome_unconfirmed')
        event=self.admission._event(subject='model-host-lifetime',kind='observation',
            value={'scope_sha256':self.admission._scope,'host_nonce':uuid.uuid4().hex,
                   'started':True,'automatic_resume':False})
        # A fixed unique event identity also arbitrates simultaneous startups.
        event['id']='model-host-'+self.admission._scope[:40]
        need(self.admission.journal.append(event) is True,'model_host_already_started')
        self.claimed=True
        self.router.bind_local_model_admission(self.admission)
        self._transport_identity=self._native_provider._transport_identity()
        self.started=True
        return self

    async def finish_trial(self):
        """Trusted host explicitly restores its original native configuration.

        No expiry-based unlock or server-cancellation inference. The finite
        allocation stays irreversibly stopped. Unconfirmed requests retain
        the bound gate; only settled transport evidence permits restoration.
        This method is not a model tool, task grant, retry or new allocation.
        """
        need(os.getpid()==self._pid and self.claimed and self.started,
             'current_model_host_required')
        def unchanged():
            need(self.services.router is self.router and
                 self.services.runtime.router is self.router and
                 self.router.config.routing.model_dump()==self._routing and
                 self.router.providers.keys()==self._providers.keys() and
                 all(self.router.providers[n] is p for n,p in self._providers.items()) and
                 self._native_provider._transport_identity()==self._transport_identity,
                 'original_native_configuration_changed')
        unchanged()
        if self.released_to_native:
            need(self.router._local_admission_provider is None and
                 self._native_provider._model_admission is None,
                 'native_return_binding_changed')
            return True
        need(not self._return_attempted,'native_return_requires_reconciliation')
        need(self.router._local_admission_provider=='local' and
             self._native_provider._model_admission is self.admission,
             'current_model_host_required')
        if not await self.aclose():
            return False
        # No await between the final identity check, detach and receipt commit.
        # Other cooperating calls still holding the old gate see its Stop.
        unchanged()
        need(self.router._local_admission_provider=='local' and
             self._native_provider._model_admission is self.admission,
             'native_return_binding_changed')
        need(not self._return_attempted,'native_return_requires_reconciliation')
        self._return_attempted=True
        def record(stage):
            event=self.admission._event(subject='model-host-return',kind='observation',
                value={'scope_sha256':self.admission._scope,'stage':stage,
                       'execution_authority':False,'new_allocation':False})
            need(self.admission.journal.append(event) is True,'native_return_receipt_failed')
        record('intent')
        self._native_provider._model_admission=None
        self.router._local_admission_provider=None
        try:
            record('complete')
        except BaseException:
            self._native_provider._model_admission=self.admission
            self.router._local_admission_provider='local'
            raise
        self.released_to_native=True
        return True

    def stop(self):
        need(self.claimed,'cannot_stop_another_model_host')
        try:self.admission.stop();return True
        except Exception:self.cleanup_confirmed=False;return False

    async def aclose(self):
        need(self.claimed,'cannot_close_another_model_host')
        try:self.cleanup_confirmed=await self.admission.aclose()
        except Exception:self.cleanup_confirmed=False
        return self.cleanup_confirmed


@asynccontextmanager
async def selected_model_host(services,factory):
    """Bind before background startup, close even after a startup exception."""
    if factory is None:
        yield None
        return
    need(callable(factory),'trusted_model_host_factory_required')
    admission=factory(services)
    if inspect.isawaitable(admission):
        if inspect.iscoroutine(admission):admission.close()
        raise ValueError('synchronous_model_host_factory_required')
    host=ModelAdmissionHost(services,admission)
    try:
        host.start()
        yield host
    finally:
        if host.claimed:await host.aclose()
