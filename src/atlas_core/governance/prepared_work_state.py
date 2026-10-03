"""Trusted current-state adapter for an existing, freshly prepared Work task.

The action boundary consumes this observer instead of model-supplied state.
It issues no permission, starts no worker and never resumes a stopped task.
Host callbacks and object identities are not protection from a hostile host.
"""
from dataclasses import asdict
from contextlib import contextmanager
from contextvars import ContextVar
import os
import time

from .action_boundary import need


class PreparedWorkObservation:
    def __init__(self, services, prepared, *, resources_ok, clock=time.time):
        from atlas_core.services import AtlasServices
        from atlas_core.coding_preparation import FreshPreparedTask, FreshTaskPreparation
        from atlas_core.development_control import DevelopmentControl
        from atlas_core.coding_connection import load_session

        need(type(services) is AtlasServices and type(prepared) is FreshPreparedTask,
             'current_preparation_required')
        preparation = services.coding_preparation
        need(type(preparation) is FreshTaskPreparation and preparation._prepared is prepared
             and preparation.services is services, 'current_preparation_required')
        need(type(services.development.control) is DevelopmentControl
             and callable(resources_ok) and callable(clock), 'trusted_host_observer_required')
        self.services, self.prepared, self.preparation = services, prepared, preparation
        self.control = services.development.control
        self.resources_ok, self.clock = resources_ok, clock
        self._callbacks = (resources_ok, clock)
        self.cs = load_session()
        self.session, self.binding = prepared.session, prepared.binding
        need(type(self.session) is self.cs.Session and self.binding.session is self.session
             and self.binding.control is self.control, 'same_prepared_session_required')
        self._pid = os.getpid()
        self._plan = self.cs.encoded(asdict(prepared.plan))
        self._spec = bytes(self.session.raw_spec)
        self._source = prepared.source_path
        self._foundation = services.coding_constitution.adoption['document_sha256']
        self._task = prepared.plan.task_id
        self._project = prepared.plan.project
        self._epoch = prepared.plan.expected_epoch
        self._attached = False
        self._publication = ContextVar('prepared_work_publication', default=False)
        self._validate()

    def _validate(self):
        need(os.getpid() == self._pid
             and self.services.coding_preparation is self.preparation
             and self.preparation._prepared is self.prepared
             and self.services.development.control is self.control,
             'work_owner_lifetime_changed')
        need(not self._attached or self.services.coding_action_observation is self,
             'work_observer_replaced')
        need((self.resources_ok, self.clock) == self._callbacks
             and self.cs.encoded(asdict(self.prepared.plan)) == self._plan
             and self.prepared.source_path == self._source
             and self.prepared.session is self.session and self.prepared.binding is self.binding
             and self.binding.control is self.control and self.binding.session is self.session
             and self.session.raw_spec == self._spec, 'work_binding_changed')
        self.preparation._same_owner()
        self.session._identity()
        # This retains the existing task's original time limits. Attaching an
        # observer cannot recreate admission or extend a saved task deadline.
        self.session._gate(dispatch=True, external=False)
        spec = self.session.spec
        need(spec['task']['id'] == self._task and spec['project'] == self._project
             and spec['run_id'] == self.prepared.plan.run_id
             and self.services.coding_constitution.adoption['document_sha256'] == self._foundation,
             'work_task_identity_changed')
        for field in ('created_utc', 'dispatch_utc', 'acceptance_utc', 'close_utc'):
            need(spec[field] == getattr(self.prepared.plan, field), 'work_deadline_changed')
        project = self.services.development.projects[self._project]
        need(project.self_development is True
             and project.action_tier == 'tier_2_reversible_local'
             and 'selfdev_context' in project.allowed_actions
             and 'selfdev_apply' in project.allowed_actions
             and project.root / spec['task']['path'] == self._source
             and not self.services.development._is_blocked(project, self._source.relative_to(project.root)),
             'work_project_scope_changed')
        self.services.development._require_selfdev_editable(project, self._source)
        return self.preparation._source(self.cs, self._source, spec['task']['source_sha256'])

    def __call__(self, task_id):
        need(type(task_id) is str and task_id == self._task, 'work_task_scope')
        if self._publication.get():
            # The original control writer lock already establishes this epoch,
            # Stop and cleanup. Never re-enter its database here. Publication
            # is bookkeeping, not admission of a concurrent worker.
            source = self._validate()
            resources = self.resources_ok()
            now = self.clock()
            need(type(resources) is bool, 'resource_observation_unknown')
            need(type(now) in (int, float) and 0 <= now < 10**11, 'work_clock_unknown')
            return {'stopped': False, 'epoch': self._epoch, 'resources_ok': resources,
                    'source_sha256': self.cs.sha(source), 'observed_at': int(now),
                    'constitution_sha256': self._foundation}
        self._validate()
        before = self.control.status(self._project)
        resources = self.resources_ok()
        need(type(resources) is bool, 'resource_observation_unknown')
        source = self._validate()
        after = self.control.status(self._project)
        # A race is unknown, not a fresh affirmative observation. Stop is read
        # again after source/resource work, not merely cached at preparation.
        need(before == after, 'work_state_changed_during_observation')
        now = self.clock()
        need(type(now) in (int, float) and 0 <= now < 10**11, 'work_clock_unknown')
        need(type(after['epoch']) is int and type(after['active_operations']) is int
             and after['active_operations'] >= 0
             and type(after['stopped']) is bool and type(after['cleanup_required']) is bool,
             'work_control_state_unknown')
        # A later owner resume is authority for fresh work, never resurrection
        # of this preparation. Even a newly selected policy for the new epoch
        # cannot make this old task eligible again.
        return {'stopped': after['stopped'] or after['cleanup_required']
                          or after['epoch'] != self._epoch,
                'epoch': after['epoch'],
                'resources_ok': resources and after['active_operations'] == 0,
                'source_sha256': self.cs.sha(source), 'observed_at': int(now),
                'constitution_sha256': self._foundation}

    @contextmanager
    def publication_guard(self, task_id):
        """Order a completed check's ledger commit against the real Stop control.

        Idle admission is checked before acquiring the lock. This guard does
        not launch a worker or claim to lock the whole machine's resources.
        """
        need(not self._publication.get(), 'nested_work_publication')
        state = self(task_id)
        need(not state['stopped'] and state['resources_ok'], 'publication_unavailable')
        with self.control.publication_guard(self._project, self._epoch):
            token = self._publication.set(True)
            try:
                self(task_id)
                yield
            finally:
                self._publication.reset(token)

    def summary(self):
        state = self(self._task)
        return {'task_id': self._task, 'project': self._project,
                'run_id': self.prepared.plan.run_id, 'expected_epoch': self._epoch,
                'observation': state, 'execution_authority': False,
                'model_calls': 0, 'source_applied': False}


def bind_for_services(services, prepared, *, resources_ok):
    """Explicit host binding; no HTTP input or model-callable selection path."""
    from atlas_core.services import AtlasServices
    need(type(services) is AtlasServices and services.coding_action_observation is None,
         'work_observer_already_bound')
    observation = PreparedWorkObservation(services, prepared, resources_ok=resources_ok)
    observation.summary()
    services.coding_action_observation = observation
    observation._attached = True
    return observation
