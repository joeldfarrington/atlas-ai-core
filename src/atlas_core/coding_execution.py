"""Foreground worker association for an already prepared registered task.

Trusted host objects only: no HTTP/model tool, saved admission loader, provider,
shell selector, new control, resume or installation. The existing worker owns
its isolated execution and cancellation; Session owns the independent checker.
"""
from __future__ import annotations

from datetime import datetime, timezone
from contextlib import contextmanager, nullcontext
import os
import math

from atlas_core import development_control
from atlas_core.coding_connection import load_session
from atlas_core.coding_preparation import FreshPreparedTask, FreshTaskPreparation, FreshTaskPlan
from atlas_core.governance.cognitive_state import CognitiveJournal, digest, need
from atlas_core.governance.coding_workflow import CodingWorkflow, recover_task
from atlas_core.coding_builder_context import PROTOCOL as CONTEXT_PROTOCOL, render_builder_prompt


def settled_checker_input_refusal(receipt, maximum_seconds):
    """Recognize a fixed checker's terminal refusal, never a passing test.

    Caller must bind this protected receipt to the current pinned Session and
    candidate. This is not a model-supplied assertion or a recovery grant.
    A crash, timeout, Stop, altered output or unknown cleanup stays uncertain.
    """
    if type(receipt) is not dict:
        return False
    elapsed, budget = receipt.get('elapsed_seconds'), receipt.get('budget_seconds')
    return (type(receipt.get('exit_code')) is int and receipt['exit_code'] == 2
        and receipt.get('complete') is False and receipt.get('cleanup_verified') is True
        and receipt.get('timed_out') is False and receipt.get('stopped') is False
        and 'result' in receipt and receipt['result'] is None
        and type(receipt.get('stdout')) is str and receipt['stdout'] == ''
        and type(receipt.get('stderr')) is str
        and receipt['stderr'] == b'checker_input_refused\n'.hex()
        and all(type(v) is int or type(v) is float and math.isfinite(v)
                for v in (elapsed,budget,maximum_seconds))
        and 0 <= elapsed <= budget <= maximum_seconds and budget > 0)


def contract_requirements(contract):
    """Preserve the exact registered text inside existing per-item bounds."""
    need(type(contract) is str and contract.strip() and len(contract) <= 6500,
         'registered_contract_bound')
    parts = []
    remaining = contract
    while len(remaining) > 1200:
        boundary = max(remaining.rfind('\n', 0, 1200), remaining.rfind(' ', 0, 1200))
        need(boundary > 0, 'registered_contract_unbreakable')
        parts.append(remaining[:boundary + 1])
        remaining = remaining[boundary + 1:]
    parts.append(remaining)
    need(len(parts) <= 12 and all(part.strip() and len(part) <= 1200 for part in parts)
         and ''.join(parts) == contract, 'registered_contract_partition')
    return parts


def registered_task_packet(services, prepared):
    """Describe the already-prepared task without attaching or running a worker."""
    cs=load_session();spec=cs.decode(bytes(prepared.session.raw_spec));task=spec['task']
    return _packet_from_spec(cs, spec, services.coding_constitution.adoption['document_sha256'])


def _packet_from_spec(cs, spec, foundation_sha256):
    task = spec['task']
    return {'schema':1,'task_id':'coding-'+spec['run_id'],
        'goal':task['objective'],'requirements':contract_requirements(task['contract']),
        'editable_file':task['path'],'source_sha256':task['source_sha256'],
        'foundation_sha256':foundation_sha256,
        'deadline_utc':cs.moment(spec['dispatch_utc']).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'max_requests':1}


def preview_registered_task(plan, *, parent_directory, foundation_sha256):
    """Read the pinned task contract before creating the coding runtime.

    This lets planning/critique settle before the existing 160-second coding
    allocation begins. It creates no state, owner, provider, grant or work claim.
    The host must compare the later prepared packet exactly with this preview;
    source/authority/stop/deadline checks remain with actual preparation/run.
    """
    import re
    need(type(plan) is FreshTaskPlan and type(plan.expected_epoch) is int
         and plan.expected_epoch > 0 and type(plan.approval_ref) is str
         and 0 < len(plan.approval_ref) <= 4096, 'preview_explicit_plan_required')
    need(type(foundation_sha256) is str and re.fullmatch('[a-f0-9]{64}',foundation_sha256),
         'preview_foundation_required')
    cs = load_session()
    spec = cs.make_fresh_spec(parent_directory, task_id=plan.task_id, project=plan.project,
        run_id=plan.run_id, created_utc=plan.created_utc, dispatch_utc=plan.dispatch_utc,
        acceptance_utc=plan.acceptance_utc, close_utc=plan.close_utc)
    session = cs.Session(spec)  # Pinned-code validation; no file creation.
    from .coding_trial_host import verification_policy
    return {'packet':_packet_from_spec(cs, session.spec, foundation_sha256),
            'verification_policy':verification_policy(spec['task']['checker_sha256'],
                                                        spec['task']['expected_cases']),
            'registered_task_id':spec['task']['id'],
            'source_provenance':spec['fresh_task']['provenance'],
            'execution_authority':False,'prepared':False}


class RegisteredCodingExecution:
    def __init__(self, services, prepared, *, journal, owner_policy, resources_ok,
                 work_admission=None):
        from atlas_core.services import AtlasServices
        need(type(services) is AtlasServices and type(prepared) is FreshPreparedTask,
             'current_preparation_required')
        prep = services.coding_preparation
        need(type(prep) is FreshTaskPreparation and prep._prepared is prepared,
             'current_preparation_required')
        need(type(journal) is CognitiveJournal and not journal.read_only,
             'development_journal_required')
        need(callable(resources_ok), 'current_resources_required')
        self.services, self.prepared, self.preparation = services, prepared, prep
        self.cs = load_session()
        self.session, self.binding = prepared.session, prepared.binding
        need(not hasattr(self.session, '_registered_worker'), 'worker_already_bound')
        self.control = services.development.control
        self.policy, self.journal, self.resources_ok = owner_policy, journal, resources_ok
        from atlas_core.governance.owner_work import OwnerWorkControls
        need(type(owner_policy) is not OwnerWorkControls or
             work_admission is owner_policy.admission, 'shared_work_admission_required')
        self.work_admission = self._work_admission = work_admission
        self._pid = os.getpid()
        self._spec = bytes(self.session.raw_spec)
        self._source = prepared.source_path
        spec = self.cs.decode(self._spec)
        need('fresh_task' in spec and spec['limits']['attempts'] == 1,
             'fixed_registered_attempt_required')
        need(type(self.session) is self.cs.Session and self.binding.session is self.session
             and self.binding.control is self.control, 'same_prepared_session_required')
        task = spec['task']
        foundation = services.coding_constitution.adoption['document_sha256']
        need(journal.identity['constitution_sha256'] == foundation,
             'journal_foundation_mismatch')
        # A fresh run remains uniquely identified in a persistent journal.
        # The registered task ID itself is retained in all wrapper evidence.
        self.packet = registered_task_packet(services, prepared)
        self._packet = self.cs.encoded(self.packet)
        self._local_invariants()
        self.loop = CodingWorkflow(self.packet, gate=services.coding_constitution,
            journal=journal, control_module=development_control, control=self.control,
            project=spec['project'], epoch=prepared.plan.expected_epoch,
            owner_policy=owner_policy, observe=self._observe,
            checker_pins={'public':task['checker_sha256'],
                          'independent':digest(task['dependency_hashes'])},
            invariant_check=self._local_invariants)
        self._bind_session_policy()

    def _binding_invariants(self):
        """Local-only checks also safe inside the canonical publication guard."""
        need(self.work_admission is self._work_admission, 'work_admission_binding_changed')
        if hasattr(self, '_installed_hooks'):
            need(self.session._registered_worker is self and
                 (self.session._should_stop, self.session._publication_guard,
                  self.session._validate_invariants) == self._installed_hooks,
                 'worker_policy_binding_changed')
        need(os.getpid() == self._pid and self.services.coding_preparation is self.preparation
             and self.preparation._prepared is self.prepared
             and self.services.development.control is self.control,
             'owner_lifetime_changed')
        need(self.cs.encoded(self.packet) == self._packet
             and self.session.raw_spec == self._spec, 'execution_binding_changed')
        self.preparation._check_foundation()
        self.session._identity()
        task = self.session.spec['task']
        self.preparation._source(self.cs, self._source, task['source_sha256'])
        project = self.services.development.projects[self.prepared.plan.project]
        need(project.root / task['path'] == self._source
             and project.action_tier == 'tier_2_reversible_local'
             and 'selfdev_apply' in project.allowed_actions
             and not self.services.development._is_blocked(project, self._source.relative_to(project.root)),
             'project_scope_changed')
        self.services.development._require_selfdev_editable(project, self._source)

    def _local_invariants(self):
        self._binding_invariants()
        self.session._gate(external=False)

    def _assess_session_policy(self):
        # No control DB re-entry here. _should_stop checks the existing owner;
        # publication runs inside its original canonical writer transaction.
        self._binding_invariants()
        state = dict(self._observe(), project=self.prepared.plan.project,
            control_epoch=self.prepared.plan.expected_epoch, stopped=False)
        return self.services.coding_constitution.assess(self.packet,
            operation='check_candidate', authority=self.policy.read(), observations=state)

    def _bind_session_policy(self):
        old_stop = self.session._should_stop
        old_publication = self.session._publication_guard
        old_invariants = self.session._validate_invariants
        need(all(callable(h) for h in (old_stop,old_publication,old_invariants)),
             'existing_session_controls_required')

        def stopped():
            try:
                if old_stop() is not False:return True
                self._assess_session_policy()
                return False
            except Exception:
                return True

        def invariants():
            old_invariants()
            self._assess_session_policy()

        @contextmanager
        def publication():
            # Preserve Session -> owner-policy -> canonical-control ordering.
            # The policy guard orders revocation against result publication.
            with self.policy.guard():
                with old_publication():
                    self._assess_session_policy()
                    yield
                    self._assess_session_policy()

        self._installed_hooks = (stopped, publication, invariants)
        self.session._registered_worker = self
        self.session._should_stop = stopped
        self.session._publication_guard = publication
        self.session._validate_invariants = invariants

    def _observe(self):
        resources = self.resources_ok()
        need(type(resources) is bool, 'resource_observation_unknown')
        return {'now_utc':datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                'source_sha256':self.cs.sha(self.cs.regular(self._source)),
                'resources_ok':resources}

    def _worker(self, worker, prompt, reserve):
        # Selection verifies delivered/consumed guidance but does not attest its
        # origin. The supported remote connection must be qualified separately.
        selected = self.session.select_manager_context(self.binding)
        task_prompt = render_builder_prompt(prompt, selected['messages'], self.packet['source_sha256'], packet=self.packet)
        self.loop.authorize('local_model')
        with self.session._lock():
            self._local_invariants()
            self.session._gate(dispatch=True)
            need(not self.session._has('WORKER_INTENT.json'), 'worker_attempt_consumed')
            self.session._save('WORKER_INTENT.json', {
                'registered_task_id':self.prepared.plan.task_id,
                'run_id':self.prepared.plan.run_id, 'packet':self.packet,
                'spec_sha256':self.cs.sha(self._spec),
                'selected_context_sha256':selected['selection_sha256'],
                'context_protocol':CONTEXT_PROTOCOL,
                'worker_prompt_sha256':self.cs.sha(task_prompt.encode()),
                'journal_identity_sha256':self.journal.identity_hash,
                'attempts_max':1, 'automatic_retry':False,
                'guidance_origin':'caller_unverified',
                'supported_chatgpt_return_qualified':False})

        def reserve_once():
            current = self.session.select_manager_context(self.binding)
            need(current == selected, 'selected_context_changed')
            self._local_invariants()
            self.session._gate(dispatch=True)
            number = reserve()
            with self.session._lock():
                self.session._save('WORKER_REQUEST.json', {'request':number,
                    'intent_sha256':self.cs.sha(self.cs.regular(self.session.root/'WORKER_INTENT.json')),
                    'selection_sha256':selected['selection_sha256'],
                    'actual_model_identity':'host_receipt_required'})
            return number

        self.cs.exclusive(self.session.root/'WORKER_PROMPT.txt', task_prompt.encode())
        result = worker(task_prompt, reserve_once)
        need(type(result) is dict and set(result) == {'complete','cleanup_verified','candidate'},
             'worker_receipt')
        need(type(result['complete']) is bool and type(result['cleanup_verified']) is bool
             and type(result['candidate']) is bytes and len(result['candidate']) <= 32768,
             'worker_receipt')
        self.cs.exclusive(self.session.root/'WORKER_SOURCE.bin', result['candidate'])
        self.session._save('WORKER_RETURN.json', {
            'complete':result['complete'],'cleanup_verified':result['cleanup_verified'],
            'candidate_sha256':self.cs.sha(result['candidate']),
            'source_authorship':'worker_return_unverified',
            'controller_authorship':'Codex', 'new_remote_reply':False,
            'source_file':'WORKER_SOURCE.bin'})
        return result

    def _check(self, source, attempt):
        need(attempt == 1, 'registered_correction_not_authorized')
        need(self.cs.regular(self.session.root/'WORKER_SOURCE.bin') == source,
             'worker_source_changed')
        result = self.session.accept_worker_source(source)
        status = self.session.status()
        need(result['status'] == status['status'] and status['status'] in ('accepted','not_accepted'),
             'registered_outcome_unconfirmed')
        receipt = self.session._read('CHECKER_RECEIPT.json') if self.session._has('CHECKER_RECEIPT.json') else None
        cleanup = receipt is None or type(receipt) is dict and receipt.get('cleanup_verified') is True
        refused = (status['status'] == 'not_accepted'
            and status.get('reason') == 'checker_process_unqualified'
            and settled_checker_input_refusal(receipt,self.session.spec['limits']['checker_seconds']))
        if status['status'] == 'not_accepted' and receipt is not None:
            need(refused or receipt.get('complete') is True and receipt.get('timed_out') is False
                 and receipt.get('stopped') is False, 'checker_outcome_unconfirmed')
        # Revalidate source, checker pins, authority and Stop after the child
        # returns. A settled refusal does not excuse any changed invariant.
        self._local_invariants()
        self.session._save('WORKER_VERIFICATION.json', {
            'registered_task_id':self.prepared.plan.task_id,'status':status['status'],
            'result_sha256':self.cs.sha(self.cs.regular(self.session.root/'RESULT.json')),
            'candidate_sha256':self.cs.sha(source),'installed':False,
            'checker_input_refused':refused,
            'checker_receipt_sha256':None if receipt is None else
                self.cs.sha(self.cs.regular(self.session.root/'CHECKER_RECEIPT.json'))})
        passed = status['status'] == 'accepted'
        return {'task_fingerprint':self.loop.fp,'candidate_sha256':self.cs.sha(source),
            'checker_pins':self.loop.pins,'public_passed':passed,
            'independent_passed':passed,'cleanup_verified':cleanup}

    def execute_backend(self, backend, *, critique):
        """Use a qualified coding engine without replacing the governed loop."""
        from atlas_core.coding_backends import execute_backend
        return execute_backend(self, backend, critique=critique)

    def execute(self, worker, *, critique):
        need(callable(worker), 'trusted_worker_required')
        self._local_invariants()
        need(not self.session._has('WORKER_INTENT.json'), 'worker_attempt_consumed')
        guard = (nullcontext() if self.work_admission is None else
                 self.work_admission.guard('registered', self.packet['task_id']))
        with guard:
            return self._execute(worker, critique=critique)

    def _execute(self, worker, *, critique):
        # The existing loop enforces reservation, authority, Stop and reflection.
        # A general two-request allowance must not enlarge this registry's one.
        self.loop.execute(lambda prompt,reserve:self._worker(worker,prompt,reserve),
            self._check, changed_hypothesis='The fixed registered task has no correction allowance.',
            critique=critique)
        return self.recover()

    def recover(self):
        """Read saved state without dispatch, authority reads, writes or renewal."""
        return recover_registered_execution(self.session,self.packet,self.journal)


def recover_registered_execution(session, packet, journal):
    """Inspect preserved Session and journal in a fresh process, without a host.

    The caller selects the existing records. No owner/control construction,
    preparation, policy read, worker, checker or write occurs during recovery.
    """
    cs = load_session()
    need(type(session) is cs.Session and type(journal) is CognitiveJournal,
         'recovery_records_required')
    result = recover_task(packet,journal)
    if result['state'] not in ('accepted','failed'):
        return result
    try:
        intent = session._read('WORKER_INTENT.json')
        request = session._read('WORKER_REQUEST.json')
        receipt = session._read('WORKER_VERIFICATION.json')
        observed = session.status()
        status = observed.get('completed_outcome', observed['status'])
        need(cs.encoded(intent['packet']) == cs.encoded(packet)
             and intent['spec_sha256'] == cs.sha(session.raw_spec)
             and intent['registered_task_id'] == session.spec['task']['id']
             and intent['run_id'] == session.spec['run_id']
             and intent['journal_identity_sha256'] == journal.identity_hash
             and request['intent_sha256'] == cs.sha(cs.regular(session.root/'WORKER_INTENT.json'))
             and request['selection_sha256'] == intent['selected_context_sha256']
             and request['request'] == result['model_requests'] == 1
             and receipt['registered_task_id'] == session.spec['task']['id']
             and receipt['result_sha256'] == cs.sha(cs.regular(session.root/'RESULT.json'))
             and receipt['candidate_sha256'] == result['candidate_sha256']
             and cs.sha(cs.regular(session.root/'WORKER_SOURCE.bin')) == result['candidate_sha256']
             and receipt['status'] == status == ('accepted' if result['state']=='accepted' else 'not_accepted'),
             'worker_verification_changed')
        if 'context_protocol' in intent or 'worker_prompt_sha256' in intent:
            need(intent.get('context_protocol') == CONTEXT_PROTOCOL
                 and intent.get('worker_prompt_sha256') ==
                     cs.sha(cs.regular(session.root/'WORKER_PROMPT.txt')),
                 'worker_prompt_evidence_changed')
        if 'checker_input_refused' in receipt:
            check = session._read('CHECKER_RECEIPT.json') if session._has('CHECKER_RECEIPT.json') else None
            expected_pin = None if check is None else cs.sha(cs.regular(session.root/'CHECKER_RECEIPT.json'))
            refusal = (status == 'not_accepted' and observed.get('reason') == 'checker_process_unqualified'
                and settled_checker_input_refusal(check,session.spec['limits']['checker_seconds']))
            need(type(receipt['checker_input_refused']) is bool
                 and receipt['checker_input_refused'] is refusal
                 and receipt.get('checker_receipt_sha256') == expected_pin,
                 'worker_checker_receipt_changed')
    except (ValueError, OSError, KeyError, TypeError):
        return dict(result,state='outcome_unconfirmed')
    return dict(result, registered_task_id=session.spec['task']['id'],
        source_authorship='worker_return_unverified', supported_chatgpt_return_qualified=False)
