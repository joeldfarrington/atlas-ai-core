"""Coding mechanics are replaceable; authority and acceptance stay with Atlas.

Trusted host API, never a model tool or plugin loader. This first adapter reuses
the existing Aider process, request budget, sandbox and independent checker.
OpenHands is described but not installed or dispatched. A backend receipt is
not evidence that its candidate works; only the retained checker decides that.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import time
from typing import Protocol

from atlas_core.governance.cognitive_state import digest, need


@dataclass(frozen=True)
class BackendDescription:
    identifier: str
    version: str | None
    license: str
    available: bool
    task_kinds: tuple[str, ...]
    mechanics: tuple[str, ...]


AIDER = BackendDescription('aider', '0.86.2', 'Apache-2.0', True,
    ('registered_single_file',), ('file_editing', 'bounded_context', 'isolated_process'))
OPENHANDS = BackendDescription('openhands', None, 'MIT (SDK)', False, (), ())
PRACTICE = BackendDescription('practice-tools', '1', 'Atlas project', True,
    ('catalog_pure_function',), ('fixed_file_editing', 'protected_tests', 'isolated_checker'))


class CodingBackend(Protocol):
    """Neutral executor contract; declarations do not grant authority."""
    def __call__(self, prompt: str, reserve): ...


def public_execution_constraints(task):
    """Describe the fixed interpreter surface, never solutions or hidden cases.

    This is context for an already selected task, not a new checker or grant.
    Unknown tasks receive no inferred capabilities. The protected checker still
    independently validates every candidate against its unchanged policy.
    """
    baseline = {
        'baseline_ready_jobs_v1': 'ef72c66523d25cfc760f689bcfb6d572f79a03ec5e4f7406cc6347df32cea614',
        'baseline_terminal_count_v1': 'a646e56ae34ee851817ece71c139ee9989f68f7d62c254a3e183277119dc0123',
        'baseline_quantity_tests_v1': 'd6abe50b11817d4578bfbdddca8c3824cc43ae8c6cb95064af7801341ca43278',
    }
    if type(task) is dict:
        for identifier,source in baseline.items():
            if task.get('checker') == {'id':identifier} and task.get('source_sha256') == source:
                scopes = {
                    'baseline_ready_jobs_v1':
                        'Edit only select_ready_jobs(jobs, now, limit); preserve its signature. '
                        'No imports or added functions. ',
                    'baseline_terminal_count_v1':
                        'Edit only count_terminal_runs(records); preserve its signature. '
                        'No imports or added functions. This refactor requires one explicit loop; '
                        'no copying, helper calls, lists or comprehensions. ',
                    'baseline_quantity_tests_v1':
                        'Keep import unittest and from quantity import parse_quantity. '
                        'Keep QuantityTests(unittest.TestCase) with 2..24 distinct test_ methods '
                        'taking only self. No other imports, classes or helper functions. ',
                }
                return ('Public interpreter scope: '+scopes[identifier]+
                    'Permitted syntax includes simple assignments, return, if/else, for, '
                    'continue/pass, literals, comparisons, boolean operators, subscripts, '
                    'addition and raises. Only the listed calls are available: type, len, sum, '
                    'int, str, list, dict, set, ValueError, NotImplementedError'+
                    (', parse_quantity' if identifier=='baseline_quantity_tests_v1' else '')+'. '+
                    ('Test assertions may use assertEqual, assertRaises, assertTrue, assertFalse, '
                     'subTest and with blocks. ' if identifier=='baseline_quantity_tests_v1' else
                     'Container attributes may use append, add or get. ')+
                    'Do not use isinstance, all, any, break, while, try/except, annotations, '
                    'decorators, nested functions, private names, attribute writes or I/O. '
                    'At most900 syntax nodes per function and2048 characters per literal. '
                    'Before submitting, check every public requirement and every forbidden construct; '
                    'fixing one reported issue is not evidence that the rest are correct. '
                    'This describes mechanics, grants no authority, and does not replace independent acceptance.')
    practice = {
        'practice_artifact_path_v1': ('574c2984434bcbe051bcc42e0e387ad6067a0bbb79a6e9fa8d3538225f44a1cf',
            'relative', 'is_absolute, parts', 'require, PurePosixPath'),
        'practice_json_overflow_v1': ('c906345a3fd29c63c4c61cda9b224c2b5836e8b57c11e2c584828298b58d7a79',
            'decode', 'loads, throw, isfinite, isinf, isnan, values, items', 'pairs, require'),
        'practice_stop_marker_v1': ('092d1833d4261af3e014fde1bab4f6c93e6a442fb704e178dc20e8742a1dbfeb',
            'require_running', 'exists, is_symlink', 'Path'),
    }
    if type(task) is dict:
        for identifier, (source, function, attributes, calls) in practice.items():
            if task.get('checker') == {'id':identifier} and task.get('source_sha256') == source:
                return (
                    'Public execution constraints for this registered capsule: edit only '+function+
                    ' and return the whole module. Preserve every byte outside that function, '
                    'including imports, blank lines and helpers; preserve its signature. '
                    'The fixed guard allows at most 700 syntax nodes. Allowed attributes: '+attributes+
                    '. Allowed builtin calls: type, str, bool, int, float, len, all, any, isinstance, '
                    'ValueError, list, dict, tuple, abs. Other named calls: '+calls+
                    '. Use assignments, return, expressions, literals/containers, comparisons, '
                    'boolean operators, subscripts, if/else, generators, lambdas, raise and pass. '
                    'No try/except, while, with, decorators, annotations, attribute writes, dynamic '
                    'keyword expansion, __ names, arbitrary calls or protected-name rebinding. '
                    'Only decode may contain for loops, list comprehensions, nested helper functions '
                    'or imports of math (or isfinite/isinf/isnan from math); such imports must stay '
                    'inside decode. Other functions may not add imports or nested helpers. '
                    'The only allowed path division is the fixed STOP_REQUEST.json name in '
                    'require_running; no other binary arithmetic. These mechanics grant no authority '
                    'and do not replace the behavioral requirements or independent acceptance.')
    if (type(task) is not dict or task.get('checker') != {'id':'identity_documents_v1'}
            or task.get('source_sha256') !=
            'd91aec6d6ad84833a2ab9dce93288cc2f870c5af6fbb6aa71d36aebd1e9308ed'):
        return ''
    return (
        'Public execution constraints for this bounded Python method: only assignments, '
        'return, expressions, for loops, if/else, continue/pass, literals/containers, '
        'comparisons, boolean operators, subscripts and the listed calls are supported. '
        'Allowed attributes: identity_dir, glob, name, lower, read_text, strip, append, '
        'is_symlink, is_file, fullmatch. Allowed named calls: sorted, str, list, dict, bool, len. '
        'glob must use the literal pattern "*.md"; read_text may use only encoding="utf-8". '
        'Do not add imports, try/except, comprehensions, helper functions, calls to _path, '
        'iterdir or other unlisted attributes/calls. Keep the existing method signature '
        'and all text outside the method unchanged. Do not rebind self, _NAME or builtin '
        'call names; no __ names, attribute writes, nested functions or decorators. '
        'At most 500 syntax nodes and 1024 characters per string/bytes literal. '
        'These mechanics describe existing enforcement; they grant no authority and '
        'do not replace the behavioral requirements or independent acceptance.')


def backend_prompt(prompt, task):
    constraints = public_execution_constraints(task)
    return prompt if not constraints else prompt+'\n\nHost execution capability description:\n'+constraints


def available_backends(*, task_kind='registered_single_file'):
    return tuple(b for b in (AIDER, PRACTICE, OPENHANDS)
                 if not b.available or task_kind in b.task_kinds)


def select_backend(identifier: str, *, task_kind='registered_single_file'):
    """Explicit selection only. No fallback, download, model or budget change."""
    need(type(identifier) is str and type(task_kind) is str, 'backend_request_shape')
    selected = next((b for b in available_backends(task_kind=task_kind) if b.identifier == identifier), None)
    need(selected is not None and selected.available, 'backend_unavailable')
    need(task_kind in selected.task_kinds, 'backend_task_kind_unqualified')
    return selected


class AiderBackend:
    """Bind an already-qualified worker to its existing registered execution."""
    def __init__(self, worker, *, evidence_kind):
        from atlas_core.coding_aider import AiderProcessWorker
        need(type(worker) is AiderProcessWorker, 'qualified_aider_worker_required')
        need(evidence_kind in ('scripted_fixture', 'local_model'),
             'backend_evidence_kind')
        from atlas_core.coding_local_completion import LocalCodingCompletion
        self._shared_completion=type(worker.completion) is LocalCodingCompletion
        if evidence_kind=='local_model':
            need(self._shared_completion,'shared_local_completion_required')
        if self._shared_completion:
            worker.completion.validate_budget(worker.request_budget)
        worker._check_runtime()
        self.worker = worker
        self.execution = worker.execution
        self._worker = worker
        self._execution = worker.execution
        self._evidence_kind = evidence_kind
        self._provider = worker.label
        self._pins = dict(worker.pins)
        self._completion=worker.completion
        self._request_budget=worker.request_budget
        self._packet = digest(self.execution.packet)
        self._consumed = False
        self._candidate_review = self._review_binding = None

    def description(self):
        return {'backend': AIDER.identifier, 'backend_version': AIDER.version,
            'license': AIDER.license, 'provider_declared': self._provider,
            'evidence_kind': self._evidence_kind,
            'task_fingerprint': self._packet, 'provider_identity_verified': False,
            'runtime_pins_sha256': digest(self._pins),
            'scope': 'registered_single_file', 'requests_max': 1,
            'automatic_retry': False, 'deployment_allowed': False}

    def validate(self, execution):
        need(self.execution is self._execution is execution and
             self.worker is self._worker and self.worker.execution is execution,
             'backend_execution_binding_changed')
        need(digest(execution.packet) == self._packet and
             self.worker.pins == self._pins and self.worker.label == self._provider and
             self.worker.completion is self._completion,
             'backend_identity_changed')
        if self._shared_completion:
            need(self.worker.request_budget is self._request_budget,'backend_request_budget_changed')
            self._completion.validate_budget(self._request_budget)
        self.worker._check_runtime()
        execution._local_invariants()
        need(self._candidate_review is self._review_binding,'backend_review_binding_changed')
        if self._candidate_review is not None:
            self._candidate_review.validate(execution)

    def bind_candidate_review(self, review):
        from atlas_core.coding_engine_gym import EngineCodingGym
        need(type(review) is EngineCodingGym and review.backend is self
             and not self._consumed and self._candidate_review is None,'backend_review_selection')
        review.validate(self.execution)
        self._candidate_review = self._review_binding = review

    def __call__(self, prompt, reserve):
        self.validate(self.execution)
        need(not self._consumed, 'backend_attempt_consumed')
        self._consumed = True
        result = self.worker(backend_prompt(prompt, self.execution.session.spec['task']), reserve)
        if self._candidate_review is not None and result.get('complete') is True and result.get('cleanup_verified') is True:
            self._candidate_review.review_candidate(result['candidate'])
        return result


def execute_backend(execution, backend, *, critique):
    """Same plan/authority/execution/check/reflection loop, named backend input.

    Saved selection is consumed before execution. An interrupted attempt is
    recovered by reading existing records; this function never resumes a job.
    Receipt failures propagate rather than manufacturing a success report.
    """
    from atlas_core.coding_execution import RegisteredCodingExecution
    need(type(execution) is RegisteredCodingExecution and type(backend) is AiderBackend,
         'registered_backend_binding_required')
    backend.validate(execution)
    execution.loop.authorize('local_model')
    session = execution.session
    with session._lock():
        execution._local_invariants()
        session._gate(dispatch=True)
        need(not session._has('BACKEND_SELECTION.json') and
             not session._has('WORKER_INTENT.json'), 'backend_attempt_consumed')
        session._save('BACKEND_SELECTION.json', backend.description())
    started = time.monotonic()
    started_utc = datetime.now(timezone.utc).isoformat()
    try:
        result = execution.execute(backend, critique=critique)
    except BaseException:
        # Recovery is read-only and cannot repeat a model request or checker.
        result = execution.recover()
        _record(execution, backend, result, started, started_utc, interrupted=True)
        raise
    _record(execution, backend, result, started, started_utc, interrupted=False)
    return result


def _reserved_work(execution):
    """Count host-reserved effort even when there is no terminal result.

    This one-attempt backend counts durable worker/request actions, not model
    claims, transport completions or billable tokens. Damaged evidence refuses
    reporting instead of being represented as zero effort.
    """
    records = execution.loop.records()
    workers = [e for e in records if e['kind']=='action' and e['value'].get('type')=='worker']
    requests = [e for e in records if e['kind']=='action' and e['value'].get('type')=='model_request']
    need(len(workers)<=1 and len(requests)<=len(workers), 'backend_effort_bounds')
    for event in workers+requests:
        value = event['value']
        need(value.get('task_fingerprint')==digest(execution.packet)
             and type(value.get('attempt')) is int and value['attempt']==1,
             'backend_effort_binding')
    if requests:
        need(type(requests[0]['value'].get('request')) is int
             and requests[0]['value']['request']==1
             and records.index(workers[0])<records.index(requests[0]),
             'backend_request_reservation_order')
    return len(workers), len(requests), digest(workers+requests)


def _record(execution, backend, result, started, started_utc, *, interrupted):
    worker = backend.worker.receipt
    complete = type(worker) is dict and worker.get('complete') is True
    cleanup = type(worker) is dict and worker.get('cleanup_verified') is True
    state = result.get('state', 'outcome_unconfirmed')
    attempts, requests, effort_sha256 = _reserved_work(execution)
    for name, count in (('attempts', attempts), ('model_requests', requests)):
        if name in result:
            need(type(result[name]) is int and result[name]==count, 'backend_effort_contradiction')
    record = dict(backend.description(), schema=1,
        started_utc=started_utc, elapsed_seconds=max(0.0, time.monotonic()-started),
        outcome=state, interrupted=interrupted, candidate_produced=complete,
        cleanup_verified=cleanup, independent_accepted=(state == 'accepted'),
        attempts=attempts, requests=requests,
        effort_basis='durable_host_worker_and_request_reservations',
        effort_evidence_sha256=effort_sha256,
        candidate_sha256=result.get('candidate_sha256'),
        usage=None, cost=None, usage_status='provider_metering_not_available',
        installed=False, supported_chatgpt_return_qualified=False,
        reliability_qualified=False)
    if backend._evidence_kind=='local_model' and backend._completion.last_usage is not None:
        record['usage']=dict(backend._completion.last_usage)
        record['usage_status']='provider_reported_usage_not_billing_verification'
        record['model_admission']=backend._completion.admission.status()
    execution.session._save('BACKEND_OUTCOME.json', record)


def summarize_outcomes(records):
    """Summarize checker-derived records, separating scripted workflow evidence.

    Caller must obtain records from trusted evidence custody. This pure reporting
    function cannot authenticate arbitrary JSON and is never an approval input.
    Unmeasured quantities remain unknown rather than counting as zero failures.
    """
    groups = {}
    seen = set()
    for row in records:
        need(type(row) is dict and type(row.get('schema')) is int and row['schema'] == 1,
             'backend_record_schema')
        kind = row.get('evidence_kind')
        need(kind in ('scripted_fixture', 'local_model', 'remote_model'), 'backend_evidence_kind')
        fp = row.get('task_fingerprint')
        need(type(fp) is str and len(fp) == 64 and all(c in '0123456789abcdef' for c in fp)
             and fp not in seen, 'duplicate_or_invalid_task')
        seen.add(fp)
        need(row.get('outcome') in ('accepted', 'failed', 'outcome_unconfirmed', 'not_started',
             'observed', 'planned', 'critiqued', 'acting', 'verifying'), 'backend_outcome')
        need(type(row.get('independent_accepted')) is bool and
             row['independent_accepted'] == (row['outcome'] == 'accepted'), 'acceptance_contradiction')
        need(type(row.get('attempts')) is int and 0 <= row['attempts'] <= 1 and
             type(row.get('requests')) is int and 0 <= row['requests'] <= 1, 'backend_attempt_bounds')
        if row['independent_accepted']:
            need(row['attempts'] == row['requests'] == 1 and
                 row.get('candidate_produced') is True and row.get('cleanup_verified') is True and
                 row.get('interrupted') is False, 'accepted_evidence_incomplete')
        elapsed = row.get('elapsed_seconds')
        import math
        need(type(elapsed) in (int, float) and math.isfinite(elapsed) and elapsed >= 0,
             'backend_elapsed')
        key = (row.get('backend'), row.get('backend_version'), row.get('provider_declared'), kind)
        need(all(type(x) is str and x for x in key), 'backend_group_identity')
        g = groups.setdefault(key, {'backend':key[0], 'version':key[1], 'provider':key[2],
            'evidence_kind':kind, 'tasks':0, 'accepted':0, 'unconfirmed':0,
            'elapsed_seconds':0.0, 'first_pass_success':None, 'eventual_success':None,
            'regression_rate':None, 'false_success_claims':None,
            'verification_accuracy':None, 'recovery_success':None,
            'rollback_success':None, 'unauthorized_action_rate':None,
            'cost':None, 'reliability_qualified':False})
        g['tasks'] += 1
        g['accepted'] += int(row['independent_accepted'])
        g['unconfirmed'] += int(row['outcome'] == 'outcome_unconfirmed')
        g['elapsed_seconds'] += elapsed
    for g in groups.values():
        if g['evidence_kind'] != 'scripted_fixture':
            g['first_pass_success'] = g['accepted'] / g['tasks']
            g['eventual_success'] = g['first_pass_success']  # v0.1 has no correction grant.
    return {'schema':1, 'groups':list(groups.values()),
        'selection_authority':False, 'automatic_trust_change':False}
