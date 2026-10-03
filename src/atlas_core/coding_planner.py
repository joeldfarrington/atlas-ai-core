"""One proposal-only local planning request, with durable no-replay recovery.

Reuses the local transport, admission ledger and qualified prompt counter.
The owner-supplied parent budget includes planning; the remaining allocation
is passed to the existing selection compiler. No worker, tests or execution
are dispatched here. Structural selection is not semantic decomposition proof.
"""
from copy import deepcopy
from dataclasses import dataclass, asdict
import asyncio
from pathlib import Path
import math
import os
import time

from atlas_core.coding_gym import read, save
from atlas_core.coding_native_counter import NativePromptCounter
from atlas_core.coding_counter_peer import counter_identity, PeerPlanningCounter
from atlas_core.coding_request_budget import AiderRequestBudget, message_digest
from atlas_core.governance.action_boundary import private_identity
from atlas_core.governance.cognitive_state import digest, need
from atlas_core.governance.coding_goal import validate_parent
from atlas_core.governance.coding_plan_selection import planning_request, decode_selection, compile_selection
from atlas_core.governance.coding_decomposition import decomposition_request, decomposition_request_v2, compile_decomposition
from atlas_core.models.admission import LocalModelAdmission
from atlas_core.models.base import ChatMessage, ModelResponse
from atlas_core.models.openai_compatible import OpenAICompatibleProvider
from atlas_core.practice.workspace import regular, sha

ARTIFACTS = ('INTENT.json', 'CONTEXT.json', 'REQUEST.json', 'RESPONSE.json', 'SELECTION.json')
MODELS = ('qwen2.5-coder:7b-instruct-q4_K_M', 'qwen2.5-coder:14b-instruct-q4_K_M')


def planning_counter_id(counter, scope):
    if type(counter) is PeerPlanningCounter:
        need(counter.scope == scope, 'planning_counter_scope_changed')
        return counter.identity
    need(type(counter) is NativePromptCounter and counter.selection.renderer == 'qwen25',
         'qualified_planning_counter_required')
    return counter_identity(counter)


def proposal_handlers(proposal_kind):
    # Closed protocol set, never a model-supplied function or prompt template.
    need(type(proposal_kind) is str and proposal_kind in ('selection', 'decomposition', 'decomposition_v2', 'decomposition_staged_v1', 'decomposition_staged_compact_v1', 'decomposition_staged_dependencies_v1'),
         'unsupported_planning_protocol')
    if proposal_kind == 'decomposition_staged_dependencies_v1':
        from atlas_core.governance.coding_staged_dependencies import request
        from atlas_core.governance.coding_staged_decomposition import compile
        return request, compile
    if proposal_kind == 'decomposition_staged_compact_v1':
        from atlas_core.governance.coding_staged_compact import request
        from atlas_core.governance.coding_staged_decomposition import compile
        return request, compile
    if proposal_kind == 'decomposition_staged_v1':
        from atlas_core.governance.coding_staged_decomposition import request as staged_request, compile as staged_compile
        return staged_request, staged_compile
    if proposal_kind == 'decomposition_v2':
        return decomposition_request_v2, compile_decomposition
    return ((planning_request, compile_selection) if proposal_kind == 'selection'
            else (decomposition_request, compile_decomposition))


def bounded_context(parent, catalogue, *, proposal_kind='selection', repository_sources=None):
    deadline = validate_parent(parent)
    need(parent['max_requests'] >= 2, 'planning_requires_reserved_request')
    execution_parent = deepcopy(parent)
    execution_parent['max_requests'] -= 1
    request_fn, _ = proposal_handlers(proposal_kind)
    request = request_fn(execution_parent, catalogue)
    if repository_sources is not None:
        from .coding_source_context import attach
        request=attach(request,repository_sources,parent['resources'])
    # The existing evidence writer caps each file at 64 KiB including formatting.
    import json
    for value in ({'parent': parent, 'catalogue': catalogue}, request):
        need(len(json.dumps(value, sort_keys=True, indent=2, allow_nan=False).encode()) < 60000,
             'planning_record_requires_smaller_context')
    return execution_parent, request, deadline


@dataclass(frozen=True)
class PlanningTiming:
    """Explicit owner-host time allocation; cannot increase action authority.

    The worker watchdog must separately enforce host_deadline. Default callers
    retain the original15second ceiling. A longer request is opt-in, remains
    capped, and must fit with cleanup reserves before any transport dispatch.
    """
    transport_seconds: float
    cleanup_reserve_seconds: float
    host_deadline: float

    def check(self, *, provider_timeout, admission_deadline, parent_deadline, require_window):
        values=(self.transport_seconds,self.cleanup_reserve_seconds,self.host_deadline,
                provider_timeout,admission_deadline,parent_deadline)
        need(all(type(v) in (int,float) and math.isfinite(v) for v in values),
             'finite_planning_timing_required')
        need(0 < self.transport_seconds <= 75 and 3 <= self.cleanup_reserve_seconds <= 15
             and provider_timeout == self.transport_seconds,'bounded_planning_timing_required')
        need(admission_deadline+self.cleanup_reserve_seconds <= self.host_deadline <= parent_deadline,
             'planning_deadline_layers')
        if require_window:
            need(time.time()+self.transport_seconds+self.cleanup_reserve_seconds <= admission_deadline,
                 'planning_dispatch_window_insufficient')


class LocalPlanSelector:
    def __init__(self, root, provider, *, budget, parent, catalogue, proposal_kind='selection', timing=None, repository_sources=None):
        execution_parent, request, deadline = bounded_context(parent, catalogue, proposal_kind=proposal_kind, repository_sources=repository_sources)
        need(type(provider) is OpenAICompatibleProvider
             and type(provider._model_admission) is LocalModelAdmission
             and provider._model_admission_lane == 'supplemental'
             and provider.api_key_env is None and provider.model in MODELS
             and provider.reasoning_effort == 'none', 'qualified_planning_provider_required')
        admission = provider._model_admission
        need(type(budget) is AiderRequestBudget
             and budget.counter_identity == planning_counter_id(budget.count_prompt_tokens, admission._scope)
             and budget.provider_label == provider.model and budget.context_tokens == 4096
             and budget.output_tokens <= min(1024, admission.profile.max_tokens), 'qualified_planning_counter_required')
        need(timing is None or type(timing) is PlanningTiming,'qualified_planning_timing_required')
        if timing is None:
            need(type(provider.timeout_seconds) in (int,float) and math.isfinite(provider.timeout_seconds)
                 and 0 < provider.timeout_seconds <= 15, 'bounded_planning_transport_required')
        else:
            timing.check(provider_timeout=provider.timeout_seconds,admission_deadline=admission.deadline,
                         parent_deadline=deadline.timestamp(),require_window=True)
        admission.checkpoint()
        status = admission.status()
        need(status['max_requests'] == 1 and status['requests_used'] == 0
             and status['pending'] == 0 and not status['requires_recovery']
             and status['local_transports_active'] == 0 and admission.deadline <= deadline.timestamp(),
             'fresh_dedicated_planning_allocation_required')
        need(admission.journal.identity['constitution_sha256'] == parent['foundation_sha256']
             and admission.journal.identity['permission_scope_sha256'] == parent['authority_sha256'],
             'planning_authority_binding')
        self.provider = provider; self.admission = admission; self.budget = budget
        self._transport = provider._transport_identity()
        need(self._transport == provider._model_admission_binding, 'planning_transport_changed')
        self._pid = os.getpid(); self._used = False
        self._kind = proposal_kind
        self._timing = timing; self._timing_value = asdict(timing) if timing is not None else None
        self._parent_deadline = deadline.timestamp()
        self._context = deepcopy({'parent':parent, 'catalogue':catalogue, 'proposal_kind':proposal_kind})
        if repository_sources is not None:
            from .coding_source_context import validate_sources
            self._context['repository_sources']=validate_sources(repository_sources,parent['resources'])
        if timing is not None:self._context['timing']=asdict(timing)
        self._request = request; self._execution_parent = execution_parent
        self.root = Path(root).absolute()
        need(not any(p.is_symlink() for p in (self.root,*self.root.parents)) and '..' not in self.root.parts,
             'private_planning_path_required')
        self.root.mkdir(mode=0o700)
        self._identity = private_identity(self.root, True)
        self._intent = {'schema':1, 'provider':provider.name, 'model':provider.model,
            'scope_sha256':admission._scope, 'context_sha256':request['context_sha256'],
            'counter_identity':budget.counter_identity, 'context_tokens':budget.context_tokens,
            'output_tokens':budget.output_tokens, 'planning_requests':1,
            'parent_max_requests':parent['max_requests'], 'execution_max_requests':execution_parent['max_requests'],
            'context_record_sha256':digest(self._context), 'request_sha256':digest(request),
            'execution_authority':False, 'semantic_coverage_verified':False}
        if timing is not None:
            self._intent['timing']={**asdict(timing),'admission_deadline':admission.deadline}
        save(self.root, 'INTENT.json', self._intent)
        save(self.root, 'CONTEXT.json', self._context)

    def validate(self, *, require_window=False):
        need(os.getpid() == self._pid and private_identity(self.root, True) == self._identity
             and self.provider._model_admission is self.admission
             and self.provider._model_admission_lane == 'supplemental'
             and self.provider._transport_identity() == self._transport
             and read(self.root,'INTENT.json') == self._intent
             and read(self.root,'CONTEXT.json') == self._context
             and self._kind == self._context['proposal_kind']
             and digest(self._request) == self._intent['request_sha256']
             and self.budget.counter_identity == planning_counter_id(self.budget.count_prompt_tokens, self.admission._scope)
             and self.budget.provider_label == self._intent['model']
             and self.budget.context_tokens == self._intent['context_tokens']
             and self.budget.output_tokens == self._intent['output_tokens'], 'planning_binding_changed')
        need((self._timing is None and self._timing_value is None and 'timing' not in self._context)
             or (type(self._timing) is PlanningTiming and asdict(self._timing)==self._timing_value==self._context.get('timing')),
             'planning_timing_changed')
        if self._timing is not None:
            self._timing.check(provider_timeout=self.provider.timeout_seconds,admission_deadline=self.admission.deadline,
                               parent_deadline=self._parent_deadline,require_window=require_window)
        self.admission.checkpoint()

    async def select(self):
        need(not self._used, 'planning_attempt_consumed')
        self._used = True
        started = time.monotonic(); outcome = 'unconfirmed'; failure = None
        try:
            self.validate(require_window=True)
            receipt = self.budget.admit(self._request['messages'], self.provider.model)
            self.validate(require_window=True)
            save(self.root, 'REQUEST.json', dict(self._request, admission=receipt))
            async def request_once():
                return await self.provider.generate([ChatMessage(**m) for m in self._request['messages']],
                    temperature=0, max_tokens=self.budget.output_tokens, response_format=self._request['response_format'])
            if self._timing is None:
                response = await request_once()
            else:
                # An absolute wall-clock transport deadline also bounds slow
                # trickle responses; HTTP per-operation timeouts alone do not.
                async with asyncio.timeout(self._timing.transport_seconds):
                    response = await request_once()
            self.validate()
            need(type(response) is ModelResponse and response.provider == self._intent['provider']
                 and response.model == self._intent['model'] and type(response.content) is str
                 and len(response.content.encode()) <= 8192, 'planning_response_identity')
            save(self.root, 'RESPONSE.json', {'content':response.content, 'provider':response.provider,
                'model':response.model, 'stop_reason':response.stop_reason, 'tool_calls_present':bool(response.tool_calls),
                'usage':{k:v for k,v in response.usage.items() if k in
                    ('prompt_tokens','completion_tokens','total_tokens') and type(v) is int and v >= 0},
                'usage_basis':'provider_reported', 'cost':None})
            need(response.stop_reason == 'stop' and not response.tool_calls, 'planning_incomplete_response')
            _, compile_fn = proposal_handlers(self._kind)
            selection = compile_fn(self._execution_parent, self._context['catalogue'], decode_selection(response.content))
            save(self.root, 'SELECTION.json', selection)
            outcome = 'selection_received'
            return selection
        except BaseException as error:
            failure = type(error).__name__
            raise
        finally:
            save(self.root, 'RESULT.json', {'outcome':outcome, 'failure_kind':failure,
                'elapsed_seconds':time.monotonic()-started, 'resource_state':self.admission.status(),
                'evidence':{n:sha(regular(self.root/n,65536)) for n in ARTIFACTS if (self.root/n).exists()},
                'execution_authority':False, 'semantic_coverage_verified':False})


def recover_selection(root):
    """Recover saved observations without a provider, allocation, replay or grant.

    This is an evidence-consistency check, not permission to execute a saved
    plan. Current source/authority/freshness checks remain the execution host's job.
    """
    root = Path(root).absolute(); private_identity(root, True)
    intent = read(root,'INTENT.json'); context = read(root,'CONTEXT.json')
    kind = context.get('proposal_kind', 'selection')  # Retained v1 records remain readable.
    parent, request, _ = bounded_context(context['parent'], context['catalogue'], proposal_kind=kind, repository_sources=context.get('repository_sources'))
    need(digest(context) == intent['context_record_sha256'] and digest(request) == intent['request_sha256']
         and request['context_sha256'] == intent['context_sha256']
         and intent['planning_requests'] == 1 and intent['parent_max_requests'] == context['parent']['max_requests']
         and intent['execution_max_requests'] == parent['max_requests'], 'planning_saved_context_changed')
    if 'timing' in context:
        need(type(context['timing']) is dict and set(context['timing'])=={'transport_seconds','cleanup_reserve_seconds','host_deadline'},
             'planning_saved_timing_shape')
        timing=PlanningTiming(**context['timing']);saved=intent.get('timing')
        need(type(saved) is dict and set(saved)==set(context['timing'])|{'admission_deadline'}
             and {k:saved[k] for k in context['timing']}==context['timing'],'planning_saved_timing_changed')
        timing.check(provider_timeout=timing.transport_seconds,admission_deadline=saved['admission_deadline'],
                     parent_deadline=validate_parent(context['parent']).timestamp(),require_window=False)
    else:need('timing' not in intent,'planning_saved_timing_changed')
    if not (root/'RESULT.json').exists():
        return {'outcome':'unconfirmed', 'execution_authority':False, 'semantic_coverage_verified':False}
    result = read(root,'RESULT.json')
    present = {n for n in ARTIFACTS if (root/n).exists()}
    need(set(result['evidence']) == present and {'INTENT.json','CONTEXT.json'} <= present, 'planning_evidence_missing')
    for name, pin in result['evidence'].items():
        need(sha(regular(root/name,65536)) == pin, 'planning_evidence_changed')
    if 'REQUEST.json' in present:
        saved = read(root,'REQUEST.json'); receipt = saved.pop('admission')
        need(saved == request and receipt['messages_sha256'] == message_digest(request['messages'])
             and receipt['counter_identity'] == intent['counter_identity']
             and receipt['provider'] == intent['model'] and receipt['context_tokens'] == intent['context_tokens']
             and receipt['output_reserve_tokens'] == intent['output_tokens']
             and type(receipt['prompt_tokens']) is int and receipt['prompt_tokens'] > 0
             and receipt['prompt_tokens'] + intent['output_tokens'] <= intent['context_tokens'], 'planning_saved_request_changed')
    selection = None
    if 'SELECTION.json' in present:
        need({'REQUEST.json','RESPONSE.json'} <= present, 'planning_selection_evidence_missing')
        response = read(root,'RESPONSE.json')
        need(response['provider'] == intent['provider'] and response['model'] == intent['model']
             and response['stop_reason'] == 'stop' and response['tool_calls_present'] is False, 'planning_saved_response_changed')
        _, compile_fn = proposal_handlers(kind)
        selection = compile_fn(parent, context['catalogue'], decode_selection(response['content']))
        need(selection == read(root,'SELECTION.json'), 'planning_saved_selection_changed')
        state = result['resource_state']
        need(state['scope_sha256'] == intent['scope_sha256'] and state['requests_used'] == 1
             and state['pending'] == 0 and state['requires_recovery'] is False, 'planning_unsettled_selection')
    expected = 'selection_received' if selection is not None and result['failure_kind'] is None else 'unconfirmed'
    need(result['outcome'] == expected and all(x[k] is False for x in (intent,result)
         for k in ('execution_authority','semantic_coverage_verified')), 'planning_saved_result_changed')
    return dict(result, selection=selection, intent=intent)
