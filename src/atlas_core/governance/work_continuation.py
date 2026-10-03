"""Bounded reviewed updates using retained transactions; never task authority.

Only the already reviewed self-development source cohort is eligible. The first
continuation may add this validator. Every manifest, ancestor receipt and source
snapshot is bound by an owner-side selection; HTTP/model data cannot select it.
"""
from copy import deepcopy
from dataclasses import dataclass
from .action_boundary import sha,private_identity
from .cognitive_state import digest,need
from .work_release import _rows,_receipt,_sha
from .work_first_install import _context,_read_bound,FirstWorkCodeSelection
from .work_selfdev_release import ReviewedSelfdevScope,CHANGED,ADDED

MODULE='src/atlas_core/governance/work_continuation.py'
ALLOWED=CHANGED|ADDED|frozenset((MODULE,))
MAX_CONTINUATIONS=6

# Exact result-delivery increment; existing continuation authority is unchanged.
DELIVERY_ADDED=frozenset(('src/atlas_core/coding_goal_delivery.py',))
DELIVERY_CHANGED=frozenset(('src/atlas_core/services.py',
    'src/atlas_core/governance/work_continuation.py',
    'src/atlas_core/governance/work_startup.py'))

# One independently reviewed exercise addition; default ALLOWED is unchanged.
EXERCISE_ADDED=frozenset(['src/atlas_core/coding_connection/session-code/deadline_registry.py', 'src/atlas_core/coding_connection/session-code/deadline_scope.py', 'src/atlas_core/coding_connection/session-code/trusted_deadline/private/checker.py', 'src/atlas_core/coding_connection/session-code/trusted_deadline/public/review-deadline-budget/PROBLEM.md', 'src/atlas_core/coding_connection/session-code/trusted_deadline/public/review-deadline-budget/PROVENANCE.json', 'src/atlas_core/coding_connection/session-code/trusted_deadline/public/review-deadline-budget/candidate.py'])
EXERCISE_CHANGED=frozenset(['src/atlas_core/governance/work_release.py', 'src/atlas_core/coding_connection/__init__.py', 'src/atlas_core/coding_connection/session-code/coding_session.py', 'src/atlas_core/coding_connection/session-code/fresh_task_registry.py', 'src/atlas_core/coding_connection/session-code/session_checker.py', 'src/atlas_core/governance/work_continuation.py', 'src/atlas_core/governance/work_startup.py', 'src/atlas_core/worker_peer.py'])

# Exact objective workflow cohort; old continuation authority is unchanged.
OBJECTIVE_CHANGED=frozenset(['src/atlas_core/coding_connection/__init__.py', 'src/atlas_core/coding_connection/session-code/coding_session.py', 'src/atlas_core/coding_counter_peer.py', 'src/atlas_core/coding_execution.py', 'src/atlas_core/coding_planner.py', 'src/atlas_core/coding_reliability.py', 'src/atlas_core/coding_trial_assembly.py', 'src/atlas_core/coding_trial_host.py', 'src/atlas_core/coding_trial_runtime.py', 'src/atlas_core/conversation_followup.py', 'src/atlas_core/governance/coding_goal.py', 'src/atlas_core/governance/coding_goal_dialogue.py', 'src/atlas_core/governance/coding_goal_gym.py', 'src/atlas_core/governance/work_continuation.py', 'src/atlas_core/governance/work_startup.py', 'src/atlas_core/models/openai_compatible.py', 'src/atlas_core/worker_peer.py'])
OBJECTIVE_ADDED=frozenset(['src/atlas_core/coding_builder_profile.py', 'src/atlas_core/coding_objective_execution.py', 'src/atlas_core/coding_objective_handoff.py', 'src/atlas_core/coding_objective_registration.py', 'src/atlas_core/coding_partial_execution.py', 'src/atlas_core/coding_partial_recovery.py', 'src/atlas_core/coding_partial_verification.py', 'src/atlas_core/coding_plan_review_verification.py', 'src/atlas_core/coding_planning_continuation.py', 'src/atlas_core/coding_planning_handoff.py', 'src/atlas_core/coding_public_diagnostics.py', 'src/atlas_core/coding_recovery_reader.py', 'src/atlas_core/coding_role_selection.py', 'src/atlas_core/coding_scope_learning.py', 'src/atlas_core/coding_source_context.py', 'src/atlas_core/coding_staged_execution.py', 'src/atlas_core/coding_staged_provider.py', 'src/atlas_core/goal_conversation.py', 'src/atlas_core/governance/coding_decomposition.py', 'src/atlas_core/governance/coding_goal_registration.py', 'src/atlas_core/governance/coding_plan_compact_review.py', 'src/atlas_core/governance/coding_plan_direct_review.py', 'src/atlas_core/governance/coding_plan_evidence_review.py', 'src/atlas_core/governance/coding_plan_grounded_review.py', 'src/atlas_core/governance/coding_plan_quote_review.py', 'src/atlas_core/governance/coding_plan_reference_review.py', 'src/atlas_core/governance/coding_plan_reference_strict_review.py', 'src/atlas_core/governance/coding_plan_review.py', 'src/atlas_core/governance/coding_plan_single_pass_review.py', 'src/atlas_core/governance/coding_plan_specific_review.py', 'src/atlas_core/governance/coding_plan_staged_review.py', 'src/atlas_core/governance/coding_review_evaluation.py', 'src/atlas_core/governance/coding_review_usage.py', 'src/atlas_core/governance/coding_staged_compact.py', 'src/atlas_core/governance/coding_staged_decomposition.py', 'src/atlas_core/worker_root_binding.py'])

# Exact saved-request and cancellation release; existing scopes stay unchanged.
REQUEST_CHANGED=frozenset(('src/atlas_core/api.py','src/atlas_core/coding_trial_runtime.py',
    'src/atlas_core/coding_staged_provider.py','src/atlas_core/memory/database.py',
    'src/atlas_core/models/admission.py','src/atlas_core/governance/work_continuation.py',
    'src/atlas_core/governance/work_startup.py'))
REQUEST_ADDED=frozenset(('src/atlas_core/objective_requests.py',
    'src/atlas_core/objective_request_binding.py','src/atlas_core/objective_cancellation.py'))

# Reviewed reliability fixes after saved-request installation. This is an exact
# source cohort, not a grant to run a job, install code, or broaden old scopes.
RELIABILITY_CHANGED=frozenset(['src/atlas_core/coding_backends.py', 'src/atlas_core/coding_builder_context.py', 'src/atlas_core/coding_engine_gym.py', 'src/atlas_core/coding_execution.py', 'src/atlas_core/coding_objective_execution.py', 'src/atlas_core/coding_planner.py', 'src/atlas_core/coding_public_diagnostics.py', 'src/atlas_core/coding_reliability.py', 'src/atlas_core/coding_reviewer.py', 'src/atlas_core/coding_role_selection.py', 'src/atlas_core/coding_scope_learning.py', 'src/atlas_core/coding_staged_execution.py', 'src/atlas_core/coding_staged_provider.py', 'src/atlas_core/coding_trial_assembly.py', 'src/atlas_core/coding_trial_host.py', 'src/atlas_core/coding_trial_runtime.py', 'src/atlas_core/governance/work_continuation.py', 'src/atlas_core/governance/work_startup.py'])
RELIABILITY_ADDED=frozenset(['src/atlas_core/coding_check_review.py', 'src/atlas_core/coding_correction_diagnostics.py', 'src/atlas_core/coding_correction_runtime.py', 'src/atlas_core/coding_correction_series.py', 'src/atlas_core/coding_lesson_transfer.py', 'src/atlas_core/coding_proposal_context.py', 'src/atlas_core/coding_review_calibration.py', 'src/atlas_core/coding_reviewer_evidence.py', 'src/atlas_core/coding_route_evidence.py', 'src/atlas_core/coding_trial_profiles.py', 'src/atlas_core/governance/coding_staged_dependencies.py'])

# Distinct owner-reviewed activation increment. Existing scopes and their
# six-step continuation bound remain unchanged; only this exact final wrapper
# may follow the qualified reliability release. No task authority is issued.
ACTIVATION_CHANGED=frozenset(('src/atlas_core/api.py',
    'src/atlas_core/governance/work_startup.py', MODULE))
ACTIVATION_ADDED=frozenset(('src/atlas_core/objective_activation.py',))

# Exact compatibility repair for settled one-task cancellation. This successor
# changes no authority, grants, test policy, or existing continuation limits.
CANCELLATION_CHANGED=frozenset(('src/atlas_core/objective_cancellation.py', MODULE))

# Exact compatibility successor: durable unknown-result reader plus validator.
UNCERTAINTY_CHANGED=frozenset(('src/atlas_core/objective_requests.py',
    'src/atlas_core/governance/work_startup.py', MODULE))
UNCERTAINTY_ADDED=frozenset(('src/atlas_core/objective_uncertainty.py',))

@dataclass(frozen=True)
class ReviewedUncertaintyScope:
    manifest_sha256:str
    source_manifest_sha256:str
    owner_reference:str
    predecessor:object
    predecessor_receipt_sha256:str

@dataclass(frozen=True)
class ReviewedCancellationScope:
    manifest_sha256:str
    source_manifest_sha256:str
    owner_reference:str
    predecessor:object
    predecessor_receipt_sha256:str

@dataclass(frozen=True)
class ReviewedActivationScope:
    manifest_sha256:str
    source_manifest_sha256:str
    owner_reference:str
    predecessor:object
    predecessor_receipt_sha256:str

@dataclass(frozen=True)
class ReviewedReliabilityScope:
    manifest_sha256:str
    source_manifest_sha256:str
    owner_reference:str
    predecessor:object
    predecessor_receipt_sha256:str

@dataclass(frozen=True)
class ReviewedRequestScope:
    manifest_sha256:str
    source_manifest_sha256:str
    owner_reference:str
    predecessor:object
    predecessor_receipt_sha256:str


@dataclass(frozen=True)
class ReviewedObjectiveScope:
    manifest_sha256:str
    source_manifest_sha256:str
    owner_reference:str
    predecessor:object
    predecessor_receipt_sha256:str


@dataclass(frozen=True)
class ReviewedContinuationScope:
    manifest_sha256:str
    source_manifest_sha256:str
    owner_reference:str
    predecessor:object
    predecessor_receipt_sha256:str


@dataclass(frozen=True)
class ReviewedExerciseScope:
    manifest_sha256:str
    source_manifest_sha256:str
    owner_reference:str
    predecessor:object
    predecessor_receipt_sha256:str


@dataclass(frozen=True)
class ReviewedDeliveryScope:
    manifest_sha256:str
    source_manifest_sha256:str
    owner_reference:str
    predecessor:object
    predecessor_receipt_sha256:str


def _prior_chain(scope):
    from .work_startup import IncrementSelection,ReviewedIncrementScope
    from .work_selfdev_release import review_scope as original_review
    if type(scope) is ReviewedUncertaintyScope:
        need(all(sha(x) for x in (scope.manifest_sha256,scope.source_manifest_sha256,scope.predecessor_receipt_sha256)), 'uncertainty_review_identity')
        ref=scope.owner_reference
        need(type(ref) is str and 1<=len(ref)<=512 and ref.strip()==ref
             and all(32<=ord(c)!=127 for c in ref), 'uncertainty_owner_reference')
        prior=scope.predecessor
        need(type(prior) is IncrementSelection and type(prior.reviewed_scope) is ReviewedCancellationScope,
             'uncertainty_exact_cancellation_predecessor')
        chain=[*_prior_chain(prior.reviewed_scope),prior]
        from .action_boundary import identifier
        need(len({s.release_id for s in chain})==len(chain) and len({s.project for s in chain})==1
             and all(identifier(s.release_id) and identifier(s.project) and sha(s.plan_sha256) for s in chain),
             'uncertainty_lineage_identity')
        return chain
    if type(scope) is ReviewedCancellationScope:
        need(all(sha(x) for x in (scope.manifest_sha256,scope.source_manifest_sha256,scope.predecessor_receipt_sha256)), 'cancellation_review_identity')
        ref=scope.owner_reference
        need(type(ref) is str and 1<=len(ref)<=512 and ref.strip()==ref
             and all(32<=ord(c)!=127 for c in ref), 'cancellation_owner_reference')
        prior=scope.predecessor
        need(type(prior) is IncrementSelection and type(prior.reviewed_scope) is ReviewedActivationScope,
             'cancellation_exact_activation_predecessor')
        chain=[*_prior_chain(prior.reviewed_scope),prior]
        from .action_boundary import identifier
        need(len({s.release_id for s in chain})==len(chain) and len({s.project for s in chain})==1
             and all(identifier(s.release_id) and identifier(s.project) and sha(s.plan_sha256) for s in chain),
             'cancellation_lineage_identity')
        return chain
    if type(scope) is ReviewedActivationScope:
        need(all(sha(x) for x in (scope.manifest_sha256,scope.source_manifest_sha256,scope.predecessor_receipt_sha256)), 'activation_review_identity')
        ref=scope.owner_reference
        need(type(ref) is str and 1<=len(ref)<=512 and ref.strip()==ref
             and all(32<=ord(c)!=127 for c in ref), 'activation_owner_reference')
        prior=scope.predecessor
        need(type(prior) is IncrementSelection and type(prior.reviewed_scope) is ReviewedReliabilityScope,
             'activation_exact_reliability_predecessor')
        chain=[*_prior_chain(prior.reviewed_scope),prior]
        from .action_boundary import identifier
        need(len({s.release_id for s in chain})==len(chain) and len({s.project for s in chain})==1
             and all(identifier(s.release_id) and identifier(s.project) and sha(s.plan_sha256) for s in chain),
             'activation_lineage_identity')
        return chain
    need(type(scope) in (ReviewedContinuationScope,ReviewedExerciseScope,ReviewedDeliveryScope,ReviewedObjectiveScope,ReviewedRequestScope,ReviewedReliabilityScope),'continuation_exact_scope')
    seen=set();tail=[];current=scope;exercise_count=0;delivery_count=0;objective_count=0;request_count=0;reliability_count=0
    for depth in range(MAX_CONTINUATIONS):
        need(type(current) in (ReviewedContinuationScope,ReviewedExerciseScope,ReviewedDeliveryScope,ReviewedObjectiveScope,ReviewedRequestScope,ReviewedReliabilityScope) and id(current) not in seen,'continuation_cycle')
        seen.add(id(current))
        need(all(sha(x) for x in (current.manifest_sha256,current.source_manifest_sha256,current.predecessor_receipt_sha256)), 'continuation_identity')
        ref=current.owner_reference
        need(type(ref) is str and 1<=len(ref)<=512 and ref.strip()==ref and all(32<=ord(c)!=127 for c in ref),'continuation_owner_reference')
        prior=current.predecessor
        need(type(prior) is IncrementSelection,'continuation_predecessor_selection')
        if type(current) is ReviewedReliabilityScope:
            reliability_count+=1
            need(reliability_count==1 and type(prior.reviewed_scope) is ReviewedRequestScope,
                 'reliability_exact_request_predecessor')
        if type(current) is ReviewedRequestScope:
            request_count+=1
            need(request_count==1 and type(prior.reviewed_scope) is ReviewedObjectiveScope,
                 'request_exact_objective_predecessor')
        if type(current) is ReviewedObjectiveScope:
            objective_count+=1
            need(objective_count==1 and type(prior.reviewed_scope) is ReviewedDeliveryScope,
                 'objective_exact_delivery_predecessor')
        if type(current) is ReviewedDeliveryScope:
            delivery_count+=1
            need(delivery_count==1 and type(prior.reviewed_scope) is ReviewedExerciseScope,
                 'delivery_exact_exercise_predecessor')
        if type(current) is ReviewedExerciseScope:
            exercise_count+=1
            need(exercise_count==1 and type(prior.reviewed_scope) is ReviewedContinuationScope,
                 'exercise_exact_continuation_predecessor')
        tail.append(prior)
        if type(prior.reviewed_scope) is ReviewedSelfdevScope:
            original_review(prior.reviewed_scope)
            first=prior.reviewed_scope.predecessor
            need(type(first.reviewed_scope) is ReviewedIncrementScope,'continuation_initial_predecessor')
            result=[first,*reversed(tail)]
            need(len({s.release_id for s in result})==len(result) and len({s.project for s in result})==1,'continuation_lineage_identity')
            from .action_boundary import identifier
            need(all(identifier(s.release_id) and identifier(s.project) and sha(s.plan_sha256) for s in result),'continuation_selection_identity')
            return result
        current=prior.reviewed_scope
    raise ValueError('continuation_depth_exhausted')


def review_scope(value):
    chain=_prior_chain(value)
    # Bounded recursion: _prior_chain checks the complete chain first.
    from .work_startup import _reviewed_scope
    return {'schema':1,'kind':('atlas-settled-uncertainty-v1' if type(value) is ReviewedUncertaintyScope else 'atlas-settled-cancellation-v1' if type(value) is ReviewedCancellationScope else 'atlas-app-activation-v1' if type(value) is ReviewedActivationScope else 'atlas-coding-reliability-v1' if type(value) is ReviewedReliabilityScope else 'atlas-saved-request-v1' if type(value) is ReviewedRequestScope else 'atlas-objective-workflow-v1' if type(value) is ReviewedObjectiveScope else 'atlas-goal-delivery-v1' if type(value) is ReviewedDeliveryScope else 'atlas-deadline-exercise-v1' if type(value) is ReviewedExerciseScope else 'atlas-reviewed-continuation-v1'),'manifest_sha256':value.manifest_sha256,
        'source_manifest_sha256':value.source_manifest_sha256,'owner_reference':value.owner_reference,
        'predecessor_receipt_sha256':value.predecessor_receipt_sha256,
        'predecessor_selection':{'release_id':chain[-1].release_id,'plan_sha256':chain[-1].plan_sha256,
            'project':chain[-1].project,'review_scope':_reviewed_scope(chain[-1].reviewed_scope)}}


def lineage_names(selection):
    from .work_startup import IncrementSelection
    need(type(selection) is IncrementSelection,'continuation_selection')
    chain=_prior_chain(selection.reviewed_scope)
    need(selection.release_id not in {s.release_id for s in chain} and selection.project==chain[-1].project,'continuation_distinct_version')
    return {s.release_id for s in chain}|{selection.release_id}


def compose(previous,expected_sources,delta,*,prior_receipt_sha256,reviewed_scope):
    from .work_startup import validated_pins
    review=review_scope(reviewed_scope);before=validated_pins(expected_sources)
    previous,delta=deepcopy(previous),deepcopy(delta);old_rows,changes=_rows(previous),_rows(delta)
    prior=reviewed_scope.predecessor
    need(previous['release_id']==prior.release_id and delta['release_id'] not in {s.release_id for s in _prior_chain(reviewed_scope)},'continuation_version')
    need(digest(previous)==prior.reviewed_scope.manifest_sha256 and prior_receipt_sha256==reviewed_scope.predecessor_receipt_sha256
        and digest(before)==review['source_manifest_sha256'] and digest(delta)==review['manifest_sha256'],'continuation_review_binding')
    exercise=type(reviewed_scope) is ReviewedExerciseScope
    delivery=type(reviewed_scope) is ReviewedDeliveryScope
    objective=type(reviewed_scope) is ReviewedObjectiveScope
    request=type(reviewed_scope) is ReviewedRequestScope
    reliability=type(reviewed_scope) is ReviewedReliabilityScope
    activation=type(reviewed_scope) is ReviewedActivationScope
    cancellation=type(reviewed_scope) is ReviewedCancellationScope
    uncertainty=type(reviewed_scope) is ReviewedUncertaintyScope
    if uncertainty:
        need({r['path'] for r in changes}==UNCERTAINTY_CHANGED|UNCERTAINTY_ADDED,'uncertainty_exact_source_scope')
        need(UNCERTAINTY_CHANGED<=before.keys() and not UNCERTAINTY_ADDED&before.keys(),'uncertainty_source_presence')
    elif cancellation:
        need({r['path'] for r in changes}==CANCELLATION_CHANGED,'cancellation_exact_source_scope')
        need(CANCELLATION_CHANGED<=before.keys(),'cancellation_source_presence')
    elif activation:
        need({r['path'] for r in changes}==ACTIVATION_CHANGED|ACTIVATION_ADDED,'activation_exact_source_scope')
        need(ACTIVATION_CHANGED<=before.keys() and not ACTIVATION_ADDED&before.keys(),'activation_source_presence')
    elif reliability:
        need({r['path'] for r in changes}==RELIABILITY_CHANGED|RELIABILITY_ADDED,'reliability_exact_source_scope')
        need(RELIABILITY_CHANGED<=before.keys() and not RELIABILITY_ADDED&before.keys(),'reliability_source_presence')
    elif request:
        need({r['path'] for r in changes}==REQUEST_CHANGED|REQUEST_ADDED,'request_exact_source_scope')
        need(REQUEST_CHANGED<=before.keys() and not REQUEST_ADDED&before.keys(),'request_source_presence')
    elif objective:
        need({r['path'] for r in changes}==OBJECTIVE_CHANGED|OBJECTIVE_ADDED,'objective_exact_source_scope')
        need(OBJECTIVE_CHANGED<=before.keys() and not OBJECTIVE_ADDED&before.keys(),'objective_source_presence')
    elif delivery:
        need({r['path'] for r in changes}==DELIVERY_CHANGED|DELIVERY_ADDED,'delivery_exact_source_scope')
        need(DELIVERY_CHANGED<=before.keys() and not DELIVERY_ADDED&before.keys(),'delivery_source_presence')
    elif exercise:
        need({r['path'] for r in changes}==EXERCISE_CHANGED|EXERCISE_ADDED,'exercise_exact_source_scope')
        need(EXERCISE_CHANGED<=before.keys() and not EXERCISE_ADDED&before.keys(),'exercise_source_presence')
    else:
        need({r['path'] for r in changes}<=ALLOWED,'continuation_source_scope')
    old={r['path']:r for r in old_rows};after=deepcopy(before);combined=deepcopy(old)
    need(all(before.get(r['path'])==r['after_sha256'] for r in old_rows),'continuation_predecessor_source')
    for row in changes:
        name=row['path']
        if name not in before:
            if uncertainty:
                need(name in UNCERTAINTY_ADDED and row['before_sha256'] is None,'uncertainty_new_file_scope')
            elif activation:
                need(name in ACTIVATION_ADDED and row['before_sha256'] is None,'activation_new_file_scope')
            elif reliability:
                need(name in RELIABILITY_ADDED and row['before_sha256'] is None,'reliability_new_file_scope')
            elif request:
                need(name in REQUEST_ADDED and row['before_sha256'] is None,'request_new_file_scope')
            elif objective:
                need(name in OBJECTIVE_ADDED and row['before_sha256'] is None,'objective_new_file_scope')
            elif delivery:
                need(name in DELIVERY_ADDED and row['before_sha256'] is None,'delivery_new_file_scope')
            elif exercise:
                need(name in EXERCISE_ADDED and row['before_sha256'] is None,'exercise_new_file_scope')
            else:
                need(name==MODULE and row['before_sha256'] is None and type(prior.reviewed_scope) is ReviewedSelfdevScope,'continuation_new_file_scope')
        else:need(row['before_sha256']==before[name],'continuation_changed_predecessor')
        after[name]=row['after_sha256']
        combined[name]=dict(row,before_sha256=old[name]['before_sha256'] if name in old else row['before_sha256'])
    composite=dict(delta,files=[combined[n] for n in sorted(combined)]);_rows(composite)
    return {'schema':1,'state':'DEVELOPMENT ONLY','predecessor':{'manifest_sha256':digest(previous),'receipt_sha256':prior_receipt_sha256,'source_manifest_sha256':digest(before)},
        'increment_manifest_sha256':digest(delta),'composite_manifest':composite,'composite_manifest_sha256':digest(composite),
        'expected_sources_before':before,'expected_sources_after':after,'rollback_sources':{r['path']:r['before_sha256'] for r in changes},
        'unchanged_startup_paths':sorted(set(old)-{r['path'] for r in changes}),'new_startup_paths':sorted(set(combined)-set(old)),
        'review_scope':review,'execution_authority':False,'installed':False,'rollback_executed':False,'installation_transaction_verified':False,'startup_receipt_replaced':False}


def _read_chain(services,selection,include_current):
    from .work_startup import _increment_initial,increment_plan
    chain=_prior_chain(selection.reviewed_scope);expected=lineage_names(selection)
    target,identity,_=_context(services,selection.project);parent=identity/'coding-increments';private_identity(parent,True)
    names={p.name for p in parent.iterdir()};required={s.release_id for s in chain}
    need(required<=names<=expected and (not include_current or names==expected),'continuation_unknown_lineage')
    if include_current:chain.append(selection)
    prior_record=None;prior_plan=None;prior_root=None;last=None
    for index,s in enumerate(chain):
        root=parent/s.release_id;record=_receipt(root);initial=record['initial_state'];plan=initial.get('plan')
        need(type(plan) is dict and initial==_increment_initial(services,s,plan,initial.get('stopped_epoch'))
            and initial['plan_sha256']==s.plan_sha256 and digest(plan)==s.plan_sha256,'continuation_initial_binding')
        need(record['release_id']==s.release_id and record['target_root']==str(target),'continuation_target')
        if index==0:
            predecessor=plan['predecessor']
            _,prior_root,prior_record=_read_bound(services,FirstWorkCodeSelection(predecessor['manifest_sha256'],selection.project))
            need(prior_record['events'][-1]['stage']=='installed' and _sha(prior_root/'receipt.json')==predecessor['receipt_sha256'],'continuation_first_receipt')
        else:
            need(prior_record['events'][-1]['stage']=='installed' and plan['expected_sources_before']==prior_plan['expected_sources_after'],'continuation_ancestor_state')
        pin=_sha(prior_root/'receipt.json')
        computed=increment_plan(prior_record['manifest'],plan['expected_sources_before'],record['manifest'],prior_receipt_sha256=pin,reviewed_scope=s.reviewed_scope)
        need(computed==plan and record['manifest_sha256']==computed['increment_manifest_sha256'],'continuation_composition')
        prior_record,prior_plan,prior_root=record,plan,root;last=(target,root,record,plan)
    return last


def predecessor(services,selection):
    result=_read_chain(services,selection,False)
    need(result[2]['events'][-1]['stage']=='installed' and _sha(result[1]/'receipt.json')==selection.reviewed_scope.predecessor_receipt_sha256,'continuation_current_predecessor')
    return result


def current_plan(services,selection,release_plan,manifest):
    _,_,record,prior_plan=predecessor(services,selection)
    need(release_plan['expected_sources_before']==prior_plan['expected_sources_after'],'continuation_source_continuity')
    computed=compose(record['manifest'],release_plan['expected_sources_before'],manifest,prior_receipt_sha256=selection.reviewed_scope.predecessor_receipt_sha256,reviewed_scope=selection.reviewed_scope)
    need(computed==release_plan and digest(computed)==selection.plan_sha256,'continuation_current_plan')
    return computed


def read_increment(services,selection):return _read_chain(services,selection,True)
