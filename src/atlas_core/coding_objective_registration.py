"""Aggregate independently registered work into one bounded planning objective.

This is a trusted host adapter, not a model-facing registration API or execution
grant. Reuse the current registered-task previews, decomposition compiler and
proposal association checks. Individual acceptance contracts remain independent;
one child's success can never establish completion of the whole objective.
"""
from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
import re

from .coding_execution import preview_registered_task
from .coding_preparation import FreshTaskPlan
from .coding_gym import read, save
from .governance.action_boundary import private_identity
from .governance.cognitive_state import digest, need
from .governance.coding_decomposition import decomposition_context
from .governance.coding_goal import BoundedCodingGoal
from .governance.coding_goal_registration import associate
from .governance.work_release import _sync_dir


def _path(path):
    p = Path(path).absolute()
    need('..' not in p.parts and not any(x.is_symlink() for x in (p, *p.parents)),
         'objective_registration_path')
    return p


def _definition(plans, parent_directory, *, parent_id, objective,
                foundation_sha256, authority_sha256, total_model_requests):
    need(type(plans) is tuple and 1 <= len(plans) <= 2
         and all(type(p) is FreshTaskPlan for p in plans), 'objective_registered_plans')
    need(type(total_model_requests) is int
         and 2 + 2 * len(plans) <= total_model_requests <= 6,
         'objective_whole_request_budget')
    for value in (foundation_sha256, authority_sha256):
        need(type(value) is str and re.fullmatch('[a-f0-9]{64}', value), 'objective_identity')
    first = plans[0]
    # No child may smuggle in another grant, epoch, project or renewed window.
    for field in ('project', 'created_utc', 'dispatch_utc', 'acceptance_utc',
                  'close_utc', 'expected_epoch', 'approval_ref'):
        need(all(getattr(p, field) == getattr(first, field) for p in plans),
             'objective_mixed_scope_or_window')
    need(len({p.task_id for p in plans}) == len(plans)
         and len({p.run_id for p in plans}) == len(plans), 'objective_duplicate_identity')
    previews = [preview_registered_task(p, parent_directory=parent_directory,
        foundation_sha256=foundation_sha256) for p in plans]
    requirements, resources, registrations, policies = [], {}, {}, {}
    for index, (plan, preview) in enumerate(zip(plans, previews), 1):
        packet = preview['packet']; path = packet['editable_file']; rid = 'resource-' + str(index)
        need(path not in {r['editable_file'] for r in resources.values()},
             'objective_same_file_requires_rebinding')
        start = len(requirements) + 1
        requirements.extend(packet['requirements'])
        resources[rid] = dict(editable_file=path, source_sha256=packet['source_sha256'],
            requirement_ids=list(range(start, len(requirements) + 1)), constraints=[])
        registrations[rid] = dict(plan=asdict(plan), preview=preview)
        policies[rid] = deepcopy(preview['verification_policy'])
    acceptance = dict(schema=1, kind='all_registered_children', policies=policies,
                      execution_authority=False)
    # bounded_context already reserves the planner request. Supply the whole
    # budget here, and retain its resulting execution parent separately.
    parent = dict(id=parent_id, project=first.project, objective=objective,
        origin='user_assigned', requirements=requirements,
        resources={r['editable_file']: r['source_sha256'] for r in resources.values()},
        foundation_sha256=foundation_sha256, authority_sha256=authority_sha256,
        acceptance_sha256=digest(acceptance), deadline_utc=previews[0]['packet']['deadline_utc'],
        max_requests=total_model_requests, max_children=len(plans), context_bytes=65536)
    from .coding_planner import bounded_context
    execution_parent, _, _ = bounded_context(parent, resources, proposal_kind='decomposition_staged_v1')
    context = decomposition_context(execution_parent, resources)
    return dict(schema=1, parent=parent, execution_parent=execution_parent,
        resources=resources, registrations=registrations,
        acceptance=acceptance, context_sha256=digest(context),
        whole_objective_requests=total_model_requests, planner_requests=1,
        plan_review_requests=1, coding_requests=2 * len(plans),
        execution_authority=False, automatic_retry=False, installed=False)


class RegisteredObjective:
    """Externally pinned host record; always revalidate against current previews."""
    @classmethod
    def create(cls, root, plans, *, parent_id, objective, foundation_sha256,
               authority_sha256, total_model_requests):
        root = _path(root)
        need(not root.exists(), 'objective_registration_consumed')
        private_identity(root.parent, True)
        value = _definition(plans, root.parent, parent_id=parent_id, objective=objective,
            foundation_sha256=foundation_sha256, authority_sha256=authority_sha256,
            total_model_requests=total_model_requests)
        root.mkdir(mode=0o700)
        save(root, 'OBJECTIVE.json', value); _sync_dir(root)
        return cls(root, expected_sha256=digest(value))

    def __init__(self, root, *, expected_sha256):
        self.root = _path(root)
        self._identity = private_identity(self.root, True)
        need(type(expected_sha256) is str and re.fullmatch('[a-f0-9]{64}', expected_sha256),
             'objective_external_pin_required')
        self.expected = expected_sha256
        self.validate()

    def validate(self):
        need(private_identity(self.root, True) == self._identity, 'objective_root_changed')
        value = read(self.root, 'OBJECTIVE.json')
        need(digest(value) == self.expected, 'objective_registration_changed')
        plans = tuple(FreshTaskPlan(**r['plan']) for r in value['registrations'].values())
        parent = value['parent']
        fresh = _definition(plans, self.root.parent, parent_id=parent['id'],
            objective=parent['objective'], foundation_sha256=parent['foundation_sha256'],
            authority_sha256=parent['authority_sha256'],
            total_model_requests=value['whole_objective_requests'])
        need(fresh == value, 'objective_current_registration_changed')
        return deepcopy(value)

    def bind_reviewed_goal(self, goal):
        """Return every exact child association only after independent review.

        Description/ID variations are handled by existing associate(). Missing,
        split, duplicate or merged registered contracts cannot become runnable.
        This method dispatches nothing and does not replace current owner checks.
        """
        return self._bindings(goal, require_ready=True)

    def _bindings(self, goal, *, require_ready):
        value = self.validate()
        need(type(goal) is BoundedCodingGoal, 'objective_typed_goal_required')
        goal._validate()
        need(goal.plan['parent'] == value['execution_parent'] and goal._decomposition is not None
             and goal._decomposition['resources'] == value['resources'],
             'objective_goal_changed')
        if require_ready:
            need(goal.reconcile()['state'] == 'READY', 'objective_plan_not_reviewed')
        mappings = {}; seen = set()
        for child in goal.plan['children']:
            matches = [(rid, r) for rid, r in value['registrations'].items()
                       if r['preview']['packet']['editable_file'] == child['packet']['editable_file']]
            need(len(matches) == 1, 'objective_unregistered_child')
            rid, registration = matches[0]
            need(rid not in seen and child['covers'] == value['resources'][rid]['requirement_ids'],
                 'objective_incomplete_child_contract')
            mapping, _ = associate(goal.plan, child['packet']['task_id'], registration['preview']['packet'])
            mappings[child['packet']['task_id']] = dict(resource_id=rid, mapping=mapping,
                verification_policy=deepcopy(registration['preview']['verification_policy']))
            seen.add(rid)
        need(seen == set(value['registrations']), 'objective_missing_registered_work')
        return dict(schema=1, objective_sha256=self.expected, plan_sha256=goal.fp,
                    children=mappings, execution_authority=False)


def verify_objective_trials(registration, goal, trials):
    """Trusted aggregate verification over actual separately checked Gym trials.

    Re-read independent checker/source/registration evidence and check cleanup
    for *every* child. Never accept model success text, a partial subset or the
    last child's receipt as proof of the parent. No worker or retry is started.
    The enclosing owner must retain custody and protect this verifier's code.
    """
    from .coding_trial_host import RegisteredGymTrial
    need(type(registration) is RegisteredObjective and type(goal) is BoundedCodingGoal
         and type(trials) is tuple and 1 <= len(trials) <= 2,
         'objective_verifier_components')
    bindings = registration._bindings(goal, require_ready=False)
    need(all(type(t) is RegisteredGymTrial and t.goal is goal
             and t.objective_registration is registration for t in trials),
         'objective_verifier_trial_identity')
    ids = [t.binding['task_id'] for t in trials]
    need(len(set(ids)) == len(ids) and set(ids) == set(bindings['children'])
         and len({str(t.root) for t in trials}) == len(trials),
         'objective_verifier_complete_distinct_trials')
    # Equal scope hashes mean equal policy, not reuse of one allocation. Pin
    # and recheck each original host ledger, journal inode and lock instead.
    instances = [t.allocation_identity() for t in trials]
    for key in ('journal_root', 'journal_file_identity', 'journal_root_identity',
                'lock_path', 'lock_identity', 'host_lifetime_sha256'):
        need(len({digest(i[key]) for i in instances}) == len(trials),
             'objective_verifier_distinct_allocations')
    def independently_check(plan, children):
        need(plan == goal.plan and digest(plan) == bindings['plan_sha256']
             and goal.reconcile()['children'] == children,
             'objective_verifier_current_state')
        registration._bindings(goal, require_ready=False)
        receipts = {}
        for trial in trials:
            result, current, passed, checker_receipt = trial._evidence()
            cleanup = trial.cleanup()
            need(current['children'] == children and passed is True
                 and type(checker_receipt) is str and result['workspace_discarded'] is True
                 and cleanup['owned_processes_absent'] is True
                 and cleanup['model_requests_settled'] is True
                 and cleanup['admission_stopped'] is True
                 and type(cleanup['model_requests_active']) is int
                 and cleanup['model_requests_active'] == 0, 'objective_verifier_child_incomplete')
            receipts[trial.binding['task_id']] = checker_receipt
        return dict(plan_sha256=digest(plan), children_sha256=digest(children),
                    checker_sha256=goal.plan['parent']['acceptance_sha256'],
                    passed=True, cleanup_verified=True)
    # verify_goal records only the existing exact receipt schema. All concrete
    # child receipts remain in their independently bound trial evidence.
    need(goal.reconcile()['state'] == 'VERIFYING', 'objective_verifier_not_complete')
    return goal.verify_goal(independently_check)
