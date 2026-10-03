"""Trusted startup selection and read-only Work installation readiness.

This composes existing custody, source and state checks. It cannot provision
records, choose a task, migrate state, start a worker, Stop/Resume, or grant
authority. Selection belongs to the trusted host, never HTTP/model/config data.
"""
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from datetime import datetime, timezone
import os

from .action_boundary import sha, identifier, private_identity
from .cognitive_state import digest, need
from .owner_foundation import FoundationSelection, OwnerFoundation, _selection
from .owner_work import WorkControlSelection
from .work_release import _receipt, release_gate, _file, _sha, _rows
from .work_first_install import _context, _read_bound, _owner_directory, FirstWorkCodeSelection
from .work_state_transition import WorkStateTransition


@dataclass(frozen=True)
class WorkStartupSelection:
    foundation: FoundationSelection
    work: WorkControlSelection
    release_sha256: str


def unavailable(state='unavailable'):
    return {'schema':1,'state':state,'installation_verified':False,
            'execution_authority':False,'automatic_dispatch':False,
            'checked_at':datetime.now(timezone.utc).isoformat()}


class WorkStartup:
    """One service-lifetime selection; damaged evidence latches unavailable."""
    def __init__(self,services,selection):
        from atlas_core.services import AtlasServices
        need(type(services) is AtlasServices and type(selection) is WorkStartupSelection,
             'trusted_work_startup_selection_required')
        _selection(selection.foundation)
        need(type(selection.work) is WorkControlSelection and sha(selection.work.adoption_sha256)
             and sha(selection.release_sha256),'work_startup_identity')
        need(services.coding_work_startup is None,'work_startup_already_selected')
        if services.coding_foundation is None:
            services.select_coding_constitution(selection.foundation)
        else:
            need(type(services.coding_foundation) is OwnerFoundation
                 and services.coding_foundation.selection==selection.foundation,'work_startup_foundation_conflict')
            services.coding_foundation.check_current()
        self.services,self.selection=services,selection
        self._selection=selection;self._pid=os.getpid();self._failed=False
        self.transition=WorkStateTransition(services,selection.work)
        self._transition=self.transition;self._control=services.development.control

    def status(self):
        try:
            need(not self._failed and self._pid==os.getpid() and self.selection is self._selection
                 and self.transition is self._transition and self.transition.services is self.services
                 and self.services.development.control is self._control,'work_startup_changed')
            self.transition._current()
            control=self._control.status(self.transition.record['project'])
            if not control['stopped'] or control['active_operations'] or control['cleanup_required']:
                return unavailable('waiting_for_stopped_idle')
            state=self.transition.inspect(stopped_epoch=control['epoch'])
            if state['generation']!=2:
                return unavailable('release_required')
            record=_receipt(self.transition.root/'release')
            need(record['manifest_sha256']==self.selection.release_sha256,'work_startup_release_selection')
            # Require a receipt even when a development copy imports the code.
            release_gate(self.transition.root,self.services.config.project_root,2,required=True)
            flags={k:state[k] for k in ('requires_recovery','safe_mode','revoked')}
            result=unavailable('owner_review_required' if any(flags.values()) else 'installed_stopped')
            result.update(installation_verified=True,**flags)
            return result
        except Exception:
            self._failed=True
            return unavailable()



LEGACY_ALLOWED=frozenset('src/atlas_core/'+n for n in (
    'coding_aider.py','coding_backends.py','coding_gym_host.py','coding_reviewer.py',
    'worker_peer.py','coding_connection/__init__.py',
    'coding_connection/session-code/fresh_task_registry.py',
    'coding_connection/session-code/session_checker.py'))
ALLOWED=LEGACY_ALLOWED|frozenset('src/atlas_core/'+n for n in (
    'worker_lifetime.py','models/openai_compatible.py','coding_counter_peer.py',
    'coding_engine_gym.py','coding_native_counter.py','coding_prompt_renderer.py'))

# A distinct complete-release profile, never an expansion of the default scope.
# The trusted owner-side coordinator supplies this exact review binding. It is
# provenance and source selection, not an approval broker or task permission.
COMPLETE_INCREMENT_ALLOWED=ALLOWED|frozenset('src/atlas_core/'+n for n in (
    'api.py','governance/live_constitution.py','governance/work_release.py',
    'governance/work_startup.py'))

@dataclass(frozen=True)
class ReviewedIncrementScope:
    manifest_sha256: str
    source_manifest_sha256: str
    owner_reference: str


def _reviewed_scope(value):
    if type(value).__module__ == __package__ + ".work_continuation":
        from .work_continuation import review_scope
        return review_scope(value)
    from .work_selfdev_release import ReviewedSelfdevScope, review_scope as selfdev_scope
    if type(value) is ReviewedSelfdevScope:
        return selfdev_scope(value)
    from .work_reconciliation import ReviewedReconciliationScope, review_scope
    if type(value) is ReviewedReconciliationScope:
        return review_scope(value)
    need(type(value) is ReviewedIncrementScope
         and sha(value.manifest_sha256) and sha(value.source_manifest_sha256)
         and type(value.owner_reference) is str and 1<=len(value.owner_reference)<=512
         and value.owner_reference.strip()==value.owner_reference
         and all(ord(c)>=32 and ord(c)!=127 for c in value.owner_reference),
         'trusted_increment_review_scope_required')
    return {'schema':1,'kind':'atlas-gym-complete-increment-v1',
            'manifest_sha256':value.manifest_sha256,
            'source_manifest_sha256':value.source_manifest_sha256,
            'owner_reference':value.owner_reference}

def validated_pins(value):
    need(type(value) is dict and 1<=len(value)<=1024,'bounded_source_pins')
    for name,pin in value.items():
        need(type(name) is str and 0<len(name)<=512,'source_pin_path')
        path=PurePosixPath(name)
        need(path.as_posix()==name and not path.is_absolute() and '..' not in path.parts
             and not any(c in name for c in ('\x00','\n','\r','\\')),'source_pin_path')
        need(sha(pin),'source_pin_hash')
    return deepcopy(value)

def increment_plan(prior, expected_sources, increment, *, prior_receipt_sha256, reviewed_scope=None):
    # No filesystem, service, model, authority, or permission operation exists here.
    if type(reviewed_scope).__module__ == __package__ + ".work_continuation":
        from .work_continuation import compose
        return compose(prior, expected_sources, increment, prior_receipt_sha256=prior_receipt_sha256, reviewed_scope=reviewed_scope)
    from .work_selfdev_release import ReviewedSelfdevScope, compose as selfdev_compose
    if type(reviewed_scope) is ReviewedSelfdevScope:
        return selfdev_compose(prior, expected_sources, increment,
            prior_receipt_sha256=prior_receipt_sha256, reviewed_scope=reviewed_scope)
    from .work_reconciliation import ReviewedReconciliationScope, compose
    if type(reviewed_scope) is ReviewedReconciliationScope:
        return compose(prior, expected_sources, increment,
                       prior_receipt_sha256=prior_receipt_sha256, reviewed_scope=reviewed_scope)
    need(sha(prior_receipt_sha256),'prior_receipt_identity_required')
    before=validated_pins(expected_sources)
    previous=deepcopy(prior); delta=deepcopy(increment)
    prior_rows=_rows(previous); changes=_rows(delta)
    need(previous['release_id']!=delta['release_id'],'distinct_upgrade_version_required')
    review=None
    if reviewed_scope is None:
        need({r['path'] for r in changes}<=ALLOWED,'upgrade_outside_reviewed_scope')
    else:
        review=_reviewed_scope(reviewed_scope)
        need({r['path'] for r in changes}==COMPLETE_INCREMENT_ALLOWED,
             'complete_increment_exact_scope_required')
        need(review['manifest_sha256']==digest(delta)
             and review['source_manifest_sha256']==digest(before),
             'complete_increment_review_binding_changed')
    old={r['path']:r for r in prior_rows}
    for row in prior_rows:
        need(before.get(row['path'])==row['after_sha256'],'prior_installation_pin_conflict')
    after=deepcopy(before); combined=deepcopy(old)
    for row in changes:
        name=row['path']
        need(name in before and before[name]==row['before_sha256'],'increment_predecessor_conflict')
        after[name]=row['after_sha256']
        # Existing coverage retains its initial predecessor. Newly covered files
        # are bound to their known current hash, never declared newly nonexistent.
        combined[name]={'path':name,
            'before_sha256':old[name]['before_sha256'] if name in old else row['before_sha256'],
            'after_sha256':row['after_sha256']}
    composite={'schema':1,'release_id':delta['release_id'],
               'owner_reference':delta['owner_reference'],'files':[combined[n] for n in sorted(combined)]}
    _rows(composite)
    need(set(combined)==set(old)|{r['path'] for r in changes},'startup_coverage_changed')
    result={'schema':1,'state':'DEVELOPMENT ONLY',
        'predecessor':{'manifest_sha256':digest(previous),'receipt_sha256':prior_receipt_sha256,
                       'source_manifest_sha256':digest(before)},
        'increment_manifest_sha256':digest(delta),'composite_manifest':composite,
        'composite_manifest_sha256':digest(composite),
        'expected_sources_before':before,'expected_sources_after':after,
        'rollback_sources':{r['path']:r['before_sha256'] for r in changes},
        'unchanged_startup_paths':sorted(set(old)-{r['path'] for r in changes}),
        'new_startup_paths':sorted(set(combined)-set(old)),
        'execution_authority':False,'installed':False,'rollback_executed':False,
        'installation_transaction_verified':False,'startup_receipt_replaced':False}
    if review is not None:result['review_scope']=review
    return result


@dataclass(frozen=True)
class IncrementSelection:
    release_id: str
    plan_sha256: str
    project: str
    reviewed_scope: object = None


def _increment_selection(value):
    need(type(value) is IncrementSelection and identifier(value.release_id)
         and sha(value.plan_sha256) and identifier(value.project), 'increment_selection')
    if value.reviewed_scope is not None:_reviewed_scope(value.reviewed_scope)


def _increment_initial(services, selection, release_plan, stopped_epoch):
    need(type(stopped_epoch) is int and stopped_epoch >= 0, 'increment_epoch')
    return {'kind': 'code_only_increment', 'project': selection.project,
            'identity_root': str(services.config.app.identity_dir),
            'stopped_epoch': stopped_epoch, 'plan': release_plan,
            'plan_sha256': selection.plan_sha256, 'execution_authority': False}


def _read_increment(services, selection, *, successor=None):
    """Bind retained history, the exact plan and current target independently."""
    _increment_selection(selection)
    if type(selection.reviewed_scope).__module__ == __package__ + ".work_continuation":
        need(successor is None, "continuation_external_successor_refused")
        from .work_continuation import read_increment
        return read_increment(services, selection)
    from .work_selfdev_release import ReviewedSelfdevScope, read_increment as read_selfdev
    if type(selection.reviewed_scope) is ReviewedSelfdevScope:
        need(successor is None, "selfdev_release_successor_depth_refused")
        return read_selfdev(services, selection)
    from .work_reconciliation import ReviewedReconciliationScope, read_increment
    if type(selection.reviewed_scope) is ReviewedReconciliationScope:
        need(successor is None, 'reconciliation_successor_depth_refused')
        return read_increment(services, selection)
    target, identity, original = _context(services, selection.project)
    parent = identity/'coding-increments'
    private_identity(parent, True)
    names = {p.name for p in parent.iterdir()}
    if successor is None:
        need(names == {selection.release_id}, 'increment_unknown_lineage')
    else:
        _increment_selection(successor)
        need(type(successor.reviewed_scope) in (ReviewedReconciliationScope, ReviewedSelfdevScope)
             and successor.reviewed_scope.predecessor == selection
             and successor.project == selection.project and successor.release_id != selection.release_id,
             'reconciliation_exact_successor_required')
        need(selection.release_id in names and names <= {selection.release_id, successor.release_id},
             'increment_unknown_lineage')
    root = parent/selection.release_id
    record = _receipt(root)
    initial = record['initial_state']
    need(type(initial) is dict and type(initial.get('plan')) is dict, 'increment_initial')
    release_plan = initial['plan']
    need(digest(release_plan) == selection.plan_sha256, 'increment_plan_binding')
    need(initial == _increment_initial(services, selection, release_plan, initial.get('stopped_epoch')),
         'increment_initial_binding')
    need(record['target_root'] == str(target) and record['release_id'] == selection.release_id,
         'increment_target_binding')
    predecessor = release_plan['predecessor']
    _, prior_root, prior = _read_bound(services, FirstWorkCodeSelection(
        predecessor['manifest_sha256'], selection.project))
    need(prior['events'][-1]['stage'] == 'installed' and prior_root == original
         and _sha(prior_root/'receipt.json') == predecessor['receipt_sha256'],
         'increment_predecessor_changed')
    # Recompute the entire composition rather than trusting stored after-pins.
    computed = increment_plan(prior['manifest'], release_plan['expected_sources_before'], record['manifest'],
                    prior_receipt_sha256=predecessor['receipt_sha256'],reviewed_scope=selection.reviewed_scope)
    need(computed == release_plan and record['manifest_sha256'] == computed['increment_manifest_sha256'],
         'increment_composition_changed')
    return target, root, record, release_plan


def _verify_sources(target, release_plan, sides):
    before = validated_pins(release_plan['expected_sources_before'])
    after = validated_pins(release_plan['expected_sources_after'])
    if release_plan.get('review_scope', {}).get('kind') == 'atlas-chat-reconciliation-increment-v1':
        from .work_reconciliation import ADDED
        need(set(before) < set(after) and set(after)-set(before) == ADDED,
             'reconciliation_source_coverage_changed')
    elif release_plan.get('review_scope', {}).get('kind') == 'atlas-selfdev-release-increment-v1':
        from .work_selfdev_release import ADDED
        need(set(before) < set(after) and set(after)-set(before) == ADDED,
             'selfdev_release_source_coverage_changed')
    elif release_plan.get('review_scope', {}).get('kind') == 'atlas-settled-uncertainty-v1':
        from .work_continuation import UNCERTAINTY_ADDED
        need(set(before) < set(after) and set(after)-set(before) == UNCERTAINTY_ADDED,
             'uncertainty_source_coverage_changed')
    elif release_plan.get('review_scope', {}).get('kind') == 'atlas-app-activation-v1':
        from .work_continuation import ACTIVATION_ADDED
        need(set(before) < set(after) and set(after)-set(before) == ACTIVATION_ADDED,
             'activation_source_coverage_changed')
    elif release_plan.get('review_scope', {}).get('kind') == 'atlas-coding-reliability-v1':
        from .work_continuation import RELIABILITY_ADDED
        need(set(before) < set(after) and set(after)-set(before) == RELIABILITY_ADDED,
             'reliability_source_coverage_changed')
    elif release_plan.get('review_scope', {}).get('kind') == 'atlas-saved-request-v1':
        from .work_continuation import REQUEST_ADDED
        need(set(before) < set(after) and set(after)-set(before) == REQUEST_ADDED,
             'request_source_coverage_changed')
    elif release_plan.get('review_scope', {}).get('kind') == 'atlas-objective-workflow-v1':
        from .work_continuation import OBJECTIVE_ADDED
        need(set(before) < set(after) and set(after)-set(before) == OBJECTIVE_ADDED,
             'objective_source_coverage_changed')
    elif release_plan.get('review_scope', {}).get('kind') == 'atlas-goal-delivery-v1':
        from .work_continuation import DELIVERY_ADDED
        need(set(before) < set(after) and set(after)-set(before) == DELIVERY_ADDED,
             'delivery_source_coverage_changed')
    elif release_plan.get('review_scope', {}).get('kind') == 'atlas-deadline-exercise-v1':
        from .work_continuation import EXERCISE_ADDED
        need(set(before) < set(after) and set(after)-set(before) == EXERCISE_ADDED,
             'exercise_source_coverage_changed')
    elif release_plan.get('review_scope', {}).get('kind') == 'atlas-reviewed-continuation-v1':
        from .work_continuation import MODULE
        need(set(before) <= set(after) and set(after)-set(before) <= {MODULE}, 'continuation_source_coverage_changed')
    else:
        need(set(before) == set(after), 'increment_source_coverage_changed')
    for name in after:
        path = target/name
        need(not any(p.is_symlink() for p in (path,*path.parents)), 'release_symlink')
        actual = _sha(path) if path.exists() else None
        need(actual in {before.get(name) if side == 'before' else after[name] for side in sides},
             'increment_source_drift')


def code_status(services, selection):
    """Read-only installation evidence; grants no Work access."""
    target, _, record, release_plan = _read_increment(services, selection)
    stage = record['events'][-1]['stage']
    need(stage in ('installed', 'rolled_back'), 'increment_not_ready')
    _verify_sources(target, release_plan, ('after',) if stage == 'installed' else ('before',))
    return {'stage': stage, 'installation_verified': stage == 'installed',
            'rollback_verified': stage == 'rolled_back', 'execution_authority': False,
            'task_authority_verified': False, 'work_available': False,
            'first_install_receipt_preserved': True}


class IncrementWorkCodeStartup:
    """Trusted read-only increment selection; every check retains no authority."""
    def __init__(self,services,selection):
        _increment_selection(selection)
        roots=_context(services,selection.project)
        need(services.coding_work_startup is None,'work_startup_already_selected')
        self.services,self.selection=services,selection
        self._services,self._selection=services,selection
        self._control=services.development.control
        self._constitution=services.constitution
        self._roots=roots
        self._directory_ids=tuple(_owner_directory(p) for p in roots[:2])
        self._pid=os.getpid();self._failed=False

    def status(self):
        try:
            need(not self._failed and os.getpid()==self._pid
                 and self.services is self._services and self.selection is self._selection
                 and self.services.development.control is self._control
                 and self.services.constitution is self._constitution,'increment_startup_changed')
            roots=_context(self.services,self.selection.project)
            need(roots==self._roots and tuple(_owner_directory(p) for p in roots[:2])==self._directory_ids,
                 'increment_startup_target_changed')
            evidence=code_status(self.services,self.selection)
            result=unavailable('installed_code_only' if evidence['installation_verified'] else 'rolled_back')
            result.update(installation_verified=evidence['installation_verified'],
                rollback_verified=evidence['rollback_verified'],task_authority_verified=False,
                first_install_receipt_preserved=True)
            return result
        except Exception:
            self._failed=True
            return unavailable()

def select_for_services(services,selection):
    from .work_first_install import FirstWorkCodeSelection, FirstWorkCodeStartup
    if type(selection) is FirstWorkCodeSelection:
        startup=FirstWorkCodeStartup(services,selection)
    elif type(selection) is IncrementSelection:
        startup=IncrementWorkCodeStartup(services,selection)
    else:
        startup=WorkStartup(services,selection)
    services.coding_work_startup=startup
    return startup
