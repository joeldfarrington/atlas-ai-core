"""Exact reconciliation successor composition, not task or deployment authority.

Reuse existing receipt, source, stopped-host transaction and startup checks.
Only one reconciliation successor to the previously reviewed complete Gym increment
is supported. Historical receipts are retained, never rewritten or replayed.
"""
from copy import deepcopy
from dataclasses import dataclass
import os

from .action_boundary import identifier, private_identity, sha
from .cognitive_state import digest, need
from .work_release import _rows, _receipt, _sha
from .work_first_install import _context

CHANGED = frozenset('src/atlas_core/'+n for n in (
    'api.py', 'runtime.py', 'schemas.py', 'memory/database.py',
    'governance/work_startup.py'))
ADDED = frozenset(('src/atlas_core/governance/work_reconciliation.py',
    'src/atlas_core/run_reconciliation.py'))


@dataclass(frozen=True)
class ReviewedReconciliationScope:
    manifest_sha256: str
    source_manifest_sha256: str
    owner_reference: str
    predecessor: object
    predecessor_receipt_sha256: str


def review_scope(value):
    from .work_startup import IncrementSelection, ReviewedIncrementScope, _increment_selection, _reviewed_scope
    need(type(value) is ReviewedReconciliationScope and sha(value.manifest_sha256)
         and sha(value.source_manifest_sha256) and sha(value.predecessor_receipt_sha256),
         'reconciliation_exact_review_required')
    need(type(value.owner_reference) is str and 1 <= len(value.owner_reference) <= 512
         and value.owner_reference.strip() == value.owner_reference
         and all(32 <= ord(c) != 127 for c in value.owner_reference), 'reconciliation_owner_reference')
    prior = value.predecessor
    need(type(prior) is IncrementSelection and type(prior.reviewed_scope) is ReviewedIncrementScope,
         'reconciliation_complete_predecessor_required')
    _increment_selection(prior)
    return {'schema':1, 'kind':'atlas-chat-reconciliation-increment-v1',
            'manifest_sha256':value.manifest_sha256, 'source_manifest_sha256':value.source_manifest_sha256,
            'owner_reference':value.owner_reference,
            'predecessor_receipt_sha256':value.predecessor_receipt_sha256,
            'predecessor_selection':{'release_id':prior.release_id, 'plan_sha256':prior.plan_sha256,
                'project':prior.project, 'review_scope':_reviewed_scope(prior.reviewed_scope)}}


def compose(previous, expected_sources, delta, *, prior_receipt_sha256, reviewed_scope):
    from .work_startup import validated_pins
    review = review_scope(reviewed_scope)
    before = validated_pins(expected_sources)
    previous, delta = deepcopy(previous), deepcopy(delta)
    old_rows, changes = _rows(previous), _rows(delta)
    prior = reviewed_scope.predecessor
    need(previous['release_id'] == prior.release_id and previous['release_id'] != delta['release_id']
         and digest(previous) == prior.reviewed_scope.manifest_sha256, 'reconciliation_predecessor_manifest')
    need(prior_receipt_sha256 == reviewed_scope.predecessor_receipt_sha256
         and digest(before) == review['source_manifest_sha256']
         and digest(delta) == review['manifest_sha256'], 'reconciliation_review_binding')
    need({r['path'] for r in changes} == CHANGED | ADDED, 'reconciliation_exact_source_scope')
    old = {r['path']:r for r in old_rows}
    for row in old_rows:
        need(before.get(row['path']) == row['after_sha256'], 'reconciliation_predecessor_source')
    after, combined = deepcopy(before), deepcopy(old)
    for row in changes:
        name = row['path']
        if name in ADDED:
            need(name not in before and row['before_sha256'] is None, 'reconciliation_new_file_predecessor')
        else:
            need(name in before and row['before_sha256'] == before[name], 'reconciliation_changed_file_predecessor')
        after[name] = row['after_sha256']
        combined[name] = dict(row, before_sha256=old[name]['before_sha256'] if name in old else row['before_sha256'])
    composite = dict(delta, files=[combined[n] for n in sorted(combined)])
    _rows(composite)
    return {'schema':1, 'state':'DEVELOPMENT ONLY',
        'predecessor':{'manifest_sha256':digest(previous), 'receipt_sha256':prior_receipt_sha256,
                       'source_manifest_sha256':digest(before)},
        'increment_manifest_sha256':digest(delta), 'composite_manifest':composite,
        'composite_manifest_sha256':digest(composite), 'expected_sources_before':before,
        'expected_sources_after':after, 'rollback_sources':{r['path']:r['before_sha256'] for r in changes},
        'unchanged_startup_paths':sorted(set(old)-{r['path'] for r in changes}),
        'new_startup_paths':sorted(set(combined)-set(old)), 'review_scope':review,
        'execution_authority':False, 'installed':False, 'rollback_executed':False,
        'installation_transaction_verified':False, 'startup_receipt_replaced':False}


def predecessor(services, selection):
    from .work_startup import _read_increment
    scope = selection.reviewed_scope
    review_scope(scope)
    need(selection.project == scope.predecessor.project
         and selection.release_id != scope.predecessor.release_id, 'reconciliation_lineage_identity')
    target, root, record, plan = _read_increment(services, scope.predecessor, successor=selection)
    need(record['events'][-1]['stage'] == 'installed'
         and _sha(root/'receipt.json') == scope.predecessor_receipt_sha256,
         'reconciliation_installed_predecessor_required')
    return target, root, record, plan


def current_plan(services, selection, release_plan, manifest):
    _, _, record, prior_plan = predecessor(services, selection)
    need(release_plan['expected_sources_before'] == prior_plan['expected_sources_after'],
         'reconciliation_complete_source_continuity')
    computed = compose(record['manifest'], release_plan['expected_sources_before'], manifest,
        prior_receipt_sha256=selection.reviewed_scope.predecessor_receipt_sha256,
        reviewed_scope=selection.reviewed_scope)
    need(computed == release_plan and digest(computed) == selection.plan_sha256,
         'reconciliation_composition_changed')
    return computed


def read_increment(services, selection):
    from .work_startup import _increment_initial
    scope = selection.reviewed_scope
    review_scope(scope)
    target, identity, _ = _context(services, selection.project)
    parent = identity/'coding-increments'
    private_identity(parent, True)
    need({p.name for p in parent.iterdir()} == {scope.predecessor.release_id, selection.release_id},
         'reconciliation_unknown_lineage')
    root = parent/selection.release_id
    record = _receipt(root)
    initial = record['initial_state']
    need(type(initial) is dict and type(initial.get('plan')) is dict, 'reconciliation_initial')
    plan = initial['plan']
    need(initial == _increment_initial(services, selection, plan, initial.get('stopped_epoch'))
         and initial['plan_sha256'] == selection.plan_sha256, 'reconciliation_initial_binding')
    need(record['release_id'] == selection.release_id and record['target_root'] == str(target),
         'reconciliation_target_binding')
    current_plan(services, selection, plan, record['manifest'])
    need(record['manifest_sha256'] == plan['increment_manifest_sha256'], 'reconciliation_manifest_binding')
    return target, root, record, plan
