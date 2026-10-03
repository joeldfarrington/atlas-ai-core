"""Project an externally verified recovered objective into its bound chat.

The trusted owner selects immutable receipt identities after independent
verification. This module checks and renders that selection; it neither verifies
code nor authenticates its own input as an owner decision. Never expose selection
to a model tool or accept it from saved task data or an HTTP request.

Receipts are passed as bounded bytes, so they cannot select paths or execute
anything. Historical outcome-unknown records remain unchanged. Conversation
publication uses the existing transactional, idempotent delivery mechanism.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re

from atlas_core.conversation_followup import publish_followup
from atlas_core.governance.cognitive_state import need


@dataclass(frozen=True)
class GoalDeliverySelection:
    objective_sha256: str
    resolution_sha256: str
    aggregate_sha256: str
    audit_sha256: str
    project_slug: str
    conversation_id: str
    run_id: str


def _hash(value):
    return hashlib.sha256(value).hexdigest()


def _digest(value):
    need(type(value) is str and re.fullmatch('[a-f0-9]{64}', value), 'delivery_digest')
    return value


def _pairs(items):
    value = {}
    for key, item in items:
        need(key not in value, 'delivery_duplicate_key')
        value[key] = item
    return value


def _read(raw, expected):
    need(type(raw) is bytes and 0 < len(raw) <= 32768, 'delivery_receipt_bytes')
    need(_hash(raw) == _digest(expected), 'delivery_receipt_changed')
    try:
        value = json.loads(raw, object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError('delivery_nonfinite')))
    except (UnicodeError, RecursionError) as exc:
        raise ValueError('delivery_receipt_json') from exc
    need(type(value) is dict, 'delivery_receipt_shape')
    return value


def _count(value, minimum=0, maximum=100000):
    need(type(value) is int and minimum <= value <= maximum, 'delivery_count')
    return value


def inspect_goal_resolution(selection, *, resolution, aggregate, audit):
    """Read-only view of a frozen owner selection; not a new coding verdict."""
    need(type(selection) is GoalDeliverySelection, 'delivery_owner_selection')
    _digest(selection.objective_sha256)
    for item in (selection.conversation_id, selection.run_id):
        need(type(item) is str and 0 < len(item) <= 128 and not any(ord(c) < 32 for c in item),
             'delivery_chat_binding')
    need(type(selection.project_slug) is str and
         re.fullmatch('[a-z0-9][a-z0-9_-]{0,79}', selection.project_slug), 'delivery_project')
    r = _read(resolution, selection.resolution_sha256)
    v = _read(aggregate, selection.aggregate_sha256)
    a = _read(audit, selection.audit_sha256)
    need(type(r.get('schema')) is int and r['schema'] == 1 and
         type(v.get('schema')) is int and v['schema'] == 1, 'delivery_schema')
    need(all(x.get('objective_sha256') == selection.objective_sha256 for x in (r, v, a)),
         'delivery_objective_binding')
    need(r.get('aggregate_verification_sha256') == selection.aggregate_sha256 and
         r.get('audit_sha256') == selection.audit_sha256, 'delivery_receipt_chain')
    for field in ('prior_archive_manifest_sha256', 'remaining_result_manifest_sha256'):
        _digest(r.get(field))
    need(r.get('state') == a.get('state') == 'COMPLETE' and
         r.get('original_history_state') == v.get('historical_state') == a.get('historical_state') == 'OUTCOME_UNKNOWN',
         'delivery_outcome')
    need(all(r.get(k) is False for k in ('historical_record_rewritten', 'production_memory_written', 'execution_authority'))
         and all(v.get(k) is False for k in ('carried_candidate_regenerated', 'history_rewritten', 'installed', 'execution_authority'))
         and all(a.get(k) is False for k in ('history_rewritten', 'installed', 'source_promoted',
                                            'model_weights_trained', 'reliability_qualified', 'savings_claim',
                                            'premium_authored_coding_patch')),
         'delivery_claim_boundary')
    need(v.get('independent') is True and v.get('accepted') is True and
         v.get('real_model_completion') is True and v.get('evidence_kind') == 'local_model' and
         a.get('real_model_completion') is True and a.get('cleanup_verified') is True and
         a.get('service_restored') is True and a.get('technical_result') == 'PASS' and
         a.get('authority_process_result') == 'PASS', 'delivery_independent_completion')
    tests = _count(v.get('tests_run'), 1)
    requests = _count(v.get('requests_used'), 1, 6)
    need(_count(a.get('tests_passed'), 1) == tests and
         _count(a.get('original_total_model_requests'), 1, 6) == requests and
         _count(a.get('remaining_exercise_requests'), 1, 6) +
         _count(a.get('original_prior_model_requests'), 0, 6) == requests,
         'delivery_usage_binding')
    need(_count(a.get('premium_intervention_during_model_coding')) == 0,
         'delivery_coding_intervention')
    need(type(a.get('held_out')) is bool and type(a.get('previous_task_exposure')) is bool,
         'delivery_exposure')
    for field in ('carried_patch_sha256', 'remaining_patch_sha256'):
        _digest(a.get(field))
    need(type(r.get('utc')) is str and r['utc'] == a.get('utc'), 'delivery_recorded_time')
    stamp = datetime.fromisoformat(r['utc'])
    need(stamp.tzinfo is not None and stamp.utcoffset() == timezone.utc.utcoffset(stamp),
         'delivery_recorded_time')
    # No arbitrary model prose, paths or identifiers enter the user-facing text.
    content = (f'The recovered coding objective passed {tests} independent acceptance checks. '
               f'The original objective used {requests} model requests in total. '
               'The earlier unconfirmed outcome is preserved in its history; this linked verification resolves it. '
               'The code changes are development candidates, not installed changes. '
               'This result does not establish general coding reliability.')
    if a['previous_task_exposure'] or not a['held_out']:
        content += ' This was not a held-out reliability test.'
    return dict(state='COMPLETE', objective_sha256=selection.objective_sha256,
                recorded_utc=r['utc'], tests_passed=tests, model_requests=requests,
                historical_state='OUTCOME_UNKNOWN', history_rewritten=False,
                installed=False, execution_authority=False, starts_work=False,
                verification_basis='externally_selected_owner_receipts',
                current_service_health_attested=False, content=content)


def publish_goal_resolution(database, selection, *, resolution, aggregate, audit):
    """Deliver once to the exact terminal chat/run; never choose a recent chat."""
    view = inspect_goal_resolution(selection, resolution=resolution, aggregate=aggregate, audit=audit)
    return publish_followup(database, conversation_id=selection.conversation_id, run_id=selection.run_id,
        project_slug=selection.project_slug,
        event_id='goal-resolution:' + selection.objective_sha256,
        kind='result', content=view['content'],
        evidence=['sha256:' + selection.objective_sha256,
                  'sha256:' + selection.resolution_sha256,
                  'sha256:' + selection.aggregate_sha256, 'sha256:' + selection.audit_sha256])
