"""A check-aware review contract, not a substitute for final verification.

A reviewer can honestly reject an independently failed candidate without
inventing a source diagnosis. Raw false approvals are retained, not corrected
by this parser or credited as reviewer success.
"""
import json
from .coding_review_anchor import reground
from .governance.cognitive_state import need
from .practice.workspace import sha

PROTOCOL = 'candidate-check-aware-v1'
INSTRUCTION = (
    'Declare basis as source_review or independent_check_failed. '
    'If the supplied protected-checker observation reports behavior_fail, do not '
    'approve the candidate. You may use basis independent_check_failed and approved '
    'false even with no source findings when you have not located its cause. '
    'Do not invent a line citation or counterexample merely to express that rejection. '
    'Use source_review for your independently identified source findings, or for '
    'approval when no defect is found and the supplied checks have not failed. '
    'Passing tests do not require approval and do not prove absence of defects. '
    'A declared basis does not grant execution or replace final verification.')


def response_format():
    from .coding_reviewer import grounded_response_format
    value = grounded_response_format()
    value['json_schema']['name'] = 'atlas_check_aware_review'
    shape = value['json_schema']['schema']
    shape['properties']['basis'] = {'type':'string',
        'enum':['source_review','independent_check_failed']}
    shape['required'].append('basis')
    return value


def interpret(raw, payload, verification):
    from .coding_reviewer import validate_precheck, parse_grounded_review
    need(type(raw) is str and 0 < len(raw.encode()) <= 16384, 'bounded_review_required')
    need(type(payload) is dict and type(payload.get('candidate_source')) is str,
         'check_review_context')
    summary = validate_precheck(verification, sha(payload['candidate_source'].encode()))
    def unique(items):
        value = {}
        for key, item in items:
            need(key not in value, 'duplicate_review_field')
            value[key] = item
        return value
    value = json.loads(raw, object_pairs_hook=unique)
    need(type(value) is dict and set(value) == {'basis','findings','approved'}
         and type(value['basis']) is str
         and value['basis'] in ('source_review','independent_check_failed')
         and type(value['approved']) is bool and type(value['findings']) is list,
         'check_review_shape')
    basis = value['basis']
    if basis == 'independent_check_failed':
        need(summary['failed'] > 0 and value['approved'] is False,
             'check_review_failure_basis_conflict')
    # Existing source/requirement/quote/counterexample validation applies to every
    # claimed source defect. No findings are fabricated or dropped. For the
    # independent-failure basis, an empty finding list does not imply approval.
    source_value = {'findings':value['findings'], 'approved':
        not value['findings'] if basis == 'independent_check_failed' else value['approved']}
    grounded, anchors = reground(json.dumps(source_value), payload, parse_grounded_review)
    decision = {'approved':value['approved'], 'findings':grounded['findings']}
    anchors.update(protocol=PROTOCOL, response_sha256=sha(raw.encode()),
        basis=basis, precheck_sha256=sha(json.dumps(summary,sort_keys=True,separators=(',',':')).encode()),
        raw_approval_preserved=True, verdict_changed=False)
    return decision, anchors
