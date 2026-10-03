"""Opt-in v6: bind negative claims to an explicit proposed/expected stage.

A before-change failure is not evidence that a proposed fix has that behavior.
This is provenance enforcement, not semantic proof. Baseline claims still need
independent reproduction; no model assertion is promoted to observed truth.
"""
from copy import deepcopy
from . import coding_plan_specific_review as v5
from . import coding_staged_decomposition as stages
from .cognitive_state import encoded,need
from .coding_plan_selection import decode_selection
from .task_contract import _text
import json

ALLOWED = {
    'implementation_contradiction': ('approach',),
    'incorrect_expected_result': ('expected_after_change',),
    'reproduction_method_error': ('scenario', 'check_method'),
    'missing_verification': ('check_method', 'risks'),
}


def _stages(context):
    value=context.get('reproduction_stages')
    notes={n['task_id']:n for n in context['planning_notes']}
    need(type(value) is dict and set(value)==set(notes),'staged_review_provenance_required')
    for ident,row in value.items():
        stages.validate_stages(row)
        need(notes[ident]['reproduction']==stages.render(row),'staged_review_notes_changed')
    return value


def request(context):
    value=_stages(context);req=v5.request(context)
    schema=req['response_format']['json_schema']['schema'];old=encoded(schema)
    item=schema['properties']['defects']['items']
    item['properties']['claim_kind']=dict(type='string',enum=list(ALLOWED))
    item['required'].append('claim_kind')
    item['properties']['plan_field']['enum']=sorted({field for fields in ALLOWED.values() for field in fields})
    req['response_format']['json_schema']['name']='atlas_plan_critic_v6'
    req['messages'][0]['content']=(
        'Temporal distinction: baseline describes BEFORE the change, often a known bug. '
        'It must never be interpreted as the proposed fix. For implementation '
        'contradictions, predict behavior only from approach and quote that field. '
        'For an incorrect desired result, quote expected_after_change. For reproduction '
        'method errors quote scenario or check_method; for missing verification quote '
        'check_method or risks. Match claim_kind to its allowed field. A baseline '
        'failure alone is never a defect in the plan. Baseline claims are untrusted '
        'until independently reproduced, regardless of the stated baseline_basis. '
        'Do not infer execution, success or authority. If a quote comes from a staged '
        'field, include its exact labelled line as rendered in reproduction. '
        +req['messages'][0]['content'].replace(old,encoded(schema)))
    focused=json.loads(req['messages'][1]['content']);focused['reproduction_stages']=deepcopy(value)
    req['messages'][1]['content']=encoded(focused)
    return req


def _normalized(value,context):
    staged=_stages(context);need(type(value) is dict,'staged_review_shape')
    normal=deepcopy(value);rows=normal.get('defects')
    need(type(rows) is list,'staged_review_defects')
    notes={n['task_id']:n for n in context['planning_notes']}
    for row in rows:
        need(type(row) is dict and set(row)==v5.DEFECT_FIELDS|{'claim_kind'},'staged_review_defect_fields')
        kind=row.pop('claim_kind');field=row.get('plan_field');ident=row.get('task_id')
        need(type(kind) is str and kind in ALLOWED and type(field) is str and field in ALLOWED[kind],
             'staged_review_claim_stage')
        need(type(ident) is str and ident in notes,'staged_review_task')
        quote=row.get('plan_quote');_text(quote,160)
        if field in ('approach','risks'):source=notes[ident][field]
        else:
            source=stages.LABELS[field]+': '+staged[ident][field]
            row['plan_field']='reproduction'
        need(len(quote.strip())>=8 and quote in source,'staged_review_quote_outside_stage')
    v5.decode(encoded(normal),context)
    return normal


def decode(raw,context):
    value=decode_selection(raw);_normalized(value,context);return value


def receipt(context,verdict):
    return v5.receipt(context,_normalized(verdict,context))
