"""Opt-in source-grounded review, retaining every v6 semantic/evidence gate.

Remove exact duplicated requirements only, retaining covers -> numbered text.
Source is independently hash-bound to the parent's registered files. Review is
still a model judgment, never execution or acceptance evidence.
"""
import json
from . import coding_plan_compact_review as v7
from .cognitive_state import encoded,need
from ..coding_source_context import attach
OUTPUT_TOKENS=v7.OUTPUT_TOKENS
PROTOCOL='atlas_plan_critic_v8_grounded'

def request(context,repository_sources=None):
    if repository_sources is None:repository_sources=context.get("repository_sources")
    req=v7.request(context);view=json.loads(req['messages'][1]['content'])
    for task in view['tasks']:
        expected=[view['requirements'][i-1] for i in task['covers']]
        # If any constraint differs, keep the full packet. No silent loss.
        if task['requirements']==expected:
            task.pop('requirements')
            task['requirements_from']='numbered requirements selected by covers'
    req['messages'][1]['content']=encoded(view)
    req['messages'][0]['content']=(
        'Judge behavioral compliance, not how polished or detailed the plan sounds. '
        'Trace proposed control flow against each requirement, including any early return. '
        'A specific approach may still violate a requirement. A risk merely being named '
        'does not cure a contradictory implementation. Task covers indexes the exact '
        'numbered requirements; duplicated text is omitted only when identical. '
        +req['messages'][0]['content'])
    # The model must emit its evidence/assessment before its final verdict.
    # This reorders the same strict schema; it changes no field or acceptance rule.
    schema=req['response_format']['json_schema']['schema']
    properties=schema['properties']
    order=['context_sha256','task_checks','coverage','defects','findings','passed']
    need(set(order)==set(properties),'grounded_review_schema_fields')
    schema['properties']={key:properties[key] for key in order}
    req['messages'][0]['content']=(
        'Work through task evidence, requirement coverage and concrete defects before '
        'the final passed verdict. For each requirement, compare the proposed approach '
        'with the required result; do not infer compliance from intent. Use short literal '
        'contiguous evidence excerpts copied without inserted whitespace or line breaks. '
        +req['messages'][0]['content'])
    req['response_format']['json_schema']['name']=PROTOCOL
    return attach(req,repository_sources,context['plan']['parent']['resources'])

def decode(raw,context):return v7.decode(raw,context)
def receipt(context,verdict):return v7.receipt(context,verdict)
