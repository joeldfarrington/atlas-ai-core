"""Opt-in v7 request compaction; all v6 verdict checks remain authoritative.

Send the exact schema as response_format once, retaining full untrusted context.
This only reserves response space; it never repairs or accepts a model reply.
"""
from . import coding_plan_staged_review as v6
from .cognitive_state import encoded,need

OUTPUT_TOKENS = 1536
PROTOCOL = 'atlas_plan_critic_v7_compact'

def request(context):
    req=v6.request(context)
    schema=req['response_format']['json_schema']['schema']
    marker='Return only JSON matching: '+encoded(schema)
    system=req['messages'][0]['content']
    need(system.count(marker)==1,'compact_review_schema_binding')
    req['messages'][0]['content']=system.replace(marker,
        'Return only JSON following the supplied response schema. Include context_sha256, '
        'task_checks for every task with literal evidence and three assessments, '
        'coverage for every requirement, defects, findings and passed. Keep reasons '
        'concise. A negative finding requires a distinct expected and predicted '
        'result and exact source quotes; an empty defects list is valid for a sound '
        'plan. Never omit a required check to shorten the answer.')
    req['response_format']['json_schema']['name']=PROTOCOL
    return req

def decode(raw,context):
    return v6.decode(raw,context)

def receipt(context,verdict):
    return v6.receipt(context,verdict)
