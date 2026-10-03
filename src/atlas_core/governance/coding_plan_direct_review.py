"""Exact non-thinking structured review, with unchanged independent decoder.

A registered thinking=False counter is selected by the trusted host. Ollama's
immediate constrained route avoids the thinking-to-structured restart. Output
and accounting remain bounded and independently checked; no fallback is added.
"""
from . import coding_plan_reference_strict_review as v10
from . import coding_plan_reference_review as v9
from .coding_plan_staged_review import ALLOWED
from copy import deepcopy
PROTOCOL='atlas_plan_critic_v12_direct'
OUTPUT_TOKENS=v10.OUTPUT_TOKENS

def request(context,repository_sources=None):
    req=v10.request(context,repository_sources)
    req['response_format']['json_schema']['name']=PROTOCOL
    defects=req['response_format']['json_schema']['schema']['properties']['defects']
    base=defects['items'];cat=v9.catalog(context);variants=[]
    for kind,fields in ALLOWED.items():
        branch=deepcopy(base)
        branch['properties']['claim_kind']=dict(type='string',enum=[kind])
        branch['properties']['plan_ref']=dict(type='string',enum=[k for k,v in cat.items() if v.get('field') in fields])
        variants.append(branch)
    defects['items']=dict(anyOf=variants)
    # One concrete counterexample suffices to reject a plan. This constrains
    # generation only; the independent v6 decoder's guarantees are unchanged.
    defects['maxItems']=1
    req['messages'][0]['content']+=' For a negative verdict, report only the strongest directly supported counterexample. Do not add speculative allegations. A sound plan still requires checking every task and requirement.'
    return req

def decode(raw,context):return v10.decode(raw,context)
def expand(value,context):return v10.expand(value,context)
def receipt(context,verdict):return v10.receipt(context,verdict)
def expansion_receipt(raw,context):
    result=v10.expansion_receipt(raw,context);result['protocol']=PROTOCOL;return result
