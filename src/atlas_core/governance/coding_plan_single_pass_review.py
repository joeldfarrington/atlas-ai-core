"""Explicit single-pass plan review; strict local acceptance remains unchanged.

Schema is counted as prompt context. No provider response_format is sent, avoiding
Ollama 0.34.3 thinking/structured-output restart. This is not a physical token cap.
"""
import json
from . import coding_plan_reference_strict_review as v10
PROTOCOL='atlas_plan_critic_v11_single_pass'
OUTPUT_TOKENS=v10.OUTPUT_TOKENS

def request(context,repository_sources=None):
    req=v10.request(context,repository_sources)
    schema=req['response_format']['json_schema']['schema']
    req['messages'][0]['content']+=' Required output JSON schema: '+json.dumps(schema,separators=(',',':'),ensure_ascii=False,allow_nan=False)
    req['response_format']=None
    return req

def decode(raw,context):return v10.decode(raw,context)
def expand(value,context):return v10.expand(value,context)
def receipt(context,verdict):return v10.receipt(context,verdict)
def expansion_receipt(raw,context):
    result=v10.expansion_receipt(raw,context);result['protocol']=PROTOCOL;return result
