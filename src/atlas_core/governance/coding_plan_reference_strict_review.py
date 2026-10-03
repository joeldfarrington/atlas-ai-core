"""v10 strengthens generation constraints; every v9/v6 acceptance gate retained."""
from . import coding_plan_reference_review as v9
from .cognitive_state import need
PROTOCOL='atlas_plan_critic_v10_reference_schema'
OUTPUT_TOKENS=v9.OUTPUT_TOKENS

def request(context,repository_sources=None):
    req=v9.request(context,repository_sources);cat=v9.catalog(context)
    schema=req['response_format']['json_schema']['schema'];p=schema['properties']
    count=len(context['plan']['parent']['requirements'])
    p['coverage'].update(minItems=count,maxItems=count)
    p['coverage']['items']['properties']['requirement']=dict(type='integer',enum=list(range(1,count+1)))
    d=p['defects']['items']['properties']
    d['requirement']=dict(type='integer',enum=list(range(1,count+1)))
    d['required_ref']=dict(type='string',enum=[k for k,v in cat.items() if 'requirement' in v])
    d['plan_ref']=dict(type='string',enum=[k for k,v in cat.items() if 'task_id' in v and v['field']!='reproduction'])
    p['task_checks']['items']['properties']['evidence']['items']=dict(type='string',enum=[k for k,v in cat.items() if v.get('field') in v9.FIELDS])
    req['response_format']['json_schema']['name']=PROTOCOL
    req['messages'][0]['content']+=(' Requirement numbers refer to whole numbered requirements, '
        'not excerpt numbers: R1.8 is excerpt 8 of requirement 1. Coverage has exactly '
        'one entry per numbered requirement, never one per excerpt. Evidence references '
        'must come from the task reproduction, approach, risks fields in that order. '
        'A possible risk or an omitted repetition of an existing constraint is not '
        'a demonstrated implementation contradiction; identify actual conflicting behavior.')
    return req

def decode(raw,context):return v9.decode(raw,context)
def expand(value,context):return v9.expand(value,context)
def receipt(context,verdict):return v9.receipt(context,verdict)
def expansion_receipt(raw,context):
    result=v9.expansion_receipt(raw,context);result['protocol']=PROTOCOL;return result
