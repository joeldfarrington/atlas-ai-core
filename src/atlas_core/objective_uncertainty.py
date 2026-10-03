"""Trusted closure of stopped execution, without resolving coding uncertainty.

Only independent owner adapters may call this after their existing custody,
restoration and artifact checks. Schema validation never substitutes for those
checks. No model-facing endpoint or authority grant is provided.
"""
import json


def settled_unknown(proof,cleanup):
    from atlas_core.objective_requests import require
    require(type(proof) is dict and set(proof)=={'independent','accepted','tests_run','scope','execution_authority'}
        and proof['independent'] is True and proof['accepted'] is False
        and proof['execution_authority'] is False and proof['scope']=='one_registered_child'
        and type(proof['tests_run']) is int and 0<=proof['tests_run']<=10000,'unknown_independent_proof')
    require(type(cleanup) is dict and set(cleanup)=={'owned_processes_absent','model_requests_active',
        'requests_used','model_requests_settled','execution_authority','automatic_retry'}
        and cleanup['owned_processes_absent'] is True and cleanup['model_requests_settled'] is True
        and cleanup['execution_authority'] is False and cleanup['automatic_retry'] is False
        and type(cleanup['model_requests_active']) is int and cleanup['model_requests_active']==0
        and type(cleanup['requests_used']) is int and 1<=cleanup['requests_used']<=6,'unknown_cleanup_unverified')
    return dict(schema=1,kind='independently_stopped_unknown',cleanup=dict(cleanup),
        coding_outcome='OUTCOME_UNKNOWN',coding_success=False,replay_allowed=False,execution_authority=False)


def validate_unknown(c,p,value):
    from atlas_core.objective_requests import require
    require(type(value) is dict and set(value)=={'kind','request_sha256','selection_sha256','goal_state',
        'proof','publication','settlement','execution_authority'} and value['kind']=='unconfirmed_settled'
        and value['goal_state']=='OUTCOME_UNKNOWN' and value['execution_authority'] is False,'unknown_result_contract')
    settlement=value['settlement']
    require(type(settlement) is dict and type(settlement.get('schema')) is int
        and settlement.get('coding_success') is False and settlement.get('replay_allowed') is False
        and settlement.get('execution_authority') is False
        and settlement==settled_unknown(value['proof'],settlement.get('cleanup')),'unknown_settlement_contract')
    pub=value['publication']
    require(type(pub) is dict and set(pub)=={'goal_state','message_ids','binding_sha256','execution_authority','starts_work'}
        and pub['goal_state']=='OUTCOME_UNKNOWN' and pub['execution_authority'] is False
        and pub['starts_work'] is False,'unknown_publication_contract')
    from atlas_core.governance.action_boundary import sha
    require(sha(pub['binding_sha256']),'unknown_publication_binding')
    ids=pub['message_ids'];require(type(ids) is list and len(ids)==1 and type(ids[0]) is str,'unknown_message_required')
    message=c.execute('SELECT * FROM messages WHERE id=?',(ids[0],)).fetchone()
    require(message is not None and message['conversation_id']==p['conversation_id'] and message['role']=='assistant','unknown_publication_target')
    metadata=json.loads(message['metadata_json'])
    require(metadata.get('origin')=='trusted_local_followup' and metadata.get('kind')=='result'
        and metadata.get('source_run_id')==p['run_id'] and metadata.get('project_slug')==p['project']
        and metadata.get('execution_authority') is False,'unknown_publication_provenance')
