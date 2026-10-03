"""Stop-only outcome projection after independent owner-window verification.

The prepared goal is retained as READY history. Its request is cancelled; this
record does not claim coding ran or manufacture a completed goal/authority.
"""
import json
from atlas_core.governance.cognitive_state import digest,need
from atlas_core.conversation_followup import publish_followup

PROOF=dict(independent=True,accepted=False,tests_run=0,scope='cancelled_before_coding',
           planning_settled=True,coding_dispatched=False,execution_authority=False)


def cancelled_state(proof):
    """Validate the outcome shape; the independent owner verifies its evidence."""
    if type(proof) is dict and digest(proof)==digest(PROOF):return 'READY'
    from atlas_core.objective_requests import require
    require(type(proof) is dict and set(proof)=={'independent','accepted','tests_run','scope',
        'stage','saved_goal_state','original_scope','model_requests','model_requests_settled','execution_authority'}
        and proof['scope']=='cancelled_settled' and proof['independent'] is True
        and proof['accepted'] is False and proof['model_requests_settled'] is True
        and proof['execution_authority'] is False
        and type(proof['model_requests']) is int and 1<=proof['model_requests']<=6
        and all(type(proof[k]) is str for k in ('stage','saved_goal_state','original_scope'))
        and type(proof['tests_run']) is int and 0<=proof['tests_run']<=10000,
        'cancel_settled_proof')
    allowed={('planning','NOT_CREATED','planning_only'),
             ('waiting','WAITING_FOR_HUMAN','planning_only'),
             ('coding','OUTCOME_UNKNOWN','one_registered_child'),
             ('coding','FAILED','one_registered_child'),
             ('coding','OUTCOME_UNKNOWN','two_registered_children'),
             ('coding','FAILED','two_registered_children')}
    require((proof['stage'],proof['saved_goal_state'],proof['original_scope']) in allowed
        and (proof['stage']=='coding' or (proof['tests_run']==0 and proof['model_requests']==1)),
        'cancel_settled_state')
    return proof['saved_goal_state']


def publish_cancelled(database,request,*,selection_sha256,proof):
    from atlas_core.objective_requests import ObjectiveRequests
    need(type(request) is dict and request==ObjectiveRequests(database).get(request['request_id'])
         and (request['state']=='cancel_requested' or (request['state']=='resolved'
              and request['result'].get('kind') in ('cancelled_before_coding','cancelled_settled'))),'cancel_saved_request_required')
    saved_state=cancelled_state(proof)
    content=('I cancelled this objective after planning and before coding began. '
        'No coding worker was started. The saved plan remains available as history, '
        'and the service has recovered. Nothing will be retried automatically.')
    if proof['scope']=='cancelled_settled':
        detail={'planning':'The active planning request finished, but its output was withheld. No coding task was started.',
            'coding':'The active model request finished, but its output was withheld. The coding result remains '+saved_state.lower().replace('_',' ')+'. No further coding work was started.',
            'waiting':'The objective was waiting for your clarification. No coding task was started.'}[proof['stage']]
        content='I cancelled this objective. '+detail+' The service has recovered. Saved history is preserved, and nothing will be retried automatically.'
    message=publish_followup(database,conversation_id=request['conversation_id'],
        run_id=request['run_id'],project_slug=request['project'],
        event_id='objective-cancel:'+digest(dict(request_id=request['request_id'],
            request_sha256=request['request_sha256'],selection_sha256=selection_sha256)),
        kind='result',content=content,
        evidence=['sha256:'+request['request_sha256'],'sha256:'+selection_sha256,'sha256:'+digest(proof)])
    return dict(goal_state='CANCELLED',saved_goal_state=saved_state,message_ids=[message['id']],
                execution_authority=False,starts_work=False)


def cancellation_result(*,request_sha256,selection_sha256,proof,publication):
    saved_state=cancelled_state(proof)
    return dict(kind='cancelled_before_coding' if proof['scope']=='cancelled_before_coding' else 'cancelled_settled',request_sha256=request_sha256,
        selection_sha256=selection_sha256,outcome='CANCELLED',saved_goal_state=saved_state,
        proof=proof,publication=publication,execution_authority=False)


def validate_cancelled(c,p,value):
    # Persisted-data refusals use the same typed error handled by the API.
    from atlas_core.objective_requests import require as need
    need(type(value) is dict and set(value)=={'kind','request_sha256','selection_sha256','outcome',
        'saved_goal_state','proof','publication','execution_authority'}
        and value['kind'] in ('cancelled_before_coding','cancelled_settled') and value['outcome']=='CANCELLED'
        and value['execution_authority'] is False and type(value['proof']) is dict,'cancel_result_contract')
    if value['kind']=='cancelled_before_coding':need(digest(value['proof'])==digest(PROOF),'cancel_result_contract')
    saved_state=cancelled_state(value['proof'])
    need(value['saved_goal_state']==saved_state and value['kind']==('cancelled_before_coding' if value['proof']['scope']=='cancelled_before_coding' else 'cancelled_settled'),'cancel_result_contract')
    pub=value['publication']
    need(type(pub) is dict and set(pub)=={'goal_state','saved_goal_state','message_ids','execution_authority','starts_work'}
         and pub['goal_state']=='CANCELLED' and pub['saved_goal_state']==saved_state
         and pub['execution_authority'] is False and pub['starts_work'] is False,'cancel_publication_contract')
    ids=pub['message_ids'];need(type(ids) is list and len(ids)==1 and type(ids[0]) is str,'cancel_message_required')
    message=c.execute('SELECT * FROM messages WHERE id=?',(ids[0],)).fetchone()
    need(message is not None and message['conversation_id']==p['conversation_id'] and message['role']=='assistant',
         'cancel_publication_target')
    metadata=json.loads(message['metadata_json'])
    need(metadata.get('origin')=='trusted_local_followup' and metadata.get('kind')=='result'
         and metadata.get('source_run_id')==p['run_id'] and metadata.get('project_slug')==p['project']
         and metadata.get('execution_authority') is False,'cancel_publication_provenance')
