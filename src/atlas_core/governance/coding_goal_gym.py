"""Bind goals to retained registered Gym execution and read-only recovery.

Trusted host composition only. No public path selector, provider construction,
new policy, source edit or automatic replay. The existing backend owns prompt
counting and shared Builder/Reviewer admission; the parent does not inject an
uncounted prompt. Planning quality and actual model efficacy remain separate.
"""
from pathlib import Path
from atlas_core.coding_gym import read
from atlas_core.practice.workspace import regular,sha
from .action_boundary import private_identity
from .cognitive_state import need,digest
from .coding_workflow import recover_task
from .task_contract import fingerprint


def bind_child_gym(gym,packet,journal,plan,plan_sha256):
    from atlas_core.coding_engine_gym import EngineCodingGym
    from atlas_core.coding_execution import RegisteredCodingExecution
    from .coding_goal import context_packet
    need(type(gym) is EngineCodingGym and type(gym.execution) is RegisteredCodingExecution,
         'goal_registered_gym_required')
    execution=gym.execution
    need(execution.packet==packet and execution.journal is journal
         and execution.loop.project==plan['parent']['project'],'goal_registered_gym_scope')
    gym.validate(execution)
    need(not gym._used and not (gym.root/'RESULT.json').exists(),'goal_gym_already_used')
    context=context_packet(plan,packet['task_id'],gym.base)
    # Registered Builder allows one request; the bound local reviewer permits
    # one request. Reserve both in the parent cap before entry, conservatively.
    required=sum(c['packet']['max_requests']+1 for c in plan['children'])
    need(required<=plan['parent']['max_requests'],'goal_gym_aggregate_budget')
    need(packet['max_requests']==1,'goal_registered_single_attempt')
    session=execution.session
    return {'type':'goal_gym_dispatch','task_id':packet['task_id'],
            'plan_sha256':plan_sha256,'task_fingerprint':fingerprint(packet),
            'gym_root':str(gym.root),'gym_identity':list(private_identity(gym.root,True)),
            'intent_sha256':sha(regular(gym.root/'INTENT.json')),
            'session_root':str(session.root),'session_identity':list(private_identity(session.root,True)),
            'spec_sha256':sha(regular(session.root/'SPEC.json')),
            'context_sha256':digest(context),'context_delivery':'existing_registered_backend_counted_context',
            'parent_context_injected':False,'reserved_calls':2,
            'execution_authority':False}


def _registered(record,packet,journal,*,proposal_task_id=None):
    from atlas_core.coding_connection import load_session
    from atlas_core.coding_execution import recover_registered_execution
    cs=load_session();root=Path(record['session_root'])
    need(list(private_identity(root,True))==record['session_identity'],'goal_session_replaced')
    raw=regular(root/'SPEC.json');need(sha(raw)==record['spec_sha256'],'goal_session_spec_changed')
    session=cs.Session(cs.decode(raw))
    need(session.root==root,'goal_session_path_changed')
    result=recover_registered_execution(session,packet,journal)
    if 'clarification_delivery' in record and result['state'] in ('accepted','failed'):
        delivery=record['clarification_delivery'];intent=session._read('WORKER_INTENT.json')
        need(delivery['task_id']==(packet['task_id'] if proposal_task_id is None else proposal_task_id)
             and delivery['registered_task_id']==session.spec['task']['id']
             and delivery['selection_sha256']==intent['selected_context_sha256']
             and delivery['execution_authority'] is False,'goal_clarification_delivery_changed')
    return result


def recover_child_gym(record,packet,journal,plan_sha256,*,proposal_task_id=None):
    """Recheck both actual Session receipt and full Gym evidence, without writes."""
    from atlas_core.coding_engine_gym import recover_engine_gym
    base=recover_task(packet,journal)
    unknown=dict(base,state='outcome_unconfirmed',gym_outcome='outcome_unconfirmed')
    try:
        need(record['plan_sha256']==plan_sha256 and record['task_id']==packet['task_id']
             and record['task_fingerprint']==fingerprint(packet),'goal_gym_identity')
        root=Path(record['gym_root'])
        need(list(private_identity(root,True))==record['gym_identity'],'goal_gym_replaced')
        need(sha(regular(root/'INTENT.json'))==record['intent_sha256'],'goal_gym_intent_changed')
        intent=read(root,'INTENT.json')
        need(intent['task_id']==packet['task_id'] and intent['task_fingerprint']==fingerprint(packet)
             and intent['source_sha256']==packet['source_sha256']
             and intent['deadline_utc']==packet['deadline_utc'],'goal_gym_task_changed')
        gym=recover_engine_gym(root)
        if gym['outcome']=='outcome_unconfirmed':return unknown
        registered=_registered(record,packet,journal,proposal_task_id=proposal_task_id)
        if gym['outcome']=='not_reproduced':
            # No worker is expected when fixed reproduction did not fail.
            need(registered['state']=='not_started','goal_gym_reproduction_conflict')
            state='failed'
        else:
            need(registered['state'] in ('accepted','failed'),'goal_registered_outcome_unknown')
            engine=read(root,'ENGINE.json')['result']
            need(engine==registered,'goal_gym_registered_result_changed')
            need(gym['outcome'] in ('accepted','not_accepted'),'goal_gym_outcome')
            need(gym['outcome']!='accepted' or registered['state']=='accepted','goal_gym_false_success')
            state='accepted' if gym['outcome']=='accepted' else 'failed'
        return dict(registered,state=state,gym_outcome=gym['outcome'],gym_result_sha256=digest(gym),
                    strategy_sha256=sha(regular(root/'STRATEGY.json')),execution_authority=False)
    except (ValueError,OSError,KeyError,TypeError):
        return unknown
