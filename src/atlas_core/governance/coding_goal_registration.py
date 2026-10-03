"""Explicit proposal-to-registered-execution association; never an authority grant.

The independently prepared Gym remains the execution boundary. Preserve both
packets, allow only descriptive goal/ID changes and lossless contract partition,
and recheck this association during recovery. No model or shell entry point.
"""
from copy import deepcopy
from .cognitive_state import digest, need
from .task_contract import validate, fingerprint, _utc
from .coding_goal import compile_plan
from atlas_core.coding_gym import read, save

TYPE = 'goal_registered_gym_dispatch'


def associate(plan, task_id, registered):
    need(plan == compile_plan(plan['parent'], plan['children']), 'registration_plan')
    child = next((c for c in plan['children'] if c['packet']['task_id'] == task_id), None)
    need(child is not None, 'registration_unknown_task')
    proposal = validate(child['packet']); registered = validate(registered)
    need(registered['task_id'].startswith('coding-')
         and registered['task_id'] != task_id
         and registered['task_id'] not in {c['packet']['task_id'] for c in plan['children']},
         'registration_distinct_identity')
    for field in ('editable_file', 'source_sha256', 'foundation_sha256'):
        need(registered[field] == proposal[field], 'registration_scope_changed')
    need(proposal['max_requests'] == registered['max_requests'] == 1,
         'registration_single_attempt')
    need(_utc(registered['deadline_utc']) <= _utc(proposal['deadline_utc']),
         'registration_deadline_expanded')
    # A registered contract may be partitioned to fit existing packet limits.
    # No whitespace folding, paraphrase, reordering or lost constraint is allowed.
    contract = '\n'.join(proposal['requirements'])
    need(registered['requirements'] == proposal['requirements']
         or ''.join(registered['requirements']) == contract,
         'registration_contract_changed')
    need(sum(c['packet']['max_requests'] + 1 for c in plan['children'])
         <= plan['parent']['max_requests'], 'registration_aggregate_budget')
    children = deepcopy(plan['children'])
    for c in children:
        if c['packet']['task_id'] == task_id:
            c['packet'] = registered
        c['depends_on'] = [registered['task_id'] if dep == task_id else dep for dep in c['depends_on']]
    translated = compile_plan(plan['parent'], children)
    return dict(schema=1, proposal_task_id=task_id, proposal_packet=proposal,
                registered_packet=registered, original_plan_sha256=digest(plan),
                execution_plan_sha256=digest(translated), contract_sha256=digest(contract),
                authority_sha256=plan['parent']['authority_sha256'],
                acceptance_sha256=plan['parent']['acceptance_sha256'],
                execution_authority=False), translated


def binding_path(goal, task_id):
    return 'REGISTRATION-' + digest(task_id) + '.json'


def validate_record(goal, record):
    need(type(record) is dict and set(record) == {
        'type','task_id','plan_sha256','task_fingerprint','mapping_sha256','registered_dispatch'},
        'registration_record_fields')
    task_id = record['task_id']
    mapping = read(goal.root, binding_path(goal, task_id))
    expected, translated = associate(goal.plan, task_id, mapping['registered_packet'])
    need(mapping == expected and digest(mapping) == record['mapping_sha256']
         and record['type'] == TYPE and record['plan_sha256'] == goal.fp
         and record['task_fingerprint'] == fingerprint(mapping['proposal_packet']),
         'registration_mapping_changed')
    nested = record['registered_dispatch']
    need(nested['type'] == 'goal_gym_dispatch'
         and nested['task_id'] == mapping['registered_packet']['task_id']
         and nested['task_fingerprint'] == fingerprint(mapping['registered_packet'])
         and nested['plan_sha256'] == digest(translated)
         and nested['proposal_task_id'] == task_id and nested['reserved_calls'] == 2
         and nested['execution_authority'] is False, 'registration_dispatch_changed')
    return mapping, translated


def recover(goal, record):
    from .coding_goal_gym import recover_child_gym
    # Association failure is a hard evidence error, never an unstarted task.
    mapping, translated = validate_record(goal, record)
    result = recover_child_gym(record['registered_dispatch'], mapping['registered_packet'],
                               goal.journal, digest(translated), proposal_task_id=record['task_id'])
    return dict(result, proposal_task_id=record['task_id'],
                execution_task_id=mapping['registered_packet']['task_id'],
                registration_sha256=digest(mapping), execution_authority=False)


def execute(goal, task_id, gym, *, critique):
    from .coding_goal_gym import bind_child_gym
    from . import coding_goal_dialogue as dialogue
    from atlas_core.coding_engine_gym import EngineCodingGym
    from atlas_core.coding_execution import RegisteredCodingExecution
    goal._validate()
    need(goal._decomposition is not None and task_id in goal.reconcile()['ready'],
         'goal_child_not_ready')
    need(type(gym) is EngineCodingGym and type(gym.execution) is RegisteredCodingExecution,
         'goal_registered_gym_required')
    mapping, translated = associate(goal.plan, task_id, gym.execution.packet)
    nested = bind_child_gym(gym, mapping['registered_packet'], goal.journal,
                             translated, digest(translated))
    nested['proposal_task_id'] = task_id
    with dialogue.mutation_guard(goal):
        need(task_id in goal.reconcile()['ready'], 'goal_child_not_ready')
        # The original proposal ID remains in clarification context. Delivery is
        # independently checked against the registered counted manager prompt.
        delivery = dialogue.validate_gym_delivery(goal, task_id, gym)
        if delivery is not None:
            nested['clarification_delivery'] = delivery
        name = binding_path(goal, task_id)
        if (goal.root / name).exists():
            need(read(goal.root, name) == mapping, 'registration_orphan_conflict')
        else:
            save(goal.root, name, mapping)
        goal.require_gym()
        record = dict(type=TYPE, task_id=task_id, plan_sha256=goal.fp,
                      task_fingerprint=fingerprint(mapping['proposal_packet']),
                      mapping_sha256=digest(mapping), registered_dispatch=nested)
        validate_record(goal, record)
        # Persist before execution. An interrupted call can only be recovered,
        # never re-entered under another alias or reconstructed as a new attempt.
        need(goal._emit('action', record, event_id='goal-gym-dispatch:'+task_id) is True,
             'goal_gym_already_reserved')
    result = gym.run(critique=critique)
    goal._validate()
    goal._emit('reflection', dict(type='goal_child_gym_outcome', task_id=task_id,
               plan_sha256=goal.fp, receipt_sha256=digest(result), execution_authority=False))
    return goal.reconcile()
