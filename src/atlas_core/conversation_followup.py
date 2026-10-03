"""Durable same-conversation follow-ups from explicitly selected trusted hosts.

Uses the existing message schema and read routes. No model invocation, tool,
public write endpoint, notification, run resumption or permission creation.
The host supplies content/provenance; persistence does not verify its truth.
"""
import hashlib
import json
import re
import uuid
from atlas_core.governance.cognitive_state import digest, need
from atlas_core.governance.task_contract import _text
from atlas_core.memory.database import Database, canonical_json, utc_now

TERMINAL = ('completed', 'failed', 'stopped', 'cancelled', 'interrupted', 'rolled_back')


def publish_followup(database, *, conversation_id, run_id, project_slug,
                     event_id, kind, content, evidence, recover_only=False):
    """Append once, or recover the identical event after a lost return.

    Caller must be a trusted local producer. This is not proof of human consent
    or a path for model-controlled tools. New messages cannot interrupt an
    active conversation operation or rewrite the original response/run.
    """
    need(type(database) is Database, 'followup_database')
    need(type(recover_only) is bool, 'followup_recovery_mode')
    for value in (conversation_id, run_id, event_id): _text(value, 128)
    need(project_slug is None or type(project_slug) is str and
         re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,79}', project_slug), 'followup_project')
    need(type(kind) is str and kind in ('correction', 'clarification', 'result'), 'followup_kind')
    _text(content, 4000)
    need(len(content.encode('utf-8')) <= 12000, 'followup_content_size')
    need(type(evidence) is list and 1 <= len(evidence) <= 12 and
         all(type(x) is str and re.fullmatch(r'sha256:[0-9a-f]{64}', x) for x in evidence)
         and len(set(evidence)) == len(evidence), 'followup_evidence')
    external = 'atlas.followup:' + hashlib.sha256(event_id.encode()).hexdigest()
    metadata = {'schema': 1, 'origin': 'trusted_local_followup', 'event_id': event_id,
                'kind': kind, 'source_run_id': run_id, 'project_slug': project_slug,
                'evidence': list(evidence), 'content_verification': 'not_attested_by_delivery',
                'execution_authority': False, 'starts_work': False,
                'external_notification_sent': False}
    encoded = canonical_json(metadata)
    with database.session() as connection:
        connection.execute('BEGIN IMMEDIATE')
        conversation = connection.execute('SELECT * FROM conversations WHERE id=?', (conversation_id,)).fetchone()
        run = connection.execute('SELECT * FROM runs WHERE id=?', (run_id,)).fetchone()
        need(conversation is not None and run is not None and run['conversation_id'] == conversation_id
             and run['project_slug'] == conversation['project_slug'] == project_slug
             and run['agent_slug'] == conversation['agent_slug'] == 'atlas', 'followup_scope')
        existing = connection.execute('SELECT * FROM messages WHERE external_id=?', (external,)).fetchall()
        if existing:
            need(len(existing) == 1 and existing[0]['conversation_id'] == conversation_id
                 and existing[0]['role'] == 'assistant' and existing[0]['content'] == content
                 and existing[0]['metadata_json'] == encoded and existing[0]['provider'] is None
                 and existing[0]['model'] is None, 'followup_identity_conflict')
            return database._row(existing[0])
        need(not recover_only, 'followup_not_previously_published')
        need(not conversation['archived'], 'followup_archived')
        need(run['status'] in TERMINAL and run['pending_approval_id'] is None, 'followup_reconcile_first')
        need(not database._unresolved_chat_work(connection, conversation_id), 'followup_reconcile_first')
        # This is a saved local message, not completion of another operation.
        # Preserve chronological ordering even if the wall clock moved back.
        latest = connection.execute('SELECT MAX(created_at) AS stamp FROM messages WHERE conversation_id=?',
                                    (conversation_id,)).fetchone()['stamp']
        now = max(utc_now(), conversation['updated_at'], latest or '')
        message_id = str(uuid.uuid4())
        connection.execute("INSERT INTO messages(id,conversation_id,role,content,provider,model,metadata_json,external_id,created_at) VALUES(?,?,'assistant',?,NULL,NULL,?,?,?)",
                           (message_id, conversation_id, content, encoded, external, now))
        connection.execute('UPDATE conversations SET updated_at=? WHERE id=?', (now, conversation_id))
        row = connection.execute('SELECT * FROM messages WHERE id=?', (message_id,)).fetchone()
    return database._row(row)


def publish_goal_question(goal, database, *, conversation_id, run_id, question_id):
    """Project one saved pending clarification into its explicitly bound chat.

    No inference of a conversation from titles, recent messages or model text.
    The trusted orchestrator supplies the run/conversation association and the
    database enforces the same project. Reading does not answer or resume it.
    """
    from atlas_core.governance.coding_goal import BoundedCodingGoal
    from atlas_core.governance.coding_goal_dialogue import mutation_guard
    need(type(goal) is BoundedCodingGoal, 'followup_goal')
    # Serialize publication with answering: a delayed producer cannot create a
    # stale question after another host has already resolved it.
    with mutation_guard(goal):
        return _publish_goal_question(goal, database, conversation_id, run_id, question_id)


def _publish_goal_question(goal, database, conversation_id, run_id, question_id):
    state = goal.reconcile()
    question = next((q for q in state['clarification']['questions'] if q['question_id'] == question_id), None)
    need(question is not None, 'followup_unknown_question')
    return publish_followup(database, conversation_id=conversation_id, run_id=run_id,
        project_slug=goal.plan['parent']['project'],
        event_id='goal-question:' + digest({'plan': goal.fp, 'question': question_id}),
        kind='clarification', content=question['question'] + '\n\n' + question['reason'],
        evidence=['sha256:' + goal.fp, 'sha256:' + digest(question)],
        recover_only=not (state['state']=='WAITING_FOR_HUMAN' and question in state['clarification']['pending']))


def record_goal_answer(goal, database, *, conversation_id, run_id, question_id,
                       message_id, disposition='implementation_guidance'):
    """Bind an explicitly selected saved user reply to the original question.

    Called by the trusted ingress/orchestrator, never inferred from model prose.
    The saved role is provenance, not an independent authentication proof.
    Scope-changing answers still cannot alter the goal's plan or permissions.
    """
    from atlas_core.governance.coding_goal import BoundedCodingGoal
    need(type(goal) is BoundedCodingGoal and type(database) is Database, 'followup_goal')
    state = goal.reconcile()
    question = next((q for q in state['clarification']['questions'] if q['question_id'] == question_id), None)
    need(question is not None, 'followup_unknown_question')
    event_id = 'goal-question:' + digest({'plan': goal.fp, 'question': question_id})
    external = 'atlas.followup:' + hashlib.sha256(event_id.encode()).hexdigest()
    with database.session() as connection:
        connection.execute('BEGIN IMMEDIATE')
        conversation = connection.execute('SELECT * FROM conversations WHERE id=?', (conversation_id,)).fetchone()
        run = connection.execute('SELECT * FROM runs WHERE id=?', (run_id,)).fetchone()
        published = connection.execute('SELECT rowid AS sequence,* FROM messages WHERE external_id=?', (external,)).fetchall()
        reply = connection.execute('SELECT rowid AS sequence,* FROM messages WHERE id=?', (message_id,)).fetchone()
        need(conversation is not None and run is not None and not conversation['archived']
             and run['conversation_id'] == conversation_id
             and run['agent_slug'] == conversation['agent_slug'] == 'atlas'
             and run['project_slug'] == conversation['project_slug'] == goal.plan['parent']['project'],
             'followup_scope')
        need(len(published) == 1 and published[0]['conversation_id'] == conversation_id
             and published[0]['role'] == 'assistant'
             and published[0]['content'] == question['question'] + '\n\n' + question['reason'],
             'followup_question_binding')
        metadata = json.loads(published[0]['metadata_json'])
        need(metadata.get('source_run_id') == run_id and metadata.get('kind') == 'clarification'
             and metadata.get('evidence') == ['sha256:' + goal.fp, 'sha256:' + digest(question)],
             'followup_question_binding')
        need(reply is not None and reply['conversation_id'] == conversation_id
             and reply['role'] == 'user' and reply['external_id'] is None
             and reply['sequence'] > published[0]['sequence'], 'followup_user_reply')
        return goal.answer_clarification(question_id, reply['content'], disposition=disposition,
            source_reference='conversation:' + conversation_id + ':message:' + message_id)


def publish_goal_result(goal, database, *, conversation_id, run_id):
    """Publish a recovered goal outcome, with no model-authored success claim.

    The trusted host binds the goal to its conversation/run. Reconciliation
    independently reloads child, review and verifier evidence before delivery.
    Repeated delivery of an identical outcome recovers the same message; it
    cannot execute work, renew a deadline or promote the resulting candidate.
    """
    from atlas_core.governance.coding_goal import BoundedCodingGoal
    from atlas_core.governance.coding_goal_dialogue import mutation_guard
    need(type(goal) is BoundedCodingGoal, 'followup_goal')
    with mutation_guard(goal):
        state = goal.reconcile()
        labels = {
            'COMPLETE': 'The bounded coding objective passed its recorded independent verification.',
            'FAILED': 'The coding attempt did not meet its verification requirements.',
            'BLOCKED': 'The coding objective is blocked by its recorded review or clarification requirements.',
            'OUTCOME_UNKNOWN': 'The coding outcome is unconfirmed. Recover the existing attempt before starting more work.',
        }
        need(state['state'] in labels, 'followup_goal_not_settled')
        # Preserve all evidence distinctions in the binding. Builder counts are
        # explicitly not total model usage and are intentionally not advertised.
        projection = {'plan_sha256': goal.fp, 'outcome': state}
        pin = digest(projection)
        content = labels[state['state']]
        if state['state'] == 'COMPLETE':
            content += ' This verifies the bounded workflow; deployment and broader coding reliability are separate.'
        return publish_followup(database, conversation_id=conversation_id, run_id=run_id,
            project_slug=goal.plan['parent']['project'],
            event_id='goal-result:' + pin, kind='result', content=content,
            evidence=['sha256:' + goal.fp, 'sha256:' + pin])
