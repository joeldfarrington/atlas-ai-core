"""One registered Gym exercise as a bounded maintenance-window trial.

Trusted assembly supplies the existing goal, Gym and admission host. This adapter
has no service controls, provider factory, grant issuer, task selector or retry.
Acceptance is bound to the protected checker, not the returned Builder claim.
"""
import asyncio
import os
from pathlib import Path
from .coding_gym import save, read
from .coding_engine_gym import EngineCodingGym, recover_engine_gym
from .models.host import ModelAdmissionHost
from .practice.workspace import regular, sha
from .governance.cognitive_state import digest, need
from .governance.coding_goal import BoundedCodingGoal
from .governance.action_boundary import private_identity


def admission_instance(host):
    """Policy scope may match; original journals, locks and host lives may not."""
    from .models.admission import LocalModelAdmission
    from .governance.cognitive_state import CognitiveJournal
    need(type(host) is ModelAdmissionHost and type(host.admission) is LocalModelAdmission,
         'trial_admission_instance_required')
    a = host.admission; j = a.journal; shared = a.shared
    need(j is a._journal and shared is a._shared and shared.journal is j
         and type(j) is CognitiveJournal, 'trial_admission_instance_changed')
    events = j.events() # validates original journal inode and complete event chain
    lives = [e for e in events if e['subject'] == 'model-host-lifetime']
    lock = Path(shared.lock_path).absolute()
    need(private_identity(lock) == shared.lock_identity and len(lives) == 1
         and lives[0]['value']['scope_sha256'] == a.status()['scope_sha256']
         and type(lives[0]['value']['host_nonce']) is str,
         'trial_admission_instance_changed')
    return dict(journal_root=str(j.root), journal_file_identity=list(private_identity(j.path)),
        journal_root_identity=list(private_identity(j.root, True)), lock_path=str(lock),
        lock_identity=list(private_identity(lock)), host_lifetime_sha256=digest(lives[0]))


def verification_policy(checker_sha256, expected_cases):
    import re
    need(type(checker_sha256) is str and re.fullmatch('[0-9a-f]{64}', checker_sha256)
         and type(expected_cases) is int and 0 < expected_cases <= 10000,
         'trial_fixed_acceptance_required')
    return {'schema': 1, 'kind': 'single_registered_gym',
            'checker_sha256': checker_sha256, 'expected_cases': expected_cases}


def goal_binding(goal, task, journal, acceptance_sha256, proposal_task_id=None,
                 objective_registration=None):
    """Reuse the exact proposal/registered association, with no new authority."""
    need(type(goal) is BoundedCodingGoal, 'trial_goal_required')
    goal._validate()
    if objective_registration is not None:
        from .coding_objective_registration import RegisteredObjective
        need(type(objective_registration) is RegisteredObjective and goal.journal is journal
             and type(proposal_task_id) is str, 'trial_objective_registration_required')
        bindings = objective_registration._bindings(goal, require_ready=False)
        child = bindings['children'].get(proposal_task_id)
        need(child is not None and child['mapping']['registered_packet'] == task
             and digest(child['verification_policy']) == acceptance_sha256,
             'trial_objective_child_binding')
        return child['mapping']
    need(len(goal.plan['children']) == 1
         and goal.plan['parent']['acceptance_sha256'] == acceptance_sha256
         and goal.journal is journal, 'trial_parent_binding')
    child = goal.plan['children'][0]
    if proposal_task_id is None:
        need(child['packet'] == task
             and child['covers'] == list(range(1, len(task['requirements'])+1))
             and goal.plan['parent']['requirements'] == task['requirements'],
             'trial_parent_binding')
        return None
    from .governance.coding_goal_registration import associate
    need(type(proposal_task_id) is str and goal._decomposition is not None
         and child['packet']['task_id'] == proposal_task_id
         and child['covers'] == list(range(1,len(goal.plan['parent']['requirements'])+1)),
         'trial_proposal_binding')
    mapping, _ = associate(goal.plan, proposal_task_id, task)
    return mapping


class RegisteredGymTrial:
    def __init__(self, root, goal, gym, model_host, *, policy, expected_policy_sha256, critique,
                 proposal_task_id=None, objective_registration=None):
        need(type(goal) is BoundedCodingGoal and type(gym) is EngineCodingGym
             and type(model_host) is ModelAdmissionHost, 'trial_qualified_components_required')
        need(policy == verification_policy(policy['checker_sha256'], policy['expected_cases'])
             and digest(policy) == expected_policy_sha256, 'trial_acceptance_pin_mismatch')
        goal._validate(); gym.validate(gym.execution)
        task = gym.execution.packet; spec = gym.execution.session.spec['task']
        mapping = goal_binding(goal, task, gym.execution.journal,
                               expected_policy_sha256, proposal_task_id, objective_registration)
        need(spec['checker_sha256'] == policy['checker_sha256']
             and spec['expected_cases'] == policy['expected_cases'], 'trial_checker_binding')
        need(gym._review_port is not None
             and gym._review_port.intent['review_protocol'] in ('candidate-regrounded-v1','candidate-check-aware-v1')
             and (gym._review_port.intent['review_protocol'] != 'candidate-check-aware-v1'
                  or gym._review_port.intent.get('independent_precheck') is True),
             'trial_regrounded_reviewer_required')
        need(model_host.services is gym.execution.services and model_host.claimed
             and model_host.started and not model_host.released_to_native,
             'trial_current_admission_host_required')
        gym._review_port.require_shared_admission(model_host.admission)
        need(not gym._used and goal.reconcile()['state'] == 'READY', 'trial_fresh_goal_required')
        self.root = Path(root).absolute()
        need(not self.root.exists() and not any(p.is_symlink() for p in (self.root,*self.root.parents)),
             'trial_fresh_evidence_root')
        project = gym.execution.prepared.source_path.parent
        need(not any(self.root.is_relative_to(v) for v in (project,gym.backend.worker.case,gym.backend.worker.scratch)),
             'trial_evidence_outside_source')
        self.root.mkdir(mode=0o700)
        self.goal,self.gym,self.host = goal,gym,model_host
        self.objective_registration = objective_registration
        self._objective_registration = objective_registration
        self._components = (goal,gym,model_host)
        self.policy = dict(policy); self.critique = dict(critique)
        self._pid = os.getpid(); self._root_id = private_identity(self.root,True)
        self._running = False
        self.binding = {'schema':1,'plan_sha256':goal.fp,'task_id':task['task_id'],
            'registered_task_id':spec['id'],'source_sha256':task['source_sha256'],
            'gym_intent_sha256':sha(regular(gym.root/'INTENT.json')),
            'acceptance_sha256':expected_policy_sha256,'policy':policy,
            'critique_sha256':digest(self.critique),'admission_scope':model_host.admission.status()['scope_sha256'],
            'execution_authority':False,'automatic_retry':False,'installed':False}
        if mapping is not None:
            self.binding.update(task_id=proposal_task_id, execution_task_id=task['task_id'],
                proposal_task_id=proposal_task_id, registration_sha256=digest(mapping),
                dispatch_kind='registered_proposal_v1')
        if objective_registration is not None:
            self.binding['objective_registration_sha256'] = objective_registration.expected
            self._admission_components = (model_host.admission, model_host.admission.journal, model_host.admission.shared)
            self.binding['admission_instance'] = admission_instance(model_host)
        save(self.root,'BINDING.json',self.binding)

    def allocation_identity(self):
        need(self.objective_registration is not None, 'trial_objective_required')
        a = self.host.admission
        need(all(x is y for x,y in zip((a,a.journal,a.shared), self._admission_components)),
             'trial_admission_instance_changed')
        current = admission_instance(self.host)
        need(current == self.binding['admission_instance'], 'trial_admission_instance_changed')
        return current

    def _check(self):
        need(self.objective_registration is self._objective_registration,
             'trial_objective_registration_changed')
        need(all(a is b for a,b in zip((self.goal,self.gym,self.host),self._components))
             and os.getpid() == self._pid and private_identity(self.root,True) == self._root_id
             and read(self.root,'BINDING.json') == self.binding
             and self.goal.fp == self.binding['plan_sha256']
             and self.policy == self.binding['policy']
             and digest(self.critique) == self.binding['critique_sha256']
             and sha(regular(self.gym.root/'INTENT.json')) == self.binding['gym_intent_sha256']
             and self.host.admission.status()['scope_sha256'] == self.binding['admission_scope'],
             'trial_binding_changed')
        if self.objective_registration is not None:
            self.allocation_identity()
        self.goal._validate()
        if 'proposal_task_id' in self.binding:
            mapping = goal_binding(self.goal, self.gym.execution.packet,
                self.gym.execution.journal, self.binding['acceptance_sha256'],
                self.binding['proposal_task_id'], self.objective_registration)
            if self.objective_registration is not None:
                need(self.objective_registration.expected == self.binding['objective_registration_sha256'],
                     'trial_objective_registration_changed')
            need(digest(mapping) == self.binding['registration_sha256']
                 and self.binding['execution_task_id'] == self.gym.execution.packet['task_id']
                 and self.binding['task_id'] == self.binding['proposal_task_id']
                 and self.binding['dispatch_kind'] == 'registered_proposal_v1',
                 'trial_registration_changed')

    def run(self):
        self._check()
        need(not (self.root/'RUN_CLAIM.json').exists(),'trial_cannot_replay')
        save(self.root,'RUN_CLAIM.json',{'binding_sha256':digest(self.binding),'pid':self._pid})
        self._running = True
        try:
            dispatch = (self.goal.execute_registered_gym if 'proposal_task_id' in self.binding
                        else self.goal.execute_gym)
            result = dispatch(self.binding['task_id'],self.gym,critique=self.critique)
            save(self.root,'RETURN.json',result)
            return result
        finally:self._running = False

    def _evidence(self):
        self._check()
        need((self.root/'RUN_CLAIM.json').is_file() and not self._running,'trial_not_terminal')
        result = recover_engine_gym(self.gym.root)
        parent = self.goal.reconcile()
        need(result['task_id'] == self.binding.get('execution_task_id', self.binding['task_id']),
             'trial_result_identity')
        passed = result['outcome'] == 'accepted' and result['verifier_passed'] is True
        receipt_sha = None
        if result['verifier_complete']:
            session = self.gym.execution.session
            receipt = session._read('CHECKER_RECEIPT.json'); check = receipt['result']
            counts = check['counts']; source = regular(self.gym.root/'BUILD.bin')
            need(receipt['complete'] is True and receipt['cleanup_verified'] is True
                 and check['checker_sha256'] == self.policy['checker_sha256']
                 and check['source_sha256'] == sha(source)
                 and type(counts['cases']) is int and counts['cases'] == self.policy['expected_cases'],
                 'trial_checker_evidence_changed')
            passed = passed and counts['failed'] == 0 and counts['passed'] == self.policy['expected_cases']
            receipt_sha = sha(regular(session.root/'CHECKER_RECEIPT.json'))
        if passed:
            child = parent['children'][self.binding['task_id']]
            need(child['state'] == 'accepted' and child['gym_outcome'] == 'accepted'
                 and child['registered_task_id'] == self.binding['registered_task_id']
                 and child['candidate_sha256'] == sha(regular(self.gym.root/'BUILD.bin')),
                 'trial_parent_result_changed')
        need(sha(regular(self.gym.execution.prepared.source_path)) == self.binding['source_sha256'],
             'trial_original_source_changed')
        return result,parent,passed,receipt_sha

    def verify(self, returned):
        # Returned success flags are never acceptance inputs. Reconcile original
        # protected evidence and fixed parent/child identities instead.
        result,parent,passed,receipt = self._evidence()
        need(read(self.root,'RETURN.json') == returned,'trial_return_changed')
        if passed and parent['state'] == 'VERIFYING' and self.objective_registration is None:
            def independent(plan,children):
                fresh,current,ok,_ = self._evidence()
                need(current['children'] == children and digest(plan) == self.goal.fp,
                     'trial_parent_verification_changed')
                return {'plan_sha256':digest(plan),'children_sha256':digest(children),
                    'checker_sha256':self.binding['acceptance_sha256'],
                    'passed':ok,'cleanup_verified':fresh['workspace_discarded'] is True}
            parent = self.goal.verify_goal(independent)
        proof = {'independent':True,'accepted':passed and parent['state'] == 'COMPLETE',
            'parent_state':parent['state'],'task_id':self.binding['task_id'],
            'registered_task_id':self.binding['registered_task_id'],
            'checker_receipt_sha256':receipt,'tests_run':result['tests_run'],
            'gym_result_sha256':digest(result),'strategy_sha256':sha(regular(self.gym.root/'STRATEGY.json')),
            'evidence_kind':result['evidence_kind'],
            'model_reliability_observation':result['model_reliability_observation'],
            'authority_change':False,'installed':False}
        if 'proposal_task_id' in self.binding:
            proof.update(proposal_task_id=self.binding['proposal_task_id'],
                execution_task_id=self.binding['execution_task_id'],
                registration_sha256=self.binding['registration_sha256'])
        if self.objective_registration is not None:
            proof.update(accepted=False, child_accepted=passed,
                objective_registration_sha256=self.objective_registration.expected,
                requires_aggregate_verification=True)
        if (self.root/'VERIFICATION.json').exists():
            need(read(self.root,'VERIFICATION.json') == proof,'trial_verification_changed')
        else:save(self.root,'VERIFICATION.json',proof)
        return proof

    def cleanup(self):
        self._check(); need(not self._running,'trial_execution_still_active')
        worker = self.gym.backend.worker; worker.cancel.set()
        settled = asyncio.run(self.host.aclose())
        state = self.host.admission.status()
        receipt = worker.receipt
        absent = worker.child_pid is None
        if worker.child_pid is not None:
            try:os.killpg(worker.child_pid,0)
            except ProcessLookupError:absent = True
        clean = (absent and not self.gym._pending_review
            and ((worker.child_pid is None and not worker._used)
                 or (type(receipt) is dict and receipt['cleanup_verified'] is True
                     and receipt['process_group_empty'] is True and receipt['proxy_joined'] is True)))
        # Zero local transports is insufficient when a remote outcome is still
        # unconfirmed. Unknown server work must keep maintenance held.
        need(settled is True and state['pending'] == 0 and state['requires_recovery'] is False
             and state['local_transports_active'] == 0,'trial_model_cleanup_unknown')
        proof = {'owned_processes_absent':clean,'model_requests_active':0,
            'model_requests_settled':True,'admission_stopped':state['stopped'],
            'requests_used':state['requests_used'],'execution_authority':False}
        if (self.root/'CLEANUP.json').exists():
            need(read(self.root,'CLEANUP.json') == proof,'trial_cleanup_changed')
        else:save(self.root,'CLEANUP.json',proof)
        return proof
