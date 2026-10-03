"""Fixed count-only operation on the host's inherited worker channel.

Only the registered parent selects the native counter. A child can supply text,
never a command, resource path, provider, profile, or larger execution budget.
"""
from dataclasses import asdict
import hashlib
import json
import re
import time

from atlas_core.coding_native_counter import NativePromptCounter
from atlas_core.coding_request_budget import message_digest


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def counter_identity(counter):
    need(type(counter) is NativePromptCounter, 'registered_native_counter_required')
    value = {'format': 'atlas-native-counter-peer-v1', 'selection': asdict(counter.selection)}
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


class CounterPeerBroker:
    def __init__(self, counter, *, review_counter=None, planning_count_limit=0):
        self.identity = counter_identity(counter)
        self.counter = counter
        self.review_counter = counter if review_counter is None else review_counter
        self.review_identity = counter_identity(self.review_counter)
        need(type(planning_count_limit) is int and 0 <= planning_count_limit <= 32,
             'bounded_planning_count_limit')
        self.planning_count_limit = planning_count_limit
        self.planning_used = set()
        self.used = set()
        self.review_used = set()

    def count_plan(self, request, host, cutoff, verify):
        """Text-only count for this registered host; never a worker launch/grant.

        Disabled by default. The trusted launcher reserves the count allowance;
        each allocation scope is consumed even if counting fails. The provider's
        separate admission ledger remains responsible for model-request limits.
        """
        need(type(request) is dict and set(request) == {'seq','op','scope','messages'}
             and request['op'] in ('count_plan','count_plan_review'), 'fixed_planning_counter_fields')
        scope = request['scope']
        need(type(scope) is str and re.fullmatch('[0-9a-f]{64}', scope) is not None,
             'planning_counter_scope')
        verify()
        need(host.poll() is None and time.time() < cutoff, 'planning_counter_host_ended')
        need(scope not in self.planning_used and len(self.planning_used) < self.planning_count_limit,
             'planning_counter_consumed')
        self.planning_used.add(scope)
        messages = request['messages']
        need(type(messages) is list and len(messages) == 2
             and all(type(m) is dict and set(m) == {'role','content'}
                     and type(m['content']) is str for m in messages)
             and [m['role'] for m in messages] == ['system','user']
             and len(json.dumps(messages,ensure_ascii=False).encode()) <= 60000,
             'bounded_planning_messages')
        binding = message_digest(messages)
        selected = self.review_counter if request['op']=='count_plan_review' else self.counter
        identity = self.review_identity if request['op']=='count_plan_review' else self.identity
        count = selected(messages)
        need(type(count) is int and count > 0 and message_digest(messages) == binding,
             'counter_result_invalid')
        verify()
        need(host.poll() is None and time.time() < cutoff, 'planning_counter_host_ended')
        return {'prompt_tokens':count, 'messages_sha256':binding, 'counter_identity':identity}

    def count_review(self, request, children, cutoff, verify):
        """One text-only review count after this parent's builder has exited.

        The reviewer gets no command/path selector or worker-launch permission.
        Failed counts consume the allowance, just as builder counts do.
        """
        need(type(request) is dict and set(request) == {'seq', 'op', 'pid', 'messages'}
             and request['op'] == 'count_review', 'fixed_review_counter_fields')
        verify()
        need(time.time() < cutoff, 'phase_dispatch_closed')
        pid = request['pid']
        need(type(pid) is int and pid in children and pid in self.used,
             'review_counter_owned_builder_required')
        item = children[pid]
        need(item['mode'] == 'aider' and item['process'].poll() == 0,
             'review_counter_completed_builder_required')
        need(pid not in self.review_used and len(self.review_used) < 9,
             'review_counter_one_attempt_per_child')
        self.review_used.add(pid)
        messages = request['messages']
        need(type(messages) is list and len(messages) == 2 and all(type(m) is dict for m in messages)
             and messages[0].get('role') == 'system' and messages[1].get('role') == 'user',
             'review_counter_two_message_context')
        digest = message_digest(messages)
        count = self.review_counter(messages)
        need(type(count) is int and count > 0 and message_digest(messages) == digest,
             'counter_result_invalid')
        verify()
        need(time.time() < cutoff and item['process'].poll() == 0,
             'counter_child_or_phase_ended')
        return {'prompt_tokens': count, 'messages_sha256': digest, 'counter_identity': self.review_identity}

    def count(self, request, children, cutoff, verify):
        need(type(request) is dict and set(request) == {'seq', 'op', 'pid', 'messages'}
             and request['op'] == 'count_prompt', 'fixed_counter_fields')
        verify()
        need(time.time() < cutoff, 'phase_dispatch_closed')
        pid = request['pid']
        need(type(pid) is int and pid in children, 'counter_owned_child_required')
        item = children[pid]
        need(item['mode'] == 'aider' and item['process'].poll() is None, 'counter_live_aider_required')
        need(pid not in self.used and len(self.used) < 9, 'counter_one_attempt_per_child')
        self.used.add(pid)  # Failed counts also consume this one-shot allowance.
        messages = request['messages']
        digest = message_digest(messages)
        count = self.counter(messages)
        need(type(count) is int and count > 0 and message_digest(messages) == digest,
             'counter_result_invalid')
        verify()
        need(time.time() < cutoff and item['process'].poll() is None, 'counter_child_or_phase_ended')
        return {'prompt_tokens': count, 'messages_sha256': digest, 'counter_identity': self.identity}


class PeerPromptCounter:
    def __init__(self, client, child_pid, identity):
        need(callable(child_pid) and type(identity) is str and
             re.fullmatch('[0-9a-f]{64}', identity) is not None, 'peer_counter_binding_required')
        self.client, self.child_pid, self.identity = client, child_pid, identity

    def __call__(self, messages):
        digest = message_digest(messages)
        pid = self.child_pid()
        need(type(pid) is int and pid > 0, 'peer_counter_child_required')
        reply = self.client.request('count_prompt', pid=pid, messages=messages)
        need(type(reply) is dict and set(reply) == {'prompt_tokens', 'messages_sha256', 'counter_identity'}
             and reply['counter_identity'] == self.identity and reply['messages_sha256'] == digest
             and type(reply['prompt_tokens']) is int and reply['prompt_tokens'] > 0,
             'peer_counter_receipt_mismatch')
        return reply['prompt_tokens']


class PeerReviewCounter(PeerPromptCounter):
    """Bound review-only client; it cannot count for another completed builder."""
    def __call__(self, messages):
        digest = message_digest(messages)
        pid = self.child_pid()
        need(type(pid) is int and pid > 0, 'peer_counter_child_required')
        reply = self.client.request('count_review', pid=pid, messages=messages)
        need(type(reply) is dict and set(reply) == {'prompt_tokens', 'messages_sha256', 'counter_identity'}
             and reply['counter_identity'] == self.identity and reply['messages_sha256'] == digest
             and type(reply['prompt_tokens']) is int and reply['prompt_tokens'] > 0,
             'peer_counter_receipt_mismatch')
        return reply['prompt_tokens']


class PeerPlanningCounter:
    """Count-only inherited channel, bound to one host model allocation."""
    def __init__(self, client, scope, identity, *, review=False):
        need(callable(getattr(client, 'request', None)) and all(type(v) is str
             and re.fullmatch('[0-9a-f]{64}', v) is not None for v in (scope,identity)),
             'peer_planning_binding_required')
        need(type(review) is bool, 'peer_planning_review_flag')
        self.client, self.scope, self.identity = client, scope, identity
        self.operation = 'count_plan_review' if review else 'count_plan'

    def __call__(self, messages):
        binding = message_digest(messages)
        reply = self.client.request(self.operation, scope=self.scope, messages=messages)
        need(type(reply) is dict and set(reply) == {'prompt_tokens','messages_sha256','counter_identity'}
             and reply['counter_identity'] == self.identity and reply['messages_sha256'] == binding
             and type(reply['prompt_tokens']) is int and reply['prompt_tokens'] > 0,
             'peer_counter_receipt_mismatch')
        return reply['prompt_tokens']
