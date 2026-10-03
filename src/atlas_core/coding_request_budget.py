"""Trusted-host admission for a fully assembled Aider model request.

The counter must count the exact provider-rendered prompt, including template
overhead. Its identity refers to independently qualified host evidence; neither
this identifier nor Aider's model metadata proves tokenizer correctness. No
tokenizer is guessed, downloaded, or selected from model-controlled input.
"""
from dataclasses import dataclass
from copy import deepcopy
import hashlib
import json
import re
from typing import Callable

from atlas_core.governance.cognitive_state import need


def message_digest(messages):
    return hashlib.sha256(json.dumps(messages, ensure_ascii=False, sort_keys=True,
                                    separators=(',', ':'), allow_nan=False).encode('utf-8')).hexdigest()


@dataclass(frozen=True)
class AiderRequestBudget:
    provider_label: str
    counter_identity: str
    context_tokens: int
    output_tokens: int
    count_prompt_tokens: Callable

    def __post_init__(self):
        need(type(self.provider_label) is str and 0 < len(self.provider_label) <= 128,
             'aider_counter_provider_required')
        need(type(self.counter_identity) is str and
             re.fullmatch('[0-9a-f]{64}', self.counter_identity) is not None,
             'aider_counter_evidence_required')
        need(type(self.context_tokens) is int and 1 < self.context_tokens <= 1048576 and
             type(self.output_tokens) is int and 0 < self.output_tokens < self.context_tokens,
             'aider_context_limits_required')
        need(callable(self.count_prompt_tokens), 'aider_prompt_counter_required')

    def admit(self, messages, provider_label):
        need(provider_label == self.provider_label, 'aider_counter_provider_mismatch')
        snapshot = message_digest(messages)
        counted = deepcopy(messages)
        tokens = self.count_prompt_tokens(counted)
        need(message_digest(counted) == snapshot, 'aider_counter_mutated_request')
        need(type(tokens) is int and tokens > 0, 'aider_prompt_count_unknown')
        need(tokens + self.output_tokens <= self.context_tokens, 'aider_context_exhausted')
        return {
            'format': 'atlas-aider-input-admission-v1',
            'provider': self.provider_label,
            'counter_identity': self.counter_identity,
            'messages_sha256': snapshot,
            'prompt_tokens': tokens,
            'output_reserve_tokens': self.output_tokens,
            'context_tokens': self.context_tokens,
            'counter_source': 'trusted_host; requires separate tokenizer qualification',
        }

    def verify_metadata(self, metadata):
        """Do not let a host admission exceed the pinned runtime's own ceilings.

        These ceilings constrain configuration; they still do not count tokens.
        """
        need(type(metadata) is dict, 'aider_runtime_context_unknown')
        model = metadata.get('openai/atlas-local')
        need(type(model) is dict, 'aider_runtime_context_unknown')
        context, output = model.get('max_input_tokens'), model.get('max_output_tokens')
        need(type(context) is int and context > 0 and type(output) is int and output > 0,
             'aider_runtime_context_unknown')
        need(self.context_tokens <= context and self.output_tokens <= output,
             'aider_budget_exceeds_runtime_metadata')
