"""Explicit v4: lossless attribution of a narrowly abbreviated source quote.

Keep the literal model reply. Only an ASCII trailing ellipsis on a unique
exact field prefix is resolvable. This cannot turn a rejection into acceptance,
change a reason/assessment, repair factual errors or modify saved goal state.
"""
from copy import deepcopy
from . import coding_plan_evidence_review as v3
from .cognitive_state import digest, encoded, need
from .coding_plan_selection import decode_selection
from .task_contract import _text


def resolve_quote(raw, source):
    _text(raw, 80)
    need(type(source) is str, 'quote_source_type')
    if len(raw.strip()) >= 8 and raw in source:
        return dict(kind='literal', raw=raw, canonical=raw, source_sha256=digest(source))
    need(raw.endswith('...'), 'quote_not_resolvable')
    prefix = raw[:-3]
    need(len(prefix.strip()) >= 8 and '...' not in prefix
         and source.startswith(prefix) and source.find(prefix, 1) == -1,
         'quote_not_unique_exact_prefix')
    return dict(kind='trailing_ellipsis', raw=raw, canonical=prefix,
                source_sha256=digest(source))


def resolve(value, context):
    # Run all existing structural/type/coverage checks before reading quotes.
    v3.v2.decode(encoded(v3._legacy(value)), context)
    canonical = deepcopy(value)
    notes = {n['task_id']: n for n in context['planning_notes']}
    resolutions = []
    for row in canonical['task_checks']:
        evidence = row.get('evidence')
        need(type(evidence) is dict and set(evidence) == set(v3.FIELDS),
             'critic_evidence_missing')
        for field in v3.FIELDS:
            resolved = resolve_quote(evidence[field], notes[row['task_id']][field])
            evidence[field] = resolved['canonical']
            resolutions.append(dict(task_id=row['task_id'], field=field, **resolved))
    # This unchanged validator remains responsible for approval consistency.
    v3.decode(encoded(canonical), context)
    return dict(raw_verdict_sha256=digest(value), context_sha256=digest(context),
                canonical_verdict=canonical, quote_resolutions=resolutions,
                execution_authority=False)


def request(context):
    req = v3.request(context)
    req['response_format']['json_schema']['name'] = 'atlas_plan_critic_v4'
    req['messages'][0]['content'] = (
        'A quote may be shortened only by appending three ASCII dots to a unique '
        'exact prefix of that source field. Do not paraphrase or omit interior '
        'text. Your literal reply and the deterministic attribution are retained. '
        + req['messages'][0]['content'])
    return req


def decode(raw, context):
    value = decode_selection(raw)
    resolve(value, context)
    return value  # Preserve the literal structure, never replace its evidence.


def receipt(context, verdict):
    resolved = resolve(verdict, context)
    return v3.receipt(context, resolved['canonical_verdict'])
