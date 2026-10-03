"""Opt-in stage-aware reproduction, preserving original proposals and budgets.

Model-authored baseline claims are labelled as claims, not verified facts. The
compiler never interprets them as intended implementation behavior. Version1/2
records remain untouched and never acquire invented stage annotations.
"""
from copy import deepcopy
from .cognitive_state import digest, encoded, need
from .task_contract import _text

FIELDS = ('scenario', 'baseline', 'expected_after_change', 'check_method', 'baseline_basis')
BASES = ('observed', 'user_report', 'source_prediction', 'unknown')
LABELS = dict(scenario='Reproduction scenario', baseline='Before change',
              expected_after_change='Expected after change', check_method='Verification method')

CLARIFICATION_GUIDANCE = (
    'Before asking a question, check the numbered requirements and supplied public source. '
    'If they already state the expected behavior, set clarification to null and use that behavior '
    'in your plan. Choose harmless implementation details yourself within the fixed contract. '
    'Ask only for a missing fact or decision that materially affects correctness, acceptance, '
    'resources or authority; name the missing information concisely. Do not ask the user to '
    'repeat supplied requirements or approve routine work. Never guess new authority or erase '
    'a real conflict. Source reading alone is source_prediction, not an observed test result. '
    'Write short complete sentences; length limits are ceilings, not targets. ')


def validate_stages(value):
    need(type(value) is dict and set(value) == set(FIELDS), 'reproduction_stage_fields')
    for field in FIELDS[:-1]:
        _text(value[field], 100)
    need(type(value['baseline_basis']) is str and value['baseline_basis'] in BASES,
         'reproduction_stage_basis')
    return value


def render(value):
    validate_stages(value)
    return '\n'.join([LABELS[f]+': '+value[f] for f in FIELDS[:-1]]
                     + ['Baseline claim basis: '+value['baseline_basis']])


def request(parent, resources):
    from .coding_decomposition import decomposition_request_v2
    req = decomposition_request_v2(parent, resources)
    schema = req['response_format']['json_schema']['schema'];old = encoded(schema)
    schema['properties']['schema']['enum'] = [3]
    properties = {f: dict(type='string', minLength=1, maxLength=100) for f in FIELDS[:-1]}
    properties['baseline_basis'] = dict(type='string', enum=list(BASES))
    schema['properties']['tasks']['items']['properties']['reproduction'] = dict(
        type='object', properties=properties, required=list(FIELDS), additionalProperties=False)
    req['response_format']['json_schema']['name'] = 'atlas_objective_decomposition_staged_v1'
    req['messages'][0]['content'] = (
        CLARIFICATION_GUIDANCE +
        'Separate current behavior from the required behavior after the proposed change. '
        'Use a structured reproduction: scenario, baseline, expected_after_change, '
        'check_method, baseline_basis. Baseline is an observation/report/prediction '
        'about BEFORE the change, never an implementation instruction. Label unknown '
        'baseline honestly. Use approach for proposed implementation behavior and risks '
        'for checks. All model-authored baseline claims still require independent '
        'verification. Preserve schema3 and all existing scope and budget restrictions. '
        + req['messages'][0]['content'].replace(old, encoded(schema)))
    return req


def compile(parent, resources, proposal):
    from .coding_decomposition import compile_decomposition
    need(type(proposal) is dict and set(proposal) == {'schema', 'context_sha256', 'tasks'}
         and type(proposal['schema']) is int and proposal['schema'] == 3
         and type(proposal['tasks']) is list, 'staged_decomposition_shape')
    normalized = deepcopy(proposal);normalized['schema'] = 1;stages = {}
    for row in normalized['tasks']:
        need(type(row) is dict and type(row.get('task_id')) is str,
             'staged_decomposition_task')
        value = validate_stages(row.get('reproduction'))
        need(row['task_id'] not in stages, 'staged_decomposition_duplicate')
        stages[row['task_id']] = deepcopy(value)
        row['reproduction'] = render(value)
    result = compile_decomposition(parent, resources, normalized)
    result.update(protocol='bounded-objective-decomposition-staged-v1', proposal=deepcopy(proposal),
        reproduction_stages=stages, normalized_proposal_sha256=digest(normalized))
    return result
