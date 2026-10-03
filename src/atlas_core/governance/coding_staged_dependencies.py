"""Opt-in dependency-ID guidance using the unchanged stage-aware compiler.

The old compact request remains recoverable byte-for-byte. This schema narrows
only dependency strings to the already-required task identifier grammar; graph
membership/order, authority and independent review remain compiler decisions.
"""
from copy import deepcopy
from .coding_staged_compact import request as compact_request, INSTRUCTIONS
from .cognitive_state import encoded

DEPENDENCIES = (
    'depends_on lists earlier task_id values from this proposal, never file paths '
    'or resource_id values. Use [] for an independent task. Do not depend on the '
    'task itself or invent dependencies merely because it edits a file. ')


def request(parent, resources):
    value=compact_request(parent,resources)
    schema=value['response_format']['json_schema']['schema']
    properties=schema['properties']['tasks']['items']['properties']
    properties['depends_on']['items']=deepcopy(properties['task_id'])
    value['response_format']['json_schema']['name']='atlas_objective_decomposition_dependencies_v1'
    value['messages'][0]['content']=DEPENDENCIES+INSTRUCTIONS+encoded(schema)
    return value
