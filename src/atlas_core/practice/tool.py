"""Duck-compatible with Atlas ToolManager; explicit host registration only."""
from .workspace import PracticeRefused, PracticeWorkspace, need


class PracticeTool:
    name = 'practice'

    def __init__(self, workspace):
        need(type(workspace) is PracticeWorkspace, 'A host-prepared workspace is required.')
        self.workspace = workspace

    def describe(self):
        return {'name': self.name, 'description': 'One host-selected fixed coding exercise in one isolated file. Read its exact contract first.',
                'actions': {
                    'read': {'description': 'Read solution.py, requirements, current hash and remaining budget.',
                             'parameters': {'type': 'object', 'properties': {}, 'additionalProperties': False}},
                    'write': {'description': 'Replace only solution.py after reading its hash. Two repairs maximum. No imports or tests in this exercise file.',
                              'parameters': {'type': 'object', 'properties': {
                                  'content': {'type': 'string', 'minLength': 1, 'maxLength': 16384},
                                  'expected_sha256': {'type': 'string', 'pattern': '^[0-9a-f]{64}$'}},
                                  'required': ['content', 'expected_sha256'], 'additionalProperties': False}},
                    'check': {'description': 'Check syntax/scope and run the protected original and independent tests. Return actual results; no code is installed.',
                              'parameters': {'type': 'object', 'properties': {}, 'additionalProperties': False}}}}

    def execute(self, action, arguments):
        need(type(arguments) is dict, 'An argument object is required.')
        if action == 'read' and not arguments: return self.workspace.read()
        if action == 'check' and not arguments: return self.workspace.check()
        if action == 'write' and set(arguments) == {'content', 'expected_sha256'}:
            return self.workspace.write(**arguments)
        raise PracticeRefused('Unknown action or arguments; paths and shell commands are not accepted.')

    def audit_arguments(self, action, arguments):
        return {'action': action, 'source_bytes': len(arguments.get('content', '').encode())
                if type(arguments.get('content')) is str else 0,
                'expected_sha256': arguments.get('expected_sha256')}

    def audit_result(self, action, result):
        return {k: result[k] for k in ['written', 'source_sha256', 'complete', 'passed', 'tests_run', 'cached'] if k in result}

    def audit_error(self, action, error):
        return type(error).__name__ + ': practice action refused'
