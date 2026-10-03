"""Public source-bound edit diagnostics, independent of protected test answers.

No execution, patch rewriting, model dispatch or authorization occurs here.
A within-boundary result says nothing about correctness or acceptance.
"""
import ast
import hashlib

LEGACY_PROTOCOL = 'function-v1'
CATALOG_PROTOCOL = 'public-catalog-v2'
CATALOG_SCOPES = {
    'ef72c66523d25cfc760f689bcfb6d572f79a03ec5e4f7406cc6347df32cea614': 'ready-jobs-feature',
    'a646e56ae34ee851817ece71c139ee9989f68f7d62c254a3e183277119dc0123': 'terminal-count-refactor',
    'd6abe50b11817d4578bfbdddca8c3824cc43ae8c6cb95064af7801341ca43278': 'quantity-test-repair',
}

SCOPES = {
    '574c2984434bcbe051bcc42e0e387ad6067a0bbb79a6e9fa8d3538225f44a1cf': ('relative',),
    'c906345a3fd29c63c4c61cda9b224c2b5836e8b57c11e2c584828298b58d7a79': ('decode',),
    '092d1833d4261af3e014fde1bab4f6c93e6a442fb704e178dc20e8742a1dbfeb': ('require_running',),
    'd91aec6d6ad84833a2ab9dce93288cc2f870c5af6fbb6aa71d36aebd1e9308ed': ('IdentityStore','documents'),
}


def public_edit_feedback(base, candidate, *, protocol=LEGACY_PROTOCOL):
    if type(protocol) is not str or protocol not in (LEGACY_PROTOCOL,CATALOG_PROTOCOL):
        raise ValueError('edit_feedback_protocol')
    if type(base) is not bytes or type(candidate) is not bytes:
        raise ValueError('edit_feedback_bytes_required')
    if not 0 < len(base) <= 32768 or not 0 < len(candidate) <= 32768:
        raise ValueError('edit_feedback_size')
    pin=lambda value: hashlib.sha256(value).hexdigest()
    result={'schema':1,'basis':'public_source_boundary','source_sha256':pin(base),
        'candidate_sha256':pin(candidate),'status':'unavailable','function':None,
        'findings':[],'acceptance':False,'execution_authority':False,
        'automatic_retry':False,'protected_tests_accessed':False}
    if protocol==CATALOG_PROTOCOL:
        result['protocol']=protocol
        task=CATALOG_SCOPES.get(result['source_sha256'])
        if task is not None:
            from atlas_core.coding_catalog_scope import guarded,TASKS
            result.update(basis='public_interpreter_scope',function=TASKS[task][1],task_id=task)
            try:
                guarded(task,candidate)
            except (SyntaxError,UnicodeError,RecursionError):
                result.update(status='invalid_source',findings=['Keep the work product valid bounded Python. No candidate code was executed.'])
            except ValueError as error:
                # Messages are fixed guard categories, never candidate text.
                reasons={
                    'test_imports':'Keep only the provided imports and QuantityTests class; extra top-level statements are outside the public interpreter scope.',
                    'test_class':'Preserve the QuantityTests class and its unittest.TestCase base without decorators or extra class options.',
                    'test_methods':'Keep two to twenty-four test_ methods in QuantityTests.',
                    'duplicate_test_method':'Use distinct test_ method names so coverage is not silently overwritten.',
                    'function_scope':'Keep only the registered top-level function; extra definitions or statements are outside the public interpreter scope.',
                    'signature':'Preserve the registered callable signature without annotations, decorators or extra parameters.',
                }
                result.update(status='outside_boundary',findings=[reasons.get(str(error),
                    'The candidate uses syntax, calls, attributes or size outside the stated public interpreter rules. No candidate code was executed.')])
            else:
                result['status']='within_boundary'
            return result
    scope=SCOPES.get(result['source_sha256'])
    if scope is None:
        return result
    result['function']='.'.join(scope)
    def split(raw):
        text=raw.decode('utf-8');tree=ast.parse(text)
        nodes=tree.body
        for index,name in enumerate(scope):
            kind=ast.FunctionDef if index==len(scope)-1 else ast.ClassDef
            found=[node for node in nodes if isinstance(node,kind) and node.name==name]
            if len(found)!=1: raise ValueError('editable_definition_missing_or_duplicated')
            node=found[0];nodes=node.body
        lines=text.splitlines(keepends=True)
        start=min([node.lineno]+[x.lineno for x in node.decorator_list])-1
        signature=ast.dump(ast.FunctionDef(name=node.name,args=node.args,body=[],
            decorator_list=node.decorator_list,returns=node.returns,
            type_comment=node.type_comment,type_params=getattr(node,'type_params',[])),
            include_attributes=False)
        return ''.join(lines[:start]),''.join(lines[node.end_lineno:]),signature
    try:
        before=split(base);after=split(candidate)
    except (SyntaxError,ValueError,UnicodeError,RecursionError):
        result.update(status='invalid_source',findings=['The candidate must remain valid Python with exactly the original editable definition.'])
        return result
    findings=[]
    if before[:2]!=after[:2]:
        findings.append('Bytes outside the editable function changed. Preserve the original imports, other definitions and surrounding text.')
    if before[2]!=after[2]:
        findings.append('The editable function signature or decorators changed. Preserve the original callable interface.')
    result.update(status='outside_boundary' if findings else 'within_boundary',findings=findings)
    return result


def lesson_for_attempt(outcome, tests_run, feedback):
    """Strategies only: no hidden cases, candidate text, grants or success claim."""
    if (outcome=='not_accepted' and type(feedback) is dict
            and feedback.get('protocol')==CATALOG_PROTOCOL
            and feedback.get('basis')=='public_interpreter_scope'
            and feedback.get('status') in ('outside_boundary','invalid_source')):
        return 'Check the public interpreter scope before submission. Keep edits within the registered work product; extra test runners, imports or helpers may be refused. A scope refusal is not behavioral verification or permission to retry.'
    if outcome=='not_accepted' and type(feedback) is dict and feedback.get('status') in ('outside_boundary','invalid_source'):
        return 'Check the public editable boundary and Python structure before submission. This attempt was rejected; do not copy changes outside the authorized function or treat it as verified.'
    if outcome=='not_accepted' and tests_run==0:
        return 'The attempt was rejected before behavioral acceptance completed. Preserve the refusal and inspect public input requirements; no passing tests or coding success were established.'
    return 'Use independent acceptance even when the reviewer approves.'
