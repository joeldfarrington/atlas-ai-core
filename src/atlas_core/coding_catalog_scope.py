"""Public interpreter scope adopted from the qualified catalog guard.

Pure syntax checks only: no exec, behavioral tests, parser or expected answers.
A scope pass never means correctness, verification, authority or permission.
"""
import ast

TASKS = {
    'ready-jobs-feature': ('feature', 'select_ready_jobs', ('jobs', 'now', 'limit')),
    'terminal-count-refactor': ('refactoring', 'count_terminal_runs', ('records',)),
    'quantity-test-repair': ('test_repair', 'QuantityTests', ()),
}
BUILTINS = {name: value for name, value in {
    'type':type, 'len':len, 'sum':sum, 'int':int, 'str':str, 'list':list,
    'dict':dict, 'set':set, 'ValueError':ValueError,
    'NotImplementedError':NotImplementedError}.items()}
ATTRS = {'append','add','get','assertEqual','assertRaises','assertTrue','assertFalse','subTest'}
NODES = (ast.Module,ast.FunctionDef,ast.arguments,ast.arg,ast.Return,ast.Assign,
    ast.AugAssign,ast.Expr,ast.Call,ast.Attribute,ast.Name,ast.Load,ast.Store,
    ast.Constant,ast.Dict,ast.List,ast.Tuple,ast.Set,ast.Compare,ast.Eq,ast.NotEq,
    ast.Lt,ast.LtE,ast.Gt,ast.GtE,ast.Is,ast.IsNot,ast.In,ast.NotIn,ast.BoolOp,
    ast.And,ast.Or,ast.UnaryOp,ast.Not,ast.USub,ast.If,ast.IfExp,ast.Subscript,
    ast.keyword,ast.For,ast.Continue,ast.Pass,ast.GeneratorExp,ast.ListComp,
    ast.comprehension,ast.Raise,ast.BinOp,ast.Add,ast.With,ast.withitem)

def require(condition, reason):
    if not condition: raise ValueError(reason)

def guarded(task, raw):
    require(type(task) is str and task in TASKS, 'unknown_task')
    require(type(raw) is bytes and 0 < len(raw) <= 32768, 'source_bound')
    tree = ast.parse(raw.decode('utf-8'))
    body = list(tree.body)
    if body and isinstance(body[0],ast.Expr) and isinstance(body[0].value,ast.Constant) and type(body[0].value.value) is str:
        body.pop(0)
    kind,name,args = TASKS[task]
    if kind == 'test_repair':
        require(len(body) == 3 and isinstance(body[0],ast.Import)
            and ast.dump(body[0]) == ast.dump(ast.parse('import unittest').body[0])
            and ast.dump(body[1]) == ast.dump(ast.parse('from quantity import parse_quantity').body[0]), 'test_imports')
        cls = body[2]
        require(isinstance(cls,ast.ClassDef) and cls.name == name
            and not cls.decorator_list and not cls.keywords
            and len(cls.bases) == 1 and ast.dump(cls.bases[0]) == ast.dump(ast.parse('unittest.TestCase',mode='eval').body), 'test_class')
        functions = cls.body
        require(2 <= len(functions) <= 24 and all(isinstance(f,ast.FunctionDef)
            and f.name.startswith('test_') for f in functions), 'test_methods')
        require(len({f.name for f in functions}) == len(functions), 'duplicate_test_method')
    else:
        require(len(body) == 1 and isinstance(body[0],ast.FunctionDef) and body[0].name == name, 'function_scope')
        functions = body
    for function in functions:
        expected = ('self',) if kind == 'test_repair' else args
        require(tuple(a.arg for a in function.args.args) == expected and not function.args.posonlyargs
            and not function.args.kwonlyargs and function.args.vararg is None and function.args.kwarg is None
            and not function.args.defaults and not function.args.kw_defaults
            and not function.decorator_list and function.returns is None
            and all(a.annotation is None for a in function.args.args)
            and function.type_comment is None and not getattr(function,'type_params',[]), 'signature')
        nodes = list(ast.walk(function))
        require(len(nodes) <= 900, 'complexity')
        for node in nodes:
            require(isinstance(node,NODES), 'unsupported_syntax')
            require(not isinstance(node,ast.FunctionDef) or node is function, 'nested_function')
            if isinstance(node,ast.Name):
                require(not node.id.startswith('_'), 'private_name')
                require(not isinstance(node.ctx,ast.Store) or node.id not in set(BUILTINS)|{'parse_quantity','self'}, 'protected_name')
            if isinstance(node,ast.Attribute):
                require(node.attr in ATTRS and isinstance(node.ctx,ast.Load), 'attribute')
            if isinstance(node,ast.Call):
                require((isinstance(node.func,ast.Name) and node.func.id in set(BUILTINS)|{'parse_quantity'})
                    or (isinstance(node.func,ast.Attribute) and node.func.attr in ATTRS), 'call')
            if isinstance(node,ast.keyword): require(node.arg is not None and not node.arg.startswith('_'), 'keyword')
            if isinstance(node,ast.Constant) and type(node.value) in (str,bytes): require(len(node.value) <= 2048, 'constant_bound')
    return kind, ast.Module(body=functions,type_ignores=[])

