"""Fixed host-selected exercises. No model-selected paths, tests or budgets."""
from types import MappingProxyType

COMMON = ('Use exactly the given function signature, no imports, helper functions, tests, '
          'I/O or external libraries. Exact built-in types exclude subclasses and bool. '
          'The original and independent acceptance tests are protected. Pure built-ins: '
          'type, int, str, bool, isinstance, len, all, any, ord, TypeError, ValueError. '
          'General loops, multiplication, recursion, custom formatting, comprehensions '
          'other than single-iterator generators, and arbitrary attributes are refused. ')

CATALOG = MappingProxyType({
    'index-v1': MappingProxyType({
        'function': 'clamp_index', 'arguments': ('index', 'length'), 'tests_run': 12,
        'nodes': ('BinOp', 'Sub'), 'methods': (), 'builtins': (),
        'contract': COMMON + 'Implement def clamp_index(index, length). Both arguments must '
            'be exact int, otherwise raise TypeError. length must be 1..256, otherwise raise '
            'ValueError. Return index clamped to the valid inclusive range 0..length-1. '
            'Negative index returns 0; an index at or beyond length returns length-1. '
            'Validate both types before range checks. Subtraction is allowed.',
        'seed': 'def clamp_index(index, length):\n    if not isinstance(index, int) or not isinstance(length, int):\n        raise TypeError("integers required")\n    if length < 1 or length > 256:\n        raise ValueError("length")\n    if index < 0:\n        return 0\n    if index > length:\n        return length - 1\n    return index\n',
    }),
    'label-v1': MappingProxyType({
        'function': 'normalize_label', 'arguments': ('value',), 'tests_run': 12,
        'nodes': (), 'methods': ('lower',), 'builtins': (),
        'contract': COMMON + 'Implement def normalize_label(value). Accept exact str only, '
            'otherwise raise TypeError. Strip surrounding whitespace. The stripped label '
            'must contain 1..24 ASCII characters, each a letter A-Z or a-z, a digit 0-9, '
            'or hyphen. Hyphens cannot be first or last; internal repeated hyphens are '
            'allowed. Invalid strings raise ValueError. Return a lowercase exact str. '
            'Methods strip, lower, isdigit and isascii are allowed; use comparisons or '
            'single-iterator generators. Use startswith/endswith for hyphen edges.',
        'seed': 'def normalize_label(value):\n    if not isinstance(value, str):\n        raise TypeError("string required")\n    text = value.strip()\n    if not text or len(text) > 24:\n        raise ValueError("label length")\n    return text.lower()\n',
    }),
    'window-v1': MappingProxyType({
        'function': 'select_window', 'arguments': ('values', 'start', 'limit'), 'tests_run': 12,
        'nodes': ('BinOp', 'Add', 'Subscript', 'Slice'), 'methods': (), 'builtins': ('tuple',),
        'contract': COMMON + 'Implement def select_window(values, start, limit). values '
            'must be an exact tuple containing only exact int items; start and limit '
            'must be exact int. Check these types before any range checks; invalid '
            'types raise TypeError. values has at most 32 items, each in -100..100. '
            'start must be 0..len(values), inclusive; limit must be 0..16. Invalid ranges '
            'raise ValueError. Return the tuple slice from start of at most limit items; '
            'truncation at the end, an empty input, start at the end, and limit 0 are valid. '
            'Do not mutate input. Additional allowed operations: tuple, addition and slices.',
        'seed': 'def select_window(values, start, limit):\n    if type(values) is not tuple or type(start) is not int or type(limit) is not int:\n        raise TypeError("tuple and integers required")\n    if not all(type(item) is int for item in values):\n        raise TypeError("integer items required")\n    if len(values) > 32 or not all(-100 <= item <= 100 for item in values):\n        raise ValueError("values")\n    if start < 0 or start > len(values) or limit < 0 or limit > 16:\n        raise ValueError("window")\n    return values[start:limit]\n',
    }),
})


def exercise(identifier):
    if type(identifier) is not str or identifier not in CATALOG:
        raise ValueError('Unknown fixed exercise identifier')
    return CATALOG[identifier]
