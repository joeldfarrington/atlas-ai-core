"""Narrow text-only Ollama v0.34.1 qwen3.5 prompt rendering.

Semantics checked against the versioned public Qwen35Renderer and registry.
This is not a claim about the identity/settings of a running provider. The
trusted host must verify that separately. No tools, images or implicit mode.
"""

GO_SPACE = '\t\n\v\f\r \u0085\u00a0\u1680' + ''.join(chr(n) for n in range(0x2000, 0x200b)) + '\u2028\u2029\u202f\u205f\u3000'


def render_qwen35_text(messages, *, thinking):
    if type(thinking) is not bool:
        raise ValueError('explicit_thinking_mode_required')
    if type(messages) is not list or not 1 <= len(messages) <= 100:
        raise ValueError('bounded_messages_required')
    total = 0
    for message in messages:
        if (type(message) is not dict or set(message) != {'role', 'content'}
                or type(message['role']) is not str or message['role'] not in ('system', 'user', 'assistant')
                or type(message['content']) is not str):
            raise ValueError('normalized_text_messages_required')
        try:
            total += len(message['content'].encode('utf-8'))
        except UnicodeError:
            raise ValueError('valid_utf8_required') from None
    if total > 150000:
        raise ValueError('prompt_text_too_large')
    start, end = '<|im_start|>', '<|im_end|>\n'
    result = []
    if messages[0]['role'] == 'system':
        result.append(start + 'system\n' + messages[0]['content'].strip(GO_SPACE) + end)
    last_query = len(messages) - 1
    for index in range(len(messages) - 1, -1, -1):
        item = messages[index]
        content = item['content'].strip(GO_SPACE)
        if item['role'] == 'user' and not (content.startswith('<tool_response>') and content.endswith('</tool_response>')):
            last_query = index
            break
    for index, item in enumerate(messages):
        role = item['role']
        content = item['content'].strip(GO_SPACE)
        prefill = index == len(messages) - 1 and role == 'assistant'
        if role == 'user' or role == 'system' and index != 0:
            result.append(start + role + '\n' + content + end)
        elif role == 'assistant':
            reasoning = ''
            if '</think>' in content:
                before, content = content.split('</think>', 1)
                reasoning = before.rsplit('<think>', 1)[-1].strip(GO_SPACE)
                content = content.lstrip('\n')
            body = ('<think>\n' + reasoning + '\n</think>\n\n' + content
                    if thinking and index > last_query else content)
            result.append(start + 'assistant\n' + body + ('' if prefill else end))
        if index == len(messages) - 1 and not prefill:
            result.append(start + 'assistant\n' + ('<think>\n' if thinking else '<think>\n\n</think>\n\n'))
    return ''.join(result)


def render_qwen25_text(messages):
    """Text-only subset of the pinned Qwen2.5-Coder Ollama template.

    Explicit nonempty leading system and final user required; no default system,
    later system, tools, images, suffix, assistant prefill or implicit thinking.
    Unlike Qwen3.5's named renderer, this template preserves content whitespace.
    """
    if type(messages) is not list or not 2 <= len(messages) <= 100:
        raise ValueError('bounded_qwen25_messages_required')
    total=0
    for index,message in enumerate(messages):
        if (type(message) is not dict or set(message)!={'role','content'}
                or type(message['role']) is not str or type(message['content']) is not str
                or message['role'] not in (('system',) if index==0 else ('user','assistant'))):
            raise ValueError('qualified_qwen25_text_roles_required')
        try:total+=len(message['content'].encode('utf-8'))
        except UnicodeError:raise ValueError('valid_utf8_required') from None
    if not messages[0]['content'] or messages[-1]['role']!='user':
        raise ValueError('explicit_system_and_final_user_required')
    if total>150000:raise ValueError('prompt_text_too_large')
    return ''.join('<|im_start|>'+m['role']+'\n'+m['content']+'<|im_end|>\n' for m in messages)+'<|im_start|>assistant\n'
