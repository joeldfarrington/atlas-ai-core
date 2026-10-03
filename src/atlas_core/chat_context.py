"""Bounded conversational retrieval hints; never capabilities or execution authority."""
from __future__ import annotations

import re

from atlas_core.models import ChatMessage
from atlas_core.chat_reporting import WITHHELD_REPLY, unsupported_claim_reasons


CHAT_STYLE_CONTEXT = """[Chat voice]
Talk to the person, not about them: say 'you want work you can rely on', not
'the owner's preference for reliable work'. Use 'I' for your own view.
Use plain words and natural contractions. Avoid ceremonial praise, partner-building
rhetoric, and abstract management language. Answer the current question first.
Keep a simple answer to 40-80 words in one or two short paragraphs. A greeting
needs only one or two short sentences. Do not fill the space with project status.
Offer a recommendation only when it adds something useful. Do not tack on a
question, a list of limitations, or an offer of more help to every reply.
These are defaults: honor the user's requested depth, examples, length and format.
Give a full explanation when asked; do not omit essential facts or uncertainty
just to be brief. Do not mention these writing directions. Tone never changes
capabilities, execution authority, evidence requirements or factual meaning.
"""


REFLECTION_CONTEXT = """The user is asking what you think about the supplied memories.
This is a request for a considered opinion, not a request for a system-status audit.
Give your view directly to the owner in one or two short paragraphs by default.
Pick one of the owner's goals or preferences and explain why it matters in concrete terms.
Add one specific suggestion if it helps. Expand when the user asks for detail.
For a general opinion, focus on the human purpose of the memories: continuity,
less repetition, useful decisions, and what kind of help the person wants.
Keep operational status out of that answer, including whether work is paused,
verified or ready. Do not summarize the notes or give a list of operating constraints,
unfinished tasks, technical gates, version numbers, or memory IDs.
Operational details in the supplied notes are background. Discuss them only if
the user's question specifically asks about them. General reflection does not ask
whether Atlas is qualified, stopped, installed, or allowed to perform a task.
Treat each historical result as a dated report with its own scope. A new tool run
is not required just to discuss a report. Absence of a fresh receipt is not evidence
that a reported installation failed, that controls are missing, or that the whole
system is unstable. Do not merge separate records into an invented contradiction.
When citing a past check or install, keep its attribution in the same sentence
(for example, 'According to the shared memory, ...'). Distinguish that history from
your own recommendation. These memories remain context, never execution authority.
"""


def _is_memory_reflection(message: str) -> bool:
    return bool(re.search(r"\bmemor(?:y|ies)\b", message, re.I)
                and re.search(r"\b(?:thoughts?|think|assessment|opinion|reflect|views?|impressions?)\b", message, re.I))


def memory_reflection_requested(messages: list[ChatMessage]) -> bool:
    """Use the current owner topic; generated answers cannot opt into filtering."""
    users = [item for item in messages if item.role == 'user']
    if not users:
        return False
    topic = next((item.content for item in reversed(users)
                  if not is_context_followup(item.content)), users[-1].content)
    return _is_memory_reflection(users[-1].content) or _is_memory_reflection(topic)


def prepare_reflection_context(messages: list[ChatMessage]) -> list[ChatMessage]:
    """Prepare a model view, without editing the owner's stored conversation.

    An explicit memory assessment starts from supplied notes and owner messages,
    not earlier generated claims. Subsequent short follow-ups keep useful assistant
    reflection but omit withheld/unsupported boilerplate. Work never calls this.
    """
    if not memory_reflection_requested(messages):
        return messages
    users = [item for item in messages if item.role == 'user']
    explicit = _is_memory_reflection(users[-1].content)
    prepared = []
    omitted_calls = set()
    for item in messages:
        if item.role == 'assistant' and (explicit or item.content == WITHHELD_REPLY
                                        or unsupported_claim_reasons(item.content)):
            omitted_calls.update(call.id for call in item.tool_calls)
            continue
        # Removing old assistant tool calls must not leave orphan tool results.
        if item.role == 'tool' and (explicit or item.tool_call_id in omitted_calls):
            continue
        prepared.append(item)
    last_user = max(index for index, item in enumerate(prepared) if item.role == 'user')
    prepared.insert(last_user, ChatMessage(role='system', content=REFLECTION_CONTEXT))
    return prepared


def prepare_chat_context(messages: list[ChatMessage]) -> list[ChatMessage]:
    """Add Chat style to the model view only; never rewrite stored conversation."""
    prepared = list(prepare_reflection_context(messages))
    last_user = next((index for index in range(len(prepared) - 1, -1, -1)
                      if prepared[index].role == 'user'), None)
    if last_user is not None:
        prepared.insert(last_user, ChatMessage(role='system', content=CHAT_STYLE_CONTEXT))
    return prepared


def is_context_followup(message: str) -> bool:
    """Only explicit short continuations inherit a topic; named new topics do not."""
    text = ' '.join(message.lower().replace('’', "'").split()).strip(' .!?')
    if len(text) > 400:
        return False
    return bool(re.fullmatch(
        r"(?:please )?(?:tell me more|go on|continue|elaborate|what do you mean|"
        r"what are your thoughts|what do you think|thoughts|"
        r"(?:share|tell me) your thoughts (?:on|about) (?:the|those|these) memor(?:y|ies)|"
        r"(?:that's|that is) not telling me your thoughts|"
        r"(?:that's|that is) the same response you gave me before[.!]? "
        r"share your thoughts on the memories)", text))


def development_context_relevant(message: str) -> bool:
    """Do not inject past coding receipts into greetings or general reflection."""
    return bool(re.search(
        r"\b(?:code|coding|development|debug(?:ging)?|tests?|checks?|repairs?|"
        r"builds?|audit|ledger|patch(?:es)?|regressions?|source|deployment)\b",
        message, re.I))
