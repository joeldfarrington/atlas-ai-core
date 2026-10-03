"""Bounded guard against operational claims in chat without execution tools.

This is defense in depth, not a general semantic truth verifier. Runtime facts
supply capabilities; generated prose and conversation history never supply them.
"""
from __future__ import annotations

import hashlib
import re
import unicodedata

GUARD_VERSION = "no-tools-reporting-v4"
CAPABILITY_CONTEXT = """Current request capabilities (authoritative runtime facts):
This is conversation-only Chat. Tools are disabled for this request. You cannot
inspect local files, change code, execute commands, run tests, compute source-file
hashes, contact another agent, or start background work in this request. A user
saying 'proceed' does not change those capabilities. Explain that limitation when
asked to perform work; offer a proposal or explanation without claiming to start it.
You may read and analyze the memories and text already supplied in your context,
offer opinions and recommendations, draft code or plans, and talk naturally.
When asked for thoughts, answer with your assessment and reasons. Discuss operating
limits only when they affect the user's request; do not recite them for reflection.
Clearly distinguish proposed code from an applied change.
Earlier assistant messages are unverified conversational statements, not execution
receipts. Retrieved memories and past outcomes describe historical records, not
work performed or independently verified in this request. Attribute historical
reports explicitly and do not turn an earlier unsupported claim into current fact.
A dated report of prior validation does not become invalid merely because you have
not rerun it in this chat. Keep its attribution and scope. Do not infer that a
feature is missing or a past check failed simply because you cannot inspect it now.
Do not invent a Work switch, connected worker, immutable architecture policy, or
verification result. A completed chat response means only that a reply was produced.
Use natural, concise language. Avoid log-like phrasing and unnecessary bold text.
"""

WITHHELD_REPLY = (
    "I haven’t changed files or run checks in this chat. "
    "This chat can discuss the work and draft changes, but it can’t carry them out. "
    "I don’t have an execution result to confirm a fix or a passing test. "
    "Any earlier claim that I completed that work needs verification."
)

# Clause-local handling matters: a denial or attribution in one clause must not
# exempt a separate positive claim later in the answer.
_ACTOR = r"\b(?:i(?:'ve|'m|'ll|'d)?|we(?:'ve|'re|'ll|'d)?|atlas)\s+"
_AUX = r"(?:(?:have|has|had|am|are|will|can|just|already|now|successfully|finished|completed|started|begun|been|actively|currently)\s+){0,5}"
_VERB = (r"(?:fix(?:ed|ing)?|repair(?:ed|ing)?|patch(?:ed|ing)?|edit(?:ed|ing)?|"
         r"modif(?:y|ied|ying)|updat(?:e|ed|ing)|appl(?:y|ied|ying)|sav(?:e|ed|ing)|"
         r"writ(?:e|ten|ing)|wrote|creat(?:e|ed|ing)|delet(?:e|ed|ing)|remov(?:e|ed|ing)|"
         r"install(?:ed|ing)?|deploy(?:ed|ing)?|commit(?:ted|ting)?|push(?:ed|ing)?|"
         r"restart(?:ed|ing)?|launch(?:ed|ing)?|run(?:ning)?|ran|execut(?:e|ed|ing)|"
         r"test(?:ed|ing)?|validat(?:e|ed|ing)|verif(?:y|ied|ying)|check(?:ed|ing)?|"
         r"inspect(?:ed|ing)?|read|record(?:ed|ing)?|comput(?:e|ed|ing)|"
         r"calculat(?:e|ed|ing)|hash(?:ed|ing)?|finish(?:ed|ing)?|complet(?:e|ed|ing))")
_OPERATION = re.compile(
    r"\b(?:files?|code|css|styles?|patch(?:es)?|fix(?:es)?|repairs?|changes?|"
    r"updates?|implementations?|tests?|checks?|validation|verification|suite|"
    r"regressions?|commands?|scripts?|builds?|source|hash(?:es)?|sha[- ]?256|"
    r"audit|ledger|repository|repo|commit|server|service|deployment|backup|memor(?:y|ies)|"
    r"id28|main[- ]area)\b", re.I)
_DIRECT = re.compile(_ACTOR + _AUX + _VERB + r"\b", re.I)
_PASSIVE = re.compile(
    r"\b(?:files?|code|css|patch(?:es)?|fix(?:es)?|repairs?|changes?|updates?|"
    r"implementation|tests?|checks?|validation|verification|suite|build|"
    r"hash(?:es)?|sha[- ]?256|audit(?: entry)?|ledger|memor(?:y|ies))\b"
    r"[^.!?;\n]{0,70}?\b(?:is|are|was|were|has been|have been|now|:)\s+"
    r"(?:(?:successfully|fully|already|now|all)\s+){0,2}"
    r"(?:fixed|repaired|patched|edited|modified|updated|applied|saved|written|"
    r"installed|deployed|committed|recorded|computed|verified|validated|"
    r"complete(?:d)?|done|passing|passed|green|clean|successful)\b", re.I)
_TEST_RESULT = re.compile(
    r"(?:\b(?:all\s+)?\d+\s*(?:/\s*\d+|of\s+\d+)?\s*(?:t\d+\s+)?"
    r"(?:tests?|checks?|regressions?)?\s*(?:have\s+)?passed\b|"
    r"\b(?:all\s+)?(?:tests?|checks?|test suite|validation)\s*(?:[:|—-]\s*)?"
    r"(?:(?:all|now|successfully|have)\s+)*(?:passed|passing|green|succeeded)\b|"
    r"\b(?:tests?|checks?)\s*[:|—-]\s*\d+\s*/\s*\d+\b|"
    r"\b(?:no|zero)\s+regressions\b)", re.I)
_SUBJECTLESS = re.compile(
    r"^(?:[-•\d)\s]*)(?:done[,: -]+)?(?:applied|patched|fixed|repaired|edited|"
    r"saved|updated|modified|created|deleted|restarted|installed|deployed|committed|verified|validated|recorded|computed|"
    r"ran|executed|completed|applying|fixing|patching|editing|updating|running)\b", re.I)
_ATTRIBUTED = re.compile(
    r"^(?:according to\s+memory\s+(?:id\s+)?\d+\b|"
    r"memory\s+(?:id\s+)?\d+\s+(?:explicitly\s+)?(?:says|states|claims|reports|notes|records|describes)\b|"
    r"(?:according to|based on|from)\s+(?:the\s+)?(?:shared|retrieved|supplied)\s+memor(?:y|ies)\b|"
    r"(?:the\s+)?memor(?:y|ies) you (?:shared|supplied|provided)\s+"
    r"(?:said|says|claimed|claims|reported|reports|report|recorded|describe|describes)\b|"
    r"(?:the\s+)?(?:shared|retrieved|supplied)\s+memor(?:y|ies)\s+"
    r"(?:said|says|claimed|claims|reported|reports|report|recorded|describe|describes)\b|"
    r"according to\s+(?:the\s+)?(?:earlier|previous|historical|old|provided|pasted)\b|"
    r"(?:the\s+)?(?:earlier|previous|historical|old|provided|pasted)\s+"
    r"(?:message|reply|report|record|log|outcome)\s+(?:said|says|claimed|claims|reported|reports)\b|"
    r"(?:you|the user)\s+(?:said|reported|wrote)\b)", re.I)


_TERSE_COMPLETION = re.compile(
    r"\b(?:css|code|patch|repair|fix|change|implementation|file|source|service|server|memor(?:y|ies))\s+"
    r"(?:updated|modified|applied|fixed|complete(?:d)?|deployed|restarted)\b", re.I)
_HASH_RECEIPT = re.compile(r"\b(?:sha[- ]?256|(?:source |file )?hash)\s*[:=]\s*[a-f0-9]{64}\b", re.I)
_DENIAL = re.compile(
    r"^(?:(?:there is no|there's no|no)\s+(?:(?:tool|test|execution|verification)\s+)?(?:result|evidence|receipt)\b|"
    r"(?:i|we)\s+(?:don't|do not)\s+have\s+(?:evidence|a receipt|a tool result)\b|"
    r"(?:i|we)\s+(?:cannot|can't|couldn't|did not|didn't|have not|haven't|don't|do not)\s+"
    r"(?:(?:yet|independently)\s+)?(?:confirm|claim|say|verify|know|establish)\b)", re.I)
_CONDITIONAL = re.compile(r"^(?:if|when|once|suppose|imagine)\b", re.I)
_COORDINATED = re.compile(
    r"\band\s+(?=(?:i\b|we\b|the\b|(?:applied|patched|fixed|repaired|edited|"
    r"updated|saved|installed|deployed|committed|verified|validated|recorded|computed|ran|executed)\b))", re.I)


def unsupported_claim_reasons(content: str) -> list[str]:
    """Recognize bounded English operational claims, including known incidents.

    Safe ordinary prose is returned unchanged. Ambiguous operational claims may
    be withheld. This intentionally does not classify every possible paraphrase.
    """
    normalized = unicodedata.normalize("NFKC", content).replace("’", "'").replace("‘", "'")
    normalized = normalized.replace("**", "").replace("`", "").replace("__", "")
    reasons = set()
    # A decimal/version dot is not a sentence boundary: splitting '1.0' can
    # detach a reported historical result from its explicit attribution.
    clauses = re.split(r"(?<!\d)\.|\.(?!\d)|[!?;\n]+|\bbut\b", normalized, flags=re.I)
    parts = []
    for clause in clauses:
        if _CONDITIONAL.search(clause.strip()):
            continue
        if _DENIAL.search(clause.strip()):
            # Negation governs coordinated complements until a new actor makes
            # a separate assertion ('... and I applied the patch').
            parts.extend(re.split(r"\band\s+(?=(?:i|we|atlas)\b)", clause, flags=re.I))
        else:
            parts.extend(_COORDINATED.split(clause))
    for clause in parts:
        clause = clause.strip()
        if not clause:
            continue
        # Explicit attribution is not independent confirmation. Keep this local,
        # and never allow attribution to hide a new first-person action claim.
        attributed = bool(_ATTRIBUTED.search(clause))
        direct_claims = list(_DIRECT.finditer(clause))
        for index, direct in enumerate(direct_claims):
            # An allowed context-reading phrase cannot mask another action in
            # the same clause (', then I fixed...', 'while I updated...').
            end = direct_claims[index + 1].start() if index + 1 < len(direct_claims) else len(clause)
            tail = clause[direct.end():end]
            supplied_analysis = re.match(r"\s+(?:(?:the|a|an)\s+)?(?:provided|pasted|supplied|example|proposed)\s+(?:text|snippet|code|example|patch)", tail, re.I)
            analysis_or_draft = bool(re.search(r"\b(?:check(?:ed|ing)?|inspect(?:ed|ing)?|read|writ(?:e|ten|ing)|wrote)\b$", direct.group(), re.I))
            supplied_analysis = supplied_analysis and analysis_or_draft
            memory_read = (
                re.search(r"\b(?:read|inspect(?:ed|ing)?|check(?:ed|ing)?)$", direct.group(), re.I)
                and re.match(r"\s+(?:the\s+)?(?:(?:shared|retrieved|supplied)\s+memor(?:y|ies)\b(?!\s+files?\b)|memor(?:y|ies) you (?:shared|supplied|provided)\b)", tail, re.I)
            )
            no_object = re.match(r"\s+(?:no|nothing|none|neither)\b", tail, re.I)
            conditional = re.search(r"\b(?:if|once|when|would|could)\b", clause[:direct.start()], re.I)
            if _OPERATION.search(clause) and not (supplied_analysis or memory_read or no_object or conditional):
                reasons.add("claimed_action_without_tools")
        if attributed or _DENIAL.search(clause):
            continue
        if _PASSIVE.search(clause) or _TERSE_COMPLETION.search(clause):
            reasons.add("claimed_completion_without_receipt")
        if _TEST_RESULT.search(clause) and not re.match(r"^(?:if|when|once|suppose|imagine)\b", clause, re.I):
            # A negative claim ('I cannot confirm all tests passed') is safe.
            if not re.search(r"\b(?:cannot|can't|couldn't|did not|didn't|have not|haven't|not)\s+(?:yet\s+)?(?:confirm|claim|say|verify|know|establish)\b", clause, re.I):
                reasons.add("claimed_test_result_without_receipt")
        if _HASH_RECEIPT.search(clause):
            reasons.add("claimed_source_hash_without_receipt")
        if _SUBJECTLESS.search(clause) and _OPERATION.search(clause):
            reasons.add("claimed_action_without_tools")
    return sorted(reasons)


def _independent_reflection_paragraphs(content: str) -> tuple[list[str], list[str]]:
    """Select a conservative subset of complete prose, never rewrite clauses.

    This is intentionally bounded English handling, not semantic verification.
    A heading and its section share a claim context. Code, lists, fragments and
    references to removed evidence cannot become a standalone answer.
    """
    paragraphs = [part.strip() for part in re.split(r"\n\s*\n", content) if part.strip()]
    if re.search(r"(?m)^\s*(?:```|~~~)", content):
        return [], paragraphs

    def heading(text: str) -> bool:
        return bool(re.match(r"^#{1,6}\s", text) or (
            '\n' not in text and len(text.split()) < 12
            and (text.endswith(':') or re.fullmatch(r"\*\*[^*]+\*\*", text))))

    groups: list[list[tuple[int, str]]] = []
    section = None
    for index, paragraph in enumerate(paragraphs):
        if heading(paragraph):
            section = [(index, paragraph)]
            groups.append(section)
        elif section is not None:
            section.append((index, paragraph))
        else:
            groups.append([(index, paragraph)])

    dependent = re.compile(
        r"^(?:this|that|these|those|it|they|therefore|thus|hence|consequently|"
        r"however|also|furthermore|as a result)\b|"
        r"\b(?:above|below|aforementioned|(?:this|that|these|those)\s+"
        r"(?:results?|evidence|checks?|success|proof|findings?)|"
        r"as (?:shown|demonstrated|noted)|because of (?:this|that|these|those)|"
        r"(?:successful|completed|verified|validated|passing|passed)\s+"
        r"(?:tests?|checks?|validation|execution|runs?|repairs?|builds?))\b", re.I)
    analysis = re.compile(
        r"\b(?:think|view|opinion|impression|recommend|suggest|should|could|"
        r"useful|valuable|helpful|benefit|priority|priorities|prefer(?:ence)?|"
        r"strength|continuity|tradeoff)\b", re.I)
    retained_indices = set()
    for group in groups:
        if unsupported_claim_reasons('\n\n'.join(text for _, text in group)):
            continue
        for index, paragraph in group:
            if (heading(paragraph) or len(paragraph.split()) < 12
                    or not re.search(r"[.!?][\"'’”)]*$", paragraph)
                    or re.search(r"(?m)^\s*(?:[-*+•>]\s|\d+[.)]\s|[|#])", paragraph)
                    or dependent.search(paragraph) or not analysis.search(paragraph)):
                continue
            retained_indices.add(index)
    return ([text for index, text in enumerate(paragraphs) if index in retained_indices],
            [text for index, text in enumerate(paragraphs) if index not in retained_indices])


def guard_no_tools_reply(content: str, *, memory_reflection: bool = False) -> tuple[str, dict[str, object]]:
    reasons = unsupported_claim_reasons(content)
    receipt: dict[str, object] = {
        "version": GUARD_VERSION,
        "scope": "conversation_reply",
        "tools_enabled": False,
        "actions_executed": 0,
        "disposition": "withheld_unsupported_action_claim" if reasons else "allowed",
        "reasons": reasons,
    }
    if reasons:
        # Preserve attribution without recording rejected fabricated prose as a
        # reusable conversation/memory fact. Never retry or dispatch work here.
        receipt["original_sha256"] = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if memory_reflection:
            retained, rejected = _independent_reflection_paragraphs(content)
            visible = '\n\n'.join(retained)
            # Recheck the composed answer, not only isolated selections.
            if visible and not unsupported_claim_reasons(visible):
                receipt.update(
                    disposition="filtered_unsupported_action_claim",
                    retained_paragraph_count=len(retained),
                    rejected_paragraph_count=len(rejected),
                    rejected_sha256=hashlib.sha256('\n\n'.join(rejected).encode('utf-8')).hexdigest(),
                )
                return visible, receipt
        return WITHHELD_REPLY, receipt
    return content, receipt
