"""Bounded citation repair, not semantic proof, approval, or permission.

Only exact source or identical Python tokens can anchor a finding. No fuzzy
matching, model retry, execution, hidden test access or baseline substitution.
Literal evidence remains immutable; the returned mapping is independently
recomputed during recovery against the same candidate and response.
"""
import io
import json
import tokenize
from atlas_core.governance.cognitive_state import need
from atlas_core.practice.workspace import sha

PROTOCOL = 'candidate-regrounded-v1'
WINDOW = 8


def tokens(line):
    """Preserve string, number, operator and comment bytes; ignore spacing only."""
    try:
        rows=list(tokenize.generate_tokens(io.StringIO(line.strip()).readline))
    except (tokenize.TokenError,IndentationError,SyntaxError):
        return None
    if any(t.type==tokenize.ERRORTOKEN for t in rows):return None
    skip={tokenize.NEWLINE,tokenize.NL,tokenize.ENDMARKER}
    result=tuple((t.type,t.string) for t in rows if t.type not in skip)
    return result or None


def reground(raw,payload,strict_parser):
    need(type(raw) is str and 0<len(raw.encode())<=16384,'bounded_review_required')
    def unique(items):
        value={}
        for key,item in items:
            need(key not in value,'duplicate_review_field');value[key]=item
        return value
    value=json.loads(raw,object_pairs_hook=unique)
    need(type(payload) is dict and type(payload.get('candidate_source')) is str
         and len(payload['candidate_source'].encode())<=65536,'bounded_anchor_source')
    need(type(value) is dict and set(value)=={'findings','approved'}
         and type(value['findings']) is list and len(value['findings'])<=4
         and type(value['approved']) is bool
         and value['approved']==(not value['findings']),'consistent_grounded_review_required')
    lines=payload['candidate_source'].splitlines();anchors=[]
    for row in value['findings']:
        need(type(row) is dict and set(row)=={'requirement','line','quote','problem','counterexample'},
             'grounded_finding_shape')
        line,quote=row['line'],row['quote']
        need(type(line) is int and 1<=line<=65536 and type(quote) is str
             and 0<len(quote.strip())<=256 and len(quote)<=256
             and '\n' not in quote and '\r' not in quote,'bounded_anchor_citation')
        resolved=line;method='exact'
        if line>len(lines) or quote!=lines[line-1].strip():
            # Global uniqueness avoids silently choosing a different occurrence
            # of the same statement. The move itself remains local and bounded.
            exact=[i for i,text in enumerate(lines,1) if text.strip()==quote]
            signature=tokens(quote)
            matches=([i for i,text in enumerate(lines,1) if tokens(text)==signature]
                if signature is not None else exact)
            need(len(matches)==1 and abs(matches[0]-line)<=WINDOW,'review_anchor_ambiguous_or_missing')
            resolved=matches[0];method='line_shift' if exact else 'token_whitespace'
        anchors.append({'requirement':row['requirement'],'original_line':line,
            'original_quote':quote,'resolved_line':resolved,
            'resolved_quote':lines[resolved-1].strip(),'method':method})
        row['line']=resolved;row['quote']=lines[resolved-1].strip()
    # All existing verdict, requirement, shape, length and duplicate controls
    # still run after resolving attribution. No finding is dropped or approved.
    decision=strict_parser(json.dumps(value),payload)
    audit={'schema':1,'protocol':PROTOCOL,'window_lines':WINDOW,
        'response_sha256':sha(raw.encode()),'candidate_sha256':sha(payload['candidate_source'].encode()),
        'anchors':anchors,'authority_change':False,'verdict_changed':False,
        'counterexample_truth_verified':False}
    return decision,audit
