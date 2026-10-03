"""Persisted Work reader generation, independent of constitutional authority."""
import json
import sqlite3

from .action_boundary import private_identity
from .cognitive_state import digest, need


def validate_format(db):
    rows=db.execute('SELECT schema,policy,foundation FROM meta').fetchall()
    need(len(rows)==1 and type(rows[0][0]) is int and rows[0][0] in (1,2),
         'unsupported_work_state')
    version,policy,foundation=rows[0]
    table=db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='state_transitions'").fetchone()
    if table is None:
        need(version==1,'work_transition_history_missing')
        return version
    history=db.execute('SELECT seq,body,previous,hash FROM state_transitions ORDER BY seq LIMIT 65').fetchall()
    need(0<len(history)<=64,'work_transition_history_size')
    head=digest({'policy':policy,'foundation':foundation,'format':1});current=1;seen=set()
    for i,(seq,raw,previous,stored) in enumerate(history,1):
        event=json.loads(raw)
        need(type(event) is dict and set(event)=={'request_id','owner_reference','from','to','checkpoint_sha256'}
             and type(event['request_id']) is str and event['request_id'] not in seen
             and type(event['owner_reference']) is str and bool(event['owner_reference'].strip())
             and type(event['from']) is int and type(event['to']) is int
             and event['from']==current and event['to']==3-current
             and type(event['checkpoint_sha256']) is str and len(event['checkpoint_sha256'])==64
             and all(c in '0123456789abcdef' for c in event['checkpoint_sha256'])
             and seq==i and previous==head and stored==digest({'previous':head,'event':event}),
             'work_transition_history_changed')
        current=event['to'];seen.add(event['request_id']);head=stored
    need(current==version,'work_transition_projection_changed')
    return version


def stored_version(path):
    private_identity(path)
    db=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=1)
    try:return validate_format(db)
    finally:db.close()
