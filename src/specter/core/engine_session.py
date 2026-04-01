from __future__ import annotations

from specter.core.session_manager import SessionManager
from specter.core.models import SessionData
from datetime import datetime
import uuid


def save_session() -> str:
    sm = SessionManager()
    sess = SessionData(
        session_id=uuid.uuid4().hex,
        name="engine_saved_session",
        created_at=datetime.utcnow(),
        findings=[],
        scopes=[],
    )
    sid = sm.save_session(sess)
    print(f"Saved session {sid}")
    return sid


from typing import Optional

def load_session(session_id: str) -> Optional[SessionData]:
    sm = SessionManager()
    try:
        return sm.load_session(session_id)
    except FileNotFoundError:
        print(f"Session {session_id} not found")
        return None


def list_saved_sessions() -> None:
    sm = SessionManager()
    for s in sm.list_sessions():
        print(f"{s.session_id}  {s.name}  created at {s.created_at}")
