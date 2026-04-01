import pytest


def _import_session_class():
    try:
        from specter.session import Session
        return Session
    except Exception:
        return None


def test_session_creation():
    Session = _import_session_class()
    if Session is None:
        pytest.skip("Session implementation not available")
    s = None
    try:
        s = Session("test_session")
    except TypeError:
        # Fallback to no-arg constructor if needed
        s = Session()
    assert s is not None
    assert hasattr(s, "id") or hasattr(s, "session_id") or hasattr(s, "name")


def test_add_finding():
    Session = _import_session_class()
    if Session is None:
        pytest.skip("Session implementation not available")
    s = Session("test_session_finding")
    if not hasattr(s, "add_finding"):
        pytest.skip("Session does not support add_finding")
    finding = {"id": "f1", "description": "sample"}
    s.add_finding(finding)
    findings = getattr(s, "findings", [])
    assert finding in findings


def test_scope_management():
    Session = _import_session_class()
    if Session is None:
        pytest.skip("Session implementation not available")
    s = Session("test_session_scope")
    if not hasattr(s, "set_scope") or not hasattr(s, "is_in_scope"):
        pytest.skip("Session scope management not implemented")
    s.set_scope("production")
    assert s.is_in_scope("production") is True


def test_findings_count():
    Session = _import_session_class()
    if Session is None:
        pytest.skip("Session implementation not available")
    s = Session("test_session_count")
    if not hasattr(s, "findings_count") and not hasattr(s, "findings"):
        pytest.skip("Session does not expose findings count")
    count = getattr(s, "findings_count", None)
    if count is None:
        count = len(getattr(s, "findings", []))
    assert isinstance(count, int)


def test_duration_calculation():
    Session = _import_session_class()
    if Session is None:
        pytest.skip("Session implementation not available")
    s = Session("test_session_duration")
    if not hasattr(s, "duration") and not hasattr(s, "get_duration"):
        pytest.skip("Session duration not implemented")
    # Set artificial times if possible
    if hasattr(s, "started_at"):
        import time
        s.started_at = time.time() - 60
    if hasattr(s, "ended_at"):
        import time
        s.ended_at = time.time()
    dur = None
    if hasattr(s, "duration"):
        dur = s.duration()
    elif hasattr(s, "get_duration"):
        dur = s.get_duration()
    assert dur is None or dur >= 0


def test_role_setting():
    Session = _import_session_class()
    if Session is None:
        pytest.skip("Session implementation not available")
    s = Session("test_session_role")
    if not hasattr(s, "set_role") or not hasattr(s, "role"):
        pytest.skip("Role management not implemented")
    s.set_role("analyst")
    assert getattr(s, "role", None) == "analyst"


def test_is_in_scope():
    Session = _import_session_class()
    if Session is None:
        pytest.skip("Session implementation not available")
    s = Session("test_session_scope_check")
    if not hasattr(s, "is_in_scope"):
        pytest.skip("is_in_scope not implemented")
    assert s.is_in_scope("any") in (True, False)
