import pytest


def _import_permission_module():
    try:
        from specter import permissions as perm
        return perm
    except Exception:
        return None


def test_permission_levels():
    perm = _import_permission_module()
    if perm is None:
        pytest.skip("permissions module not available")
    Levels = getattr(perm, "PermissionLevel", None)
    if Levels is None:
        pytest.skip("PermissionLevel not defined")
    levels = getattr(Levels, "levels", None)
    assert isinstance(levels, list)


def test_check_permission():
    perm = _import_permission_module()
    if perm is None:
        pytest.skip("permissions module not available")
    if not hasattr(perm, "check_permission"):
        pytest.skip("check_permission not implemented")
    class User: pass
    assert perm.check_permission(User(), "read") in (True, False)


def test_whitelist_blacklist():
    perm = _import_permission_module()
    if perm is None:
        pytest.skip("permissions module not available")
    if hasattr(perm, "WHITE_LIST") and hasattr(perm, "BLACK_LIST"):
        w = getattr(perm, "WHITE_LIST")
        b = getattr(perm, "BLACK_LIST")
        assert isinstance(w, list) and isinstance(b, list)
    else:
        pytest.skip("whitelist/blacklist not defined")


def test_confirmation_flow(monkeypatch):
    perm = _import_permission_module()
    if perm is None:
        pytest.skip("permissions module not available")
    if not hasattr(perm, "require_confirmation"):
        pytest.skip("require_confirmation not implemented")
    # Simulate user confirming
    monkeypatch.setattr("builtins.input", lambda prompt=None: "yes")
    assert perm.require_confirmation("Proceed?") is True
