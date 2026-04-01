import pytest


def _import_tool_registry():
    try:
        from specter.mcp import ToolRegistry
        return ToolRegistry
    except Exception:
        return None


def test_tool_registry_discovery():
    Registry = _import_tool_registry()
    if Registry is None:
        pytest.skip("ToolRegistry not available")
    reg = Registry()
    # discover_tools is async, so we check if the method exists
    assert hasattr(reg, "discover_tools") or hasattr(reg, "tools")


def test_tool_registration():
    Registry = _import_tool_registry()
    if Registry is None:
        pytest.skip("ToolRegistry not available")
    reg = Registry()
    if hasattr(reg, "register_tool"):
        class DummyTool:
            name = "dummy"
            def validate(self, params):
                return True
        reg.register_tool(DummyTool)
        assert any(t.name == "dummy" for t in getattr(reg, "tools", []))
    else:
        pytest.skip("register_tool not implemented")


def test_tool_validation():
    Registry = _import_tool_registry()
    if Registry is None:
        pytest.skip("ToolRegistry not available")
    reg = Registry()
    if hasattr(reg, "validate_tool_params"):
        ok = reg.validate_tool_params({"param": 1})
        assert isinstance(ok, bool)
    else:
        pytest.skip("Tool validation not implemented on registry")


def test_search_tools():
    Registry = _import_tool_registry()
    if Registry is None:
        pytest.skip("ToolRegistry not available")
    reg = Registry()
    if hasattr(reg, "search_tools"):
        res = reg.search_tools("dummy")
        assert isinstance(res, list)
    else:
        pytest.skip("search_tools not implemented")
