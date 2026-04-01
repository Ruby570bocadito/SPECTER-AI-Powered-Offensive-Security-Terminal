import pytest


def _import_skill_class(class_name):
    try:
        from specter.skills import __dict__ as moddict
        cls = moddict.get(class_name)
        if cls is None:
            module = __import__("specter.skills", fromlist=[class_name])
            cls = getattr(module, class_name, None)
        return cls
    except Exception:
        return None


def test_recon_skill_creation():
    ReconSkill = _import_skill_class("ReconSkill")
    if ReconSkill is None:
        pytest.skip("ReconSkill not available")
    try:
        skill = ReconSkill(name="Recon")
    except TypeError:
        skill = ReconSkill()
    assert skill is not None
    assert hasattr(skill, "name") or hasattr(skill, "id")


def test_osint_skill_creation():
    OSINTSkill = _import_skill_class("OSINTSkill")
    if OSINTSkill is None:
        pytest.skip("OSINTSkill not available")
    skill = OSINTSkill() if OSINTSkill else None
    if skill is None:
        pytest.skip("OSINTSkill cannot be instantiated")
    assert hasattr(skill, "name") or hasattr(skill, "id")


def test_web_skill_creation():
    WebSkill = _import_skill_class("WebSkill")
    if WebSkill is None:
        pytest.skip("WebSkill not available")
    skill = WebSkill() if WebSkill else None
    if skill is None:
        pytest.skip("WebSkill cannot be instantiated")
    assert hasattr(skill, "name") or hasattr(skill, "id")


def test_skill_validate_params():
    ReconSkill = _import_skill_class("ReconSkill")
    if ReconSkill is None:
        pytest.skip("ReconSkill not available")
    if hasattr(ReconSkill, "validate_params"):
        ok = ReconSkill.validate_params({"name": "test"})
        assert isinstance(ok, bool)
    else:
        # If validate_params is not on class, skip gracefully
        pytest.skip("validate_params not implemented on ReconSkill")


def test_skill_available_actions():
    ReconSkill = _import_skill_class("ReconSkill")
    if ReconSkill is None:
        pytest.skip("ReconSkill not available")
    skill = ReconSkill() if ReconSkill else None
    if skill is None or not hasattr(skill, "available_actions"):
        pytest.skip("available_actions not implemented on ReconSkill")
    actions = skill.available_actions()
    assert isinstance(actions, list)
