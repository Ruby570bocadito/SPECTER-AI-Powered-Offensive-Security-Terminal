from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List
import importlib


@dataclass
class Step:
    skill: str
    action: str
    params: Dict[str, Any] = field(default_factory=dict)
    requires_confirmation: bool = False


@dataclass
class Workflow:
    name: str
    description: str
    steps: List[Step] = field(default_factory=list)


class WorkflowEngine:
    def __init__(self) -> None:
        self.workflows: Dict[str, Workflow] = self._build_default_workflows()

    def _build_default_workflows(self) -> Dict[str, Workflow]:
        return {
            "full_recon": Workflow(
                name="full_recon",
                description="Full reconnaissance workflow",
                steps=[
                    Step(skill="ping_sweep", action="execute"),
                    Step(skill="port_scan", action="execute"),
                    Step(skill="service_scan", action="execute"),
                    Step(skill="os_fingerprint", action="execute"),
                ],
            ),
            "web_audit": Workflow(
                name="web_audit",
                description="Web audit workflow",
                steps=[
                    Step(skill="dir_fuzz", action="execute"),
                    Step(skill="nuclei_scan", action="execute"),
                    Step(skill="sqlmap_test", action="execute"),
                ],
            ),
            "ad_attack": Workflow(
                name="ad_attack",
                description="Active Directory attack workflow",
                steps=[
                    Step(skill="ldap_enum", action="execute"),
                    Step(skill="kerberoast", action="execute"),
                    Step(skill="bloodhound_collect", action="execute"),
                ],
            ),
            "quick_scan": Workflow(
                name="quick_scan",
                description="Lightweight quick scan",
                steps=[
                    Step(skill="ping_sweep", action="execute"),
                    Step(skill="port_scan", action="execute", params={"limit": 100}),
                ],
            ),
        }

    def execute_workflow(self, name: str, session: Any) -> Dict[str, Any]:
        if name not in self.workflows:
            raise ValueError(f"Workflow '{name}' not found")
        wf = self.workflows[name]
        results: List[Dict[str, Any]] = []
        step_index = 1
        for step in wf.steps:
            # If a step requires confirmation, we assume approval in this automated context
            if step.requires_confirmation:
                # In a real system, you'd pause and await user confirmation. Here we continue.
                pass

            step_res = self._execute_step(step, session)
            results.append(
                {
                    "step": step_index,
                    "skill": step.skill,
                    "action": step.action,
                    "params": step.params,
                    "success": step_res.get("success", True),
                    "detail": step_res.get("detail", ""),
                }
            )
            step_index += 1

        # Export workflow results to session if supported, otherwise attach to session object directly
        if hasattr(session, "store_workflow_result"):
            session.store_workflow_result(name, results)
        elif hasattr(session, "append_workflow_result"):
            session.append_workflow_result(name, results)
        else:
            setattr(session, f"workflow_{name}", results)

        return {"workflow": name, "results": results}

    def _execute_step(self, step: Step, session: Any) -> Dict[str, Any]:
        try:
            module = importlib.import_module(f"specter.skills.{step.skill}")
            fn = getattr(module, step.action, None)
            if not callable(fn):
                fn = getattr(module, "execute", None)
            if callable(fn):
                # Try to pass session if the function accepts it
                try:
                    detail = fn(session=session, **step.params)  # type: ignore
                    return {"success": True, "detail": detail}
                except TypeError:
                    detail = fn(**step.params)  # type: ignore
                    return {"success": True, "detail": detail}
            return {"success": False, "detail": f"Skill '{step.skill}' has no callable '{step.action}' or 'execute'"}
        except Exception as e:
            return {"success": False, "detail": f"Error executing step {step.skill}: {str(e)}"}
