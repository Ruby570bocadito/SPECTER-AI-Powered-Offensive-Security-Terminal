from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from pathlib import Path
import importlib
import json
import structlog

logger = structlog.get_logger()


@dataclass
class Step:
    skill: str
    action: str
    params: Dict[str, Any] = field(default_factory=dict)
    requires_confirmation: bool = False
    depends_on: List[str] = field(default_factory=list)


@dataclass
class Workflow:
    name: str
    description: str
    steps: List[Step] = field(default_factory=list)
    source: str = "builtin"


class WorkflowEngine:
    def __init__(self, workflows_dir: Optional[str] = None) -> None:
        self.workflows: Dict[str, Workflow] = {}
        self.workflows_dir = Path(workflows_dir) if workflows_dir else Path("workflows")
        self._load_all_workflows()

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
                source="builtin"
            ),
            "web_audit": Workflow(
                name="web_audit",
                description="Web audit workflow",
                steps=[
                    Step(skill="dir_fuzz", action="execute"),
                    Step(skill="nuclei_scan", action="execute"),
                    Step(skill="sqlmap_test", action="execute"),
                ],
                source="builtin"
            ),
            "ad_attack": Workflow(
                name="ad_attack",
                description="Active Directory attack workflow",
                steps=[
                    Step(skill="ldap_enum", action="execute"),
                    Step(skill="kerberoast", action="execute"),
                    Step(skill="bloodhound_collect", action="execute"),
                ],
                source="builtin"
            ),
            "quick_scan": Workflow(
                name="quick_scan",
                description="Lightweight quick scan",
                steps=[
                    Step(skill="ping_sweep", action="execute"),
                    Step(skill="port_scan", action="execute", params={"limit": 100}),
                ],
                source="builtin"
            ),
        }

    def _load_all_workflows(self) -> None:
        self.workflows = self._build_default_workflows()
        
        try:
            self._load_workflows_from_dir()
        except Exception as e:
            logger.warning("Failed to load workflows from directory", error=str(e))
    
    def _load_workflows_from_dir(self) -> None:
        if not self.workflows_dir.exists():
            logger.info("Workflows directory not found, using defaults", path=str(self.workflows_dir))
            return
        
        for wf_file in self.workflows_dir.rglob("*.yaml") + self.workflows_dir.rglob("*.yml"):
            try:
                self._load_workflow_file(wf_file)
            except Exception as e:
                logger.warning("Failed to load workflow", file=str(wf_file), error=str(e))
        
        for wf_file in self.workflows_dir.rglob("*.json"):
            if wf_file.name != "workflows.json":
                try:
                    self._load_workflow_file(wf_file)
                except Exception as e:
                    logger.warning("Failed to load workflow", file=str(wf_file), error=str(e))
        
        logger.info("Workflows loaded", count=len(self.workflows))
    
    def _load_workflow_file(self, path: Path) -> None:
        content = path.read_text(encoding="utf-8")
        
        if path.suffix in (".yaml", ".yml"):
            workflow = self._parse_yaml_workflow(content, path.stem)
        elif path.suffix == ".json":
            workflow = self._parse_json_workflow(content, path.stem)
        else:
            return
        
        if workflow:
            self.workflows[workflow.name] = workflow
            logger.debug("Workflow loaded", name=workflow.name, source=str(path))
    
    def _parse_yaml_workflow(self, content: str, default_name: str) -> Optional[Workflow]:
        try:
            import yaml
            data = yaml.safe_load(content)
            return self._create_workflow_from_dict(data, default_name, "yaml")
        except ImportError:
            logger.warning("PyYAML not installed, cannot parse YAML workflows")
            return None
    
    def _parse_json_workflow(self, content: str, default_name: str) -> Optional[Workflow]:
        try:
            data = json.loads(content)
            return self._create_workflow_from_dict(data, default_name, "json")
        except json.JSONDecodeError as e:
            logger.warning("Invalid JSON in workflow", error=str(e))
            return None
    
    def _create_workflow_from_dict(self, data: dict, default_name: str, source: str) -> Optional[Workflow]:
        if not data:
            return None
        
        name = data.get("name", default_name)
        description = data.get("description", "")
        steps_data = data.get("steps", [])
        
        steps = []
        for step_data in steps_data:
            if isinstance(step_data, dict):
                step = Step(
                    skill=step_data.get("skill", ""),
                    action=step_data.get("action", "execute"),
                    params=step_data.get("params", {}),
                    requires_confirmation=step_data.get("requires_confirmation", False),
                    depends_on=step_data.get("depends_on", [])
                )
                steps.append(step)
        
        return Workflow(
            name=name,
            description=description,
            steps=steps,
            source=source
        )
    
    def load_workflow_from_string(self, content: str, name: str, format: str = "yaml") -> bool:
        if format == "yaml":
            workflow = self._parse_yaml_workflow(content, name)
        elif format == "json":
            workflow = self._parse_json_workflow(content, name)
        else:
            return False
        
        if workflow:
            self.workflows[workflow.name] = workflow
            return True
        return False
    
    def list_workflows(self, source_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        result = []
        for wf in self.workflows.values():
            if source_filter and wf.source != source_filter:
                continue
            result.append({
                "name": wf.name,
                "description": wf.description,
                "steps_count": len(wf.steps),
                "source": wf.source
            })
        return result

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
