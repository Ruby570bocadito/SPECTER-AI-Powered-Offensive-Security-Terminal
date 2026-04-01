"""Agent Orchestrator con Sub-Agentes para tareas paralelas"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Optional, Callable
from enum import Enum
import asyncio
import time
import structlog
import platform
import subprocess
import shutil
import re

logger = structlog.get_logger()


class AgentStatus(Enum):
    IDLE = "idle"
    THINKING = "thinking"
    EXECUTING = "executing"
    WAITING = "waiting"
    DONE = "done"
    ERROR = "error"
    CANCELLED = "cancelled"


class AgentRole(Enum):
    ORCHESTRATOR = "orchestrator"
    RECON = "recon"
    EXPLOIT = "exploit"
    ANALYST = "analyst"
    REPORTER = "reporter"
    COORDINATOR = "coordinator"


@dataclass
class AgentMessage:
    from_agent: str
    to_agent: Optional[str]
    content: Any
    message_type: str
    timestamp: float = field(default_factory=time.time)


@dataclass
class AgentTask:
    id: str
    description: str
    agent_role: AgentRole
    status: AgentStatus = AgentStatus.IDLE
    result: Any = None
    error: Optional[str] = None
    dependencies: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None


async def _run_cmd(cmd: list[str] | str, timeout: int = 120) -> tuple[str, str, int]:
    """Ejecuta un comando de shell y retorna (stdout, stderr, returncode)."""
    try:
        if platform.system() == "Windows":
            shell_args = ["cmd.exe", "/c", cmd] if isinstance(cmd, str) else cmd
        else:
            shell_args = ["/bin/sh", "-c", cmd] if isinstance(cmd, str) else cmd

        proc = await asyncio.create_subprocess_exec(
            *shell_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        stdout = stdout_bytes.decode("utf-8", errors="replace").strip()
        stderr = stderr_bytes.decode("utf-8", errors="replace").strip()
        return stdout, stderr, proc.returncode
    except asyncio.TimeoutError:
        return "", f"Timeout after {timeout}s", -1
    except FileNotFoundError:
        tool = shell_args[0] if shell_args else "unknown"
        return "", f"Tool not found: {tool}", -1
    except Exception as exc:
        return "", f"Error executing command: {exc}", -1


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


class BaseAgent:
    """Clase base para agentes con ejecución real de comandos"""

    def __init__(self, agent_id: str, name: str, role: AgentRole):
        self.id = agent_id
        self.name = name
        self.role = role
        self.status = AgentStatus.IDLE
        self._running = False
        self.message_queue: list[AgentMessage] = []
        self.memory: dict = {}
        self._cmd_executor: Optional[Callable] = None

    def set_cmd_executor(self, executor: Callable) -> None:
        """Set the command executor function"""
        self._cmd_executor = executor

    async def _execute_command(self, cmd: list[str] | str, timeout: int = 120) -> tuple[str, str, int]:
        """Execute a command using the configured executor or fallback to _run_cmd"""
        if self._cmd_executor:
            if asyncio.iscoroutinefunction(self._cmd_executor):
                return await self._cmd_executor(cmd, timeout)
            return self._cmd_executor(cmd, timeout)
        return await _run_cmd(cmd, timeout)

    async def think(self, context: dict) -> str:
        return f"{self.name} thinking about task: {context.get('task_description', 'unknown')}"

    async def execute(self, task: AgentTask) -> dict:
        self.status = AgentStatus.EXECUTING
        try:
            result = await self._execute_task(task)
            self.status = AgentStatus.DONE
            return {"success": True, "result": result}
        except Exception as e:
            self.status = AgentStatus.ERROR
            return {"success": False, "error": str(e)}

    async def _execute_task(self, task: AgentTask) -> Any:
        raise NotImplementedError

    def receive_message(self, message: AgentMessage) -> None:
        self.message_queue.append(message)

    def can_handle(self, task: AgentTask) -> bool:
        return task.agent_role == self.role or any(
            cap in task.description.lower() for cap in getattr(self, 'capabilities', [])
        )


class ReconAgent(BaseAgent):
    """Agente especializado en reconocimiento con ejecución real"""

    def __init__(self, agent_id: str = "recon_1"):
        super().__init__(agent_id, "Recon Agent", AgentRole.RECON)
        self.capabilities = ["scan", "recon", "nmap", "enum", "discover", "ping", "dns", "subdomain"]

    async def _execute_task(self, task: AgentTask) -> Any:
        desc = task.description.lower()
        results: dict[str, Any] = {"commands_executed": [], "findings": []}

        targets = self._extract_targets(task.description)
        if not targets:
            return {"error": "No target specified in task description"}

        target = targets[0]

        # Port scanning
        if any(kw in desc for kw in ["port", "scan", "nmap", "puerto"]):
            if _tool_available("nmap"):
                cmd = ["nmap", "-sV", "-T4", "--top-ports", "1000", "-oG", "-", target]
                stdout, stderr, rc = await self._execute_command(cmd, timeout=180)
                results["commands_executed"].append({"tool": "nmap", "cmd": " ".join(cmd), "returncode": rc})
                if rc == 0:
                    results["findings"].extend(self._parse_nmap_output(stdout, target))
                else:
                    results["findings"].append({"type": "error", "tool": "nmap", "detail": stderr})

        # Host discovery
        if any(kw in desc for kw in ["ping", "host", "discover", "live", "sweep"]):
            if _tool_available("nmap"):
                cmd = ["nmap", "-sn", target]
                stdout, stderr, rc = await self._execute_command(cmd, timeout=60)
                results["commands_executed"].append({"tool": "nmap-ping", "cmd": " ".join(cmd), "returncode": rc})
                if rc == 0:
                    hosts = [l for l in stdout.split("\n") if "Nmap scan report" in l or "Host is up" in l]
                    results["findings"].append({"type": "host_discovery", "hosts": hosts})

        # DNS enumeration
        if any(kw in desc for kw in ["dns", "subdomain", "domain", "record"]):
            for tool_name, tool_cmd in [
                ("dig", ["dig", "+short", "ANY", target]),
                ("nslookup", ["nslookup", target]),
            ]:
                if _tool_available(tool_name):
                    stdout, stderr, rc = await self._execute_command(tool_cmd, timeout=30)
                    results["commands_executed"].append({"tool": tool_name, "returncode": rc})
                    if rc == 0 and stdout:
                        results["findings"].append({"type": "dns_records", "tool": tool_name, "data": stdout[:2000]})

        # Subdomain enumeration
        if any(kw in desc for kw in ["subdomain", "subfinder", "amass"]):
            for tool_name, tool_cmd in [
                ("subfinder", ["subfinder", "-d", target, "-silent"]),
                ("amass", ["amass", "enum", "-d", target, "-passive"]),
            ]:
                if _tool_available(tool_name):
                    stdout, stderr, rc = await self._execute_command(tool_cmd, timeout=120)
                    results["commands_executed"].append({"tool": tool_name, "returncode": rc})
                    if rc == 0 and stdout:
                        subs = [l.strip() for l in stdout.split("\n") if l.strip()]
                        results["findings"].append({"type": "subdomains", "tool": tool_name, "count": len(subs), "data": "\n".join(subs[:50])})

        # Service enumeration
        if any(kw in desc for kw in ["service", "version", "banner"]):
            if _tool_available("nmap"):
                cmd = ["nmap", "-sV", "--version-intensity", "5", "-T4", target]
                stdout, stderr, rc = await self._execute_command(cmd, timeout=300)
                results["commands_executed"].append({"tool": "nmap-service", "returncode": rc})
                if rc == 0:
                    results["findings"].extend(self._parse_nmap_output(stdout, target))

        # OS fingerprinting
        if any(kw in desc for kw in ["os", "fingerprint", "sistema operativo"]):
            if _tool_available("nmap"):
                cmd = ["nmap", "-O", "--osscan-guess", target]
                stdout, stderr, rc = await self._execute_command(cmd, timeout=120)
                results["commands_executed"].append({"tool": "nmap-os", "returncode": rc})
                if rc == 0:
                    os_lines = [l.strip() for l in stdout.split("\n") if "OS:" in l or "OS details" in l or "Running:" in l]
                    results["findings"].append({"type": "os_detection", "data": "\n".join(os_lines)})

        # Default: basic nmap if nothing matched
        if not results["commands_executed"]:
            if _tool_available("nmap"):
                cmd = ["nmap", "-sV", "-T4", target]
                stdout, stderr, rc = await self._execute_command(cmd, timeout=180)
                results["commands_executed"].append({"tool": "nmap", "returncode": rc})
                if rc == 0:
                    results["findings"].extend(self._parse_nmap_output(stdout, target))

        return results

    def _parse_nmap_output(self, output: str, target: str) -> list[dict]:
        findings = []
        for line in output.split("\n"):
            if ("/tcp" in line or "/udp" in line) and "open" in line.lower():
                parts = line.split()
                if len(parts) >= 3:
                    port = parts[0].split("/")[0]
                    service = parts[2] if len(parts) > 2 else "unknown"
                    version = " ".join(parts[3:]) if len(parts) > 3 else ""
                    findings.append({
                        "type": "open_port", "target": target,
                        "port": port, "service": service, "version": version,
                        "severity": "INFO"
                    })
        return findings

    def _extract_targets(self, description: str) -> list[str]:
        patterns = [
            r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b",
            r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
        ]
        targets = []
        for pattern in patterns:
            targets.extend(re.findall(pattern, description))
        return list(set(targets))


class ExploitAgent(BaseAgent):
    """Agente especializado en explotación con ejecución real"""

    def __init__(self, agent_id: str = "exploit_1"):
        super().__init__(agent_id, "Exploit Agent", AgentRole.EXPLOIT)
        self.capabilities = ["exploit", "shell", "payload", "access", "vuln", "attack"]

    async def _execute_task(self, task: AgentTask) -> Any:
        desc = task.description.lower()
        results: dict[str, Any] = {"commands_executed": [], "findings": []}
        targets = self._extract_targets(task.description)
        target = targets[0] if targets else None

        if not target:
            return {"error": "No target specified"}

        # Search for exploits
        if any(kw in desc for kw in ["exploit", "search", "cve", "vulnerability"]):
            if _tool_available("searchsploit"):
                search_terms = target if "/" not in target else target.split("/")[-1]
                cmd = ["searchsploit", search_terms]
                stdout, stderr, rc = await self._execute_command(cmd, timeout=30)
                results["commands_executed"].append({"tool": "searchsploit", "returncode": rc})
                if rc == 0 and stdout:
                    exploits = [l.strip() for l in stdout.split("\n") if "|" in l and "Exploit" not in l.split("|")[0]]
                    results["findings"].append({"type": "exploits_found", "count": len(exploits), "data": "\n".join(exploits[:20])})

        # SQL injection testing
        if any(kw in desc for kw in ["sql", "sqli", "injection", "sqlmap"]):
            if _tool_available("sqlmap"):
                url = target if target.startswith("http") else f"http://{target}"
                cmd = ["sqlmap", "-u", url, "--batch", "--risk=1", "--level=2", "--dbs"]
                stdout, stderr, rc = await self._execute_command(cmd, timeout=300)
                results["commands_executed"].append({"tool": "sqlmap", "returncode": rc})
                if "vulnerable" in stdout.lower() or "injection" in stdout.lower():
                    results["findings"].append({"type": "sqli_found", "target": url, "severity": "CRIT", "detail": stdout[:2000]})

        # Nuclei vulnerability scanning
        if any(kw in desc for kw in ["nuclei", "vuln", "vulnerability", "template"]):
            if _tool_available("nuclei"):
                url = target if target.startswith("http") else f"http://{target}"
                cmd = ["nuclei", "-u", url, "-severity", "critical,high,medium", "-silent"]
                stdout, stderr, rc = await self._execute_command(cmd, timeout=300)
                results["commands_executed"].append({"tool": "nuclei", "returncode": rc})
                if rc == 0 and stdout:
                    vulns = [l.strip() for l in stdout.split("\n") if l.strip()]
                    results["findings"].append({"type": "nuclei_vulns", "count": len(vulns), "data": "\n".join(vulns[:30])})

        # Metasploit checks
        if any(kw in desc for kw in ["metasploit", "msf", "msfconsole"]):
            if _tool_available("msfconsole"):
                cmd_str = f"msfconsole -q -x 'search {target}; exit'"
                stdout, stderr, rc = await self._execute_command(cmd_str, timeout=60)
                results["commands_executed"].append({"tool": "msfconsole", "returncode": rc})
                if rc == 0 and stdout:
                    results["findings"].append({"type": "msf_modules", "data": stdout[:2000]})

        # Default: searchsploit if nothing matched
        if not results["commands_executed"]:
            if _tool_available("searchsploit"):
                cmd = ["searchsploit", target]
                stdout, stderr, rc = await self._execute_command(cmd, timeout=30)
                results["commands_executed"].append({"tool": "searchsploit", "returncode": rc})

        return results

    def _extract_targets(self, description: str) -> list[str]:
        patterns = [
            r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b",
            r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
            r"https?://[^\s]+",
        ]
        targets = []
        for pattern in patterns:
            targets.extend(re.findall(pattern, description))
        return list(set(targets))


class AnalystAgent(BaseAgent):
    """Agente especializado en análisis de resultados"""

    def __init__(self, agent_id: str = "analyst_1"):
        super().__init__(agent_id, "Analyst Agent", AgentRole.ANALYST)
        self.capabilities = ["analyze", "analyse", "parse", "interpret", "correlate", "risk"]

    async def _execute_task(self, task: AgentTask) -> Any:
        desc = task.description.lower()
        results: dict[str, Any] = {"analysis": {}, "risk_assessment": {}, "recommendations": []}

        if any(kw in desc for kw in ["scan", "result", "output", "analyze", "analisis"]):
            scan_data = self._extract_data_section(task.description)

            if scan_data:
                results["analysis"] = {
                    "total_lines": len(scan_data.split("\n")),
                    "open_ports": self._count_pattern(scan_data, r"\bopen\b"),
                    "services": self._extract_services(scan_data),
                    "potential_vulns": self._count_pattern(scan_data, r"CVE-|VULN|vulnerab"),
                }

                if results["analysis"]["open_ports"] > 10:
                    results["risk_assessment"]["attack_surface"] = "LARGE"
                    results["recommendations"].append("Reduce attack surface by closing unnecessary ports")
                elif results["analysis"]["open_ports"] > 5:
                    results["risk_assessment"]["attack_surface"] = "MEDIUM"
                    results["recommendations"].append("Review exposed services for necessity")
                else:
                    results["risk_assessment"]["attack_surface"] = "SMALL"

                if results["analysis"]["potential_vulns"] > 0:
                    results["risk_assessment"]["vulnerability_risk"] = "HIGH"
                    results["recommendations"].append("Prioritize CVE remediation")

        if any(kw in desc for kw in ["correlate", "correlation", "relate"]):
            results["analysis"]["correlation"] = "Cross-referencing findings..."
            results["recommendations"].append("Review correlated findings for attack chains")

        return results

    def _count_pattern(self, text: str, pattern: str) -> int:
        return len(re.findall(pattern, text, re.IGNORECASE))

    def _extract_services(self, text: str) -> list[str]:
        services = []
        for line in text.split("\n"):
            if "/tcp" in line or "/udp" in line:
                parts = line.split()
                if len(parts) >= 3:
                    services.append(f"{parts[0]}: {parts[2]}")
        return services[:20]

    def _extract_data_section(self, description: str) -> str:
        match = re.search(r"data:\s*\n(.+?)(?:\n\n|$)", description, re.DOTALL)
        if match:
            return match.group(1)
        return description


class ReporterAgent(BaseAgent):
    """Agente especializado en generación de reportes"""

    def __init__(self, agent_id: str = "reporter_1"):
        super().__init__(agent_id, "Reporter Agent", AgentRole.REPORTER)
        self.capabilities = ["report", "document", "export", "summary", "markdown", "html"]

    async def _execute_task(self, task: AgentTask) -> Any:
        findings_data = self._extract_findings(task.description)

        return {
            "title": "SPECTER Security Assessment Report",
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "executive_summary": self._generate_executive_summary(findings_data),
            "findings": findings_data,
            "markdown": self._generate_markdown_report(findings_data),
        }

    def _generate_executive_summary(self, findings: list[dict]) -> str:
        if not findings:
            return "No findings to report. The assessment did not identify any security issues."

        total = len(findings)
        critical = sum(1 for f in findings if f.get("severity", "").upper() in ("CRIT", "CRITICAL"))
        high = sum(1 for f in findings if f.get("severity", "").upper() == "HIGH")

        summary = f"Assessment identified {total} findings."
        if critical > 0:
            summary += f" {critical} critical severity findings require immediate attention."
        if high > 0:
            summary += f" {high} high severity findings should be addressed promptly."
        return summary

    def _generate_markdown_report(self, findings: list[dict]) -> str:
        lines = [
            "# SPECTER Security Assessment Report",
            f"\n**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n",
            "## Executive Summary",
            self._generate_executive_summary(findings),
            "\n## Findings\n",
        ]

        for i, f in enumerate(findings, 1):
            severity = f.get("severity", "INFO").upper()
            lines.append(f"### {i}. [{severity}] {f.get('type', 'Finding')}")
            if f.get("target"):
                lines.append(f"- **Target:** {f['target']}")
            if f.get("detail"):
                lines.append(f"- **Detail:** {f['detail'][:500]}")
            lines.append("")

        return "\n".join(lines)

    def _extract_findings(self, description: str) -> list[dict]:
        import json
        match = re.search(r'(\[.*?\])', description, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass
        return [{"type": "assessment", "detail": description[:500], "severity": "INFO"}]


class AgentOrchestrator:
    """Orquestador principal de agentes con ejecución real"""

    def __init__(self, cmd_executor: Optional[Callable] = None):
        self.agents: dict[str, BaseAgent] = {}
        self.tasks: dict[str, AgentTask] = {}
        self.task_queue: asyncio.Queue = asyncio.Queue()
        self.results: dict[str, Any] = {}
        self.message_history: list[AgentMessage] = []
        self._running = False
        self._cmd_executor = cmd_executor
        self._agent_factory: dict[AgentRole, type] = {
            AgentRole.RECON: ReconAgent,
            AgentRole.EXPLOIT: ExploitAgent,
            AgentRole.ANALYST: AnalystAgent,
            AgentRole.REPORTER: ReporterAgent,
        }

    def set_cmd_executor(self, executor: Callable) -> None:
        """Set command executor for all agents"""
        self._cmd_executor = executor
        for agent in self.agents.values():
            agent.set_cmd_executor(executor)

    def register_agent(self, agent: BaseAgent) -> None:
        self.agents[agent.id] = agent
        if self._cmd_executor:
            agent.set_cmd_executor(self._cmd_executor)
        logger.info("Agent registered", agent_id=agent.id, role=agent.role.value)

    def create_agent(self, role: AgentRole, agent_id: str = None) -> BaseAgent:
        if agent_id is None:
            agent_id = f"{role.value}_{len([a for a in self.agents.values() if a.role == role])}"

        agent_class = self._agent_factory.get(role)
        if not agent_class:
            raise ValueError(f"No factory for role {role}")

        agent = agent_class(agent_id)
        if self._cmd_executor:
            agent.set_cmd_executor(self._cmd_executor)
        self.register_agent(agent)
        return agent

    def add_task(self, task: AgentTask) -> str:
        self.tasks[task.id] = task
        logger.info("Task added", task_id=task.id, role=task.agent_role.value)
        return task.id

    async def execute_task(self, task: AgentTask) -> dict:
        agent = self._find_available_agent(task)

        if not agent:
            agent = self.create_agent(task.agent_role)

        agent.status = AgentStatus.THINKING
        await agent.think({"task": task})

        agent.status = AgentStatus.EXECUTING
        result = await agent.execute(task)

        task.result = result
        task.status = AgentStatus.DONE if result.get("success") else AgentStatus.ERROR
        task.completed_at = time.time()

        self.results[task.id] = result

        return result

    def _find_available_agent(self, task: AgentTask) -> Optional[BaseAgent]:
        for agent in self.agents.values():
            if agent.can_handle(task) and agent.status in [AgentStatus.IDLE, AgentStatus.DONE]:
                return agent
        return None

    async def execute_parallel(self, tasks: list[AgentTask]) -> dict[str, dict]:
        async def run_task(t: AgentTask) -> tuple[str, dict]:
            result = await self.execute_task(t)
            return t.id, result

        results = await asyncio.gather(
            *[run_task(t) for t in tasks],
            return_exceptions=True
        )

        return {r[0]: r[1] for r in results if not isinstance(r, Exception)}

    async def execute_sequential(self, tasks: list[AgentTask]) -> dict[str, dict]:
        results = {}
        for task in tasks:
            if not self._check_dependencies(task):
                results[task.id] = {"success": False, "error": "Dependencies not met"}
                continue

            result = await self.execute_task(task)
            results[task.id] = result

            if not result.get("success"):
                break

        return results

    def _check_dependencies(self, task: AgentTask) -> bool:
        for dep_id in task.dependencies:
            if dep_id in self.tasks:
                dep_task = self.tasks[dep_id]
                if dep_task.status != AgentStatus.DONE:
                    return False
        return True

    async def orchestrate(self, workflow: list[dict]) -> dict:
        tasks = []
        for w in workflow:
            task = AgentTask(
                id=w.get("id", f"task_{len(tasks)}"),
                description=w.get("description", ""),
                agent_role=AgentRole[w.get("role", "RECON").upper()],
                dependencies=w.get("depends_on", [])
            )
            tasks.append(task)
            self.add_task(task)

        mode = "parallel" if workflow[0].get("mode") == "parallel" else "sequential"

        if mode == "parallel":
            return await self.execute_parallel(tasks)
        else:
            return await self.execute_sequential(tasks)

    def get_status(self) -> dict:
        return {
            "total_agents": len(self.agents),
            "total_tasks": len(self.tasks),
            "active_agents": sum(1 for a in self.agents.values() if a.status == AgentStatus.EXECUTING),
            "pending_tasks": sum(1 for t in self.tasks.values() if t.status in [AgentStatus.IDLE, AgentStatus.THINKING]),
            "completed_tasks": sum(1 for t in self.tasks.values() if t.status == AgentStatus.DONE),
            "agents": {
                agent.id: {
                    "role": agent.role.value,
                    "status": agent.status.value
                }
                for agent in self.agents.values()
            }
        }

    async def deploy_task(self, description: str, context: dict) -> str:
        """Despliega una tarea al orquestador"""
        role = self._infer_role_from_description(description)

        task = AgentTask(
            id=f"task_{int(time.time())}",
            description=description,
            agent_role=role
        )

        self.add_task(task)
        asyncio.create_task(self.execute_task(task))

        return task.id

    def get_task_status(self, task_id: str) -> dict:
        task = self.tasks.get(task_id)
        if not task:
            return {"status": "not_found"}

        return {
            "id": task.id,
            "description": task.description,
            "status": task.status.value,
            "result": task.result,
            "error": task.error
        }

    def _infer_role_from_description(self, description: str) -> AgentRole:
        desc = description.lower()

        if any(kw in desc for kw in ["recon", "scan", "enum", "port", "host", "descubrir"]):
            return AgentRole.RECON
        elif any(kw in desc for kw in ["exploit", "attack", "vuln", "test"]):
            return AgentRole.EXPLOIT
        elif any(kw in desc for kw in ["report", "document", "informe"]):
            return AgentRole.REPORTER
        elif any(kw in desc for kw in ["analyze", "analisis", "analizar"]):
            return AgentRole.ANALYST
        else:
            return AgentRole.RECON

    def list_agents(self) -> list[dict]:
        return [
            {
                "name": agent.name,
                "role": agent.role.value,
                "status": agent.status.value,
                "id": agent.id
            }
            for agent in self.agents.values()
        ]

    def cancel_all(self) -> None:
        for agent in self.agents.values():
            agent.status = AgentStatus.CANCELLED
        self._running = False


class SmartOrchestrator(AgentOrchestrator):
    """Orquestador inteligente que puede crear agentes según necesidad"""

    def __init__(self, cmd_executor: Optional[Callable] = None):
        super().__init__(cmd_executor=cmd_executor)
        self.max_agents_per_role = 3
        self.task_history: list[dict] = []

    async def smart_orchestrate(self, objective: str, context: dict) -> dict:
        decomposed = await self._decompose_task(objective)

        tasks = []
        for i, subtask in enumerate(decomposed):
            role = self._infer_role(subtask)
            task = AgentTask(
                id=f"smart_task_{i}",
                description=subtask,
                agent_role=role
            )
            tasks.append(task)

        results = await self.execute_parallel(tasks)

        synthesis = await self._synthesize_results(results)

        self.task_history.append({
            "objective": objective,
            "tasks": len(tasks),
            "results": results,
            "synthesis": synthesis
        })

        return {
            "objective": objective,
            "tasks_executed": len(tasks),
            "results": results,
            "final_report": synthesis
        }

    async def _decompose_task(self, objective: str) -> list[str]:
        subtasks = []

        if any(kw in objective.lower() for kw in ["scan", "recon", "enum"]):
            subtasks.append("Realizar reconocimiento de puertos y servicios")
            subtasks.append("Enumerar vulnerabilidades encontradas")

        if any(kw in objective.lower() for kw in ["exploit", "attack", "test"]):
            subtasks.append("Intentar explotación de vulnerabilidades")
            subtasks.append("Verificar acceso obtenido")

        if any(kw in objective.lower() for kw in ["analyze", "analisis"]):
            subtasks.append("Analizar resultados de reconocimiento")

        if any(kw in objective.lower() for kw in ["report", "informe"]):
            subtasks.append("Generar reporte final")

        if not subtasks:
            subtasks = [f"Ejecutar: {objective}"]

        return subtasks

    def _infer_role(self, task_description: str) -> AgentRole:
        desc = task_description.lower()

        if any(kw in desc for kw in ["recon", "scan", "enum", "port", "host"]):
            return AgentRole.RECON
        elif any(kw in desc for kw in ["exploit", "attack", "vuln"]):
            return AgentRole.EXPLOIT
        elif any(kw in desc for kw in ["report", "document"]):
            return AgentRole.REPORTER
        else:
            return AgentRole.ANALYST

    async def _synthesize_results(self, results: dict) -> str:
        if not results:
            return "No results to synthesize"

        success_count = sum(1 for r in results.values() if r.get("success"))
        total = len(results)

        synthesis = f"Se ejecutaron {total} tareas, {success_count} exitosas.\n\n"

        for task_id, result in results.items():
            if result.get("success"):
                synthesis += f"- {task_id}: Exitoso\n"
            else:
                synthesis += f"- {task_id}: Fallido ({result.get('error', 'Unknown')})\n"

        return synthesis
