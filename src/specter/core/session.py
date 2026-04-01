"""SPECTER Session Management"""

from datetime import datetime
from typing import Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import uuid
import json
from pathlib import Path
from specter.core.permissions import PermissionLevel


class Role(Enum):
    """Roles del operador SPECTER"""
    PENTESTER = "pentester"
    RED_TEAMER = "red-teamer"
    BLUE_TEAMER = "blue-teamer"
    CTF_PLAYER = "ctf-player"
    FORENSIC_ANALYST = "forensic-analyst"
    DEFAULT = "default"


@dataclass
class Finding:
    """Representa un hallazgo de seguridad"""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    title: str = ""
    description: str = ""
    severity: str = "INFO"  # CRIT, HIGH, MED, LOW, INFO
    cvss: Optional[float] = None
    tool: Optional[str] = None
    target: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    evidence: list[str] = field(default_factory=list)
    
    def __str__(self) -> str:
        return f"[{self.severity}] {self.title}"


@dataclass
class ScopeEntry:
    """Entrada en el scope de la operación"""
    target: str
    type: str = "ip"  # ip, domain, cidr, url
    added_at: datetime = field(default_factory=datetime.now)
    notes: str = ""


@dataclass
class Session:
    """Sesión de trabajo de SPECTER"""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = "default"
    created_at: datetime = field(default_factory=datetime.now)
    role: Optional[Role] = None
    scope: list[ScopeEntry] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    current_skill: Optional[str] = None
    log: list[dict[str, Any]] = field(default_factory=list)
    permission_level: PermissionLevel = field(default_factory=lambda: PermissionLevel.OBSERVATION)

    # ── Memoria conversacional para el LLM ─────────────────────────────────────
    # Cada entrada: {"role": "user" | "assistant", "content": "..."}
    conversation_history: list[dict[str, str]] = field(default_factory=list)

    # Tamaño máximo del historial (en mensajes), para no saturar el contexto
    MAX_HISTORY: int = field(default=20, init=False, repr=False)

    # Context para el LLM
    context: dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        from specter.core.config import SpecterConfig
        self.config = SpecterConfig()
    
    def set_config(self, config: "SpecterConfig") -> None:
        """Establece la configuración"""
        self.config = config
    
    def add_finding(self, finding: Finding) -> None:
        """Añade un hallazgo a la sesión"""
        self.findings.append(finding)
        self._log_action("finding_added", {"finding_id": finding.id})
    
    def add_to_scope(self, target: str, target_type: str = "ip", notes: str = "") -> None:
        """Añade un objetivo al scope"""
        entry = ScopeEntry(target=target, type=target_type, notes=notes)
        self.scope.append(entry)
        self._log_action("scope_added", {"target": target, "type": target_type})

    def is_in_scope(self, target: str) -> bool:
        """Verifica si un objetivo está en el scope"""
        return any(entry.target == target for entry in self.scope)

    def set_role(self, role: Role) -> None:
        """Establece el rol del operador"""
        self.role = role
        self._log_action("role_changed", {"role": role.value})

    # ── Memoria conversacional ────────────────────────────────────────────────

    def add_message(self, role: str, content: str) -> None:
        """Añade un mensaje al historial de conversación.

        role: 'user' | 'assistant'
        Trunca el historial si supera MAX_HISTORY para evitar saturar el contexto.
        """
        self.conversation_history.append({"role": role, "content": content})
        if len(self.conversation_history) > self.MAX_HISTORY:
            # Keep always the first message as anchor, drop oldest middle ones
            self.conversation_history = self.conversation_history[-self.MAX_HISTORY:]

    def build_conversation_prompt(self) -> str:
        """Construye el contexto conversacional como string para añadir al system prompt."""
        if not self.conversation_history:
            return ""
        lines = ["\n\n## Historial de conversación reciente"]
        for msg in self.conversation_history[-10:]:  # last 10 for context
            prefix = "Usuario" if msg["role"] == "user" else "SPECTER"
            lines.append(f"  [{prefix}]: {msg['content'][:500]}")
        return "\n".join(lines)

    # ── Scope para el LLM ────────────────────────────────────────────────────

    def get_scope_summary(self) -> str:
        """Devuelve el scope formateado para incluir en el system prompt."""
        if not self.scope:
            return ""
        targets = ", ".join(e.target for e in self.scope)
        return (
            f"\n\n## Scope de la operación\n"
            f"Objetivos autorizados: {targets}\n"
            f"IMPORTANTE: Solo propones acciones contra estos objetivos. "
            f"Rechazas cualquier acción fuera de este scope."
        )

    # ── Persistencia de hallazgos ────────────────────────────────────────────

    def save_findings(self, sessions_dir: str = "sessions") -> Path:
        """Guarda los hallazgos en disco como JSON."""
        path = Path(sessions_dir) / self.id
        path.mkdir(parents=True, exist_ok=True)
        findings_file = path / "findings.json"
        data = [
            {
                "id": f.id,
                "title": f.title,
                "description": f.description,
                "severity": f.severity,
                "cvss": f.cvss,
                "tool": f.tool,
                "target": f.target,
                "timestamp": f.timestamp.isoformat(),
                "evidence": f.evidence,
            }
            for f in self.findings
        ]
        findings_file.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        return findings_file

    def load_findings(self, sessions_dir: str = "sessions") -> int:
        """Carga hallazgos desde disco. Retorna el número cargado."""
        path = Path(sessions_dir) / self.id / "findings.json"
        if not path.exists():
            return 0
        data = json.loads(path.read_text())
        loaded = 0
        existing_ids = {f.id for f in self.findings}
        for item in data:
            if item["id"] not in existing_ids:
                self.findings.append(Finding(
                    id=item["id"],
                    title=item["title"],
                    description=item.get("description", ""),
                    severity=item.get("severity", "INFO"),
                    cvss=item.get("cvss"),
                    tool=item.get("tool"),
                    target=item.get("target"),
                    timestamp=datetime.fromisoformat(item["timestamp"]),
                    evidence=item.get("evidence", []),
                ))
                loaded += 1
        return loaded

    def _log_action(self, action: str, data: dict[str, Any]) -> None:
        """Registra una acción en el log de auditoría"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "data": data,
            "session_id": self.id,
        }
        self.log.append(entry)

    @property
    def duration(self) -> str:
        """Duración de la sesión"""
        delta = datetime.now() - self.created_at
        hours, remainder = divmod(int(delta.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    @property
    def findings_count(self) -> dict[str, int]:
        """Cuenta de hallazgos por severidad"""
        counts = {"CRIT": 0, "HIGH": 0, "MED": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            if f.severity in counts:
                counts[f.severity] += 1
        return counts

    def generate_session_report(self) -> str:
        """Genera un reporte de texto de la sesión usando datos reales"""
        lines = [
            "# SP ECTER - Session Report",
            "",
            f"**Session ID:** `{self.id}`",
            f"**Name:** {self.name}",
            f"**Created:** {self.created_at.strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Duration:** {self.duration}",
            f"**Role:** {self.role.value if self.role else 'None'}",
            "",
            "---",
            "",
            "## Scope",
            "",
        ]

        if self.scope:
            for entry in self.scope:
                lines.append(f"- **{entry.type.upper()}**: `{entry.target}`")
        else:
            lines.append("_No scope defined_")

        lines.extend([
            "",
            "---",
            "",
            "## Findings Summary",
            "",
            f"| Severity | Count |",
            f"|---|---|",
            f"| CRIT | {self.findings_count['CRIT']} |",
            f"| HIGH | {self.findings_count['HIGH']} |",
            f"| MED | {self.findings_count['MED']} |",
            f"| LOW | {self.findings_count['LOW']} |",
            f"| INFO | {self.findings_count['INFO']} |",
            "",
            f"**Total Findings:** {len(self.findings)}",
            "",
            "---",
            "",
            "## Detailed Findings",
            "",
        ])

        if self.findings:
            for i, f in enumerate(self.findings, 1):
                lines.extend([
                    f"### {i}. [{f.severity}] {f.title}",
                    "",
                    f"- **ID:** `{f.id}`",
                    f"- **Tool:** {f.tool or 'N/A'}",
                    f"- **Target:** {f.target or 'N/A'}",
                    f"- **CVSS:** {f.cvss if f.cvss else 'N/A'}",
                    f"- **Timestamp:** {f.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
                    "",
                ])
                if f.description:
                    lines.extend([f"**Description:** {f.description}", ""])
                if f.evidence:
                    lines.append("**Evidence:**")
                    for ev in f.evidence:
                        lines.append(f"- {ev}")
                    lines.append("")
        else:
            lines.append("_No findings in this session_")

        lines.extend([
            "---",
            "",
            "*Report generated by SPECTER AI-Powered Security Terminal*",
        ])

        return "\n".join(lines)


# (Permissions integration is handled via Session.permission_level in the dataclass)
