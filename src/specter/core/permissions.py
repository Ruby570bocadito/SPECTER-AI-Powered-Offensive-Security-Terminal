from __future__ import annotations

import json
import os
import sys
import datetime
from enum import Enum
from typing import Optional, Any, Dict, Set

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Confirm
from rich import box


class PermissionLevel(Enum):
    OBSERVATION = 0  # view/read-only, no action
    ACTIVE = 1       # allow simple confirmations
    INTRUSIVE = 2    # require explicit confirmation with impact description


class PermissionManager:
    """Robust permission manager with Rich UI, tool trust lists and history.

    Features:
    - confirm_interactive(tool_name, risk_level, description, role=None) -> bool
    - is_trusted_tool(tool_name, role=None) -> bool
    - add_to_whitelist(tool_name, role=None)
    - add_to_blacklist(tool_name, role=None)
    - confirmation_required property
    - warn/deny history for non-allowed attempts
    """

    def __init__(self, current_level: PermissionLevel = PermissionLevel.OBSERVATION,
                 log_path: Optional[str] = None) -> None:
        self.current_level = current_level
        # Logs for permission decisions
        if log_path:
            self.log_path = log_path
        else:
            base = os.path.join(os.path.dirname(__file__), "..", "..", "logs")
            self.log_path = os.path.abspath(os.path.join(base, "permissions.log"))
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)

        # Simple in-memory history; could be extended to disk-backed
        self.denied_history: list[Dict[str, Any]] = []

        # Global and per-role lists
        self.whitelist: Set[str] = set()
        self.blacklist: Set[str] = set()
        self.role_whitelist: Dict[str, Set[str]] = {}
        self.role_blacklist: Dict[str, Set[str]] = {}

        # Rich console for UI
        self.console = Console()

    # --- Basic helpers ---
    def _log(self, text: str) -> None:
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(text + "\n")
        except Exception:
            pass

    def _log_event(self, event: Dict[str, Any]) -> None:
        self._log(json.dumps(event, ensure_ascii=False))

    # --- Public API ---
    @property
    def confirmation_required(self) -> bool:
        return self.current_level != PermissionLevel.OBSERVATION

    def is_trusted_tool(self, tool_name: str, role: Optional[str] = None) -> bool:
        if tool_name in self.whitelist:
            return True
        if role:
            whitelist = self.role_whitelist.get(role, set())
            if tool_name in whitelist:
                return True
            blacklist = self.role_blacklist.get(role, set())
            if tool_name in blacklist:
                return False
        # If not whitelisted globally, not trusted
        return False

    def add_to_whitelist(self, tool_name: str, role: Optional[str] = None) -> None:
        if role:
            self.role_whitelist.setdefault(role, set()).add(tool_name)
        else:
            self.whitelist.add(tool_name)

    def add_to_blacklist(self, tool_name: str, role: Optional[str] = None) -> None:
        if role:
            self.role_blacklist.setdefault(role, set()).add(tool_name)
        else:
            self.blacklist.add(tool_name)

    def confirm_interactive(self, tool_name: str, risk_level: int, description: str, role: Optional[str] = None) -> bool:
        """Display a Rich panel requesting confirmation for a given tool.

        - If the tool is globally or role-wise whitelisted, auto-approve.
        - If the tool is blacklisted for the role, auto-deny.
        - Otherwise, render a Rich Panel with details and await user confirmation.
        - Logs the outcome for auditing and provides a history of denials.
        """
        # Fast-paths
        if tool_name in self.whitelist:
            self._log_event({"timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                             "action": "confirm_interactive",
                             "tool": tool_name,
                             "granted": True,
                             "role": role})
            return True
        if role and tool_name in self.role_whitelist.get(role, set()):
            self._log_event({"timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                             "action": "confirm_interactive",
                             "tool": tool_name,
                             "granted": True,
                             "role": role})
            return True
        if role and tool_name in self.role_blacklist.get(role, set()):
            self.denied_history.append({"timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                                        "tool": tool_name, "role": role, "reason": "explicit blacklist"})
            self._log_event({"timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                             "action": "confirm_interactive_denied",
                             "tool": tool_name,
                             "role": role})
            return False
        if tool_name in self.blacklist:
            self.denied_history.append({"timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                                        "tool": tool_name, "role": role, "reason": "global blacklist"})
            self._log_event({"timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                             "action": "confirm_interactive_denied",
                             "tool": tool_name})
            return False

        # If non-interactive, deny by default for safety unless explicitly whitelisted
        interactive = hasattr(sys, "stdin") and sys.stdin is not None and sys.stdin.isatty()
        if not interactive:
            self._log_event({"timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                             "action": "confirm_interactive_non_interactive",
                             "tool": tool_name,
                             "role": role})
            return False

        # Build panel content
        panel_title = "Permission Confirmation"
        table = Table.grid(padding=1)
        table.add_row("Tool:", tool_name)
        table.add_row("Role:", str(role) if role else "N/A")
        table.add_row("Risk:", str(risk_level))
        table.add_row("Description:", description)
        panel = Panel(table, title=panel_title, border_style="#00FF88", box=box.ROUNDED)
        self.console.print(panel)

        # Custom confirm prompt using Rich Confirm for better UX
        try:
            granted = bool(Confirm.ask(f"Proceed with '{tool_name}'?" , default=False))
        except Exception:
            # Fallback to deny if confirmation cannot be obtained
            granted = False
        # Log outcome
        self._log_event({"timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                         "action": "confirm_interactive",
                         "tool": tool_name,
                         "granted": granted,
                         "role": role})
        if not granted:
            self.denied_history.append({"timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                                        "tool": tool_name, "role": role, "reason": description})
        return granted

    def log_permission_event(self, action: str, granted: bool, reason: str) -> None:
        self._log_event({"timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                         "action": action,
                         "granted": granted,
                         "reason": reason,
                         "level": self.current_level.name})
