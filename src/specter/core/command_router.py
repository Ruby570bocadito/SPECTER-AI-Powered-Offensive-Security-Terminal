"""Command Router - Slash command parsing and dispatch"""

import asyncio
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from specter.core.engine import SpecterEngine


class CommandRouter:
    """
    Routes slash commands (/help, /scope, /tools, etc.) to engine handlers.
    
    Extracted from SpecterEngine._handle_slash_command to reduce coupling.
    """
    
    def __init__(self, engine: "SpecterEngine"):
        self._engine = engine
    
    async def route(self, command: str) -> None:
        """Parse and dispatch a slash command.
        
        Args:
            command: Full slash command string (e.g. "/scope set 192.168.1.1")
        """
        parts = command[1:].split(maxsplit=2)
        cmd = parts[0].lower() if parts else ""
        action = parts[1].lower() if len(parts) > 1 else ""
        arg = parts[2] if len(parts) > 2 else ""
        
        handlers = {
            "help": lambda: self._engine._show_help(),
            "save": lambda: self._engine._handle_save_command(arg),
            "clear": lambda: self._engine.console.clear(),
            "exit": lambda: self._engine.console.print("[yellow]Usa Ctrl+C o cierra la terminal[/]"),
            "quit": lambda: self._engine.console.print("[yellow]Usa Ctrl+C o cierra la terminal[/]"),
            "salir": lambda: self._engine.console.print("[yellow]Usa Ctrl+C o cierra la terminal[/]"),
        }
        
        if cmd in handlers:
            handlers[cmd]()
            return
        
        # Commands with sub-actions
        if cmd == "model":
            await self._route_model(action, arg)
        elif cmd == "scope":
            self._route_scope(action, arg)
        elif cmd == "role":
            await self._route_role(action, arg)
        elif cmd in ("skills", "skill"):
            self._engine._show_skills()
        elif cmd in ("tools", "tool"):
            self._engine._show_tools()
        elif cmd in ("findings", "finding"):
            self._route_findings(action, arg)
        elif cmd == "report":
            await self._route_report(action)
        elif cmd == "session":
            self._engine._show_session_info()
        elif cmd == "log":
            self._engine._show_log()
        elif cmd == "history":
            self._engine._show_history(arg)
        elif cmd == "wordlist" or cmd == "dict":
            self._engine._show_wordlists(action, arg)
        elif cmd == "agent":
            await self._engine._handle_agent_command(action, arg)
        elif cmd == "read":
            self._engine._handle_read_command(arg)
        else:
            self._engine.console.print(f"[yellow]Comando desconocido: /{cmd}[/]")
            self._engine.console.print("[dim]Usa /help para ver comandos disponibles[/]")
    
    async def _route_model(self, action: str, arg: str) -> None:
        """Route /model sub-commands."""
        if action == "list":
            await self._engine._list_models()
        elif action == "switch" or (action and not action.startswith("-")):
            await self._engine._switch_model(action if action else arg)
        else:
            self._engine._show_model_info()
    
    def _route_scope(self, action: str, arg: str) -> None:
        """Route /scope sub-commands."""
        if action == "set" and arg:
            self._engine._handle_scope_command(arg)
        elif action in ("show", ""):
            self._engine._show_scope()
        elif action == "clear":
            self._engine.session.scope.clear()
            self._engine.console.print("[#00FF88][OK][/] Scope limpiado")
    
    async def _route_role(self, action: str, arg: str) -> None:
        """Route /role sub-commands."""
        if action == "list":
            self._engine._list_roles()
        elif action == "set" and arg:
            await self._engine._set_role(arg)
        elif action and action not in ("set", "show", "list"):
            await self._engine._set_role(action)
        else:
            self._engine._show_role()
    
    def _route_findings(self, action: str, arg: str) -> None:
        """Route /findings sub-commands."""
        if action == "add" and arg:
            self._engine._add_finding(arg)
        else:
            self._engine._show_findings()
    
    async def _route_report(self, action: str) -> None:
        """Route /report sub-commands."""
        if action in ("session", "status"):
            self._engine._show_session_report()
        else:
            await self._engine._generate_report()
