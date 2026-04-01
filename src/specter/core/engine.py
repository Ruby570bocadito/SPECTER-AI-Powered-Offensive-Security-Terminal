"""SPECTER Core Engine - Orquestador Principal"""

import asyncio
import sys
import time
from datetime import datetime
from specter.core.permissions import PermissionManager, PermissionLevel
from specter.utils.audit import AuditLogger
from specter.utils.logging import setup_logging
import structlog
from typing import Optional, Any
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from specter.core.session import Session, Finding
from specter.core.config import SpecterConfig

logger = structlog.get_logger()


class SpecterEngine:
    """
    CORE ENGINE de SPECTER
    
    Orquesta la interacción entre:
    - CLI (input del usuario)
    - LLM (razonamiento e interpretación)
    - Skills (habilidades especializadas)
    - Tools (herramientas MCP)
    - Session (contexto y memoria)
    """
    
    def __init__(self, session: Session, config: SpecterConfig):
        self.session = session
        self.config = config
        self.console = Console()
        self.skill_manager: Optional[SkillManager] = None
        self.tool_registry: Optional[ToolRegistry] = None
        self.advanced_tool_registry: Optional[AdvancedToolRegistry] = None
        self.agent_orchestrator: Optional[SmartOrchestrator] = None
        self._initialized = False
        self.interactive_mode = False
        self._last_generated_code: Optional[dict] = None
        self._cancel_requested = False
        self._permission_manager = PermissionManager(current_level=PermissionLevel.OBSERVATION)
        self._audit_logger = AuditLogger(path="specter/log/audit.log")
        try:
            setup_logging(level="INFO", log_file="specter/log/specter.log", json_output=True)
        except Exception:
            pass
    
    async def initialize(self) -> None:
        """Inicializa el motor de SPECTER"""
        if self._initialized:
            return
        logger.info("Initializing SPECTER Engine", session_id=self.session.id)
        
        from specter.skills import SkillManager
        from specter.mcp import ToolRegistry
        from specter.mcp.advanced_registry import AdvancedToolRegistry
        from specter.agents.orchestrator import SmartOrchestrator
        
        self.tool_registry = ToolRegistry()
        await self.tool_registry.discover_tools()
        self.advanced_tool_registry = AdvancedToolRegistry(self.tool_registry)
        await self.advanced_tool_registry.discover_tools()
        self.agent_orchestrator = SmartOrchestrator()
        self.skill_manager = SkillManager(
            tool_registry=self.tool_registry,
            config=self.config,
        )
        await self.skill_manager.load_skills()
        self._initialized = True
        logger.info("SPECTER Engine initialized", 
                    tools_count=len(self.tool_registry.tools),
                    advanced_tools=len(self.advanced_tool_registry.tools))
    
    async def process_input(self, user_input: str) -> None:
        """Procesa el input del usuario"""
        if user_input.startswith("/"):
            await self._handle_slash_command(user_input)
        else:
            await self._process_natural_language(user_input)
    
    async def _process_natural_language(self, user_input: str) -> None:
        """Procesa input conversacional con el LLM usando streaming"""
        if not self.config.llm_enabled:
            self.console.print("[yellow]LLM deshabilitado. Usa /help para ver comandos.[/]")
            return

        from specter.llm.prompt_builder import PromptBuilder
        from specter.llm.connection_manager import OllamaConnectionManager, OllamaConnectionError
        from rich.markdown import Markdown
        from rich.markup import escape as markup_escape

        detected_targets = self._auto_detect_scope(user_input)
        if detected_targets:
            for target in detected_targets:
                if not self.session.is_in_scope(target):
                    target_type = self._detect_target_type(target)
                    self.session.add_to_scope(target, target_type)
                    self.console.print(f"[#00D4FF][i]Scope auto-detect:[/] [#00FF88]{target}[/] [{target_type}]")

        self.session.add_message("user", user_input)
        self._cancel_requested = False

        try:
            cm = OllamaConnectionManager.get_instance()
            cm.update_config(self.config.ollama_host, self.config.ollama_model)
            
            try:
                cm.connect()
            except OllamaConnectionError as e:
                self.console.print(f"[yellow]LLM no disponible: {e}[/]")
                return

            role = self.session.role.value if self.session.role else "pentester"
            prompt_builder = PromptBuilder()
            system_prompt = prompt_builder.build_system_prompt(role)

            scope_ctx = self.session.get_scope_summary()
            if scope_ctx:
                system_prompt += scope_ctx

            context = self.session.build_conversation_prompt()
            if context:
                system_prompt += context

            self.console.print()
            self.console.print(f"[#555555]◈ Modelo:[/] [#00D4FF]{markup_escape(self.config.ollama_model)}[/]")
            
            response = await self._stream_response(
                lambda: cm.generate_stream(user_input, system_prompt),
                "Pensando"
            )

            if response and response.strip():
                if response.startswith("[cache]"):
                    response = response[7:response.find("[/cache]")]
                    self.console.print("[#555555][Cache hit][/]")
                
                self.session.add_message("assistant", response.strip())
                self.console.print()
                self._display_llm_response(response.strip())
                
                await self._execute_llm_commands(response, cm, system_prompt)

        except asyncio.CancelledError:
            self.console.print("\n[yellow]Operación cancelada por el usuario[/]")
        except Exception as exc:
            self.console.print(f"\n[bold #FF3366][!][/] [red]Fallo al consultar LLM:[/] {exc}")
    
    async def _stream_response(self, stream_func, label: str) -> str:
        """Genera respuesta con streaming en tiempo real"""
        import threading
        import time
        from rich.live import Live
        from rich.panel import Panel
        
        result = {"chunks": [], "error": None, "done": False, "first_token": False}
        self._cancel_requested = False
        start_time = time.time()
        
        def collect_stream():
            try:
                for chunk in stream_func():
                    if self._cancel_requested:
                        break
                    result["chunks"].append(chunk)
                    if not result["first_token"]:
                        result["first_token"] = True
            except Exception as e:
                result["error"] = e
            finally:
                result["done"] = True
        
        thread = threading.Thread(target=collect_stream)
        thread.start()
        
        def make_panel() -> Panel:
            elapsed = int(time.time() - start_time)
            tokens_count = len(result["chunks"])
            response_so_far = "".join(result["chunks"])
            
            if not result["first_token"]:
                content = f"[yellow]⏳ Cargando modelo...[/] [dim]({elapsed}s)[/]"
            else:
                if response_so_far:
                    content = f"[green]◆ Generando[/] [cyan]{tokens_count} tokens[/] [dim]({elapsed}s)[/]\n\n{response_so_far}"
                else:
                    content = f"[green]◆ Generando[/] [cyan]{tokens_count} tokens[/] [dim]({elapsed}s)[/]"
            
            return Panel.fit(
                content,
                title=f"[bold]◈ {label}[/]",
                border_style="#00D4FF",
                width=80
            )
        
        try:
            with Live(make_panel(), console=self.console, refresh_per_second=10, transient=True) as live:
                while not result["done"]:
                    if result["error"]:
                        thread.join(timeout=0.1)
                        raise result["error"]
                    live.update(make_panel())
                    await asyncio.sleep(0.1)
        finally:
            thread.join(timeout=1)
        
        if result["error"]:
            raise result["error"]
        
        return "".join(result["chunks"])
        
        return "".join(result["chunks"])
    
    async def _handle_slash_command(self, command: str) -> None:
        """Maneja comandos que empiezan con /"""
        parts = command[1:].split(maxsplit=2)
        cmd = parts[0].lower() if parts else ""
        action = parts[1].lower() if len(parts) > 1 else ""
        arg = parts[2] if len(parts) > 2 else ""

        match cmd:
            case "help":
                self._show_help()
            case "save":
                self._handle_save_command(arg)
            case "model":
                if action == "list":
                    await self._list_models()
                elif action == "switch" or (action and not action.startswith("-")):
                    await self._switch_model(action if action else arg)
                else:
                    self._show_model_info()
            case "scope":
                if action == "set" and arg:
                    self._handle_scope_command(arg)
                elif action in ("show", ""):
                    self._show_scope()
                elif action == "clear":
                    self.session.scope.clear()
                    self.console.print("[#00FF88][OK][/] Scope limpiado")
            case "role":
                if action == "list":
                    self._list_roles()
                elif action == "set" and arg:
                    await self._set_role(arg)
                elif action and action not in ("set", "show", "list"):
                    await self._set_role(action)
                else:
                    self._show_role()
            case "skills" | "skill":
                self._show_skills()
            case "tools" | "tool":
                self._show_tools()
            case "findings" | "finding":
                if action == "add" and arg:
                    self._add_finding(arg)
                else:
                    self._show_findings()
            case "report":
                if action == "session" or action == "status":
                    self._show_session_report()
                else:
                    await self._generate_report()
            case "session":
                self._show_session_info()
            case "log":
                self._show_log()
            case "history":
                self._show_history(arg)
            case "clear":
                self.console.clear()
            case "wordlist" | "dict":
                self._show_wordlists(action, arg)
            case "agent":
                await self._handle_agent_command(action, arg)
            case "read":
                self._handle_read_command(arg)
            case "exit" | "quit" | "salir":
                self.console.print("[yellow]Usa Ctrl+C o cierra la terminal[/]")
            case _:
                self.console.print(f"[yellow]Comando desconocido: /{cmd}[/]")
                self.console.print("[dim]Usa /help para ver comandos disponibles[/]")
    
    async def process_interactive_input(self, user_input: str) -> None:
        """Procesa input en modo interactivo (después de ejecutar comando)
        
        El usuario escribe libremente qué quiere hacer después.
        El sistema interpreta su intención y actúa accordingly.
        """
        if not self.config.llm_enabled:
            self.console.print("[yellow]LLM deshabilitado. Usa /help para ver comandos.[/]")
            return

        from specter.llm.prompt_builder import PromptBuilder
        from specter.llm.client import OllamaClient
        from rich.markdown import Markdown
        from rich.markup import escape as markup_escape

        user_input = user_input.strip()
        if not user_input:
            user_input = "continuar"

        role = self.session.role.value if self.session.role else "pentester"
        prompt_builder = PromptBuilder()
        system_prompt = prompt_builder.build_system_prompt(role)

        scope_ctx = self.session.get_scope_summary()
        if scope_ctx:
            system_prompt += scope_ctx

        context = self.session.build_conversation_prompt()
        if context:
            system_prompt += context

        interactive_prompt = (
            f"CONTEXTO: El usuario está en modo interactivo después de un comando.\n"
            f"Entrada del usuario: '{user_input}'\n\n"
            f"Instrucciones del usuario:\n"
            f"- Si dice 'continuar', 'siguiente', etc → propón siguiente paso y usa <cmd>\n"
            f"- Si dice 'analiza', 'explica' → da análisis detallado\n"
            f"- Si dice 'cambia', 'otro' → sugiere enfoque diferente\n"
            f"- Si dice 'estado' → muestra resumen de sesión\n"
            f"- Si dice 'parar', 'stop' → confirma y termina\n"
            f"- Si escribe cualquier cosa → responde apropiadamente\n\n"
            f"Siempre puedes usar <cmd> para proponer comandos si el usuario quiere continuar.\n"
            f"Responde de forma concisa y orientada a la acción."
        )

        self.session.add_message("user", user_input)

        try:
            from specter.llm.connection_manager import OllamaConnectionManager
            from rich.markup import escape as markup_escape
            
            cm = OllamaConnectionManager.get_instance()
            cm.update_config(self.config.ollama_host, self.config.ollama_model)
            
            if not cm._connected:
                cm.connect()

            self.console.print()
            self.console.print(f"[#555555]◈ Modelo:[/] [#00D4FF]{markup_escape(self.config.ollama_model)}[/]")
            
            self._display_orchestrator_activity()
            
            response = await self._stream_response(
                lambda: cm.generate_stream(interactive_prompt, system_prompt),
                "Procesando"
            )

            if response and response.strip():
                self.session.add_message("assistant", response.strip())
                self.console.print()
                self._display_llm_response(response.strip())
                
                await self._execute_llm_commands(response, cm, system_prompt)

        except Exception as exc:
            self.console.print(f"[bold #FF3366][!][/] [red]Fallo al consultar LLM:[/] {exc}")


    async def _execute_llm_commands(
        self, response: str, client, system_prompt: str
    ) -> None:
        """Detecta bloques <cmd>...</cmd> o <code>...</code> y ejecuta comandos.
        
        Características:
        - Detecta automáticamente si el usuario quiere leer archivos
        - Despliega agentes automáticamente para tareas complejas
        - Formatea outputs para comandos comunes (nmap, etc.)
        - Parsea resultados y sugiere hallazgos
        - Pide al usuario qué hacer después
        """
        import re, asyncio
        from pathlib import Path
        from rich.table import Table
        from rich.panel import Panel
        from rich.syntax import Syntax
        from rich.markdown import Markdown

        user_input = self.session.conversation_history[-1]["content"] if self.session.conversation_history else ""
        
        permission_mode = getattr(self.config, "permission_mode", "standard")
        
        file_patterns = [
            r"^leer\s+([^\s]+)",
            r"^ver\s+([^\s]+)",
            r"^mostrar\s+([^\s]+)",
            r"^cat\s+([^\s]+)",
        ]
        
        is_file_request = False
        for pattern in file_patterns:
            match = re.match(pattern, user_input.strip(), re.IGNORECASE)
            if match:
                filepath = match.group(1).strip().strip("'\"")
                if permission_mode == "paranoid":
                    self.console.print("[yellow]⚠ Modo Paranoid: ¿Confirmas leer el archivo?[/]")
                    from rich.prompt import Confirm
                    if not Confirm.ask("  Leer archivo?", default=False):
                        self.console.print("[#444444]Operación cancelada[/]")
                        return
                self._handle_read_command(filepath)
                is_file_request = True
                break
        
        if is_file_request:
            return
        
        agent_patterns = [
            r"^despliega\s+(?:el\s+)?agente",
            r"^crea\s+(?:un\s+)?agente",
            r"^inicia\s+(?:el\s+)?agente",
            r"^ejecuta\s+agente",
        ]
        
        is_agent_request = False
        for pattern in agent_patterns:
            if re.match(pattern, user_input.strip(), re.IGNORECASE):
                if permission_mode == "paranoid":
                    self.console.print("[yellow]⚠ Modo Paranoid: ¿Confirmas crear un agente?[/]")
                    from rich.prompt import Confirm
                    if not Confirm.ask("  Desplegar agente?", default=False):
                        self.console.print("[#444444]Operación cancelada[/]")
                        return
                if self.agent_orchestrator:
                    await self._handle_agent_command("spawn", user_input)
                    is_agent_request = True
                    break
        
        if is_agent_request:
            return

        cmd_pattern = r"<(?:cmd|code|shell)>(.*?)</(?:cmd|code|shell)>"
        commands = re.findall(cmd_pattern, response, re.DOTALL | re.IGNORECASE)
        if not commands:
            return

        for raw_cmd in commands:
            cmd = raw_cmd.strip()
            if not cmd:
                continue
            
            invalid_patterns = [
                r"^(comando|command|cmd|example|e\.g\.|example:|sample)$",
                r"^<.*>$",
                r"^\[.*\]$",
                r"^[^a-zA-Z]*$",
            ]
            
            is_invalid = any(re.match(p, cmd, re.IGNORECASE) for p in invalid_patterns)
            if is_invalid or len(cmd) < 3:
                self.console.print(f"[yellow]Ignorando comando inválido: '{cmd}'[/]")
                continue

            from rich.panel import Panel
            
            self.console.print()
            self.console.print(Panel.fit(
                "[#00FF88]▶ COMANDO[/]\n"
                + f"[#FFFFFF]{cmd}[/]",
                title="[#00D4FF]SPECTER[/]",
                border_style="#00D4FF",
                style="#1a1a2e on #0d1117"
            ))

            permission_mode = getattr(self.config, "permission_mode", "standard")
            if permission_mode == "expert":
                confirmed = True
                self.console.print("[#666666]Modo expert: auto-ejecutando...[/]")
            elif permission_mode == "paranoid":
                self.console.print("[#FFD60A]⚠ Modo paranoid: confirmación requerida[/]")
                from rich.prompt import Confirm
                confirmed = Confirm.ask("[#FF6B35]¿Ejecutar?[/]", default=False)
            else:
                from rich.prompt import Confirm
                confirmed = Confirm.ask("[bold #FFD60A]¿Ejecutar?[/]", default=False)

            if not confirmed:
                self.console.print("[#8B949E]Comando omitido.[/]")
                continue

            self.console.print()
            self.console.print(f"[bold #00FF88]▶ Ejecutando...[/]")

            output, error, returncode = await self._run_shell_command(cmd)

            self._display_command_output(cmd, output, error, returncode)

            findings_data = self._parse_command_results(cmd, output, error, returncode)
            if findings_data:
                self._display_findings_summary(findings_data)

            self.console.print()
            action_type, user_input = self._ask_next_action()

            if action_type == "interactive":
                if user_input.lower() in ["continuar", "continue", "siguiente", "next", ""]:
                    continue_prompt = (
                        f"Comando ejecutado: {cmd}\n"
                        f"Resultados:\n{output[:2000]}\n\n"
                        "El usuario quiere CONTINUAR con más comandos. "
                        "Propón el siguiente paso lógico en esta fase de pentesting. "
                        "Usa <cmd> para solicitar ejecución."
                    )
                elif user_input.lower() in ["analiza", "analizar", "analyze", "análisis", "explica"]:
                    continue_prompt = (
                        f"Comando ejecutado: {cmd}\n"
                        f"Resultados:\n{output[:2000]}\n\n"
                        "El usuario quiere un ANÁLISIS DETALLADO. "
                        "Explica qué significa cada resultado, qué vulnerabilidades se encontraron, "
                        "y qué impacto tienen. Sugiere qué hacer después."
                    )
                elif user_input.lower() in ["cambia", "cambiar", "cambio", "otro", "change"]:
                    continue_prompt = (
                        f"Comando ejecutado: {cmd}\n"
                        f"Resultados:\n{output[:2000]}\n\n"
                        "El usuario quiere CAMBIAR DE ENFOQUE o hacer algo diferente. "
                        "Pregúntale qué quiere hacer o sugiere alternativas."
                    )
                elif user_input.lower() in ["estado", "status", "sesión", "session"]:
                    continue_prompt = None
                    self.interactive_mode = False
                    self._show_session_info()
                    return
                elif user_input.lower() in ["parar", "stop", "fin", "salir"]:
                    continue_prompt = None
                    self.interactive_mode = False
                    self.console.print("[yellow]Operación detenida por el usuario[/]")
                    return
                else:
                    continue_prompt = (
                        f"Comando ejecutado: {cmd}\n"
                        f"Resultados:\n{output[:2000]}\n\n"
                        f"El usuario ha dicho: '{user_input}'\n"
                        "Responde a lo que el usuario pide y propón siguiente paso si es apropiado."
                    )
            else:
                continue_prompt = None

            if continue_prompt and output:
                self.console.print()
                from specter.llm.connection_manager import OllamaConnectionManager
                cm = OllamaConnectionManager.get_instance()
                
                analysis = await self._stream_response(
                    lambda: cm.generate_stream(continue_prompt, system_prompt),
                    "Analizando"
                )

                if analysis and analysis.strip():
                    self.console.print()
                    self.console.rule("[bold #00FF88]◆ Análisis[/]")
                    self.console.print(Markdown(analysis.strip()))
                    await self._execute_llm_commands(analysis, cm, system_prompt)

    def _display_command_output(self, cmd: str, output: str, error: str, returncode: int) -> None:
        """Muestra el output formateado según el tipo de comando"""
        cmd_lower = cmd.lower()

        if "nmap" in cmd_lower:
            self._display_nmap_output(output, error, returncode)
        elif "dirb" in cmd_lower or "gobuster" in cmd_lower:
            self._display_dir_fuzz_output(output, error, returncode)
        elif "nikto" in cmd_lower:
            self._display_nikto_output(output, error, returncode)
        elif "whatweb" in cmd_lower or "wappalyzer" in cmd_lower:
            self._display_tech_output(output, error, returncode)
        elif "sqlmap" in cmd_lower:
            self._display_sqlmap_output(output, error, returncode)
        elif "hydra" in cmd_lower:
            self._display_hydra_output(output, error, returncode)
        else:
            self._display_generic_output(output, error, returncode)

    def _display_nmap_output(self, output: str, error: str, returncode: int) -> None:
        """Formatea output de nmap"""
        from rich.table import Table

        if "PORT" in output and "STATE" in output:
            table = Table(title="◈ Resultados del Escaneo", border_style="#00D4FF")
            table.add_column("Puerto", style="#00FF88")
            table.add_column("Estado", style="#00D4FF")
            table.add_column("Servicio", style="#FFD60A")
            table.add_column("Versión", style="#8B949E")

            for line in output.split("\n"):
                line = line.strip()
                if "/" in line and any(state in line.upper() for state in ["OPEN", "CLOSED", "FILTERED"]):
                    parts = [p for p in line.split() if p]
                    if len(parts) >= 3:
                        port = parts[0]
                        state = parts[1]
                        service = parts[2]
                        version = " ".join(parts[3:]) if len(parts) > 3 else ""
                        state_color = "#00FF88" if "open" in state.lower() else "#FF3366"
                        table.add_row(port, f"[{state_color}]{state}[/]", service, version)

            if table.row_count > 0:
                self.console.print(table)
                self.console.print(f"[dim]Puertos abiertos encontrados: {table.row_count}[/]")
            else:
                self._display_generic_output(output, error, returncode)
        else:
            self._display_generic_output(output, error, returncode)

    def _display_dir_fuzz_output(self, output: str, error: str, returncode: int) -> None:
        """Formatea output de dirb/gobuster"""
        table = Table(title="◈ Directorios/DKicheros Encontrados", border_style="#00D4FF")
        table.add_column("URL", style="#00FF88")
        table.add_column("Código", style="#FFD60A")
        table.add_column("Tamaño", style="#8B949E")

        found_count = 0
        for line in output.split("\n"):
            if "+ http" in line or "200" in line or "301" in line or "403" in line:
                parts = line.split()
                for p in parts:
                    if p.startswith("http"):
                        url = p.rstrip("/")
                        code = next((x for x in parts if x.isdigit() and len(x) == 3), "-")
                        size = next((x for x in parts if x.isdigit() and len(x) > 3), "-")
                        table.add_row(url, code, size)
                        found_count += 1
                        break

        if found_count > 0:
            self.console.print(table)
            self.console.print(f"[dim]Recursos encontrados: {found_count}[/]")
        else:
            self._display_generic_output(output, error, returncode)

    def _display_nikto_output(self, output: str, error: str, returncode: int) -> None:
        """Formatea output de Nikto"""
        table = Table(title="◈ Vulnerabilidades Web (Nikto)", border_style="#FF6B35")
        table.add_column("severidad", style="#FFD60A")
        table.add_column("Descripción", style="#E8E8E8")
        table.add_column("URL", style="#00D4FF")

        vuln_count = 0
        for line in output.split("\n"):
            if "+ " in line and any(x in line for x in ["OSVDB", "CVE", "WARNING", "INFO"]):
                parts = line[2:].split(" - ", 1)
                if len(parts) >= 2:
                    vuln_type = parts[0].strip()
                    description = parts[1].strip()[:80]
                    table.add_row(vuln_type[:10], description, "")
                    vuln_count += 1

        if vuln_count > 0:
            self.console.print(table)
            self.console.print(f"[yellow]Vulnerabilidades potenciales: {vuln_count}[/]")
        else:
            self._display_generic_output(output, error, returncode)

    def _display_tech_output(self, output: str, error: str, returncode: int) -> None:
        """Formatea output de tecnologías web"""
        table = Table(title="◈ Tecnologías Detectadas", border_style="#00D4FF")
        table.add_column("Tecnología", style="#00FF88")
        table.add_column("Versión/Info", style="#8B949E")
        table.add_column("Tipo", style="#FFD60A")

        tech_count = 0
        for line in output.split("\n"):
            line = line.strip()
            if line and not line.startswith("-") and "[" not in line[:5]:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    tech = parts[0].strip()
                    info = parts[1].strip()
                    table.add_row(tech, info[:40], "Web")
                    tech_count += 1

        if tech_count > 0:
            self.console.print(table)
            self.console.print(f"[dim]Tecnologías identificadas: {tech_count}[/]")
        else:
            self._display_generic_output(output, error, returncode)

    def _display_sqlmap_output(self, output: str, error: str, returncode: int) -> None:
        """Formatea output de SQLMap"""
        if any(x in output.lower() for x in ["vulnerable", "injection", "parameter"]):
            self.console.print(Panel.fit(
                "[bold #FF3366]⚠ POSIBLE INYECCIÓN SQL DETECTADA[/]\n\n"
                f"[#E8E8E8]{output[:500]}...[/]",
                border_style="#FF3366",
                title="SQLMap Alert"
            ))
        else:
            self._display_generic_output(output, error, returncode)

    def _display_hydra_output(self, output: str, error: str, returncode: int) -> None:
        """Formatea output de Hydra"""
        if "login:" in output and "password:" in output:
            self.console.print(Panel.fit(
                "[bold #FF3366]⚠ CREDENCIALES ENCONTRADAS[/]\n\n"
                f"[#00FF88]{output}[/]",
                border_style="#FF3366",
                title="Hydra Alert"
            ))
        else:
            self._display_generic_output(output, error, returncode)

    def _display_generic_output(self, output: str, error: str, returncode: int) -> None:
        """Output genérico formateado"""
        from rich.syntax import Syntax
        
        if output:
            syntax = Syntax(output[:3000], "text", theme="monokai", line_numbers=True)
            self.console.print(Panel(syntax, title="Output", border_style="#00D4FF"))
        if error:
            self.console.print(Panel(f"[#FF3366]{error[:500]}[/]", title="Error", border_style="#FF3366"))
        self.console.print(f"[dim]Exit code: {returncode}[/]")

    def _parse_command_results(self, cmd: str, output: str, error: str, returncode: int) -> list[dict]:
        """Parsea resultados y retorna datos para hallazgos potenciales"""
        findings = []
        cmd_lower = cmd.lower()

        if "nmap" in cmd_lower and "open" in output.lower():
            for line in output.split("\n"):
                line = line.strip()
                if "open" in line.lower() and "/" in line:
                    if any(x in line.lower() for x in ["ftp", "telnet", "rsh", "rexec"]):
                        findings.append({
                            "type": "info",
                            "severity": "MED",
                            "title": f"Servicio inseguro: {line.split()[2] if len(line.split()) > 2 else 'desconocido'}",
                            "detail": line
                        })
                    elif any(x in line.lower() for x in ["mysql", "postgresql", "mongodb", "redis"]):
                        findings.append({
                            "type": "info",
                            "severity": "MED",
                            "title": f"Base de datos expuesta: {line.split()[2] if len(line.split()) > 2 else 'desconocido'}",
                            "detail": line
                        })

        return findings

    def _display_findings_summary(self, findings: list[dict]) -> None:
        """Muestra resumen de hallazgos potenciales"""
        if not findings:
            return

        self.console.print()
        self.console.print(Panel.fit(
            "[bold #FFD60A]⚡ Posibles Hallazgos Detectados[/]\n\n" +
            "\n".join(f"[{f['severity']}] {f['title']}" for f in findings),
            border_style="#FFD60A"
        ))

        from rich.prompt import Confirm
        if Confirm.ask("[bold #00D4FF]¿Añadir estos hallazgos a la sesión?[/]", default=False):
            from specter.core.session import Finding
            for f in findings:
                self.session.add_finding(Finding(
                    title=f["title"],
                    description=f["detail"],
                    severity=f["severity"],
                    tool="auto-detect"
                ))
            self.console.print(f"[#00FF88]✓ {len(findings)} hallazgos añadidos[/]")

    def _ask_next_action(self) -> tuple[str, str]:
        """Modo interactivo: muestra sugerencias y retorna acción
        
        Returns:
            tuple: (action, user_input)
            - action: 'interactive'
            - user_input: texto libre del usuario
        """
        from rich.panel import Panel
        from rich.prompt import Prompt

        suggestions = (
            "[dim]Escribe número o texto libremente:[/]\n\n"
            "[1] [#FF6B35]continuar[/] → siguiente paso lógico\n"
            "[2] [#00D4FF]analiza esto[/] → análisis detallado\n"
            "[3] [#FFD60A]cambia enfoque[/] → otro enfoque\n"
            "[4] [#8B949E]estado[/] → ver sesión actual\n"
            "[5] [#FF3366]parar[/] → finalizar aquí"
        )

        self.console.print()
        self.console.print(Panel(
            suggestions,
            title="◈ Modo Interactivo",
            border_style="#FF6B35",
            width=65
        ))

        self.interactive_mode = True
        
        choice = Prompt.ask("\n[#FFD60A]¿Qué deseas hacer?[/]", default="1")
        
        choice_map = {
            "1": "continuar",
            "2": "analiza esto",
            "3": "cambia enfoque",
            "4": "estado",
            "5": "parar"
        }
        
        return ("interactive", choice_map.get(choice.strip(), choice.strip()))

    async def _run_shell_command(self, cmd: str) -> tuple[str, str, int]:
        """Ejecuta un comando de shell y retorna (stdout, stderr, returncode)."""
        import asyncio, subprocess, platform

        try:
            if platform.system() == "Windows":
                shell_args = ["cmd.exe", "/c", cmd]
            else:
                shell_args = ["/bin/sh", "-c", cmd]

            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    shell_args,
                    capture_output=True,
                    text=True,
                    timeout=300,
                    errors="replace",
                )
            )
            return result.stdout.strip(), result.stderr.strip(), result.returncode
        except subprocess.TimeoutExpired:
            return "", "Timeout: el comando tardó más de 5 minutos.", -1
        except Exception as exc:
            return "", f"Error al ejecutar comando: {exc}", -1

    async def _execute_batch(self, commands: list[str]) -> list[dict]:
        """Ejecuta múltiples comandos en paralelo.
        
        Args:
            commands: Lista de comandos a ejecutar
            
        Returns:
            Lista de diccionarios con {command, stdout, stderr, returncode, success}
        """
        import asyncio
        
        if not commands:
            return []
        
        self.console.print(f"[#00D4FF]▶ Ejecutando {len(commands)} comandos en paralelo...[/]")
        
        tasks = [self._run_shell_command(cmd) for cmd in commands]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        batch_results = []
        for cmd, result in zip(commands, results):
            if isinstance(result, Exception):
                batch_results.append({
                    "command": cmd,
                    "stdout": "",
                    "stderr": str(result),
                    "returncode": -1,
                    "success": False
                })
            else:
                stdout, stderr, returncode = result
                batch_results.append({
                    "command": cmd,
                    "stdout": stdout,
                    "stderr": stderr,
                    "returncode": returncode,
                    "success": returncode == 0
                })
        
        successful = sum(1 for r in batch_results if r["success"])
        self.console.print(f"[#00FF88]✓[/] {successful}/{len(commands)} comandos completados")
        
        return batch_results

    async def _execute_batch_with_dependencies(
        self, 
        commands: list[dict],
        max_concurrent: int = 5
    ) -> list[dict]:
        """Ejecuta comandos con dependencias y límite de concurrencia.
        
        Args:
            commands: Lista de {command, depends_on: list[str]}
            max_concurrent: Número máximo de comandos simultáneos
            
        Returns:
            Lista de resultados
        """
        import asyncio
        
        if not commands:
            return []
        
        results = {}
        running = set()
        completed = set()
        
        async def run_command(cmd_item):
            cmd = cmd_item["command"]
            result = await self._run_shell_command(cmd)
            return cmd_item.get("id", cmd), result
        
        while len(completed) < len(commands):
            available = [
                c for c in commands 
                if c.get("id", c["command"]) not in completed
                and all(d in completed for d in c.get("depends_on", []))
                and c.get("id", c["command"]) not in running
            ]
            
            if not available:
                if running:
                    done, _ = await asyncio.wait(running, return_when=asyncio.FIRST_COMPLETED)
                    for task in done:
                        cmd_id, result = await task
                        results[cmd_id] = result
                        completed.add(cmd_id)
                        running.discard(task)
                continue
            
            batch = available[:max_concurrent]
            tasks = set()
            for cmd_item in batch:
                task = asyncio.create_task(run_command(cmd_item))
                running.add(task)
                tasks.add(task)
            
            if tasks:
                done, _ = await asyncio.wait(tasks, return_when=asyncio.ALL_COMPLETED)
                for task in done:
                    cmd_id, result = await task
                    results[cmd_id] = result
                    completed.add(cmd_id)
                    running.discard(task)
        
        return [
            {"command": c.get("id", c["command"]), "result": results.get(c.get("id", c["command"]))}
            for c in commands
        ]

    def _display_llm_response(self, response: str) -> None:
        """Muestra la respuesta del LLM con código compacto"""
        import re
        from rich.markdown import Markdown

        code_blocks = list(re.finditer(r"```(\w+)?\n(.*?)```", response, re.DOTALL))
        
        if not code_blocks:
            self.console.print(Markdown(response))
            return

        last_end = 0
        for match in code_blocks:
            text_before = response[last_end:match.start()]
            if text_before.strip():
                self.console.print(Markdown(text_before))
            
            lang = match.group(1) or "text"
            code = match.group(2).strip()
            filename = self._extract_filename_from_context(code, lang)
            
            self._last_generated_code = {"code": code, "lang": lang, "filename": filename}
            
            self._display_code_block(code, lang, filename)
            
            last_end = match.end()
        
        text_after = response[last_end:]
        if text_after.strip():
            self.console.print(Markdown(text_after))
        
        if self._last_generated_code:
            self.console.print("[dim]Usa /save para guardar el codigo[/]")
    
    def _display_orchestrator_activity(self) -> None:
        """Muestra actividad del orquestador con specter-mini"""
        if self.agent_orchestrator:
            agents = self.agent_orchestrator.list_agents()
            if agents:
                self.console.print(f"[#444444]◈ Worker:[/] [#666666]specter-mini 1[/]")
                self.console.print(f"[#444444]  Estado:[/] [#666666]Activo[/]")
    
    def _display_code_block(self, code: str, lang: str, filename: str = "") -> None:
        """Muestra un bloque de código con tema oscuro elegante"""
        from rich.syntax import Syntax
        from rich.panel import Panel
        from rich.style import Style
        from pygments.style import Style as PygmentsStyle
        from pygments.token import (
            Keyword, Name, Comment, String, Error, Number, Operator, Generic,
            Token, Whitespace, Punctuation
        )
        
        lines = code.split("\n")
        is_short = len(lines) <= 5 and len(code) < 300
        
        class DarkCodeStyle(PygmentsStyle):
            background_color = "#0d1117"
            styles = {
                Whitespace: "#3D3D3D",
                Comment: "italic #8b949e",
                Comment.Preproc: "bold #00D4FF",
                Keyword: "#FF7B72",
                Keyword.Constant: "#79C0FF",
                Keyword.Declaration: "#FF7B72",
                Keyword.Namespace: "#FF7B72",
                Keyword.Pseudo: "#FF7B72",
                Keyword.Reserved: "#FF7B72",
                Keyword.Type: "#79C0FF",
                Operator: "#FF7B72",
                Operator.Word: "#FF7B72",
                Name: "#E6EDF3",
                Name.Attribute: "#79C0FF",
                Name.Builtin: "#79C0FF",
                Name.Builtin.Pseudo: "#79C0FF",
                Name.Class: "#D2A8FF",
                Name.Constant: "#79C0FF",
                Name.Decorator: "#D2A8FF",
                Name.Entity: "#FF7B72",
                Name.Exception: "#D2A8FF",
                Name.Function: "#D2A8FF",
                Name.Property: "#79C0FF",
                Name.Tag: "#7EE787",
                Name.Variable: "#79C0FF",
                Name.Variable.Class: "#79C0FF",
                Name.Variable.Global: "#79C0FF",
                Name.Variable.Instance: "#79C0FF",
                Number: "#79C0FF",
                Number.Float: "#79C0FF",
                Number.Hex: "#79C0FF",
                Number.Integer: "#79C0FF",
                Number.Integer.Long: "#79C0FF",
                Number.Oct: "#79C0FF",
                Punctuation: "#E6EDF3",
                String: "#A5D6FF",
                String.Doc: "#A5D6FF",
                String.Backtick: "#A5D6FF",
                String.Char: "#A5D6FF",
                String.Delimiter: "#A5D6FF",
                String.Double: "#A5D6FF",
                String.Escape: "#79C0FF",
                String.Heredoc: "#A5D6FF",
                String.Interpol: "#79C0FF",
                String.Other: "#A5D6FF",
                String.Regex: "#A5D6FF",
                String.Single: "#A5D6FF",
                String.Symbol: "#A5D6FF",
                Generic: "#E6EDF3",
                Generic.Deleted: "#FF7B72",
                Generic.Emph: "italic #E6EDF3",
                Generic.Error: "#FF7B72",
                Generic.Heading: "bold #E6EDF3",
                Generic.Inserted: "#7EE787",
                Generic.Output: "#E6EDF3",
                Generic.Prompt: "#00D4FF",
                Generic.Strong: "bold #E6EDF3",
                Generic.Subheading: "bold #00D4FF",
                Generic.Traceback: "#FF7B72",
                Token: "#E6EDF3",
                Token.Other: "#FF7B72",
                Error: "#FF7B72",
            }
        
        syntax = Syntax(
            code, 
            lexer=lang if lang != "text" else "text",
            theme=DarkCodeStyle,
            line_numbers=not is_short,
            background_color="#0d1117"
        )
        
        header = f"```" + lang if lang != "text" else "```"
        if filename:
            header = f"{filename} · " + header
        
        self.console.print(Panel(
            syntax,
            title=f"[dim]{header}[/dim]",
            border_style="#30363D",
            padding=(0, 1),
            width=100 if not is_short else 80,
            height=min(20, len(lines) + 2) if not is_short else None,
            style="on #0d1117"
        ))
    
    def _extract_filename_from_context(self, code: str, lang: str) -> str:
        """Intenta extraer nombre de archivo del código"""
        patterns = {
            "python": [r"#\s*file:\s*(\S+\.py)", r"filename\s*=\s*['\"](\S+\.py)['\"]"],
            "javascript": [r"//\s*file:\s*(\S+\.js)", r"export\s+const\s+(\S+)"],
            "bash": [r"#\s*script:\s*(\S+\.sh)", r"#!/bin/(?:bash|sh)\s*#\s*(\S+)"],
            "powershell": [r"#\s*script:\s*(\S+\.ps1)"],
        }
        
        for pattern in patterns.get(lang, []):
            import re
            match = re.search(pattern, code, re.IGNORECASE)
            if match:
                return match.group(1)
        return ""
    
    def _save_generated_code(self, code: str, lang: str, custom_name: str = "") -> str:
        """Guarda código generado en archivos ordenados
        
        Estructura de directorios:
        generated/
        ├── scripts/
        ├── exploits/
        ├── payloads/
        ├── analysis/
        └── reports/
        """
        from pathlib import Path
        import uuid
        
        category = self._categorize_code(code, lang)
        base_dir = Path(f"generated/{category}")
        base_dir.mkdir(parents=True, exist_ok=True)
        
        ext = self._get_extension(lang)
        if custom_name:
            filename = custom_name if custom_name.endswith(ext) else custom_name + ext
        else:
            filename = f"script_{uuid.uuid4().hex[:8]}{ext}"
        
        filepath = base_dir / filename
        filepath.write_text(code, encoding="utf-8")
        
        return str(filepath)
    
    def _categorize_code(self, code: str, lang: str) -> str:
        """Categoriza el código según su contenido"""
        code_lower = code.lower()
        
        if any(x in code_lower for x in ["exploit", "payload", "shellcode", "msfvenom", "metasploit"]):
            return "exploits"
        elif any(x in code_lower for x in ["nmap", "scan", "recon", "enum"]):
            return "scans"
        elif any(x in code_lower for x in ["hash", "crack", "password", "credential"]):
            return "passwords"
        elif any(x in code_lower for x in ["analyze", "forensic", "volatility", "memory"]):
            return "analysis"
        elif any(x in code_lower for x in ["report", "document", "findings"]):
            return "reports"
        elif lang in ["python", "bash", "powershell"] and len(code.split("\n")) > 10:
            return "scripts"
        else:
            return "misc"
    
    def _get_extension(self, lang: str) -> str:
        """Obtiene extensión según lenguaje"""
        extensions = {
            "python": ".py",
            "py": ".py",
            "javascript": ".js",
            "js": ".js",
            "bash": ".sh",
            "sh": ".sh",
            "powershell": ".ps1",
            "ps1": ".ps1",
            "c": ".c",
            "cpp": ".cpp",
            "java": ".java",
            "ruby": ".rb",
            "go": ".go",
            "rust": ".rs",
            "text": ".txt",
        }
        return extensions.get(lang.lower(), ".txt")
    
    def _handle_save_code(self, code: str, lang: str, name: str = "") -> str:
        """Maneja guardar código y retorna la ruta"""
        try:
            filepath = self._save_generated_code(code, lang, name)
            self.console.print(f"[#00FF88]✓[/] Guardado en: [dim]{filepath}[/]")
            return filepath
        except Exception as e:
            self.console.print(f"[#FF3366]Error[/] al guardar: {e}")
            return ""
    
    def _handle_save_command(self, filename: str = "") -> None:
        """Maneja el comando /save"""
        if not self._last_generated_code:
            self.console.print("[yellow]No hay código para guardar.[/]")
            self.console.print("[dim]Genera código primero y luego usa /save[/]")
            return
        
        code = self._last_generated_code["code"]
        lang = self._last_generated_code["lang"]
        
        self._handle_save_code(code, lang, filename)
    
    def _show_session_report(self) -> None:
        """Muestra reporte de la sesión"""
        from rich.markdown import Markdown
        report = self.session.generate_session_report()
        self.console.print(Markdown(report))
    
    def _show_session_info(self) -> None:
        """Muestra información de la sesión"""
        from rich.table import Table
        from rich.panel import Panel
        
        table = Table(title="Información de Sesión", border_style="#00D4FF")
        table.add_column("Campo", style="#00FF88")
        table.add_column("Valor", style="#E8E8E8")
        
        table.add_row("ID", self.session.id)
        table.add_row("Nombre", self.session.name)
        table.add_row("Duración", self.session.duration)
        table.add_row("Rol", self.session.role.value if self.session.role else "No establecido")
        table.add_row("Scope", f"{len(self.session.scope)} objetivos")
        table.add_row("Findings", f"{len(self.session.findings)} hallazgos")
        
        self.console.print(Panel.fit(table, border_style="#00D4FF"))
    
    def _show_history(self, query: str = "") -> None:
        """Muestra el historial de comandos"""
        from specter.utils.history import CommandHistory
        from rich.table import Table
        from rich.panel import Panel
        
        history = CommandHistory()
        
        if query:
            commands = history.search(query)
            if not commands:
                self.console.print(f"[dim]No hay resultados para '{query}'[/]")
                return
            
            table = Table(title=f"Resultados de búsqueda: '{query}'", border_style="#00D4FF")
            table.add_column("#", style="#8B949E", width=4)
            table.add_column("Comando", style="#00FF88")
            
            for i, cmd in enumerate(commands, 1):
                table.add_row(str(i), cmd)
        else:
            commands = history.get_recent(20)
            if not commands:
                self.console.print("[dim]No hay historial[/]")
                return
            
            table = Table(title="Historial de Comandos (últimos 20)", border_style="#00D4FF")
            table.add_column("#", style="#8B949E", width=4)
            table.add_column("Comando", style="#00FF88")
            table.add_column("Timestamp", style="#8B949E")
            
            history_data = history._history[-20:]
            for i, (entry, cmd) in enumerate(zip(history_data, commands), 1):
                ts = entry.get("timestamp", "")[:19].replace("T", " ") if isinstance(entry, dict) else ""
                table.add_row(str(i), cmd, ts)
        
        self.console.print(table)
    
    def _show_log(self) -> None:
        """Muestra el log de acciones"""
        from rich.table import Table
        from rich.panel import Panel
        
        if not self.session.log:
            self.console.print("[dim]No hay entradas en el log[/]")
            return
        
        table = Table(title="Log de Sesión", border_style="#8B949E")
        table.add_column("Timestamp", style="#8B949E")
        table.add_column("Acción", style="#00D4FF")
        table.add_column("Detalles", style="#E8E8E8")
        
        for entry in self.session.log[-20:]:
            ts = entry.get("timestamp", "")[:19].replace("T", " ")
            action = entry.get("action", "")
            data = str(entry.get("data", ""))[:50]
            table.add_row(ts, action, data)
        
        self.console.print(table)
    
    def _show_skills(self) -> None:
        """Muestra skills disponibles"""
        from rich.table import Table
        from rich.panel import Panel
        
        if not self.skill_manager:
            self.console.print("[yellow]Skill manager no inicializado[/]")
            return
        
        table = Table(title="Skills Disponibles", border_style="#00D4FF")
        table.add_column("Skill", style="#00FF88")
        table.add_column("Descripción", style="#E8E8E8")
        table.add_column("Categoría", style="#FFD60A")
        
        skills = self.skill_manager.list_skills()
        if not skills:
            self.console.print("[dim]No hay skills cargados[/]")
            return
        
        for skill in skills:
            table.add_row(
                skill.get("name", ""),
                skill.get("description", "")[:50],
                skill.get("category", "")
            )
        
    def _show_tools(self) -> None:
        """Muestra herramientas disponibles con categorías avanzadas"""
        from rich.table import Table
        from rich.panel import Panel
        
        tools = None
        total_categories = 0
        
        if self.advanced_tool_registry and self.advanced_tool_registry.tools:
            tools = list(self.advanced_tool_registry.tools.values())
            total_categories = len(set(t.category.split('/')[0] for t in tools))
        elif self.tool_registry:
            tools = self.tool_registry.list_tools()
            total_categories = len(set(t.category.split('/')[0] for t in tools))
        
        if not tools:
            self.console.print("[yellow]No hay herramientas disponibles[/]")
            return
        
        self.console.print(Panel.fit(
            "[#00D4FF]◈ Herramientas MCP Disponibles[/]\n"
            "[#8B949E]Total: {} herramientas en {} categorías[/]".format(
                len(tools), 
                total_categories
            ),
            border_style="#00D4FF"
        ))
        
        categories = {}
        for tool in tools:
            cat = tool.category.split('/')[0]
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(tool)
        
        for cat in sorted(categories.keys()):
            cat_tools = categories[cat]
            table = Table(title="[{}] {} herramientas".format("#FFD60A", cat.upper()), border_style="#00D4FF")
            table.add_column("Herramienta", style="#00FF88")
            table.add_column("Descripción", style="#8B949E")
            table.add_column("Riesgo", style="#E8E8E8")
            table.add_column("Modos", style="#00D4FF")
            
            for tool in cat_tools[:15]:
                risk_icons = {0: "[#00FF88]🟢", 1: "[#FFD60A]🟡", 2: "[#FF3366]🔴"}
                risk = risk_icons.get(tool.risk_level, "[#8B949E]?")
                modes = ", ".join(tool.execution_modes) if hasattr(tool, 'execution_modes') and tool.execution_modes else "default"
                table.add_row(
                    tool.name,
                    tool.description[:40] + "..." if len(tool.description) > 40 else tool.description,
                    risk,
                    "[#00D4FF]{}".format(modes)
                )
            
            self.console.print(table)
            self.console.print()
    
    def _show_findings(self) -> None:
        """Muestra hallazgos de la sesión"""
        from rich.table import Table
        from rich.panel import Panel
        
        if not self.session.findings:
            self.console.print("[dim]No hay hallazgos en esta sesión[/]")
            return
        
        table = Table(title="Findings", border_style="#FF6B35")
        table.add_column("ID", style="#8B949E")
        table.add_column("Severidad", style="#00D4FF")
        table.add_column("Título", style="#E8E8E8")
        table.add_column("Herramienta", style="#FFD60A")
        
        for f in self.session.findings:
            severity_color = "#FF3366" if f.severity == "CRIT" else "#FF6B35" if f.severity == "HIGH" else "#FFD60A"
            table.add_row(f.id[:8], f"[{severity_color}]{f.severity}[/]", f.title[:40], f.tool or "-")
        
        self.console.print(table)
        self.console.print(f"[dim]Total: {len(self.session.findings)} hallazgos[/]")
    
    def _add_finding(self, description: str) -> None:
        """Añade un hallazgo manualmente"""
        from specter.core.session import Finding
        
        if not description:
            self.console.print("[yellow]Uso: /findings add <descripción>[/]")
            return
        
        finding = Finding(title=description, severity="INFO")
        self.session.add_finding(finding)
        self.console.print(f"[#00FF88]✓[/] Hallazgo aniadido: {description[:50]}")


    
    def _show_help(self) -> None:
        """Muestra ayuda de comandos"""
        help_text = """
## Comandos Disponibles

### Configuración de Sesión
| Comando | Descripción |
|---------|-------------|
| `/scope <target>` | Añadir objetivo al scope |
| `/role <nombre>` | Cambiar rol (pentester, red-team, etc.) |
| `/session` | Ver información de la sesión |

### Skills y Herramientas
| Comando | Descripción |
|---------|-------------|
| `/skills` | Listar skills disponibles |
| `/tools` | Listar herramientas disponibles |
| `/skill <nombre>` | Activar skill específico |

### Wordlists y Diccionarios
| Comando | Descripción |
|---------|-------------|
| `/wordlist dir` | Directorios comunes |
| `/wordlist subdomain` | Subdominios comunes |
| `/wordlist user` | Nombres de usuario |
| `/wordlist pass` | Contraseñas comunes |
| `/wordlist sql` | SQL Injection payloads |
| `/wordlist xss` | XSS payloads |
| `/wordlist all` | Todas las wordlists |

### Agentes
| Comando | Descripción |
|---------|-------------|
| `/agent list` | Listar agentes |
| `/agent spawn <task>` | Desplegar tarea |
| `/agent status` | Estado del orquestador |

### Archivos
| Comando | Descripción |
|---------|-------------|
| `/read <ruta>` | Leer y mostrar archivo |

### Resultados
| Comando | Descripción |
|---------|-------------|
| `/findings` | Ver hallazgos de la sesión |
| `/export` | Exportar sesión |

### Sistema
| Comando | Descripción |
|---------|-------------|
| `/help` | Mostrar esta ayuda |
| `/clear` | Limpiar pantalla |
| `/exit` | Salir de SPECTER |

### Roles Disponibles
- `pentester` - Auditor profesional
- `red-teamer` - Operador ofensivo
- `blue-teamer` - Defensor
- `ctf-player` - Jugador CTF
- `forensic-analyst` - Analista forense
"""
        from rich.markdown import Markdown
        self.console.print(Markdown(help_text))

    def _show_wordlists(self, action: str, arg: str) -> None:
        """Muestra wordlists y diccionarios disponibles"""
        from specter.wordlists.dictionaries import AttackDictionary
        
        attack_dict = AttackDictionary()
        
        if action == "dir":
            items = attack_dict.get_directories()
            title = "Directorios Comunes"
        elif action == "subdomain":
            items = attack_dict.get_subdomains()
            title = "Subdominios Comunes"
        elif action == "user" | "users":
            items = attack_dict.get_usernames()
            title = "Usernames Comunes"
        elif action == "pass" | "password":
            items = attack_dict.get_passwords()[:50]
            title = "Contraseñas Comunes (Top 50)"
        elif action == "sql":
            items = attack_dict.get_sql_payloads()
            title = "SQL Injection Payloads"
        elif action == "xss":
            items = attack_dict.get_xss_payloads()
            title = "XSS Payloads"
        elif action == "lfi":
            items = attack_dict.get_lfi_payloads()
            title = "LFI Payloads"
        elif action == "cve":
            items = attack_dict.get_cve_patterns()
            title = "CVE Search Patterns"
        elif arg:
            items = attack_dict.get_all()
            title = "Todas las Wordlists"
        else:
            table = Table(title="Wordlists Disponibles")
            table.add_column("Comando", style="#00D4FF")
            table.add_column("Descripción", style="#8B949E")
            table.add_row("/wordlist dir", "Directorios comunes (72)")
            table.add_row("/wordlist subdomain", "Subdominios (100+)")
            table.add_row("/wordlist user", "Usernames (50+)")
            table.add_row("/wordlist pass", "Contraseñas (100+)")
            table.add_row("/wordlist sql", "SQL Injection payloads")
            table.add_row("/wordlist xss", "XSS payloads")
            table.add_row("/wordlist lfi", "LFI payloads")
            table.add_row("/wordlist cve", "CVE search patterns")
            table.add_row("/wordlist all", "Todas las wordlists")
            self.console.print(table)
            return
        
        self.console.print(f"[bold]◈ {title}[/bold]")
        for item in items[:30]:
            self.console.print(f"  [dim]{item}[/]")
        if len(items) > 30:
            self.console.print(f"  [dim]... y {len(items) - 30} más[/]")

    async def _handle_agent_command(self, action: str, arg: str) -> None:
        """Maneja comandos de agentes"""
        from rich.table import Table
        from rich.progress import Progress, SpinnerColumn, TextColumn
        
        if action == "list":
            agents = self.agent_orchestrator.list_agents() if self.agent_orchestrator else []
            table = Table(title="Agentes Disponibles")
            table.add_column("Nombre", style="#00D4FF")
            table.add_column("Rol", style="#FFD60A")
            table.add_column("Estado", style="#00FF88")
            for agent in agents:
                table.add_row(agent.get("name", ""), agent.get("role", ""), agent.get("status", ""))
            self.console.print(table)
        elif action == "spawn" and arg:
            self.console.print(f"[#444444]◈ Worker:[/] [#666666]specter-mini 1[/]")
            self.console.print(f"[#444444]  Desplegando tarea:[/] [#00D4FF]{arg}[/]")
            
            task_id = await self.agent_orchestrator.deploy_task(arg, {})
            
            self.console.print(f"[#444444]  Tarea ID:[/] [#00FF88]{task_id}[/]")
            self.console.print(f"[#00FF88][OK][/] Tarea desplegada: {arg}")
            
            await self._show_agent_progress(task_id)
        elif action == "status":
            status = self.agent_orchestrator.get_status() if self.agent_orchestrator else {}
            self.console.print(f"[bold]◈ Estado del Orquestador[/bold]")
            self.console.print(f"  Agentes: {status.get('active_agents', 0)}")
            self.console.print(f"  Tareas: {status.get('pending_tasks', 0)}")
        else:
            self.console.print("[yellow]Uso: /agent list | spawn <tarea> | status[/]")

    async def _show_agent_progress(self, task_id: str) -> None:
        """Muestra el progreso del agente en tiempo real"""
        from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
        
        status = self.agent_orchestrator.get_task_status(task_id) if self.agent_orchestrator else {}
        
        with Progress(
            SpinnerColumn(spinner_name="dots2", style="#00FF88"),
            TextColumn(f"[#666666]Ejecutando:[/] [#00D4FF]{status.get('description', task_id)}[/]"),
            TimeElapsedColumn(),
            console=self.console,
            transient=True,
        ) as progress:
            task = progress.add_task("working", total=None)
            
            while status.get("status") not in ["done", "error", "cancelled"]:
                await asyncio.sleep(0.5)
                status = self.agent_orchestrator.get_task_status(task_id) if self.agent_orchestrator else {}
                progress.update(task, description=f"[#666666]{status.get('status', 'working')}[/]")
        
        if status.get("result"):
            self.console.print(f"[#00FF88]✓ Resultado:[/]")
            self.console.print(f"  [#8B949E]{status.get('result')}[/]")

    def _handle_read_command(self, filepath: str) -> None:
        """Lee un archivo y lo muestra"""
        from pathlib import Path
        from rich.syntax import Syntax
        
        if not filepath:
            self.console.print("[yellow]Uso: /read <ruta_archivo>[/]")
            return
        
        path = Path(filepath)
        if not path.exists():
            self.console.print(f"[red]Archivo no encontrado: {filepath}[/]")
            return
        
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            lang = "python" if filepath.endswith(".py") else "text"
            syntax = Syntax(content, lang, theme="monokai", line_numbers=True)
            self.console.print(syntax)
        except Exception as e:
            self.console.print(f"[red]Error al leer archivo: {e}[/]")

    # ── Gestión de Modelos ──────────────────────────────────────────────────

    def _show_model_info(self) -> None:
        """Muestra información del modelo activo."""
        from rich.markup import escape as markup_escape
        self.console.print(Panel.fit(
            f"[bold]◈ Modelo Activo[/bold]\n\n"
            f"Nombre:       [bold #00D4FF]{markup_escape(self.config.ollama_model)}[/]\n"
            f"Host:         [#8B949E]{markup_escape(self.config.ollama_host)}[/]\n"
            f"Temperatura:  [#FFD60A]{self.config.llm_temperature}[/]\n"
            f"Ctx window:   [#8B949E]{self.config.llm_context_window}[/]\n"
            f"Modo permisos:[#00FF88]{self.config.permission_mode}[/]",
            border_style="#00D4FF"
        ))

    async def _list_models(self) -> None:
        """Lista los modelos disponibles en Ollama (y LM Studio si está activo)."""
        import urllib.request
        import json
        from rich.table import Table

        table = Table(title="Modelos Disponibles")
        table.add_column("Proveedor", style="#8B949E")
        table.add_column("Modelo", style="#00D4FF")
        table.add_column("Tamaño", style="#FFD60A")
        table.add_column("Activo", style="#00FF88")

        total = 0

        # ── Ollama ──────────────────────────────────────────────────────────
        try:
            url = self.config.ollama_host.rstrip("/") + "/api/tags"
            with urllib.request.urlopen(url, timeout=4) as resp:
                data = json.loads(resp.read())
            for m in data.get("models", []):
                name = m.get("name", "")
                size_bytes = m.get("size", 0)
                size_gb = f"{size_bytes / 1e9:.1f} GB" if size_bytes else "?"
                active = "[bold #00FF88]✓ activo[/]" if name == self.config.ollama_model else ""
                table.add_row("Ollama", name, size_gb, active)
                total += 1
        except Exception as e:
            table.add_row("Ollama", f"[red]No disponible ({e})[/]", "", "")

        # ── LM Studio (puerto 1234 por defecto) ──────────────────────────────
        try:
            lms_url = "http://localhost:1234/v1/models"
            with urllib.request.urlopen(lms_url, timeout=2) as resp:
                data = json.loads(resp.read())
            for m in data.get("data", []):
                name = m.get("id", "")
                active = "[bold #00FF88]✓ activo[/]" if name == self.config.ollama_model else ""
                table.add_row("LM Studio", name, "?", active)
                total += 1
        except Exception:
            pass  # LM Studio no está corriendo — silencioso

        if total == 0:
            self.console.print("[yellow]No se encontraron modelos. ¿Está Ollama corriendo?[/]")
            self.console.print("[dim]Lanza con: ollama serve[/]")
        else:
            self.console.print(table)
            self.console.print(
                f"[dim]Usa [bold]/model switch <nombre>[/] para cambiar el modelo activo.[/]"
            )

    async def _switch_model(self, model_name: str) -> None:
        """Cambia el modelo activo y persiste la configuración en .env."""
        from rich.markup import escape as markup_escape

        if not model_name:
            self.console.print(
                "[yellow]Uso: /model switch <nombre>  (ej: /model switch qwen2.5)[/]\n"
                "[dim]Usa /model list para ver los modelos disponibles.[/]"
            )
            return

        old_model = self.config.ollama_model

        self.config.ollama_model = model_name

        env_path = self.session.context.get("env_path", ".env")
        self._persist_env_key("OLLAMA_MODEL", model_name, env_path)

        self.console.print(Panel.fit(
            f"[bold][#00FF88]◎ Modelo cambiado[/][/bold]\n\n"
            f"Anterior: [#8B949E]{markup_escape(old_model)}[/]\n"
            f"Activo:   [bold][#00D4FF]{markup_escape(model_name)}[/][/bold]\n\n"
            f"[dim]Guardado en .env — activo en esta sesión y en las siguientes.[/]",
            border_style="#00FF88"
        ))

    def _persist_env_key(self, key: str, value: str, env_path: str = ".env") -> None:
        """Escribe o actualiza una clave en el archivo .env."""
        from pathlib import Path
        path = Path(env_path)
        line_new = f"{key}={value}\n"

        if path.exists():
            lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
            updated = False
            for i, line in enumerate(lines):
                if line.startswith(f"{key}=") or line.startswith(f"{key} ="):
                    lines[i] = line_new
                    updated = True
                    break
            if not updated:
                lines.append(line_new)
            path.write_text("".join(lines), encoding="utf-8")
        else:
            path.write_text(line_new, encoding="utf-8")

    def _show_scope(self) -> None:
        """Muestra el scope actual"""
        from rich.table import Table
        table = Table(title="Scope de la Operación")
        table.add_column("Objetivo", style="#00D4FF")
        table.add_column("Tipo", style="#00FF88")
        table.add_column("Notas", style="#8B949E")
        if not self.session.scope:
            table.add_row("[dim]No hay objetivos en scope[/]", "", "")
        else:
            for entry in self.session.scope:
                table.add_row(entry.target, entry.type, entry.notes or "")
        self.console.print(table)
    
    def _handle_scope_command(self, args: str) -> None:
        """Maneja comandos de scope"""
        if args.startswith("set "):
            target = args[4:].strip()
            self.session.add_to_scope(target)
            self.console.print(f"[#00FF88][OK][/] Aniadido al scope: {target}")
        elif args == "clear":
            self.session.scope.clear()
            self.console.print("[#00FF88][OK][/] Scope limpiado")
        else:
            self.session.add_to_scope(args)
            self.console.print(f"[#00FF88][OK][/] Aniadido al scope: {args}")
    
    def _auto_detect_scope(self, user_input: str) -> list[str]:
        """Detecta automáticamente objetivos (IPs, dominios, URLs) en el input del usuario.
        
        Returns:
            list: Lista de objetivos detectados
        """
        import re
        
        targets = []
        
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|dev|app|co|us|uk|eu|de|fr|es|it|ru|cn|jp|br|in|au|nl|pl|se|no|dk|fi|at|be|ch|ie|info|biz|xyz|top|site|live|cloud|tech|ai|app|me|tv|cc|tv|pro|online|store)\b'
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        cidr_pattern = r'\b(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3})/(?:[0-9]|[1-2][0-9]|3[0-2])\b'
        hostname_pattern = r'\b[a-zA-Z0-9][a-zA-Z0-9\-]*\.[a-zA-Z]{2,}\b'
        
        found_ips = re.findall(ip_pattern, user_input)
        found_cidrs = re.findall(cidr_pattern, user_input)
        found_domains = re.findall(domain_pattern, user_input)
        found_urls = re.findall(url_pattern, user_input)
        found_hostnames = re.findall(hostname_pattern, user_input)
        
        targets.extend(found_cidrs)
        
        for ip in found_ips:
            if not any(ip in cidr for cidr in targets):
                targets.append(ip)
        
        for url in found_urls:
            url_clean = url.rstrip('/')
            if '://' in url_clean:
                domain = url_clean.split('://')[1].split('/')[0]
                if domain not in targets and not any(domain in t for t in targets):
                    targets.append(domain)
        
        for domain in found_domains:
            if domain not in targets and not any(domain in t for t in targets):
                targets.append(domain)
        
        for hostname in found_hostnames:
            if hostname not in targets and not any(hostname in t for t in targets):
                targets.append(hostname)
        
        return list(dict.fromkeys(targets))
    
    def _detect_target_type(self, target: str) -> str:
        """Detecta el tipo de objetivo"""
        import re
        
        ip_pattern = r'^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))(?:/\d+)?$'
        url_pattern = r'^https?://'
        cidr_pattern = r'/\d+$'
        
        if re.match(ip_pattern, target):
            if re.search(cidr_pattern, target):
                return "network"
            return "ip"
        elif re.match(url_pattern, target):
            return "url"
        elif re.match(r'^[a-zA-Z0-9]+\.[a-zA-Z]{2,}$', target):
            return "domain"
        else:
            return "unknown"
    
    async def _set_role(self, role_args: str) -> None:
        """Establece el rol del operador y muestra feedback inmediato."""
        from specter.core.session import Role
        # /role set red-teamer  → role_args puede ser 'set red-teamer' o solo 'red-teamer'
        parts = role_args.strip().split()
        role_name = parts[-1].lower()  # toma siempre el último token como nombre
        role_map = {
            "pentester": Role.PENTESTER,
            "red-team": Role.RED_TEAMER,
            "red-teamer": Role.RED_TEAMER,
            "blue-team": Role.BLUE_TEAMER,
            "blue-teamer": Role.BLUE_TEAMER,
            "ctf": Role.CTF_PLAYER,
            "ctf-player": Role.CTF_PLAYER,
            "forense": Role.FORENSIC_ANALYST,
            "forensic": Role.FORENSIC_ANALYST,
        }
        role = role_map.get(role_name)
        if role:
            self.session.set_role(role)
            self.console.print(Panel.fit(
                f"""[bold]◈ ROL ACTIVADO[/bold]

[bold #00D4FF]{role.value.upper()}[/]

[#8B949E]El system prompt del LLM se actualizó para reflejar este rol.
Si hay scope definido, también se inyectará en cada consulta.[/]""",
                border_style="#00FF88"
            ))
        else:
            available = ", ".join(role_map.keys())
            self.console.print(f"[red]Rol desconocido: {role_name}[/]")
            self.console.print(f"[#8B949E]Roles disponibles: {available}[/]")

    def _list_roles(self) -> None:
        from rich.table import Table
        table = Table(title="Roles de Operador")
        table.add_column("Rol", style="#00D4FF")
        table.add_column("Descripción", style="#8B949E")
        roles = [
            ("pentester",   "Auditor profesional — metodología PTES, documentación exhaustiva"),
            ("red-teamer",  "Operador ofensivo — OPSEC, evasion, sigiloso"),
            ("blue-teamer", "Defensor — remediación, SIEM, detecciones"),
            ("ctf-player",  "Jugador CTF — educativo, hints progresivos"),
            ("forensic",    "Analista forense — cadena de custodia"),
        ]
        active = self.session.role.value if self.session.role else ""
        for r, d in roles:
            marker = "[bold #00FF88]► [/]" if r == active else "  "
            table.add_row(f"{marker}{r}", d)
        self.console.print(table)
    
    def _show_role(self) -> None:
        """Muestra el rol actual"""
        if self.session.role:
            self.console.print(f"Rol activo: [#00FF88]{self.session.role.value}[/]")
        else:
            self.console.print("[yellow]No hay rol activo[/]")
    
    def _show_skills(self) -> None:
        """Muestra skills disponibles"""
        from rich.table import Table
        table = Table(title="Skills Disponibles")
        table.add_column("Skill", style="#00D4FF")
        table.add_column("Descripción", style="#00FF88")
        table.add_column("Estado", style="#FFD60A")
        skills = [
            ("recon", "Reconocimiento y enumeracion", "[OK]"),
            ("osint", "Inteligencia de fuentes abiertas", "[--]"),
            ("web", "Auditoria de aplicaciones web", "[--]"),
            ("exploit", "Explotacion de vulnerabilidades", "[--]"),
            ("postex", "Post-explotacion", "[--]"),
            ("forense", "Analisis forense y DFIR", "[--]"),
            ("ad", "Active Directory security", "[--]"),
            ("report", "Generacion de informes", "[--]"),
        ]
        for skill_id, desc, status in skills:
            active = "[#00FF88]" if self.session.current_skill == skill_id else "[#8B949E]"
            table.add_row(skill_id, desc, f"{active}{status}[/]")
        self.console.print(table)
    
    # ── Gestión de Hallazgos ────────────────────────────────────────────

    def _add_finding(self, description: str) -> None:
        """Añade un hallazgo manual desde el operador.

        Formato: <severidad> <título>  (ej: HIGH Puerto MySQL expuesto)
        Si no hay severidad reconocida al inicio, se asume INFO.
        """
        sev_map = {"crit": "CRIT", "critical": "CRIT", "high": "HIGH",
                   "med": "MED", "medium": "MED", "low": "LOW", "info": "INFO"}
        parts = description.strip().split(maxsplit=1)
        if len(parts) >= 2 and parts[0].lower() in sev_map:
            severity = sev_map[parts[0].lower()]
            title = parts[1]
        else:
            severity = "INFO"
            title = description.strip()

        if not title:
            self.console.print("[yellow]Uso: /findings add [severidad] <título>[/]")
            return

        finding = Finding(title=title, severity=severity, tool="manual")
        self.session.add_finding(finding)
        # Persistir en disco automáticamente
        saved_path = self.session.save_findings()
        self.console.print(
            f"[#00FF88][OK][/] Hallazgo [{severity}] añadido: {title}\n"
            f"[dim]ID: {finding.id} | Guardado en {saved_path}[/]"
        )

    def _score_finding(self, args: str) -> None:
        """Asigna score CVSS a un hallazgo: /finding score <id> <score>."""
        parts = args.strip().split()
        if len(parts) < 2:
            self.console.print("[yellow]Uso: /finding score <id> <cvss> (ej: /finding score a1b2 7.5)[/]")
            return
        finding_id, score_str = parts[0], parts[1]
        try:
            score = float(score_str)
        except ValueError:
            self.console.print(f"[red]Score inválido: {score_str}[/]")
            return
        for f in self.session.findings:
            if f.id.startswith(finding_id):
                f.cvss = score
                self.session.save_findings()
                self.console.print(f"[#00FF88][OK][/] CVSS {score} asignado a {f.id}: {f.title}")
                return
        self.console.print(f"[red]Hallazgo no encontrado: {finding_id}[/]")

    # ── Report Generator ─────────────────────────────────────────────────

    async def _generate_report(self, preview: bool = False) -> None:
        """Genera un informe Markdown de la sesión actual."""
        from pathlib import Path
        from datetime import datetime
        from rich.markdown import Markdown

        session = self.session
        now = datetime.now().strftime("%Y-%m-%d %H:%M")
        counts = session.findings_count
        scope_targets = ", ".join(e.target for e in session.scope) or "Sin scope definido"
        role = session.role.value if session.role else "Ninguno"

        sev_colors = {"CRIT": "#FF3366", "HIGH": "#FF6B35", "MED": "#FFD60A",
                      "LOW": "#00FF88", "INFO": "#8B949E"}

        # ── Construir contenido Markdown ───────────────────────────────
        lines = [
            f"# SPECTER — Informe de Sesión",
            f"",
            f"**Fecha:** {now}  ",
            f"**Sesión ID:** `{session.id}`  ",
            f"**Nombre:** {session.name}  ",
            f"**Duración:** {session.duration}  ",
            f"**Rol:** {role}  ",
            f"",
            f"---",
            f"",
            f"## Scope de la Operación",
            f"",
            f"{scope_targets}",
            f"",
            f"---",
            f"",
            f"## Resumen Ejecutivo",
            f"",
            f"| Severidad | Hallazgos |",
            f"|---|---|",
            f"| 🚨 CRÍTICA | {counts['CRIT']} |",
            f"| 🔴 ALTA | {counts['HIGH']} |",
            f"| 🟡 MEDIA | {counts['MED']} |",
            f"| 🟢 BAJA | {counts['LOW']} |",
            f"| ℹ️ INFO | {counts['INFO']} |",
            f"| **TOTAL** | **{len(session.findings)}** |",
            f"",
            f"---",
            f"",
            f"## Hallazgos Detallados",
            f"",
        ]

        if not session.findings:
            lines.append("*No hay hallazgos registrados en esta sesión.*")
        else:
            for i, f in enumerate(session.findings, 1):
                lines += [
                    f"### {i}. [{f.severity}] {f.title}",
                    f"",
                    f"- **ID:** `{f.id}`",
                    f"- **Severidad:** {f.severity}",
                    f"- **CVSS:** {f.cvss if f.cvss is not None else 'N/A'}",
                    f"- **Herramienta:** {f.tool or 'manual'}",
                    f"- **Objetivo:** {f.target or scope_targets}",
                    f"- **Timestamp:** {f.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
                    f"",
                ]
                if f.description:
                    lines += [f"**Descripción:**", f"", f.description, f""]
                if f.evidence:
                    lines += [f"**Evidencia:**", f""]
                    for ev in f.evidence:
                        lines.append(f"- {ev}")
                    lines.append(f"")

        lines += [
            f"---",
            f"",
            f"## Log de Acciones",
            f"",
            f"| Timestamp | Acción | Datos |",
            f"|---|---|---|",
        ]
        for entry in session.log[-20:]:
            ts = entry['timestamp'][:19].replace('T', ' ')
            action = entry['action']
            data = str(entry.get('data', ''))[:60]
            lines.append(f"| {ts} | {action} | {data} |")

        lines += [
            f"",
            f"---",
            f"",
            f"*Generado automáticamente por SPECTER v2.0*",
        ]

        report_md = "\n".join(lines)

        if preview:
            self.console.print(Markdown(report_md))
            return

        # ── Guardar en disco ───────────────────────────────────────
        report_dir = Path("sessions") / session.id
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / f"report_{now.replace(':', '-').replace(' ', '_')}.md"
        report_path.write_text(report_md, encoding="utf-8")

        self.console.print()
        self.console.print(Panel.fit(
            f"[bold #00FF88]◎ Informe generado[/]\n\n"
            f"Ruta: [bold #00D4FF]{report_path}[/]\n"
            f"Hallazgos: [bold]{len(session.findings)}[/] — "
            f"[#FF3366]CRIT: {counts['CRIT']}[/]  "
            f"[#FF6B35]HIGH: {counts['HIGH']}[/]  "
            f"[#FFD60A]MED: {counts['MED']}[/]  "
            f"[#00FF88]LOW: {counts['LOW']}[/]",
            border_style="#00FF88"
        ))

    async def _export_report(self, fmt: str) -> None:
        """Exporta report en el formato pedido. Por ahora siempre MD (extensible)."""
        await self._generate_report(preview=False)

    def _show_session_report(self) -> None:
        """Muestra un reporte rápido de la sesión usando datos reales"""
        from rich.markdown import Markdown
        
        report = self.session.generate_session_report()
        self.console.print(Markdown(report))

    # ── Contexto y Log ──────────────────────────────────────────────────

    def _show_context(self) -> None:
        """Muestra el historial de conversación en memoria."""
        history = self.session.conversation_history
        if not history:
            self.console.print("[#8B949E]No hay historial de conversación.[/]")
            return
        self.console.print(f"[bold]Historial conversacional ({len(history)} mensajes)[/]")
        for msg in history:
            prefix = "[bold #00FF88]Usuario ▶[/]" if msg["role"] == "user" else "[bold #00D4FF]SPECTER ◆[/]"
            content = msg["content"][:200] + ("..." if len(msg["content"]) > 200 else "")
            self.console.print(f"{prefix} {content}")
            self.console.print()

    def _show_log(self) -> None:
        from rich.table import Table
        table = Table(title="Log de Sesión")
        table.add_column("Timestamp", style="#8B949E")
        table.add_column("Acción", style="#00D4FF")
        table.add_column("Datos", style="#E8E8E8")
        for entry in self.session.log[-30:]:
            ts = entry['timestamp'][:19].replace('T', ' ')
            table.add_row(ts, entry['action'], str(entry.get('data', ''))[:80])
        self.console.print(table)

    def _export_log(self) -> None:
        from pathlib import Path
        import json
        log_dir = Path("sessions") / self.session.id
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / "session_log.json"
        log_path.write_text(json.dumps(self.session.log, indent=2, ensure_ascii=False))
        self.console.print(f"[#00FF88][OK][/] Log exportado: [#00D4FF]{log_path}[/]")

    def _set_mode(self, mode: str) -> None:
        mode_map = {"paranoid": "paranoid", "standard": "standard", "expert": "expert"}
        if mode in mode_map:
            self.config.permission_mode = mode
            self.console.print(f"[#00FF88][OK][/] Modo de permisos: [bold]{mode}[/]")
        else:
            self.console.print("[yellow]Modos disponibles: paranoid | standard | expert[/]")

    def _show_findings(self) -> None:
        """Muestra hallazgos de la sesión"""
        from rich.table import Table
        table = Table(title=f"Hallazgos ({len(self.session.findings)})")
        table.add_column("ID", style="#8B949E")
        table.add_column("Severidad", style="#00FF88")
        table.add_column("Título", style="#00D4FF")
        table.add_column("Herramienta", style="#8B949E")
        severity_colors = {
            "CRIT": "#FF3366",
            "HIGH": "#FF6B35",
            "MED": "#FFD60A",
            "LOW": "#00FF88",
            "INFO": "#8B949E",
        }
        if not self.session.findings:
            table.add_row("[dim]No hay hallazgos[/]", "", "", "")
        else:
            for f in self.session.findings:
                color = severity_colors.get(f.severity, "#8B949E")
                table.add_row(
                    f.id,
                    f"[{color}]{f.severity}[/]",
                    f.title,
                    f.tool or "",
                )
        self.console.print(table)
    
    def _show_session_info(self) -> None:
        """Muestra información de la sesión"""
        counts = self.session.findings_count
        self.console.print(Panel.fit(
            f"""[b]Información de Sesión[/b]
            
ID: [#00D4FF]{self.session.id}[/]
Nombre: [#00FF88]{self.session.name}[/]
Duración: [#00FF88]{self.session.duration}[/]
Rol: [#FFD60A]{self.session.role.value if self.session.role else "Ninguno"}[/]
 
[b]Hallazgos[/b]
[ #FF3366]CRIT: {counts['CRIT']}[/]  [#FF6B35]HIGH: {counts['HIGH']}[/]  
[ #FFD60A]MED: {counts['MED']}[/]  [#00FF88]LOW: {counts['LOW']}[/]  [#8B949E]INFO: {counts['INFO']}[/]
 
[b]Scope[/b]
Objetivos: [#00D4FF]{len(self.session.scope)}[/]""",
            border_style="#00FF88"
        ))

    # --- Permissions/Audit integration hooks (best-effort) ---
    def _execute_with_permissions(self, action: str, tool: str, params: Optional[dict], risk_level: int = 0, *args, **kwargs):
        """Wrapper to enforce permissions before executing a tool, and log audit events."""
        from datetime import datetime as _dt
        try:
            per_ok = self._permission_manager.check_permission(action, risk_level)
        except Exception:
            per_ok = True
        if not per_ok:
            granted = self._permission_manager.request_confirmation(tool, params or {}, risk_description=f"Risk level {risk_level}")
            if not granted:
                self._audit_logger.log_action(self.session.id, action, tool, params or {}, result="blocked", timestamp=_dt.utcnow().isoformat() + "Z")
                raise PermissionError(f"Permission denied for action '{action}' on tool '{tool}'")
            self._permission_manager.log_permission_event(action, granted=True, reason="Explicit grant via workflow")
        else:
            self._permission_manager.log_permission_event(action, granted=True, reason="Granted by policy")
        result = None
        if hasattr(self, "execute_tool"):
            try:
                result = self.execute_tool(tool, params or {}, *args, **kwargs)
            except Exception:
                result = None
        self._audit_logger.log_action(self.session.id, action, tool, params or {}, result=result, timestamp=_dt.utcnow().isoformat() + "Z")
        return result
