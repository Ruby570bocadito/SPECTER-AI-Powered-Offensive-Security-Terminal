# SPECTER - AI-Powered Offensive Security Terminal

```
         ^
       _-^-_
    _-',^. `-_.
 ._-' ,'   `.   `-_      Security | Pentesting | Exploitation | Control | Terminal
!`-_._________`-':::
!   /\        /\::::    Unseen. Unconstrained. Unstoppable.
;  /  \      /..\ :::
! /    \    /....\::
!/      \  /......\:
;--.___. \/_.__.--;;
 '-_    `:!;;;;;;;'
     `-_, :!;;;''
         `-!'
```

**SPECTER** es un asistente de inteligencia artificial local especializado en ciberseguridad ofensiva y defensiva. 100% offline. Diseñado para **pentesters profesionales**, **equipos Red/Blue Team**, y **jugadores CTF**.

---

## ✨ Características Principales

| Característica | Descripción |
|----------------|-------------|
| 🤖 **LLM Local** | Integración con Ollama (devstral, llama3, qwen, gemma). Zero datos a la nube |
| 🔧 **MCP Avanzado** | Tool Templates, Chaining, Auto-discovery, Output Parsers |
| 🧠 **Skills IA** | Recon, OSINT, Web, Post-Ex, Forense, Active Directory, Reporting |
| ⚡ **Orquestador** | Sub-agentes paralelos: Recon, Exploit, Analyst, Reporter |
| 📚 **Wordlists** | 700+ entradas integradas + soporte para rockyou.txt, SecLists, archivos externos |
| 🔄 **Workflows** | Conditional steps, loops, variables, editor interactivo, ejecución real de skills |
| 🛡️ **Sandbox** | Allow-all con blacklist inteligente, scope validation, rate limiting, auto-sudo |
| 🔒 **Guardrails** | Validación de comandos LLM: flags inventados, IPs inválidas, CVEs falsos |
| 💾 **Persistencia** | SQLite para findings, backup/restore de sesiones JSON |
| 📊 **Reporting** | Markdown, JSON, CSV + export ATT&CK Navigator para visualización |
| 🧩 **Plugins** | Sistema v2 con schema validation, dependency resolution, sandboxing, hot-reload |
| 🌐 **i18n** | Soporte multi-idioma (español/inglés) |
| 📋 **Log Rotation** | Rotación automática con compresión gzip |
| 🐳 **Docker** | Kali Linux + herramientas pentesting + Ollama |
| 🎨 **UI** | Tema oscuro, syntax highlighting, código compacto |

---

## 🚀 Instalación

### Requisitos
- Python 3.10+
- Ollama (opcional, para LLM)

### Instalación rápida

```bash
git clone https://github.com/Ruby570bocadito/SPECTER-AI-Powered-Offensive-Security-Terminal.git
cd SPECTER-AI-Powered-Offensive-Security-Terminal
pip install -e ".[dev,ollama,export,workflows]"
./run.sh
```

### Con Ollama (recomendado)

```bash
# Instalar Ollama: https://ollama.com
ollama pull devstral-small-2:latest
ollama serve
./run.sh
```

> El modelo por defecto es `devstral-small-2:latest`. Cambialo con `/model switch <nombre>`.

### Docker (entorno completo)

```bash
# Construir y ejecutar con Ollama incluido
docker compose up -d

# Acceder al terminal
docker compose exec specter python -m specter.cli.main
```

> El Docker incluye Kali Linux con nmap, gobuster, ffuf, nikto, sqlmap, hydra, crackmapexec, impacket, y más.

---

## 📖 Uso

### Inicio

```bash
# Con LLM
./run.sh

# Sin LLM (solo terminal)
./run.sh --no-llm
```

### Comandos Principales

| Comando | Descripción |
|---------|-------------|
| `/scope set 192.168.1.1` | Añadir IP al scope |
| `/scope set example.com` | Añadir dominio |
| `/scope` | Ver scope actual |
| `/scope clear` | Limpiar scope |
| `/model list` | Ver modelos disponibles |
| `/model switch <nombre>` | Cambiar modelo activo |
| `/role pentester` | Auditor profesional |
| `/role red-teamer` | Operador ofensivo |
| `/role blue-teamer` | Defensor |
| `/role ctf-player` | Jugador CTF |
| `/role forensic-analyst` | Analista forense |
| `/skills` | Listar skills |
| `/tools` | Listar herramientas MCP |
| `/wordlist dir` | 72 directorios comunes |
| `/wordlist subdomain` | 120+ subdominios |
| `/wordlist user` | 60+ usernames |
| `/wordlist pass` | 150+ contraseñas |
| `/wordlist sql` | SQL Injection payloads |
| `/wordlist xss` | XSS payloads |
| `/wordlist lfi` | LFI payloads |
| `/wordlist cve` | CVE search patterns |
| `/agent list` | Ver agentes |
| `/agent spawn <task>` | Desplegar tarea |
| `/read <archivo>` | Leer archivo |
| `/finding add "texto"` | Añadir hallazgo |
| `/findings` | Ver hallazgos |
| `/report generate` | Generar informe |
| `/session` | Info de sesión |
| `/mode paranoid` | Confirmación en cada comando |
| `/mode standard` | Modo por defecto |
| `/mode expert` | Sin confirmaciones |
| `/deploy task <desc>` | Desplegar tarea a agentes |
| `/deploy status` | Estado de tareas desplegadas |
| `/deploy list` | Listar tareas desplegadas |
| `/workflow run <name>` | Ejecutar workflow (full_pentest, web_audit, etc.) |
| `/workflow list` | Listar workflows disponibles |
| `/workflow status` | Estado del workflow en curso |
| `/plugin list` | Listar plugins instalados |
| `/plugin install <name>` | Instalar plugin desde marketplace |
| `/plugin info <name>` | Info de un plugin |
| `/plugin search <query>` | Buscar plugins en marketplace |
| `/perf` | Estadísticas de performance del engine |
| `/help` | Ayuda completa |
| `/clear` | Limpiar terminal |

### Conversación Natural

Habla con SPECTER en español o inglés:

```
Usuario: "escanea los puertos de 192.168.1.1"
SPECTER: Voy a realizar un escaneo de puertos...
<cmd>nmap -sV -p- 192.168.1.1</cmd>
[Output formateado con tabla de puertos]
¿Qué siguiente paso sugiere?
  1. Enumerar servicios web (nikto, nuclei)
  2. Intentar fuerza bruta en SSH
  3. Análisis SSL/TLS
```

El LLM puede:
- **Ejecutar comandos** usando etiquetas `<cmd>...</cmd>`
- **Leer archivos** con "muéstrame el contenido de X"
- **Desplegar agentes** automáticamente para tareas complejas
- **Generar código** en bloques markdown con syntax highlighting
- **Auto-sudo** — si un comando falla por permisos, reintenta con sudo automáticamente

---

## 🛡️ Seguridad

### Sandbox (Allow-All)

SPECTER usa un modelo **allow-all con blacklist inteligente de destructivos**:

**Permitido** — cualquier herramienta de pentesting:
- nmap, gobuster, ffuf, nikto, sqlmap, hydra
- mimikatz, responder, bloodhound, crackmapexec
- proxychains, chisel, reverse shells
- custom exploits y scripts propios

**Bloqueado** — solo destructivos:
- `rm -rf /`, `rm -r -f /`, `rm -f -r /` (cualquier orden de flags)
- `dd if=/dev/zero`, `mkfs`, `> /dev/sdX`
- Fork bombs, shutdown/reboot/halt/poweroff
- `kill -9 1`, `killall systemd`, `pkill -SIGKILL init`
- `systemctl poweroff/reboot/halt`

### Restricciones Activas

| Protección | Descripción |
|---|---|
| **Scope Validation** | Solo ataca IPs/dominios en scope autorizado (soporta CIDR, subdominios) |
| **Rate Limiting** | 2s mínimo entre comandos (evita loops del LLM) |
| **Límite de Sesión** | 500 comandos máximo por sesión |
| **LLM Guardrails** | Detecta flags inventados, IPs inválidas, CVEs falsos, sintaxis incorrecta |
| **Logging Separado** | `commands_llm.jsonl` vs `commands_manual.jsonl` |
| **Modo Paranoid** | Confirmación obligatoria para cada comando |
| **Auto-Sudo** | Reintenta con sudo si detecta error de permisos |
| **Audit HMAC Chain** | Logs de auditoría con cadena HMAC para detección de tampering |

---

## 🤖 Sub-Agentes

| Agente | Función |
|--------|---------|
| Recon Agent | OSINT, fingerprinting, enumeración |
| Exploit Agent | Exploits, bypass AV/EDR/AMSI |
| Analyst Agent | Análisis de resultados |
| Reporter Agent | Generación de reportes |

---

## 🧩 Sistema de Plugins

Plugins con validación completa:

```yaml
# plugin.yaml
name: my-plugin
version: 1.0.0
description: Custom recon tool
author: tu-nombre
min_specter_version: 0.1.0
dependencies:
  - requests
  - beautifulsoup4
entry_point: my_plugin.main
permissions:
  - network
  - filesystem
```

```bash
# Desde SPECTER
/plugin install plugin.zip    # Instalar desde archivo
/plugin list                   # Listar plugins
/plugin enable <nombre>        # Activar
/plugin disable <nombre>       # Desactivar
/plugin reload <nombre>        # Hot-reload
/plugin uninstall <nombre>     # Desinstalar
```

---

## 📚 Wordlists Externas

Carga wordlists externas además de las integradas:

```bash
# Cargar archivo externo
/wordlist load /path/to/rockyou.txt

# Descargar SecLists
/wordlist download Discovery/Web-Content/common.txt

# Escanear directorio
/wordlist scan /usr/share/wordlists/

# Merge de wordlists
/wordlist merge rockyou.txt custom.txt output.txt
```

---

## 📊 MITRE ATT&CK Navigator

Exporta hallazgos como capas de ATT&CK Navigator:

```bash
# Exportar capa para Navigator
/mitre export-navigator

# Ver matriz de cobertura
/mitre coverage

# Exportar reporte completo
/mitre report
```

El archivo JSON resultante se importa directamente en [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).

---

## 💾 Persistencia

### Backup/Restore de Sesiones

```bash
# Backup automático al cerrar sesión
# Los datos se guardan en sessions/<id>/session_backup.json

# Restaurar sesión
# (desde el código)
from specter.core.session import Session
session = Session.restore_from_backup("sessions/abc123/session_backup.json")
```

### FindingStore (SQLite)

Los hallazgos se almacenan en SQLite para persistencia total:

```python
from specter.core.storage import FindingStore, PersistentFinding

store = FindingStore("sessions/my_session/findings.db")
store.add(PersistentFinding(
    title="SQL Injection en login",
    severity="CRIT",
    tool="sqlmap",
    target="http://target.com/login",
    cvss=9.8,
))

# Exportar
store.export_markdown()  # Reporte profesional
store.export_json()      # Para integración con otras herramientas
```

---

## 📦 Arquitectura

```
src/specter/
├── agents/                    # Orquestador y sub-agentes
├── cli/                       # CLI interactiva (prompt_toolkit)
├── core/                      # Motor principal
│   ├── engine.py              # Orquestador principal
│   ├── llm_handler.py         # Streaming y gestión de modelos
│   ├── command_executor.py    # Ejecución de comandos, batch, agentes
│   ├── report_generator.py    # Generación de reportes
│   ├── command_router.py      # Routing de slash commands
│   ├── tool_service.py        # Display de output de herramientas
│   ├── sandbox.py             # Allow-all sandbox con auto-sudo
│   ├── guardrails.py          # LLM command validation
│   ├── storage.py             # SQLite FindingStore
│   ├── session.py             # Session management + backup/restore
│   ├── permissions.py         # 3 modos de permiso
│   ├── mitre.py               # MITRE ATT&CK integration
│   ├── mitre_navigator.py     # ATT&CK Navigator export
│   ├── audit.py               # Audit log con HMAC chain
│   ├── wordlist_loader.py     # External wordlists (SecLists, rockyou)
│   ├── i18n.py                # Internacionalización (es/en)
│   ├── log_rotation.py        # Rotación de logs con gzip
│   └── config.py              # Configuración (pydantic-settings)
├── llm/                       # Integración Ollama
│   ├── client.py              # Cliente Ollama
│   ├── prompt_builder.py      # System prompts por rol
│   ├── connection_manager.py  # Gestión de conexión
│   └── service.py             # Streaming service
├── mcp/                       # Model Context Protocol
│   ├── tool.py                # Definición de herramientas
│   ├── registry.py            # Registro básico
│   ├── advanced_registry.py   # Templates, chains, parsers
│   └── executor.py            # Motor de ejecución con wordlists integradas
├── skills/                    # Skills de IA
│   ├── recon.py, osint.py, web.py
│   ├── postex.py, forense.py, ad.py
│   └── report.py, advanced_framework.py
├── wordlists/                 # Diccionarios integrados (700+ entradas)
│   └── dictionaries.py
├── workflows/                 # Motor de workflows
│   ├── executor.py            # WorkflowExecutor con conditional branching
│   └── definitions.py         # 5 workflows built-in
└── plugins/                   # Sistema de plugins v2
    ├── base.py                # Plugin base class
    ├── plugin_manager.py      # Manager con sandbox, deps, hot-reload
    └── marketplace.py         # Plugin marketplace client
```

---

## 🧪 Testing

```bash
# Instalar dependencias de desarrollo
pip install -e ".[dev]"

# Ejecutar tests
python -m pytest tests/ -v

# Con coverage
python -m pytest tests/ --cov=src/specter --cov-report=html

# Tests específicos
python -m pytest tests/test_sandbox.py tests/test_guardrails.py tests/test_engine.py -v
```

**314 tests pasan** (sandbox + guardrails + engine + core + skills + workflows + executor + marketplace + command router + LLM handler + e2e).

---

## ⚙️ Configuración

```env
# .env
SPECTER_OLLAMA_HOST=http://localhost:11434
SPECTER_OLLAMA_MODEL=devstral-small-2:latest
SPECTER_DATA_DIR=./sessions
SPECTER_AUDIT_SECRET=your-secret-key
```

```ini
# specter.ini (configuración avanzada)
[llm]
host = http://localhost:11434
model = devstral-small-2:latest
temperature = 0.7

[permissions]
mode = standard
auto_save = true

[ui]
colors = dark
show_model = true
language = es
```

---

## 🔧 Solución de Problemas

### Windows encoding
```cmd
chcp 65001
```

### Ollama no responde
```bash
ollama serve
ollama pull devstral-small-2:latest
```

### Import errors
```bash
pip install -e .
```

### Comando necesita root
SPECTER detecta automáticamente errores de permisos y pregunta si quieres reintentar con `sudo`. Solo necesitás que tu usuario tenga sudo configurado.

### Salir de SPECTER
- Escribí `exit`, `quit` o `salir`
- O presioná `Ctrl+C` dos veces seguidas

---

## ⚠️ Uso Ético

Este software es para **uso profesional ético autorizado**. Solo usa en sistemas donde tengas permiso explícito por escrito. Los autores no se responsabilizan del uso indebido.

---

## 📄 Licencia

MIT License

---

## 🏗️ CI/CD

El proyecto incluye GitHub Actions para:
- **Linting** con Ruff
- **Testing** con pytest + coverage
- **Type checking** con mypy
- **Multi-plataforma**: Ubuntu + Windows, Python 3.10-3.12

---

## 🐳 Docker Compose

```yaml
# docker-compose.yml incluido
services:
  ollama:
    image: ollama/ollama:latest
    ports: ["11434:11434"]
    volumes: [ollama_data:/root/.ollama]
    deploy:
      resources:
        reservations:
          devices: [{driver: nvidia, count: 1, capabilities: [gpu]}]

  specter:
    build: .
    depends_on: [ollama]
    environment:
      - SPECTER_OLLAMA_HOST=http://ollama:11434
    volumes:
      - specter_sessions:/app/sessions
      - specter_output:/app/output
    network_mode: host
```
