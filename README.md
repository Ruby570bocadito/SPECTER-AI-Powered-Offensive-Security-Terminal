# SPECTER - AI-Powered Offensive Security Terminal

```
    _-_.     _-',^. `-_.
 ._-' ,'   `.   `-_      Security | Pentesting | Exploitation | Control | Terminal
!`-_._________`-':::
!   /\        /\::::    Unseen. Unconstrained. Unstoppable.
;  /  \      /..\ :::
!/      \  /......\:
;--.___. \/_.__.--;;
 '-_    `:!;;;;;;;'
     `-_, :!;;;''
         `-!'
```

**SPECTER** es un asistente de inteligencia artificial local especializado en ciberseguridad ofensivo y defensiva. Ejecútalo 100% offline.

---

## ✨ Características Principales

| Característica | Descripción |
|----------------|-------------|
| 🤖 **LLM Local** | Integración con Ollama (devstral, llama3.2, qwen) |
| 🔧 **MCP Avanzado** | Tool Templates, Chaining, Auto-discovery, Parsers |
| 🧠 **Skills IA** | Dependencies, Events, Templates, Cross-skill, Analytics |
| ⚡ **Orquestador** | Sub-agentes parallel: Recon, Exploit, Analyst, Reporter |
| 📚 **Dictionaries** | 72 directorios, 114 subdomains, payloads SQL/XSS/LFI |
| 🔄 **Workflows** | Conditional, Loop, Variables, Interactive |
| 🛡️ **Permisos** | 3 modos: paranoid/standard/expert con auditoría |
| 📊 **Reporting** | MD, JSON, CSV |
| 🎨 **UI** | Tema oscuro, syntax highlighting, código compacto |

---

## 🚀 Instalación

### Requisitos
- Python 3.10+
- Ollama (opcional, para LLM)

### Windows
```powershell
cd specter
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -e .
python -m specter.cli.main
```

### Linux/macOS
```bash
cd specter
python -m venv venv
source venv/bin/activate
pip install -e .
python -m specter.cli.main
```

### Ollama (opcional)
```bash
# Instalar Ollama desde https://ollama.com
ollama pull devstral-small-2:latest
```

---

## 📖 Uso

### Inicio
```bash
python -m specter.cli.main
# Sin LLM:
python -m specter.cli.main --no-llm
```

### Comandos

| Comando | Descripción |
|---------|-------------|
| `/scope 192.168.1.1` | Añadir IP al scope |
| `/scope example.com` | Añadir dominio |
| `/scope` | Ver scope actual |
| `/scope clear` | Limpiar scope |
| `/role <rol>` | Cambiar rol (pentester, red-team, blue-team) |
| `/skills` | Listar skills |
| `/tools` | Listar herramientas |
| `/wordlist dir` | Ver directorios comunes |
| `/wordlist subdomain` | Ver subdominios |
| `/wordlist sql` | Ver payloads SQLi |
| `/wordlist xss` | Ver payloads XSS |
| `/agent list` | Ver agentes |
| `/agent spawn <task>` | Desplegar tarea |
| `/read <archivo>` | Leer archivo |
| `/finding add "texto"` | Añadir hallazgo |
| `/report generate` | Generar informe |
| `/mode paranoid` | Modo confirmación total |
| `/mode expert` | Sin confirmaciones |
| `/help` | Ayuda |
| `/clear` | Limpiar |

### Conversación Natural

El modelo puede:
- **Ejecutar comandos** cuando usas `<cmd>...</cmd>`
- **Leer archivos** con `leer <ruta>`, `ver <ruta>`, `cat <ruta>`
- **Desplegar agentes** con `despliega agente`, `crea agente`, `inicia agente`

---

## 🎨 Modos de Permiso

| Modo | Lectura | Agentes | Comandos | Descripción |
|------|---------|---------|----------|-------------|
| **paranoid** | ✋ | ✋ | ✋ | Confirmación en TODO |
| **standard** | ✓ | ✓ | ✋ | Por defecto |
| **expert** | ✓ | ✓ | ✓ | Auto-ejecuta |

---

## 🤖 Sub-Agentes

| Agente | Función |
|--------|---------|
| Recon Agent | OSINT, fingerprinting, enumeración |
| Exploit Agent | Exploits, bypass AV/EDR |
| Analyst Agent | Análisis de resultados |
| Reporter Agent | Generación de reportes |

---

## 📦字典 (Dictionaries)

```bash
/wordlist dir          # 72 directorios comunes
/wordlist subdomain    # 114 subdominios  
/wordlist user         # 50+ usernames
/wordlist pass         # 100+ contraseñas
/wordlist sql          # SQL Injection payloads
/wordlist xss          # XSS payloads
/wordlist lfi          # LFI payloads
/wordlist cve          # CVE search patterns
/wordlist all          # Todos
```

---

## ⚙️ Configuración

```env
# specter.ini
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

---

## ⚠️ Uso Ético

Este software es para **uso profesional ético autorizado**. Solo usa en sistemas donde tengas permiso explícito.

---

## 📄 Licencia

MIT License
