# SpecterEngine

## Descripción

`SpecterEngine` es el núcleo orquestador de SPECTER. Coordina la interacción entre:

- CLI (input del usuario)
- LLM (razonamiento e interpretación)
- Skills (habilidades especializadas)
- Tools (herramientas MCP)
- Session (contexto y memoria)

## Ubicación

```
src/specter/core/engine.py
```

## Clase Principal

```python
class SpecterEngine:
    def __init__(self, session: Session, config: SpecterConfig):
        self.session = session
        self.config = config
        self.console = Console()
        self.skill_manager: Optional[SkillManager] = None
        self.tool_registry: Optional[ToolRegistry] = None
```

## Métodos Principales

### `initialize()`

Inicializa el motor, carga skills y herramientas.

```python
await engine.initialize()
```

### `process_input(user_input: str)`

Procesa input del usuario (comandos o lenguaje natural).

```python
await engine.process_input("/scope set 192.168.1.1")
await engine.process_input("escanea los puertos de 192.168.1.1")
```

### `_execute_batch(commands: list[str])`

Ejecuta múltiples comandos en paralelo.

```python
results = await engine._execute_batch([
    "nmap -sV 192.168.1.1",
    "nmap -sV 192.168.1.2",
    "nmap -sV 192.168.1.3"
])
```

### `_execute_batch_with_dependencies(commands, max_concurrent=5)`

Ejecuta comandos con dependencias y límite de concurrencia.

```python
results = await engine._execute_batch_with_dependencies([
    {"id": "scan1", "command": "nmap 192.168.1.1"},
    {"id": "scan2", "command": "nmap 192.168.1.2", "depends_on": ["scan1"]},
])
```

## Integración de Permisos

El motor verifica permisos antes de ejecutar herramientas:

```python
async def _execute_with_permissions(
    self, 
    action: str, 
    tool: str, 
    params: Optional[dict],
    risk_level: int = 0
):
```

## Ejecución de Comandos LLM

El LLM puede proponer comandos usando `<cmd>...</cmd>`:

```
<cmd>nmap -sV 192.168.1.1</cmd>
```

El sistema pide confirmación antes de ejecutar (excepto en modo expert).