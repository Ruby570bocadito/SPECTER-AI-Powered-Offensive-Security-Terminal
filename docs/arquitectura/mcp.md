# MCP Tool Registry

## Descripción

Registry central de herramientas MCP con sistema de caché para optimizar rendimiento.

## Ubicación

```
src/specter/mcp/registry.py
```

## Características

### Caché TTL

Las herramientas se cachean con TTL de 1 hora por defecto:

```python
registry = ToolRegistry(cache_ttl=3600)  # 1 hora

# La primera llamada populates el caché
tool = registry.get_tool_cached("network.port_scan")

# Llamadas siguientes usan caché
tool = registry.get_tool_cached("network.port_scan")  # cache hit
```

### Invalidation

```python
# Invalidar caché específico
registry.invalidate_cache("network.port_scan")

# Invalidar todo el caché
registry.invalidate_cache()
```

### Estadísticas

```python
stats = registry.get_cache_stats()
# {'cached_tools': 5, 'total_tools': 15, 'cache_ttl': 3600}
```

## Herramientas Incorporadas

### Red

| Herramienta | Descripción | Riesgo |
|-------------|-------------|--------|
| `network.port_scan` | Escaneo de puertos | 1 |
| `network.ping_sweep` | Descubrimiento de hosts | 0 |
| `network.dns_enum` | Enumeración DNS | 0 |

### Sistema

| Herramienta | Descripción | Riesgo |
|-------------|-------------|--------|
| `system.process_list` | Lista procesos | 0 |
| `system.network_conns` | Conexiones de red | 0 |

### Web

| Herramienta | Descripción | Riesgo |
|-------------|-------------|--------|
| `web.dir_fuzz` | Fuzzing directorios | 1 |
| `web.sqlmap` | Test inyección SQL | 2 |

### Password

| Herramienta | Descripción | Riesgo |
|-------------|-------------|--------|
| `password.hash_crack` | Crackeo de hashes | 1 |

## Registro de Herramientas

```python
from specter.mcp.tool import MCPTool, ToolParameter

registry.register(MCPTool(
    name="custom.tool",
    description="Herramienta custom",
    category="custom",
    skill="recon",
    risk_level=1,
    parameters=[
        ToolParameter(name="target", type="string", required=True),
    ],
    command="custom_tool"
))
```

## Búsqueda

```python
# Por categoría
tools = registry.list_tools(category="network")

# Por nivel de riesgo
tools = registry.list_by_risk_level(0)

# Búsqueda por texto
tools = registry.search("port")
```