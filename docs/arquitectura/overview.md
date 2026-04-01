# Arquitectura de SPECTER

## Diagrama de Componentes

```
┌─────────────────────────────────────────────────────────────────┐
│                         SPECTER CLI                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │   Prompt    │  │  Commands   │  │  Context-Aware           │  │
│  │   Parser    │  │  Handler    │  │  Completer               │  │
│  └──────┬──────┘  └──────┬──────┘  └─────────────────────────┘  │
└─────────┼────────────────┼──────────────────────────────────────┘
          │                │
          ▼                ▼
┌─────────────────────────────────────────────────────────────────┐
│                     SPECTER ENGINE                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │   LLM       │  │  Session     │  │  Permission             │  │
│  │   Client    │  │  Manager     │  │  Manager                │  │
│  └──────┬──────┘  └──────┬──────┘  └─────────────────────────┘  │
│         │                │                                      │
│  ┌──────┴────────────────┴──────┐                               │
│  │     Skill Manager            │                               │
│  │  (Lazy Loading)               │                               │
│  └──────┬───────────────────────┘                               │
└─────────┼───────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│                       SKILLS LAYER                               │
│  ┌───────┐ ┌───────┐ ┌───────┐ ┌───────┐ ┌───────┐             │
│  │ Recon │ │ OSINT │ │  Web  │ │Postex │ │Forense│ ...         │
│  └───────┘ └───────┘ └───────┘ └───────┘ └───────┘             │
└─────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│                      MCP TOOLS LAYER                             │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │  Tool Registry (Cached)                                      │ │
│  │  - network.port_scan    - web.dir_fuzz     - system.*      │ │
│  │  - network.ping_sweep   - web.sqlmap       - hash.*        │ │
│  │  - network.dns_enum     - vuln.scan        - cve.lookup     │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## Flujo de Datos

1. **Usuario** → CLI (comando o lenguaje natural)
2. **CLI** → Engine (procesa input)
3. **Engine** → LLM (si está habilitado) o Skills
4. **Skills** → Tool Registry → Comandos del sistema
5. **Resultados** → Session (almacena hallazgos)
6. **Report** → Genera informes (MD, PDF, DOCX, HTML)

## Módulos Principales

| Módulo | Descripción |
|--------|-------------|
| `core/engine` | Orquestador principal |
| `core/session` | Gestión de sesiones y hallazgos |
| `core/permissions` | Sistema de permisos |
| `skills/*` | Habilidades especializadas |
| `mcp/registry` | Registro de herramientas (con caché) |
| `llm/*` | Integración con LLM |
| `cli/*` | Interfaz de línea de comandos |

## Patrones de Diseño

- **Lazy Loading**: Skills se cargan bajo demanda
- **Cache TTL**: Herramientas MCP con caché de 1 hora
- **Batch Processing**: Comandos paralelos con dependencias
- **Plugin System**: Sistema extensible de plugins
- **Actionable Errors**: Errores con sugerencias de resolución