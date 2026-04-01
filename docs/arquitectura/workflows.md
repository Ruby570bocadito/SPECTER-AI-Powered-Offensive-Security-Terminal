# Workflow Engine

## Descripción

Sistema de automatización de flujos de trabajo con soporte para archivos YAML y JSON.

## Ubicación

```
src/specter/workflows.py
```

## Uso Básico

```python
from specter.workflows import WorkflowEngine

engine = WorkflowEngine(workflows_dir="workflows/custom")

# Listar workflows
workflows = engine.list_workflows()

# Ejecutar workflow
results = engine.execute_workflow("full_recon", session)
```

## Workflows Predeterminados

| Workflow | Descripción |
|----------|-------------|
| `full_recon` | Reconocimiento completo |
| `web_audit` | Auditoría web completa |
| `ad_attack` | Ataque Active Directory |
| `quick_scan` | Scan rápido |

## Formato YAML

```yaml
# workflows/osint_breach_check.yaml
name: "osint_breach_check"
description: "Check for email breaches"
steps:
  - skill: osint
    action: email_breach
    params:
      domain: "{{target}}"
  - skill: osint
    action: paste_search
    params:
      email: "{{email}}"
```

## Formato JSON

```json
{
  "name": "web_scan",
  "description": "Full web vulnerability scan",
  "steps": [
    {
      "skill": "web",
      "action": "dir_fuzz",
      "params": {
        "url": "http://target.com"
      }
    },
    {
      "skill": "web",
      "action": "nuclei_scan",
      "params": {
        "target": "http://target.com"
      }
    }
  ]
}
```

## Variables de Plantilla

Los workflows soportan variables:

```yaml
steps:
  - skill: recon
    action: scan
    params:
      target: "{{target}}"
```

Las variables se reemplazan en tiempo de ejecución con el contexto de la sesión.

## Dependencias

```yaml
steps:
  - id: scan1
    skill: recon
    action: ping_sweep
    params:
      network: "192.168.1.0/24"
  
  - id: scan2
    skill: recon
    action: port_scan
    depends_on: ["scan1"]
    params:
      targets: "{{scan1.results.hosts}}"
```

## Carga Programática

```python
# Cargar workflow desde string
engine.load_workflow_from_string(yaml_content, "custom", format="yaml")

# Filtrar por origen
builtin = engine.list_workflows(source_filter="builtin")
custom = engine.list_workflows(source_filter="yaml")
```