# Referencia de Comandos

## Comandos de Sesión

| Comando | Descripción |
|---------|-------------|
| `/scope set <target>` | Añadir objetivo al scope |
| `/scope show` | Ver scope actual |
| `/scope clear` | Limpiar scope |
| `/session` | Información de sesión |
| `/role <nombre>` | Cambiar rol |
| `/model switch <nombre>` | Cambiar modelo LLM |

## Comandos de Skills

| Comando | Descripción |
|---------|-------------|
| `/skills` | Listar skills disponibles |
| `/skill use <nombre>` | Activar skill |
| `/skill info <nombre>` | Info de skill |
| `/tools` | Listar herramientas |

## Comandos de Hallazgos

| Comando | Descripción |
|---------|-------------|
| `/findings` | Ver hallazgos |
| `/findings add <desc>` | Añadir hallazgo |
| `/finding score <id> <cvss>` | Asignar CVSS |

## Comandos de Reportes

| Comando | Descripción |
|---------|-------------|
| `/report generate` | Generar informe |
| `/report preview` | Vista previa |
| `/report export <fmt>` | Exportar (md/json/csv) |

## Comandos de Workflows

| Comando | Descripción |
|---------|-------------|
| `/workflow run <nombre>` | Ejecutar workflow |
| `/workflow list` | Listar workflows |

## Roles Disponibles

- `pentester` - Auditor profesional
- `red-team` - Red Team
- `blue-team` - Blue Team
- `ctf-player` - CTF
- `forensic` - Forense

## Modos

| Comando | Descripción |
|---------|-------------|
| `/mode paranoid` | Máxima seguridad |
| `/mode standard` | Moderado |
| `/mode expert` | Sin confirmaciones |

## Utilidades

| Comando | Descripción |
|---------|-------------|
| `/help` | Mostrar ayuda |
| `/clear` | Limpiar pantalla |
| `/history` | Historial |
| `/log` | Ver log |
| `exit` | Salir |

## Ejemplos

```bash
/scope set 192.168.1.1
/role pentester
/skill use recon
/workflow run quick_scan
/report generate
```