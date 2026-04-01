# Configuración

## Variables de Entorno

Crear archivo `.env` en la raíz del proyecto:

```env
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama3.2
PERMISSION_MODE=standard
LOG_LEVEL=INFO
LLM_TEMPERATURE=0.7
LLM_CONTEXT_WINDOW=4096
```

## Configuración

| Variable | Descripción | Valor por defecto |
|----------|-------------|-------------------|
| `OLLAMA_HOST` | Host de Ollama | `http://localhost:11434` |
| `OLLAMA_MODEL` | Modelo a usar | `llama3.2` |
| `PERMISSION_MODE` | Modo de permisos | `standard` |
| `LOG_LEVEL` | Nivel de log | `INFO` |
| `LLM_TEMPERATURE` | Temperatura del LLM | `0.7` |

## Modos de Permisos

| Modo | Descripción |
|------|-------------|
| `paranoid` | Confirmación en todas las acciones |
| `standard` | Solo confirmación en acciones intrusivas |
| `expert` | Sin confirmaciones |

## Archivo de Configuración

También puedes usar un archivo TOML:

```toml
[llm]
host = "http://localhost:11434"
model = "llama3.2"
temperature = 0.7
context_window = 4096
enabled = true

[permissions]
mode = "standard"

[logging]
level = "INFO"
file = "specter/log/specter.log"

[ui]
colors = true
autocomplete = true
```

## Modelos Soportados

- **Ollama**: Cualquier modelo disponible localmente
- **LM Studio**: Conectado en `http://localhost:1234`

### Modelos Recomendados

| Modelo | RAM | Uso |
|--------|-----|-----|
| `llama3.2` | 2GB | General |
| `mistral` | 4GB | Mejor rendimiento |
| `codellama` | 4GB | Código |
| `mixtral` | 6GB | Mejor calidad |