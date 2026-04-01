# Guía de Instalación

## Requisitos

- Python 3.10+ (3.11, 3.12, 3.13)
- Ollama (opcional, para LLM)
- 4GB RAM mínimo
- 2GB espacio en disco

## Instalación

### Linux / macOS

```bash
cd specter
python -m venv venv
source venv/bin/activate
pip install -e .

chmod +x run.sh
./run.sh
```

### Windows (PowerShell)

```powershell
cd specter
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -e .

.\run.bat
```

### Windows (CMD)

```cmd
cd specter
python -m venv venv
venv\Scripts\activate.bat
pip install -e .

run.bat
```

## Ollama (Opcional)

### Linux/macOS

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2
```

### Windows

Descargar desde https://ollama.com/download

```powershell
ollama pull llama3.2
```

## Verificación

```bash
specter --help
specter --version
```

## Modo sin LLM

```bash
specter --no-llm
```

## Desarrollo

```bash
pip install -e ".[dev]"
pytest tests/
ruff check src/
mypy src/
```