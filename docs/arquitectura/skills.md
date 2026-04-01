# Sistema de Skills

## Descripción

Los skills son módulos especializados que encapsulan funcionalidad de seguridad ofensiva y defensiva.

## Ubicación

```
src/specter/skills/
├── base.py        # Clase base y tipos
├── manager.py     # Gestor con carga lazy
├── recon.py       # Reconocimiento
├── osint.py       # OSINT
├── web.py         # Auditoría web
├── postex.py      # Post-explotación
├── forense.py     # Análisis forense
├── ad.py          # Active Directory
└── report.py      # Generación de informes
```

## Clase Base

```python
class BaseSkill(ABC):
    name: str = ""
    description: str = ""
    category: str = ""
    risk_level: RiskLevel = RiskLevel.ACTIVE
    
    @abstractmethod
    async def execute(self, action: str, params: dict) -> SkillResult:
        pass
    
    @abstractmethod
    async def validate_params(self, action: str, params: dict) -> bool:
        pass
```

## Niveles de Riesgo

```python
class RiskLevel(Enum):
    PASIVE = 0      # Solo lectura
    ACTIVE = 1      # Genera tráfico/estado
    INTRUSIVE = 2   # Alto impacto
```

## Carga Lazy

Los skills se cargan bajo demanda para mejorar rendimiento:

```python
skill_manager = SkillManager(tool_registry, config)

# No carga skills hasta que se usen
skill = await skill_manager.get_skill_lazy("recon")

# O ejecutar directamente
result = await skill_manager.execute_skill("recon", "scan", {"target": "192.168.1.1"})
```

## Skills Disponibles

| Skill | Descripción | Herramientas |
|-------|-------------|--------------|
| `recon` | Reconocimiento | nmap, ping, DNS enum |
| `osint` | OSINT | WHOIS, Shodan, GitHub |
| `web` | Auditoría web | gobuster, sqlmap, Nuclei |
| `postex` | Post-explotación |-shell, hashdump |
| `forense` | DFIR | Timeline, evidence |
| `ad` | Active Directory | BloodHound, ldapenum |
| `report` | Informes | MD, JSON, CSV, PDF |