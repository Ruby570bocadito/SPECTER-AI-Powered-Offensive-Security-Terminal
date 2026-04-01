"""Skill Manager - Gestor de Skills con carga lazy"""

import structlog
import asyncio
from typing import Optional
from specter.skills.base import BaseSkill, SkillResult
from specter.mcp import ToolRegistry
from specter.core.config import SpecterConfig

logger = structlog.get_logger()

SKILL_REGISTRY = {
    "recon": ("specter.skills.recon", "ReconSkill"),
    "osint": ("specter.skills.osint", "OsintSkill"),
    "web": ("specter.skills.web", "WebSkill"),
    "postex": ("specter.skills.postex", "PostExSkill"),
    "forense": ("specter.skills.forense", "ForenseSkill"),
    "ad": ("specter.skills.ad", "AdSkill"),
    "report": ("specter.skills.report", "ReportSkill"),
}


class SkillManager:
    """Gestiona los skills disponibles en SPECTER con carga lazy"""
    
    def __init__(self, tool_registry: ToolRegistry, config: SpecterConfig):
        self.tool_registry = tool_registry
        self.config = config
        self.skills: dict[str, BaseSkill] = {}
        self._loaded_skills: set[str] = set()
        self._loading_skills: set[str] = set()
        self._lazy_mode = True
    
    async def load_skills(self) -> None:
        """Carga solo metadatos de skills (lazy mode)"""
        logger.info("Initializing skill registry (lazy mode)", count=len(SKILL_REGISTRY))
        logger.info("Skills will be loaded on-demand when executed")
    
    async def load_all_skills(self) -> None:
        """Fuerza carga de todos los skills"""
        logger.info("Loading all skills...")
        for skill_name in SKILL_REGISTRY:
            await self._load_skill(skill_name)
        logger.info("All skills loaded", count=len(self.skills))
    
    async def _load_skill(self, skill_name: str) -> Optional[BaseSkill]:
        """Carga un skill específico"""
        if skill_name in self._loaded_skills:
            return self.skills.get(skill_name)
        
        if skill_name in self._loading_skills:
            while skill_name in self._loading_skills:
                await asyncio.sleep(0.1)
            return self.skills.get(skill_name)
        
        if skill_name not in SKILL_REGISTRY:
            logger.warning("Unknown skill", skill=skill_name)
            return None
        
        self._loading_skills.add(skill_name)
        
        try:
            module_path, class_name = SKILL_REGISTRY[skill_name]
            module = __import__(module_path, fromlist=[class_name])
            skill_class = getattr(module, class_name)
            skill_instance = skill_class()
            
            self.skills[skill_name] = skill_instance
            self._loaded_skills.add(skill_name)
            logger.debug("Skill loaded on-demand", skill=skill_name)
            return skill_instance
        except Exception as e:
            logger.error("Failed to load skill", skill=skill_name, error=str(e))
            return None
        finally:
            self._loading_skills.discard(skill_name)
    
    async def _register_skill(self, skill: BaseSkill) -> None:
        """Registra un skill en el manager"""
        self.skills[skill.name] = skill
        logger.debug("Skill registered", skill=skill.name)
    
    async def execute_skill(
        self, 
        skill_name: str, 
        action: str, 
        params: dict
    ) -> SkillResult:
        """Ejecuta una acción de un skill con carga lazy"""
        
        if self._lazy_mode and skill_name not in self._loaded_skills:
            logger.debug("Loading skill on-demand", skill=skill_name)
            await self._load_skill(skill_name)
        
        if skill_name not in self.skills:
            return SkillResult(
                success=False,
                error=f"Skill no encontrado: {skill_name}"
            )
        
        skill = self.skills[skill_name]
        
        # Validar parámetros
        if not await skill.validate_params(action, params):
            return SkillResult(
                success=False,
                error=f"Parámetros inválidos para {action}"
            )
        
        # Ejecutar
        try:
            result = await skill.execute(action, params)
            return result
        except Exception as e:
            logger.error("Skill execution failed", skill=skill_name, action=action, error=str(e))
            return SkillResult(
                success=False,
                error=str(e)
            )
    
    def get_skill(self, name: str) -> Optional[BaseSkill]:
        """Obtiene un skill por nombre (sin carga lazy)"""
        return self.skills.get(name)
    
    async def get_skill_lazy(self, name: str) -> Optional[BaseSkill]:
        """Obtiene un skill por nombre con carga lazy"""
        if name not in self._loaded_skills:
            await self._load_skill(name)
        return self.skills.get(name)
    
    def get_loaded_skills(self) -> list[str]:
        """Retorna lista de skills cargados"""
        return list(self._loaded_skills)
    
    def get_available_skills(self) -> list[str]:
        """Retorna lista de skills disponibles (sin cargar)"""
        return list(SKILL_REGISTRY.keys())
    
    def list_skills(self) -> list[dict]:
        """Lista todos los skills disponibles"""
        return [
            {
                "name": s.name,
                "description": s.description,
                "category": s.category,
                "risk_level": s.risk_level.value,
                "actions": s.get_available_actions(),
            }
            for s in self.skills.values()
        ]
    
    async def execute_skills_parallel(
        self,
        skill_tasks: list[tuple[str, str, dict]],
        max_concurrent: int = 3,
    ) -> list[SkillResult]:
        """Ejecuta múltiples skills en paralelo con límite de concurrencia.
        
        Args:
            skill_tasks: Lista de tuplas (skill_name, action, params)
            max_concurrent: Máximo de skills ejecutándose simultáneamente
        
        Returns:
            Lista de resultados en el mismo orden que skill_tasks
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def run_with_limit(task: tuple[str, str, dict]) -> SkillResult:
            skill_name, action, params = task
            async with semaphore:
                return await self.execute_skill(skill_name, action, params)
        
        tasks = [run_with_limit(task) for task in skill_tasks]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        final_results = []
        for r in results:
            if isinstance(r, Exception):
                final_results.append(SkillResult(success=False, error=str(r)))
            else:
                final_results.append(r)
        
        return final_results
    
    def detect_parallel_tasks(self, user_input: str) -> list[tuple[str, str, dict]]:
        """Detecta si el input requiere ejecutar múltiples skills en paralelo.
        
        Returns:
            Lista de tuplas (skill_name, action, params) o lista vacía
        """
        tasks = []
        user_lower = user_input.lower()
        
        if any(word in user_lower for word in ["reconocimiento", "recon", "enumera", "enum"]):
            if "dominio" in user_lower or "domain" in user_lower:
                tasks.append(("recon", "full_scan", {"target": self._extract_target(user_input)}))
            if "subdomain" in user_lower or "subdominio" in user_lower:
                tasks.append(("recon", "subdomain_enum", {"target": self._extract_target(user_input)}))
            if "web" in user_lower or "servidor" in user_lower:
                tasks.append(("web", "scan", {"target": self._extract_target(user_input)}))
        
        if any(word in user_lower for word in ["osint", "inteligencia"]):
            if "dominio" in user_lower:
                tasks.append(("osint", "domain", {"domain": self._extract_target(user_input)}))
            if "email" in user_lower or "correo" in user_lower:
                tasks.append(("osint", "email_lookup", {"email": self._extract_target(user_input)}))
        
        return tasks
    
    def _extract_target(self, text: str) -> str:
        """Extrae el target de un texto"""
        import re
        patterns = [
            r"(?:https?://)?(?:www\.)?([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)",
            r"(?:target|host|ip|dominio|domain)[:\s]+([^\s]+)",
            r"([^\s]+\.(?:com|org|net|gov|edu|io|co)[^\s]*)",
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)
        return text.split()[0] if text.split() else ""
