"""Web Skill - Auditoría de Aplicaciones Web"""

import shutil
import subprocess
import time
from typing import Any

import structlog

from specter.skills.base import BaseSkill, SkillResult, RiskLevel

logger = structlog.get_logger()


class WebSkill(BaseSkill):
    """
    Skill de Auditoría Web
    
    Proporciona herramientas para:
    - Fuzzing de directorios (gobuster, ffuf)
    - Test de inyección SQL (sqlmap)
    - Escaneo de vulnerabilidades (Nuclei)
    - Detección de WAF (wafw00f)
    - Análisis de cabeceras HTTP
    """
    
    name = "web"
    description = "Auditoría de aplicaciones web - OWASP Top 10"
    category = "web"
    risk_level = RiskLevel.ACTIVE
    
    def __init__(self):
        super().__init__()
        self.tools = [
            "web.dir_fuzz",
            "web.sqlmap",
            "web.nuclei",
            "web.waf_detect",
            "web.header_analyze",
            "web.screenshot",
            # Expanded web tooling
            "web.xss_test",
            "web.cors_scan",
            "web.graphql_map",
        ]
        self.workflows = ["web_audit", "quick_web_scan"]
    
    def get_available_actions(self) -> list[str]:
        return [
            "dir_fuzz",
            "sqlmap_test",
            "nuclei_scan",
            "waf_detect",
            "header_analyze",
            "screenshot",
            # New actions
            "xss_test",
            "cors_scan",
            "graphql_map",
        ]
    
    async def validate_params(self, action: str, params: dict[str, Any]) -> bool:
        if action in ("dir_fuzz", "sqlmap_test", "nuclei_scan", "waf_detect", "header_analyze", "screenshot"):
            return "target" in params
        return True
    
    async def execute(self, action: str, params: dict[str, Any]) -> SkillResult:
        start = time.time()
        
        match action:
            case "dir_fuzz":
                return await self._dir_fuzz(params)
            case "sqlmap_test":
                return await self._sqlmap_test(params)
            case "nuclei_scan":
                return await self._nuclei_scan(params)
            case "waf_detect":
                return await self._waf_detect(params)
            case "header_analyze":
                return await self._header_analyze(params)
            case "screenshot":
                return await self._screenshot(params)
            case _:
                return SkillResult(success=False, error=f"Acción desconocida: {action}")
    
    async def _dir_fuzz(self, params: dict) -> SkillResult:
        """Fuzzing de directorios web"""
        target = params["target"]
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        
        tool = "gobuster" if shutil.which("gobuster") else "ffuf" if shutil.which("ffuf") else None
        
        if not tool:
            return SkillResult(success=False, error="No se encontró gobuster ni ffuf")
        
        try:
            if tool == "gobuster":
                cmd = ["gobuster", "dir", "-u", target, "-w", wordlist, "-o", f"/tmp/specter_gobuster.txt"]
            else:
                cmd = ["ffuf", "-u", f"{target}/FUZZ", "-w", wordlist, "-o", "/tmp/specter_ffuf.json"]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=params.get("timeout", 300))
            
            findings = []
            if result.returncode == 0:
                count = len([l for l in result.stdout.splitlines() if l.strip()])
                findings.append({"type": "dir_fuzz", "paths_found": count, "target": target})
            
            return SkillResult(
                success=result.returncode == 0,
                output=result.stdout + result.stderr,
                findings=findings,
                execution_time=time.time() - start,
            )
        except subprocess.TimeoutExpired:
            return SkillResult(success=False, error="Timeout en fuzzing", execution_time=time.time() - start)
        except FileNotFoundError:
            return SkillResult(success=False, error=f"{tool} no está instalado", execution_time=time.time() - start)
        except Exception as e:
            return SkillResult(success=False, error=str(e), execution_time=time.time() - start)
    
    async def _sqlmap_test(self, params: dict) -> SkillResult:
        """Test de inyección SQL con sqlmap"""
        target = params["target"]
        
        if not shutil.which("sqlmap"):
            return SkillResult(success=False, error="sqlmap no está instalado")
        
        try:
            cmd = ["sqlmap", "-u", target, "--batch", "--risk=1", "--level=1"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=params.get("timeout", 300))
            
            findings = []
            if "vulnerable" in result.stdout.lower():
                findings.append({"type": "sqli", "target": target, "severity": "HIGH"})
            
            return SkillResult(
                success=result.returncode == 0,
                output=result.stdout + result.stderr,
                findings=findings,
                execution_time=time.time() - start,
            )
        except subprocess.TimeoutExpired:
            return SkillResult(success=False, error="Timeout en sqlmap", execution_time=time.time() - start)
        except Exception as e:
            return SkillResult(success=False, error=str(e), execution_time=time.time() - start)
    
    async def _nuclei_scan(self, params: dict) -> SkillResult:
        """Escaneo con Nuclei"""
        target = params["target"]
        
        if not shutil.which("nuclei"):
            return SkillResult(success=False, error="nuclei no está instalado")
        
        try:
            template = params.get("template", "")
            cmd = ["nuclei", "-u", target] + (["-t", template] if template else [])
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=params.get("timeout", 300))
            
            findings = []
            if "CVE-" in result.stdout:
                findings.append({"type": "cve_found", "target": target, "severity": "MED"})
            
            return SkillResult(
                success=result.returncode == 0,
                output=result.stdout + result.stderr,
                findings=findings,
                execution_time=time.time() - start,
            )
        except subprocess.TimeoutExpired:
            return SkillResult(success=False, error="Timeout en nuclei", execution_time=time.time() - start)
        except Exception as e:
            return SkillResult(success=False, error=str(e), execution_time=time.time() - start)
    
    async def _waf_detect(self, params: dict) -> SkillResult:
        """Detección de WAF"""
        target = params["target"]
        
        if not shutil.which("wafw00f"):
            return SkillResult(success=False, error="wafw00f no está instalado")
        
        try:
            cmd = ["wafw00f", target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            findings = []
            if "No WAF detected" not in result.stdout:
                findings.append({"type": "waf_detected", "target": target})
            
            return SkillResult(
                success=result.returncode == 0,
                output=result.stdout,
                findings=findings,
                execution_time=time.time() - start,
            )
        except Exception as e:
            return SkillResult(success=False, error=str(e), execution_time=time.time() - start)
    
    async def _header_analyze(self, params: dict) -> SkillResult:
        """Análisis de cabeceras HTTP"""
        target = params["target"]
        if not target.startswith("http"):
            target = f"http://{target}"
        
        try:
            cmd = ["curl", "-I", "-s", target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            findings = []
            for line in result.stdout.splitlines():
                if line.lower().startswith("server:"):
                    findings.append({"type": "server_header", "value": line.split(":", 1)[1].strip()})
                if "x-powered-by" in line.lower():
                    findings.append({"type": "x_powered_by", "value": line.split(":", 1)[1].strip()})
                if "strict-transport-security" not in line.lower():
                    findings.append({"type": "missing_hsts", "severity": "LOW"})
            
            return SkillResult(
                success=result.returncode == 0,
                output=result.stdout,
                findings=findings,
                execution_time=time.time() - start,
            )
        except Exception as e:
            return SkillResult(success=False, error=str(e), execution_time=time.time() - start)
    
    async def _screenshot(self, params: dict) -> SkillResult:
        """Captura de pantalla web"""
        target = params["target"]
        if not target.startswith("http"):
            target = f"http://{target}"
        
        tool = "eyewitness" if shutil.which("eyewitness") else "webscreenshot" if shutil.which("webscreenshot") else None
        
        if not tool:
            return SkillResult(success=False, error="No se encontró eyewitness ni webscreenshot")
        
        try:
            outdir = f"/tmp/specter_screens_{target.replace('://', '_').replace('/', '_')}"
            
            if tool == "eyewitness":
                cmd = ["eyewitness", "-d", outdir, "-f", target]
            else:
                cmd = ["webscreenshot", "-u", target, "-o", outdir + ".png"]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            return SkillResult(
                success=result.returncode == 0,
                output=result.stdout,
                artifacts={outdir: "Capturas de pantalla"},
                execution_time=time.time() - start,
            )
        except Exception as e:
            return SkillResult(success=False, error=str(e), execution_time=time.time() - start)

    async def _xss_test(self, params: dict) -> SkillResult:
        """Prueba básica de XSS en un endpoint con payloads simples"""
        target = params["target"]
        import time as _time, urllib.parse
        start = _time.time()
        payloads = ["<script>alert(1)</script>", "\" onload=alert(1)//"]
        try:
            results = []
            for p in payloads:
                sep = '&' if '?' in target else '?'
                test_url = f"{target}{sep}specter_xss={urllib.parse.quote(p)}"
                cmd = ["curl", "-s", test_url]
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if p in (r.stdout or ''):
                    results.append({"payload": p, "hit": True})
                else:
                    results.append({"payload": p, "hit": False})

            findings = [f for f in results if f["hit"]]
            return SkillResult(
                success=True,
                output="XSS test completed",
                findings=findings if findings else [{"type": "xss_test", "value": "No payload reflected"}],
                execution_time=_time.time() - start,
            )
        except Exception as e:
            return SkillResult(success=False, error=str(e), execution_time=_time.time() - start)

    async def _cors_scan(self, params: dict) -> SkillResult:
        """Análisis básico de cabeceras CORS para un endpoint"""
        target = params["target"]
        start = time.time()
        try:
            cmd = ["curl", "-I", "-s", target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            headers = result.stdout.splitlines()
            cors = {
                "origin": any("Access-Control-Allow-Origin" in h for h in headers),
                "allow_origin": next((h.split(":",1)[1].strip() for h in headers if h.lower().startswith("access-control-allow-origin")), None)
            }
            findings = [{"type": "cors", "header": k, "value": v} for k,v in cors.items() if v is not None]
            return SkillResult(
                success=result.returncode == 0,
                output=result.stdout,
                findings=findings or [{"type": "cors", "value": "No headers detected"}],
                execution_time=time.time() - start,
            )
        except Exception as e:
            return SkillResult(success=False, error=str(e), execution_time=time.time() - start)

    async def _graphql_map(self, params: dict) -> SkillResult:
        """Introspección básica de GraphQL a través de introspección de schema"""
        endpoint = params.get("endpoint") or params.get("target")
        if not endpoint:
            return SkillResult(success=False, error="Endpoint requerido para graphql_map")
        import json, urllib.request
        start = time.time()
        try:
            payload = json.dumps({"query": "{ __schema { types { name } } }"}).encode("utf-8")
            req = urllib.request.Request(endpoint, data=payload, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
            types = data.get("data", {}).get("__schema", {}).get("types", [])
            findings = [{"type": "graphql_type", "name": t.get("name")} for t in types if t.get("name")]
            output = f"Types: {len(findings)}"
            return SkillResult(
                success=True,
                output=output,
                findings=findings,
                execution_time=time.time() - start,
            )
        except Exception as e:
            return SkillResult(success=False, error=str(e), execution_time=time.time() - start)
