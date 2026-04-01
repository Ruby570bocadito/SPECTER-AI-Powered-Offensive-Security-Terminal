"""OSINT Skill - Inteligencia de Fuentes Abiertas"""

import json
import re
import subprocess
import time
from typing import Any

import structlog

from specter.skills.base import BaseSkill, SkillResult, RiskLevel

logger = structlog.get_logger()


class OsintSkill(BaseSkill):
    """
    Skill OSINT - Open Source Intelligence
    
    Proporciona herramientas para:
    - Consulta WHOIS
    - Enumeración de subdominios
    - Recolección de emails
    - Búsqueda en Shodan
    - Extracción de metadatos
    - Búsqueda en GitHub
    - Consulta Certificate Transparency
    """
    
    name = "osint"
    description = "Inteligencia de fuentes abiertas"
    category = "osint"
    risk_level = RiskLevel.PASIVE
    
    def __init__(self):
        super().__init__()
        self.tools = [
            "osint.whois",
            "osint.subdomain_enum",
            "osint.email_harvest",
            "osint.shodan",
            "osint.metadata",
            "osint.github",
            "osint.crtsh",
            # Expanded OSINT tools
            "osint.google_dorks",
            "osint.wayback_query",
            "osint.hunter_lookup",
        ]
        self.workflows = ["full_osint", "rapid_osint"]
    
    def get_available_actions(self) -> list[str]:
        return [
            "whois_lookup",
            "subdomain_enum",
            "email_harvest",
            "shodan_query",
            "metadata_extract",
            "github_search",
            "crtsh_query",
            # New actions
            "google_dorks",
            "wayback_query",
            "hunter_lookup",
        ]
    
    async def validate_params(self, action: str, params: dict[str, Any]) -> bool:
        if action in ("whois_lookup", "subdomain_enum", "email_harvest", "crtsh_query"):
            return "domain" in params
        if action in ("shodan_query", "github_search"):
            return "query" in params
        if action == "metadata_extract":
            return "path" in params or "target" in params
        return True
    
    async def execute(self, action: str, params: dict[str, Any]) -> SkillResult:
        start = time.time()
        
        match action:
            case "whois_lookup":
                return await self._whois_lookup(params, start)
            case "subdomain_enum":
                return await self._subdomain_enum(params, start)
            case "email_harvest":
                return await self._email_harvest(params, start)
            case "shodan_query":
                return await self._shodan_query(params, start)
            case "metadata_extract":
                return await self._metadata_extract(params, start)
            case "github_search":
                return await self._github_search(params, start)
            case "crtsh_query":
                return await self._crtsh_query(params, start)
            case "google_dorks":
                return await self._google_dorks(params, start)
            case "wayback_query":
                return await self._wayback_query(params, start)
            case "hunter_lookup":
                return await self._hunter_lookup(params, start)
            case _:
                return SkillResult(success=False, error=f"Acción desconocida: {action}")
    
    async def _whois_lookup(self, params: dict, start: float) -> SkillResult:
        domain = params.get("domain") or params.get("target")
        
        try:
            result = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=60)
            
            findings = []
            for line in result.stdout.splitlines():
                if ":" in line:
                    key, val = line.split(":", 1)
                    key, val = key.strip(), val.strip()
                    if key in ("Registrar", "Name Server", "Registrant", "Creation Date", "Expiry Date"):
                        findings.append({"type": "whois", "field": key, "value": val})
            
            return SkillResult(
                success=result.returncode == 0,
                output=result.stdout,
                findings=findings,
                execution_time=time.time() - start,
            )
        except FileNotFoundError:
            return SkillResult(success=False, error="whois no instalado", execution_time=time.time() - start)
        except Exception as e:
            return SkillResult(success=False, error=str(e), execution_time=time.time() - start)
    
    async def _subdomain_enum(self, params: dict, start: float) -> SkillResult:
        domain = params.get("domain")
        
        findings = []
        output_parts = []
        
        # Try amass
        if subprocess.run(["which", "amass"], capture_output=True).returncode == 0:
            try:
                r = subprocess.run(["amass", "enum", "-d", domain, "-silent"], 
                                  capture_output=True, text=True, timeout=120)
                for line in r.stdout.splitlines():
                    if line.strip():
                        findings.append({"type": "subdomain", "source": "amass", "value": line.strip()})
                output_parts.append(r.stdout)
            except Exception:
                pass
        
        # Try subfinder
        if subprocess.run(["which", "subfinder"], capture_output=True).returncode == 0:
            try:
                r = subprocess.run(["subfinder", "-d", domain, "-silent"],
                                  capture_output=True, text=True, timeout=60)
                for line in r.stdout.splitlines():
                    if line.strip():
                        findings.append({"type": "subdomain", "source": "subfinder", "value": line.strip()})
                output_parts.append(r.stdout)
            except Exception:
                pass
        
        # Fallback: dig
        if not findings:
            try:
                r = subprocess.run(["dig", "+short", "ANY", domain], 
                                  capture_output=True, text=True, timeout=30)
                for line in r.stdout.splitlines():
                    line = line.strip()
                    if line and domain in line:
                        findings.append({"type": "subdomain", "source": "dig", "value": line})
                output_parts.append(r.stdout)
            except Exception:
                pass
        
        # Deduplicate
        seen = set()
        unique = []
        for f in findings:
            if f["value"] not in seen:
                seen.add(f["value"])
                unique.append(f)
        
        return SkillResult(
            success=True,
            output="\n".join(output_parts),
            findings=unique if unique else [{"type": "subdomain", "value": "No se encontraron subdominios"}],
            execution_time=time.time() - start,
        )
    
    async def _email_harvest(self, params: dict, start: float) -> SkillResult:
        domain = params.get("domain")
        
        emails = set()
        output = ""
        
        # Try theHarvester
        if subprocess.run(["which", "theHarvester"], capture_output=True).returncode == 0:
            try:
                r = subprocess.run(["theHarvester", "-d", domain, "-b", "all", "-f", "/tmp/specter_emails"],
                                  capture_output=True, text=True, timeout=120)
                output += r.stdout
                for line in r.stdout.splitlines():
                    for email in re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", line):
                        emails.add(email)
            except Exception:
                pass
        
        findings = [{"type": "email", "value": e} for e in sorted(emails)]
        if not findings:
            findings = [{"type": "email", "value": "No se encontraron emails"}]
        
        return SkillResult(
            success=True,
            output=output,
            findings=findings,
            execution_time=time.time() - start,
        )
    
    async def _shodan_query(self, params: dict, start: float) -> SkillResult:
        query = params.get("query")
        limit = params.get("limit", 20)
        
        if subprocess.run(["which", "shodan"], capture_output=True).returncode != 0:
            return SkillResult(success=False, error="Shodan CLI no instalado", execution_time=time.time() - start)
        
        try:
            r = subprocess.run(["shodan", "search", "--limit", str(limit), query],
                              capture_output=True, text=True, timeout=60)
            
            findings = []
            for line in r.stdout.splitlines():
                ip_match = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
                for ip in ip_match:
                    findings.append({"type": "shodan_result", "ip": ip, "query": query})
            
            return SkillResult(
                success=r.returncode == 0,
                output=r.stdout,
                findings=findings if findings else [{"type": "shodan_result", "value": "Sin resultados"}],
                execution_time=time.time() - start,
            )
        except Exception as e:
            return SkillResult(success=False, error=str(e), execution_time=time.time() - start)
    
    async def _metadata_extract(self, params: dict, start: float) -> SkillResult:
        path = params.get("path") or params.get("target")
        
        if subprocess.run(["which", "exiftool"], capture_output=True).returncode != 0:
            return SkillResult(success=False, error="exiftool no instalado", execution_time=time.time() - start)
        
        try:
            r = subprocess.run(["exiftool", path], capture_output=True, text=True, timeout=30)
            
            findings = []
            for line in r.stdout.splitlines():
                m = re.match(r"([^:]+):\s*(.+)", line)
                if m:
                    findings.append({"type": "metadata", "tag": m.group(1).strip(), "value": m.group(2).strip()})
            
            return SkillResult(
                success=r.returncode == 0,
                output=r.stdout,
                findings=findings,
                execution_time=time.time() - start,
            )
        except Exception as e:
            return SkillResult(success=False, error=str(e), execution_time=time.time() - start)
    
    async def _github_search(self, params: dict, start: float) -> SkillResult:
        query = params.get("query")
        
        try:
            import urllib.request
            import urllib.parse
            
            url = f"https://api.github.com/search/repositories?q={urllib.parse.quote(query)}&per_page=5"
            req = urllib.request.Request(url, headers={"User-Agent": "SPECTER-OSINT"})
            
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
            
            findings = []
            for item in data.get("items", []):
                findings.append({
                    "type": "github_repo",
                    "name": item.get("full_name"),
                    "url": item.get("html_url"),
                    "stars": item.get("stargazers_count"),
                })
            
            output = "\n".join([f"{f['name']} - {f['url']}" for f in findings])
            
            return SkillResult(
                success=True,
                output=output,
                findings=findings,
                execution_time=time.time() - start,
            )
        except Exception as e:
            return SkillResult(success=False, error=str(e), execution_time=time.time() - start)
    
    async def _crtsh_query(self, params: dict, start: float) -> SkillResult:
        domain = params.get("domain")
        
        try:
            url = f"https://crt.sh/?q={domain}&output=json"
            r = subprocess.run(["curl", "-s", url], capture_output=True, text=True, timeout=60)
            
            try:
                data = json.loads(r.stdout)
            except json.JSONDecodeError:
                data = []
            
            domains = set()
            for item in data:
                name_value = item.get("name_value", "")
                for v in str(name_value).split("\n"):
                    v = v.strip()
                    if v:
                        domains.add(v)
            
            findings = [{"type": "certificate_domain", "domain": d} for d in sorted(domains)]
            
            return SkillResult(
                success=True,
                output=r.stdout,
                findings=findings if findings else [{"type": "certificate_domain", "value": "No se encontraron certificados"}],
                execution_time=time.time() - start,
            )
        except Exception as e:
            return SkillResult(success=False, error=str(e), execution_time=time.time() - start)

    async def _google_dorks(self, params: dict, start: float) -> SkillResult:
        query = params.get("query") or params.get("domain")
        if not query:
            return SkillResult(success=False, error="Se requiere 'query' o 'domain' para google_dorks", execution_time=time.time() - start)

        import urllib.request
        import urllib.parse
        try:
            url = f"https://www.google.com/search?q={urllib.parse.quote(query)}"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Specter)"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                html = resp.read().decode(errors="ignore")
            # crude extraction of result URLs from google's search page
            import re
            urls = set(re.findall(r"/url\?q=(https?:\/\/[^&]+)(&|$)", html))
            findings = [{"type": "google_dork_result", "url": urllib.parse.unquote(u[0])} for u in urls if u]
            output = f"Found {len(findings)} results" if findings else "Sin resultados"
            return SkillResult(
                success=True,
                output=output,
                findings=findings or [{"type": "google_dork_result", "value": "No results"}],
                execution_time=time.time() - start,
            )
        except Exception as e:
            return SkillResult(success=False, error=str(e), execution_time=time.time() - start)

    async def _wayback_query(self, params: dict, start: float) -> SkillResult:
        domain = params.get("domain") or params.get("target")
        if not domain:
            return SkillResult(success=False, error="Se requiere 'domain' o 'target' para Wayback query", execution_time=time.time() - start)
        import urllib.request
        import json
        try:
            # CDX API for snapshots
            url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&limit=5&collapse=original"
            with urllib.request.urlopen(url, timeout=30) as resp:
                data = json.loads(resp.read())
            # data is a list of rows, first row is headers
            findings = []
            for row in data[1:]:
                timestamp, original = row[0], row[2] if len(row) > 2 else ("", "")
                findings.append({"type": "wayback_snapshot", "timestamp": timestamp, "original": original})
            output = "Wayback snapshots: {} results".format(len(findings))
            return SkillResult(
                success=True,
                output=output,
                findings=findings or [{"type": "wayback_snapshot", "value": "No snapshots"}],
                execution_time=time.time() - start,
            )
        except Exception as e:
            return SkillResult(success=False, error=str(e), execution_time=time.time() - start)

    async def _hunter_lookup(self, params: dict, start: float) -> SkillResult:
        domain = params.get("domain") or params.get("target")
        if not domain:
            return SkillResult(success=False, error="Se requiere 'domain' para hunter_lookup", execution_time=time.time() - start)
        import os
        api_key = os.environ.get("HUNTER_API_KEY")
        if not api_key:
            return SkillResult(success=False, error="Hunter API key no configurada (HUNTER_API_KEY)", execution_time=time.time() - start)
        import urllib.request, urllib.parse, json
        try:
            url = f"https://api.hunter.io/v2/domain-search?domain={urllib.parse.quote(domain)}&api_key={urllib.parse.quote(api_key)}"
            with urllib.request.urlopen(url, timeout=30) as resp:
                data = json.loads(resp.read())
            emails = data.get("data", {}).get("emails", [])
            findings = [{"type": "hunter_email", "email": e.get("value"), "confidence": e.get("confidence")} for e in emails]
            output = f"Emails found: {len(findings)}" if findings else "No emails found"
            return SkillResult(
                success=True,
                output=output,
                findings=findings or [{"type": "hunter_email", "value": "No emails"}],
                execution_time=time.time() - start,
            )
        except Exception as e:
            return SkillResult(success=False, error=str(e), execution_time=time.time() - start)
