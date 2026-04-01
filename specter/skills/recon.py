"""Recon Skill - Reconocimiento yEnumeración"""

import asyncio
import subprocess
import shutil
import os
import time
import structlog
from typing import Any
from specter.skills.base import BaseSkill, SkillResult, RiskLevel

logger = structlog.get_logger()


class ReconSkill(BaseSkill):
    """
    Skill de Reconocimiento
    
    Proporciona herramientas para:
    - Escaneo de puertos
    - Descubrimiento de hosts
    -Enumeración de servicios
    - Fingerprinting
    """
    
    name = "recon"
    description = "Reconocimiento y enumeración de objetivos"
    category = "recon"
    risk_level = RiskLevel.ACTIVE
    
    def __init__(self):
        super().__init__()
        self.tools = [
            "network.port_scan",
            "network.ping_sweep",
            "network.dns_enum",
            "network.service_enum",
            # Expanded capabilities
            "recon.vuln_scan",
            "recon.ssl_analyze",
            "recon.snmp_enum",
        ]
        self.workflows = ["full_recon", "quick_scan", "web_footprint"]
    
    def get_available_actions(self) -> list[str]:
        return [
            "port_scan",
            "ping_sweep",
            "dns_enum",
            "service_scan",
            "os_fingerprint",
            # New actions
            "vuln_scan",
            "ssl_analyze",
            "snmp_enum",
        ]
    
    async def validate_params(self, action: str, params: dict[str, Any]) -> bool:
        """Valida parámetros según la acción"""
        
        if action == "port_scan":
            return "target" in params
        
        if action == "ping_sweep":
            return "target" in params
        
        if action == "dns_enum":
            return "domain" in params
        
        return True
    
    async def execute(self, action: str, params: dict[str, Any]) -> SkillResult:
        """Ejecuta la acción de recon"""
        
        import time
        start = time.time()
        
        match action:
            case "port_scan":
                return await self._port_scan(params)
            case "ping_sweep":
                return await self._ping_sweep(params)
            case "dns_enum":
                return await self._dns_enum(params)
            case "service_scan":
                return await self._service_scan(params)
            case "os_fingerprint":
                return await self._os_fingerprint(params)
            case "vuln_scan":
                return await self._vuln_scan(params)
            case "ssl_analyze":
                return await self._ssl_analyze(params)
            case "snmp_enum":
                return await self._snmp_enum(params)
            case _:
                return SkillResult(
                    success=False,
                    error=f"Acción desconocida: {action}"
                )
    
    async def _port_scan(self, params: dict) -> SkillResult:
        """Ejecuta escaneo de puertos con nmap"""
        
        target = params["target"]
        ports = params.get("ports", "1-1000")
        scan_type = params.get("scan_type", "-sS")
        timing = params.get("timing", "-T3")
        
        # Construir comando
        cmd = [
            "nmap",
            scan_type,
            timing,
            "-p", ports,
            "-oA", f"/tmp/specter_nmap_{target.replace('.', '_')}",
            target
        ]
        
        logger.info("Running nmap", target=target, ports=ports)
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=params.get("timeout", 300)
            )
            
            output = result.stdout + result.stderr
            
            # Parsear resultados
            findings = self._parse_nmap_output(output, target)
            
            return SkillResult(
                success=result.returncode == 0,
                output=output,
                findings=findings,
                artifacts={
                    f"/tmp/specter_nmap_{target.replace('.', '_')}.xml": "Resultado XML de nmap",
                    f"/tmp/specter_nmap_{target.replace('.', '_')}.nmap": "Resultado normal de nmap",
                },
                execution_time=time.time() - start
            )
            
        except subprocess.TimeoutExpired:
            return SkillResult(
                success=False,
                error=f"Timeout en escaneo de {target}"
            )
        except FileNotFoundError:
            return SkillResult(
                success=False,
                error="nmap no está instalado. Instálalo con: sudo apt install nmap"
            )
        except Exception as e:
            return SkillResult(
                success=False,
                error=str(e)
            )
    
    async def _ping_sweep(self, params: dict) -> SkillResult:
        """Ejecuta ping sweep para descubrir hosts"""
        
        target = params["target"]
        
        cmd = ["nmap", "-sn", "-oG", "-", target]
        
        logger.info("Running ping sweep", target=target)
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            # Parsear hosts descubiertos
            hosts = []
            for line in result.stdout.split("\n"):
                if "Up" in line or "Status: Up" in line:
                    hosts.append(line)
            
            return SkillResult(
                success=True,
                output=f"Hosts descubiertos: {len(hosts)}\n" + "\n".join(hosts[:20]),
                findings=[{"type": "host_discovered", "count": len(hosts)}],
            )
            
        except Exception as e:
            return SkillResult(success=False, error=str(e))
    
    async def _dns_enum(self, params: dict) -> SkillResult:
        """Enumeración DNS"""
        
        domain = params["domain"]
        
        # Usar dnsx o dig
        cmd = ["dig", "+short", domain, "ANY"]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            return SkillResult(
                success=result.returncode == 0,
                output=result.stdout or "Sin resultados"
            )
            
        except FileNotFoundError:
            # Fallback a nslookup
            cmd = ["nslookup", domain]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                return SkillResult(
                    success=result.returncode == 0,
                    output=result.stdout
                )
            except Exception as e:
                return SkillResult(success=False, error=str(e))
        except Exception as e:
            return SkillResult(success=False, error=str(e))
    
    async def _service_scan(self, params: dict) -> SkillResult:
        """Escaneo de servicios con detección de versiones"""
        
        target = params["target"]
        ports = params.get("ports", "top-100")
        
        cmd = [
            "nmap",
            "-sV",
            "-T4",
            "-p", ports,
            target
        ]
        
        logger.info("Running service scan", target=target)
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            findings = self._parse_nmap_output(result.stdout, target)
            
            return SkillResult(
                success=result.returncode == 0,
                output=result.stdout,
                findings=findings
            )
            
        except Exception as e:
            return SkillResult(success=False, error=str(e))
    
    async def _os_fingerprint(self, params: dict) -> SkillResult:
        """Fingerprinting de sistema operativo"""
        
        target = params["target"]
        
        cmd = ["nmap", "-O", "-T4", target]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            return SkillResult(
                success=result.returncode == 0,
                output=result.stdout
            )
            
        except Exception as e:
            return SkillResult(success=False, error=str(e))

    async def _vuln_scan(self, params: dict) -> SkillResult:
        """Escaneo de vulnerabilidades con nmap --script vuln"""
        import time as _time
        start = _time.time()
        target = params["target"]
        ports = params.get("ports", "1-1000")
        # Use -sV for service/version info and vuln scripts
        cmd = ["nmap", "-sV", "--script", "vuln", "-p", ports, "-T4", "-oA", f"/tmp/specter_nmap_vuln_{target.replace('.', '_')}", target]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=params.get("timeout", 600))
            output = result.stdout + result.stderr
            findings = self._parse_nmap_output(output, target)
            return SkillResult(
                success=result.returncode == 0,
                output=output,
                findings=findings,
                execution_time=_time.time() - start
            )
        except FileNotFoundError:
            return SkillResult(success=False, error="nmap no está instalado")
        except subprocess.TimeoutExpired:
            return SkillResult(success=False, error=f"Timeout en vuln scan de {target}")
        except Exception as e:
            return SkillResult(success=False, error=str(e))

    async def _ssl_analyze(self, params: dict) -> SkillResult:
        """Análisis de SSL con sslscan o testssl.sh (si están disponibles)"""
        import time as _time
        start = _time.time()
        target = params["target"]

        # Prefer sslscan, fallback to testssl.sh
        sslcmd = None
        if shutil.which("sslscan"):
            sslcmd = ["sslscan", target if ":" in target else f"{target}:443"]
        elif shutil.which("testssl.sh"):
            sslcmd = ["bash", "./testssl.sh", f"{target}:443"]

        if not sslcmd:
            return SkillResult(success=False, error="ni sslscan ni testssl.sh están instalados")

        try:
            result = subprocess.run(sslcmd, capture_output=True, text=True, timeout=params.get("timeout", 300))
            output = result.stdout + result.stderr
            # Basic parsing: if we see critical warnings, mark as high risk
            findings = []
            if "RC4" in output or "weak" in output or "VULNERABLE" in output:
                findings.append({"type": "ssl_issue", "description": "Potential SSL weakness", "severity": "HIGH"})
            return SkillResult(
                success=result.returncode == 0,
                output=output,
                findings=findings or [{"type": "ssl_analysis", "description": "No obvious issues"}],
                execution_time=_time.time() - start
            )
        except subprocess.TimeoutExpired:
            return SkillResult(success=False, error="Timeout en ssl analysis")
        except Exception as e:
            return SkillResult(success=False, error=str(e))

    async def _snmp_enum(self, params: dict) -> SkillResult:
        """Enumeración SNMP simple con snmpwalk (comunidad pública por defecto)"""
        import time as _time
        start = _time.time()
        target = params["target"]
        community = params.get("community", "public")
        # Try v2c walk from root OID
        cmd = ["snmpwalk", "-v2c", "-c", community, target]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            output = result.stdout
            findings: list[dict] = []
            for line in output.splitlines():
                if line.strip():
                    findings.append({"type": "snmp", "oid": line.split(" ", 1)[0], "value": line.strip()})
            return SkillResult(
                success=result.returncode == 0,
                output=output,
                findings=findings if findings else [{"type": "snmp", "value": "No SNMP data"}],
                execution_time=_time.time() - start
            )
        except FileNotFoundError:
            return SkillResult(success=False, error="snmpwalk no está instalado")
        except Exception as e:
            return SkillResult(success=False, error=str(e))
    
    def _parse_nmap_output(self, output: str, target: str) -> list[dict]:
        """Parsea output de nmap y extrae hallazgos"""
        
        findings = []
        lines = output.split("\n")
        
        for line in lines:
            # Puerto abierto
            if "/tcp" in line or "/udp" in line:
                parts = line.split()
                if len(parts) >= 3:
                    port = parts[0].split("/")[0]
                    state = parts[1]
                    service = parts[2] if len(parts) > 2 else "unknown"
                    
                    if state == "open":
                        findings.append({
                            "type": "open_port",
                            "target": target,
                            "port": port,
                            "service": service,
                            "severity": "INFO"
                        })
            
            # OS Detection
            if "OS details:" in line or "OS:" in line:
                findings.append({
                    "type": "os_detected",
                    "target": target,
                    "os": line.strip(),
                    "severity": "INFO"
                })
            
            # Vulnerabilidades conocidas
            if "CVE-" in line:
                findings.append({
                    "type": "potential_vulnerability",
                    "target": target,
                    "cve": line.strip(),
                    "severity": "HIGH"
                })
        
        return findings
