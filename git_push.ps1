# Git push script for SPECTER
$ErrorActionPreference = "Stop"
$env:GIT_TERMINAL_PROMPT = "0"
$env:GCM_INTERACTIVE = "never"

git remote add origin https://github.com/Ruby570bocadito/SPECTER-AI-Powered-Offensive-Security-Terminal.git 2>$null
git remote set-url origin https://github.com/Ruby570bocadito/SPECTER-AI-Powered-Offensive-Security-Terminal.git

git add -A
git commit -m "feat: major architecture overhaul and skill implementations

- Consolidated directory structure: all modules moved into specter/
- Implemented real agent execution (ReconAgent, ExploitAgent, AnalystAgent, ReporterAgent)
- Connected AgentOrchestrator to SpecterEngine command executor
- Implemented AD skill: bloodhound, kerberoast, asrep_roast, ldap_enum, certipy, ntlm_relay, dcsync, pass_the_hash
- Implemented PostEx skill: priv_esc (linux/windows), credential_dump, lateral_movement, persistence, pivot
- Implemented Forense skill: memory_acquire/analyze, disk_acquire, log_analysis, ioc_extract, yara_scan, timeline
- Added MITRE ATT&CK mapping module (specter/core/mitre.py)
- Added session templates (8 pre-configured assessment types)
- Added 20 integration tests
- Fixed duplicate run_specter function in cli/main.py
- Fixed execution_time bug in recon.py
- Added specter/__init__.py and specter/agents/__init__.py"

git push -u origin master --force
