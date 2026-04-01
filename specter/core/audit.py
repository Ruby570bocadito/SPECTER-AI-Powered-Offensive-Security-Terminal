from __future__ import annotations

import json
import os
import hashlib
import datetime
from typing import List, Dict, Any, Optional


class AuditLogger:
    """Append-only audit logger for actions performed by Specter.

    - log_action(session_id, action, tool, params, result, timestamp)
    - export_audit_log(format='json') -> str
    - verify_integrity() -> bool
    """

    def __init__(self, log_dir: Optional[str] = None):
        base = log_dir or os.path.join(os.path.dirname(__file__), "..", "..", "logs")
        self.log_dir = os.path.abspath(base)
        os.makedirs(self.log_dir, exist_ok=True)
        self.log_path = os.path.join(self.log_dir, "audit.log")
        self.sig_path = os.path.join(self.log_dir, "audit.sig")

    def _read_all(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self.log_path):
            return []
        entries: List[Dict[str, Any]] = []
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except Exception:
                    continue
        return entries

    def log_action(self, session_id: Optional[str], action: str, tool: str, params: Dict[str, Any], result: Any, timestamp: Optional[str] = None) -> None:
        ts = timestamp or datetime.datetime.utcnow().isoformat() + "Z"
        entry = {
            "timestamp": ts,
            "session_id": session_id,
            "action": action,
            "tool": tool,
            "params": params,
            "result": result,
        }
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        self._update_signature()

    def _update_signature(self) -> None:
        sha = hashlib.sha256()
        with open(self.log_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha.update(chunk)
        with open(self.sig_path, "w", encoding="utf-8") as f:
            f.write(sha.hexdigest())

    def export_audit_log(self, format: str = "json") -> str:
        logs = self._read_all()
        if format == "json":
            return json.dumps(logs, default=str, ensure_ascii=False)
        elif format == "text":
            return "\n".join([str(entry) for entry in logs])
        else:
            return json.dumps(logs, default=str, ensure_ascii=False)

    def verify_integrity(self) -> bool:
        if not os.path.exists(self.log_path) or not os.path.exists(self.sig_path):
            return True  # nothing to verify yet
        sha = hashlib.sha256()
        with open(self.log_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha.update(chunk)
        with open(self.sig_path, "r", encoding="utf-8") as fsig:
            stored = fsig.read().strip()
        return sha.hexdigest() == stored
