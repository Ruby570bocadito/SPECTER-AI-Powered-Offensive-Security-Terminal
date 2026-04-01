import json
import os
from pathlib import Path
from typing import Any


class JSONStorage:
    def save(self, data: Any, path: str) -> None:
        dirpath = os.path.dirname(path)
        os.makedirs(dirpath, exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2, default=self._default_json)

    def load(self, path: str) -> Any:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def exists(self, path: str) -> bool:
        return Path(path).exists()

    def _default_json(self, obj: Any) -> Any:
        # Fallback for non-serializable objects (e.g., datetime)
        try:
            return obj.isoformat()
        except Exception:
            return str(obj)


class SessionStorage(JSONStorage):
    def __init__(self, base_dir: Optional[str] = None) -> None:
        # Default to ~/.specter/sessions/
        self.base_dir = Path(base_dir or os.path.expanduser("~/.specter/sessions"))
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def session_path(self, session_id: str) -> str:
        return str(self.base_dir / f"{session_id}.json")
