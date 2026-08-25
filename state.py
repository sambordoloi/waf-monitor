import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class StateStore:
    def __init__(self, path: str):
        self.path = Path(path)
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self._write({"sessions": {}, "last_run": None})

    def _read(self) -> dict[str, Any]:
        return json.loads(self.path.read_text())

    def _write(self, data: dict[str, Any]) -> None:
        self.path.write_text(json.dumps(data, indent=2, default=str))

    def get_session(self, ip: str) -> dict[str, Any] | None:
        with self._lock:
            return self._read()["sessions"].get(ip)

    def was_debugged(self, ip: str) -> bool:
        session = self.get_session(ip)
        return bool(session and session.get("status") == "done")

    def list_active_sessions(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            sessions = self._read()["sessions"]
            return {ip: s for ip, s in sessions.items() if s.get("status") == "active"}

    def start_session(self, ip: str, uri: str, block_count: int, client: str) -> None:
        with self._lock:
            data = self._read()
            data["sessions"][ip] = {
                "status": "active",
                "started_at": datetime.now(timezone.utc).isoformat(),
                "uri": uri,
                "block_count": block_count,
                "client": client,
                "hits_seen": 0,
            }
            self._write(data)

    def mark_done(self, ip: str, reason: str) -> None:
        with self._lock:
            data = self._read()
            if ip in data["sessions"]:
                data["sessions"][ip]["status"] = "done"
                data["sessions"][ip]["finished_reason"] = reason
                data["sessions"][ip]["finished_at"] = datetime.now(timezone.utc).isoformat()
            self._write(data)

    def clear_session(self, ip: str) -> bool:
        with self._lock:
            data = self._read()
            if ip not in data["sessions"]:
                return False
            del data["sessions"][ip]
            self._write(data)
            return True

    def touch_run(self) -> None:
        with self._lock:
            data = self._read()
            data["last_run"] = datetime.now(timezone.utc).isoformat()
            self._write(data)
