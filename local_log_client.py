import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import Config
from log_parse import NGINX_BACKEND_RE, TOKEN_PATH_RE, hit_from_fields, parse_nginx_backend_line

logger = logging.getLogger(__name__)


class LocalLogClient:
    def __init__(self, config: Config):
        self.config = config
        self.paths = [p.strip() for p in config.app_log_path.split(",") if p.strip()]
        self.tail_bytes = config.app_log_tail_mb * 1024 * 1024

    def _resolve_log_files(self, path: Path) -> list[Path]:
        if not path.exists():
            logger.warning("APP_LOG_PATH not found: %s", path)
            return []
        if path.is_file():
            return [path]
        if path.is_dir():
            files = sorted(path.glob("access_api.log*")) or sorted(p for p in path.glob("*.log") if p.is_file())
            return files
        return []

    def find_token_hits(self, ip: str, since: datetime | None = None) -> list[dict[str, Any]]:
        if not self.paths:
            return []
        hits: list[dict[str, Any]] = []
        for path_str in self.paths:
            for log_file in self._resolve_log_files(Path(path_str)):
                hits.extend(self._search_file(log_file, ip, since))
        hits.sort(key=lambda h: str(h.get("time") or ""), reverse=True)
        if hits:
            logger.info("Local log: found %s hit(s) for %s", len(hits), ip)
        return hits[:10]

    def _search_file(self, path: Path, ip: str, since: datetime | None) -> list[dict[str, Any]]:
        hits: list[dict[str, Any]] = []
        try:
            with path.open("rb") as handle:
                handle.seek(0, 2)
                size = handle.tell()
                handle.seek(max(0, size - self.tail_bytes))
                raw = handle.read()
        except OSError as exc:
            logger.warning("Cannot read %s: %s", path, exc)
            return hits

        for line in raw.decode("utf-8", errors="replace").splitlines():
            if ip not in line or not TOKEN_PATH_RE.search(line):
                continue
            if not NGINX_BACKEND_RE.match(line.strip()):
                continue
            data = parse_nginx_backend_line(line)
            if ip not in data.get("http_x_forwarded_for", ""):
                continue
            hit = hit_from_fields(data, source="local_log")
            if hit.get("username") or hit.get("status") in {"200", "201"}:
                hits.append(hit)
        return hits
