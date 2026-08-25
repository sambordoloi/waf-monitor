import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import Config
from elk_client import parse_username

logger = logging.getLogger(__name__)

TOKEN_PATH_RE = re.compile(r"/api/token/?", re.I)
# nginx backend: remote_addr: "..." - time_local: [25/Aug/2026:07:05:03 +0000] - ...
NGINX_BACKEND_RE = re.compile(r"^\s*remote_addr:\s")


def _parse_timestamp(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        ts = float(value)
        if ts > 1e12:
            ts /= 1000
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    if isinstance(value, str):
        text = value.strip().strip("[]")
        for fmt in (
            "%d/%b/%Y:%H:%M:%S %z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
        ):
            try:
                dt = datetime.strptime(text.replace("Z", "+0000"), fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except ValueError:
                continue
    return None


def parse_nginx_backend_line(line: str) -> dict[str, str]:
    """Parse CV3 nginx backend access_api.log lines."""
    data: dict[str, str] = {}
    for part in line.split(" - "):
        part = part.strip()
        if ": " not in part:
            continue
        key, _, rest = part.partition(": ")
        key = key.strip()
        rest = rest.strip()
        if len(rest) >= 2 and rest[0] == rest[-1] == '"':
            rest = rest[1:-1]
        elif len(rest) >= 2 and rest[0] == "[" and rest[-1] == "]":
            rest = rest[1:-1]
        data[key] = rest
    return data


def _record_has_ip(data: dict[str, Any], ip: str) -> bool:
    xff = str(data.get("http_x_forwarded_for") or "")
    if xff:
        forwarded_ips = [part.strip() for part in xff.split(",")]
        if ip in forwarded_ips or ip in xff:
            return True
    for key in ("remote_addr", "clientip", "client_ip", "x_forwarded_for"):
        value = str(data.get(key) or "")
        if value == ip or ip in value:
            return True
    return False


def _record_is_token(data: dict[str, Any], line: str) -> bool:
    request = str(data.get("request") or data.get("message") or "")
    if TOKEN_PATH_RE.search(request):
        return True
    uri = str(data.get("uri") or data.get("request_uri") or "")
    if TOKEN_PATH_RE.search(uri):
        return True
    return bool(TOKEN_PATH_RE.search(line))


def _record_timestamp(data: dict[str, Any]) -> datetime | None:
    for key in ("time_local", "@timestamp", "timestamp", "time"):
        ts = _parse_timestamp(data.get(key))
        if ts:
            return ts
    return None


def _hit_from_record(data: dict[str, Any]) -> dict[str, Any]:
    body = data.get("request_body") or data.get("body") or ""
    return {
        "time": data.get("time_local") or data.get("@timestamp") or data.get("timestamp"),
        "request": data.get("request") or data.get("message"),
        "status": data.get("status"),
        "username": parse_username(str(body)) if body else None,
        "user_agent": data.get("http_user_agent") or data.get("user_agent"),
        "uuid": data.get("request_uuid"),
        "source": "local_log",
    }


def _parse_line(line: str) -> dict[str, Any] | None:
    line = line.strip()
    if not line:
        return None
    if NGINX_BACKEND_RE.match(line):
        return parse_nginx_backend_line(line)
    try:
        data = json.loads(line)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass
    return None


class LocalLogClient:
    def __init__(self, config: Config):
        self.config = config
        self.paths = [p.strip() for p in config.app_log_path.split(",") if p.strip()]
        self.tail_bytes = config.app_log_tail_mb * 1024 * 1024

    def find_token_hits(
        self,
        ip: str,
        since: datetime | None = None,
    ) -> list[dict[str, Any]]:
        if not self.paths:
            return []

        hits: list[dict[str, Any]] = []
        for path_str in self.paths:
            path = Path(path_str)
            if not path.exists():
                logger.warning("APP_LOG_PATH not found: %s", path)
                continue
            hits.extend(self._search_file(path, ip, since))

        hits.sort(key=lambda h: str(h.get("time") or ""), reverse=True)
        if hits:
            logger.info(
                "Local log: found %s hit(s) for %s in %s",
                len(hits),
                ip,
                ", ".join(self.paths),
            )
        else:
            logger.warning(
                "Local log: no /api/token/ hits for IP %s in %s",
                ip,
                ", ".join(self.paths),
            )
        return hits[:10]

    def _search_file(
        self,
        path: Path,
        ip: str,
        since: datetime | None,
    ) -> list[dict[str, Any]]:
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

        if since and since.tzinfo is None:
            since = since.replace(tzinfo=timezone.utc)

        text = raw.decode("utf-8", errors="replace")
        for line in text.splitlines():
            if ip not in line or not TOKEN_PATH_RE.search(line):
                continue

            data = _parse_line(line)
            if not data or not _record_has_ip(data, ip) or not _record_is_token(data, line):
                continue

            ts = _record_timestamp(data)
            if since and ts and ts < since.astimezone(timezone.utc):
                continue

            hit = _hit_from_record(data)
            if hit.get("username"):
                hits.append(hit)
            elif hit.get("status") in {"200", "201"}:
                hits.append(hit)

        return hits
