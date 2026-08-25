import json
import re

TOKEN_PATH_RE = re.compile(r"/api/token/?", re.I)
NGINX_BACKEND_RE = re.compile(r"^\s*remote_addr:\s")


def parse_username(body: str) -> str | None:
    if not body:
        return None
    try:
        cleaned = body
        if "\\x22" in body:
            cleaned = body.encode("utf-8").decode("unicode_escape")
        data = json.loads(cleaned)
        return data.get("username") or data.get("client_id")
    except Exception:
        match = re.search(r'"username"\s*:\s*"([^"]+)"', body)
        if match:
            return match.group(1)
        match = re.search(r'username\\x22:\\x22([^\\"]+)', body)
        if match:
            return match.group(1)
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


def hit_from_fields(data: dict[str, str], *, source: str = "elk") -> dict:
    body = data.get("request_body") or data.get("body") or ""
    return {
        "time": data.get("time_local") or data.get("@timestamp") or data.get("timestamp"),
        "request": data.get("request") or data.get("message"),
        "status": data.get("status"),
        "username": parse_username(str(body)) if body else None,
        "user_agent": data.get("http_user_agent") or data.get("user_agent"),
        "uuid": data.get("request_uuid"),
        "source": source,
    }
