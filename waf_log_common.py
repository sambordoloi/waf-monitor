from typing import Any


def get_http_request(record: dict[str, Any]) -> dict[str, Any]:
    return record.get("httpRequest") or record.get("httprequest") or {}


def is_api_uri(uri: str) -> bool:
    return uri.startswith("/api")


def is_valid_api(uri: str) -> bool:
    if uri == "/api/token/":
        return True
    if "/dem_" in uri:
        return True
    return False


def client_from_uri(uri: str) -> str | None:
    if "/dem_" not in uri:
        return None
    part = uri.split("dem_", 1)[1]
    return part.split("/", 1)[0]
