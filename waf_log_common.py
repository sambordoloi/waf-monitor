from typing import Any


def get_http_request(record: dict[str, Any]) -> dict[str, Any]:
    return record.get("httpRequest") or record.get("httprequest") or {}


def is_api_uri(uri: str) -> bool:
    return uri.startswith("/api")


def normalize_token_uri(uri: str) -> str:
    return uri.rstrip("/") or uri


def is_token_uri(uri: str) -> bool:
    return normalize_token_uri(uri) == "/api/token"


def is_valid_api(uri: str) -> bool:
    if is_token_uri(uri):
        return True
    if "/dem_" in uri:
        return True
    return False


def uri_matches_filter(uri: str, uri_filter: str | None) -> bool:
    if not uri_filter:
        return True
    if is_token_uri(uri) and is_token_uri(uri_filter):
        return True
    return uri == uri_filter


def client_from_uri(uri: str) -> str | None:
    if "/dem_" not in uri:
        return None
    part = uri.split("dem_", 1)[1]
    return part.split("/", 1)[0]
