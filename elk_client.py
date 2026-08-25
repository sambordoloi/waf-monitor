import json
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from elasticsearch import Elasticsearch

from config import Config

logger = logging.getLogger(__name__)


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


class ElkClient:
    def __init__(self, config: Config):
        self.config = config
        kwargs: dict[str, Any] = {
            "hosts": [config.elk_url],
            "verify_certs": config.elk_verify_ssl,
        }
        if config.elk_user:
            kwargs["basic_auth"] = (config.elk_user, config.elk_password)
        self.es = Elasticsearch(**kwargs)

    def _ip_clauses(self, ip: str) -> list[dict[str, Any]]:
        return [
            {"wildcard": {"http_x_forwarded_for": f"*{ip}*"}},
            {"match_phrase": {"http_x_forwarded_for": ip}},
            {"term": {"remote_addr": ip}},
            {"wildcard": {"remote_addr": f"*{ip}*"}},
            {"wildcard": {"http_x_forwarded_for.keyword": f"*{ip}*"}},
        ]

    def _token_clauses(self) -> list[dict[str, Any]]:
        return [
            {"wildcard": {"request": "*POST /api/token/*"}},
            {"wildcard": {"request": "*post /api/token/*"}},
            {"wildcard": {"request": "* /api/token/*"}},
        ]

    def _search(self, query: dict[str, Any]) -> list[dict[str, Any]]:
        response = self.es.search(index=self.config.elk_index, body=query)
        hits: list[dict[str, Any]] = []
        for hit in response.get("hits", {}).get("hits", []):
            src = hit.get("_source", {})
            hits.append(
                {
                    "time": src.get("time_local") or src.get("@timestamp"),
                    "request": src.get("request"),
                    "status": src.get("status"),
                    "username": parse_username(src.get("request_body", "")),
                    "user_agent": src.get("http_user_agent"),
                    "uuid": src.get("request_uuid"),
                }
            )
        return hits

    def find_token_hits(
        self,
        ip: str,
        window_minutes: int | None = None,
        since: datetime | None = None,
    ) -> list[dict[str, Any]]:
        minutes = window_minutes if window_minutes is not None else self.config.elk_window_minutes
        time_clause: dict[str, Any]
        if since is not None:
            if since.tzinfo is None:
                since = since.replace(tzinfo=timezone.utc)
            time_clause = {"range": {"@timestamp": {"gte": since.isoformat()}}}
        else:
            time_clause = {"range": {"@timestamp": {"gte": f"now-{minutes}m", "lte": "now"}}}

        base_must = [
            {
                "bool": {
                    "should": self._ip_clauses(ip),
                    "minimum_should_match": 1,
                }
            },
            {
                "bool": {
                    "should": self._token_clauses(),
                    "minimum_should_match": 1,
                }
            },
        ]

        query = {
            "query": {"bool": {"must": base_must + [time_clause]}},
            "size": 10,
            "sort": [{"@timestamp": "desc"}],
        }
        hits = self._search(query)
        if hits:
            logger.info("ELK: found %s hit(s) for %s on /api/token/", len(hits), ip)
            return hits

        # Broader fallback: same IP + token path, no time filter (ingest lag / time field mismatch).
        fallback = {
            "query": {"bool": {"must": base_must}},
            "size": 10,
            "sort": [{"@timestamp": "desc"}],
        }
        hits = self._search(fallback)
        if hits:
            logger.info(
                "ELK: found %s hit(s) for %s (fallback without time filter)",
                len(hits),
                ip,
            )
        else:
            logger.warning("ELK: no /api/token/ hits for IP %s in index %s", ip, self.config.elk_index)
        return hits

    def count_hits_since(self, ip: str, window_minutes: int | None = None) -> int:
        return len(self.find_token_hits(ip, window_minutes=window_minutes))
