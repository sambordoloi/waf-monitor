import logging
from datetime import datetime, timezone
from typing import Any

from elasticsearch import Elasticsearch

from config import Config
from log_parse import NGINX_BACKEND_RE, hit_from_fields, parse_nginx_backend_line, parse_username

logger = logging.getLogger(__name__)


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
            {"wildcard": {"http_x_forwarded_for.keyword": f"*{ip}*"}},
            {"wildcard": {"message": f"*http_x_forwarded_for: \"{ip}\"*"}},
            {"wildcard": {"message": f"*http_x_forwarded_for: *{ip}*"}},
            {"query_string": {"default_field": "message", "query": f"http_x_forwarded_for AND {ip}"}},
        ]

    def _token_clauses(self) -> list[dict[str, Any]]:
        return [
            {"wildcard": {"request": "*POST /api/token/*"}},
            {"wildcard": {"request": "*post /api/token/*"}},
            {"wildcard": {"request": "* /api/token/*"}},
            {"wildcard": {"message": "*POST /api/token/*"}},
            {"wildcard": {"message": "*post /api/token/*"}},
            {"query_string": {"default_field": "message", "query": "POST AND /api/token/"}},
        ]

    def _time_clauses(
        self,
        since: datetime | None,
        window_minutes: int,
    ) -> list[dict[str, Any]]:
        if since is not None:
            if since.tzinfo is None:
                since = since.replace(tzinfo=timezone.utc)
            iso = since.isoformat()
            return [
                {"range": {"@timestamp": {"gte": iso}}},
                {"range": {"time_local": {"gte": iso}}},
            ]
        return [
            {"range": {"@timestamp": {"gte": f"now-{window_minutes}m", "lte": "now"}}},
        ]

    def _hit_from_source(self, src: dict[str, Any]) -> dict[str, Any]:
        message = str(src.get("message") or "")
        if NGINX_BACKEND_RE.match(message):
            return hit_from_fields(parse_nginx_backend_line(message), source="elk")
        merged = {k: str(v) if v is not None else "" for k, v in src.items()}
        hit = hit_from_fields(merged, source="elk")
        if not hit.get("username"):
            body = src.get("request_body") or message
            hit["username"] = parse_username(str(body))
        return hit

    def _search(self, query: dict[str, Any]) -> list[dict[str, Any]]:
        response = self.es.search(index=self.config.elk_index, body=query)
        hits: list[dict[str, Any]] = []
        for hit in response.get("hits", {}).get("hits", []):
            src = hit.get("_source", {})
            parsed = self._hit_from_source(src)
            if parsed.get("username") or parsed.get("status") in {"200", "201"}:
                hits.append(parsed)
        return hits

    def _run_queries(self, ip: str, since: datetime | None, window_minutes: int) -> list[dict[str, Any]]:
        ip_should = {"bool": {"should": self._ip_clauses(ip), "minimum_should_match": 1}}
        token_should = {"bool": {"should": self._token_clauses(), "minimum_should_match": 1}}
        message_must = [
            {"wildcard": {"message": f"*http_x_forwarded_for: \"{ip}\"*"}},
            {"wildcard": {"message": "*POST /api/token/*"}},
        ]

        attempts: list[dict[str, Any]] = []
        for time_clause in self._time_clauses(since, window_minutes):
            attempts.append(
                {
                    "query": {"bool": {"must": [ip_should, token_should, time_clause]}},
                    "size": 10,
                    "sort": [{"@timestamp": "desc"}],
                }
            )
            attempts.append(
                {
                    "query": {"bool": {"must": message_must + [time_clause]}},
                    "size": 10,
                    "sort": [{"@timestamp": "desc"}],
                }
            )

        attempts.append(
            {"query": {"bool": {"must": [ip_should, token_should]}}, "size": 10, "sort": [{"@timestamp": "desc"}]}
        )
        attempts.append(
            {"query": {"bool": {"must": message_must}}, "size": 10, "sort": [{"@timestamp": "desc"}]}
        )

        for query in attempts:
            hits = self._search(query)
            if hits:
                return hits
        return []

    def find_token_hits(
        self,
        ip: str,
        window_minutes: int | None = None,
        since: datetime | None = None,
    ) -> list[dict[str, Any]]:
        minutes = window_minutes if window_minutes is not None else self.config.elk_window_minutes
        hits = self._run_queries(ip, since, minutes)
        if hits:
            logger.info("ELK: found %s hit(s) for %s on /api/token/ in %s", len(hits), ip, self.config.elk_index)
        else:
            logger.warning("ELK: no /api/token/ hits for IP %s in index %s", ip, self.config.elk_index)
        return hits

    def count_hits_since(self, ip: str, window_minutes: int | None = None) -> int:
        return len(self.find_token_hits(ip, window_minutes=window_minutes))
