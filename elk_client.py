import logging
from datetime import datetime, timezone
from typing import Any

from elasticsearch import ApiError, Elasticsearch

from config import Config
from log_parse import NGINX_BACKEND_RE, TOKEN_PATH_RE, hit_from_fields, parse_nginx_backend_line, parse_username

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

    def _time_clause(self, since: datetime | None, window_minutes: int) -> dict[str, Any] | None:
        if since is not None:
            if since.tzinfo is None:
                since = since.replace(tzinfo=timezone.utc)
            return {"range": {"@timestamp": {"gte": since.isoformat()}}}
        return {"range": {"@timestamp": {"gte": f"now-{window_minutes}m", "lte": "now"}}}

    def _hit_from_source(self, src: dict[str, Any]) -> dict[str, Any] | None:
        message = str(src.get("message") or "")
        if NGINX_BACKEND_RE.match(message):
            hit = hit_from_fields(parse_nginx_backend_line(message), source="elk")
        else:
            merged = {k: str(v) if v is not None else "" for k, v in src.items()}
            hit = hit_from_fields(merged, source="elk")
            if not hit.get("username"):
                body = src.get("request_body") or message
                hit["username"] = parse_username(str(body))

        request = str(hit.get("request") or message)
        if not TOKEN_PATH_RE.search(request) and not TOKEN_PATH_RE.search(message):
            return None
        if not (hit.get("username") or hit.get("status") in {"200", "201"}):
            return None
        return hit

    def _search(self, query: dict[str, Any]) -> list[dict[str, Any]]:
        try:
            response = self.es.search(index=self.config.elk_index, body=query)
        except ApiError as exc:
            logger.warning("ELK query failed (%s): %s", exc.status_code, exc.message)
            return []
        hits: list[dict[str, Any]] = []
        for hit in response.get("hits", {}).get("hits", []):
            parsed = self._hit_from_source(hit.get("_source", {}))
            if parsed:
                hits.append(parsed)
        return hits

    def _run_queries(self, ip: str, since: datetime | None, window_minutes: int) -> list[dict[str, Any]]:
        # Same query that works in Kibana: match_phrase on message for the client IP.
        base_must: list[dict[str, Any]] = [
            {"match_phrase": {"message": ip}},
            {"match_phrase": {"message": "POST /api/token/"}},
        ]

        attempts: list[dict[str, Any]] = []
        time_clause = self._time_clause(since, window_minutes)

        if time_clause:
            attempts.append(
                {
                    "query": {"bool": {"must": base_must + [time_clause]}},
                    "size": 10,
                    "sort": [{"@timestamp": "desc"}],
                }
            )

        # Fallback without time filter (ingest lag).
        attempts.append(
            {
                "query": {"bool": {"must": base_must}},
                "size": 10,
                "sort": [{"@timestamp": "desc"}],
            }
        )

        # IP only — filter /api/token/ when parsing hits.
        ip_only = [{"match_phrase": {"message": ip}}]
        if time_clause:
            attempts.append(
                {
                    "query": {"bool": {"must": ip_only + [time_clause]}},
                    "size": 20,
                    "sort": [{"@timestamp": "desc"}],
                }
            )
        attempts.append(
            {
                "query": {"bool": {"must": ip_only}},
                "size": 20,
                "sort": [{"@timestamp": "desc"}],
            }
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
