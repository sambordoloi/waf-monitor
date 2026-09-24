import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from elasticsearch import ApiError, Elasticsearch

from config import Config
from log_parse import NGINX_BACKEND_RE, TOKEN_PATH_RE, hit_from_fields, parse_nginx_backend_line, parse_username

logger = logging.getLogger(__name__)


class ElkClient:
    def __init__(self, config: Config, error_notifier=None):
        self.config = config
        self.error_notifier = error_notifier
        kwargs: dict[str, Any] = {
            "hosts": [config.elk_url],
            "verify_certs": config.elk_verify_ssl,
        }
        if config.elk_user:
            kwargs["basic_auth"] = (config.elk_user, config.elk_password)
        self.es = Elasticsearch(**kwargs)

    def check_connection(self) -> None:
        try:
            self.es.info()
        except Exception as exc:
            if self.error_notifier:
                self.error_notifier.notify(
                    "elk_connect",
                    "ELK not connecting",
                    f"URL: `{self.config.elk_url}` index: `{self.config.elk_index}`",
                    exc,
                )
            raise

    def _notify_elk_query_error(self, exc: Exception) -> None:
        if self.error_notifier:
            self.error_notifier.notify(
                "elk_query",
                "ELK query failed",
                f"URL: `{self.config.elk_url}` index: `{self.config.elk_index}`",
                exc,
            )

    def _effective_since(self, since: datetime | None) -> datetime | None:
        if since is None:
            return None
        if since.tzinfo is None:
            since = since.replace(tzinfo=timezone.utc)
        buffer = max(0, self.config.elk_since_buffer_minutes)
        if buffer:
            since = since - timedelta(minutes=buffer)
        return since

    def _time_clause(self, since: datetime | None, window_minutes: int) -> dict[str, Any] | None:
        since = self._effective_since(since)
        if since is not None:
            return {"range": {"@timestamp": {"gte": since.isoformat()}}}
        return {"range": {"@timestamp": {"gte": f"now-{window_minutes}m", "lte": "now"}}}

    def _parse_source(self, src: dict[str, Any], *, require_token: bool = False) -> dict[str, Any] | None:
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
        if require_token and not TOKEN_PATH_RE.search(request) and not TOKEN_PATH_RE.search(message):
            return None
        if require_token and not (hit.get("username") or hit.get("status") in {"200", "201"}):
            return None
        return hit

    def _search(self, query: dict[str, Any], *, require_token: bool = False) -> list[dict[str, Any]]:
        try:
            response = self.es.search(index=self.config.elk_index, body=query)
        except ApiError as exc:
            logger.warning("ELK query failed (%s): %s", exc.status_code, exc.message)
            self._notify_elk_query_error(exc)
            return []
        except Exception as exc:
            logger.warning("ELK query failed: %s", exc)
            self._notify_elk_query_error(exc)
            return []
        hits: list[dict[str, Any]] = []
        for hit in response.get("hits", {}).get("hits", []):
            parsed = self._parse_source(hit.get("_source", {}), require_token=require_token)
            if parsed:
                hits.append(parsed)
        return hits

    def _run_token_queries(self, ip: str, since: datetime | None, window_minutes: int) -> list[dict[str, Any]]:
        token_path_clause = {
            "bool": {
                "should": [
                    {"match_phrase": {"message": "POST /api/token/"}},
                    {"match_phrase": {"message": "POST /api/token "}},
                ],
                "minimum_should_match": 1,
            }
        }
        base_must = [
            {"match_phrase": {"message": ip}},
            token_path_clause,
        ]
        ip_only = [{"match_phrase": {"message": ip}}]

        attempts: list[tuple[dict[str, Any], bool]] = []
        time_clause = self._time_clause(since, window_minutes)
        if time_clause:
            attempts.append(
                ({"query": {"bool": {"must": base_must + [time_clause]}}, "size": 10, "sort": [{"@timestamp": "desc"}]}, True)
            )
            attempts.append(
                ({"query": {"bool": {"must": ip_only + [time_clause]}}, "size": 20, "sort": [{"@timestamp": "desc"}]}, False)
            )
        attempts.append(
            ({"query": {"bool": {"must": base_must}}, "size": 10, "sort": [{"@timestamp": "desc"}]}, True)
        )
        attempts.append(
            ({"query": {"bool": {"must": ip_only}}, "size": 20, "sort": [{"@timestamp": "desc"}]}, False)
        )

        for query, require_token in attempts:
            hits = self._search(query, require_token=require_token)
            if hits:
                token_hits = [
                    hit
                    for hit in hits
                    if TOKEN_PATH_RE.search(str(hit.get("request") or ""))
                    or hit.get("username")
                ]
                if token_hits:
                    return token_hits
                if not require_token:
                    return hits
        return []

    def find_token_hits(
        self,
        ip: str,
        window_minutes: int | None = None,
        since: datetime | None = None,
    ) -> list[dict[str, Any]]:
        minutes = window_minutes if window_minutes is not None else self.config.elk_window_minutes
        hits = self._run_token_queries(ip, since, minutes)
        if hits:
            logger.info("ELK: found %s hit(s) for %s on /api/token/ in %s", len(hits), ip, self.config.elk_index)
        else:
            logger.warning("ELK: no /api/token/ hits for IP %s in index %s", ip, self.config.elk_index)
        return hits

    def find_username_for_ip(
        self,
        ip: str,
        since: datetime | None = None,
        hours: int = 24,
    ) -> str | None:
        minutes = hours * 60
        ip_only = [{"match_phrase": {"message": ip}}]
        attempts: list[dict[str, Any]] = []
        time_clause = self._time_clause(since, minutes)
        if time_clause:
            attempts.append({"query": {"bool": {"must": ip_only + [time_clause]}}, "size": 5, "sort": [{"@timestamp": "desc"}]})
        attempts.append({"query": {"bool": {"must": ip_only}}, "size": 5, "sort": [{"@timestamp": "desc"}]})

        for query in attempts:
            for hit in self._search(query, require_token=False):
                if hit.get("username"):
                    return hit["username"]
        return None
