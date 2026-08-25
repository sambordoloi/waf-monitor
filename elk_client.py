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

    def find_token_hits(self, ip: str, window_minutes: int | None = None) -> list[dict[str, Any]]:
        minutes = window_minutes if window_minutes is not None else self.config.elk_window_minutes
        since = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"match_phrase": {"http_x_forwarded_for": ip}},
                        {
                            "bool": {
                                "should": [
                                    {"wildcard": {"request": "*POST /api/token/*"}},
                                    {"wildcard": {"request": "*dem_*"}},
                                ],
                                "minimum_should_match": 1,
                            }
                        },
                        {"range": {"@timestamp": {"gte": since.isoformat()}}},
                    ]
                }
            },
            "size": 10,
            "sort": [{"@timestamp": "desc"}],
        }

        response = self.es.search(index=self.config.elk_index, body=query)
        hits = []
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

    def count_hits_since(self, ip: str, window_minutes: int | None = None) -> int:
        return len(self.find_token_hits(ip, window_minutes=window_minutes))
