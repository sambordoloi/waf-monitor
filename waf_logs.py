import gzip
import json
import logging
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from io import BytesIO
from typing import Any

import boto3

from config import Config

logger = logging.getLogger(__name__)


def get_http_request(record: dict[str, Any]) -> dict[str, Any]:
    return record.get("httpRequest") or record.get("httprequest") or {}


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


def record_time(record: dict[str, Any]) -> datetime | None:
    ts = record.get("timestamp")
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(int(ts) / 1000, tz=timezone.utc)
    except (TypeError, ValueError):
        return None


class WafLogReader:
    def __init__(self, config: Config):
        self.config = config
        self.s3 = boto3.client("s3", region_name=config.aws_region)

    def _list_keys(self, start: datetime, end: datetime) -> list[str]:
        keys: list[str] = []
        hour = start.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
        end_utc = end.astimezone(timezone.utc)
        while hour <= end_utc:
            prefix = f"{self.config.waf_log_prefix}{hour.strftime('%Y/%m/%d/%H/')}"
            paginator = self.s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=self.config.waf_log_bucket, Prefix=prefix):
                for obj in page.get("Contents", []):
                    key = obj["Key"]
                    if key.endswith(".log") or key.endswith(".log.gz"):
                        keys.append(key)
            hour += timedelta(hours=1)
        return sorted(set(keys))

    def _iter_records(self, start: datetime, end: datetime):
        keys = self._list_keys(start, end)
        if not keys:
            logger.warning(
                "No WAF log files in s3://%s/%s (%s → %s)",
                self.config.waf_log_bucket,
                self.config.waf_log_prefix,
                start.isoformat(),
                end.isoformat(),
            )
            return
        logger.debug("Reading %s WAF log file(s)", len(keys))
        for key in keys:
            body = self.s3.get_object(Bucket=self.config.waf_log_bucket, Key=key)["Body"].read()
            if key.endswith(".gz"):
                lines = gzip.GzipFile(fileobj=BytesIO(body))
            else:
                lines = body.splitlines()
            for raw_line in lines:
                line = raw_line.strip() if isinstance(raw_line, bytes) else raw_line.strip()
                if not line:
                    continue
                record = json.loads(line)
                ts = record_time(record)
                if ts is None or ts < start or ts > end:
                    continue
                yield record

    def blocked_valid_counts(
        self,
        registry: dict[str, str],
        window_minutes: int,
    ) -> dict[str, dict[str, Any]]:
        end = datetime.now(timezone.utc)
        start = end - timedelta(minutes=window_minutes)
        per_ip: Counter[str] = Counter()
        sample_uri: dict[str, str] = {}
        sample_rule: dict[str, str] = {}

        for record in self._iter_records(start, end):
            if (record.get("action") or "").upper() != "BLOCK":
                continue
            req = get_http_request(record)
            uri = req.get("uri") or ""
            if not is_valid_api(uri):
                continue
            ip = req.get("clientIp") or req.get("clientip")
            if not ip:
                continue
            if uri == "/api/token/" and ip not in registry:
                continue
            per_ip[ip] += 1
            sample_uri[ip] = uri
            sample_rule[ip] = record.get("terminatingRuleId") or record.get("terminatingruleid") or "unknown"

        result: dict[str, dict[str, Any]] = {}
        for ip, count in per_ip.items():
            uri = sample_uri[ip]
            client = registry.get(ip) or client_from_uri(uri) or "unknown"
            result[ip] = {
                "count": count,
                "uri": uri,
                "rule": sample_rule[ip],
                "client": client,
            }
        return result

    def count_allows_since(self, ip: str, since: datetime, uri_filter: str | None = None) -> int:
        end = datetime.now(timezone.utc)
        count = 0
        for record in self._iter_records(since, end):
            if (record.get("action") or "").upper() != "ALLOW":
                continue
            req = get_http_request(record)
            if (req.get("clientIp") or req.get("clientip")) != ip:
                continue
            uri = req.get("uri") or ""
            if not is_valid_api(uri):
                continue
            if uri_filter and uri != uri_filter:
                continue
            count += 1
        return count
