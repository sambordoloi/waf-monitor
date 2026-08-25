import gzip
import json
import logging
from collections import Counter
from datetime import datetime, timedelta, timezone
from io import BytesIO
from typing import Any, Iterator

import boto3

from config import Config
from waf_log_common import client_from_uri, get_http_request, is_valid_api

logger = logging.getLogger(__name__)


def record_time(record: dict[str, Any]) -> datetime | None:
    ts = record.get("timestamp")
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(int(ts) / 1000, tz=timezone.utc)
    except (TypeError, ValueError):
        return None


def parse_waf_record(raw: str | bytes) -> dict[str, Any] | None:
    try:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        return json.loads(raw.strip())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


class WafLogReader:
    def __init__(self, config: Config):
        self.config = config
        self.source = config.log_source
        if self.source == "cloudwatch":
            self.logs = boto3.client("logs", region_name=config.aws_region)
        else:
            self.s3 = boto3.client("s3", region_name=config.aws_region)

    def _iter_records_cloudwatch(
        self,
        start: datetime,
        end: datetime,
        *,
        filter_pattern: str | None = None,
        quiet: bool = False,
    ) -> Iterator[dict[str, Any]]:
        start_ms = int(start.timestamp() * 1000)
        end_ms = int(end.timestamp() * 1000)
        kwargs: dict[str, Any] = {
            "logGroupName": self.config.cloudwatch_log_group,
            "startTime": start_ms,
            "endTime": end_ms,
            "limit": 10000,
        }
        if filter_pattern:
            kwargs["filterPattern"] = filter_pattern
        events_read = 0
        while True:
            response = self.logs.filter_log_events(**kwargs)
            for event in response.get("events", []):
                record = parse_waf_record(event.get("message", ""))
                if not record:
                    continue
                ts = record_time(record)
                if ts is None or ts < start or ts > end:
                    continue
                events_read += 1
                yield record
            token = response.get("nextToken")
            if not token:
                break
            kwargs["nextToken"] = token

        if events_read == 0:
            if not quiet:
                logger.warning(
                    "No WAF events in CloudWatch log group %s (%s → %s)",
                    self.config.cloudwatch_log_group,
                    start.isoformat(),
                    end.isoformat(),
                )
        elif not quiet:
            logger.info(
                "CloudWatch: read %s event(s) from %s",
                events_read,
                self.config.cloudwatch_log_group,
            )

    def _list_s3_keys(self, start: datetime, end: datetime) -> list[str]:
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

    def _iter_records_s3(self, start: datetime, end: datetime) -> Iterator[dict[str, Any]]:
        keys = self._list_s3_keys(start, end)
        if not keys:
            logger.warning(
                "No WAF log files in s3://%s/%s (%s → %s)",
                self.config.waf_log_bucket,
                self.config.waf_log_prefix,
                start.isoformat(),
                end.isoformat(),
            )
            return
        logger.info("S3: reading %s WAF log file(s)", len(keys))
        for key in keys:
            body = self.s3.get_object(Bucket=self.config.waf_log_bucket, Key=key)["Body"].read()
            lines = gzip.GzipFile(fileobj=BytesIO(body)) if key.endswith(".gz") else body.splitlines()
            for raw_line in lines:
                line = raw_line.strip() if isinstance(raw_line, bytes) else raw_line.strip()
                if not line:
                    continue
                record = parse_waf_record(line)
                if not record:
                    continue
                ts = record_time(record)
                if ts is None or ts < start or ts > end:
                    continue
                yield record

    def _iter_records(
        self,
        start: datetime,
        end: datetime,
        *,
        filter_pattern: str | None = None,
        quiet: bool = False,
    ) -> Iterator[dict[str, Any]]:
        if self.source == "cloudwatch":
            yield from self._iter_records_cloudwatch(
                start, end, filter_pattern=filter_pattern, quiet=quiet
            )
        else:
            yield from self._iter_records_s3(start, end)

    def blocked_valid_counts(
        self,
        registry: dict[str, str],
        window_minutes: int,
        registry_only: bool = False,
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
            if registry_only and uri == "/api/token/" and ip not in registry:
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

    def _record_matches_session(
        self,
        record: dict[str, Any],
        ip: str,
        since: datetime,
        uri_filter: str | None,
    ) -> bool:
        ts = record_time(record)
        if ts is None or ts < since:
            return False
        req = get_http_request(record)
        if (req.get("clientIp") or req.get("clientip")) != ip:
            return False
        uri = req.get("uri") or ""
        if not is_valid_api(uri):
            return False
        if uri_filter and uri != uri_filter:
            return False
        return True

    def has_allow_since(self, ip: str, since: datetime, uri_filter: str | None = None) -> bool:
        end = datetime.now(timezone.utc)
        allow_filter = '{ $.action = "ALLOW" }' if self.source == "cloudwatch" else None
        for record in self._iter_records(
            since,
            end,
            filter_pattern=allow_filter,
            quiet=True,
        ):
            if (record.get("action") or "").upper() != "ALLOW":
                continue
            if not self._record_matches_session(record, ip, since, uri_filter):
                continue
            return True
        return False

    def session_event_counts(
        self,
        ip: str,
        since: datetime,
        uri_filter: str | None = None,
    ) -> dict[str, int]:
        end = datetime.now(timezone.utc)
        allows = 0
        blocks = 0
        for record in self._iter_records(since, end, quiet=True):
            if not self._record_matches_session(record, ip, since, uri_filter):
                continue
            action = (record.get("action") or "").upper()
            if action == "ALLOW":
                allows += 1
            elif action == "BLOCK":
                blocks += 1
        return {"allows": allows, "blocks": blocks}
