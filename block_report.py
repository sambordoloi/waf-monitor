import logging
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from waf_log_common import get_http_request, is_api_uri

logger = logging.getLogger(__name__)


def blocked_api_report(logs_reader, registry: dict[str, str], hours: int = 24) -> list[dict[str, Any]]:
    """Summarise WAF BLOCK events on /api* URIs for the last N hours."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    per_ip: Counter[str] = Counter()
    per_ip_uri: dict[str, Counter[str]] = defaultdict(Counter)
    per_ip_rule: dict[str, str] = {}

    for record in logs_reader._iter_records(start, end):
        if (record.get("action") or "").upper() != "BLOCK":
            continue
        req = get_http_request(record)
        uri = req.get("uri") or ""
        if not is_api_uri(uri):
            continue
        ip = req.get("clientIp") or req.get("clientip")
        if not ip:
            continue
        per_ip[ip] += 1
        per_ip_uri[ip][uri] += 1
        per_ip_rule[ip] = record.get("terminatingRuleId") or record.get("terminatingruleid") or "unknown"

    rows: list[dict[str, Any]] = []
    for ip, count in per_ip.most_common():
        top_uri, top_count = per_ip_uri[ip].most_common(1)[0]
        uri_summary = ", ".join(f"{u} ({c})" for u, c in per_ip_uri[ip].most_common(3))
        rows.append(
            {
                "ip": ip,
                "blocks": count,
                "top_uri": top_uri,
                "top_uri_blocks": top_count,
                "uris": uri_summary,
                "rule": per_ip_rule.get(ip, "unknown"),
                "registry_client": registry.get(ip),
            }
        )
    logger.info("Block report: %s IP(s) on /api* in last %sh", len(rows), hours)
    return rows
