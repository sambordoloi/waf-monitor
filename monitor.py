#!/usr/bin/env python3
import logging
import sys
import time
from datetime import datetime, timedelta, timezone

from config import Config
from elk_client import ElkClient
from notify import format_debug_done, format_debug_started, notify_slack
from state import StateStore
from waf_client import WafClient, normalize_ip_set_id
from waf_logs import WafLogReader

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("waf-monitor")


class WafMonitor:
    def __init__(self, config: Config):
        self.config = config
        self.state = StateStore(config.state_file)
        self.waf = WafClient(config)
        self.logs = WafLogReader(config)
        self.elk = ElkClient(config) if config.elk_url else None

    def detect_and_allow(self, registry: dict[str, str]) -> None:
        blocked = self.logs.blocked_valid_counts(
            registry,
            self.config.block_window_minutes,
            registry_only=self.config.registry_only,
        )
        for ip, info in blocked.items():
            if info["count"] < self.config.block_threshold:
                continue
            existing = self.state.get_session(ip)
            if existing and existing.get("status") == "active":
                continue
            if not self.config.debug_ip_set_id:
                logger.error("DEBUG_IP_SET_ID is not configured")
                return

            self.waf.add_ip_to_debug_set(ip)
            self.state.start_session(
                ip=ip,
                uri=info["uri"],
                block_count=info["count"],
                client=info["client"],
            )
            msg = format_debug_started(
                ip=ip,
                client=info["client"],
                uri=info["uri"],
                block_count=info["count"],
                rule=info["rule"],
            )
            notify_slack(self.config.slack_webhook_url, msg)
            logger.info("Debug session started for %s (%s)", ip, info["client"])

    def check_hits_and_remove(self) -> None:
        for ip, session in self.state.list_active_sessions().items():
            started_at = datetime.fromisoformat(session["started_at"])
            if started_at.tzinfo is None:
                started_at = started_at.replace(tzinfo=timezone.utc)

            # Trigger on WAF ALLOW (fast) — remove IP first, then query ELK for debug details.
            waf_allow_count = self.logs.count_allows_since(ip, started_at, session.get("uri"))
            if waf_allow_count >= self.config.hits_to_remove:
                self.waf.remove_ip_from_debug_set(ip)
                logger.info(
                    "Removed %s from debug set after %s WAF ALLOW(s); checking ELK",
                    ip,
                    waf_allow_count,
                )

                elk_hits = self.elk.find_token_hits(ip) if self.elk else []
                self.state.mark_done(ip, reason=f"{waf_allow_count}_waf_allow(s)_then_elk")
                msg = format_debug_done(
                    ip=ip,
                    client=session.get("client", "unknown"),
                    reason=f"{waf_allow_count} WAF ALLOW(s), then ELK check",
                    elk_hits=elk_hits,
                )
                notify_slack(self.config.slack_webhook_url, msg)
                logger.info("Debug session closed for %s", ip)
                continue

            age = datetime.now(timezone.utc) - started_at
            if age >= timedelta(minutes=self.config.debug_expire_minutes):
                self.waf.remove_ip_from_debug_set(ip)
                self.state.mark_done(ip, reason="expired_no_hits")
                notify_slack(
                    self.config.slack_webhook_url,
                    f":hourglass: WAF debug expired for `{ip}` — no ELK/WAF hit in "
                    f"{self.config.debug_expire_minutes}m",
                )
                logger.info("Debug session expired for %s", ip)

    def run_once(self) -> None:
        registry = self.waf.load_registry()
        logger.info("Registry loaded: %s client IP(s)", len(registry))

        blocked = self.logs.blocked_valid_counts(
            registry,
            self.config.block_window_minutes,
            registry_only=self.config.registry_only,
        )
        if blocked:
            for ip, info in blocked.items():
                logger.info(
                    "Blocked in window: ip=%s client=%s uri=%s count=%s rule=%s (threshold=%s)",
                    ip,
                    info["client"],
                    info["uri"],
                    info["count"],
                    info["rule"],
                    self.config.block_threshold,
                )
        else:
            scope = "registry IPs only on /api/token/" if self.config.registry_only else "all blocked IPs"
            logger.info(
                "No qualifying BLOCK events in last %s min "
                "(scope: %s on /api/token/ or /dem_* URI)",
                self.config.block_window_minutes,
                scope,
            )

        active = self.state.list_active_sessions()
        if active:
            logger.info("Active debug session(s): %s", ", ".join(active.keys()))
        else:
            logger.info("Active debug session(s): none")

        self.detect_and_allow(registry)
        self.check_hits_and_remove()
        self.state.touch_run()
        logger.info("Scan complete")

    def run_forever(self) -> None:
        logger.info(
            "WAF monitor started (interval=%ss, block_threshold=%s, hits_to_remove=%s, "
            "window=%sm, registry_only=%s, log_source=%s)",
            self.config.monitor_interval,
            self.config.block_threshold,
            self.config.hits_to_remove,
            self.config.block_window_minutes,
            self.config.registry_only,
            self.config.log_source,
        )
        if self.config.log_source == "cloudwatch":
            logger.info("WAF logs: CloudWatch log group %s", self.config.cloudwatch_log_group)
        else:
            logger.info(
                "WAF logs: s3://%s/%s",
                self.config.waf_log_bucket,
                self.config.waf_log_prefix,
            )
        while True:
            try:
                self.run_once()
            except Exception:
                logger.exception("Monitor iteration failed")
            time.sleep(self.config.monitor_interval)


def main() -> None:
    config = Config()
    if not config.debug_ip_set_id:
        logger.warning("DEBUG_IP_SET_ID is empty — set it in .env before production use")
    else:
        normalized = normalize_ip_set_id(config.debug_ip_set_id)
        if normalized != config.debug_ip_set_id.strip():
            logger.warning(
                "DEBUG_IP_SET_ID looked like an ARN; using UUID %s (set UUID directly in .env)",
                normalized,
            )
    WafMonitor(config).run_forever()


if __name__ == "__main__":
    main()
