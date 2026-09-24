#!/usr/bin/env python3
import argparse
import logging
import sys
import time
from datetime import datetime, timedelta, timezone

from alerts import ErrorNotifier
from config import Config
from elk_client import ElkClient
from notify import (
    format_block_report,
    format_debug_done,
    format_debug_expired,
    format_debug_started,
    notify_slack,
)
from token_log_client import TokenLogClient
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
        self.alerts = ErrorNotifier(
            config.slack_webhook_url,
            cooldown_seconds=config.error_alert_cooldown_seconds,
        )
        self.state = StateStore(config.state_file)
        self.waf = WafClient(config, error_notifier=self.alerts)
        self.logs = WafLogReader(config, error_notifier=self.alerts)
        self.token_logs = TokenLogClient(config, error_notifier=self.alerts)
        self._last_full_scan = 0.0
        self._last_wait_log: dict[str, float] = {}

    def _add_ip_to_debug_set(self, ip: str) -> bool:
        try:
            self.waf.add_ip_to_debug_set(ip)
            return True
        except Exception as exc:
            self.alerts.notify(
                "waf_add_ip",
                "Failed to add IP to debug set",
                f"IP: `{ip}` set: `{self.config.debug_ip_set_name}`",
                exc,
            )
            return False

    def _remove_ip_from_debug_set(self, ip: str) -> bool:
        try:
            self.waf.remove_ip_from_debug_set(ip)
            return True
        except Exception as exc:
            self.alerts.notify(
                "waf_remove_ip",
                "Failed to remove IP from debug set",
                f"IP: `{ip}` set: `{self.config.debug_ip_set_name}`",
                exc,
            )
            return False

    def maybe_run_daily_report(self) -> None:
        if not self.config.daily_report_enabled:
            return
        now_utc = datetime.now(timezone.utc)
        # 02:30 UTC = 08:00 IST — run once during 02:30–02:59 UTC only.
        if now_utc.hour != self.config.daily_report_hour_utc:
            return
        if now_utc.minute < self.config.daily_report_minute_utc:
            return
        today = now_utc.date().isoformat()
        if self.state.get_last_daily_report_date() == today:
            return
        logger.info(
            "Running daily block report (%sh, /api*) at %s UTC",
            self.config.daily_report_hours,
            now_utc.strftime("%H:%M"),
        )
        run_block_report(
            self.config,
            hours=self.config.daily_report_hours,
            send_slack=bool(self.config.slack_webhook_url),
        )
        self.state.set_last_daily_report_date(today)

    def detect_and_allow(self, registry: dict[str, str], blocked: dict) -> None:
        for ip, info in blocked.items():
            if info["count"] < self.config.block_threshold:
                continue
            if self.state.was_debugged(ip):
                continue
            existing = self.state.get_session(ip)
            if existing and existing.get("status") == "active":
                continue
            if not self.config.debug_ip_set_id:
                logger.error("DEBUG_IP_SET_ID is not configured")
                return

            if not self._add_ip_to_debug_set(ip):
                continue
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

    def _close_debug_session(
        self,
        ip: str,
        session: dict,
        reason: str,
        elk_hits: list | None = None,
    ) -> None:
        elk_hits = elk_hits or []
        client = session.get("client", "unknown")
        if elk_hits and elk_hits[0].get("username"):
            client = elk_hits[0]["username"]
        self.state.mark_done(ip, reason=reason)
        msg = format_debug_done(
            ip=ip,
            client=client,
            reason=reason,
            elk_hits=elk_hits,
        )
        notify_slack(self.config.slack_webhook_url, msg)
        logger.info("Debug session closed for %s", ip)
        self._last_wait_log.pop(ip, None)

    def check_hits_and_remove(self, *, verbose: bool = False) -> bool:
        """Return True if any active session was closed."""
        closed = False
        for ip, session in self.state.list_active_sessions().items():
            started_at = datetime.fromisoformat(session["started_at"])
            if started_at.tzinfo is None:
                started_at = started_at.replace(tzinfo=timezone.utc)

            age = datetime.now(timezone.utc) - started_at

            # Match any valid API URI for this IP — WAF may log /api/token vs /api/token/.
            if self.logs.has_allow_since(ip, started_at, uri_filter=None):
                if not self._remove_ip_from_debug_set(ip):
                    continue
                logger.info("Removed %s from debug set after WAF ALLOW", ip)
                elk_hits = self.token_logs.find_token_hits(ip, since=started_at) if self.token_logs.enabled else []
                self._close_debug_session(
                    ip,
                    session,
                    reason="WAF ALLOW, then ELK check",
                    elk_hits=elk_hits,
                )
                closed = True
                continue

            if self.token_logs.enabled:
                elk_hits = self.token_logs.find_token_hits(ip, since=started_at)
                if elk_hits:
                    if not self._remove_ip_from_debug_set(ip):
                        continue
                    logger.info(
                        "Removed %s from debug set after ELK /api/token/ hit (no WAF ALLOW yet)",
                        ip,
                    )
                    self._close_debug_session(
                        ip,
                        session,
                        reason="ELK /api/token/ hit (request reached app)",
                        elk_hits=elk_hits,
                    )
                    closed = True
                    continue

            if verbose or self._should_log_wait(ip):
                counts = self.logs.session_event_counts(ip, started_at, uri_filter=None)
                logger.info(
                    "Waiting on %s: age=%ss allows=%s blocks_since_start=%s",
                    ip,
                    int(age.total_seconds()),
                    counts["allows"],
                    counts["blocks"],
                )

            if age >= timedelta(minutes=self.config.debug_expire_minutes):
                counts = self.logs.session_event_counts(ip, started_at, uri_filter=None)
                elk_hits: list = []
                if self.token_logs.enabled:
                    elk_hits = self.token_logs.find_token_hits(
                        ip,
                        since=started_at,
                        window_minutes=self.config.elk_window_minutes,
                    )
                self._remove_ip_from_debug_set(ip)
                if elk_hits and elk_hits[0].get("username"):
                    self._close_debug_session(
                        ip,
                        session,
                        reason="ELK hit on expire (late ingest, no WAF ALLOW seen)",
                        elk_hits=elk_hits,
                    )
                else:
                    self.state.mark_done(ip, reason="expired_no_hits")
                    notify_slack(
                        self.config.slack_webhook_url,
                        format_debug_expired(
                            ip,
                            expire_minutes=self.config.debug_expire_minutes,
                            allows=counts["allows"],
                            blocks=counts["blocks"],
                            log_source=self.config.log_source,
                            elk_hits=elk_hits,
                        ),
                    )
                    logger.info(
                        "Debug session expired for %s (allows=%s blocks=%s log_source=%s)",
                        ip,
                        counts["allows"],
                        counts["blocks"],
                        self.config.log_source,
                    )
                self._last_wait_log.pop(ip, None)
                closed = True
        return closed

    def _should_log_wait(self, ip: str) -> bool:
        now = time.time()
        last = self._last_wait_log.get(ip, 0.0)
        if now - last >= 30:
            self._last_wait_log[ip] = now
            return True
        return False

    def run_full_scan(self) -> None:
        registry = self.waf.load_registry()
        if registry:
            logger.info("Registry loaded: %s client IP(s)", len(registry))
        elif self.config.registry_s3_bucket or self.config.log_source == "s3":
            logger.info("Registry empty or unreadable")
        else:
            logger.info("Registry skipped (CloudWatch — set REGISTRY_S3_BUCKET to load client names)")

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

        self.detect_and_allow(registry, blocked)
        self.state.touch_run()
        logger.info("Full scan complete (log_source=%s)", self.config.log_source)
        self._last_full_scan = time.time()

    def run_forever(self) -> None:
        if not self.config.slack_webhook_url:
            logger.warning(
                "SLACK_WEBHOOK_URL is not set — debug notifications and error alerts are disabled"
            )
        else:
            logger.info("Slack error alerts enabled (cooldown=%ss)", self.config.error_alert_cooldown_seconds)
        logger.info(
            "WAF monitor started (interval=%ss, active_poll=%ss, block_threshold=%s, "
            "window=%sm, registry_only=%s, log_source=%s)",
            self.config.monitor_interval,
            self.config.active_poll_interval,
            self.config.block_threshold,
            self.config.block_window_minutes,
            self.config.registry_only,
            self.config.log_source,
        )
        if self.config.daily_report_enabled:
            logger.info(
                "Daily report: %sh /api* blocks at %02d:%02d UTC (08:00 IST) → Slack",
                self.config.daily_report_hours,
                self.config.daily_report_hour_utc,
                self.config.daily_report_minute_utc,
            )
        if self.config.log_source == "cloudwatch":
            logger.info("WAF logs: CloudWatch log group %s", self.config.cloudwatch_log_group)
        else:
            logger.warning(
                "LOG_SOURCE=s3 — ALLOW detection is slow (minutes). "
                "Set LOG_SOURCE=cloudwatch and CLOUDWATCH_LOG_GROUP in .env"
            )
            logger.info(
                "WAF logs: s3://%s/%s",
                self.config.waf_log_bucket,
                self.config.waf_log_prefix,
            )
        while True:
            try:
                self.maybe_run_daily_report()
                active = self.state.list_active_sessions()
                if active:
                    self.check_hits_and_remove()
                    if time.time() - self._last_full_scan >= self.config.monitor_interval:
                        self.run_full_scan()
                        self.check_hits_and_remove()
                    time.sleep(self.config.active_poll_interval)
                else:
                    self.run_full_scan()
                    self.check_hits_and_remove()
                    time.sleep(self.config.monitor_interval)
            except Exception as exc:
                logger.exception("Monitor iteration failed")
                self.alerts.notify(
                    "monitor_loop",
                    "Monitor iteration failed",
                    "Unexpected error in main loop (monitor will retry)",
                    exc,
                )
                time.sleep(self.config.active_poll_interval)


def run_block_report(config: Config, hours: int, send_slack: bool) -> None:
    alerts = ErrorNotifier(config.slack_webhook_url, cooldown_seconds=config.error_alert_cooldown_seconds)
    waf = WafClient(config, error_notifier=alerts)
    logs = WafLogReader(config, error_notifier=alerts)
    registry = waf.load_registry()
    rows = logs.blocked_api_report(registry, hours=hours)

    elk = ElkClient(config, error_notifier=alerts) if config.elk_url else None
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    if elk:
        for row in rows:
            username = elk.find_username_for_ip(row["ip"], since=since, hours=hours)
            if username:
                row["username"] = username

    text = format_block_report(rows, hours)
    print(text)
    if send_slack:
        notify_slack(config.slack_webhook_url, text)
    logger.info("Block report done (%s IP(s), last %sh)", len(rows), hours)


def remove_ip_for_debug(config: Config, ip: str) -> None:
    waf = WafClient(config)
    state = StateStore(config.state_file)
    waf.remove_ip_from_debug_set(ip)
    cleared = state.clear_session(ip)
    if cleared:
        logger.info("Cleared debug session state for %s", ip)
    else:
        logger.info("No debug session state for %s", ip)
    logger.info("Done — %s removed from debug IP set and can be debugged again", ip)


def main() -> None:
    parser = argparse.ArgumentParser(description="WAF debug monitor")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("run", help="Run continuous monitor loop (default)")

    remove_parser = subparsers.add_parser(
        "remove-ip",
        help="Remove IP from debug WAF set and clear session state",
    )
    remove_parser.add_argument("ip", help="Client IP to remove, e.g. 49.37.111.213")

    report_parser = subparsers.add_parser(
        "report-24h",
        help="Report blocked /api* IPs in last 24h with ELK usernames",
    )
    report_parser.add_argument("--hours", type=int, default=24, help="Lookback hours (default 24)")
    report_parser.add_argument("--slack", action="store_true", help="Post report to Slack")

    args = parser.parse_args()
    command = args.command or "run"

    config = Config()
    if not config.debug_ip_set_id:
        logger.error("DEBUG_IP_SET_ID is empty — set it in .env")
        sys.exit(1)

    if command == "remove-ip":
        remove_ip_for_debug(config, args.ip.strip())
        return

    if command == "report-24h":
        if config.log_source == "cloudwatch" and not config.cloudwatch_log_group.strip():
            logger.error("CLOUDWATCH_LOG_GROUP is required when LOG_SOURCE=cloudwatch")
            sys.exit(1)
        run_block_report(config, hours=args.hours, send_slack=args.slack)
        return

    if config.log_source == "cloudwatch" and not config.cloudwatch_log_group.strip():
        logger.error("CLOUDWATCH_LOG_GROUP is required when LOG_SOURCE=cloudwatch — set it in .env")
        sys.exit(1)
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
