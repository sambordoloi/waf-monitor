import logging
import time

from notify import format_error, notify_slack

logger = logging.getLogger(__name__)


class ErrorNotifier:
    """Send error alerts to Slack with per-key cooldown to avoid spam."""

    def __init__(self, webhook_url: str, cooldown_seconds: int = 3600):
        self.webhook_url = webhook_url
        self.cooldown_seconds = cooldown_seconds
        self._last_sent: dict[str, float] = {}

    def notify(self, key: str, title: str, detail: str, exc: Exception | None = None) -> None:
        if not self.webhook_url:
            logger.error(
                "Slack error alert not sent (SLACK_WEBHOOK_URL empty) — %s: %s (%s)",
                title,
                detail,
                exc,
            )
            return
        now = time.time()
        last = self._last_sent.get(key, 0.0)
        if now - last < self.cooldown_seconds:
            logger.debug(
                "Slack error alert suppressed (cooldown %ss) key=%s title=%s",
                self.cooldown_seconds,
                key,
                title,
            )
            return
        self._last_sent[key] = now
        try:
            notify_slack(self.webhook_url, format_error(title, detail, exc))
            logger.info("Slack error alert sent: %s (%s)", title, key)
        except Exception:
            logger.exception("Failed to send Slack error alert")
