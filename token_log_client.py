import logging
from datetime import datetime
from typing import Any

from config import Config
from elk_client import ElkClient
from local_log_client import LocalLogClient

logger = logging.getLogger(__name__)


class TokenLogClient:
    """Find /api/token/ hits by IP — ELK default, optional local log file."""

    def __init__(self, config: Config):
        self.mode = config.token_lookup
        self.local = LocalLogClient(config) if config.app_log_path.strip() else None
        self.elk = ElkClient(config) if config.elk_url else None

        if self.mode == "elk" and self.elk:
            logger.info("Token lookup: ELK index %s", config.elk_index)
        elif self.mode == "local" and self.local:
            logger.info("Token lookup: local log %s", config.app_log_path)
        elif self.mode == "both":
            logger.info("Token lookup: ELK %s, local %s", config.elk_index, config.app_log_path or "(none)")
        else:
            logger.warning("Token lookup disabled — set ELK_URL and/or APP_LOG_PATH")

    @property
    def enabled(self) -> bool:
        return bool(
            (self.mode in ("elk", "both") and self.elk)
            or (self.mode in ("local", "both") and self.local)
        )

    def find_token_hits(
        self,
        ip: str,
        since: datetime | None = None,
        window_minutes: int | None = None,
    ) -> list[dict[str, Any]]:
        if self.mode in ("elk", "both") and self.elk:
            hits = self.elk.find_token_hits(ip, since=since, window_minutes=window_minutes)
            if hits:
                return hits
        if self.mode in ("local", "both") and self.local:
            return self.local.find_token_hits(ip, since=since)
        return []
