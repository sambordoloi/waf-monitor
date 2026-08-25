import logging
from datetime import datetime
from typing import Any

from config import Config
from elk_client import ElkClient
from local_log_client import LocalLogClient

logger = logging.getLogger(__name__)


class TokenLogClient:
    """Find /api/token/ hits by IP — local log file first, then ELK."""

    def __init__(self, config: Config):
        self.local = LocalLogClient(config) if config.app_log_path.strip() else None
        self.elk = ElkClient(config) if config.elk_url else None
        if self.local:
            logger.info("Token lookup: local log path(s) %s", config.app_log_path)
        elif self.elk:
            logger.info("Token lookup: ELK index %s", config.elk_index)
        else:
            logger.warning("Token lookup disabled — set APP_LOG_PATH and/or ELK_URL")

    @property
    def enabled(self) -> bool:
        return bool(self.local or self.elk)

    def find_token_hits(
        self,
        ip: str,
        since: datetime | None = None,
        window_minutes: int | None = None,
    ) -> list[dict[str, Any]]:
        if self.local:
            hits = self.local.find_token_hits(ip, since=since)
            if hits:
                return hits
        if self.elk:
            return self.elk.find_token_hits(ip, since=since, window_minutes=window_minutes)
        return []
