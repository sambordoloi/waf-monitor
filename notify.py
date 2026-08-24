import json
import logging

import requests

logger = logging.getLogger(__name__)


def notify_slack(webhook_url: str, text: str) -> None:
    if not webhook_url:
        logger.info("Slack disabled: %s", text)
        return
    response = requests.post(
        webhook_url,
        json={"text": text},
        timeout=15,
    )
    response.raise_for_status()


def format_debug_started(ip: str, client: str, uri: str, block_count: int, rule: str) -> str:
    return (
        f":warning: *WAF debug started*\n"
        f"Client: `{client}`\n"
        f"IP: `{ip}`\n"
        f"API: `{uri}`\n"
        f"Blocks (window): `{block_count}`\n"
        f"Rule: `{rule}`\n"
        f"Action: temp allow (1 hit then remove)"
    )


def format_debug_done(ip: str, client: str, reason: str, elk_hits: list[dict]) -> str:
    lines = [
        f":white_check_mark: *WAF debug closed*\n"
        f"Client: `{client}`\n"
        f"IP: `{ip}`\n"
        f"Reason: `{reason}`\n"
        f"ELK hits: `{len(elk_hits)}`",
    ]
    if elk_hits:
        for hit in elk_hits[:3]:
            lines.append(
                f"• user=`{hit.get('username')}` status=`{hit.get('status')}` "
                f"ua=`{hit.get('user_agent')}` time=`{hit.get('time')}`"
            )
    else:
        lines.append("• _No ELK hits yet — ingest may lag; search manually if needed._")
    lines.append("_Passwords are never included._")
    return "\n".join(lines)
