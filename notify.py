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
        f":warning: *WAF debug — IP added to temp allow*\n"
        f"IP added: `{ip}`\n"
        f"API: `{uri}`\n"
        f"Blocks (window): `{block_count}`\n"
        f"Rule: `{rule}`\n"
        f"Registry client: `{client}`\n"
        f"_Waiting for 1 allow → ELK lookup for username._"
    )


def format_debug_done(ip: str, client: str, reason: str, elk_hits: list[dict]) -> str:
    username = client
    if elk_hits and elk_hits[0].get("username"):
        username = elk_hits[0]["username"]

    lines = [
        f":white_check_mark: *WAF debug complete — client identified*\n"
        f"*Client:* `{username}`\n"
        f"IP: `{ip}`\n"
        f"Reason: `{reason}`",
    ]
    if elk_hits:
        hit = elk_hits[0]
        lines.append(
            f"Token API: status=`{hit.get('status')}` time=`{hit.get('time')}` "
            f"ua=`{hit.get('user_agent')}`"
        )
        if len(elk_hits) > 1:
            lines.append(f"_({len(elk_hits)} ELK hit(s) in window)_")
    else:
        lines.append("_No ELK username found — check cv2* index._")
    lines.append("_Passwords are never included._")
    return "\n".join(lines)


def format_block_report(rows: list[dict], hours: int) -> str:
    lines = [
        f":bar_chart: *WAF blocks last {hours}h* (`/api*` URIs)\n"
        f"_{len(rows)} blocked IP(s)_",
    ]
    if not rows:
        lines.append("_No /api blocks in this window._")
        return "\n".join(lines)

    for row in rows[:40]:
        username = row.get("username") or row.get("registry_client") or "unknown"
        lines.append(
            f"• `{row['ip']}` | client=`{username}` | blocks=`{row['blocks']}` | "
            f"apis: {row['uris']} | rule=`{row['rule']}`"
        )
    if len(rows) > 40:
        lines.append(f"_…and {len(rows) - 40} more IP(s)_")
    return "\n".join(lines)
