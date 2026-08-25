# WAF Debug Monitor (Docker)

Continuously monitors **WAF logs** (CloudWatch by default) for blocked valid client APIs, temporarily allowlists the IP, removes it after **1 WAF ALLOW**, queries ELK for username from `/api/token/`, and posts debug info to Slack.

## Flow

```text
Every 60s loop:
  1. Scan WAF CloudWatch logs (last 30m)
  2. BLOCK on /api/token/ or /dem_* (all IPs by default)
  3. If blocked >= threshold → add IP to debug-temp-allow (once per IP — never re-add)
  4. On first WAF ALLOW → remove IP immediately, then query ELK + Slack
  5. If no WAF ALLOW in 5 min → remove IP (fail-safe)
```

## Prerequisites

1. WAF logging to **CloudWatch** (default) — set `LOG_SOURCE=s3` to use S3 instead (slower ALLOW detection)
2. WAF IP set `debug_temp_allow_ip` + high-priority ALLOW rule
3. Client registry at `s3://aws-waf-logs-cv3/config/waf-ip-clients.json` (optional, for names)
4. ELK with nginx logs (`http_x_forwarded_for`, `request_body`, `request`)
5. IAM permissions (see below)

## Setup

```bash
cd waf-monitor
cp .env.example .env
# Edit .env with DEBUG_IP_SET_ID, ELK_URL, SLACK_WEBHOOK_URL, etc.

docker compose up -d --build
docker compose logs -f waf-monitor
```

## Environment variables

| Variable | Description |
|----------|-------------|
| `MONITOR_INTERVAL` | Loop seconds (default `60`) |
| `DEBUG_IP_SET_ID` | WAF debug temp IP set ID |
| `DEBUG_IP_SET_NAME` | WAF debug temp IP set name |
| `BLOCK_THRESHOLD` | Blocks before debug (default `10`) |
| `LOG_SOURCE` | `cloudwatch` (default) or `s3` |
| `CLOUDWATCH_LOG_GROUP` | **Required** when using CloudWatch — your WAF log group name |
| `HITS_TO_REMOVE` | Remove after N hits (default `1`) |
| `ELK_URL` | Elasticsearch URL |
| `ELK_INDEX` | Index pattern e.g. `cv2*` |
| `ELK_WINDOW_MINUTES` | ELK search window (default `60` = last 1 hour) |
| `SLACK_WEBHOOK_URL` | Optional Slack webhook |

## IAM permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::aws-waf-logs-cv3",
        "arn:aws:s3:::aws-waf-logs-cv3/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": ["wafv2:GetIPSet", "wafv2:UpdateIPSet"],
      "Resource": "arn:aws:wafv2:ap-south-1:231322554539:regional/ipset/debug_temp_allow_ip/*"
    },
    {
      "Effect": "Allow",
      "Action": ["logs:FilterLogEvents"],
      "Resource": "arn:aws:logs:ap-south-1:231322554539:log-group:aws-waf-logs-cv3:*"
    }
  ]
}
```

## Registry file example

`s3://aws-waf-logs-cv3/config/waf-ip-clients.json`

```json
{
  "52.74.226.127/32": "SALMON",
  "54.170.138.104/32": "DIALOG"
}
```

## Notes

- Passwords from ELK `request_body` are **never** sent to Slack.
- Monitors **all blocked IPs** on `/api/token/` and `/dem_*` URIs (set `REGISTRY_ONLY=true` for legacy registry-only token filtering).
- Each IP is debugged **at most once** — completed sessions are never re-added.
- Registry file is optional — ELK `request_body.username` is used when found.
- State is persisted in Docker volume `/data/state.json`.
