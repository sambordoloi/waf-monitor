# WAF Debug Monitor (Docker)

Continuously monitors **CloudWatch WAF logs** (or S3) for blocked valid client APIs, temporarily allowlists the IP, removes it after **1 WAF ALLOW**, queries ELK, and posts debug info to Slack.

## Flow

```text
Every 60s loop:
  1. Scan CloudWatch log group aws-waf-logs-cv1 (last 30m) — ~1–2 min latency
  2. BLOCK on /api/token/ or /dem_* (all IPs by default)
  3. If blocked >= threshold → add IP to debug-temp-allow
  4. If debug IP has >= 1 WAF ALLOW → remove IP immediately, then query ELK + Slack
  5. If no WAF ALLOW in 5 min → remove IP (fail-safe)
```

## Prerequisites

1. WAF logging to **CloudWatch Logs** (`aws-waf-logs-cv1`) — or set `LOG_SOURCE=s3`
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
| `HITS_TO_REMOVE` | Remove after N hits (default `1`) |
| `ELK_URL` | Elasticsearch URL |
| `ELK_INDEX` | Index pattern e.g. `nginx-*` |
| `SLACK_WEBHOOK_URL` | Optional Slack webhook |

## IAM permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["logs:FilterLogEvents", "logs:DescribeLogGroups"],
      "Resource": "arn:aws:logs:ap-south-1:231322554539:log-group:aws-waf-logs-cv1:*"
    },
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": "arn:aws:s3:::aws-waf-logs-cv3/config/*"
    },
    {
      "Effect": "Allow",
      "Action": ["wafv2:GetIPSet", "wafv2:UpdateIPSet"],
      "Resource": "arn:aws:wafv2:ap-south-1:231322554539:regional/ipset/debug_temp_allow_ip/*"
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
- Registry file is optional — used for client names in Slack when known.
- State is persisted in Docker volume `/data/state.json`.
