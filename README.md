# WAF Debug Monitor (Docker)

Continuously monitors WAF S3 logs for **blocked valid client APIs**, temporarily allowlists the IP, removes it after **1 ELK/WAF hit**, and posts debug info to Slack.

## Flow

```text
Every 60s loop:
  1. Scan WAF S3 logs (last 30m)
  2. BLOCK on /api/token/ (registry IP) or /dem_* ?
  3. If blocked >= 10 times → add IP to debug-temp-allow
  4. If debug IP has >= 1 ELK hit → remove IP + Slack report
  5. If no hit in 5 min → remove IP (fail-safe)
```

## Prerequisites

1. WAF logging to S3 (already configured)
2. WAF IP set `debug-temp-allow` + high-priority ALLOW rule
3. Client registry at `s3://aws-waf-logs-cv3/config/waf-ip-clients.json`
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
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::aws-waf-logs-cv3",
        "arn:aws:s3:::aws-waf-logs-cv3/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": ["wafv2:GetIPSet", "wafv2:UpdateIPSet"],
      "Resource": "arn:aws:wafv2:ap-south-1:231322554539:regional/ipset/debug-temp-allow/*"
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
- Only `/api/token/` (registry IPs) and `/dem_*` URIs are monitored.
- State is persisted in Docker volume `/data/state.json`.
