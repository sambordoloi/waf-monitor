# WAF Debug Monitor (Docker)

Continuously monitors **WAF logs** (CloudWatch by default) for blocked valid client APIs, temporarily allowlists the IP, removes it after **1 WAF ALLOW**, looks up username from **ELK** (`cv2*` nginx backend logs), and posts debug info to Slack.

## Flow

```text
Every 60s loop:
  1. Scan WAF CloudWatch logs (last 30m)
  2. BLOCK on /api/token/ or /dem_* (all IPs by default)
  3. If blocked >= threshold → add IP to debug-temp-allow (once per IP — never re-add)
  4. On first WAF ALLOW → remove IP immediately, then search app log / ELK + Slack
  5. If no WAF ALLOW in 5 min → remove IP (fail-safe)
```

## Prerequisites

1. WAF logging to **CloudWatch** (default) — set `LOG_SOURCE=s3` to use S3 instead (slower ALLOW detection)
2. WAF IP set `debug_temp_allow_ip` + high-priority ALLOW rule
3. Client registry at `s3://aws-waf-logs-cv3/config/waf-ip-clients.json` (optional, for names)
4. ELK with nginx backend logs in `cv2*` (same format as `access_api.log` — `http_x_forwarded_for`, `request_body`)
5. IAM permissions (see below)

## Setup

```bash
cd waf-monitor
cp .env.example .env
# Edit .env: DEBUG_IP_SET_ID, CLOUDWATCH_LOG_GROUP, ELK_URL, ELK_INDEX=cv2*

docker compose up -d --build
docker compose logs -f waf-monitor
```

You should see at startup:

```text
Token lookup: ELK index cv2*
```

### Remove an IP (manual debug reset)

Removes the IP from the WAF debug temp-allow set and clears its session in state so it can be debugged again:

```bash
docker compose exec waf-monitor python monitor.py remove-ip 49.37.111.213
```

### Slack notifications

Set `SLACK_WEBHOOK_URL` in `.env`. The monitor sends:

1. **IP added** — when an IP is added to temp allow (`:warning: WAF debug — IP added`)
2. **Client identified** — after debug completes with ELK username (`:white_check_mark: Client: DEVOPS`)

### 24h block report (`/api*`)

All WAF blocks on URIs starting with `/api`, with ELK username per IP:

```bash
# Print report
docker compose exec waf-monitor python monitor.py report-24h

# Post to Slack
docker compose exec waf-monitor python monitor.py report-24h --slack

# Custom window
docker compose exec waf-monitor python monitor.py report-24h --hours 24 --slack
```

Cron example (optional — built-in scheduler runs at 02:30 UTC if `DAILY_REPORT_ENABLED=true`):

```bash
# Manual run
docker compose exec waf-monitor python monitor.py report-24h --slack
```

Built-in schedule (server UTC): runs at **02:30 UTC** (= 08:00 IST):

```bash
DAILY_REPORT_ENABLED=true
DAILY_REPORT_HOUR_UTC=2
DAILY_REPORT_MINUTE_UTC=30
DAILY_REPORT_HOURS=24
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
```

## Environment variables

| Variable | Description |
|----------|-------------|
| `MONITOR_INTERVAL` | Full block scan interval in seconds (default `60`) |
| `ACTIVE_POLL_INTERVAL` | Allow/ELK check interval during active debug (default `5`) |
| `DEBUG_IP_SET_ID` | WAF debug temp IP set ID |
| `DEBUG_IP_SET_NAME` | WAF debug temp IP set name |
| `BLOCK_THRESHOLD` | Blocks before debug (default `10`) |
| `LOG_SOURCE` | `cloudwatch` (default) or `s3` |
| `CLOUDWATCH_LOG_GROUP` | **Required** when using CloudWatch — your WAF log group name |
| `HITS_TO_REMOVE` | Remove after N hits (default `1`) |
| `TOKEN_LOOKUP` | `elk` (default), `local`, or `both` |
| `ELK_URL` | Elasticsearch URL for username lookup |
| `ELK_INDEX` | Index pattern e.g. `cv2*` |
| `APP_LOG_PATH` | Optional local log (only if `TOKEN_LOOKUP=local` or `both`) |
| `ELK_WINDOW_MINUTES` | ELK search window (default `60` = last 1 hour) |
| `SLACK_WEBHOOK_URL` | Slack webhook — IP added + client name + daily report |
| `DAILY_REPORT_ENABLED` | Auto 24h report at 02:30 UTC / 08:00 IST (default `true`) |
| `DAILY_REPORT_HOUR_UTC` | Hour UTC (default `2`) |
| `DAILY_REPORT_MINUTE_UTC` | Minute UTC (default `30`) |
| `DAILY_REPORT_HOURS` | Report lookback hours (default `24`) |

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
- Registry file is optional — username from ELK `request_body` / `message` field is used when found.
- State is persisted in Docker volume `/data/state.json`.
