import os


def env_int(name: str, default: int) -> int:
    return int(os.getenv(name, str(default)))


def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name, str(default)).lower()
    return value in {"1", "true", "yes", "on"}


class Config:
    monitor_interval = env_int("MONITOR_INTERVAL", 60)

    aws_region = os.getenv("AWS_REGION", "ap-south-1")
    waf_scope = os.getenv("WAF_SCOPE", "REGIONAL")

    waf_log_bucket = os.getenv("WAF_LOG_BUCKET", "aws-waf-logs-cv3")
    waf_log_prefix = os.getenv(
        "WAF_LOG_PREFIX",
        "AWSLogs/231322554539/WAFLogs/ap-south-1/WAF-CV3/",
    )
    registry_s3_key = os.getenv("REGISTRY_S3_KEY", "config/waf-ip-clients.json")
    # If true, only /api/token/ blocks from registry IPs are monitored (legacy).
    registry_only = env_bool("REGISTRY_ONLY", False)

    debug_ip_set_name = os.getenv("DEBUG_IP_SET_NAME", "debug-temp-allow")
    debug_ip_set_id = os.getenv("DEBUG_IP_SET_ID", "")

    block_threshold = env_int("BLOCK_THRESHOLD", 10)
    block_window_minutes = env_int("BLOCK_WINDOW_MINUTES", 30)
    debug_expire_minutes = env_int("DEBUG_EXPIRE_MINUTES", 5)
    hits_to_remove = env_int("HITS_TO_REMOVE", 1)

    elk_url = os.getenv("ELK_URL", "")
    elk_index = os.getenv("ELK_INDEX", "nginx-*")
    elk_user = os.getenv("ELK_USER", "")
    elk_password = os.getenv("ELK_PASSWORD", "")
    elk_verify_ssl = env_bool("ELK_VERIFY_SSL", True)

    slack_webhook_url = os.getenv("SLACK_WEBHOOK_URL", "")
    state_file = os.getenv("STATE_FILE", "/data/state.json")
