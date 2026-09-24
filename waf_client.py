import ipaddress
import json
import logging

import boto3
from botocore.exceptions import ClientError

from config import Config

logger = logging.getLogger(__name__)


def normalize_ip_set_id(value: str) -> str:
    """Accept UUID or full ARN; WAF API requires UUID only."""
    value = value.strip()
    if value.startswith("arn:"):
        return value.rsplit("/", 1)[-1]
    return value


class WafClient:
    def __init__(self, config: Config, error_notifier=None):
        self.config = config
        self.error_notifier = error_notifier
        self.client = boto3.client("wafv2", region_name=config.aws_region)
        self._s3 = None
        self.debug_ip_set_id = normalize_ip_set_id(config.debug_ip_set_id)

    @property
    def s3(self):
        if self._s3 is None:
            self._s3 = boto3.client("s3", region_name=config.aws_region)
        return self._s3

    def _registry_bucket(self) -> str | None:
        if self.config.registry_s3_bucket:
            return self.config.registry_s3_bucket
        # Legacy: registry lived next to WAF log files in S3.
        if self.config.log_source == "s3":
            return self.config.waf_log_bucket or None
        return None

    def load_registry(self) -> dict[str, str]:
        bucket = self._registry_bucket()
        if not bucket:
            return {}
        key = self.config.registry_s3_key
        try:
            obj = self.s3.get_object(Bucket=bucket, Key=key)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in {"NoSuchKey", "NoSuchBucket", "404", "AccessDenied", "403"}:
                detail = f"Registry: `s3://{bucket}/{key}` (set `REGISTRY_S3_BUCKET` / `WAF_LOG_BUCKET`)"
                logger.warning("%s — %s", detail, exc)
                if self.error_notifier:
                    self.error_notifier.notify(
                        "registry_s3",
                        "Client registry S3 read failed",
                        detail,
                        exc,
                    )
                return {}
            raise
        raw = json.loads(obj["Body"].read())
        registry: dict[str, str] = {}
        for cidr, client in raw.items():
            ip = cidr.split("/")[0]
            registry[ip] = client
        return registry

    def add_ip_to_debug_set(self, ip: str) -> None:
        cidr = f"{ip}/32"
        resp = self.client.get_ip_set(
            Name=self.config.debug_ip_set_name,
            Scope=self.config.waf_scope,
            Id=self.debug_ip_set_id,
        )
        addresses = list(resp["IPSet"]["Addresses"])
        if cidr in addresses:
            return
        addresses.append(cidr)
        self.client.update_ip_set(
            Name=self.config.debug_ip_set_name,
            Scope=self.config.waf_scope,
            Id=self.debug_ip_set_id,
            Addresses=addresses,
            LockToken=resp["LockToken"],
        )
        logger.info("Added %s to debug IP set", cidr)

    def remove_ip_from_debug_set(self, ip: str) -> None:
        cidr = f"{ip}/32"
        resp = self.client.get_ip_set(
            Name=self.config.debug_ip_set_name,
            Scope=self.config.waf_scope,
            Id=self.debug_ip_set_id,
        )
        addresses = list(resp["IPSet"]["Addresses"])
        if cidr not in addresses:
            return
        addresses.remove(cidr)
        self.client.update_ip_set(
            Name=self.config.debug_ip_set_name,
            Scope=self.config.waf_scope,
            Id=self.debug_ip_set_id,
            Addresses=addresses,
            LockToken=resp["LockToken"],
        )
        logger.info("Removed %s from debug IP set", cidr)

    @staticmethod
    def ip_in_cidrs(ip: str, cidrs: list[str]) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for cidr in cidrs:
            try:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False
