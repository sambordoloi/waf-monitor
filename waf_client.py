import ipaddress
import json
import logging

import boto3
from botocore.exceptions import ClientError

from config import Config

logger = logging.getLogger(__name__)


class WafClient:
    def __init__(self, config: Config):
        self.config = config
        self.client = boto3.client("wafv2", region_name=config.aws_region)
        self.s3 = boto3.client("s3", region_name=config.aws_region)

    def load_registry(self) -> dict[str, str]:
        try:
            obj = self.s3.get_object(
                Bucket=self.config.waf_log_bucket,
                Key=self.config.registry_s3_key,
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchKey":
                logger.warning(
                    "Registry file not found: s3://%s/%s",
                    self.config.waf_log_bucket,
                    self.config.registry_s3_key,
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
            Id=self.config.debug_ip_set_id,
        )
        addresses = list(resp["IPSet"]["Addresses"])
        if cidr in addresses:
            return
        addresses.append(cidr)
        self.client.update_ip_set(
            Name=self.config.debug_ip_set_name,
            Scope=self.config.waf_scope,
            Id=self.config.debug_ip_set_id,
            Addresses=addresses,
            LockToken=resp["LockToken"],
        )
        logger.info("Added %s to debug IP set", cidr)

    def remove_ip_from_debug_set(self, ip: str) -> None:
        cidr = f"{ip}/32"
        resp = self.client.get_ip_set(
            Name=self.config.debug_ip_set_name,
            Scope=self.config.waf_scope,
            Id=self.config.debug_ip_set_id,
        )
        addresses = list(resp["IPSet"]["Addresses"])
        if cidr not in addresses:
            return
        addresses.remove(cidr)
        self.client.update_ip_set(
            Name=self.config.debug_ip_set_name,
            Scope=self.config.waf_scope,
            Id=self.config.debug_ip_set_id,
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
