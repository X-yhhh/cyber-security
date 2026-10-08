"""安装时登记本机范围；密钥、端点和运行态位于仓库之外，不参与 Git 交付。"""
import ipaddress
from pathlib import Path
import uuid

from .common import instant, read_private, require
from .contract import capability_set_sha256

REQUIRED = set("platform stateDir assetId executorId sensorId captureScopeId environment interface localAddresses peerAddresses servicePorts protectedPeers protectedServicePorts capabilityIds bundleIds policyHashes authorization limits trustFile budgetKeyFile controlPlaneURL credentialFile targetURL targetCA targetCertificate targetKey capabilityHash".split())
OPTIONAL = {"controlPlaneCA", "pfHelper", "inboundCapabilities"}


def load(path):
    c = read_private(path)
    require(isinstance(c, dict) and REQUIRED <= c.keys() and c.keys() <= REQUIRED | OPTIONAL, "CONFIG_FIELDS_INVALID")
    require(c["platform"] in ("pf", "wfp") and c["environment"] in ("lab", "authorized"), "CONFIG_SCOPE_INVALID")
    for key in ("assetId", "executorId", "sensorId", "captureScopeId"):
        require(str(uuid.UUID(c[key])) == c[key], "CONFIG_ID_INVALID")
    require(isinstance(c["interface"], str) and 0 < len(c["interface"]) <= 256, "CONFIG_SCOPE_INVALID")
    for key in ("localAddresses", "peerAddresses"):
        require(isinstance(c[key], list) and 0 < len(c[key]) <= 100, "CONFIG_SCOPE_INVALID")
        for value in c[key]:
            require(str(ipaddress.IPv4Address(value)) == value, "CONFIG_SCOPE_INVALID")
    for value in c["protectedPeers"]:
        ipaddress.ip_network(value)
    for key in ("servicePorts", "protectedServicePorts"):
        require(isinstance(c[key], list) and all(type(p) is int and 0 < p <= 65535 for p in c[key]), "CONFIG_SCOPE_INVALID")
    require(c["servicePorts"], "CONFIG_SCOPE_INVALID")
    for key in ("capabilityIds", "bundleIds"):
        require(isinstance(c[key], list) and c[key], "CONFIG_SCOPE_INVALID")
        for value in c[key]:
            require(str(uuid.UUID(value)) == value, "CONFIG_ID_INVALID")
    import re
    require(isinstance(c["policyHashes"], list) and c["policyHashes"] and
            all(re.fullmatch("[0-9a-f]{64}", value) for value in c["policyHashes"] + [c["capabilityHash"]]),
            "CONFIG_HASH_INVALID")
    # 全入站登记只在 PF lab 有效；每项绑定控制面保护集摘要和本机保护端口摘要，后者在授权时按现配置重算。
    inbound = c.get("inboundCapabilities", [])
    require(isinstance(inbound, list) and all(
        isinstance(item, dict) and set(item) == {"capabilityId", "protectionSetSha256", "protectedPortsSha256"} and
        item["capabilityId"] in c["capabilityIds"] and
        all(isinstance(item[k], str) and re.fullmatch("[0-9a-f]{64}", item[k])
            for k in ("protectionSetSha256", "protectedPortsSha256")) for item in inbound) and
        len({item["capabilityId"] for item in inbound}) == len(inbound), "CONFIG_CAPABILITY_INVALID")
    require(not inbound or (c["platform"] == "pf" and c["environment"] == "lab"), "CONFIG_SCOPE_INVALID")
    # capabilityHash 不是自由填写的值：必须等于本机登记推出的能力集合摘要，控制面领取时再独立比对。
    require(c["capabilityHash"] == capability_set_sha256(c), "CONFIG_HASH_INVALID")
    grant = c["authorization"]
    require(set(grant) == {"id", "revision", "status", "validFrom", "validUntil"} and
            type(grant["revision"]) is int and grant["revision"] > 0 and
            str(uuid.UUID(grant["id"])) == grant["id"] and grant["status"] in ("active", "revoked") and
            instant(grant["validFrom"]) < instant(grant["validUntil"]), "CONFIG_AUTHORIZATION_INVALID")
    bounds = {"maxTtlSeconds": 60, "maxContinuousBlockSeconds": 120,
              "maxActiveRulesPerAsset": 10, "maxNewActionsPerMinute": 5}
    require(set(c["limits"]) == set(bounds) and all(type(c["limits"][k]) is int and
            0 < c["limits"][k] <= v for k, v in bounds.items()), "CONFIG_LIMITS_INVALID")
    for key in ("stateDir", "trustFile", "budgetKeyFile", "credentialFile", "targetCA", "targetCertificate", "targetKey"):
        require(Path(c[key]).is_absolute(), "CONFIG_PATH_INVALID")
    return c


class RuntimeConfig:
    """配置解析失败时新命令拒绝；恢复器保留最后身份和平台信息以继续清理。"""
    def __init__(self, path):
        self.path = path
        self.last = load(path)

    def __call__(self):
        current = load(self.path)
        for key in ("platform", "stateDir", "assetId", "executorId", "environment", "interface",
                    "budgetKeyFile", "controlPlaneURL", "controlPlaneCA", "targetURL", "targetCA",
                    "targetCertificate", "targetKey", "pfHelper"):
            require(current.get(key) == self.last.get(key), "CONFIG_RESTART_REQUIRED")
        self.last = current
        return current
