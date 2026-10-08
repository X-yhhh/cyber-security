"""按独立版本校验命令和回执；本机配置只能收窄已签发命令。"""
import base64
import ipaddress
from pathlib import Path
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator, FormatChecker

from .common import Rejected, canonical, digest, instant, parse, require

SCHEMAS = Path(__file__).resolve().parents[1] / "docs" / "contracts"
SCOPE_FIELDS = "assetId sensorId bootId captureScopeId targetRef peerKey keyEpoch environment scope addressFamily direction transport servicePort".split()
BINDING_FIELDS = "assetId sensorId bootId captureScopeId environment executorBootId peerKey keyEpoch direction transport addressFamily scope servicePort".split()
TERMINAL = {"rejected", "revoked", "expired"}


IMPLICIT_PROTECTED_PORTS = (22, 53, 3389)


def protected_ports(protected):
    """管理、解析和远程桌面端口始终保护；P4 与 P5 用同一升序集合算摘要和封禁区间。"""
    require(all(type(port) is int and 1 <= port <= 65535 for port in protected), "CONFIG_SCOPE_INVALID")
    ports = sorted(set(protected) | set(IMPLICIT_PROTECTED_PORTS))
    require(len(ports) <= 128, "CONFIG_SCOPE_INVALID")
    return ports


def protected_ports_sha256(protected):
    """保护端口清单摘要：含隐式端口的升序 JCS 数组，与控制面 Java 实现逐字节一致。"""
    return digest(protected_ports(protected))


def capability_items_sha256(items):
    """能力集合摘要按 capabilityId 排序后取 JCS 摘要；控制面从 guard_capability 独立重算比对。"""
    return digest(sorted(items, key=lambda item: item["capabilityId"]))


def capability_set_sha256(config):
    """由本机登记推出心跳上报的 capabilityHash；全入站项绑定保护集与保护端口摘要。"""
    inbound = {item["capabilityId"]: item for item in config.get("inboundCapabilities", [])}
    items = []
    for capability in sorted(set(config["capabilityIds"])):
        registered = inbound.get(capability)
        items.append({"capabilityId": capability, "scope": "peer_inbound" if registered else "peer_service",
                      "protectionSetSha256": registered["protectionSetSha256"] if registered else None,
                      "protectedPortsSha256": registered["protectedPortsSha256"] if registered else None})
    return capability_items_sha256(items)


def unprotected_ranges(protected):
    """把保护端口从可封禁的 TCP 端口全集中扣除，供规则和状态清理共用。"""
    ranges, start = [], 1
    for port in protected_ports(protected):
        if start < port:
            ranges.append([start, port - 1])
        start = port + 1
    if start <= 65535:
        ranges.append([start, 65535])
    return ranges


def validate(kind, value):
    validator = Draft202012Validator(parse((SCHEMAS / f"{kind}.schema.json").read_bytes()),
                                     format_checker=FormatChecker())
    require(validator.is_valid(value), "CONTRACT_INVALID")


def scope_hash(payload):
    return digest({key: payload[key] for key in SCOPE_FIELDS})


def verify(envelope, trust, now):
    """先校验结构及受信任公钥有效期，再验签；旧密钥被撤销后不可新执行。"""
    validate("action-command", envelope)
    key = trust.get(envelope["keyId"])
    require(key is not None and key.get("status") == "active", "SIGNING_KEY_UNTRUSTED")
    require(instant(key["notBefore"]) <= now < instant(key["notAfter"]), "SIGNING_KEY_EXPIRED")
    try:
        public = serialization.load_der_public_key(base64.b64decode(key["publicKeyDer"], validate=True))
        require(isinstance(public, Ed25519PublicKey), "SIGNING_KEY_UNTRUSTED")
        signature = base64.b64decode(envelope["signature"] + "==", altchars=b"-_", validate=True)
        public.verify(signature, canonical(envelope["payload"]))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise Rejected("SIGNATURE_INVALID") from exc
    return envelope["payload"]


def inbound_exemption(payload, config):
    """全入站规则覆盖保护端口以外的全部端口，只按本机登记的能力放行。

    条件：命令能力 ID 已在 inboundCapabilities 登记、平台为 PF、环境为 lab，且登记时的保护端口摘要
    与当前配置重算一致。未登记保持正式默认拒绝；没有配置项以外的开关。
    """
    registered = [item for item in config.get("inboundCapabilities", [])
                  if item["capabilityId"] == payload["capabilityId"]]
    require(len(registered) == 1, "PROTECTED_TARGET")
    require(config.get("platform") == "pf" and config["environment"] == "lab", "CAPABILITY_NOT_SUPPORTED")
    require(registered[0]["protectedPortsSha256"] == protected_ports_sha256(config["protectedServicePorts"]),
            "PROTECTION_SET_UNVERIFIED")
    require(payload["servicePort"] is None and payload["addressFamily"] == "ipv4" and
            payload["transport"] == "tcp", "SCOPE_DENIED")


def authorize(payload, config, boot, now):
    for field in ("assetId", "executorId", "environment", "sensorId", "captureScopeId"):
        require(payload[field] == config[field], "SCOPE_DENIED")
    require(payload["executorBootId"] == boot, "BOOT_ID_MISMATCH")
    require(payload["direction"] == "inbound", "CAPABILITY_NOT_SUPPORTED")
    inbound = payload["scope"] == "peer_inbound"
    if inbound:
        inbound_exemption(payload, config)
    require(payload["capabilityId"] in config["capabilityIds"] and
            payload["bundleId"] in config["bundleIds"] and
            payload["policySha256"] in config["policyHashes"], "CAPABILITY_NOT_SUPPORTED")
    grant = config["authorization"]
    require(grant["status"] == "active" and payload["authorizationId"] == grant["id"] and
            payload["authorizationRevision"] == grant["revision"], "AUTHORIZATION_INACTIVE")
    issued, apply, until, lease = [instant(payload[key]) for key in
                                  ("issuedAt", "applyBy", "blockUntil", "leaseExpiresAt")]
    require(instant(grant["validFrom"]) <= issued <= now <= apply < until <= lease <=
            instant(grant["validUntil"]) and apply - issued <= 5 and
            until - issued <= min(60, config["limits"]["maxTtlSeconds"]), "COMMAND_EXPIRED")
    if not inbound:
        require(payload["servicePort"] in config["servicePorts"], "SCOPE_DENIED")
        require(payload["servicePort"] not in set(config["protectedServicePorts"]) | {22, 53, 3389},
                "PROTECTED_TARGET")


def endpoints(payload, resolved, config):
    """目标只由本机 mTLS 解析器获得；远端命令没有可任意指定的地址。"""
    require(set(resolved) == {"Local", "Peer", "Protocol"} and resolved["Protocol"] == 6,
            "TARGET_REFERENCE_REJECTED")
    try:
        local, local_port = resolved["Local"].rsplit(":", 1)
        peer, peer_port = resolved["Peer"].rsplit(":", 1)
        a, b = ipaddress.IPv4Address(local), ipaddress.IPv4Address(peer)
        require(0 < int(peer_port) <= 65535 and 0 < int(local_port) <= 65535, "SCOPE_DENIED")
        require((payload["scope"] == "peer_inbound" and payload["servicePort"] is None and
                 payload["direction"] == "inbound") or
                (payload["scope"] == "peer_service" and int(local_port) == payload["servicePort"]),
                "SCOPE_DENIED")
    except (ValueError, KeyError) as exc:
        raise Rejected("TARGET_REFERENCE_REJECTED") from exc
    require(a != b and not b.is_multicast and not b.is_unspecified and not b.is_reserved,
            "TARGET_REFERENCE_REJECTED")
    require(str(a) in config["localAddresses"] and str(b) in config["peerAddresses"], "SCOPE_DENIED")
    require(not any(b in ipaddress.ip_network(value) for value in config["protectedPeers"]),
            "PROTECTED_TARGET")
    interface = config["interface"]
    require(isinstance(interface, str) and 0 < len(interface) <= 256, "INVALID_INTERFACE")
    scope = {"local": str(a), "peer": str(b), "port": payload["servicePort"], "interface": interface}
    if payload["scope"] == "peer_inbound":
        scope["ranges"] = unprotected_ranges(config["protectedServicePorts"])
    return scope
