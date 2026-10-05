"""复用 rc.2 JSON Schema 和 RFC8785；本机配置只能收窄已签发命令。"""
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
BINDING_FIELDS = "assetId sensorId bootId captureScopeId environment executorBootId peerKey keyEpoch direction transport addressFamily servicePort".split()
TERMINAL = {"rejected", "revoked", "expired"}


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


def authorize(payload, config, boot, now):
    for field in ("assetId", "executorId", "environment", "sensorId", "captureScopeId"):
        require(payload[field] == config[field], "SCOPE_DENIED")
    require(payload["executorBootId"] == boot, "BOOT_ID_MISMATCH")
    require(payload["direction"] == "inbound", "CAPABILITY_NOT_SUPPORTED")
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
        require(0 < int(peer_port) <= 65535 and int(local_port) == payload["servicePort"], "SCOPE_DENIED")
    except (ValueError, KeyError) as exc:
        raise Rejected("TARGET_REFERENCE_REJECTED") from exc
    require(a != b and not b.is_multicast and not b.is_unspecified and not b.is_reserved,
            "TARGET_REFERENCE_REJECTED")
    require(str(a) in config["localAddresses"] and str(b) in config["peerAddresses"], "SCOPE_DENIED")
    require(not any(b in ipaddress.ip_network(value) for value in config["protectedPeers"]),
            "PROTECTED_TARGET")
    interface = config["interface"]
    require(isinstance(interface, str) and 0 < len(interface) <= 256, "INVALID_INTERFACE")
    return {"local": str(a), "peer": str(b), "port": payload["servicePort"], "interface": interface}
