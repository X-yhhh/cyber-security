"""P4 Java/P5 Python 的真实签名及规范化兼容验证入口，仅消费独立测试目录。"""
import base64
from pathlib import Path
import sys
import time

from cryptography.hazmat.primitives import serialization

from .common import canonical, digest, parse
from .contract import capability_set_sha256, protected_ports_sha256, scope_hash, unprotected_ranges, verify


def main(root):
    envelope = parse((root / "command.json").read_bytes())
    payload = verify(envelope, parse((root / "trust.json").read_bytes()), time.time())
    key = serialization.load_der_private_key((root / "key.der").read_bytes(), password=None)
    signature = base64.urlsafe_b64encode(key.sign(canonical(payload))).rstrip(b"=").decode()
    result = {"signature": signature, "scopeHash": scope_hash(payload),
              "vectorHash": digest(parse((root / "vector.json").read_bytes()))}
    if (root / "binding.json").exists():
        # B1.6：同一保护端口与能力登记，由 Python 独立给出区间和摘要供 Java 比对。
        binding = parse((root / "binding.json").read_bytes())
        result.update(ranges=unprotected_ranges(binding["protectedServicePorts"]),
                      protectedPortsSha256=protected_ports_sha256(binding["protectedServicePorts"]),
                      capabilitySetSha256=capability_set_sha256(binding["config"]))
    print(canonical(result).decode())


if __name__ == "__main__":
    main(Path(sys.argv[1]))
