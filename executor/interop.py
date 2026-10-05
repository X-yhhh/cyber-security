"""P4 Java/P5 Python 的真实签名及规范化兼容验证入口，仅消费独立测试目录。"""
import base64
from pathlib import Path
import sys
import time

from cryptography.hazmat.primitives import serialization

from .common import canonical, digest, parse
from .contract import scope_hash, verify


def main(root):
    envelope = parse((root / "command.json").read_bytes())
    payload = verify(envelope, parse((root / "trust.json").read_bytes()), time.time())
    key = serialization.load_der_private_key((root / "key.der").read_bytes(), password=None)
    signature = base64.urlsafe_b64encode(key.sign(canonical(payload))).rstrip(b"=").decode()
    print(canonical({"signature": signature, "scopeHash": scope_hash(payload),
                     "vectorHash": digest(parse((root / "vector.json").read_bytes()))}).decode())


if __name__ == "__main__":
    main(Path(sys.argv[1]))
