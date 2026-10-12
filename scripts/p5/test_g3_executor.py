"""g3_executor 的配置组装与 subject 绑定核验；不需要 root、不启动进程。"""
import base64
import json
from pathlib import Path
import sys
import tempfile
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from executor.common import Rejected, digest
from executor.config import load as load_config
from executor.contract import capability_set_sha256, protected_ports_sha256
from executor.common import canonical
from scripts.p5 import g3_executor

PROTECTION = {"protectedBudgetTargetIds": [], "protectedServicePorts": [22, 53, 3389]}


def sample():
    caps = sorted(str(uuid.uuid4()) for _ in range(4))
    inbound = [caps[0]]
    c = {"capabilityIds": caps, "inboundCapabilities": [{"capabilityId": caps[0], "protectionSetSha256": digest(PROTECTION),
                                                         "protectedPortsSha256": protected_ports_sha256(PROTECTION["protectedServicePorts"])}]}
    blob = base64.b64encode(b"-----BEGIN CERTIFICATE-----\n").decode()
    return {"assetId": str(uuid.uuid4()), "executorId": str(uuid.uuid4()), "sensorId": str(uuid.uuid4()), "captureScopeId": str(uuid.uuid4()),
            "authorization": {"id": str(uuid.uuid4()), "revision": 2, "status": "active", "validFrom": "2026-10-12T00:00:00Z", "validUntil": "2026-10-12T02:00:00Z"},
            "controlPlaneURL": "https://127.0.0.1:19643", "targetURL": "https://127.0.0.1:19644",
            "peerAddresses": ["127.30.0.2", "127.30.0.3"], "servicePorts": [21, 80], "capabilityIds": caps, "inboundCapabilityIds": inbound,
            "capabilityHash": capability_set_sha256(c), "protection": PROTECTION, "bundleId": str(uuid.uuid4()), "policySha256": "a" * 64,
            "commandTrust": {"k": {"status": "active"}}, "credential": "token", "budgetKey": base64.b64encode(b"k" * 32).decode(),
            "controlPlaneCA": blob, "targetCA": blob, "targetCertificate": blob, "targetKey": blob}


class G3ExecutorTest(unittest.TestCase):
    def test_assembled_config_is_valid_and_fixed_to_loopback(self):
        with tempfile.TemporaryDirectory() as root:
            work = Path(root)
            c = g3_executor.assemble(sample(), work)
            c["pfHelper"] = str(work / "helper")
            path = work / "executor-config.json"
            path.write_bytes(canonical(c))
            path.chmod(0o600)
            loaded = load_config(path)
            self.assertEqual((loaded["platform"], loaded["interface"], loaded["localAddresses"], loaded["environment"]), ("pf", "lo0", ["127.0.0.1"], "lab"))
            self.assertEqual(loaded["limits"], g3_executor.LIMITS)
            self.assertEqual(oct((work / "credential").stat().st_mode & 0o777), "0o600")

    def test_capability_hash_must_match_control_plane(self):
        data = sample()
        data["capabilityHash"] = "0" * 64
        with tempfile.TemporaryDirectory() as root, self.assertRaisesRegex(Rejected, "LAB_CAPABILITY_MISMATCH"):
            g3_executor.assemble(data, Path(root))


if __name__ == "__main__":
    unittest.main()
