"""PF 全入站区间与枚举的离线回归；不操作系统防火墙。"""
import uuid
import unittest
from pathlib import Path
import subprocess
import sys
import time

import tempfile

from .common import Rejected, canonical, digest, parse, write_new
from .config import load
from .contract import (capability_items_sha256, capability_set_sha256, protected_ports, protected_ports_sha256,
                       unprotected_ranges)
from .pf_canary import canary_scope
from .platform import PF, inbound_ranges


VECTORS = Path(__file__).resolve().parents[1] / "docs" / "contracts" / "examples" / "capability-binding-vectors.json"


class PlatformTest(unittest.TestCase):
    def test_protected_ports_and_capability_set_match_shared_java_vectors(self):
        """B1.6：与后端 GuardCapabilityBindingTest 读取同一向量，任一侧算法漂移即失败。"""
        vectors = parse(VECTORS.read_bytes())
        self.assertEqual(vectors["implicitProtectedPorts"], [22, 53, 3389])
        for case in vectors["protectedPorts"]:
            with self.subTest(ports=case["input"]):
                self.assertEqual(protected_ports(case["input"]), case["effective"])
                self.assertEqual(unprotected_ranges(case["input"]), case["ranges"])
                self.assertEqual(protected_ports_sha256(case["input"]), case["protectedPortsSha256"])
        for ports in vectors["invalidProtectedPorts"]:
            with self.subTest(invalid=ports[:3]), self.assertRaisesRegex(Rejected, "CONFIG_SCOPE_INVALID"):
                protected_ports(ports)
        for case in vectors["capabilitySets"]:
            with self.subTest(items=len(case["items"])):
                self.assertEqual(capability_items_sha256(case["items"]), case["capabilitySetSha256"])
                if case["items"]:
                    config = {"capabilityIds": [item["capabilityId"] for item in case["items"]],
                              "inboundCapabilities": [{k: item[k] for k in ("capabilityId", "protectionSetSha256",
                                                                            "protectedPortsSha256")}
                                                      for item in case["items"] if item["scope"] == "peer_inbound"]}
                    self.assertEqual(capability_set_sha256(config), case["capabilitySetSha256"])

    def test_config_binds_capability_hash_and_restricts_inbound_registration(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            ids = [str(uuid.uuid4()) for _ in range(7)]
            base = {"platform": "pf", "stateDir": str(root / "state"), "assetId": ids[0], "executorId": ids[1],
                    "sensorId": ids[2], "captureScopeId": ids[3], "environment": "lab", "interface": "lo0",
                    "localAddresses": ["127.0.0.1"], "peerAddresses": ["127.0.0.2"], "servicePorts": [55001],
                    "protectedPeers": [], "protectedServicePorts": [55002], "capabilityIds": [ids[4]],
                    "bundleIds": [ids[5]], "policyHashes": ["a" * 64],
                    "authorization": {"id": ids[6], "revision": 1, "status": "active",
                                      "validFrom": "2026-10-08T00:00:00Z", "validUntil": "2026-10-09T00:00:00Z"},
                    "limits": {"maxTtlSeconds": 60, "maxContinuousBlockSeconds": 120,
                               "maxActiveRulesPerAsset": 10, "maxNewActionsPerMinute": 5},
                    **{k: str(root / k) for k in ("trustFile", "budgetKeyFile", "credentialFile", "targetCA",
                                                  "targetCertificate", "targetKey")},
                    "controlPlaneURL": "https://127.0.0.1:1", "targetURL": "https://127.0.0.1:1",
                    "inboundCapabilities": [{"capabilityId": ids[4], "protectionSetSha256": "e" * 64,
                                             "protectedPortsSha256": protected_ports_sha256([55002])}]}
            counter = iter(range(100))

            def written(config):
                path = root / f"config-{next(counter)}.json"
                write_new(path, canonical(config))
                return path

            good = {**base, "capabilityHash": capability_set_sha256(base)}
            self.assertEqual(load(written(good))["capabilityHash"], capability_set_sha256(base))
            peer_service = {k: v for k, v in base.items() if k != "inboundCapabilities"}
            self.assertNotEqual(capability_set_sha256(peer_service), good["capabilityHash"])
            cases = {"CONFIG_HASH_INVALID": [{"capabilityHash": "c" * 64},
                                             {"inboundCapabilities": [], "capabilityHash": good["capabilityHash"]}],
                     "CONFIG_SCOPE_INVALID": [{"environment": "authorized"}, {"platform": "wfp"}],
                     "CONFIG_CAPABILITY_INVALID": [
                         {"inboundCapabilities": [{**base["inboundCapabilities"][0], "capabilityId": ids[5]}]},
                         {"inboundCapabilities": base["inboundCapabilities"] * 2},
                         {"inboundCapabilities": [{**base["inboundCapabilities"][0], "bypass": True}]}]}
            for code, changes in cases.items():
                for change in changes:
                    config = {**base, **change}
                    if "capabilityHash" not in change and code != "CONFIG_CAPABILITY_INVALID":
                        config["capabilityHash"] = capability_set_sha256(config)
                    config.setdefault("capabilityHash", good["capabilityHash"])
                    with self.subTest(code=code, change=sorted(change)), self.assertRaisesRegex(Rejected, code):
                        load(written(config))
            self.assertEqual(digest([22, 53, 3389, 55002]), protected_ports_sha256([55002]))

    def test_protected_ports_are_excluded_and_ranges_cover_every_other_port(self):
        ranges = unprotected_ranges([443, 53, 443, 65535])
        scope = {"port": None, "ranges": ranges}
        self.assertEqual(inbound_ranges(scope), ranges)
        covered = {port for first, last in ranges for port in range(first, last + 1)}
        self.assertEqual(covered, set(range(1, 65536)) - {22, 53, 443, 3389, 65535})
        for altered in ([[1, 30], [31, 65535]], [[1, 21], [21, 65535]], [[1, 21]],
                        [[1, 21], [23, 53], [54, 65535]],
                        [[1, 21], [23, 52], [54, 3388], [3390, 9999], [10130, 65535]]):
            with self.subTest(altered=altered), self.assertRaises(Rejected):
                inbound_ranges({"port": None, "ranges": altered})
        self.assertEqual(inbound_ranges({"port": None, "ranges": unprotected_ranges([1, 23, 65535])}),
                         unprotected_ranges([1, 23, 65535]))

    def test_inbound_canary_requires_protected_control_port(self):
        config = {"platform": "pf", "environment": "lab", "interface": "lo0",
                  "localAddresses": ["127.0.0.1"], "peerAddresses": ["127.0.0.2"],
                  "servicePorts": [55001], "protectedServicePorts": [22, 53, 3389, 55002]}
        port, scope = canary_scope(config, "peer_inbound")
        self.assertEqual(port, 55001)
        self.assertFalse(any(first <= 55002 <= last for first, last in scope["ranges"]))
        self.assertTrue(any(first <= 55001 <= last for first, last in scope["ranges"]))
        for change in ({"protectedServicePorts": [22, 53, 3389]},
                       {"servicePorts": [55002]}, {"interface": "en0"},
                       {"peerAddresses": ["192.0.2.2"]}):
            with self.subTest(change=change), self.assertRaisesRegex(Rejected, "CANARY_SCOPE_REQUIRED"):
                canary_scope({**config, **change}, "peer_inbound")

    def test_inventory_reconstructs_inbound_scope_and_rejects_foreign_rule(self):
        command = str(uuid.uuid4())
        ranges = unprotected_ranges([443])
        lines = [f'block drop quick on lo0 inet proto tcp from 127.0.0.2 to 127.0.0.1 '
                 f'port {first}:{last} label "hg5-{command}"' for first, last in ranges]
        pf = object.__new__(PF)
        pf.root = PF.anchor_root(str(uuid.uuid4()))
        pf.run = lambda args: command if args[-1] == "Anchors" else "\n".join(lines)
        scope = pf.inventory()[command]["scope"]
        self.assertEqual(scope, {"local": "127.0.0.1", "peer": "127.0.0.2", "interface": "lo0",
                                 "port": None, "ranges": ranges})
        original = lines[0]
        lines[0] = lines[0].replace("127.0.0.2", "127.0.0.3")
        with self.assertRaisesRegex(Rejected, "UNKNOWN_OWNED_RULE"):
            pf.inventory()
        for invalid in ("65536:65537", "40:30", "unknown-service"):
            with self.subTest(invalid=invalid):
                lines[0] = original.replace("1:21", invalid)
                with self.assertRaisesRegex(Rejected, "UNKNOWN_OWNED_RULE"):
                    pf.inventory()

    def test_pf_install_uses_identical_ranges_for_rules_and_state_cleanup(self):
        command = str(uuid.uuid4())
        ranges = unprotected_ranges([443])
        scope = {"local": "127.0.0.1", "peer": "127.0.0.2", "port": None,
                 "interface": "lo0", "ranges": ranges}
        pf = object.__new__(PF)
        pf.root, pf.helper = PF.anchor_root(str(uuid.uuid4())), Path("/private/tmp/helper")
        self.assertEqual(len(pf.handle(command)), 62)
        pf.preflight, pf.inventory = lambda: None, lambda: {}
        calls = []
        pf.run = lambda args, data=None: calls.append((args, data))
        pf.install(command, scope, time.time() + 5)
        self.assertEqual(len(calls), 2)
        rules = calls[0][1].splitlines()
        self.assertEqual(len(rules), len(ranges))
        self.assertTrue(all("port 22 " not in rule and "port 53 " not in rule and
                            "port 443 " not in rule and "port 3389 " not in rule for rule in rules))
        self.assertEqual(calls[1][0][1:], ["kill-ranges", "127.0.0.1", "127.0.0.2",
                                             ",".join(f"{a}:{b}" for a, b in ranges), "lo0"])
        if sys.platform == "darwin":
            for executor_id in (str(uuid.uuid4()), "ffffffff-ffff-ffff-ffff-ffffffffffff"):
                with self.subTest(executor_id=executor_id):
                    pf.root = PF.anchor_root(executor_id)
                    result = subprocess.run(["/sbin/pfctl", "-n", "-a", pf.handle(command), "-f", "-"],
                                            input=calls[0][1], text=True, capture_output=True, timeout=5)
                    self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
