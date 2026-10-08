"""真实 Go/mTLS 与签名账本对拍；规则替身不构成 PF 平台验收。"""
from concurrent.futures import ThreadPoolExecutor
import copy
import os
from pathlib import Path
import time
import unittest

from .canary_targets import CanaryTargets
from .common import Rejected, ident, stamp
from .contract import authorize, protected_ports_sha256
from .engine import Engine
from . import test_engine


class CanaryTest(unittest.TestCase):
    def setUp(self):
        f = self.fixture = test_engine.EngineTest()
        f.setUp()
        self.addCleanup(f.doCleanups)
        f.config.update(platform="pf", localAddresses=["127.0.0.1"], peerAddresses=["127.0.0.2"],
                        protectedServicePorts=[22, 53, 3389, 55002])
        f.resolver.result.update(Local="127.0.0.1:55001", Peer="127.0.0.2:55003")
        f.config["inboundCapabilities"] = [{"capabilityId": f.config["capabilityIds"][0], "protectionSetSha256": "e" * 64,
                                            "protectedPortsSha256": protected_ports_sha256(f.config["protectedServicePorts"])}]
        # 回环验收与正式入口是同一个 Engine，不存在专用子类或授权例外。
        self.engine = Engine(f.store, f.firewall, f.resolver, lambda: f.config,
                             lambda: f.trust, f.engine.budget_key, f.clock)

    def test_inbound_requires_registered_lab_pf_capability_and_unchanged_protection(self):
        """B1.5：全入站只按本机登记放行；未登记仍是正式默认拒绝，任一条件不符都不安装规则。"""
        f = self.fixture
        good = copy.deepcopy(f.config)
        other = ident()
        cases = [("unregistered", {"inboundCapabilities": []}, "PROTECTED_TARGET"),
                 ("otherCapability", {"capabilityIds": [good["capabilityIds"][0], other],
                                      "inboundCapabilities": [{**good["inboundCapabilities"][0], "capabilityId": other}]},
                  "PROTECTED_TARGET"),
                 ("wfp", {"platform": "wfp"}, "CAPABILITY_NOT_SUPPORTED"),
                 ("protectionChanged", {"protectedServicePorts": [22, 53, 3389, 55002, 55004]},
                  "PROTECTION_SET_UNVERIFIED"),
                 ("controlPortDropped", {"protectedServicePorts": [22, 53, 3389]}, "PROTECTION_SET_UNVERIFIED")]
        for name, changes, code in cases:
            with self.subTest(case=name):
                f.config.clear()
                f.config.update(copy.deepcopy(good), **copy.deepcopy(changes))
                with self.assertRaisesRegex(Rejected, code):
                    f.engine.accept(f.signed(f.payload(scope="peer_inbound", servicePort=None)))
        # 环境属于账本身份，引擎会先以 LEDGER_IDENTITY_CHANGED 拒绝；这里直接覆盖授权门禁本身。
        authorized = {**copy.deepcopy(good), "environment": "authorized"}
        p = {**f.payload(scope="peer_inbound", servicePort=None), "environment": "authorized"}
        with self.assertRaisesRegex(Rejected, "CAPABILITY_NOT_SUPPORTED"):
            authorize(p, authorized, f.engine.boot, f.clock.time())
        self.assertEqual(f.firewall.installs, 0)
        f.config.clear()
        f.config.update(copy.deepcopy(good))
        self.assertEqual(f.engine.accept(f.signed(f.payload(scope="peer_inbound", servicePort=None))), "applied")
        self.assertEqual(f.firewall.installs, 1)

    def test_inbound_real_mtls_signature_binding_budget_and_recovery(self):
        f = self.fixture
        f.clock = time
        self.engine.clock = time
        f.config["authorization"].update(validFrom=stamp(time.time() - 60), validUntil=stamp(time.time() + 60))
        f.trust["test"].update(notBefore=stamp(time.time() - 60), notAfter=stamp(time.time() + 60))
        self.engine.start()
        f.engine = self.engine
        executable = Path(os.environ.get("P5_GUARDTARGETS", "sensor/bin/guardtargets")).resolve()
        targets = CanaryTargets(self.engine, executable)
        self.addCleanup(targets.close)
        self.engine.resolver = targets.resolver
        binding, registration = targets.lease("peer_inbound", 55001, 55003)
        p = f.payload(scope="peer_inbound", servicePort=None, bootId=binding["bootId"],
                      targetRef=binding["targetRef"], peerKey=binding["peerKey"], blockUntil=stamp(time.time() + .6))
        p["applyBy"] = stamp(time.time() + .3)
        self.engine.pulse("recovery")
        self.assertEqual(self.engine.accept(f.signed(p)), "applied")
        row = f.store.command(p["commandId"])
        self.assertEqual(row["token"], registration["stableTargetToken"])
        self.assertEqual(self.engine.accept(f.signed(p)), "applied")
        self.assertEqual(row["deadline"], f.store.command(p["commandId"])["deadline"])
        ranges = row["scope"]["ranges"]
        self.assertFalse(any(a <= 55002 <= b for a, b in ranges))
        with self.assertRaises(Rejected):
            targets.resolver.resolve({**p, "scope": "peer_service", "servicePort": 55001})
        def submit(_):
            try:
                self.engine.accept(f.signed({**p, "commandId": ident(), "actionId": ident(), "idempotencyKey": ident()}))
            except Rejected as exc:
                return str(exc)
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(list(pool.map(submit, range(2))), ["TARGET_BUDGET_BUSY"] * 2)
        time.sleep(.65)
        self.engine.recover()
        self.assertEqual(f.store.command(p["commandId"])["status"], "expired")
        self.assertFalse(f.firewall.rules)
        self.assertTrue(self.engine.clearance_proofs())


if __name__ == "__main__":
    unittest.main()
