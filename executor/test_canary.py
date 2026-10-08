"""真实 Go/mTLS 与签名账本对拍；规则替身不构成 PF 平台验收。"""
from concurrent.futures import ThreadPoolExecutor
import copy
import os
from pathlib import Path
import re
import tempfile
import time
import unittest
from unittest.mock import patch

from .canary_targets import CanaryTargets
from .common import Rejected, canonical, ident, parse, stamp, write_new
from .contract import authorize, protected_ports_sha256
from .engine import Engine
from .platform import PF
from . import pf_lab, test_engine


class CanaryTest(test_engine.RenewalCases, unittest.TestCase):
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

    def renewal_payload(self, **changes):
        return self.fixture.payload(scope="peer_inbound", servicePort=None, **changes)

    def other_target(self):
        # 同一回环对端的全入站与单服务是两个独立登记的稳定目标，不放宽 canary 地址边界。
        return self.fixture.payload(scope="peer_service", servicePort=55001)

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
        f.keep_recovery_alive()
        executable = Path(os.environ.get("P5_GUARDTARGETS", "sensor/bin/guardtargets")).resolve()
        targets = CanaryTargets(self.engine, executable)
        self.addCleanup(targets.close)
        self.engine.resolver = targets.resolver
        binding, registration = targets.lease("peer_inbound", 55001, 55003)
        p = f.payload(scope="peer_inbound", servicePort=None, bootId=binding["bootId"],
                      targetRef=binding["targetRef"], peerKey=binding["peerKey"], blockUntil=stamp(time.time() + 6))
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
        time.sleep(max(0, row["deadline"] - time.monotonic()) + .05)
        self.engine.recover()
        self.assertEqual(f.store.command(p["commandId"])["status"], "expired")
        self.assertFalse(f.firewall.rules)
        self.assertTrue(self.engine.clearance_proofs())


class LabRulesTest(unittest.TestCase):
    """pfctl/clang/ifconfig 全替身：覆盖 lab 编排与失败清理，不运行特权命令。"""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.binary = self.directory / "guardtargets"
        write_new(self.binary, b"synthetic-not-executable")
        self.root = pf_lab.DEFAULT_ROOT
        self.anchors = {"com.apple/*": b'pass all label "apple-fixture"\n'}
        self.enabled, self.alias = False, False
        self.calls = []
        self.fixture = test_engine.EngineTest()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.pf = object.__new__(PF)
        self.pf.root = PF.anchor_root(self.fixture.config["executorId"])
        self.pf.run = lambda args, data=None: self.command(args, data)[0]
        self.fixture.engine.adapter = self.pf

    def command(self, args, data=None, *, binary=False):
        self.calls.append((args, data))
        out = b""
        if args[0] == "/usr/bin/clang":
            write_new(Path(args[-1]), b"synthetic-not-executable")
        elif args[-1] == "--abi":
            out = b'{"kernelMatches":true}'
        elif args[0] == "/sbin/ifconfig":
            if "alias" in args:
                self.alias = True
            elif "-alias" in args:
                self.alias = False
            out = b"inet 127.0.0.2 " if self.alias else b""
        elif args[0] == "/sbin/pfctl":
            if "-n" in args:
                pass
            elif "-E" in args:
                self.enabled, out = True, b"Token : 1234"
            elif "-X" in args:
                self.enabled = False
            elif args[-1] == "info":
                out = b"Status: Enabled" if self.enabled else b"Status: Disabled"
            elif "-f" in args:
                raw = data.encode() if isinstance(data, str) else data
                if "-a" in args:
                    self.anchors[args[args.index("-a") + 1]] = raw
                else:
                    self.root = raw
                    found = re.search(rb'anchor "(hg5[^/]+)/\*"', raw)
                    if found:
                        self.pf.root = found[1].decode()
            elif args[-1] == "-sr":
                out = self.anchors.get(args[args.index("-a") + 1], b"") if "-a" in args else self.root
            elif args[-1] != "Anchors":
                self.fail(f"unexpected pfctl arguments: {args}")
        else:
            self.fail(f"unexpected executable: {args[0]}")
        return (out, b"") if binary else (out.decode(), "")

    def fake_run(self, config, key, key_id, output, mode, targets, scenario, checkpoint):
        self.assertEqual(mode, "peer_inbound")
        if scenario in ("before_ledger", "after_ledger", "after_install"):
            checkpoint(scenario + "_recovered")
        else:
            checkpoint("installed")
            checkpoint(scenario + "_recovered")
        write_new(output, canonical({"passed": True}))

    def run_lab(self, run=None):
        with patch.object(pf_lab.sys, "platform", "darwin"), \
                patch.object(pf_lab.os, "geteuid", return_value=0, create=True), \
                patch.object(pf_lab, "command", side_effect=self.command), \
                patch.object(pf_lab, "keys", side_effect=lambda d, k: d.mkdir()), \
                patch.object(pf_lab, "build", return_value=self.fixture.engine), \
                patch.object(pf_lab, "run", side_effect=run or self.fake_run), \
                patch("builtins.print"):
            pf_lab.main(self.directory / "run", self.binary)

    def test_e1_preset_user_rules_survive_all_required_checkpoints(self):
        self.root = pf_lab.USER_ROOT
        self.anchors[pf_lab.USER_ANCHOR] = pf_lab.USER_ANCHOR_RULE
        self.run_lab()
        summary = parse((self.directory / "run/summary.json").read_bytes())
        self.assertTrue(summary["passed"])
        self.assertTrue(summary["userFixturePreexisting"])
        self.assertEqual(self.root, pf_lab.USER_ROOT)
        self.assertEqual(self.anchors[pf_lab.USER_ANCHOR], pf_lab.USER_ANCHOR_RULE)
        checks = {entry["scenario"]: entry["checks"] for entry in summary["userRuleChecks"]}
        for scenario in ("ttl", "revoke", "before_ledger", "after_ledger", "after_install"):
            stages = [entry["stage"] for entry in checks[scenario]]
            self.assertIn(scenario + "_recovered", stages)
            self.assertTrue(all(entry["unchanged"] for entry in checks[scenario]))
        self.assertIn("installed", [entry["stage"] for entry in checks["ttl"]])
        unknown = summary["unknownRule"]
        self.assertTrue(unknown["ruleUnchanged"] and unknown["paused"] and unknown["fixtureCleanup"])
        self.assertIn("STATE_RECONCILIATION_FAILED", unknown["recoveryErrors"])
        self.assertTrue(all(summary["cleanup"].values()))
        self.assertFalse(self.enabled or self.alias)
        self.assertFalse(any("-F" in args or "-d" in args for args, _ in self.calls))

    def test_e1_default_root_gets_fixed_recorded_fixture_then_restores(self):
        self.run_lab()
        summary = parse((self.directory / "run/summary.json").read_bytes())
        self.assertTrue(summary["passed"])
        self.assertFalse(summary["userFixturePreexisting"])
        self.assertEqual(self.root, pf_lab.DEFAULT_ROOT)
        self.assertEqual(self.anchors[pf_lab.USER_ANCHOR], b"")
        self.assertEqual((self.directory / "run/user-fixture-anchor.conf").read_bytes(), pf_lab.USER_ANCHOR_RULE)

    def test_e1_unexpected_existing_rules_rejected_before_mutation(self):
        for root, user in ((pf_lab.DEFAULT_ROOT + b"pass all\n", b""),
                           (pf_lab.DEFAULT_ROOT, pf_lab.USER_ANCHOR_RULE),
                           (pf_lab.USER_ROOT, pf_lab.USER_ANCHOR_RULE + b"\n")):
            with self.subTest(root=root, user=user), self.assertRaisesRegex(Rejected, "LAB_UNEXPECTED_ROOT_RULES"):
                pf_lab.existing_rules(root, user)

    def test_e1_byte_change_fails_and_preserves_modified_user_anchor(self):
        self.root = pf_lab.USER_ROOT
        self.anchors[pf_lab.USER_ANCHOR] = pf_lab.USER_ANCHOR_RULE
        def corrupt(*args, **kwargs):
            self.anchors[pf_lab.USER_ANCHOR] += b"\n"
            self.fake_run(*args, **kwargs)
        with self.assertRaisesRegex(Rejected, "LAB_USER_RULES_CHANGED"):
            self.run_lab(corrupt)
        summary = parse((self.directory / "run/summary.json").read_bytes())
        self.assertFalse(summary["passed"])
        self.assertFalse(summary["cleanup"]["userAnchorUnchanged"])
        self.assertEqual(self.anchors[pf_lab.USER_ANCHOR], pf_lab.USER_ANCHOR_RULE + b"\n")
        self.assertEqual(self.root, pf_lab.USER_ROOT)
        self.assertFalse(self.enabled or self.alias)

    def test_e1_unknown_probe_does_not_clean_changed_injection(self):
        original_recover = self.fixture.engine.recover
        def corrupt():
            original_recover()
            self.anchors[self.pf.root] += b"\n"
        with patch.object(pf_lab, "command", side_effect=self.command), \
                patch.object(self.fixture.engine, "recover", side_effect=corrupt):
            with self.assertRaisesRegex(Rejected, "LAB_UNKNOWN_FIXTURE_CLEANUP_FAILED"):
                pf_lab.unknown_rule_probe(self.fixture.engine)
        self.assertEqual(self.anchors[self.pf.root], pf_lab.UNKNOWN_RULE + b"\n")
        self.assertTrue(self.fixture.store.get("paused"))

    def test_e1_root_change_is_reported_and_never_overwritten_on_cleanup(self):
        changed = []
        def corrupt(*args, **kwargs):
            self.root += b'pass all label "external-user-change"\n'
            changed.append(self.root)
            self.fake_run(*args, **kwargs)
        with self.assertRaisesRegex(Rejected, "LAB_USER_RULES_CHANGED"):
            self.run_lab(corrupt)
        summary = parse((self.directory / "run/summary.json").read_bytes())
        self.assertFalse(summary["passed"])
        self.assertFalse(summary["cleanup"]["rootRestored"])
        self.assertFalse(summary["cleanup"]["rootUnchanged"])
        self.assertEqual(self.root, changed[0])
        self.assertFalse(self.enabled or self.alias)

    def test_e1_unknown_failure_keeps_report_and_changed_rule(self):
        original_recover = self.fixture.engine.recover
        def corrupt():
            original_recover()
            self.anchors[self.pf.root] += b"\n"
        with patch.object(self.fixture.engine, "recover", side_effect=corrupt):
            with self.assertRaisesRegex(Rejected, "LAB_UNKNOWN_FIXTURE_CLEANUP_FAILED"):
                self.run_lab()
        summary = parse((self.directory / "run/summary.json").read_bytes())
        self.assertFalse(summary["passed"])
        self.assertFalse(summary["unknownRule"]["passed"])
        self.assertFalse(summary["unknownRule"]["fixtureCleanup"])
        self.assertTrue(summary["unknownRule"]["paused"])
        self.assertEqual(self.anchors[self.pf.root], pf_lab.UNKNOWN_RULE + b"\n")


if __name__ == "__main__":
    unittest.main()
