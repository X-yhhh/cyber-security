"""签名平台报告：只接受真实 PF 证据；签名可被 P4 同算法验证。全部为合成文件，不运行 PF。"""
import base64
import json
import os
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from executor.common import Rejected, canonical
from scripts.p5 import platform_report as r


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))
    return path


class PlatformReportTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.d = Path(self.temp.name)
        self.lab = self.d / "lab"
        write(self.lab / "launch-record.json", {"task": "e1e2-lab", "exitCode": 0, "commit": "c" * 40})
        write(self.lab / "evidence/summary.json", {"passed": True, "cleanup": {"rootRestored": True},
                                                   "unknownRule": {"passed": True},
                                                   "scenarios": [{"scenario": "ttl", "passed": True}]})
        self.e3 = {scope: write(self.d / f"{scope}.json", {"realPF": True, "scenarios": [
            {"scope": scope, "scenario": s, "passed": True} for s in ("revoke", "disconnect", "receipt_loss")]})
            for scope in ("peer_service", "peer_inbound")}
        self.launches = []
        for scope in ("peer_service", "peer_inbound"):
            for scenario in ("revoke", "disconnect", "receipt_loss"):
                launch = self.d / "root" / f"{scope}-{scenario}"
                write(launch / "launch-record.json", {"task": "e3-executor", "exitCode": 0, "commit": "c" * 40,
                                                      "scope": scope, "scenario": scenario,
                                                      "rendezvous": str(self.d.resolve() / f"{scope}-{scenario}")})
                write(launch / "evidence/result.json", {"realPF": True, "passed": True, "scope": scope, "scenario": scenario})
                self.launches.append(launch)
        self.request = {"capabilityKey": "k", "version": "1", "platform": "macos", "adapterVersion": "hostguard-executor/1",
                        "addressFamily": "ipv4", "transport": "tcp", "direction": "inbound", "family": "brute_force",
                        "profile": "flow-prefix-v1", "behaviorScope": ["x"], "latencyLimits": {"maxMs": 20000},
                        "level": "lab_auto", "evidenceRef": "r", "evidenceSha256": "e" * 64, "runnerIdentity": "runner"}
        self.key = ed25519.Ed25519PrivateKey.generate()

    def test_platform_capability_equals_request_without_evidence_and_signature_verifies(self):
        items = r.collect([self.lab], [self.e3["peer_service"]], "peer_service", self.launches)
        envelope = r.sign(r.build("platform", self.request, items, {"evaluation": "v"}), self.key, "runner")
        expected = {k: v for k, v in self.request.items() if k not in r.WITHOUT_EVIDENCE}
        self.assertEqual(envelope["payload"]["capability"], expected)
        signature = base64.urlsafe_b64decode(envelope["signature"] + "=" * (-len(envelope["signature"]) % 4))
        self.key.public_key().verify(signature, canonical(envelope["payload"]))
        self.assertEqual(envelope["keyId"], "runner")

    def test_rejects_synthetic_failed_incomplete_or_mixed_evidence(self):
        cases = {
            "rehearsal": (lambda: write(self.e3["peer_service"], {**json.loads(self.e3["peer_service"].read_text()), "realPF": False}),
                          "REPORT_EVIDENCE_NOT_REAL"),
            "failedRound": (lambda: write(self.e3["peer_service"], {"realPF": True, "scenarios": [
                {"scope": "peer_service", "scenario": "revoke", "passed": False}]}), "REPORT_EVIDENCE_FAILED"),
            "missingScenario": (lambda: write(self.e3["peer_service"], {"realPF": True, "scenarios": [
                {"scope": "peer_service", "scenario": "revoke", "passed": True}]}), "REPORT_E3_INCOMPLETE"),
            "labExit": (lambda: write(self.lab / "launch-record.json", {"task": "e1e2-lab", "exitCode": 1, "commit": "c"}),
                        "REPORT_EVIDENCE_NOT_REAL"),
            "labCleanup": (lambda: write(self.lab / "evidence/summary.json", {"passed": True, "cleanup": {"aliasRemoved": False},
                                                                              "unknownRule": {"passed": True}, "scenarios": []}),
                           "REPORT_EVIDENCE_FAILED"),
            "rootMissing": (lambda: self.launches.pop(0), "REPORT_E3_ROOT_EVIDENCE_MISSING"),
            "rootExit": (lambda: write(self.launches[0] / "launch-record.json", {
                **json.loads((self.launches[0] / "launch-record.json").read_text()), "exitCode": 1}),
                         "REPORT_EVIDENCE_NOT_REAL"),
            "rootNotReal": (lambda: write(self.launches[0] / "evidence/result.json", {
                "realPF": False, "passed": True, "scope": "peer_service", "scenario": "revoke"}), "REPORT_EVIDENCE_FAILED"),
            "rootOtherRun": (lambda: write(self.launches[0] / "launch-record.json", {
                **json.loads((self.launches[0] / "launch-record.json").read_text()),
                "rendezvous": str(self.d.resolve() / "other-run" / "peer_service-revoke")}), "REPORT_E3_ROOT_EVIDENCE_MISSING"),
        }
        for name, (mutate, code) in cases.items():
            with self.subTest(case=name):
                self.setUp()
                mutate()
                with self.assertRaisesRegex(Rejected, code):
                    r.collect([self.lab], [self.e3["peer_service"]], "peer_service", self.launches)
        self.setUp()
        with self.assertRaisesRegex(Rejected, "REPORT_E3_INCOMPLETE"):
            r.collect([self.lab], [self.e3["peer_inbound"]], "peer_service", self.launches)
        with self.assertRaisesRegex(Rejected, "REPORT_E1E2_MISSING"):
            r.collect([], [self.e3["peer_service"]], "peer_service", self.launches)

    def test_scope_level_exemption_and_key_location_rules(self):
        items = r.collect([self.lab], [self.e3["peer_inbound"]], "peer_inbound", self.launches)
        inbound = {**self.request, "scope": "peer_inbound", "protectionSetSha256": "p" * 64}
        with self.assertRaisesRegex(Rejected, "REPORT_EXEMPTION_REQUIRED"):
            r.build("platform", inbound, items, {})
        exemption = r.build("exemption", inbound, items, {})
        self.assertEqual((exemption["scope"], exemption["platform"], exemption["protectionSetSha256"]),
                         ("peer_inbound", "macos-pf", "p" * 64))
        with self.assertRaisesRegex(Rejected, "REPORT_SCOPE_INVALID"):
            r.build("exemption", self.request, items, {})
        with self.assertRaisesRegex(Rejected, "REPORT_LEVEL_INVALID"):
            r.build("platform", {**self.request, "level": "research"}, items, {})
        key = self.d / "runner.der"
        key.write_bytes(self.key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
        os.chmod(key, 0o644)
        with self.assertRaisesRegex(Rejected, "REPORT_KEY_PERMISSIONS"):
            r.private_key(key)
        os.chmod(key, 0o600)
        r.private_key(key)
        with self.assertRaisesRegex(Rejected, "REPORT_KEY_INSIDE_REPOSITORY"):
            r.private_key(r.ROOT / "scripts/p5/README.md")


if __name__ == "__main__":
    unittest.main()
