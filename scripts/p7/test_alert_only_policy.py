"""ML-8：只用合成策略检查来源审查、冻结语义及字段边界，不读取训练或测试集。"""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import compose_policy as c


class AlertOnlyPolicyTest(unittest.TestCase):
    def setUp(self):
        self.source = c.load(Path(__file__).parent / "testdata/composed-policy.json")
        self.review = dict(policyId=self.source["policyId"], status="reviewed",
                           definitionSha256=c.digest(c.canonical(self.source)), createdBy=1, reviewedBy=2)
        self.version = self.source["policyVersion"] + "+alert-only"

    def derive(self):
        return c.derive_alert_only(self.source, self.review, self.version)

    def test_derivation_is_deterministic_and_preserves_source_and_deployment(self):
        before = copy.deepcopy(self.source)
        derived, record = self.derive()
        self.assertEqual((derived, record), self.derive())
        self.assertEqual(before, self.source)
        self.assertEqual("alert_only", derived["mode"])
        self.assertTrue(all(not row["autoEligible"] and not row["modelAutoEligible"] for row in derived["familyPolicies"]))
        self.assertTrue(all(not row["autoEligible"] for row in derived["rulePolicies"]))
        self.assertEqual(c.frozen_semantics(self.source), c.frozen_semantics(derived))
        for field in c.DEPLOYMENT_FIELDS:
            self.assertEqual(self.source[field], derived[field])
        self.assertEqual(c.policy_diff(self.source, derived), record["changes"])
        self.assertTrue(record["requiresIndependentReview"])

    def test_unreviewed_or_self_reviewed_or_wrong_identity_rejected(self):
        for change in ({"status": "draft"}, {"status": "retired"}, {"reviewedBy": None},
                       {"reviewedBy": 1}, {"policyId": "wrong"}):
            with self.subTest(change=change), self.assertRaisesRegex(c.PolicyError, "独立审查"):
                c.derive_alert_only(self.source, self.review | change, self.version)

    def test_tampered_source_threshold_rejected_by_review_digest(self):
        self.source["rulePolicies"][0]["threshold"] += 1
        with self.assertRaisesRegex(c.PolicyError, "已审查策略哈希不符"):
            self.derive()

    def test_derived_frozen_semantics_change_rejected(self):
        derived, _ = self.derive()
        derived["rulePolicies"][0]["threshold"] += 1
        with self.assertRaisesRegex(c.PolicyError, "冻结策略语义不一致"):
            c.validate_alert_only_derivation(self.source, derived)

    def test_deployment_and_optional_profile_drift_rejected(self):
        for field, value in (("maxTtlSeconds", 30), ("protectionSetSha256", "f" * 64),
                             ("supportedCapabilityIds", ["b52f519e-f779-4a11-95d7-ae8f0ecb7c13"]),
                             ("acceptedProfiles", [self.source["profile"], "flow-final-v1"])):
            derived, _ = self.derive()
            if value == derived.get(field):
                continue
            derived[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(c.PolicyError, "改动越界"):
                c.validate_alert_only_derivation(self.source, derived)

    def test_any_automatic_switch_or_mode_reenabled_rejected(self):
        for change in (lambda p: p.update(mode="auto"),
                       lambda p: p["familyPolicies"][0].update(autoEligible=True),
                       lambda p: p["familyPolicies"][0].update(autoEligible=True, modelAutoEligible=True),
                       lambda p: p["rulePolicies"][0].update(autoEligible=True)):
            derived, _ = self.derive()
            change(derived)
            with self.assertRaises(c.PolicyError):
                c.validate_alert_only_derivation(self.source, derived)

    def test_empty_or_reused_version_rejected(self):
        for version in ("", " ", self.source["policyVersion"]):
            with self.subTest(version=version), self.assertRaisesRegex(c.PolicyError, "新的非空"):
                c.derive_alert_only(self.source, self.review, version)

    def test_cli_writes_provenance_and_never_overwrites_existing_outputs(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name, value in (("source.json", self.source), ("review.json", self.review)):
                (root / name).write_text(json.dumps(value))
            args = [sys.executable, str(Path(c.__file__)), "derive-alert-only", "--source", str(root / "source.json"),
                    "--source-review", str(root / "review.json"), "--version", self.version,
                    "--output", str(root / "policy.json"), "--record", str(root / "record.json")]
            result = subprocess.run(args, capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr)
            record = c.load(root / "record.json")
            self.assertEqual(c.digest((root / "source.json").read_bytes()), record["sourceFileSha256"])
            original = (root / "record.json").read_bytes()
            (root / "policy.json").unlink()
            self.assertEqual(2, subprocess.run(args, capture_output=True).returncode)
            self.assertFalse((root / "policy.json").exists())
            self.assertEqual(original, (root / "record.json").read_bytes())

    def test_cli_invalid_review_leaves_no_outputs(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "source.json").write_text(json.dumps(self.source))
            (root / "review.json").write_text(json.dumps(self.review | {"status": "draft"}))
            result = subprocess.run([sys.executable, str(Path(c.__file__)), "derive-alert-only",
                                     "--source", str(root / "source.json"), "--source-review", str(root / "review.json"),
                                     "--version", self.version, "--output", str(root / "out.json"),
                                     "--record", str(root / "record.json")], capture_output=True)
            self.assertEqual(2, result.returncode)
            self.assertFalse((root / "out.json").exists())
            self.assertFalse((root / "record.json").exists())


if __name__ == "__main__":
    unittest.main()
