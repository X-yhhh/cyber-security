"""C1a：只用合成策略检查 inbound 规则口径派生的来源审查与字段边界，不读取训练或测试集。"""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import compose_policy as c


class RuleInboundPolicyTest(unittest.TestCase):
    def setUp(self):
        self.source = c.load(Path(__file__).parent / "testdata/composed-policy.json")
        self.review = dict(policyId=self.source["policyId"], status="reviewed",
                           definitionSha256=c.digest(c.canonical(self.source)), createdBy=1, reviewedBy=2)

    def test_only_id_and_version_change(self):
        before = copy.deepcopy(self.source)
        derived, record = c.derive_rule_inbound(self.source, self.review)
        self.assertEqual((derived, record), c.derive_rule_inbound(self.source, self.review))
        self.assertEqual(before, self.source)
        self.assertEqual(derived["policyVersion"], self.source["policyVersion"] + "+rule-inbound-20261018")
        self.assertEqual({x["path"] for x in record["changes"]}, {"/policyId", "/policyVersion"})
        self.assertEqual(derived["mode"], self.source["mode"])
        self.assertEqual(derived["rulePolicies"], self.source["rulePolicies"])
        self.assertTrue(record["requiresIndependentReview"] and not record["testRead"] and not record["thresholdsChanged"])

    def test_rejects_unreviewed_source_and_any_other_change(self):
        for change in ({"status": "draft"}, {"reviewedBy": 1}, {"definitionSha256": "0" * 64}):
            with self.subTest(change=change), self.assertRaises(c.PolicyError):
                c.derive_rule_inbound(self.source, self.review | change)
        derived, _ = c.derive_rule_inbound(self.source, self.review)
        for path, value in ((("rulePolicies", 0, "threshold"), 1), (("mode",), "auto" if self.source["mode"] != "auto" else "alert_only"),
                            (("maxTtlSeconds",), 45)):
            tampered = copy.deepcopy(derived)
            target = tampered
            for key in path[:-1]:
                target = target[key]
            if path[-1] not in target and not isinstance(target, list):
                continue
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(c.PolicyError):
                c.validate_rule_inbound_derivation(self.source, tampered)
        twice = copy.deepcopy(derived)
        with self.assertRaises(c.PolicyError):
            c.derive_rule_inbound(twice, dict(self.review, policyId=twice["policyId"], definitionSha256=c.digest(c.canonical(twice))))

    def test_cli_writes_new_files_only(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "s.json").write_text(json.dumps(self.source))
            (root / "r.json").write_text(json.dumps(self.review))
            command = [sys.executable, str(Path(c.__file__)), "derive-rule-inbound", "--source", str(root / "s.json"),
                       "--source-review", str(root / "r.json"), "--output", str(root / "p.json"), "--record", str(root / "d.json")]
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertEqual(json.loads((root / "p.json").read_text())["policyVersion"].split("+")[-1], "rule-inbound-20261018")
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 2)


if __name__ == "__main__":
    unittest.main()
