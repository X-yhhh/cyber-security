"""B2 合成与拒绝路径；仅合成 JSON，不读取真实训练/测试数据或连接 P4。"""
import copy
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import compose_policy as c

FIXTURES = Path(__file__).resolve().parent / "testdata"


class ComposePolicyTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="b2-test-")
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        for path in FIXTURES.glob("*.json"):
            shutil.copyfile(path, self.folder / path.name)

    def read(self, name):
        return c.load(self.folder / name)

    def write(self, name, value):
        (self.folder / name).write_text(json.dumps(value, allow_nan=False) + "\n")

    def mutate(self, name, edit, binding=None):
        value = self.read(name)
        edit(value)
        self.write(name, value)
        if binding:
            layer = self.read("candidate-auto.json")
            layer["sourceSha256"][binding] = c.digest((self.folder / name).read_bytes())
            self.write("candidate-auto.json", layer)
        if binding == "sourceEligibility":
            self.sync_closeout()

    def sync_closeout(self):
        """改写 L1 报告后，收口夹具按新报告原字节重新绑定；专测收口不符时直接改收口记录。"""
        raw = (self.folder / "source-eligibility.json").read_bytes()
        report, closeout = c.decode(raw), self.read("p6-closeout.json")
        closeout.update(evaluationId=report["evaluationId"], evaluationVersion=report["version"],
                        modelSha256=report["modelSha256"], evaluationPlanSha256=report["evaluationPlanSha256"],
                        gates=report["gates"], classEligibility=report["classEligibility"])
        closeout["evidenceSha256"]["l1Report"] = c.digest(raw)
        self.write("p6-closeout.json", closeout)

    def args(self, auto=True):
        result = {"candidate_layer": self.folder / ("candidate-auto.json" if auto else "candidate-alert.json"),
                  "policy_preview": self.folder / "policy-preview.json",
                  "rules_comparison": self.folder / "rules-comparison.json",
                  "deployment_binding": self.folder / "deployment-binding.json",
                  "evaluation_plan": self.folder / "evaluation-plan.json",
                  "protection_set": self.folder / "protection-set.json"}
        if auto:
            result.update(source_eligibility=self.folder / "source-eligibility.json",
                          evaluated_policy=self.folder / "evaluated-policy.json",
                          closeout=self.folder / "p6-closeout.json")
        return result

    def rejects(self, message, auto=True):
        with self.assertRaisesRegex(c.PolicyError, message):
            c.compose_files(**self.args(auto))

    def test_generated_rule_only_policy_matches_fixture(self):
        policy = c.compose_files(**self.args())
        self.assertEqual(self.read("composed-policy.json"), policy)
        self.assertTrue(policy["rulePolicies"][0]["autoEligible"])
        self.assertFalse(policy["familyPolicies"][0]["modelAutoEligible"])

    def test_no_report_all_sources_alert_only(self):
        policy = c.compose_files(**self.args(False))
        self.assertEqual(self.read("evaluated-policy.json"), policy)
        self.assertEqual("alert_only", policy["mode"])
        self.assertFalse(any(row["autoEligible"] or row["modelAutoEligible"] for row in policy["familyPolicies"]))
        self.assertFalse(any(row["autoEligible"] for row in policy["rulePolicies"]))

    def test_model_only_eligible_never_enables_rule(self):
        self.mutate("candidate-auto.json", lambda v: (v["familyPolicies"][0].update(modelAutoRequested=True),
                                                      v["rulePolicies"][0].update(autoRequested=False)))
        def model_only(report):
            entry = report["classEligibility"]["port_scan"]
            entry["modelOnly"]["offlineEligible"] = True
            entry["ruleOnly"]["scan-ports"]["offlineEligible"] = False
        self.mutate("source-eligibility.json", model_only, "sourceEligibility")
        policy = c.compose_files(**self.args())
        self.assertTrue(policy["familyPolicies"][0]["modelAutoEligible"])
        self.assertFalse(policy["rulePolicies"][0]["autoEligible"])

    def test_no_report_rejects_model_request(self):
        self.mutate("candidate-alert.json", lambda v: v["familyPolicies"][0].update(modelAutoRequested=True))
        self.rejects("无报告却请求可自动", False)

    def test_no_report_rejects_rule_request(self):
        self.mutate("candidate-alert.json", lambda v: v["rulePolicies"][0].update(autoRequested=True))
        self.rejects("无报告却请求可自动", False)

    def test_missing_deployment_field(self):
        self.mutate("deployment-binding.json", lambda v: v.pop("maxTtlSeconds"))
        self.rejects("字段缺失或未知")

    def test_missing_frozen_field(self):
        self.mutate("candidate-auto.json", lambda v: v.pop("episodeSeconds"))
        self.rejects("字段缺失或未知")

    def test_source_byte_hash_mismatch(self):
        with (self.folder / "policy-preview.json").open("a") as stream:
            stream.write(" ")
        self.rejects("源文件哈希不符: policyPreview")

    def test_protection_hash_mismatch(self):
        self.mutate("protection-set.json", lambda v: v.update(protectedServicePorts=[23]))
        self.rejects("保护集哈希不符")

    def test_plan_hash_mismatch(self):
        self.mutate("candidate-auto.json", lambda v: v.update(evaluationPlanSha256="0" * 64))
        self.rejects("评价计划哈希不符")

    def test_feature_profile_hash_mismatch(self):
        self.mutate("candidate-auto.json", lambda v: v["sourceSha256"].update(featureProfile="0" * 64))
        self.rejects("源文件哈希不符: featureProfile")

    def test_incomplete_and_duplicate_categories(self):
        for rows in (self.read("candidate-auto.json")["familyPolicies"][:3],
                     [self.read("candidate-auto.json")["familyPolicies"][0]] * 4):
            with self.subTest(rows=len(rows)):
                self.mutate("candidate-auto.json", lambda v: v.update(familyPolicies=rows))
                self.rejects("类别必须完整且唯一")

    def test_threshold_out_of_range(self):
        self.mutate("candidate-auto.json", lambda v: v["familyPolicies"][0].update(alertThreshold=1.1))
        self.mutate("policy-preview.json", lambda v: v["classes"]["port_scan"]["parameters"].update(alertThreshold=1.1), "policyPreview")
        self.rejects("Schema")

    def test_threshold_reversal(self):
        self.mutate("candidate-auto.json", lambda v: v["familyPolicies"][0].update(alertThreshold=0.95))
        self.mutate("policy-preview.json", lambda v: v["classes"]["port_scan"]["parameters"].update(alertThreshold=0.95), "policyPreview")
        self.rejects("类别阈值越界")

    def test_global_threshold_reversal(self):
        self.mutate("candidate-auto.json", lambda v: v.update(autoThreshold=0.5))
        self.rejects("全局阈值越界")

    def test_invalid_scope(self):
        self.mutate("candidate-auto.json", lambda v: v["familyPolicies"][0].update(scope="peer_service"))
        self.rejects("非法类别作用域")

    def test_report_source_contradiction(self):
        self.mutate("source-eligibility.json", lambda v: v["classEligibility"]["port_scan"].update(offlineEligible=False), "sourceEligibility")
        self.rejects("类别与来源开关矛盾")

    def test_model_request_cannot_borrow_rule_eligibility(self):
        self.mutate("candidate-auto.json", lambda v: v["familyPolicies"][0].update(modelAutoRequested=True))
        self.rejects("模型请求与来源资格矛盾")

    def test_rule_request_cannot_borrow_model_eligibility(self):
        def change(v):
            entry = v["classEligibility"]["port_scan"]
            entry["modelOnly"]["offlineEligible"] = True
            entry["ruleOnly"]["scan-ports"]["offlineEligible"] = False
        self.mutate("source-eligibility.json", change, "sourceEligibility")
        self.rejects("规则请求与来源资格矛盾")

    def test_partial_report_rejected_even_when_source_disabled(self):
        self.mutate("source-eligibility.json", lambda v: v["classEligibility"]["dos_slow"].pop("modelOnly"), "sourceEligibility")
        self.rejects("modelOnly")

    def test_extra_rule_qualification_rejected(self):
        self.mutate("source-eligibility.json", lambda v: v["classEligibility"]["dos_slow"]["ruleOnly"].update(extra={"offlineEligible":True}), "sourceEligibility")
        self.rejects("报告规则来源不完整或多余")

    def test_p6_source_alias_is_checked_when_present(self):
        def add_alias(v):
            v["sourceEligibility"] = {family: {"model": row["modelOnly"], "rules": row["ruleOnly"]}
                                      for family, row in v["classEligibility"].items()}
        self.mutate("source-eligibility.json", add_alias, "sourceEligibility")
        self.assertEqual(self.read("composed-policy.json"), c.compose_files(**self.args()))
        self.mutate("source-eligibility.json", lambda v: v["sourceEligibility"]["port_scan"]["model"].update(offlineEligible=True), "sourceEligibility")
        self.rejects("分来源报告别名矛盾")

    def test_report_binding_mismatch(self):
        self.mutate("source-eligibility.json", lambda v: v.update(decisionPolicySha256="0" * 64), "sourceEligibility")
        self.rejects("报告策略哈希不符")

    def test_invalid_evaluation_id_list_rejected(self):
        self.mutate("evaluation-plan.json", lambda v: v.update(evaluationIds="synthetic-p6-l1"), "evaluationPlan")
        digest = c.digest((self.folder / "evaluation-plan.json").read_bytes())
        self.mutate("candidate-auto.json", lambda v: v.update(evaluationPlanSha256=digest))
        self.mutate("source-eligibility.json", lambda v: v.update(evaluationPlanSha256=digest), "sourceEligibility")
        self.rejects("评价 ID 清单无效")

    def test_report_model_mismatch(self):
        self.mutate("source-eligibility.json", lambda v: v.update(modelSha256="0" * 64), "sourceEligibility")
        self.rejects("报告模型哈希不符")

    def test_changed_frozen_model_id_rejected(self):
        self.mutate("candidate-auto.json", lambda v: v.update(modelId="00000000-0000-4000-8000-000000000099"))
        self.rejects("冻结策略语义不一致")

    def test_failed_gate_rejects_auto(self):
        self.mutate("source-eligibility.json", lambda v: v["gates"].update(G2=False), "sourceEligibility")
        self.rejects("G1/G2 未通过")

    def test_auto_requires_completed_closeout_for_same_report(self):
        args = self.args()
        args.pop("closeout")
        with self.assertRaisesRegex(c.PolicyError, "P6 收口记录"):
            c.compose_files(**args)
        self.mutate("p6-closeout.json", lambda v: v.update(completed=False))
        self.rejects("P6 收口未完成")

    def test_closeout_bound_to_other_report_rejected(self):
        self.mutate("p6-closeout.json", lambda v: v["evidenceSha256"].update(l1Report="0" * 64))
        self.rejects("未绑定该 L1 报告")

    def test_closeout_disagreeing_with_report_rejected(self):
        for key, value in (("evaluationId", "other"), ("modelSha256", "4" * 64)):
            with self.subTest(key=key):
                self.setUp()
                self.mutate("p6-closeout.json", lambda v: v.update({key: value}))
                self.rejects("收口记录与报告不一致")

    def test_closeout_without_report_rejected(self):
        args = self.args(False)
        args["closeout"] = self.folder / "p6-closeout.json"
        with self.assertRaisesRegex(c.PolicyError, "须与 L1 报告同时提供"):
            c.compose_files(**args)

    def test_invalid_protection_set_structure_rejected(self):
        for edit in (lambda v: v.update(extra=True), lambda v: v.update(protectedServicePorts=[0]),
                     lambda v: v.update(protectedServicePorts=[True]),
                     lambda v: v.update(protectedServicePorts=list(range(1000, 1126)))):
            with self.subTest():
                self.setUp()
                self.mutate("protection-set.json", edit)
                self.rejects("保护集结构|protection-set")

    def test_family_alert_threshold_must_match_global_when_not_per_class(self):
        def drop(value):
            for item in value["classes"].values():
                item["parameters"].pop("alertThreshold")
        self.mutate("policy-preview.json", drop, "policyPreview")
        c.compose_files(**self.args())
        self.mutate("candidate-auto.json", lambda v: v["familyPolicies"][0].update(alertThreshold=0.7))
        self.rejects("alertThreshold")

    def test_report_or_preview_missing_class_rejected(self):
        self.mutate("source-eligibility.json", lambda v: v["classEligibility"].pop("dos_slow"), "sourceEligibility")
        with self.assertRaises(c.PolicyError):
            c.compose_files(**self.args())
        self.setUp()
        self.mutate("policy-preview.json", lambda v: v["classes"].pop("dos_slow"), "policyPreview")
        self.rejects("preview 类别不完整")

    def test_legacy_rule_conditions_are_not_dropped(self):
        self.mutate("rules-comparison.json", lambda v: v["rules"][0].update(servicePorts=[22], minElapsedMs=10000), "rulesComparison")
        self.rejects("旧规则须重新审计")

    def test_missing_rule_operator_is_not_invented(self):
        self.mutate("rules-comparison.json", lambda v: v["rules"][0].pop("operator"), "rulesComparison")
        self.rejects("旧规则须重新审计")

    def test_invalid_rule_feature(self):
        self.mutate("candidate-auto.json", lambda v: v["rulePolicies"][0].update(field="parentConnectionId"))
        self.mutate("rules-comparison.json", lambda v: v["rules"][0].update(field="parentConnectionId"), "rulesComparison")
        self.rejects("规则字段不在特征档案")

    def test_unknown_rule_family_rejected_not_silently_dropped(self):
        self.mutate("candidate-auto.json", lambda v: v["rulePolicies"][0].update(family="unknown"))
        self.rejects("未知规则类别")

    def test_rejects_duplicate_rule_id(self):
        self.mutate("candidate-auto.json", lambda v: v["rulePolicies"].append(copy.deepcopy(v["rulePolicies"][0])))
        self.rejects("规则 ID 无效或重复")

    def test_direct_policy_rejects_contradictory_model_switch(self):
        policy = self.read("composed-policy.json")
        policy["familyPolicies"][0].update(autoEligible=False, modelAutoEligible=True)
        with self.assertRaisesRegex(c.PolicyError, "来源开关矛盾"):
            c.validate_policy(policy)

    def test_strict_json(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}', b'{"x":"\\ud800"}'):
            with self.subTest(raw=raw), self.assertRaises(c.PolicyError):
                c.decode(raw)

    def test_inspect_portable_research_fixture(self):
        policy = {"alertThreshold":0.6,"maxEvidenceAgeMs":10000,"policyVersion":"research",
                  "automaticExecutionEnabled":False,"classes":{},"ruleSourceVersion":"old","ruleVersion":"old","rules":[]}
        self.write("research.json", policy)
        result = c.inspect(self.folder / "research.json")
        self.assertEqual(21, result["count"])
        self.assertEqual(20, sum("required property" in e["message"] for e in result["schemaErrors"]))

    def cli(self, output):
        args = [sys.executable, "-B", str(c.ROOT / "scripts/p7/compose_policy.py"), "compose"]
        for key, value in self.args().items():
            args += ["--" + key.replace("_", "-"), str(value)]
        return subprocess.run(args + ["--output", str(output)], capture_output=True, text=True)

    def test_cli_generates_and_never_overwrites(self):
        output = self.folder / "generated.json"
        result = self.cli(output)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(self.read("composed-policy.json"), c.load(output))
        original = output.read_bytes()
        self.assertEqual(2, self.cli(output).returncode)
        self.assertEqual(original, output.read_bytes())

    def test_cli_failure_leaves_no_output(self):
        self.mutate("deployment-binding.json", lambda v: v.pop("maxTtlSeconds"))
        output = self.folder / "not-created.json"
        result = self.cli(output)
        self.assertEqual(2, result.returncode)
        self.assertNotIn("Traceback", result.stderr)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
