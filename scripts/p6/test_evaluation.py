"""P6 口径与测试访问边界回归；全部使用合成样本，不打开真实 test。"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

import numpy as np

from evaluate import ROOT, CODE, frozen_rules, inputs, load_registered, metadata, read, run, sha, write
from metrics import CLASSES, first_decisions, gates_and_eligibility, report
from runtime import compare, predict
from access_multiclass_test import access
from multiclass_common import PLAN


PLAN_METRICS = {"gates": {"G1": {"attackDetectionMin": .90, "falsePositiveRateMax": .02},
                          "G2": {"macroF1Min": .80}},
                "automaticEligibility": {"recallMin": .8, "precisionMin": .9}}


class MetricsTest(unittest.TestCase):
    def test_first_hit_not_highest_or_final_score(self):
        scores = np.array([[.99, 0, 0, .99, 0], [.95, 0, .95, 0, 0], [.1, 0, 0, .1, 0]])
        first, selected = first_decisions(["p"] * 3, [30, 20, 40], [0] * 3,
                                          ["a", "b", "c"], scores, np.zeros((3, 4), bool), .9)
        self.assertEqual(first.tolist(), [1])
        self.assertEqual(selected[0].tolist(), [2])

    def test_repeated_snapshots_and_continuations_count_once(self):
        scores = np.tile([.9, .9, 0, 0, 0], (4, 1))
        first, selected = first_decisions(["p", "p", "q", "p"], [1, 2, 3, 4], [0, 1, 0, 0],
                                          ["a", "b", "c", "d"], scores, np.zeros((4, 4), bool), .9)
        self.assertEqual(len(first), 2)
        self.assertEqual(selected[0].tolist(), [1, 1])

    def test_same_observation_model_precedes_rule(self):
        _, selected = first_decisions(["p"], [1], [0], ["a"], np.array([[.9, 0, .9, 0, 0]]),
                                      np.array([[True, False, False, False]]), .9)
        self.assertEqual([item.tolist() for item in selected], [[2], [1], [2]])

    def test_earlier_rule_remains_combined_first_alert(self):
        _, selected = first_decisions(["p", "p"], [1, 2], [0, 1], ["a", "b"],
                                      np.array([[.1, .1, 0, 0, 0], [.9, 0, .9, 0, 0]]),
                                      np.array([[True, False, False, False], [False] * 4]), .9)
        self.assertEqual(selected[2].tolist(), [1])

    def test_normal_sources_are_equal_weight_not_pooled(self):
        labels = np.array([0] * 10 + [0] * 100 + [1, 2, 3, 4])
        predicted = labels.copy()
        predicted[0] = 1
        sources = ["internal"] * 10 + ["website"] * 100 + ["internal"] * 4
        result = report(labels, predicted, sources, ["scenario"] * len(labels), l1=True)
        self.assertAlmostEqual(result["falsePositiveRate"], .05)
        self.assertEqual(result["normalSourceFpr"]["website"]["rate"], 0)

    def test_attack_detection_equal_weight_allows_wrong_attack_class(self):
        labels = np.array([0, 0, 1, 2] + [3] * 100 + [4])
        predicted = labels.copy()
        predicted[2] = 2
        predicted[-1] = 0
        result = report(labels, predicted, ["internal", "website"] + ["internal"] * 103,
                        ["scenario"] * len(labels), l1=True)
        self.assertEqual(result["attackDetection"], .75)
        self.assertEqual(result["perClass"]["port_scan"]["recall"], 0)

    def test_missing_l1_denominator_cannot_pass(self):
        result = report([0, 1, 2, 3, 4], [0, 1, 2, 3, 4], ["internal"] * 5, ["s"] * 5, l1=True)
        gates, _ = gates_and_eligibility(result, PLAN_METRICS)
        self.assertIsNone(result["falsePositiveRate"])
        self.assertFalse(gates["G1"])
        self.assertFalse(gates["G2"])

    def test_offline_pass_does_not_enable_actions(self):
        result = report([0, 0, 1, 2, 3, 4], [0, 0, 1, 2, 3, 4],
                        ["internal", "website"] + ["internal"] * 4, ["s"] * 6, l1=True)
        gates, eligibility = gates_and_eligibility(result, PLAN_METRICS)
        self.assertTrue(gates["G1"] and gates["G2"])
        self.assertTrue(all(item["offlineEligible"] for item in eligibility.values()))
        self.assertTrue(all(not item["automaticExecutionEnabled"] for item in eligibility.values()))

    def test_l3_subset_does_not_invent_other_attack_detection(self):
        result = report([0, 4], [1, 4], ["internal"] * 2, ["s"] * 2)
        self.assertIsNone(result["attackDetectionByClass"]["port_scan"])
        self.assertEqual(result["attackDetection"], 1)
        self.assertEqual(result["falsePositiveRate"], 1)


class InputTest(unittest.TestCase):
    def setUp(self):
        self.feature = read(ROOT / "docs/contracts/feature-profile.json")
        features = {name.split(".")[1]: 1 for name in self.feature["numericFeatures"] if name.startswith("features.")}
        contexts = [{"windowSeconds": window, **{name.split(".")[2]: 1 for name in self.feature["numericFeatures"]
                                               if name.startswith(f"contexts.{window}.")}} for window in (1, 5, 30)]
        self.row = {"label": "normal", "input": {"features": features, "contexts": contexts,
                                                 "transport": "tcp", "direction": "inbound", "serviceClass": "web"}}
        self.pre = {"vocabularies": [["tcp"], ["inbound"], ["web"]]}

    def test_nullable_mask_and_input_identity_exclusion(self):
        self.row["input"]["features"]["iatMeanUs"] = None
        baseline = inputs([self.row], self.feature, self.pre)
        self.row.update({"parentConnectionId": "identity", "label": "dos_slow", "activityId": "label"})
        other = inputs([self.row], self.feature, self.pre)
        self.assertTrue(all(np.array_equal(baseline[name], other[name]) for name in baseline))
        self.assertEqual(baseline["numeric_missing"][0, 9], 1)
        self.assertEqual(baseline["categorical_codes"].dtype, np.int64)

    def test_required_null_rejected(self):
        self.row["input"]["features"]["elapsedMs"] = None
        with self.assertRaises(ValueError):
            inputs([self.row], self.feature, self.pre)

    def test_nonfinite_or_negative_rejected(self):
        for bad in (float("nan"), float("inf"), -1):
            self.row["input"]["features"]["elapsedMs"] = bad
            with self.assertRaises(ValueError):
                inputs([self.row], self.feature, self.pre)

    def test_missing_window_rejected(self):
        self.row["input"]["contexts"].pop()
        with self.assertRaises(ValueError):
            inputs([self.row], self.feature, self.pre)

    def test_unknown_category_maps_to_frozen_unknown_code(self):
        self.row["input"]["serviceClass"] = "other"
        self.assertEqual(inputs([self.row], self.feature, self.pre)["categorical_codes"][0, 2], 0)

    def test_rules_respect_service_gate_and_missing_mask(self):
        feed = inputs([self.row], self.feature, self.pre)
        policy = {"rules": [{"field": "contexts.30.peerFlowStarts", "threshold": 1,
                              "servicePorts": [21, 22], "minElapsedMs": 0}]}
        self.assertFalse(frozen_rules(feed, [{"servicePort": 80}], self.feature, policy).any())
        self.assertTrue(frozen_rules(feed, [{"servicePort": 22}], self.feature, policy).any())
        feed["numeric_missing"][0, self.feature["numericFeatures"].index("contexts.30.peerFlowStarts")] = 1
        self.assertFalse(frozen_rules(feed, [{"servicePort": 22}], self.feature, policy).any())

    def test_current_rule_operators_and_missing_mask(self):
        feed = inputs([self.row], self.feature, self.pre)
        operators = ("gte", "gt", "lte", "lt", "eq")
        policy = {"familyPolicies": [], "rulePolicies": [
            {"ruleId": name, "family": "port_scan", "field": "contexts.30.peerFlowStarts",
             "operator": name, "threshold": 1} for name in operators]}
        self.assertEqual(frozen_rules(feed, [{"servicePort": 80}], self.feature, policy).tolist(),
                         [[True, False, True, False, True]])
        feed["numeric_missing"][0, self.feature["numericFeatures"].index("contexts.30.peerFlowStarts")] = 1
        self.assertFalse(frozen_rules(feed, [{"servicePort": 80}], self.feature, policy).any())


class RuntimeTest(unittest.TestCase):
    def test_small_probability_error_cannot_hide_threshold_flip(self):
        result = compare(np.array([[.9, .9, 0, 0, 0]]), np.array([[.899999, .899999, 0, 0, 0]]), .9)
        self.assertLess(result["maxProbabilityAbsError"], 1e-4)
        self.assertFalse(result["passed"])

    def test_family_flip_rejected(self):
        result = compare(np.array([[1, .50001, .49999, 0, 0]]), np.array([[1, .49999, .50001, 0, 0]]), .9)
        self.assertFalse(result["passed"])

    def test_invalid_onnx_output_rejected(self):
        class Invalid:
            def run(self, names, feed):
                return np.array([[float("nan")]]), np.zeros((1, 4))
        with self.assertRaises(ValueError):
            predict(Invalid(), {"numeric_values": np.ones((1, 43))})


class AccessTest(unittest.TestCase):
    def fixture(self, root):
        folder = root / "test"
        folder.mkdir()
        (folder / "dataset.jsonl").write_text('{"synthetic":true}\n')
        (root / "candidate.onnx").write_bytes(b"synthetic")
        write(root / "manifest.json", {"datasetSha256": {"test": sha(folder / "dataset.jsonl")}})
        write(root / "plan.json", {"plan": PLAN, "stage": "P6", "maxTestEvaluations": 3,
                                    "candidateSha256": sha(root / "candidate.onnx"),
                                    "splitManifestSha256": sha(root / "manifest.json"),
                                    "testDatasetSha256": sha(folder / "dataset.jsonl"),
                                    "evaluationIds": ["p6-l1-01", "p6-l1-02", "p6-l1-03"]})
        (root / "test-access.jsonl").write_text("")
        return argparse.Namespace(candidate=root / "candidate.onnx", evaluation_plan=root / "plan.json",
                                  evaluation_id="p6-l1-01", change_record=None)

    def cleanup_permissions(self, root):
        if os.name != "nt":
            os.chmod(root / "test", 0o700)
            os.chmod(root / "test/dataset.jsonl", 0o600)

    def test_failed_hash_consumes_attempt_and_reseals(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self.fixture(root)
            (root / "test/dataset.jsonl").write_text('{"changed":true}\n')
            try:
                with self.assertRaises(ValueError):
                    access(args, root)
                events = [json.loads(value) for value in (root / "test-access.jsonl").read_text().splitlines()]
                self.assertEqual(sum(value["event"] == "access_started" for value in events), 1)
                if os.name != "nt":
                    self.assertEqual((root / "test").stat().st_mode & 0o777, 0)
                    os.chmod(root / "test", 0o700)
                    self.assertEqual((root / "test/dataset.jsonl").stat().st_mode & 0o777, 0)
                    os.chmod(root / "test", 0)
                with self.assertRaises(ValueError):
                    access(args, root)
            finally:
                self.cleanup_permissions(root)

    def test_repeat_requires_registered_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self.fixture(root)
            (root / "test-access.jsonl").write_text(json.dumps({"event": "access_started", "evaluationId": "p6-l1-01"}) + "\n")
            args.evaluation_id = "p6-l1-02"
            with self.assertRaises(ValueError):
                access(args, root)
            entries = [json.loads(value) for value in (root / "test-access.jsonl").read_text().splitlines()]
            self.assertEqual(sum(value["event"] == "access_started" for value in entries), 1)

    def test_plan_test_hash_mismatch_denied_before_open(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self.fixture(root)
            plan = read(args.evaluation_plan)
            plan["testDatasetSha256"] = "0" * 64
            args.evaluation_plan.write_text(json.dumps(plan))
            with self.assertRaises(ValueError):
                access(args, root)
            self.assertNotIn("access_started", (root / "test-access.jsonl").read_text())

    def test_unsupported_fourth_evaluation_denied(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self.fixture(root)
            args.evaluation_id = "p6-l1-04"
            with self.assertRaises(ValueError):
                access(args, root)
            self.assertNotIn("access_started", (root / "test-access.jsonl").read_text())

    def test_real_subprocess_stream_reseals(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self.fixture(root)
            candidate = root / "candidate"
            candidate.mkdir()
            (candidate / "model.onnx").write_bytes(args.candidate.read_bytes())
            (candidate / "evaluation-plan.json").write_bytes(args.evaluation_plan.read_bytes())
            registration = {"frozen": str(root), "candidate": str(candidate), "layer": "L1",
                            "evaluationId": args.evaluation_id, "evaluationOrdinal": 1,
                            "datasetSha256": read(root / "manifest.json")["datasetSha256"]["test"]}
            try:
                self.assertEqual(load_registered(registration, root), [{"synthetic": True}])
                if os.name != "nt":
                    self.assertEqual((root / "test").stat().st_mode & 0o777, 0)
                self.assertIn("access_completed", (root / "test-access.jsonl").read_text())
            finally:
                self.cleanup_permissions(root)


class PipelineTest(unittest.TestCase):
    def fixture(self, root):
        base = InputTest()
        base.setUp()
        observations, rows = [], []
        labels = ("normal", "normal", *CLASSES[1:])
        for index, label in enumerate(labels):
            identifier, parent = str(uuid.uuid4()), str(uuid.uuid4())
            value = json.loads(json.dumps(base.row))
            value["input"]["features"]["elapsedMs"] = index
            value.update({"observationId": identifier, "parentConnectionId": parent,
                          "label": label, "activityId": "synthetic", "profile": "flow-final-v1",
                          "websiteSupplement": index == 1})
            rows.append(value)
            observations.append({"contractVersion": "host-guard/5.0.0-rc.2", **value["input"],
                                 "observationId": identifier, "parentConnectionId": parent,
                                 "profile": value["profile"], "asOf": "2026-10-07T00:00:01Z",
                                 "snapshotIndex": 0, "servicePort": 80})
        extract = root / "extract"
        source = extract / "synthetic"
        source.mkdir(parents=True)
        (source / "observations.jsonl").write_text("".join(json.dumps(row) + "\n" for row in observations))
        write(source / "extraction.json", {"observationsSha256": sha(source / "observations.jsonl")})
        sources = {"synthetic/observations.jsonl": {"observationsSha256": sha(source / "observations.jsonl"),
                                                   "proofSha256": sha(source / "extraction.json")}}
        return rows, {"extract": str(extract), "observationSources": sources}, base

    def test_metadata_missing_or_tampered_refuses_guessing(self):
        with tempfile.TemporaryDirectory() as temporary:
            rows, registration, _ = self.fixture(Path(temporary))
            self.assertEqual(len(metadata(rows, registration)), len(rows))
            rows[0]["parentConnectionId"] = str(uuid.uuid4())
            with self.assertRaises(ValueError):
                metadata(rows, registration)

    def test_source_hash_change_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rows, registration, _ = self.fixture(root)
            with (root / "extract/synthetic/observations.jsonl").open("a") as stream:
                stream.write("{}\n")
            with self.assertRaises(ValueError):
                metadata(rows, registration)

    def test_synthetic_full_access_report_and_runtime_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data, source_registration, base = self.fixture(root)
            frozen, candidate, output = [root / name for name in ("frozen", "candidate", "output")]
            (frozen / "test").mkdir(parents=True)
            candidate.mkdir()
            output.mkdir()
            (frozen / "test/dataset.jsonl").write_text("".join(json.dumps(row) + "\n" for row in data))
            counts = {name: sum(row["label"] == name for row in data) for name in CLASSES}
            write(frozen / "manifest.json", {"datasetSha256": {"test": sha(frozen / "test/dataset.jsonl")},
                                             "snapshotCounts": {"test": counts}, "connectionCounts": {"test": counts},
                                             "exclusions": {}, "limitations": ["synthetic only"]})
            (candidate / "model.onnx").write_bytes(b"synthetic-model")
            (candidate / "checksums.json").write_text("{}")
            plan = {**PLAN_METRICS, "plan": PLAN, "stage": "P6", "maxTestEvaluations": 3,
                    "evaluationVersion": "host-guard-evaluation/synthetic-2",
                    "candidateSha256": sha(candidate / "model.onnx"),
                    "splitManifestSha256": sha(frozen / "manifest.json"),
                    "testDatasetSha256": sha(frozen / "test/dataset.jsonl"),
                    "evaluationIds": ["p6-l1-01", "p6-l1-02", "p6-l1-03"]}
            write(candidate / "evaluation-plan.json", plan)
            write(candidate / "decision-policy.json", {"synthetic": True})
            write(candidate / "model-manifest.json", {"synthetic": True})
            (frozen / "test-access.jsonl").write_text("")
            registration = {**source_registration, "layer": "L1", "evaluationId": "p6-l1-01", "evaluationOrdinal": 1,
                            "candidate": str(candidate), "frozen": str(frozen),
                            "datasetSha256": plan["testDatasetSha256"],
                            "candidateChecksumsSha256": sha(candidate / "checksums.json"),
                            "datasetManifestSha256": sha(frozen / "manifest.json"),
                            "evaluationPlanSha256": sha(candidate / "evaluation-plan.json"),
                            "evaluationVersion": plan["evaluationVersion"],
                            "decisionPolicySha256": sha(candidate / "decision-policy.json"),
                            "modelManifestSha256": sha(candidate / "model-manifest.json"),
                            "candidateSchemaSha256": sha(ROOT / "docs/contracts/model-manifest.schema.json"),
                            "policySchemaSha256": sha(ROOT / "docs/contracts/decision-policy.schema.json"),
                            "priorAccessLogSha256": sha(frozen / "test-access.jsonl"),
                            "codeSha256": {name: sha(ROOT / name) for name in CODE},
                            "packages": {"numpy": np.__version__, "onnxruntime": __import__("onnxruntime").__version__,
                                         "lightgbm": "test"}}
            write(output / "registration.json", registration)
            write(output / "registration-receipt.json", {"sha256": sha(output / "registration.json")})
            scores = np.array([[.01, .0025, .0025, .0025, .0025]] * 2 +
                              [[.99, *[.99 if i == c else 0 for i in range(4)]] for c in range(4)])
            policy = {"alertThreshold": .9,
                      "familyPolicies": [{"family": name, "alertThreshold": .9} for name in CLASSES[1:]],
                      "rulePolicies": [
                          {"ruleId": "scan-exact", "family": "port_scan", "field": "features.elapsedMs",
                           "operator": "eq", "threshold": 2},
                          {"ruleId": "scan-overbroad", "family": "port_scan", "field": "features.elapsedMs",
                           "operator": "gte", "threshold": 0}]}
            try:
                with patch("evaluate.checked_candidate", return_value=({}, plan, base.feature, policy, base.pre)), \
                     patch("evaluate.session", return_value=object()), \
                     patch("evaluate.predict", return_value=scores), \
                     patch("evaluate.framework_predict", return_value=scores), \
                     patch("evaluate.time.perf_counter", return_value=1.0), \
                     patch.dict("sys.modules", {"lightgbm": SimpleNamespace(__version__="test")}):
                    run(argparse.Namespace(registration=output / "registration.json"))
                result = read(output / "report.json")
                self.assertEqual(result["testEvaluationsUsed"], 1)
                self.assertTrue(result["gates"]["G1"] and result["gates"]["G2"])
                self.assertEqual(result["version"], plan["evaluationVersion"])
                rules = result["classEligibility"]["port_scan"]["ruleOnly"]
                self.assertTrue(rules["scan-exact"]["offlineEligible"])
                self.assertFalse(rules["scan-overbroad"]["offlineEligible"])
                self.assertEqual(result["ruleOnlyById"]["scan-exact"]["perClass"]["port_scan"]["precision"], 1)
                self.assertLess(result["ruleOnlyById"]["scan-overbroad"]["perClass"]["port_scan"]["precision"], .9)
                self.assertEqual(result["sourceEligibility"]["port_scan"]["rules"], rules)
                self.assertFalse(result["automaticExecutionEnabled"])
                self.assertIsNone(result["snapshotsPerSecond"])
                self.assertTrue((output / "runtime-bundle/feed.npz").exists())
                self.assertFalse((output / ".evaluation-lock").exists())
                if os.name != "nt":
                    self.assertEqual((frozen / "test").stat().st_mode & 0o777, 0)
            finally:
                AccessTest().cleanup_permissions(frozen)


if __name__ == "__main__":
    unittest.main()
