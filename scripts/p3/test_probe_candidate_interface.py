"""T1.7 接口探针回归：只用合成小图，不读取冻结数据、test 或真实制品。"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

import numpy as np

HAS_ONNX = all(importlib.util.find_spec(name) for name in ("onnx", "onnxruntime", "jsonschema"))
if HAS_ONNX:
    import onnx
    from onnx import TensorProto, helper, numpy_helper

    import probe_candidate_interface as probe
    from freeze_multiclass_candidate import converted_model

NUMERIC = json.loads(Path(__file__).resolve().parents[2].joinpath("docs/contracts/feature-profile.json")
                     .read_text(encoding="utf-8"))["numericFeatures"]


@unittest.skipUnless(HAS_ONNX, "需要 onnx、onnxruntime 与 jsonschema")
class SourceBindingTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="probe-binding-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.summary_path = self.root / "reproduction-summary.json"
        self.ledger = self.root / "fit-ledger-round2.jsonl"
        for filename in ("model.onnx", "preprocessing.json", "code-manifest.json"):
            (self.root / filename).write_text("{}", encoding="utf-8")
        self.summary = {"run": "synthetic-run", "target": "ablation-no-host-context",
                        "featureSet": "no_host_context", "fit": {"algorithm": "lightgbm"},
                        "finalTestRead": False, "candidateOnly": True,
                        "artifacts": {name: probe.sha(self.root / name)
                                      for name in ("model.onnx", "preprocessing.json")},
                        "codeManifestSha256": probe.sha(self.root / "code-manifest.json")}
        probe.write(self.summary_path, self.summary)
        self.event = {"event": "fit-completed", "run": "synthetic-run", "target": self.summary["target"],
                      "summarySha256": probe.sha(self.summary_path)}
        self.ledger.write_text(json.dumps(self.event) + "\n", encoding="utf-8")

    def bind(self):
        return probe.source_binding(self.root, self.summary["target"],
                                    reproduction_summary=self.summary_path, fit_ledger=self.ledger)

    def test_reproduction_binds_artifacts_summary_and_ledger(self):
        result = self.bind()
        self.assertEqual(result["record"]["artifactSha256"], probe.sha(self.root / "model.onnx"))
        self.assertEqual(result["evidence"]["summarySha256"], probe.sha(self.summary_path))
        self.assertEqual(result["evidence"]["fitLedgerSha256"], probe.sha(self.ledger))

    def test_summary_hash_mismatch_is_rejected(self):
        self.ledger.write_text(json.dumps(self.event | {"summarySha256": "0" * 64}) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "摘要哈希"):
            self.bind()

    def test_missing_completed_record_is_rejected(self):
        self.ledger.write_text(json.dumps(self.event | {"event": "fit-reserved"}) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "fit-completed"):
            self.bind()

    def test_target_mismatch_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "目标名"):
            probe.source_binding(self.root, "another-model", reproduction_summary=self.summary_path,
                                 fit_ledger=self.ledger)
        self.ledger.write_text(json.dumps(self.event | {"target": "another-model"}) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "fit-completed"):
            self.bind()

    def test_artifact_hash_mismatch_is_rejected(self):
        (self.root / "preprocessing.json").write_text("changed", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "制品哈希"):
            self.bind()

    def test_duplicate_completed_record_is_rejected(self):
        self.ledger.write_text(json.dumps(self.event) + "\n" + json.dumps(self.event) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "唯一"):
            self.bind()

    def test_run_events_binding_is_preserved(self):
        events = self.root / "run-events.jsonl"
        record = {"name": self.summary["target"], "artifactSha256": probe.sha(self.root / "model.onnx"),
                  "featureSet": "no_host_context", "algorithm": "lightgbm"}
        events.write_text(json.dumps({"event": "fit-completed", "record": record}) + "\n", encoding="utf-8")
        probe.write(self.root / "experiment-plan.json", {"purpose": "synthetic-test"})
        result = probe.source_binding(self.root, self.summary["target"], run_events=events)
        self.assertEqual(result["record"], record)
        self.assertEqual(result["metricsPath"], self.root / "validation-metrics.json")


def wrapper_model(indices, categorical=None, numeric_width=43):
    """仿现行导出包装：43+3 输入，图内按 feature_indices 选列，线性层加 softmax 代替树。"""
    categorical = TensorProto.FLOAT if categorical is None else categorical
    width = 2 * len(indices) + 3
    weights = np.random.default_rng(7).normal(size=(width, 5)).astype(np.float32)
    nodes = [helper.make_node("Gather", ["numeric_values", "feature_indices"], ["values_selected"], axis=1),
             helper.make_node("Gather", ["numeric_missing", "feature_indices"], ["missing_selected"], axis=1)]
    category = "categorical_codes"
    if categorical == TensorProto.INT64:
        nodes.append(helper.make_node("Cast", ["categorical_codes"], ["category_float"], to=TensorProto.FLOAT))
        category = "category_float"
    nodes += [helper.make_node("Concat", ["values_selected", "missing_selected", category], ["features"], axis=1),
              helper.make_node("MatMul", ["features", "weights"], ["logits"]),
              helper.make_node("Softmax", ["logits"], ["probabilities"], axis=1),
              helper.make_node("Gather", ["probabilities", "normal_index"], ["normal"], axis=1),
              helper.make_node("Sub", ["one", "normal"], ["attack_score"]),
              helper.make_node("Gather", ["probabilities", "family_indices"], ["family_scores"], axis=1)]
    graph = helper.make_graph(
        nodes, "synthetic",
        [helper.make_tensor_value_info("numeric_values", TensorProto.FLOAT, [None, numeric_width]),
         helper.make_tensor_value_info("numeric_missing", TensorProto.FLOAT, [None, numeric_width]),
         helper.make_tensor_value_info("categorical_codes", categorical, [None, 3])],
        [helper.make_tensor_value_info("attack_score", TensorProto.FLOAT, [None, 1]),
         helper.make_tensor_value_info("family_scores", TensorProto.FLOAT, [None, 4])],
        initializer=[numpy_helper.from_array(np.asarray(indices, dtype=np.int64), "feature_indices"),
                     numpy_helper.from_array(weights, "weights"),
                     numpy_helper.from_array(np.asarray([0], dtype=np.int64), "normal_index"),
                     numpy_helper.from_array(np.asarray([1, 2, 3, 4], dtype=np.int64), "family_indices"),
                     numpy_helper.from_array(np.asarray([1.0], dtype=np.float32), "one")])
    model = helper.make_model(graph, opset_imports=[helper.make_operatorsetid("", 15)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    return model


def feed(rows=64):
    rng = np.random.default_rng(11)
    return {"numeric_values": rng.normal(size=(rows, 43)).astype(np.float32),
            "numeric_missing": (rng.random((rows, 43)) < .1).astype(np.float32),
            "categorical_codes": rng.integers(0, 4, size=(rows, 3)).astype(np.int64)}


@unittest.skipUnless(HAS_ONNX, "需要 onnx、onnxruntime 与 jsonschema")
class ProbeTest(unittest.TestCase):
    def setUp(self):
        self.hosts = probe.host_indices(NUMERIC)
        self.indices = [i for i in range(43) if i not in self.hosts]
        self.root = Path(tempfile.mkdtemp(prefix="t17-test-"))

    def export(self, model, name):
        source, target = self.root / f"{name}-15.onnx", self.root / f"{name}.onnx"
        onnx.save(model, source)
        converted_model(source, target)
        return target

    def test_host_fields_are_three_windows_by_two(self):
        self.assertEqual([NUMERIC[i].split(".", 1)[1] for i in self.hosts],
                         ["1.hostFlowStarts", "1.hostDistinctPeers", "5.hostFlowStarts", "5.hostDistinctPeers",
                          "30.hostFlowStarts", "30.hostDistinctPeers"])

    def test_float_categories_are_patched_without_changing_outputs(self):
        original = wrapper_model(self.indices)
        onnx.save(original, self.root / "original.onnx")
        patched = wrapper_model(self.indices)
        self.assertTrue(probe.patch_categorical(patched))
        path = self.export(patched, "patched")
        probe.check_contract(onnx.load(path))
        values = feed()
        old = probe.run(probe.session(self.root / "original.onnx"),
                        values | {"categorical_codes": values["categorical_codes"].astype(np.float32)})
        new = probe.run(probe.session(path), values)
        self.assertTrue(np.array_equal(old, new))

    def test_int64_input_is_left_unchanged(self):
        model = wrapper_model(self.indices, TensorProto.INT64)
        before = model.SerializeToString()
        self.assertFalse(probe.patch_categorical(model))
        self.assertEqual(before, model.SerializeToString())

    def test_contract_rejects_float_categories_wrong_width_and_old_opset(self):
        with self.assertRaisesRegex(ValueError, "categorical_codes"):
            probe.check_contract(onnx.load(self.export(wrapper_model(self.indices), "float")))
        with self.assertRaisesRegex(ValueError, "numeric_values"):
            probe.check_contract(onnx.load(self.export(
                wrapper_model([i for i in self.indices if i < 42], TensorProto.INT64, numeric_width=42), "narrow")))
        with self.assertRaisesRegex(ValueError, "opset"):
            probe.check_contract(wrapper_model(self.indices, TensorProto.INT64))

    def test_feature_selection_rejects_host_columns_and_graph_mismatch(self):
        model = wrapper_model(self.indices, TensorProto.INT64)
        preprocessing = {"featureSet": "no_host_context", "numericIndices": self.indices}
        self.assertEqual(probe.check_feature_selection(model, preprocessing, self.hosts)["excludedHostIndices"], self.hosts)
        with self.assertRaisesRegex(ValueError, "主机上下文"):
            probe.check_feature_selection(model, preprocessing | {"numericIndices": self.indices + [self.hosts[0]]},
                                          self.hosts)
        with self.assertRaisesRegex(ValueError, "feature_indices"):
            probe.check_feature_selection(model, preprocessing | {"numericIndices": self.indices[:-1]}, self.hosts)
        with self.assertRaisesRegex(ValueError, "主机上下文"):
            probe.check_feature_selection(model, preprocessing | {"featureSet": "full"}, self.hosts)

    def test_perturbation_touches_only_host_columns_and_detects_dependence(self):
        values = feed()
        others = [i for i in range(43) if i not in self.hosts]
        for variant in ("single_peer", "extreme_missing"):
            changed = probe.perturbed(values, self.hosts, variant)
            self.assertTrue(np.array_equal(changed["numeric_values"][:, others], values["numeric_values"][:, others]))
            self.assertTrue(np.array_equal(changed["numeric_missing"][:, others], values["numeric_missing"][:, others]))
            self.assertFalse(np.array_equal(changed["numeric_values"][:, self.hosts], values["numeric_values"][:, self.hosts]))
        free = probe.session(self.export(wrapper_model(self.indices, TensorProto.INT64), "free"))
        bound = probe.session(self.export(wrapper_model(list(range(43)), TensorProto.INT64), "bound"))
        changed = probe.perturbed(values, self.hosts, "extreme_missing")
        self.assertTrue(np.array_equal(probe.run(free, values), probe.run(free, changed)))
        self.assertFalse(np.array_equal(probe.run(bound, values), probe.run(bound, changed)))


if __name__ == "__main__":
    unittest.main()
