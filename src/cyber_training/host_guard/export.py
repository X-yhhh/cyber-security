"""导出三输入ONNX，在图内绑定训练预处理与独立校准；只写候选，不加载pickle。"""
from __future__ import annotations

import time

import numpy as np
import onnx
from onnx import TensorProto, helper, numpy_helper
import onnxruntime as ort
import torch

from .models import calibrated, predict


def _preprocessing(parameters):
    constants = []
    def constant(name, array):
        constants.append(numpy_helper.from_array(np.asarray(array), name)); return name
    one = constant("p3_one", np.float32(1))
    mean = constant("p3_mean", np.asarray(parameters["meanLog"], dtype=np.float32))
    scale = constant("p3_scale", np.asarray(parameters["scaleLog"], dtype=np.float32))
    indices = constant("p3_indices", np.asarray(parameters["indices"], dtype=np.int64))
    nodes = [helper.make_node("Add", ["numeric_values", one], ["p3_positive"]),
             helper.make_node("Log", ["p3_positive"], ["p3_log"]),
             helper.make_node("Equal", ["numeric_missing", one], ["p3_is_missing"]),
             helper.make_node("Where", ["p3_is_missing", mean, "p3_log"], ["p3_filled"]),
             helper.make_node("Sub", ["p3_filled", mean], ["p3_centered"]),
             helper.make_node("Div", ["p3_centered", scale], ["p3_scaled"]),
             helper.make_node("Gather", ["p3_scaled", indices], ["p3_selected"], axis=1),
             helper.make_node("Gather", ["numeric_missing", indices], ["p3_masks"], axis=1),
             helper.make_node("Cast", ["categorical_codes"], ["p3_categories"], to=TensorProto.FLOAT),
             helper.make_node("Concat", ["p3_selected", "p3_masks", "p3_categories"], ["features"], axis=1)]
    return nodes, constants


def export(algorithm, model, preprocessing, calibration, path):
    columns = len(preprocessing.parameters["indices"]) * 2 + 3
    if algorithm == "mlp":
        class Probability(torch.nn.Module):
            def __init__(self, inner):
                super().__init__(); self.inner = inner
            def forward(self, features):
                return torch.sigmoid(self.inner(features))
        device = next(model.parameters()).device
        torch.onnx.export(Probability(model.to("cpu").eval()), torch.zeros((2, columns)), path,
                          input_names=["features"], output_names=["raw_score"], opset_version=17,
                          dynamic_axes={"features": {0: "N"}, "raw_score": {0: "N"}}, dynamo=False)
        model.to(device)
        graph_model = onnx.load(path)
        raw_name = "raw_score"
    else:
        from onnxmltools import convert_xgboost, convert_lightgbm
        from onnxmltools.convert.common.data_types import FloatTensorType
        args = {"initial_types": [("features", FloatTensorType([None, columns]))], "target_opset": 15}
        graph_model = (convert_xgboost(model, **args) if algorithm == "xgboost" else convert_lightgbm(model, zipmap=False, **args))
        output = graph_model.graph.output[-1].name
        graph_model.graph.initializer.append(numpy_helper.from_array(np.asarray([1], dtype=np.int64), "p3_attack_index"))
        graph_model.graph.node.append(helper.make_node("Gather", [output, "p3_attack_index"], ["raw_score"], axis=1))
        raw_name = "raw_score"
    prefix, constants = _preprocessing(preprocessing.parameters)
    original = list(graph_model.graph.node)
    del graph_model.graph.node[:]; graph_model.graph.node.extend(prefix + original)
    graph_model.graph.initializer.extend(constants)
    del graph_model.graph.input[:]
    graph_model.graph.input.extend([helper.make_tensor_value_info("numeric_values", TensorProto.FLOAT, [None, 43]),
                                   helper.make_tensor_value_info("numeric_missing", TensorProto.FLOAT, [None, 43]),
                                   helper.make_tensor_value_info("categorical_codes", TensorProto.INT64, [None, 3])])
    nodes = []
    if calibration["method"] == "platt":
        for name, value in [("clip_low", 1e-6), ("clip_high", 1 - 1e-6),
                            ("slope", calibration["slope"]), ("intercept", calibration["intercept"])]:
            graph_model.graph.initializer.append(numpy_helper.from_array(np.asarray(value, dtype=np.float32), "p3_" + name))
        nodes = [helper.make_node("Clip", [raw_name, "p3_clip_low", "p3_clip_high"], ["p3_p"]),
                 helper.make_node("Sub", ["p3_one", "p3_p"], ["p3_q"]),
                 helper.make_node("Div", ["p3_p", "p3_q"], ["p3_odds"]),
                 helper.make_node("Log", ["p3_odds"], ["p3_logit"]),
                 helper.make_node("Mul", ["p3_logit", "p3_slope"], ["p3_slope_logit"]),
                 helper.make_node("Add", ["p3_slope_logit", "p3_intercept"], ["p3_calibrated_logit"]),
                 helper.make_node("Sigmoid", ["p3_calibrated_logit"], ["attack_score"])]
    else:
        nodes.append(helper.make_node("Identity", [raw_name], ["attack_score"]))
    graph_model.graph.node.extend(nodes)
    del graph_model.graph.output[:]
    graph_model.graph.output.append(helper.make_tensor_value_info("attack_score", TensorProto.FLOAT, [None, 1]))
    if not any(opset.domain == "" for opset in graph_model.opset_import):
        graph_model.opset_import.append(helper.make_opsetid("", 17))
    for opset in graph_model.opset_import:
        if opset.domain == "":
            opset.version = 17
    graph_model.ir_version = min(graph_model.ir_version, 10)
    onnx.checker.check_model(graph_model)
    onnx.save(graph_model, path)


def session(path):
    options = ort.SessionOptions(); options.intra_op_num_threads = 4; options.inter_op_num_threads = 1
    return ort.InferenceSession(str(path), sess_options=options, providers=["CPUExecutionProvider"])


def score_session(runtime, preprocessing, batch):
    output = runtime.run(["attack_score"], preprocessing.feed(batch))[0]
    if output.dtype != np.float32 or output.shape != (len(batch.rows), 1) or not np.isfinite(output).all():
        raise ValueError("ONNX输出契约不符")
    return output[:, 0]


def parity(path, algorithm, model, preprocessing, calibration, batches, thresholds):
    runtime = session(path); maximum, flips, count = 0.0, 0, 0
    by_role = {}
    for batch in batches:
        expected = calibrated(predict(algorithm, model, preprocessing.transform(batch)), calibration)
        actual = score_session(runtime, preprocessing, batch)
        error = float(np.max(np.abs(expected - actual)))
        changed = sum(int(np.count_nonzero((expected >= t) != (actual >= t))) for t in thresholds)
        by_role[batch.role] = {"rows": len(actual), "maxAbsError": error, "thresholdFlips": changed}
        maximum = max(maximum, error); flips += changed; count += len(actual)
    passed = maximum <= 1e-4 and flips == 0
    return {"status": "passed" if passed else "failed", "rows": count, "maxAbsError": maximum,
            "thresholdFlips": flips, "checkedThresholds": thresholds, "byRole": by_role,
            "provider": "CPUExecutionProvider", "runtimeVersion": ort.__version__, "embeddedPreprocessingAndCalibration": True}


def latency(path, preprocessing, batch):
    runtime = session(path); one = batch.take([0]); feed = preprocessing.feed(one)
    for _ in range(10):
        runtime.run(None, feed)
    values = []
    for _ in range(200):
        start = time.perf_counter(); runtime.run(None, feed); values.append((time.perf_counter() - start) * 1000)
    return {"scope": "warm ONNX CPU batch=1 only", "iterations": 200, "p50Ms": float(np.percentile(values, 50)),
            "p95Ms": float(np.percentile(values, 95)), "maxMs": max(values), "osActionLatencyVerified": False}
