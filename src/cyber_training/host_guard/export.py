"""导出三输入ONNX，在图内绑定训练预处理与独立校准；只写候选，不加载pickle。"""
from __future__ import annotations

import json
import time

import numpy as np
import onnx
from onnx import TensorProto, helper, numpy_helper
import onnxruntime as ort
import torch

from .data import PREPROCESS_V1, PREPROCESS_V2
from .models import calibrated, predict


def _preprocessing(parameters):
    """把 Preprocessor.transform 嵌入图内；算子顺序和中间精度必须与 numpy 版本一致。

    v2 先把原始数值提升为 double，log/插补/中心化/缩放后再舍入 float32，使
    ORT 特征与训练特征逐位一致；v1 保留历史 float32 图，仅用于复现旧产物。
    """
    version = parameters.get("version")
    if version not in (PREPROCESS_V1, PREPROCESS_V2):
        raise ValueError("未知预处理版本")
    constants = []
    def constant(name, array):
        constants.append(numpy_helper.from_array(np.asarray(array), name)); return name
    one = constant("p3_one", np.float32(1))
    mean32 = np.asarray(parameters["meanLog"], dtype=np.float32)
    scale32 = np.asarray(parameters["scaleLog"], dtype=np.float32)
    indices = constant("p3_indices", np.asarray(parameters["indices"], dtype=np.int64))
    if version == PREPROCESS_V2:
        mean = constant("p3_mean", mean32.astype(np.float64))
        scale = constant("p3_scale", scale32.astype(np.float64))
        one_double = constant("p3_one_double", np.float64(1))
        nodes = [helper.make_node("Cast", ["numeric_values"], ["p3_values_double"], to=TensorProto.DOUBLE),
                 helper.make_node("Add", ["p3_values_double", one_double], ["p3_positive"])]
    else:
        mean = constant("p3_mean", mean32)
        scale = constant("p3_scale", scale32)
        nodes = [helper.make_node("Add", ["numeric_values", one], ["p3_positive"])]
    nodes += [helper.make_node("Log", ["p3_positive"], ["p3_log"]),
             helper.make_node("Equal", ["numeric_missing", one], ["p3_is_missing"]),
             helper.make_node("Where", ["p3_is_missing", mean, "p3_log"], ["p3_filled"]),
             helper.make_node("Sub", ["p3_filled", mean], ["p3_centered"]),
             helper.make_node("Div", ["p3_centered", scale],
                              ["p3_scaled_double" if version == PREPROCESS_V2 else "p3_scaled"])]
    if version == PREPROCESS_V2:
        nodes.append(helper.make_node("Cast", ["p3_scaled_double"], ["p3_scaled"], to=TensorProto.FLOAT))
    nodes += [helper.make_node("Gather", ["p3_scaled", indices], ["p3_selected"], axis=1),
             helper.make_node("Gather", ["numeric_missing", indices], ["p3_masks"], axis=1),
             helper.make_node("Cast", ["categorical_codes"], ["p3_categories"], to=TensorProto.FLOAT),
             helper.make_node("Concat", ["p3_selected", "p3_masks", "p3_categories"], ["features"], axis=1)]
    return nodes, constants


def _xgboost_graph(model, columns):
    """用原生 JSON 树生成二分类概率图，避免第三方转换器改变树的概率聚合。"""
    booster = model.get_booster()
    config = json.loads(booster.save_config())["learner"]
    parameters = config["learner_model_param"]
    if (model.get_xgb_params().get("objective") != "binary:logistic"
            or config["gradient_booster"]["name"] != "gbtree"
            or parameters.get("num_target") != "1"
            or parameters.get("num_class") != "0"):
        raise ValueError("仅支持单目标 binary:logistic gbtree 导出")
    raw_base_score = parameters["base_score"]
    base_score = float(json.loads(raw_base_score)[0] if raw_base_score.startswith("[") else raw_base_score)
    if not 0 < base_score < 1:
        raise ValueError("XGBoost 基础概率不在开区间内")

    nodes, tree_outputs = [], []
    for tree_id, encoded in enumerate(booster.get_dump(dump_format="json")):
        attributes = dict(
            nodes_treeids=[], nodes_nodeids=[], nodes_featureids=[], nodes_modes=[], nodes_values=[],
            nodes_truenodeids=[], nodes_falsenodeids=[], nodes_missing_value_tracks_true=[],
            target_treeids=[], target_nodeids=[], target_ids=[], target_weights=[])
        def visit(node):
            node_id = int(node["nodeid"])
            attributes["nodes_treeids"].append(0)
            attributes["nodes_nodeids"].append(node_id)
            if "leaf" in node:
                attributes["nodes_featureids"].append(0)
                attributes["nodes_modes"].append("LEAF")
                attributes["nodes_values"].append(0.0)
                attributes["nodes_truenodeids"].append(0)
                attributes["nodes_falsenodeids"].append(0)
                attributes["nodes_missing_value_tracks_true"].append(0)
                attributes["target_treeids"].append(0)
                attributes["target_nodeids"].append(node_id)
                attributes["target_ids"].append(0)
                attributes["target_weights"].append(float(node["leaf"]))
                return
            feature = node["split"]
            if not feature.startswith("f") or not feature[1:].isdigit():
                raise ValueError("XGBoost 树缺少数字特征索引")
            feature_id = int(feature[1:])
            if not 0 <= feature_id < columns:
                raise ValueError("XGBoost 树特征索引越界")
            attributes["nodes_featureids"].append(feature_id)
            # XGBoost compares float32 features with a strict `<`; the ONNX
            # runtime's LT boundary can round the same value below the split.
            # LEQ at the previous representable float32 value preserves that
            # comparison for every representable input.
            split = np.float32(node["split_condition"])
            attributes["nodes_modes"].append("BRANCH_LEQ")
            attributes["nodes_values"].append(float(np.nextafter(split, -np.inf, dtype=np.float32)))
            attributes["nodes_truenodeids"].append(int(node["yes"]))
            attributes["nodes_falsenodeids"].append(int(node["no"]))
            attributes["nodes_missing_value_tracks_true"].append(int(node["missing"] == node["yes"]))
            for child in node["children"]:
                visit(child)
        visit(json.loads(encoded))
        output = f"xgb_tree_{tree_id}"
        nodes.append(helper.make_node("TreeEnsembleRegressor", ["features"], [output], domain="ai.onnx.ml",
                                     n_targets=1, aggregate_function="SUM", post_transform="NONE", **attributes))
        tree_outputs.append(output)

    if len(tree_outputs) == 1:
        nodes.append(helper.make_node("Identity", tree_outputs, ["xgb_tree_margin"]))
    else:
        nodes.append(helper.make_node("Sum", tree_outputs, ["xgb_tree_margin"]))
    nodes.extend([
        helper.make_node("Add", ["xgb_tree_margin", "xgb_base_margin"], ["xgb_margin"]),
        helper.make_node("Sigmoid", ["xgb_margin"], ["raw_score"])])

    graph = helper.make_graph(
        nodes,
        "xgboost_binary_probability",
        [helper.make_tensor_value_info("features", TensorProto.FLOAT, [None, columns])],
        [helper.make_tensor_value_info("raw_score", TensorProto.FLOAT, [None, 1])],
        [numpy_helper.from_array(np.asarray(np.log(base_score / (1 - base_score)), dtype=np.float32), "xgb_base_margin")])
    converted = helper.make_model(graph, producer_name="cyber-training-xgboost-json",
                                  opset_imports=[helper.make_opsetid("", 17), helper.make_opsetid("ai.onnx.ml", 1)])
    converted.ir_version = 10
    return converted


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
        if algorithm == "xgboost":
            graph_model = _xgboost_graph(model, columns)
        else:
            from onnxmltools import convert_lightgbm
            from onnxmltools.convert.common.data_types import FloatTensorType
            graph_model = convert_lightgbm(model, zipmap=False,
                                           initial_types=[("features", FloatTensorType([None, columns]))], target_opset=15)
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
