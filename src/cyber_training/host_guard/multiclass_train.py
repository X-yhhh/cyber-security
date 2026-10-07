"""P3-B 多分类训练、选型、阈值预览和 ONNX 候选导出。

输入是 P3-A 冻结的 train/validation ``dataset.jsonl``。加载器只读取这两种
开发角色；test/L3 不在本模块的路径或参数中出现。模型与报告均写入新的受控
run 目录，已有 run 不覆盖。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import time
import heapq
from datetime import datetime
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

import numpy as np

CLASSES = ("normal", "port_scan", "brute_force", "dos_flood", "dos_slow")
ATTACKS = CLASSES[1:]
NUMERIC = [
    "features.elapsedMs", "features.bytesOutbound", "features.bytesInbound",
    "features.packetsOutbound", "features.packetsInbound", "features.lengthMin",
    "features.lengthMax", "features.lengthMean", "features.lengthStd",
    "features.iatMeanUs", "features.iatStdUs", "features.synCount",
    "features.synAckCount", "features.rstCount", "features.finCount",
    "features.handshakeSeen",
]
for window in (1, 5, 30):
    NUMERIC += [
        f"contexts.{window}.coverageMs", f"contexts.{window}.peerFlowStarts",
        f"contexts.{window}.peerSynCount", f"contexts.{window}.peerRstCount",
        f"contexts.{window}.peerDistinctServicePorts", f"contexts.{window}.hostFlowStarts",
        f"contexts.{window}.hostDistinctPeers", f"contexts.{window}.peerBytesOutbound",
        f"contexts.{window}.peerBytesInbound",
    ]
CATEGORICAL = ("transport", "direction", "serviceClass")
NULLABLE = {"features." + x for x in ("iatMeanUs", "iatStdUs", "synCount", "synAckCount", "rstCount", "finCount", "handshakeSeen")}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(8 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_new(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")


def _feature_value(observation: dict, name: str):
    parts = name.split(".")
    if parts[0] == "features":
        return observation["features"][parts[1]]
    window = int(parts[1])
    context = next(item for item in observation["contexts"] if item["windowSeconds"] == window)
    return context[parts[2]]


@dataclass
class Dataset:
    rows: list[dict]
    values: np.ndarray
    missing: np.ndarray
    categories: np.ndarray
    labels: np.ndarray
    parent_ids: np.ndarray
    source_ids: np.ndarray
    metadata: list[dict]
    role: str

    @classmethod
    def load(cls, path: Path, role="train", expected_hash=None, metadata_path=None) -> "Dataset":
        """拒绝测试路径；生产加载时先核验开发清单，再匹配旁路顺序。"""
        if role not in ("train", "validation") or any("test" in part.lower() or "l3" in part.lower() for part in path.parts):
            raise ValueError("禁止访问 test/L3")
        if expected_hash is not None and sha256(path) != expected_hash:
            raise ValueError("冻结数据哈希不符")
        rows, values, missing, categories = [], [], [], []
        with path.open(encoding="utf-8") as stream:
            for line in stream:
                row = json.loads(line)
                observation = row["input"]
                if row["label"] not in CLASSES:
                    raise ValueError(f"未知类别: {row['label']}")
                if observation.get("transport") != "tcp" or observation.get("direction") != "inbound":
                    raise ValueError("数据不满足 TCP/inbound 训练契约")
                numeric, masks = [], []
                for name in NUMERIC:
                    value = _feature_value(observation, name)
                    if value is None and name not in NULLABLE:
                        raise ValueError(f"不可空特征缺失: {name}")
                    numeric.append(0.0 if value is None else float(value))
                    masks.append(float(value is None))
                values.append(numeric); missing.append(masks)
                categories.append([observation.get(name) for name in CATEGORICAL])
                rows.append(row)
        if not rows:
            raise ValueError(f"空数据集: {path}")
        if not np.isfinite(values).all() or np.any(np.asarray(values) < 0):
            raise ValueError("非有限或负数特征")
        metadata = []
        if metadata_path is not None:
            with metadata_path.open(encoding="utf-8") as stream:
                metadata = [json.loads(line) for line in stream]
            if len(metadata) != len(rows) or any(m['observationId'] != r['observationId'] or m['parentConnectionId'] != r['parentConnectionId'] for m,r in zip(metadata,rows)):
                raise ValueError("旁路与冻结数据错位")
        return cls(rows, np.asarray(values, dtype=np.float32), np.asarray(missing, dtype=np.float32),
                   np.asarray(categories, dtype=object),
                   np.asarray([CLASSES.index(row["label"]) for row in rows], dtype=np.int64),
                   np.asarray([row["parentConnectionId"] for row in rows], dtype=object),
                   np.asarray(["website" if row.get("websiteSupplement") else "internal" for row in rows], dtype=object), metadata, role)

    def subset(self, indices: np.ndarray) -> "Dataset":
        return Dataset([self.rows[i] for i in indices], self.values[indices], self.missing[indices],
                       self.categories[indices], self.labels[indices], self.parent_ids[indices], self.source_ids[indices],
                       [self.metadata[i] for i in indices] if self.metadata else [], self.role)


class Preprocessor:
    """只在 train 拟合 log1p、插补、缩放和类别编码。"""

    def __init__(self, feature_set="full", include_service_class=True):
        self.feature_set = feature_set
        self.include_service_class = include_service_class
        self.indices = self._indices(feature_set)
        self.mean = None
        self.scale = None
        self.vocab = None

    @staticmethod
    def _indices(feature_set):
        if feature_set == "full":
            return list(range(43))
        if feature_set == "no_host_context":
            return list(range(16)) + [i for i in range(16, 43) if (i - 16) % 9 not in (5, 6)]
        if feature_set in ("base", "reference"):
            return list(range(16))
        raise ValueError(f"未知特征集: {feature_set}")

    def fit(self, dataset: Dataset):
        if dataset.role != "train":
            raise ValueError("预处理仅能拟合 train")
        if len(dataset.rows) == 0:
            raise ValueError("不能对空 train 拟合")
        logged = np.log1p(dataset.values.astype(np.float64))
        observed = 1.0 - dataset.missing
        weight = self._parent_weights(dataset)[:, None] * observed
        self.mean = (logged * weight).sum(axis=0) / np.maximum(weight.sum(axis=0), 1e-12)
        filled = np.where(dataset.missing == 1, self.mean, logged)
        variance = np.average((filled - self.mean) ** 2, weights=self._parent_weights(dataset), axis=0)
        self.scale = np.where(variance > 1e-12, np.sqrt(variance), 1.0)
        # 沿用已验证 v2：参数存 float32，运算提升 double，最终才舍入。
        self.mean = self.mean.astype(np.float32).astype(np.float64)
        self.scale = self.scale.astype(np.float32).astype(np.float64)
        self.vocab = [sorted(set(dataset.categories[:, i].tolist())) for i in range(3)]
        return self

    @staticmethod
    def _parent_weights(dataset):
        counts = Counter(dataset.parent_ids.tolist())
        return np.asarray([1.0 / counts[value] for value in dataset.parent_ids], dtype=np.float64)

    def transform(self, dataset: Dataset):
        if self.mean is None:
            raise ValueError("预处理尚未拟合")
        logged = np.log1p(dataset.values.astype(np.float64))
        filled = np.where(dataset.missing == 1, self.mean, logged)
        numeric = ((filled - self.mean) / self.scale)[:, self.indices].astype(np.float32)
        masks = dataset.missing[:, self.indices].astype(np.float32)
        categorical = []
        for i, values in enumerate(dataset.categories.T):
            if i == 2 and not self.include_service_class:
                continue
            mapping = {value: index + 1 for index, value in enumerate(self.vocab[i])}
            categorical.append(np.asarray([mapping.get(value, 0) for value in values], dtype=np.float32))
        cat = np.column_stack(categorical).astype(np.float32) if categorical else np.empty((len(dataset.rows), 0), dtype=np.float32)
        return np.concatenate([numeric, masks, cat], axis=1)

    def parameters(self):
        return {"version": "p3-preprocess-v2", "featureSet": self.feature_set,
                "includeServiceClass": self.include_service_class, "numericIndices": self.indices,
                "meanLog": self.mean.astype(np.float32).tolist(), "scaleLog": self.scale.astype(np.float32).tolist(),
                "vocabularies": self.vocab, "fitRole": "train"}

    @classmethod
    def restore(cls, parameters):
        result = cls(parameters['featureSet'], parameters['includeServiceClass'])
        result.mean = np.asarray(parameters['meanLog'], dtype=np.float32).astype(np.float64)
        result.scale = np.asarray(parameters['scaleLog'], dtype=np.float32).astype(np.float64)
        result.vocab = parameters['vocabularies']
        return result

    def codes(self, dataset):
        maps = [{v:j+1 for j,v in enumerate(vocab)} for vocab in self.vocab]
        return np.asarray([[maps[i].get(v,0) for i,v in enumerate(row)] for row in dataset.categories], dtype=np.int64)


def sample_weights(dataset: Dataset, class_cap=3.0):
    """先使每条 parent 的快照权重和为 1，再施加有上限的类别平衡。"""
    parent = Preprocessor._parent_weights(dataset)
    counts = np.bincount(dataset.labels, weights=parent, minlength=len(CLASSES))
    factors = np.minimum(class_cap, counts.max() / np.maximum(counts, 1.0))
    weights = parent * factors[dataset.labels]
    return weights, {CLASSES[i]: float(factors[i]) for i in range(len(CLASSES))}


def fit_model(algorithm, x, y, weights, seed, config, validation=None):
    start = time.perf_counter()
    if algorithm == "xgboost":
        from xgboost import XGBClassifier
        kwargs = dict(n_estimators=config["n_estimators"], max_depth=config["max_depth"],
                      learning_rate=config["learning_rate"], min_child_weight=config["min_child_weight"],
                      subsample=0.9, colsample_bytree=0.9, reg_lambda=2.0,
                      objective="multi:softprob", num_class=len(CLASSES), eval_metric="mlogloss",
                      tree_method="hist", device="cuda", n_jobs=config["threads"], random_state=seed)
        if validation is not None:
            kwargs["early_stopping_rounds"] = config["early_stopping_rounds"]
        model = XGBClassifier(**kwargs)
        fit_kwargs = {"sample_weight": weights}
        if validation is not None:
            fit_kwargs["eval_set"] = [(validation[0], validation[1])]
        model.fit(x, y, verbose=False, **fit_kwargs)
        device = "cuda"
    elif algorithm == "lightgbm":
        from lightgbm import LGBMClassifier, early_stopping
        model = LGBMClassifier(n_estimators=config["n_estimators"], max_depth=config["max_depth"],
                               num_leaves=config["num_leaves"], learning_rate=config["learning_rate"],
                               min_child_samples=config["min_child_samples"], reg_lambda=2.0,
                               objective="multiclass", num_class=len(CLASSES), n_jobs=config["threads"],
                               random_state=seed, verbosity=-1, deterministic=True, force_col_wise=True)
        fit_kwargs = {"sample_weight": weights}
        callbacks = []
        if validation is not None:
            fit_kwargs["eval_set"] = [validation]
            callbacks = [early_stopping(config["early_stopping_rounds"], verbose=False)]
        model.fit(x, y, callbacks=callbacks, **fit_kwargs)
        device = "cpu"
    else:
        raise ValueError(f"未登记算法: {algorithm}")
    return model, {"algorithm": algorithm, "seed": seed, "fitSeconds": time.perf_counter() - start,
                   "device": device, "bestIteration": int(getattr(model, "best_iteration", getattr(model, 'best_iteration_', 0)) or 0),
                   "rows": len(y), "classWeightCap": config["class_weight_cap"]}


def probabilities(model, x):
    values = np.asarray(model.predict_proba(x), dtype=np.float32)
    if values.shape[1] != len(CLASSES):
        raise ValueError(f"概率列数不符: {values.shape}")
    return values


def connection_scores(dataset: Dataset, probabilities_: np.ndarray):
    """返回每条连接的最高攻击分，供诊断使用；判定路径使用 connection_scores_at。"""
    grouped = defaultdict(list)
    for index, parent in enumerate(dataset.parent_ids):
        grouped[parent].append(index)
    scores, labels, sources, activities, scenarios = [], [], [], [], []
    for parent, indices in grouped.items():
        labels_for_parent = dataset.labels[indices]
        if not np.all(labels_for_parent == labels_for_parent[0]):
            raise ValueError(f"parentConnectionId 标签冲突: {parent}")
        if dataset.metadata:
            indices = sorted(indices, key=lambda i: dataset.metadata[i].get("asOf", ""))
        attack_values = 1.0 - probabilities_[indices, 0]
        attack_score = float(np.max(attack_values))
        family = probabilities_[indices[int(np.argmax(attack_values))], 1:]
        scores.append(np.r_[attack_score, family])
        labels.append(int(dataset.labels[indices[0]]))
        sources.append(str(dataset.source_ids[indices[0]]))
        activities.append(str(dataset.rows[indices[0]].get("activityId", "unknown")))
        scenarios.append(str(dataset.rows[indices[0]].get("originalScenario", dataset.rows[indices[0]].get("activityId", "unknown"))))
    return (np.asarray(scores, dtype=np.float32), np.asarray(labels, dtype=np.int64),
            np.asarray(sources, dtype=object), np.asarray(activities, dtype=object),
            np.asarray(scenarios, dtype=object))


def connection_scores_at(dataset, probabilities_, alert_threshold):
    """连接判定：按 asOf 顺序取第一个达到告警阈值的快照。"""
    grouped = defaultdict(list)
    for index, parent in enumerate(dataset.parent_ids):
        grouped[parent].append(index)
    scores, labels, sources, activities, scenarios = [], [], [], [], []
    for parent, indices in grouped.items():
        if dataset.metadata:
            indices = sorted(indices, key=lambda i: dataset.metadata[i].get("asOf", ""))
        selected = next((i for i in indices if 1.0 - float(probabilities_[i, 0]) >= alert_threshold), None)
        labels_for_parent = dataset.labels[indices]
        if not np.all(labels_for_parent == labels_for_parent[0]):
            raise ValueError(f"parentConnectionId 标签冲突: {parent}")
        if selected is None:
            selected = indices[-1]
            score = np.r_[0.0, probabilities_[selected, 1:]]
        else:
            score = np.r_[1.0 - probabilities_[selected, 0], probabilities_[selected, 1:]]
        row = dataset.rows[selected]
        scores.append(score); labels.append(int(dataset.labels[indices[0]]))
        sources.append(str(dataset.source_ids[indices[0]]))
        activities.append(str(row.get("activityId", "unknown")))
        scenarios.append(str(row.get("originalScenario", row.get("activityId", "unknown"))))
    return (np.asarray(scores, dtype=np.float32), np.asarray(labels, dtype=np.int64),
            np.asarray(sources, dtype=object), np.asarray(activities, dtype=object),
            np.asarray(scenarios, dtype=object), np.asarray(list(grouped), dtype=object))


def metrics(dataset: Dataset, probabilities_: np.ndarray, alert_threshold=0.5):
    scores, labels, sources, _, scenarios, _ = connection_scores_at(dataset, probabilities_, alert_threshold)
    predicted = np.where(scores[:, 0] >= alert_threshold, 1 + np.argmax(scores[:, 1:], axis=1), 0)
    matrix = np.zeros((len(CLASSES), len(CLASSES)), dtype=int)
    for truth, guess in zip(labels, predicted):
        matrix[truth, guess] += 1
    f1 = []
    recalls = {}
    precisions = {}
    for index, name in enumerate(CLASSES):
        tp = matrix[index, index]; fp = matrix[:, index].sum() - tp; fn = matrix[index].sum() - tp
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        precisions[name] = precision; recalls[name] = recall
        f1.append(2 * precision * recall / (precision + recall) if precision + recall else 0.0)
    normal = labels == 0
    fpr = float(np.mean(predicted[normal] != 0)) if normal.any() else 0.0
    attack_recalls = [float(np.mean(predicted[labels == i] != 0))
                      for i in range(1, len(CLASSES)) if np.any(labels == i)]
    attack_detect = float(np.mean(attack_recalls)) if attack_recalls else 0.0
    def grouped_metrics(group_values):
        result = {}
        for group in sorted(set(group_values.tolist())):
            mask = group_values == group
            normal_mask = mask & (labels == 0)
            attack_mask = mask & (labels != 0)
            result[str(group)] = {"rows": int(mask.sum()),
                                  "falsePositiveRate": float(np.mean(predicted[normal_mask] != 0)) if np.any(normal_mask) else None,
                                  "attackDetection": float(np.mean(predicted[attack_mask] != 0)) if np.any(attack_mask) else None}
        return result
    score_values = scores[:, 0]
    source_fprs = [value["falsePositiveRate"] for value in grouped_metrics(sources).values()
                   if value["falsePositiveRate"] is not None]
    source_attack = [value["attackDetection"] for value in grouped_metrics(sources).values()
                     if value["attackDetection"] is not None]
    equal_fpr = float(np.mean(source_fprs)) if source_fprs else fpr
    return {"alertThreshold": alert_threshold, "rows": int(len(labels)), "macroF1": float(np.mean(f1)),
            "attackDetection": attack_detect, "falsePositiveRate": equal_fpr,
            "falsePositiveWeighting": "equal-source-internal-website",
            "precision": precisions, "recall": recalls, "confusionMatrix": matrix.tolist(),
            "sourceCount": int(len(set(sources.tolist()))),
            "sourceMetrics": grouped_metrics(sources), "scenarioMetrics": grouped_metrics(scenarios),
            "scoreDistribution": {"min": float(np.min(score_values)), "p50": float(np.quantile(score_values, .5)),
                                   "p95": float(np.quantile(score_values, .95)), "max": float(np.max(score_values)),
                                   "uniqueRounded1e6": int(len(set(np.round(score_values, 6).tolist())))}}


def select_alert_threshold(dataset, probabilities_):
    raw_scores = 1.0 - probabilities_[:, 0]
    candidates = sorted(set([0.0, 1.0, *np.quantile(raw_scores, np.linspace(0.0, 1.0, 101)).tolist()]))
    eligible = []
    for threshold in candidates:
        scores, labels, sources, _, _, _ = connection_scores_at(dataset, probabilities_, threshold)
        source_fprs = []
        for source in sorted(set(sources.tolist())):
            normal = (sources == source) & (labels == 0)
            if np.any(normal):
                source_fprs.append(float(np.mean(scores[normal, 0] >= threshold)))
        fpr = float(np.mean(source_fprs)) if source_fprs else 0.0
        if fpr <= 0.01:
            eligible.append(threshold)
    if not eligible:
        return 1.0
    def recall(threshold):
        scores, labels, _, _, _, _ = connection_scores_at(dataset, probabilities_, threshold)
        return float(np.mean([np.mean(scores[labels == i, 0] >= threshold) for i in range(1, len(CLASSES)) if np.any(labels == i)]))
    return float(max(eligible, key=recall))


def select_policy(dataset, probabilities_, alert_threshold):
    """旧版分组没有来源身份，禁止生成可能被误用的自动参数。"""
    raise RuntimeError("策略须使用 multiclass_audit 的 peerKey/时间窗零拟合预览")


def export_onnx(model, algorithm, preprocessor: Preprocessor, path: Path):
    """导出接收契约原始三输入的双输出候选。"""
    import onnx
    import onnx.compose
    from onnx import TensorProto, helper, numpy_helper
    if algorithm == "xgboost":
        from onnxmltools import convert_xgboost
        from onnxmltools.convert.common.data_types import FloatTensorType
        converted = convert_xgboost(model, initial_types=[("features", FloatTensorType([None, model.n_features_in_]))], target_opset=15)
    else:
        from onnxmltools import convert_lightgbm
        from onnxmltools.convert.common.data_types import FloatTensorType
        converted = convert_lightgbm(model, initial_types=[("features", FloatTensorType([None, model.n_features_in_]))], target_opset=15)
    # Some onnxmltools versions omit or downgrade the default-domain import.
    # Normalize it before adding opset-15 wrapper nodes and merging graphs.
    del converted.opset_import[:]
    converted.opset_import.extend([helper.make_operatorsetid("", 15),
                                   helper.make_operatorsetid("ai.onnx.ml", 3)])
    # 先把 sklearn 转换图的概率输出变成两个契约输出，再用 wrapper 提供原始输入。
    graph = converted.graph
    zipmaps = [node for node in graph.node if node.op_type == "ZipMap"]
    if zipmaps:
        zipmap = zipmaps[-1]; probability_name = zipmap.input[0]
        graph.node.remove(zipmap)
    else:
        probability_name = graph.output[-1].name
    del graph.output[:]
    graph.node.extend([
        helper.make_node("Gather", [probability_name, "p3_normal_index"], ["p3_normal"], axis=1),
        helper.make_node("Sub", ["p3_one", "p3_normal"], ["attack_score"]),
        helper.make_node("Gather", [probability_name, "p3_family_indices"], ["family_scores"], axis=1),
    ])
    graph.initializer.extend([
        numpy_helper.from_array(np.asarray([0], dtype=np.int64), "p3_normal_index"),
        numpy_helper.from_array(np.asarray([1.0], dtype=np.float32), "p3_one"),
        numpy_helper.from_array(np.asarray([1, 2, 3, 4], dtype=np.int64), "p3_family_indices"),
    ])
    graph.output.extend([
        helper.make_tensor_value_info("attack_score", TensorProto.FLOAT, [None, 1]),
        helper.make_tensor_value_info("family_scores", TensorProto.FLOAT, [None, 4]),
    ])
    converted.ir_version = min(converted.ir_version, 10)
    onnx.checker.check_model(converted)

    # wrapper 的数值变换与训练端 Preprocessor 完全一致；categorical_codes
    # 已按 train 词表编码，未知值为 0。这样导出的图不接触标识符或标签辅助列。
    from onnx import TensorProto, helper, numpy_helper
    n = len(preprocessor.indices)
    cat_count = 2 if not preprocessor.include_service_class else 3
    wrapper_inputs = [
        helper.make_tensor_value_info("numeric_values", TensorProto.FLOAT, [None, 43]),
        helper.make_tensor_value_info("numeric_missing", TensorProto.FLOAT, [None, 43]),
        helper.make_tensor_value_info("categorical_codes", TensorProto.INT64, [None, 3]),
    ]
    wrapper_nodes = [
        helper.make_node("Cast", ["numeric_values"], ["numeric_values_double"], to=TensorProto.DOUBLE),
        helper.make_node("Constant", [], ["one"], value=numpy_helper.from_array(np.asarray(1.0, dtype=np.float64))),
        helper.make_node("Add", ["numeric_values_double", "one"], ["numeric_plus_one"]),
        helper.make_node("Log", ["numeric_plus_one"], ["logged"]),
        helper.make_node("Equal", ["numeric_missing", "zero"], ["observed_bool"]),
        helper.make_node("Where", ["observed_bool", "logged", "mean_broadcast"], ["filled"]),
        helper.make_node("Sub", ["filled", "mean_broadcast"], ["centered"]),
        helper.make_node("Div", ["centered", "scale_broadcast"], ["scaled"]),
        helper.make_node("Cast", ["scaled"], ["scaled_float"], to=TensorProto.FLOAT),
        helper.make_node("Gather", ["scaled_float", "feature_indices"], ["numeric_selected"], axis=1),
        helper.make_node("Gather", ["numeric_missing", "feature_indices"], ["missing_selected"], axis=1),
        helper.make_node("Cast", ["categorical_codes"], ["categorical_float"], to=TensorProto.FLOAT),
        helper.make_node("Gather", ["categorical_float", "category_indices"], ["categories_selected"], axis=1),
        helper.make_node("Concat", ["numeric_selected", "missing_selected", "categories_selected"], ["features"], axis=1),
    ]
    wrapper_initializers = [
        numpy_helper.from_array(np.asarray(0.0, dtype=np.float32), "zero"),
        numpy_helper.from_array(preprocessor.mean.astype(np.float64), "mean_broadcast"),
        numpy_helper.from_array(preprocessor.scale.astype(np.float64), "scale_broadcast"),
        numpy_helper.from_array(np.asarray(preprocessor.indices, dtype=np.int64), "feature_indices"),
        numpy_helper.from_array(np.asarray(list(range(cat_count)), dtype=np.int64), "category_indices"),
    ]
    # 转换图输入只保留内部 features；wrapper 输出与其连接。
    converted.graph.input[0].name = "features"
    wrapper_graph = helper.make_graph(wrapper_nodes, "p3_preprocess", wrapper_inputs,
                                      [helper.make_tensor_value_info("features", TensorProto.FLOAT, [None, model.n_features_in_])],
                                      initializer=wrapper_initializers)
    wrapper_model = helper.make_model(wrapper_graph, opset_imports=[helper.make_operatorsetid("", 15)])
    wrapper_model.ir_version = converted.ir_version
    merged = onnx.compose.merge_models(wrapper_model, converted, io_map=[("features", "features")])
    merged.ir_version = min(merged.ir_version, 10)
    onnx.checker.check_model(merged)
    onnx.save(merged, path)


def default_config():
    return {"n_estimators": 500, "max_depth": 6, "learning_rate": .06,
            "min_child_weight": 5, "num_leaves": 31, "min_child_samples": 30,
            "early_stopping_rounds": 40, "threads": 8, "class_weight_cap": 3.0}


def append_event(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n")


def onnx_parity(path: Path, preprocessor: Preprocessor, dataset: Dataset,
                expected_probabilities: np.ndarray, alert_threshold: float) -> dict:
    """在同一 validation 批次比较框架概率与三输入 ONNX 双输出。"""
    import onnxruntime as ort
    runtime = ort.InferenceSession(str(path), providers=["CPUExecutionProvider"])
    feed = {"numeric_values": dataset.values, "numeric_missing": dataset.missing,
            "categorical_codes": np.asarray([[({v: j + 1 for j, v in enumerate(preprocessor.vocab[i])}).get(value, 0)
                                               for i, value in enumerate(row)] for row in dataset.categories], dtype=np.int64)}
    actual_attack, actual_family = runtime.run(["attack_score", "family_scores"], feed)
    expected_attack = (1.0 - expected_probabilities[:, [0]]).astype(np.float32)
    expected_family = expected_probabilities[:, 1:].astype(np.float32)
    actual_attack = np.asarray(actual_attack, dtype=np.float32)
    actual_family = np.asarray(actual_family, dtype=np.float32)
    expected_label = np.where(expected_attack[:, 0] >= alert_threshold, 1 + np.argmax(expected_family, axis=1), 0)
    actual_label = np.where(actual_attack[:, 0] >= alert_threshold, 1 + np.argmax(actual_family, axis=1), 0)
    return {"status": "passed" if max(float(np.max(np.abs(actual_attack - expected_attack))),
                                             float(np.max(np.abs(actual_family - expected_family)))) <= 1e-4
                                             and int(np.count_nonzero(expected_label != actual_label)) == 0 else "failed",
            "maxAbsError": max(float(np.max(np.abs(actual_attack - expected_attack))),
                                float(np.max(np.abs(actual_family - expected_family)))),
            "thresholdFlips": int(np.count_nonzero(expected_label != actual_label)),
            "rows": len(dataset.rows), "provider": "CPUExecutionProvider", "runtimeVersion": ort.__version__}


def experiment_plan(train_path, validation_path):
    return {"plan": "p3-multiclass-20261006-v1", "stage": "P3-B", "candidateOnly": True,
            "finalTestRead": False, "classOrder": list(CLASSES), "featureContract": "host-guard/5.0.0-rc.2",
            "dataset": {"train": str(train_path), "validation": str(validation_path),
                        "trainSha256": sha256(train_path), "validationSha256": sha256(validation_path)},
            "experiments": {"main": {"algorithms": ["xgboost", "lightgbm"], "featureSet": "full", "seeds": [42, 43, 44]},
                            "hyperparameters": {"algorithms": ["xgboost", "lightgbm"], "seeds": [42], "featureSet": "full", "maxFits": 6},
                            "ablation": [{"name": "no_serviceClass", "featureSet": "full", "includeServiceClass": False},
                                         {"name": "no_host_context", "featureSet": "no_host_context", "includeServiceClass": True}],
                            "reference": {"name": "single_flow_16", "featureSet": "reference", "includeServiceClass": True}},
            "selection": {"validationOnly": True, "alertFprMax": .01, "minDistinctFlowsCandidates": [2, 3, 5],
                          "tieBreak": ["macroF1", "attackDetection"], "thresholdGrid": "quantiles"},
            "exitCriteria": {"validationAttackDetectionMin": .85, "validationFprMax": .02, "onnxMaxAbsError": 1e-4,
                              "onnxThresholdFlips": 0, "iterationLimit": 30},
            "budget": {"maxFits": 30, "maxSecondsPerFit": 7200, "classWeightCap": 3.0},
            "runtime": {"python": platform.python_version(), "platform": platform.platform()}}


def run(args):
    # 已有运行超出全局预算：本轮仅允许审计，不再重复拟合。
    raise RuntimeError("P3-B 累计拟合预算已耗尽；仅允许 multiclass_audit 零拟合收尾")
    train_path, validation_path, run_dir = map(Path, (args.train, args.validation, args.run))
    run_dir.mkdir(parents=True, exist_ok=False)
    plan = experiment_plan(train_path, validation_path)
    write_new(run_dir / "experiment-plan.json", plan)
    train, validation = Dataset.load(train_path, role="train", expected_hash=args.train_sha256,
                                     metadata_path=args.train_metadata), Dataset.load(
                                         validation_path, role="validation", expected_hash=args.validation_sha256,
                                         metadata_path=args.validation_metadata)
    train_hash, validation_hash = sha256(train_path), sha256(validation_path)
    summary = {"status": "running", "fits": [], "dataset": {"trainRows": len(train.rows), "validationRows": len(validation.rows),
                                                               "trainSha256": train_hash, "validationSha256": validation_hash},
               "candidateOnly": True, "finalTestRead": False}
    append_event(run_dir / "run-events.jsonl", {"event": "started", "summary": summary})
    config = default_config()
    specs = [(algorithm, "full", True, seed, f"main-{algorithm}-seed{seed}", {})
             for algorithm in ("xgboost", "lightgbm") for seed in (42, 43, 44)]
    specs += [item for algorithm in ("xgboost", "lightgbm") for item in (
        (algorithm, "full", True, 42, f"tune-{algorithm}-shallow", {"max_depth": 4, "num_leaves": 15}),
        (algorithm, "full", True, 42, f"tune-{algorithm}-conservative", {"learning_rate": .03, "n_estimators": 800}),
    )]
    specs += [("lightgbm", "full", False, 42, "ablation-no-serviceClass", {}),
              ("lightgbm", "no_host_context", True, 42, "ablation-no-host-context", {}),
              ("lightgbm", "reference", True, 42, "reference-single-flow-16", {})]
    if args.smoke:
        specs = [("xgboost", "full", True, 42, "smoke-xgboost", {})]
        config.update(n_estimators=3, early_stopping_rounds=2)
    best = None
    prepared = {}
    for algorithm, feature_set, service, seed, name, overrides in specs:
        fit_config = config | overrides
        cache_key = (feature_set, service)
        if cache_key not in prepared:
            pre = Preprocessor(feature_set, service).fit(train)
            prepared[cache_key] = (pre, pre.transform(train), pre.transform(validation),
                                    sample_weights(train, fit_config["class_weight_cap"]))
        pre, x_train, x_validation, (weights, balance) = prepared[cache_key]
        model, fit_info = fit_model(algorithm, x_train, train.labels, weights, seed, fit_config, (x_validation, validation.labels))
        validation_prob = probabilities(model, x_validation)
        alert = select_alert_threshold(validation, validation_prob)
        report = metrics(validation, validation_prob, alert)
        policy = select_policy(validation, validation_prob, alert)
        artifact = run_dir / "models" / name
        artifact.mkdir(parents=True)
        write_new(artifact / "preprocessing.json", pre.parameters())
        write_new(artifact / "validation-metrics.json", report | {"policyPreview": policy, "classBalanceFactors": balance})
        parity = None
        try:
            export_onnx(model, algorithm, pre, artifact / "model.onnx")
            export_status = "passed"
            parity = onnx_parity(artifact / "model.onnx", pre, validation, validation_prob, alert)
            write_new(artifact / "onnx-parity.json", parity)
        except Exception as error:
            (artifact / "export-error.txt").write_text(f"{type(error).__name__}: {error}\n", encoding="utf-8")
            export_status = "failed"
        record = {"name": name, "algorithm": algorithm, "seed": seed, "featureSet": feature_set,
                  "includeServiceClass": service, "fit": fit_info, "validation": report, "onnxParity": parity,
                  "export": export_status, "artifactSha256": sha256(artifact / "model.onnx") if (artifact / "model.onnx").exists() else None}
        summary["fits"].append(record)
        if (export_status == "passed" and parity is not None and parity["status"] == "passed"
                and report["falsePositiveRate"] <= .01
                and (best is None or (report["macroF1"], report["attackDetection"])
                     > (best["validation"]["macroF1"], best["validation"]["attackDetection"]))):
            best = record | {"preprocessing": pre.parameters(), "policy": policy}
        append_event(run_dir / "run-events.jsonl", {"event": "fit-completed", "record": record})
    if best is None:
        raise RuntimeError("没有同时满足 FPR、ONNX 导出和对拍条件的可选候选")
    write_new(run_dir / "selection.json", {"selected": best["name"], "validationOnly": True, "candidateOnly": True,
                                            "selectionCriterion": "FPR<=1%, then macroF1, then attackDetection", "policy": best["policy"]})
    summary["status"] = "completed"
    summary["selected"] = best["name"]
    summary["finalTestRead"] = False
    write_new(run_dir / "run-summary.json", summary)
    print(json.dumps({"status": summary["status"], "run": str(run_dir), "selected": best["name"], "fits": len(summary["fits"]), "finalTestRead": False}, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--train", type=Path, required=True)
    parser.add_argument("--validation", type=Path, required=True)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--train-sha256", required=True)
    parser.add_argument("--validation-sha256", required=True)
    parser.add_argument("--train-metadata", type=Path, required=True)
    parser.add_argument("--validation-metadata", type=Path, required=True)
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    run(args)


if __name__ == "__main__":
    main()
