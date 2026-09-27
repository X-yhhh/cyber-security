"""第 10 步：把冻结并通过第 9 步判定的 T1 候选导出为单一 ONNX 图，校验一致性与性能，生成交付目录。

ONNX 图（opset 17 + ai.onnx.ml 3）包含完整推理链路，后端只需按契约传入原始流字段：

    flow_numeric (double[N, K]) ─┬─ 直接特征 → float32
                                 ├─ 派生特征（rate、比率、差值、速率，与 ``features`` 中的公式和精度一致）
                                 └─ 中位数插补 + 缺失指示列（与训练时 SimpleImputer 相同的统计量）
    flow_categorical (string[N, C]) ─ LabelEncoder（与 OrdinalEncoder 同一词表，未知/空值 → -1）
    → XGBoost 树集成 → attack_probability (float[N])、is_attack (bool[N]，prob >= 冻结阈值)

前置条件（任一不满足即 fail-closed）：冻结文件已提交且与 HEAD 一致；第 9 步 ``final-verdict.json`` 通过且冻结哈希一致；
候选制品 SHA-256 与冻结记录一致；只使用验证分区做一致性校验，不读取 holdout。
第 10 步门槛（ONNX 概率误差 ≤ 1e-4 且判定 100% 一致、单条 P95 ≤ 5 ms、batch 1024 吞吐 ≥ 20k 条/秒）
全部通过才生成 ``deliverable = ready_for_review`` 的交付目录；未通过时只写运行目录，不生成交付物。
交付物仍需本机后端校验哈希并经人工审批后才能激活，本步骤不激活任何模型。
"""

from __future__ import annotations

import csv
import json
import shutil
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from . import GLOBAL_SEED
from ..config import ROOT
from .datasets import load_cached, load_manifest
from .features import (
    CATEGORICAL, SUBSET_TO_RAW, V0_CATEGORICAL, V0_FEATURES, V1_RAW_COLUMNS, FeatureContractError, build_v2,
)
from .final_eval import (
    AUDIT_LOG, FREEZE_REL, FreezeError, T1Model, _git, _logger, _rel, load_freeze, verify_files,
)
from .guard import LeakageError, SplitIndex
from .runtime import RUNS_ROOT, RunContext, keep_awake, package_versions, sha256_file, write_json

DELIVERY_ROOT = ROOT / "delivery"
MODEL_KEY = "unsw-binary"
DEFAULT_VERSION = "2026.09.0"
MANIFEST_VERSION = "1.0"
FEATURE_CONTRACT_VERSION = "unsw-nb15-flow-v3.1"
OPSET = {"": 17, "ai.onnx.ml": 3}
TREE_OPSET = 15  # onnxmltools 1.16 的 XGBoost 转换器最高支持 15，随后升级到 17
RUNTIME = {"onnxruntime": "1.23.2", "execution_provider": "CPUExecutionProvider"}
PARITY_ROWS = 10_000
PARITY_TOLERANCE = 1e-4
LATENCY_RUNS, LATENCY_WARMUP = 2_000, 200
BATCH_SIZE, BATCH_RUNS = 1_024, 60
EXPORT_GATES = (("parity_max_abs_diff", "ONNX 与训练框架概率最大绝对误差", "<=", PARITY_TOLERANCE),
                ("parity_decision_agreement", "阈值判定一致率", ">=", 1.0),
                ("latency_p95_ms", "单条推理延迟 P95（ONNX Runtime CPU）", "<=", 5.0),
                ("batch_throughput_rows_per_s", "batch 1024 吞吐（条/秒）", ">=", 20_000.0))
INPUT_NUMERIC, INPUT_CATEGORICAL = "flow_numeric", "flow_categorical"
OUTPUT_PROB, OUTPUT_DECISION = "attack_probability", "is_attack"

# 原始流字段的单位与说明（UNSW-NB15 特征说明）；``nullable`` 字段允许 NaN（训练数据中本就缺失，由图内插补）。
FIELD_SPEC: dict[str, tuple[str, str]] = {
    "dur": ("秒", "流持续时间"), "spkts": ("包", "源→目的包数"), "dpkts": ("包", "目的→源包数"),
    "sbytes": ("字节", "源→目的字节数"), "dbytes": ("字节", "目的→源字节数"),
    "sttl": ("跳数", "源→目的 TTL"), "dttl": ("跳数", "目的→源 TTL"),
    "sload": ("比特/秒", "源端速率"), "dload": ("比特/秒", "目的端速率"),
    "sloss": ("包", "源端重传/丢弃包数"), "dloss": ("包", "目的端重传/丢弃包数"),
    "sinpkt": ("毫秒", "源端包到达间隔"), "dinpkt": ("毫秒", "目的端包到达间隔"),
    "sjit": ("毫秒", "源端抖动"), "djit": ("毫秒", "目的端抖动"),
    "swin": ("字节", "源端 TCP 窗口"), "dwin": ("字节", "目的端 TCP 窗口"),
    "stcpb": ("序号", "源端 TCP 初始序号"), "dtcpb": ("序号", "目的端 TCP 初始序号"),
    "tcprtt": ("秒", "TCP 建连往返时间（synack + ackdat）"), "synack": ("秒", "SYN 到 SYN-ACK 的时间"),
    "ackdat": ("秒", "SYN-ACK 到 ACK 的时间"), "smean": ("字节", "源端平均包长"), "dmean": ("字节", "目的端平均包长"),
    "trans_depth": ("计数", "HTTP 请求/响应事务深度"), "response_body_len": ("字节", "HTTP 响应体长度"),
    "ct_srv_src": ("计数", "最近 100 条连接中同服务同源地址的连接数"),
    "ct_state_ttl": ("计数", "按状态与 TTL 区间统计的编号"),
    "ct_dst_ltm": ("计数", "最近 100 条连接中同目的地址的连接数"),
    "ct_src_dport_ltm": ("计数", "最近 100 条连接中同源地址同目的端口的连接数"),
    "ct_dst_sport_ltm": ("计数", "最近 100 条连接中同目的地址同源端口的连接数"),
    "ct_dst_src_ltm": ("计数", "最近 100 条连接中同源同目的地址的连接数"),
    "is_ftp_login": ("0/1", "FTP 会话是否登录"), "ct_ftp_cmd": ("计数", "FTP 会话中的命令数"),
    "ct_flw_http_mthd": ("计数", "HTTP 服务中带 GET/POST 等方法的流数"),
    "ct_src_ltm": ("计数", "最近 100 条连接中同源地址的连接数"),
    "ct_srv_dst": ("计数", "最近 100 条连接中同服务同目的地址的连接数"),
    "is_sm_ips_ports": ("0/1", "源/目的地址与端口是否相同"),
    "proto": ("类别", "传输协议（小写字符串，如 tcp、udp）"), "service": ("类别", "应用服务（如 http、dns，未知为 -）"),
    "state": ("类别", "连接状态（如 FIN、INT）"),
}
NULLABLE_FIELDS = ("ct_flw_http_mthd",)

# 派生特征：名称 → (依赖字段, 精度来源, 公式说明)。``raw`` 表示用原始 double 计算（``features.build_v0`` 的 rate），
# ``view`` 表示先把输入舍入到 float32 再转回 double 计算（``features.add_engineered`` 在 float32 视图上计算）。
DERIVED: dict[str, tuple[tuple[str, ...], str, str]] = {
    "rate": (("spkts", "dpkts", "dur"), "raw", "(spkts + dpkts - 1) / dur；dur = 0 时为缺失"),
    "sbytes_per_spkt": (("sbytes", "spkts"), "view", "sbytes / (spkts + 1)"),
    "dbytes_per_dpkt": (("dbytes", "dpkts"), "view", "dbytes / (dpkts + 1)"),
    "sbytes_dbytes_ratio": (("sbytes", "dbytes"), "view", "sbytes / (dbytes + 1)"),
    "spkts_dpkts_ratio": (("spkts", "dpkts"), "view", "spkts / (dpkts + 1)"),
    "ttl_diff": (("sttl", "dttl"), "view", "sttl - dttl"),
    "synack_ackdat_diff": (("synack", "ackdat"), "view", "synack - ackdat"),
    "bytes_rate": (("sbytes", "dbytes", "dur"), "view", "(sbytes + dbytes) / (dur + 1e-6)"),
}


class ExportError(RuntimeError):
    """候选不满足导出前置条件，或预处理结构超出导出器支持范围。"""


# ---------------------------------------------------------------- 契约（由冻结记录与预处理器推出，不猜测）

@dataclass(frozen=True)
class Contract:
    """ONNX 输入输出契约。``numeric_fields`` / ``categorical_fields`` 是后端必须按顺序提供的原始流字段。"""

    columns: tuple[str, ...]  # 训练视图的模型列（冻结顺序）
    numeric_fields: tuple[str, ...]
    categorical_fields: tuple[str, ...]
    medians: tuple[float, ...]  # 与数值模型列一一对应
    indicator_columns: tuple[str, ...]  # 缺失指示列（按训练时顺序）
    vocabularies: dict[str, tuple[str, ...]]
    feature_names: tuple[str, ...]  # 进入树模型的特征顺序
    threshold: float


def contract_from(preprocessor: Any, columns: list[str], threshold: float) -> Contract:
    """校验预处理器正是第 6 步 P1 方案（中位数插补 + 缺失指示 + 有序编码），并推出契约；结构不符即拒绝导出。"""
    from sklearn.impute import SimpleImputer
    from sklearn.preprocessing import OrdinalEncoder

    steps = getattr(preprocessor, "steps", None)
    if not steps or [name for name, _ in steps] != ["columns"]:
        raise ExportError("preprocessor must be Pipeline([('columns', ColumnTransformer)])")
    ct = preprocessor.named_steps["columns"]
    if ct.remainder != "drop" or [name for name, *_ in ct.transformers_ if name != "remainder"] != ["numeric", "categorical"]:
        raise ExportError("unexpected ColumnTransformer layout")
    numeric_pipe = ct.named_transformers_["numeric"]
    if [name for name, _ in numeric_pipe.steps] != ["impute"]:
        raise ExportError("numeric pipeline must contain only the median imputer (scheme P1)")
    imputer = numeric_pipe.named_steps["impute"]
    if not isinstance(imputer, SimpleImputer) or imputer.strategy != "median" or not imputer.add_indicator:
        raise ExportError("numeric imputer must be SimpleImputer(strategy='median', add_indicator=True)")
    if not (isinstance(imputer.missing_values, float) and np.isnan(imputer.missing_values)):
        raise ExportError("imputer must treat NaN as missing")
    encoder = ct.named_transformers_["categorical"]
    if not isinstance(encoder, OrdinalEncoder) or encoder.handle_unknown != "use_encoded_value" \
            or encoder.unknown_value != -1 or encoder.encoded_missing_value != -1:
        raise ExportError("categorical encoder must be OrdinalEncoder with unknown/missing → -1")

    numeric_cols = list(ct.transformers_[0][2])
    categorical_cols = list(ct.transformers_[1][2])
    if numeric_cols + categorical_cols != [c for c in columns if c not in CATEGORICAL] + [c for c in columns if c in CATEGORICAL]:
        raise ExportError("preprocessor columns differ from the frozen column order")
    unsupported = [c for c in categorical_cols if c not in V0_CATEGORICAL]
    if unsupported:
        raise ExportError(f"categorical features without a raw-field mapping: {unsupported}")
    unknown = [c for c in numeric_cols if c not in V0_FEATURES and c not in DERIVED]
    if unknown:
        raise ExportError(f"numeric features without an export formula: {unknown}")

    direct = [c for c in numeric_cols if c not in DERIVED]
    extra = [f for c in numeric_cols if c in DERIVED for f in DERIVED[c][0]]
    numeric_fields = tuple(dict.fromkeys([*direct, *extra]))
    indicator = tuple(numeric_cols[i] for i in imputer.indicator_.features_)
    names = tuple(preprocessor.get_feature_names_out())
    expected = (*numeric_cols, *(f"missingindicator_{c}" for c in indicator), *categorical_cols)
    if names != expected:
        raise ExportError(f"preprocessor output order differs from the export layout: {names}")
    vocab = {c: tuple(str(v) for v in cats) for c, cats in zip(categorical_cols, encoder.categories_)}
    return Contract(columns=tuple(columns), numeric_fields=numeric_fields, categorical_fields=tuple(categorical_cols),
                    medians=tuple(float(v) for v in imputer.statistics_), indicator_columns=indicator,
                    vocabularies=vocab, feature_names=names, threshold=float(threshold))


def raw_inputs(raw: pd.DataFrame, contract: Contract) -> dict[str, np.ndarray]:
    """由 D1 原始帧（``register`` 后的原始字段名）构造 ONNX 输入；缺少字段即终止。"""
    need = [SUBSET_TO_RAW[f] for f in (*contract.numeric_fields, *contract.categorical_fields)]
    missing = sorted(set(need) - set(raw.columns))
    if missing:
        raise FeatureContractError(f"raw frame lacks contract fields: {missing}")
    numeric = np.column_stack([raw[SUBSET_TO_RAW[f]].to_numpy(dtype=np.float64) for f in contract.numeric_fields])
    categorical = np.column_stack([raw[SUBSET_TO_RAW[f]].astype("string").fillna("").to_numpy(dtype=object).astype(str)
                                   for f in contract.categorical_fields])
    return {INPUT_NUMERIC: numeric, INPUT_CATEGORICAL: categorical}

# ---------------------------------------------------------------- ONNX 图

class _Graph:
    """最小的 ONNX 图构造器：自动命名节点与中间张量。"""

    def __init__(self) -> None:
        self.nodes: list[Any] = []
        self.initializers: list[Any] = []
        self._n = 0

    def name(self, prefix: str) -> str:
        self._n += 1
        return f"{prefix}_{self._n}"

    def const(self, value: Any, dtype: Any, prefix: str = "c") -> str:
        from onnx import numpy_helper

        name = self.name(prefix)
        self.initializers.append(numpy_helper.from_array(np.asarray(value, dtype=dtype), name))
        return name

    def op(self, op_type: str, inputs: list[str], domain: str = "", out: str | None = None, **attrs: Any) -> str:
        from onnx import helper

        out = out or self.name(op_type.lower())
        self.nodes.append(helper.make_node(op_type, inputs, [out], name=self.name(f"n_{op_type}"), domain=domain, **attrs))
        return out


def _column(g: _Graph, source: str, index: int) -> str:
    """取 ``source[:, index]``，形状 [N, 1]。"""
    return g.op("Gather", [source, g.const([index], np.int64, "idx")], axis=1)


def _nan_if_inf(g: _Graph, x: str) -> str:
    return g.op("Where", [g.op("IsInf", [x]), g.const(np.nan, np.float64, "nan"), x])


def _view(g: _Graph, x: str) -> str:
    """模拟 ``features`` 中 float32 视图：double → float32 → double。"""
    from onnx import TensorProto

    return g.op("Cast", [g.op("Cast", [x], to=TensorProto.FLOAT)], to=TensorProto.DOUBLE)


def _derived(g: _Graph, name: str, field: dict[str, str]) -> str:
    """派生特征（double），与 ``features.build_v0`` / ``add_engineered`` 的公式、精度和缺失规则一致。"""
    one = lambda: g.const(1.0, np.float64, "one")  # noqa: E731
    deps, precision, _ = DERIVED[name]
    v = {d: (field[d] if precision == "raw" else _view(g, field[d])) for d in deps}
    if name == "rate":
        packets = g.op("Sub", [g.op("Add", [v["spkts"], v["dpkts"]]), one()])
        zero = g.op("Equal", [v["dur"], g.const(0.0, np.float64, "zero")])
        value = g.op("Where", [zero, g.const(np.nan, np.float64, "nan"), g.op("Div", [packets, v["dur"]])])
    elif name in ("sbytes_per_spkt", "dbytes_per_dpkt", "sbytes_dbytes_ratio", "spkts_dpkts_ratio"):
        num, den = deps
        value = g.op("Div", [v[num], g.op("Add", [v[den], one()])])
    elif name in ("ttl_diff", "synack_ackdat_diff"):
        value = g.op("Sub", [v[deps[0]], v[deps[1]]])
    elif name == "bytes_rate":
        value = g.op("Div", [g.op("Add", [v["sbytes"], v["dbytes"]]),
                             g.op("Add", [v["dur"], g.const(1e-6, np.float64, "eps")])])
    else:
        raise ExportError(f"no ONNX formula for {name}")
    return _nan_if_inf(g, value)


def preprocessing_graph(contract: Contract) -> tuple[_Graph, str]:
    """构造预处理部分，返回 (图, 特征矩阵张量名)；特征矩阵为 float32 [N, len(feature_names)]。"""
    from onnx import TensorProto

    g = _Graph()
    field = {f: _column(g, INPUT_NUMERIC, i) for i, f in enumerate(contract.numeric_fields)}
    numeric_cols = [c for c in contract.columns if c not in CATEGORICAL]
    values: dict[str, str] = {}
    for col in numeric_cols:
        x = _derived(g, col, field) if col in DERIVED else field[col]
        values[col] = g.op("Cast", [x], to=TensorProto.FLOAT)
    outputs = []
    for col, median in zip(numeric_cols, contract.medians):
        x = values[col]
        outputs.append(g.op("Where", [g.op("IsNaN", [x]), g.const(np.float32(median), np.float32, "median"), x]))
    for col in contract.indicator_columns:
        outputs.append(g.op("Cast", [g.op("IsNaN", [values[col]])], to=TensorProto.FLOAT))
    for i, col in enumerate(contract.categorical_fields):
        vocab = contract.vocabularies[col]
        text = _column(g, INPUT_CATEGORICAL, i)
        outputs.append(g.op("LabelEncoder", [text], domain="ai.onnx.ml", keys_strings=list(vocab),
                            values_floats=[float(k) for k in range(len(vocab))], default_float=-1.0))
    return g, g.op("Concat", outputs, axis=1, out="model_features")


def tree_graph(booster_model: Any, n_features: int) -> Any:
    """用 onnxmltools 转换 XGBoost（opset 15），返回其 GraphProto；输入名为 ``model_features``。"""
    import onnxmltools
    from onnxmltools.convert.common.data_types import FloatTensorType

    onx = onnxmltools.convert_xgboost(booster_model, initial_types=[("model_features", FloatTensorType([None, n_features]))],
                                      target_opset=TREE_OPSET)
    ops = {n.op_type for n in onx.graph.node}
    if "TreeEnsembleClassifier" not in ops or ops - {"TreeEnsembleClassifier", "Identity", "Cast", "ZipMap"}:
        raise ExportError(f"unexpected XGBoost ONNX operators: {sorted(ops)}")
    if "ZipMap" in ops:
        raise ExportError("XGBoost ONNX graph contains ZipMap; probabilities must be a tensor")
    return onx.graph


def build_model(contract: Contract, booster_model: Any, debug_features: bool = False) -> Any:
    """完整 ONNX 模型：原始字段 → 预处理 → 树集成 → 攻击概率与阈值判定。``debug_features`` 额外输出特征矩阵（仅用于校验）。"""
    import onnx
    from onnx import TensorProto, helper

    g, features = preprocessing_graph(contract)
    tree = tree_graph(booster_model, len(contract.feature_names))
    prob_name = tree.output[1].name
    nodes = [*g.nodes, *tree.node]
    inits = [*g.initializers, *tree.initializer]
    tail = _Graph()
    tail._n = g._n
    positive = tail.op("Slice", [prob_name, tail.const([1], np.int64), tail.const([2], np.int64), tail.const([1], np.int64)])
    prob = tail.op("Reshape", [positive, tail.const([-1], np.int64)], out=OUTPUT_PROB)
    # 与训练时 numpy 判定一致：float32 概率提升为 double 后与冻结阈值（double）比较。
    tail.op("GreaterOrEqual", [tail.op("Cast", [prob], to=TensorProto.DOUBLE),
                               tail.const(contract.threshold, np.float64, "threshold")], out=OUTPUT_DECISION)
    nodes += tail.nodes
    inits += tail.initializers
    outputs = [helper.make_tensor_value_info(OUTPUT_PROB, TensorProto.FLOAT, ["N"]),
               helper.make_tensor_value_info(OUTPUT_DECISION, TensorProto.BOOL, ["N"])]
    if debug_features:
        outputs.append(helper.make_tensor_value_info(features, TensorProto.FLOAT, ["N", len(contract.feature_names)]))
    graph = helper.make_graph(nodes, "unsw_binary_flow_classifier", [
        helper.make_tensor_value_info(INPUT_NUMERIC, TensorProto.DOUBLE, ["N", len(contract.numeric_fields)]),
        helper.make_tensor_value_info(INPUT_CATEGORICAL, TensorProto.STRING, ["N", len(contract.categorical_fields)]),
    ], outputs, initializer=inits)
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid(d, v) for d, v in OPSET.items()],
                              producer_name="cyber_training.v2.export", ir_version=8)
    onnx.checker.check_model(model, full_check=True)
    return model

# ---------------------------------------------------------------- 校验

def session(model_bytes: bytes, threads: int | None = None) -> Any:
    import onnxruntime as ort

    options = ort.SessionOptions()
    if threads:
        options.intra_op_num_threads = threads
    return ort.InferenceSession(model_bytes, options, providers=["CPUExecutionProvider"])


def parity(sess: Any, inputs: dict[str, np.ndarray], reference_prob: np.ndarray, reference_features: np.ndarray | None,
           threshold: float) -> dict[str, Any]:
    """ONNX Runtime 输出与训练框架（sklearn 预处理 + XGBoost CPU）逐行比较。"""
    names = [OUTPUT_PROB, OUTPUT_DECISION] + (["model_features"] if reference_features is not None else [])
    out = sess.run(names, inputs)
    prob, decision = out[0].astype(np.float64), out[1].astype(bool)
    reference_decision = reference_prob >= threshold
    diff = np.abs(prob - reference_prob)
    result = {"rows": int(len(prob)), "parity_max_abs_diff": float(diff.max()), "mean_abs_diff": float(diff.mean()),
              "parity_decision_agreement": float((decision == reference_decision).mean()),
              "decision_mismatches": int((decision != reference_decision).sum()),
              "onnx_attack_rate": float(decision.mean())}
    if reference_features is not None:
        f = out[2]
        same_nan = np.isnan(f) == np.isnan(reference_features)
        result["feature_nan_pattern_equal"] = bool(same_nan.all())
        result["feature_max_abs_diff"] = float(np.nanmax(np.abs(np.where(np.isnan(f), 0, f)
                                                                 - np.where(np.isnan(reference_features), 0, reference_features))))
    return result, prob, decision


def benchmark(sess: Any, inputs: dict[str, np.ndarray]) -> dict[str, Any]:
    """单条延迟（逐条调用 ``run``）与 batch=1024 吞吐；只计时 ``run`` 本身。"""
    n = len(inputs[INPUT_NUMERIC])
    single = [{k: v[j % n:j % n + 1] for k, v in inputs.items()} for j in range(LATENCY_RUNS + LATENCY_WARMUP)]
    times = []
    for j, feed in enumerate(single):
        start = time.perf_counter()
        sess.run([OUTPUT_PROB], feed)
        if j >= LATENCY_WARMUP:
            times.append((time.perf_counter() - start) * 1000.0)
    batch = {k: v[:BATCH_SIZE] for k, v in inputs.items()}
    for _ in range(5):
        sess.run([OUTPUT_PROB], batch)
    start = time.perf_counter()
    for _ in range(BATCH_RUNS):
        sess.run([OUTPUT_PROB], batch)
    elapsed = time.perf_counter() - start
    lat = np.asarray(times)
    return {"latency_runs": LATENCY_RUNS, "latency_p50_ms": float(np.percentile(lat, 50)),
            "latency_p95_ms": float(np.percentile(lat, 95)), "latency_p99_ms": float(np.percentile(lat, 99)),
            "batch_size": BATCH_SIZE, "batch_runs": BATCH_RUNS,
            "batch_latency_ms": float(elapsed / BATCH_RUNS * 1000.0),
            "batch_throughput_rows_per_s": float(BATCH_SIZE * BATCH_RUNS / elapsed)}


def judge_export(values: dict[str, float]) -> list[dict[str, Any]]:
    out = []
    for key, name, op, limit in EXPORT_GATES:
        value = float(values[key])
        ok = value >= limit if op == ">=" else value <= limit
        out.append({"metric": key, "name": name, "value": value, "op": op, "threshold": limit, "passed": bool(ok)})
    return out

# ---------------------------------------------------------------- 前置条件与数据

def load_verdict(record: dict[str, Any], freeze_sha: str) -> tuple[Path, dict[str, Any]]:
    """最新的第 9 步运行必须通过判定，且对应当前冻结文件。"""
    runs = sorted(RUNS_ROOT.glob("final-eval-*/final-verdict.json"))
    if not runs:
        raise ExportError("no final-eval run with final-verdict.json; run step 9 first")
    path = runs[-1]
    verdict = json.loads(path.read_text(encoding="utf-8"))
    if verdict.get("freeze_sha256") != freeze_sha:
        raise ExportError("latest final-verdict.json belongs to a different freeze")
    if not verdict.get("passed_step9") or verdict.get("deliverable") != "pending_export":
        raise ExportError("step 9 did not pass; the candidate cannot be exported")
    if verdict.get("candidate") != record["t1"]["model"] or float(verdict["threshold"]) != float(record["t1"]["threshold"]):
        raise ExportError("final-verdict.json candidate/threshold differ from the freeze")
    return path.parent, verdict


def validation_sample(record: dict[str, Any], size: int = PARITY_ROWS, seed: int = GLOBAL_SEED
                      ) -> tuple[np.ndarray, pd.DataFrame, np.ndarray]:
    """从验证分区固定种子抽样（不解锁 holdout），返回 (行号, 原始字段帧, 标签)。"""
    manifest_file, manifest = load_manifest()
    if sha256_file(manifest_file) != record["register_manifest"]["sha256"]:
        raise FreezeError("register manifest changed since freeze")
    split = SplitIndex.load(ROOT / record["split"]["dir"] / "split-d1-raw.npz", audit_log=AUDIT_LOG)
    if split.fingerprint != record["split"]["d1_raw_fingerprint"]:
        raise LeakageError("D1 split changed since freeze")
    rows = np.sort(np.random.default_rng(seed).choice(split.validation, size=size, replace=False))
    raw = load_cached("d1_raw.parquet", manifest, columns=[*V1_RAW_COLUMNS, "Label"])
    sample = raw.iloc[rows].reset_index(drop=True)
    del raw
    return rows, sample, sample["Label"].to_numpy(dtype=np.int8)

# ---------------------------------------------------------------- 交付文件

def preprocessing_contract(contract: Contract) -> dict[str, Any]:
    """``preprocessing.json``：图内预处理的可审查说明。ONNX 图已包含全部步骤，后端不得重复实现预处理。"""
    return {
        "contract_version": FEATURE_CONTRACT_VERSION,
        "embedded_in_onnx": True,
        "note": "预处理已打包进 model.onnx；后端只负责按顺序提供原始字段、校验单位与缺失规则，不得自行插补或编码。",
        "inputs": {
            INPUT_NUMERIC: {"dtype": "float64", "shape": ["N", len(contract.numeric_fields)],
                            "fields": [{"index": i, "name": f, "unit": FIELD_SPEC[f][0], "description": FIELD_SPEC[f][1],
                                        "nullable": f in NULLABLE_FIELDS, "min": 0}
                                       for i, f in enumerate(contract.numeric_fields)]},
            INPUT_CATEGORICAL: {"dtype": "string", "shape": ["N", len(contract.categorical_fields)],
                                "fields": [{"index": i, "name": f, "description": FIELD_SPEC[f][1],
                                            "vocabulary": list(contract.vocabularies[f]), "unknown_encoded_as": -1}
                                           for i, f in enumerate(contract.categorical_fields)]},
        },
        "input_rules": [
            "非 nullable 数值字段出现 NaN、±Inf 或负数时拒绝推理（fail-closed），不得补 0 或补中位数。",
            f"nullable 字段（{', '.join(NULLABLE_FIELDS)}）以 NaN 表示缺失，由图内中位数插补并生成缺失指示列。",
            "类别字段为 UNSW-NB15 Argus 输出的原始小写字符串；词表外取值在图内编码为 -1，后端应记录为漂移信号。",
            "字段单位必须与 UNSW-NB15 一致（dur 为秒，sinpkt/dinpkt/sjit/djit 为毫秒，sload/dload 为比特/秒）；来源不能证明单位一致时拒绝推理。",
        ],
        "derived_features": [{"name": n, "formula": DERIVED[n][2], "inputs": list(DERIVED[n][0]),
                              "precision": "float64（原始值）" if DERIVED[n][1] == "raw" else "输入先舍入为 float32 再以 float64 计算",
                              "non_finite": "NaN（随后插补）"} for n in contract.columns if n in DERIVED],
        "imputation": {"strategy": "median（仅训练分区拟合）",
                       "medians": {c: m for c, m in zip([c for c in contract.columns if c not in CATEGORICAL], contract.medians)},
                       "missing_indicators": [f"missingindicator_{c}" for c in contract.indicator_columns]},
        "encoding": {"method": "ordinal（词表顺序即编码值）", "unknown_or_missing": -1},
        "model_feature_order": list(contract.feature_names),
        "outputs": {OUTPUT_PROB: "float32[N]，攻击概率", OUTPUT_DECISION: f"bool[N]，attack_probability >= {contract.threshold!r}"},
    }


def write_replay(path: Path, inputs: dict[str, np.ndarray], contract: Contract, prob: np.ndarray, decision: np.ndarray,
                 labels: np.ndarray) -> None:
    """本机回放样本：原始输入字段（float64 以 repr 精确写出）+ 远端 ONNX 输出。不含地址、端口、时间戳或行号。"""
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow([*contract.numeric_fields, *contract.categorical_fields, "label", "expected_probability", "expected_is_attack"])
        for i in range(len(prob)):
            writer.writerow([*(repr(float(v)) for v in inputs[INPUT_NUMERIC][i]), *inputs[INPUT_CATEGORICAL][i],
                             int(labels[i]), repr(float(np.float32(prob[i]))), int(decision[i])])


def build_manifest(version: str, record: dict[str, Any], verdict_dir: Path, contract: Contract,
                   files: dict[str, str], gates: list[dict[str, Any]], perf: dict[str, Any], parity_result: dict[str, Any],
                   train_commit: str, export_commit: str, model_size: int) -> dict[str, Any]:
    t1 = record["t1"]
    holdout = json.loads((verdict_dir / "t1-holdout-metrics.json").read_text(encoding="utf-8"))
    return {
        "manifest_version": MANIFEST_VERSION,
        "model_key": MODEL_KEY, "model_version": f"{MODEL_KEY}-{version}", "version": version,
        "task": "binary_flow_classification",
        "created_at": datetime.now().astimezone().isoformat(),
        "algorithm": {"name": "XGBoost", "library_version": package_versions()["xgboost"], "params": t1["params"],
                      "best_iteration": t1["best_iteration"], "trees_used": t1["best_iteration"] + 1, "seed": t1["seed"]},
        "artifact": {"file": "model.onnx", "format": "onnx", "sha256": files["model.onnx"], "size_bytes": model_size,
                     "opset": OPSET, "ir_version": 8, "preprocessing_embedded": True},
        "runtime": {**RUNTIME, "tested_onnxruntime": package_versions()["onnxruntime"],
                    "custom_ops": False, "note": "只使用 ONNX 标准算子与 ai.onnx.ml 的 LabelEncoder / TreeEnsembleClassifier"},
        "dataset": {"name": "UNSW-NB15（Kaggle mrwellsdavid/unsw-nb15，原始 4 个 CSV）",
                    "register_manifest_sha256": record["register_manifest"]["sha256"],
                    "split_fingerprint": record["split"]["d1_raw_fingerprint"],
                    "split_audit_sha256": record["split"]["split_audit_sha256"]},
        "feature_contract": {"version": FEATURE_CONTRACT_VERSION, "view": t1["view"], "preprocessing_scheme": t1["scheme"],
                             "inputs": {INPUT_NUMERIC: list(contract.numeric_fields), INPUT_CATEGORICAL: list(contract.categorical_fields)},
                             "model_features": list(contract.feature_names), "contract_file": "preprocessing.json"},
        "labels": {"0": "Normal", "1": "Attack"},
        "decision": {"output": OUTPUT_DECISION, "probability_output": OUTPUT_PROB, "threshold": contract.threshold,
                     "rule": "attack_probability >= threshold → Attack", "policy": t1["threshold_policy"],
                     "selected_on": "validation", "adjustable": False},
        "evaluation": {
            "validation": t1["validation_metrics"],
            "holdout": {k: holdout[k] for k in ("rows", "attack_rows", "accuracy", "precision", "recall", "macro_f1",
                                                "weighted_f1", "roc_auc", "pr_auc", "fpr", "fnr", "mcc", "confusion")},
            "holdout_run": verdict_dir.name, "step9_passed": True,
            "export_gates": gates, "performance": perf,
            "parity": {k: parity_result[k] for k in ("rows", "parity_max_abs_diff", "parity_decision_agreement")},
        },
        "provenance": {"freeze_file": FREEZE_REL, "freeze_sha256": sha256_file(ROOT / FREEZE_REL),
                       "freeze_commit": _git("log", "-1", "--format=%H", "--", FREEZE_REL),
                       "training_commit": train_commit, "export_commit": export_commit,
                       "candidate_run": t1["source_run"], "candidate_files": t1["files"]},
        "limitations": [
            "只适用于 UNSW-NB15 分布的流量特征二分类；跨数据集（NF-ToN-IoT-v2）评估接近随机，不能用于其他网络环境的直接判定。",
            "不做攻击类别判定，也不等同于原始包检测、终端行为识别或攻击阶段预测。",
            "输入字段缺失、单位不符或非法数值时必须拒绝推理并转人工/规则研判，不得静默造值。",
            "工作点对阈值敏感（holdout 上阈值 0.30→0.35 时 FNR 从 4.70% 升至 5.79%），后端不得调整阈值。",
            "Fuzzers（检出率 81.1%）与 Analysis（76.7%）是主要漏报来源。",
            "模型权重在线冻结；再训练只能在离线训练环境按计划执行并重新审批。",
        ],
        "activation": {"status": "candidate", "requires": ["后端校验 checksums.json 与 manifest 中的 SHA-256",
                                                          "本机 ONNX Runtime 回放 replay-sample.csv 与远端输出一致",
                                                          "人工审批后才能激活"]},
        "files": files,
    }

def write_report(path: Path, manifest: dict[str, Any], parity_result: dict[str, Any], perf: dict[str, Any],
                 gates: list[dict[str, Any]], passed: bool) -> None:
    ev = manifest["evaluation"]["holdout"]
    lines = [
        f"# 第 10 步：导出与交付（{manifest['model_version']}）", "",
        f"候选：XGBoost（{manifest['algorithm']['trees_used']} 棵树），视图 {manifest['feature_contract']['view']}，"
        f"预处理 {manifest['feature_contract']['preprocessing_scheme']}，冻结阈值 {manifest['decision']['threshold']:.6f}。", "",
        "预处理（派生特征、中位数插补与缺失指示、类别有序编码）与模型打包为同一个 ONNX 图"
        f"（opset {OPSET['']}，ai.onnx.ml {OPSET['ai.onnx.ml']}），后端只需按 `preprocessing.json` 顺序提供原始字段。", "",
        "## 第 10 步门槛", "", "| 指标 | 门槛 | 实测 | 结果 |", "|---|---|---:|---|",
    ]
    for g in gates:
        op = g["op"].replace(">=", "≥").replace("<=", "≤")
        value = f"{g['value']:.3e}" if g["metric"] == "parity_max_abs_diff" else (
            f"{g['value'] * 100:.2f}%" if g["metric"] == "parity_decision_agreement" else f"{g['value']:,.3f}")
        lines.append(f"| {g['name']} | {op} {g['threshold']:g} | {value} | {'通过' if g['passed'] else '**未通过**'} |")
    lines += ["", f"**第 10 步判定：{'通过，可提交本机审批' if passed else '未通过，不能交付'}**。", "",
              "## 一致性（验证分区固定种子抽样，holdout 未读取）", "",
              f"- 样本 {parity_result['rows']:,} 条；ONNX Runtime 与训练框架（sklearn 预处理 + XGBoost CPU）概率最大绝对误差 "
              f"{parity_result['parity_max_abs_diff']:.3e}，平均 {parity_result['mean_abs_diff']:.3e}；"
              f"阈值判定不一致 {parity_result['decision_mismatches']} 条。",
              f"- 图内特征矩阵与 sklearn 预处理输出：缺失位置一致 = {parity_result['feature_nan_pattern_equal']}，"
              f"最大绝对误差 {parity_result['feature_max_abs_diff']:.3e}。", "",
              "## 性能（ONNX Runtime CPU，训练主机）", "",
              f"- 单条：P50 {perf['latency_p50_ms']:.3f} ms、P95 {perf['latency_p95_ms']:.3f} ms、P99 {perf['latency_p99_ms']:.3f} ms"
              f"（{perf['latency_runs']} 次，线程数 {perf['threads']}）。",
              f"- batch {perf['batch_size']}：每批 {perf['batch_latency_ms']:.2f} ms，吞吐 {perf['batch_throughput_rows_per_s']:,.0f} 条/秒。",
              f"- 模型大小 {manifest['artifact']['size_bytes'] / 1024 / 1024:.2f} MiB。", "",
              "## holdout 指标（第 9 步，未重新评估）", "",
              f"Macro-F1 {ev['macro_f1']:.4f}、FNR {ev['fnr'] * 100:.2f}%、FPR {ev['fpr'] * 100:.2f}%、"
              f"PR-AUC {ev['pr_auc']:.4f}、ROC-AUC {ev['roc_auc']:.4f}（{ev['rows']:,} 行）。", "",
              "## 本机验证（待执行）", "",
              "交付目录传到本机后，后端应校验 `checksums.json` 与 manifest 中的 SHA-256，用本机 ONNX Runtime 回放 "
              "`replay-sample.csv`（输入与远端输出），概率误差与判定一致性按同一门槛判定，并把结果追加到本报告。", "",
              "## 使用限制", "", *(f"- {item}" for item in manifest["limitations"])]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run(candidate: str | None = None, version: str = DEFAULT_VERSION) -> Path:
    """执行第 10 步。门槛全部通过时写 ``delivery/unsw-binary-<version>/``；已存在同版本交付目录时拒绝覆盖。"""
    import onnx

    record, freeze_sha = load_freeze()
    t1 = record["t1"]
    if candidate and candidate != t1["model"]:
        raise FreezeError(f"--candidate {candidate} differs from frozen T1 model {t1['model']}")
    if t1["model"] != "XGBoost":
        raise ExportError(f"export supports the frozen XGBoost candidate only, got {t1['model']}")
    verdict_dir, _ = load_verdict(record, freeze_sha)
    delivery = DELIVERY_ROOT / f"{MODEL_KEY}-{version}"
    if delivery.exists():
        raise FileExistsError(f"delivery directory already exists: {_rel(delivery)}")
    candidate_dir = RUNS_ROOT / t1["source_run"] / "candidate"
    verify_files(candidate_dir, t1["files"])

    ctx = RunContext("export", GLOBAL_SEED, {"freeze_file": FREEZE_REL, "freeze_sha256": freeze_sha, "version": version,
                                              "candidate": t1["model"], "parity_rows": PARITY_ROWS, "opset": OPSET})
    run_dir = ctx.run_dir
    say = _logger(run_dir / "training.log")
    with keep_awake():
        model = T1Model(t1["model"], candidate_dir, t1["files"])
        contract = contract_from(model.preprocessor, t1["columns"], t1["threshold"])
        if model.impl.n_features_in_ != len(contract.feature_names):
            raise ExportError("XGBoost feature count differs from the preprocessor output")
        onx = build_model(contract, model.impl)
        debug = build_model(contract, model.impl, debug_features=True)
        model_bytes = onx.SerializeToString()
        (run_dir / "model.onnx").write_bytes(model_bytes)
        say(f"onnx built: {len(model_bytes)} bytes, ops={sorted({n.op_type for n in onx.graph.node})}")

        _, raw, labels = validation_sample(record)
        view = build_v2(raw)[list(t1["columns"])]
        ref_features = model.preprocessor.transform(view).astype(np.float32)
        ref_prob = model.predict(view).astype(np.float64)
        inputs = raw_inputs(raw, contract)
        result, prob, decision = parity(session(debug.SerializeToString()), inputs, ref_prob, ref_features, contract.threshold)
        # 交付图（无调试输出）必须与调试图给出相同结果。
        final_prob = session(model_bytes).run([OUTPUT_PROB], inputs)[0]
        if not np.array_equal(final_prob, prob.astype(np.float32)):
            raise ExportError("delivery graph output differs from the debug graph")
        say(f"parity max_abs_diff={result['parity_max_abs_diff']:.3e} mismatches={result['decision_mismatches']}")

        threads = 1
        perf = {"threads": threads, **benchmark(session(model_bytes, threads=threads), inputs)}
        say(f"latency p95={perf['latency_p95_ms']:.3f}ms throughput={perf['batch_throughput_rows_per_s']:.0f}/s")
        gates = judge_export({**result, **perf})
        passed = all(g["passed"] for g in gates)
        write_json(run_dir / "export-parity.json", result)
        write_json(run_dir / "export-performance.json", perf)
        write_json(run_dir / "preprocessing.json", preprocessing_contract(contract))
        write_replay(run_dir / "replay-sample.csv", inputs, contract, prob, decision, labels)

        train_cfg = json.loads((RUNS_ROOT / t1["source_run"] / "run-config.json").read_text(encoding="utf-8"))
        files = {name: sha256_file(run_dir / name) for name in ("model.onnx", "preprocessing.json", "replay-sample.csv")}
        manifest = build_manifest(version, record, verdict_dir, contract, files, gates, perf, result,
                                  train_cfg["git"]["commit"], _git("rev-parse", "HEAD"), len(model_bytes))
        manifest["export"] = {"run": run_dir.name, "passed": passed,
                              "deliverable": "ready_for_review" if passed else "rejected"}
        write_json(run_dir / "model_manifest.json", manifest)
        write_json(run_dir / "export-verdict.json", {"freeze_sha256": freeze_sha, "run": run_dir.name, "gates": gates,
                                                      "passed_step10": passed,
                                                      "deliverable": manifest["export"]["deliverable"]})
        write_report(run_dir / "evaluation-report.md", manifest, result, perf, gates, passed)
        onnx.checker.check_model(run_dir / "model.onnx", full_check=True)
    ctx.finish()
    if passed:
        package(run_dir, verdict_dir, delivery)
        say(f"delivery written: {_rel(delivery)}")
    else:
        say("export gates failed; no delivery directory written")
    return run_dir


DELIVERY_FILES = ("model.onnx", "preprocessing.json", "model_manifest.json", "evaluation-report.md", "replay-sample.csv",
                  "export-parity.json", "export-performance.json", "export-verdict.json")
EVIDENCE_FROM_STEP9 = ("final-evaluation.md", "final-verdict.json", "t1-holdout-metrics.json", "t1-holdout-category-recall.csv",
                       "t1-roc-pr.png", "t1-threshold-sensitivity.csv", "t1-threshold-sensitivity.png", "generalization.csv")


def package(run_dir: Path, verdict_dir: Path, delivery: Path) -> Path:
    """复制交付文件与第 9 步评估证据，生成 ``checksums.json``（覆盖交付目录内全部文件）。"""
    (delivery / "evidence").mkdir(parents=True)
    for name in DELIVERY_FILES:
        shutil.copy2(run_dir / name, delivery / name)
    for name in EVIDENCE_FROM_STEP9:
        shutil.copy2(verdict_dir / name, delivery / "evidence" / name)
    RunContext.checksum_dir(delivery)
    return delivery
