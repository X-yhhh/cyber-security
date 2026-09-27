"""特征视图构造。

V0：与 UNSW-NB15 官方 45 列子集同名的 42 个预测特征，由原始数据按字段名映射得到；
``rate`` 在原始数据中不存在，按 ``(Spkts + Dpkts - 1) / dur`` 派生，``dur=0`` 时记为缺失（不造值）。
"""

from __future__ import annotations

import numpy as np
import pandas as pd

V0_FEATURES = (
    "dur", "proto", "service", "state", "spkts", "dpkts", "sbytes", "dbytes", "rate",
    "sttl", "dttl", "sload", "dload", "sloss", "dloss", "sinpkt", "dinpkt", "sjit", "djit",
    "swin", "stcpb", "dtcpb", "dwin", "tcprtt", "synack", "ackdat", "smean", "dmean",
    "trans_depth", "response_body_len", "ct_srv_src", "ct_state_ttl", "ct_dst_ltm",
    "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm", "is_ftp_login", "ct_ftp_cmd",
    "ct_flw_http_mthd", "ct_src_ltm", "ct_srv_dst", "is_sm_ips_ports",
)
V0_CATEGORICAL = ("proto", "service", "state")
# 子集字段名 → 原始数据字段名（register 已去除原始字段名中的空白）。
SUBSET_TO_RAW = {
    "dur": "dur", "proto": "proto", "service": "service", "state": "state",
    "spkts": "Spkts", "dpkts": "Dpkts", "sbytes": "sbytes", "dbytes": "dbytes",
    "sttl": "sttl", "dttl": "dttl", "sload": "Sload", "dload": "Dload",
    "sloss": "sloss", "dloss": "dloss", "sinpkt": "Sintpkt", "dinpkt": "Dintpkt",
    "sjit": "Sjit", "djit": "Djit", "swin": "swin", "stcpb": "stcpb", "dtcpb": "dtcpb",
    "dwin": "dwin", "tcprtt": "tcprtt", "synack": "synack", "ackdat": "ackdat",
    "smean": "smeansz", "dmean": "dmeansz", "trans_depth": "trans_depth",
    "response_body_len": "res_bdy_len", "ct_srv_src": "ct_srv_src", "ct_state_ttl": "ct_state_ttl",
    "ct_dst_ltm": "ct_dst_ltm", "ct_src_dport_ltm": "ct_src_dport_ltm",
    "ct_dst_sport_ltm": "ct_dst_sport_ltm", "ct_dst_src_ltm": "ct_dst_src_ltm",
    "is_ftp_login": "is_ftp_login", "ct_ftp_cmd": "ct_ftp_cmd", "ct_flw_http_mthd": "ct_flw_http_mthd",
    "ct_src_ltm": "ct_src_ltm", "ct_srv_dst": "ct_srv_dst", "is_sm_ips_ports": "is_sm_ips_ports",
}
V0_RAW_COLUMNS = sorted(set(SUBSET_TO_RAW.values()))


class FeatureContractError(ValueError):
    """输入缺少构造特征视图所需的字段。"""


def build_v0(raw: pd.DataFrame) -> pd.DataFrame:
    """由 D1 原始数据构造 V0 视图（42 列，顺序固定为 ``V0_FEATURES``）。

    数值列转为 float32 以控制内存；类别列保持字符串。缺少任何映射字段即终止，不补默认值。
    """
    missing = sorted(set(V0_RAW_COLUMNS) - set(raw.columns))
    if missing:
        raise FeatureContractError(f"raw frame lacks V0 source columns: {missing}")
    out: dict[str, pd.Series] = {}
    for name in V0_FEATURES:
        if name == "rate":
            duration = raw["dur"].astype("float64")
            packets = raw["Spkts"].astype("float64") + raw["Dpkts"].astype("float64") - 1.0
            rate = packets / duration.where(duration != 0)
            out[name] = rate.replace([np.inf, -np.inf], np.nan).astype("float32")
        elif name in V0_CATEGORICAL:
            out[name] = raw[SUBSET_TO_RAW[name]].astype("string")
        else:
            out[name] = raw[SUBSET_TO_RAW[name]].astype("float32")
    return pd.DataFrame(out, index=raw.index)[list(V0_FEATURES)]


# ---------------------------------------------------------------- V1～V4（第 7 步）

V1_RAW_COLUMNS = sorted({*V0_RAW_COLUMNS, "dsport"})
DSPORT_BUCKET = "dsport_bucket"
V1_FEATURES = (*V0_FEATURES, DSPORT_BUCKET)
V2_ENGINEERED = (
    "sbytes_per_spkt", "dbytes_per_dpkt", "sbytes_dbytes_ratio", "spkts_dpkts_ratio",
    "ttl_diff", "synack_ackdat_diff", "bytes_rate",
)
V2_FEATURES = (*V1_FEATURES, *V2_ENGINEERED)
CATEGORICAL = (*V0_CATEGORICAL, DSPORT_BUCKET)
# 近似随机的 TCP 初始序列号，V3 中直接删除。
RANDOM_ISN = ("stcpb", "dtcpb")
# UNSW 实验环境中取值较固定的 TTL 特征，V4 诊断时删除。
TTL_FEATURES = ("sttl", "dttl", "ct_state_ttl")
RAW_TO_SUBSET = {raw: subset for subset, raw in SUBSET_TO_RAW.items()}


def dsport_bucket(dsport: pd.Series) -> pd.Series:
    """目的端口分桶：well_known 0–1023 / registered 1024–49151 / dynamic 49152–65535。

    缺失或超出 0–65535 的值归入 ``missing``，不猜测其真实端口。
    """
    port = pd.to_numeric(dsport, errors="coerce").astype("float64")
    bucket = pd.Series("missing", index=dsport.index, dtype="object")
    bucket[(port >= 0) & (port <= 1023)] = "well_known"
    bucket[(port >= 1024) & (port <= 49151)] = "registered"
    bucket[(port >= 49152) & (port <= 65535)] = "dynamic"
    return bucket.astype("string")


def build_v1(raw: pd.DataFrame) -> pd.DataFrame:
    """V1 = V0 + ``dsport_bucket``。``dsport`` 本身不入模，只提供分桶。"""
    if "dsport" not in raw.columns:
        raise FeatureContractError("raw frame lacks dsport for V1")
    out = build_v0(raw)
    out[DSPORT_BUCKET] = dsport_bucket(raw["dsport"])
    return out[list(V1_FEATURES)]


def add_engineered(view: pd.DataFrame) -> pd.DataFrame:
    """在 V1 上追加 V2 的比率、差值与速率特征（按计划 §6 定义，分母加常数避免除零）。

    不做 log1p：单调变换不改变树模型分裂，且 log1p 不能直接导出 ONNX。
    """
    f = {c: view[c].astype("float64") for c in ("sbytes", "dbytes", "spkts", "dpkts", "sttl", "dttl",
                                                 "synack", "ackdat", "dur")}
    extra = {
        "sbytes_per_spkt": f["sbytes"] / (f["spkts"] + 1.0),
        "dbytes_per_dpkt": f["dbytes"] / (f["dpkts"] + 1.0),
        "sbytes_dbytes_ratio": f["sbytes"] / (f["dbytes"] + 1.0),
        "spkts_dpkts_ratio": f["spkts"] / (f["dpkts"] + 1.0),
        "ttl_diff": f["sttl"] - f["dttl"],
        "synack_ackdat_diff": f["synack"] - f["ackdat"],
        "bytes_rate": (f["sbytes"] + f["dbytes"]) / (f["dur"] + 1e-6),
    }
    out = view.copy()
    for name in V2_ENGINEERED:
        out[name] = extra[name].replace([np.inf, -np.inf], np.nan).astype("float32")
    return out


def build_v2(raw: pd.DataFrame) -> pd.DataFrame:
    return add_engineered(build_v1(raw))[list(V2_FEATURES)]


def redundancy_drops(pairs: pd.DataFrame, mutual_information: pd.Series, columns: list[str] | tuple[str, ...]
                     ) -> list[str]:
    """按 |ρ| 降序贪心去冗余：一对特征都还在时删除互信息较低者（持平时删除第二个）。

    ``pairs`` 为 EDA 的 ``feature_a, feature_b, spearman``（原始字段名），``mutual_information``
    以原始字段名为索引；两者都按 ``SUBSET_TO_RAW`` 映射到 V0 名称。返回按删除顺序排列的列名。
    """
    to_view = lambda name: RAW_TO_SUBSET.get(name, name)  # noqa: E731
    mi = {to_view(k): float(v) for k, v in mutual_information.items()}
    kept = set(columns)
    dropped: list[str] = []
    ordered = pairs.assign(_abs=pairs["spearman"].abs()).sort_values("_abs", ascending=False, kind="mergesort")
    for row in ordered.itertuples():
        a, b = to_view(row.feature_a), to_view(row.feature_b)
        if a not in kept or b not in kept:
            continue
        if a not in mi or b not in mi:
            raise FeatureContractError(f"mutual information missing for redundancy pair {a}/{b}")
        victim = a if mi[a] < mi[b] else b
        kept.discard(victim)
        dropped.append(victim)
    return dropped


def cumulative_importance_keep(importance: pd.Series, share: float = 0.99) -> list[str]:
    """按重要性降序保留累计占比达到 ``share`` 所需的最少特征（含跨过阈值的那一个）。"""
    ordered = importance.sort_values(ascending=False, kind="mergesort")
    total = float(ordered.sum())
    if total <= 0:
        raise ValueError("importance sums to zero; cannot select features")
    cumulative = ordered.cumsum() / total
    count = int((cumulative < share).sum()) + 1
    return list(ordered.index[:min(count, len(ordered))])


def numeric_features(columns: list[str] | tuple[str, ...]) -> list[str]:
    return [c for c in columns if c not in CATEGORICAL]


def categorical_features(columns: list[str] | tuple[str, ...]) -> list[str]:
    return [c for c in columns if c in CATEGORICAL]
