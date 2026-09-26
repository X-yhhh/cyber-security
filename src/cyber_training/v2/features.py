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


def numeric_features(columns: list[str] | tuple[str, ...]) -> list[str]:
    return [c for c in columns if c not in V0_CATEGORICAL]


def categorical_features(columns: list[str] | tuple[str, ...]) -> list[str]:
    return [c for c in columns if c in V0_CATEGORICAL]
