"""路线 B 阶段 2 第 8 项：golden fixtures，只验证「流记录 → 特征 → 输出」这一层（包 → 流记录由阶段 6 另建）。

- 选主机 H：验证分区中入站攻击最多的 responder（只用验证分区标签挑主机，holdout 无法解锁）。
- 取 H 时间轴上作为源或目的的连续 400 条流（已按 D12 排除的流不计），即传感器部署在 H 上时看到的全部流。
- 地址按首次出现顺序一一映射到 RFC 5737 文档保留地址段；端口、协议、时间保持原值。
- 一条入站流的协议改为词表外取值 ``proto-253``，覆盖 OOV 情形。
- 期望特征用 ``feature_audit.recompute_ct`` 只在这 400 条流上计算；期望输出由交付 ONNX 图只在
  「H 为 responder 且窗口已满」的流上计算。出站流记 ``not_in_model_scope``，窗口未满记 ``window_not_ready``。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from .datasets import load_cached
from .export import INPUT_CATEGORICAL, INPUT_NUMERIC, OUTPUT_DECISION, OUTPUT_PROB
from .feature_audit import recompute_ct
from .guard import SplitIndex
from .route_b_v4 import CT_V4, NUMERIC
from .runtime import RunContext, sha256_file, write_json

DOC_BLOCKS = ("192.0.2.", "198.51.100.", "203.0.113.")
MAX_ADDRESSES = 250 * len(DOC_BLOCKS)
BEFORE, AFTER, OOV_POSITION = 150, 250, 120
OOV_PROTO = "proto-253"
SINGLE = {"dur": "dur", "sbytes": "sbytes", "dbytes": "dbytes", "sload": "Sload", "dload": "Dload", "tcprtt": "tcprtt",
          "ackdat": "ackdat", "synack": "synack", "smean": "smeansz", "dmean": "dmeansz", "spkts": "Spkts", "dpkts": "Dpkts"}
META = ["srcip", "sport", "dstip", "dsport", "proto", "Stime", "Ltime"]


def doc_address(i: int) -> str:
    """第 i 个地址 → 文档保留地址；主机号 1～250，避开网络号与广播地址。"""
    return f"{DOC_BLOCKS[i // 250]}{i % 250 + 1}"


def select_slice(raw: pd.DataFrame, excluded: np.ndarray, validation: np.ndarray) -> tuple[np.ndarray, str]:
    v = raw.iloc[validation]
    host = v.loc[v["Label"].to_numpy() == 1, "dstip"].value_counts().index[0]
    src, dst = raw["srcip"].to_numpy(), raw["dstip"].to_numpy()
    touch = np.flatnonzero(((src == host) | (dst == host)) & ~excluded)
    order = touch[np.lexsort((touch, raw["Stime"].to_numpy()[touch], raw["Ltime"].to_numpy()[touch]))]
    anchor_ok = np.isin(order, validation) & (raw["Label"].to_numpy()[order] == 1) & (dst[order] == host)
    anchor = int(np.flatnonzero(anchor_ok & (np.arange(order.size) >= BEFORE))[0])
    return order[anchor - BEFORE: anchor + AFTER], host


def _dump(path: Path, records: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for r in records:
            stream.write(json.dumps(r, ensure_ascii=False) + "\n")


def build(manifest: dict[str, Any], split_dir: Path, excluded: np.ndarray, sess: Any, out_dir: Path) -> dict[str, Any]:
    """生成 fixtures 目录（含 checksums.json），返回写入 manifest 的摘要。"""
    raw = load_cached("d1_raw.parquet", manifest, columns=[*META, *SINGLE.values(), "Label"])
    split = SplitIndex.load(Path(split_dir) / "split-d1-raw.npz")  # 不传审计日志：holdout 无法解锁
    rows, host = select_slice(raw, excluded, np.sort(split.validation))
    flows = raw.iloc[rows][[*META, *SINGLE.values()]].reset_index(drop=True)
    del raw
    uniq = list(dict.fromkeys(np.column_stack([flows["srcip"].to_numpy(), flows["dstip"].to_numpy()]).ravel()))
    if len(uniq) > MAX_ADDRESSES:
        raise ValueError(f"too many distinct addresses for documentation ranges: {len(uniq)}")
    mapping = {ip: doc_address(i) for i, ip in enumerate(uniq)}
    flows["srcip"], flows["dstip"] = flows["srcip"].map(mapping), flows["dstip"].map(mapping)
    sensor = mapping[host]
    for load, pkts in (("Sload", "Spkts"), ("Dload", "Dpkts")):  # 规格 §4
        flows.loc[((flows["dur"] <= 0) | (flows[pkts] <= 1)).to_numpy(), load] = 0.0
    inbound = (flows["dstip"] == sensor).to_numpy()
    oov = int(np.flatnonzero(inbound & (np.arange(len(flows)) >= OOV_POSITION))[0])
    flows["proto"] = flows["proto"].astype("string")
    flows.loc[oov, "proto"] = OOV_PROTO
    ct = recompute_ct(flows)
    status = np.where(~inbound, "not_in_model_scope",
                      np.where(ct["window_ready"].to_numpy(), "scored", "window_not_ready"))
    numeric = np.column_stack([flows[SINGLE[f]].to_numpy(dtype=np.float64) if f in SINGLE
                               else ct[f"{f}_v4"].to_numpy(dtype=np.float64) for f in NUMERIC])
    categorical = np.column_stack([flows["proto"].to_numpy(dtype=object),
                                   ct["service_v4"].to_numpy(dtype=object)]).astype(str)
    scored = np.flatnonzero(status == "scored")
    prob, decision = sess.run([OUTPUT_PROB, OUTPUT_DECISION],
                              {INPUT_NUMERIC: numeric[scored], INPUT_CATEGORICAL: categorical[scored]})
    out_dir.mkdir(parents=True)
    recs = flows.to_dict("records")
    _dump(out_dir / "raw-flows.jsonl", [
        {"seq": i, "srcip": r["srcip"], "sport": int(r["sport"]), "dstip": r["dstip"], "dsport": int(r["dsport"]),
         "proto": str(r["proto"]), "stime": int(r["Stime"]), "ltime": int(r["Ltime"]),
         **{f: float(r[c]) for f, c in SINGLE.items()}} for i, r in enumerate(recs)])
    feats = []
    for i in range(len(flows)):
        row = {"seq": i, "status": str(status[i])}
        for j, f in enumerate(NUMERIC):
            hide = f in CT_V4 and status[i] != "scored"
            row[f] = None if hide or np.isnan(numeric[i, j]) else float(numeric[i, j])
        feats.append({**row, "proto": categorical[i, 0], "service": categorical[i, 1]})
    _dump(out_dir / "expected-features.jsonl", feats)
    _dump(out_dir / "expected-outputs.jsonl", [{"seq": int(i), "attack_probability": float(p), "is_attack": bool(d)}
                                               for i, p, d in zip(scored, prob, decision)])
    s = status == "scored"
    col = lambda name: numeric[:, NUMERIC.index(name)]  # noqa: E731
    with np.errstate(invalid="ignore"):
        coverage = {
            "single_packet": bool((s & (col("spkts") + col("dpkts") == 1)).any()),
            "dur_zero": bool((s & (col("dur") == 0)).any()),
            "tcp_handshake_incomplete": bool((s & (categorical[:, 0] == "tcp") & (col("tcprtt") == 0)).any()),
            "non_tcp": bool((s & (categorical[:, 0] != "tcp")).any()),
            "zero_reverse_packets": bool((s & (col("dpkts") == 0)).any()),
            "window_not_ready": bool((status == "window_not_ready").any()),
            "window_just_full": bool(scored.size and scored[0] == 99),
            "dense_same_endpoint": bool((s & (col("ct_src_ltm") >= 50)).any()),
            "out_of_vocabulary_category": bool(status[oov] == "scored"),
            "outbound_not_in_scope": bool((status == "not_in_model_scope").any()),
        }
    info = {"dir": "fixtures", "sensor_host": sensor, "window": 100, "flows": int(len(flows)), "scored": int(scored.size),
            "status_counts": {k: int(v) for k, v in pd.Series(status).value_counts().items()},
            "coverage": coverage, "missing_coverage": [k for k, v in coverage.items() if not v],
            "address_mapping": "RFC 5737 文档保留地址，按首次出现顺序一一映射", "oov_seq": oov, "oov_value": OOV_PROTO}
    write_json(out_dir / "fixture.json", info)
    RunContext.checksum_dir(out_dir)
    return {**info, "checksums_sha256": sha256_file(out_dir / "checksums.json")}
