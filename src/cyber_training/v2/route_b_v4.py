"""路线 B 阶段 2：契约 ``unsw-nb15-flow-v4`` 的训练帧、新切分与特征视图（命令 ``prepare-v4``）。

- 训练帧：D1 原始缓存按 V2 构造，``ct_*`` 换成 feature-audit 的单主机重算值，``service`` 换成端口口径；
  ``sload``/``dload`` 按规格 §4 在 ``dur = 0`` 或该方向包数 ≤ 1 时取 0。帧与 ``d1_raw.parquet`` 按行对齐。
- 切分：只取窗口已满且未被 D12 排除的行；按 v4 契约输入（17 数值 + 2 类别）去重并整组剔除标签冲突，
  再按无序端点对分组切分（训练计划 §4.2 的规则），种子从 20261001 起依次试 5 个，只按切分统计挑选。
  去重键改为 v4 输入而不是 v3.1 的 39 列：模型实际看到的是 v4 字段，按它去重才能保证跨分区特征向量重叠为 0。
- 视图：G1 冻结的 F5 写成 ``train.Context`` 可读取的 ``feature-views.json``，绑定新切分指纹，不做再选择。
不读取 holdout；只写运行目录。
"""

from __future__ import annotations

import gc
import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from . import GLOBAL_SEED
from .datasets import DataIntegrityError, deduplicate, endpoint_pair, load_cached, load_manifest
from .feature_ablation import define_groups
from .features import V1_RAW_COLUMNS, build_v2
from .guard import SplitIndex
from .runtime import RUNS_ROOT, RunContext, sha256_file, write_json
from .split import SplitAuditError, audit_partitions, category_share_deviation, grouped_split, split_d2

CONTRACT_VERSION = "unsw-nb15-flow-v4"
SPEC_DOCUMENT = "docs/特征规格-unsw-nb15-flow-v4.md"
SPEC_SHA256 = "dbba110432c2c381ec291e2ec373601256c7ca990efa3e7bdad405c25120c6f1"
SPLIT_SEED = 20261001
AUDIT_RUN, V3_RUN, ABLATION_RUN = "feature-audit-20260929-1327", "feature-20260927-1249", "feature-ablation-20260929-1359"
VIEW = "v4"
FRAME_KIND = "route-b-v4"
# 规格 §2.1 的顺序，即 ONNX ``flow_numeric`` 的列顺序。
NUMERIC = ("dur", "sbytes", "dbytes", "sload", "dload", "tcprtt", "ackdat", "synack", "smean", "dmean", "spkts", "dpkts",
           "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm")
CATEGORICAL = ("proto", "service")
CT_V4 = ("ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm")
REMOVED = {
    "sttl": "UNSW 靶场环境 TTL，分裂捷径", "ct_state_ttl": "无可审计的生成映射，依赖 TTL",
    "sloss": "Argus 内部实现，无法按训练口径复现", "sjit": "Argus 内部实现", "djit": "Argus 内部实现",
    "dinpkt": "Argus 内部实现", "ct_flw_http_mthd": "需要解析 HTTP 载荷，违反 D8",
    "ct_dst_sport_ltm": "单主机视角下退化（众数占比 ≥ 97%）", "ct_dst_src_ltm": "单主机视角下与 ct_src_ltm 结构等价",
}
_DROP = (*REMOVED, "dttl", "ttl_diff")


def view_columns() -> list[str]:
    """G1 冻结的 F5 模型列（与消融 F5 完全相同）。"""
    v3 = json.loads((RUNS_ROOT / V3_RUN / "feature-views.json").read_text(encoding="utf-8"))["views"]["V3"]
    return [c for c, _ in define_groups(v3)["F5"]]


def apply_boundaries(frame: pd.DataFrame) -> pd.DataFrame:
    """规格 §4：``dur = 0`` 或该方向包数 ≤ 1 时 load 取 0（CSV 中 0.04% 的行与此不符）。原地修改并返回。"""
    for load, pkts in (("sload", "spkts"), ("dload", "dpkts")):
        bad = (frame["dur"].to_numpy() <= 0) | (frame[pkts].to_numpy() <= 1)
        frame.loc[bad, load] = np.float32(0)
    return frame


def load_frame(manifest: dict[str, Any], audit_dir: Path | None = None
               ) -> tuple[pd.DataFrame, np.ndarray, pd.Series, np.ndarray]:
    """返回 (v4 训练帧, 标签, attack_cat, 可用掩码)。可用 = 窗口已满且未被 D12 排除。重算缓存哈希不符即终止。"""
    audit_dir = Path(audit_dir) if audit_dir else RUNS_ROOT / AUDIT_RUN
    meta = json.loads((audit_dir / "recomputed-cache.json").read_text(encoding="utf-8"))
    cache = audit_dir / meta["file"]
    if sha256_file(cache) != meta["sha256"]:
        raise DataIntegrityError(f"SHA-256 mismatch for {cache.name}")
    raw = load_cached("d1_raw.parquet", manifest, columns=[*V1_RAW_COLUMNS, "Label", "attack_cat"])
    re = pd.read_parquet(cache)
    if len(re) != len(raw):
        raise DataIntegrityError("recomputed cache is not row-aligned with d1_raw.parquet")
    labels = raw["Label"].to_numpy(dtype=np.int8)
    cats = raw["attack_cat"].astype("string").fillna("Normal").reset_index(drop=True)
    frame = build_v2(raw).reset_index(drop=True)
    del raw
    gc.collect()
    frame = frame.drop(columns=[c for c in _DROP if c in frame.columns])
    for c in CT_V4:
        frame[c] = re[f"{c}_v4"].to_numpy(dtype=np.float32)
    frame["service"] = pd.Series(re["service_v4"].to_numpy(), dtype="string")
    usable = re["window_ready"].to_numpy(dtype=bool) & ~re["excluded"].to_numpy(dtype=bool)
    del re
    gc.collect()
    return apply_boundaries(frame), labels, cats, usable


def split_d1(frame: pd.DataFrame, labels: np.ndarray, cats: pd.Series, usable: np.ndarray, ips: pd.DataFrame,
             seeds: tuple[int, ...]) -> tuple[dict[str, np.ndarray], dict[str, Any]]:
    """可用行 → 按 v4 输入去重 → 端点分组切分；返回相对缓存行位置的分区索引与审计记录。"""
    key = [*NUMERIC, *CATEGORICAL]
    rows = np.flatnonzero(usable)
    local = frame.iloc[rows][key].reset_index(drop=True)
    local["Label"] = labels[rows]
    keep, stats = deduplicate(local, key, "Label")
    kept_local = np.flatnonzero(keep.to_numpy())
    kept_rows = rows[kept_local]
    groups = endpoint_pair(ips.iloc[kept_rows]).to_numpy()
    y = labels[kept_rows]
    c = cats.iloc[kept_rows].reset_index(drop=True)
    feats = local.iloc[kept_local][key].reset_index(drop=True)
    attempts, best = [], None
    for seed in seeds:
        parts = grouped_split(pd.Series(groups), pd.Series(y), seed, c)
        audit = audit_partitions(parts, y, groups, feats)
        dev = max(abs(p["attack_rate"] - audit["overall_attack_rate"]) for p in audit["partitions"].values())
        share = category_share_deviation(parts, c.to_numpy(), y)
        attempts.append({"seed": seed, "passed": audit["passed"], "max_attack_rate_deviation": dev,
                         "mean_attack_category_share_deviation": share,
                         "shares": {n: p["share"] for n, p in audit["partitions"].items()}})
        if audit["passed"] and (best is None or dev + share < best[0]):
            best = (dev + share, seed, parts, audit)
    if best is None:
        raise SplitAuditError(f"no seed produced a passing v4 split: {attempts}")
    _, seed, parts, audit = best
    by_cat = {n: {str(k): int(v) for k, v in c.iloc[r].value_counts().items()} for n, r in parts.items()}
    return {n: kept_rows[r] for n, r in parts.items()}, {
        "strategy": "usable rows (window ready, not excluded) + dedup on v4 inputs + endpoint-pair grouped split",
        "usable_rows": int(rows.size), "dedup_key": key, "dedup": stats, "selected_seed": seed,
        "seed_attempts": attempts, "attack_cat_by_partition": by_cat, **audit}


def run(seed: int = SPLIT_SEED, attempts: int = 5) -> str:
    """执行 ``prepare-v4``：写 ``split-v4-*/``（切分与审计）和 ``feature-v4-*/``（冻结视图）。审计失败即终止。"""
    manifest_file, manifest = load_manifest()
    seeds = tuple(seed + i for i in range(attempts))
    columns = view_columns()
    ctx = RunContext("split-v4", seed, {"seeds_tried": seeds, "register_manifest": str(manifest_file),
                                         "audit_run": AUDIT_RUN, "contract": CONTRACT_VERSION, "spec_sha256": SPEC_SHA256})
    frame, labels, cats, usable = load_frame(manifest)
    missing = sorted(set(columns) - set(frame.columns))
    if missing:
        raise DataIntegrityError(f"v4 frame lacks view columns: {missing}")
    ips = load_cached("d1_raw.parquet", manifest, columns=["srcip", "dstip"])
    parts, d1_audit = split_d1(frame, labels, cats, usable, ips, seeds)
    del frame, ips
    gc.collect()
    SplitIndex(parts["train"], parts["validation"], parts["holdout"]).save(ctx.path("split-d1-raw.npz"))
    d2 = load_cached("d2.parquet", manifest, columns=["Label", "Attack"])
    d2_parts, d2_audit = split_d2(d2["Label"].to_numpy(), d2["Attack"], seed)
    if not d2_audit["passed"]:
        raise SplitAuditError(f"D2 split audit failed: {d2_audit['checks']}")
    SplitIndex(d2_parts["train"], d2_parts["validation"], d2_parts["holdout"]).save(ctx.path("split-d2.npz"))
    audits: dict[str, Any] = {"register_manifest_sha256": sha256_file(manifest_file), "d1_raw": d1_audit, "d2": d2_audit}
    for name in ("split-d1-raw.npz", "split-d2.npz"):
        audits[name] = {"sha256": sha256_file(ctx.path(name)), "fingerprint": SplitIndex.load(ctx.path(name)).fingerprint}
    write_json(ctx.path("split-audit.json"), audits)
    ctx.finish()
    fingerprint = audits["split-d1-raw.npz"]["fingerprint"]

    view_ctx = RunContext("feature-v4", seed, {"split_dir": ctx.run_dir.name, "ablation_run": ABLATION_RUN})
    contract = {"version": CONTRACT_VERSION, "spec_document": SPEC_DOCUMENT, "spec_sha256": SPEC_SHA256,
                "numeric_fields": list(NUMERIC), "categorical_fields": list(CATEGORICAL), "removed_fields": REMOVED}
    write_json(view_ctx.path("feature-views.json"), {"views": {VIEW: columns}, "split_fingerprint": fingerprint,
                                                      "frame": FRAME_KIND, "contract": contract})
    write_json(view_ctx.path("feature-selection.json"), {
        "selected_view": VIEW, "rule": "G1 冻结的 F5（路线 B §7.2），阶段 2 不再做视图选择",
        "ablation_run": ABLATION_RUN, "failed_runs": []})
    view_ctx.finish()
    return f"{ctx.run_dir}\n{view_ctx.run_dir}"
