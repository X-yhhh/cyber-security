"""第 5 步：切分与切分审计。

- D1 原始数据：按 ``datasets.deduplicate`` 去重并剔除标签冲突组，再以无序端点对为组，
  攻击组与纯正常组分别按行数贪心分配到 train/validation/holdout（70/15/15），保证同一端点对只出现在一个分区。
- D1 子集：官方训练部分内部分层切出 15% 验证集；官方测试部分作为多分类任务的锁定 holdout。
- D2：分层抽样 150 万行后按 70/15/15 分层切分（该副本无 IP 字段，无法分组）。

只保存行位置索引（相对 ``data/processed`` 缓存）与审计结果；审计任一项不满足即终止。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from . import GLOBAL_SEED
from .datasets import (
    SUBSET_EXCLUDED, d1_dedup_key, d1_model_columns, deduplicate, endpoint_pair, load_cached, load_manifest,
)
from .guard import PARTITIONS, SplitIndex
from .runtime import RunContext, sha256_file, write_json

RATIOS = {"train": 0.70, "validation": 0.15, "holdout": 0.15}
MAX_ATTACK_RATE_DEVIATION = 0.02  # 各分区攻击比例与总体的最大绝对偏差
MAX_SIZE_DEVIATION = 0.03  # 各分区行数占比与目标比例的最大绝对偏差
D2_SAMPLE_ROWS = 1_500_000


class SplitAuditError(ValueError):
    """切分审计未通过。"""


def assign_groups(group_sizes: pd.Series, seed: int, ratios: dict[str, float] = RATIOS) -> dict[str, str]:
    """把组分配到分区，使各分区累计行数尽量接近目标比例。

    先按种子打乱再按组大小降序（大组先放，稳定排序保留随机次序），
    每组放入"目标行数 - 已分配行数"缺口最大的分区。返回 {组: 分区}。
    """
    rng = np.random.default_rng(seed)
    order = group_sizes.index.to_numpy()[rng.permutation(len(group_sizes))]
    shuffled = group_sizes.loc[order]
    ordered = shuffled.iloc[np.argsort(-shuffled.to_numpy(), kind="stable")]
    total = float(group_sizes.sum())
    filled = {name: 0.0 for name in ratios}
    assignment: dict[str, str] = {}
    for group, size in ordered.items():
        target = max(ratios, key=lambda name: ratios[name] * total - filled[name])
        assignment[group] = target
        filled[target] += float(size)
    return assignment


STRATIFIED_TRIALS = 4000


def assign_groups_stratified(counts: pd.DataFrame, seed: int, ratios: dict[str, float] = RATIOS,
                             trials: int = STRATIFIED_TRIALS) -> dict[str, str]:
    """按多维计数（每列一个攻击类别）把组分配到分区，使每个类别在各分区的占比都接近目标比例。

    做 ``trials`` 次随机顺序的贪心分配（每组放入攻击行缺口最大的分区），
    以"各类别在各分区占比与目标比例的平均绝对偏差 + 攻击行占比偏差"为得分，取最小者。
    由种子完全决定，结果可复现；同一组只进入一个分区。
    """
    rng = np.random.default_rng(seed)
    names = list(ratios)
    target = np.array([ratios[n] for n in names])
    matrix = counts.to_numpy(dtype="float64")
    sizes = matrix.sum(axis=1)
    cat_totals = np.maximum(matrix.sum(axis=0), 1.0)
    total = sizes.sum()
    best_score, best_choice = np.inf, None
    for _ in range(trials):
        order = rng.permutation(len(sizes))
        filled = np.zeros(len(names))
        choice = np.empty(len(sizes), dtype=np.int64)
        for i in order:
            j = int(np.argmax(target * total - filled))
            choice[i] = j
            filled[j] += sizes[i]
        per_part = np.stack([matrix[choice == j].sum(axis=0) for j in range(len(names))])
        shares = per_part / cat_totals
        score = float(np.abs(shares - target[:, None]).mean() + np.abs(filled / total - target).mean())
        if score < best_score:
            best_score, best_choice = score, choice
    return {group: names[j] for group, j in zip(counts.index, best_choice)}


def grouped_split(groups: pd.Series, labels: pd.Series, seed: int, categories: pd.Series | None = None
                  ) -> dict[str, np.ndarray]:
    """端点分组切分；返回各分区的行位置。

    含攻击的组：给出 ``categories`` 时按各攻击类别计数做多维分层分配，否则按攻击行数分配；
    纯正常组按行数分配。同一组只会进入一个分区。
    """
    frame = pd.DataFrame({"group": groups.to_numpy(), "label": labels.to_numpy()})
    per_group = frame.groupby("group", sort=True)["label"].agg(["size", "sum"])
    attack_groups = per_group[per_group["sum"] > 0]
    normal_groups = per_group[per_group["sum"] == 0]
    if categories is not None:
        attacks = frame.assign(cat=categories.to_numpy())[frame["label"].to_numpy() == 1]
        matrix = pd.crosstab(attacks["group"], attacks["cat"]).reindex(attack_groups.index, fill_value=0)
        attack_assignment = assign_groups_stratified(matrix, seed)
    else:
        attack_assignment = assign_groups(attack_groups["sum"], seed)
    assignment = {**attack_assignment, **assign_groups(normal_groups["size"], seed + 1)}
    partition = frame["group"].map(assignment).to_numpy()
    return {name: np.flatnonzero(partition == name).astype(np.int64) for name in PARTITIONS}


def audit_partitions(parts: dict[str, np.ndarray], labels: np.ndarray, groups: np.ndarray | None,
                     features: pd.DataFrame | None) -> dict[str, Any]:
    """审计：分区规模、攻击比例、端点组重叠、特征向量重叠。返回审计记录并附 ``passed``。"""
    total = sum(len(v) for v in parts.values())
    overall_rate = float(labels.mean())
    record: dict[str, Any] = {"overall_attack_rate": overall_rate, "partitions": {}, "checks": {}}
    for name, rows in parts.items():
        rate = float(labels[rows].mean()) if len(rows) else float("nan")
        record["partitions"][name] = {
            "rows": int(len(rows)),
            "share": len(rows) / total,
            "attack_rows": int(labels[rows].sum()),
            "attack_rate": rate,
            "groups": int(pd.unique(groups[rows]).size) if groups is not None else None,
        }
    checks = record["checks"]
    checks["size_within_tolerance"] = all(
        abs(record["partitions"][n]["share"] - RATIOS[n]) <= MAX_SIZE_DEVIATION for n in PARTITIONS)
    checks["attack_rate_within_tolerance"] = all(
        abs(record["partitions"][n]["attack_rate"] - overall_rate) <= MAX_ATTACK_RATE_DEVIATION for n in PARTITIONS)
    checks["every_partition_has_attacks"] = all(record["partitions"][n]["attack_rows"] > 0 for n in PARTITIONS)
    if groups is not None:
        sets = {n: set(pd.unique(groups[parts[n]])) for n in PARTITIONS}
        overlap = sum(len(sets[a] & sets[b]) for a in PARTITIONS for b in PARTITIONS if a < b)
        record["endpoint_group_overlap"] = overlap
        checks["endpoint_group_overlap_zero"] = overlap == 0
    if features is not None:
        hashed = pd.util.hash_pandas_object(features, index=False).to_numpy()
        sets = {n: set(hashed[parts[n]]) for n in PARTITIONS}
        overlap = sum(len(sets[a] & sets[b]) for a in PARTITIONS for b in PARTITIONS if a < b)
        record["feature_vector_overlap"] = overlap
        checks["feature_vector_overlap_zero"] = overlap == 0
    record["passed"] = all(checks.values())
    return record


def stratified_three_way(labels: np.ndarray, seed: int, rows: np.ndarray | None = None) -> dict[str, np.ndarray]:
    """分层 70/15/15 切分（用于无分组键的数据）。"""
    rows = np.arange(len(labels)) if rows is None else rows
    train, rest = train_test_split(rows, test_size=0.30, stratify=labels[rows], random_state=seed)
    validation, holdout = train_test_split(rest, test_size=0.50, stratify=labels[rest], random_state=seed)
    return {"train": np.sort(train), "validation": np.sort(validation), "holdout": np.sort(holdout)}


def category_share_deviation(parts: dict[str, np.ndarray], categories: np.ndarray, labels: np.ndarray) -> float:
    """各攻击类别在各分区的实际占比与目标比例的平均绝对偏差（只看攻击行）。"""
    attack = labels == 1
    deviations = []
    for cat in pd.unique(categories[attack]):
        total = float(((categories == cat) & attack).sum())
        for name, rows in parts.items():
            share = float(((categories[rows] == cat) & attack[rows]).sum()) / total
            deviations.append(abs(share - RATIOS[name]))
    return float(np.mean(deviations)) if deviations else 0.0


def split_d1_raw(frame: pd.DataFrame, seeds: tuple[int, ...]) -> tuple[dict[str, np.ndarray], dict[str, Any]]:
    """D1 原始数据：去重 → 端点分组切分。

    依次尝试 ``seeds``，只用切分统计（不看任何模型结果）挑选通过审计且攻击比例最大偏差最小的一次；
    全部未通过则终止。返回相对缓存行位置的分区索引与审计记录。
    """
    key = d1_dedup_key(frame)
    keep, dedup_stats = deduplicate(frame, key, "Label")
    kept_rows = np.flatnonzero(keep.to_numpy())
    kept = frame.iloc[kept_rows]
    groups = endpoint_pair(kept).to_numpy()
    labels = kept["Label"].to_numpy()
    attempts = []
    best: tuple[float, int, dict[str, np.ndarray], dict[str, Any]] | None = None
    for seed in seeds:
        local = grouped_split(pd.Series(groups), pd.Series(labels), seed, kept["attack_cat"].reset_index(drop=True))
        audit = audit_partitions(local, labels, groups, kept[key].reset_index(drop=True))
        deviation = max(abs(p["attack_rate"] - audit["overall_attack_rate"]) for p in audit["partitions"].values())
        category_share = category_share_deviation(local, kept["attack_cat"].to_numpy(), labels)
        score = deviation + category_share
        attempts.append({"seed": seed, "passed": audit["passed"], "max_attack_rate_deviation": deviation,
                         "mean_attack_category_share_deviation": category_share,
                         "shares": {n: p["share"] for n, p in audit["partitions"].items()}})
        if audit["passed"] and (best is None or score < best[0]):
            best = (score, seed, local, audit)
    if best is None:
        raise SplitAuditError(f"no seed produced a passing endpoint-grouped split: {attempts}")
    _, seed, local, audit = best
    parts = {name: kept_rows[rows] for name, rows in local.items()}
    by_category = {
        name: {str(k): int(v) for k, v in kept["attack_cat"].iloc[rows].value_counts().items()}
        for name, rows in local.items()
    }
    return parts, {
        "strategy": "dedup + unordered endpoint-pair grouped split (attack groups stratified by attack_cat counts)",
        "dedup_key": key, "dedup": dedup_stats, "selected_seed": seed, "seed_attempts": attempts,
        "attack_cat_by_partition": by_category, **audit,
    }


def split_d1_subset(train: pd.DataFrame, seed: int) -> tuple[dict[str, np.ndarray], dict[str, Any]]:
    """D1 子集：官方训练部分内部按 ``attack_cat`` 分层切出 15% 验证；holdout 指官方测试文件的全部行。"""
    rows = np.arange(len(train))
    fit, validation = train_test_split(rows, test_size=0.15, stratify=train["attack_cat"], random_state=seed)
    features = [c for c in train.columns if c not in SUBSET_EXCLUDED]
    hashed = pd.util.hash_pandas_object(train[features], index=False).to_numpy()
    overlap = len(set(hashed[fit]) & set(hashed[validation]))
    return {"train": np.sort(fit), "validation": np.sort(validation)}, {
        "strategy": "official train file stratified by attack_cat into train/validation; official test file is the locked holdout",
        "train_rows": int(len(fit)), "validation_rows": int(len(validation)),
        "train_validation_feature_vector_overlap": overlap,
        "note": "官方子集自带跨分区重复特征向量，此处只报告不剔除，以保持官方切分可比",
    }


def split_d2(labels: np.ndarray, attack: pd.Series, seed: int, sample_rows: int = D2_SAMPLE_ROWS
             ) -> tuple[dict[str, np.ndarray], dict[str, Any]]:
    """D2：按 ``Attack`` 分层抽样 ``sample_rows`` 行，再按二分类标签分层 70/15/15。"""
    rows = np.arange(len(labels))
    sampled, _ = train_test_split(rows, train_size=sample_rows, stratify=attack.to_numpy(), random_state=seed)
    parts = stratified_three_way(labels, seed, np.sort(sampled))
    audit = audit_partitions(parts, labels, None, None)
    audit["checks"].pop("size_within_tolerance", None)
    return parts, {"strategy": "stratified sample by Attack then stratified 70/15/15 (no IP fields available)",
                   "sample_rows": sample_rows, **audit}


def run(seed: int = GLOBAL_SEED, attempts: int = 5, manifest_path: Path | None = None) -> Path:
    """执行第 5 步。输出 ``split-*.npz``（行位置索引）与 ``split-audit.json``；审计失败即终止。"""
    manifest_file, manifest = load_manifest(manifest_path)
    seeds = tuple(seed + i for i in range(attempts))
    ctx = RunContext("split", seed, {"seeds_tried": seeds, "ratios": RATIOS, "register_manifest": str(manifest_file),
                                     "max_attack_rate_deviation": MAX_ATTACK_RATE_DEVIATION,
                                     "max_size_deviation": MAX_SIZE_DEVIATION, "d2_sample_rows": D2_SAMPLE_ROWS})
    audits: dict[str, Any] = {"register_manifest_sha256": sha256_file(manifest_file)}

    d1 = load_cached("d1_raw.parquet", manifest)
    parts, audits["d1_raw"] = split_d1_raw(d1, seeds)
    SplitIndex(parts["train"], parts["validation"], parts["holdout"]).save(ctx.path("split-d1-raw.npz"))
    audits["d1_raw"]["model_columns"] = d1_model_columns(d1)
    del d1

    subset_train = load_cached("d1_subset_train.parquet", manifest)
    subset_test_rows = manifest["processed_cache"]["d1_subset_test.parquet"]["rows"]
    sub_parts, audits["d1_subset"] = split_d1_subset(subset_train, seed)
    np.savez_compressed(ctx.path("split-d1-subset.npz"), train=sub_parts["train"], validation=sub_parts["validation"])
    audits["d1_subset"]["holdout_rows"] = int(subset_test_rows)

    d2 = load_cached("d2.parquet", manifest, columns=["Label", "Attack"])
    d2_parts, audits["d2"] = split_d2(d2["Label"].to_numpy(), d2["Attack"], seed)
    SplitIndex(d2_parts["train"], d2_parts["validation"], d2_parts["holdout"]).save(ctx.path("split-d2.npz"))
    if not audits["d2"]["passed"]:
        raise SplitAuditError(f"D2 split audit failed: {audits['d2']['checks']}")

    for name in ("split-d1-raw.npz", "split-d2.npz"):
        audits[name] = {"sha256": sha256_file(ctx.path(name)),
                        "fingerprint": SplitIndex.load(ctx.path(name)).fingerprint}
    audits["split-d1-subset.npz"] = {"sha256": sha256_file(ctx.path("split-d1-subset.npz"))}
    write_json(ctx.path("split-audit.json"), audits)
    ctx.finish()
    return ctx.run_dir
