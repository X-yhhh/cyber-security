"""第 4 步：探索性数据分析（EDA）。

只做描述统计，不拟合任何会进入模型的对象。为避免 holdout 信息影响后续特征选择，
凡是会指导建模决策的统计（分位数/偏度、类别攻击率、Spearman 相关、互信息、D1/D2 分布差异）
只在第 5 步切分得到的训练分区上计算；全量数据只用于概览、缺失、重复与标签分布。
图保存为 300 dpi PNG，对应数值另存 CSV。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.colors import LinearSegmentedColormap
from scipy.stats import ks_2samp, skew
from sklearn.feature_selection import mutual_info_classif
from sklearn.model_selection import train_test_split

from . import GLOBAL_SEED
from .datasets import (
    D1_CATEGORICAL, D2_COMMON_SOURCE_COLUMNS, common_view_d1, common_view_d2, d1_dedup_key,
    d1_model_columns, deduplicate, load_cached, load_manifest,
)
from .guard import SplitIndex
from .runtime import RUNS_ROOT, RunContext, sha256_file, write_json

# 配色：分类色取参考调色板前两槽（已通过色觉缺陷校验）；相关热力图用蓝-灰-红发散色。
NORMAL_COLOR = "#2a78d6"
ATTACK_COLOR = "#eb6834"
INK = "#0b0b0b"
INK_SECONDARY = "#52514e"
GRID = "#e1e0d9"
DIVERGING = LinearSegmentedColormap.from_list("blue_gray_red", ["#104281", "#2a78d6", "#f0efec", "#e34948", "#9b1c1c"])
SAMPLE_ROWS = 200_000
HIGH_CORRELATION = 0.95


def _style() -> None:
    plt.rcParams.update({
        "font.family": ["Microsoft YaHei", "SimHei", "DejaVu Sans"],
        "axes.unicode_minus": False,
        "axes.edgecolor": "#c3c2b7", "axes.labelcolor": INK_SECONDARY, "axes.titlecolor": INK,
        "xtick.color": INK_SECONDARY, "ytick.color": INK_SECONDARY,
        "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6,
        "axes.spines.top": False, "axes.spines.right": False,
        "figure.dpi": 100, "savefig.dpi": 300, "savefig.bbox": "tight",
    })


def _save(fig: plt.Figure, path: Path) -> None:
    fig.savefig(path)
    plt.close(fig)


def latest_split_dir(runs_root: Path = RUNS_ROOT) -> Path:
    candidates = sorted(Path(runs_root).glob("split-*/split-audit.json"))
    if not candidates:
        raise FileNotFoundError("no split run found; run `python -m cyber_training.v2 split` first")
    return candidates[-1].parent


def overview_table(frame: pd.DataFrame) -> pd.DataFrame:
    """每列类型、缺失数/率、唯一值数。"""
    return pd.DataFrame({
        "dtype": frame.dtypes.astype(str),
        "missing": frame.isna().sum(),
        "missing_rate": frame.isna().mean(),
        "unique": frame.nunique(dropna=True),
    }).rename_axis("column").reset_index()


def numeric_profile(frame: pd.DataFrame, columns: list[str]) -> pd.DataFrame:
    """分位数与偏度；``log1p_skew`` 对非负列计算，含负值的列记为缺失。"""
    rows = []
    for column in columns:
        values = frame[column].dropna().to_numpy(dtype="float64")
        if values.size == 0:
            continue
        q = np.quantile(values, [0.01, 0.5, 0.99])
        nonneg = values.min() >= 0
        rows.append({
            "column": column, "p1": q[0], "p50": q[1], "p99": q[2], "max": values.max(),
            "zero_rate": float((values == 0).mean()),
            "skew": float(skew(values)) if values.std() > 0 else 0.0,
            "log1p_skew": float(skew(np.log1p(values))) if nonneg and values.std() > 0 else np.nan,
        })
    return pd.DataFrame(rows).sort_values("skew", key=np.abs, ascending=False)


def category_attack_rates(frame: pd.DataFrame, column: str, top: int = 20) -> pd.DataFrame:
    stats = frame.groupby(column, dropna=False)["Label"].agg(["size", "mean"]).rename(
        columns={"size": "rows", "mean": "attack_rate"})
    return stats.sort_values("rows", ascending=False).head(top).rename_axis("value").reset_index()


def high_correlation_pairs(corr: pd.DataFrame, threshold: float = HIGH_CORRELATION) -> pd.DataFrame:
    """|ρ| 超过阈值的特征对（上三角，按 |ρ| 降序）。"""
    upper = corr.where(np.triu(np.ones(corr.shape, dtype=bool), k=1))
    pairs = upper.stack().rename("spearman").reset_index()
    pairs.columns = ["feature_a", "feature_b", "spearman"]
    pairs = pairs[pairs["spearman"].abs() > threshold]
    return pairs.reindex(pairs["spearman"].abs().sort_values(ascending=False).index).reset_index(drop=True)


def plot_label_distribution(counts: pd.Series, title: str, path: Path) -> None:
    """类别分布横向条形图（对数横轴），数值直接标注；正常类用蓝、攻击类用橙。"""
    counts = counts.sort_values()
    fig, ax = plt.subplots(figsize=(7.5, 0.42 * len(counts) + 1.2))
    colors = [NORMAL_COLOR if str(k).lower() in ("normal", "benign", "0") else ATTACK_COLOR for k in counts.index]
    ax.barh([str(k) for k in counts.index], counts.to_numpy(), color=colors, height=0.6)
    ax.set_xscale("log")
    ax.set_xlabel("记录数（对数刻度）")
    ax.set_title(title, loc="left", fontsize=11)
    ax.grid(axis="y", visible=False)
    for y, value in enumerate(counts.to_numpy()):
        ax.text(value * 1.08, y, f"{int(value):,}", va="center", fontsize=8, color=INK_SECONDARY)
    ax.set_xlim(right=counts.max() * 6)
    _save(fig, path)


def plot_log1p_histograms(frame: pd.DataFrame, labels: np.ndarray, columns: list[str], path: Path) -> None:
    """偏度最大的数值特征：原始值（截断到 p99.5 以便看清主体）与 log1p 后的正常/攻击分布对比。

    纵轴为各类别内的占比（每类柱高之和为 1），避免密度刻度出现 1e-5 之类难读的数量级。
    """
    fig, axes = plt.subplots(len(columns), 2, figsize=(9, 2.0 * len(columns)))
    axes = np.atleast_2d(axes)
    for row, column in enumerate(columns):
        values = frame[column].to_numpy(dtype="float64")
        finite = values[~np.isnan(values)]
        upper = float(np.quantile(finite, 0.995)) if finite.size else 1.0
        panels = (
            (lambda v: v[v <= upper], (float(finite.min()) if finite.size else 0.0, upper), f"{column} · 原始值（≤p99.5）"),
            (np.log1p, None, f"{column} · log1p"),
        )
        for col, (transform, value_range, title) in enumerate(panels):
            ax = axes[row, col]
            for label, color, text in ((0, NORMAL_COLOR, "正常"), (1, ATTACK_COLOR, "攻击")):
                subset = transform(values[(labels == label) & ~np.isnan(values)])
                if subset.size == 0:
                    continue
                weights = np.full(subset.size, 1.0 / subset.size)
                ax.hist(subset, bins=50, range=value_range, weights=weights, color=color, alpha=0.55, label=text)
            ax.set_title(title, loc="left", fontsize=9)
            ax.set_ylabel("类内占比", fontsize=7)
            ax.tick_params(labelsize=7)
            ax.ticklabel_format(axis="x", style="plain", useOffset=False) if col == 0 and upper < 1e6 else None
    axes[0, 1].legend(fontsize=8, frameon=False, loc="upper right")
    fig.tight_layout()
    _save(fig, path)


def plot_category_rates(tables: dict[str, pd.DataFrame], path: Path) -> None:
    """类别特征 Top 取值的记录数（条）与攻击率（右侧标注），每个特征一个子图。"""
    fig, axes = plt.subplots(1, len(tables), figsize=(5 * len(tables), 6))
    for ax, (column, table) in zip(np.atleast_1d(axes), tables.items()):
        table = table.iloc[::-1]
        ax.barh(table["value"].astype(str), table["rows"], color=NORMAL_COLOR, height=0.6)
        ax.set_xscale("log")
        ax.set_title(f"{column}：Top-{len(table)} 取值", loc="left", fontsize=10)
        ax.set_xlabel("记录数（对数刻度）")
        ax.grid(axis="y", visible=False)
        for y, (rows, rate) in enumerate(zip(table["rows"], table["attack_rate"])):
            ax.text(rows * 1.1, y, f"攻击率 {rate:.1%}", va="center", fontsize=7, color=INK_SECONDARY)
        ax.set_xlim(right=table["rows"].max() * 20)
    fig.tight_layout()
    _save(fig, path)


def plot_correlation(corr: pd.DataFrame, path: Path) -> None:
    fig, ax = plt.subplots(figsize=(12, 10.5))
    image = ax.imshow(corr.to_numpy(), cmap=DIVERGING, vmin=-1, vmax=1)
    ax.set_xticks(range(len(corr)), corr.columns, rotation=90, fontsize=6)
    ax.set_yticks(range(len(corr)), corr.index, fontsize=6)
    ax.grid(False)
    ax.set_title("数值特征 Spearman 相关系数（训练分区抽样）", loc="left", fontsize=11)
    fig.colorbar(image, ax=ax, fraction=0.035, pad=0.02, label="ρ")
    _save(fig, path)


def plot_ranked_bars(series: pd.Series, title: str, xlabel: str, path: Path) -> None:
    series = series.sort_values()
    fig, ax = plt.subplots(figsize=(7.5, 0.3 * len(series) + 1.2))
    ax.barh(series.index.astype(str), series.to_numpy(), color=NORMAL_COLOR, height=0.6)
    ax.set_title(title, loc="left", fontsize=11)
    ax.set_xlabel(xlabel)
    ax.grid(axis="y", visible=False)
    for y, value in enumerate(series.to_numpy()):
        ax.text(value, y, f" {value:.3f}", va="center", fontsize=7, color=INK_SECONDARY)
    ax.set_xlim(right=series.max() * 1.15)
    _save(fig, path)


def train_sample(rows: np.ndarray, labels: np.ndarray, size: int, seed: int) -> np.ndarray:
    """在训练分区内按标签分层抽样（不足 ``size`` 时全取）。"""
    if len(rows) <= size:
        return np.sort(rows)
    picked, _ = train_test_split(rows, train_size=size, stratify=labels[rows], random_state=seed)
    return np.sort(picked)


def run(seed: int = GLOBAL_SEED, split_dir: Path | None = None, manifest_path: Path | None = None) -> Path:
    """执行第 4 步 EDA，输出 ``runs/eda-*/``（PNG + CSV + ``eda-summary.json``）。"""
    _style()
    manifest_file, manifest = load_manifest(manifest_path)
    split_dir = Path(split_dir) if split_dir else latest_split_dir()
    ctx = RunContext("eda", seed, {"register_manifest": str(manifest_file), "split_dir": str(split_dir),
                                   "sample_rows": SAMPLE_ROWS, "high_correlation": HIGH_CORRELATION})
    out = ctx.run_dir
    summary: dict[str, Any] = {"split_audit_sha256": sha256_file(split_dir / "split-audit.json")}

    # 1-2. 全量概览、缺失与标签分布（描述性，不指导建模参数）。
    d1 = load_cached("d1_raw.parquet", manifest)
    overview_table(d1).to_csv(out / "d1-overview.csv", index=False)
    label_counts = d1["Label"].map({0: "Normal", 1: "Attack"}).value_counts()
    attack_counts = d1["attack_cat"].value_counts()
    label_counts.rename("rows").to_csv(out / "d1-label-counts.csv")
    attack_counts.rename("rows").to_csv(out / "d1-attack-cat-counts.csv")
    plot_label_distribution(label_counts, "D1 UNSW-NB15 原始数据：二分类标签分布", out / "d1-label-distribution.png")
    plot_label_distribution(attack_counts, "D1 UNSW-NB15 原始数据：攻击类别分布", out / "d1-attack-cat-distribution.png")
    summary["d1_imbalance_ratio_normal_to_attack"] = float(label_counts["Normal"] / label_counts["Attack"])

    # 6. 重复与标签冲突（全量）。
    key = d1_dedup_key(d1)
    keep, dedup = deduplicate(d1, key, "Label")
    retained = d1.loc[keep, "Label"]
    summary["d1_duplicates"] = {**dedup, "exact_full_row_duplicates": int(d1.duplicated().sum()),
                                "dedup_key_columns": len(key),
                                "attack_rate_before": float(d1["Label"].mean()),
                                "attack_rate_after": float(retained.mean())}

    # 3-5、7：只在训练分区抽样上计算。
    split = SplitIndex.load(split_dir / "split-d1-raw.npz")
    labels_all = d1["Label"].to_numpy()
    sample_rows = train_sample(split.train, labels_all, SAMPLE_ROWS, seed)
    sample = d1.iloc[sample_rows].reset_index(drop=True)
    labels = sample["Label"].to_numpy()
    model_columns = d1_model_columns(d1)
    numeric = [c for c in model_columns if c not in D1_CATEGORICAL]
    del d1

    profile = numeric_profile(sample, numeric)
    profile.to_csv(out / "d1-numeric-profile.csv", index=False)
    # 二值/低基数列（如 is_sm_ips_ports）的"偏度"只反映类别不平衡，不属于长尾，不参与长尾图。
    continuous = [c for c in profile["column"] if sample[c].nunique(dropna=True) > 10]
    top_skewed = profile[profile["log1p_skew"].notna() & profile["column"].isin(continuous)].head(12)["column"].tolist()
    plot_log1p_histograms(sample, labels, top_skewed[:6], out / "d1-skewed-log1p-1.png")
    plot_log1p_histograms(sample, labels, top_skewed[6:12], out / "d1-skewed-log1p-2.png")

    category_tables = {c: category_attack_rates(sample, c) for c in D1_CATEGORICAL}
    pd.concat([t.assign(feature=c) for c, t in category_tables.items()]).to_csv(out / "d1-category-attack-rates.csv", index=False)
    plot_category_rates(category_tables, out / "d1-category-attack-rates.png")

    variable = [c for c in numeric if sample[c].nunique(dropna=True) > 1]
    corr = sample[variable].corr(method="spearman")
    corr.to_csv(out / "d1-spearman.csv")
    pairs = high_correlation_pairs(corr)
    pairs.to_csv(out / "d1-high-correlation-pairs.csv", index=False)
    plot_correlation(corr, out / "d1-spearman-heatmap.png")

    encoded = sample[model_columns].copy()
    for c in D1_CATEGORICAL:
        encoded[c] = encoded[c].astype("category").cat.codes
    encoded = encoded.astype("float64").fillna(-1.0)
    discrete = np.array([c in D1_CATEGORICAL for c in model_columns])
    mi = pd.Series(mutual_info_classif(encoded.to_numpy(), labels, discrete_features=discrete, random_state=seed),
                   index=model_columns).sort_values(ascending=False)
    mi.rename("mutual_information").to_csv(out / "d1-mutual-information.csv")
    plot_ranked_bars(mi.head(20), "与标签的互信息 Top-20（训练分区抽样）", "互信息（nats）", out / "d1-mutual-information.png")

    # 8. D1 与 D2 公共特征分布对比（两侧均取训练分区）。
    d2_split = SplitIndex.load(split_dir / "split-d2.npz")
    d2 = load_cached("d2.parquet", manifest, columns=D2_COMMON_SOURCE_COLUMNS)
    d2_rows = train_sample(d2_split.train, d2["Label"].to_numpy(), SAMPLE_ROWS, seed)
    d2_view = common_view_d2(d2.iloc[d2_rows])
    d1_view = common_view_d1(sample)
    ks = pd.DataFrame([
        {"feature": c, "ks_statistic": ks_2samp(d1_view[c].dropna(), d2_view[c].dropna()).statistic,
         "d1_median": float(d1_view[c].median()), "d2_median": float(d2_view[c].median())}
        for c in d1_view.columns
    ]).sort_values("ks_statistic", ascending=False)
    ks.to_csv(out / "d1-d2-common-feature-ks.csv", index=False)
    plot_ranked_bars(ks.set_index("feature")["ks_statistic"], "D1 与 D2 公共特征分布差异（KS 统计量）", "KS 统计量（0~1，越大差异越大）",
                     out / "d1-d2-common-feature-ks.png")
    d2_labels = load_cached("d2.parquet", manifest, columns=["Attack"])["Attack"].value_counts()
    plot_label_distribution(d2_labels, "D2 NF-ToN-IoT-v2：攻击类别分布", out / "d2-attack-distribution.png")

    summary.update({
        "d1_train_sample_rows": int(len(sample_rows)),
        "d1_top_skewed": top_skewed,
        "d1_high_correlation_pairs": int(len(pairs)),
        "d1_mutual_information_top10": {k: float(v) for k, v in mi.head(10).items()},
        "d1_constant_in_sample": [c for c in numeric if c not in variable],
        "d1_d2_ks": {r.feature: float(r.ks_statistic) for r in ks.itertuples()},
        "d2_attack_counts": {str(k): int(v) for k, v in d2_labels.items()},
    })
    write_json(out / "eda-summary.json", summary)
    ctx.finish()
    return out
