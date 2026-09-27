"""第 7 步：特征工程对比。

在 D1 原始数据上比较 V0～V3 四个特征视图对 RF 与 LightGBM 的影响；预处理统一使用第 6 步为树模型确定的
P1（中位数插补 + 缺失指示 + Ordinal 编码）。每个种子从训练分区分层抽样 ``SAMPLE_ROWS`` 行拟合，在完整验证
分区上以阈值 0.5 评估；holdout 不被读取。选出 ``V*`` 后，另在 ``V*`` 上去掉 TTL 特征得到 V4 诊断视图，
只用于量化对 UNSW 环境 TTL 的依赖，不参与选型。

V3 的构造只使用训练信息：冗余对与互信息来自 EDA（EDA 只在训练分区上计算），重要性筛选用第一个种子的训练
抽样拟合 LightGBM。视图定义写入 ``feature-views.json``，续跑时复用，保证各种子使用同一特征列表。

输出：逐次结果 ``feature-runs.csv``（可断点续跑）、汇总 ``feature-summary.csv``、论文版式
``feature-comparison.md``、``feature-selection.json``、``feature-views.json``、V2 重要性 CSV 与 Top-30 图。
"""

from __future__ import annotations

import gc
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from . import GLOBAL_SEED
from .datasets import load_cached, load_manifest
from .features import (
    RANDOM_ISN, TTL_FEATURES, V0_FEATURES, V1_FEATURES, V1_RAW_COLUMNS, V2_FEATURES, build_v2,
    cumulative_importance_keep, redundancy_drops,
)
from .guard import LeakageError, SplitIndex
from .preprocess import (
    RF_JOBS, SAMPLE_ROWS, SEEDS, SCHEME_BY_KEY, THRESHOLD, binary_metrics, build_preprocessor, latest_dir,
    make_rf, train_sample,
)
from .runtime import RunContext, keep_awake, write_json

SCHEME = SCHEME_BY_KEY["P1"]  # §5.5：树模型使用 P1
MODELS = ("RF", "LightGBM")
COMPARED_VIEWS = ("V0", "V1", "V2", "V3")
DIAGNOSTIC_VIEW = "V4"
DIAGNOSTIC_MODELS = ("LightGBM",)
SELECTION_TIE = 0.002
IMPORTANCE_SHARE = 0.99
# M8 参数，固定 600 轮、不在验证集早停（验证集只用于评估）。
LGBM_PARAMS = {
    "n_estimators": 600, "learning_rate": 0.05, "num_leaves": 127, "min_child_samples": 50,
    "colsample_bytree": 0.8, "subsample": 0.8, "subsample_freq": 1, "n_jobs": RF_JOBS, "verbose": -1,
}
RF_PARAMS = {"n_estimators": 100, "max_depth": 24, "min_samples_leaf": 1, "max_features": "sqrt", "n_jobs": RF_JOBS}
RUN_COLUMNS = ("view", "model", "seed", "status", "fit_rows", "n_features", "encoded_features", "fit_seconds",
               "precision", "recall", "f1", "macro_f1", "accuracy", "auc", "pr_auc", "fpr", "fnr",
               "tp", "fp", "tn", "fn", "error")
# 表号接续第 6 步的表 1～3。
TABLE_NUMBERS = {"RF": 4, "LightGBM": 5}
TABLE_METRICS = (("precision", "Precision"), ("recall", "Recall"), ("f1", "F1-score"),
                 ("accuracy", "Accuracy"), ("auc", "AUC"))


def make_lgbm(seed: int):
    from lightgbm import LGBMClassifier

    return LGBMClassifier(random_state=seed, **LGBM_PARAMS)


def make_model(name: str, seed: int):
    if name == "RF":
        return make_rf(False, seed)
    if name == "LightGBM":
        return make_lgbm(seed)
    raise ValueError(f"unknown model: {name}")


def _check_train_rows(rows: np.ndarray, split: SplitIndex) -> None:
    if not np.isin(rows, split.train).all():
        raise LeakageError("fit rows include indices outside the training partition")


def fit_on_rows(columns: list[str], model_name: str, seed: int, frame: pd.DataFrame, labels: np.ndarray,
                fit_rows: np.ndarray, split: SplitIndex) -> tuple[Any, Any, float]:
    """只在训练分区的 ``fit_rows`` 上拟合 P1 预处理与模型，返回 (预处理器, 模型, 拟合秒数)。"""
    _check_train_rows(fit_rows, split)
    start = time.perf_counter()
    preprocessor = build_preprocessor(SCHEME, seed, columns)
    x_fit = preprocessor.fit_transform(frame.iloc[fit_rows][columns]).astype(np.float32, copy=False)
    model = make_model(model_name, seed)
    model.fit(x_fit, labels[fit_rows])
    return preprocessor, model, time.perf_counter() - start


def run_one(view: str, columns: list[str], model_name: str, seed: int, frame: pd.DataFrame, labels: np.ndarray,
            fit_rows: np.ndarray, split: SplitIndex) -> dict[str, Any]:
    """拟合一次并在完整验证分区上以阈值 0.5 评估；额外报告 PR-AUC（强不平衡下比 ROC-AUC 更敏感）。"""
    from sklearn.metrics import average_precision_score

    preprocessor, model, fit_seconds = fit_on_rows(columns, model_name, seed, frame, labels, fit_rows, split)
    x_val = preprocessor.transform(frame.iloc[split.validation][columns]).astype(np.float32, copy=False)
    y_val = labels[split.validation]
    prob = model.predict_proba(x_val)[:, 1]
    encoded = int(x_val.shape[1])
    del model, preprocessor, x_val
    gc.collect()
    return {"view": view, "model": model_name, "seed": seed, "status": "ok", "fit_rows": int(len(fit_rows)),
            "n_features": len(columns), "encoded_features": encoded, "fit_seconds": fit_seconds,
            **binary_metrics(y_val, prob, THRESHOLD), "pr_auc": float(average_precision_score(y_val, prob)),
            "error": ""}


def gain_importance(preprocessor: Any, model: Any, columns: list[str]) -> pd.Series:
    """LightGBM gain 重要性，按视图列名汇总（缺失指示列的 gain 计入其来源特征）。"""
    names = list(preprocessor.get_feature_names_out())
    gains = model.booster_.feature_importance(importance_type="gain")
    if len(names) != len(gains):
        raise ValueError("encoded feature names do not match booster features")
    series = pd.Series(gains, index=[n.removeprefix("missingindicator_") for n in names], dtype="float64")
    return series.groupby(level=0).sum().reindex(columns, fill_value=0.0)

# ---------------------------------------------------------------- 视图定义

def _dir_name(path: Any) -> str:
    """取目录名；兼容 Windows 反斜杠路径在任意平台上的解析。"""
    return str(path).replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]


def load_eda_inputs(eda_dir: Path, split_dir: Path) -> tuple[pd.DataFrame, pd.Series]:
    """读取 EDA 冗余对与互信息；EDA 必须基于同一份切分（只在训练分区上计算），否则 fail-closed。"""
    import json

    config = json.loads((eda_dir / "run-config.json").read_text(encoding="utf-8"))
    eda_split = _dir_name(config.get("params", {}).get("split_dir", ""))
    if eda_split != _dir_name(split_dir):
        raise LeakageError(f"EDA {eda_dir.name} was computed on split {eda_split!r}, expected {Path(split_dir).name!r}")
    pairs = pd.read_csv(eda_dir / "d1-high-correlation-pairs.csv")
    mi = pd.read_csv(eda_dir / "d1-mutual-information.csv", index_col=0)["mutual_information"]
    return pairs, mi


def define_views(frame: pd.DataFrame, labels: np.ndarray, split: SplitIndex, fit_rows: np.ndarray,
                 pairs: pd.DataFrame, mutual_information: pd.Series, seed: int
                 ) -> tuple[dict[str, list[str]], dict[str, Any], pd.Series]:
    """构造 V0～V3 的列表。V3 = V2 − 冗余对低互信息者 − TCP 初始序列号，再按训练抽样上
    LightGBM gain 保留累计 ``IMPORTANCE_SHARE``。返回 (视图, 构造说明, V2 重要性)。"""
    v2 = list(V2_FEATURES)
    preprocessor, model, _ = fit_on_rows(v2, "LightGBM", seed, frame, labels, fit_rows, split)
    v2_importance = gain_importance(preprocessor, model, v2)
    del preprocessor, model
    redundant = redundancy_drops(pairs, mutual_information, v2)
    candidates = [c for c in v2 if c not in set(redundant) | set(RANDOM_ISN)]
    preprocessor, model, _ = fit_on_rows(candidates, "LightGBM", seed, frame, labels, fit_rows, split)
    candidate_importance = gain_importance(preprocessor, model, candidates)
    del preprocessor, model
    gc.collect()
    kept = set(cumulative_importance_keep(candidate_importance, IMPORTANCE_SHARE))
    v3 = [c for c in candidates if c in kept]
    views = {"V0": list(V0_FEATURES), "V1": list(V1_FEATURES), "V2": v2, "V3": v3}
    notes = {
        "importance_seed": seed, "importance_fit_rows": int(len(fit_rows)), "importance_share": IMPORTANCE_SHARE,
        "redundancy_dropped": redundant, "random_isn_dropped": list(RANDOM_ISN),
        "importance_dropped": [c for c in candidates if c not in kept],
        "candidate_importance": {k: float(v) for k, v in candidate_importance.items()},
    }
    return views, notes, v2_importance


def diagnostic_view(views: dict[str, list[str]], selected: str) -> list[str]:
    """V4：在选中视图上去掉 TTL 特征（只用于诊断，不参与选型）。"""
    return [c for c in views[selected] if c not in TTL_FEATURES]

# ---------------------------------------------------------------- 汇总与选择

def summarize(runs: pd.DataFrame) -> pd.DataFrame:
    ok = runs[runs["status"] == "ok"]
    metrics = ["precision", "recall", "f1", "macro_f1", "accuracy", "auc", "pr_auc", "fpr", "fnr",
               "fit_seconds", "n_features"]
    grouped = ok.groupby(["view", "model"])[metrics]
    summary = grouped.mean().add_suffix("_mean").join(grouped.std(ddof=0).add_suffix("_std"))
    summary["seeds"] = ok.groupby(["view", "model"])["seed"].nunique()
    order = {v: i for i, v in enumerate((*COMPARED_VIEWS, DIAGNOSTIC_VIEW))}
    summary = summary.reset_index()
    summary["_order"] = summary["view"].map(order)
    return summary.sort_values(["model", "_order"]).drop(columns="_order").reset_index(drop=True)


def select_view(summary: pd.DataFrame, expected_seeds: int, expected_models: tuple[str, ...] = MODELS
                ) -> dict[str, Any]:
    """以 RF 与 LightGBM 验证集 Macro-F1 均值排序；V3 与第一名差距 ≤ ``SELECTION_TIE`` 时优先选 V3。

    任一 (视图, 模型) 的成功种子数不足时拒绝选型（fail-closed），需先 ``--resume`` 补跑。
    """
    compared = summary[summary["view"].isin(COMPARED_VIEWS)]
    complete = compared[compared["seeds"] >= expected_seeds]
    counts = complete.groupby("view")["model"].nunique()
    incomplete = sorted(set(COMPARED_VIEWS) - set(counts[counts == len(expected_models)].index))
    if incomplete:
        raise RuntimeError(f"views without complete runs for all models/seeds: {incomplete}; rerun with --resume")
    means = complete.groupby("view")["macro_f1_mean"].mean().reindex(COMPARED_VIEWS)
    ranked = means.sort_values(ascending=False, kind="mergesort")
    top = str(ranked.index[0])
    gap_v3 = float(ranked.iloc[0] - means["V3"])
    selected = "V3" if gap_v3 <= SELECTION_TIE else top
    return {
        "selected_view": selected, "top_by_mean_macro_f1": top, "v3_gap_to_top": gap_v3,
        "mean_macro_f1": {k: float(v) for k, v in ranked.items()},
        "rule": "RF 与 LightGBM 验证集 Macro-F1 均值最高；V3 与第一名差距 ≤ 0.002 时优先选 V3",
        "tie": SELECTION_TIE,
    }

# ---------------------------------------------------------------- 报告

def markdown_table(summary: pd.DataFrame, model: str, number: int) -> str:
    """版式同第 6 步：上方中英文表题，行为指标、列为 V0～V3，保留 3 位小数，每行最优值加粗。"""
    part = summary[summary["model"] == model].set_index("view")
    keys = [v for v in COMPARED_VIEWS if v in part.index]
    lines = [
        f"表 {number}  {model} 模型在不同特征视图下的性能对比",
        f"Table {number}  Performance comparison of {model} under different feature views",
        "",
        "| 指标 | " + " | ".join(keys) + " |",
        "|---|" + "---:|" * len(keys),
    ]
    for column, title in TABLE_METRICS:
        values = part.loc[keys, f"{column}_mean"]
        best = values.max()
        cells = [f"**{v:.3f}**" if np.isclose(v, best) else f"{v:.3f}" for v in values]
        lines.append(f"| {title} | " + " | ".join(cells) + " |")
    counts = [f"{int(part.loc[k, 'n_features_mean'])}" for k in keys]
    lines.append("| 特征数 | " + " | ".join(counts) + " |")
    return "\n".join(lines)


def ttl_diagnostic_lines(summary: pd.DataFrame, selected: str) -> list[str]:
    diag = summary[summary["view"] == DIAGNOSTIC_VIEW]
    lines = []
    for row in diag.itertuples():
        base = summary[(summary["view"] == selected) & (summary["model"] == row.model)]
        if base.empty:
            continue
        b = base.iloc[0]
        lines.append(
            f"{row.model}：去掉 TTL 特征后 Macro-F1 {b['macro_f1_mean']:.3f} → {row.macro_f1_mean:.3f}"
            f"（{row.macro_f1_mean - b['macro_f1_mean']:+.3f}），PR-AUC {b['pr_auc_mean']:.3f} → {row.pr_auc_mean:.3f}，"
            f"FNR {b['fnr_mean']:.2%} → {row.fnr_mean:.2%}，FPR {b['fpr_mean']:.2%} → {row.fpr_mean:.2%}。"
        )
    return lines


def plot_importance(importance: pd.Series, path: Path, top: int = 30) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    from .eda import GRID, INK, INK_SECONDARY, _style

    _style()
    data = (importance / importance.sum()).sort_values(ascending=False).head(top)[::-1]
    fig, ax = plt.subplots(figsize=(7.5, 8))
    ax.barh(data.index, data.values, color="#2a78d6", height=0.7)
    ax.set_xlabel("gain 占比", color=INK_SECONDARY)
    ax.grid(axis="y", visible=False)
    ax.grid(axis="x", color=GRID)
    ax.set_title(f"V2 特征重要性 Top-{top}（LightGBM gain，训练抽样）", loc="left", fontsize=11, color=INK)
    fig.savefig(path)
    plt.close(fig)


def report(run_dir: Path, expected_seeds: int) -> dict[str, Any]:
    runs = pd.read_csv(run_dir / "feature-runs.csv")
    summary = summarize(runs)
    summary.to_csv(run_dir / "feature-summary.csv", index=False, encoding="utf-8")
    failed = runs[runs["status"] != "ok"][["view", "model", "seed", "error"]].to_dict("records")
    selection = select_view(summary, expected_seeds)
    selection["ttl_diagnostic"] = ttl_diagnostic_lines(summary, selection["selected_view"])
    selection["failed_runs"] = failed
    write_json(run_dir / "feature-selection.json", selection)
    body = [
        f"# 特征工程对比（验证集，阈值 0.5，{expected_seeds} 个种子均值）", "",
        "数据：D1 UNSW-NB15 原始数据；预处理 P1（中位数插补 + 缺失指示 + Ordinal 编码）；每个种子从训练分区分层抽样拟合，"
        "完整验证分区评估；holdout 未读取。Precision/Recall/F1 以攻击为正类；标准差、PR-AUC、FPR、FNR、Macro-F1 与耗时见 "
        "feature-summary.csv，视图构造见 feature-views.json。", "",
    ]
    for model in MODELS:
        body += [markdown_table(summary, model, TABLE_NUMBERS[model]), ""]
    ranking = "，".join(f"{k} {v:.4f}" for k, v in selection["mean_macro_f1"].items())
    body += ["## 选择", "",
             f"- Macro-F1 均值（RF 与 LightGBM）：{ranking}。",
             f"- 第一名 {selection['top_by_mean_macro_f1']}，V3 与第一名差距 {selection['v3_gap_to_top']:.4f}"
             f"（阈值 {SELECTION_TIE}），选定 V* = **{selection['selected_view']}**。", "",
             f"## TTL 依赖诊断（V4 = {selection['selected_view']} 去掉 sttl、dttl、ct_state_ttl，不参与选型）", ""]
    body += [f"- {line}" for line in selection["ttl_diagnostic"]] or ["- 诊断未完成"]
    if failed:
        body += ["", "## 失败记录", ""] + [f"- {f['view']} {f['model']} seed={f['seed']}：{f['error']}" for f in failed]
    (run_dir / "feature-comparison.md").write_text("\n".join(body) + "\n", encoding="utf-8")
    return selection

# ---------------------------------------------------------------- 主循环

def completed_keys(path: Path) -> set[tuple[str, str, int]]:
    if not path.exists():
        return set()
    done = pd.read_csv(path)
    done = done[done["status"] == "ok"]
    return {(r.view, r.model, int(r.seed)) for r in done.itertuples()}


def append_row(path: Path, row: dict[str, Any]) -> None:
    frame = pd.DataFrame([{c: row.get(c, "") for c in RUN_COLUMNS}])
    frame.to_csv(path, mode="a", header=not path.exists(), index=False, encoding="utf-8")


def load_frame(manifest: dict[str, Any]) -> tuple[pd.DataFrame, np.ndarray]:
    """读取并校验 D1 原始缓存，构造 V2 全量视图（V0/V1 为其列子集）。"""
    raw = load_cached("d1_raw.parquet", manifest, columns=[*V1_RAW_COLUMNS, "Label"])
    labels = raw["Label"].to_numpy(dtype=np.int8)
    frame = build_v2(raw)
    del raw
    gc.collect()
    return frame, labels


def run(seed: int = GLOBAL_SEED, resume: Path | None = None, split_dir: Path | None = None,
        eda_dir: Path | None = None, seeds: tuple[int, ...] = SEEDS, sample_rows: int = SAMPLE_ROWS) -> Path:
    """执行第 7 步。``resume`` 指向已有运行目录时复用其 ``feature-views.json`` 并跳过已完成的 (视图, 模型, 种子)。"""
    import json

    manifest_file, manifest = load_manifest()
    split_dir = Path(split_dir) if split_dir else latest_dir("split-*/split-audit.json")
    eda_dir = Path(eda_dir) if eda_dir else latest_dir("eda-*/eda-summary.json")
    params = {"register_manifest": str(manifest_file), "split_dir": str(split_dir), "eda_dir": str(eda_dir),
              "sample_rows": sample_rows, "seeds": list(seeds), "models": list(MODELS), "scheme": SCHEME.key,
              "threshold": THRESHOLD, "lightgbm": LGBM_PARAMS, "rf": RF_PARAMS, "importance_share": IMPORTANCE_SHARE,
              "selection_tie": SELECTION_TIE}
    if resume:
        run_dir = Path(resume)
    else:
        ctx = RunContext("feature", seed, params)
        run_dir = ctx.run_dir
    log = run_dir / "training.log"
    runs_csv = run_dir / "feature-runs.csv"
    views_file = run_dir / "feature-views.json"

    def say(message: str) -> None:
        with log.open("a", encoding="utf-8") as stream:
            stream.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {message}\n")

    pairs, mi = load_eda_inputs(eda_dir, split_dir)
    frame, labels = load_frame(manifest)
    split = SplitIndex.load(split_dir / "split-d1-raw.npz")
    fit_rows = {s: train_sample(split, labels, sample_rows, s) for s in seeds}

    with keep_awake():
        if views_file.exists():
            spec = json.loads(views_file.read_text(encoding="utf-8"))
            views = spec["views"]
            say(f"reuse views: " + ", ".join(f"{k}={len(v)}" for k, v in views.items()))
        else:
            views, notes, v2_importance = define_views(frame, labels, split, fit_rows[seeds[0]], pairs, mi, seeds[0])
            write_json(views_file, {"views": views, "construction": notes, "split_fingerprint": split.fingerprint})
            v2_importance.rename("gain").to_csv(run_dir / "v2-importance.csv", encoding="utf-8")
            plot_importance(v2_importance, run_dir / "v2-importance-top30.png")
            say("views: " + ", ".join(f"{k}={len(v)}" for k, v in views.items()))
        done = completed_keys(runs_csv)
        say(f"start: {len(COMPARED_VIEWS)} views x {len(MODELS)} models x {len(seeds)} seeds; {len(done)} already done")

        def execute(view: str, columns: list[str], model_name: str, run_seed: int) -> None:
            if (view, model_name, run_seed) in done:
                return
            try:
                row = run_one(view, columns, model_name, run_seed, frame, labels, fit_rows[run_seed], split)
                say(f"{view} {model_name} seed={run_seed} macro_f1={row['macro_f1']:.4f} pr_auc={row['pr_auc']:.4f} "
                    f"t={row['fit_seconds']:.0f}s")
            except Exception as exc:  # 单组失败记录后继续，汇总时显式标出
                row = {"view": view, "model": model_name, "seed": run_seed, "status": "failed",
                       "error": f"{type(exc).__name__}: {exc}"[:500]}
                say(f"{view} {model_name} seed={run_seed} FAILED {row['error']}")
            append_row(runs_csv, row)

        for run_seed in seeds:
            for view in COMPARED_VIEWS:
                for model_name in MODELS:
                    execute(view, views[view], model_name, run_seed)
        # 选型后再在 V* 上做 TTL 诊断；诊断视图随 V* 写回 feature-views.json。
        selected = select_view(summarize(pd.read_csv(runs_csv)), len(seeds))["selected_view"]
        v4 = diagnostic_view(views, selected)
        spec = json.loads(views_file.read_text(encoding="utf-8"))
        spec["diagnostic"] = {"view": DIAGNOSTIC_VIEW, "base": selected, "columns": v4, "removed": list(TTL_FEATURES)}
        write_json(views_file, spec)
        for run_seed in seeds:
            for model_name in DIAGNOSTIC_MODELS:
                execute(DIAGNOSTIC_VIEW, v4, model_name, run_seed)
    selection = report(run_dir, len(seeds))
    say(f"done: V*={selection['selected_view']}")
    if not resume:
        ctx.finish()
    else:
        RunContext.checksum_dir(run_dir)
    return run_dir
