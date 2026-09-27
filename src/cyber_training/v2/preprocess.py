"""第 6 步：预处理对比试验。

在 D1 原始数据的 V0 视图上，从"不做预处理"的基线出发、每组只改变一个因素，比较 12 组预处理方案
对 LR、RF、MLP 三类模型的影响。每个种子从训练分区分层抽样 ``SAMPLE_ROWS`` 行拟合（预处理与采样器
只接触训练行），在完整验证分区上以阈值 0.5 评估；holdout 不被读取。

输出：逐次结果 ``preprocessing-runs.csv``（可断点续跑）、汇总 ``preprocessing-summary.csv``、
参考论文版式的 ``preprocessing-comparison.md``、热力图与 ``preprocessing-selection.json``。
"""

from __future__ import annotations

import time
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.decomposition import PCA
from sklearn.exceptions import ConvergenceWarning
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import (
    FunctionTransformer, MinMaxScaler, OneHotEncoder, OrdinalEncoder, QuantileTransformer, RobustScaler,
    StandardScaler,
)

from . import GLOBAL_SEED
from .datasets import load_cached, load_manifest
from .features import V0_FEATURES, V0_RAW_COLUMNS, build_v0, categorical_features, numeric_features
from .guard import LeakageError, SplitIndex
from .runtime import RUNS_ROOT, RunContext, keep_awake, sha256_file, write_json

SAMPLE_ROWS = 400_000
SEEDS = (20260927, 20260928, 20260929)
THRESHOLD = 0.5
MODELS = ("LR", "RF", "MLP")
RARE_CATEGORY_FREQUENCY = 0.001
RF_JOBS = 16  # 20 线程中保留 4 个给系统、SSH 与驱动
SELECTION_TIE = 0.002


@dataclass(frozen=True)
class Scheme:
    """一组预处理配置。``components`` 用于"差距很小时选更简单方案"的比较。"""

    key: str
    label: str
    impute: str  # zero | median
    encode: str  # ordinal | onehot
    transform: str  # none | log1p | quantile
    scale: str  # none | standard | minmax | robust
    reduce: str  # none | pca
    balance: str  # none | class_weight | undersample | smote

    @property
    def components(self) -> int:
        return sum([
            self.impute == "median", self.encode == "onehot", self.transform != "none",
            self.scale != "none", self.reduce != "none", self.balance != "none",
        ])


SCHEMES = (
    Scheme("P0", "不做预处理", "zero", "ordinal", "none", "none", "none", "none"),
    Scheme("P1", "中位数插补", "median", "ordinal", "none", "none", "none", "none"),
    Scheme("P2", "One-hot", "median", "onehot", "none", "none", "none", "none"),
    Scheme("P3", "Standard", "median", "onehot", "none", "standard", "none", "none"),
    Scheme("P4", "MinMax", "median", "onehot", "none", "minmax", "none", "none"),
    Scheme("P5", "Robust", "median", "onehot", "none", "robust", "none", "none"),
    Scheme("P6", "log1p+Standard", "median", "onehot", "log1p", "standard", "none", "none"),
    Scheme("P7", "Quantile", "median", "onehot", "quantile", "none", "none", "none"),
    Scheme("P8", "P6+PCA", "median", "onehot", "log1p", "standard", "pca", "none"),
    Scheme("P9", "P6+类权重", "median", "onehot", "log1p", "standard", "none", "class_weight"),
    Scheme("P10", "P6+欠采样", "median", "onehot", "log1p", "standard", "none", "undersample"),
    Scheme("P11", "P6+SMOTE", "median", "onehot", "log1p", "standard", "none", "smote"),
)
SCHEME_BY_KEY = {s.key: s for s in SCHEMES}


def signed_log1p(values: np.ndarray) -> np.ndarray:
    return np.sign(values) * np.log1p(np.abs(values))


def build_preprocessor(scheme: Scheme, seed: int, columns: tuple[str, ...] | list[str] = V0_FEATURES) -> Pipeline:
    """按方案构造预处理流水线（不含重采样）。所有组件只在调用方传入的训练行上拟合。

    ``columns`` 为输入视图的列（默认 V0）；类别列由 ``features.CATEGORICAL`` 判定，其余视为数值列。
    """
    numeric = numeric_features(columns)
    categorical = categorical_features(columns)
    steps: list[tuple[str, Any]] = []
    if scheme.impute == "zero":
        steps.append(("impute", SimpleImputer(strategy="constant", fill_value=0.0)))
    else:
        steps.append(("impute", SimpleImputer(strategy="median", add_indicator=True)))
    if scheme.transform == "log1p":
        steps.append(("log1p", FunctionTransformer(signed_log1p, feature_names_out="one-to-one")))
    elif scheme.transform == "quantile":
        steps.append(("quantile", QuantileTransformer(output_distribution="normal", n_quantiles=1000,
                                                      subsample=200_000, random_state=seed)))
    scaler = {"standard": StandardScaler(), "minmax": MinMaxScaler(), "robust": RobustScaler()}.get(scheme.scale)
    if scaler is not None:
        steps.append(("scale", scaler))
    if scheme.encode == "ordinal":
        encoder: Any = OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1,
                                      encoded_missing_value=-1, dtype=np.float32)
    else:
        encoder = OneHotEncoder(handle_unknown="infrequent_if_exist", min_frequency=RARE_CATEGORY_FREQUENCY,
                                sparse_output=False, dtype=np.float32)
    columns = ColumnTransformer(
        [("numeric", Pipeline(steps), numeric), ("categorical", encoder, categorical)],
        verbose_feature_names_out=False,
    )
    pipeline_steps: list[tuple[str, Any]] = [("columns", columns)]
    if scheme.reduce == "pca":
        pipeline_steps.append(("pca", PCA(n_components=0.95, svd_solver="full", random_state=seed)))
    return Pipeline(pipeline_steps)


def resample(x: np.ndarray, y: np.ndarray, scheme: Scheme, seed: int) -> tuple[np.ndarray, np.ndarray]:
    """只作用于已变换的训练矩阵：随机欠采样到 正:负 = 1:3，或 SMOTE 到 1:2。"""
    if scheme.balance == "undersample":
        from imblearn.under_sampling import RandomUnderSampler

        return RandomUnderSampler(sampling_strategy=1 / 3, random_state=seed).fit_resample(x, y)
    if scheme.balance == "smote":
        from imblearn.over_sampling import SMOTE

        return SMOTE(sampling_strategy=0.5, k_neighbors=5, random_state=seed).fit_resample(x, y)
    return x, y


# ---------------------------------------------------------------- 模型

def make_lr(balanced: bool, seed: int):
    from sklearn.linear_model import LogisticRegression

    return LogisticRegression(C=1.0, solver="lbfgs", max_iter=1000, tol=1e-4,
                              class_weight="balanced" if balanced else None, random_state=seed)


def make_rf(balanced: bool, seed: int):
    from sklearn.ensemble import RandomForestClassifier

    return RandomForestClassifier(n_estimators=100, max_depth=24, min_samples_leaf=1, max_features="sqrt",
                                  n_jobs=RF_JOBS, class_weight="balanced" if balanced else None, random_state=seed)


class TorchMLP:
    """2×256 隐层 MLP（ReLU、dropout 0.2），AdamW 1e-3，batch 8192，固定 15 轮，CUDA 训练。

    类权重方案下正类损失乘以 负/正 样本比。CUDA 不可用时显式失败，不静默退回 CPU。
    """

    def __init__(self, balanced: bool, seed: int, epochs: int = 15, batch_size: int = 8192):
        self.balanced, self.seed, self.epochs, self.batch_size = balanced, seed, epochs, batch_size
        self.model = None

    def fit(self, x: np.ndarray, y: np.ndarray) -> "TorchMLP":
        import torch
        from torch import nn

        if not torch.cuda.is_available():
            raise RuntimeError("MLP requires CUDA; refusing to fall back to CPU silently")
        torch.manual_seed(self.seed)
        device = torch.device("cuda")
        self.model = nn.Sequential(
            nn.Linear(x.shape[1], 256), nn.ReLU(), nn.Dropout(0.2),
            nn.Linear(256, 256), nn.ReLU(), nn.Dropout(0.2), nn.Linear(256, 1),
        ).to(device)
        positives = max(float(y.sum()), 1.0)
        pos_weight = torch.tensor([(len(y) - positives) / positives if self.balanced else 1.0], device=device)
        loss_fn = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
        optimizer = torch.optim.AdamW(self.model.parameters(), lr=1e-3, weight_decay=1e-4)
        features = torch.as_tensor(np.nan_to_num(x, nan=0.0, posinf=0.0, neginf=0.0), dtype=torch.float32, device=device)
        target = torch.as_tensor(y, dtype=torch.float32, device=device)
        generator = torch.Generator(device=device).manual_seed(self.seed)
        self.model.train()
        for _ in range(self.epochs):
            order = torch.randperm(len(target), device=device, generator=generator)
            for start in range(0, len(order), self.batch_size):
                batch = order[start:start + self.batch_size]
                optimizer.zero_grad(set_to_none=True)
                loss_fn(self.model(features[batch]).squeeze(1), target[batch]).backward()
                optimizer.step()
        del features, target
        torch.cuda.empty_cache()
        return self

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        import torch

        self.model.eval()
        out = []
        with torch.no_grad():
            for start in range(0, len(x), 65_536):
                chunk = torch.as_tensor(np.nan_to_num(x[start:start + 65_536], nan=0.0, posinf=0.0, neginf=0.0),
                                        dtype=torch.float32, device="cuda")
                out.append(torch.sigmoid(self.model(chunk).squeeze(1)).cpu().numpy())
        prob = np.concatenate(out)
        return np.column_stack([1.0 - prob, prob])

    def release(self) -> None:
        import torch

        self.model = None
        torch.cuda.empty_cache()


def make_model(name: str, scheme: Scheme, seed: int):
    balanced = scheme.balance == "class_weight"
    if name == "LR":
        return make_lr(balanced, seed)
    if name == "RF":
        return make_rf(balanced, seed)
    if name == "MLP":
        return TorchMLP(balanced, seed)
    raise ValueError(f"unknown model: {name}")


# ---------------------------------------------------------------- 指标

def binary_metrics(y: np.ndarray, prob: np.ndarray, threshold: float = THRESHOLD) -> dict[str, float]:
    """阈值 ``threshold`` 下的二分类指标；Precision/Recall/F1 以攻击为正类，另给 Macro-F1。"""
    from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score

    pred = (prob >= threshold).astype(np.int8)
    tn = int(((pred == 0) & (y == 0)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    tp = int(((pred == 1) & (y == 1)).sum())
    return {
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "macro_f1": float(f1_score(y, pred, average="macro", zero_division=0)),
        "accuracy": float(accuracy_score(y, pred)),
        "auc": float(roc_auc_score(y, prob)) if len(np.unique(y)) == 2 else float("nan"),
        "fpr": fp / max(fp + tn, 1),
        "fnr": fn / max(fn + tp, 1),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
    }


# ---------------------------------------------------------------- 主循环

RUN_COLUMNS = ("scheme", "model", "seed", "status", "fit_rows", "encoded_features", "fit_seconds",
               "precision", "recall", "f1", "macro_f1", "accuracy", "auc", "fpr", "fnr", "tp", "fp", "tn", "fn", "error")


def train_sample(split: SplitIndex, labels: np.ndarray, size: int, seed: int) -> np.ndarray:
    rows = split.train
    if len(rows) <= size:
        return np.sort(rows)
    picked, _ = train_test_split(rows, train_size=size, stratify=labels[rows], random_state=seed)
    return np.sort(picked)


def run_one(scheme: Scheme, model_name: str, seed: int, features: pd.DataFrame, labels: np.ndarray,
            fit_rows: np.ndarray, split: SplitIndex) -> dict[str, Any]:
    """在 ``fit_rows``（必须属于训练分区）上拟合预处理与模型，在完整验证分区上评估。"""
    if not np.isin(fit_rows, split.train).all():
        raise LeakageError("fit rows include indices outside the training partition")
    start = time.perf_counter()
    preprocessor = build_preprocessor(scheme, seed)
    x_fit = preprocessor.fit_transform(features.iloc[fit_rows]).astype(np.float32, copy=False)
    y_fit = labels[fit_rows]
    x_fit, y_fit = resample(x_fit, y_fit, scheme, seed)
    model = make_model(model_name, scheme, seed)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", ConvergenceWarning)
        model.fit(x_fit, y_fit)
    fit_seconds = time.perf_counter() - start
    x_val = preprocessor.transform(features.iloc[split.validation]).astype(np.float32, copy=False)
    prob = model.predict_proba(x_val)[:, 1]
    if hasattr(model, "release"):
        model.release()
    return {"scheme": scheme.key, "model": model_name, "seed": seed, "status": "ok", "fit_rows": int(len(y_fit)),
            "encoded_features": int(x_fit.shape[1]), "fit_seconds": fit_seconds,
            **binary_metrics(labels[split.validation], prob), "error": ""}


def completed_keys(path: Path) -> set[tuple[str, str, int]]:
    if not path.exists():
        return set()
    done = pd.read_csv(path)
    done = done[done["status"] == "ok"]
    return {(r.scheme, r.model, int(r.seed)) for r in done.itertuples()}


def append_row(path: Path, row: dict[str, Any]) -> None:
    frame = pd.DataFrame([{c: row.get(c, "") for c in RUN_COLUMNS}])
    frame.to_csv(path, mode="a", header=not path.exists(), index=False, encoding="utf-8")


def latest_dir(pattern: str, runs_root: Path = RUNS_ROOT) -> Path:
    candidates = sorted(Path(runs_root).glob(pattern))
    if not candidates:
        raise FileNotFoundError(f"no run matches {pattern}")
    return candidates[-1].parent


def run(seed: int = GLOBAL_SEED, resume: Path | None = None, split_dir: Path | None = None,
        schemes: tuple[str, ...] | None = None, models: tuple[str, ...] = MODELS, seeds: tuple[int, ...] = SEEDS,
        sample_rows: int = SAMPLE_ROWS) -> Path:
    """执行第 6 步。``resume`` 指向已有运行目录时跳过已完成的 (方案, 模型, 种子)。"""
    manifest_file, manifest = load_manifest()
    split_dir = Path(split_dir) if split_dir else latest_dir("split-*/split-audit.json")
    selected = [SCHEME_BY_KEY[k] for k in schemes] if schemes else list(SCHEMES)
    params = {"register_manifest": str(manifest_file), "split_dir": str(split_dir), "sample_rows": sample_rows,
              "seeds": list(seeds), "models": list(models), "schemes": [s.key for s in selected],
              "threshold": THRESHOLD, "rf_jobs": RF_JOBS}
    if resume:
        run_dir = Path(resume)
        log = run_dir / "training.log"
    else:
        ctx = RunContext("preprocess", seed, params)
        run_dir, log = ctx.run_dir, ctx.path("training.log")
    runs_csv = run_dir / "preprocessing-runs.csv"
    done = completed_keys(runs_csv)

    raw = load_cached("d1_raw.parquet", manifest, columns=[*V0_RAW_COLUMNS, "Label"])
    labels = raw["Label"].to_numpy(dtype=np.int8)
    features = build_v0(raw)
    del raw
    split = SplitIndex.load(split_dir / "split-d1-raw.npz")

    def say(message: str) -> None:
        with log.open("a", encoding="utf-8") as stream:
            stream.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {message}\n")

    say(f"start: {len(selected)} schemes x {len(models)} models x {len(seeds)} seeds; {len(done)} already done")
    with keep_awake():
        for run_seed in seeds:
            fit_rows = train_sample(split, labels, sample_rows, run_seed)
            for scheme in selected:
                for model_name in models:
                    if (scheme.key, model_name, run_seed) in done:
                        continue
                    try:
                        row = run_one(scheme, model_name, run_seed, features, labels, fit_rows, split)
                        say(f"{scheme.key} {model_name} seed={run_seed} f1={row['f1']:.4f} auc={row['auc']:.4f} "
                            f"t={row['fit_seconds']:.0f}s")
                    except Exception as exc:  # 单组失败记录后继续，汇总时显式标出
                        row = {"scheme": scheme.key, "model": model_name, "seed": run_seed, "status": "failed",
                               "error": f"{type(exc).__name__}: {exc}"[:500]}
                        say(f"{scheme.key} {model_name} seed={run_seed} FAILED {row['error']}")
                    append_row(runs_csv, row)
    report(run_dir)
    say("done")
    if not resume:
        ctx.finish()
    else:
        RunContext.checksum_dir(run_dir)
    return run_dir


# ---------------------------------------------------------------- 汇总与报告

TABLE_METRICS = (("precision", "Precision"), ("recall", "Recall"), ("f1", "F1-score"),
                 ("accuracy", "Accuracy"), ("auc", "AUC"))
MODEL_TITLES = {"LR": "LR", "RF": "RF", "MLP": "MLP"}


def summarize(runs: pd.DataFrame) -> pd.DataFrame:
    ok = runs[runs["status"] == "ok"]
    metrics = ["precision", "recall", "f1", "macro_f1", "accuracy", "auc", "fpr", "fnr", "fit_seconds", "encoded_features"]
    grouped = ok.groupby(["scheme", "model"])[metrics]
    summary = grouped.mean().add_suffix("_mean").join(grouped.std(ddof=0).add_suffix("_std"))
    summary["seeds"] = ok.groupby(["scheme", "model"])["seed"].nunique()
    order = {s.key: i for i, s in enumerate(SCHEMES)}
    summary = summary.reset_index()
    summary["_order"] = summary["scheme"].map(order)
    return summary.sort_values(["model", "_order"]).drop(columns="_order").reset_index(drop=True)


def select_scheme(summary: pd.DataFrame, expected_models: tuple[str, ...] = MODELS) -> dict[str, Any]:
    """以 3 个模型验证集 Macro-F1 均值排序；与第一名差距 < 0.002 时选组件更少者。

    只有三个模型都成功的方案才参与排序。另给出树模型可用的最优不缩放方案（P0/P1/P2）。
    """
    pivot = summary.pivot(index="scheme", columns="model", values="macro_f1_mean")
    complete = pivot.dropna(subset=[m for m in expected_models if m in pivot.columns])
    complete = complete[[m for m in expected_models if m in complete.columns]]
    if len(complete.columns) != len(expected_models) or complete.empty:
        raise ValueError("no scheme has results for every model")
    ranking = complete.mean(axis=1).sort_values(ascending=False)
    best = ranking.index[0]
    close = [k for k, v in ranking.items() if ranking.iloc[0] - v < SELECTION_TIE]
    chosen = min(close, key=lambda k: (SCHEME_BY_KEY[k].components, list(ranking.index).index(k)))
    tree = summary[(summary["model"] == "RF") & summary["scheme"].isin(["P0", "P1", "P2"])]
    tree_best = tree.sort_values("macro_f1_mean", ascending=False)["scheme"].iloc[0] if len(tree) else None
    return {
        "selected_scheme": chosen,
        "top_by_mean_macro_f1": best,
        "tie_margin": SELECTION_TIE,
        "tied_candidates": close,
        "ranking": {k: float(v) for k, v in ranking.items()},
        "tree_unscaled_best": tree_best,
        "rule": "3 个模型验证集 Macro-F1 均值最高；差距 < 0.002 时选组件更少的方案",
    }


def markdown_table(summary: pd.DataFrame, model: str, number: int) -> str:
    """参考论文"表4"版式：上方中英文表题，行为指标、列为方案，保留 3 位小数，每行最优值加粗。"""
    part = summary[summary["model"] == model].set_index("scheme")
    keys = [s.key for s in SCHEMES if s.key in part.index]
    lines = [
        f"表 {number}  {MODEL_TITLES[model]} 模型在不同预处理方案下的性能对比",
        f"Table {number}  Performance comparison of {MODEL_TITLES[model]} under different preprocessing schemes",
        "",
        "| 指标 | " + " | ".join(keys) + " |",
        "|---|" + "---:|" * len(keys),
    ]
    for column, title in TABLE_METRICS:
        values = part.loc[keys, f"{column}_mean"]
        best = values.max()
        cells = [f"**{v:.3f}**" if np.isclose(v, best) else f"{v:.3f}" for v in values]
        lines.append(f"| {title} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def conclusions(summary: pd.DataFrame, selection: dict[str, Any]) -> list[str]:
    """由数据自动生成的客观结论（不做推断性夸大）。"""
    pivot = summary.pivot(index="scheme", columns="model", values="macro_f1_mean")
    notes = []
    for model in [m for m in MODELS if m in pivot.columns]:
        col = pivot[model].dropna()
        if {"P2", "P3"} <= set(col.index):
            notes.append(f"{model}：StandardScaler（P3）相对未缩放（P2）的 Macro-F1 变化 {col['P3'] - col['P2']:+.3f}。")
        if {"P6", "P7"} <= set(col.index):
            notes.append(f"{model}：log1p+Standard（P6）与 Quantile（P7）的 Macro-F1 分别为 {col['P6']:.3f} / {col['P7']:.3f}。")
        if {"P6", "P8"} <= set(col.index):
            notes.append(f"{model}：PCA 降维（P8）相对 P6 的 Macro-F1 变化 {col['P8'] - col['P6']:+.3f}。")
    notes.append(f"按 3 个模型 Macro-F1 均值，选定方案为 {selection['selected_scheme']}"
                 f"（均值最高的是 {selection['top_by_mean_macro_f1']}，差距阈值 {SELECTION_TIE}）。")
    return notes


def plot_heatmap(summary: pd.DataFrame, path: Path) -> None:
    """方案 × 模型的验证集 F1 热力图（单色顺序色阶，格内直接标注数值）。"""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.colors import LinearSegmentedColormap

    from .eda import _style

    _style()
    pivot = summary.pivot(index="model", columns="scheme", values="f1_mean")
    pivot = pivot[[s.key for s in SCHEMES if s.key in pivot.columns]].reindex([m for m in MODELS if m in pivot.index])
    cmap = LinearSegmentedColormap.from_list("blue_seq", ["#cde2fb", "#6da7ec", "#2a78d6", "#184f95", "#0d366b"])
    fig, ax = plt.subplots(figsize=(1.0 * pivot.shape[1] + 1.8, 0.8 * pivot.shape[0] + 1.4))
    values = pivot.to_numpy(dtype="float64")
    image = ax.imshow(values, cmap=cmap, aspect="auto")
    ax.set_xticks(range(pivot.shape[1]), pivot.columns)
    ax.set_yticks(range(pivot.shape[0]), pivot.index)
    ax.grid(False)
    mid = np.nanmean(values)
    for i in range(values.shape[0]):
        for j in range(values.shape[1]):
            if not np.isnan(values[i, j]):
                ax.text(j, i, f"{values[i, j]:.3f}", ha="center", va="center", fontsize=8,
                        color="#ffffff" if values[i, j] > mid else "#0b0b0b")
    ax.set_title("不同预处理方案的验证集 F1（攻击类，3 个种子均值）", loc="left", fontsize=11)
    fig.colorbar(image, ax=ax, fraction=0.03, pad=0.02, label="F1")
    fig.savefig(path)
    plt.close(fig)


def report(run_dir: Path) -> dict[str, Any]:
    runs = pd.read_csv(run_dir / "preprocessing-runs.csv")
    summary = summarize(runs)
    summary.to_csv(run_dir / "preprocessing-summary.csv", index=False, encoding="utf-8")
    selection = select_scheme(summary)
    failed = runs[runs["status"] != "ok"][["scheme", "model", "seed", "error"]].to_dict("records")
    selection["failed_runs"] = failed
    write_json(run_dir / "preprocessing-selection.json", selection)
    models = [m for m in MODELS if m in set(summary["model"])]
    legend = "\n".join(f"- {s.key}：{s.label}（插补={s.impute}，编码={s.encode}，变换={s.transform}，"
                       f"缩放={s.scale}，降维={s.reduce}，不平衡={s.balance}）" for s in SCHEMES)
    body = [
        "# 预处理对比试验（验证集，阈值 0.5，3 个种子均值）", "",
        "数据：D1 UNSW-NB15 原始数据 V0 视图（42 个特征）；每个种子从训练分区分层抽样拟合，完整验证分区评估；holdout 未读取。"
        " Precision/Recall/F1 以攻击为正类；标准差、FPR、FNR、Macro-F1 与耗时见 preprocessing-summary.csv。", "",
    ]
    for number, model in enumerate(models, start=1):
        body += [markdown_table(summary, model, number), ""]
    body += ["## 方案说明", "", legend, "", "## 结论", ""] + [f"- {n}" for n in conclusions(summary, selection)]
    if failed:
        body += ["", "## 失败记录", ""] + [f"- {f['scheme']} {f['model']} seed={f['seed']}：{f['error']}" for f in failed]
    (run_dir / "preprocessing-comparison.md").write_text("\n".join(body) + "\n", encoding="utf-8")
    plot_heatmap(summary, run_dir / "preprocessing-f1-heatmap.png")
    return selection
