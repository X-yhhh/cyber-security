"""第 8 步：多模型训练与调优（T1 二分类）。

三个阶段，各自写入独立运行目录，后一阶段读取前一阶段的最新结果：

- ``screen``：9 个模型（M1～M9）以计划 §7.1 初始参数在完整训练分区上训练，完整验证分区评估；
- ``tune``：初筛 Macro-F1 前 3 名外加 MLP（合计 ≤ 4 个）用 Optuna TPE 调参，只在训练分区拟合、验证分区评分；
- ``seeds``：调优后前 3 名各用 5 个种子重训，按 §7.4 规则选型，并保存选中模型主种子的候选制品。

数据与预处理：D1 原始数据、第 7 步选出的 ``V*`` 视图；树模型（DT/RF/ET/XGBoost/LightGBM）用 P1，
其余模型（LR/SVM/GNB/MLP）用 ``P*`` = P7。预处理器只在训练分区拟合。holdout 在本步骤中不被读取。

阈值（§7.3）：每次训练都在验证分区上选阈值——在 FNR ≤ 4% 的阈值中取 FPR 最小者；没有阈值满足时取 F1 最优
阈值并标记 ``constraint_met=False``。报告指标均在所选阈值下计算。XGBoost、LightGBM 与 MLP 的早停使用
验证分区（§7.1），因此验证集指标偏乐观，最终以第 9 步的锁定 holdout 为准。
"""

from __future__ import annotations

import gc
import json
import pickle
import time
import warnings
from pathlib import Path
from typing import Any, Callable

import numpy as np
import pandas as pd

from . import GLOBAL_SEED, REPRO_SEEDS
from .datasets import load_manifest
from .feature_compare import load_frame
from .guard import LeakageError, SplitIndex
from .preprocess import RF_JOBS, SCHEME_BY_KEY, binary_metrics, build_preprocessor, latest_dir, train_sample
from .runtime import RunContext, keep_awake, sha256_file, write_json

STAGES = ("screen", "tune", "seeds")
MODELS = ("LR", "SVM", "GNB", "DT", "RF", "ET", "XGBoost", "LightGBM", "MLP")
TREE_MODELS = ("DT", "RF", "ET", "XGBoost", "LightGBM")
TREE_SCHEME, DENSE_SCHEME = "P1", "P7"  # §5.5
TARGET_FNR = 0.04  # §7.3
SCREEN_TOP, TUNE_MUST, TUNE_MAX, SEEDS_TOP = 3, "MLP", 4, 3
MAX_FNR_STD, MAX_FNR, MAX_FPR, TIE = 0.02, 0.05, 0.015, 0.003  # §7.4
FOREST_SEARCH_FRACTION = 0.5
TUNE_BUDGET = {  # 模型: (试验次数, 时间上限秒)
    "XGBoost": (30, 40 * 60), "LightGBM": (30, 40 * 60), "RF": (12, 50 * 60), "ET": (12, 50 * 60),
    "MLP": (20, 40 * 60),
}
LATENCY_ROWS, THROUGHPUT_BATCH, THROUGHPUT_REPEATS = 200, 1024, 10

SCREEN_PARAMS: dict[str, dict[str, Any]] = {
    "LR": {"C": 1.0, "solver": "lbfgs", "max_iter": 1000},
    "SVM": {"C": 0.5, "dual": False, "calibration": "sigmoid", "cv": 3},
    "GNB": {},
    "DT": {"max_depth": 24, "min_samples_leaf": 5},
    "RF": {"n_estimators": 200, "max_depth": 32, "min_samples_leaf": 2, "max_features": "sqrt"},
    "ET": {"n_estimators": 200, "max_depth": 32, "min_samples_leaf": 2, "max_features": "sqrt"},
    "XGBoost": {"n_estimators": 2000, "learning_rate": 0.05, "max_depth": 8, "subsample": 0.8,
                "colsample_bytree": 0.8, "min_child_weight": 1.0, "gamma": 0.0, "early_stopping_rounds": 100},
    "LightGBM": {"n_estimators": 3000, "learning_rate": 0.05, "num_leaves": 127, "min_child_samples": 50,
                 "colsample_bytree": 0.8, "subsample": 0.8, "subsample_freq": 1, "reg_lambda": 0.0,
                 "early_stopping_rounds": 100},
    "MLP": {"width": 512, "layers": 3, "dropout": 0.3, "lr": 1e-3, "weight_decay": 1e-4, "batch_size": 8192,
            "max_epochs": 30, "patience": 5},
}
RUN_COLUMNS = ("stage", "model", "seed", "status", "trial", "fit_rows", "encoded_features", "fit_seconds",
               "threshold", "constraint_met", "precision", "recall", "f1", "macro_f1", "accuracy", "auc", "pr_auc",
               "fpr", "fnr", "tp", "fp", "tn", "fn", "best_iteration", "latency_p50_ms", "latency_p95_ms",
               "throughput_rows_s", "model_bytes", "params", "error")


def scheme_for(model: str):
    return SCHEME_BY_KEY[TREE_SCHEME if model in TREE_MODELS else DENSE_SCHEME]

# ---------------------------------------------------------------- 阈值（§7.3）

def select_threshold(y: np.ndarray, prob: np.ndarray, target_fnr: float = TARGET_FNR) -> tuple[float, bool]:
    """在验证分区上选阈值（判定规则 ``prob >= threshold``）。

    在 FNR ≤ ``target_fnr`` 的阈值中取 FPR 最小者（FPR 相同时取最高阈值）；没有阈值满足时取攻击类 F1 最优
    阈值，并返回 ``constraint_met=False``。只用于验证分区，调用方不得传入 holdout。
    """
    from sklearn.metrics import precision_recall_curve, roc_curve

    y = np.asarray(y)
    if len(np.unique(y)) != 2:
        raise ValueError("threshold selection needs both classes")
    fpr, tpr, thresholds = roc_curve(y, prob, drop_intermediate=False)
    ok = np.flatnonzero((1.0 - tpr) <= target_fnr + 1e-12)
    ok = ok[np.isfinite(thresholds[ok])]
    if ok.size:
        best = ok[np.argmin(fpr[ok])]  # roc_curve 阈值递减，argmin 返回首个最小值，即其中最高阈值
        return float(thresholds[best]), True
    precision, recall, pr_thresholds = precision_recall_curve(y, prob)
    f1 = 2 * precision[:-1] * recall[:-1] / np.maximum(precision[:-1] + recall[:-1], 1e-12)
    return float(pr_thresholds[int(np.argmax(f1))]), False


def evaluate(y: np.ndarray, prob: np.ndarray) -> dict[str, Any]:
    """选阈值并在该阈值下计算指标（含 PR-AUC）。"""
    from sklearn.metrics import average_precision_score

    threshold, met = select_threshold(y, prob)
    return {"threshold": threshold, "constraint_met": met, **binary_metrics(y, prob, threshold),
            "pr_auc": float(average_precision_score(y, prob))}

# ---------------------------------------------------------------- 模型封装
# 统一接口：fit(x, y, x_val, y_val, reporter) → self；predict(x) → 攻击类概率；
# ``reporter(step, value)`` 用于 Optuna 剪枝（value 越大越好），不需要时为 None。

Reporter = Callable[[int, float], None] | None


class SklearnModel:
    """sklearn 估计器封装；不使用验证分区。"""

    def __init__(self, estimator: Any):
        self.estimator = estimator
        self.best_iteration = None

    def fit(self, x, y, x_val, y_val, reporter: Reporter = None) -> "SklearnModel":
        from sklearn.exceptions import ConvergenceWarning

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ConvergenceWarning)
            self.estimator.fit(x, y)
        return self

    def predict(self, x) -> np.ndarray:
        return self.estimator.predict_proba(x)[:, 1]

    def to_cpu(self) -> None:
        if hasattr(self.estimator, "n_jobs") and self.estimator.n_jobs:
            self.estimator.n_jobs = 1  # 单条延迟：避免每次调用的 joblib 并行开销

    def native_bytes(self) -> int:
        return model_bytes(self)

    def save(self, directory: Path) -> list[Path]:
        path = directory / "model.pkl"
        path.write_bytes(pickle.dumps(self.estimator, protocol=pickle.HIGHEST_PROTOCOL))
        return [path]


class XGBModel:
    """XGBoost（hist，CUDA），验证分区早停；每 50 轮向 reporter 报告负 logloss。"""

    def __init__(self, params: dict[str, Any], seed: int):
        from xgboost import XGBClassifier

        p = dict(params)
        self.early = int(p.pop("early_stopping_rounds"))
        self.model = XGBClassifier(tree_method="hist", device="cuda", eval_metric="logloss", random_state=seed,
                                   n_jobs=RF_JOBS, early_stopping_rounds=self.early, **p)
        self.best_iteration = None

    def fit(self, x, y, x_val, y_val, reporter: Reporter = None) -> "XGBModel":
        import xgboost

        callbacks = []
        if reporter is not None:
            class Prune(xgboost.callback.TrainingCallback):
                def after_iteration(self, model, epoch, evals_log):
                    if (epoch + 1) % 50 == 0:
                        reporter(epoch + 1, -float(evals_log["validation_0"]["logloss"][-1]))
                    return False

            callbacks.append(Prune())
        self.model.set_params(callbacks=callbacks or None)
        self.model.fit(x, y, eval_set=[(x_val, y_val)], verbose=False)
        self.model.set_params(callbacks=None)
        self.best_iteration = int(self.model.best_iteration)
        return self

    def predict(self, x) -> np.ndarray:
        return self.model.predict_proba(x)[:, 1]

    def to_cpu(self) -> None:
        self.model.set_params(device="cpu")

    def native_bytes(self) -> int:
        return len(self.model.get_booster().save_raw("json"))

    def save(self, directory: Path) -> list[Path]:
        path = directory / "model.json"
        self.model.save_model(path)
        return [path]


class LGBMModel:
    """LightGBM（CPU），验证分区早停；每 50 轮向 reporter 报告负 logloss。"""

    def __init__(self, params: dict[str, Any], seed: int):
        from lightgbm import LGBMClassifier

        p = dict(params)
        self.early = int(p.pop("early_stopping_rounds"))
        self.model = LGBMClassifier(random_state=seed, n_jobs=RF_JOBS, verbose=-1, **p)
        self.best_iteration = None

    def fit(self, x, y, x_val, y_val, reporter: Reporter = None) -> "LGBMModel":
        import lightgbm

        callbacks = [lightgbm.early_stopping(self.early, verbose=False)]
        if reporter is not None:
            def prune(env):
                if (env.iteration + 1) % 50 == 0:
                    reporter(env.iteration + 1, -float(env.evaluation_result_list[0][2]))
            callbacks.append(prune)
        self.model.fit(x, y, eval_set=[(x_val, y_val)], eval_metric="binary_logloss", callbacks=callbacks)
        self.best_iteration = int(self.model.best_iteration_)
        return self

    def predict(self, x) -> np.ndarray:
        return self.model.predict_proba(x)[:, 1]

    def to_cpu(self) -> None:
        pass

    def native_bytes(self) -> int:
        return len(self.model.booster_.model_to_string().encode("utf-8"))

    def save(self, directory: Path) -> list[Path]:
        path = directory / "model.txt"
        self.model.booster_.save_model(str(path))
        return [path]


class MLPModel:
    """PyTorch MLP：宽度 ``width`` × ``layers`` 层（BatchNorm + ReLU + Dropout），AdamW + OneCycle，
    验证损失早停（patience），恢复最佳轮次权重。不使用 pos_weight（§5.5）。CUDA 不可用时显式失败。"""

    def __init__(self, params: dict[str, Any], seed: int):
        self.p, self.seed = dict(params), seed
        self.net = None
        self.device = "cuda"
        self.best_iteration = None

    def _build(self, n_in: int):
        from torch import nn

        width, layers, dropout = int(self.p["width"]), int(self.p["layers"]), float(self.p["dropout"])
        dims = [n_in] + [max(width // (2 ** i), 32) for i in range(layers)]
        blocks: list[Any] = []
        for a, b in zip(dims[:-1], dims[1:]):
            blocks += [nn.Linear(a, b), nn.BatchNorm1d(b), nn.ReLU(), nn.Dropout(dropout)]
        return nn.Sequential(*blocks, nn.Linear(dims[-1], 1))

    def fit(self, x, y, x_val, y_val, reporter: Reporter = None) -> "MLPModel":
        import torch
        from torch import nn

        if not torch.cuda.is_available():
            raise RuntimeError("MLP requires CUDA; refusing to fall back to CPU silently")
        torch.manual_seed(self.seed)
        device = torch.device("cuda")
        self.net = self._build(x.shape[1]).to(device)
        batch, epochs, patience = int(self.p["batch_size"]), int(self.p["max_epochs"]), int(self.p["patience"])
        xt = torch.as_tensor(np.nan_to_num(x), dtype=torch.float32, device=device)
        yt = torch.as_tensor(y, dtype=torch.float32, device=device)
        xv = torch.as_tensor(np.nan_to_num(x_val), dtype=torch.float32, device=device)
        yv = torch.as_tensor(y_val, dtype=torch.float32, device=device)
        steps = (len(yt) + batch - 1) // batch
        optimizer = torch.optim.AdamW(self.net.parameters(), lr=float(self.p["lr"]),
                                      weight_decay=float(self.p["weight_decay"]))
        scheduler = torch.optim.lr_scheduler.OneCycleLR(optimizer, max_lr=float(self.p["lr"]),
                                                        total_steps=epochs * steps)
        loss_fn = nn.BCEWithLogitsLoss()
        generator = torch.Generator(device=device).manual_seed(self.seed)
        best, best_state, stale = float("inf"), None, 0
        try:
            for epoch in range(epochs):
                self.net.train()
                order = torch.randperm(len(yt), device=device, generator=generator)
                for start in range(0, len(order), batch):
                    idx = order[start:start + batch]
                    if len(idx) < 2:  # BatchNorm 需要至少 2 条
                        continue
                    optimizer.zero_grad(set_to_none=True)
                    loss_fn(self.net(xt[idx]).squeeze(1), yt[idx]).backward()
                    optimizer.step()
                    scheduler.step()
                val_loss = self._loss(xv, yv, loss_fn)
                if reporter is not None:
                    reporter(epoch + 1, -val_loss)
                if val_loss < best - 1e-6:
                    best, stale, self.best_iteration = val_loss, 0, epoch + 1
                    best_state = {k: v.detach().clone() for k, v in self.net.state_dict().items()}
                else:
                    stale += 1
                    if stale >= patience:
                        break
        finally:
            del xt, yt, xv, yv
            torch.cuda.empty_cache()
        self.net.load_state_dict(best_state)
        self.net.eval()
        return self

    def _loss(self, xv, yv, loss_fn) -> float:
        import torch

        self.net.eval()
        total = 0.0
        with torch.no_grad():
            for start in range(0, len(yv), 65_536):
                total += float(loss_fn(self.net(xv[start:start + 65_536]).squeeze(1), yv[start:start + 65_536])
                               ) * len(yv[start:start + 65_536])
        return total / len(yv)

    def predict(self, x) -> np.ndarray:
        import torch

        self.net.eval()
        out = []
        with torch.no_grad():
            for start in range(0, len(x), 65_536):
                chunk = torch.as_tensor(np.nan_to_num(x[start:start + 65_536]), dtype=torch.float32, device=self.device)
                out.append(torch.sigmoid(self.net(chunk).squeeze(1)).cpu().numpy())
        return np.concatenate(out)

    def to_cpu(self) -> None:
        self.net = self.net.to("cpu")
        self.device = "cpu"

    def _state_bytes(self) -> bytes:
        import io

        import torch

        buffer = io.BytesIO()
        torch.save(self.net.state_dict(), buffer)
        return buffer.getvalue()

    def native_bytes(self) -> int:
        return len(self._state_bytes())

    def save(self, directory: Path) -> list[Path]:
        weights, arch = directory / "model-state.pt", directory / "model-arch.json"
        weights.write_bytes(self._state_bytes())
        write_json(arch, {"params": self.p, "n_in": int(self.net[0].in_features), "best_epoch": self.best_iteration})
        return [weights, arch]

    def release(self) -> None:
        import torch

        self.net = None
        torch.cuda.empty_cache()


def build_model(name: str, params: dict[str, Any], seed: int):
    """按模型名与参数构造封装；森林与 SVM 的并行度固定为 ``RF_JOBS``。"""
    from sklearn.calibration import CalibratedClassifierCV
    from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.naive_bayes import GaussianNB
    from sklearn.svm import LinearSVC
    from sklearn.tree import DecisionTreeClassifier

    p = dict(params)
    if name == "LR":
        return SklearnModel(LogisticRegression(random_state=seed, **p))
    if name == "SVM":
        svc = LinearSVC(C=p["C"], dual=p["dual"], random_state=seed)
        return SklearnModel(CalibratedClassifierCV(svc, method=p["calibration"], cv=p["cv"], n_jobs=p["cv"]))
    if name == "GNB":
        return SklearnModel(GaussianNB(**p))
    if name == "DT":
        return SklearnModel(DecisionTreeClassifier(random_state=seed, **p))
    if name in ("RF", "ET"):
        cls = RandomForestClassifier if name == "RF" else ExtraTreesClassifier
        return SklearnModel(cls(random_state=seed, n_jobs=RF_JOBS, **p))
    if name == "XGBoost":
        return XGBModel(p, seed)
    if name == "LightGBM":
        return LGBMModel(p, seed)
    if name == "MLP":
        return MLPModel(p, seed)
    raise ValueError(f"unknown model: {name}")

class _ByteCounter:
    """只计数、不保存内容的写入目标，用于估算序列化体积而不复制大模型。"""

    def __init__(self) -> None:
        self.size = 0

    def write(self, data: Any) -> int:
        size = memoryview(data).nbytes  # 协议 5 会传入 PickleBuffer，没有 len()
        self.size += size
        return size


def model_bytes(wrapper: Any) -> int:
    if isinstance(wrapper, SklearnModel):
        counter = _ByteCounter()
        pickle.dump(wrapper.estimator, counter, protocol=pickle.HIGHEST_PROTOCOL)
        return counter.size
    return wrapper.native_bytes()


def measure_speed(wrapper: Any, x_val: np.ndarray, seed: int) -> dict[str, float]:
    """原框架 CPU 推理速度（已变换的特征矩阵，不含预处理）：单条 P50/P95 与 batch=1024 吞吐。

    只作为模型间的相对比较；§1 的延迟门槛在第 10 步用 ONNX Runtime 判定。
    """
    wrapper.to_cpu()
    rng = np.random.default_rng(seed)
    rows = rng.choice(len(x_val), size=min(LATENCY_ROWS, len(x_val)), replace=False)
    wrapper.predict(x_val[rows[:5]])  # 预热
    single = []
    for r in rows:
        start = time.perf_counter()
        wrapper.predict(x_val[r:r + 1])
        single.append((time.perf_counter() - start) * 1000)
    batch = x_val[:THROUGHPUT_BATCH]
    start = time.perf_counter()
    for _ in range(THROUGHPUT_REPEATS):
        wrapper.predict(batch)
    elapsed = time.perf_counter() - start
    return {"latency_p50_ms": float(np.percentile(single, 50)), "latency_p95_ms": float(np.percentile(single, 95)),
            "throughput_rows_s": len(batch) * THROUGHPUT_REPEATS / elapsed}

# ---------------------------------------------------------------- 数据

class Matrices:
    """按 (方案, 种子) 缓存变换后的训练/验证矩阵；预处理器只在完整训练分区上拟合。

    同一时间只保留一组矩阵，控制内存（§1.1）。``fit_rows`` 必须属于训练分区。
    """

    def __init__(self, frame: pd.DataFrame, labels: np.ndarray, split: SplitIndex, columns: list[str]):
        self.frame, self.labels, self.split, self.columns = frame, labels, split, list(columns)
        if not np.isin(split.train, np.arange(len(frame))).all():
            raise LeakageError("split indices exceed frame length")
        self._key: tuple[str, int] | None = None
        self._data: dict[str, Any] = {}

    def get(self, scheme_key: str, seed: int) -> dict[str, Any]:
        if self._key != (scheme_key, seed):
            self._data = {}
            gc.collect()
            preprocessor = build_preprocessor(SCHEME_BY_KEY[scheme_key], seed, self.columns)
            train = np.sort(self.split.train)
            x_train = preprocessor.fit_transform(self.frame.iloc[train][self.columns]).astype(np.float32, copy=False)
            x_val = preprocessor.transform(self.frame.iloc[self.split.validation][self.columns]
                                           ).astype(np.float32, copy=False)
            self._data = {"preprocessor": preprocessor, "x_train": np.ascontiguousarray(x_train),
                          "y_train": self.labels[train], "x_val": np.ascontiguousarray(x_val),
                          "y_val": self.labels[self.split.validation], "train_rows": train}
            self._key = (scheme_key, seed)
        return self._data

    def subsample(self, data: dict[str, Any], fraction: float, seed: int) -> tuple[np.ndarray, np.ndarray]:
        """森林调参用：训练分区内按标签分层抽取 ``fraction`` 的行（位置索引对应 ``x_train``）。"""
        size = int(len(data["y_train"]) * fraction)
        picked = train_sample(self.split, self.labels, size, seed)
        positions = np.searchsorted(data["train_rows"], picked)
        if not np.array_equal(data["train_rows"][positions], picked):
            raise LeakageError("subsample rows are not in the training partition")
        return data["x_train"][positions], data["y_train"][positions]

# ---------------------------------------------------------------- 单次训练

def fit_and_score(model_name: str, params: dict[str, Any], seed: int, data: dict[str, Any],
                  x_fit: np.ndarray | None = None, y_fit: np.ndarray | None = None,
                  reporter: Reporter = None, speed: bool = True) -> tuple[dict[str, Any], Any]:
    """训练一次并在完整验证分区上按 §7.3 选阈值评估；返回 (结果行, 模型封装)。

    ``x_fit``/``y_fit`` 缺省为完整训练矩阵（森林调参时传入训练分区抽样）。
    """
    x_fit = data["x_train"] if x_fit is None else x_fit
    y_fit = data["y_train"] if y_fit is None else y_fit
    start = time.perf_counter()
    wrapper = build_model(model_name, params, seed)
    wrapper.fit(x_fit, y_fit, data["x_val"], data["y_val"], reporter)
    fit_seconds = time.perf_counter() - start
    prob = wrapper.predict(data["x_val"])
    row = {"model": model_name, "seed": seed, "status": "ok", "fit_rows": int(len(y_fit)),
           "encoded_features": int(data["x_val"].shape[1]), "fit_seconds": fit_seconds,
           **evaluate(data["y_val"], prob), "best_iteration": wrapper.best_iteration,
           "params": json.dumps(params, ensure_ascii=False, sort_keys=True), "error": ""}
    if speed:
        row["model_bytes"] = model_bytes(wrapper)
        row.update(measure_speed(wrapper, data["x_val"], seed))
    return row, wrapper


def release(wrapper: Any) -> None:
    if hasattr(wrapper, "release"):
        wrapper.release()
    gc.collect()

# ---------------------------------------------------------------- 调优搜索空间（§7.2）

def suggest(model: str, trial: Any) -> dict[str, Any]:
    base = dict(SCREEN_PARAMS[model])
    if model == "XGBoost":
        base.update(max_depth=trial.suggest_int("max_depth", 6, 12),
                    learning_rate=trial.suggest_float("learning_rate", 0.02, 0.2, log=True),
                    min_child_weight=trial.suggest_float("min_child_weight", 1.0, 20.0, log=True),
                    gamma=trial.suggest_float("gamma", 0.0, 5.0),
                    subsample=trial.suggest_float("subsample", 0.6, 1.0),
                    colsample_bytree=trial.suggest_float("colsample_bytree", 0.5, 1.0))
    elif model == "LightGBM":
        base.update(num_leaves=trial.suggest_int("num_leaves", 31, 255, log=True),
                    learning_rate=trial.suggest_float("learning_rate", 0.02, 0.2, log=True),
                    min_child_samples=trial.suggest_int("min_child_samples", 20, 200, log=True),
                    reg_lambda=trial.suggest_float("reg_lambda", 0.0, 10.0))
    elif model in ("RF", "ET"):
        base.update(n_estimators=trial.suggest_int("n_estimators", 100, 250, step=50),
                    max_depth=trial.suggest_categorical("max_depth", [24, 32, 40]),
                    min_samples_leaf=trial.suggest_int("min_samples_leaf", 1, 10),
                    max_features=trial.suggest_categorical("max_features", ["sqrt", 0.3]))
    elif model == "MLP":
        base.update(width=trial.suggest_categorical("width", [256, 512, 1024]),
                    layers=trial.suggest_int("layers", 2, 4),
                    dropout=trial.suggest_float("dropout", 0.1, 0.5),
                    lr=trial.suggest_float("lr", 3e-4, 3e-3, log=True))
    else:
        raise ValueError(f"no search space for {model}")
    return base


PRUNER_WARMUP = {"XGBoost": 100, "LightGBM": 100, "MLP": 3, "RF": 0, "ET": 0}

# ---------------------------------------------------------------- 选择规则

def screen_ranking(rows: pd.DataFrame) -> list[str]:
    """初筛：按验证集 Macro-F1 降序；只统计成功的模型。"""
    ok = rows[rows["status"] == "ok"].sort_values("macro_f1", ascending=False, kind="mergesort")
    return list(dict.fromkeys(ok["model"]))


def tune_candidates(ranking: list[str]) -> list[str]:
    """§7.2：初筛前 3 名，外加 MLP 必选（若不在前 3），合计不超过 4 个。

    初筛中只有可调模型（XGBoost、LightGBM、RF、ET、MLP）才有搜索空间；不可调模型进入前 3 时顺延，
    并在结果中记录被跳过的模型。
    """
    tunable = [m for m in ranking if m in TUNE_BUDGET]
    picked = tunable[:SCREEN_TOP]
    if TUNE_MUST not in picked:
        picked.append(TUNE_MUST)
    return picked[:TUNE_MAX]


def select_final(summary: pd.DataFrame) -> dict[str, Any]:
    """§7.4 选型：FNR 标准差 ≤ 2% → 平均 FNR ≤ 5% 且平均 FPR ≤ 1.5% → Macro-F1 最高；
    与最高者差距 ≤ 0.003 时优先延迟 P95 更低、体积更小者。没有模型满足前两条时返回 ``selected=None``。"""
    checks = []
    for r in summary.itertuples():
        checks.append({"model": r.model, "fnr_std_ok": bool(r.fnr_std <= MAX_FNR_STD),
                       "rates_ok": bool(r.fnr_mean <= MAX_FNR and r.fpr_mean <= MAX_FPR),
                       "macro_f1_mean": float(r.macro_f1_mean), "latency_p95_ms": float(r.latency_p95_ms_mean),
                       "model_bytes": float(r.model_bytes_mean)})
    eligible = [c for c in checks if c["fnr_std_ok"] and c["rates_ok"]]
    result: dict[str, Any] = {
        "rule": "FNR 标准差 ≤ 2% → 平均 FNR ≤ 5% 且平均 FPR ≤ 1.5% → Macro-F1 最高；差距 ≤ 0.003 时选延迟 P95 更低、体积更小者",
        "checks": checks, "tie": TIE, "selected": None, "top_by_macro_f1": None, "tied": []}
    if not eligible:
        return result
    top = max(eligible, key=lambda c: c["macro_f1_mean"])
    tied = [c for c in eligible if top["macro_f1_mean"] - c["macro_f1_mean"] <= TIE]
    chosen = min(tied, key=lambda c: (c["latency_p95_ms"], c["model_bytes"], -c["macro_f1_mean"]))
    result.update(selected=chosen["model"], top_by_macro_f1=top["model"], tied=[c["model"] for c in tied])
    return result

# ---------------------------------------------------------------- 结果记录与报告

SUMMARY_METRICS = ("precision", "recall", "f1", "macro_f1", "accuracy", "auc", "pr_auc", "fpr", "fnr", "threshold",
                   "fit_seconds", "latency_p50_ms", "latency_p95_ms", "throughput_rows_s", "model_bytes")
TABLE_ROWS = (("precision", "Precision", True), ("recall", "Recall", True), ("f1", "F1-score", True),
              ("accuracy", "Accuracy", True), ("auc", "AUC", True), ("macro_f1", "Macro-F1", True),
              ("pr_auc", "PR-AUC", True), ("fpr", "FPR", False), ("fnr", "FNR", False))


def append_row(path: Path, row: dict[str, Any]) -> None:
    frame = pd.DataFrame([{c: row.get(c, "") for c in RUN_COLUMNS}])
    frame.to_csv(path, mode="a", header=not path.exists(), index=False, encoding="utf-8")


def read_rows(path: Path) -> pd.DataFrame:
    return pd.read_csv(path) if path.exists() else pd.DataFrame(columns=list(RUN_COLUMNS))


def paper_table(frame: pd.DataFrame, models: list[str], number: int, title_zh: str, title_en: str,
                suffix: str = "") -> str:
    """版式同 §5.3：上方中英文表题，行为指标、列为模型，保留 3 位小数，每行最优值加粗（FPR/FNR 取最小）。

    ``frame`` 以模型为索引，列名为指标名加 ``suffix``（如 ``_mean``）。附加阈值、延迟与体积行（不加粗）。
    """
    lines = [f"表 {number}  {title_zh}", f"Table {number}  {title_en}", "",
             "| 指标 | " + " | ".join(models) + " |", "|---|" + "---:|" * len(models)]
    for key, title, higher in TABLE_ROWS:
        values = frame.loc[models, f"{key}{suffix}"].astype(float)
        best = values.max() if higher else values.min()
        cells = [f"**{v:.3f}**" if np.isclose(v, best) else f"{v:.3f}" for v in values]
        lines.append(f"| {title} | " + " | ".join(cells) + " |")
    extra = (("threshold", "阈值", "{:.4f}"), ("latency_p95_ms", "单条延迟 P95（ms）", "{:.3f}"),
             ("throughput_rows_s", "batch=1024 吞吐（条/秒）", "{:,.0f}"), ("model_bytes", "模型体积（MB）", "{:.2f}"))
    for key, title, fmt in extra:
        values = frame.loc[models, f"{key}{suffix}"].astype(float)
        if key == "model_bytes":
            values = values / 1e6
        lines.append(f"| {title} | " + " | ".join(fmt.format(v) for v in values) + " |")
    return "\n".join(lines)


def plot_grouped_bars(summary: pd.DataFrame, path: Path) -> None:
    """多种子复现结果的 Precision/Recall/F1/AUC 分组柱状图（均值，误差线为种子标准差）。"""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    from .eda import GRID, INK, INK_SECONDARY, _style

    _style()
    colors = ("#2a78d6", "#eb6834", "#1baf7a", "#eda100")  # 固定分类色序，按模型顺序分配
    metrics = (("precision", "Precision"), ("recall", "Recall"), ("f1", "F1"), ("auc", "AUC"))
    models = list(summary["model"])
    width = 0.8 / max(len(models), 1)
    fig, ax = plt.subplots(figsize=(8, 4.5))
    x = np.arange(len(metrics))
    for i, model in enumerate(models):
        r = summary[summary["model"] == model].iloc[0]
        means = [r[f"{k}_mean"] for k, _ in metrics]
        stds = [r[f"{k}_std"] for k, _ in metrics]
        offset = (i - (len(models) - 1) / 2) * width
        ax.bar(x + offset, means, width * 0.92, yerr=stds, color=colors[i % len(colors)], label=model,
               error_kw={"ecolor": INK_SECONDARY, "elinewidth": 1, "capsize": 2})
        for xi, v in zip(x + offset, means):
            ax.text(xi, v + 0.004, f"{v:.3f}", ha="center", va="bottom", fontsize=7, color=INK_SECONDARY)
    ax.set_xticks(x, [t for _, t in metrics])
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("验证集指标（5 个种子均值）", color=INK_SECONDARY)
    ax.grid(axis="x", visible=False)
    ax.grid(axis="y", color=GRID)
    ax.legend(frameon=False, ncol=len(models), loc="lower center", bbox_to_anchor=(0.5, 1.0))
    ax.set_title("调优后候选模型的多种子复现结果", loc="left", fontsize=11, color=INK, pad=28)
    fig.savefig(path)
    plt.close(fig)

# ---------------------------------------------------------------- 阶段

def completed(path: Path, key: Callable[[Any], Any]) -> set:
    rows = read_rows(path)
    return {key(r) for r in rows[rows["status"] == "ok"].itertuples()}


def failures(rows: pd.DataFrame, key: tuple[str, ...] = ("model",)) -> list[dict[str, Any]]:
    """仍未成功的失败记录；续跑已补齐的旧失败行不再列出（原始行保留在逐次 CSV 中）。"""
    ok = {tuple(r) for r in rows.loc[rows["status"] == "ok", list(key)].itertuples(index=False)}
    bad = rows[(rows["status"] == "failed")]
    bad = bad[[tuple(r) not in ok for r in bad[list(key)].itertuples(index=False)]]
    return bad[[*key, "error"]].to_dict("records")


def summarize(rows: pd.DataFrame) -> pd.DataFrame:
    """按模型汇总成功行：各指标均值与标准差（总体标准差 ddof=0，单种子时为 0）。"""
    ok = rows[rows["status"] == "ok"].copy()
    ok[list(SUMMARY_METRICS)] = ok[list(SUMMARY_METRICS)].astype(float)
    grouped = ok.groupby("model", sort=False)[list(SUMMARY_METRICS)]
    out = grouped.mean().add_suffix("_mean").join(grouped.std(ddof=0).add_suffix("_std"))
    out["n"] = grouped.size()
    out["constraint_met_all"] = ok.groupby("model", sort=False)["constraint_met"].apply(
        lambda s: bool(s.astype(str).str.lower().eq("true").all()))
    return out.reset_index()


class Context:
    """一次阶段运行共享的数据：manifest、切分、`V*` 列与按方案缓存的矩阵。"""

    def __init__(self, split_dir: Path | None, feature_dir: Path | None):
        self.manifest_file, manifest = load_manifest()
        self.split_dir = Path(split_dir) if split_dir else latest_dir("split-*/split-audit.json")
        self.feature_dir = Path(feature_dir) if feature_dir else latest_dir("feature-*/feature-selection.json")
        selection = json.loads((self.feature_dir / "feature-selection.json").read_text(encoding="utf-8"))
        spec = json.loads((self.feature_dir / "feature-views.json").read_text(encoding="utf-8"))
        self.view = selection["selected_view"]
        self.columns = list(spec["views"][self.view])
        self.split = SplitIndex.load(self.split_dir / "split-d1-raw.npz")
        if spec["split_fingerprint"] != self.split.fingerprint:
            raise LeakageError("feature views were built on a different split")
        frame, self.labels = load_frame(manifest)
        self.matrices = Matrices(frame, self.labels, self.split, self.columns)

    def params(self) -> dict[str, Any]:
        return {"register_manifest": str(self.manifest_file), "split_dir": str(self.split_dir),
                "feature_dir": str(self.feature_dir), "view": self.view, "columns": self.columns,
                "split_fingerprint": self.split.fingerprint, "tree_scheme": TREE_SCHEME,
                "dense_scheme": DENSE_SCHEME, "target_fnr": TARGET_FNR}

    def data(self, model: str, seed: int) -> dict[str, Any]:
        return self.matrices.get(scheme_for(model).key, seed)


def _logger(path: Path) -> Callable[[str], None]:
    def say(message: str) -> None:
        with path.open("a", encoding="utf-8") as stream:
            stream.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {message}\n")
    return say


def _failed_row(stage: str, model: str, seed: int, exc: Exception, trial: Any = "") -> dict[str, Any]:
    return {"stage": stage, "model": model, "seed": seed, "status": "failed", "trial": trial,
            "error": f"{type(exc).__name__}: {exc}"[:500]}


def _order(models: list[str]) -> list[str]:
    """数据按方案分组执行，减少矩阵重建次数；结果仍按原模型顺序报告。"""
    return sorted(models, key=lambda m: (scheme_for(m).key, models.index(m)))

def run_screen(ctx: Context, run_dir: Path, say: Callable[[str], None], models: tuple[str, ...]) -> dict[str, Any]:
    """§7.1 初筛：每个模型以初始参数、主种子训练一次。"""
    runs_csv = run_dir / "screen-runs.csv"
    done = completed(runs_csv, lambda r: r.model)
    for model in _order(list(models)):
        if model in done:
            continue
        say(f"screen {model} start (scheme {scheme_for(model).key})")
        try:
            row, wrapper = fit_and_score(model, SCREEN_PARAMS[model], GLOBAL_SEED, ctx.data(model, GLOBAL_SEED))
            release(wrapper)
            row["stage"] = "screen"
            say(f"screen {model} macro_f1={row['macro_f1']:.4f} fnr={row['fnr']:.4f} fpr={row['fpr']:.4f} "
                f"t={row['fit_seconds']:.0f}s")
        except Exception as exc:  # 单模型失败只记录，汇总时显式标出
            row = _failed_row("screen", model, GLOBAL_SEED, exc)
            say(f"screen {model} FAILED {row['error']}")
        append_row(runs_csv, row)
    rows = read_rows(runs_csv)
    ranking = screen_ranking(rows)
    picked = tune_candidates(ranking)
    summary = summarize(rows).set_index("model")
    order = [m for m in ranking]
    selection = {"ranking": ranking, "tune_candidates": picked,
                 "skipped_untunable": [m for m in ranking[:SCREEN_TOP] if m not in TUNE_BUDGET],
                 "failed": failures(rows),
                 "rule": "初筛 Macro-F1 前 3 名（只计有搜索空间的模型）外加 MLP 必选，合计 ≤ 4 个"}
    write_json(run_dir / "screen-selection.json", selection)
    body = ["# 第 8 步初筛：9 个模型的验证集结果", "",
            f"数据：D1 原始数据完整训练分区（{len(ctx.split.train):,} 行），"
            f"完整验证分区评估；特征视图 {ctx.view}（{len(ctx.columns)} 列）；树模型用 {TREE_SCHEME}，其余用 {DENSE_SCHEME}。",
            f"阈值：验证集上 FNR ≤ {TARGET_FNR:.0%} 时 FPR 最小（§7.3）；指标均在所选阈值下计算。种子 {GLOBAL_SEED}。",
            "XGBoost、LightGBM、MLP 用验证集早停，指标偏乐观。推理速度为原框架 CPU、已变换矩阵、不含预处理，只作相对比较。",
            "", paper_table(summary, order, 6, "初筛结果（验证集，列按 Macro-F1 降序）",
                            "Screening results on the validation partition", "_mean"), "",
            f"调优候选：{', '.join(picked)}。"]
    if selection["skipped_untunable"]:
        body.append(f"前 3 名中无搜索空间而顺延的模型：{', '.join(selection['skipped_untunable'])}。")
    if selection["failed"]:
        body += ["", "失败记录："] + [f"- {f['model']}：{f['error']}" for f in selection["failed"]]
    (run_dir / "model-screening.md").write_text("\n".join(body) + "\n", encoding="utf-8")
    summary.reset_index().to_csv(run_dir / "screen-summary.csv", index=False, encoding="utf-8")
    return selection

def journal_storage(run_dir: Path, model: str):
    """Optuna journal 存储（逐试验追加，支持续跑）。默认的符号链接锁在 Windows 普通用户下需要额外特权，
    改用基于 O_EXCL 打开文件的锁。"""
    from optuna.storages import JournalStorage
    from optuna.storages.journal import JournalFileBackend, JournalFileOpenLock

    path = str(run_dir / f"optuna-{model}.journal")
    return JournalStorage(JournalFileBackend(path, lock_obj=JournalFileOpenLock(path)))


def _tune_one(ctx: Context, run_dir: Path, say: Callable[[str], None], model: str) -> None:
    """单模型 Optuna TPE 搜索（固定种子、MedianPruner）；试验写入 journal，支持续跑。"""
    import optuna
    n_trials, timeout = TUNE_BUDGET[model]
    storage = journal_storage(run_dir, model)
    study = optuna.create_study(
        study_name=model, storage=storage, direction="maximize", load_if_exists=True,
        sampler=optuna.samplers.TPESampler(seed=GLOBAL_SEED),
        pruner=optuna.pruners.MedianPruner(n_startup_trials=5, n_warmup_steps=PRUNER_WARMUP[model]))
    finished = [t for t in study.trials if t.state.is_finished()]
    remaining = n_trials - len(finished)
    if remaining <= 0:
        return
    data = ctx.data(model, GLOBAL_SEED)
    x_fit = y_fit = None
    if model in ("RF", "ET"):  # §7.2：森林搜索用 50% 训练行，最终参数再用全量重训
        x_fit, y_fit = ctx.matrices.subsample(data, FOREST_SEARCH_FRACTION, GLOBAL_SEED)
    runs_csv = run_dir / "tune-trials.csv"

    def objective(trial: Any) -> float:
        params = suggest(model, trial)

        def reporter(step: int, value: float) -> None:
            trial.report(value, step)
            if trial.should_prune():
                raise optuna.TrialPruned()

        try:
            row, wrapper = fit_and_score(model, params, GLOBAL_SEED, data, x_fit, y_fit, reporter, speed=False)
        except optuna.TrialPruned:
            append_row(runs_csv, {"stage": "tune", "model": model, "seed": GLOBAL_SEED, "status": "pruned",
                                  "trial": trial.number, "params": json.dumps(params, sort_keys=True)})
            say(f"tune {model} trial {trial.number} pruned")
            gc.collect()
            raise
        release(wrapper)
        row.update(stage="tune", trial=trial.number)
        append_row(runs_csv, row)
        say(f"tune {model} trial {trial.number} macro_f1={row['macro_f1']:.4f} fnr={row['fnr']:.4f} "
            f"fpr={row['fpr']:.4f} t={row['fit_seconds']:.0f}s")
        for key in ("fnr", "fpr", "pr_auc", "threshold"):
            trial.set_user_attr(key, float(row[key]))
        return float(row["macro_f1"])

    optuna.logging.set_verbosity(optuna.logging.WARNING)
    say(f"tune {model} start: {remaining} trials left, timeout {timeout // 60} min")
    study.optimize(objective, n_trials=remaining, timeout=timeout, catch=(Exception,), gc_after_trial=True)


def run_tune(ctx: Context, run_dir: Path, say: Callable[[str], None], screen_dir: Path) -> dict[str, Any]:
    """§7.2 调优：逐模型搜索，再以最优参数在完整训练分区上用主种子重训（含速度测量），据此排序。"""
    import optuna

    screen = json.loads((screen_dir / "screen-selection.json").read_text(encoding="utf-8"))
    models = list(screen["tune_candidates"])
    for model in _order(models):
        _tune_one(ctx, run_dir, say, model)
    best_csv = run_dir / "tune-best.csv"
    done = completed(best_csv, lambda r: r.model)
    studies: dict[str, Any] = {}
    for model in _order(models):
        storage = journal_storage(run_dir, model)
        study = optuna.load_study(study_name=model, storage=storage)
        complete = [t for t in study.trials if t.state == optuna.trial.TrialState.COMPLETE]
        studies[model] = {"trials": len(study.trials), "complete": len(complete),
                          "pruned": sum(t.state == optuna.trial.TrialState.PRUNED for t in study.trials),
                          "failed": sum(t.state == optuna.trial.TrialState.FAIL for t in study.trials)}
        if not complete:
            say(f"tune {model}: no completed trial, skipped")
            continue
        best = study.best_trial
        params = {**SCREEN_PARAMS[model], **best.params}
        studies[model].update(best_trial=best.number, best_search_macro_f1=float(best.value), params=params)
        if model in done:
            continue
        say(f"tune {model} refit best trial {best.number} on full training partition")
        try:
            row, wrapper = fit_and_score(model, params, GLOBAL_SEED, ctx.data(model, GLOBAL_SEED))
            release(wrapper)
            row["stage"] = "tune-best"
        except Exception as exc:
            row = _failed_row("tune-best", model, GLOBAL_SEED, exc)
        append_row(best_csv, row)
    rows = read_rows(best_csv)
    ranking = screen_ranking(rows)
    selection = {"candidates": models, "studies": studies, "ranking": ranking, "seed_candidates": ranking[:SEEDS_TOP],
                 "screen_dir": screen_dir.name,
                 "rule": "以最优参数在完整训练分区重训后的验证集 Macro-F1 排序，取前 3 名进入多种子复现"}
    write_json(run_dir / "tune-selection.json", selection)
    screen_summary = pd.read_csv(screen_dir / "screen-summary.csv").set_index("model")
    tuned = summarize(rows).set_index("model")
    lines = ["# 第 8 步调优：Optuna TPE 搜索结果", "",
             f"每个模型固定试验次数与时间上限（先到者为准），TPE 种子 {GLOBAL_SEED}，MedianPruner（前 5 次不剪枝）。"
             f"森林在 {FOREST_SEARCH_FRACTION:.0%} 训练行上搜索；所有模型的最优参数都在完整训练分区上用主种子重训后评估。", "",
             "| 模型 | 试验 / 完成 / 剪枝 / 失败 | 初筛 Macro-F1 | 调优后 Macro-F1 | 提升 | 调优后 FNR | 调优后 FPR | 最优参数 |",
             "|---|---|---:|---:|---:|---:|---:|---|"]
    for model in models:
        s = studies[model]
        counts = f"{s['trials']} / {s['complete']} / {s['pruned']} / {s['failed']}"
        base = float(screen_summary.loc[model, "macro_f1_mean"]) if model in screen_summary.index else float("nan")
        if model not in tuned.index:
            lines.append(f"| {model} | {counts} | {base:.4f} | — | — | — | — | 无完成试验或重训失败 |")
            continue
        t = tuned.loc[model]
        shown = {k: (round(v, 4) if isinstance(v, float) else v) for k, v in s["params"].items()
                 if k in s.get("params", {}) and k not in ("early_stopping_rounds",)}
        lines.append(f"| {model} | {counts} | {base:.4f} | {t['macro_f1_mean']:.4f} | {t['macro_f1_mean'] - base:+.4f} "
                     f"| {t['fnr_mean']:.2%} | {t['fpr_mean']:.2%} | `{json.dumps(shown, ensure_ascii=False)}` |")
    lines += ["", f"进入多种子复现：{', '.join(selection['seed_candidates'])}。"]
    (run_dir / "model-tuning.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return selection


def save_candidate(ctx: Context, run_dir: Path, model: str, params: dict[str, Any],
                   say: Callable[[str], None]) -> dict[str, Any]:
    """以主种子重训选中模型并保存候选制品（预处理器、模型、阈值、特征列）到 ``candidate/``。

    制品只供第 9～10 步使用，位于被 Git 忽略的 ``runs/``；pickle 仅用于本仓库自己生成的对象，
    交付格式由第 10 步导出为 ONNX 后另行校验。
    """
    data = ctx.data(model, GLOBAL_SEED)
    row, wrapper = fit_and_score(model, params, GLOBAL_SEED, data, speed=False)
    out = run_dir / "candidate"
    out.mkdir()
    files = wrapper.save(out)
    prep = out / "preprocessor.pkl"
    prep.write_bytes(pickle.dumps(data["preprocessor"], protocol=pickle.HIGHEST_PROTOCOL))
    files.append(prep)
    meta = {"model": model, "seed": GLOBAL_SEED, "params": params, "threshold": row["threshold"],
            "constraint_met": row["constraint_met"], "scheme": scheme_for(model).key, "view": ctx.view,
            "columns": ctx.columns, "split_fingerprint": ctx.split.fingerprint, "best_iteration": row["best_iteration"],
            "validation_metrics": {k: row[k] for k in ("macro_f1", "fnr", "fpr", "pr_auc", "auc")},
            "files": {p.name: sha256_file(p) for p in files},
            "note": "验证集阈值与指标；holdout 未读取。XGBoost/LightGBM/MLP 使用验证集早停。"}
    write_json(out / "candidate.json", meta)
    release(wrapper)
    say(f"candidate {model} saved threshold={row['threshold']:.6f} macro_f1={row['macro_f1']:.4f}")
    return meta


def run_seeds(ctx: Context, run_dir: Path, say: Callable[[str], None], tune_dir: Path) -> dict[str, Any]:
    """§7.4 多种子复现：调优后前 3 名 × 5 个种子，按选型规则选出最终 T1 模型。"""
    tune = json.loads((tune_dir / "tune-selection.json").read_text(encoding="utf-8"))
    models = list(tune["seed_candidates"])
    params = {m: tune["studies"][m]["params"] for m in models}
    runs_csv = run_dir / "seed-runs.csv"
    done = completed(runs_csv, lambda r: (r.model, int(r.seed)))
    for seed in REPRO_SEEDS:
        for model in _order(models):
            if (model, seed) in done:
                continue
            say(f"seeds {model} seed={seed} start")
            try:
                row, wrapper = fit_and_score(model, params[model], seed, ctx.data(model, seed))
                release(wrapper)
                row["stage"] = "seeds"
                say(f"seeds {model} seed={seed} macro_f1={row['macro_f1']:.4f} fnr={row['fnr']:.4f} "
                    f"fpr={row['fpr']:.4f} t={row['fit_seconds']:.0f}s")
            except Exception as exc:
                row = _failed_row("seeds", model, seed, exc)
                say(f"seeds {model} seed={seed} FAILED {row['error']}")
            append_row(runs_csv, row)
    rows = read_rows(runs_csv)
    summary = summarize(rows)
    summary = summary.set_index("model").loc[[m for m in models if m in set(summary["model"])]].reset_index()
    incomplete = [m for m in models if int(summary.set_index("model")["n"].get(m, 0)) < len(REPRO_SEEDS)]
    selection = select_final(summary[~summary["model"].isin(incomplete)])
    selection.update(models=models, incomplete=incomplete, tune_dir=tune_dir.name, params=params)
    if selection["selected"]:
        saved = run_dir / "candidate" / "candidate.json"
        if saved.exists():  # 续跑：复用已保存的候选制品，不重复训练
            selection["candidate"] = json.loads(saved.read_text(encoding="utf-8"))
            if selection["candidate"]["model"] != selection["selected"]:
                raise ValueError("existing candidate does not match the selected model")
        else:
            selection["candidate"] = save_candidate(ctx, run_dir, selection["selected"], params[selection["selected"]],
                                                    say)
    write_json(run_dir / "model-selection.json", selection)
    summary.to_csv(run_dir / "seed-summary.csv", index=False, encoding="utf-8")
    plot_grouped_bars(summary, run_dir / "model-comparison.png")
    write_comparison(run_dir, summary, selection)
    return selection


def write_comparison(run_dir: Path, summary: pd.DataFrame, selection: dict[str, Any]) -> None:
    """主对比表 ``model-comparison.md``：均值 ± 标准差（5 个种子）与选型判定。"""
    frame = summary.set_index("model")
    models = list(frame.index)
    lines = ["# 第 8 步主对比：调优后候选模型的多种子复现", "",
             f"种子 {', '.join(map(str, REPRO_SEEDS))}；每个种子重新拟合预处理器与模型，并在验证集上重新选阈值（§7.3）。"
             "表中为均值 ± 标准差（总体标准差）。", "",
             "表 7　多种子复现结果", "",
             "| 指标 | " + " | ".join(models) + " |", "|---|" + "---:|" * len(models)]
    for key, title, higher in TABLE_ROWS:
        means = frame[f"{key}_mean"].astype(float)
        best = means.max() if higher else means.min()
        cells = []
        for m in models:
            mean, std = float(frame.loc[m, f"{key}_mean"]), float(frame.loc[m, f"{key}_std"])
            text = f"{mean:.4f} ± {std:.4f}"
            cells.append(f"**{text}**" if np.isclose(mean, best) else text)
        lines.append(f"| {title} | " + " | ".join(cells) + " |")
    for key, title, fmt in (("threshold", "阈值", "{:.4f}"), ("latency_p95_ms", "单条延迟 P95（ms）", "{:.3f}"),
                            ("throughput_rows_s", "batch=1024 吞吐（条/秒）", "{:,.0f}"),
                            ("model_bytes", "模型体积（MB）", "{:.2f}"), ("fit_seconds", "训练用时（s）", "{:.0f}")):
        vals = frame[f"{key}_mean"].astype(float) / (1e6 if key == "model_bytes" else 1)
        lines.append(f"| {title} | " + " | ".join(fmt.format(v) for v in vals) + " |")
    lines += ["", "![多种子复现结果](model-comparison.png)", "", "## 选型判定（§7.4）", "",
              "| 模型 | FNR 标准差 ≤ 2% | 平均 FNR ≤ 5% 且 FPR ≤ 1.5% | Macro-F1 均值 |", "|---|---|---|---:|"]
    for c in selection["checks"]:
        lines.append(f"| {c['model']} | {'是' if c['fnr_std_ok'] else '否'} | {'是' if c['rates_ok'] else '否'} "
                     f"| {c['macro_f1_mean']:.4f} |")
    if selection["selected"]:
        lines += ["", f"选定 T1 模型：**{selection['selected']}**（Macro-F1 最高者 {selection['top_by_macro_f1']}；"
                  f"差距 ≤ {TIE} 的并列候选：{', '.join(selection['tied'])}）。"]
    else:
        lines += ["", "没有模型同时满足前两条规则，第 8 步不产生候选模型。"]
    if selection["incomplete"]:
        lines.append(f"种子未跑全、未参与选型：{', '.join(selection['incomplete'])}。")
    (run_dir / "model-comparison.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def run(stage: str, resume: Path | None = None, split_dir: Path | None = None, feature_dir: Path | None = None,
        source_dir: Path | None = None, models: tuple[str, ...] = MODELS) -> Path:
    """执行第 8 步的一个阶段。``source_dir`` 为上一阶段目录（缺省取最新）；``resume`` 续跑已有目录。"""
    if stage not in STAGES:
        raise ValueError(f"unknown stage: {stage}")
    if stage != "screen":
        pattern = {"tune": "train-screen-*/screen-selection.json", "seeds": "train-tune-*/tune-selection.json"}[stage]
        source_dir = Path(source_dir) if source_dir else latest_dir(pattern)
    ctx = Context(split_dir, feature_dir)
    params = {**ctx.params(), "stage": stage, "source_dir": str(source_dir) if source_dir else None,
              "models": list(models), "screen_params": SCREEN_PARAMS, "tune_budget": TUNE_BUDGET,
              "repro_seeds": list(REPRO_SEEDS), "rf_jobs": RF_JOBS}
    if resume:
        run_dir, run_ctx = Path(resume), None
    else:
        run_ctx = RunContext(f"train-{stage}", GLOBAL_SEED, params)
        run_dir = run_ctx.run_dir
    say = _logger(run_dir / "training.log")
    say(f"stage {stage} start view={ctx.view} columns={len(ctx.columns)} source={source_dir}")
    with keep_awake():
        if stage == "screen":
            result = run_screen(ctx, run_dir, say, models)
        elif stage == "tune":
            result = run_tune(ctx, run_dir, say, source_dir)
        else:
            result = run_seeds(ctx, run_dir, say, source_dir)
    say(f"stage {stage} done: {json.dumps({k: result.get(k) for k in ('ranking', 'tune_candidates', 'seed_candidates', 'selected') if k in result}, ensure_ascii=False)}")
    if run_ctx:
        run_ctx.finish()
    else:
        RunContext.checksum_dir(run_dir)
    return run_dir
