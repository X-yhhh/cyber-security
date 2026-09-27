"""第 8b 步：T2 多分类（D1 子集，10 类 ``attack_cat``）。

计划 §7.5：LightGBM、XGBoost 为主模型，RF、MLP 为对照。类别不平衡用平衡类权重（样本权重 n / (k·n_c)）处理；
对训练分区中少于 ``SMOTE_TARGET`` 条的小类（Analysis、Backdoor、Shellcode、Worms），比较"只用类权重"与
"类权重 + SMOTE 到 5,000 条"两种做法。不做超参搜索：XGBoost、RF、MLP 复用 T1 调优参数，LightGBM 复用
T1 初筛参数（T1 未调优 LightGBM）。

数据：D1 子集官方训练文件，按第 5 步 ``split-d1-subset.npz`` 分为训练/验证；42 个预测特征（V0，与子集列同名）。
树模型用 P1，MLP 用 P7；预处理器只在真实训练行上拟合，SMOTE 只作用于训练行。官方测试文件是 T2 的锁定
holdout，本步骤不读取，锁定评估留给第 9 步。XGBoost、LightGBM、MLP 用验证分区早停（未加权 mlogloss），
验证集指标偏乐观。T2 只作研判参考输出，不驱动任何自动处置。
"""

from __future__ import annotations

import gc
import json
import pickle
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from . import GLOBAL_SEED
from .datasets import load_cached, load_manifest
from .features import V0_FEATURES, categorical_features, numeric_features
from .guard import LeakageError, SplitIndex
from .preprocess import RF_JOBS, SCHEME_BY_KEY, build_preprocessor, latest_dir, signed_log1p
from .runtime import RunContext, keep_awake, sha256_file, write_json

TRAIN_CACHE = "d1_subset_train.parquet"
HOLDOUT_CACHE = "d1_subset_test.parquet"  # 锁定 holdout：本模块不得读取
CLASSES = ("Normal", "Analysis", "Backdoor", "DoS", "Exploits", "Fuzzers", "Generic", "Reconnaissance",
           "Shellcode", "Worms")
MODELS = ("LightGBM", "XGBoost", "RF", "MLP")
TREE_MODELS = ("LightGBM", "XGBoost", "RF")
VARIANTS = ("cw", "cw_smote")
VARIANT_LABEL = {"cw": "类权重", "cw_smote": "类权重 + SMOTE"}
SMOTE_TARGET, SMOTE_NEIGHBORS = 5000, 5
TIE = 0.003
T1_TUNE_DIR = "train-tune-*/tune-selection.json"
T1_SCREEN_LIGHTGBM = {"n_estimators": 3000, "learning_rate": 0.05, "num_leaves": 127, "min_child_samples": 50,
                      "colsample_bytree": 0.8, "subsample": 0.8, "subsample_freq": 1, "reg_lambda": 0.0,
                      "early_stopping_rounds": 100}
RUN_COLUMNS = ("model", "variant", "status", "fit_rows", "synthetic_rows", "encoded_features", "fit_seconds",
               "best_iteration", "macro_f1", "weighted_f1", "balanced_accuracy", "accuracy", "macro_precision",
               "macro_recall", "min_class_recall", "params", "error")


class ClassContractError(ValueError):
    """``attack_cat`` 出现契约外的类别。"""


def encode_classes(values: pd.Series) -> np.ndarray:
    """按固定顺序 ``CLASSES`` 编码；出现未知类别即终止，不静默归类。"""
    mapping = {name: i for i, name in enumerate(CLASSES)}
    codes = values.astype("string").map(mapping)
    if codes.isna().any():
        unknown = sorted(set(values.astype("string")[codes.isna()].dropna()))
        raise ClassContractError(f"unknown attack_cat values: {unknown}")
    return codes.to_numpy(dtype=np.int64)


def balanced_weights(y: np.ndarray, n_classes: int = len(CLASSES)) -> np.ndarray:
    """平衡类权重 n / (k·n_c)，按样本展开；每个出现的类别权重和相等。"""
    counts = np.bincount(y, minlength=n_classes).astype("float64")
    present = int((counts > 0).sum())
    per_class = len(y) / (present * np.maximum(counts, 1.0))
    return per_class[y].astype(np.float32)


def inverse_signed_log1p(values: np.ndarray) -> np.ndarray:
    return np.sign(values) * np.expm1(np.abs(values))

# ---------------------------------------------------------------- SMOTE（只作用于训练行）

def smote_augment(frame: pd.DataFrame, y: np.ndarray, seed: int, target: int = SMOTE_TARGET
                  ) -> tuple[pd.DataFrame, np.ndarray]:
    """对训练行中少于 ``target`` 条的类别用 SMOTE-NC 合成到 ``target`` 条，返回只含合成行的 (特征, 标签)。

    合成在原始特征空间进行：数值列先做 signed log1p（避免字节、速率等长尾列主导近邻距离），
    类别列（proto/service/state）按名义变量取近邻众数；合成后逆变换回原单位，原为整数的列四舍五入。
    调用方必须只传入训练分区的行；预处理器仍只在真实训练行上拟合，再变换合成行。
    """
    from imblearn.over_sampling import SMOTENC

    counts = np.bincount(y, minlength=len(CLASSES))
    strategy = {c: target for c in range(len(CLASSES)) if 0 < counts[c] < target}
    if not strategy:
        return frame.iloc[:0].copy(), y[:0]
    too_small = [CLASSES[c] for c in strategy if counts[c] <= SMOTE_NEIGHBORS]
    if too_small:
        raise ValueError(f"classes too small for SMOTE k={SMOTE_NEIGHBORS}: {too_small}")
    numeric = numeric_features(list(frame.columns))
    categorical = categorical_features(list(frame.columns))
    if frame[numeric].isna().any().any():
        raise ValueError("SMOTE input has missing numeric values; refusing to impute silently")
    work = pd.concat([pd.DataFrame(signed_log1p(frame[numeric].to_numpy(dtype="float64")), columns=numeric,
                                   index=frame.index), frame[categorical].astype("string").astype(object)], axis=1)
    sampler = SMOTENC(categorical_features=[work.columns.get_loc(c) for c in categorical],
                      sampling_strategy=strategy, k_neighbors=SMOTE_NEIGHBORS, random_state=seed)
    x_res, y_res = sampler.fit_resample(work, y)
    synthetic = pd.DataFrame(x_res).iloc[len(work):].reset_index(drop=True)
    synthetic.columns = work.columns
    out = pd.DataFrame(index=synthetic.index)
    for col in frame.columns:
        if col in categorical:
            out[col] = synthetic[col].astype("string")
        else:
            values = inverse_signed_log1p(synthetic[col].to_numpy(dtype="float64"))
            if pd.api.types.is_integer_dtype(frame[col].dtype):
                values = np.rint(values)
            out[col] = values.astype(frame[col].dtype if pd.api.types.is_integer_dtype(frame[col].dtype)
                                      else "float64")
    return out[list(frame.columns)], np.asarray(y_res)[len(work):].astype(np.int64)

# ---------------------------------------------------------------- 模型封装
# 统一接口：fit(x, y, w, x_val, y_val) → self；predict(x) → (n, 10) 概率；save(dir) → 文件列表。
# 训练损失按样本权重加权；早停看验证分区的未加权 mlogloss。

class LGBMMulti:
    def __init__(self, params: dict[str, Any], seed: int):
        from lightgbm import LGBMClassifier

        p = dict(params)
        self.early = int(p.pop("early_stopping_rounds"))
        self.model = LGBMClassifier(objective="multiclass", num_class=len(CLASSES), random_state=seed,
                                    n_jobs=RF_JOBS, verbose=-1, **p)
        self.best_iteration = None

    def fit(self, x, y, w, x_val, y_val) -> "LGBMMulti":
        import lightgbm

        self.model.fit(x, y, sample_weight=w, eval_set=[(x_val, y_val)], eval_metric="multi_logloss",
                       callbacks=[lightgbm.early_stopping(self.early, verbose=False)])
        self.best_iteration = int(self.model.best_iteration_)
        return self

    def predict(self, x) -> np.ndarray:
        return self.model.predict_proba(x)

    def save(self, directory: Path) -> list[Path]:
        path = directory / "model.txt"
        self.model.booster_.save_model(str(path))
        return [path]


class XGBMulti:
    def __init__(self, params: dict[str, Any], seed: int):
        from xgboost import XGBClassifier

        p = dict(params)
        early = int(p.pop("early_stopping_rounds"))
        self.model = XGBClassifier(objective="multi:softprob", num_class=len(CLASSES), tree_method="hist",
                                   device="cuda", eval_metric="mlogloss", random_state=seed, n_jobs=RF_JOBS,
                                   early_stopping_rounds=early, **p)
        self.best_iteration = None

    def fit(self, x, y, w, x_val, y_val) -> "XGBMulti":
        self.model.fit(x, y, sample_weight=w, eval_set=[(x_val, y_val)], verbose=False)
        self.best_iteration = int(self.model.best_iteration)
        return self

    def predict(self, x) -> np.ndarray:
        return self.model.predict_proba(x)

    def save(self, directory: Path) -> list[Path]:
        path = directory / "model.json"
        self.model.save_model(path)
        return [path]


class RFMulti:
    def __init__(self, params: dict[str, Any], seed: int):
        from sklearn.ensemble import RandomForestClassifier

        self.model = RandomForestClassifier(random_state=seed, n_jobs=RF_JOBS, **params)
        self.best_iteration = None

    def fit(self, x, y, w, x_val, y_val) -> "RFMulti":
        self.model.fit(x, y, sample_weight=w)
        return self

    def predict(self, x) -> np.ndarray:
        return self.model.predict_proba(x)

    def save(self, directory: Path) -> list[Path]:
        path = directory / "model.pkl"
        path.write_bytes(pickle.dumps(self.model, protocol=pickle.HIGHEST_PROTOCOL))
        return [path]

class MLPMulti:
    """PyTorch MLP（结构同 T1 ``train.MLPModel``），10 类输出，样本加权交叉熵；验证分区未加权交叉熵早停。
    CUDA 不可用时显式失败。"""

    def __init__(self, params: dict[str, Any], seed: int):
        self.p, self.seed = dict(params), seed
        self.net = None
        self.best_iteration = None

    def _build(self, n_in: int):
        from torch import nn

        width, layers, dropout = int(self.p["width"]), int(self.p["layers"]), float(self.p["dropout"])
        dims = [n_in] + [max(width // (2 ** i), 32) for i in range(layers)]
        blocks: list[Any] = []
        for a, b in zip(dims[:-1], dims[1:]):
            blocks += [nn.Linear(a, b), nn.BatchNorm1d(b), nn.ReLU(), nn.Dropout(dropout)]
        return nn.Sequential(*blocks, nn.Linear(dims[-1], len(CLASSES)))

    def fit(self, x, y, w, x_val, y_val) -> "MLPMulti":
        import torch
        from torch.nn import functional as F

        if not torch.cuda.is_available():
            raise RuntimeError("MLP requires CUDA; refusing to fall back to CPU silently")
        torch.manual_seed(self.seed)
        device = torch.device("cuda")
        self.net = self._build(x.shape[1]).to(device)
        batch, epochs, patience = int(self.p["batch_size"]), int(self.p["max_epochs"]), int(self.p["patience"])
        xt = torch.as_tensor(np.nan_to_num(x), dtype=torch.float32, device=device)
        yt = torch.as_tensor(y, dtype=torch.long, device=device)
        wt = torch.as_tensor(w, dtype=torch.float32, device=device)
        xv = torch.as_tensor(np.nan_to_num(x_val), dtype=torch.float32, device=device)
        yv = torch.as_tensor(y_val, dtype=torch.long, device=device)
        steps = (len(yt) + batch - 1) // batch
        optimizer = torch.optim.AdamW(self.net.parameters(), lr=float(self.p["lr"]),
                                      weight_decay=float(self.p["weight_decay"]))
        scheduler = torch.optim.lr_scheduler.OneCycleLR(optimizer, max_lr=float(self.p["lr"]),
                                                        total_steps=epochs * steps)
        generator = torch.Generator(device=device).manual_seed(self.seed)
        best, best_state, stale = float("inf"), None, 0
        try:
            for epoch in range(epochs):
                self.net.train()
                order = torch.randperm(len(yt), device=device, generator=generator)
                for start in range(0, len(order), batch):
                    idx = order[start:start + batch]
                    if len(idx) >= 2:  # BatchNorm 需要至少 2 条
                        optimizer.zero_grad(set_to_none=True)
                        loss = F.cross_entropy(self.net(xt[idx]), yt[idx], reduction="none")
                        (loss * wt[idx]).sum().div(wt[idx].sum()).backward()
                        optimizer.step()
                    scheduler.step()
                self.net.eval()
                with torch.no_grad():
                    val_loss = float(F.cross_entropy(self.net(xv), yv))
                if val_loss < best - 1e-6:
                    best, stale, self.best_iteration = val_loss, 0, epoch + 1
                    best_state = {k: v.detach().clone() for k, v in self.net.state_dict().items()}
                else:
                    stale += 1
                    if stale >= patience:
                        break
        finally:
            del xt, yt, wt, xv, yv
            torch.cuda.empty_cache()
        self.net.load_state_dict(best_state)
        self.net.eval()
        return self

    def predict(self, x) -> np.ndarray:
        import torch

        out = []
        with torch.no_grad():
            for start in range(0, len(x), 65_536):
                chunk = torch.as_tensor(np.nan_to_num(x[start:start + 65_536]), dtype=torch.float32, device="cuda")
                out.append(torch.softmax(self.net(chunk), dim=1).cpu().numpy())
        return np.concatenate(out)

    def save(self, directory: Path) -> list[Path]:
        import torch

        weights, arch = directory / "model-state.pt", directory / "model-arch.json"
        torch.save(self.net.state_dict(), weights)
        write_json(arch, {"params": self.p, "n_in": int(self.net[0].in_features), "n_out": len(CLASSES),
                          "best_epoch": self.best_iteration})
        return [weights, arch]

    def release(self) -> None:
        import torch

        self.net = None
        torch.cuda.empty_cache()


def build_model(name: str, params: dict[str, Any], seed: int):
    cls = {"LightGBM": LGBMMulti, "XGBoost": XGBMulti, "RF": RFMulti, "MLP": MLPMulti}.get(name)
    if cls is None:
        raise ValueError(f"unknown model: {name}")
    return cls(params, seed)


def scheme_for(model: str):
    return SCHEME_BY_KEY["P1" if model in TREE_MODELS else "P7"]

# ---------------------------------------------------------------- 指标与参数

def multiclass_metrics(y: np.ndarray, prob: np.ndarray) -> tuple[dict[str, float], pd.DataFrame, np.ndarray]:
    """按 argmax 判定；返回 (汇总指标, 每类 precision/recall/F1/support, 10×10 混淆矩阵[真实, 预测])。"""
    from sklearn.metrics import accuracy_score, balanced_accuracy_score, confusion_matrix, precision_recall_fscore_support

    labels = list(range(len(CLASSES)))
    pred = prob.argmax(axis=1)
    precision, recall, f1, support = precision_recall_fscore_support(y, pred, labels=labels, zero_division=0)
    per_class = pd.DataFrame({"class": CLASSES, "precision": precision, "recall": recall, "f1": f1,
                              "support": support.astype(int)})
    present = support > 0
    summary = {
        "macro_f1": float(f1[present].mean()),
        "weighted_f1": float(np.average(f1, weights=support)),
        "balanced_accuracy": float(balanced_accuracy_score(y, pred)),
        "accuracy": float(accuracy_score(y, pred)),
        "macro_precision": float(precision[present].mean()),
        "macro_recall": float(recall[present].mean()),
        "min_class_recall": float(recall[present].min()),
    }
    return summary, per_class, confusion_matrix(y, pred, labels=labels)


def model_params(tune_dir: Path) -> dict[str, dict[str, Any]]:
    """复用 T1 参数：XGBoost/RF/MLP 取调优结果；LightGBM 未在 T1 调优，取初筛参数。"""
    tune = json.loads((Path(tune_dir) / "tune-selection.json").read_text(encoding="utf-8"))
    params = {"LightGBM": dict(T1_SCREEN_LIGHTGBM)}
    for model in ("XGBoost", "RF", "MLP"):
        study = tune["studies"].get(model) or {}
        if "params" not in study:
            raise ValueError(f"T1 tuning result lacks params for {model}")
        params[model] = dict(study["params"])
    return params


def select_best(rows: pd.DataFrame, tie: float = TIE) -> dict[str, Any]:
    """在验证集上按 Macro-F1 选 (模型, 做法)；与最高者差距 ≤ ``tie`` 时优先不用 SMOTE，再按 Balanced Accuracy。"""
    ok = rows[rows["status"] == "ok"]
    if ok.empty:
        return {"selected": None}
    top = ok.loc[ok["macro_f1"].astype(float).idxmax()]
    tied = ok[float(top["macro_f1"]) - ok["macro_f1"].astype(float) <= tie]
    chosen = tied.assign(_smote=(tied["variant"] == "cw_smote").astype(int)).sort_values(
        ["_smote", "balanced_accuracy"], ascending=[True, False], kind="mergesort").iloc[0]
    return {"selected": {"model": chosen["model"], "variant": chosen["variant"]},
            "top_by_macro_f1": {"model": top["model"], "variant": top["variant"]},
            "tied": [{"model": r.model, "variant": r.variant} for r in tied.itertuples()],
            "rule": f"验证集 Macro-F1 最高；差距 ≤ {tie} 时优先不用 SMOTE，再按 Balanced Accuracy"}

# ---------------------------------------------------------------- 数据

class SubsetData:
    """D1 子集官方训练文件与第 5 步切分；只读取训练文件，不打开官方测试文件（锁定 holdout）。

    ``split-d1-subset.npz`` 的 SHA-256 必须与切分审计一致，训练/验证行不得重叠或越界。
    按做法缓存变换后的矩阵：预处理器只在真实训练行上拟合，SMOTE 合成行只追加到训练矩阵。
    """

    def __init__(self, split_dir: Path | None = None):
        self.manifest_file, manifest = load_manifest()
        self.split_dir = Path(split_dir) if split_dir else latest_dir("split-*/split-audit.json")
        audit = json.loads((self.split_dir / "split-audit.json").read_text(encoding="utf-8"))
        npz = self.split_dir / "split-d1-subset.npz"
        if sha256_file(npz) != audit["split-d1-subset.npz"]["sha256"]:
            raise LeakageError("split-d1-subset.npz does not match the split audit")
        with np.load(npz) as parts:
            self.train_rows, self.val_rows = np.sort(parts["train"]), np.sort(parts["validation"])
        frame = load_cached(TRAIN_CACHE, manifest)
        if np.intersect1d(self.train_rows, self.val_rows).size:
            raise LeakageError("subset train and validation rows overlap")
        if max(self.train_rows.max(), self.val_rows.max()) >= len(frame):
            raise LeakageError("subset split indices exceed the official training file")
        self.columns = list(V0_FEATURES)
        self.features = frame[self.columns]
        self.labels = encode_classes(frame["attack_cat"])
        self.fingerprint = sha256_file(npz)
        self._cache: dict[tuple[str, str], dict[str, Any]] = {}

    def params(self) -> dict[str, Any]:
        return {"register_manifest": str(self.manifest_file), "split_dir": str(self.split_dir),
                "split_d1_subset_sha256": self.fingerprint, "columns": self.columns, "classes": list(CLASSES),
                "train_rows": int(len(self.train_rows)), "validation_rows": int(len(self.val_rows)),
                "holdout": f"{HOLDOUT_CACHE}（未读取）"}

    def data(self, scheme_key: str, variant: str, seed: int = GLOBAL_SEED) -> dict[str, Any]:
        key = (scheme_key, variant)
        if key not in self._cache:
            self._cache.clear()
            gc.collect()
            real = self.features.iloc[self.train_rows]
            y_real = self.labels[self.train_rows]
            preprocessor = build_preprocessor(SCHEME_BY_KEY[scheme_key], seed, self.columns)
            x_train = preprocessor.fit_transform(real).astype(np.float32, copy=False)
            y_train, synthetic_rows = y_real, 0
            if variant == "cw_smote":
                synth, y_synth = smote_augment(real, y_real, seed)
                if len(y_synth):
                    x_train = np.vstack([x_train, preprocessor.transform(synth).astype(np.float32, copy=False)])
                    y_train = np.concatenate([y_real, y_synth])
                    synthetic_rows = int(len(y_synth))
            elif variant != "cw":
                raise ValueError(f"unknown variant: {variant}")
            x_val = preprocessor.transform(self.features.iloc[self.val_rows]).astype(np.float32, copy=False)
            self._cache[key] = {"preprocessor": preprocessor, "x_train": np.ascontiguousarray(x_train),
                                "y_train": y_train, "w_train": balanced_weights(y_train),
                                "x_val": np.ascontiguousarray(x_val), "y_val": self.labels[self.val_rows],
                                "synthetic_rows": synthetic_rows}
        return self._cache[key]

# ---------------------------------------------------------------- 运行

def fit_and_score(model: str, params: dict[str, Any], data: dict[str, Any], seed: int = GLOBAL_SEED
                  ) -> tuple[dict[str, Any], pd.DataFrame, np.ndarray, Any]:
    """训练一次并在验证分区评估；返回 (结果行, 每类指标, 混淆矩阵, 模型封装)。"""
    start = time.perf_counter()
    wrapper = build_model(model, params, seed)
    wrapper.fit(data["x_train"], data["y_train"], data["w_train"], data["x_val"], data["y_val"])
    fit_seconds = time.perf_counter() - start
    summary, per_class, matrix = multiclass_metrics(data["y_val"], wrapper.predict(data["x_val"]))
    row = {"model": model, "status": "ok", "fit_rows": int(len(data["y_train"])),
           "synthetic_rows": data["synthetic_rows"], "encoded_features": int(data["x_val"].shape[1]),
           "fit_seconds": fit_seconds, "best_iteration": wrapper.best_iteration, **summary,
           "params": json.dumps(params, ensure_ascii=False, sort_keys=True), "error": ""}
    return row, per_class, matrix, wrapper


def release(wrapper: Any) -> None:
    if hasattr(wrapper, "release"):
        wrapper.release()
    gc.collect()


def append_row(path: Path, row: dict[str, Any]) -> None:
    frame = pd.DataFrame([{c: row.get(c, "") for c in RUN_COLUMNS}])
    frame.to_csv(path, mode="a", header=not path.exists(), index=False, encoding="utf-8")


def read_rows(path: Path) -> pd.DataFrame:
    return pd.read_csv(path) if path.exists() else pd.DataFrame(columns=list(RUN_COLUMNS))


def latest_rows(rows: pd.DataFrame) -> pd.DataFrame:
    """每个 (模型, 做法) 保留成功行；从未成功的保留最后一次失败，便于报告。"""
    ok = rows[rows["status"] == "ok"].drop_duplicates(["model", "variant"], keep="last")
    done = set(zip(ok["model"], ok["variant"]))
    bad = rows[rows["status"] != "ok"]
    bad = bad[[(m, v) not in done for m, v in zip(bad["model"], bad["variant"])]]
    return pd.concat([ok, bad.drop_duplicates(["model", "variant"], keep="last")], ignore_index=True)


def _logger(path: Path):
    def say(message: str) -> None:
        with path.open("a", encoding="utf-8") as stream:
            stream.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {message}\n")
    return say


def save_candidate(data: SubsetData, run_dir: Path, model: str, variant: str, params: dict[str, Any], say
                   ) -> dict[str, Any]:
    """以主种子重训选中组合并保存到 ``candidate/``（模型、预处理器、类别映射、特征列、文件 SHA-256）。

    制品位于被 Git 忽略的 ``runs/``，只供第 9 步锁定评估；pickle 仅用于本仓库自己生成的对象。
    """
    prepared = data.data(scheme_for(model).key, variant)
    row, _, _, wrapper = fit_and_score(model, params, prepared)
    out = run_dir / "candidate"
    out.mkdir()
    files = wrapper.save(out)
    prep = out / "preprocessor.pkl"
    prep.write_bytes(pickle.dumps(prepared["preprocessor"], protocol=pickle.HIGHEST_PROTOCOL))
    files.append(prep)
    meta = {"task": "multiclass_attack_category", "model": model, "variant": variant, "seed": GLOBAL_SEED,
            "params": params, "scheme": scheme_for(model).key, "columns": data.columns,
            "label_mapping": {i: name for i, name in enumerate(CLASSES)}, "decision": "argmax",
            "split_d1_subset_sha256": data.fingerprint, "best_iteration": row["best_iteration"],
            "validation_metrics": {k: row[k] for k in ("macro_f1", "weighted_f1", "balanced_accuracy",
                                                       "min_class_recall")},
            "files": {p.name: sha256_file(p) for p in files},
            "note": "验证集指标；官方测试文件未读取。只作研判参考输出，不驱动自动处置。"}
    write_json(out / "candidate.json", meta)
    release(wrapper)
    say(f"candidate {model}/{variant} saved macro_f1={row['macro_f1']:.4f}")
    return meta

def run(resume: Path | None = None, split_dir: Path | None = None, tune_dir: Path | None = None,
        models: tuple[str, ...] = MODELS, variants: tuple[str, ...] = VARIANTS) -> Path:
    """执行第 8b 步：模型 × 做法逐一训练并在验证分区评估，选出组合并保存候选制品。``resume`` 续跑已有目录。"""
    unknown = sorted(set(models) - set(MODELS)) + sorted(set(variants) - set(VARIANTS))
    if unknown:
        raise ValueError(f"unknown models/variants: {unknown}")
    tune_dir = Path(tune_dir) if tune_dir else latest_dir(T1_TUNE_DIR)
    params = model_params(tune_dir)
    data = SubsetData(split_dir)
    run_params = {**data.params(), "t1_tune_dir": str(tune_dir), "models": list(models), "variants": list(variants),
                  "model_params": params, "smote_target": SMOTE_TARGET, "smote_k": SMOTE_NEIGHBORS,
                  "class_weight": "balanced (n / (k·n_c))", "rf_jobs": RF_JOBS}
    if resume:
        run_dir, run_ctx = Path(resume), None
    else:
        run_ctx = RunContext("train-multiclass", GLOBAL_SEED, run_params)
        run_dir = run_ctx.run_dir
    say = _logger(run_dir / "training.log")
    runs_csv = run_dir / "multiclass-runs.csv"
    done = set(zip(*[read_rows(runs_csv).query("status == 'ok'")[c] for c in ("model", "variant")]))
    say(f"multiclass start models={list(models)} variants={list(variants)} tune_dir={tune_dir.name}")
    with keep_awake():
        # 按 (方案, 做法) 分组执行，减少预处理与 SMOTE 的重复计算
        for model, variant in sorted(((m, v) for m in models for v in variants),
                                     key=lambda mv: (scheme_for(mv[0]).key, mv[1], models.index(mv[0]))):
            if (model, variant) in done:
                continue
            say(f"{model}/{variant} start (scheme {scheme_for(model).key})")
            try:
                row, per_class, matrix, wrapper = fit_and_score(model, params[model],
                                                                data.data(scheme_for(model).key, variant))
                release(wrapper)
                per_class.to_csv(run_dir / f"per-class-{model}-{variant}.csv", index=False, encoding="utf-8")
                pd.DataFrame(matrix, index=CLASSES, columns=CLASSES).to_csv(
                    run_dir / f"confusion-{model}-{variant}.csv", encoding="utf-8")
                say(f"{model}/{variant} macro_f1={row['macro_f1']:.4f} bal_acc={row['balanced_accuracy']:.4f} "
                    f"t={row['fit_seconds']:.0f}s")
            except Exception as exc:  # 单个组合失败只记录，报告中显式标出
                row = {"model": model, "status": "failed", "error": f"{type(exc).__name__}: {exc}"[:500]}
                say(f"{model}/{variant} FAILED {row['error']}")
            row["variant"] = variant
            append_row(runs_csv, row)
        rows = latest_rows(read_rows(runs_csv))
        selection = select_best(rows)
        selection.update(tune_dir=tune_dir.name, model_params=params,
                         failed=rows[rows["status"] != "ok"][["model", "variant", "error"]].to_dict("records"))
        if selection["selected"]:
            model, variant = selection["selected"]["model"], selection["selected"]["variant"]
            saved = run_dir / "candidate" / "candidate.json"
            if saved.exists():  # 续跑：复用已保存的候选制品
                selection["candidate"] = json.loads(saved.read_text(encoding="utf-8"))
                if (selection["candidate"]["model"], selection["candidate"]["variant"]) != (model, variant):
                    raise ValueError("existing candidate does not match the selected combination")
            else:
                selection["candidate"] = save_candidate(data, run_dir, model, variant, params[model], say)
        write_json(run_dir / "multiclass-selection.json", selection)
        write_report(run_dir, rows, selection, data)
    say(f"multiclass done: selected={selection['selected']}")
    if run_ctx:
        run_ctx.finish()
    else:
        RunContext.checksum_dir(run_dir)
    return run_dir

# ---------------------------------------------------------------- 报告

REPORT_METRICS = (("macro_f1", "Macro-F1"), ("weighted_f1", "Weighted-F1"), ("balanced_accuracy", "Balanced Accuracy"),
                  ("accuracy", "Accuracy"), ("macro_precision", "Macro-Precision"), ("macro_recall", "Macro-Recall"),
                  ("min_class_recall", "最小类召回率"))


def _label(model: str, variant: str) -> str:
    return f"{model}（{VARIANT_LABEL[variant]}）"


def plot_confusion(matrix: np.ndarray, path: Path, title: str) -> None:
    """按真实类别归一化的混淆矩阵热力图（格内为行百分比）。"""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.colors import LinearSegmentedColormap

    from .eda import INK, INK_SECONDARY, _style

    _style()
    share = matrix / np.maximum(matrix.sum(axis=1, keepdims=True), 1)
    cmap = LinearSegmentedColormap.from_list("blues", ["#f7f6f2", "#2a78d6", "#104281"])
    fig, ax = plt.subplots(figsize=(8, 7))
    ax.imshow(share, cmap=cmap, vmin=0, vmax=1)
    ax.grid(False)
    for i in range(len(CLASSES)):
        for j in range(len(CLASSES)):
            if matrix[i, j]:
                ax.text(j, i, f"{share[i, j]:.0%}" if share[i, j] >= 0.005 else "<1%", ha="center", va="center",
                        fontsize=7, color="white" if share[i, j] > 0.55 else INK)
    ax.set_xticks(range(len(CLASSES)), CLASSES, rotation=45, ha="right")
    ax.set_yticks(range(len(CLASSES)), CLASSES)
    ax.set_xlabel("预测类别", color=INK_SECONDARY)
    ax.set_ylabel("真实类别", color=INK_SECONDARY)
    ax.set_title(title, loc="left", fontsize=11, color=INK)
    fig.savefig(path)
    plt.close(fig)


def write_report(run_dir: Path, rows: pd.DataFrame, selection: dict[str, Any], data: SubsetData) -> None:
    """``multiclass-report.md``：汇总表、每类召回率、SMOTE 对比、选型与混淆矩阵。"""
    ok = rows[rows["status"] == "ok"].copy()
    ok["label"] = [_label(m, v) for m, v in zip(ok["model"], ok["variant"])]
    ok = ok.sort_values("macro_f1", ascending=False, kind="mergesort")
    labels = list(ok["label"])
    counts = pd.Series(data.labels[data.train_rows]).value_counts().reindex(range(len(CLASSES)), fill_value=0)
    lines = ["# 第 8b 步：T2 多分类（D1 子集，10 类 attack_cat）", "",
             f"数据：官方训练文件，训练分区 {len(data.train_rows):,} 行、验证分区 {len(data.val_rows):,} 行；"
             f"V0 的 {len(data.columns)} 个特征；树模型用 P1，MLP 用 P7。官方测试文件（锁定 holdout）未读取。",
             "类别不平衡用平衡类权重；SMOTE 做法把训练分区中少于 "
             f"{SMOTE_TARGET:,} 条的类别用 SMOTE-NC 合成到 {SMOTE_TARGET:,} 条（只作用于训练行，预处理器只在真实行上拟合）。",
             "不做超参搜索：XGBoost/RF/MLP 复用 T1 调优参数，LightGBM 复用 T1 初筛参数。判定取 argmax。"
             "XGBoost、LightGBM、MLP 用验证分区早停，指标偏乐观。", "",
             "训练分区类别分布：" + "，".join(f"{CLASSES[i]} {int(counts[i]):,}" for i in range(len(CLASSES))) + "。", ""]
    if not ok.empty:
        lines += ["表 8　T2 多分类验证集结果（列按 Macro-F1 降序）", "",
                  "| 指标 | " + " | ".join(labels) + " |", "|---|" + "---:|" * len(labels)]
        for key, title in REPORT_METRICS:
            values = ok[key].astype(float)
            cells = [f"**{v:.3f}**" if np.isclose(v, values.max()) else f"{v:.3f}" for v in values]
            lines.append(f"| {title} | " + " | ".join(cells) + " |")
        lines.append("| 训练用时（s） | " + " | ".join(f"{v:.0f}" for v in ok["fit_seconds"].astype(float)) + " |")
        lines += ["", "表 9　每类召回率（验证集）", "", "| 类别 | 验证行数 | " + " | ".join(labels) + " |",
                  "|---|---:|" + "---:|" * len(labels)]
        per_class = {r.label: pd.read_csv(run_dir / f"per-class-{r.model}-{r.variant}.csv").set_index("class")
                     for r in ok.itertuples()}
        for name in CLASSES:
            recalls = [float(per_class[l].loc[name, "recall"]) for l in labels]
            support = int(per_class[labels[0]].loc[name, "support"])
            best = max(recalls)
            lines.append(f"| {name} | {support:,} | " + " | ".join(
                f"**{v:.3f}**" if np.isclose(v, best) else f"{v:.3f}" for v in recalls) + " |")
        lines += ["", "SMOTE 对比（类权重 + SMOTE 减 只用类权重）：", "",
                  "| 模型 | ΔMacro-F1 | ΔBalanced Accuracy | 小类召回率变化 |", "|---|---:|---:|---|"]
        small = [CLASSES[i] for i in range(len(CLASSES)) if 0 < counts[i] < SMOTE_TARGET]
        for model in MODELS:
            pair = ok[ok["model"] == model].set_index("variant")
            if not {"cw", "cw_smote"} <= set(pair.index):
                continue
            base, smote = per_class[_label(model, "cw")], per_class[_label(model, "cw_smote")]
            deltas = "，".join(f"{c} {smote.loc[c, 'recall'] - base.loc[c, 'recall']:+.3f}" for c in small)
            lines.append(f"| {model} | {pair.loc['cw_smote', 'macro_f1'] - pair.loc['cw', 'macro_f1']:+.4f} | "
                         f"{pair.loc['cw_smote', 'balanced_accuracy'] - pair.loc['cw', 'balanced_accuracy']:+.4f} "
                         f"| {deltas} |")
    chosen = selection.get("selected")
    if chosen:
        name = _label(chosen["model"], chosen["variant"])
        matrix = pd.read_csv(run_dir / f"confusion-{chosen['model']}-{chosen['variant']}.csv", index_col=0).to_numpy()
        plot_confusion(matrix, run_dir / "confusion-selected.png", f"{name} 验证集混淆矩阵（按真实类别归一化）")
        lines += ["", f"选定 T2 模型：**{name}**（{selection['rule']}；并列候选："
                  + "、".join(_label(t["model"], t["variant"]) for t in selection["tied"]) + "）。",
                  "", "![混淆矩阵](confusion-selected.png)"]
    else:
        lines += ["", "没有成功的组合，第 8b 步不产生候选模型。"]
    if selection.get("failed"):
        lines += ["", "失败记录："] + [f"- {f['model']}/{f['variant']}：{f['error']}" for f in selection["failed"]]
    lines += ["", "T2 只作研判参考输出，不驱动任何自动处置；锁定评估在第 9 步进行。"]
    (run_dir / "multiclass-report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
