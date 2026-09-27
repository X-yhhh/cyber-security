"""第 9 步：锁定评估（T1 holdout 判定、T2 官方测试文件评估）与 T3 跨数据集泛化评估。

分两个阶段执行，中间必须提交冻结文件：

- ``freeze``：不读取任何 holdout。校验 T1/T2 候选制品的 SHA-256，在验证分区上复现候选记录的验证指标，
  把模型文件、预处理器、阈值、特征顺序、切分指纹等写入 ``docs/v2/pre-final-freeze.json``（随后提交到 Git）。
- ``evaluate``（需要 ``--unlock-holdout``）：要求冻结文件与 Git HEAD 一致、制品哈希未变、同一切分的 holdout
  从未解锁；写追加式审计记录后解锁，T1 在 holdout 上只评估一次并按 §1 门槛判定（``final-verdict.json``），
  T2 在官方测试文件上评估一次，T3 做 D1/D2 公共特征 2×2 泛化实验（只写报告，不影响判定）。
- ``generalization``：只在 ``evaluate`` 的 T3 失败时，用 ``--resume`` 在同一运行目录补跑 T3。

候选中的 ``preprocessor.pkl`` 是本仓库第 8/8b 步生成的对象，只在 SHA-256 与冻结记录一致后才反序列化；
来源不明的 pickle 一律不加载。延迟、吞吐与 ONNX 一致性门槛在第 10 步用 ONNX Runtime 判定，本步骤记为待定。
"""

from __future__ import annotations

import gc
import json
import pickle
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from . import GLOBAL_SEED
from ..config import ROOT
from .datasets import (
    COMMON_FEATURES, D2_COMMON_SOURCE_COLUMNS, DataIntegrityError, common_view_d1, common_view_d2,
    load_cached, load_manifest,
)
from .guard import HoldoutLockedError, LeakageError, SplitIndex
from .preprocess import binary_metrics, latest_dir
from .runtime import RUNS_ROOT, RunContext, keep_awake, sha256_file, write_json

FREEZE_FILE = ROOT / "docs" / "v2" / "pre-final-freeze.json"
FREEZE_REL = "docs/v2/pre-final-freeze.json"
AUDIT_LOG = RUNS_ROOT / "holdout-audit.jsonl"
T1_SOURCE = "train-seeds-*/candidate/candidate.json"
T2_SOURCE = "train-multiclass-*/candidate/candidate.json"
REPRO_TOLERANCE = 1e-3  # 训练时 XGBoost 在 GPU 上推理，冻结复现在 CPU 上推理，阈值附近个别样本可能翻转
# §1 验收门槛：(键, 名称, 比较, 门槛)。只在 holdout 上判定一次。
HOLDOUT_GATES = (("macro_f1", "Macro-F1", ">=", 0.92), ("fnr", "FNR", "<=", 0.05), ("fpr", "FPR", "<=", 0.015),
                 ("pr_auc", "PR-AUC", ">=", 0.93), ("roc_auc", "ROC-AUC", ">=", 0.99))
SEED_GATE = ("fnr_std", "多种子 FNR 标准差（验证集）", "<=", 0.02)
EXPORT_GATES = ("单条推理延迟 P95 ≤ 5 ms（ONNX Runtime CPU）", "batch 1024 吞吐 ≥ 20k 条/秒",
                "ONNX 与训练框架概率最大绝对误差 ≤ 1e-4")
SENSITIVITY_GRID = np.round(np.arange(0.10, 0.9001, 0.05), 2)


class FreezeError(RuntimeError):
    """冻结记录缺失、未提交或与制品不一致；此时拒绝解锁 holdout。"""


def _rel(path: Path) -> str:
    """仓库内相对路径（正斜杠），避免在证据里写入主机绝对路径。"""
    try:
        return Path(path).resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return Path(path).name


def _logger(path: Path):
    def say(message: str) -> None:
        with path.open("a", encoding="utf-8") as stream:
            stream.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} {message}\n")
    return say

# ---------------------------------------------------------------- 制品加载（只在哈希校验通过后）

def verify_files(candidate_dir: Path, files: dict[str, str]) -> None:
    """候选目录中每个文件的 SHA-256 必须与记录一致，否则 fail-closed。"""
    for name, digest in files.items():
        path = Path(candidate_dir) / name
        if not path.is_file():
            raise FreezeError(f"missing candidate file: {name}")
        actual = sha256_file(path)
        if actual != digest:
            raise FreezeError(f"SHA-256 mismatch for {name}: {actual}")


def load_preprocessor(candidate_dir: Path, files: dict[str, str]) -> Any:
    verify_files(candidate_dir, {"preprocessor.pkl": files["preprocessor.pkl"]})
    return pickle.loads((Path(candidate_dir) / "preprocessor.pkl").read_bytes())


class T1Model:
    """T1 候选（二分类）的 CPU 推理封装；只支持第 8 步可能选出的 XGBoost / LightGBM。"""

    def __init__(self, model: str, candidate_dir: Path, files: dict[str, str]):
        verify_files(candidate_dir, files)
        self.model = model
        if model == "XGBoost":
            from xgboost import XGBClassifier

            self.impl = XGBClassifier()
            self.impl.load_model(Path(candidate_dir) / "model.json")
            self.impl.set_params(device="cpu")
        elif model == "LightGBM":
            import lightgbm

            self.impl = lightgbm.Booster(model_file=str(Path(candidate_dir) / "model.txt"))
        else:
            raise FreezeError(f"final-eval does not support candidate model {model}")
        self.preprocessor = load_preprocessor(candidate_dir, files)

    def predict(self, frame: pd.DataFrame) -> np.ndarray:
        x = np.ascontiguousarray(self.preprocessor.transform(frame).astype(np.float32, copy=False))
        if self.model == "XGBoost":
            return self.impl.predict_proba(x)[:, 1]
        return self.impl.predict(x)


class T2Model:
    """T2 候选（10 类）的推理封装；只支持 LightGBM / XGBoost。输出 (n, 10) 概率，判定取 argmax。"""

    def __init__(self, model: str, candidate_dir: Path, files: dict[str, str]):
        verify_files(candidate_dir, files)
        self.model = model
        if model == "LightGBM":
            import lightgbm

            self.impl = lightgbm.Booster(model_file=str(Path(candidate_dir) / "model.txt"))
        elif model == "XGBoost":
            from xgboost import XGBClassifier

            self.impl = XGBClassifier()
            self.impl.load_model(Path(candidate_dir) / "model.json")
            self.impl.set_params(device="cpu")
        else:
            raise FreezeError(f"final-eval does not support T2 model {model}")
        self.preprocessor = load_preprocessor(candidate_dir, files)

    def predict(self, frame: pd.DataFrame) -> np.ndarray:
        x = np.ascontiguousarray(self.preprocessor.transform(frame).astype(np.float32, copy=False))
        return self.impl.predict_proba(x) if self.model == "XGBoost" else self.impl.predict(x)

# ---------------------------------------------------------------- 指标

def full_binary_metrics(y: np.ndarray, prob: np.ndarray, threshold: float) -> dict[str, Any]:
    """§8 第 2 项的完整二分类指标（攻击为正类，判定 ``prob >= threshold``）。"""
    from sklearn.metrics import average_precision_score, f1_score, matthews_corrcoef, roc_auc_score

    base = binary_metrics(y, prob, threshold)
    pred = (prob >= threshold).astype(np.int8)
    return {
        "rows": int(len(y)), "attack_rows": int(y.sum()), "attack_rate": float(y.mean()), "threshold": float(threshold),
        "accuracy": base["accuracy"], "precision": base["precision"], "recall": base["recall"], "f1": base["f1"],
        "macro_f1": base["macro_f1"], "weighted_f1": float(f1_score(y, pred, average="weighted", zero_division=0)),
        "roc_auc": float(roc_auc_score(y, prob)), "pr_auc": float(average_precision_score(y, prob)),
        "specificity": 1.0 - base["fpr"], "fpr": base["fpr"], "fnr": base["fnr"],
        "mcc": float(matthews_corrcoef(y, pred)),
        "confusion": {k: base[k] for k in ("tn", "fp", "fn", "tp")},
    }


def judge(metrics: dict[str, Any], gates=HOLDOUT_GATES) -> list[dict[str, Any]]:
    out = []
    for key, name, op, limit in gates:
        value = float(metrics[key])
        ok = value >= limit if op == ">=" else value <= limit
        out.append({"metric": key, "name": name, "value": value, "op": op, "threshold": limit, "passed": bool(ok)})
    return out


def category_recall(categories: pd.Series, prob: np.ndarray, threshold: float) -> pd.DataFrame:
    """按 ``attack_cat`` 分组：攻击类为检出率（召回率），Normal 为判为攻击的比例（即 FPR）。"""
    pred = prob >= threshold
    frame = pd.DataFrame({"attack_cat": categories.astype("string").to_numpy(), "flagged": pred})
    grouped = frame.groupby("attack_cat", observed=True)["flagged"].agg(["size", "sum"])
    grouped = grouped.rename(columns={"size": "rows", "sum": "flagged_attack"}).reset_index()
    grouped["flagged_attack"] = grouped["flagged_attack"].astype(int)
    grouped["recall"] = np.where(grouped["attack_cat"] == "Normal", np.nan, grouped["flagged_attack"] / grouped["rows"])
    grouped["missed"] = np.where(grouped["attack_cat"] == "Normal", 0, grouped["rows"] - grouped["flagged_attack"])
    grouped["normal_flagged_rate"] = np.where(grouped["attack_cat"] == "Normal",
                                              grouped["flagged_attack"] / grouped["rows"], np.nan)
    return grouped.sort_values("rows", ascending=False).reset_index(drop=True)


def threshold_sensitivity(y: np.ndarray, prob: np.ndarray, extra: float) -> pd.DataFrame:
    rows = []
    for t in sorted({*map(float, SENSITIVITY_GRID), float(extra)}):
        m = binary_metrics(y, prob, t)
        rows.append({"threshold": t, "fnr": m["fnr"], "fpr": m["fpr"], "macro_f1": m["macro_f1"],
                     "is_frozen_threshold": bool(abs(t - extra) < 1e-12)})
    return pd.DataFrame(rows)

# ---------------------------------------------------------------- 数据

class D1Raw:
    """D1 原始数据的 V2 全量视图、二分类标签与 ``attack_cat``；切分从 ``split-d1-raw.npz`` 读取，holdout 默认锁定。"""

    def __init__(self, manifest: dict[str, Any], split_dir: Path):
        from .feature_compare import load_frame

        self.split = SplitIndex.load(Path(split_dir) / "split-d1-raw.npz", audit_log=AUDIT_LOG)
        self.frame, self.labels = load_frame(manifest)
        self.categories = load_cached("d1_raw.parquet", manifest, columns=["attack_cat"])["attack_cat"]
        if len(self.categories) != len(self.frame) or self.split.holdout_size + len(self.split.train) \
                + len(self.split.validation) > len(self.frame):
            raise LeakageError("D1 split does not match the registered raw data")


def check_reproduction(expected: dict[str, float], actual: dict[str, float], tolerance: float = REPRO_TOLERANCE
                       ) -> dict[str, Any]:
    """候选记录的验证指标必须在容差内复现（CPU 推理与训练时 GPU 推理的浮点差异在容差内）。"""
    diffs = {k: abs(float(actual[k]) - float(v)) for k, v in expected.items()}
    worst = max(diffs.values()) if diffs else 0.0
    if worst > tolerance:
        raise FreezeError(f"validation metrics not reproduced: {diffs}")
    return {"max_abs_diff": worst, "tolerance": tolerance, "diffs": diffs}


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()

# ---------------------------------------------------------------- 冻结（不读取 holdout）

def _subset_split(split_dir: Path) -> tuple[np.ndarray, np.ndarray, str]:
    audit = json.loads((Path(split_dir) / "split-audit.json").read_text(encoding="utf-8"))
    npz = Path(split_dir) / "split-d1-subset.npz"
    digest = sha256_file(npz)
    if digest != audit["split-d1-subset.npz"]["sha256"]:
        raise LeakageError("split-d1-subset.npz does not match the split audit")
    with np.load(npz) as parts:
        return np.sort(parts["train"]), np.sort(parts["validation"]), digest


def freeze(t1_dir: Path | None = None, t2_dir: Path | None = None, split_dir: Path | None = None) -> Path:
    """冻结 T1/T2 候选：校验制品、在验证分区上复现验证指标，写 ``docs/v2/pre-final-freeze.json``。

    不解锁、不读取任何 holdout（D1 原始 holdout 与子集官方测试文件）。已有冻结文件时拒绝覆盖。
    """
    from .multiclass import CLASSES, TRAIN_CACHE, encode_classes, multiclass_metrics
    from .train import evaluate

    if FREEZE_FILE.exists():
        raise FreezeError(f"{FREEZE_REL} already exists; a new attempt needs a new split (plan §4.3)")
    t1_dir = Path(t1_dir) if t1_dir else latest_dir(T1_SOURCE).parent
    t2_dir = Path(t2_dir) if t2_dir else latest_dir(T2_SOURCE).parent
    split_dir = Path(split_dir) if split_dir else latest_dir("split-*/split-audit.json")
    t1 = json.loads((t1_dir / "candidate" / "candidate.json").read_text(encoding="utf-8"))
    t2 = json.loads((t2_dir / "candidate" / "candidate.json").read_text(encoding="utf-8"))
    manifest_file, manifest = load_manifest()

    # T1：切分指纹一致，验证分区上复现阈值下的指标。
    d1 = D1Raw(manifest, split_dir)
    if d1.split.fingerprint != t1["split_fingerprint"]:
        raise LeakageError("T1 candidate was trained on a different split")
    model = T1Model(t1["model"], t1_dir / "candidate", t1["files"])
    val = d1.split.validation
    prob = model.predict(d1.frame.iloc[val][t1["columns"]])
    y_val = d1.labels[val]
    at_threshold = binary_metrics(y_val, prob, t1["threshold"])
    from sklearn.metrics import average_precision_score, roc_auc_score

    t1_actual = {"macro_f1": at_threshold["macro_f1"], "fnr": at_threshold["fnr"], "fpr": at_threshold["fpr"],
                 "pr_auc": float(average_precision_score(y_val, prob)), "auc": float(roc_auc_score(y_val, prob))}
    t1_repro = check_reproduction(t1["validation_metrics"], t1_actual)
    reselected = evaluate(y_val, prob)["threshold"]
    del model, prob, d1
    gc.collect()

    # T2：子集切分一致，验证分区复现。
    train_rows, val_rows, subset_digest = _subset_split(split_dir)
    if subset_digest != t2["split_d1_subset_sha256"]:
        raise LeakageError("T2 candidate was trained on a different subset split")
    if [t2["label_mapping"][str(i)] for i in range(len(CLASSES))] != list(CLASSES):
        raise FreezeError("T2 label mapping differs from the class contract")
    subset = load_cached(TRAIN_CACHE, manifest)
    t2_model = T2Model(t2["model"], t2_dir / "candidate", t2["files"])
    summary, _, _ = multiclass_metrics(encode_classes(subset["attack_cat"].iloc[val_rows]),
                                       t2_model.predict(subset.iloc[val_rows][t2["columns"]]))
    t2_repro = check_reproduction(t2["validation_metrics"], summary)
    del t2_model, subset
    gc.collect()

    seed_summary = pd.read_csv(t1_dir / "seed-summary.csv").set_index("model").loc[t1["model"]]
    record = {
        "frozen_at": datetime.now().astimezone().isoformat(),
        "base_commit": _git("rev-parse", "HEAD"),
        "register_manifest": {"file": _rel(manifest_file), "sha256": sha256_file(manifest_file)},
        "split": {"dir": _rel(split_dir), "d1_raw_fingerprint": t1["split_fingerprint"],
                  "d1_subset_sha256": subset_digest,
                  "split_audit_sha256": sha256_file(split_dir / "split-audit.json")},
        "attempt": 1,
        "t1": {"source_run": t1_dir.name, "model": t1["model"], "seed": t1["seed"], "params": t1["params"],
               "best_iteration": t1["best_iteration"], "scheme": t1["scheme"], "view": t1["view"],
               "columns": t1["columns"], "threshold": t1["threshold"], "threshold_policy": "验证集上 FNR ≤ 4% 的阈值中 FPR 最小者",
               "decision": "prob >= threshold → Attack", "label_mapping": {"0": "Normal", "1": "Attack"},
               "files": t1["files"], "candidate_json_sha256": sha256_file(t1_dir / "candidate" / "candidate.json"),
               "validation_metrics": t1["validation_metrics"], "validation_reproduction": t1_repro,
               "cpu_reselected_threshold": reselected,
               "seed_fnr_std": float(seed_summary["fnr_std"]), "seed_runs": int(seed_summary["n"])},
        "t2": {"source_run": t2_dir.name, "model": t2["model"], "variant": t2["variant"], "seed": t2["seed"],
               "params": t2["params"], "best_iteration": t2["best_iteration"], "scheme": t2["scheme"],
               "columns": t2["columns"], "label_mapping": t2["label_mapping"], "decision": t2["decision"],
               "files": t2["files"], "candidate_json_sha256": sha256_file(t2_dir / "candidate" / "candidate.json"),
               "validation_metrics": t2["validation_metrics"], "validation_reproduction": t2_repro},
        "gates": {"holdout": [dict(zip(("metric", "name", "op", "threshold"), g)) for g in HOLDOUT_GATES],
                  "validation": dict(zip(("metric", "name", "op", "threshold"), SEED_GATE)),
                  "deferred_to_export": list(EXPORT_GATES)},
        "holdout_read": False,
        "note": "冻结时未读取任何 holdout；权重与预处理器不提交，只记录 SHA-256。",
    }
    write_json(FREEZE_FILE, record)
    return FREEZE_FILE

# ---------------------------------------------------------------- 解锁前置条件

def load_freeze() -> tuple[dict[str, Any], str]:
    """读取冻结文件，要求其已提交且与 HEAD 一致；返回 (记录, 文件 SHA-256)。"""
    if not FREEZE_FILE.is_file():
        raise FreezeError(f"{FREEZE_REL} is missing; run final-eval --stage freeze and commit it first")
    if not _git("ls-files", FREEZE_REL):
        raise FreezeError(f"{FREEZE_REL} is not committed")
    if _git("status", "--porcelain", "--", FREEZE_REL):
        raise FreezeError(f"{FREEZE_REL} has uncommitted changes")
    return json.loads(FREEZE_FILE.read_text(encoding="utf-8")), sha256_file(FREEZE_FILE)


def prior_unlocks(fingerprint: str, audit_log: Path = AUDIT_LOG) -> list[dict[str, Any]]:
    if not Path(audit_log).is_file():
        return []
    events = [json.loads(line) for line in Path(audit_log).read_text(encoding="utf-8").splitlines() if line.strip()]
    return [e for e in events if e.get("split_fingerprint") == fingerprint]


def append_audit(event: dict[str, Any], audit_log: Path = AUDIT_LOG) -> None:
    Path(audit_log).parent.mkdir(parents=True, exist_ok=True)
    with Path(audit_log).open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({**event, "at": datetime.now().astimezone().isoformat()}, ensure_ascii=False) + "\n")


def require_first_unlock(fingerprint: str, audit_log: Path = AUDIT_LOG) -> None:
    """同一切分的 holdout 只能解锁一次（计划 §4.3）；已有解锁记录即拒绝。"""
    seen = prior_unlocks(fingerprint, audit_log)
    if seen:
        raise HoldoutLockedError(f"holdout of split {fingerprint[:12]} was already unlocked at {seen[0].get('at')}; "
                                 "a new attempt needs a new split seed")

# ---------------------------------------------------------------- 图

def _plt():
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    from .eda import _style

    _style()
    return plt


def plot_curves(y: np.ndarray, prob: np.ndarray, threshold: float, path: Path) -> None:
    """ROC 与 PR 曲线（左右两栏），标出冻结阈值对应的工作点。"""
    from sklearn.metrics import average_precision_score, precision_recall_curve, roc_auc_score, roc_curve

    from .eda import ATTACK_COLOR, INK, INK_SECONDARY, NORMAL_COLOR

    plt = _plt()
    point = binary_metrics(y, prob, threshold)
    fpr, tpr, _ = roc_curve(y, prob)
    precision, recall, _ = precision_recall_curve(y, prob)
    fig, (a, b) = plt.subplots(1, 2, figsize=(11, 4.6))
    a.plot(fpr, tpr, color=NORMAL_COLOR, lw=1.6)
    a.plot([0, 1], [0, 1], color=INK_SECONDARY, lw=0.8, ls="--")
    a.scatter([point["fpr"]], [1 - point["fnr"]], color=ATTACK_COLOR, zorder=3, s=28)
    a.annotate(f"阈值 {threshold:.3f}", (point["fpr"], 1 - point["fnr"]), xytext=(12, -18),
               textcoords="offset points", color=INK, fontsize=8)
    a.set_xscale("symlog", linthresh=0.01)
    a.set_xlim(0, 1)
    a.set_title(f"ROC 曲线（AUC = {roc_auc_score(y, prob):.4f}）", loc="left", fontsize=11)
    a.set_xlabel("FPR（对数刻度，0.01 以下线性）")
    a.set_ylabel("TPR（召回率）")
    b.plot(recall, precision, color=NORMAL_COLOR, lw=1.6)
    b.scatter([point["recall"]], [point["precision"]], color=ATTACK_COLOR, zorder=3, s=28)
    b.axhline(y.mean(), color=INK_SECONDARY, lw=0.8, ls="--")
    b.set_title(f"PR 曲线（AP = {average_precision_score(y, prob):.4f}）", loc="left", fontsize=11)
    b.set_xlabel("Recall")
    b.set_ylabel("Precision")
    b.set_ylim(0, 1.02)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def plot_sensitivity(table: pd.DataFrame, threshold: float, path: Path) -> None:
    from .eda import ATTACK_COLOR, INK_SECONDARY, NORMAL_COLOR

    plt = _plt()
    grid = table[~table["is_frozen_threshold"] | table["threshold"].isin(SENSITIVITY_GRID)]
    fig, ax = plt.subplots(figsize=(7.5, 4.2))
    ax.plot(grid["threshold"], grid["fnr"] * 100, color=ATTACK_COLOR, lw=1.6, marker="o", ms=3, label="FNR（漏报率）")
    ax.plot(grid["threshold"], grid["fpr"] * 100, color=NORMAL_COLOR, lw=1.6, marker="o", ms=3, label="FPR（误报率）")
    ax.axvline(threshold, color=INK_SECONDARY, lw=0.8, ls="--")
    ax.axhline(5.0, color=ATTACK_COLOR, lw=0.6, ls=":")
    ax.axhline(1.5, color=NORMAL_COLOR, lw=0.6, ls=":")
    ax.text(threshold, ax.get_ylim()[1] * 0.95, f" 冻结阈值 {threshold:.3f}", color=INK_SECONDARY, fontsize=8, va="top")
    ax.set_xlabel("阈值")
    ax.set_ylabel("比例（%）")
    ax.set_title("holdout 阈值敏感性（点线为 FNR 5% / FPR 1.5% 门槛）", loc="left", fontsize=11)
    ax.legend(frameon=False, fontsize=8)
    fig.savefig(path)
    plt.close(fig)

# ---------------------------------------------------------------- T3 泛化（只写报告）

D1_COMMON_SOURCE_COLUMNS = ["dur", "sbytes", "dbytes", "Spkts", "Dpkts", "sttl", "dttl", "Label"]
FEATURE_MAP = (  # 公共特征 → (D1 来源, D2 来源, 单位)
    ("duration_s", "dur（秒）", "FLOW_DURATION_MILLISECONDS / 1000", "秒"),
    ("src_bytes", "sbytes", "IN_BYTES", "字节"),
    ("dst_bytes", "dbytes", "OUT_BYTES", "字节"),
    ("src_pkts", "Spkts", "IN_PKTS", "包"),
    ("dst_pkts", "Dpkts", "OUT_PKTS", "包"),
    ("min_ttl", "min(sttl, dttl)", "MIN_TTL", "跳"),
    ("max_ttl", "max(sttl, dttl)", "MAX_TTL", "跳"),
    ("src_bytes_per_pkt", "sbytes / (Spkts + 1)", "IN_BYTES / (IN_PKTS + 1)", "字节/包"),
    ("dst_bytes_per_pkt", "dbytes / (Dpkts + 1)", "OUT_BYTES / (OUT_PKTS + 1)", "字节/包"),
)


def t3_params() -> dict[str, Any]:
    """T1 未调优 LightGBM（第 8 步调优的是 XGBoost/RF/ET/MLP），这里沿用 T1 初筛参数。"""
    from .train import SCREEN_PARAMS

    return dict(SCREEN_PARAMS["LightGBM"])


def _common(frame: pd.DataFrame, source: str) -> np.ndarray:
    view = common_view_d1(frame) if source == "D1" else common_view_d2(frame)
    if list(view.columns) != list(COMMON_FEATURES):
        raise DataIntegrityError("common feature order differs from COMMON_FEATURES")
    return np.ascontiguousarray(view.to_numpy(dtype=np.float32))


def load_common(manifest: dict[str, Any], split: SplitIndex, source: str) -> dict[str, np.ndarray]:
    """按分区返回公共特征矩阵与标签；调用方必须已解锁 ``split``。D2 只读取切分抽中的 150 万行。"""
    if source == "D1":
        raw = load_cached("d1_raw.parquet", manifest, columns=D1_COMMON_SOURCE_COLUMNS)
        label = "Label"
    else:
        raw = load_cached("d2.parquet", manifest, columns=D2_COMMON_SOURCE_COLUMNS)
        label = "Label"
    out = {}
    for part, rows in (("train", split.train), ("validation", split.validation), ("holdout", split.holdout)):
        rows = np.sort(rows)
        chunk = raw.iloc[rows]
        out[f"x_{part}"] = _common(chunk, source)
        out[f"y_{part}"] = chunk[label].to_numpy(dtype=np.int8)
    del raw
    gc.collect()
    return out


def generalization(manifest: dict[str, Any], d1_split: SplitIndex, d2_split: SplitIndex, run_dir: Path, say
                   ) -> pd.DataFrame:
    """D1→D1、D1→D2、D2→D2、D2→D1：各自在训练分区拟合、验证分区早停，在两个数据集的 holdout 上评估。

    判定阈值 0.5（跨分布时验证集阈值没有意义）；Macro-F1 与 ROC-AUC 不参与 §1 判定。
    """
    import lightgbm
    from lightgbm import LGBMClassifier
    from sklearn.metrics import roc_auc_score

    from .preprocess import RF_JOBS

    data = {"D1": load_common(manifest, d1_split, "D1"), "D2": load_common(manifest, d2_split, "D2")}
    rows = []
    for source in ("D1", "D2"):
        p = t3_params()
        early = int(p.pop("early_stopping_rounds"))
        model = LGBMClassifier(random_state=GLOBAL_SEED, n_jobs=RF_JOBS, verbose=-1, **p)
        d = data[source]
        model.fit(d["x_train"], d["y_train"], eval_set=[(d["x_validation"], d["y_validation"])],
                  eval_metric="binary_logloss", callbacks=[lightgbm.early_stopping(early, verbose=False)])
        for target in ("D1", "D2"):
            t = data[target]
            prob = model.predict_proba(t["x_holdout"])[:, 1]
            m = binary_metrics(t["y_holdout"], prob, 0.5)
            rows.append({"train": source, "test": target, "train_rows": int(len(d["y_train"])),
                         "test_rows": int(len(t["y_holdout"])), "test_attack_rate": float(t["y_holdout"].mean()),
                         "best_iteration": int(model.best_iteration_), "macro_f1": m["macro_f1"],
                         "roc_auc": float(roc_auc_score(t["y_holdout"], prob)), "fnr": m["fnr"], "fpr": m["fpr"]})
            say(f"T3 {source}->{target} macro_f1={m['macro_f1']:.4f} auc={rows[-1]['roc_auc']:.4f}")
        del model
        gc.collect()
    table = pd.DataFrame(rows)
    table.to_csv(run_dir / "generalization.csv", index=False)
    return table

# ---------------------------------------------------------------- 锁定评估

def evaluate_t1(freeze_record: dict[str, Any], d1: D1Raw, run_dir: Path, say) -> dict[str, Any]:
    t1 = freeze_record["t1"]
    candidate = RUNS_ROOT / t1["source_run"] / "candidate"
    model = T1Model(t1["model"], candidate, t1["files"])
    rows = np.sort(d1.split.holdout)
    y = d1.labels[rows]
    prob = model.predict(d1.frame.iloc[rows][t1["columns"]])
    threshold = float(t1["threshold"])
    metrics = full_binary_metrics(y, prob, threshold)
    gates = judge(metrics)
    seed_gate = judge({"fnr_std": t1["seed_fnr_std"]}, (SEED_GATE,))[0]
    cats = category_recall(d1.categories.iloc[rows], prob, threshold)
    cats.to_csv(run_dir / "t1-holdout-category-recall.csv", index=False)
    sens = threshold_sensitivity(y, prob, threshold)
    sens.to_csv(run_dir / "t1-threshold-sensitivity.csv", index=False)
    plot_curves(y, prob, threshold, run_dir / "t1-roc-pr.png")
    plot_sensitivity(sens, threshold, run_dir / "t1-threshold-sensitivity.png")
    write_json(run_dir / "t1-holdout-metrics.json", metrics)
    passed = all(g["passed"] for g in gates) and seed_gate["passed"]
    say(f"T1 holdout macro_f1={metrics['macro_f1']:.4f} fnr={metrics['fnr']:.4f} fpr={metrics['fpr']:.4f} "
        f"passed={passed}")
    del model
    gc.collect()
    return {"metrics": metrics, "gates": gates, "seed_gate": seed_gate, "passed_step9": passed, "categories": cats}


def evaluate_t2(freeze_record: dict[str, Any], manifest: dict[str, Any], run_dir: Path, say) -> dict[str, Any]:
    """T2 在子集官方测试文件（82,332 行）上评估一次；只报告，不参与 §1 判定。"""
    from .multiclass import CLASSES, HOLDOUT_CACHE, encode_classes, multiclass_metrics, plot_confusion

    t2 = freeze_record["t2"]
    model = T2Model(t2["model"], RUNS_ROOT / t2["source_run"] / "candidate", t2["files"])
    test = load_cached(HOLDOUT_CACHE, manifest)
    y = encode_classes(test["attack_cat"])
    summary, per_class, matrix = multiclass_metrics(y, model.predict(test[t2["columns"]]))
    per_class.to_csv(run_dir / "t2-test-per-class.csv", index=False)
    pd.DataFrame(matrix, index=CLASSES, columns=CLASSES).to_csv(run_dir / "t2-test-confusion.csv")
    plot_confusion(matrix, run_dir / "t2-test-confusion.png",
                   f"T2 官方测试文件混淆矩阵（{t2['model']}，行归一化）")
    write_json(run_dir / "t2-test-metrics.json", {"rows": int(len(y)), **summary})
    say(f"T2 test macro_f1={summary['macro_f1']:.4f} bal_acc={summary['balanced_accuracy']:.4f}")
    return {"summary": summary, "per_class": per_class, "rows": int(len(y))}

def run_evaluate(unlock_holdout: bool, candidate: str | None = None, resume: Path | None = None,
                 only_generalization: bool = False) -> Path:
    """锁定评估。T1/T2 各自的 holdout 只评估一次；``only_generalization`` 只在同一运行目录补跑 T3。"""
    if not unlock_holdout:
        raise HoldoutLockedError("final-eval evaluate requires --unlock-holdout")
    record, freeze_sha = load_freeze()
    if candidate and candidate != record["t1"]["model"]:
        raise FreezeError(f"--candidate {candidate} differs from frozen T1 model {record['t1']['model']}")
    manifest_file, manifest = load_manifest()
    if sha256_file(manifest_file) != record["register_manifest"]["sha256"]:
        raise FreezeError("register manifest changed since freeze")
    split_dir = ROOT / record["split"]["dir"]
    if sha256_file(split_dir / "split-audit.json") != record["split"]["split_audit_sha256"]:
        raise FreezeError("split audit changed since freeze")
    for task in ("t1", "t2"):
        verify_files(RUNS_ROOT / record[task]["source_run"] / "candidate", record[task]["files"])
    d1_split = SplitIndex.load(split_dir / "split-d1-raw.npz", audit_log=AUDIT_LOG)
    d2_split = SplitIndex.load(split_dir / "split-d2.npz", audit_log=AUDIT_LOG)
    if d1_split.fingerprint != record["split"]["d1_raw_fingerprint"]:
        raise LeakageError("D1 split changed since freeze")
    subset_key = "d1-subset:" + record["split"]["d1_subset_sha256"]

    if only_generalization:
        if resume is None or not (Path(resume) / "final-verdict.json").is_file():
            raise FreezeError("--stage generalization needs --resume <final-eval run with final-verdict.json>")
        run_dir = Path(resume)
        say = _logger(run_dir / "training.log")
        verdict = json.loads((run_dir / "final-verdict.json").read_text(encoding="utf-8"))
        if verdict["freeze_sha256"] != freeze_sha:
            raise FreezeError("resume run belongs to a different freeze")
        for split in (d1_split, d2_split):
            split._unlocked = True  # 已在该运行中解锁并审计，不重复写解锁事件
        append_audit({"event": "generalization_rerun", "run": run_dir.name})
        with keep_awake():
            table = generalization(manifest, d1_split, d2_split, run_dir, say)
        write_report(run_dir, record, verdict, table)
        RunContext.checksum_dir(run_dir)
        return run_dir

    for key in (d1_split.fingerprint, subset_key):
        require_first_unlock(key)
    ctx = RunContext("final-eval", GLOBAL_SEED, {"freeze_file": FREEZE_REL, "freeze_sha256": freeze_sha,
                                                   "candidate": record["t1"]["model"], "attempt": record["attempt"]})
    run_dir = ctx.run_dir
    say = _logger(run_dir / "training.log")
    reason = f"第 9 步锁定评估（第 {record['attempt']} 次尝试），冻结文件 {freeze_sha[:12]}，运行 {run_dir.name}"
    with keep_awake():
        d1 = D1Raw(manifest, split_dir)
        d1.split.unlock_holdout(reason)
        say(f"unlocked D1 raw holdout ({d1.split.holdout_size} rows)")
        t1 = evaluate_t1(record, d1, run_dir, say)
        del d1
        gc.collect()
        append_audit({"event": "holdout_unlocked", "reason": reason, "split_fingerprint": subset_key})
        t2 = evaluate_t2(record, manifest, run_dir, say)
        verdict = {
            "freeze_file": FREEZE_REL, "freeze_sha256": freeze_sha, "attempt": record["attempt"],
            "run": run_dir.name, "candidate": record["t1"]["model"], "threshold": record["t1"]["threshold"],
            "holdout_rows": t1["metrics"]["rows"], "gates": t1["gates"], "validation_gate": t1["seed_gate"],
            "deferred_to_export": list(EXPORT_GATES), "passed_step9": t1["passed_step9"],
            "deliverable": "pending_export" if t1["passed_step9"] else "rejected",
            "note": ("第 9 步门槛全部通过；延迟、吞吐与 ONNX 一致性在第 10 步判定，未通过同样不能交付。"
                     if t1["passed_step9"] else "未通过：不能交付；按 §4.3 换种子重新切分后回到第 7～8 步。"),
        }
        write_json(run_dir / "final-verdict.json", verdict)
        table = None
        try:
            d2_split.unlock_holdout(f"{reason}：T3 泛化评估")
            d1_split.unlock_holdout(f"{reason}：T3 泛化评估（同一次运行内读取 D1 公共特征）")
            table = generalization(manifest, d1_split, d2_split, run_dir, say)
        except Exception as exc:  # T3 只写报告；失败不影响判定，记录后可用 --stage generalization 补跑
            say(f"T3 failed: {type(exc).__name__}: {exc}")
            write_json(run_dir / "generalization-error.json", {"error": f"{type(exc).__name__}: {exc}"})
    write_report(run_dir, record, verdict, table)
    ctx.finish()
    return run_dir

# ---------------------------------------------------------------- 报告

def _fmt(value: float, pct: bool = False) -> str:
    return f"{value * 100:.2f}%" if pct else f"{value:.4f}"


def write_report(run_dir: Path, record: dict[str, Any], verdict: dict[str, Any], table: pd.DataFrame | None) -> None:
    """``final-evaluation.md``：判定表、完整指标、混淆矩阵、分类别检出率、阈值敏感性、T2、T3。只读运行目录中的产物。"""
    t1m = json.loads((run_dir / "t1-holdout-metrics.json").read_text(encoding="utf-8"))
    cats = pd.read_csv(run_dir / "t1-holdout-category-recall.csv")
    sens = pd.read_csv(run_dir / "t1-threshold-sensitivity.csv")
    t2m = json.loads((run_dir / "t2-test-metrics.json").read_text(encoding="utf-8"))
    t2c = pd.read_csv(run_dir / "t2-test-per-class.csv")
    t1, t2 = record["t1"], record["t2"]
    c = t1m["confusion"]
    lines = [
        "# 第 9 步：锁定评估与泛化评估", "",
        f"运行 `{run_dir.name}`，第 {record['attempt']} 次尝试。冻结文件 `{FREEZE_REL}`（SHA-256 `{verdict['freeze_sha256'][:16]}…`）"
        f"在解锁前已提交；holdout 只评估一次，解锁记录写入 `runs/holdout-audit.jsonl`。", "",
        f"T1 候选：{t1['model']}（来源 `{t1['source_run']}`，视图 {t1['view']} 共 {len(t1['columns'])} 列，预处理 {t1['scheme']}），"
        f"冻结阈值 {t1['threshold']:.6f}（{t1['threshold_policy']}）。", "",
        "## T1 验收判定（D1 原始数据 holdout）", "",
        f"holdout {t1m['rows']:,} 行，其中攻击 {t1m['attack_rows']:,} 行（{_fmt(t1m['attack_rate'], True)}）。", "",
        "| 指标 | 门槛 | holdout 实测 | 结果 |", "|---|---|---:|---|",
    ]
    for g in verdict["gates"]:
        pct = g["metric"] in ("fnr", "fpr")
        limit = f"{g['threshold'] * 100:.1f}%" if pct else f"{g['threshold']}"
        lines.append(f"| {g['name']} | {g['op'].replace('>=', '≥').replace('<=', '≤')} {limit} | "
                     f"{_fmt(g['value'], pct)} | {'通过' if g['passed'] else '**未通过**'} |")
    vg = verdict["validation_gate"]
    lines.append(f"| {vg['name']} | ≤ 2.0% | {_fmt(vg['value'], True)} | {'通过' if vg['passed'] else '**未通过**'} |")
    for item in verdict["deferred_to_export"]:
        lines.append(f"| {item} | — | 第 10 步测 | 待定 |")
    lines += ["", f"**第 9 步判定：{'通过' if verdict['passed_step9'] else '未通过'}**。{verdict['note']}", "",
              "## T1 完整指标", "", "| 指标 | 值 |", "|---|---:|"]
    for key, name in (("accuracy", "Accuracy"), ("precision", "Precision（攻击）"), ("recall", "Recall（攻击）"),
                      ("f1", "F1（攻击）"), ("macro_f1", "Macro-F1"), ("weighted_f1", "Weighted-F1"),
                      ("roc_auc", "ROC-AUC"), ("pr_auc", "PR-AUC"), ("specificity", "Specificity"),
                      ("fpr", "FPR"), ("fnr", "FNR"), ("mcc", "MCC")):
        lines.append(f"| {name} | {_fmt(t1m[key])} |")
    lines += ["", "混淆矩阵（行为真实，列为预测）：", "", "| | 预测 Normal | 预测 Attack |", "|---|---:|---:|",
              f"| 真实 Normal | {c['tn']:,} | {c['fp']:,} |", f"| 真实 Attack | {c['fn']:,} | {c['tp']:,} |", "",
              "ROC / PR 曲线见 `t1-roc-pr.png`，阈值敏感性见 `t1-threshold-sensitivity.png`。", "",
              "## T1 按 attack_cat 的检出率", "", "| 类别 | holdout 行数 | 检出 | 漏报 | 检出率 |", "|---|---:|---:|---:|---:|"]
    for r in cats.itertuples():
        if r.attack_cat == "Normal":
            lines.append(f"| Normal | {r.rows:,} | 误报 {r.flagged_attack:,} | — | FPR {_fmt(r.normal_flagged_rate, True)} |")
        else:
            lines.append(f"| {r.attack_cat} | {r.rows:,} | {r.flagged_attack:,} | {r.missed:,} | {_fmt(r.recall, True)} |")
    lines += ["", "## T1 阈值敏感性", "", "| 阈值 | FNR | FPR | Macro-F1 |", "|---:|---:|---:|---:|"]
    for r in sens.itertuples():
        mark = "（冻结）" if r.is_frozen_threshold else ""
        lines.append(f"| {r.threshold:.3f}{mark} | {_fmt(r.fnr, True)} | {_fmt(r.fpr, True)} | {_fmt(r.macro_f1)} |")
    lines += ["", "## T2 多分类（D1 子集官方测试文件，只作研判参考）", "",
              f"{t2['model']}（{t2['variant']}），官方测试文件 {t2m['rows']:,} 行，判定取 argmax。不参与 §1 判定。", "",
              "| 指标 | 验证集 | 官方测试文件 |", "|---|---:|---:|"]
    for key, name in (("macro_f1", "Macro-F1"), ("weighted_f1", "Weighted-F1"), ("balanced_accuracy", "Balanced Accuracy"),
                      ("min_class_recall", "最小类别召回率")):
        val = t2["validation_metrics"].get(key)
        lines.append(f"| {name} | {_fmt(val) if val is not None else '—'} | {_fmt(t2m[key])} |")
    lines += ["", "| 类别 | 支持数 | Precision | Recall | F1 |", "|---|---:|---:|---:|---:|"]
    for r in t2c.itertuples():
        lines.append(f"| {r[1]} | {r.support:,} | {_fmt(r.precision)} | {_fmt(r.recall)} | {_fmt(r.f1)} |")
    lines += ["", "混淆矩阵见 `t2-test-confusion.png` / `.csv`。", "", "## T3 跨数据集泛化（只写报告，不影响判定）", ""]
    lines += ["公共特征映射（`datasets.COMMON_FEATURES`，协议与端口编码不同，不做映射）：", "",
              "| 公共特征 | D1 来源 | D2 来源 | 单位 |", "|---|---|---|---|"]
    lines += [f"| `{a}` | {b} | {d} | {u} |" for a, b, d, u in FEATURE_MAP]
    if table is None:
        lines += ["", "T3 未完成，错误见 `generalization-error.json`；可用 `--stage generalization --resume` 补跑。"]
    else:
        lines += ["", "LightGBM（T1 初筛参数；T1 未调优 LightGBM），各自训练分区拟合、验证分区早停，在目标数据集 holdout 上评估，阈值 0.5。", "",
                  "| 训练 → 测试 | D1 holdout | D2 holdout |", "|---|---:|---:|"]
        for source in ("D1", "D2"):
            cells = []
            for target in ("D1", "D2"):
                r = table[(table["train"] == source) & (table["test"] == target)].iloc[0]
                cells.append(f"{r.macro_f1:.3f} / {r.roc_auc:.3f}")
            lines.append(f"| {source} 训练 | {' | '.join(cells)} |")
        lines += ["", "格内为 Macro-F1 / ROC-AUC。跨数据集结果只说明模型只对其训练分布负责，不作为调参目标。"]
    lines += ["", "## 使用限制", "",
              "- 结论只适用于 UNSW-NB15 分布的流量特征二分类；T2 类别只作研判参考，不驱动自动处置。",
              "- holdout 已消耗：若之后回到第 7～8 步调整，必须按 §4.3 换种子重新切分。"]
    (run_dir / "final-evaluation.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
