"""路线 B 阶段 1 §7.1 第 5、6 项：v4 特征集消融（F0～F5）与 D2 泛化对照。

约束：
- 只用 train + validation；holdout 不读取、不解锁（SplitIndex 不传审计日志，访问即抛错）。
- 固定 P1 预处理；XGBoost 用第 8 步冻结参数，LightGBM 用第 8 步初筛参数；验证分区早停，阈值按 §7.3 在验证分区选。
- 所有组只在单主机 ``ct_*`` 窗口已满的行上训练与评估，保证 F0～F5 样本完全相同。
- v4 口径的 ``ct_*`` 与 ``service`` 来自 feature-audit 运行的重算缓存，读取前校验 SHA-256。
- 泛化对照只在 D2 验证分区上评估，只写报告，不参与选型。本步骤不产出交付模型。
"""

from __future__ import annotations

import gc
import json
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from . import GLOBAL_SEED
from .datasets import (COMMON_FEATURES, D2_COMMON_SOURCE_COLUMNS, DataIntegrityError, common_view_d1, common_view_d2,
                       load_cached, load_manifest)
from .feature_audit import latest_split_dir
from .features import V1_RAW_COLUMNS, build_v2
from .final_eval import category_recall
from .guard import SplitIndex
from .preprocess import SCHEME_BY_KEY, binary_metrics, build_preprocessor
from .runtime import RUNS_ROOT, RunContext, keep_awake, sha256_file, write_json
from .train import SCREEN_PARAMS, build_model, evaluate, release

SEEDS = (20260927, 20260928, 20260929)
MODELS = ("XGBoost", "LightGBM")
CT = ("ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm")
# 2026.09.0 交付模型的视图（V3）与 XGBoost 冻结参数所在的运行；缺失即终止，不回退到其他运行。
VIEW_RUN, PARAMS_RUN = "feature-20260927-1249", "train-seeds-20260927-1458"
D1_COMMON_COLUMNS = ["dur", "sbytes", "dbytes", "Spkts", "Dpkts", "sttl", "dttl", "Label"]
# 训练计划 §1 门槛；G1 只在验证集上判定 F5 是否可交付，holdout 判定留到阶段 2。
GATES = {"macro_f1": (">=", 0.92), "fnr": ("<=", 0.05), "fpr": ("<=", 0.015), "pr_auc": (">=", 0.93),
         "fnr_std": ("<=", 0.02)}
DESCRIPTIONS = {"F0": "v3.1 交付视图 V3（基线）", "F1": "去 `sttl`、`ct_state_ttl`", "F2": "再去 `sloss`、`sjit`、`djit`、`dinpkt`",
                "F3": "`ct_*` 换成单主机重算值", "F4": "`service` 换成端口口径，删 `ct_flw_http_mthd`",
                "F5": "删 `ct_dst_sport_ltm`、`ct_dst_src_ltm`（v4 候选）"}
ROW_KEYS = ("group", "model", "seed", "status", "features", "encoded_features", "fit_rows", "fit_seconds",
            "best_iteration", "threshold", "constraint_met", "macro_f1", "pr_auc", "precision", "recall", "fnr", "fpr",
            "macro_f1_at_0.5", "fnr_at_0.5", "fpr_at_0.5", "category_recall", "top15_gain", "top1_over_top2", "error")

def define_groups(v3: list[str]) -> dict[str, list[tuple[str, str]]]:
    """返回 {组名: [(模型列名, 来源)]}，来源为 ``csv``（原 CSV/派生列）或 ``v4``（单主机重算列）。

    每组只比上一组改一个因素；列名保持模型视图名称，保证类别列判定（``features.CATEGORICAL``）不变。
    """
    f0 = [(c, "csv") for c in v3]
    f1 = [(c, s) for c, s in f0 if c not in ("sttl", "ct_state_ttl")]
    f2 = [(c, s) for c, s in f1 if c not in ("sloss", "sjit", "djit", "dinpkt")]
    f3 = [(c, "v4" if c in CT else s) for c, s in f2]
    f4 = [(c, "v4" if c == "service" else s) for c, s in f3 if c != "ct_flw_http_mthd"]
    f5 = [(c, s) for c, s in f4 if c not in ("ct_dst_sport_ltm", "ct_dst_src_ltm")]
    return {"F0": f0, "F1": f1, "F2": f2, "F3": f3, "F4": f4, "F5": f5}


def group_view(frame: pd.DataFrame, spec: list[tuple[str, str]], rows: np.ndarray) -> pd.DataFrame:
    """按组定义取列：``v4`` 来源读取 ``<列>_v4``，再改回模型列名。"""
    source = [f"{c}_v4" if s == "v4" else c for c, s in spec]
    missing = sorted(set(source) - set(frame.columns))
    if missing:
        raise DataIntegrityError(f"frame lacks group columns: {missing}")
    view = frame.iloc[rows][source]
    view.columns = [c for c, _ in spec]
    return view


def load_frame(manifest: dict[str, Any], audit_dir: Path) -> tuple[pd.DataFrame, np.ndarray, pd.Series, np.ndarray]:
    """读取 D1 原始缓存构造 V2 全量视图，并按行拼上 feature-audit 的 v4 重算列。

    返回 (特征表, 标签, attack_cat, 窗口已满掩码)。重算缓存的 SHA-256 与行数不符即终止。
    """
    meta = json.loads((audit_dir / "recomputed-cache.json").read_text(encoding="utf-8"))
    cache = audit_dir / meta["file"]
    if sha256_file(cache) != meta["sha256"]:
        raise DataIntegrityError(f"SHA-256 mismatch for {cache.name}")
    raw = load_cached("d1_raw.parquet", manifest, columns=[*V1_RAW_COLUMNS, "Label", "attack_cat"])
    re = pd.read_parquet(cache)
    if len(re) != len(raw) or len(re) != meta["rows"]:
        raise DataIntegrityError("recomputed cache is not row-aligned with d1_raw.parquet")
    labels = raw["Label"].to_numpy(dtype=np.int8)
    cats = raw["attack_cat"].astype("string").fillna("Normal").reset_index(drop=True)
    frame = build_v2(raw).reset_index(drop=True)
    del raw
    gc.collect()
    for c in CT:
        frame[f"{c}_v4"] = re[f"{c}_v4"].to_numpy(dtype=np.float32)
    frame["service_v4"] = pd.Series(re["service_v4"].to_numpy(), dtype="string")
    ready = re["window_ready"].to_numpy(dtype=bool)
    del re
    gc.collect()
    return frame, labels, cats, ready


def build_matrices(frame: pd.DataFrame, spec: list[tuple[str, str]], train: np.ndarray, val: np.ndarray,
                   seed: int) -> dict[str, Any]:
    """P1 预处理只在训练行上拟合；返回训练/验证矩阵与预处理器。"""
    columns = [c for c, _ in spec]
    pre = build_preprocessor(SCHEME_BY_KEY["P1"], seed, columns)
    x_train = pre.fit_transform(group_view(frame, spec, train)).astype(np.float32, copy=False)
    x_val = pre.transform(group_view(frame, spec, val)).astype(np.float32, copy=False)
    return {"preprocessor": pre, "x_train": np.ascontiguousarray(x_train), "x_val": np.ascontiguousarray(x_val)}


def gain(wrapper: Any, preprocessor: Any, columns: list[str]) -> pd.Series:
    """按模型列名汇总 gain 重要性（缺失指示列计入来源列），降序。"""
    names = list(preprocessor.get_feature_names_out())
    model = wrapper.model
    if hasattr(model, "get_booster"):
        score = model.get_booster().get_score(importance_type="total_gain")
        values = [score.get(f"f{i}", 0.0) for i in range(len(names))]
    else:
        values = list(model.booster_.feature_importance(importance_type="gain"))
    series = pd.Series(values, index=[n.removeprefix("missingindicator_") for n in names], dtype="float64")
    return series.groupby(level=0).sum().reindex(columns, fill_value=0.0).sort_values(ascending=False)


def fit_one(group: str, model: str, seed: int, params: dict[str, Any], data: dict[str, Any], y_train: np.ndarray,
            y_val: np.ndarray, cats_val: pd.Series, columns: list[str]) -> dict[str, Any]:
    """训练一次，在验证分区按 §7.3 选阈值评估，另给阈值 0.5 的指标、分类召回与 gain 前 15。"""
    start = time.perf_counter()
    wrapper = build_model(model, params, seed)
    wrapper.fit(data["x_train"], y_train, data["x_val"], y_val)
    seconds = time.perf_counter() - start
    prob = wrapper.predict(data["x_val"])
    ev = evaluate(y_val, prob)
    half = binary_metrics(y_val, prob, 0.5)
    rec = category_recall(cats_val, prob, ev["threshold"])
    rec = {r.attack_cat: float(r.recall) for r in rec.itertuples() if r.attack_cat != "Normal"}
    g = gain(wrapper, data["preprocessor"], columns)
    top = g.head(15)
    ratio = float(g.iloc[0] / g.iloc[1]) if len(g) > 1 and g.iloc[1] > 0 else float("nan")
    best_iteration = wrapper.best_iteration
    release(wrapper)
    return {"group": group, "model": model, "seed": seed, "status": "ok", "features": len(columns),
            "encoded_features": int(data["x_val"].shape[1]), "fit_rows": int(len(y_train)), "fit_seconds": seconds,
            "best_iteration": best_iteration, "threshold": ev["threshold"],
            "constraint_met": ev["constraint_met"], "macro_f1": ev["macro_f1"], "pr_auc": ev["pr_auc"],
            "precision": ev["precision"], "recall": ev["recall"], "fnr": ev["fnr"], "fpr": ev["fpr"],
            "macro_f1_at_0.5": half["macro_f1"], "fnr_at_0.5": half["fnr"], "fpr_at_0.5": half["fpr"],
            "category_recall": json.dumps(rec, ensure_ascii=False),
            "top15_gain": json.dumps({k: float(v) for k, v in top.items()}, ensure_ascii=False),
            "top1_over_top2": ratio, "error": ""}


def append_row(path: Path, row: dict[str, Any]) -> None:
    pd.DataFrame([{k: row.get(k, "") for k in ROW_KEYS}]).to_csv(path, mode="a", header=not path.exists(), index=False)


def completed(path: Path) -> set[tuple[str, str, int]]:
    if not path.exists():
        return set()
    rows = pd.read_csv(path)
    return {(r.group, r.model, int(r.seed)) for r in rows.itertuples() if r.status == "ok"}


METRICS = ("macro_f1", "pr_auc", "fnr", "fpr", "macro_f1_at_0.5", "fnr_at_0.5", "fpr_at_0.5")


def summarize(runs: pd.DataFrame) -> pd.DataFrame:
    """按 (组, 模型) 汇总各指标的均值与标准差（只统计成功的运行）。"""
    ok = runs[runs["status"] == "ok"]
    agg = ok.groupby(["group", "model"])[list(METRICS)].agg(["mean", "std"])
    agg.columns = [f"{m}_{s}" for m, s in agg.columns]
    agg["runs"] = ok.groupby(["group", "model"]).size()
    return agg.reset_index()


def _ms(row: Any, metric: str, pct: bool = False) -> str:
    mean, std = row[f"{metric}_mean"], row[f"{metric}_std"]
    if pct:
        return f"{100 * mean:.2f}% ± {100 * (0 if np.isnan(std) else std):.2f}"
    return f"{mean:.4f} ± {0 if np.isnan(std) else std:.4f}"


def gate_check(summary: pd.DataFrame, group: str = "F5", model: str = "XGBoost") -> list[dict[str, Any]]:
    """在验证集上按训练计划 §1 门槛检查指定组（G1 参考，holdout 判定留到阶段 2）。"""
    row = summary[(summary["group"] == group) & (summary["model"] == model)]
    if row.empty:
        return []
    r = row.iloc[0]
    values = {"macro_f1": r["macro_f1_mean"], "fnr": r["fnr_mean"], "fpr": r["fpr_mean"],
              "pr_auc": r["pr_auc_mean"], "fnr_std": r["fnr_std"]}
    out = []
    for name, (op, bound) in GATES.items():
        v = float(values[name])
        ok = v >= bound if op == ">=" else v <= bound
        out.append({"metric": name, "value": v, "op": op, "bound": bound, "passed": bool(ok)})
    return out


def render(runs: pd.DataFrame, gen: pd.DataFrame | None, info: dict[str, Any]) -> str:
    """生成消融报告 Markdown（只含字段级与模型级统计，不含地址与单条流）。"""
    s = summarize(runs)
    L = ["# 路线 B §7.1 第 5、6 项：v4 特征集消融与泛化对照", "",
         f"训练 {info['train_rows']:,} 行、验证 {info['val_rows']:,} 行（均为单主机窗口已满的行）；holdout 未读取。"
         "固定 P1 预处理；XGBoost 用第 8 步冻结参数，LightGBM 用初筛参数；每组 3 个种子。"
         "「选定阈值」为验证集上 FNR ≤ 4% 时 FPR 最小的阈值。", "", "## 1. 分组", "",
         "| 组 | 相对上一组的改动 | 特征数 |", "|---|---|---:|"]
    for g, d in DESCRIPTIONS.items():
        L.append(f"| {g} | {d} | {info['features'][g]} |")
    for model in MODELS:
        L += ["", f"## 2. {model}（均值 ± 标准差）", "",
              "| 组 | Macro-F1 | ΔMacro-F1 | PR-AUC | FNR | FPR | Macro-F1@0.5 | FNR@0.5 | FPR@0.5 |",
              "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
        sub = s[s["model"] == model].set_index("group").reindex(list(DESCRIPTIONS)).dropna(how="all")
        prev = None
        for g, r in sub.iterrows():
            delta = "—" if prev is None else f"{r['macro_f1_mean'] - prev:+.4f}"
            prev = r["macro_f1_mean"]
            L.append(f"| {g} | {_ms(r, 'macro_f1')} | {delta} | {_ms(r, 'pr_auc')} | {_ms(r, 'fnr', True)} | "
                     f"{_ms(r, 'fpr', True)} | {_ms(r, 'macro_f1_at_0.5')} | {_ms(r, 'fnr_at_0.5', True)} | "
                     f"{_ms(r, 'fpr_at_0.5', True)} |")
    ok = runs[(runs["status"] == "ok") & (runs["model"] == "XGBoost")]
    rec = pd.DataFrame([{"group": r.group, **json.loads(r.category_recall)} for r in ok.itertuples()])
    if not rec.empty:
        rec = rec.groupby("group").mean().reindex(list(DESCRIPTIONS)).dropna(how="all")
        L += ["", "## 3. 各攻击类召回（XGBoost，选定阈值，3 种子均值）", "",
              "| 组 | " + " | ".join(rec.columns) + " |", "|---|" + "---:|" * len(rec.columns)]
        for g, r in rec.iterrows():
            L.append(f"| {g} | " + " | ".join(f"{100 * v:.1f}%" for v in r) + " |")
    L += ["", "## 4. gain 重要性前 5（XGBoost，首个种子）与捷径检查", "", "| 组 | 前 5 | top1/top2 |", "|---|---|---:|"]
    for g in DESCRIPTIONS:
        r = ok[(ok["group"] == g) & (ok["seed"] == SEEDS[0])]
        if not r.empty:
            top = list(json.loads(r.iloc[0]["top15_gain"]))[:5]
            L.append(f"| {g} | {'、'.join(f'`{t}`' for t in top)} | {float(r.iloc[0]['top1_over_top2']):.1f} |")
    L += ["", "top1/top2 ≥ 10 视为疑似分裂捷径（v3.1 的 `sttl` 为 30 倍）。", ""]
    return "\n".join(L + render_tail(s, gen))


def render_tail(s: pd.DataFrame, gen: pd.DataFrame | None) -> list[str]:
    """报告后半：F2→F3 观测点代价、F5 验证集门槛检查、D2 泛化对照。"""
    L = ["## 5. 观测点变化的代价与 G1 参考", ""]
    x = s[s["model"] == "XGBoost"].set_index("group")
    if {"F2", "F3"} <= set(x.index):
        d = x.loc["F3", "macro_f1_mean"] - x.loc["F2", "macro_f1_mean"]
        L.append(f"- F2→F3（`ct_*` 换成单主机重算值）XGBoost ΔMacro-F1 = {d:+.4f}"
                 f"{'，下降超过 0.02' if d < -0.02 else ''}。")
    checks = gate_check(s)
    if checks:
        L += ["- F5（v4 候选）XGBoost 验证集对照训练计划 §1 门槛（G1 参考；holdout 判定留到阶段 2）：", "",
              "| 指标 | 实测 | 门槛 | 结果 |", "|---|---:|---:|---|"]
        for c in checks:
            pct = c["metric"] in ("fnr", "fpr", "fnr_std")
            v = f"{100 * c['value']:.2f}%" if pct else f"{c['value']:.4f}"
            b = f"{100 * c['bound']:.1f}%" if pct else f"{c['bound']:.2f}"
            L.append(f"| {c['metric']} | {v} | {c['op']} {b} | {'通过' if c['passed'] else '未通过'} |")
    if gen is not None and not gen.empty:
        L += ["", "## 6. 泛化对照（D1 训练，D1/D2 验证分区，阈值 0.5，只作报告）", "",
              "| 公共特征 | 测试 | Macro-F1 | ROC-AUC | FNR | FPR |", "|---|---|---:|---:|---:|---:|"]
        for r in gen.itertuples():
            L.append(f"| {r.view} | {r.test} | {r.macro_f1:.4f} | {r.roc_auc:.4f} | {100 * r.fnr:.2f}% | "
                     f"{100 * r.fpr:.2f}% |")
    return L + [""]


def generalization(manifest: dict[str, Any], d1: SplitIndex, d2: SplitIndex) -> pd.DataFrame:
    """D1 公共特征（含 TTL 与不含 TTL）训练 LightGBM，在 D1、D2 验证分区上评估。不读 holdout。"""
    import lightgbm
    from lightgbm import LGBMClassifier
    from sklearn.metrics import roc_auc_score

    from .preprocess import RF_JOBS

    views = {"含 TTL（9 项）": list(COMMON_FEATURES),
             "不含 TTL（7 项）": [c for c in COMMON_FEATURES if c not in ("min_ttl", "max_ttl")]}
    raw1 = load_cached("d1_raw.parquet", manifest, columns=D1_COMMON_COLUMNS)
    raw2 = load_cached("d2.parquet", manifest, columns=D2_COMMON_SOURCE_COLUMNS)
    part = lambda raw, rows, fn: (fn(raw.iloc[np.sort(rows)]), raw["Label"].to_numpy()[np.sort(rows)].astype(np.int8))  # noqa: E731
    x1t, y1t = part(raw1, d1.train, common_view_d1)
    x1v, y1v = part(raw1, d1.validation, common_view_d1)
    x2v, y2v = part(raw2, d2.validation, common_view_d2)
    del raw1, raw2
    gc.collect()
    rows = []
    for name, cols in views.items():
        p = dict(SCREEN_PARAMS["LightGBM"])
        early = int(p.pop("early_stopping_rounds"))
        model = LGBMClassifier(random_state=GLOBAL_SEED, n_jobs=RF_JOBS, verbose=-1, **p)
        model.fit(x1t[cols].to_numpy(np.float32), y1t, eval_set=[(x1v[cols].to_numpy(np.float32), y1v)],
                  eval_metric="binary_logloss", callbacks=[lightgbm.early_stopping(early, verbose=False)])
        for test, x, y in (("D1 验证", x1v, y1v), ("D2 验证", x2v, y2v)):
            prob = model.predict_proba(x[cols].to_numpy(np.float32))[:, 1]
            m = binary_metrics(y, prob, 0.5)
            rows.append({"view": name, "test": test, "rows": int(len(y)), "macro_f1": m["macro_f1"],
                         "roc_auc": float(roc_auc_score(y, prob)), "fnr": m["fnr"], "fpr": m["fpr"]})
        del model
        gc.collect()
    return pd.DataFrame(rows)


def run(seed: int = GLOBAL_SEED, resume: Path | None = None, split_dir: Path | None = None,
        audit_dir: Path | None = None, manifest_path: Path | None = None) -> Path:
    """执行第 5、6 项。输出 ``feature-ablation-*/``：逐次结果、汇总、G1 参考检查、泛化对照与报告。"""
    manifest_file, manifest = load_manifest(manifest_path)
    split_dir = Path(split_dir) if split_dir else latest_split_dir()
    if audit_dir is None:
        found = sorted(RUNS_ROOT.glob("feature-audit-*/recomputed-cache.json"))
        if not found:
            raise FileNotFoundError("no feature-audit run found; run `python -m cyber_training.v2 feature-audit` first")
        audit_dir = found[-1].parent
    audit_dir = Path(audit_dir)
    view_dir, params_dir = RUNS_ROOT / VIEW_RUN, RUNS_ROOT / PARAMS_RUN
    for d in (view_dir, params_dir):
        if not d.is_dir():
            raise FileNotFoundError(f"required run directory missing: {d.name}")
    v3 = json.loads((view_dir / "feature-views.json").read_text(encoding="utf-8"))["views"]["V3"]
    selection = json.loads((params_dir / "model-selection.json").read_text(encoding="utf-8"))
    params = {"XGBoost": dict(selection["params"]["XGBoost"]), "LightGBM": dict(SCREEN_PARAMS["LightGBM"])}
    groups = define_groups(v3)
    if resume:
        run_dir = Path(resume)
    else:
        run_dir = RunContext("feature-ablation", seed, {
            "register_manifest": str(manifest_file), "split_dir": str(split_dir), "audit_dir": str(audit_dir),
            "view_run": VIEW_RUN, "params_run": PARAMS_RUN, "seeds": list(SEEDS), "models": list(MODELS),
            "params": params, "scheme": "P1", "gates": GATES}).run_dir
    log = run_dir / "training.log"

    def say(message: str) -> None:
        with log.open("a", encoding="utf-8") as stream:
            stream.write(message + "\n")
        print(message, flush=True)

    split = SplitIndex.load(split_dir / "split-d1-raw.npz")  # 不传审计日志：holdout 无法解锁
    d2 = SplitIndex.load(split_dir / "split-d2.npz")
    runs_csv, gen_csv = run_dir / "ablation-runs.csv", run_dir / "generalization-validation.csv"
    done = completed(runs_csv)
    with keep_awake():
        frame, labels, cats, ready = load_frame(manifest, audit_dir)
        train = np.sort(split.train[ready[split.train]])
        val = np.sort(split.validation[ready[split.validation]])
        y_train, y_val = labels[train], labels[val]
        cats_val = cats.iloc[val].reset_index(drop=True)
        info = {"train_rows": int(train.size), "val_rows": int(val.size),
                "features": {g: len(spec) for g, spec in groups.items()}}
        write_json(run_dir / "ablation-info.json",
                   {**info, "groups": {g: [f"{c}:{s}" for c, s in spec] for g, spec in groups.items()}})
        for g, spec in groups.items():
            todo = [(m, s) for m in MODELS for s in SEEDS if (g, m, s) not in done]
            if not todo:
                continue
            say(f"{g}: building P1 matrices ({len(spec)} features)")
            data = build_matrices(frame, spec, train, val, GLOBAL_SEED)
            for m, s in todo:
                try:
                    row = fit_one(g, m, s, params[m], data, y_train, y_val, cats_val, [c for c, _ in spec])
                except Exception as exc:  # 单组失败记录后继续，--resume 只重跑失败项
                    row = {"group": g, "model": m, "seed": s, "status": "failed", "error": repr(exc)[:500]}
                append_row(runs_csv, row)
                say(f"{g} {m} {s} {row['status']} macro_f1={row.get('macro_f1', float('nan')):.4f}")
            del data
            gc.collect()
        del frame
        gc.collect()
        if not gen_csv.exists():
            say("generalization on D1/D2 validation partitions")
            generalization(manifest, split, d2).to_csv(gen_csv, index=False)
    runs, gen = pd.read_csv(runs_csv), pd.read_csv(gen_csv)
    summary = summarize(runs)
    summary.to_csv(run_dir / "ablation-summary.csv", index=False)
    write_json(run_dir / "g1-gate-check.json", gate_check(summary))
    (run_dir / "feature-ablation.md").write_text(render(runs, gen, info), encoding="utf-8")
    RunContext.checksum_dir(run_dir)
    say(f"done: {run_dir}")
    return run_dir
