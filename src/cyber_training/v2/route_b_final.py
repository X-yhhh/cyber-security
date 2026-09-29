"""路线 B 阶段 2 第 9 步：v4 T1 候选的冻结与锁定评估（命令 ``final-v4 --final-stage freeze|evaluate``）。

与 v2 ``final_eval`` 的差异：只有 T1 二分类，不含 T2；冻结文件单独放在 ``docs/route-b/pre-final-freeze-v4.json``；
特征帧用 ``route_b_v4.load_frame``。其余规则不变：冻结不读 holdout；评估要求冻结文件已提交且无改动；
同一切分的 holdout 只解锁一次并写追加式审计日志；门槛沿用训练计划 §1，不调整。
"""

from __future__ import annotations

import gc
import json
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from . import GLOBAL_SEED
from ..config import ROOT
from .datasets import load_manifest
from .final_eval import (AUDIT_LOG, EXPORT_GATES, HOLDOUT_GATES, SEED_GATE, FreezeError, T1Model, _git, _logger, _rel,
                         category_recall, check_reproduction, full_binary_metrics, generalization, judge, plot_curves,
                         plot_sensitivity, require_first_unlock, threshold_sensitivity, verify_files)
from .guard import HoldoutLockedError, LeakageError, SplitIndex
from .preprocess import binary_metrics
from .route_b_v4 import CONTRACT_VERSION, SPEC_SHA256, VIEW, load_frame
from .runtime import RUNS_ROOT, RunContext, keep_awake, sha256_file, write_json

FREEZE_REL = "docs/route-b/pre-final-freeze-v4.json"
FREEZE_FILE = ROOT / FREEZE_REL
THRESHOLD_POLICY = "验证集上 FNR ≤ 4% 的阈值中 FPR 最小者"


def find_candidate() -> Path:
    """最新一次候选视图为 v4 的多种子复现运行；v2 的候选不会被选中。"""
    for path in sorted(RUNS_ROOT.glob("train-seeds-*/candidate/candidate.json"), reverse=True):
        if json.loads(path.read_text(encoding="utf-8")).get("view") == VIEW:
            return path.parent.parent
    raise FreezeError("no train-seeds run with a v4 candidate")


def find_split(fingerprint: str) -> Path:
    for path in sorted(RUNS_ROOT.glob("split-v4-*/split-audit.json"), reverse=True):
        if json.loads(path.read_text(encoding="utf-8"))["split-d1-raw.npz"]["fingerprint"] == fingerprint:
            return path.parent
    raise LeakageError("candidate split fingerprint matches no split-v4 run")


def freeze(t1_dir: Path | None = None) -> Path:
    """冻结 v4 T1 候选：校验制品、在验证分区复现指标并写冻结文件。不读 holdout；已有冻结文件时拒绝覆盖。"""
    from sklearn.metrics import average_precision_score, roc_auc_score

    from .train import evaluate

    if FREEZE_FILE.exists():
        raise FreezeError(f"{FREEZE_REL} already exists; a new attempt needs a new split seed")
    t1_dir = Path(t1_dir) if t1_dir else find_candidate()
    cand_json = t1_dir / "candidate" / "candidate.json"
    t1 = json.loads(cand_json.read_text(encoding="utf-8"))
    if t1["view"] != VIEW:
        raise FreezeError(f"candidate view {t1['view']} is not {VIEW}")
    split_dir = find_split(t1["split_fingerprint"])
    audit = json.loads((split_dir / "split-audit.json").read_text(encoding="utf-8"))
    manifest_file, manifest = load_manifest()
    split = SplitIndex.load(split_dir / "split-d1-raw.npz")  # 不传审计日志：holdout 无法解锁
    frame, labels, _, _ = load_frame(manifest)
    model = T1Model(t1["model"], t1_dir / "candidate", t1["files"])
    val = np.sort(split.validation)
    prob, y = model.predict(frame.iloc[val][t1["columns"]]), labels[val]
    del frame, model
    gc.collect()
    m = binary_metrics(y, prob, t1["threshold"])
    actual = {"macro_f1": m["macro_f1"], "fnr": m["fnr"], "fpr": m["fpr"],
              "pr_auc": float(average_precision_score(y, prob)), "auc": float(roc_auc_score(y, prob))}
    repro = check_reproduction(t1["validation_metrics"], actual)
    seed = pd.read_csv(t1_dir / "seed-summary.csv").set_index("model").loc[t1["model"]]
    keys = ("model", "seed", "params", "best_iteration", "scheme", "view", "columns", "threshold", "files",
            "validation_metrics")
    record = {
        "frozen_at": datetime.now().astimezone().isoformat(), "base_commit": _git("rev-parse", "HEAD"),
        "contract": {"version": CONTRACT_VERSION, "spec_sha256": SPEC_SHA256},
        "register_manifest": {"file": _rel(manifest_file), "sha256": sha256_file(manifest_file)},
        "split": {"dir": _rel(split_dir), "seed": audit["d1_raw"]["selected_seed"],
                  "d1_raw_fingerprint": t1["split_fingerprint"], "d2_fingerprint": audit["split-d2.npz"]["fingerprint"],
                  "split_audit_sha256": sha256_file(split_dir / "split-audit.json")},
        "attempt": 1,
        "t1": {**{k: t1[k] for k in keys}, "source_run": t1_dir.name, "threshold_policy": THRESHOLD_POLICY,
               "decision": "prob >= threshold → Attack", "label_mapping": {"0": "Normal", "1": "Attack"},
               "candidate_json_sha256": sha256_file(cand_json), "validation_reproduction": repro,
               "cpu_reselected_threshold": evaluate(y, prob)["threshold"],
               "seed_fnr_std": float(seed["fnr_std"]), "seed_runs": int(seed["n"])},
        "gates": {"holdout": [dict(zip(("metric", "name", "op", "threshold"), g)) for g in HOLDOUT_GATES],
                  "validation": dict(zip(("metric", "name", "op", "threshold"), SEED_GATE)),
                  "deferred_to_export": list(EXPORT_GATES)},
        "holdout_read": False, "note": "冻结时未读取 holdout；权重与预处理器不提交，只记录 SHA-256。",
    }
    FREEZE_FILE.parent.mkdir(parents=True, exist_ok=True)
    write_json(FREEZE_FILE, record)
    return FREEZE_FILE


def load_freeze() -> tuple[dict[str, Any], str]:
    """读取 v4 冻结文件，要求已提交且无未提交改动；返回 (记录, 文件 SHA-256)。"""
    if not FREEZE_FILE.is_file():
        raise FreezeError(f"{FREEZE_REL} is missing; run final-v4 --final-stage freeze and commit it first")
    if not _git("ls-files", FREEZE_REL) or _git("status", "--porcelain", "--", FREEZE_REL):
        raise FreezeError(f"{FREEZE_REL} is not committed or has uncommitted changes")
    return json.loads(FREEZE_FILE.read_text(encoding="utf-8")), sha256_file(FREEZE_FILE)


def _num(v: Any) -> str:
    return f"{v:.4f}" if isinstance(v, (int, float)) else str(v)


def write_report(run_dir: Path, verdict: dict[str, Any], metrics: dict[str, Any], table: pd.DataFrame | None) -> None:
    L = ["# 路线 B 阶段 2 第 9 步：v4 锁定评估", "",
         f"冻结文件 `{FREEZE_REL}`（SHA-256 `{verdict['freeze_sha256'][:12]}…`），第 {verdict['attempt']} 次尝试。"
         f"holdout {metrics['rows']:,} 行（攻击 {metrics['attack_rows']:,}），只读取这一次；阈值 {verdict['threshold']:.6f} 在验证集上选定。",
         "", "| 门槛 | 实测 | 要求 | 结果 |", "|---|---:|---:|---|"]
    for g in [*verdict["gates"], verdict["validation_gate"]]:
        L.append(f"| {g.get('name', g.get('metric'))} | {_num(g.get('value'))} | {g.get('op')} {g.get('threshold')} | "
                 f"{'通过' if g.get('passed') else '未通过'} |")
    L += ["", f"第 9 步判定：**{'通过' if verdict['passed_step9'] else '未通过'}**。延迟、吞吐与 ONNX 一致性在第 10 步判定。", ""]
    if table is not None:
        L += ["## 泛化对照（公共特征，阈值 0.5，只作报告）", "", "| 训练 | 测试 | Macro-F1 | ROC-AUC | FNR | FPR |",
              "|---|---|---:|---:|---:|---:|"]
        L += [f"| {r.train} | {r.test} | {r.macro_f1:.4f} | {r.roc_auc:.4f} | {100 * r.fnr:.2f}% | {100 * r.fpr:.2f}% |"
              for r in table.itertuples()]
    (run_dir / "final-evaluation.md").write_text("\n".join(L) + "\n", encoding="utf-8")


def run_evaluate(unlock_holdout: bool) -> Path:
    """锁定评估：新切分的 holdout 只读一次，按训练计划 §1 判定；泛化对照只写报告。"""
    if not unlock_holdout:
        raise HoldoutLockedError("final-v4 evaluate requires --unlock-holdout")
    record, freeze_sha = load_freeze()
    manifest_file, manifest = load_manifest()
    if sha256_file(manifest_file) != record["register_manifest"]["sha256"]:
        raise FreezeError("register manifest changed since freeze")
    split_dir = ROOT / record["split"]["dir"]
    if sha256_file(split_dir / "split-audit.json") != record["split"]["split_audit_sha256"]:
        raise FreezeError("split audit changed since freeze")
    t1 = record["t1"]
    candidate = RUNS_ROOT / t1["source_run"] / "candidate"
    verify_files(candidate, t1["files"])
    d1 = SplitIndex.load(split_dir / "split-d1-raw.npz", audit_log=AUDIT_LOG)
    d2 = SplitIndex.load(split_dir / "split-d2.npz", audit_log=AUDIT_LOG)
    if d1.fingerprint != record["split"]["d1_raw_fingerprint"]:
        raise LeakageError("D1 split changed since freeze")
    for s in (d1, d2):
        require_first_unlock(s.fingerprint)
    ctx = RunContext("final-eval-v4", GLOBAL_SEED, {"freeze_file": FREEZE_REL, "freeze_sha256": freeze_sha,
                                                     "candidate": t1["model"], "attempt": record["attempt"]})
    run_dir, say = ctx.run_dir, _logger(ctx.run_dir / "training.log")
    reason = f"路线 B v4 锁定评估（第 {record['attempt']} 次），冻结文件 {freeze_sha[:12]}，运行 {run_dir.name}"
    with keep_awake():
        frame, labels, cats, _ = load_frame(manifest)
        d1.unlock_holdout(reason)
        rows = np.sort(d1.holdout)
        model = T1Model(t1["model"], candidate, t1["files"])
        prob, y, thr = model.predict(frame.iloc[rows][t1["columns"]]), labels[rows], float(t1["threshold"])
        del frame, model
        gc.collect()
        metrics = full_binary_metrics(y, prob, thr)
        gates = judge(metrics)
        seed_gate = judge({"fnr_std": t1["seed_fnr_std"]}, (SEED_GATE,))[0]
        category_recall(cats.iloc[rows], prob, thr).to_csv(run_dir / "t1-holdout-category-recall.csv", index=False)
        sens = threshold_sensitivity(y, prob, thr)
        sens.to_csv(run_dir / "t1-threshold-sensitivity.csv", index=False)
        plot_curves(y, prob, thr, run_dir / "t1-roc-pr.png")
        plot_sensitivity(sens, thr, run_dir / "t1-threshold-sensitivity.png")
        write_json(run_dir / "t1-holdout-metrics.json", metrics)
        passed = all(g["passed"] for g in gates) and seed_gate["passed"]
        say(f"v4 holdout macro_f1={metrics['macro_f1']:.4f} fnr={metrics['fnr']:.4f} fpr={metrics['fpr']:.4f} passed={passed}")
        verdict = {"freeze_file": FREEZE_REL, "freeze_sha256": freeze_sha, "attempt": record["attempt"], "run": run_dir.name,
                   "candidate": t1["model"], "threshold": t1["threshold"], "holdout_rows": metrics["rows"],
                   "gates": gates, "validation_gate": seed_gate, "deferred_to_export": list(EXPORT_GATES),
                   "passed_step9": passed, "deliverable": "pending_export" if passed else "rejected"}
        write_json(run_dir / "final-verdict.json", verdict)
        table = None
        try:
            d2.unlock_holdout(f"{reason}：泛化对照")
            table = generalization(manifest, d1, d2, run_dir, say)
        except Exception as exc:  # 泛化只写报告，失败不影响判定
            say(f"generalization failed: {type(exc).__name__}: {exc}")
    write_report(run_dir, verdict, metrics, table)
    ctx.finish()
    return run_dir
