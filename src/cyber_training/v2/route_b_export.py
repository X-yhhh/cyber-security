"""路线 B 阶段 2 第 10 步：v4 候选导出为单一 ONNX 图，生成 golden fixtures 与交付包（命令 ``export-v4``）。

复用 ``export`` 的图构造、一致性与性能检查。差异：``flow_numeric`` 列顺序按规格 §2.1；训练端输入为 CSV 原始值
（``sload``/``dload`` 按规格 §4 置 0）+ 单主机重算 ``ct_*`` + 端口口径 ``service``；manifest 写入 v4 契约、
规格哈希、消融引用、fixtures 与 v4 能力边界。前置条件：v4 冻结文件已提交、第 9 步判定通过；一致性校验只用验证分区。
"""

from __future__ import annotations

import json
import shutil
from dataclasses import replace
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from . import GLOBAL_SEED
from ..config import ROOT
from .datasets import DataIntegrityError, load_cached, load_manifest
from .export import (DELIVERY_ROOT, INPUT_CATEGORICAL, INPUT_NUMERIC, MODEL_KEY, OPSET, OUTPUT_PROB, PARITY_ROWS,
                     ExportError, benchmark, build_manifest, build_model, contract_from, judge_export, package, parity,
                     preprocessing_contract, session, write_replay, write_report)
from .features import SUBSET_TO_RAW, V1_RAW_COLUMNS, build_v2
from .final_eval import FreezeError, T1Model, _git, _logger, _rel, verify_files
from .guard import LeakageError, SplitIndex
from .route_b_final import FREEZE_REL, load_freeze
from .route_b_fixtures import build as build_fixtures
from .route_b_v4 import (ABLATION_RUN, AUDIT_RUN, CATEGORICAL, CONTRACT_VERSION, CT_V4, NUMERIC, REMOVED, SPEC_DOCUMENT,
                         SPEC_SHA256)
from .runtime import RUNS_ROOT, RunContext, keep_awake, sha256_file, write_json

DEFAULT_VERSION = "2026.10.0"
V4_FIELDS = {
    "dur": ("秒", "末包时间 − 首包时间"), "sbytes": ("字节", "initiator→responder IP 字节和"),
    "dbytes": ("字节", "responder→initiator IP 字节和"),
    "sload": ("比特/秒", "sbytes×8×(spkts−1)/spkts/dur；spkts≤1 或 dur=0 时为 0"),
    "dload": ("比特/秒", "dbytes×8×(dpkts−1)/dpkts/dur；dpkts≤1 或 dur=0 时为 0"),
    "tcprtt": ("秒", "synack + ackdat；非 TCP 或握手不完整时为 0"), "ackdat": ("秒", "SYN-ACK → 其后首个纯 ACK"),
    "synack": ("秒", "首个纯 SYN → 首个 SYN-ACK"), "smean": ("字节", "round(sbytes/spkts)"),
    "dmean": ("字节", "round(dbytes/dpkts)"), "spkts": ("包", "initiator→responder 包数"),
    "dpkts": ("包", "responder→initiator 包数"),
    "ct_srv_src": ("条", "本机窗口内 service 与源地址都相同的流数"), "ct_srv_dst": ("条", "本机窗口内 service 与目的地址都相同的流数"),
    "ct_dst_ltm": ("条", "本机窗口内目的地址相同的流数"), "ct_src_ltm": ("条", "本机窗口内源地址相同的流数"),
    "ct_src_dport_ltm": ("条", "本机窗口内源地址与目的端口都相同的流数"),
    "proto": ("类别", "IANA 协议号关键字（小写）"), "service": ("类别", "按 responder 端口固定映射，未命中为 -"),
}
INPUT_RULES = [
    f"字段按 {SPEC_DOCUMENT}（SHA-256 {SPEC_SHA256[:12]}…）计算；数值字段均不可为空，出现 NaN、±Inf 或负数时拒绝推理，不得补值。",
    "ct_* 来自本机单主机窗口（每个地址族最近 100 条已完成流，含当前流）；窗口未满时不推理，状态记 window_not_ready。",
    "首个模型只评估 IPv4 且本机为 responder 的流；IPv6 与出站流记 not_in_model_scope，不送推理。",
    "类别词表外取值在图内编码为 -1，后端记录为漂移信号，不拒绝记录；后端不得自行插补、编码或调整阈值。",
]


def recomputed() -> pd.DataFrame:
    meta = json.loads((RUNS_ROOT / AUDIT_RUN / "recomputed-cache.json").read_text(encoding="utf-8"))
    cache = RUNS_ROOT / AUDIT_RUN / meta["file"]
    if sha256_file(cache) != meta["sha256"]:
        raise DataIntegrityError(f"SHA-256 mismatch for {cache.name}")
    return pd.read_parquet(cache)


def contract_inputs(raw: pd.DataFrame, re: pd.DataFrame) -> tuple[dict[str, np.ndarray], pd.DataFrame]:
    """由同一组值构造 ONNX 输入（float64，列顺序 = NUMERIC）与训练视图帧，用于一致性校验与回放样本。"""
    raw, re = raw.reset_index(drop=True).copy(), re.reset_index(drop=True)
    for load, pkts in (("Sload", "Spkts"), ("Dload", "Dpkts")):
        raw.loc[(raw["dur"].to_numpy() <= 0) | (raw[pkts].to_numpy() <= 1), load] = 0.0
    view = build_v2(raw).reset_index(drop=True)
    for c in CT_V4:
        view[c] = re[f"{c}_v4"].to_numpy(dtype=np.float32)
    view["service"] = pd.Series(re["service_v4"].to_numpy(), dtype="string")
    src = {f: raw[SUBSET_TO_RAW[f]].to_numpy(dtype=np.float64) for f in NUMERIC if f not in CT_V4}
    src.update({c: re[f"{c}_v4"].to_numpy(dtype=np.float64) for c in CT_V4})
    categorical = np.column_stack([raw["proto"].astype("string").fillna("").to_numpy(dtype=object),
                                   re["service_v4"].to_numpy(dtype=object)]).astype(str)
    return {INPUT_NUMERIC: np.column_stack([src[f] for f in NUMERIC]), INPUT_CATEGORICAL: categorical}, view


def validation_sample(record: dict[str, Any], manifest: dict[str, Any], re_all: pd.DataFrame, size: int = PARITY_ROWS
                      ) -> tuple[pd.DataFrame, pd.DataFrame, np.ndarray]:
    split = SplitIndex.load(ROOT / record["split"]["dir"] / "split-d1-raw.npz")  # 不传审计日志：holdout 无法解锁
    if split.fingerprint != record["split"]["d1_raw_fingerprint"]:
        raise LeakageError("D1 split changed since freeze")
    rows = np.sort(np.random.default_rng(GLOBAL_SEED).choice(split.validation, size=size, replace=False))
    raw = load_cached("d1_raw.parquet", manifest, columns=[*V1_RAW_COLUMNS, "Label"]).iloc[rows]
    return raw, re_all.iloc[rows], raw["Label"].to_numpy(dtype=np.int8)


def load_verdict(freeze_sha: str, t1: dict[str, Any]) -> Path:
    for path in sorted(RUNS_ROOT.glob("final-eval-v4-*/final-verdict.json"), reverse=True):
        v = json.loads(path.read_text(encoding="utf-8"))
        if v.get("freeze_sha256") != freeze_sha:
            continue
        if not v.get("passed_step9"):
            raise ExportError("step 9 did not pass for this freeze; no export")
        if v["candidate"] != t1["model"] or v["threshold"] != t1["threshold"]:
            raise ExportError("final-verdict.json candidate/threshold differ from the freeze")
        return path.parent
    raise ExportError("no v4 final-verdict.json for this freeze")


def v4_preprocessing(contract: Any) -> dict[str, Any]:
    pc = preprocessing_contract(contract)
    pc["contract_version"], pc["spec"] = CONTRACT_VERSION, {"document": SPEC_DOCUMENT, "sha256": SPEC_SHA256}
    for key in (INPUT_NUMERIC, INPUT_CATEGORICAL):
        for f in pc["inputs"][key]["fields"]:
            unit, f["description"] = V4_FIELDS[f["name"]]
            if key == INPUT_NUMERIC:
                f.update(unit=unit, nullable=False)
    pc["input_rules"] = INPUT_RULES
    return pc


def limitations(verdict_dir: Path) -> list[str]:
    cats = pd.read_csv(verdict_dir / "t1-holdout-category-recall.csv")
    weak = cats[cats["attack_cat"] != "Normal"].sort_values("recall").head(2)
    worst = "、".join(f"{r.attack_cat}（{100 * r.recall:.1f}%）" for r in weak.itertuples())
    return [
        "只适用于 UNSW-NB15 分布的流量特征二分类；跨数据集（NF-ToN-IoT-v2）评估接近随机，不能直接用于其他网络环境。",
        "不含 TTL 类特征；ct_* 为单主机视角（本机最近 100 条已完成流）；只覆盖传感器可见流量，不代表全网观测。",
        "首个模型只评估 IPv4、本机为 responder 的入站流；以出站为主的终端覆盖率低，此时规则研判是主要手段。",
        "ct_* 的判别力依赖攻击流量的突发程度；UNSW 上无法检验对未见过主机的效果，须由影子验证确认。",
        "service 只按标准端口映射；非标准端口服务、被动 FTP 数据连接与 QUIC 记为 -。",
        f"holdout 上召回最低的攻击类：{worst}。",
        "输入字段缺失、单位不符或非法数值时必须拒绝推理并转人工/规则研判，不得静默造值；后端不得调整阈值。",
        "模型权重在线冻结；再训练只能在离线训练环境按计划执行并重新审批。",
    ]


def run(version: str = DEFAULT_VERSION) -> Path:
    """执行 v4 第 10 步。门槛全部通过时写 ``delivery/unsw-binary-<version>/``（含 fixtures）；同版本已存在即拒绝。"""
    import onnx

    record, freeze_sha = load_freeze()
    t1 = record["t1"]
    if t1["model"] != "XGBoost":
        raise ExportError(f"export supports the frozen XGBoost candidate only, got {t1['model']}")
    verdict_dir = load_verdict(freeze_sha, t1)
    delivery = DELIVERY_ROOT / f"{MODEL_KEY}-{version}"
    if delivery.exists():
        raise FileExistsError(f"delivery directory already exists: {_rel(delivery)}")
    manifest_file, manifest = load_manifest()
    if sha256_file(manifest_file) != record["register_manifest"]["sha256"]:
        raise FreezeError("register manifest changed since freeze")
    candidate_dir = RUNS_ROOT / t1["source_run"] / "candidate"
    verify_files(candidate_dir, t1["files"])
    ctx = RunContext("export-v4", GLOBAL_SEED, {"freeze_file": FREEZE_REL, "freeze_sha256": freeze_sha, "version": version,
                                                 "contract": CONTRACT_VERSION, "parity_rows": PARITY_ROWS, "opset": OPSET})
    run_dir, say = ctx.run_dir, _logger(ctx.run_dir / "training.log")
    with keep_awake():
        model = T1Model(t1["model"], candidate_dir, t1["files"])
        base = contract_from(model.preprocessor, t1["columns"], t1["threshold"])
        if set(base.numeric_fields) != set(NUMERIC) or tuple(base.categorical_fields) != CATEGORICAL:
            raise ExportError(f"candidate inputs differ from the v4 contract: {base.numeric_fields}")
        contract = replace(base, numeric_fields=NUMERIC)
        onx, debug = build_model(contract, model.impl), build_model(contract, model.impl, debug_features=True)
        model_bytes = onx.SerializeToString()
        (run_dir / "model.onnx").write_bytes(model_bytes)
        re_all = recomputed()
        raw, re, labels = validation_sample(record, manifest, re_all)
        inputs, view = contract_inputs(raw, re)
        ref_features = model.preprocessor.transform(view[t1["columns"]]).astype(np.float32)
        ref_prob = model.predict(view[t1["columns"]]).astype(np.float64)
        result, prob, decision = parity(session(debug.SerializeToString()), inputs, ref_prob, ref_features, contract.threshold)
        if not np.array_equal(session(model_bytes).run([OUTPUT_PROB], inputs)[0], prob.astype(np.float32)):
            raise ExportError("delivery graph output differs from the debug graph")
        say(f"parity max_abs_diff={result['parity_max_abs_diff']:.3e} agreement={result['parity_decision_agreement']}")
        perf = {"threads": 1, **benchmark(session(model_bytes, threads=1), inputs)}
        gates = judge_export({**result, **perf})
        passed = all(g["passed"] for g in gates)
        write_json(run_dir / "export-parity.json", result)
        write_json(run_dir / "export-performance.json", perf)
        write_json(run_dir / "preprocessing.json", v4_preprocessing(contract))
        write_replay(run_dir / "replay-sample.csv", inputs, contract, prob, decision, labels)
        fixtures = build_fixtures(manifest, ROOT / record["split"]["dir"], re_all["excluded"].to_numpy(dtype=bool),
                                  re_all["ct_src_ltm_v4"].to_numpy(dtype=np.float64), session(model_bytes),
                                  run_dir / "fixtures")
        del re_all
        say(f"fixtures: {fixtures['flows']} flows, {fixtures['scored']} scored, missing={fixtures['missing_coverage']}")
        files = {n: sha256_file(run_dir / n) for n in ("model.onnx", "preprocessing.json", "replay-sample.csv")}
        train_cfg = json.loads((RUNS_ROOT / t1["source_run"] / "run-config.json").read_text(encoding="utf-8"))
        m = build_manifest(version, record, verdict_dir, contract, files, gates, perf, result,
                           train_cfg["git"]["commit"], _git("rev-parse", "HEAD"), len(model_bytes))
        m["feature_contract"].update({
            "version": CONTRACT_VERSION, "spec_document": SPEC_DOCUMENT, "spec_sha256": SPEC_SHA256,
            "inputs": {INPUT_NUMERIC: [{"name": f, "unit": V4_FIELDS[f][0]} for f in NUMERIC],
                       INPUT_CATEGORICAL: list(CATEGORICAL)},
            "removed_fields": REMOVED, "supported_viewpoints": ["responder"], "supported_address_families": ["ipv4"],
            "window": {"size": 100, "scope": "per_sensor_per_address_family", "includes_current_flow": True}})
        m["dataset"]["split"] = {"seed": record["split"]["seed"], "fingerprint": record["split"]["d1_raw_fingerprint"],
                                 "split_audit_sha256": record["split"]["split_audit_sha256"],
                                 "holdout_attempt": record["attempt"]}
        m["evaluation"]["ablation_ref"] = {"run": ABLATION_RUN,
                                           "report_sha256": sha256_file(RUNS_ROOT / ABLATION_RUN / "feature-ablation.md")}
        m["fixtures"] = fixtures
        m["provenance"].update({"freeze_file": FREEZE_REL, "freeze_sha256": freeze_sha,
                                "freeze_commit": _git("log", "-1", "--format=%H", "--", FREEZE_REL)})
        m["limitations"] = limitations(verdict_dir)
        m["export"] = {"run": run_dir.name, "passed": passed, "deliverable": "ready_for_review" if passed else "rejected"}
        write_json(run_dir / "model_manifest.json", m)
        write_json(run_dir / "export-verdict.json", {"freeze_sha256": freeze_sha, "run": run_dir.name, "gates": gates,
                                                      "passed_step10": passed, "deliverable": m["export"]["deliverable"]})
        write_report(run_dir / "evaluation-report.md", m, result, perf, gates, passed)
        onnx.checker.check_model(run_dir / "model.onnx", full_check=True)
    ctx.finish()
    if passed:
        package(run_dir, verdict_dir, delivery)
        shutil.copytree(run_dir / "fixtures", delivery / "fixtures")
        RunContext.checksum_dir(delivery)
        say(f"delivery written: {_rel(delivery)}")
    else:
        say("export gates failed; no delivery directory written")
    return run_dir
