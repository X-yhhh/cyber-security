"""路线 B 阶段 7：v4 训练切分的特征基线统计与 ``2026.10.1`` 交付（命令 ``baseline-v4``）。

影子验证与 M8 漂移要按 v4 原始输入字段计算 PSI，而 ``2026.10.0`` 的 manifest 没有基线块。本模块分三步：

- ``compute``：从原始 4 个 CSV 按登记（``register``）、``ct_*`` 重算（``feature_audit.recompute_ct``）与
  ``prepare-v4``（``route_b_v4``）的同一代码重建训练帧与切分，只在临时目录落 parquet（与训练端读缓存的路径一致），
  逐项核对原始文件哈希、数据指纹、切分指纹与切分审计内容；任一绑定项不符立即终止，不产出基线。
  通过后只在训练分区（模型拟合所用的全部行）上，按 ONNX 输入口径计算 ``feature_baseline_stats``（schema ``baseline-v1``）：
  float64 原始值，``sload``/``dload`` 按规格 §4 置 0，``ct_*`` 为训练端单主机重算值，``service`` 为端口口径。
- ``package``：新 manifest 由旧 manifest 深拷贝，只改版本号与时间并新增基线块和 ``provenance.derived_from``；
  其余制品逐字节复制（不重新导出 ONNX），重建 ``checksums.json``。
- ``verify``：交付自校验（哈希、manifest 只差允许字段、基线结构与后端解析规则一致、权限、无地址字面量）。

约束：不训练、不改权重/阈值/预处理。holdout 行位置只参与切分复现与审计核对（与 ``prepare-v4`` 相同），
不参与任何基线统计；基线只含分箱边界与计数，不含数据行或地址。
"""

from __future__ import annotations

import copy
import gc
import hashlib
import json
import math
import os
import platform
import re as regex
import shutil
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import numpy as np
import pandas as pd

from ..config import ROOT
from . import register
from .export import DELIVERY_ROOT, INPUT_CATEGORICAL, INPUT_NUMERIC, MODEL_KEY
from .feature_audit import RAW_COLUMNS, _classify, recompute_ct
from .features import V1_RAW_COLUMNS
from .guard import SplitIndex
from .route_b_export import contract_inputs
from .route_b_v4 import CATEGORICAL, NUMERIC, SPLIT_SEED, assemble_frame, split_d1
from .runtime import RUNS_ROOT, RunContext, git_commit, sha256_file, write_json

SCHEMA_VERSION = "baseline-v1"
METHOD = "train_partition_decile_bins"
NUMERIC_BINNING = "bin = count of edges strictly less than value; edges ascending and unique; bins = len(edges) + 1"
OTHER = "__other__"
PSI = {"epsilon": 0.0001, "warning": 0.2, "alert": 0.3, "min_samples": 200}
QUANTILES = tuple(i / 10 for i in range(1, 10))  # 0.1…0.9，逐个除法避免累加误差
MIN_CATEGORY_SHARE = 0.001
MAX_CATEGORY_KEY = 64  # 后端 FeatureBaseline 对类别键长度的上限
PROPORTION_TOLERANCE = 1e-6  # 与后端 FeatureBaseline 的比例和容差一致
AUDIT_FLOAT_RTOL = 1e-9  # 切分审计浮点项（比例、偏差）的相对容差；整数、字符串必须完全相等

SOURCE_VERSION = "2026.10.0"
TARGET_VERSION = "2026.10.1"
EXPECTED_ONNX_SHA256 = "c87b883d0ac32b0a827441eb5d97164acaa46e67653fb79cd369b9c794949358"
# 训练主机写出的归档证据（Git 中为 LF，训练主机工作区为 CRLF；manifest 记录的是 CRLF 字节的哈希）。
REGISTER_EVIDENCE = "docs/v2/evidence/register-20260926-2019-dataset-manifest.json"
SPLIT_AUDIT_EVIDENCE = "docs/route-b/evidence/stage2/split-audit.json"
RECOMPUTED_EVIDENCE = "docs/route-b/evidence/recomputed-cache.json"
FREEZE_FILE = "docs/route-b/pre-final-freeze-v4.json"
# 交付包中逐字节复制的文件/目录；export-*.json 另按通配匹配。manifest 与 checksums.json 由本步骤重写。
COPIED = ("model.onnx", "preprocessing.json", "replay-sample.csv", "evaluation-report.md", "fixtures", "evidence")
REWRITTEN = ("model_manifest.json", "checksums.json")
ALLOWED_DIFF = ("/model_version", "/version", "/created_at", "/feature_baseline_stats", "/provenance/derived_from")
DERIVED_CHANGE = "仅新增 feature_baseline_stats；权重、预处理、阈值、fixtures 不变"
IPV4_LITERAL = regex.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


class BaselineError(ValueError):
    """基线统计的输入或结构不满足 baseline-v1 约束。"""


class ReproductionError(RuntimeError):
    """切分或数据复现与已交付 manifest / 归档证据不一致；不得产出基线。"""


class DeliveryError(RuntimeError):
    """交付包构建或自校验失败。"""


# ---------------------------------------------------------------- 统计（纯函数，单测覆盖）

def decile_edges(values: Any) -> list[float]:
    """训练值在 0.1…0.9 分位点的分位数（``numpy.quantile``，``method="linear"``），去重后升序。

    只使用有限值；有限值全为同一值时去重后只剩 1 个边界（2 个箱，其中高箱计数为 0）；没有有限值时返回空数组（1 个箱）。
    """
    v = np.asarray(values, dtype=np.float64)
    v = v[np.isfinite(v)]
    if not v.size:
        return []
    return [float(e) for e in np.unique(np.quantile(v, QUANTILES, method="linear"))]


def bin_index(values: Any, edges: list[float]) -> np.ndarray:
    """箱号 = ``edges`` 中严格小于 v 的元素个数，即 ``searchsorted(edges, v, side="left")``；与后端 ``NumericField.bin`` 一致。"""
    return np.searchsorted(np.asarray(edges, dtype=np.float64), np.asarray(values, dtype=np.float64), side="left")


def numeric_stats(values: Any) -> dict[str, Any]:
    """单个数值字段的基线：``edges``、``counts``（和等于 ``count``）、``proportions`` 与 ``count``。

    出现 NaN/±Inf 即终止：v4 契约要求数值字段非空且有限，训练分区也不应出现；不静默丢弃。
    """
    v = np.asarray(values, dtype=np.float64)
    if not v.size:
        raise BaselineError("numeric field has no training values")
    if not np.isfinite(v).all():
        raise BaselineError(f"numeric field has {int((~np.isfinite(v)).sum())} non-finite training values")
    edges = decile_edges(v)
    counts = np.bincount(bin_index(v, edges), minlength=len(edges) + 1)
    total = int(v.size)
    if int(counts.sum()) != total:
        raise BaselineError("bin counts do not sum to the value count")
    return {"edges": edges, "counts": [int(c) for c in counts], "proportions": [float(c) / total for c in counts],
            "count": total}


def categorical_stats(values: Any, min_share: float = MIN_CATEGORY_SHARE) -> dict[str, Any]:
    """单个类别字段的基线：占比 ≥ ``min_share`` 的取值单独成键（按计数降序、取值升序），其余并入 ``__other__``。

    ``__other__`` 键始终存在（可为 0）。取值缺失、为空、超过后端键长上限或本身等于 ``__other__`` 时终止，不改写取值。
    """
    s = pd.Series(values, dtype="object")
    if not len(s):
        raise BaselineError("categorical field has no training values")
    if s.isna().any():
        raise BaselineError(f"categorical field has {int(s.isna().sum())} missing training values")
    s = s.astype(str)
    counts = s.value_counts(sort=False)
    total = int(counts.sum())
    kept = counts[counts / total >= min_share]
    for key in kept.index:
        if not key or len(key) > MAX_CATEGORY_KEY or key == OTHER:
            raise BaselineError(f"categorical key {key!r} cannot be written as a baseline key")
    ordered = sorted(kept.items(), key=lambda kv: (-int(kv[1]), kv[0]))
    out = {k: int(c) for k, c in ordered}
    out[OTHER] = total - sum(out.values())
    return {"counts": out, "proportions": {k: c / total for k, c in out.items()}, "count": total}


def build_baseline(numeric: dict[str, Any], categorical: dict[str, Any], source: dict[str, Any],
                   numeric_fields: tuple[str, ...] = NUMERIC, categorical_fields: tuple[str, ...] = CATEGORICAL
                   ) -> dict[str, Any]:
    """按 baseline-v1 的键序组装 ``feature_baseline_stats``。``numeric``/``categorical`` 为字段 → 原始取值。"""
    missing = sorted({*numeric_fields} ^ set(numeric)) + sorted({*categorical_fields} ^ set(categorical))
    if missing:
        raise BaselineError(f"baseline fields differ from the contract: {missing}")
    return {
        "schema_version": SCHEMA_VERSION, "method": METHOD, "source": source, "numeric_binning": NUMERIC_BINNING,
        "categorical_other": OTHER, "psi": dict(PSI),
        "numeric": {f: numeric_stats(numeric[f]) for f in numeric_fields},
        "categorical": {f: categorical_stats(categorical[f]) for f in categorical_fields},
    }


def validate_baseline(block: Any, numeric_fields: tuple[str, ...] = NUMERIC,
                      categorical_fields: tuple[str, ...] = CATEGORICAL) -> list[str]:
    """按后端 ``FeatureBaseline.fromManifest`` 的解析规则（并加上计数一致性）检查基线块；返回问题列表，空表示通过。"""
    p: list[str] = []
    if not isinstance(block, dict):
        return ["block is not an object"]
    if block.get("schema_version") != SCHEMA_VERSION or block.get("method") != METHOD:
        p.append("schema_version/method")
    if block.get("numeric_binning") != NUMERIC_BINNING or block.get("categorical_other") != OTHER:
        p.append("numeric_binning/categorical_other")
    psi = block.get("psi", {})
    if psi != PSI or not (0 < psi.get("epsilon", 0) < 0.01 and 0 < psi.get("warning", 0) < psi.get("alert", 0)):
        p.append("psi")
    src = block.get("source", {})
    if src.get("partition") != "train" or not isinstance(src.get("rows"), int) or src.get("rows", 0) < 1:
        p.append("source.partition/rows")
    num, cat = block.get("numeric", {}), block.get("categorical", {})
    if list(num) != list(numeric_fields) or list(cat) != list(categorical_fields):
        p.append("field set/order differs from the contract")
    for f, x in num.items():
        edges, counts, props = x.get("edges", []), x.get("counts", []), x.get("proportions", [])
        if not all(isinstance(e, float) and math.isfinite(e) for e in edges):
            p.append(f"numeric.{f}.edges not finite floats")
        if any(not b > a for a, b in zip(edges, edges[1:])):
            p.append(f"numeric.{f}.edges not strictly ascending")
        if not (len(counts) == len(props) == len(edges) + 1):
            p.append(f"numeric.{f} length mismatch")
        if sum(counts) != x.get("count") or x.get("count") != src.get("rows"):
            p.append(f"numeric.{f}.counts sum/count")
        if any(not 0 <= v <= 1 for v in props) or abs(sum(props) - 1.0) > PROPORTION_TOLERANCE:
            p.append(f"numeric.{f}.proportions")
    for f, x in cat.items():
        counts, props = x.get("counts", {}), x.get("proportions", {})
        if OTHER not in counts or list(counts) != list(props):
            p.append(f"categorical.{f} keys")
        if any(not k or len(k) > MAX_CATEGORY_KEY for k in props):
            p.append(f"categorical.{f} key length")
        if sum(counts.values()) != x.get("count") or x.get("count") != src.get("rows"):
            p.append(f"categorical.{f}.counts sum/count")
        if any(not 0 <= v <= 1 for v in props.values()) or abs(sum(props.values()) - 1.0) > PROPORTION_TOLERANCE:
            p.append(f"categorical.{f}.proportions")
    return p


# ---------------------------------------------------------------- JSON / 哈希工具

def delivery_json_bytes(payload: Any) -> bytes:
    """交付包 JSON 的字节格式，与训练主机 ``write_json`` 在 Windows 上的输出一致：UTF-8、缩进 2、CRLF、无末尾换行。"""
    return json.dumps(payload, ensure_ascii=False, indent=2, default=str).replace("\n", "\r\n").encode("utf-8")


def crlf_sha256(path: Path) -> str:
    """把 Git 中的 LF 文本还原为训练主机上的 CRLF 后求 SHA-256（manifest 记录的是训练主机字节的哈希）。"""
    data = Path(path).read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    return hashlib.sha256(data).hexdigest()


def diff_json(a: Any, b: Any, path: str = "") -> list[str]:
    """JSON 深比较，返回差异路径（JSON Pointer 风格）；新增/删除的键也列出。"""
    if isinstance(a, dict) and isinstance(b, dict):
        out: list[str] = []
        for key in [*a, *(k for k in b if k not in a)]:
            sub = f"{path}/{key}"
            if key not in a or key not in b:
                out.append(sub)
            else:
                out += diff_json(a[key], b[key], sub)
        return out
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return [path or "/"]
        return [d for i, (x, y) in enumerate(zip(a, b)) for d in diff_json(x, y, f"{path}/{i}")]
    same = type(a) is type(b) and a == b
    return [] if same else [path or "/"]


def compare_audit(expected: Any, actual: Any, rtol: float = AUDIT_FLOAT_RTOL) -> tuple[list[str], float]:
    """切分审计对比：整数、字符串、布尔完全相等，浮点按相对容差；返回 (差异路径, 浮点最大相对差)。"""
    worst = 0.0

    def walk(a: Any, b: Any, path: str) -> list[str]:
        nonlocal worst
        if isinstance(a, dict) and isinstance(b, dict):
            if set(a) != set(b):
                return [f"{path}/{{keys}}"]
            return [d for k in a for d in walk(a[k], b[k], f"{path}/{k}")]
        if isinstance(a, list) and isinstance(b, list):
            if len(a) != len(b):
                return [path]
            return [d for i, (x, y) in enumerate(zip(a, b)) for d in walk(x, y, f"{path}/{i}")]
        if isinstance(a, float) and isinstance(b, float):
            rel = abs(a - b) / max(abs(a), 1e-300) if a != b else 0.0
            worst = max(worst, rel)
            return [] if rel <= rtol else [path]
        return [] if type(a) is type(b) and a == b else [path]

    return walk(expected, actual, ""), worst


def _plain(payload: Any) -> Any:
    """经一次 JSON 往返，得到与归档文件相同的纯 Python 类型（tuple→list、numpy 标量→内置类型）。"""
    return json.loads(json.dumps(payload, default=lambda o: o.item() if hasattr(o, "item") else str(o)))


def _logger(path: Path) -> Callable[[str], None]:
    def say(message: str) -> None:
        line = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {message}"
        with path.open("a", encoding="utf-8") as stream:
            stream.write(line + "\n")
        print(line, flush=True)
    return say


class Checks:
    """复现核对记录：``bind`` 为绑定项（不符即不得产出基线），``info`` 为只作记录的参考项。"""

    def __init__(self) -> None:
        self.binding: list[dict[str, Any]] = []
        self.informational: list[dict[str, Any]] = []

    def bind(self, name: str, expected: Any, actual: Any) -> bool:
        ok = _plain(expected) == _plain(actual)
        self.binding.append({"check": name, "expected": expected, "actual": actual, "passed": ok})
        return ok

    def info(self, name: str, **fields: Any) -> None:
        self.informational.append({"check": name, **fields})

    @property
    def passed(self) -> bool:
        return all(c["passed"] for c in self.binding)

    def record(self, **extra: Any) -> dict[str, Any]:
        return {"passed": self.passed, "binding": self.binding, "informational": self.informational, **extra}

    def halt_if_failed(self, path: Path, **extra: Any) -> None:
        """有绑定项不符时写出核对记录并终止（fail-closed）。"""
        if not self.passed:
            write_json(path, self.record(**extra))
            bad = [c["check"] for c in self.binding if not c["passed"]]
            raise ReproductionError(f"reproduction mismatch, baseline not produced: {bad}")


# ---------------------------------------------------------------- compute：复现切分 + 训练分区基线

def _rebuild_caches(raw_root: Path, reg: dict[str, Any], checks: Checks, tmp: Path, say: Callable[[str], None]
                    ) -> tuple[pd.DataFrame, pd.DataFrame]:
    """原始 CSV → ``d1_raw`` 与 ``ct_*`` 重算列。两者都经临时 parquet 往返，与训练端读缓存的类型完全一致。"""
    for name in ("NUSW-NB15_features.csv", *register.D1_RAW_FILES):
        rec, path = reg["d1"]["files"][name], raw_root / name
        checks.bind(f"raw file {name} sha256/bytes", [rec["sha256"], rec["bytes"]],
                    [sha256_file(path), path.stat().st_size] if path.is_file() else ["missing", None])
    say("parsing raw CSVs with register.load_d1_raw")
    raw, conversions = register.load_d1_raw(raw_root)
    cache_rec = reg["processed_cache"]["d1_raw.parquet"]
    raw_rec = reg["d1"]["raw"]
    checks.bind("d1_raw conversions", raw_rec["conversions"], conversions)
    checks.bind("d1_raw attack_cat counts", raw_rec["attack_cat_counts"],
                {str(k): int(v) for k, v in raw["attack_cat"].value_counts().items()})
    checks.bind("d1_raw rows/columns", [cache_rec["rows"], raw_rec["columns"]], [len(raw), raw.shape[1]])
    checks.bind("d1_raw data_fingerprint (in memory)", cache_rec["data_fingerprint"], register.frame_fingerprint(raw))
    parquet = tmp / "d1_raw.parquet"
    raw.to_parquet(parquet, index=False, engine="pyarrow", compression="zstd")
    checks.info("d1_raw.parquet sha256", archived=cache_rec["sha256"], rebuilt=sha256_file(parquet),
                note="parquet 字节依赖写出实现细节，只作参考；以 data_fingerprint 绑定")
    del raw
    gc.collect()
    raw = pd.read_parquet(parquet)
    checks.bind("d1_raw data_fingerprint (parquet reload)", cache_rec["data_fingerprint"], register.frame_fingerprint(raw))
    say(f"recomputing ct_* on {len(raw):,} rows (feature_audit.recompute_ct)")
    recomputed = recompute_ct(raw[RAW_COLUMNS])
    meta = json.loads((ROOT / RECOMPUTED_EVIDENCE).read_text(encoding="utf-8"))
    cache = tmp / meta["file"]
    recomputed.to_parquet(cache, index=False)
    checks.bind("recomputed cache rows/columns", [meta["rows"], meta["columns"]], [len(recomputed), list(recomputed.columns)])
    checks.info("recomputed cache sha256", archived=meta["sha256"], rebuilt=sha256_file(cache),
                note="parquet 字节只作参考；以切分指纹与审计内容绑定")
    del recomputed
    gc.collect()
    return raw, pd.read_parquet(cache)


def compute(raw_root: Path | None = None, source_delivery: Path | None = None, runs_root: Path = RUNS_ROOT) -> Path:
    """复现 v4 切分并核对；全部绑定项通过后在训练分区上写 ``feature-baseline-stats.json``。返回运行目录。"""
    raw_root = Path(raw_root) if raw_root else register.D1_ROOT
    source_delivery = Path(source_delivery) if source_delivery else DELIVERY_ROOT / f"{MODEL_KEY}-{SOURCE_VERSION}"
    manifest = json.loads((source_delivery / "model_manifest.json").read_text(encoding="utf-8"))
    ds, fc = manifest["dataset"], manifest["feature_contract"]
    commit = git_commit()
    ctx = RunContext("baseline-v4", SPLIT_SEED, {"raw_root": str(raw_root), "source_delivery": str(source_delivery),
                                                   "contract": fc["version"], "quantiles": QUANTILES,
                                                   "min_category_share": MIN_CATEGORY_SHARE, "psi": PSI},
                     runs_root=runs_root)
    say, out = _logger(ctx.path("training.log")), ctx.path("reproduction-check.json")
    checks = Checks()

    # 1. 归档证据与已交付 manifest 的哈希链（CRLF 还原）。
    freeze = json.loads((ROOT / FREEZE_FILE).read_text(encoding="utf-8"))
    checks.bind("register manifest sha256 (evidence, CRLF)", ds["register_manifest_sha256"], crlf_sha256(ROOT / REGISTER_EVIDENCE))
    checks.bind("split audit sha256 (evidence, CRLF)", ds["split_audit_sha256"], crlf_sha256(ROOT / SPLIT_AUDIT_EVIDENCE))
    checks.bind("freeze file sha256 (CRLF)", manifest["provenance"]["freeze_sha256"], crlf_sha256(ROOT / FREEZE_FILE))
    checks.bind("freeze split record", [ds["split_fingerprint"], ds["split"]["seed"], ds["split_audit_sha256"]],
                [freeze["split"]["d1_raw_fingerprint"], freeze["split"]["seed"], freeze["split"]["split_audit_sha256"]])
    archived = json.loads((ROOT / SPLIT_AUDIT_EVIDENCE).read_text(encoding="utf-8"))
    checks.bind("archived split fingerprint", ds["split_fingerprint"], archived["split-d1-raw.npz"]["fingerprint"])
    checks.bind("archived register_manifest_sha256", ds["register_manifest_sha256"], archived["register_manifest_sha256"])
    checks.halt_if_failed(out)
    reg = json.loads((ROOT / REGISTER_EVIDENCE).read_text(encoding="utf-8"))
    split_id = Path(freeze["split"]["dir"]).name

    # 2. 原始 CSV → 缓存 → v4 帧 → 切分，逐项核对。
    with tempfile.TemporaryDirectory(prefix="baseline-v4-") as tmp:
        raw, recomputed = _rebuild_caches(raw_root, reg, checks, Path(tmp), say)
        checks.halt_if_failed(out)
        say("assembling v4 frame and reproducing split_d1")
        frame, labels, cats, usable = assemble_frame(raw, recomputed)
        parts, audit = split_d1(frame, labels, cats, usable, raw[["srcip", "dstip"]],
                                tuple(SPLIT_SEED + i for i in range(5)))
    split = SplitIndex(parts["train"], parts["validation"], parts["holdout"])  # 不传审计日志：holdout 无法解锁
    checks.bind("split fingerprint", ds["split_fingerprint"], split.fingerprint)
    checks.bind("selected seed", ds["split"]["seed"], audit["selected_seed"])
    diffs, worst = compare_audit(archived["d1_raw"], _plain(audit))
    checks.bind("split audit d1_raw content", [], diffs)
    checks.info("split audit float max relative diff", value=worst, rtol=AUDIT_FLOAT_RTOL)
    checks.info("split-d1-raw.npz sha256", archived=archived["split-d1-raw.npz"]["sha256"],
                note="npz 为带时间戳的 zip，字节不可复现；以行位置指纹绑定")
    checks.info("d2 split", archived_fingerprint=archived["split-d2.npz"]["fingerprint"],
                note="本机无 D2 数据，未重算；D2 不参与本基线，登记与审计文件哈希已按 CRLF 核对")
    checks.halt_if_failed(out)
    train = np.sort(split.train)
    del parts, split, cats
    gc.collect()
    return _train_baseline(ctx, checks, say, manifest, split_id, commit, raw, recomputed, frame, usable, train, audit)


def _train_baseline(ctx: RunContext, checks: Checks, say: Callable[[str], None], manifest: dict[str, Any], split_id: str,
                    commit: dict[str, Any], raw: pd.DataFrame, recomputed: pd.DataFrame, frame: pd.DataFrame,
                    usable: np.ndarray, train: np.ndarray, audit: dict[str, Any]) -> Path:
    """训练分区：范围核对 → ONNX 口径输入 → 与训练帧逐值对拍 → 缺失/异常报告 → 基线。"""
    out = ctx.path("reproduction-check.json")
    ds, fc = manifest["dataset"], manifest["feature_contract"]
    checks.bind("train rows", audit["partitions"]["train"]["rows"], int(train.size))
    # 范围：训练分区 = 窗口已满且未被 D12 排除的行（响应方视角、IPv4），即模型拟合所用的全部行（train.Matrices）。
    ips = pd.unique(pd.concat([raw["srcip"].iloc[train], raw["dstip"].iloc[train]], ignore_index=True).astype("string"))
    cls = np.array([_classify(a) for a in ips], dtype=bool).reshape(-1, 2)
    checks.bind("train rows usable (window ready, not excluded)", True, bool(usable[train].all()))
    checks.bind("train endpoints all valid IPv4", True, bool(cls[:, 0].all()))
    checks.bind("manifest scope", [["responder"], ["ipv4"]], [fc["supported_viewpoints"], fc["supported_address_families"]])
    checks.bind("manifest inputs", [list(NUMERIC), list(CATEGORICAL)],
                [[f["name"] for f in fc["inputs"][INPUT_NUMERIC]], list(fc["inputs"][INPUT_CATEGORICAL])])
    say(f"building ONNX-aligned inputs for {train.size:,} train rows")
    inputs, _ = contract_inputs(raw.iloc[train][V1_RAW_COLUMNS], recomputed.iloc[train])
    num, cat = inputs[INPUT_NUMERIC], inputs[INPUT_CATEGORICAL]
    fit = frame.iloc[train]
    value_mismatch = {}
    for i, f in enumerate(NUMERIC):
        a, b = num[:, i].astype(np.float32), fit[f].to_numpy(dtype=np.float32)
        value_mismatch[f] = int((~((a == b) | (np.isnan(a) & np.isnan(b)))).sum())
    value_mismatch.update({f: int((cat[:, i] != fit[f].astype("string").fillna("").to_numpy(dtype=object)).sum())
                           for i, f in enumerate(CATEGORICAL)})
    checks.bind("ONNX inputs (float32) equal training frame values, per field", {f: 0 for f in value_mismatch}, value_mismatch)
    missing = {
        "numeric_non_finite": {f: int((~np.isfinite(num[:, i])).sum()) for i, f in enumerate(NUMERIC)},
        "numeric_negative": {f: int((num[:, i] < 0).sum()) for i, f in enumerate(NUMERIC)},
        "categorical_empty": {f: int((cat[:, i] == "").sum()) for i, f in enumerate(CATEGORICAL)},
        "dsport_missing_rows": int(raw["dsport"].iloc[train].isna().sum()),
    }
    checks.info("train missing / abnormal values", **missing)
    checks.halt_if_failed(out)
    del frame, fit, recomputed
    gc.collect()
    non_finite = sum(missing["numeric_non_finite"].values()) + sum(missing["categorical_empty"].values())
    if non_finite:
        write_json(out, checks.record(missing_values=missing))
        raise BaselineError(f"train partition has non-finite/empty contract inputs: {missing}")

    source = {
        "partition": "train", "split_id": split_id, "split_fingerprint": ds["split_fingerprint"], "seed": ds["split"]["seed"],
        "rows": int(train.size),
        "scope": {"viewpoints": list(fc["supported_viewpoints"]), "address_families": list(fc["supported_address_families"])},
        "code_commit": commit["commit"] + ("+dirty" if commit["dirty"] else ""),
        "values": "ONNX 输入口径（进入 preprocessing 之前）：float64 原始值；sload/dload 在 dur=0 或该方向包数≤1 时为 0；"
                  "ct_* 为训练端单主机重算值；service 为端口口径（dsport 缺失时为 -，与训练一致）",
        "missing_values": {"numeric_non_finite": 0, "categorical_empty": 0,
                           "dsport_missing_rows": missing["dsport_missing_rows"],
                           "handling": "训练分区无缺失或非有限值，未丢弃任何行"},
        "reproduction": f"切分由原始 CSV 按同一代码复现（{platform.system()} {platform.machine()}），指纹与 manifest 一致",
    }
    say("computing decile baselines")
    baseline = build_baseline({f: num[:, i] for i, f in enumerate(NUMERIC)}, {f: cat[:, i] for i, f in enumerate(CATEGORICAL)},
                              source)
    problems = validate_baseline(baseline)
    checks.bind("baseline structure (backend parser rules)", [], problems)
    robustness = {}
    for i, f in enumerate(NUMERIC):
        x = baseline["numeric"][f]
        c32 = np.bincount(bin_index(num[:, i].astype(np.float32), x["edges"]), minlength=len(x["edges"]) + 1)
        robustness[f] = int(np.abs(c32 - np.asarray(x["counts"])).sum())
    checks.info("float32-cast values vs float64 bin counts (rows moved)", **robustness)
    checks.halt_if_failed(out)
    write_json(ctx.path("feature-baseline-stats.json"), baseline)
    write_json(out, checks.record(split_id=split_id, train_rows=int(train.size), missing_values=missing,
                                  edges_per_field={f: len(baseline["numeric"][f]["edges"]) for f in NUMERIC},
                                  categorical_keys={f: list(baseline["categorical"][f]["counts"]) for f in CATEGORICAL}))
    ctx.finish()
    say(f"baseline written: {ctx.run_dir.name}")
    return ctx.run_dir


# ---------------------------------------------------------------- package / verify：2026.10.1 交付

def delivery_checksums(delivery: Path) -> dict[str, str]:
    """交付目录内除顶层 ``checksums.json`` 外全部文件的 SHA-256（相对路径，按路径排序）。"""
    delivery = Path(delivery)
    return {p.relative_to(delivery).as_posix(): sha256_file(p) for p in sorted(delivery.rglob("*"))
            if p.is_file() and p != delivery / "checksums.json"}


def _copied_entries(source: Path) -> list[str]:
    """需逐字节复制的顶层条目；源目录出现未知条目即终止，避免静默遗漏。"""
    names = sorted(p.name for p in source.iterdir())
    exports = [n for n in names if n.startswith("export-") and n.endswith(".json")]
    unknown = sorted(set(names) - {*COPIED, *exports, *REWRITTEN})
    if unknown or not set(COPIED) <= set(names):
        raise DeliveryError(f"unexpected source delivery layout: unknown={unknown}")
    return [*COPIED, *exports]


def build_manifest(old: dict[str, Any], old_sha256: str, baseline: dict[str, Any], version: str, created_at: str
                   ) -> dict[str, Any]:
    """新 manifest = 旧 manifest 深拷贝，只改 ``model_version``/``version``/``created_at``，新增基线块与 ``provenance.derived_from``。"""
    m = copy.deepcopy(old)
    m["model_version"], m["version"], m["created_at"] = f"{MODEL_KEY}-{version}", version, created_at
    m["provenance"]["derived_from"] = {"model_version": old["model_version"], "manifest_sha256": old_sha256,
                                       "change": DERIVED_CHANGE}
    m["feature_baseline_stats"] = baseline
    return m


def package(baseline_run: Path, source_delivery: Path, delivery_root: Path, version: str = TARGET_VERSION,
            created_at: str | None = None, expected_onnx_sha256: str = EXPECTED_ONNX_SHA256) -> Path:
    """写 ``<delivery_root>/unsw-binary-<version>/`` 并自校验；目标已存在或源交付校验失败即终止。返回交付目录。"""
    baseline_run, source = Path(baseline_run), Path(source_delivery)
    check = json.loads((baseline_run / "reproduction-check.json").read_text(encoding="utf-8"))
    if not check.get("passed"):
        raise DeliveryError("reproduction check did not pass; refusing to package")
    baseline = json.loads((baseline_run / "feature-baseline-stats.json").read_text(encoding="utf-8"))
    target = Path(delivery_root) / f"{MODEL_KEY}-{version}"
    if target.exists():
        raise FileExistsError(f"delivery directory already exists: {target.name}")
    declared = json.loads((source / "checksums.json").read_text(encoding="utf-8"))
    bad = [k for k, v in declared.items() if sha256_file(source / k) != v]
    old_bytes = (source / "model_manifest.json").read_bytes()
    old = json.loads(old_bytes)
    if bad or old["artifact"]["sha256"] != expected_onnx_sha256:
        raise DeliveryError(f"source delivery failed checksum verification: {bad}")
    if baseline["source"]["split_fingerprint"] != old["dataset"]["split_fingerprint"] or validate_baseline(baseline):
        raise DeliveryError("baseline does not match the source manifest split or fails structure checks")
    if delivery_json_bytes(old) != old_bytes:
        raise DeliveryError("source manifest is not in the expected JSON byte format; cannot guarantee minimal diff")

    entries = _copied_entries(source)  # 布局检查放在建目录之前，失败时不留半成品
    target.mkdir(parents=False)
    for name in entries:
        src = source / name
        (shutil.copytree if src.is_dir() else shutil.copy2)(src, target / name)
    created_at = created_at or datetime.now(timezone.utc).isoformat()
    new = build_manifest(old, hashlib.sha256(old_bytes).hexdigest(), baseline, version, created_at)
    (target / "model_manifest.json").write_bytes(delivery_json_bytes(new))
    (target / "checksums.json").write_bytes(delivery_json_bytes(delivery_checksums(target)))
    for name in (".", *REWRITTEN):
        os.chmod(target / name, stat.S_IMODE((source / name).stat().st_mode))
    return target


def verify(delivery: Path, source_delivery: Path, expected_onnx_sha256: str = EXPECTED_ONNX_SHA256,
           version: str = TARGET_VERSION) -> dict[str, Any]:
    """交付自校验（只读）。返回检查记录，``passed`` 为全部检查项的合取。"""
    new_dir, old_dir = Path(delivery), Path(source_delivery)
    old_bytes, new_bytes = (old_dir / "model_manifest.json").read_bytes(), (new_dir / "model_manifest.json").read_bytes()
    old, new = json.loads(old_bytes), json.loads(new_bytes)
    c: dict[str, bool] = {}
    declared = json.loads((new_dir / "checksums.json").read_text(encoding="utf-8"))
    actual = delivery_checksums(new_dir)
    c["checksums_cover_all_files"] = set(declared) == set(actual)
    c["checksums_match"] = all(actual.get(k) == v for k, v in declared.items())
    onnx_sha = sha256_file(new_dir / "model.onnx")
    c["model_onnx_sha256_expected"] = onnx_sha == expected_onnx_sha256
    c["artifact_sha256_and_size"] = (new["artifact"]["sha256"] == onnx_sha
                                     and new["artifact"]["size_bytes"] == (new_dir / "model.onnx").stat().st_size)
    c["manifest_files_hashes"] = all(sha256_file(new_dir / k) == v for k, v in new["files"].items())
    fx = new_dir / new["fixtures"]["dir"]
    fx_declared = json.loads((fx / "checksums.json").read_text(encoding="utf-8"))
    c["fixtures_checksums"] = (sha256_file(fx / "checksums.json") == new["fixtures"]["checksums_sha256"]
                               and all(sha256_file(fx / k) == v for k, v in fx_declared.items()))
    old_files = {p.relative_to(old_dir).as_posix() for p in old_dir.rglob("*") if p.is_file()}
    new_files = {p.relative_to(new_dir).as_posix() for p in new_dir.rglob("*") if p.is_file()}
    c["same_file_set"] = old_files == new_files
    c["copied_files_byte_identical"] = all((old_dir / k).read_bytes() == (new_dir / k).read_bytes()
                                           for k in old_files - set(REWRITTEN))
    diff = diff_json(old, new)
    c["manifest_diff_only_allowed"] = sorted(diff) == sorted(ALLOWED_DIFF)
    c["manifest_values"] = (new["model_version"] == f"{MODEL_KEY}-{version}" and new["version"] == version
                            and new["created_at"].endswith("+00:00") and new["activation"]["status"] == "candidate"
                            and new["provenance"]["derived_from"] == {
                                "model_version": old["model_version"], "manifest_sha256": hashlib.sha256(old_bytes).hexdigest(),
                                "change": DERIVED_CHANGE})
    c["manifest_json_format_crlf"] = delivery_json_bytes(new) == new_bytes
    b = new.get("feature_baseline_stats", {})
    inputs = new["feature_contract"]["inputs"]
    c["baseline_structure"] = not validate_baseline(b, tuple(f["name"] for f in inputs[INPUT_NUMERIC]),
                                                    tuple(inputs[INPUT_CATEGORICAL]))
    c["baseline_split_fingerprint"] = b.get("source", {}).get("split_fingerprint") == old["dataset"]["split_fingerprint"]
    c["baseline_no_ipv4_literal"] = not IPV4_LITERAL.search(json.dumps(b, ensure_ascii=False))
    modes = {}
    for k in {".", *old_files, *{p.relative_to(old_dir).as_posix() for p in old_dir.rglob("*") if p.is_dir()}}:
        modes[k] = stat.S_IMODE((old_dir / k).stat().st_mode) == stat.S_IMODE((new_dir / k).stat().st_mode)
    c["permissions_match_source"] = all(modes.values())
    return {"delivery": new_dir.name, "source_delivery": old_dir.name, "passed": all(c.values()), "checks": c,
            "manifest_sha256": sha256_file(new_dir / "model_manifest.json"),
            "source_manifest_sha256": hashlib.sha256(old_bytes).hexdigest(), "model_onnx_sha256": onnx_sha,
            "checksums_sha256": sha256_file(new_dir / "checksums.json"), "manifest_diff": diff,
            "checksum_entries": len(declared)}


def render_summary(baseline: dict[str, Any], check: dict[str, Any], delivery: dict[str, Any]) -> str:
    """阶段 7 基线摘要（Markdown）：只含字段级统计与核对结果，不含数据行、地址或主机路径。"""
    s = baseline["source"]
    L = ["# 路线 B 阶段 7：v4 训练切分特征基线（unsw-binary-2026.10.1）", "",
         f"- 方法：`{baseline['method']}`（schema `{baseline['schema_version']}`）；分箱：{baseline['numeric_binning']}",
         f"- 来源：`{s['split_id']}` 训练分区，种子 {s['seed']}，{s['rows']:,} 行；范围 viewpoints={s['scope']['viewpoints']}、"
         f"address_families={s['scope']['address_families']}；代码提交 `{s['code_commit']}`",
         f"- 取值口径：{s['values']}",
         f"- 缺失/异常：数值非有限值 0、类别空值 0；dsport 缺失 {s['missing_values']['dsport_missing_rows']} 行（service 记 -）；"
         f"负值计数 {sum(check['missing_values']['numeric_negative'].values())}。{s['missing_values']['handling']}。", "",
         "## 切分复现核对（绑定项，任一不符即不产出基线）", "", "| 检查项 | 结果 |", "|---|---|"]
    L += [f"| {c['check']} | {'一致' if c['passed'] else '不一致'} |" for c in check["binding"]]
    L += ["", "参考项（不绑定）：" + "；".join(c["check"] for c in check["informational"]) + "。", "",
          "## 数值字段", "", "| 字段 | edges 数 | 箱数 | 最小 edge | 最大 edge | 最大箱占比 |", "|---|---:|---:|---:|---:|---:|"]
    for f, x in baseline["numeric"].items():
        e = x["edges"]
        lo, hi = (f"{e[0]:.6g}", f"{e[-1]:.6g}") if e else ("—", "—")
        L.append(f"| `{f}` | {len(e)} | {len(e) + 1} | {lo} | {hi} | {max(x['proportions']):.4f} |")
    L += ["", "## 类别字段", "", "| 字段 | 单独成键的取值数 | `__other__` 占比 | 取值 |", "|---|---:|---:|---|"]
    for f, x in baseline["categorical"].items():
        keys = [k for k in x["counts"] if k != OTHER]
        L.append(f"| `{f}` | {len(keys)} | {x['proportions'][OTHER]:.6f} | {'、'.join(keys)} |")
    L += ["", "## 交付自校验", "", f"- 交付目录：`{delivery['delivery']}`（源 `{delivery['source_delivery']}`）",
          f"- 新 manifest SHA-256：`{delivery['manifest_sha256']}`；源 manifest：`{delivery['source_manifest_sha256']}`",
          f"- model.onnx SHA-256：`{delivery['model_onnx_sha256']}`；checksums.json 条目 {delivery['checksum_entries']}",
          f"- manifest 差异键：{'、'.join(f'`{d}`' for d in delivery['manifest_diff'])}",
          "- 检查项：" + "；".join(f"{k} {'通过' if v else '未通过'}" for k, v in delivery["checks"].items()), ""]
    return "\n".join(L)


def latest_baseline_run(runs_root: Path = RUNS_ROOT) -> Path:
    candidates = sorted(Path(runs_root).glob("baseline-v4-*/feature-baseline-stats.json"))
    if not candidates:
        raise FileNotFoundError("no baseline-v4 run found; run `baseline-v4 --baseline-stage compute` first")
    return candidates[-1].parent


def run(stage: str = "compute", raw_root: Path | None = None, source_delivery: Path | None = None,
        baseline_run: Path | None = None, delivery_root: Path | None = None, version: str = TARGET_VERSION,
        delivery: Path | None = None) -> str:
    """CLI 入口：``compute`` 复现并算基线；``package`` 写交付并自校验、写摘要；``verify`` 只读自校验。失败即抛出。"""
    source_delivery = Path(source_delivery) if source_delivery else DELIVERY_ROOT / f"{MODEL_KEY}-{SOURCE_VERSION}"
    if stage == "compute":
        return str(compute(raw_root, source_delivery))
    delivery_root = Path(delivery_root) if delivery_root else DELIVERY_ROOT
    if stage == "package":
        baseline_run = Path(baseline_run) if baseline_run else latest_baseline_run()
        target = package(baseline_run, source_delivery, delivery_root, version)
        record = verify(target, source_delivery, version=version)
        write_json(baseline_run / "delivery-check.json", record)
        baseline = json.loads((baseline_run / "feature-baseline-stats.json").read_text(encoding="utf-8"))
        check = json.loads((baseline_run / "reproduction-check.json").read_text(encoding="utf-8"))
        (baseline_run / "baseline-summary.md").write_text(render_summary(baseline, check, record), encoding="utf-8")
        RunContext.checksum_dir(baseline_run)
        if not record["passed"]:
            raise DeliveryError(f"delivery self-check failed: {record['checks']}")
        return str(target)
    if stage == "verify":
        target = Path(delivery) if delivery else delivery_root / f"{MODEL_KEY}-{version}"
        record = verify(target, source_delivery, version=version)
        if not record["passed"]:
            raise DeliveryError(f"delivery self-check failed: {record['checks']}")
        return json.dumps(record, ensure_ascii=False, indent=2)
    raise ValueError(f"unknown baseline stage: {stage}")
