"""已登记数据的读取、去重键与端点分组键。

所有后续步骤只能通过本模块读取 ``data/processed`` 缓存：读取前按最新（或指定）登记 manifest
校验 SHA-256，哈希不符即终止，避免在被改动的数据上训练。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd

from ..config import ROOT
from .runtime import RUNS_ROOT, sha256_file

PROCESSED_ROOT = ROOT / "data" / "processed"

# D1 原始数据中不作为模型输入的列：标识、时间、目标。
D1_IDENTIFIERS = ("srcip", "dstip", "sport", "dsport", "Stime", "Ltime")
D1_TARGETS = ("attack_cat", "Label")
# TCP 初始序列号近似随机（约 142 万个不同值），会让本质相同的记录看起来不同，因此不参与去重键。
D1_DEDUP_IGNORED = ("stcpb", "dtcpb")
D1_CATEGORICAL = ("proto", "service", "state")
SUBSET_EXCLUDED = ("id", "label", "attack_cat")


class DataIntegrityError(ValueError):
    """缓存数据与登记 manifest 不一致。"""


def latest_register_manifest(runs_root: Path = RUNS_ROOT) -> Path:
    """返回最新一次登记运行的 manifest 路径；不存在时终止。"""
    candidates = sorted(Path(runs_root).glob("register-*/dataset-manifest.json"))
    if not candidates:
        raise DataIntegrityError("no register run found; run `python -m cyber_training.v2 register` first")
    return candidates[-1]


def load_manifest(path: Path | None = None) -> tuple[Path, dict[str, Any]]:
    path = Path(path) if path else latest_register_manifest()
    return path, json.loads(path.read_text(encoding="utf-8"))


def load_cached(name: str, manifest: dict[str, Any], columns: list[str] | None = None,
                processed_root: Path = PROCESSED_ROOT) -> pd.DataFrame:
    """按登记 manifest 校验并读取缓存（如 ``d1_raw.parquet``）。

    行数与 SHA-256 均需与 manifest 一致；``columns`` 仅影响读取列，不影响校验。
    """
    record = manifest["processed_cache"].get(name)
    if record is None:
        raise DataIntegrityError(f"{name} is not registered in the manifest")
    path = Path(processed_root) / name
    if not path.is_file():
        raise DataIntegrityError(f"missing processed cache: {path}")
    digest = sha256_file(path)
    if digest != record["sha256"]:
        raise DataIntegrityError(f"SHA-256 mismatch for {name}: {digest}")
    frame = pd.read_parquet(path, columns=columns)
    if len(frame) != record["rows"]:
        raise DataIntegrityError(f"{name} row count {len(frame)} != {record['rows']}")
    return frame


def d1_model_columns(frame: pd.DataFrame) -> list[str]:
    """D1 原始数据中可作为模型输入候选的列（排除标识、时间与目标）。"""
    return [c for c in frame.columns if c not in (*D1_IDENTIFIERS, *D1_TARGETS)]


def d1_dedup_key(frame: pd.DataFrame) -> list[str]:
    """去重键：模型候选列再去掉 TCP 初始序列号。"""
    return [c for c in d1_model_columns(frame) if c not in D1_DEDUP_IGNORED]


def endpoint_pair(frame: pd.DataFrame) -> pd.Series:
    """无序端点对 ``min(srcip,dstip)|max(srcip,dstip)``，双向流量归入同一组。"""
    src = frame["srcip"].astype("string")
    dst = frame["dstip"].astype("string")
    if src.isna().any() or dst.isna().any():
        raise DataIntegrityError("endpoint grouping requires non-missing srcip/dstip")
    low = src.where(src <= dst, dst)
    high = dst.where(src <= dst, src)
    return (low + "|" + high).astype("string")


def deduplicate(frame: pd.DataFrame, key: list[str], label: str) -> tuple[pd.Series, dict[str, int]]:
    """返回保留行掩码与统计。

    规则：同一去重键下标签不一致的整组记录全部剔除（冲突行）；其余按键保留首次出现的行。
    不修改输入数据，行位置保持与缓存一致，便于用行索引引用。
    """
    labels_per_key = frame.groupby(key, dropna=False, sort=False)[label].transform("nunique")
    conflict = labels_per_key > 1
    duplicate = frame.duplicated(key, keep="first") & ~conflict
    keep = ~conflict & ~duplicate
    stats = {
        "input_rows": int(len(frame)),
        "label_conflict_rows_removed": int(conflict.sum()),
        "duplicate_rows_removed": int(duplicate.sum()),
        "rows_retained": int(keep.sum()),
    }
    return keep, stats



# D1 与 D2 的公共语义特征映射（单位统一为秒、字节、包）。
# 假设：NetFlow v2 的 IN_* 为客户端→服务端（对应 D1 的 s*），OUT_* 为反向（对应 d*）；
# D1 的 sttl/dttl 是方向 TTL，D2 只有流级 MIN/MAX_TTL，因此用 min/max(sttl, dttl) 对齐。
COMMON_FEATURES = ("duration_s", "src_bytes", "dst_bytes", "src_pkts", "dst_pkts", "min_ttl", "max_ttl",
                   "src_bytes_per_pkt", "dst_bytes_per_pkt")


def common_view_d1(frame: pd.DataFrame) -> pd.DataFrame:
    out = pd.DataFrame({
        "duration_s": frame["dur"].astype("float64"),
        "src_bytes": frame["sbytes"].astype("float64"),
        "dst_bytes": frame["dbytes"].astype("float64"),
        "src_pkts": frame["Spkts"].astype("float64"),
        "dst_pkts": frame["Dpkts"].astype("float64"),
        "min_ttl": frame[["sttl", "dttl"]].min(axis=1).astype("float64"),
        "max_ttl": frame[["sttl", "dttl"]].max(axis=1).astype("float64"),
    })
    return _add_ratios(out)


def common_view_d2(frame: pd.DataFrame) -> pd.DataFrame:
    out = pd.DataFrame({
        "duration_s": frame["FLOW_DURATION_MILLISECONDS"].astype("float64") / 1000.0,
        "src_bytes": frame["IN_BYTES"].astype("float64"),
        "dst_bytes": frame["OUT_BYTES"].astype("float64"),
        "src_pkts": frame["IN_PKTS"].astype("float64"),
        "dst_pkts": frame["OUT_PKTS"].astype("float64"),
        "min_ttl": frame["MIN_TTL"].astype("float64"),
        "max_ttl": frame["MAX_TTL"].astype("float64"),
    })
    return _add_ratios(out)


D2_COMMON_SOURCE_COLUMNS = ["FLOW_DURATION_MILLISECONDS", "IN_BYTES", "OUT_BYTES", "IN_PKTS", "OUT_PKTS",
                            "MIN_TTL", "MAX_TTL", "Label"]


def _add_ratios(out: pd.DataFrame) -> pd.DataFrame:
    out["src_bytes_per_pkt"] = out["src_bytes"] / (out["src_pkts"] + 1.0)
    out["dst_bytes_per_pkt"] = out["dst_bytes"] / (out["dst_pkts"] + 1.0)
    return out[list(COMMON_FEATURES)]
