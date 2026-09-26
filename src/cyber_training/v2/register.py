"""第 3 步：数据登记。

校验两个 Kaggle 数据集（D1 UNSW-NB15、D2 NF-ToN-IoT-v2）的文件哈希，按字段字典解析 D1 原始 CSV，
规范化标签与端口字段，检查 D2 标签一致性，并输出 ``dataset-manifest.json`` 与统一的 parquet 缓存。
任一哈希、行数或标签计数与已审计值不符即终止（fail-closed），不会静默修正数据。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from ..config import ROOT
from ..data import EXPECTED_HASHES as D1_HASHES
from . import GLOBAL_SEED
from .runtime import RunContext, sha256_file, write_json

D1_ROOT = ROOT / "data" / "raw" / "unsw-nb15"
D2_ROOT = ROOT / "data" / "raw" / "nf-ton-iot-v2-kaggle"
PROCESSED_ROOT = ROOT / "data" / "processed"
EXCLUDED_ROOT = ROOT / "data" / "excluded"

D1_RAW_FILES = tuple(f"UNSW-NB15_{i}.csv" for i in range(1, 5))
# 该 Kaggle 副本文件名与内容相反：testing-set 是训练分区，training-set 是测试分区。
D1_SUBSET_TRAIN = "UNSW_NB15_testing-set.csv"
D1_SUBSET_TEST = "UNSW_NB15_training-set.csv"
D2_FILE = "NF-ToN-IoT-V2.parquet"
D2_HASHES = {
    D2_FILE: "4e8c9ac5cfda1ba1b3f1dbe450feed0dde48b809425bf65eabcd23086afb6624",
    "NetFlow v2 Features.csv": "f20e86a939f9eb53b06ace15de4cc977ed61c02e538c6465efe72b635448e939",
}

EXPECTED = {
    "d1_raw_rows": 2_540_047,
    "d1_raw_label_counts": {0: 2_218_764, 1: 321_283},
    "d1_subset_train_rows": 175_341,
    "d1_subset_test_rows": 82_332,
    "d2_rows": 13_135_881,
}

D1_CATEGORICAL = ("srcip", "dstip", "proto", "state", "service")
D1_PORTS = ("sport", "dsport")
D1_CANONICAL_ATTACKS = (
    "Normal", "Analysis", "Backdoor", "DoS", "Exploits", "Fuzzers",
    "Generic", "Reconnaissance", "Shellcode", "Worms",
)
SOURCES = {
    "d1": {
        "kaggle": "mrwellsdavid/unsw-nb15",
        "url": "https://www.kaggle.com/datasets/mrwellsdavid/unsw-nb15",
        "license": "原作者学术使用条款（需引用 Moustafa & Slay, 2015）；Kaggle 页面许可为 unknown，再分发前需核对原始条款",
    },
    "d2": {
        "kaggle": "dhoogla/nftoniotv2",
        "url": "https://www.kaggle.com/datasets/dhoogla/nftoniotv2",
        "license": "CC-BY-NC-SA-4.0（Kaggle 元数据）；原始来源 University of Queensland NF-ToN-IoT-v2",
    },
}


class RegistrationError(ValueError):
    """数据与已审计事实不一致。"""


def verify_hashes(root: Path, expected: dict[str, str]) -> dict[str, dict[str, Any]]:
    """逐文件计算 SHA-256 并与期望值比较；缺失或不符时抛 ``RegistrationError``。"""
    result: dict[str, dict[str, Any]] = {}
    for name, digest in expected.items():
        path = root / name
        if not path.is_file():
            raise RegistrationError(f"missing source file: {path}")
        actual = sha256_file(path)
        if actual != digest:
            raise RegistrationError(f"SHA-256 mismatch for {name}: {actual}")
        result[name] = {"bytes": path.stat().st_size, "sha256": actual}
    return result


def d1_feature_names(dictionary: Path) -> list[str]:
    """从 ``NUSW-NB15_features.csv``（cp1252）读取 49 个字段名，去除空白（如 ``ct_src_ ltm``）。"""
    frame = pd.read_csv(dictionary, encoding="cp1252")
    names = [str(n).strip().replace(" ", "") for n in frame["Name"]]
    if len(names) != 49 or len(set(names)) != 49:
        raise RegistrationError(f"feature dictionary must define 49 unique fields, got {len(names)}")
    return names


def parse_port(values: pd.Series) -> tuple[pd.Series, dict[str, int]]:
    """把端口字段转为可空整数：十进制、``0x`` 十六进制均支持；``-``/空白/无法解析记为缺失并计数。"""
    text = values.astype("string").str.strip()
    is_hex = text.str.lower().str.startswith("0x").fillna(False)
    decimal = pd.to_numeric(text.where(~is_hex), errors="coerce")
    hexed = text.where(is_hex).dropna().map(lambda v: int(v, 16) if _is_hex(v) else np.nan)
    parsed = decimal.copy()
    parsed.loc[hexed.index] = hexed.astype("float64")
    blank = text.isna() | text.isin(["", "-"])
    stats = {
        "hex_converted": int(is_hex.sum()),
        "dash_or_blank": int(blank.sum()),
        "unparseable": int((parsed.isna() & ~blank).sum()),
    }
    return parsed.astype("Int64"), stats


def _is_hex(value: str) -> bool:
    try:
        int(value, 16)
        return True
    except ValueError:
        return False


def normalize_attack_cat(attack_cat: pd.Series, label: pd.Series) -> tuple[pd.Series, dict[str, int]]:
    """规范化攻击类别：去空白、``Backdoors``→``Backdoor``、正常行空值→``Normal``。

    校验 label=0 ⇔ Normal；出现冲突或未知类别时抛 ``RegistrationError``。
    """
    text = attack_cat.astype("string").str.strip().replace({"": pd.NA, "Backdoors": "Backdoor"})
    filled_normal = int((text.isna() & (label == 0)).sum())
    text = text.mask(text.isna() & (label == 0), "Normal")
    unknown = sorted(set(text.dropna().unique()) - set(D1_CANONICAL_ATTACKS))
    if unknown:
        raise RegistrationError(f"unknown attack categories: {unknown}")
    attack_without_cat = int((text.isna() & (label == 1)).sum())
    conflicts = int(((text == "Normal") & (label == 1)).sum() + ((text != "Normal") & text.notna() & (label == 0)).sum())
    if conflicts or attack_without_cat:
        raise RegistrationError(f"label/attack_cat conflicts={conflicts}, attack rows without category={attack_without_cat}")
    return text, {"normal_filled_from_blank": filled_normal}


def profile(frame: pd.DataFrame, label: str) -> dict[str, Any]:
    """统计行列数、缺失单元格、完全重复行与标签分布（不修改数据）。"""
    return {
        "rows": int(len(frame)),
        "columns": int(frame.shape[1]),
        "missing_cells": int(frame.isna().sum().sum()),
        "missing_by_column": {c: int(v) for c, v in frame.isna().sum().items() if v},
        "exact_duplicate_rows": int(frame.duplicated(keep="first").sum()),
        "label_counts": {str(k): int(v) for k, v in frame[label].value_counts().sort_index().items()},
    }


def load_d1_raw(root: Path = D1_ROOT) -> tuple[pd.DataFrame, dict[str, Any]]:
    """解析 D1 四个无表头原始 CSV 并规范化。返回数据与转换记录；行数/标签计数不符即终止。"""
    names = d1_feature_names(root / "NUSW-NB15_features.csv")
    dtypes = {name: "string" for name in (*D1_CATEGORICAL, *D1_PORTS, "attack_cat")}
    frames = []
    per_file: dict[str, int] = {}
    for filename in D1_RAW_FILES:
        part = pd.read_csv(root / filename, header=None, names=names, dtype=dtypes,
                           encoding="utf-8-sig", low_memory=False, na_values=[""], keep_default_na=False)
        per_file[filename] = int(len(part))
        frames.append(part)
    data = pd.concat(frames, ignore_index=True)
    if len(data) != EXPECTED["d1_raw_rows"]:
        raise RegistrationError(f"D1 raw row count {len(data)} != {EXPECTED['d1_raw_rows']}")
    data["Label"] = pd.to_numeric(data["Label"], errors="raise").astype("int8")
    counts = data["Label"].value_counts().to_dict()
    if {int(k): int(v) for k, v in counts.items()} != EXPECTED["d1_raw_label_counts"]:
        raise RegistrationError(f"D1 raw label counts {counts} differ from audited values")
    conversions: dict[str, Any] = {"rows_per_file": per_file}
    for column in D1_PORTS:
        data[column], conversions[f"{column}_parse"] = parse_port(data[column])
    data["attack_cat"], conversions["attack_cat"] = normalize_attack_cat(data["attack_cat"], data["Label"])
    for column in D1_CATEGORICAL:
        data[column] = data[column].str.strip().str.lower()
    service_dash = int((data["service"] == "-").sum())
    conversions["service_dash_kept_as_category"] = service_dash
    blank_numeric: dict[str, int] = {}
    for column in data.columns:
        if column in (*D1_CATEGORICAL, *D1_PORTS, "attack_cat", "Label"):
            continue
        values = data[column]
        if values.dtype == object:
            # 原始 CSV 中部分数值列含仅空白的单元格：显式记为缺失并计数，其余非数值仍然终止。
            blank = values.astype("string").str.strip().eq("").fillna(False)
            if blank.any():
                blank_numeric[column] = int(blank.sum())
                values = values.mask(blank)
        data[column] = pd.to_numeric(values, errors="raise")
    conversions["numeric_blank_to_missing"] = blank_numeric
    return data, conversions


def load_d1_subset(root: Path = D1_ROOT) -> tuple[dict[str, pd.DataFrame], dict[str, Any]]:
    """读取 45 列预定义子集并按内容确认分区角色（175,341 行为训练，82,332 行为测试）。"""
    train = pd.read_csv(root / D1_SUBSET_TRAIN)
    test = pd.read_csv(root / D1_SUBSET_TEST)
    if (len(train), len(test)) != (EXPECTED["d1_subset_train_rows"], EXPECTED["d1_subset_test_rows"]):
        raise RegistrationError(f"subset sizes {len(train)}/{len(test)} do not match audited roles")
    for frame in (train, test):
        frame["attack_cat"] = frame["attack_cat"].astype("string").str.strip().replace({"Backdoors": "Backdoor"})
    record = {
        "role_mapping": {"train": D1_SUBSET_TRAIN, "test": D1_SUBSET_TEST},
        "role_mapping_reason": "文件名与内容相反；按行数与标签分布确认角色，不按文件名推断",
        "train": profile(train, "label"),
        "test": profile(test, "label"),
        "attack_cat_train": {str(k): int(v) for k, v in train["attack_cat"].value_counts().items()},
        "attack_cat_test": {str(k): int(v) for k, v in test["attack_cat"].value_counts().items()},
    }
    return {"train": train, "test": test}, record


def load_d2(root: Path = D2_ROOT) -> tuple[pd.DataFrame, dict[str, Any]]:
    """读取 D2 parquet 并检查 ``Label`` 与 ``Attack=="Benign"`` 是否一致；不一致计数写入记录，超过 0 即终止。"""
    data = pd.read_parquet(root / D2_FILE)
    if len(data) != EXPECTED["d2_rows"]:
        raise RegistrationError(f"D2 row count {len(data)} != {EXPECTED['d2_rows']}")
    data["Attack"] = data["Attack"].astype("string").str.strip()
    benign = data["Attack"].str.lower() == "benign"
    mismatch = int(((data["Label"] == 0) != benign).sum())
    if mismatch:
        raise RegistrationError(f"D2 Label/Attack mismatch rows: {mismatch}")
    record = {
        "label_attack_mismatch_rows": mismatch,
        "attack_counts": {str(k): int(v) for k, v in data["Attack"].value_counts().items()},
        "contains_ip_fields": any(c.startswith("IPV4_") for c in data.columns),
    }
    return data, record


def frame_fingerprint(frame: pd.DataFrame) -> str:
    """基于列名与逐行哈希的数据指纹，与行顺序相关。"""
    import hashlib

    digest = hashlib.sha256("\x1f".join(map(str, frame.columns)).encode())
    digest.update(pd.util.hash_pandas_object(frame, index=False).values.tobytes())
    return digest.hexdigest()


def guard_excluded_sources() -> None:
    """确认排除数据集（HIKARI）不在 ``data/raw`` 中；否则终止，防止误入新流程。"""
    raw = ROOT / "data" / "raw"
    offenders = [p.name for p in raw.iterdir() if "hikari" in p.name.lower()] if raw.exists() else []
    if offenders:
        raise RegistrationError(f"excluded datasets present under data/raw: {offenders}")


def run(processed_root: Path = PROCESSED_ROOT) -> Path:
    """执行第 3 步并返回运行目录。

    副作用：写 ``data/processed/{d1_raw,d1_subset_train,d1_subset_test,d2}.parquet``（被 Git 忽略）
    与 ``runs/register-*/dataset-manifest.json``。
    """
    ctx = RunContext("register", GLOBAL_SEED, {"processed_root": str(processed_root)})
    guard_excluded_sources()
    d1_files = verify_hashes(D1_ROOT, D1_HASHES)
    d2_files = verify_hashes(D2_ROOT, D2_HASHES)

    d1_raw, d1_conversions = load_d1_raw()
    subsets, subset_record = load_d1_subset()
    d2, d2_record = load_d2()

    processed_root.mkdir(parents=True, exist_ok=True)
    outputs = {
        "d1_raw.parquet": d1_raw,
        "d1_subset_train.parquet": subsets["train"],
        "d1_subset_test.parquet": subsets["test"],
        "d2.parquet": d2,
    }
    caches: dict[str, Any] = {}
    for name, frame in outputs.items():
        path = processed_root / name
        frame.to_parquet(path, index=False, engine="pyarrow", compression="zstd")
        caches[name] = {"sha256": sha256_file(path), "bytes": path.stat().st_size,
                        "rows": int(len(frame)), "data_fingerprint": frame_fingerprint(frame)}

    manifest = {
        "manifest_version": "v2",
        "approved_sources": ["d1", "d2"],
        "excluded_sources": {"hikari-2021-2022": "来源为 Zenodo 而非 Kaggle，已移至 data/excluded，禁止读取"},
        "d1": {
            **SOURCES["d1"],
            "files": d1_files,
            "raw": {**profile(d1_raw, "Label"), "conversions": d1_conversions,
                    "attack_cat_counts": {str(k): int(v) for k, v in d1_raw["attack_cat"].value_counts().items()}},
            "subset": subset_record,
        },
        "d2": {**SOURCES["d2"], "files": d2_files, **profile(d2, "Label"), **d2_record},
        "processed_cache": caches,
    }
    write_json(ctx.path("dataset-manifest.json"), manifest)
    ctx.finish()
    return ctx.run_dir
