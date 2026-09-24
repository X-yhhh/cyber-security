from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from .config import DATA_ROOT

RAW_FILES = [f"UNSW-NB15_{i}.csv" for i in range(1, 5)]
SUBSET_TRAIN_FILE = "UNSW_NB15_testing-set.csv"
SUBSET_TEST_FILE = "UNSW_NB15_training-set.csv"
EXPECTED_HASHES = {
    "NUSW-NB15_features.csv": "c55f19cceebb6360dc50f44f8a5f246ccefbcf8a6c604ac1ad46e643869cafce",
    "UNSW-NB15_1.csv": "7d851bbeabd27894ce39c8e78835c73341fc946652fb7743b9eff193b55eb511",
    "UNSW-NB15_2.csv": "6130ad02873cc6069ae695cf2844f2e8c2e9a9a1b7532dd82ab8f202757cacf8",
    "UNSW-NB15_3.csv": "ae990a96c3dfcd425ce2801aadb1727a34d5e0ae6d8215dbcdae60dedfaef640",
    "UNSW-NB15_4.csv": "cdf563692d51d405541dd659ddcdad9fa01f001f05fe9fc4b67f00ca12fbc96a",
    SUBSET_TRAIN_FILE: "bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa",
    SUBSET_TEST_FILE: "734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559",
}
TARGET = "Label"
IDENTIFIERS = {"srcip", "dstip", "sport", "dsport", "Stime", "Ltime", "id"}
RAW_TO_SUBSET = {
    "dur": "dur", "proto": "proto", "service": "service", "state": "state",
    "Spkts": "spkts", "Dpkts": "dpkts", "sbytes": "sbytes", "dbytes": "dbytes",
    "sttl": "sttl", "dttl": "dttl", "Sload": "sload", "Dload": "dload",
    "sloss": "sloss", "dloss": "dloss", "Sintpkt": "sinpkt", "Dintpkt": "dinpkt",
    "Sjit": "sjit", "Djit": "djit", "swin": "swin", "stcpb": "stcpb",
    "dtcpb": "dtcpb", "dwin": "dwin", "tcprtt": "tcprtt", "synack": "synack",
    "ackdat": "ackdat", "smeansz": "smean", "dmeansz": "dmean",
    "trans_depth": "trans_depth", "res_bdy_len": "response_body_len",
    "ct_srv_src": "ct_srv_src", "ct_state_ttl": "ct_state_ttl", "ct_dst_ltm": "ct_dst_ltm",
    "ct_src_dport_ltm": "ct_src_dport_ltm", "ct_dst_sport_ltm": "ct_dst_sport_ltm",
    "ct_dst_src_ltm": "ct_dst_src_ltm", "is_ftp_login": "is_ftp_login",
    "ct_ftp_cmd": "ct_ftp_cmd", "ct_flw_http_mthd": "ct_flw_http_mthd",
    "ct_src_ltm": "ct_src_ltm", "ct_srv_dst": "ct_srv_dst",
    "is_sm_ips_ports": "is_sm_ips_ports",
}
V0_FEATURES = [
    "dur", "proto", "service", "state", "spkts", "dpkts", "sbytes", "dbytes", "rate",
    "sttl", "dttl", "sload", "dload", "sloss", "dloss", "sinpkt", "dinpkt", "sjit", "djit",
    "swin", "stcpb", "dtcpb", "dwin", "tcprtt", "synack", "ackdat", "smean", "dmean",
    "trans_depth", "response_body_len", "ct_srv_src", "ct_state_ttl", "ct_dst_ltm",
    "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm", "is_ftp_login", "ct_ftp_cmd",
    "ct_flw_http_mthd", "ct_src_ltm", "ct_srv_dst", "is_sm_ips_ports",
]
RAW_TO_SUBSET["rate"] = "rate (derived: (Spkts + Dpkts - 1) / dur; dur=0 -> missing)"
SUBSET_TO_RAW = {value: key for key, value in RAW_TO_SUBSET.items() if key != "rate"}
SOURCE_AUDIT_FULL_ROW_DUPLICATES = 266


def audit_duplicate_counts(parsed_exact: int, source_audit: int = SOURCE_AUDIT_FULL_ROW_DUPLICATES) -> dict:
    return {
        "parsed_exact_duplicate_rows": int(parsed_exact),
        "source_audit_exact_duplicate_rows": int(source_audit),
        "source_audit_reconciled": int(parsed_exact) == int(source_audit),
        "source_audit_note": (
            "source manifest uses a different duplicate-audit scope; parsed exact duplicates are retained for this run"
            if int(parsed_exact) != int(source_audit)
            else "parsed exact duplicates reconcile with the source manifest"
        ),
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def feature_names(data_root: Path = DATA_ROOT) -> list[str]:
    dictionary = pd.read_csv(data_root / "NUSW-NB15_features.csv", encoding="cp1252")
    names = dictionary["Name"].astype(str).str.strip().tolist()
    if len(names) != 49 or len(set(names)) != 49:
        raise ValueError(f"feature dictionary must define 49 unique columns, got {len(names)}")
    return names


def verify_source_files(data_root: Path = DATA_ROOT) -> dict:
    files = ["NUSW-NB15_features.csv", *RAW_FILES, SUBSET_TRAIN_FILE, SUBSET_TEST_FILE]
    manifest = {"source": "mrwellsdavid/unsw-nb15", "files": {}}
    for name in files:
        path = data_root / name
        if not path.is_file():
            raise FileNotFoundError(path)
        digest = sha256_file(path)
        expected = EXPECTED_HASHES[name]
        if digest != expected:
            raise ValueError(f"SHA-256 mismatch for {name}: {digest}")
        manifest["files"][name] = {"bytes": path.stat().st_size, "sha256": digest}
    return manifest


def load_raw(data_root: Path = DATA_ROOT, verify_hashes: bool = True) -> tuple[pd.DataFrame, dict]:
    if verify_hashes:
        file_manifest = verify_source_files(data_root)
    else:
        file_manifest = {"files": {}}
    names = feature_names(data_root)
    frames = []
    for filename in RAW_FILES:
        frame = pd.read_csv(data_root / filename, header=None, names=names, encoding="utf-8-sig", low_memory=False)
        if frame.shape[1] != 49:
            raise ValueError(f"{filename} has {frame.shape[1]} columns")
        frames.append(frame)
        file_manifest["files"].setdefault(filename, {})["rows"] = int(len(frame))
    data = pd.concat(frames, ignore_index=True)
    data.columns = [str(c).strip().replace(" ", "") for c in data.columns]
    data["attack_cat"] = data["attack_cat"].astype("string").str.strip().replace({"": pd.NA, "Backdoor": "Backdoors"})
    data[TARGET] = pd.to_numeric(data[TARGET], errors="raise").astype("int8")
    if set(data[TARGET].unique()) != {0, 1}:
        raise ValueError("binary labels must be exactly 0=normal and 1=attack")
    if len(data) != 2_540_047:
        raise ValueError(f"raw row count mismatch: {len(data)}")
    missing = int(data.isna().sum().sum())
    duplicates = int(data.duplicated(keep="first").sum())
    raw_label_counts = {str(k): int(v) for k, v in data[TARGET].value_counts().sort_index().items()}
    data = data.drop_duplicates(keep="first").reset_index(drop=True)
    manifest = {
        **file_manifest,
        "dataset": "UNSW-NB15",
        "source_url": "https://www.kaggle.com/datasets/mrwellsdavid/unsw-nb15",
        "license": "Kaggle lists unknown; dataset description grants academic research use with attribution; verify original terms before redistribution/commercial use.",
        "raw_rows": 2_540_047,
        "raw_columns": 49,
        "missing_cells_after_normalization": missing,
        "exact_duplicate_rows_removed": duplicates,
        "duplicate_audit": audit_duplicate_counts(duplicates),
        "raw_label_counts": raw_label_counts,
        "rows_after_deduplication": int(len(data)),
        "label_counts_after_deduplication": {str(k): int(v) for k, v in data[TARGET].value_counts().sort_index().items()},
        "subset_split_mapping": {"train": SUBSET_TRAIN_FILE, "test": SUBSET_TEST_FILE},
        "raw_to_subset_mapping": {"mapped_fields": SUBSET_TO_RAW, "derived_fields": {"rate": "(Spkts + Dpkts - 1) / dur; dur=0 -> missing"}},
    }
    manifest["data_fingerprint"] = hash_frame(data)
    return data, manifest


def hash_frame(frame: pd.DataFrame) -> str:
    digest = hashlib.sha256()
    digest.update("\x1f".join(map(str, frame.columns)).encode())
    hashes = pd.util.hash_pandas_object(frame, index=False, categorize=True).to_numpy(dtype="uint64")
    digest.update(hashes.tobytes())
    return digest.hexdigest()


def make_split(labels: pd.Series, seed: int) -> dict[str, np.ndarray]:
    indices = np.arange(len(labels))
    train_idx, remainder = train_test_split(indices, test_size=0.30, random_state=seed, stratify=labels)
    valid_idx, test_idx = train_test_split(remainder, test_size=0.50, random_state=seed, stratify=labels.iloc[remainder])
    return {"train": train_idx, "validation": valid_idx, "test": test_idx}


def prepare_v0_features(frame: pd.DataFrame) -> pd.DataFrame:
    missing = sorted(set(SUBSET_TO_RAW) - set(frame.columns))
    required = {"Spkts", "Dpkts", "dur"}
    if not required.issubset(frame.columns):
        raise ValueError(f"raw flow schema cannot produce V0; missing={sorted(required - set(frame.columns))}")
    # Complete raw files provide every mapped field.  Missing columns are
    # materialized as NaN for small fixtures and are then handled by the
    # train-fitted imputer; no value is fabricated here.
    fields = {}
    for name in V0_FEATURES:
        if name == "rate":
            continue
        raw_name = SUBSET_TO_RAW[name]
        fields[name] = frame[raw_name] if raw_name in frame else pd.Series(np.nan, index=frame.index)
    features = pd.DataFrame(fields, index=frame.index)
    features.columns = [name for name in V0_FEATURES if name != "rate"]
    duration = pd.to_numeric(frame["dur"], errors="coerce")
    packet_count = pd.to_numeric(frame["Spkts"], errors="coerce") + pd.to_numeric(frame["Dpkts"], errors="coerce") - 1
    rate = packet_count.div(duration.where(duration != 0))
    rate = rate.replace([np.inf, -np.inf], np.nan)
    insert_at = V0_FEATURES.index("rate")
    features.insert(insert_at, "rate", rate)
    return features[V0_FEATURES]


def deduplicate_v0_rows(frame: pd.DataFrame, features: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, int]:
    if len(frame) != len(features):
        raise ValueError("raw records and V0 features must have the same row count")
    keyed = features.assign(_target=frame[TARGET].to_numpy())
    signatures = pd.util.hash_pandas_object(keyed, index=False, categorize=True)
    keep = ~signatures.duplicated(keep="first")
    removed = int((~keep).sum())
    return frame.loc[keep].reset_index(drop=True), features.loc[keep].reset_index(drop=True), removed


def endpoint_group_ids(frame: pd.DataFrame) -> np.ndarray:
    src = frame["srcip"].astype(str).to_numpy()
    dst = frame["dstip"].astype(str).to_numpy()
    return np.array(["|".join(sorted((left, right))) for left, right in zip(src, dst, strict=True)], dtype=object)


def split_audit(frame: pd.DataFrame, split: dict[str, np.ndarray], model_features: pd.DataFrame | None = None) -> dict:
    partition_hashes: dict[str, set[int]] = {}
    feature_hashes: dict[str, set[int]] = {}
    groups = endpoint_group_ids(frame)
    group_sets = {}
    result = {"partitions": {}, "exact_feature_target_overlap": {}, "endpoint_group_overlap": {}}
    leakage_features = model_features if model_features is not None else frame.drop(columns=[TARGET, "attack_cat"], errors="ignore")
    keyed_frame = leakage_features.assign(_target=frame[TARGET].to_numpy())
    keyed = pd.util.hash_pandas_object(keyed_frame, index=False, categorize=True).to_numpy(dtype="uint64")
    feature_only = pd.util.hash_pandas_object(leakage_features, index=False, categorize=True).to_numpy(dtype="uint64")
    for name, ids in split.items():
        partition_hashes[name] = set(map(int, keyed[ids]))
        feature_hashes[name] = set(map(int, feature_only[ids]))
        group_sets[name] = set(groups[ids])
        result["partitions"][name] = {
            "rows": int(len(ids)),
            "fraction": float(len(ids) / len(frame)),
            "label_counts": {str(k): int(v) for k, v in frame.iloc[ids][TARGET].value_counts().sort_index().items()},
            "fingerprint": hash_frame(frame.iloc[ids].reset_index(drop=True)),
            "endpoint_group_count": int(len(group_sets[name])),
        }
    names = list(split)
    for i, left in enumerate(names):
        for right in names[i + 1:]:
            result["exact_feature_target_overlap"][f"{left}:{right}"] = len(partition_hashes[left] & partition_hashes[right])
            result.setdefault("feature_vector_overlap", {})[f"{left}:{right}"] = len(feature_hashes[left] & feature_hashes[right])
            result["endpoint_group_overlap"][f"{left}:{right}"] = len(group_sets[left] & group_sets[right])
    return result


def endpoint_stress_split(frame: pd.DataFrame, seed: int) -> tuple[dict[str, np.ndarray], dict]:
    groups = endpoint_group_ids(frame)
    unique = np.unique(groups)
    if len(unique) < 3:
        raise ValueError("endpoint stress split requires at least three unique groups")
    rng = np.random.default_rng(seed)
    rng.shuffle(unique)
    train_end = min(max(1, int(len(unique) * 0.70)), len(unique) - 2)
    valid_end = min(max(train_end + 1, int(len(unique) * 0.85)), len(unique) - 1)
    group_assignment = {g: "train" for g in unique[:train_end]}
    group_assignment.update({g: "validation" for g in unique[train_end:valid_end]})
    group_assignment.update({g: "test" for g in unique[valid_end:]})
    split = {name: np.flatnonzero(np.isin(groups, [g for g, part in group_assignment.items() if part == name])) for name in ("train", "validation", "test")}
    labels = {name: sorted(map(int, frame.iloc[ids][TARGET].unique())) for name, ids in split.items()}
    audit = {
        "method": "randomized whole unordered endpoint-pair groups; diagnostic only",
        "seed": seed,
        "total_endpoint_groups": int(len(unique)),
        "group_counts": {name: int(sum(part == name for part in group_assignment.values())) for name in ("train", "validation", "test")},
        "row_counts": {name: int(len(ids)) for name, ids in split.items()},
        "class_coverage": labels,
        "evaluable": all(values == [0, 1] for values in labels.values()),
        "group_overlap": {"train:validation": 0, "train:test": 0, "validation:test": 0},
        "warning": "UNSW-NB15 has a small endpoint universe; this split is a stress test, not a stable deployment-generalization estimate.",
    }
    return split, audit


def load_subset_audit(data_root: Path = DATA_ROOT) -> dict:
    train = pd.read_csv(data_root / SUBSET_TRAIN_FILE, encoding="utf-8-sig", low_memory=False)
    test = pd.read_csv(data_root / SUBSET_TEST_FILE, encoding="utf-8-sig", low_memory=False)
    if len(train) != 175_341 or len(test) != 82_332:
        raise ValueError("predefined subset row counts do not match audited reversed filename mapping")
    for frame in (train, test):
        if "label" not in frame or "attack_cat" not in frame:
            raise ValueError("subset schema missing label or attack_cat")
    train_clean = train.drop(columns=["id"], errors="ignore").copy()
    test_clean = test.drop(columns=["id"], errors="ignore").copy()
    for subset in (train_clean, test_clean):
        subset["attack_cat"] = subset["attack_cat"].astype("string").str.strip().replace({"Backdoor": "Backdoors"})
    train_hash = pd.util.hash_pandas_object(train_clean, index=False, categorize=True).value_counts()
    test_hash = pd.util.hash_pandas_object(test_clean, index=False, categorize=True).value_counts()
    return {
        "mapping": {"train": SUBSET_TRAIN_FILE, "test": SUBSET_TEST_FILE},
        "train_rows": len(train), "test_rows": len(test),
        "train_label_counts": {str(k): int(v) for k, v in train["label"].value_counts().sort_index().items()},
        "test_label_counts": {str(k): int(v) for k, v in test["label"].value_counts().sort_index().items()},
        "exact_overlap_excluding_id": int(sum(min(int(train_hash.get(key, 0)), int(test_hash.get(key, 0))) for key in train_hash.index.intersection(test_hash.index))),
        "multiclass_labels": sorted(train["attack_cat"].astype(str).str.strip().unique().tolist()),
        "used_in_raw_training": False,
    }


def _json_safe(value):
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, np.ndarray):
        return _json_safe(value.tolist())
    if isinstance(value, np.generic):
        return value.item()
    if isinstance(value, Path):
        return str(value)
    return value


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_json_safe(value), indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
