"""验证冻结输入、隔离数据角色并构造模型张量；绝不搜索或读取 final_test。"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import numpy as np

ROLES = ("train", "validation_selection", "validation_calibration")


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write(path, value):
    """独占创建证据文件，失败和既有实验均不覆盖。"""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")


def time_ms(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000


def contract_validator(contracts, name):
    """显式实现date-time检查，避免jsonschema缺少可选依赖时静默跳过格式验证。"""
    from jsonschema import Draft202012Validator, FormatChecker
    checker = FormatChecker()
    @checker.checks("date-time", raises=(ValueError, TypeError))
    def valid_date(value):
        if not isinstance(value, str):
            return True
        return datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is not None
    if checker.conforms("2026-19-40T00:00:00Z", "date-time") or checker.conforms("invalid", "uuid"):
        raise ValueError("格式验证器未生效")
    schema = read(Path(contracts) / f"docs/contracts/{name}.schema.json")
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=checker)


@dataclass
class Batch:
    rows: list[dict]
    observations: list[dict]
    values: np.ndarray
    missing: np.ndarray
    categories: np.ndarray
    role: str

    @property
    def y(self):
        return np.asarray([row["label"] for row in self.rows], dtype=np.int64)

    @property
    def weights(self):
        return np.asarray([row["sampleWeight"] for row in self.rows], dtype=np.float64)

    def take(self, indices):
        ids = np.asarray(indices, dtype=np.int64)
        return Batch([self.rows[i] for i in ids], [self.observations[i] for i in ids],
                     self.values[ids], self.missing[ids], self.categories[ids], self.role)


def vector(observation, profile):
    """按冻结顺序展开窗口；未知字段不参与模型，非结构性缺失及非有限值直接拒绝。"""
    contexts = observation["contexts"]
    if [row["windowSeconds"] for row in contexts] != [1, 5, 30]:
        raise ValueError("上下文顺序不符")
    numeric, missing = [], []
    for name in profile["numericFeatures"]:
        parts = name.split(".")
        value = (observation["features"][parts[1]] if parts[0] == "features" else
                 contexts[[1, 5, 30].index(int(parts[1]))][parts[2]])
        if value is None and name not in profile["nullableNumericFeatures"]:
            raise ValueError("不可空特征缺失")
        mask = float(value is None)
        numeric.append(0.0 if value is None else float(value))
        missing.append(mask)
    values = np.asarray(numeric, dtype=np.float32)
    if not np.isfinite(values).all() or np.any(values < 0):
        raise ValueError("非法数值特征")
    return values, np.asarray(missing, dtype=np.float32), [observation[k] for k in profile["categoricalFeatures"]]


class Dataset:
    """校准访问要求已落盘的选型锁；加载器不接受任意分区名或 final 路径。"""
    def __init__(self, root, contracts, public, plan, audit_path):
        self.root, self.contracts, self.public = map(Path, (root, contracts, public))
        self.plan, self.audit_path = plan, Path(audit_path)
        if plan.get("candidateOnly") is not True or plan.get("finalTestRead") is not False:
            raise ValueError("实验计划越过候选/最终测试边界")
        freeze_path = self.public / "docs/p2/data-readiness/freeze-manifest.json"
        software_path = self.contracts / "docs/p2/freeze-manifest.json"
        for path, expected in [(freeze_path, plan["datasetFreezeSha256"]),
                               (software_path, plan["softwareFreezeSha256"]),
                               (self.contracts / "docs/contracts/feature-profile.json", plan["featureProfileSha256"])]:
            if sha(path) != expected:
                raise ValueError("冻结入口哈希不符: " + path.name)
        freeze, software = read(freeze_path), read(software_path)
        for folder, entries in [(self.public, freeze["publicFiles"]), (self.contracts, software["files"]),
                                (self.root, freeze["datasetFiles"])]:
            for name, expected in entries.items():
                if sha(folder / name) != expected:
                    raise ValueError("冻结文件被修改: " + name)
        spec = importlib.util.spec_from_file_location("p2_verifier", self.public / "scripts/p2/data_readiness/verify_dataset.py")
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        self.verification = verifier.verify(self.root)
        self.profile = read(self.contracts / "docs/contracts/feature-profile.json")
        # 同时与模型 schema 中不可变的顺序常量核对，拒绝保持版本号但改序。
        model_schema = read(self.contracts / "docs/contracts/model-manifest.schema.json")
        for name in ("numericFeatures", "categoricalFeatures"):
            if self.profile[name] != model_schema["properties"][name]["const"]:
                raise ValueError("模型 schema 与 profile 顺序不同")
        self.verification["trainingExecuted"] = False
        self._audit("integrity_only", "all_development_roles")

    def _audit(self, operation, role):
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        with self.audit_path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps({"operation": operation, "role": role, "finalTestRead": False}) + "\n")

    def load(self, role, selection_lock=None):
        if role not in ROLES:
            raise ValueError("禁止访问未批准数据角色")
        if role == "validation_calibration":
            if selection_lock is None or not Path(selection_lock).is_file():
                raise ValueError("校准前必须冻结模型选型")
            lock = read(selection_lock)
            if not lock.get("selectionFrozen") or lock.get("calibrationUsedForSelection") is not False:
                raise ValueError("无效选型锁")
            frozen_model = Path(selection_lock).parent / "experiments" / lock["experimentId"] / "model.onnx"
            if sha(frozen_model) != lock["artifactSha256"]:
                raise ValueError("选型锁模型哈希不符")
        rows, obs, vals, masks, cats = [], [], [], [], []
        with (self.root / "index.jsonl").open(encoding="utf-8") as index, (self.root / "observations.jsonl").open(encoding="utf-8") as observations:
            for a, b in zip(index, observations, strict=True):
                row = json.loads(a)
                if row["split"] != role:
                    continue
                o = json.loads(b)
                v, m, c = vector(o, self.profile)
                rows.append(row); obs.append(o); vals.append(v); masks.append(m); cats.append(c)
        if not rows or len({row["label"] for row in rows}) != 2:
            raise ValueError("角色缺少正负例")
        self._audit("load_features", role)
        return Batch(rows, obs, np.asarray(vals), np.asarray(masks), np.asarray(cats), role)


class Preprocessor:
    """仅 train 加权拟合插补/缩放/类别表；未知类别为0，观察类别从1编码。"""
    def __init__(self, parameters):
        self.parameters = parameters

    @classmethod
    def fit(cls, batch, feature_set="context"):
        if batch.role != "train":
            raise ValueError("预处理只能拟合 train")
        logged = np.log1p(batch.values.astype(np.float64))
        observed = 1.0 - batch.missing
        weights = batch.weights[:, None] * observed
        mean = (logged * weights).sum(axis=0) / np.maximum(weights.sum(axis=0), 1e-12)
        filled = np.where(batch.missing == 1, mean, logged)
        variance = np.average((filled - mean) ** 2, weights=batch.weights, axis=0)
        scale = np.where(variance > 1e-12, np.sqrt(variance), 1.0)
        if feature_set not in ("base", "context", "no_host_context", "peer_context"):
            raise ValueError("未知特征消融")
        indices = list(range(16 if feature_set == "base" else 43))
        if feature_set == "no_host_context":
            indices = [i for i in indices if i < 16 or (i - 16) % 9 not in (0, 5, 6)]
        if feature_set == "peer_context":
            # 新prefix实验只增加对端上下文，显式排除主机全局连接数和对端数。
            indices = [i for i in indices if i < 16 or (i - 16) % 9 not in (5, 6)]
        return cls({"version": "p3-preprocess-v1", "fitRole": "train", "numericFeatureCount": 43,
                    "meanLog": mean.astype(np.float32).tolist(), "scaleLog": scale.astype(np.float32).tolist(),
                    "indices": indices, "featureSet": feature_set, "unknownCategoryCode": 0,
                    "vocabularies": [sorted(set(batch.categories[:, i])) for i in range(3)]})

    def codes(self, batch):
        return np.asarray([[({v: j + 1 for j, v in enumerate(vocab)}).get(value, 0)
                            for value, vocab in zip(row, self.parameters["vocabularies"], strict=True)]
                           for row in batch.categories], dtype=np.int64)

    def feed(self, batch):
        return {"numeric_values": batch.values, "numeric_missing": batch.missing, "categorical_codes": self.codes(batch)}

    def transform(self, batch):
        mean = np.asarray(self.parameters["meanLog"], dtype=np.float32)
        scale = np.asarray(self.parameters["scaleLog"], dtype=np.float32)
        logged = np.log(batch.values + np.float32(1))
        filled = np.where(batch.missing == 1, mean, logged)
        ids = self.parameters["indices"]
        return np.concatenate([((filled - mean) / scale)[:, ids], batch.missing[:, ids],
                               self.codes(batch).astype(np.float32)], axis=1).astype(np.float32)
