"""锁定 holdout 与"只在训练集拟合"的约束。

``SplitIndex`` 持有 train/validation/holdout 三个分区的行索引。holdout 默认锁定：
未显式解锁时访问即抛出 ``HoldoutLockedError``；解锁需要给出原因，并写入追加式审计日志。
``fit_on_train`` 保证预处理器、采样器只接触训练分区。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np

PARTITIONS = ("train", "validation", "holdout")


class HoldoutLockedError(PermissionError):
    """在未解锁时读取 holdout 分区。"""


class LeakageError(ValueError):
    """拟合数据包含训练分区之外的行。"""


def index_fingerprint(indices: dict[str, np.ndarray]) -> str:
    digest = hashlib.sha256()
    for name in PARTITIONS:
        array = np.ascontiguousarray(np.sort(indices[name]).astype(np.int64))
        digest.update(name.encode())
        digest.update(array.tobytes())
    return digest.hexdigest()


@dataclass
class SplitIndex:
    """分区索引与 holdout 锁。

    输入：三个互不相交的 int64 行索引数组。构造时校验不相交，违反则 fail-closed。
    ``audit_log`` 为追加式 JSONL，每次解锁记录时间、原因与指纹。
    """

    train: np.ndarray
    validation: np.ndarray
    _holdout: np.ndarray
    audit_log: Path | None = None
    _unlocked: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        self.train = np.asarray(self.train, dtype=np.int64)
        self.validation = np.asarray(self.validation, dtype=np.int64)
        self._holdout = np.asarray(self._holdout, dtype=np.int64)
        parts = {"train": self.train, "validation": self.validation, "holdout": self._holdout}
        for a in PARTITIONS:
            for b in PARTITIONS:
                if a < b and np.intersect1d(parts[a], parts[b]).size:
                    raise LeakageError(f"partitions {a} and {b} overlap")

    @property
    def fingerprint(self) -> str:
        return index_fingerprint({"train": self.train, "validation": self.validation, "holdout": self._holdout})

    @property
    def holdout(self) -> np.ndarray:
        if not self._unlocked:
            raise HoldoutLockedError("holdout is locked; call unlock_holdout(reason) from final-eval only")
        return self._holdout

    @property
    def holdout_size(self) -> int:
        return int(self._holdout.size)

    def unlock_holdout(self, reason: str) -> None:
        if not reason or not reason.strip():
            raise ValueError("unlocking the holdout requires a non-empty reason")
        if self.audit_log is None:
            raise HoldoutLockedError("unlocking requires an audit log path")
        self.audit_log.parent.mkdir(parents=True, exist_ok=True)
        with self.audit_log.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({
                "event": "holdout_unlocked",
                "at": datetime.now().astimezone().isoformat(),
                "reason": reason,
                "split_fingerprint": self.fingerprint,
            }, ensure_ascii=False) + "\n")
        self._unlocked = True

    def save(self, path: Path) -> None:
        np.savez_compressed(path, train=self.train, validation=self.validation, holdout=self._holdout)

    @classmethod
    def load(cls, path: Path, audit_log: Path | None = None) -> "SplitIndex":
        with np.load(path) as data:
            return cls(data["train"], data["validation"], data["holdout"], audit_log=audit_log)


def fit_on_train(estimator: Any, frame: Any, rows: np.ndarray, split: SplitIndex, y: Any = None) -> Any:
    """只用训练分区的行拟合 ``estimator``。

    ``rows`` 必须是 ``split.train`` 的子集（允许抽样），否则抛 ``LeakageError``。
    ``frame`` 按位置索引（``iloc``/NumPy 下标）。返回拟合后的 estimator。
    """
    rows = np.asarray(rows, dtype=np.int64)
    if not np.isin(rows, split.train).all():
        raise LeakageError("fit rows include indices outside the training partition")
    subset = frame.iloc[rows] if hasattr(frame, "iloc") else frame[rows]
    if y is None:
        return estimator.fit(subset)
    target = y.iloc[rows] if hasattr(y, "iloc") else np.asarray(y)[rows]
    return estimator.fit(subset, target)
