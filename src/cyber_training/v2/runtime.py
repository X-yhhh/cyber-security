"""运行目录、运行配置记录与全局种子。

每次运行写入 ``runs/<step>-<YYYYMMDD-HHMM>/``，并生成 ``run-config.json``，
记录参数、种子、git commit、依赖版本与 GPU 信息，保证结果可追溯。
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import random
import subprocess
import sys
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from importlib import metadata
from pathlib import Path
from typing import Any

import numpy as np

from ..config import ROOT

RUNS_ROOT = ROOT / "runs"
TRACKED_PACKAGES = (
    "numpy", "pandas", "scikit-learn", "torch", "xgboost", "lightgbm", "imbalanced-learn",
    "optuna", "onnx", "onnxruntime", "skl2onnx", "onnxmltools", "pyarrow",
)


def set_global_seed(seed: int) -> None:
    """固定 Python、NumPy 与（若可用）PyTorch 的随机源；不修改 CUDA 确定性开关以外的全局状态。"""
    random.seed(seed)
    np.random.seed(seed)
    os.environ["PYTHONHASHSEED"] = str(seed)
    try:
        import torch

        torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)
    except ImportError:
        pass


def git_commit(root: Path = ROOT) -> dict[str, Any]:
    """返回当前 commit 与工作区是否干净；git 不可用时显式标记为 unknown，而不是伪造值。"""
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, check=True).stdout.strip()
        dirty = bool(subprocess.run(["git", "status", "--porcelain"], cwd=root, capture_output=True, text=True, check=True).stdout.strip())
        return {"commit": commit, "dirty": dirty}
    except (OSError, subprocess.CalledProcessError):
        return {"commit": "unknown", "dirty": None}


def package_versions() -> dict[str, str | None]:
    versions: dict[str, str | None] = {}
    for name in TRACKED_PACKAGES:
        try:
            versions[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            versions[name] = None
    return versions


def gpu_info() -> dict[str, Any]:
    try:
        import torch

        if not torch.cuda.is_available():
            return {"cuda_available": False}
        props = torch.cuda.get_device_properties(0)
        return {
            "cuda_available": True,
            "name": props.name,
            "total_memory_mib": props.total_memory // (1024 * 1024),
            "torch_cuda": torch.version.cuda,
        }
    except ImportError:
        return {"cuda_available": False, "torch": "missing"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, payload: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    return path


@dataclass
class RunContext:
    """单次运行的上下文。

    输入：步骤名、种子、参数字典。副作用：创建运行目录并写 ``run-config.json``。
    ``finish`` 会为目录内全部产物生成 ``checksums.json``；运行目录已存在时拒绝覆盖（fail-closed）。
    """

    step: str
    seed: int
    params: dict[str, Any] = field(default_factory=dict)
    runs_root: Path = RUNS_ROOT
    run_dir: Path = field(init=False)

    def __post_init__(self) -> None:
        stamp = datetime.now().strftime("%Y%m%d-%H%M")
        self.run_dir = Path(self.runs_root) / f"{self.step}-{stamp}"
        if self.run_dir.exists():
            raise FileExistsError(f"run directory already exists: {self.run_dir}")
        self.run_dir.mkdir(parents=True)
        set_global_seed(self.seed)
        write_json(self.run_dir / "run-config.json", {
            "step": self.step,
            "seed": self.seed,
            "params": self.params,
            "started_at": datetime.now().astimezone().isoformat(),
            "git": git_commit(),
            "python": platform.python_version(),
            "platform": platform.platform(),
            "packages": package_versions(),
            "gpu": gpu_info(),
        })

    def path(self, name: str) -> Path:
        return self.run_dir / name

    def finish(self) -> dict[str, str]:
        return self.checksum_dir(self.run_dir)

    @staticmethod
    def checksum_dir(run_dir: Path) -> dict[str, str]:
        """为运行目录内全部产物（除 checksums.json 自身）生成 SHA-256 清单。"""
        checksums = {
            str(p.relative_to(run_dir)).replace("\\", "/"): sha256_file(p)
            for p in sorted(Path(run_dir).rglob("*"))
            if p.is_file() and p.name != "checksums.json"
        }
        write_json(Path(run_dir) / "checksums.json", checksums)
        return checksums


@contextmanager
def keep_awake():
    """长任务期间阻止 Windows 进入睡眠（ES_CONTINUOUS | ES_SYSTEM_REQUIRED）；非 Windows 无操作。"""
    if sys.platform != "win32":
        yield
        return
    import ctypes

    kernel32 = ctypes.windll.kernel32
    kernel32.SetThreadExecutionState(0x80000000 | 0x00000001)
    try:
        yield
    finally:
        kernel32.SetThreadExecutionState(0x80000000)
