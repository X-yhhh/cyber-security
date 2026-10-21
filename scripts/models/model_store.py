#!/usr/bin/env python3
"""模型版本库 `models/` 的唯一写入口：入库、退役、核验，不提供删除。

每个模型版本（以 manifest 的模型版本号区分）占一个只读子目录，入库后字节不再改写；
退役只改 `registry.json` 中的状态与原因，文件永久保留，便于历史推理按 manifest 摘要追溯。
版本库只做长期存档，不是后端挂载根目录：发布时把版本目录只读复制到
`cyber.guard.artifact-root` 下，再走 /models 登记与发布组合审批。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

STORE = Path(__file__).resolve().parents[2] / "models"
REGISTRY = "registry.json"
SUMS = "SHA256SUMS"
# 后端挂载必需的同目录文件；source-model.onnx 为训练端导出的转换前原件，可选保存。
REQUIRED = ("model.onnx", "preprocessing.json")
OPTIONAL = ("calibration.json", "source-model.onnx")
MANIFESTS = ("model-manifest.json", "model_manifest.json")
VERSION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


class StoreError(RuntimeError):
    """任何哈希、状态或目录不一致都中止，不做部分写入。"""


def sha(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(8 << 20), b""):
            value.update(chunk)
    return value.hexdigest()


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def load_registry(store: Path) -> dict:
    path = store / REGISTRY
    if not path.exists():
        return {"version": "model-store/1", "models": []}
    registry = json.loads(path.read_text(encoding="utf-8"))
    if registry.get("version") != "model-store/1" or not isinstance(registry.get("models"), list):
        raise StoreError("registry.json 版本或结构不符")
    return registry


def save_registry(store: Path, registry: dict) -> None:
    """先写同目录临时文件再原子替换，避免中断留下半个索引。"""
    store.mkdir(parents=True, exist_ok=True)
    text = json.dumps(registry, ensure_ascii=False, indent=2) + "\n"
    fd, temp = tempfile.mkstemp(dir=store, prefix=".registry-", suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(text)
    os.replace(temp, store / REGISTRY)


def manifest_facts(source: Path) -> tuple[str, dict, str]:
    """读取 v5（camelCase）或旧 v4（snake_case）manifest，返回文件名、内容与模型版本号。"""
    names = [name for name in MANIFESTS if (source / name).is_file()]
    if len(names) != 1:
        raise StoreError("源目录必须恰有一个 model-manifest.json 或 model_manifest.json")
    manifest = json.loads((source / names[0]).read_text(encoding="utf-8"))
    version = manifest.get("modelVersion") or manifest.get("model_version")
    if not isinstance(version, str) or not VERSION_PATTERN.fullmatch(version):
        raise StoreError("manifest 缺少合法的模型版本号")
    return names[0], manifest, version


def expected_hashes(manifest: dict) -> dict[str, str]:
    """manifest 声明的制品摘要；入库前逐一核对，声明缺失的文件不得冒充已绑定。"""
    if "artifactSha256" in manifest:
        expected = {"model.onnx": manifest["artifactSha256"], "preprocessing.json": manifest.get("preprocessingSha256")}
        if manifest.get("calibrationSha256"):
            expected["calibration.json"] = manifest["calibrationSha256"]
        return expected
    files = manifest.get("files") or {}
    return {"model.onnx": (manifest.get("artifact") or {}).get("sha256"), "preprocessing.json": files.get("preprocessing.json")}


def collect(source: Path) -> tuple[str, dict, str, list[str]]:
    manifest_name, manifest, version = manifest_facts(source)
    for name in REQUIRED:
        if not (source / name).is_file():
            raise StoreError(f"源目录缺少 {name}")
    for name, digest in expected_hashes(manifest).items():
        if not digest or sha(source / name) != digest:
            raise StoreError(f"{name} 与 manifest 声明的 SHA-256 不符")
    names = [manifest_name, *REQUIRED, *[name for name in OPTIONAL if (source / name).is_file()]]
    return manifest_name, manifest, version, names


def add(store: Path, source: Path, origin: str, note: str | None) -> dict:
    """入库一个新版本；同版本号已存在时，内容一致则视为幂等，否则拒绝覆盖。"""
    manifest_name, manifest, version, names = collect(source)
    registry = load_registry(store)
    digests = {name: sha(source / name) for name in names}
    prior = next((m for m in registry["models"] if m["modelVersion"] == version), None)
    if prior is not None:
        if prior["files"] != digests:
            raise StoreError(f"{version} 已入库且内容不同；新权重或新 manifest 必须使用新版本号")
        return prior
    target = store / version
    if target.exists():
        raise StoreError(f"{target.name} 目录已存在但未登记，先人工核查")
    staging = Path(tempfile.mkdtemp(dir=store if store.exists() else None, prefix=f".{version}-"))
    try:
        for name in names:
            shutil.copyfile(source / name, staging / name)
            if sha(staging / name) != digests[name]:
                raise StoreError(f"复制后 {name} 哈希不符")
        (staging / SUMS).write_text("".join(f"{digests[n]}  {n}\n" for n in sorted(names)), encoding="utf-8")
        for path in staging.iterdir():
            path.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        store.mkdir(parents=True, exist_ok=True)
        staging.rename(target)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    entry = {
        "modelVersion": version,
        "contractVersion": manifest.get("contractVersion") or manifest.get("manifest_version"),
        "algorithm": manifest.get("algorithm") if isinstance(manifest.get("algorithm"), str) else (manifest.get("algorithm") or {}).get("name"),
        "manifestFile": manifest_name,
        "manifestSha256": digests[manifest_name],
        "artifactSha256": digests["model.onnx"],
        "files": digests,
        "source": origin,
        "archivedAt": now(),
        "status": "available",
        "retiredAt": None,
        "retiredReason": None,
        "note": note,
    }
    registry["models"].append(entry)
    save_registry(store, registry)
    return entry


def retire(store: Path, version: str, reason: str) -> dict:
    """只把状态改为 retired 并记录原因；目录与文件保持不动，不可逆。"""
    if not reason.strip():
        raise StoreError("退役必须写明原因")
    registry = load_registry(store)
    entry = next((m for m in registry["models"] if m["modelVersion"] == version), None)
    if entry is None:
        raise StoreError(f"{version} 未入库")
    if entry["status"] == "retired":
        raise StoreError(f"{version} 已退役")
    entry.update({"status": "retired", "retiredAt": now(), "retiredReason": reason.strip()})
    save_registry(store, registry)
    return entry


def verify(store: Path) -> list[str]:
    """核对索引与目录一一对应、每个文件字节未变；返回问题清单，空表示通过。"""
    problems = []
    registry = load_registry(store)
    seen = set()
    for entry in registry["models"]:
        version = entry["modelVersion"]
        if version in seen:
            problems.append(f"{version}: 索引重复")
        seen.add(version)
        if entry.get("status") not in ("available", "retired"):
            problems.append(f"{version}: 未知状态 {entry.get('status')}")
        directory = store / version
        if not directory.is_dir():
            problems.append(f"{version}: 目录缺失（版本不得删除）")
            continue
        present = {p.name for p in directory.iterdir()} - {SUMS}
        if present != set(entry["files"]):
            problems.append(f"{version}: 文件清单与索引不符")
        for name, digest in entry["files"].items():
            if (directory / name).is_file() and sha(directory / name) != digest:
                problems.append(f"{version}: {name} 哈希改变")
    for directory in store.iterdir() if store.exists() else ():
        if directory.is_dir() and not directory.name.startswith(".") and directory.name not in seen:
            problems.append(f"{directory.name}: 目录未登记")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--store", type=Path, default=STORE, help=argparse.SUPPRESS)
    commands = parser.add_subparsers(dest="command", required=True)
    add_cmd = commands.add_parser("add", help="从冻结目录入库一个模型版本")
    add_cmd.add_argument("--source", type=Path, required=True, help="含 manifest、model.onnx、preprocessing.json 的冻结目录")
    add_cmd.add_argument("--origin", required=True, help="来源说明（仓库相对路径或 ~ 开头），写入索引，不得含绝对用户路径")
    add_cmd.add_argument("--note")
    retire_cmd = commands.add_parser("retire", help="退役一个版本（不删除文件）")
    retire_cmd.add_argument("--version", required=True)
    retire_cmd.add_argument("--reason", required=True)
    commands.add_parser("verify", help="核验索引与全部版本文件")
    args = parser.parse_args(argv)
    try:
        if args.command == "add":
            if args.origin.startswith("/"):
                raise StoreError("--origin 不得为绝对路径")
            print(json.dumps(add(args.store, args.source, args.origin, args.note), ensure_ascii=False, indent=2))
        elif args.command == "retire":
            print(json.dumps(retire(args.store, args.version, args.reason), ensure_ascii=False, indent=2))
        else:
            problems = verify(args.store)
            for problem in problems:
                print(problem, file=sys.stderr)
            print("passed" if not problems else "failed")
            return 1 if problems else 0
    except StoreError as error:
        print(f"拒绝：{error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
