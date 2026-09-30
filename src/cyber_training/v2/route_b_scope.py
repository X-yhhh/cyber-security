"""开发路线阶段 1 模型线 A1：收窄评估范围的 ``2026.10.2`` 交付（命令 ``scope-v4``）。

``2026.10.1`` 在本机受控实验中暴露：UDP 单包应答与看不到握手的 TCP 片段大量误报（main 仓库路线 B §13.8.1）。
``2026.10.2`` 只在 manifest 中收窄评估范围，不训练、不改权重/阈值/预处理/基线：

- ``feature_contract.supported_protocols = ["tcp"]``、``feature_contract.requires_handshake_seen = true``：
  与已有的 ``supported_viewpoints``/``supported_address_families`` 一起，评估范围为 responder + IPv4 + TCP +
  ``handshakeSeen=true``。``handshakeSeen`` 是 v4 契约的记录元数据，不进模型输入，因此不改契约、不改冻结规格。
  范围外记录由后端推理门禁记为 ``not_in_model_scope``，交给规则引擎。
- ``limitations`` 追加一条范围说明；``provenance.derived_from`` 记录源版本与源 manifest 哈希。
- 其余文件逐字节复制（含 ONNX、fixtures、``feature_baseline_stats``），重建 ``checksums.json``。

``feature_baseline_stats`` 保持 ``2026.10.1`` 的训练分区口径（responder + IPv4，全部协议）：UNSW CSV 没有逐包信息，
训练端无法按 ``handshake_seen`` 重算同口径基线。PSI 因此是“收窄后的线上分布 vs 原训练分布”，报告须如实说明。
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .export import DELIVERY_ROOT, MODEL_KEY
from .route_b_baseline import (EXPECTED_ONNX_SHA256, DeliveryError, delivery_checksums, delivery_json_bytes,
                               diff_json, validate_baseline)
from .runtime import sha256_file

SOURCE_VERSION = "2026.10.1"
TARGET_VERSION = "2026.10.2"
SCOPE_PROTOCOLS = ["tcp"]
REQUIRES_HANDSHAKE_SEEN = True
REWRITTEN = ("model_manifest.json", "checksums.json")
ALLOWED_DIFF = ("/model_version", "/version", "/created_at", "/provenance/derived_from",
                "/feature_contract/supported_protocols", "/feature_contract/requires_handshake_seen", "/limitations")
DERIVED_CHANGE = ("仅收窄评估范围：supported_protocols=[tcp]、requires_handshake_seen=true；"
                  "权重、预处理、阈值、fixtures、feature_baseline_stats 不变")
SCOPE_LIMITATION = ("2026.10.2 起评估范围收窄为 responder + IPv4 + TCP + handshake_seen=true：UDP、ICMP 与看不到握手的 TCP 片段"
                    "记为 not_in_model_scope，由规则引擎覆盖；feature_baseline_stats 仍为 2026.10.1 的训练分区口径"
                    "（responder + IPv4，全部协议），PSI 为收窄后的线上分布对原训练分布。")


def build_manifest(old: dict[str, Any], old_sha256: str, version: str, created_at: str) -> dict[str, Any]:
    """新 manifest = 旧 manifest 深拷贝；只改版本、时间、评估范围两项、``limitations`` 与 ``provenance.derived_from``。"""
    fc = old.get("feature_contract", {})
    if fc.get("supported_viewpoints") != ["responder"] or fc.get("supported_address_families") != ["ipv4"]:
        raise DeliveryError("source manifest scope is not responder + ipv4; refusing to narrow an unexpected scope")
    if "supported_protocols" in fc or "requires_handshake_seen" in fc:
        raise DeliveryError("source manifest already declares protocol/handshake scope")
    m = copy.deepcopy(old)
    m["model_version"], m["version"], m["created_at"] = f"{MODEL_KEY}-{version}", version, created_at
    m["feature_contract"]["supported_protocols"] = list(SCOPE_PROTOCOLS)
    m["feature_contract"]["requires_handshake_seen"] = REQUIRES_HANDSHAKE_SEEN
    m["limitations"] = [*old.get("limitations", []), SCOPE_LIMITATION]
    m["provenance"]["derived_from"] = _derived(old, old_sha256)
    return m


def _derived(old: dict[str, Any], old_sha256: str) -> dict[str, Any]:
    """派生记录；源 manifest 自身的派生记录保留在 ``previous`` 中，形成可追溯的版本链。"""
    record = {"model_version": old["model_version"], "manifest_sha256": old_sha256, "change": DERIVED_CHANGE}
    if "derived_from" in old.get("provenance", {}):
        record["previous"] = old["provenance"]["derived_from"]
    return record


def diff_allowed(diff: list[str]) -> bool:
    """差异路径全部落在允许的键（或其子路径）内，且每个允许的键都确有变化。"""
    covered = {a for a in ALLOWED_DIFF for d in diff if d == a or d.startswith(a + "/")}
    return all(any(d == a or d.startswith(a + "/") for a in ALLOWED_DIFF) for d in diff) and covered == set(ALLOWED_DIFF)


def _source_entries(source: Path) -> list[str]:
    names = sorted(p.name for p in source.iterdir())
    if not set(REWRITTEN) <= set(names) or "model.onnx" not in names:
        raise DeliveryError("unexpected source delivery layout")
    return [n for n in names if n not in REWRITTEN]


def package(source_delivery: Path, delivery_root: Path, version: str = TARGET_VERSION, created_at: str | None = None,
            expected_onnx_sha256: str = EXPECTED_ONNX_SHA256) -> Path:
    """写 ``<delivery_root>/unsw-binary-<version>/``；目标已存在、源交付校验失败或格式不符即终止。返回交付目录。"""
    source = Path(source_delivery)
    target = Path(delivery_root) / f"{MODEL_KEY}-{version}"
    if target.exists():
        raise FileExistsError(f"delivery directory already exists: {target.name}")
    declared = json.loads((source / "checksums.json").read_text(encoding="utf-8"))
    actual = delivery_checksums(source)
    old_bytes = (source / "model_manifest.json").read_bytes()
    old = json.loads(old_bytes)
    if set(declared) != set(actual) or any(actual[k] != v for k, v in declared.items()):
        raise DeliveryError("source delivery failed checksum verification")
    if old["artifact"]["sha256"] != expected_onnx_sha256 or sha256_file(source / "model.onnx") != expected_onnx_sha256:
        raise DeliveryError("source model.onnx is not the expected artifact")
    if delivery_json_bytes(old) != old_bytes:
        raise DeliveryError("source manifest is not in the expected JSON byte format; cannot guarantee minimal diff")
    if validate_baseline(old.get("feature_baseline_stats")):
        raise DeliveryError("source manifest has no valid feature_baseline_stats")
    created_at = created_at or datetime.now(timezone.utc).isoformat()
    new = build_manifest(old, hashlib.sha256(old_bytes).hexdigest(), version, created_at)

    entries = _source_entries(source)
    target.mkdir(parents=False)
    for name in entries:
        src = source / name
        (shutil.copytree if src.is_dir() else shutil.copy2)(src, target / name)
    (target / "model_manifest.json").write_bytes(delivery_json_bytes(new))
    (target / "checksums.json").write_bytes(delivery_json_bytes(delivery_checksums(target)))
    for name in (".", *REWRITTEN):
        os.chmod(target / name, stat.S_IMODE((source / name).stat().st_mode))
    return target


def verify(delivery: Path, source_delivery: Path, expected_onnx_sha256: str = EXPECTED_ONNX_SHA256,
           version: str = TARGET_VERSION) -> dict[str, Any]:
    """交付自校验（只读）。``passed`` 为全部检查项的合取；记录不含主机路径。"""
    new_dir, old_dir = Path(delivery), Path(source_delivery)
    old_bytes, new_bytes = (old_dir / "model_manifest.json").read_bytes(), (new_dir / "model_manifest.json").read_bytes()
    old, new = json.loads(old_bytes), json.loads(new_bytes)
    c: dict[str, bool] = {}
    declared = json.loads((new_dir / "checksums.json").read_text(encoding="utf-8"))
    actual = delivery_checksums(new_dir)
    c["checksums_cover_all_files"] = set(declared) == set(actual)
    c["checksums_match"] = all(actual.get(k) == v for k, v in declared.items())
    onnx_sha = sha256_file(new_dir / "model.onnx")
    c["model_onnx_sha256_expected"] = onnx_sha == expected_onnx_sha256 == new["artifact"]["sha256"]
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
    c["manifest_diff_only_allowed"] = diff_allowed(diff)
    fc = new["feature_contract"]
    c["scope_values"] = (fc.get("supported_viewpoints") == ["responder"] and fc.get("supported_address_families") == ["ipv4"]
                         and fc.get("supported_protocols") == SCOPE_PROTOCOLS
                         and fc.get("requires_handshake_seen") is REQUIRES_HANDSHAKE_SEEN)
    c["baseline_unchanged"] = new.get("feature_baseline_stats") == old.get("feature_baseline_stats")
    c["decision_unchanged"] = new.get("decision") == old.get("decision") and new["decision"].get("adjustable") is False
    c["manifest_values"] = (new["model_version"] == f"{MODEL_KEY}-{version}" and new["version"] == version
                            and new["created_at"].endswith("+00:00") and new["activation"]["status"] == "candidate"
                            and new["limitations"][-1] == SCOPE_LIMITATION
                            and new["provenance"]["derived_from"] == _derived(old, hashlib.sha256(old_bytes).hexdigest()))
    c["manifest_json_format_crlf"] = delivery_json_bytes(new) == new_bytes
    modes = {}
    for k in {".", *old_files, *{p.relative_to(old_dir).as_posix() for p in old_dir.rglob("*") if p.is_dir()}}:
        modes[k] = stat.S_IMODE((old_dir / k).stat().st_mode) == stat.S_IMODE((new_dir / k).stat().st_mode)
    c["permissions_match_source"] = all(modes.values())
    return {"delivery": new_dir.name, "source_delivery": old_dir.name, "passed": all(c.values()), "checks": c,
            "manifest_sha256": sha256_file(new_dir / "model_manifest.json"),
            "source_manifest_sha256": hashlib.sha256(old_bytes).hexdigest(), "model_onnx_sha256": onnx_sha,
            "checksums_sha256": sha256_file(new_dir / "checksums.json"), "manifest_diff": sorted(diff),
            "checksum_entries": len(declared)}


def run(stage: str = "package", source_delivery: Path | None = None, delivery_root: Path | None = None,
        version: str = TARGET_VERSION) -> str:
    """CLI 入口：``package`` 写交付并自校验，``verify`` 只读自校验；失败即抛出。返回自校验记录 JSON。"""
    source_delivery = Path(source_delivery) if source_delivery else DELIVERY_ROOT / f"{MODEL_KEY}-{SOURCE_VERSION}"
    delivery_root = Path(delivery_root) if delivery_root else DELIVERY_ROOT
    if stage == "package":
        target = package(source_delivery, delivery_root, version)
    elif stage == "verify":
        target = delivery_root / f"{MODEL_KEY}-{version}"
    else:
        raise ValueError(f"unknown scope stage: {stage}")
    record = verify(target, source_delivery, version=version)
    if not record["passed"]:
        raise DeliveryError(f"delivery self-check failed: {record['checks']}")
    return json.dumps(record, ensure_ascii=False, indent=2)
