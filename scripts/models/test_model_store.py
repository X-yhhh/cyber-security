"""模型版本库只追加、退役不删、核验能发现篡改与缺失的协议测试。"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("model_store", Path(__file__).with_name("model_store.py"))
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def frozen(root: Path, version: str, weights: bytes = b"onnx-bytes", legacy: bool = False) -> Path:
    """合成冻结目录；字节为占位符，只验证存档协议，不代表真实模型。"""
    source = root / f"src-{version}-{digest(weights)[:6]}"
    source.mkdir(exist_ok=True)
    pre, cal = b'{"fitRole":"train"}', b'{"method":"none"}'
    (source / "model.onnx").write_bytes(weights)
    (source / "preprocessing.json").write_bytes(pre)
    if legacy:
        manifest = {"manifest_version": "1.0", "model_version": version, "artifact": {"sha256": digest(weights)},
                    "files": {"preprocessing.json": digest(pre)}}
        (source / "model_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    else:
        (source / "calibration.json").write_bytes(cal)
        manifest = {"contractVersion": "host-guard/5.0.0-rc.3", "modelVersion": version, "algorithm": "lightgbm",
                    "artifactSha256": digest(weights), "preprocessingSha256": digest(pre), "calibrationSha256": digest(cal)}
        (source / "model-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return source


class ModelStoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = self.root / "models"

    def tearDown(self) -> None:
        for path in self.root.rglob("*"):
            path.chmod(0o700)
        self.temp.cleanup()

    def test_add_copies_read_only_files_and_registers_available(self) -> None:
        entry = MODULE.add(self.store, frozen(self.root, "v1"), ".cache/x/prepared-v1", None)
        self.assertEqual(entry["status"], "available")
        directory = self.store / "v1"
        self.assertEqual(sorted(p.name for p in directory.iterdir()),
                         ["SHA256SUMS", "calibration.json", "model-manifest.json", "model.onnx", "preprocessing.json"])
        self.assertFalse((directory / "model.onnx").stat().st_mode & 0o222)
        self.assertEqual(MODULE.verify(self.store), [])

    def test_same_version_is_idempotent_but_different_bytes_are_rejected(self) -> None:
        MODULE.add(self.store, frozen(self.root, "v1"), "a", None)
        MODULE.add(self.store, frozen(self.root, "v1"), "a", None)
        self.assertEqual(len(MODULE.load_registry(self.store)["models"]), 1)
        with self.assertRaises(MODULE.StoreError):
            MODULE.add(self.store, frozen(self.root, "v1", b"other-weights"), "a", None)

    def test_manifest_hash_mismatch_is_rejected_without_writing(self) -> None:
        source = frozen(self.root, "v1")
        (source / "model.onnx").write_bytes(b"tampered")
        with self.assertRaises(MODULE.StoreError):
            MODULE.add(self.store, source, "a", None)
        self.assertFalse((self.store / "v1").exists())

    def test_retire_keeps_files_and_cannot_repeat(self) -> None:
        MODULE.add(self.store, frozen(self.root, "v1"), "a", None)
        entry = MODULE.retire(self.store, "v1", "被 v2 取代")
        self.assertEqual((entry["status"], entry["retiredReason"]), ("retired", "被 v2 取代"))
        self.assertTrue((self.store / "v1" / "model.onnx").is_file())
        self.assertEqual(MODULE.verify(self.store), [])
        with self.assertRaises(MODULE.StoreError):
            MODULE.retire(self.store, "v1", "again")
        with self.assertRaises(MODULE.StoreError):
            MODULE.retire(self.store, "v9", "missing")

    def test_legacy_snake_case_manifest_is_supported(self) -> None:
        entry = MODULE.add(self.store, frozen(self.root, "unsw-binary-2026.09.0", legacy=True), "~/Workspace/deliveries/x", None)
        self.assertEqual(entry["manifestFile"], "model_manifest.json")
        self.assertEqual(MODULE.verify(self.store), [])

    def test_verify_reports_deleted_tampered_and_unregistered_versions(self) -> None:
        MODULE.add(self.store, frozen(self.root, "v1"), "a", None)
        MODULE.add(self.store, frozen(self.root, "v2", b"w2"), "a", None)
        target = self.store / "v1" / "model.onnx"
        target.chmod(0o600)
        target.write_bytes(b"changed")
        for path in (self.store / "v2").iterdir():
            path.chmod(0o600)
            path.unlink()
        (self.store / "v2").rmdir()
        (self.store / "stray").mkdir()
        problems = MODULE.verify(self.store)
        self.assertTrue(any("v1: model.onnx 哈希改变" in p for p in problems))
        self.assertTrue(any("v2: 目录缺失" in p for p in problems))
        self.assertTrue(any("stray: 目录未登记" in p for p in problems))

    def test_cli_rejects_absolute_origin(self) -> None:
        source = frozen(self.root, "v1")
        code = MODULE.main(["--store", str(self.store), "add", "--source", str(source), "--origin", str(source)])
        self.assertEqual(code, 2)
        self.assertFalse(self.store.exists())


if __name__ == "__main__":
    unittest.main()
