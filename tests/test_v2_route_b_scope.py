"""开发路线阶段 1 A1：2026.10.2 收窄评估范围交付的打包与自校验单测；只用合成交付，不读真实数据。"""

import hashlib
import json

import numpy as np
import pytest

from cyber_training.v2 import route_b_baseline as bl
from cyber_training.v2 import route_b_scope as sc
from cyber_training.v2.route_b_v4 import CATEGORICAL, NUMERIC


def _write(path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _baseline():
    rng = np.random.default_rng(0)
    source = {"partition": "train", "rows": 400, "split_fingerprint": "fp"}
    return bl.build_baseline({f: rng.random(400) for f in NUMERIC}, {f: ["tcp"] * 300 + ["udp"] * 100 for f in CATEGORICAL},
                             source)


def _source(root):
    src = root / f"{bl.MODEL_KEY}-{sc.SOURCE_VERSION}"
    for name, data in {"model.onnx": b"onnx-bytes", "preprocessing.json": b"{}", "replay-sample.csv": b"a,b\n",
                       "evaluation-report.md": b"# r\n", "export-verdict.json": b"{}", "evidence/final-verdict.json": b"{}",
                       "fixtures/raw-flows.jsonl": b"{}\n"}.items():
        _write(src / name, data)
    _write(src / "fixtures/checksums.json", bl.delivery_json_bytes({"raw-flows.jsonl": hashlib.sha256(b"{}\n").hexdigest()}))
    sha = lambda p: hashlib.sha256((src / p).read_bytes()).hexdigest()  # noqa: E731
    manifest = {"model_version": f"{bl.MODEL_KEY}-{sc.SOURCE_VERSION}", "version": sc.SOURCE_VERSION,
                "created_at": "2026-09-30T07:27:55+00:00",
                "artifact": {"file": "model.onnx", "sha256": sha("model.onnx"), "size_bytes": 10},
                "feature_contract": {"version": "unsw-nb15-flow-v4", "supported_viewpoints": ["responder"],
                                     "supported_address_families": ["ipv4"]},
                "decision": {"threshold": 0.35, "adjustable": False},
                "limitations": ["旧限制"], "activation": {"status": "candidate"},
                "provenance": {"derived_from": {"model_version": "x"}},
                "files": {n: sha(n) for n in ("model.onnx", "preprocessing.json", "replay-sample.csv")},
                "fixtures": {"dir": "fixtures", "checksums_sha256": sha("fixtures/checksums.json")},
                "feature_baseline_stats": _baseline()}
    _write(src / "model_manifest.json", bl.delivery_json_bytes(manifest))
    _write(src / "checksums.json", bl.delivery_json_bytes(bl.delivery_checksums(src)))
    return src, sha("model.onnx")


def test_package_narrows_scope_and_keeps_everything_else(tmp_path):
    src, onnx = _source(tmp_path)
    (tmp_path / "out").mkdir()
    out = sc.package(src, tmp_path / "out", expected_onnx_sha256=onnx)
    record = sc.verify(out, src, expected_onnx_sha256=onnx)
    assert record["passed"], record["checks"]
    assert sc.diff_allowed(record["manifest_diff"])
    assert not sc.diff_allowed([*record["manifest_diff"], "/decision/threshold"])
    new = json.loads((out / "model_manifest.json").read_text(encoding="utf-8"))
    fc = new["feature_contract"]
    assert fc["supported_protocols"] == ["tcp"] and fc["requires_handshake_seen"] is True
    assert fc["supported_viewpoints"] == ["responder"] and fc["supported_address_families"] == ["ipv4"]
    assert new["model_version"] == f"{bl.MODEL_KEY}-{sc.TARGET_VERSION}" and new["activation"]["status"] == "candidate"
    assert new["limitations"] == ["旧限制", sc.SCOPE_LIMITATION]
    assert new["provenance"]["derived_from"]["manifest_sha256"] == hashlib.sha256(
        (src / "model_manifest.json").read_bytes()).hexdigest()
    assert new["provenance"]["derived_from"]["previous"] == {"model_version": "x"}
    with pytest.raises(FileExistsError):
        sc.package(src, tmp_path / "out", expected_onnx_sha256=onnx)
    (out / "model.onnx").write_bytes(b"tampered")
    bad = sc.verify(out, src, expected_onnx_sha256=onnx)
    assert not bad["passed"] and not bad["checks"]["checksums_match"]


def test_package_refuses_unexpected_source(tmp_path):
    src, onnx = _source(tmp_path)
    with pytest.raises(bl.DeliveryError, match="expected artifact"):
        sc.package(src, tmp_path / "o1", expected_onnx_sha256="0" * 64)
    (src / "replay-sample.csv").write_bytes(b"changed")
    with pytest.raises(bl.DeliveryError, match="checksum"):
        sc.package(src, tmp_path / "o2", expected_onnx_sha256=onnx)
    assert not (tmp_path / "o2").exists()


def test_build_manifest_refuses_already_narrowed_or_other_scope():
    base = {"model_version": "m", "feature_contract": {"supported_viewpoints": ["responder"],
                                                        "supported_address_families": ["ipv4"]},
            "provenance": {}, "limitations": []}
    narrowed = json.loads(json.dumps(base))
    narrowed["feature_contract"]["supported_protocols"] = ["tcp"]
    with pytest.raises(bl.DeliveryError, match="already"):
        sc.build_manifest(narrowed, "0" * 64, sc.TARGET_VERSION, "2026-10-01T00:00:00+00:00")
    outbound = json.loads(json.dumps(base))
    outbound["feature_contract"]["supported_viewpoints"] = ["initiator"]
    with pytest.raises(bl.DeliveryError, match="scope"):
        sc.build_manifest(outbound, "0" * 64, sc.TARGET_VERSION, "2026-10-01T00:00:00+00:00")
