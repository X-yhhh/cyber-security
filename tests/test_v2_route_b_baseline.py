"""阶段 7 基线统计（baseline-v1）与 2026.10.1 交付打包/自校验的单测；不读取任何真实数据。"""

import hashlib
import json

import numpy as np
import pytest

from cyber_training.v2 import route_b_baseline as bl
from cyber_training.v2.route_b_v4 import CATEGORICAL, NUMERIC


def test_decile_edges_match_numpy_linear_quantiles():
    v = np.arange(1, 11, dtype=float)  # 线性插值：q=0.1 → 1.9，…，q=0.9 → 9.1
    edges = bl.decile_edges(v)
    assert edges == pytest.approx([1.9, 2.8, 3.7, 4.6, 5.5, 6.4, 7.3, 8.2, 9.1])
    assert edges == [float(e) for e in np.quantile(v, [i / 10 for i in range(1, 10)], method="linear")]


def test_bin_index_boundaries():
    edges = [1.0, 2.0, 3.0]
    # 小于最小 edge → 0；恰等于 edge → 该 edge 的左侧箱（严格小于才计数）；大于最大 edge → len(edges)
    values = [0.5, 1.0, 1.0000001, 2.0, 2.5, 3.0, 3.5, 1e12, -1e12]
    assert bl.bin_index(values, edges).tolist() == [0, 0, 1, 1, 2, 2, 3, 3, 0]
    assert bl.bin_index([5.0], []).tolist() == [0]  # 无边界：只有 1 个箱


def test_numeric_stats_ties_deduplicate_edges_and_counts_sum():
    v = np.array([0.0] * 85 + [1.0] * 10 + [7.0] * 5)  # q=0.8 落在 0 内部、q=0.9 落在 1 内部，插值不跨值
    x = bl.numeric_stats(v)
    assert x["edges"] == [0.0, 1.0]  # 分位数大量重合，去重后只剩两个
    assert x["counts"] == [85, 10, 5] and x["count"] == 100 and sum(x["counts"]) == 100
    assert x["proportions"] == [0.85, 0.1, 0.05]
    # 跨值插值产生训练中未出现的边界（符合 method="linear"），计数仍按严格小于规则
    y = bl.numeric_stats(np.array([0.0] * 80 + [1.0] * 20))
    assert y["edges"] == pytest.approx([0.0, 0.2, 1.0]) and y["counts"] == [80, 0, 20, 0]


def test_numeric_stats_constant_field():
    x = bl.numeric_stats(np.full(50, 3.0))
    assert x["edges"] == [3.0] and x["counts"] == [50, 0] and x["proportions"] == [1.0, 0.0]
    assert bl.decile_edges([]) == [] and bl.decile_edges([np.nan, np.inf]) == []


def test_numeric_stats_rejects_non_finite():
    with pytest.raises(bl.BaselineError, match="non-finite"):
        bl.numeric_stats([1.0, np.nan, 2.0])
    with pytest.raises(bl.BaselineError, match="non-finite"):
        bl.numeric_stats([1.0, np.inf])


def test_categorical_stats_merges_rare_values_into_other():
    values = ["tcp"] * 9000 + ["udp"] * 990 + ["icmp"] * 9 + ["sctp"] * 1  # icmp 0.0009、sctp 0.0001 < 0.001
    x = bl.categorical_stats(values)
    assert list(x["counts"]) == ["tcp", "udp", bl.OTHER]
    assert x["counts"] == {"tcp": 9000, "udp": 990, bl.OTHER: 10} and x["count"] == 10000
    assert x["proportions"][bl.OTHER] == pytest.approx(0.001)
    # 恰好 0.001 单独成键；__other__ 即使为 0 也必须存在
    y = bl.categorical_stats(["a"] * 999 + ["b"])
    assert y["counts"] == {"a": 999, "b": 1, bl.OTHER: 0} and y["proportions"][bl.OTHER] == 0.0


def test_categorical_stats_rejects_reserved_missing_and_long_keys():
    with pytest.raises(bl.BaselineError):
        bl.categorical_stats([bl.OTHER] * 10)
    with pytest.raises(bl.BaselineError, match="missing"):
        bl.categorical_stats(["tcp", None])
    with pytest.raises(bl.BaselineError):
        bl.categorical_stats(["x" * 65] * 3)


def _baseline(rows: int = 300) -> dict:
    rng = np.random.default_rng(0)
    numeric = {f: rng.exponential(1.0 + i, rows) for i, f in enumerate(NUMERIC)}
    numeric["ct_srv_src"] = rng.integers(1, 5, rows).astype(float)
    categorical = {"proto": rng.choice(["tcp", "udp", "arp"], rows), "service": rng.choice(["-", "dns", "http"], rows)}
    source = {"partition": "train", "split_id": "split-test", "split_fingerprint": "f" * 64, "seed": 1, "rows": rows,
              "scope": {"viewpoints": ["responder"], "address_families": ["ipv4"]}, "code_commit": "test"}
    return bl.build_baseline(numeric, categorical, source)


def test_build_baseline_layout_and_validation():
    b = _baseline()
    assert list(b) == ["schema_version", "method", "source", "numeric_binning", "categorical_other", "psi", "numeric",
                       "categorical"]
    assert b["psi"] == {"epsilon": 0.0001, "warning": 0.2, "alert": 0.3, "min_samples": 200}
    assert list(b["numeric"]) == list(NUMERIC) and list(b["categorical"]) == list(CATEGORICAL)
    assert bl.validate_baseline(json.loads(json.dumps(b))) == []
    with pytest.raises(bl.BaselineError, match="differ"):
        bl.build_baseline({"dur": [1.0]}, {}, b["source"])


@pytest.mark.parametrize("tamper", [
    lambda b: b["numeric"]["dur"]["edges"].reverse(),
    lambda b: b["numeric"]["dur"]["counts"].__setitem__(0, b["numeric"]["dur"]["counts"][0] + 1),
    lambda b: b["categorical"]["proto"]["counts"].pop(bl.OTHER),
    lambda b: b["numeric"].pop("dload"),
    lambda b: b["source"].__setitem__("partition", "holdout"),
    lambda b: b["psi"].__setitem__("warning", 0.5),
])
def test_validate_baseline_detects_tampering(tamper):
    b = json.loads(json.dumps(_baseline()))
    tamper(b)
    assert bl.validate_baseline(b)


def test_diff_json_and_compare_audit():
    a = {"x": 1, "y": {"z": [1, 2]}, "k": 0.5}
    assert bl.diff_json(a, {"x": 1, "y": {"z": [1, 3]}, "k": 0.5, "n": 1}) == ["/y/z/1", "/n"]
    diffs, worst = bl.compare_audit({"r": 0.1, "n": 3}, {"r": 0.1 * (1 + 1e-12), "n": 3})
    assert diffs == [] and 0 < worst < 1e-9
    assert bl.compare_audit({"n": 3}, {"n": 4})[0] == ["/n"]


def test_crlf_hash_and_delivery_json_format(tmp_path):
    payload = {"a": "中文", "b": [1, 2.5]}
    data = bl.delivery_json_bytes(payload)
    assert b"\r\n" in data and not data.endswith(b"\n") and "中文".encode() in data
    (tmp_path / "lf.json").write_bytes(data.replace(b"\r\n", b"\n"))
    assert bl.crlf_sha256(tmp_path / "lf.json") == hashlib.sha256(data).hexdigest()


def _write(path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _source_delivery(root, fingerprint: str):
    src = root / f"{bl.MODEL_KEY}-{bl.SOURCE_VERSION}"
    for name, data in {"model.onnx": b"onnx-bytes", "preprocessing.json": b"{}", "replay-sample.csv": b"a,b\n",
                       "evaluation-report.md": b"# r\n", "export-verdict.json": b"{}", "evidence/final-verdict.json": b"{}",
                       "fixtures/raw-flows.jsonl": b"{}\n"}.items():
        _write(src / name, data)
    fx = {"raw-flows.jsonl": hashlib.sha256(b"{}\n").hexdigest()}
    _write(src / "fixtures/checksums.json", bl.delivery_json_bytes(fx))
    sha = lambda p: hashlib.sha256((src / p).read_bytes()).hexdigest()  # noqa: E731
    manifest = {"model_version": f"{bl.MODEL_KEY}-{bl.SOURCE_VERSION}", "version": bl.SOURCE_VERSION,
                "created_at": "2026-09-29T16:09:45+08:00",
                "artifact": {"file": "model.onnx", "sha256": sha("model.onnx"), "size_bytes": 10},
                "dataset": {"split_fingerprint": fingerprint},
                "feature_contract": {"inputs": {"flow_numeric": [{"name": f} for f in NUMERIC],
                                                "flow_categorical": list(CATEGORICAL)}},
                "activation": {"status": "candidate"}, "provenance": {"training_commit": "x"},
                "files": {n: sha(n) for n in ("model.onnx", "preprocessing.json", "replay-sample.csv")},
                "fixtures": {"dir": "fixtures", "checksums_sha256": sha("fixtures/checksums.json")}}
    _write(src / "model_manifest.json", bl.delivery_json_bytes(manifest))
    checks = {k: v for k, v in bl.delivery_checksums(src).items() if k != "fixtures/checksums.json"}
    _write(src / "checksums.json", bl.delivery_json_bytes(checks))
    return src, sha("model.onnx")


def test_package_and_verify_synthetic_delivery(tmp_path):
    b = _baseline()
    src, onnx_sha = _source_delivery(tmp_path, b["source"]["split_fingerprint"])
    run = tmp_path / "run"
    _write(run / "feature-baseline-stats.json", json.dumps(b).encode())
    _write(run / "reproduction-check.json", b'{"passed": true}')
    (tmp_path / "out").mkdir()
    out = bl.package(run, src, tmp_path / "out", expected_onnx_sha256=onnx_sha)
    record = bl.verify(out, src, expected_onnx_sha256=onnx_sha)
    assert record["passed"], record["checks"]
    assert sorted(record["manifest_diff"]) == sorted(bl.ALLOWED_DIFF)
    new = json.loads((out / "model_manifest.json").read_text(encoding="utf-8"))
    assert new["model_version"] == f"{bl.MODEL_KEY}-{bl.TARGET_VERSION}" and new["activation"]["status"] == "candidate"
    assert new["provenance"]["derived_from"]["manifest_sha256"] == hashlib.sha256(
        (src / "model_manifest.json").read_bytes()).hexdigest()
    assert "fixtures/checksums.json" in json.loads((out / "checksums.json").read_text())
    with pytest.raises(FileExistsError):
        bl.package(run, src, tmp_path / "out", expected_onnx_sha256=onnx_sha)
    (out / "replay-sample.csv").write_bytes(b"tampered")
    bad = bl.verify(out, src, expected_onnx_sha256=onnx_sha)
    assert not bad["passed"] and not bad["checks"]["checksums_match"]


def test_package_refuses_failed_reproduction_or_unknown_layout(tmp_path):
    b = _baseline()
    src, onnx_sha = _source_delivery(tmp_path, b["source"]["split_fingerprint"])
    run = tmp_path / "run"
    _write(run / "feature-baseline-stats.json", json.dumps(b).encode())
    _write(run / "reproduction-check.json", b'{"passed": false}')
    with pytest.raises(bl.DeliveryError, match="reproduction"):
        bl.package(run, src, tmp_path / "out", expected_onnx_sha256=onnx_sha)
    _write(run / "reproduction-check.json", b'{"passed": true}')
    _write(src / "stray.bin", b"x")
    with pytest.raises(bl.DeliveryError, match="layout"):
        bl.package(run, src, tmp_path / "out2", expected_onnx_sha256=onnx_sha)
