"""独立复核P3候选哈希、输入契约、跨平台分数与决策；不训练、不读最终测试集。"""
from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath
import platform

import numpy as np
import onnxruntime as ort

from .data import read, sha


def verify(root):
    root = Path(root)
    checksums = read(root / "checksums.json")
    for name, expected in checksums.items():
        pure = PurePosixPath(name)
        if pure.is_absolute() or ".." in pure.parts or "\\" in name:
            raise ValueError("制品路径逃逸")
        if sha(root / name) != expected:
            raise ValueError("制品哈希不符: " + name)
    folder = root / "candidate"
    manifest, policy = read(folder / "model-manifest.json"), read(folder / "decision-policy.json")
    if manifest["candidateOnly"] is not True or manifest["finalEvaluationReportSha256"] is not None:
        raise ValueError("候选/最终测试边界被改变")
    if policy["mode"] != "alert_only" or policy["modelId"] != manifest["modelId"]:
        raise ValueError("策略模式或模型绑定不符")
    for field, name in [("artifactSha256", "candidate/model.onnx"), ("preprocessingSha256", "candidate/preprocessing.json"),
                        ("featureProfileSha256", "candidate/feature-profile.json"),
                        ("calibrationSha256", "candidate/calibration.json"), ("validationReportSha256", "validation-report.json"),
                        ("evaluationPlanSha256", "experiment-plan.json")]:
        if manifest[field] != sha(root / name):
            raise ValueError("manifest绑定不符: " + field)
    options = ort.SessionOptions(); options.intra_op_num_threads = 4; options.inter_op_num_threads = 1
    runtime = ort.InferenceSession(str(folder / "model.onnx"), sess_options=options, providers=["CPUExecutionProvider"])
    expected_names = ["numeric_values", "numeric_missing", "categorical_codes"]
    if [node.name for node in runtime.get_inputs()] != expected_names:
        raise ValueError("ONNX输入名称/顺序不符")
    if [node.type for node in runtime.get_inputs()] != ["tensor(float)", "tensor(float)", "tensor(int64)"]:
        raise ValueError("ONNX输入类型不符")
    if [node.shape[1] for node in runtime.get_inputs()] != [43, 43, 3]:
        raise ValueError("ONNX输入形状不符")
    with np.load(folder / "parity-fixture.npz", allow_pickle=False) as fixture:
        actual = runtime.run(["attack_score"], {name: fixture[name] for name in expected_names})[0]
        expected = fixture["expected"]
    if actual.shape != (len(expected), 1) or actual.dtype != np.float32:
        raise ValueError("输出形状/类型不符")
    actual = actual[:, 0]
    if not np.isfinite(actual).all() or np.any((actual < 0) | (actual > 1)):
        raise ValueError("非法ONNX输出")
    error = float(np.max(np.abs(actual - expected)))
    flips = {name: int(np.count_nonzero((actual >= policy[name]) != (expected >= policy[name])))
             for name in ["alertThreshold", "autoThreshold"]}
    if error > 1e-4 or any(flips.values()):
        raise ValueError("跨平台数值/阈值决策不一致")
    return {"status": "passed", "filesVerified": len(checksums), "rows": len(actual), "maxAbsError": error,
            "thresholdFlips": flips, "platform": platform.system(), "architecture": platform.machine(),
            "runtimeVersion": ort.__version__, "candidateOnly": True, "finalTestRead": False,
            "modelSha256": manifest["artifactSha256"]}


if __name__ == "__main__":
    import json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.run), ensure_ascii=False))
