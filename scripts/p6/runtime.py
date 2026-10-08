"""P6 ONNX 输入、框架对拍与跨平台重放；仅处理冻结数值张量。"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
from pathlib import Path

import numpy as np
import onnxruntime as ort


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def session(model):
    """拒绝张量名、类型或宽度漂移，CPU 会话只使用冻结 ONNX。"""
    options = ort.SessionOptions()
    options.intra_op_num_threads = 8
    options.inter_op_num_threads = 1
    result = ort.InferenceSession(str(model), sess_options=options, providers=["CPUExecutionProvider"])
    inputs = {value.name: value for value in result.get_inputs()}
    expected = {"numeric_values": ("tensor(float)", 43), "numeric_missing": ("tensor(float)", 43),
                "categorical_codes": ("tensor(int64)", 3)}
    if set(inputs) != set(expected):
        raise ValueError("ONNX 输入名不符")
    for name, (kind, width) in expected.items():
        value = inputs[name]
        if value.type != kind or len(value.shape) != 2 or value.shape[1] != width:
            raise ValueError("ONNX 输入类型或维度不符")
    outputs = {value.name: value for value in result.get_outputs()}
    if set(outputs) != {"attack_score", "family_scores"}:
        raise ValueError("ONNX 输出名不符")
    for name, width in (("attack_score", 1), ("family_scores", 4)):
        value = outputs[name]
        if value.type != "tensor(float)" or len(value.shape) != 2 or value.shape[1] != width:
            raise ValueError("ONNX 输出契约不符")
    return result


def predict(runtime, feed, batch_size=4096):
    """全量分批推理；非法输出显式失败，不回退或裁剪概率。"""
    parts = []
    count = len(feed["numeric_values"])
    for start in range(0, count, batch_size):
        batch = {name: values[start:start + batch_size] for name, values in feed.items()}
        attack, family = runtime.run(["attack_score", "family_scores"], batch)
        output = np.column_stack((attack, family))
        if output.shape != (len(batch["numeric_values"]), 5) or not np.isfinite(output).all() \
                or (output < -1e-6).any() or (output > 1.000001).any() \
                or not np.allclose(output[:, 0], output[:, 1:].sum(axis=1), atol=1e-5, rtol=0):
            raise ValueError("ONNX 概率不符")
        parts.append(output)
    if not parts:
        raise ValueError("空推理输入")
    return np.concatenate(parts).astype(np.float32)


def framework_predict(feed, preprocessing, model):
    """按冻结 train 预处理还原 LightGBM 文本模型，无拟合或可执行序列化。"""
    import lightgbm as lgb
    values = feed["numeric_values"].astype(np.float64)
    mean = np.asarray(preprocessing["meanLog"], dtype=np.float32).astype(np.float64)
    scale = np.asarray(preprocessing["scaleLog"], dtype=np.float32).astype(np.float64)
    if mean.shape != (43,) or scale.shape != (43,) or not np.isfinite(mean).all() \
            or not np.isfinite(scale).all() or (scale <= 0).any():
        raise ValueError("冻结预处理维度或数值不符")
    logged = np.log1p(values)
    filled = np.where(feed["numeric_missing"] == 1, mean, logged)
    numeric = ((filled - mean) / scale).astype(np.float32)
    indices = preprocessing["numericIndices"]
    if not indices or len(set(indices)) != len(indices) or any(type(i) is not int or not 0 <= i < 43 for i in indices):
        raise ValueError("冻结特征选列非法")
    categories = feed["categorical_codes"].astype(np.float32)
    if not preprocessing["includeServiceClass"]:
        categories = categories[:, :2]
    matrix = np.column_stack((numeric[:, indices], feed["numeric_missing"][:, indices], categories))
    result = np.asarray(lgb.Booster(model_file=str(model)).predict(matrix, num_threads=8))
    if result.shape != (len(values), 5) or not np.isfinite(result).all():
        raise ValueError("框架概率非法")
    return np.column_stack((1.0 - result[:, 0], result[:, 1:]))


def decision_labels(output, threshold):
    """按冻结家族阈值决定告警；跨端对拍与连接统计共用同一规则。"""
    families = np.argmax(output[:, 1:], axis=1)
    if isinstance(threshold, dict):
        names = ("port_scan", "brute_force", "dos_flood", "dos_slow")
        cutoffs = np.asarray([threshold[names[i]] for i in families])
    else:
        cutoffs = threshold
    return np.where(output[:, 0] >= cutoffs, families + 1, 0)


def compare(actual, expected, threshold):
    """同时报告分差、逐快照类别翻转及告警翻转，后者不能被 argmax 掩盖。"""
    if actual.shape != expected.shape or not np.isfinite(expected).all() or not np.isfinite(actual).all():
        raise ValueError("对拍维度或数值不符")
    labels, old_labels = decision_labels(actual, threshold), decision_labels(expected, threshold)
    hit, old_hit = labels > 0, old_labels > 0
    error = float(np.abs(actual.astype(np.float64) - expected.astype(np.float64)).max())
    flips = int((labels != old_labels).sum())
    return {"rows": len(actual), "maxProbabilityAbsError": error, "classFlips": flips,
            "alertFlips": int((hit != old_hit).sum()), "passed": error <= 1e-4 and flips == 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    bundle, output = args.bundle.resolve(), args.output.resolve()
    if output.exists() or not any(part in (".cache", "artifacts") for part in output.parts):
        raise ValueError("输出须为受控新目录")
    manifest = read(bundle / "runtime-bundle.json")
    for name, expected in manifest["files"].items():
        if Path(name).name != name or sha(bundle / name) != expected:
            raise ValueError("运行包哈希不符")
    if sha(Path(__file__)) != manifest["runtimeCodeSha256"]:
        raise ValueError("运行时代码未冻结")
    runtime = session(bundle / "model.onnx")
    with np.load(bundle / "feed.npz", allow_pickle=False) as data:
        feed = {name: data[name] for name in ("numeric_values", "numeric_missing", "categorical_codes")}
    expected = np.load(bundle / "mac-output.npy", allow_pickle=False)
    actual = predict(runtime, feed)
    result = compare(actual, expected, manifest["alertThreshold"])
    output.mkdir(parents=True, mode=0o700)
    np.save(output / "output.npy", actual, allow_pickle=False)
    write(output / "runtime-report.json", {**result, "modelSha256": sha(bundle / "model.onnx"),
                                           "bundleSha256": sha(bundle / "runtime-bundle.json"),
                                           "outputSha256": sha(output / "output.npy"),
                                           "platform": platform.system(), "machine": platform.machine(),
                                           "runtimeVersion": ort.__version__,
                                           "runtimeCodeSha256": sha(Path(__file__))})
    print(json.dumps(result))
    if not result["passed"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
