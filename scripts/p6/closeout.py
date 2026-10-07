"""P6 收口：绑定原始评价与双端对拍证据，不改候选或在线策略。"""
from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np

from runtime import compare, read, sha, write


def closeout(run, cross_platform, l3_run, output):
    """直接复算保存的全量概率差；G3 待验，离线通过不授予真实动作资格。"""
    registration = read(run / "registration.json")
    report = read(run / "report.json")
    bundle = run / "runtime-bundle"
    runtime_manifest = read(bundle / "runtime-bundle.json")
    remote = read(cross_platform / "runtime-report.json")
    if (registration["layer"] != "L1" or report["registrationSha256"] != sha(run / "registration.json")
            or remote["bundleSha256"] != sha(bundle / "runtime-bundle.json")
            or remote["runtimeCodeSha256"] != registration["codeSha256"]["scripts/p6/runtime.py"]
            or remote["modelSha256"] != report["modelSha256"]
            or remote["outputSha256"] != sha(cross_platform / "output.npy")
            or report["modelSha256"] != sha(bundle / "model.onnx")
            or report["platform"] != "Darwin" or remote["platform"] != "Windows"):
        raise ValueError("双端证据与评价绑定不符")
    for name, expected in runtime_manifest["files"].items():
        if Path(name).name != name or sha(bundle / name) != expected:
            raise ValueError("对拍包内容改变")
    parity = compare(np.load(cross_platform / "output.npy", allow_pickle=False),
                     np.load(bundle / "mac-output.npy", allow_pickle=False), runtime_manifest["alertThreshold"])
    if any(remote[key] != parity[key] for key in ("rows", "maxProbabilityAbsError", "classFlips", "alertFlips", "passed")):
        raise ValueError("对拍报告与全量输出不一致")
    l3 = read(l3_run / "report.json")
    if (l3["layer"] != "L3" or l3["modelSha256"] != report["modelSha256"]
            or l3["version"] != report["version"]
            or l3["registrationSha256"] != sha(l3_run / "registration.json")):
        raise ValueError("L3 未使用同一冻结组合")
    complete = (report["gates"]["G1"] is True and report["gates"]["G2"] is True
                and report["frameworkParity"]["passed"] and parity["passed"] and l3["frameworkParity"]["passed"])
    result = {"stage": "P6", "completed": bool(complete), "evaluationId": report["evaluationId"],
              "evaluationVersion": report["version"], "modelSha256": report["modelSha256"],
              "evaluationPlanSha256": report["evaluationPlanSha256"],
              "codeSha256": registration["codeSha256"],
              "gates": report["gates"], "classEligibility": report["classEligibility"],
              "testEvaluationsUsed": report["testEvaluationsUsed"], "crossPlatformParity": parity,
              "l3": {"connections": l3["modelOnly"]["connections"],
                     "dosSlowDetection": l3["modelOnly"]["attackDetectionByClass"]["dos_slow"],
                     "normalFalsePositiveRate": l3["modelOnly"]["falsePositiveRate"],
                     "reportOnly": True, "previouslyInspectedSource": True},
              "l2": {"status": "not_prepared_optional_A7", "crossDatasetGeneralizationVerified": False},
              "evidenceSha256": {"registration": sha(run / "registration.json"),
                                 "l1Report": sha(run / "report.json"),
                                 "runtimeBundle": sha(bundle / "runtime-bundle.json"),
                                 "windowsRuntimeReport": sha(cross_platform / "runtime-report.json"),
                                 "windowsOutput": sha(cross_platform / "output.npy"),
                                 "l3Registration": sha(l3_run / "registration.json"),
                                 "l3Report": sha(l3_run / "report.json")},
              "candidateOnly": True, "automaticExecutionEnabled": False,
              "remaining": ["P5 platform required scenarios", "P7 G3", "P8 asset authorization",
                            "L2 optional A7 cross-dataset evaluation", "P7 rc.2 candidate to rc.3 manifest migration"]}
    write(output, result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--cross-platform", type=Path, required=True)
    parser.add_argument("--l3-run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not any(part in (".cache", "artifacts") for part in args.output.resolve().parts):
        raise ValueError("收口记录须位于受控目录")
    result = closeout(args.run, args.cross_platform, args.l3_run, args.output)
    print(__import__("json").dumps({"completed": result["completed"], "gates": result["gates"],
                                  "crossPlatformParity": result["crossPlatformParity"]}))
    if not result["completed"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
