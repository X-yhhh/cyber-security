#!/usr/bin/env python3
"""从已登记策略派生新版本：只允许改 policyId/policyVersion 并按 manifest 增设 acceptedProfiles。

J1 实测（R3）表明冻结策略只接受 flow-prefix-v1 时，短连接类别（扫描、洪泛、多数暴力破解）只产生 final
快照而整组被拒。模型 manifest 同时支持 prefix/final，阈值也是在两者混合的 validation 上选定的，因此派生
版本把 acceptedProfiles 设为 manifest.profiles。其余字段（阈值、规则、证据窗口、开关、能力、预算）逐项
必须与来源相同，否则拒绝；输出附差异记录。不读 test、不拟合、不登记、不审批。
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import uuid

import rfc8785
from compose_policy import validate_policy

ROOT = Path(__file__).resolve().parents[2]
ALLOWED = {"policyId", "policyVersion", "acceptedProfiles"}


def derive(source, manifest, version):
    validate_policy(source)
    if not isinstance(version, str) or not version.strip() or version == source["policyVersion"]:
        raise ValueError("派生版本必须是新的非空 policyVersion")
    profiles = list(manifest["profiles"])
    if source["profile"] not in profiles:
        raise ValueError("来源策略的 profile 不在 manifest.profiles 中")
    derived = dict(source)
    derived["policyVersion"] = version
    # 确定性派生：同一来源与版本得到同一 ID，可重放核对。
    derived["policyId"] = str(uuid.uuid5(uuid.UUID(source["policyId"]), "acceptedProfiles:" + version))
    derived["acceptedProfiles"] = profiles
    changed = sorted(k for k in set(source) | set(derived) if source.get(k) != derived.get(k))
    if not set(changed) <= ALLOWED:
        raise ValueError(f"派生改动越界: {changed}")
    validate_policy(derived)
    record = dict(sourcePolicyId=source["policyId"], sourceJcsSha256=hashlib.sha256(rfc8785.dumps(source)).hexdigest(),
                  derivedPolicyId=derived["policyId"], derivedJcsSha256=hashlib.sha256(rfc8785.dumps(derived)).hexdigest(),
                  changedFields=changed, acceptedProfiles=profiles, unchangedFields=sorted(set(source) - set(changed)),
                  testRead=False, newFits=0, thresholdsChanged=False)
    return derived, record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--record", type=Path, required=True)
    args = parser.parse_args()
    derived, record = derive(json.loads(args.source.read_text()), json.loads(args.manifest.read_text()), args.version)
    for path, value in ((args.output, derived), (args.record, record)):
        with path.open("x", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    print(json.dumps(dict(policyId=record["derivedPolicyId"], changed=record["changedFields"]), ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except ValueError as exc:
        sys.exit(str(exc))
