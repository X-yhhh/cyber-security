"""显式管理员运行的 P5 回环验收：仅接受初始 Disabled PF，最终恢复原过滤规则。"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import time

from .__main__ import keys
from .common import canonical, digest, ident, parse, require, stamp, write_new
from .contract import capability_set_sha256, protected_ports_sha256
from .pf_engine_canary import SCENARIOS, run
from .platform import PF


def command(args, data=None):
    """固定参数执行系统工具，原始诊断仅保留在受控 run 目录。"""
    result = subprocess.run(args, input=data, text=True, capture_output=True, timeout=15)
    require(result.returncode == 0, "LAB_SYSTEM_COMMAND_FAILED")
    return result.stdout, result.stderr


def main(directory, guardtargets):
    require(sys.platform == "darwin" and os.geteuid() == 0, "LAB_ADMIN_REQUIRED")
    require(directory.is_absolute() and not directory.exists(), "LAB_NEW_DIRECTORY_REQUIRED")
    require(guardtargets.is_absolute() and guardtargets.is_file(), "LAB_TARGET_BINARY_REQUIRED")
    directory.mkdir(mode=0o700, parents=True)
    info = command(["/sbin/pfctl", "-s", "info"])[0]
    require("Status: Disabled" in info, "LAB_REQUIRES_DISABLED_PF")
    original = command(["/sbin/pfctl", "-sr"])[0]
    require(original.strip() == 'scrub-anchor "com.apple/*" all fragment reassemble\nanchor "com.apple/*" all',
            "LAB_UNEXPECTED_ROOT_RULES")
    apple = command(["/sbin/pfctl", "-a", "com.apple/*", "-sr"])[0]
    loopback = command(["/sbin/ifconfig", "lo0"])[0]
    require("inet 127.0.0.2 " not in loopback, "LAB_ALIAS_ALREADY_PRESENT")
    write_new(directory / "root-before.conf", original.encode())
    write_new(directory / "apple-before.txt", apple.encode())
    helper = directory / "pf-state-helper"
    source = Path(__file__).resolve().parent / "pf_state_helper.c"
    command(["/usr/bin/clang", "-O2", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(helper)])
    helper.chmod(0o700)
    require(parse(command([str(helper), "--abi"])[0])["kernelMatches"], "PF_ABI_UNVERIFIED")
    summary = {"passed": False, "rebootTested": False, "scenarios": [],
               "guardtargetsSha256": hashlib.sha256(guardtargets.read_bytes()).hexdigest(),
               "sources": {str(p.relative_to(source.parent.parent)): hashlib.sha256(p.read_bytes()).hexdigest()
                           for p in sorted(source.parent.glob("*.py")) + [source]}, "cleanup": {}}
    token = None
    alias = False
    attached = False
    try:
        command(["/sbin/ifconfig", "lo0", "alias", "127.0.0.2", "netmask", "255.255.255.255"])
        alias = True
        for index, scenario in enumerate(SCENARIOS):
            root = directory / scenario
            root.mkdir(mode=0o700)
            keys(root / "keys", "canary")
            now = time.time()
            c = {k: ident() for k in ("assetId", "executorId", "sensorId", "captureScopeId")}
            port = 55100 + index * 10
            c.update(platform="pf", environment="lab", interface="lo0", localAddresses=["127.0.0.1"],
                     peerAddresses=["127.0.0.2"], servicePorts=[port], protectedServicePorts=[22, 53, 3389, port + 1],
                     protectedPeers=[], stateDir=str(root / "state"), pfHelper=str(helper),
                     capabilityIds=[ident()], bundleIds=[ident()], policyHashes=["a" * 64],
                     authorization={"id": ident(), "revision": 1, "status": "active",
                                    "validFrom": stamp(now - 1), "validUntil": stamp(now + 180)},
                     limits={"maxTtlSeconds": 60, "maxContinuousBlockSeconds": 120,
                             "maxActiveRulesPerAsset": 10, "maxNewActionsPerMinute": 5},
                     trustFile=str(root / "keys/trust.json"), budgetKeyFile=str(root / "keys/budget.key"),
                     controlPlaneURL="https://127.0.0.1:1", credentialFile=str(root / "unused-credential"),
                     targetURL="https://127.0.0.1:1", targetCA=str(root / "unused-ca"),
                     targetCertificate=str(root / "unused-cert"), targetKey=str(root / "unused-key"))
            # lab 没有 P4 保护文件：按同一格式自建保护集，并像正式配置一样登记全入站能力。
            protection = {"protectedBudgetTargetIds": [], "protectedServicePorts": c["protectedServicePorts"]}
            c["inboundCapabilities"] = [{"capabilityId": c["capabilityIds"][0], "protectionSetSha256": digest(protection),
                                         "protectedPortsSha256": protected_ports_sha256(c["protectedServicePorts"])}]
            path = root / "config.json"
            if scenario == "asset_limit":
                c["limits"]["maxActiveRulesPerAsset"] = 1
            elif scenario == "rate_limit":
                c["limits"]["maxNewActionsPerMinute"] = 1
            elif scenario == "renewal_limit":
                c["limits"]["maxContinuousBlockSeconds"] = 6
            c["capabilityHash"] = capability_set_sha256(c)
            write_new(path, canonical(c))
            rules = original + f'anchor "{PF.anchor_root(c["executorId"])}/*" all\n'
            command(["/sbin/pfctl", "-n", "-R", "-f", "-"], rules)
            command(["/sbin/pfctl", "-R", "-f", "-"], rules)
            attached = True
            if token is None:
                out, err = command(["/sbin/pfctl", "-E"])
                found = re.search(r"Token\s*:\s*(\d+)", out + err)
                require(found is not None, "LAB_ENABLE_TOKEN_MISSING")
                token = found[1]
                write_new(directory / "enable-token", token.encode())
            run(path, root / "keys/signing.der", "canary", root / "result.json",
                "peer_inbound", guardtargets, scenario)
            result = parse((root / "result.json").read_bytes())
            summary["scenarios"].append({"scenario": scenario, "passed": result["passed"]})
        summary["passed"] = all(s["passed"] for s in summary["scenarios"])
    finally:
        # 每项恢复独立尝试；失败记录并继续其余清理，绝不运行全局 flush 或强制 -d。
        actions = []
        if attached:
            actions.append(("rootRestored", ["/sbin/pfctl", "-R", "-f", "-"], original))
        if token is not None:
            actions.append(("tokenReleased", ["/sbin/pfctl", "-X", token], None))
        if alias:
            actions.append(("aliasRemoved", ["/sbin/ifconfig", "lo0", "-alias", "127.0.0.2"], None))
        for name, args, data in actions:
            try:
                command(args, data)
                summary["cleanup"][name] = True
            except Exception:
                summary["cleanup"][name] = False
        try:
            summary["cleanup"].update(
                rootUnchanged=command(["/sbin/pfctl", "-sr"])[0] == original,
                appleUnchanged=command(["/sbin/pfctl", "-a", "com.apple/*", "-sr"])[0] == apple,
                pfDisabled="Status: Disabled" in command(["/sbin/pfctl", "-s", "info"])[0],
                aliasAbsent="inet 127.0.0.2 " not in command(["/sbin/ifconfig", "lo0"])[0])
        except Exception:
            summary["cleanup"]["verificationFailed"] = False
        summary["passed"] = summary["passed"] and all(summary["cleanup"].values())
        write_new(directory / "summary.json", canonical(summary))
        print(canonical({k: summary[k] for k in ("passed", "scenarios", "cleanup")}).decode())
    require(summary["passed"], "LAB_ACCEPTANCE_FAILED")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--guardtargets", type=Path, required=True)
    args = parser.parse_args()
    main(args.directory, args.guardtargets)
