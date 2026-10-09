"""显式管理员运行的 P5 回环验收：仅接受初始 Disabled PF，最终恢复原过滤规则。"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import time

from .__main__ import build, keys
from .common import Rejected, canonical, digest, ident, parse, require, stamp, write_new
from .contract import capability_set_sha256, protected_ports_sha256
from .pf_engine_canary import E2_LIMITS, SCENARIOS, run
from .platform import PF


DEFAULT_ROOT = b'scrub-anchor "com.apple/*" all fragment reassemble\nanchor "com.apple/*" all\n'
USER_ANCHOR = "p5-user-fixture"
USER_RULE = b'pass on lo0 inet proto icmp from 127.0.0.1 to 127.0.0.1 no state label "p5-user-root"\n'
USER_ANCHOR_RULE = USER_RULE.replace(b"p5-user-root", b"p5-user-anchor")
USER_ROOT = DEFAULT_ROOT + USER_RULE + f'anchor "{USER_ANCHOR}" all\n'.encode()
UNKNOWN_RULE = USER_RULE.replace(b"p5-user-root", b"p5-unknown-fixture")


def command(args, data=None, *, binary=False):
    """固定参数执行系统工具，原始诊断仅保留在受控 run 目录。"""
    result = subprocess.run(args, input=data, text=not binary, capture_output=True, timeout=15)
    require(result.returncode == 0, "LAB_SYSTEM_COMMAND_FAILED")
    return result.stdout, result.stderr


def read_rules(anchor=None):
    """保留 pfctl 原始输出字节，不做 strip、换行转换或规则排序。"""
    args = ["/sbin/pfctl"] + (["-a", anchor] if anchor else []) + ["-sr"]
    return command(args, binary=True)[0]


def existing_rules(original, user):
    """只接受默认根或固定的用户夹具组合；任意额外规则、孤立 anchor 均拒绝。"""
    require((original == DEFAULT_ROOT and user == b"") or
            (original == USER_ROOT and user == USER_ANCHOR_RULE), "LAB_UNEXPECTED_ROOT_RULES")


class UserRuleGuard:
    """每个检查点保存三份原始输出并逐字节核对；不修改任何规则。"""

    def __init__(self, directory, root, user, apple):
        self.directory = directory
        self.expected = {"root": root, "user": user, "apple": apple}
        self.checks = []

    def check(self, stage):
        actual = {"root": read_rules(), "user": read_rules(USER_ANCHOR), "apple": read_rules("com.apple/*")}
        record = {"stage": stage, "unchanged": actual == self.expected, "sha256": {}}
        for name, data in actual.items():
            write_new(self.directory / f"user-check-{len(self.checks):02d}-{name}.txt", data)
            record["sha256"][name] = hashlib.sha256(data).hexdigest()
        self.checks.append(record)
        require(record["unchanged"], "LAB_USER_RULES_CHANGED")


def unknown_rule_probe(engine, report=None):
    """注入固定 lab 规则，证明执行器不代删；夹具仅在字节仍匹配时清理自己的注入。"""
    anchor = engine.adapter.root
    require(not read_rules(anchor), "LAB_UNKNOWN_ANCHOR_NOT_EMPTY")
    if report is None:
        report = {}
    report.update(passed=False, fixtureCleanup=False)
    try:
        command(["/sbin/pfctl", "-a", anchor, "-f", "-"], UNKNOWN_RULE, binary=True)
        before = read_rules(anchor)
        report.update(ruleUtf8=before.decode(), ruleSha256=hashlib.sha256(before).hexdigest())
        require(before == UNKNOWN_RULE, "LAB_UNKNOWN_FIXTURE_MISMATCH")
        engine.recover()
        snapshot = engine.snapshot()
        try:
            engine.stop()
        except Rejected as exc:
            require(str(exc) == "RECOVERY_PENDING", "LAB_UNKNOWN_UNEXPECTED_ERROR")
        else:
            require(False, "LAB_UNKNOWN_NOT_REJECTED")
        report.update(paused=engine.store.get("paused"), recoveryErrors=snapshot["recoveryErrors"],
                      ruleUnchanged=read_rules(anchor) == before)
        report["passed"] = (report["paused"] and report["ruleUnchanged"] and
                            "STATE_RECONCILIATION_FAILED" in report["recoveryErrors"])
        require(report["passed"], "LAB_UNKNOWN_RULE_FAILED")
    finally:
        # 这不是执行器的恢复路径：只清理本次明确注入、且没有被修改的夹具。
        if read_rules(anchor) == UNKNOWN_RULE:
            command(["/sbin/pfctl", "-a", anchor, "-f", "-"], "")
            report["fixtureCleanup"] = read_rules(anchor) == b""
        report["passed"] = report["passed"] and report["fixtureCleanup"]
        require(report["fixtureCleanup"], "LAB_UNKNOWN_FIXTURE_CLEANUP_FAILED")
    return report


def main(directory, guardtargets):
    require(sys.platform == "darwin" and os.geteuid() == 0, "LAB_ADMIN_REQUIRED")
    require(directory.is_absolute() and not directory.exists(), "LAB_NEW_DIRECTORY_REQUIRED")
    require(guardtargets.is_absolute() and guardtargets.is_file(), "LAB_TARGET_BINARY_REQUIRED")
    directory.mkdir(mode=0o700, parents=True)
    info = command(["/sbin/pfctl", "-s", "info"])[0]
    require("Status: Disabled" in info, "LAB_REQUIRES_DISABLED_PF")
    original, user = read_rules(), read_rules(USER_ANCHOR)
    existing_rules(original, user)
    apple = read_rules("com.apple/*")
    loopback = command(["/sbin/ifconfig", "lo0"])[0]
    require("inet 127.0.0.2 " not in loopback, "LAB_ALIAS_ALREADY_PRESENT")
    write_new(directory / "root-before.conf", original)
    write_new(directory / "apple-before.txt", apple)
    write_new(directory / "user-anchor-before.conf", user)
    write_new(directory / "user-fixture-root.conf", USER_ROOT)
    write_new(directory / "user-fixture-anchor.conf", USER_ANCHOR_RULE)
    helper = directory / "pf-state-helper"
    source = Path(__file__).resolve().parent / "pf_state_helper.c"
    command(["/usr/bin/clang", "-O2", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(helper)])
    helper.chmod(0o700)
    require(parse(command([str(helper), "--abi"])[0])["kernelMatches"], "PF_ABI_UNVERIFIED")
    summary = {"passed": False, "rebootTested": False, "scenarios": [],
               "guardtargetsSha256": hashlib.sha256(guardtargets.read_bytes()).hexdigest(),
               "sources": {str(p.relative_to(source.parent.parent)): hashlib.sha256(p.read_bytes()).hexdigest()
                           for p in sorted(source.parent.glob("*.py")) + [source]}, "cleanup": {},
               "userFixturePreexisting": original == USER_ROOT, "userRuleChecks": []}
    token = None
    alias = False
    attached = False
    fixture_created = False
    try:
        if original == DEFAULT_ROOT:
            fixture_created = True
            command(["/sbin/pfctl", "-a", USER_ANCHOR, "-f", "-"], USER_ANCHOR_RULE, binary=True)
            require(read_rules(USER_ANCHOR) == USER_ANCHOR_RULE, "LAB_USER_FIXTURE_MISMATCH")
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
            c["limits"].update(E2_LIMITS.get(scenario, {}))
            c["capabilityHash"] = capability_set_sha256(c)
            write_new(path, canonical(c))
            rules = USER_ROOT.decode() + f'anchor "{PF.anchor_root(c["executorId"])}/*" all\n'
            command(["/sbin/pfctl", "-n", "-R", "-f", "-"], rules)
            require(read_rules() == (attached or original), "LAB_USER_RULES_CHANGED")
            attached = rules.encode()
            command(["/sbin/pfctl", "-R", "-f", "-"], rules)
            guard = UserRuleGuard(root, rules.encode(), USER_ANCHOR_RULE, apple)
            summary["userRuleChecks"].append({"scenario": scenario, "checks": guard.checks})
            guard.check("before")
            if token is None:
                out, err = command(["/sbin/pfctl", "-E"])
                found = re.search(r"Token\s*:\s*(\d+)", out + err)
                require(found is not None, "LAB_ENABLE_TOKEN_MISSING")
                token = found[1]
                write_new(directory / "enable-token", token.encode())
            run(path, root / "keys/signing.der", "canary", root / "result.json",
                "peer_inbound", guardtargets, scenario, checkpoint=guard.check)
            guard.check("scenario_complete")
            if scenario == "ttl":
                probe_engine = build(path, resolver=False)
                summary["unknownRule"] = {}
                try:
                    unknown_rule_probe(probe_engine, summary["unknownRule"])
                finally:
                    probe_engine.adapter.close()
                guard.check("unknown_rule_recovery")
            result = parse((root / "result.json").read_bytes())
            summary["scenarios"].append({"scenario": scenario, "passed": result["passed"]})
        summary["passed"] = (all(s["passed"] for s in summary["scenarios"]) and
                             summary.get("unknownRule", {}).get("passed", False))
    finally:
        # 每项恢复独立尝试；失败记录并继续其余清理，绝不运行全局 flush 或强制 -d。
        actions = []
        if attached:
            actions.append(("rootRestored", ["/sbin/pfctl", "-R", "-f", "-"], original.decode()))
        if token is not None:
            actions.append(("tokenReleased", ["/sbin/pfctl", "-X", token], None))
        if alias:
            actions.append(("aliasRemoved", ["/sbin/ifconfig", "lo0", "-alias", "127.0.0.2"], None))
        for name, args, data in actions:
            try:
                if name == "rootRestored":
                    # 只恢复本次挂接或已恢复的根；不覆盖运行期间出现的外部改动。
                    require(read_rules() in (attached, original), "LAB_USER_RULES_CHANGED")
                command(args, data)
                summary["cleanup"][name] = True
            except Exception:
                summary["cleanup"][name] = False
        if fixture_created:
            try:
                require(read_rules(USER_ANCHOR) == USER_ANCHOR_RULE, "LAB_USER_RULES_CHANGED")
                command(["/sbin/pfctl", "-a", USER_ANCHOR, "-f", "-"], "")
                summary["cleanup"]["userFixtureRemoved"] = read_rules(USER_ANCHOR) == user
            except Exception:
                summary["cleanup"]["userFixtureRemoved"] = False
        try:
            summary["cleanup"].update(
                rootUnchanged=read_rules() == original,
                userAnchorUnchanged=read_rules(USER_ANCHOR) == user,
                appleUnchanged=read_rules("com.apple/*") == apple,
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
