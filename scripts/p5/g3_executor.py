"""A6 正式 G3 的 root 侧常驻执行器：在本轮 PF 会话内运行 `executor run` 与独立 `executor recover`。

由 lab_root_launch.py 的 g3-executor 任务以 root 暂存副本启动。只从用户态 rendezvous 目录复制
数据文件（不执行其中内容），配置由本脚本按固定 lab 回环范围组装并经 subject 绑定核验；
执行器进程与恢复进程均为 executor 包的原始服务入口，本脚本不改变任何执行门。

协议（文件，rendezvous 目录由 owner 所有）：
- 用户态写 input.json → 本脚本写 boot.json（执行器 boot，交回 owner）；
- 用户态写 stop → 本脚本等待已安装规则清空（TTL 或撤销）后停止两进程并退出 PF 会话；
- 结果写 root 工作目录 result.json，副本交回 rendezvous。
"""
import argparse
import base64
from contextlib import ExitStack
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from executor.common import Rejected, canonical, digest, parse, require, stamp, write_new
from executor.config import load as load_config
from executor.contract import capability_set_sha256, protected_ports_sha256
from executor.subject_binding import configured, verify_config
from pf_session import session

LIMITS = {"maxTtlSeconds": 60, "maxContinuousBlockSeconds": 120, "maxActiveRulesPerAsset": 10, "maxNewActionsPerMinute": 5}
COPIED = ("controlPlaneCA", "targetCA", "targetCertificate", "targetKey")


def owned(path, owner):
    """不跟随软链接打开并按 fstat 核对普通文件与属主。"""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != owner:
        os.close(fd)
        raise Rejected("LAB_EXTERNAL_INPUT_UNTRUSTED")
    with os.fdopen(fd, "rb") as stream:
        raw = stream.read((1 << 20) + 1)
    require(len(raw) <= 1 << 20, "LAB_EXTERNAL_INPUT_UNTRUSTED")
    return raw


def give(directory, owner, name, value):
    path = directory / name
    write_new(path, canonical(value))
    os.chown(path, owner, -1)


def assemble(data, work):
    """固定 PF/lo0/回环本机地址；对端、端口、能力与授权来自控制面登记，组装后按 executor 配置规则校验。"""
    for key in COPIED:
        write_new(work / (key + ".pem"), base64.b64decode(data[key]))
    write_new(work / "command-trust.json", canonical(data["commandTrust"]))
    write_new(work / "credential", data["credential"].encode())
    write_new(work / "budget.key", base64.b64decode(data["budgetKey"]))
    c = {k: data[k] for k in ("assetId", "executorId", "sensorId", "captureScopeId", "authorization", "controlPlaneURL",
                              "targetURL", "peerAddresses", "servicePorts", "capabilityIds")}
    c.update(platform="pf", environment="lab", interface="lo0", localAddresses=["127.0.0.1"], protectedPeers=[],
             protectedServicePorts=data["protection"]["protectedServicePorts"], stateDir=str(work / "state"),
             bundleIds=[data["bundleId"]], policyHashes=[data["policySha256"]], limits=dict(LIMITS),
             trustFile=str(work / "command-trust.json"), budgetKeyFile=str(work / "budget.key"),
             credentialFile=str(work / "credential"), controlPlaneCA=str(work / "controlPlaneCA.pem"),
             targetCA=str(work / "targetCA.pem"), targetCertificate=str(work / "targetCertificate.pem"),
             targetKey=str(work / "targetKey.pem"), capabilityIds=sorted(data["capabilityIds"]))
    c["inboundCapabilities"] = [{"capabilityId": cap, "protectionSetSha256": digest(data["protection"]),
                                 "protectedPortsSha256": protected_ports_sha256(c["protectedServicePorts"])}
                                for cap in sorted(data["inboundCapabilityIds"])]
    c["capabilityHash"] = capability_set_sha256(c)
    require(c["capabilityHash"] == data["capabilityHash"], "LAB_CAPABILITY_MISMATCH")
    return c


def status(python, config):
    out = subprocess.run([python, "-B", "-s", "-m", "executor", "status", "--config", str(config)], cwd=ROOT,
                         capture_output=True, text=True, timeout=30)
    require(out.returncode == 0, "LAB_EXECUTOR_STATUS_FAILED")
    return parse(out.stdout.strip().splitlines()[-1].encode())


def stop_process(process, name, facts):
    started, outcome = time.monotonic(), "exited"
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            outcome = "killed_after_timeout"
            process.kill()
            process.wait(timeout=5)
    facts[name] = {"returnCode": process.returncode, "outcome": outcome, "seconds": round(time.monotonic() - started, 3)}
    require(outcome == "exited" and process.returncode in (0, -signal.SIGTERM), "LAB_EXECUTOR_PROCESS_FAILED")


def run(directory, work, owner, max_seconds):
    os.umask(0o077)
    info = os.lstat(directory)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == owner, "E3_RENDEZVOUS_UNTRUSTED")
    deadline = time.monotonic() + 900
    while not (directory / "input.json").exists():
        require(time.monotonic() < deadline, "LAB_INPUT_NOT_READY")
        time.sleep(.5)
    data = parse(owned(directory / "input.json", owner))
    write_new(work / "input-sha256.txt", digest(data).encode())
    c = assemble(data, work)
    runtime_binding = verify_config(configured(), c)
    require(runtime_binding is not None, "LAB_SUBJECT_BINDING_REQUIRED")
    result = {"kind": "g3_executor", "passed": False, "realPF": True, "runtimeSubjectBinding": runtime_binding,
              "authorizationReference": os.environ.get("HOSTGUARD_LAB_AUTHORIZATION"), "startedAt": stamp(time.time())}
    python = sys.executable
    with ExitStack() as stack:
        helper, check, pf_facts = stack.enter_context(session(work, c["executorId"], os.environ.get("HOSTGUARD_LAB_AUTHORIZATION")))
        c["pfHelper"] = str(helper)
        config = work / "executor-config.json"
        write_new(config, canonical(c))
        load_config(config)
        logs = {name: stack.enter_context((work / (name + ".log")).open("xb")) for name in ("run", "recover")}
        env = dict(os.environ)
        processes = {}
        processes["recover"] = subprocess.Popen([python, "-X", "faulthandler", "-u", "-B", "-s", "-m", "executor", "recover",
                                                 "--config", str(config)], cwd=ROOT, env=env, stdout=logs["recover"], stderr=subprocess.STDOUT)
        stack.callback(stop_process, processes["recover"], "recoverStop", result)
        processes["run"] = subprocess.Popen([python, "-X", "faulthandler", "-u", "-B", "-s", "-m", "executor", "run",
                                             "--config", str(config)], cwd=ROOT, env=env, stdout=logs["run"], stderr=subprocess.STDOUT)
        # 退出顺序：先停 run（engine.stop 清规则），再停 recover，最后由 PF 会话核对锚点为空。
        stack.callback(stop_process, processes["run"], "runStop", result)
        boot, until = None, time.monotonic() + 60
        while boot is None:
            require(time.monotonic() < until and processes["run"].poll() is None, "LAB_EXECUTOR_START_FAILED")
            time.sleep(1)
            boot = status(python, config).get("executorBootId")
        give(directory, owner, "boot.json", {"executorBootId": boot, "at": stamp(time.time())})
        result["executorBootId"] = boot
        limit = time.monotonic() + max_seconds
        samples = []
        while not (directory / "stop").exists():
            require(time.monotonic() < limit, "LAB_SESSION_TIMEOUT")
            require(all(p.poll() is None for p in processes.values()), "LAB_EXECUTOR_EXITED")
            check()
            time.sleep(2)
            snapshot = status(python, config)
            samples.append({"at": stamp(time.time()), **{k: snapshot[k] for k in ("activeRuleCount", "paused", "pendingReceipts")},
                            "recoveryErrors": len(snapshot["recoveryErrors"])})
            give(directory, owner, "status.next", samples[-1])
            os.replace(directory / "status.next", directory / "status.json")
        # 停止请求后不主动撤销：等已安装规则按 TTL 或控制面撤销清空，最长两个 TTL。
        drain = time.monotonic() + 2 * LIMITS["maxTtlSeconds"] + 30
        while status(python, config)["activeRuleCount"] and time.monotonic() < drain:
            time.sleep(2)
        final = status(python, config)
        result.update(drainedActiveRuleCount=final["activeRuleCount"], finalPaused=final["paused"],
                      finalPendingReceipts=final["pendingReceipts"], finalRecoveryErrors=final["recoveryErrors"],
                      samples=len(samples), maxActiveRules=max([s["activeRuleCount"] or 0 for s in samples] or [0]))
        write_new(work / "status-samples.json", canonical(samples))
        check()
        stack.close()
    result["pfSession"] = pf_facts
    result["passed"] = bool(pf_facts["passed"] and result["drainedActiveRuleCount"] == 0 and not result["finalRecoveryErrors"]
                            and result["runStop"]["returnCode"] in (0, -signal.SIGTERM)
                            and result["recoverStop"]["returnCode"] in (0, -signal.SIGTERM))
    result["finishedAt"] = stamp(time.time())
    write_new(work / "result.json", canonical(result))
    give(directory, owner, "result.json", result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--owner-uid", required=True, type=int)
    parser.add_argument("--max-seconds", type=int, default=5400)
    args = parser.parse_args()
    require(args.work.is_dir() and not any(args.work.iterdir()), "LAB_WORK_DIRECTORY_INVALID")
    try:
        outcome = run(args.directory, args.work, args.owner_uid, args.max_seconds)
    except Exception as exc:
        import traceback
        traceback.print_exc()
        try:
            give(args.directory, args.owner_uid, "error.json", {"error": str(exc) if isinstance(exc, Rejected) else type(exc).__name__})
        except Exception:
            pass
        raise SystemExit(1)
    raise SystemExit(0 if outcome["passed"] else 1)
