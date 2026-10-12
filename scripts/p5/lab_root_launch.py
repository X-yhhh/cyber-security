"""A4 root 启动器：只运行 root 所有、逐文件核对过的暂存副本；须用 SIP 保护的 /usr/bin/python3 -I 执行。

调用方先把本文件复制到 root 所有目录并核对 SHA 后再执行（见 scripts/p5/README.md）。启动器：
1. 拒绝已存在的运行目录；在 /private/var/root/hostguard-lab/<runId> 建 root:wheel 0700 目录；
2. 用 ditto 复制暂存包，核对清单 SHA 等于授权时给出的值，逐文件核对 SHA、无多余文件、软链接不越界；
3. 以最小环境（系统 PATH、HOME=/var/root、仅指向副本的 PYTHONPATH）运行单一任务；
4. 把证据目录复制一份交给 --owner-uid 只读查看；root 原件保留。
保持 Python 3.9 兼容（系统解释器）。不提供任意命令入口。
"""
import argparse
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import time

RUNS = "/private/var/root/hostguard-lab"
TASKS = ("p1-probe", "e1e2-lab", "e3-executor", "g3-executor")
E3_SECRETS = ("credential", "budget.key", "targetKey.pem")


def sha(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def fail(code):
    sys.stderr.write(code + "\n")
    raise SystemExit(2)


def verify(stage, manifest):
    seen = set()
    for directory, names, files in os.walk(stage):
        for name in names + files:
            path = os.path.join(directory, name)
            relative = os.path.relpath(path, stage)
            seen.add(relative)
            if os.path.islink(path):
                target = os.readlink(path)
                resolved = os.path.realpath(path)
                if manifest["symlinks"].get(relative) != target or os.path.isabs(target) or \
                        not resolved.startswith(os.path.realpath(stage) + os.sep):
                    fail("STAGE_SYMLINK_MISMATCH:" + relative)
            elif os.path.isfile(path):
                if manifest["files"].get(relative, {}).get("sha256") != sha(path):
                    fail("STAGE_FILE_MISMATCH:" + relative)
    expected = set(manifest["files"]) | set(manifest["symlinks"])
    if not expected <= seen or any(os.path.isfile(os.path.join(stage, r)) or os.path.islink(os.path.join(stage, r))
                                   for r in seen - expected):
        fail("STAGE_FILE_SET_MISMATCH")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--task", choices=TASKS, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--authorization-reference", required=True)
    parser.add_argument("--owner-uid", type=int, required=True)
    parser.add_argument("--evidence-copy", required=True)
    parser.add_argument("--rendezvous", help="e3-executor：orchestrate.py --mode pf 的运行目录")
    parser.add_argument("--scope", choices=("peer_service", "peer_inbound"))
    parser.add_argument("--scenario", choices=("revoke", "disconnect", "receipt_loss"))
    parser.add_argument("--ready-marker", help="e3-executor/g3-executor：副本核验完成后创建的就绪标记（新绝对路径），用户侧据此再启动后端")
    parser.add_argument("--max-seconds", type=int, default=5400, help="g3-executor：会话最长秒数（不含排空）")
    args = parser.parse_args()
    if (args.task == "e3-executor") != bool(args.rendezvous and args.scope and args.scenario):
        fail("E3_ROUND_ARGUMENTS_REQUIRED")
    if args.task == "g3-executor" and not (args.rendezvous and not args.scope and not args.scenario and 60 <= args.max_seconds <= 7200):
        fail("G3_ARGUMENTS_REQUIRED")
    if os.geteuid() != 0 or sys.flags.isolated != 1:
        fail("ROOT_ISOLATED_PYTHON_REQUIRED")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{5,62}", args.run_id) or not re.fullmatch(r"[0-9a-f]{64}", args.manifest_sha256):
        fail("INVALID_ARGUMENT")
    if os.path.exists(args.evidence_copy) or not os.path.isabs(args.evidence_copy):
        fail("EVIDENCE_COPY_MUST_BE_NEW_ABSOLUTE")
    os.umask(0o077)
    os.makedirs(RUNS, mode=0o700, exist_ok=True)
    os.chown(RUNS, 0, 0)
    os.chmod(RUNS, 0o700)
    run = os.path.join(RUNS, args.run_id)
    os.mkdir(run, 0o700)
    manifest_path = os.path.join(run, "manifest.json")
    subprocess.run(["/bin/cp", os.path.join(args.stage, "manifest.json"), manifest_path], check=True)
    if sha(manifest_path) != args.manifest_sha256:
        fail("STAGE_MANIFEST_SHA_MISMATCH")
    with open(manifest_path) as stream:
        manifest = json.load(stream)
    bundle = os.path.join(run, "stage")
    subprocess.run(["/usr/bin/ditto", os.path.join(args.stage, "stage"), bundle], check=True)
    subprocess.run(["/usr/sbin/chown", "-R", "-h", "0:0", run], check=True)
    subprocess.run(["/bin/chmod", "-R", "go-w", run], check=True)
    verify(bundle, manifest)
    app = os.path.join(bundle, "app")
    python = os.path.join(bundle, manifest["python"])
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/var/root", "LANG": "en_US.UTF-8",
           "PYTHONPATH": app + ":" + os.path.join(bundle, "site"), "PYTHONNOUSERSITE": "1",
           "PYTHONDONTWRITEBYTECODE": "1", "HOSTGUARD_LAB_AUTHORIZATION": args.authorization_reference,
           "DYLD_LIBRARY_PATH": os.path.join(bundle, manifest["dyldLibraryPath"]),
           "DYLD_FRAMEWORK_PATH": os.path.join(bundle, manifest["dyldFrameworkPath"])}
    evidence = os.path.join(run, "evidence")
    record = {"runId": args.run_id, "task": args.task, "commit": manifest["commit"],
              "manifestSha256": args.manifest_sha256, "authorizationReference": args.authorization_reference,
              "kernelVersion": os.uname().version,
              "launcherBlockedSignals": sorted(str(x) for x in signal.pthread_sigmask(signal.SIG_BLOCK, []))}
    if manifest.get('subjectBinding') is not None:
        env['HOSTGUARD_SUBJECT_BINDING']=os.path.join(bundle,'subject-binding.json')
        record['subjectBinding']=manifest['subjectBinding']
    if args.task == "p1-probe":
        helper = os.path.join(run, "pf-state-helper")
        subprocess.run(["/usr/bin/clang", "-O2", "-Wall", "-Wextra", "-Werror",
                        os.path.join(app, "scripts/p1/pf_state_helper.c"), "-o", helper], check=True, env=env)
        os.chmod(helper, 0o700)
        record["helperSha256"] = sha(helper)
        command = [python, "-B", "-s", os.path.join(app, "scripts/p1/pf_probe.py"), "probe",
                   "--output", evidence, "--helper", helper, "--port", "55231"]
    elif args.task == "e1e2-lab":
        command = [python, "-B", "-s", "-m", "executor.pf_lab", "--directory", evidence,
                   "--guardtargets", os.path.join(bundle, "guardtargets")]
    elif args.task == "g3-executor":
        # 正式 G3：常驻执行器与独立恢复器，只读取 rendezvous 中 owner 所有的数据文件。
        if not os.path.isabs(args.rendezvous) or os.path.realpath(args.rendezvous) != args.rendezvous:
            fail("E3_RENDEZVOUS_INVALID")
        info = os.lstat(args.rendezvous)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != args.owner_uid:
            fail("E3_RENDEZVOUS_UNTRUSTED")
        if args.ready_marker:
            if not os.path.isabs(args.ready_marker) or os.path.lexists(args.ready_marker):
                fail("E3_READY_MARKER_INVALID")
            marker = os.open(args.ready_marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.fchown(marker, args.owner_uid, -1)
            os.close(marker)
        os.mkdir(evidence, 0o700)
        record.update(rendezvous=args.rendezvous, maxSeconds=args.max_seconds)
        command = [python, "-B", "-s", os.path.join(app, "scripts/p5/g3_executor.py"), "--directory", args.rendezvous,
                   "--work", evidence, "--owner-uid", str(args.owner_uid), "--max-seconds", str(args.max_seconds)]
    else:
        # 单轮 E3：等待用户态中继建好管道；只读其数据文件的副本，root 工作目录即证据目录。
        if not os.path.isabs(args.rendezvous) or os.path.realpath(args.rendezvous) != args.rendezvous:
            fail("E3_RENDEZVOUS_INVALID")
        round_dir = os.path.join(args.rendezvous, args.scope + "-" + args.scenario)
        if args.ready_marker:
            # 副本已核验、即将等待管道：交给用户侧的就绪信号，避免后端在 root 侧就绪前超时。
            if not os.path.isabs(args.ready_marker) or os.path.lexists(args.ready_marker):
                fail("E3_READY_MARKER_INVALID")
            marker = os.open(args.ready_marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.fchown(marker, args.owner_uid, -1)
            os.close(marker)
        deadline = time.monotonic() + 900
        while not all(os.path.exists(os.path.join(round_dir, n)) for n in ("from-executor.fifo", "to-executor.fifo")):
            if time.monotonic() > deadline:
                fail("E3_RELAY_NOT_READY")
            time.sleep(.5)
        info = os.lstat(round_dir)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != args.owner_uid:
            fail("E3_RENDEZVOUS_UNTRUSTED")
        os.mkdir(evidence, 0o700)
        env.update(P5_FIREWALL="pf", P5_A4_REFERENCE=args.authorization_reference,
                   P5_GUARDTARGETS=os.path.join(bundle, "guardtargets"))
        record.update(scope=args.scope, scenario=args.scenario, rendezvous=round_dir)
        command = [python, "-B", "-s", os.path.join(app, "scripts/p5/joint_executor.py"), "--directory", round_dir,
                   "--work", evidence, "--owner-uid", str(args.owner_uid)]
    alias = False
    if args.task == "p1-probe":
        # P1 探针只用回环 127.0.0.2 作对端；仅在原先不存在时临时添加，结束只移除本次添加的别名。
        loopback = subprocess.run(["/sbin/ifconfig", "lo0"], capture_output=True, text=True, check=True).stdout
        if "inet 127.0.0.2 " in loopback:
            fail("LAB_ALIAS_ALREADY_PRESENT")
        subprocess.run(["/sbin/ifconfig", "lo0", "alias", "127.0.0.2", "netmask", "255.255.255.255"], check=True)
        alias = True
    try:
        # 子任务输出另存一份随证据交回，便于定位失败；原 launch.log 仍保留在 root 目录。
        with open(os.path.join(run, "task.log"), "xb") as task_log:
            try:
                exit_code = subprocess.run(command, cwd=app, env=env, timeout=args.max_seconds + 600 if args.task == "g3-executor" else 1800, stdout=task_log,
                                           stderr=subprocess.STDOUT).returncode
            except subprocess.TimeoutExpired:
                # run() 已终止并回收子任务；照常写启动记录并交回证据，记为失败。
                exit_code, record["timedOut"] = 124, True
    finally:
        if alias:
            removed = subprocess.run(["/sbin/ifconfig", "lo0", "-alias", "127.0.0.2"]).returncode == 0
            loopback = subprocess.run(["/sbin/ifconfig", "lo0"], capture_output=True, text=True).stdout
            record["aliasRemoved"] = removed and "inet 127.0.0.2 " not in loopback
    record["exitCode"] = exit_code if record.get("aliasRemoved", True) else 3
    with open(os.path.join(run, "launch-record.json"), "x") as stream:
        json.dump(record, stream, sort_keys=True, indent=1)
    copy = args.evidence_copy
    os.makedirs(copy, 0o700)
    subprocess.run(["/usr/bin/ditto", run + "/evidence", copy + "/evidence"], check=False)
    for secret in E3_SECRETS:
        path = os.path.join(copy, "evidence", secret)
        if os.path.lexists(path):
            os.remove(path)
    subprocess.run(["/bin/cp", os.path.join(run, "launch-record.json"), copy + "/launch-record.json"], check=True)
    subprocess.run(["/bin/cp", os.path.join(run, "task.log"), copy + "/task.log"], check=False)
    subprocess.run(["/usr/sbin/chown", "-R", str(args.owner_uid), copy], check=True)
    subprocess.run(["/bin/chmod", "-R", "u+rX,go-rwx", copy], check=True)
    print(json.dumps(record, sort_keys=True))
    raise SystemExit(record["exitCode"])


if __name__ == "__main__":
    main()
