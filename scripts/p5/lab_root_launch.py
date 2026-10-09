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
import subprocess
import sys

RUNS = "/private/var/root/hostguard-lab"
TASKS = ("p1-probe", "e1e2-lab")


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
    args = parser.parse_args()
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
              "kernelVersion": os.uname().version}
    if args.task == "p1-probe":
        helper = os.path.join(run, "pf-state-helper")
        subprocess.run(["/usr/bin/clang", "-O2", "-Wall", "-Wextra", "-Werror",
                        os.path.join(app, "scripts/p1/pf_state_helper.c"), "-o", helper], check=True, env=env)
        os.chmod(helper, 0o700)
        record["helperSha256"] = sha(helper)
        command = [python, "-B", "-s", os.path.join(app, "scripts/p1/pf_probe.py"), "probe",
                   "--output", evidence, "--helper", helper, "--port", "55231"]
    else:
        command = [python, "-B", "-s", "-m", "executor.pf_lab", "--directory", evidence,
                   "--guardtargets", os.path.join(bundle, "guardtargets")]
    result = subprocess.run(command, cwd=app, env=env, timeout=1800)
    record["exitCode"] = result.returncode
    with open(os.path.join(run, "launch-record.json"), "x") as stream:
        json.dump(record, stream, sort_keys=True, indent=1)
    copy = args.evidence_copy
    os.makedirs(copy, 0o700)
    subprocess.run(["/usr/bin/ditto", run + "/evidence", copy + "/evidence"], check=False)
    subprocess.run(["/bin/cp", os.path.join(run, "launch-record.json"), copy + "/launch-record.json"], check=True)
    subprocess.run(["/usr/sbin/chown", "-R", str(args.owner_uid), copy], check=True)
    subprocess.run(["/bin/chmod", "-R", "u+rX,go-rwx", copy], check=True)
    print(json.dumps(record, sort_keys=True))
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
