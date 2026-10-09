#!/usr/bin/env python3
"""PF 精确状态删除 ABI 的只读静态证据：系统更新后、申请实机 canary 前运行。

只读取 uname、sw_vers、/sbin/pfctl 字节与反汇编，并在临时目录编译两份 helper（_Static_assert
校验布局与 ioctl 编号），调用其 --abi 子命令（只读 uname，不打开 /dev/pf）。不需要 root，
不修改 PF、接口或系统配置。静态证据不能替代实机 canary：放行新构建前仍须 P1 探针通过。
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
IOCTL = 0xC0D84429
HELPERS = ("scripts/p1/pf_state_helper.c", "executor/pf_state_helper.c")


def run(args):
    return subprocess.run(args, capture_output=True, text=True, timeout=60, check=True).stdout


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def ioctl_sites(disassembly):
    """arm64 以 mov w1,#低16位 + movk w1,#高16位,lsl#16 装载 ioctl 请求号；只认紧邻成对出现。"""
    lines = disassembly.splitlines()
    low, high = f"#0x{IOCTL & 0xFFFF:x}", f"#0x{IOCTL >> 16:x}, lsl #16"
    sites = []
    for index in range(len(lines) - 1):
        first, second = lines[index], lines[index + 1]
        if re.search(r"\bmov\s+w1, " + re.escape(low) + r"$", first) and \
                re.search(r"\bmovk\s+w1, " + re.escape(high) + r"$", second):
            sites.append(first.split()[0])
    return sites


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    output = parser.parse_args().output.resolve()
    if output.exists():
        raise SystemExit("output exists")
    uname = os.uname()
    build = re.search(r"root:(xnu-[^/]+)/", uname.version)
    evidence = {"kind": "pf-abi-static-evidence/1", "requiresRuntimeCanary": True,
                "kernelRelease": uname.release, "kernelVersion": uname.version,
                "xnuBuild": build[1] if build else None, "machine": uname.machine,
                "productVersion": run(["/usr/bin/sw_vers", "-productVersion"]).strip(),
                "buildVersion": run(["/usr/bin/sw_vers", "-buildVersion"]).strip(),
                "pfctlSha256": sha("/sbin/pfctl"), "expectedIoctl": hex(IOCTL), "structSize": 216}
    disassembly = run(["/usr/bin/otool", "-arch", "arm64e", "-tv", "/sbin/pfctl"])
    evidence["pfctlArm64eIoctlSites"] = ioctl_sites(disassembly)
    evidence["pfctlArm64eDisassemblySha256"] = hashlib.sha256(disassembly.encode()).hexdigest()
    evidence["helpers"] = {}
    with tempfile.TemporaryDirectory() as temporary:
        for source in HELPERS:
            binary = Path(temporary) / Path(source).parent.name
            # -Werror 让 _Static_assert（216 字节、偏移、_IOWR 编号）失败即编译失败。
            run(["/usr/bin/clang", "-O2", "-Wall", "-Wextra", "-Werror", str(ROOT / source), "-o", str(binary)])
            abi = subprocess.run([str(binary), "--abi"], capture_output=True, text=True, timeout=10)
            evidence["helpers"][source] = {"sourceSha256": sha(ROOT / source), "staticAssertsCompiled": True,
                                           "abiExitCode": abi.returncode, "abi": json.loads(abi.stdout)}
    evidence["staticPassed"] = (len(evidence["pfctlArm64eIoctlSites"]) >= 1 and platform.machine() == "arm64"
                                and all(h["staticAssertsCompiled"] for h in evidence["helpers"].values()))
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x") as stream:
        json.dump(evidence, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({k: evidence[k] for k in ("xnuBuild", "pfctlSha256", "pfctlArm64eIoctlSites", "staticPassed")}))


if __name__ == "__main__":
    main()
