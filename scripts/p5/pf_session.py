"""A4 后显式 root 运行的单轮 PF 会话；只挂接专用 anchor 并释放本轮 enable token。"""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import re
import sys

from executor.common import canonical, parse, require, write_new
from executor.pf_lab import USER_ANCHOR, command, existing_rules, read_rules
from executor.platform import PF


EMPTY_CHILD = re.compile(r'anchor "[0-9a-f-]{36}" all \{\n\}\n')


def owned_rules_remain(text):
    """`-a <根>/* -sr` 会递归列出子 anchor；PF 保留的空命令子 anchor 输出为 `anchor "<id>" all {` 与 `}`。

    只把这种空壳视为无规则；任何规则行、非命令 ID 子 anchor 或嵌套内容都算残留。
    """
    return bool(EMPTY_CHILD.sub("", text.decode() if isinstance(text, bytes) else text).strip())


@contextmanager
def session(directory, executor_id, authorization, *, loopback_alias=True):
    """未知根规则/既有别名拒绝；恢复前核对原始字节，不覆盖并行修改。

    调用方须先停执行器与恢复进程并清空其规则。失败证据保留在外部目录，
    本入口不调用 sudo、不全局 flush、不用 -d 强制关闭其他 PF 使用者。
    """
    require(sys.platform == "darwin" and os.geteuid() == 0 and authorization,
            "A4_ROOT_AND_AUTHORIZATION_REQUIRED")
    require("Status: Disabled" in command(["/sbin/pfctl", "-s", "info"])[0], "LAB_REQUIRES_DISABLED_PF")
    original, user, apple = read_rules(), read_rules(USER_ANCHOR), read_rules("com.apple/*")
    existing_rules(original, user)
    require("inet 127.0.0.2 " not in command(["/sbin/ifconfig", "lo0"])[0], "LAB_ALIAS_ALREADY_PRESENT")
    anchor = PF.anchor_root(executor_id)
    require(not owned_rules_remain(read_rules(anchor + "/*")), "LAB_ANCHOR_NOT_EMPTY")
    helper = directory / "pf-state-helper"
    source = Path(__file__).resolve().parents[2] / "executor/pf_state_helper.c"
    command(["/usr/bin/clang", "-O2", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(helper)])
    helper.chmod(0o700)
    require(parse(command([str(helper), "--abi"])[0])["kernelMatches"], "PF_ABI_UNVERIFIED")
    write_new(directory / "root-before.conf", original)
    write_new(directory / "user-before.conf", user)
    write_new(directory / "apple-before.conf", apple)
    attached = original + f'anchor "{anchor}/*" all\n'.encode()
    token, alias, root_changed = None, False, False
    facts = {"passed": False, "cleanup": {}, "authorizationReference": authorization}
    try:
        command(["/sbin/pfctl", "-n", "-R", "-f", "-"], attached, binary=True)
        require(read_rules() == original, "LAB_USER_RULES_CHANGED")
        # 即使工具异常也尝试核对恢复；不把“命令返回失败”当作“没有变更”。
        root_changed = True
        command(["/sbin/pfctl", "-R", "-f", "-"], attached, binary=True)
        if loopback_alias:
            alias = True
            command(["/sbin/ifconfig", "lo0", "alias", "127.0.0.2", "netmask", "255.255.255.255"])
        out, err = command(["/sbin/pfctl", "-E"])
        found = re.search(r"Token\s*:\s*(\d+)", out + err)
        require(found is not None, "LAB_ENABLE_TOKEN_MISSING")
        token = found[1]
        write_new(directory / "enable-token", token.encode())
        def check():
            require(read_rules() == attached and read_rules(USER_ANCHOR) == user and
                    read_rules("com.apple/*") == apple, "LAB_USER_RULES_CHANGED")
        check()
        try:
            yield helper, check, facts
        except BaseException as exc:
            # 保留会话内的原始失败；否则最终的会话失败码会掩盖真实原因。
            facts["bodyError"] = str(exc) if exc.__class__.__name__ == "Rejected" else exc.__class__.__name__
            raise
        check()
        remaining = read_rules(anchor + "/*")
        facts["ownedAnchorListingSha256"] = hashlib.sha256(remaining).hexdigest()
        require(not owned_rules_remain(remaining), "LAB_OWNED_RULES_REMAIN")
        facts["passed"] = True
    finally:
        operations = []
        if root_changed:
            operations.append(("rootRestored", ["/sbin/pfctl", "-R", "-f", "-"], original))
        if token:
            operations.append(("tokenReleased", ["/sbin/pfctl", "-X", token], None))
        if alias:
            operations.append(("aliasRemoved", ["/sbin/ifconfig", "lo0", "-alias", "127.0.0.2"], None))
        for name, args, data in operations:
            try:
                if name == "rootRestored":
                    require(read_rules() in (attached, original), "LAB_USER_RULES_CHANGED")
                command(args, data, binary=data is not None)
                facts["cleanup"][name] = True
            except Exception:
                facts["cleanup"][name] = False
        try:
            facts["cleanup"].update(rootUnchanged=read_rules() == original,
                userUnchanged=read_rules(USER_ANCHOR) == user, appleUnchanged=read_rules("com.apple/*") == apple,
                pfDisabled="Status: Disabled" in command(["/sbin/pfctl", "-s", "info"])[0],
                aliasAbsent="inet 127.0.0.2 " not in command(["/sbin/ifconfig", "lo0"])[0])
        except Exception:
            facts["cleanup"]["verified"] = False
        facts["passed"] = facts["passed"] and all(facts["cleanup"].values())
        write_new(directory / "pf-session.json", canonical(facts))
        require(facts["passed"], "LAB_PF_SESSION_OR_CLEANUP_FAILED")
