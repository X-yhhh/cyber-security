"""仅管理专用 PF anchor/WFP 子层；不接管默认策略、不执行任意 shell。"""
import base64
import ctypes as C
import ipaddress
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time
import uuid

from .common import Rejected, parse, require
from .contract import unprotected_ranges


def inbound_ranges(scope):
    """安装、枚举和状态清理均使用同一份已扣除保护端口的闭区间。"""
    ranges = scope.get("ranges")
    require(scope.get("port") is None and isinstance(ranges, list) and 1 < len(ranges) <= 129,
            "SCOPE_DENIED")
    previous = 0
    protected = []
    for pair in ranges:
        require(isinstance(pair, list) and len(pair) == 2 and
                all(type(p) is int and 1 <= p <= 65535 for p in pair) and
                previous < pair[0] <= pair[1], "SCOPE_DENIED")
        protected.extend(range(previous + 1, pair[0]))
        previous = pair[1]
    protected.extend(range(previous + 1, 65536))
    require(len(protected) <= 128 and {22, 53, 3389} <= set(protected) and
            ranges == unprotected_ranges(protected), "SCOPE_DENIED")
    return ranges


class PF:
    @staticmethod
    def anchor_root(executor_id):
        # PF anchor 名称最多 63 字节；22 字符编码保留完整 UUID，仍可容纳子命令 UUID。
        encoded = base64.urlsafe_b64encode(uuid.UUID(executor_id).bytes).rstrip(b"=").decode("ascii")
        return "hg5" + encoded

    def __init__(self, executor_id, helper):
        require(sys.platform == "darwin", "PLATFORM_UNSUPPORTED")
        self.root = self.anchor_root(executor_id)
        self.helper = Path(helper)
        require(self.helper.is_absolute() and not self.helper.is_symlink(), "PF_HELPER_INVALID")
        require(self.helper.is_file() and self.helper.stat().st_uid == 0 and
                self.helper.stat().st_mode & 0o022 == 0, "PF_HELPER_PERMISSIONS_INVALID")

    @staticmethod
    def run(args, data=None):
        try:
            result = subprocess.run(args, input=data, text=True, capture_output=True, timeout=.5,
                                    env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"})
            require(result.returncode == 0, "PF_OPERATION_FAILED")
            return result.stdout
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Rejected("PF_OPERATION_FAILED") from exc

    def handle(self, command):
        return self.root + "/" + str(uuid.UUID(command))

    def preflight(self):
        require(os.geteuid() == 0, "PF_PERMISSION_REQUIRED")
        info = self.run(["/sbin/pfctl", "-s", "info"])
        require("Status: Enabled" in info, "PF_NOT_ENABLED")
        root = self.run(["/sbin/pfctl", "-sr"])
        require(any(line.strip() == f'anchor "{self.root}/*" all' for line in root.splitlines()),
                "PF_ANCHOR_NOT_ATTACHED")
        require(parse(self.run([str(self.helper), "--abi"]))["kernelMatches"], "PF_ABI_UNVERIFIED")

    def install(self, command, scope, apply_by):
        self.preflight()
        require(command not in self.inventory(), "RULE_ALREADY_EXISTS")
        a, b = ipaddress.IPv4Address(scope["local"]), ipaddress.IPv4Address(scope["peer"])
        require(re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", scope["interface"]) is not None,
                "SCOPE_DENIED")
        if scope["port"] is None:
            ranges = inbound_ranges(scope)
        else:
            require(set(scope) == {"local", "peer", "port", "interface"} and
                    type(scope["port"]) is int and 0 < scope["port"] <= 65535, "SCOPE_DENIED")
            ranges = [[scope["port"], scope["port"]]]
        rule = "".join(f'block drop quick on {scope["interface"]} inet proto tcp from {b} to {a} '
                       f'port {first if first == last else f"{first}:{last}"} label "hg5-{command}"\n'
                       for first, last in ranges)
        require(time.time() <= apply_by, "COMMAND_EXPIRED")
        self.run(["/sbin/pfctl", "-a", self.handle(command), "-f", "-"], rule)
        if scope["port"] is None:
            encoded = ",".join(f"{first}:{last}" for first, last in ranges)
            self.run([str(self.helper), "kill-ranges", str(a), str(b), encoded, scope["interface"]])
        else:
            self.run([str(self.helper), "kill", str(a), str(b), str(scope["port"]), scope["interface"]])

    def inventory(self):
        # 执行器只在命令子 anchor 写规则；命名空间根上的规则也必须报告未知归属。
        require(not self.run(["/sbin/pfctl", "-a", self.root, "-sr"]).strip(), "UNKNOWN_OWNED_RULE")
        anchors = self.run(["/sbin/pfctl", "-a", self.root, "-s", "Anchors"])
        result = {}
        for anchor in anchors.splitlines():
            child = anchor.strip().rsplit("/", 1)[-1]
            # 空子 anchor 可由 PF 保留；任何非本机命令 UUID 的名字仍作为异常处理。
            require(re.fullmatch(r"[0-9a-f-]{36}", child) is not None, "UNKNOWN_OWNED_RULE")
            handle = self.handle(child)
            raw = self.run(["/sbin/pfctl", "-a", handle, "-sr"]).strip()
            if not raw:
                continue
            rows = []
            for line in raw.splitlines():
                match = re.fullmatch(r'block drop quick on ([A-Za-z0-9_.-]+) inet proto tcp from '
                                     r'(\d+\.\d+\.\d+\.\d+)(?:/32)? to (\d+\.\d+\.\d+\.\d+)(?:/32)? '
                                     r'port (?:= )?([A-Za-z0-9_-]+)(?::([0-9]+))? label "hg5-([0-9a-f-]{36})"', line)
                require(match is not None and match[6] == child, "UNKNOWN_OWNED_RULE")
                try:
                    port = int(match[4]) if match[4].isdigit() else socket.getservbyname(match[4], "tcp")
                    end = int(match[5]) if match[5] else port
                    ipaddress.IPv4Address(match[2])
                    ipaddress.IPv4Address(match[3])
                except (OSError, ValueError) as exc:
                    raise Rejected("UNKNOWN_OWNED_RULE") from exc
                require(1 <= port <= end <= 65535, "UNKNOWN_OWNED_RULE")
                rows.append((match[1], match[2], match[3], port, end))
            require(len(rows) <= 129 and len({row[:3] for row in rows}) == 1,
                    "UNKNOWN_OWNED_RULE")
            interface, peer, local = rows[0][:3]
            scope = {"interface": interface, "peer": peer, "local": local, "port": rows[0][3]}
            if len(rows) > 1 or rows[0][3] != rows[0][4]:
                scope["port"] = None
                scope["ranges"] = [[row[3], row[4]] for row in rows]
                inbound_ranges(scope)
            result[child] = {"handle": handle, "scope": scope}
        return result

    def remove(self, command, scope):
        existing = self.inventory().get(command)
        if existing is None:
            return
        require(existing["scope"] == scope, "RULE_OWNERSHIP_UNVERIFIED")
        self.run(["/sbin/pfctl", "-a", self.handle(command), "-f", "-"], "")

    def close(self):
        pass


class WFP:
    """复用 P1 的已审查 ABI；P5 用独立非持久子层，恢复器可在 owner 崩溃后删除。

    flags=0 的对象不跨 BFE/主机重启持久化；正常进程退出仍由账本恢复器清理。
    新实现须在目标 Windows 独立验收，不能沿用 P1 动态会话的通过结论。
    """
    def __init__(self, executor_id, interface):
        from scripts.p1 import wfp_native as native
        require(os.name == "nt", "PLATFORM_UNSUPPORTED")
        self.n = native
        self.engine = native.Engine(dynamic=False)
        self.uuid = uuid.uuid5(uuid.NAMESPACE_URL, "hostguard-p5:" + executor_id)
        self.sublayer = native.GUID.parse(str(self.uuid))
        self.prefix = "HostGuard.P5." + executor_id + "."
        self.interface = interface
        dll = self.engine.dll
        dll.FwpmSubLayerDeleteByKey0.argtypes = [native.P, C.POINTER(native.GUID)]
        dll.FwpmSubLayerDeleteByKey0.restype = native.U32

    def handle(self, command):
        return "wfp:" + str(uuid.UUID(command))

    def preflight(self):
        self._rows()

    def _rows(self):
        n, dll, handle = self.n, self.engine.dll, self.engine.handle
        enum = n.P()
        n.check(dll.FwpmFilterCreateEnumHandle0(handle, None, C.byref(enum)))
        rows = []
        try:
            while True:
                count, ptr = n.U32(), n.P()
                n.check(dll.FwpmFilterEnum0(handle, enum, 256, C.byref(ptr), C.byref(count)))
                try:
                    values = C.cast(ptr, C.POINTER(C.POINTER(n.Filter)))
                    for i in range(count.value):
                        f = values[i].contents
                        name = f.display.name or ""
                        if bytes(f.sublayer) != bytes(self.sublayer) and not name.startswith(self.prefix):
                            continue
                        require(bytes(f.sublayer) == bytes(self.sublayer) and name.startswith(self.prefix) and
                                f.flags == 0 and f.action.type == 0x1001 and f.count == 5,
                                "UNKNOWN_OWNED_RULE")
                        command = name[len(self.prefix):]
                        require(str(uuid.UUID(command)) == command, "UNKNOWN_OWNED_RULE")
                        expected = list(n.CONDITIONS) + ["4cd62a49-59c3-4969-b7f3-bda5d32890a4"]  # IP_LOCAL_INTERFACE
                        types, members = (3, 3, 1, 2, 4), ("uint32", "uint32", "uint8", "uint16", "pointer")
                        decoded = []
                        for j in range(5):
                            c = f.conditions[j]
                            require(str(c.key) == expected[j] and c.match == 0 and c.value.type == types[j],
                                    "UNKNOWN_OWNED_RULE")
                            value = getattr(c.value.value, members[j])
                            decoded.append(C.cast(value, C.POINTER(n.U64)).contents.value if j == 4 else value)
                        require(decoded[2] == 6 and decoded[4] == self._luid(), "UNKNOWN_OWNED_RULE")
                        require(str(f.key) == str(uuid.uuid5(self.uuid, command + ":" + str(f.layer))),
                                "RULE_OWNERSHIP_UNVERIFIED")
                        rows.append({"command": command, "id": f.id, "layer": str(f.layer),
                                     "scope": {"local": str(ipaddress.IPv4Address(decoded[0])),
                                               "peer": str(ipaddress.IPv4Address(decoded[1])),
                                               "port": decoded[3], "interface": self.interface}})
                finally:
                    if ptr:
                        dll.FwpmFreeMemory0(C.byref(ptr))
                if count.value < 256:
                    return rows
        finally:
            n.check(dll.FwpmFilterDestroyEnumHandle0(handle, enum))

    def _luid(self):
        n = self.n
        iphelper = C.WinDLL("iphlpapi.dll", use_last_error=True)
        convert = iphelper.ConvertInterfaceAliasToLuid
        convert.argtypes = [C.c_wchar_p, C.POINTER(n.U64)]
        convert.restype = n.U32
        luid = n.U64()
        n.check(convert(self.interface, C.byref(luid)))
        return luid.value

    def inventory(self):
        groups = {}
        for row in self._rows():
            groups.setdefault(row["command"], []).append(row)
        result = {}
        for command, rows in groups.items():
            require(len(rows) == 2 and {r["layer"] for r in rows} == set(self.n.LAYERS) and
                    rows[0]["scope"] == rows[1]["scope"], "WFP_PARTIAL_RULE_SET")
            result[command] = {"handle": self.handle(command), "scope": rows[0]["scope"]}
        return result

    def install(self, command, scope, apply_by):
        n, dll, handle = self.n, self.engine.dll, self.engine.handle
        require(scope["interface"] == self.interface and command not in self.inventory(), "SCOPE_DENIED")
        values = (int(ipaddress.IPv4Address(scope["local"])), int(ipaddress.IPv4Address(scope["peer"])),
                  6, scope["port"])
        conditions = (n.Condition * 5)()
        for i, (kind, member) in enumerate(zip((3, 3, 1, 2), ("uint32", "uint32", "uint8", "uint16"))):
            conditions[i].key = n.GUID.parse(n.CONDITIONS[i])
            conditions[i].value.type = kind
            setattr(conditions[i].value.value, member, values[i])
        luid = n.U64(self._luid())
        conditions[4].key = n.GUID.parse("4cd62a49-59c3-4969-b7f3-bda5d32890a4")
        conditions[4].value.type = 4
        conditions[4].value.value.pointer = C.cast(C.pointer(luid), n.P)
        n.check(dll.FwpmTransactionBegin0(handle, 0))
        try:
            ptr = n.P()
            code = dll.FwpmSubLayerGetByKey0(handle, C.byref(self.sublayer), C.byref(ptr))
            if code == n.SUBLAYER_NOT_FOUND:
                sub = n.Sublayer()
                sub.key, sub.display, sub.weight = self.sublayer, n.Display(self.prefix + "Sublayer", None), 0x7000
                n.check(dll.FwpmSubLayerAdd0(handle, C.byref(sub), None))
            else:
                n.check(code)
                try:
                    sub = C.cast(ptr, C.POINTER(n.Sublayer)).contents
                    require(sub.display.name == self.prefix + "Sublayer" and sub.flags == 0,
                            "RULE_OWNERSHIP_UNVERIFIED")
                finally:
                    dll.FwpmFreeMemory0(C.byref(ptr))
            for layer in n.LAYERS:
                f = n.Filter()
                f.key, f.layer, f.sublayer = n.GUID.parse(str(uuid.uuid5(self.uuid, command + ":" + layer))), n.GUID.parse(layer), self.sublayer
                f.display, f.count, f.conditions = n.Display(self.prefix + command, None), 5, conditions
                f.weight.type, f.weight.value.uint8, f.action.type = 1, 15, 0x1001
                n.check(dll.FwpmFilterAdd0(handle, C.byref(f), None, C.byref(n.U64())))
            require(time.time() <= apply_by, "COMMAND_EXPIRED")
            n.check(dll.FwpmTransactionCommit0(handle))
        except BaseException:
            dll.FwpmTransactionAbort0(handle)
            raise

    def remove(self, command, scope):
        n, dll, handle = self.n, self.engine.dll, self.engine.handle
        rows = [r for r in self._rows() if r["command"] == command]
        require(all(row["scope"] == scope for row in rows), "RULE_OWNERSHIP_UNVERIFIED")
        n.check(dll.FwpmTransactionBegin0(handle, 0))
        try:
            for row in rows:
                n.check(dll.FwpmFilterDeleteById0(handle, row["id"]))
            n.check(dll.FwpmTransactionCommit0(handle))
        except BaseException:
            dll.FwpmTransactionAbort0(handle)
            raise

    def close(self):
        self.engine.close()
