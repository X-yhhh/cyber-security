"""Windows x64 WFP 最小绑定，仅供 P1 独立动态会话探针。

结构和 GUID 按 Microsoft WinSDK fwpmtypes.h/fwptypes.h/fwpmu.h；不安装驱动，
不创建 persistent/boot-time 对象。只提供 IPv4/TCP 入站对端+本机服务阻断。
"""
import ctypes as C
import ipaddress
import os
import uuid

U8, U16, U32, U64 = C.c_uint8, C.c_uint16, C.c_uint32, C.c_uint64
P = C.c_void_p


class GUID(C.Structure):
    _fields_ = [('data1', U32), ('data2', U16), ('data3', U16), ('data4', U8 * 8)]

    @classmethod
    def parse(cls, value):
        return cls.from_buffer_copy(uuid.UUID(value).bytes_le)

    def __str__(self):
        return str(uuid.UUID(bytes_le=bytes(self)))


class Display(C.Structure):
    _fields_ = [('name', C.c_wchar_p), ('description', C.c_wchar_p)]


class Blob(C.Structure):
    _fields_ = [('size', U32), ('data', P)]


class ValueUnion(C.Union):
    _fields_ = [('uint8', U8), ('uint16', U16), ('uint32', U32), ('pointer', P)]


class Value(C.Structure):
    _fields_ = [('type', U32), ('value', ValueUnion)]


class Session(C.Structure):
    _fields_ = [('key', GUID), ('display', Display), ('flags', U32), ('timeout', U32),
                ('pid', U32), ('sid', P), ('username', C.c_wchar_p), ('kernel', U32)]


class Sublayer(C.Structure):
    _fields_ = [('key', GUID), ('display', Display), ('flags', U32), ('provider', P),
                ('data', Blob), ('weight', U16)]


class Condition(C.Structure):
    _fields_ = [('key', GUID), ('match', U32), ('value', Value)]


class Action(C.Structure):
    _fields_ = [('type', U32), ('key', GUID)]


class Context(C.Union):
    _fields_ = [('raw', U64), ('key', GUID)]


class Filter(C.Structure):
    _fields_ = [('key', GUID), ('display', Display), ('flags', U32), ('provider', P),
                ('data', Blob), ('layer', GUID), ('sublayer', GUID), ('weight', Value),
                ('count', U32), ('conditions', C.POINTER(Condition)), ('action', Action),
                ('context', Context), ('reserved', P), ('id', U64), ('effectiveWeight', Value)]


SUBLAYER = GUID.parse('8c1b7a6d-6f6b-4387-9c7f-1c0cb4d6cf64')
LAYERS = ('5926dfc8-e3cf-4426-a283-dc393f5d0f9d',  # INBOUND_TRANSPORT_V4
          'e1cd9fe7-f4b5-4273-96c0-592e487b8650')  # ALE_AUTH_RECV_ACCEPT_V4
CONDITIONS = ('d9ee00de-c1ef-4617-bfe3-ffd8f5a08957', 'b235ae9a-1d64-49b8-a44c-5ff3d9095045',
              '3971ef2b-623e-4f9a-8cb1-6e79b806b9a7', '0c1ba1af-5765-453f-af22-a8f791ac775b')
PREFIX = 'HostGuard.P1.WFP.'
FILTER_NOT_FOUND, SUBLAYER_NOT_FOUND = 0x80320003, 0x80320007


def check(code):
    if code:
        raise OSError(f'WFP_ERROR_0x{code:08x}')


class Engine:
    """句柄只归当前进程；观察者用只读会话，动态所有者退出时 BFE 自动回收。"""
    def __init__(self, dynamic=False):
        if os.name != 'nt' or C.sizeof(P) != 8:
            raise OSError('WINDOWS_X64_REQUIRED')
        expected = {Session: 72, Sublayer: 72, Condition: 40, Filter: 200}
        if any(C.sizeof(k) != v for k, v in expected.items()):
            raise OSError('WFP_ABI_MISMATCH')
        self.dll = C.WinDLL('fwpuclnt.dll', use_last_error=True)
        signatures = {
            'FwpmEngineOpen0': [C.c_wchar_p, U32, P, C.POINTER(Session), C.POINTER(P)],
            'FwpmEngineClose0': [P], 'FwpmFreeMemory0': [C.POINTER(P)],
            'FwpmSubLayerAdd0': [P, C.POINTER(Sublayer), P],
            'FwpmSubLayerGetByKey0': [P, C.POINTER(GUID), C.POINTER(P)],
            'FwpmFilterAdd0': [P, C.POINTER(Filter), P, C.POINTER(U64)],
            'FwpmFilterDeleteById0': [P, U64],
            'FwpmFilterGetById0': [P, U64, C.POINTER(P)],
            'FwpmTransactionBegin0': [P, U32], 'FwpmTransactionCommit0': [P],
            'FwpmTransactionAbort0': [P],
            'FwpmFilterCreateEnumHandle0': [P, P, C.POINTER(P)],
            'FwpmFilterEnum0': [P, P, U32, C.POINTER(P), C.POINTER(U32)],
            'FwpmFilterDestroyEnumHandle0': [P, P],
        }
        for name, args in signatures.items():
            fn = getattr(self.dll, name); fn.argtypes = args
            fn.restype = None if name == 'FwpmFreeMemory0' else U32
        session = Session(); session.flags = 1 if dynamic else 0; session.timeout = 250
        session.display = Display(PREFIX + ('Owner' if dynamic else 'Observer'), 'P1 bounded probe')
        self.handle = P()
        check(self.dll.FwpmEngineOpen0(None, 10, None, C.byref(session), C.byref(self.handle)))
        self.dynamic = dynamic

    def close(self):
        if self.handle:
            check(self.dll.FwpmEngineClose0(self.handle)); self.handle = P()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def exists(self, ident):
        ptr = P(); code = self.dll.FwpmFilterGetById0(self.handle, ident, C.byref(ptr))
        if code == FILTER_NOT_FOUND:
            return False
        check(code)
        self.dll.FwpmFreeMemory0(C.byref(ptr))
        return True

    def inventory(self):
        """只读枚举整个项目子层及命名空间；任何残留均关闭新命令门禁，不删未知归属。"""
        ptr = P(); code = self.dll.FwpmSubLayerGetByKey0(self.handle, C.byref(SUBLAYER), C.byref(ptr))
        present = code != SUBLAYER_NOT_FOUND
        if present:
            check(code); self.dll.FwpmFreeMemory0(C.byref(ptr))
        enum = P(); check(self.dll.FwpmFilterCreateEnumHandle0(self.handle, None, C.byref(enum)))
        rows = []
        try:
            while True:
                count = U32(); ptr = P()
                check(self.dll.FwpmFilterEnum0(self.handle, enum, 256, C.byref(ptr), C.byref(count)))
                try:
                    arr = C.cast(ptr, C.POINTER(C.POINTER(Filter)))
                    for i in range(count.value):
                        f = arr[i].contents
                        if bytes(f.sublayer) == bytes(SUBLAYER) or (f.display.name or '').startswith(PREFIX):
                            rows.append({'id': f.id, 'flags': f.flags, 'layer': str(f.layer)})
                finally:
                    if ptr:
                        self.dll.FwpmFreeMemory0(C.byref(ptr))
                if count.value < 256:
                    break
        finally:
            check(self.dll.FwpmFilterDestroyEnumHandle0(self.handle, enum))
        return {'sublayerPresent': present, 'filters': rows}

    def install(self, local, peer, port, action_id):
        """同一事务装入两个动态过滤器；字段为 host byte order 精确相等，不接管默认策略。"""
        if not self.dynamic:
            raise ValueError('DYNAMIC_OWNER_REQUIRED')
        values = (int(ipaddress.IPv4Address(local)), int(ipaddress.IPv4Address(peer)), 6, port)
        types = (3, 3, 1, 2)  # FWP_UINT32, UINT32, UINT8, UINT16
        members = ('uint32', 'uint32', 'uint8', 'uint16')
        conditions = (Condition * 4)()
        for i in range(4):
            conditions[i].key = GUID.parse(CONDITIONS[i]); conditions[i].value.type = types[i]
            setattr(conditions[i].value.value, members[i], values[i])
        check(self.dll.FwpmTransactionBegin0(self.handle, 0))
        ids = []
        try:
            sub = Sublayer(); sub.key = SUBLAYER; sub.display = Display(PREFIX + 'Sublayer', None)
            sub.weight = 0x7000
            check(self.dll.FwpmSubLayerAdd0(self.handle, C.byref(sub), None))
            for layer in LAYERS:
                f = Filter(); f.key = GUID.parse(str(uuid.uuid4())); f.layer = GUID.parse(layer)
                f.sublayer = SUBLAYER; f.display = Display(PREFIX + action_id, None)
                f.weight.type = 1; f.weight.value.uint8 = 15
                f.count = 4; f.conditions = conditions; f.action.type = 0x1001  # terminating BLOCK
                ident = U64()
                check(self.dll.FwpmFilterAdd0(self.handle, C.byref(f), None, C.byref(ident)))
                ids.append(ident.value)
            check(self.dll.FwpmTransactionCommit0(self.handle))
        except BaseException:
            self.dll.FwpmTransactionAbort0(self.handle)
            raise
        return ids

    def remove(self, ids):
        for ident in ids:
            code = self.dll.FwpmFilterDeleteById0(self.handle, ident)
            if code != FILTER_NOT_FOUND:
                check(code)
