"""Windows SCM 独立执行/恢复服务入口；停止与关机通知触发清理，不安装服务。"""
import ctypes as C
from pathlib import Path
import sys
import threading
import time

from .__main__ import build, cycle
from .common import Rejected, require
from .transport import ControlPlane


def serve(name, path, role):
    require(sys.platform == "win32" and name in ("HostGuard.P5.Executor", "HostGuard.P5.Recovery") and
            role in ("run", "recover") and Path(path).is_absolute(), "SCM_CONFIGURATION_INVALID")
    adv = C.WinDLL("advapi32", use_last_error=True)
    dword = C.c_uint32

    class Status(C.Structure):
        _fields_ = [(key, dword) for key in ("type", "state", "accepted", "win32Exit", "serviceExit", "checkpoint", "waitHint")]

    main_type = C.WINFUNCTYPE(None, dword, C.POINTER(C.c_wchar_p))
    handler_type = C.WINFUNCTYPE(dword, dword, dword, C.c_void_p, C.c_void_p)

    class Entry(C.Structure):
        _fields_ = [("name", C.c_wchar_p), ("main", main_type)]

    adv.RegisterServiceCtrlHandlerExW.argtypes = [C.c_wchar_p, handler_type, C.c_void_p]
    adv.RegisterServiceCtrlHandlerExW.restype = C.c_void_p
    adv.SetServiceStatus.argtypes = [C.c_void_p, C.POINTER(Status)]
    adv.SetServiceStatus.restype = C.c_int
    adv.StartServiceCtrlDispatcherW.argtypes = [C.POINTER(Entry)]
    adv.StartServiceCtrlDispatcherW.restype = C.c_int
    stop = threading.Event()
    handle, passed = None, False

    def report(state, code=0):
        status = Status(0x10, state, 0x105 if state == 4 else 0, code, 0, 1, 10000)
        require(adv.SetServiceStatus(handle, C.byref(status)), "SCM_STATUS_FAILED")

    @handler_type
    def control(code, *_):
        if code in (1, 5, 15):
            stop.set()
            report(3)
        return 0

    @main_type
    def main(*_):
        nonlocal handle, passed
        handle = adv.RegisterServiceCtrlHandlerExW(name, control, None)
        if not handle:
            return
        engine = None
        try:
            engine = build(path, resolver=role == "run")
            with engine.store.lock(role, blocking=False):
                try:
                    if role == "run":
                        engine.start()
                        client = ControlPlane(engine.config)
                        engine.pulse("executor")
                        deadline = time.monotonic() + 2
                        while not stop.is_set() and not engine.healthy_recovery() and time.monotonic() < deadline:
                            stop.wait(.05)
                    report(4)
                    while not stop.is_set():
                        try:
                            if role == "run":
                                cycle(engine, client)
                            elif engine.store.get("boot"):
                                engine.boot = engine.store.get("boot")
                                engine.pulse("recovery")
                                hb = engine.store.get("executorHeartbeat", {})
                                lost = hb.get("boot") != engine.boot or not 0 <= time.monotonic() - hb.get("at", -100) <= 4
                                engine.recover(force=lost)
                        except Exception as exc:
                            engine.store.audit("service.error", errorCode="SCM_LOOP_FAILED")
                            if isinstance(exc, Rejected) and str(exc) == "CLOCK_UNTRUSTED":
                                engine.stop()
                        stop.wait(.25 if role == "recover" else 1)
                finally:
                    engine.stop()
                passed = True
        except Exception:
            passed = False
        finally:
            if engine:
                engine.adapter.close()
            report(1, 0 if passed else 1)

    table = (Entry * 2)()
    table[0] = Entry(name, main)
    require(adv.StartServiceCtrlDispatcherW(table), "SCM_DISPATCH_FAILED")
    require(passed, "SCM_RECOVERY_UNVERIFIED")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--role", choices=("run", "recover"), required=True)
    args = parser.parse_args()
    serve(args.name, args.config, args.role)
