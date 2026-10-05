#!/usr/bin/env python3
"""P1 SCM 生命周期入口：STOP/PRESHUTDOWN 立即停止新命令并独立核验动态会话清零。

只供已登记的一次性 canary 探针；服务安装/启动不等于真实重启时效通过。
使用既有获准解释器，不安装驱动、不改变系统安全策略，也不接受网络命令。
"""
import argparse
import ctypes as C
from pathlib import Path
import threading
import sys
import traceback


def serve(name, manifest, base):
    from wfp_probe import audit, supervise
    adv=C.WinDLL('advapi32',use_last_error=True)
    DWORD=C.c_uint32
    class Status(C.Structure):
        _fields_=[(k,DWORD) for k in ('type','state','accepted','win32Exit','serviceExit','checkpoint','waitHint')]
    Main=C.WINFUNCTYPE(None,DWORD,C.POINTER(C.c_wchar_p))
    Handler=C.WINFUNCTYPE(DWORD,DWORD,DWORD,C.c_void_p,C.c_void_p)
    class Entry(C.Structure):
        _fields_=[('name',C.c_wchar_p),('main',Main)]
    adv.RegisterServiceCtrlHandlerExW.argtypes=[C.c_wchar_p,Handler,C.c_void_p]
    adv.RegisterServiceCtrlHandlerExW.restype=C.c_void_p
    adv.SetServiceStatus.argtypes=[C.c_void_p,C.POINTER(Status)];adv.SetServiceStatus.restype=C.c_int
    adv.StartServiceCtrlDispatcherW.argtypes=[C.POINTER(Entry)];adv.StartServiceCtrlDispatcherW.restype=C.c_int
    stop=threading.Event();handle=None
    lifecycle=base.parent
    lifecycle.mkdir(parents=True,exist_ok=True)
    received=[];outcome={'successful':False}
    def report(state,accepted=0,code=0):
        status=Status(0x10,state,accepted,code,0,1 if state==3 else 0,5000 if state==3 else 0)
        if not adv.SetServiceStatus(handle,C.byref(status)):raise C.WinError(C.get_last_error())
    @Handler
    def control(code,event,data,context):
        if code in (1,5,15):
            # STOP=1、SHUTDOWN=5、PRESHUTDOWN=15；回调只发信号，清理在恢复循环执行。
            received.append(code)
            audit(lifecycle,'scm','control_received',control=code,newCommandsAccepted=False)
            stop.set();report(3)
        return 0
    @Main
    def main(argc,argv):
        nonlocal handle
        handle=adv.RegisterServiceCtrlHandlerExW(name,control,None)
        if not handle:return
        try:
            audit(lifecycle,'scm','dispatcher_connected',service=name)
            report(4,0x105)
            result=supervise(manifest,base,'none',stop)
            # 空枚举不能掩盖子进程初始化失败；SCM 成功须绑定真实 ready 和恢复结果。
            clean=result['inventory']=={'sublayerPresent':False,'filters':[]}
            passed=clean and result['ownerReady'] and result['ownerExitCode']==0
            outcome['successful']=passed
            audit(lifecycle,'scm','service_stopped',controls=received,clean=clean,
                  ownerReady=result['ownerReady'],successful=passed)
            report(1,code=0 if passed else 1)
        except BaseException:
            audit(lifecycle,'scm','service_failed',traceback=traceback.format_exc())
            report(1,code=1)
    table=(Entry*2)();table[0]=Entry(name,main)
    if not adv.StartServiceCtrlDispatcherW(table):raise C.WinError(C.get_last_error())
    # SCM 服务退出失败必须传播到外层启动器，不能留下互相矛盾的 ExitCode=0。
    if not outcome['successful']:raise RuntimeError('SCM_EXECUTION_FAILED')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--name',required=True);p.add_argument('--manifest',type=Path,required=True);p.add_argument('--case-dir',type=Path,required=True)
    a=p.parse_args()
    if not a.name.startswith('HostGuard.P1.') or len(a.name)>80:p.error('专用服务命名空间无效')
    if not a.manifest.is_absolute() or not a.case_dir.is_absolute():p.error('须使用受控绝对路径')
    serve(a.name,a.manifest,a.case_dir)
