#!/usr/bin/env python3
"""SCM/计划任务共同外层入口；先创建诊断，再导入 WFP 模块。

由既有获准 Python 绝对路径直接启动，不改变 PowerShell 执行策略或 SAC。
每次启动独立输出目录，保留身份类别、cwd、版本、异常栈与退出码。
"""
import argparse
import datetime
import json
import os
from pathlib import Path
import sys
import traceback
import uuid


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--module-dir',type=Path,required=True);p.add_argument('--logs',type=Path,required=True)
    p.add_argument('--mode',choices=['preflight','boot','service'],default='preflight')
    p.add_argument('--manifest',type=Path);p.add_argument('--service-name')
    p.add_argument('--case-dir',type=Path)
    a=p.parse_args()
    if not a.logs.is_absolute() or not a.module_dir.is_absolute():p.error('须使用绝对路径')
    base=a.logs/(datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+uuid.uuid4().hex)
    base.mkdir()
    def record(event,**fields):
        with (base/'bootstrap.jsonl').open('a',encoding='utf-8') as f:
            f.write(json.dumps(dict(event=event,utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),**fields))+'\n')
            f.flush();os.fsync(f.fileno())
    record('launcher_entered',python=sys.version,executable=sys.executable,cwd=os.getcwd(),pid=os.getpid(),mode=a.mode)
    code=1
    try:
        if not a.module_dir.is_dir():raise ValueError('MODULE_DIRECTORY_UNAVAILABLE')
        os.chdir(a.module_dir);sys.path.insert(0,str(a.module_dir))
        import ctypes
        import ctypes.wintypes as W
        adv=ctypes.WinDLL('advapi32',use_last_error=True)
        adv.GetUserNameW.argtypes=[W.LPWSTR,ctypes.POINTER(W.DWORD)];adv.GetUserNameW.restype=W.BOOL
        name=ctypes.create_unicode_buffer(256);size=W.DWORD(len(name))
        if not adv.GetUserNameW(name,ctypes.byref(size)):raise ctypes.WinError(ctypes.get_last_error())
        record('identity_checked',systemIdentity=name.value.upper()=='SYSTEM')
        import wfp_reboot_observer as observer
        from wfp_probe import boot_id,write_new,utc
        inventory=observer.initial_inventory(base)
        write_new(base/'preflight.json',dict(inventory=inventory,bootId=boot_id(),observedUtc=utc(),
            ready=inventory=={'sublayerPresent':False,'filters':[]},newCommandsAccepted=False))
        if inventory!={'sublayerPresent':False,'filters':[]}:raise RuntimeError('RECOVERY_INCOMPLETE')
        if a.mode=='boot':
            if a.manifest is None:raise ValueError('MANIFEST_REQUIRED')
            sys.argv=[str(a.module_dir/'wfp_reboot_observer.py'),'boot','--case-dir',str(base),'--manifest',str(a.manifest)]
            observer.main()
        elif a.mode=='service':
            if a.manifest is None or not a.service_name or not a.service_name.startswith('HostGuard.P1.'):
                raise ValueError('SERVICE_SCOPE_REQUIRED')
            from wfp_service import serve
            if a.case_dir is not None and not a.case_dir.is_absolute():
                raise ValueError('ABSOLUTE_CASE_DIRECTORY_REQUIRED')
            serve(a.service_name,a.manifest,a.case_dir or base/'case')
        code=0
    except BaseException as e:
        record('launcher_failed',type=type(e).__name__,traceback=traceback.format_exc())
    record('launcher_exited',exitCode=code)
    return code


if __name__=='__main__':raise SystemExit(main())
