#!/usr/bin/env python3
"""一次重启验收的只读观察器；不安装/恢复阻断，不接受新命令，不改变系统策略。

watch 在租约期间逐次读取实际规则；boot 在启动时先记录残留再启动有界canary。
启动观察任务的存在不代表严格时效通过，必须有到期前删除观察和新boot清零证据。
"""
import argparse
import ctypes
import datetime as dt
import json
import os
from pathlib import Path
import socket
import subprocess
import time

from wfp_native import Engine
from wfp_probe import audit, boot_id, write_new, assert_isolation, validate_scope


def initial_inventory(base, attempts=30):
    """BFE 暂未就绪可重试；异常不换成空枚举，首次成功/全部失败均留证。

    日志由外层启动器在任何 Python 导入之前创建。ready 只能在真实清零枚举后发布。
    """
    for attempt in range(attempts):
        try:
            with Engine() as observer:
                inventory=observer.inventory()
            # 先同步保存内核枚举；身份/网络元数据失败不能抹去已经取得的清零证据。
            audit(base,'boot-observer','inventory_observed',attempt=attempt,inventory=inventory)
            return inventory
        except OSError as error:
            audit(base,'boot-observer','bfe_unavailable',attempt=attempt,winerror=getattr(error,'winerror',None))
            if attempt+1==attempts:raise
            time.sleep(.2)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode',choices=('watch','boot','preflight'));p.add_argument('--case-dir',type=Path,required=True)
    p.add_argument('--manifest',type=Path);a=p.parse_args();base=a.case_dir
    if a.mode=='boot' and a.manifest is None:p.error('boot requires manifest')
    if a.mode=='preflight':
        inventory=initial_inventory(base)
        result={'inventory':inventory,'bootId':boot_id(),'observedUtc':dt.datetime.now(dt.timezone.utc).isoformat(),
                'ready':inventory=={'sublayerPresent':False,'filters':[]},'newCommandsAccepted':False}
        write_new(base/'preflight.json',result)
        if not result['ready']:raise RuntimeError('RECOVERY_INCOMPLETE')
        return
    if a.mode=='watch':
        # 观察器在普通应用之后退出，尽力记录所有者终止后的真实BFE状态；无证据不判通过。
        kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        kernel.SetProcessShutdownParameters.argtypes=[ctypes.c_uint32,ctypes.c_uint32]
        kernel.SetProcessShutdownParameters.restype=ctypes.c_int
        if not kernel.SetProcessShutdownParameters(0x100,0):
            raise ctypes.WinError(ctypes.get_last_error())
        audit(base,'reboot-watch','watch_ready',pid=os.getpid(),bootId=boot_id())
        with Engine() as observer:
            end=time.monotonic()+100;previous=None
            while time.monotonic()<end:
                applied=base/'applied.json'
                if applied.exists():
                    lease=json.loads(applied.read_text());ids=lease['filterIds']
                    try:
                        present=[i for i in ids if observer.exists(i)]
                    except OSError as error:
                        audit(base,'reboot-watch','observation_unavailable',winerror=getattr(error,'winerror',None))
                        return
                    state=len(present)
                    if state!=previous:
                        audit(base,'reboot-watch','actual_filters',remaining=state,
                              deadlineMonotonic=lease['deadlineMonotonic'],
                              delaySeconds=time.monotonic()-lease['deadlineMonotonic'])
                        previous=state
                    if state==0:
                        return
                time.sleep(0.01)
    else:
        audit(base,'boot-observer','started',pid=os.getpid(),bootId=boot_id())
        inventory=initial_inventory(base)
        result={'observedUtc':dt.datetime.now(dt.timezone.utc).isoformat(),'bootId':boot_id(),
                'inventory':inventory,'newCommandsAccepted':False,'canaryPids':[]}
        # 即便网络尚未就绪或隔离检查失败，也先保留启动初次枚举，绝不靠重新清理制造空结果。
        write_new(base/'boot-inventory.json',result)
        if inventory!={'sublayerPresent':False,'filters':[]}:
            result['status']='recovery_incomplete'
        else:
            try:
                m=json.loads(a.manifest.read_text(encoding='utf-8-sig'));validate_scope(m,time.time())
                result['isolation']=assert_isolation(m)
                # 覆盖网接口可能晚于BFE启动，只等待本机绑定就绪，最多60秒，不延长授权。
                end=time.monotonic()+60
                while True:
                    try:
                        with socket.socket() as check:
                            check.bind((m['local'],0))
                        break
                    except OSError:
                        if time.monotonic()>=end:raise RuntimeError('LOCAL_INTERFACE_UNAVAILABLE')
                        time.sleep(0.2)
                validate_scope(m,time.time())
                # 只启动既有普通回显，恢复流量核验；不会重新安装旧租约或动态阻断。
                for port in (m['port'],m['controlPort']):
                    proc=subprocess.Popen([m['binary'],'--listen',f'{m["local"]}:{port}',
                                           '--peer',m['peer'],'--duration','180s'],
                                          stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                                          creationflags=0x08000000)
                    result['canaryPids'].append(proc.pid)
                result['status']='reconciled_no_commands_accepted'
            except Exception as error:
                result['status']='reconciled_canary_unavailable'
                result['error']=type(error).__name__
        write_new(base/'boot-observation.json',result)
        audit(base,'boot-observer','complete',status=result['status'],remaining=len(inventory['filters']))


if __name__=='__main__':
    main()
