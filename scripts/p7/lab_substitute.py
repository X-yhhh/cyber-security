#!/usr/bin/env python3
"""隔离 synthetic 会话的执行器替身：持续心跳、领取和核对空规则。

只使用内存防火墙。synthetic 会话的服务端执行门必须拒绝所有命令；
若实际领取非空命令则立即失败，不能用本工具声称完成真实封禁。
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import signal
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT/'scripts/p5'))
from executor.common import canonical, ident, require
from executor.transport import HTTPS
from scripts.p5.joint_executor import MemoryFirewall
from scripts.p7.lab_run import digest, stamp


def run(directory):
    config=json.loads((directory/'private/substitute.json').read_bytes())
    http=HTTPS(config['baseUrl'],config['caFile'],config['certificateFile'],config['keyFile'],local=True)
    token=(directory/'private/executor.credential').read_text().strip()
    firewall=MemoryFirewall()
    stopped=False
    def stop(*_):
        nonlocal stopped
        stopped=True
    signal.signal(signal.SIGTERM,stop)
    signal.signal(signal.SIGINT,stop)
    def post(operation,body):
        result=http.post('/api/v2/machine/executors/'+config['executorId']+'/'+operation,body,
                         {'Authorization':'Bearer '+token,'Idempotency-Key':ident()})
        require(result.get('error') is None and isinstance(result.get('data'),dict),'LAB_SUBSTITUTE_RESPONSE_INVALID')
        return result['data']
    with (directory/'substitute.jsonl').open('x') as output:
        def record(row):
            output.write(canonical(dict(at=stamp(),**row)).decode()+'\n');output.flush()
        while not stopped:
            try:
                owned=firewall.inventory()
                post('heartbeats',dict(bootId=config['bootId'],adapterVersion='hostguard-executor/1',
                     capabilityHash=config['capabilityHash'],pendingRecovery=False,activeRuleCount=len(owned),clockSkewMs=0))
                normalized=dict(digestVersion='guard-state/1',assetId=config['assetId'],executorId=config['executorId'],
                     executorBootId=config['bootId'],rules=[],pendingRevocations=[])
                rec=post('reconciliations',dict(executorBootId=config['bootId'],observedAt=stamp(),digestVersion='guard-state/1',
                     stateDigest=digest(normalized),ownedRules=[],pendingRevocations=[],recoveryErrors=[]))
                claims=post('command-claims',dict(bootId=config['bootId'],capabilityHash=config['capabilityHash'],maxItems=10,waitSeconds=0))
                require(claims.get('commands')==[] and claims.get('revocations')==[],'LAB_SYNTHETIC_COMMAND_UNEXPECTED')
                record(dict(kind='observation',commandIds=[],installedRules=list(owned),reconciliation=rec))
            except Exception as error:
                record(dict(kind='failure',code=str(error) if isinstance(error,ValueError) else type(error).__name__))
                raise
            for _ in range(20):
                if stopped:break
                time.sleep(.1)
        record(dict(kind='stopped',installedRules=list(firewall.inventory())))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--directory',type=Path,required=True)
    run(parser.parse_args().directory.resolve())
