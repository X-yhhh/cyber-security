"""候选策略 v2 的真实目标累计阻断账本；不接收 boot/epoch 作为预算身份。

研究目标映射由数据旁路冻结，不进入模型。只在预登记且完整可观测的健康冷却
窗口后开启新预算轮次；毫秒间隙、低分和证据身份改变不会恢复额度。
"""
from dataclasses import dataclass
import math


@dataclass
class Account:
    blocked_ms: float = 0
    last_end: float = -math.inf
    last_evidence: float = -math.inf
    generation: int = 0


class TargetBudget:
    def __init__(self, cooldown_seconds=120):
        if cooldown_seconds != 120:
            raise ValueError('首版冷却期限固定120秒，不得借调参重置额度')
        self.cooldown_ms = cooldown_seconds * 1000
        self.accounts = {}

    def observe(self, target, at, attack_evidence, healthy_since=None):
        """healthy_since 须来自冻结捕获轨迹，不能由单条低分观察推断全程健康。"""
        if not isinstance(target, str) or not target:
            raise ValueError('缺少稳定真实目标映射，拒绝候选动作')
        if not math.isfinite(at) or healthy_since is not None and (not math.isfinite(healthy_since) or healthy_since > at):
            raise ValueError('目标预算时刻/健康旁路无效')
        a=self.accounts.setdefault(target, Account())
        if (a.blocked_ms and healthy_since is not None and healthy_since <= a.last_end
                and at-max(a.last_end,a.last_evidence) >= self.cooldown_ms
                and not attack_evidence):
            a.blocked_ms=0; a.generation+=1
        if attack_evidence:
            a.last_evidence=at
        return a

    def proposed_ms(self, target, start, end):
        if not math.isfinite(start) or not math.isfinite(end) or end <= start:
            raise ValueError('租约区间无效')
        a=self.accounts[target]
        # 重叠部分只记一次，间隙不抹去已发生阻断。
        return a.blocked_ms + max(0, end-max(start,a.last_end))

    def commit(self, target, start, end):
        a=self.accounts[target]
        total=self.proposed_ms(target,start,end)
        if end<=start or total>120000:
            raise ValueError('累计自动阻断超过120秒，转人工')
        a.blocked_ms=total;a.last_end=max(a.last_end,end)


def interval_overlap(start, end, other_start, other_end):
    """半开租约区间；连接在整个存活区间内相交即算附带误伤。"""
    return start < other_end and other_start < end


def evaluate_timeline(episodes, actions, benign_connections, target_ids):
    """分母来自冻结标签时间线；无观察的攻击桶也保留，未知标签不转正常。

    同时报告首次响应、桶内覆盖秒数和等待人工时段。这里只是候选时间区间，
    不声称 OS 生效；真实生效/撤销时间由 P5/P7 回执替换。
    """
    result=[]
    for ep in episodes:
        if ep['endMs'] <= ep['startMs']:
            raise ValueError('攻击时间线非法')
        spans=[(max(a['startMs'],ep['startMs']),min(a['endMs'],ep['endMs'])) for a in actions
               if a['targetId']==ep['targetId'] and interval_overlap(a['startMs'],a['endMs'],ep['startMs'],ep['endMs'])]
        spans.sort();merged=[]
        for start,end in spans:
            if merged and start<=merged[-1][1]:merged[-1]=(merged[-1][0],max(end,merged[-1][1]))
            else:merged.append((start,end))
        blocked=sum(e-s for s,e in merged)
        first=merged[0][0] if merged else None
        for bucket in range(math.floor(ep['startMs']/30000),math.ceil(ep['endMs']/30000)):
            start=max(ep['startMs'],bucket*30000);end=min(ep['endMs'],(bucket+1)*30000)
            covered=sum(max(0,min(end,e)-max(start,s)) for s,e in merged)
            result.append(dict(episodeId=ep['episodeId'],targetId=ep['targetId'],bucket=bucket,
                startMs=start,endMs=end,blockedMs=covered,hasObservation=ep.get('hasObservation',False),
                label=ep.get('label'),firstResponseDelayMs=None if first is None else max(0,first-ep['startMs']),
                episodeBlockedMs=blocked,episodeUnblockedMs=ep['endMs']-ep['startMs']-blocked))
    collateral=[]
    for b in benign_connections:
        for a in actions:
            if b['targetId']==a['targetId'] and interval_overlap(b['startMs'],b['endMs'],a['startMs'],a['endMs']):
                collateral.append(dict(parentConnectionId=b['parentConnectionId'],actionId=a['actionId']))
    return dict(unit='label_timeline_target_30s_bucket',opportunities=result,collateral=collateral,
                targets=len(set(target_ids)),automaticExecutionSupported=False)
