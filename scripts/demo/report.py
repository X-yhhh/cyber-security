#!/usr/bin/env python3
"""按准确运行目录、资产与段标记汇总事实；不生成或导入模型成绩、G3 资格或发布报告。"""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.demo.common import CLEANUP, instant, load, require, safe_main, write


def summarize(state, facts, worker):
    """命令按 decisionId 关联段内判定；仅 projected 回执证明 applied/expired，未知项从不默认成功。"""
    results, assigned = [], set()
    marks = {r['id']: r for r in (worker or {}).get('scenes', [])}
    for scene in state['scenes']:
        mark = marks.get(scene['id'], {})
        start, end = mark.get('startedAt'), mark.get('endedAt')
        result = {'id': scene['id'], 'expected': scene['expected'], 'family': scene['family'],
                  'startedAt': start, 'endedAt': end, 'firstAlertFamily': None, 'latencyMs': None,
                  'latencyBand': 'missing', 'commands': [], 'budgetEvents': [], 'conclusion': '不符合'}
        if start and end and mark.get('finished'):
            # 接受段结束后 10 秒内的推理完成；场景之间有至少 180 秒间隔，不能跨段挪用。
            ds = [d for d in facts['decisions'] if instant(start) <= instant(d['at']) <= instant(end) + 10]
            alerts = sorted([d for d in ds if d['source'] == 'model' and d['decision'] in ('alert', 'block_candidate')], key=lambda d: instant(d['at']))
            if alerts:
                result['firstAlertFamily'] = alerts[0]['family']
                result['latencyMs'] = round((instant(alerts[0]['at']) - instant(start)) * 1000, 3)
                result['latencyBand'] = 'within' if result['latencyMs'] <= scene['latencyLimitMs'] else 'late'
            ids = {d['id'] for d in ds}
            commands = [c for c in facts['commands'] if c['decisionId'] in ids]
            next_start = min([instant(m['startedAt']) for m in marks.values() if m.get('startedAt') and instant(m['startedAt']) > instant(end)] or [instant(state.get('endedAt') or end)])
            for c in commands:
                assigned.add(c['id'])
                receipts = [r for r in facts['receipts'] if r['commandId'] == c['id'] and r['projected']]
                applied = next((r['at'] for r in receipts if r['status'] == 'applied'), None)
                expired = next((r['at'] for r in receipts if r['status'] == 'expired'), None)
                result['commands'].append({'id': c['id'], 'scope': c['scope'], 'appliedAt': applied, 'expiredAt': expired,
                                           'ttlVerified': bool(applied and expired and c['state'] == 'expired' and
                                               0 < instant(c['blockUntil']) - instant(c['at']) <= 60 and
                                               instant(c['at']) - 1 <= instant(applied) < instant(c['blockUntil']) and
                                               instant(c['blockUntil']) - 1 <= instant(expired) <= min(instant(c['blockUntil']) + 10, next_start))})
                resets = [e for e in facts['budgetEvents'] if e['targetId'] == c['budgetTargetId'] and instant(c['at']) <= instant(e['at']) < next_start and e['kind'] == 'reset']
                result['budgetEvents'] += resets
                result['commands'][-1]['budgetRecovered'] = bool(expired and any(instant(e['at']) >= instant(expired) + 120 for e in resets))
            detected = result['firstAlertFamily'] == scene['family'] and result['latencyBand'] == 'within'
            safe_commands = all(next((d['family'] == scene['family'] and d['source'] == 'model' for d in ds if d['id'] == c['decisionId']), False) for c in commands)
            if scene['id'] == 'S0':
                okay = not any(d['decision'] in ('alert', 'block_candidate') for d in ds) and not commands
            elif scene['id'] == 'S4' or state['mode'] == 'alert-only':
                okay = detected and not commands
            elif scene['id'] == 'S3':
                okay = detected and all(c['scope'] == 'peer_service' and c['ttlVerified'] and c['budgetRecovered'] for c in result['commands'])
            else:
                okay = detected and bool(commands) and all(c['scope'] == scene['expected'] and c['ttlVerified'] and c['budgetRecovered'] for c in result['commands']) and bool(result['budgetEvents'])
            result['conclusion'] = '符合' if okay and safe_commands else '降级' if scene['id'] == 'S3' and not commands and not alerts else '不符合'
        results.append(result)
    cleanup = {k: state.get('cleanup', {}).get(k) is True for k in CLEANUP}
    unexpected = [c['id'] for c in facts['commands'] if c['id'] not in assigned]
    passed = not unexpected and not state.get('factCollectionError') and not state.get('cleanupErrors') and bool((worker or {}).get('finished') and (worker or {}).get('stopped')) and bool(state.get('completed')) and all(cleanup.values()) and all(r['conclusion'] in ('符合', '降级') for r in results)
    return {**{k: state.get(k) for k in ('runId', 'purpose', 'operator', 'mode', 'startedAt', 'endedAt', 'baseline', 'sameBaseline', 'authorization', 'backup', 'errorType', 'errorCode', 'cleanupErrors', 'factCollectionError')},
            'unattributedCommandIds': unexpected, 'demoOnly': True, 'modelEvaluation': False, 'scenes': results, 'cleanup': cleanup, 'passed': passed}


def render(record):
    lines = ['# 演示运行记录', '', '运行号：' + record['runId'], '结果：' + ('通过' if record['passed'] else '未通过'),
             '用途：' + str(record.get('purpose')), '模式：' + record['mode'],
             '执行人：' + str(record.get('operator')),
             '时间：' + str(record.get('startedAt')) + ' — ' + str(record.get('endedAt')),
             '同基线：' + str(record.get('sameBaseline')),
             '授权：`' + json.dumps(record.get('authorization'), ensure_ascii=False) + '`',
             '备份：`' + json.dumps(record.get('backup'), ensure_ascii=False) + '`', '',
             '此记录仅报告本次演示，不授予模型现场成绩或自动资格。', '',
             '| 段 / 起止 | 预期 | 首告警类别 | 时延 ms / 档位 | 命令 / 范围 / applied / expired / TTL | 预算恢复事件 | 结论 |',
             '|---|---|---|---|---|---|---|']
    for r in record['scenes']:
        commands = ', '.join(c['id'] + '/' + str(c['scope']) + '/' + str(c['appliedAt']) + '/' + str(c['expiredAt']) + '/' + str(c['ttlVerified']) for c in r['commands']) or '无'
        lines.append(f"| {r['id']} / {r['startedAt']} — {r['endedAt']} | {r['expected']} | {r['firstAlertFamily']} | {r['latencyMs']} / {r['latencyBand']} | {commands} | {', '.join(e['id'] for e in r['budgetEvents']) or '无'} | {r['conclusion']} |")
    lines += ['', '收尾：', ''] + ['- ' + k + '：' + str(v) for k, v in record['cleanup'].items()]
    lines += ['', '基线：', '', '```json', json.dumps(record.get('baseline'), ensure_ascii=False, indent=2), '```', '', '错误：`' + json.dumps({k:record.get(k) for k in ('errorCode', 'errorType', 'cleanupErrors', 'factCollectionError', 'unattributedCommandIds')}, ensure_ascii=False) + '`']
    return ('\n'.join(lines) + '\n').encode()


def compare(a, b):
    """一致要求两次均通过、同模式/基线/场景；不比较随机命令 ID 或精确时延。"""
    def signatures(r):
        return {s['id']: {'family': s['firstAlertFamily'], 'issued': bool(s['commands']),
                          'scopes': sorted({c['scope'] for c in s['commands']}),
                          'expired': all(c['ttlVerified'] for c in s['commands']),
                          'latencyBand': s['latencyBand'], 'conclusion': s['conclusion']} for s in r['scenes']}
    x, y = signatures(a), signatures(b)
    rows = {k: x.get(k) == y.get(k) for k in sorted(set(x) | set(y))}
    same = a.get('baseline') == b.get('baseline') and bool(a.get('baseline'))
    cleanup = a['cleanup'] == b['cleanup'] and all(a['cleanup'].values())
    return {'runs': [a['runId'], b['runId']], 'sameBaseline': same, 'sameMode': a['mode'] == b['mode'],
            'scenes': rows, 'cleanup': cleanup,
            'consistent': bool(a['passed'] and b['passed'] and same and cleanup and a['mode'] == b['mode'] and all(rows.values()))}


def generate(folder):
    d = Path(folder)
    record = summarize(load(d / 'state.json'), load(d / 'facts.json'), load(d / 'worker.json') if (d / 'worker.json').exists() else None)
    write(d / 'record.json', record, replace=(d / 'record.json').exists())
    write(d / 'record.md', render(record), replace=(d / 'record.md').exists())
    return record


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', required=True)
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument('--run')
    group.add_argument('--compare', nargs=2)
    args = p.parse_args()
    root = Path(args.root)
    for v in ([args.run] if args.run else args.compare):
        require(v and Path(v).name == v and v.startswith('demo-'), 'RUN_ID_INVALID')
    if args.compare:
        result = compare(*(load(root / v / 'record.json') for v in args.compare))
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result['consistent'] else 1
    result = generate(root / args.run)
    print(json.dumps({'runId': result['runId'], 'passed': result['passed']}))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(safe_main(main))
