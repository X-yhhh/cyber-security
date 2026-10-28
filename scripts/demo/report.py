#!/usr/bin/env python3
"""按准确运行目录、资产与段标记汇总事实；不生成或导入模型成绩、G3 资格或发布报告。"""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.demo.common import CLEANUP, instant, load, require, safe_main, write

RULE_EXPECTATIONS = {'S1': {'scan-ports'}, 'S2': {'brute-starts'}}


def _rule_hits(facts, scene_id, started):
    grouped = {}
    for row in facts.get('ruleEvaluations', []):
        if row.get('sceneId') != scene_id or row.get('matched') not in (True, 1):
            continue
        key = (row['ruleId'], row['family'], row['direction'])
        hit = grouped.setdefault(key, {'ruleId': row['ruleId'], 'family': row['family'], 'direction': row['direction'],
                                       'count': 0, 'firstAt': row['firstAt']})
        hit['count'] += row['count']
        if instant(row['firstAt']) < instant(hit['firstAt']):
            hit['firstAt'] = row['firstAt']
    for hit in grouped.values():
        hit['latencyMs'] = round((instant(hit['firstAt']) - instant(started)) * 1000, 3) if started else None
    return sorted(grouped.values(), key=lambda hit: (hit['ruleId'], hit['family'], hit['direction']))


def summarize(state, facts, worker):
    """命令按 decisionId 关联段内判定；仅 projected 回执证明 applied/expired，未知项从不默认成功。"""
    results, assigned = [], set()
    marks = {r['id']: r for r in (worker or {}).get('scenes', [])}
    for scene in state['scenes']:
        mark = marks.get(scene['id'], {})
        start, end = mark.get('startedAt'), mark.get('endedAt')
        result = {'id': scene['id'], 'expected': scene['expected'], 'family': scene['family'],
                  'startedAt': start, 'endedAt': end, 'firstAlertFamily': None, 'latencyMs': None,
                  'latencyBand': 'missing', 'commands': [], 'budgetEvents': [], 'modelConclusion': '不符合',
                  'ruleHits': _rule_hits(facts, scene['id'], start), 'ruleConclusion': '不符合',
                  'controlConnections': None, 'newControlConnections': None, 'directionCounts': {k: 0 for k in ('inbound', 'unknown', 'outbound')}}
        observation_facts = facts.get('sceneObservations', {}).get(scene['id'], {})
        result.update({k: observation_facts.get(k) for k in ('controlConnections', 'newControlConnections')})
        result['directionCounts'] = observation_facts.get('directionCounts', result['directionCounts'])
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
            result['modelConclusion'] = '符合' if okay and safe_commands else '降级' if scene['id'] == 'S3' and not commands and not alerts else '不符合'
        control_ok = result['newControlConnections'] == 0 and isinstance(result['controlConnections'], int) and result['controlConnections'] <= 1
        if scene['id'] == 'S0':
            rule_ok = not result['ruleHits'] and control_ok
        elif scene['id'] in RULE_EXPECTATIONS:
            expected = RULE_EXPECTATIONS[scene['id']]
            expected_inbound = any(hit['ruleId'] in expected and hit['direction'] == 'inbound' and hit['count'] > 0 for hit in result['ruleHits'])
            inbound_only = all(hit['direction'] == 'inbound' for hit in result['ruleHits'])
            rule_ok = expected_inbound and inbound_only and control_ok
        else:
            rule_ok = False
            result['ruleConclusion'] = '不适用'
        if scene['id'] in {'S0', *RULE_EXPECTATIONS}:
            result['ruleConclusion'] = '符合' if rule_ok else '不符合'
        results.append(result)
    cleanup = {k: state.get('cleanup', {}).get(k) is True for k in CLEANUP}
    unexpected = [c['id'] for c in facts['commands'] if c['id'] not in assigned]
    passed = not unexpected and not state.get('factCollectionError') and not state.get('cleanupErrors') and bool((worker or {}).get('finished') and (worker or {}).get('stopped')) and bool(state.get('completed')) and all(cleanup.values()) and all(r['modelConclusion'] in ('符合', '降级') for r in results)
    rule_source_command_ids = sorted(c['id'] for c in facts['commands'] if c.get('source') == 'rule')
    all_rule_hits = [row for row in facts.get('ruleEvaluations', [])
                     if row.get('sceneId') == '*' and row.get('matched') in (True, 1)]
    non_inbound_rule_hits = [row for row in all_rule_hits if row.get('direction') != 'inbound']
    by_scene = {r['id']: r for r in results}
    s0 = by_scene.get('S0', {})
    clean_s0 = bool(s0.get('startedAt') and s0.get('endedAt') and s0.get('ruleConclusion') == '符合' and
                    not any(d['decision'] in ('alert', 'block_candidate') for d in facts['decisions']
                            if instant(s0['startedAt']) <= instant(d['at']) <= instant(s0['endedAt']) + 10))
    rule_demo_passed = bool(state.get('completed') and (worker or {}).get('finished') and (worker or {}).get('stopped') and
                            not state.get('factCollectionError') and not facts.get('observationFactsError') and
                            not state.get('cleanupErrors') and all(cleanup.values()) and
                            clean_s0 and all(by_scene.get(scene_id, {}).get('ruleConclusion') == '符合' for scene_id in ('S1', 'S2')) and
                            not non_inbound_rule_hits and not rule_source_command_ids)
    return {**{k: state.get(k) for k in ('runId', 'purpose', 'operator', 'mode', 'startedAt', 'endedAt', 'baseline', 'sameBaseline', 'authorization', 'backup', 'errorType', 'errorCode', 'cleanupErrors', 'factCollectionError')},
            'unattributedCommandIds': unexpected, 'demoOnly': True, 'modelEvaluation': False, 'directionCounts': facts.get('directionCounts', {}),
            'observationFactsError': facts.get('observationFactsError'),
            'scenes': results, 'cleanup': cleanup, 'passed': passed,
            'ruleDemo': {'passed': rule_demo_passed, 'ruleSourceCommandIds': rule_source_command_ids,
                         'nonInboundRuleEvaluations': non_inbound_rule_hits}}


def render(record):
    lines = ['# 演示运行记录', '', '运行号：' + record['runId'],
             '模型口径结果：' + ('通过' if record['passed'] else '未通过'),
             '规则演示结果：' + ('通过' if record.get('ruleDemo', {}).get('passed') else '未通过'),
             '用途：' + str(record.get('purpose')), '模式：' + record['mode'],
             '执行人：' + str(record.get('operator')),
             '时间：' + str(record.get('startedAt')) + ' — ' + str(record.get('endedAt')),
             '同基线：' + str(record.get('sameBaseline')),
             '授权：`' + json.dumps(record.get('authorization'), ensure_ascii=False) + '`',
             '备份：`' + json.dumps(record.get('backup'), ensure_ascii=False) + '`', '',
             '此记录仅报告本次演示，不授予模型现场成绩或自动资格。', '',
             '## 模型结论', '',
             '| 段 / 起止 | 预期 | 首告警类别 | 时延 ms / 档位 | 命令 / 范围 / applied / expired / TTL | 预算恢复事件 | 结论 |',
             '|---|---|---|---|---|---|---|']
    for r in record['scenes']:
        commands = ', '.join(c['id'] + '/' + str(c['scope']) + '/' + str(c['appliedAt']) + '/' + str(c['expiredAt']) + '/' + str(c['ttlVerified']) for c in r['commands']) or '无'
        lines.append(f"| {r['id']} / {r['startedAt']} — {r['endedAt']} | {r['expected']} | {r['firstAlertFamily']} | {r['latencyMs']} / {r['latencyBand']} | {commands} | {', '.join(e['id'] for e in r['budgetEvents']) or '无'} | {r['modelConclusion']} |")
    lines += ['', '## 规则结论：规则命中只作为演示事实，不是模型成绩或误报率', '',
              '| 段 / 起止 | ruleHits（规则 / 类别 / 方向 / 次数 / 首次 / 时延 ms） | 方向计数 | controlConnections | newControlConnections | 结论 |',
              '|---|---|---|---:|---:|---|']
    for r in record['scenes']:
        hits = ', '.join(f"{h['ruleId']}/{h['family']}/{h['direction']}/{h['count']}/{h['firstAt']}/{h['latencyMs']}" for h in r['ruleHits']) or '无'
        directions = ', '.join(k + '=' + str(v) for k, v in r['directionCounts'].items())
        lines.append(f"| {r['id']} / {r['startedAt']} — {r['endedAt']} | {hits} | {directions} | {r['controlConnections']} | {r['newControlConnections']} | {r['ruleConclusion']} |")
    lines += ['', '规则演示运行级判定：' + ('通过' if record.get('ruleDemo', {}).get('passed') else '未通过'),
              '非入站规则评价：' + str(len(record.get('ruleDemo', {}).get('nonInboundRuleEvaluations', []))),
              '规则来源命令：' + (', '.join(record.get('ruleDemo', {}).get('ruleSourceCommandIds', [])) or '无')]
    lines += ['', '收尾：', ''] + ['- ' + k + '：' + str(v) for k, v in record['cleanup'].items()]
    lines += ['', '基线：', '', '```json', json.dumps(record.get('baseline'), ensure_ascii=False, indent=2), '```', '', '错误：`' + json.dumps({k:record.get(k) for k in ('errorCode', 'errorType', 'cleanupErrors', 'factCollectionError', 'observationFactsError', 'unattributedCommandIds')}, ensure_ascii=False) + '`']
    return ('\n'.join(lines) + '\n').encode()


def compare(a, b):
    """一致要求两次均通过、同模式/基线/场景；不比较随机命令 ID 或精确时延。"""
    def signatures(r):
        return {s['id']: {'family': s['firstAlertFamily'], 'issued': bool(s['commands']),
                          'scopes': sorted({c['scope'] for c in s['commands']}),
                          'expired': all(c['ttlVerified'] for c in s['commands']),
                          'latencyBand': s['latencyBand'], 'conclusion': s['modelConclusion'],
                          'ruleIds': sorted({hit['ruleId'] for hit in s.get('ruleHits', [])}),
                          'ruleConclusion': s.get('ruleConclusion')} for s in r['scenes']}
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
