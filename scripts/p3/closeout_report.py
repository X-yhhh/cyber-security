"""汇总 P3-B 审计证据并绑定文件哈希；不读取模型数据集。"""
import json
from pathlib import Path

from multiclass_train import sha256, write_new

root = Path('.cache/p3b-20261007')
audit = root / 'audit-mac-v2'
load = lambda path: json.loads(path.read_text(encoding='utf-8'))
metrics = load(audit / 'validation-report.json')
verification = load(root / 'verification-v1/verification.json')
inventory = load(root / 'fit-inventory.json')
summary = load(root / 'windows-evidence/run-main-v3/run-summary.json')
corrected = load(audit / 'corrected-matrix.json')
eligible = [f for f in corrected['fits'] if f['onnxParity']['status'] == 'passed'
            and f['validation']['falsePositiveRate'] <= .01]
selected = max(eligible, key=lambda f: (f['validation']['macroF1'], f['validation']['attackDetection']))['name']
assert selected == summary['selected']
out = root / 'closeout-v1'
out.mkdir(exist_ok=False)
evidence = [p for directory in [audit, root / 'verification-v1', root / 'audit-windows-v1']
            for p in directory.iterdir() if p.is_file()]
evidence += [root / 'fit-inventory.json', root / 'windows-evidence/run-main-v3/run-summary.json',
             Path('.cache/p3-a-20261007/frozen/test-access.jsonl')]
evidence += list(Path('scratch/p3b_payload').glob('*.py'))
evidence += [Path('scratch/p3b_payload/run_step.cmd')]
write_new(out / 'checksums.json', {str(p): sha256(p) for p in evidence})
write_new(out / 'status.json', {
    'P3BClosed': False, 'P3CReady': False, 'candidateOnly': True, 'automaticExecutionEnabled': False,
    'newFitsThisContinuation': 0, 'completedFitsLowerBound': inventory['provenFitLowerBound'],
    'fitBudget': 30, 'selected': selected, 'finalTestRead': False,
    'validation': {k: metrics[k] for k in ('attackDetection','macroF1','falsePositiveRate','normalSourceFpr','alertThreshold')},
    'B0': 'run plans retained; cumulative budget enforcement failed; no immutable per-fit code manifest',
    'B1': '9 focused tests passed on both platforms; future fitting entry disabled',
    'B2': '13-fit main matrix completed; all prior attempts retained',
    'B3': 'corrected peer/time preview and validation-only rules recorded; no live eligibility',
    'B4': 'numerical gate and ablations passed; offload explanation inherited from P3-A, not freshly packet-audited',
    'B5': 'cross-platform ONNX passed; full train original-framework comparison unavailable',
    'remaining': ['native model/train framework outputs missing', 'at least 32 completed fits exceed 30-fit budget',
                  'single-flow reference ONNX parity failed; excluded from candidate selection'],
    'nextDecision': 'retain candidate-only and alert-only; resolve evidence recovery or explicitly revise fitting budget before any further fit',
    'offloadEvidence': {'reference': 'docs/p3/README.md section 5.2 and P3-A pre-freeze review',
                        'explanation': 'IP length exceeds MTU; P3-A attributes large packets to merged outbound HTTP responses',
                        'newPacketRead': False, 'notProven': 'exact GRO/GSO/TSO mechanism and deployed Mac capture behavior',
                        'coverage': {'Hulk': .093, 'DDoS': .304}, 'noQualityRuleRelaxation': True},
    'verification': verification,
})
report = f'''# P3-B 执行收尾报告

2026-10-07：主矩阵及零拟合审计结束；P3-B 尚未通过完整出口，P3-C 未开始。

## 实测结果

- 研究候选：`{selected}`；13 个主矩阵 fit 已结束，无训练进程。
- validation 四攻击类等权检出率 {metrics['attackDetection']:.6%}，macro-F1 {metrics['macroF1']:.6f}。
- 内部正常与网页补充 FPR 均为 0；告警阈值 {metrics['alertThreshold']}。
- 规则/模型/OR 并用检出率为 78.3213% / 98.5961% / 98.5981%；FPR 为 0.535557% / 0 / 0.535557%。
- 两项消融未触发 0.10 下降判据；原始分布、常数类对照、树分裂次数重要性及种子波动已报告。
- Mac/Windows 完整 validation、train ONNX 最大分差分别 5.364419e-7、1.192093e-7，类别翻转均为 0。
- 本次接续新增拟合 0 次，两端 9 项回归通过；未改标签、切分或质量过滤。

## 未通过项

1. Windows 原生模型与 train 框架概率未保存。现有 Windows validation 框架对拍通过，但不能据此推断完整 train 对拍通过；两端 ONNX 一致也不能替代此证据。
2. 先前尝试、smoke、重启合计已证明至少 {inventory['provenFitLowerBound']} 次完整拟合，超过图片路线累计 30 次上限。部分中断尝试可能有额外拟合。原入口没有跨 run 限额，当前入口已禁用拟合；不改写历史计划掩盖偏差。
3. 单流参照导出分差约 0.0259，未通过；仅保留框架参照报告，不作为交付候选。
4. 洪泛大包来源沿用 P3-A 的服务器响应合并解释；本次未重新读取原始包，不能独立证明具体 offload 机制。Hulk 9.3%、DDoS 30.4% 的可判定覆盖局限继续保留。

## 修复与边界

旧 attackDetection 错用类别召回率，已按任意攻击类检出修正；候选不变。旧策略错误地按内部/网页聚合，已作废，现使用真实来源作用域、服务端口、10 秒最新 parent 证据，标签只用于事后统计。预览不包含真实授权、targetRef、动作预算与平台恢复证明，全部类别仍为 `alert_only`。

另存 int64 类别输入 Cast 修复图，权重未改，Mac 相对原图 validation 输出完全一致。全部生成物在忽略目录，未提交/推送，未修改后端、执行器或前端。test/L3 未读取；Mac test 权限为 000，访问日志仍只有封存事件。权限和自报字段不是独立的操作系统取证证明。

## 接续条件

可先查找是否存在本轮原生模型或 train 框架输出的可信备份；当前 run 中未发现。若需重训以重建完整证据，必须先明确调整本轮累计预算，并提前保存原生非 pickle 模型、全量框架概率和代码/参数哈希；不能复用旧模型成绩。当前不自动重训，不进入 P3-C/P6。

精确文件哈希见 `checksums.json`，机器状态与门槛见 `status.json`。本报告不授予生产或自动封禁能力。
'''
(out / 'report.md').write_text(report, encoding='utf-8')
print(json.dumps({'status':'evidence_complete_stage_not_closed', 'output':str(out), 'newFits':0}))
