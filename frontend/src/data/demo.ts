/**
 * 前端演示数据。
 *
 * 本轮前端只负责界面，不对接后端或数据库；字段命名与状态枚举取自
 * docs/接口设计.md 与 docs/数据库设计.md，便于后续替换为真实 API。
 * 所有地址均为 RFC 5737 / 私有网段示例值，不含真实网络或个人数据。
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low'
export type EventStatus = 'open' | 'investigating' | 'contained' | 'resolved' | 'false_positive' | 'closed'

export const severityLabel: Record<Severity, string> = {
  critical: '严重',
  high: '高',
  medium: '中',
  low: '低',
}

export const eventStatusLabel: Record<EventStatus, string> = {
  open: '待处理',
  investigating: '研判中',
  contained: '已遏制',
  resolved: '已解决',
  false_positive: '误报',
  closed: '已关闭',
}

/** 状态机：security_event 合法迁移（数据库设计 §4） */
export const eventTransitions: Record<EventStatus, EventStatus[]> = {
  open: ['investigating'],
  investigating: ['contained', 'false_positive', 'closed'],
  contained: ['resolved', 'closed'],
  resolved: ['closed'],
  false_positive: ['closed'],
  closed: [],
}

export interface Asset {
  id: string
  name: string
  os: 'macOS' | 'Windows'
  env: 'production' | 'range'
  criticality: '关键' | '重要' | '一般'
  owner: string
  address: string
  authorization: { status: 'approved' | 'pending' | 'expired'; from: string; to: string; requestedBy: string }
}

export const assets: Asset[] = [
  { id: 'AST-001', name: 'mac-studio-lab', os: 'macOS', env: 'production', criticality: '关键', owner: '资产管理员 · 李', address: '10.20.0.11', authorization: { status: 'approved', from: '2026-09-01', to: '2026-12-31', requestedBy: 'asset_admin' } },
  { id: 'AST-002', name: 'win-dev-workstation', os: 'Windows', env: 'production', criticality: '重要', owner: '资产管理员 · 李', address: '10.20.0.24', authorization: { status: 'approved', from: '2026-09-01', to: '2026-12-31', requestedBy: 'asset_admin' } },
  { id: 'AST-003', name: 'range-victim-01', os: 'Windows', env: 'range', criticality: '一般', owner: '靶场负责人 · 周', address: '192.168.56.10', authorization: { status: 'pending', from: '2026-10-01', to: '2026-10-31', requestedBy: 'asset_admin' } },
  { id: 'AST-004', name: 'range-replay-node', os: 'macOS', env: 'range', criticality: '一般', owner: '靶场负责人 · 周', address: '192.168.56.20', authorization: { status: 'expired', from: '2026-08-01', to: '2026-08-31', requestedBy: 'asset_admin' } },
]

export interface Sensor {
  id: string
  assetId: string
  version: string
  status: 'online' | 'degraded' | 'offline'
  lastHeartbeat: string
  accepted: number
  dropped: number
  queue: number
  cpu: number
  mem: number
  featureErrors: number
}

export const sensors: Sensor[] = [
  { id: 'SNS-MAC-01', assetId: 'AST-001', version: '0.4.2', status: 'online', lastHeartbeat: '12 秒前', accepted: 184220, dropped: 38, queue: 12, cpu: 6.4, mem: 142, featureErrors: 0 },
  { id: 'SNS-WIN-01', assetId: 'AST-002', version: '0.4.2', status: 'degraded', lastHeartbeat: '48 秒前', accepted: 96410, dropped: 2210, queue: 840, cpu: 18.9, mem: 231, featureErrors: 17 },
  { id: 'SNS-RNG-01', assetId: 'AST-003', version: '0.4.1', status: 'offline', lastHeartbeat: '2 小时前', accepted: 0, dropped: 0, queue: 0, cpu: 0, mem: 0, featureErrors: 0 },
]

export interface DataSource {
  id: string
  name: string
  kind: '传感器' | '公开数据集' | '回放' | '安全日志'
  schema: string
  mapping: { version: string; status: 'draft' | 'approved' }
  lastSuccess: string
  accepted: number
  rejected: number
}

export const dataSources: DataSource[] = [
  { id: 'SRC-01', name: 'mac-studio-lab 流记录', kind: '传感器', schema: 'flow.v2', mapping: { version: 'm-2026.09.2', status: 'approved' }, lastSuccess: '2026-09-27 10:42', accepted: 184220, rejected: 312 },
  { id: 'SRC-02', name: 'win-dev-workstation 流记录', kind: '传感器', schema: 'flow.v2', mapping: { version: 'm-2026.09.2', status: 'approved' }, lastSuccess: '2026-09-27 10:41', accepted: 96410, rejected: 1804 },
  { id: 'SRC-03', name: 'UNSW-NB15 基准', kind: '公开数据集', schema: 'unsw.v1', mapping: { version: 'm-2026.08.1', status: 'approved' }, lastSuccess: '2026-09-18 21:05', accepted: 257673, rejected: 0 },
  { id: 'SRC-04', name: '靶场预制回放', kind: '回放', schema: 'flow.v2', mapping: { version: 'm-2026.09.3', status: 'draft' }, lastSuccess: '—', accepted: 0, rejected: 0 },
]

export interface Alert {
  id: string
  eventId: string
  time: string
  assetId: string
  signal: 'model' | 'rule'
  label: string
  score: number
  severity: Severity
  quality: '可推理' | '待人工' | '拒绝'
  model: string
  peer: string
}

export const alerts: Alert[] = [
  { id: 'ALT-20931', eventId: 'EVT-1042', time: '10:41:08', assetId: 'AST-002', signal: 'model', label: 'DoS', score: 0.974, severity: 'critical', quality: '可推理', model: 'unsw-binary-2026.09.0', peer: '198.51.100.23:445' },
  { id: 'ALT-20930', eventId: 'EVT-1042', time: '10:40:51', assetId: 'AST-002', signal: 'rule', label: '连接速率超阈', score: 1, severity: 'high', quality: '可推理', model: 'rule/rate-v3', peer: '198.51.100.23:445' },
  { id: 'ALT-20927', eventId: 'EVT-1041', time: '10:32:14', assetId: 'AST-001', signal: 'model', label: 'Reconnaissance', score: 0.812, severity: 'medium', quality: '可推理', model: 'unsw-binary-2026.09.0', peer: '203.0.113.7:22' },
  { id: 'ALT-20925', eventId: 'EVT-1041', time: '10:31:40', assetId: 'AST-001', signal: 'rule', label: '异常端口序列', score: 1, severity: 'medium', quality: '可推理', model: 'rule/service-v2', peer: '203.0.113.7:*' },
  { id: 'ALT-20919', eventId: 'EVT-1039', time: '09:58:02', assetId: 'AST-002', signal: 'model', label: 'Exploits', score: 0.688, severity: 'high', quality: '待人工', model: 'unsw-binary-2026.09.0', peer: '198.51.100.90:8080' },
  { id: 'ALT-20911', eventId: 'EVT-1038', time: '09:21:47', assetId: 'AST-001', signal: 'model', label: 'Generic', score: 0.541, severity: 'low', quality: '可推理', model: 'unsw-binary-2026.09.0', peer: '203.0.113.51:53' },
]

export interface TimelineItem { time: string; actor: string; kind: 'alert' | 'transition' | 'note' | 'action'; text: string }

export interface SecurityEvent {
  id: string
  title: string
  severity: Severity
  status: EventStatus
  assetIds: string[]
  firstSeen: string
  lastSeen: string
  alertCount: number
  assignee: string
  risk: { total: number; parts: { name: string; value: number; note: string }[] }
  timeline: TimelineItem[]
}

export const events: SecurityEvent[] = [
  {
    id: 'EVT-1042', title: 'win-dev-workstation 出现 SMB 方向 DoS 类流量', severity: 'critical', status: 'investigating', assetIds: ['AST-002'],
    firstSeen: '2026-09-27 10:40', lastSeen: '2026-09-27 10:41', alertCount: 14, assignee: 'analyst · 陈',
    risk: { total: 86, parts: [
      { name: '模型分数', value: 34, note: '0.974，阈值策略 v2 · 高置信区间' },
      { name: '独立证据', value: 22, note: '规则 rate-v3 独立命中，非同源' },
      { name: '资产关键性', value: 15, note: '重要 · 开发工作站' },
      { name: '告警频度', value: 10, note: '60 秒内 14 条' },
      { name: '数据可信度', value: 5, note: '特征完整；传感器处于降级，扣减' },
    ] },
    timeline: [
      { time: '10:40:51', actor: 'rule/rate-v3', kind: 'alert', text: '连接速率 1,820/min 超过阈值 600/min' },
      { time: '10:41:08', actor: 'unsw-binary-2026.09.0', kind: 'alert', text: '分类为 DoS，分数 0.974' },
      { time: '10:41:30', actor: 'correlator', kind: 'transition', text: '14 条告警归并为事件，状态 open' },
      { time: '10:43:02', actor: 'analyst · 陈', kind: 'transition', text: 'open → investigating' },
      { time: '10:44:40', actor: 'analyst · 陈', kind: 'note', text: '对端不在资产清单内；确认非本机业务流量，准备提交临时阻断申请。' },
    ],
  },
  {
    id: 'EVT-1041', title: 'mac-studio-lab 收到 SSH 端口探测序列', severity: 'medium', status: 'open', assetIds: ['AST-001'],
    firstSeen: '2026-09-27 10:31', lastSeen: '2026-09-27 10:32', alertCount: 6, assignee: '未分派',
    risk: { total: 58, parts: [
      { name: '模型分数', value: 22, note: '0.812 · Reconnaissance' },
      { name: '独立证据', value: 14, note: '规则 service-v2 命中' },
      { name: '资产关键性', value: 12, note: '关键' },
      { name: '告警频度', value: 4, note: '2 分钟内 6 条' },
      { name: '数据可信度', value: 6, note: '特征完整' },
    ] },
    timeline: [
      { time: '10:31:40', actor: 'rule/service-v2', kind: 'alert', text: '同一对端 90 秒内访问 23 个端口' },
      { time: '10:32:14', actor: 'unsw-binary-2026.09.0', kind: 'alert', text: '分类为 Reconnaissance，分数 0.812' },
      { time: '10:32:30', actor: 'correlator', kind: 'transition', text: '归并为事件，状态 open' },
    ],
  },
  {
    id: 'EVT-1039', title: 'win-dev-workstation 8080 端口可疑载荷特征', severity: 'high', status: 'contained', assetIds: ['AST-002'],
    firstSeen: '2026-09-27 09:57', lastSeen: '2026-09-27 09:58', alertCount: 3, assignee: 'analyst · 陈',
    risk: { total: 64, parts: [
      { name: '模型分数', value: 18, note: '0.688 · 位于人工复核区间' },
      { name: '独立证据', value: 8, note: '无独立规则命中' },
      { name: '资产关键性', value: 15, note: '重要' },
      { name: '告警频度', value: 3, note: '低' },
      { name: '数据可信度', value: 20, note: '部分特征待人工，未扣减上限' },
    ] },
    timeline: [
      { time: '09:58:02', actor: 'unsw-binary-2026.09.0', kind: 'alert', text: '分类为 Exploits，分数 0.688，质量：待人工' },
      { time: '10:05:11', actor: 'analyst · 陈', kind: 'transition', text: 'open → investigating' },
      { time: '10:12:48', actor: 'approver · 王', kind: 'action', text: '批准 ACT-311：阻断 198.51.100.90 入站 TCP/8080，TTL 30 分钟' },
      { time: '10:13:00', actor: 'analyst · 陈', kind: 'transition', text: 'investigating → contained' },
    ],
  },
  {
    id: 'EVT-1038', title: 'mac-studio-lab DNS 流量分类为 Generic', severity: 'low', status: 'false_positive', assetIds: ['AST-001'],
    firstSeen: '2026-09-27 09:21', lastSeen: '2026-09-27 09:21', alertCount: 1, assignee: 'analyst · 陈',
    risk: { total: 21, parts: [
      { name: '模型分数', value: 9, note: '0.541' },
      { name: '独立证据', value: 0, note: '无' },
      { name: '资产关键性', value: 12, note: '关键' },
      { name: '告警频度', value: 0, note: '单次' },
      { name: '数据可信度', value: 0, note: '—' },
    ] },
    timeline: [
      { time: '09:21:47', actor: 'unsw-binary-2026.09.0', kind: 'alert', text: '分类为 Generic，分数 0.541' },
      { time: '09:40:02', actor: 'analyst · 陈', kind: 'transition', text: 'open → investigating → false_positive' },
      { time: '09:40:30', actor: 'analyst · 陈', kind: 'note', text: '对端为内部解析器，已提交人工反馈样本。' },
    ],
  },
]

export interface Policy { id: string; name: string; env: string; actions: string[]; maxTtl: number; approval: '人工' | '策略内自动'; status: 'active' | 'draft' }

export const policies: Policy[] = [
  { id: 'POL-07', name: '工作站入站临时阻断', env: 'production', actions: ['host.block.inbound'], maxTtl: 60, approval: '人工', status: 'active' },
  { id: 'POL-09', name: '靶场出站阻断', env: 'range', actions: ['host.block.outbound'], maxTtl: 120, approval: '策略内自动', status: 'active' },
  { id: 'POL-11', name: '主机限速（待适配器验证）', env: 'production', actions: ['host.rate_limit'], maxTtl: 30, approval: '人工', status: 'draft' },
]

export type ApprovalStatus = 'pending' | 'approved' | 'rejected' | 'expired' | 'cancelled'
export type ExecStatus = 'queued' | 'running' | 'succeeded' | 'failed' | 'timed_out' | 'rollback_pending' | 'rolled_back' | 'rollback_failed' | 'unavailable'

export interface ResponseAction {
  id: string
  eventId: string
  assetId: string
  action: string
  target: string
  ttl: number
  policy: string
  requester: string
  approver?: string
  approval: ApprovalStatus
  execution: ExecStatus
  idempotencyKey: string
  requestedAt: string
  expiresAt: string
}

export const actions: ResponseAction[] = [
  { id: 'ACT-314', eventId: 'EVT-1042', assetId: 'AST-002', action: 'host.block.inbound', target: '198.51.100.23 · TCP/445', ttl: 30, policy: 'POL-07 v3', requester: 'analyst · 陈', approval: 'pending', execution: 'queued', idempotencyKey: 'evt1042-blk-445-01', requestedAt: '10:45:12', expiresAt: '11:15:12' },
  { id: 'ACT-311', eventId: 'EVT-1039', assetId: 'AST-002', action: 'host.block.inbound', target: '198.51.100.90 · TCP/8080', ttl: 30, policy: 'POL-07 v3', requester: 'analyst · 陈', approver: 'approver · 王', approval: 'approved', execution: 'unavailable', idempotencyKey: 'evt1039-blk-8080-01', requestedAt: '10:10:31', expiresAt: '10:40:31' },
  { id: 'ACT-305', eventId: 'EVT-1030', assetId: 'AST-001', action: 'host.block.inbound', target: '203.0.113.99 · TCP/3389', ttl: 15, policy: 'POL-07 v2', requester: 'analyst · 陈', approver: 'approver · 王', approval: 'rejected', execution: 'queued', idempotencyKey: 'evt1030-blk-3389-01', requestedAt: '昨天 16:20', expiresAt: '昨天 16:35' },
]

export const approvalLabel: Record<ApprovalStatus, string> = { pending: '待审批', approved: '已批准', rejected: '已拒绝', expired: '已过期', cancelled: '已撤销' }
export const execLabel: Record<ExecStatus, string> = {
  queued: '未执行', running: '执行中', succeeded: '已生效', failed: '失败', timed_out: '超时', rollback_pending: '待回滚', rolled_back: '已回滚', rollback_failed: '回滚失败', unavailable: '执行器未开放',
}

export type ReleaseStage = 'candidate' | 'validated' | 'shadow' | 'approved' | 'active' | 'retired' | 'rolled_back'
export const releaseStages: ReleaseStage[] = ['candidate', 'validated', 'shadow', 'approved', 'active']
export const stageLabel: Record<ReleaseStage, string> = { candidate: '候选', validated: '已校验', shadow: '影子', approved: '已批准', active: '活动', retired: '已停用', rolled_back: '已回退' }

export interface ModelVersion {
  version: string
  task: string
  stage: ReleaseStage
  runtime: string
  sha256: string
  dataset: string
  features: number
  threshold: string
  metrics: { name: string; value: string }[]
  checks: { name: string; ok: boolean | null; note: string }[]
  registeredAt: string
}

export const models: ModelVersion[] = [
  {
    version: 'unsw-binary-2026.09.0', task: '正常 / 攻击二分类', stage: 'active', runtime: 'ONNX Runtime 1.22 · CPU', sha256: '9f3c1e07a4b2d8e61f0c5b97a3d24e18c6f0b1a29e7d45c3b8a61f2e0d97c4a1',
    dataset: 'UNSW-NB15 · split fp 4c1e…a07b', features: 42, threshold: 'v2 · 0.62（验证集选取）',
    metrics: [{ name: 'Macro-F1', value: '0.912' }, { name: '攻击召回', value: '0.957' }, { name: '正常流误报率', value: '1.8%' }, { name: 'p95 延迟', value: '3.1 ms' }],
    checks: [
      { name: '权重 SHA-256', ok: true, note: '与 manifest 一致' },
      { name: '特征顺序与单位', ok: true, note: '42 项 · flow.v2 契约' },
      { name: '预处理 / 标签映射', ok: true, note: '内嵌于 ONNX 图，无 pickle' },
      { name: '冒烟推理', ok: true, note: 'golden fixtures 64/64' },
    ],
    registeredAt: '2026-09-19',
  },
  {
    version: 'unsw-multiclass-2026.10.0-rc1', task: '攻击类别（10 类）', stage: 'validated', runtime: 'ONNX Runtime 1.22 · CPU', sha256: 'c27a90e5f1d3b4a8e6c0f29d17b5a3e84c1f60d2b9a7e53f8c4d1a06b2e9f370',
    dataset: 'UNSW-NB15 · split fp 4c1e…a07b', features: 42, threshold: 'v1 · 每类 top-1',
    metrics: [{ name: 'Macro-F1', value: '0.604' }, { name: 'DoS 召回', value: '0.418' }, { name: '正常流误报率', value: '2.3%' }, { name: 'p95 延迟', value: '4.8 ms' }],
    checks: [
      { name: '权重 SHA-256', ok: true, note: '与 manifest 一致' },
      { name: '特征顺序与单位', ok: true, note: '42 项' },
      { name: '预处理 / 标签映射', ok: true, note: '10 类映射' },
      { name: '冒烟推理', ok: true, note: '64/64' },
    ],
    registeredAt: '2026-09-25',
  },
  {
    version: 'unsw-binary-2026.10.0-rc2', task: '正常 / 攻击二分类', stage: 'candidate', runtime: 'ONNX Runtime 1.22 · CPU', sha256: '51e0b9c3a7d2f84e6b1c09a5d3f7e2b48c6a1d0f9e3b75c2a8d4f16e0b3c97a2',
    dataset: 'UNSW-NB15 + 反馈集 fb-2026.09 · split fp 88d2…1c4e', features: 42, threshold: '待选择',
    metrics: [{ name: 'Macro-F1', value: '—' }, { name: '攻击召回', value: '—' }, { name: '正常流误报率', value: '—' }, { name: 'p95 延迟', value: '—' }],
    checks: [
      { name: '权重 SHA-256', ok: null, note: '未校验' },
      { name: '特征顺序与单位', ok: null, note: '未校验' },
      { name: '预处理 / 标签映射', ok: null, note: '未校验' },
      { name: '冒烟推理', ok: null, note: '未校验' },
    ],
    registeredAt: '2026-09-27',
  },
]

export interface DriftWindow { window: string; psi: number; rejectRate: number; fpFeedback: number; dropRate: number }
export const driftWindows: DriftWindow[] = Array.from({ length: 24 }, (_, i) => {
  const h = String(i).padStart(2, '0')
  const bump = i > 15 && i < 20 ? 0.09 : 0
  return {
    window: `${h}:00`,
    psi: +(0.04 + Math.abs(Math.sin(i * 0.7)) * 0.05 + bump).toFixed(3),
    rejectRate: +(0.6 + Math.abs(Math.cos(i * 0.5)) * 0.8 + bump * 10).toFixed(2),
    fpFeedback: i % 6 === 0 ? 1 : 0,
    dropRate: +(0.2 + (i > 15 && i < 20 ? 2.1 : 0.1 * (i % 3))).toFixed(2),
  }
})

export interface FeedbackSample { id: string; alertId: string; label: string; basis: string; reviewer: string; eligible: boolean | null }
export const feedback: FeedbackSample[] = [
  { id: 'FB-0412', alertId: 'ALT-20911', label: 'normal', basis: '对端为内部解析器，业务确认', reviewer: 'analyst · 陈', eligible: true },
  { id: 'FB-0409', alertId: 'ALT-20874', label: 'normal', basis: '备份任务时段，变更单 CHG-88', reviewer: 'analyst · 陈', eligible: null },
  { id: 'FB-0401', alertId: 'ALT-20790', label: 'dos', basis: '靶场回放 RUN-17 预置标签', reviewer: 'analyst · 周', eligible: false },
]

export interface TrainingJob { id: string; status: 'requested' | 'approved' | 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'; dataset: string; requester: string; approver?: string; output?: string; createdAt: string }
export const trainingJobs: TrainingJob[] = [
  { id: 'TJ-008', status: 'completed', dataset: 'UNSW-NB15 + fb-2026.09', requester: 'model_operator · 赵', approver: 'model_releaser · 孙', output: 'unsw-binary-2026.10.0-rc2', createdAt: '2026-09-26' },
  { id: 'TJ-009', status: 'requested', dataset: 'UNSW-NB15 + fb-2026.10', requester: 'model_operator · 赵', createdAt: '2026-09-27' },
]

export interface ReplayScenario { id: string; name: string; source: string; rows: number; rate: string; range: string }
export const replayScenarios: ReplayScenario[] = [
  { id: 'SCN-03', name: 'UNSW 测试子集 · DoS 片段', source: 'SRC-03', rows: 12264, rate: '200 流/秒', range: '靶场 · range-victim-01' },
  { id: 'SCN-04', name: '交付 CSV 离线回放', source: 'SRC-03', rows: 4096, rate: '最大速率', range: '仅离线推理，不发包' },
]

export interface AuditEntry { id: string; time: string; actor: string; action: string; resource: string; result: 'success' | 'denied' | 'failed'; requestId: string }
export const auditLog: AuditEntry[] = [
  { id: 'AUD-99121', time: '2026-09-27 10:45:12', actor: 'analyst · 陈', action: 'action.request', resource: 'event/EVT-1042 → ACT-314', result: 'success', requestId: 'req-7f2a91' },
  { id: 'AUD-99120', time: '2026-09-27 10:44:40', actor: 'analyst · 陈', action: 'event.note', resource: 'event/EVT-1042', result: 'success', requestId: 'req-7f2a77' },
  { id: 'AUD-99117', time: '2026-09-27 10:38:03', actor: 'analyst · 陈', action: 'approval.decide', resource: 'approval/ACT-314', result: 'denied', requestId: 'req-7f29d0' },
  { id: 'AUD-99110', time: '2026-09-27 10:14:02', actor: 'approver · 王', action: 'action.execute', resource: 'action/ACT-311', result: 'failed', requestId: 'req-7f2611' },
  { id: 'AUD-99108', time: '2026-09-27 10:12:48', actor: 'approver · 王', action: 'approval.decide', resource: 'approval/ACT-311', result: 'success', requestId: 'req-7f25c4' },
  { id: 'AUD-99096', time: '2026-09-27 09:02:11', actor: 'model_operator · 赵', action: 'model.candidate.register', resource: 'model/unsw-binary-2026.10.0-rc2', result: 'success', requestId: 'req-7f1e08' },
  { id: 'AUD-99090', time: '2026-09-27 08:40:55', actor: 'platform_admin', action: 'iam.role.assign', resource: 'user/u-0007', result: 'success', requestId: 'req-7f1c3b' },
  { id: 'AUD-99081', time: '2026-09-27 08:12:30', actor: 'connector/src-02', action: 'machine.ingest.submit', resource: 'data_source/SRC-02', result: 'success', requestId: 'req-7f1a02' },
]

export const roles = [
  { key: 'platform_admin', name: '平台管理员', scope: '管理类全局 · 查询只读', deny: '响应申请/审批/执行、模型发布' },
  { key: 'asset_source_admin', name: '资产与数据源管理员', scope: '显式资产与数据源', deny: 'IAM、授权审批、研判、响应审批' },
  { key: 'security_analyst', name: '安全分析员', scope: '显式资产 / 数据源', deny: '审批、策略批准、直接执行' },
  { key: 'response_approver', name: '响应审批员', scope: '审批所属且仍授权的资产', deny: '审批本人申请、直接执行' },
  { key: 'model_operator', name: '模型操作员', scope: '模型注册范围', deny: '训练/推理、批准发布' },
  { key: 'model_releaser', name: '模型发布审批员', scope: '模型注册范围', deny: '激活模型、批准本人申请' },
  { key: 'auditor', name: '审计只读', scope: '显式审计范围', deny: '任何业务写入' },
]

export interface User { id: string; username: string; name: string; status: 'active' | 'frozen'; roles: string[]; lastLogin: string }
export const users: User[] = [
  { id: 'u-0001', username: 'admin', name: '本机管理员', status: 'active', roles: ['platform_admin'], lastLogin: '2026-09-27 08:30' },
  { id: 'u-0004', username: 'chen.analyst', name: '陈', status: 'active', roles: ['security_analyst'], lastLogin: '2026-09-27 09:02' },
  { id: 'u-0005', username: 'wang.approver', name: '王', status: 'active', roles: ['response_approver'], lastLogin: '2026-09-27 10:10' },
  { id: 'u-0006', username: 'li.assets', name: '李', status: 'active', roles: ['asset_source_admin'], lastLogin: '2026-09-26 17:44' },
  { id: 'u-0007', username: 'zhao.model', name: '赵', status: 'active', roles: ['model_operator'], lastLogin: '2026-09-27 08:58' },
  { id: 'u-0008', username: 'sun.release', name: '孙', status: 'active', roles: ['model_releaser'], lastLogin: '2026-09-25 14:20' },
  { id: 'u-0009', username: 'audit.ro', name: '审计', status: 'active', roles: ['auditor'], lastLogin: '2026-09-20 11:03' },
]

export const assetName = (id: string) => assets.find((a) => a.id === id)?.name ?? id
