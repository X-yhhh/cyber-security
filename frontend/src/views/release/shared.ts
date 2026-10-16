/**
 * 模型与发布页面（任务单 F3）共用的标签、名称索引与错误文案。
 *
 * - 等级文案沿用 lab 会话详情的口径：lab_auto 一律写「lab 自动（仅 lab）」，alert_only 与未登记来源写「只告警」。
 * - 名称索引按需读取（每类最多 200 条），只在调用方有对应读权限、真正需要显示名称时才发请求，
 *   避免打开某个分段时顺带读取无关集合；读取失败退回截断 ID。
 * - 有引用的对象删除或退役时后端返回 409 RESOURCE_IN_USE，这里统一改写为带处理建议的说明。
 */
import { reactive } from 'vue'
import { ApiError } from '@/api/client'
import { can } from '@/api/session'
import { errText } from '@/composables/load'
import { releaseApi, type EvaluationPlan, type ReleaseBundle, type ReleaseCapability, type ReleaseModel, type ReleasePolicy } from '@/api/v2/release'

export const modelStatusLabel: Record<string, string> = { pending: '待校验', validated: '已校验', failed: '校验失败', retired: '已退役' }
export const datasetStatusLabel: Record<string, string> = { active: '启用', retired: '已退役' }
export const policyStatusLabel: Record<string, string> = { draft: '草稿', reviewed: '已审核', retired: '已退役' }
export const bundleStatusLabel: Record<string, string> = { candidate: '候选', evaluated: '已封存待批', approved: '已批准', active: '已激活', suspended: '已暂停', retired: '已退役' }
export const evaluationStatusLabel: Record<string, string> = { pending: '待运行', running: '运行中', completed: '已完成', passed: '通过', failed: '未通过' }
export const replayStatusLabel: Record<string, string> = { queued: '排队中', running: '回放中', completed: '已完成', failed: '失败' }
export const runKindLabel: Record<string, string> = { development: '开发', final: '最终（final）', replay: '回放', canary: '灰度（canary）', platform: '平台（platform）' }
export const envLabel: Record<string, string> = { research: '研究', lab: 'lab', authorized: '授权' }
export const levelLabel: Record<string, string> = { research: '研究', alert_only: '只告警', lab_auto: 'lab 自动（仅 lab）', authorized_auto: '授权自动' }
export const modeLabel: Record<string, string> = { alert_only: '只告警', auto: '自动' }
export const scopeLabel: Record<string, string> = { peer_service: '对端 + 服务端口', peer_inbound: '对端全部入站' }
export const familyLabel: Record<string, string> = { port_scan: '端口扫描', brute_force: '暴力破解', dos_flood: '洪泛拒绝服务', dos_slow: '慢速拒绝服务' }
export const FAMILIES = ['port_scan', 'brute_force', 'dos_flood', 'dos_slow'] as const
export const profileLabel: Record<string, string> = { 'flow-prefix-v1': '流前缀', 'flow-final-v1': '流结束' }

/** 当前控制面接受的协议版本（后端 GuardJson.versions），申请发布组合时作为默认值，可改。 */
export const DEFAULT_PROTOCOL_VERSIONS = {
  observation: 'host-guard/5.0.0-rc.2',
  decision: 'host-guard-decision/2026-10-08.1',
  evaluation: 'host-guard-evaluation/2026-10-08.1',
  health: 'host-guard-capture-health/1.0.0',
}

export const short = (id: string | null | undefined) => (id ? id.slice(0, 8) : '—')
export const modelTitle = (m: Pick<ReleaseModel, 'displayName' | 'modelKey'>) => m.displayName || m.modelKey
export const policyTitle = (p: Pick<ReleasePolicy, 'displayName' | 'policyKey'>) => p.displayName || p.policyKey
/** 组合标题：有显示名（命名规范 R 编号）用显示名，否则退回组合键前 8 位。 */
export const bundleTitle = (b: Pick<ReleaseBundle, 'displayName' | 'bundleKey'>) => b.displayName || `组合 ${b.bundleKey.slice(0, 8)}`
export const isObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v)

/** 引用冲突的处理建议按对象给出；其他错误沿用 errText（含 request-id）。 */
const inUseHint: Record<string, string> = {
  model: '模型仍被发布组合或策略引用，请先暂停或退役相关发布组合后再退役。',
  dataset: '数据集仍被评价计划引用，不能退役。',
  policy: '策略已被发布组合引用或不再是草稿，不能删除。',
  bundle: '发布组合在资产上仍有生效的绑定，请先暂停后再退役。',
  default: '该对象仍被引用，请先处理活动绑定或关联资源。',
}
export function releaseErr(e: unknown, kind: keyof typeof inUseHint = 'default') {
  if (e instanceof ApiError && e.code === 'RESOURCE_IN_USE') {
    return `${inUseHint[kind]}（409 RESOURCE_IN_USE${e.requestId ? `，request-id ${e.requestId}` : ''}）`
  }
  return errText(e)
}

/* ---------------- 名称索引（模块级缓存，写后可 refresh） ---------------- */
type IndexKey = 'models' | 'policies' | 'plans' | 'capabilities'
const index = reactive({
  models: new Map<string, ReleaseModel>(),
  policies: new Map<string, ReleasePolicy>(),
  plans: new Map<string, EvaluationPlan>(),
  capabilities: new Map<string, ReleaseCapability>(),
})
const loaded = new Map<IndexKey, Promise<void>>()
const permissionOf: Record<IndexKey, string> = { models: 'resource.read', policies: 'resource.read', plans: 'evaluation.read', capabilities: 'resource.read' }
const loaders: Record<IndexKey, () => Promise<{ items: { id: string }[] }>> = {
  models: () => releaseApi.listModels({ limit: 200 }),
  policies: () => releaseApi.listPolicies({ limit: 200 }),
  plans: () => releaseApi.listEvaluationPlans({ limit: 200 }),
  capabilities: () => releaseApi.listCapabilities({ limit: 200 }),
}

/** 读取名称索引；无权限或失败时保持为空，调用方显示截断 ID。force 用于写后刷新。 */
export function ensureIndex(key: IndexKey, force = false): Promise<void> {
  if (!can(permissionOf[key])) return Promise.resolve()
  if (!force && loaded.has(key)) return loaded.get(key)!
  const p = loaders[key]()
    .then((page) => { (index as Record<IndexKey, Map<string, unknown>>)[key] = new Map(page.items.map((x) => [x.id, x])) })
    .catch(() => { loaded.delete(key) })
  loaded.set(key, p)
  return p
}

export const releaseIndex = index
export const modelName = (id: string | null | undefined) => {
  if (!id) return '—'
  const m = index.models.get(id)
  return m ? modelTitle(m) : `模型 ${short(id)}`
}
export const policyName = (id: string | null | undefined) => {
  if (!id) return '—'
  const p = index.policies.get(id)
  // 有显示名时它已包含 P 编号与用途，不再拼技术版本串。
  return p ? (p.displayName || `${p.policyKey} · ${p.version}`) : `策略 ${short(id)}`
}
export const planName = (id: string | null | undefined) => {
  if (!id) return '—'
  const p = index.plans.get(id)
  return p ? p.planKey : `计划 ${short(id)}`
}
export const capabilityName = (id: string | null | undefined) => {
  if (!id) return '—'
  const c = index.capabilities.get(id)
  return c ? c.capabilityKey : `能力 ${short(id)}`
}

/** 能力载荷中的业务字段（登记时的原始请求体，不含证据位置）。 */
export function capabilityFacts(c: ReleaseCapability) {
  const p = isObject(c.payload) ? c.payload : {}
  const str = (k: string) => (typeof p[k] === 'string' ? p[k] as string : null)
  const scope = Array.isArray(p.behaviorScope) ? (p.behaviorScope as unknown[]).map(String) : []
  const latency = isObject(p.latencyLimits) && typeof p.latencyLimits.maxMs === 'number' ? p.latencyLimits.maxMs : null
  return {
    family: str('family'), profile: str('profile'), direction: str('direction'), transport: str('transport'),
    addressFamily: str('addressFamily'), adapterVersion: str('adapterVersion'), behaviorScope: scope, maxMs: latency,
  }
}
