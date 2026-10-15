/**
 * F3 策略上传预校验：直接编译仓库的 2020-12 Schema，不复制或修改冻结契约。
 * 此处只判断结构与可本地证明的不变量；模型归属、签名、能力和独立批准仍由后端裁决。
 */
import Ajv2020 from 'ajv/dist/2020'
import addFormats from 'ajv-formats'
import schema from '../../../../docs/contracts/decision-policy.schema.json'
import featureProfile from '../../../../docs/contracts/feature-profile.json'

export type AttackFamily = 'port_scan' | 'brute_force' | 'dos_flood' | 'dos_slow'
export type FlowProfile = 'flow-prefix-v1' | 'flow-final-v1'
export interface FamilyPolicy {
  family: AttackFamily
  autoEligible: boolean
  modelAutoEligible: boolean
  alertThreshold: number
  autoThreshold: number
  minDistinctFlows: number
  scope: 'peer_service' | 'peer_inbound'
}
export interface RulePolicy {
  ruleId: string
  family: AttackFamily
  field: string
  operator: 'gte' | 'gt' | 'lte' | 'lt' | 'eq'
  threshold: number
  autoEligible: boolean
}
export interface DecisionPolicy {
  contractVersion: 'host-guard/5.0.0-rc.4'
  policyId: string
  policyVersion: string
  mode: 'alert_only' | 'auto'
  modelId: string
  family: string
  familyPolicies: FamilyPolicy[]
  rulePolicies?: RulePolicy[]
  profile: FlowProfile
  acceptedProfiles?: FlowProfile[]
  alertThreshold: number
  autoThreshold: number
  minDistinctFlows: number
  minEvidenceSpanMs: number
  episodeSeconds: 30
  contextWindowSeconds: 1 | 5 | 30
  minPeerFlowStarts: number
  maxEvidenceAgeMs: number
  maxTtlSeconds: number
  maxContinuousBlockSeconds: number
  maxActiveRulesPerAsset: number
  maxNewActionsPerMinute: number
  supportedCapabilityIds: string[]
  protectionSetSha256: string
  evaluationPlanSha256: string
}

/** path 使用 JSON Pointer，可直接映射到表单字段或 JSON 编辑器。 */
export interface PolicyIssue { path: string; code: string; message: string }
export type PolicyCheck = { valid: true; policy: DecisionPolicy; issues: [] } | { valid: false; issues: PolicyIssue[] }

const ajv = new Ajv2020({ allErrors: true, strict: true })
addFormats(ajv)
const validate = ajv.compile<DecisionPolicy>(schema)

/** 接受已解析 JSON 或上传原文；非法原文只返回通用错误，不把上传内容回显到日志或异常。 */
export function validateDecisionPolicy(input: unknown): PolicyCheck {
  let value = input
  if (typeof input === 'string') {
    try { value = JSON.parse(input) }
    catch { return { valid: false, issues: [{ path: '', code: 'INVALID_JSON', message: '策略文件必须是有效的 JSON。' }] } }
  }
  if (!validate(value)) {
    return { valid: false, issues: (validate.errors ?? []).map((error) => ({
      path: `${error.instancePath}${error.keyword === 'required' ? `/${error.params.missingProperty}` : error.keyword === 'additionalProperties' ? `/${error.params.additionalProperty}` : ''}`,
      code: 'SCHEMA_INVALID',
      message: `不符合策略 Schema：${error.message ?? error.keyword}`,
    })) }
  }
  const issues: PolicyIssue[] = []
  const issue = (path: string, code: string, message: string) => { issues.push({ path, code, message }) }
  const families = new Set<string>()
  value.familyPolicies.forEach((family, index) => {
    const path = `/familyPolicies/${index}`
    if (families.has(family.family)) issue(`${path}/family`, 'INVALID_FAMILY_POLICIES', '四个攻击类别必须各出现一次。')
    families.add(family.family)
    if (family.scope !== (family.family === 'port_scan' ? 'peer_inbound' : 'peer_service')) issue(`${path}/scope`, 'INVALID_FAMILY_SCOPE', '该类别的证据作用域不符合契约。')
    if (family.autoThreshold < family.alertThreshold) issue(`${path}/autoThreshold`, 'INVALID_POLICY_THRESHOLDS', '自动阈值不得低于告警阈值。')
    if (family.modelAutoEligible && !family.autoEligible) issue(`${path}/modelAutoEligible`, 'INVALID_FAMILY_POLICIES', '模型自动资格要求该类别允许自动路径。')
  })
  const rules = new Set<string>()
  value.rulePolicies?.forEach((rule, index) => {
    if (rules.has(rule.ruleId)) issue(`/rulePolicies/${index}/ruleId`, 'INVALID_RULE_POLICY', '规则编号不得重复。')
    rules.add(rule.ruleId)
    if (!featureProfile.numericFeatures.includes(rule.field)) issue(`/rulePolicies/${index}/field`, 'INVALID_RULE_FIELD', '规则只能引用契约登记的数值特征。')
  })
  if (value.autoThreshold < value.alertThreshold) issue('/autoThreshold', 'INVALID_POLICY_THRESHOLDS', '自动阈值不得低于告警阈值。')
  if (value.minEvidenceSpanMs > value.maxEvidenceAgeMs) issue('/minEvidenceSpanMs', 'INVALID_POLICY_THRESHOLDS', '最短证据跨度不得超过证据有效期。')
  if (value.acceptedProfiles && !value.acceptedProfiles.includes(value.profile)) issue('/acceptedProfiles', 'INVALID_POLICY_PROFILES', '允许的快照类型必须包含主类型。')
  return issues.length ? { valid: false, issues } : { valid: true, policy: value, issues: [] }
}

export class DecisionPolicyValidationError extends Error {
  readonly code = 'POLICY_PREVALIDATION_FAILED'
  constructor(public readonly issues: PolicyIssue[]) {
    super(issues.map((issue) => `${issue.path || '/'}：${issue.message}`).join('；'))
    this.name = 'DecisionPolicyValidationError'
  }
}

/** 起草前必经入口；失败时尚未发送请求，也不产生服务端状态。 */
export function requireDecisionPolicy(input: unknown): DecisionPolicy {
  const result = validateDecisionPolicy(input)
  if (!result.valid) throw new DecisionPolicyValidationError(result.issues)
  return result.policy
}
