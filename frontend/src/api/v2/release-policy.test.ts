import { describe, expect, it } from 'vitest'
import { policyFixture } from '@/test/fixtures/release'
import { requireDecisionPolicy, validateDecisionPolicy } from './release-policy'

describe('F3 策略原文预校验', () => {
  it('复用契约示例，支持 JSON 对象与上传原文，保持原输入不变', () => {
    const policy = policyFixture()
    const before = JSON.stringify(policy)
    expect(validateDecisionPolicy(policy)).toMatchObject({ valid: true, policy })
    expect(requireDecisionPolicy(before)).toEqual(policy)
    expect(JSON.stringify(policy)).toBe(before)
  })

  it('非法 JSON 返回固定错误，不回显原文', () => {
    expect(validateDecisionPolicy('{uploaded-private-content')).toEqual({ valid: false, issues: [{ path: '', code: 'INVALID_JSON', message: '策略文件必须是有效的 JSON。' }] })
  })

  it.each([
    ['缺少必填项', (policy: Record<string, any>) => { delete policy.mode }, '/mode'],
    ['未知顶层字段', (policy: Record<string, any>) => { policy.approved = true }, '/approved'],
    ['未知嵌套字段', (policy: Record<string, any>) => { policy.familyPolicies[0].approved = true }, '/familyPolicies/0/approved'],
    ['非法 UUID', (policy: Record<string, any>) => { policy.modelId = 'model' }, '/modelId'],
    ['非法 SHA-256', (policy: Record<string, any>) => { policy.protectionSetSha256 = 'F'.repeat(64) }, '/protectionSetSha256'],
    ['越界 TTL', (policy: Record<string, any>) => { policy.maxTtlSeconds = 61 }, '/maxTtlSeconds'],
    ['非整数预算', (policy: Record<string, any>) => { policy.maxNewActionsPerMinute = 1.5 }, '/maxNewActionsPerMinute'],
    ['重复能力引用', (policy: Record<string, any>) => { policy.supportedCapabilityIds.push(policy.supportedCapabilityIds[0]) }, '/supportedCapabilityIds'],
    ['非有限阈值', (policy: Record<string, any>) => { policy.autoThreshold = Infinity }, '/autoThreshold'],
  ])('%s 在字段路径处报告 Schema 错误', (_, mutate, path) => {
    const policy = policyFixture()
    mutate(policy)
    const result = validateDecisionPolicy(policy)
    expect(result.valid).toBe(false)
    expect(result.issues).toContainEqual(expect.objectContaining({ path, code: 'SCHEMA_INVALID' }))
  })

  it.each([
    ['重复类别', (policy: Record<string, any>) => { policy.familyPolicies[1] = { ...policy.familyPolicies[0] } }, 'INVALID_FAMILY_POLICIES'],
    ['扫描作用域错误', (policy: Record<string, any>) => { policy.familyPolicies[0].scope = 'peer_service' }, 'INVALID_FAMILY_SCOPE'],
    ['类别阈值倒置', (policy: Record<string, any>) => { policy.familyPolicies[0].autoThreshold = 0.1 }, 'INVALID_POLICY_THRESHOLDS'],
    ['模型来源资格越界', (policy: Record<string, any>) => { policy.familyPolicies[0].modelAutoEligible = true }, 'INVALID_FAMILY_POLICIES'],
    ['全局阈值倒置', (policy: Record<string, any>) => { policy.autoThreshold = 0.1 }, 'INVALID_POLICY_THRESHOLDS'],
    ['证据时间倒置', (policy: Record<string, any>) => { policy.minEvidenceSpanMs = 20000 }, 'INVALID_POLICY_THRESHOLDS'],
    ['允许类型缺少主类型', (policy: Record<string, any>) => { policy.acceptedProfiles = ['flow-final-v1'] }, 'INVALID_POLICY_PROFILES'],
    ['未知规则特征', (policy: Record<string, any>) => { policy.rulePolicies = [{ ruleId: 'fixture', family: 'brute_force', field: 'secretField', operator: 'gte', threshold: 1, autoEligible: false }] }, 'INVALID_RULE_FIELD'],
  ])('%s 与后端静态不变量保持一致', (_, mutate, code) => {
    const policy = policyFixture()
    mutate(policy)
    const result = validateDecisionPolicy(policy)
    expect(result.valid).toBe(false)
    expect(result.issues).toContainEqual(expect.objectContaining({ code }))
  })
})
