/** 经真实客户端与 msw 验证请求协议、失败传播及写后回读，不把夹具当作后端授权证据。 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { guard, resetCsrf } from '@/api/client'
import { errText } from '@/composables/load'
import { requests, server } from '@/test/handlers'
import { signIn } from '@/test/handlers/auth'
import { labRow, policyFixture, releaseRows, releaseState, RELEASE_IDS as ids, RELEASE_SHA as sha, resetReleaseState } from '@/test/handlers/release'
import { singleRoleUsers } from '@/test/roles'
import { DecisionPolicyValidationError, MODEL_VALIDATION_PROFILE_ID, releaseApi as api, type BundleRequest } from './release'

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
afterAll(() => server.close())
beforeEach(() => { resetReleaseState(); resetCsrf(); requests.length = 0; signIn(singleRoleUsers.model_operator) })
afterEach(() => server.resetHandlers())
const reviewer = () => signIn(singleRoleUsers.security_reviewer)
const report = { reportRef: 'fixtures/report.json', sha256: sha, runnerIdentity: 'fixture-runner' }
const registration = { manifestRef: 'fixtures/manifest.json', manifestSha256: sha, displayName: '测试候选', notes: null }
const bundleRequest: BundleRequest = { modelId: ids.validatedModel, policyId: ids.reviewedPolicy, featureProfileSha256: sha, extractorSha256: sha, protocolVersions: {}, evaluationPlanId: ids.plan, capabilityIds: [ids.capability], environment: 'lab' }

describe('F3 列表、详情与子资源', () => {
  it('所有集合均读取 v2 信封与真实 DTO 形状', async () => {
    const pairs = [
      [api.listModels, api.getModel, ids.model], [api.listDatasets, api.getDataset, ids.dataset],
      [api.listBundles, api.getBundle, ids.bundle], [api.listPolicies, api.getPolicy, ids.policy],
      [api.listCapabilities, api.getCapability, ids.capability], [api.listEvaluationPlans, api.getEvaluationPlan, ids.plan],
      [api.listEvaluations, api.getEvaluation, ids.evaluation], [api.listReplayRuns, api.getReplayRun, ids.replay],
      [api.listLabRuns, api.getLabRun, ids.lab],
    ] as const
    for (const [list, get, id] of pairs) {
      expect((await list()).items.some((item) => item.id === id)).toBe(true)
      expect(await get(id)).toMatchObject({ id })
    }
    expect(requests).toHaveLength(18)
    expect(requests.every((request) => request.startsWith('GET /api/v2/'))).toBe(true)
  })

  it('搜索、状态、时间、排序与游标按契约发送，切换筛选不能复用游标', async () => {
    const filtered = await api.listModels({ q: '合成', status: 'pending', from: '2026-10-15T00:00:00Z', until: '2026-10-16T00:00:00Z', sort: 'updatedAt' })
    expect(filtered.items.map((row) => row.id)).toEqual([ids.model])
    const first = await api.listModels({ limit: 1 })
    expect(first.nextCursor).toBeTruthy()
    const second = await api.listModels({ limit: 1, cursor: first.nextCursor! })
    expect(second.items[0].id).not.toBe(first.items[0].id)
    expect(second.nextCursor).toBeNull()
    await expect(api.listModels({ cursor: first.nextCursor!, status: 'pending' })).rejects.toMatchObject({ status: 400, code: 'INVALID_CURSOR' })
    await expect(guard.read('replay-runs', { assetId: ids.asset })).rejects.toMatchObject({ status: 400, code: 'INVALID_QUERY' })
    await expect(guard.read('evaluations', { q: 'report' })).rejects.toMatchObject({ status: 400, code: 'INVALID_QUERY' })
    await expect(guard.read('capabilities', { status: 'lab_auto' })).rejects.toMatchObject({ status: 400, code: 'INVALID_QUERY' })
  })

  it('校验结果直接返回报告/null；绑定只有组合子资源；lab 事实使用 after 而不是游标', async () => {
    expect(await api.getModelValidations(ids.model)).toBeNull()
    expect(await api.getModelValidations(ids.validatedModel)).toEqual({ status: 'validated' })
    expect((await api.listBundleBindings(ids.approvedBundle)).items[0]).toMatchObject({ assetId: ids.asset })
    releaseState.events[ids.lab].push({ eventId: crypto.randomUUID(), sequence: 2, sha256: sha, fact: { kind: 'lifecycle' } })
    const first = await api.getLabEvents(ids.lab, { after: 0, limit: 1 })
    expect(first.nextAfter).toBe(1)
    expect((await api.getLabEvents(ids.lab, { after: first.nextAfter!, limit: 1 })).items[0].sequence).toBe(2)
    expect(await api.getLabReportInput(ids.lab)).toMatchObject({ runStatus: 'registered' })
    expect(await api.getLabQualifications(ids.completedLab)).toMatchObject({ sources: [] })
    expect(requests).not.toContain('GET /api/v2/bindings')
  })

  it('401、403、404 与 request-id 原样传播', async () => {
    signIn(null)
    await expect(api.listModels()).rejects.toMatchObject({ status: 401, requestId: 'req-release-error' })
    signIn(singleRoleUsers.security_analyst)
    await expect(api.listEvaluations()).rejects.toMatchObject({ status: 403, code: 'SCOPE_DENIED' })
    signIn(singleRoleUsers.model_operator)
    await expect(api.getModel(crypto.randomUUID())).rejects.toMatchObject({ status: 404, code: 'RESOURCE_NOT_FOUND' })
  })
})

describe('F3 登记、资料与并发控制', () => {
  it('模型与数据集的登记/编辑/校验/退役可回读，校验 profile 固定', async () => {
    const model = await api.registerModel(registration)
    expect(model).toMatchObject({ candidateOnly: true, validationStatus: 'pending', revision: 1 })
    await api.updateModel(model.id, 1, { displayName: '修改后的模型', notes: null })
    expect(await api.getModel(model.id)).toMatchObject({ displayName: '修改后的模型', notes: null, revision: 2 })
    expect(await api.validateModel(model.id)).toEqual({ status: 'validated' })
    expect(releaseState.writes.at(-1)?.body).toEqual({ validationProfileId: MODEL_VALIDATION_PROFILE_ID })
    expect(await api.getModelValidations(model.id)).toEqual({ status: 'validated' })
    await api.retireModel(model.id, 3, '停止使用候选')
    expect(await api.getModel(model.id)).toMatchObject({ validationStatus: 'retired', revision: 4 })
    const dataset = await api.registerDataset(registration)
    await api.updateDataset(dataset.id, 1, { notes: '修正说明', displayName: null })
    await api.retireDataset(dataset.id, 2, '数据集退役')
    expect(await api.getDataset(dataset.id)).toMatchObject({ notes: '修正说明', displayName: null, status: 'retired', revision: 3 })
    expect(releaseState.writes.every((write) => /^[0-9a-f-]{36}$/i.test(write.idempotencyKey ?? ''))).toBe(true)
    expect(new Set(releaseState.writes.map((write) => write.idempotencyKey)).size).toBe(releaseState.writes.length)
    expect(releaseState.writes.filter((write) => write.method === 'PATCH').every((write) => write.ifMatch)).toBe(true)
  })

  it('同键重试只写一次，同键不同体冲突，旧 revision 冲突不覆盖资料', async () => {
    const key = crypto.randomUUID()
    const first = await api.updateDataset(ids.dataset, 1, { notes: '同一次提交' }, key)
    expect(await api.updateDataset(ids.dataset, 1, { notes: '同一次提交' }, key)).toEqual(first)
    await expect(api.updateDataset(ids.dataset, 1, { notes: '另一内容' }, key)).rejects.toMatchObject({ status: 409, code: 'IDEMPOTENCY_CONFLICT' })
    await expect(api.updateDataset(ids.dataset, 1, { notes: '过期编辑' })).rejects.toMatchObject({ status: 409, code: 'REVISION_CONFLICT' })
    expect(await api.getDataset(ids.dataset)).toMatchObject({ notes: '同一次提交', revision: 2 })
  })

  it('引用冲突保留 409 说明与 request-id，非操作角色不能写入', async () => {
    try { await api.retireModel(ids.validatedModel, 1, '仍被引用') }
    catch (error) { expect(errText(error)).toContain('该对象仍被引用'); expect(errText(error)).toContain('request-id req-release-error') }
    expect(await api.getModel(ids.validatedModel)).toMatchObject({ validationStatus: 'validated' })
    signIn(singleRoleUsers.auditor)
    await expect(api.updateModel(ids.model, 1, { notes: '不可写' })).rejects.toMatchObject({ status: 403 })
  })

  it('组合与策略只改显示名；组合审核侧也可改名，策略只限起草侧，名称可搜索', async () => {
    await api.updateBundle(ids.bundle, 1, { displayName: 'R9 · lab · 合成验收', notes: '命名规范示例' })
    expect(await api.getBundle(ids.bundle)).toMatchObject({ displayName: 'R9 · lab · 合成验收', notes: '命名规范示例', revision: 2, status: 'candidate' })
    expect(releaseState.writes.at(-1)).toMatchObject({ method: 'PATCH', ifMatch: '1' })
    await api.updatePolicy(ids.policy, 1, { displayName: 'P9 · 合成只告警' })
    expect(await api.getPolicy(ids.policy)).toMatchObject({ displayName: 'P9 · 合成只告警', revision: 2 })
    expect((await api.listBundles({ q: 'R9' })).items.map((b) => b.id)).toContain(ids.bundle)
    reviewer()
    await api.updateBundle(ids.bundle, 2, { notes: null })
    expect(await api.getBundle(ids.bundle)).toMatchObject({ notes: null, revision: 3 })
    await expect(api.updatePolicy(ids.policy, 2, { displayName: '越权' })).rejects.toMatchObject({ status: 403 })
    signIn(singleRoleUsers.auditor)
    await expect(api.updateBundle(ids.bundle, 3, { displayName: '越权' })).rejects.toMatchObject({ status: 403 })
  })

  it('策略起草必须先预校验；本人草稿删除带 If-Match，重试无重复副作用', async () => {
    expect(() => api.draftPolicy('{invalid')).toThrow(DecisionPolicyValidationError)
    expect(requests).toEqual([])
    const policy = { ...policyFixture(), policyId: crypto.randomUUID() }
    const created = await api.draftPolicy(JSON.stringify(policy))
    expect(await api.getPolicy(created.id)).toMatchObject({ status: 'draft', definition: policy })
    const key = crypto.randomUUID()
    await expect(api.deletePolicy(created.id, 1, key)).resolves.toMatchObject({ status: 'deleted' })
    await expect(api.deletePolicy(created.id, 1, key)).resolves.toMatchObject({ status: 'deleted' })
    expect(releaseState.writes.at(-1)).toMatchObject({ method: 'DELETE', ifMatch: '1', body: undefined })
    await expect(api.getPolicy(created.id)).rejects.toMatchObject({ status: 404 })
    await expect(api.deletePolicy(ids.reviewedPolicy, 1)).rejects.toMatchObject({ status: 409, code: 'RESOURCE_IN_USE' })
  })

  it('审核由另一人完成，状态按选择回写', async () => {
    releaseState.owners[ids.policy] = singleRoleUsers.security_reviewer.id
    reviewer()
    await expect(api.reviewPolicy(ids.policy, 1, { decision: 'approve', reason: '本人不可审核' })).rejects.toMatchObject({ status: 403, code: 'APPROVAL_SEPARATION_REQUIRED' })
    releaseState.owners[ids.policy] = singleRoleUsers.model_operator.id
    await api.reviewPolicy(ids.policy, 1, { decision: 'approve', reason: '独立审核通过' })
    expect(await api.getPolicy(ids.policy)).toMatchObject({ status: 'reviewed', revision: 2 })
  })
})

describe('F3 发布与验证记录', () => {
  it('组合申请→导入→封存→独立批准→激活→暂停→退役，各步带正确 revision', async () => {
    const created = await api.requestBundle(bundleRequest)
    const imported = await api.importBundleReport(created.id, report)
    expect((await api.listEvaluations()).items.some((row) => row.id === imported.id)).toBe(true)
    await api.sealBundle(created.id, 1, [imported.id])
    expect(await api.getBundle(created.id)).toMatchObject({ status: 'evaluated', revision: 2 })
    reviewer()
    await api.decideBundle(created.id, 2, { decision: 'approve', reason: '独立审核' })
    await api.activateBundle(created.id, 3, { assetIds: [ids.asset], authorizationIds: [ids.authorization] })
    expect((await api.listBundleBindings(created.id)).items[0]).toMatchObject({ status: 'active' })
    await api.suspendBundle(created.id, 4, { reason: '暂停验证', revokeExisting: true })
    expect((await api.listBundleBindings(created.id)).items[0]).toMatchObject({ status: 'suspended' })
    await api.retireBundle(created.id, 5, '验证完成')
    expect(await api.getBundle(created.id)).toMatchObject({ status: 'retired', revision: 6 })
    expect(releaseState.writes.filter((write) => /sealings|decisions|activations|suspensions|retirements/.test(write.path)).map((write) => write.ifMatch)).toEqual(['1', '2', '3', '4', '5'])
    expect(releaseState.writes.find((write) => write.path.endsWith('/imports'))?.ifMatch).toBeNull()
  })

  it('冻结计划保留原摘要，能力登记保留 scope；候选组合由申请方撤回', async () => {
    const plan = await api.registerEvaluationPlan({ planRef: 'fixtures/p6-plan.json', planSha256: sha })
    expect(await api.getEvaluationPlan(plan.id)).toMatchObject({ planSha256: sha })
    const capability = await api.registerCapability({ capabilityKey: 'fixture-new', version: '1', platform: 'macos', adapterVersion: 'fixture', addressFamily: 'ipv4', transport: 'tcp', direction: 'inbound', family: 'brute_force', profile: 'flow-prefix-v1', behaviorScope: [], latencyLimits: {}, level: 'research', evidenceRef: 'fixtures/proof.json', evidenceSha256: sha, runnerIdentity: 'fixture-runner' })
    expect(await api.getCapability(capability.id)).toMatchObject({ level: 'research', scope: 'peer_service' })
    await api.retireBundle(ids.bundle, 1, '撤回候选')
    expect(await api.getBundle(ids.bundle)).toMatchObject({ status: 'retired' })
  })

  it('研究回放固定 1 倍速并回写运行/完成/失败状态', async () => {
    const created = await api.createReplayRun({ scenarioId: crypto.randomUUID(), scenarioSha256: sha, modelId: ids.model, policyId: ids.policy, speed: 1 })
    await api.startReplayRun(created.id, { scenarioRef: 'fixtures/scenario.json', closeoutRef: 'fixtures/closeout.json', bindings: [] })
    expect(await api.getReplayRun(created.id)).toMatchObject({ status: 'running', speed: 1 })
    await api.completeReplayRun(created.id, { reportRef: 'fixtures/report.json', reportSha256: sha })
    expect(await api.getReplayRun(created.id)).toMatchObject({ status: 'completed' })
    await api.failReplayRun(ids.replay, { reasonCode: 'FIXTURE_STOP', reason: '合成回放取消' })
    expect(await api.getReplayRun(ids.replay)).toMatchObject({ status: 'failed' })
    expect(releaseState.writes.every((write) => write.ifMatch === null)).toBe(true)
  })

  it('lab 资格、运行与追加事实分开回写；合成报告不授予自动资格', async () => {
    const created = await api.createLabRun({ sessionRef: 'fixtures/session.json', sha256: sha, runnerIdentity: 'fixture-runner' })
    expect(created).toMatchObject({ eligibilityStatus: 'pending', runStatus: 'registered' })
    reviewer()
    await api.decideLabRun(created.id, 1, { decision: 'approve', reason: '独立批准合成会话' })
    signIn(singleRoleUsers.model_operator)
    await api.startLabRun(created.id, 2)
    await api.interruptLabRun(created.id, 3, '暂停合成 runner')
    await api.resumeLabRun(created.id, 4)
    const eventId = crypto.randomUUID()
    await api.appendLabFact(created.id, 5, { eventId, scenarioId: crypto.randomUUID(), kind: 'decision', referenceId: crypto.randomUUID() })
    expect((await api.getLabEvents(created.id)).items[0]).toMatchObject({ eventId })
    await api.completeLabRun(created.id, 6, { outcome: 'completed', reason: '合成运行完成' })
    expect(await api.importLabReport(created.id, 7, report)).toMatchObject({ passed: false, qualificationEffect: 'none', qualifiedSources: [] })
    expect((await api.getLabQualifications(created.id)).sources).toEqual([])
    await api.reconcileLabRun(created.id, 8)
    reviewer()
    await api.revokeLabRun(created.id, 9, '作废测试资格')
    expect(await api.getLabRun(created.id)).toMatchObject({ effectiveEligibility: 'revoked', runStatus: 'completed', executionAuthority: false, cleanupStatus: 'not_asserted', revision: 10 })
    expect(labRow(created.id).executionAuthority).toBe(false)
    expect(releaseRows('evaluations').some((row) => row.runKind === 'canary' && row.status === 'failed')).toBe(true)
  })
})
