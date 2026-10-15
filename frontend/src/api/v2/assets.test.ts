/** F4 v2 协议、状态回读及失败边界；MSW 是合成接口，真实范围隔离另由后端集成测试验证。 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { http, HttpResponse } from 'msw'
import { api, guard, resetCsrf } from '@/api/client'
import { errText } from '@/composables/load'
import { assetsApi, type AuthorizationRequest } from './assets'
import { server, requests } from '@/test/handlers'
import { signIn } from '@/test/handlers/auth'
import { ASSET_1, ASSET_2, resetDetectState } from '@/test/handlers/detect'
import { assetsState, resetAssetsState } from '@/test/handlers/assets'
import { releaseState, resetReleaseState, RELEASE_IDS } from '@/test/handlers/release'
import { configDefinition, F4_IDS } from '@/test/fixtures/assets'
import { me, singleRoleUsers } from '@/test/roles'

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
afterAll(() => server.close())
beforeEach(() => { resetDetectState(); resetAssetsState(); resetReleaseState(); resetCsrf(); requests.length = 0; signIn(singleRoleUsers.platform_admin) })
afterEach(() => server.resetHandlers())
const authorization = (): AuthorizationRequest => ({ interfaces: ['fixture0'], observationAllowed: true, executionScopes: [], validFrom: new Date(Date.now() - 1000).toISOString(), validUntil: new Date(Date.now() + 86_400_000).toISOString(), evidenceRef: 'fixture-authorization-reference' })

describe('F4 查询与范围', () => {
  it('资产搜索、状态、游标与详情保持同一数据；未知环境参数不伪装成后端筛选', async () => {
    expect((await assetsApi.listAssets({ q: 'host-lab', status: 'active' })).items.map((a) => a.id)).toEqual([ASSET_1])
    const first = await assetsApi.listAssets({ limit: 1 })
    const next = await assetsApi.listAssets({ cursor: first.nextCursor!, limit: 2 })
    expect(next.items).toHaveLength(1); expect(next.nextCursor).toBeNull()
    expect(next.items[0].id).not.toBe(first.items[0].id)
    expect((await assetsApi.getAsset(ASSET_1)).assetKey).toBe('host-lab-01')
    await expect(guard.read('assets', { environment: 'lab' })).rejects.toMatchObject({ code: 'INVALID_QUERY' })
    await expect(assetsApi.listAssets({ limit: 201 })).rejects.toMatchObject({ code: 'INVALID_PAGE_SIZE' })
  })

  it('游标绑定主体、集合、筛选与范围，限制后续页追加，不产生空尾页', async () => {
    const first = await assetsApi.listAssets({ limit: 1 })
    await assetsApi.createAsset({ assetKey: 'new-host', platform: 'windows', environment: 'research', owner: 'fixture' })
    expect((await assetsApi.listAssets({ cursor: first.nextCursor! })).items).toHaveLength(1)
    await expect(assetsApi.listAssets({ cursor: first.nextCursor!, status: 'active' })).rejects.toMatchObject({ code: 'INVALID_CURSOR' })
    await expect(assetsApi.listSensors({ cursor: first.nextCursor! })).rejects.toMatchObject({ code: 'INVALID_CURSOR' })
    await expect(assetsApi.listAssets({ cursor: 'tampered' })).rejects.toMatchObject({ code: 'INVALID_CURSOR' })
    signIn(singleRoleUsers.auditor)
    await expect(assetsApi.listAssets({ cursor: first.nextCursor! })).rejects.toMatchObject({ code: 'INVALID_CURSOR' })
    expect((await assetsApi.listAssets({ limit: 3 })).nextCursor).toBeNull()
  })

  it('范围在分页前过滤，跨资产详情与引用不泄露存在性，写入仍拒绝', async () => {
    const scoped = me(['platform_admin']); scoped.bindings.forEach((b) => { b.scopeType = 'asset'; b.scopeId = '1' }); signIn(scoped)
    expect((await assetsApi.listAssets({ limit: 1 })).items.map((a) => a.id)).toEqual([ASSET_1])
    expect((await assetsApi.listSensors()).items.map((s) => s.id)).toEqual([F4_IDS.sensor])
    await expect(assetsApi.getAsset(ASSET_2)).rejects.toMatchObject({ status: 404 })
    await expect(assetsApi.getSensor(F4_IDS.otherSensor)).rejects.toMatchObject({ status: 404 })
    await expect(assetsApi.listConfigs({ sensorId: F4_IDS.otherSensor })).rejects.toMatchObject({ status: 404 })
    await expect(assetsApi.updateAsset(ASSET_2, 1, { owner: 'blocked' })).rejects.toMatchObject({ status: 403 })
    expect(assetsState.writes).toEqual([])
  })

  it('授权与配置查询、详情返回本人 ID，历史空归属保留 null', async () => {
    const auths = await assetsApi.listAuthorizations({ assetId: ASSET_1, status: 'pending' })
    expect(auths.asOf).toBeTruthy()
    expect(auths.items.find((a) => a.id === F4_IDS.ownAuthorization)?.requestedBy).toBe(singleRoleUsers.platform_admin.id)
    expect((await assetsApi.getConfig(F4_IDS.ownConfig)).requestedBy).toBe(singleRoleUsers.platform_admin.id)
    assetsState.configs[0].requestedBy = null
    expect((await assetsApi.getConfig(F4_IDS.ownConfig)).requestedBy).toBeNull()
    expect((await assetsApi.listConfigs({ sensorId: F4_IDS.sensor, status: 'draft' })).items).toHaveLength(2)
    expect(JSON.stringify(auths)).not.toContain('evidenceRef')
  })

  it('机器客户端只走 v2；两类心跳与窗口分开，健康未知和回放不冒充现场健康', async () => {
    const clients = await assetsApi.listMachineClients({ assetId: ASSET_1, clientType: 'sensor' })
    expect(clients.items.map((c) => c.id)).toEqual([F4_IDS.sensorClient])
    expect(JSON.stringify(clients)).not.toMatch(/credential|secret|token/i)
    expect((await assetsApi.listSensorHeartbeats()).items.find((h) => h.id === F4_IDS.sensor)?.healthState).toBe('healthy')
    assetsState.executorHeartbeats[0].healthState = 'unknown'
    assetsState.executorHeartbeats[0].receivedAt = null
    assetsState.executorHeartbeats[0].freshness = 'no_record'
    expect((await assetsApi.listExecutorHeartbeats()).items[0].healthState).toBe('unknown')
    const windows = await assetsApi.listHealthWindows({ sensorId: F4_IDS.sensor })
    expect(windows.items.map((w) => w.healthState).sort()).toEqual(['healthy', 'replay_healthy', 'stale', 'unhealthy', 'unknown'])
    const replay = (await assetsApi.listHealthWindows({ verificationStatus: 'replay_healthy' })).items[0]
    expect(replay).toMatchObject({ captureSource: 'file_replay', serverVerifiedHealthy: false, counterEnd: { kernelDrops: null } })
    expect(requests).toContain('GET /api/v2/machine-clients')
    expect(requests.some((r) => r.includes('/api/v1/') || r.endsWith('/heartbeats'))).toBe(false)
  })

  it('发布与绑定读取沿用 v2 子资源，不虚构按资产的绑定集合', async () => {
    releaseState.rows['release-bundles'].find((b) => b.id === RELEASE_IDS.approvedBundle)!.status = 'active'
    expect((await assetsApi.listBundles('active')).items.some((b) => b.id === RELEASE_IDS.approvedBundle)).toBe(true)
    expect((await assetsApi.listBundleBindings(RELEASE_IDS.approvedBundle)).items).toHaveLength(1)
    expect((await assetsApi.listCapabilities()).items.length).toBeGreaterThan(0)
  })

  it('未登录 401、无功能权限 403；只读审计身份不允许写入', async () => {
    signIn(singleRoleUsers.security_analyst)
    await expect(assetsApi.listHealthWindows()).rejects.toMatchObject({ status: 403 })
    await expect(assetsApi.listMachineClients()).rejects.toMatchObject({ status: 403 })
    signIn(singleRoleUsers.auditor)
    await expect(assetsApi.updateAsset(ASSET_1, 1, { status: 'disabled' })).rejects.toMatchObject({ status: 403 })
    signIn(null)
    await expect(assetsApi.listAssets()).rejects.toMatchObject({ status: 401, requestId: 'req-f2-error' })
    expect(assetsState.writes).toEqual([])
  })
})

describe('F4 写入与失败边界', () => {
  it('登记、编辑与生命周期写后可重读，停用暂停绑定，启用不恢复，退役拒绝再启用', async () => {
    const created = await assetsApi.createAsset({ assetKey: 'fixture-new', platform: 'macos', environment: 'research', owner: 'fixture-owner' })
    expect(await assetsApi.getAsset(created.id)).toMatchObject({ revision: 1, status: 'active', criticality: 'medium' })
    await assetsApi.updateAsset(created.id, 1, { displayName: '新显示名', notes: '测试说明', owner: 'new-owner', criticality: 'critical' })
    expect(await assetsApi.getAsset(created.id)).toMatchObject({ revision: 2, displayName: '新显示名', criticality: 'critical' })
    const binding = releaseState.bindings[RELEASE_IDS.approvedBundle][0]; binding.assetId = created.id; binding.status = 'active'
    await assetsApi.updateAsset(created.id, 2, { status: 'disabled' })
    expect(binding.status).toBe('suspended')
    await assetsApi.updateAsset(created.id, 3, { status: 'active' })
    expect(binding.status).toBe('suspended')
    await assetsApi.updateAsset(created.id, 4, { status: 'retired' })
    await expect(assetsApi.updateAsset(created.id, 5, { status: 'active' })).rejects.toMatchObject({ code: 'STATE_CONFLICT' })
    expect((await assetsApi.getAsset(created.id)).status).toBe('retired')
    expect(assetsState.writes.map((w) => w.ifMatch)).toEqual([null, '1', '2', '3', '4'])
    expect(new Set(assetsState.writes.map((w) => w.key)).size).toBe(5)
  })

  it('普通写入同键重放只变更一次；换内容或修订冲突，不自动重试', async () => {
    const key = crypto.randomUUID(), body = { owner: 'idempotent-owner' }
    const result = await assetsApi.updateAsset(ASSET_1, 1, body, key)
    expect(await assetsApi.updateAsset(ASSET_1, 1, body, key)).toEqual(result)
    expect(assetsState.writes).toHaveLength(1)
    await expect(assetsApi.updateAsset(ASSET_1, 1, { owner: 'changed' }, key)).rejects.toMatchObject({ code: 'IDEMPOTENCY_CONFLICT' })
    await expect(assetsApi.updateAsset(ASSET_1, 1, body)).rejects.toMatchObject({ code: 'REVISION_CONFLICT', message: expect.stringContaining('刷新') })
    expect((await assetsApi.getAsset(ASSET_1)).revision).toBe(2)
  })

  it.each([409, 412])('HTTP %s 修订冲突提示刷新并保留 request-id，只发一次请求', async (status) => {
    let count = 0
    server.use(http.patch('/api/v2/assets/:id', () => { count++; return HttpResponse.json({ requestId: 'req-stale', data: null, error: { code: 'REVISION_CONFLICT', message: 'stale' } }, { status }) }))
    const error = await assetsApi.updateAsset(ASSET_1, 1, { owner: 'stale' }).catch((e: unknown) => e)
    expect(errText(error)).toContain('刷新后重试。'); expect(errText(error)).toContain('request-id req-stale'); expect(count).toBe(1)
  })

  it('授权申请、本人撤回与独立批准/驳回/撤销均回写状态；本人审批与代人撤回拒绝', async () => {
    const request = await assetsApi.requestAuthorization(ASSET_1, authorization())
    await expect(assetsApi.withdrawAuthorization(F4_IDS.authorization, 1, '他人申请')).rejects.toMatchObject({ status: 403 })
    await assetsApi.withdrawAuthorization(request.id, 1, '本人撤回')
    expect((await assetsApi.listAuthorizations({ status: 'revoked' })).items.some((a) => a.id === request.id)).toBe(true)
    signIn(me(['security_reviewer'], singleRoleUsers.platform_admin.id))
    await expect(assetsApi.decideAuthorization(F4_IDS.ownAuthorization, 1, 'approve', '自批')).rejects.toMatchObject({ code: 'APPROVAL_SEPARATION_REQUIRED' })
    signIn(singleRoleUsers.security_reviewer)
    const approved = await assetsApi.decideAuthorization(F4_IDS.authorization, 1, 'approve', '独立批准')
    expect(approved).toMatchObject({ status: 'active', revision: 2 })
    await assetsApi.revokeAuthorization(approved.id, 2, '到期收回')
    expect((await assetsApi.listAuthorizations({ status: 'revoked' })).items.find((a) => a.id === approved.id)?.revision).toBe(3)
    await assetsApi.decideAuthorization(F4_IDS.ownAuthorization, 1, 'reject', '不符合范围')
    expect(assetsState.authorizations.find((a) => a.id === F4_IDS.ownAuthorization)?.status).toBe('revoked')
  })

  it.each(['sensors', 'executors'] as const)('%s 登记与轮换凭据只返回一次，启用不恢复旧凭据，吊销后为终态', async (kind) => {
    const key = crypto.randomUUID()
    const issued = kind === 'sensors' ? await assetsApi.createSensor({ assetId: ASSET_1, platform: 'macos', captureScopeId: crypto.randomUUID() }, key) : await assetsApi.createExecutor({ assetId: ASSET_1, platform: 'macos', capabilityProbeRef: 'fixture-probe' }, key)
    expect(issued.credential).toBeTruthy()
    const get = () => kind === 'sensors' ? assetsApi.getSensor(issued.id) : assetsApi.getExecutor(issued.id)
    await assetsApi.updateMachine(kind, issued.id, 1, { displayName: '新设备' })
    await assetsApi.changeMachineStatus(kind, issued.id, 2, 'disabled', '维护')
    expect((await get()).status).toBe(kind === 'sensors' ? 'offline' : 'suspended')
    expect(await assetsApi.changeMachineStatus(kind, issued.id, 3, 'active', '恢复')).toMatchObject({ credentialRotationRequired: true })
    expect(assetsState.clients.find((c) => c.id === issued.clientId)?.status).toBe('revoked')
    const rotationKey = crypto.randomUUID(), rotated = await assetsApi.rotateCredential(kind, issued.id, '轮换', rotationKey)
    await expect(assetsApi.rotateCredential(kind, issued.id, '轮换', rotationKey)).rejects.toMatchObject({ code: 'CREDENTIAL_ALREADY_ISSUED' })
    expect(rotated.credential).not.toBe(issued.credential)
    expect(JSON.stringify(assetsState)).not.toContain(issued.credential)
    expect(JSON.stringify(assetsState)).not.toContain(rotated.credential)
    await assetsApi.revokeMachineClient(issued.clientId, '撤销接入')
    expect((await get()).status).toBe('revoked')
    await expect(assetsApi.changeMachineStatus(kind, issued.id, 5, 'active', '不允许恢复')).rejects.toMatchObject({ code: 'STATE_CONFLICT' })
    await expect(assetsApi.rotateCredential(kind, issued.id, '')).rejects.toMatchObject({ code: 'STATE_CONFLICT' })
  })

  it('登记同键重放不二次签发、不新增设备，DELETE 携带修订且无正文', async () => {
    const key = crypto.randomUUID(), body = { assetId: ASSET_1, platform: 'macos' as const, captureScopeId: crypto.randomUUID() }
    await assetsApi.createSensor(body, key)
    await expect(assetsApi.createSensor(body, key)).rejects.toMatchObject({ code: 'CREDENTIAL_ALREADY_ISSUED' })
    expect(assetsState.sensors).toHaveLength(3)
    let deletion!: Request
    server.events.on('request:start', function capture({ request }) { if (request.method === 'DELETE') deletion = request })
    await assetsApi.deleteConfig(F4_IDS.ownConfig, 1)
    expect(deletion.headers.get('If-Match')).toBe('1'); expect(deletion.headers.get('Idempotency-Key')).toBeTruthy(); expect(deletion.body).toBeNull()
  })

  it('采集配置起草、本人删除、引用保护、独立批准和旧配置退役，不把批准冒充代理验证', async () => {
    const draft = await assetsApi.draftConfig(F4_IDS.sensor, configDefinition())
    expect(await assetsApi.getConfig(draft.id)).toMatchObject({ requestedBy: singleRoleUsers.platform_admin.id, status: 'draft', revision: 1 })
    await expect(assetsApi.deleteConfig(F4_IDS.config, 1)).rejects.toMatchObject({ status: 403 })
    assetsState.referencedConfigs.add(F4_IDS.ownConfig)
    await expect(assetsApi.deleteConfig(F4_IDS.ownConfig, 1)).rejects.toMatchObject({ code: 'RESOURCE_IN_USE' })
    await assetsApi.deleteConfig(draft.id, 1)
    await expect(assetsApi.getConfig(draft.id)).rejects.toMatchObject({ status: 404 })
    signIn(me(['security_reviewer'], singleRoleUsers.platform_admin.id))
    await expect(assetsApi.decideConfig(F4_IDS.ownConfig, 1, 'approve', '自批')).rejects.toMatchObject({ code: 'APPROVAL_SEPARATION_REQUIRED' })
    signIn(singleRoleUsers.security_reviewer)
    await assetsApi.decideConfig(F4_IDS.config, 1, 'approve', '独立批准')
    expect(await assetsApi.getConfig(F4_IDS.config)).toMatchObject({ status: 'active', revision: 2 })
    await assetsApi.decideConfig(F4_IDS.ownConfig, 1, 'approve', '批准替换')
    expect((await assetsApi.getConfig(F4_IDS.config)).status).toBe('retired')
    expect((await assetsApi.getSensor(F4_IDS.sensor)).status).toBe('active')
  })

  it('没有有效观察授权时拒绝配置批准；驳回只改变本配置，旧配置不变', async () => {
    assetsState.authorizations.find((a) => a.id === F4_IDS.activeAuthorization)!.validUntil = '2026-01-01T00:00:00Z'
    signIn(singleRoleUsers.security_reviewer)
    await expect(assetsApi.decideConfig(F4_IDS.config, 1, 'approve', '已到期')).rejects.toMatchObject({ code: 'AUTHORIZATION_INACTIVE' })
    expect((await assetsApi.getConfig(F4_IDS.config)).revision).toBe(1)
    expect(await assetsApi.decideConfig(F4_IDS.config, 1, 'reject', '授权无效')).toMatchObject({ status: 'rejected', revision: 2 })
  })

  it('缺失幂等、修订或 CSRF 的请求不产生写记录', async () => {
    await expect(api.patch(`/api/v2/assets/${ASSET_1}`, { status: 'disabled' }, { 'If-Match': '1' })).rejects.toMatchObject({ code: 'INVALID_UUID' })
    await expect(api.patch(`/api/v2/assets/${ASSET_1}`, { status: 'disabled' }, { 'Idempotency-Key': crypto.randomUUID() })).rejects.toMatchObject({ code: 'REVISION_CONFLICT' })
    const response = await fetch(`/api/v2/assets/${ASSET_1}`, { method: 'PATCH', headers: { 'Idempotency-Key': crypto.randomUUID(), 'If-Match': '1', 'Content-Type': 'application/json' }, body: JSON.stringify({ status: 'disabled' }) })
    expect(response.status).toBe(403)
    expect(assetsState.writes).toEqual([])
  })
})
