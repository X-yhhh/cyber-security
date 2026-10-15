/**
 * F4 状态接口夹具：资产、授权、设备、配置、机器凭据及健康投影。
 * 校验范围、职责分离、修订与幂等；只在内存中回写，不执行采集、命令或防火墙动作。
 * 一次性凭据由响应临时生成，不保存到状态、写记录或幂等缓存；重放返回已签发错误。
 */
import { http } from 'msw'
import type { Asset, Authorization, ConfigDraft, Executor, Sensor, SensorConfig } from '@/api/v2/assets'
import { CAPTURE_CONTRACT, CAPTURE_HEALTH_VERSIONS, INTERFACE_RE, MAX_BATCH_SIZE, SHA256_RE } from '@/api/v2/assets'
import { isUuid } from '@/api/v2/detect'
import { createAssetsFixture } from '@/test/fixtures/assets'
import { currentUser } from './auth'
import { detectState } from './detect'
import { releaseState } from './release'
import { fixtureCan, fixtureFail, fixtureOk } from './access'

export interface AssetWrite { method: string; path: string; key: string; ifMatch: string | null }
function initialState() { return { ...createAssetsFixture(), writes: [] as AssetWrite[], referencedConfigs: new Set<string>() } }
export let assetsState = initialState()
const replays = new Map<string, { fingerprint: string; data?: unknown; status: number; credential: boolean }>()
// 不透明游标仅保存于夹具内存，绑定主体、权限、范围与筛选；不是服务端加密游标的实现。
const cursors = new Map<string, { binding: string; ids: string[]; offset: number; asOf: string }>()
export function resetAssetsState() { assetsState = initialState(); replays.clear(); cursors.clear() }

class FixtureError extends Error { constructor(readonly status: number, readonly code: string) { super(code) } }
function check(value: unknown, status: number, code: string): asserts value { if (!value) throw new FixtureError(status, code) }
function user() { const u = currentUser(); check(u, 401, 'UNAUTHENTICATED'); return u }
function authorize(permission: string, assetId?: string | null, read = false) {
  const u = user()
  check(fixtureCan(u, permission), 403, 'SCOPE_DENIED')
  check(fixtureCan(u, permission, assetId), read ? 404 : 403, read ? 'RESOURCE_NOT_FOUND' : 'SCOPE_DENIED')
  return u
}
async function reply(fn: () => unknown | Promise<unknown>, status = 200) {
  try { user(); return fixtureOk(await fn(), status) } catch (e) {
    if (!(e instanceof FixtureError)) throw e
    return fixtureFail(e.status, e.code, e.code === 'REVISION_CONFLICT' ? '资源已更新，请刷新后重试' : '操作未完成')
  }
}
const assetRows = () => detectState.assets as Asset[]
function find<T extends { id: string }>(rows: T[], id: string) { const row = rows.find((r) => r.id === id); check(row, 404, 'RESOURCE_NOT_FOUND'); return row }
const asset = (id: string) => find(assetRows(), id)
const devices = (kind: 'sensors' | 'executors') => kind === 'sensors' ? assetsState.sensors : assetsState.executors
function revision(request: Request, row: { revision: number }) { check(request.headers.get('If-Match') === String(row.revision), 409, 'REVISION_CONFLICT') }
function fields(body: Record<string, unknown>, required: string[], optional: string[] = []) {
  check(required.every((k) => k in body) && Object.keys(body).every((k) => required.includes(k) || optional.includes(k)), 400, 'INVALID_REQUEST')
}
function reason(body: Record<string, unknown>) { check(typeof body.reason === 'string' && body.reason.trim(), 400, 'INVALID_REQUEST') }
function separate(row: { requestedBy?: number | string | null }) { check(String(row.requestedBy) !== String(user().id), 403, 'APPROVAL_SEPARATION_REQUIRED') }
function owner(row: { requestedBy?: number | string | null }) { check(row.requestedBy != null && String(row.requestedBy) === String(user().id), 403, 'SCOPE_DENIED') }

/** 重放先匹配原请求，再返回原响应；凭据响应永不缓存，换路径/修订/内容也不能复用同一键。 */
async function write(request: Request, permission: string, assetId: string | null, status: number, run: (body: Record<string, unknown>) => unknown, credential = false) {
  const actor = authorize(permission, assetId)
  const key = request.headers.get('Idempotency-Key') ?? ''
  check(isUuid(key), 400, 'INVALID_UUID')
  check(request.headers.get('X-CSRF-TOKEN') === 'csrf-test', 403, 'CSRF_INVALID')
  const body = request.method === 'DELETE' ? {} : await request.json() as Record<string, unknown>
  check(body && !Array.isArray(body) && typeof body === 'object', 400, 'INVALID_REQUEST')
  const path = new URL(request.url).pathname, ifMatch = request.headers.get('If-Match')
  const fingerprint = JSON.stringify([request.method, path, body, ifMatch])
  const replayKey = `${actor.id}:${key}`, replay = replays.get(replayKey)
  if (replay) {
    check(replay.fingerprint === fingerprint, 409, 'IDEMPOTENCY_CONFLICT')
    check(!replay.credential, 409, 'CREDENTIAL_ALREADY_ISSUED')
    return structuredClone(replay.data)
  }
  const data = run(body)
  assetsState.writes.push({ method: request.method, path, key, ifMatch })
  replays.set(replayKey, { fingerprint, ...(credential ? {} : { data: structuredClone(data) }), status, credential })
  return data
}

type Row = { id: string; assetId?: string | null; status?: string; createdAt?: string; updatedAt?: string | null; [key: string]: unknown }
type Collection = 'assets' | 'authorizations' | 'sensors' | 'executors' | 'sensor-configs' | 'machine-clients' | 'health-windows' | 'sensor-heartbeats' | 'executor-heartbeats'
const readPermission = (c: Collection) => c === 'machine-clients' ? (user().permissions.includes('sensor.manage') ? 'sensor.manage' : 'iam.manage') : c.includes('heartbeat') || c === 'health-windows' ? 'ops.read' : 'resource.read'
function rows(c: Collection): Row[] {
  const all = { assets: assetRows(), authorizations: assetsState.authorizations, sensors: assetsState.sensors, executors: assetsState.executors, 'sensor-configs': assetsState.configs, 'machine-clients': assetsState.clients, 'health-windows': assetsState.healthWindows,
    'sensor-heartbeats': assetsState.sensorHeartbeats.map((h) => { const s = find(assetsState.sensors, h.id); return { ...h, status: s.status, revision: s.revision, healthState: ['offline', 'revoked'].includes(s.status) ? 'unhealthy' : h.healthState } }),
    'executor-heartbeats': assetsState.executorHeartbeats.map((h) => { const e = find(assetsState.executors, h.id); return { ...h, status: e.status, revision: e.revision, healthState: ['suspended', 'revoked'].includes(e.status) ? 'unhealthy' : h.healthState } }),
  }
  return all[c] as unknown as Row[]
}
const states: Partial<Record<Collection, string[]>> = { assets: ['active', 'disabled', 'retired'], authorizations: ['pending', 'active', 'expired', 'revoked'], sensors: ['pending', 'active', 'offline', 'revoked'], executors: ['pending', 'active', 'suspended', 'revoked'], 'sensor-configs': ['draft', 'pending', 'approved', 'active', 'retired', 'rejected'], 'machine-clients': ['active', 'disabled', 'revoked'] }
function list(c: Collection, request: Request) {
  const permission = readPermission(c), actor = authorize(permission), q = new URL(request.url).searchParams
  const extra = c === 'assets' ? ['q', 'sort'] : c === 'sensors' || c === 'executors' ? ['assetId', 'q', 'sort'] : c === 'sensor-configs' ? ['assetId', 'sensorId', 'q'] : c === 'machine-clients' ? ['assetId', 'clientType'] : c === 'health-windows' ? ['assetId', 'sensorId', 'captureScopeId', 'verificationStatus'] : ['assetId', 'sensorId', 'executorId']
  const allowed = ['limit', 'cursor', 'status', 'from', 'until', ...extra]
  check([...q].every(([k, v]) => allowed.includes(k) && v.trim() && q.getAll(k).length === 1), 400, 'INVALID_QUERY')
  const limit = Number(q.get('limit') ?? 50)
  check(Number.isInteger(limit) && limit >= 1 && limit <= 200, 400, 'INVALID_PAGE_SIZE')
  if (q.has('status')) check(states[c]?.includes(q.get('status')!), 400, 'INVALID_QUERY')
  if (q.has('sort')) check(['createdAt', 'updatedAt'].includes(q.get('sort')!), 400, 'INVALID_QUERY')
  for (const name of ['assetId', 'sensorId', 'executorId']) if (q.has(name)) {
    check(isUuid(q.get(name)!), 400, 'INVALID_UUID')
    const target = name === 'assetId' ? asset(q.get(name)!) : find<Sensor | Executor>(name === 'sensorId' ? assetsState.sensors : assetsState.executors, q.get(name)!)
    authorize(permission, 'assetId' in target ? target.assetId : target.id, true)
  }
  for (const name of ['from', 'until']) if (q.has(name)) check(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$/.test(q.get(name)!) && Number.isFinite(Date.parse(q.get(name)!)), 400, 'INVALID_TIME_RANGE')
  if (q.has('from') && q.has('until')) check(Date.parse(q.get('from')!) < Date.parse(q.get('until')!), 400, 'INVALID_TIME_RANGE')
  const all = rows(c).filter((r) => fixtureCan(actor, permission, c === 'assets' ? r.id : r.assetId))
  const filtered = all.filter((r) => (!q.has('assetId') || r.assetId === q.get('assetId')) && (!q.has('sensorId') || (c === 'sensor-heartbeats' ? r.id : r.sensorId) === q.get('sensorId')) && (!q.has('executorId') || r.id === q.get('executorId')) && (!q.has('status') || r.status === q.get('status')) && (!q.has('clientType') || r.clientType === q.get('clientType')) && (!q.has('captureScopeId') || r.captureScopeId === q.get('captureScopeId')) && (!q.has('verificationStatus') || r.verificationStatus === q.get('verificationStatus')) && (!q.has('q') || ['displayName', 'assetKey', 'agentKey', 'configVersion'].some((key) => String(r[key] ?? '').toLowerCase().startsWith(q.get('q')!.toLowerCase()))) && (!q.has('from') || String(r.createdAt ?? r.receivedAt ?? '') >= q.get('from')!) && (!q.has('until') || String(r.createdAt ?? r.receivedAt ?? '') < q.get('until')!))
  const sort = q.get('sort') ?? 'createdAt'
  filtered.sort((a, b) => String(b[sort] ?? b.createdAt ?? '').localeCompare(String(a[sort] ?? a.createdAt ?? '')) || b.id.localeCompare(a.id))
  const binding = JSON.stringify([actor.id, actor.permissions, actor.bindings, c, [...q].filter(([k]) => !['cursor', 'limit'].includes(k)).sort()])
  let ids = filtered.map((r) => r.id), offset = 0, asOf = new Date().toISOString()
  if (q.has('cursor')) {
    const cursor = cursors.get(q.get('cursor')!)
    check(cursor?.binding === binding, 400, 'INVALID_CURSOR')
    check(cursor.ids.slice(0, cursor.offset).every((id) => all.some((r) => r.id === id)), 404, 'RESOURCE_NOT_FOUND')
    ;({ ids, offset, asOf } = cursor)
  }
  const visible = ids.slice(offset).map((id) => filtered.find((r) => r.id === id)).filter((r): r is Row => !!r)
  const items = visible.slice(0, limit)
  let nextCursor: string | null = null
  if (visible.length > limit) { nextCursor = crypto.randomUUID(); cursors.set(nextCursor, { binding, ids, offset: ids.indexOf(items[items.length - 1].id) + 1, asOf }) }
  return { ...(!['assets', 'sensors', 'executors'].includes(c) ? { asOf } : {}), items, nextCursor }
}

/** 以下处理器按当前 v2 路径显式注册，避免吞掉其他卡片的请求或意外的 v1 调用。 */
export const assetsHandlers = [
  ...(['assets', 'authorizations', 'sensors', 'executors', 'sensor-configs', 'machine-clients', 'health-windows', 'sensor-heartbeats', 'executor-heartbeats'] as Collection[]).flatMap((c) => [
    http.get(`/api/v2/${c}`, ({ request }) => reply(() => list(c, request))),
    http.get(`/api/v2/${c}/:id`, ({ params }) => reply(() => { const row = find(rows(c), String(params.id)); authorize(readPermission(c), c === 'assets' ? row.id : row.assetId, true); return row })),
  ]),
  http.post('/api/v2/assets', ({ request }) => reply(() => write(request, 'asset.manage', null, 201, (b) => {
    fields(b, ['assetKey', 'platform', 'environment', 'owner'], ['displayName', 'notes'])
    check(typeof b.assetKey === 'string' && b.assetKey && typeof b.owner === 'string' && b.owner && ['macos', 'windows'].includes(String(b.platform)) && ['research', 'lab', 'authorized'].includes(String(b.environment)), 400, 'INVALID_ASSET_SCOPE')
    check(!assetRows().some((a) => a.assetKey === b.assetKey), 409, 'CONFLICT')
    const id = crypto.randomUUID(), now = new Date().toISOString()
    assetRows().push({ id, assetKey: String(b.assetKey), assetType: 'host', environment: String(b.environment), criticality: 'medium', owner: String(b.owner), status: 'active', labels: { platform: b.platform as string }, revision: 1, createdAt: now, updatedAt: now, displayName: b.displayName as string ?? null, notes: b.notes as string ?? null })
    return { id, revision: 1 }
  }), 201)),
  http.patch('/api/v2/assets/:id', ({ request, params }) => reply(() => {
    const row = asset(String(params.id))
    return write(request, 'asset.manage', row.id, 200, (b) => {
      revision(request, row); fields(b, [], ['displayName', 'notes', 'owner', 'criticality', 'status'])
      check(Object.keys(b).length, 400, 'INVALID_REQUEST')
      if (b.status) { check(['active', 'disabled', 'retired'].includes(String(b.status)), 400, 'INVALID_ASSET_SCOPE'); check(row.status !== 'retired' || b.status === 'retired', 409, 'STATE_CONFLICT') }
      if (b.criticality) check(['low', 'medium', 'high', 'critical'].includes(String(b.criticality)), 400, 'INVALID_ASSET_SCOPE')
      Object.assign(row, b, { revision: row.revision + 1, updatedAt: new Date().toISOString() })
      if (row.status !== 'active') for (const bindings of Object.values(releaseState.bindings)) for (const binding of bindings) if (binding.assetId === row.id && binding.status === 'active') { binding.status = 'suspended'; binding.revision++ }
      return { id: row.id, status: row.status, revision: row.revision }
    })
  })),
  http.post('/api/v2/assets/:id/authorizations', ({ request, params }) => reply(() => {
    const a = asset(String(params.id))
    return write(request, 'authorization.request', a.id, 201, (b) => {
      fields(b, ['interfaces', 'observationAllowed', 'executionScopes', 'validFrom', 'validUntil', 'evidenceRef'])
      check(Array.isArray(b.interfaces) && b.interfaces.length && b.interfaces.length <= 16 && b.interfaces.every((i) => typeof i === 'string' && INTERFACE_RE.test(i)) && typeof b.observationAllowed === 'boolean' && Array.isArray(b.executionScopes), 400, 'INVALID_AUTHORIZATION_SCOPE')
      check(Date.parse(String(b.validUntil)) > Math.max(Date.now(), Date.parse(String(b.validFrom))), 422, 'AUTHORIZATION_INACTIVE')
      const row: Authorization = { id: crypto.randomUUID(), assetId: a.id, status: 'pending', revision: 1, createdAt: new Date().toISOString(), requestedBy: user().id, validFrom: String(b.validFrom), validUntil: String(b.validUntil), validity: Date.parse(String(b.validFrom)) > Date.now() ? 'not_yet_valid' : 'valid', scope: { interfaces: b.interfaces as string[], observationAllowed: b.observationAllowed as boolean, executionScopes: b.executionScopes as Authorization['scope']['executionScopes'] } }
      assetsState.authorizations.push(row); return { id: row.id, status: row.status, revision: row.revision }
    })
  }, 201)),
  ...(['decisions', 'withdrawals', 'revocations'] as const).map((op) => http.post(`/api/v2/authorizations/:id/${op}`, ({ request, params }) => reply(() => {
    const row = find(assetsState.authorizations, String(params.id))
    return write(request, op === 'withdrawals' ? 'authorization.request' : 'authorization.approve', row.assetId, op === 'revocations' ? 202 : 200, (b) => {
      revision(request, row); fields(b, op === 'decisions' ? ['decision', 'reason'] : ['reason']); reason(b)
      if (op === 'withdrawals') owner(row)
      if (op === 'decisions') { separate(row); check(['approve', 'reject'].includes(String(b.decision)), 400, 'INVALID_DECISION') }
      check(op === 'revocations' ? row.status === 'active' : row.status === 'pending', 409, 'STATE_CONFLICT')
      row.status = op === 'decisions' && b.decision === 'approve' ? 'active' : 'revoked'; row.revision++
      return { id: row.id, status: row.status, revision: row.revision }
    })
  }, op === 'revocations' ? 202 : 200))),
  ...(['sensors', 'executors'] as const).flatMap((kind) => [
    http.post(`/api/v2/${kind}`, ({ request }) => reply(async () => {
      // 登记请求的资产来自正文；协议头和副作用仍由统一 write 校验。
      const body = await request.clone().json() as { assetId: string }
      const a = asset(body.assetId)
      return write(request, 'sensor.manage', a.id, 201, (b) => {
        fields(b, ['assetId', 'platform', kind === 'sensors' ? 'captureScopeId' : 'capabilityProbeRef'], ['displayName', 'notes'])
        check(['macos', 'windows'].includes(String(b.platform)), 400, 'CAPABILITY_NOT_SUPPORTED')
        const id = crypto.randomUUID(), clientId = crypto.randomUUID(), status = kind === 'sensors' ? 'active' : 'pending', now = new Date().toISOString()
        const common = { id, assetId: a.id, platform: String(b.platform), status, revision: 1, displayName: b.displayName as string ?? null, notes: b.notes as string ?? null, createdAt: now }
        if (kind === 'sensors') assetsState.sensors.push({ ...common, agentKey: id, agentVersion: 'v5-pending', capabilities: [], registeredAt: now, lastHeartbeatAt: null, guardBootId: null })
        else assetsState.executors.push({ ...common, adapterVersion: 'unverified', capabilityHash: '', bootId: null, lastHeartbeat: null, health: null })
        assetsState.clients.push({ id: clientId, assetId: a.id, sensorId: kind === 'sensors' ? id : null, executorId: kind === 'executors' ? id : null, clientType: kind === 'sensors' ? 'sensor' : 'executor', status: 'active', createdAt: now, lastUsedAt: null, expiresAt: null })
        return { id, clientId, credential: crypto.randomUUID(), status, revision: 1 }
      }, true)
    }, 201)),
    http.patch(`/api/v2/${kind}/:id`, ({ request, params }) => reply(() => {
      const row = find<Sensor | Executor>(devices(kind), String(params.id))
      return write(request, 'sensor.manage', row.assetId, 200, (b) => { revision(request, row); fields(b, [], ['displayName', 'notes']); check(Object.keys(b).length, 400, 'INVALID_REQUEST'); Object.assign(row, b); row.revision++; return { id: row.id, revision: row.revision } })
    })),
    http.post(`/api/v2/${kind}/:id/status-changes`, ({ request, params }) => reply(() => {
      const row = find<Sensor | Executor>(devices(kind), String(params.id)), client = assetsState.clients.find((c) => c.sensorId === row.id || c.executorId === row.id)
      return write(request, 'sensor.manage', row.assetId, 200, (b) => {
        revision(request, row); fields(b, ['status', 'reason']); reason(b); check(['active', 'disabled'].includes(String(b.status)), 400, 'INVALID_REQUEST')
        check(client && row.status !== 'revoked' && (b.status !== 'active' || asset(row.assetId).status === 'active'), 409, 'STATE_CONFLICT')
        const status = b.status === 'active' ? 'active' : kind === 'sensors' ? 'offline' : 'suspended'
        check(status !== row.status, 409, 'STATE_CONFLICT')
        row.status = status; row.revision++; if (b.status === 'disabled') client.status = 'revoked'
        return { id: row.id, status, revision: row.revision, credentialRotationRequired: client.status === 'revoked' }
      })
    })),
    http.post(`/api/v2/${kind}/:id/credential-rotations`, ({ request, params }) => reply(() => {
      const row = find<Sensor | Executor>(devices(kind), String(params.id)), client = assetsState.clients.find((c) => c.sensorId === row.id || c.executorId === row.id)
      return write(request, 'sensor.manage', row.assetId, 200, (b) => {
        fields(b, [], ['reason']); check(client && row.status !== 'revoked' && (client.status === 'active' || client.status === 'revoked' && row.status === 'active'), 409, 'STATE_CONFLICT')
        client.status = 'active'; return { id: row.id, clientId: client.id, credential: crypto.randomUUID(), status: row.status, rotatedAt: new Date().toISOString() }
      }, true)
    })),
  ]),
  http.post('/api/v2/sensors/:id/configs', ({ request, params }) => reply(() => {
    const sensor = find(assetsState.sensors, String(params.id))
    return write(request, 'sensor.manage', sensor.assetId, 201, (b) => {
      fields(b, ['contractVersion', 'profileSha256', 'captureHealthVersion', 'interfaceIds', 'limits', 'captureScopeId', 'addressFamily', 'buildSha256'])
      check(b.contractVersion === CAPTURE_CONTRACT && CAPTURE_HEALTH_VERSIONS.some((v) => v === b.captureHealthVersion) && SHA256_RE.test(String(b.profileSha256)), 422, 'CONTRACT_UNSUPPORTED')
      check(SHA256_RE.test(String(b.buildSha256)) && isUuid(String(b.captureScopeId)), 400, 'INVALID_REQUEST')
      const limits = b.limits as { maxBatchSize?: number }
      check(Array.isArray(b.interfaceIds) && b.interfaceIds.length === 1 && INTERFACE_RE.test(String(b.interfaceIds[0])) && ['ipv4', 'ipv6'].includes(String(b.addressFamily)) && limits && Number.isInteger(limits.maxBatchSize) && limits.maxBatchSize! >= 1 && limits.maxBatchSize! <= MAX_BATCH_SIZE, 400, 'INVALID_CAPTURE_SCOPE')
      const row: SensorConfig = { id: crypto.randomUUID(), assetId: sensor.assetId, sensorId: sensor.id, status: 'draft', revision: 1, createdAt: new Date().toISOString(), requestedBy: user().id, configVersion: crypto.randomUUID(), featureContractVersion: CAPTURE_CONTRACT, activatedAt: null, contentSha256: null, definition: structuredClone(b) as unknown as ConfigDraft }
      assetsState.configs.push(row); return { id: row.id, status: row.status, revision: row.revision }
    })
  }, 201)),
  http.post('/api/v2/sensor-configs/:id/decisions', ({ request, params }) => reply(() => {
    const row = find(assetsState.configs, String(params.id))
    return write(request, 'authorization.approve', row.assetId, 200, (b) => {
      revision(request, row); fields(b, ['decision', 'reason']); reason(b); separate(row); check(['approve', 'reject'].includes(String(b.decision)), 400, 'INVALID_DECISION'); check(row.status === 'draft' && row.definition, 409, 'STATE_CONFLICT')
      if (b.decision === 'approve') {
        check(assetsState.authorizations.some((a) => a.assetId === row.assetId && a.status === 'active' && Date.parse(a.validFrom) <= Date.now() && Date.parse(a.validUntil) > Date.now() && a.scope.observationAllowed && a.scope.interfaces?.includes(row.definition!.interfaceIds![0])), 422, 'AUTHORIZATION_INACTIVE')
        for (const old of assetsState.configs) if (old.sensorId === row.sensorId && old.status === 'active') { old.status = 'retired'; old.revision++ }
      }
      row.status = b.decision === 'approve' ? 'active' : 'rejected'; row.revision++; return { id: row.id, status: row.status, revision: row.revision }
    })
  })),
  http.delete('/api/v2/sensor-configs/:id', ({ request, params }) => reply(() => {
    const row = find(assetsState.configs, String(params.id))
    return write(request, 'sensor.manage', row.assetId, 200, () => { revision(request, row); owner(row); check(row.status === 'draft' && !assetsState.referencedConfigs.has(row.id), 409, 'RESOURCE_IN_USE'); assetsState.configs = assetsState.configs.filter((r) => r !== row); return { id: row.id, status: 'deleted' } })
  })),
  http.post('/api/v2/machine-clients/:id/revocations', ({ request, params }) => reply(() => {
    const row = find(assetsState.clients, String(params.id))
    return write(request, 'sensor.manage', row.assetId, 202, (b) => { fields(b, ['reason']); reason(b); check(['active', 'disabled'].includes(row.status), 409, 'STATE_CONFLICT'); row.status = 'revoked'; for (const device of [...assetsState.sensors, ...assetsState.executors]) if (device.id === row.sensorId || device.id === row.executorId) { device.status = 'revoked'; device.revision++ } return { id: row.id, status: row.status } })
  }, 202)),
]
