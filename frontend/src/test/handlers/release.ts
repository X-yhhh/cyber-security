/**
 * F3 的 msw 支持：列表/详情/子资源、请求头约束和写后回读。
 * 仅在测试服务器注册，不进入产品数据流；不模拟真实验签、制品读取或防火墙执行。
 * 这些夹具用于页面行为验证，不能代替后端的范围、授权与发布资格验收。
 */
import { http, HttpResponse } from 'msw'
import { MODEL_VALIDATION_PROFILE_ID, isSha256 } from '@/api/v2/release'
import { requireDecisionPolicy } from '@/api/v2/release-policy'
import { isUuid } from '@/api/v2/detect'
import type { GuardLabRun } from '@/api/types'
import type { Permission } from '@/router/nav'
import {
  createReleaseFixture, RELEASE_COLLECTIONS, RELEASE_IDS, RELEASE_SHA, RELEASE_TIME,
  type ReleaseCollection, type ReleaseCollections,
} from '@/test/fixtures/release'
import { currentUser } from './auth'

export { RELEASE_IDS, RELEASE_SHA, policyFixture } from '@/test/fixtures/release'
export let releaseState = createReleaseFixture()
const replays = new Map<string, { fingerprint: string; data: unknown }>()
const cursors = new Map<string, { signature: string; offset: number; ids: string[] }>()
const deletedPolicies = new Map<string, Row>()
export const resetReleaseState = () => { releaseState = createReleaseFixture(); replays.clear(); cursors.clear(); deletedPolicies.clear() }

interface Row { id: string; revision?: number; status?: string; validationStatus?: string; createdAt?: string; updatedAt?: string | null; [field: string]: unknown }
const rows = (collection: ReleaseCollection) => releaseState.rows[collection] as unknown as Row[]
const find = (collection: ReleaseCollection, id: string) => {
  const row = rows(collection).find((row) => row.id === id)
  check(row, 404, 'RESOURCE_NOT_FOUND')
  return row
}
class FixtureError extends Error {
  constructor(readonly status: number, readonly code: string) { super(code) }
}
function check(condition: unknown, status: number, code: string): asserts condition {
  if (!condition) throw new FixtureError(status, code)
}
const messages: Record<string, string> = {
  RESOURCE_IN_USE: '该对象仍被引用，请先处理活动绑定或关联资源。',
  REVISION_CONFLICT: '记录已变化，请刷新后重试。',
  APPROVAL_SEPARATION_REQUIRED: '必须由另一位具有权限的用户审核。',
  SCOPE_DENIED: '当前身份没有执行此操作的权限。',
  RESOURCE_NOT_FOUND: '记录不存在或不在可见范围内。',
}
async function reply(work: () => unknown | Promise<unknown>, status = 200) {
  try { return HttpResponse.json({ requestId: 'req-release', data: await work(), error: null }, { status }) }
  catch (error) {
    if (!(error instanceof FixtureError)) throw error
    return HttpResponse.json({ requestId: 'req-release-error', data: null, error: { code: error.code, message: messages[error.code] ?? error.code } }, { status: error.status })
  }
}
function authorize(permission: Permission) {
  const user = currentUser()
  check(user, 401, 'UNAUTHENTICATED')
  check(user.permissions.includes(permission), 403, 'SCOPE_DENIED')
  return user
}
const readPermission = (collection: ReleaseCollection): Permission => ['evaluations', 'evaluation-plans', 'replay-runs', 'lab-validation-runs'].includes(collection) ? 'evaluation.read' : 'resource.read'
const touch = (row: Row) => { row.revision = (row.revision ?? 0) + 1; row.updatedAt = new Date().toISOString() }
const result = (row: Row) => ({ id: row.id, status: row.status, revision: row.revision })
function reason(body: Record<string, unknown>) { check(typeof body.reason === 'string' && body.reason.trim(), 400, 'INVALID_REQUEST') }
function review(body: Record<string, unknown>, id: string) {
  reason(body)
  check(body.decision === 'approve' || body.decision === 'reject', 400, 'INVALID_REQUEST')
  check(releaseState.owners[id] !== currentUser()?.id, 403, 'APPROVAL_SEPARATION_REQUIRED')
}
function fields(body: Record<string, unknown>, required: string[], optional: string[] = []) {
  check(required.every((key) => key in body), 400, 'INVALID_REQUEST')
  check(Object.keys(body).every((key) => required.includes(key) || optional.includes(key)), 400, 'UNKNOWN_FIELD')
}

/** 缓存绑定主体、方法和地址；同键异体或不同 If-Match 冲突，重放前仍验证当前权限。 */
async function write(request: Request, permission: Permission, row: Row | undefined, work: (body: Record<string, unknown>) => unknown) {
  const user = authorize(permission)
  const key = request.headers.get('Idempotency-Key')
  check(key && isUuid(key), 400, 'INVALID_UUID')
  check(request.headers.has('X-CSRF-TOKEN'), 403, 'CSRF_INVALID')
  const text = await request.text()
  let body: Record<string, unknown> = {}
  if (text) {
    try { body = JSON.parse(text) }
    catch { throw new FixtureError(400, 'INVALID_JSON') }
  }
  check(body && typeof body === 'object' && !Array.isArray(body), 400, 'INVALID_REQUEST')
  const path = new URL(request.url).pathname
  const ifMatch = request.headers.get('If-Match')
  releaseState.writes.push({ method: request.method, path, body: text ? body : undefined, ifMatch, idempotencyKey: key })
  const cacheKey = `${user.id}:${request.method}:${path}:${key}`
  const fingerprint = JSON.stringify({ body, ifMatch })
  const cached = replays.get(cacheKey)
  if (cached) {
    check(cached.fingerprint === fingerprint, 409, 'IDEMPOTENCY_CONFLICT')
    return structuredClone(cached.data)
  }
  if (row) check(ifMatch === String(row.revision), 409, 'REVISION_CONFLICT')
  const data = work(body)
  replays.set(cacheKey, { fingerprint, data: structuredClone(data) })
  return data
}

const statusValues: Partial<Record<ReleaseCollection, string[]>> = {
  models: ['pending', 'validated', 'failed', 'retired'], datasets: ['active', 'retired'],
  'decision-policies': ['draft', 'reviewed', 'retired'], 'release-bundles': ['candidate', 'evaluated', 'approved', 'active', 'suspended', 'retired'],
  evaluations: ['pending', 'running', 'completed', 'failed'], 'replay-runs': ['queued', 'running', 'completed', 'failed'],
  'lab-validation-runs': ['registered', 'running', 'interrupted', 'completed', 'failed', 'cancelled'],
}
const searchKeys: Partial<Record<ReleaseCollection, string[]>> = {
  models: ['displayName', 'modelKey'], datasets: ['displayName', 'datasetKey'], 'decision-policies': ['displayName', 'policyKey'],
  'release-bundles': ['bundleKey'], capabilities: ['capabilityKey'], 'evaluation-plans': ['planKey'],
}
function list(collection: ReleaseCollection, request: Request) {
  const user = authorize(readPermission(collection))
  const query = new URL(request.url).searchParams
  const allowed = collection === 'lab-validation-runs' ? ['cursor', 'limit', 'status'] : ['cursor', 'limit', 'status', 'q', 'from', 'until', 'sort']
  for (const [key, value] of query) check(allowed.includes(key) && value.trim() && query.getAll(key).length === 1, 400, 'INVALID_QUERY')
  const limit = Number(query.get('limit') ?? 50)
  check(Number.isInteger(limit) && limit >= 1 && limit <= 200, 400, 'INVALID_PAGE_SIZE')
  const status = query.get('status'), q = query.get('q'), from = query.get('from'), until = query.get('until'), sort = query.get('sort') ?? 'createdAt'
  if (status) check(statusValues[collection]?.includes(status), 400, 'INVALID_QUERY')
  if (q) check(searchKeys[collection] && q.length <= 128 && !/[\u0000-\u001f\u007f]/.test(q), 400, 'INVALID_QUERY')
  check(sort === 'createdAt' || sort === 'updatedAt', 400, 'INVALID_QUERY')
  for (const time of [from, until]) if (time) check(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$/.test(time) && Number.isFinite(Date.parse(time)), 400, 'INVALID_QUERY')
  if (from && until) check(Date.parse(from) < Date.parse(until), 400, 'INVALID_QUERY')
  let selected = rows(collection).filter((row) =>
    (!status || (collection === 'models' ? row.validationStatus : collection === 'lab-validation-runs' ? row.runStatus : row.status) === status)
    && (!q || searchKeys[collection]!.some((key) => String(row[key] ?? '').toLowerCase().startsWith(q.toLowerCase())))
    && (!from || Date.parse(String(row.createdAt)) >= Date.parse(from))
    && (!until || Date.parse(String(row.createdAt)) < Date.parse(until)),
  )
  const time = (row: Row) => String((sort === 'updatedAt' ? row.updatedAt : null) ?? row.createdAt ?? RELEASE_TIME)
  selected.sort((left, right) => time(right).localeCompare(time(left)) || right.id.localeCompare(left.id))
  const binding = new URLSearchParams(query); binding.delete('cursor'); binding.delete('limit'); binding.sort()
  const signature = `${user.id}:${collection}:${binding}`
  const cursor = query.get('cursor')
  let offset = 0, ids = selected.map((row) => row.id)
  if (cursor) {
    const saved = cursors.get(cursor)
    check(saved?.signature === signature, 400, 'INVALID_CURSOR')
    offset = saved.offset; ids = saved.ids
    selected = ids.flatMap((id) => rows(collection).filter((row) => row.id === id))
  }
  const items = selected.slice(offset, offset + limit)
  let nextCursor: string | null = null
  if (offset + limit < selected.length) {
    nextCursor = `fixture-${crypto.randomUUID()}`
    cursors.set(nextCursor, { signature, offset: offset + limit, ids })
  }
  return { items, nextCursor }
}

const readHandlers = RELEASE_COLLECTIONS.flatMap((collection) => [
  http.get(`/api/v2/${collection}`, ({ request }) => reply(() => list(collection, request))),
  http.get(`/api/v2/${collection}/:id`, ({ params }) => reply(() => { authorize(readPermission(collection)); return find(collection, String(params.id)) })),
])

const childHandlers = [
  http.get('/api/v2/models/:id/validations', ({ params }) => reply(() => { authorize('resource.read'); find('models', String(params.id)); return releaseState.validations[String(params.id)] ?? null })),
  http.get('/api/v2/release-bundles/:id/bindings', ({ params }) => reply(() => { authorize('resource.read'); find('release-bundles', String(params.id)); return { items: releaseState.bindings[String(params.id)] ?? [] } })),
  http.get('/api/v2/lab-validation-runs/:id/:child', ({ request, params }) => reply(() => {
    authorize('evaluation.read')
    const id = String(params.id), run = find('lab-validation-runs', id)
    if (params.child === 'qualifications') return releaseState.qualifications[id] ?? { sessionId: id, bundleId: run.bundleId, bundleUsable: false, sources: [] }
    if (params.child === 'report-input') return { contractVersion: 'host-guard-lab/1.1.0', session: { sessionId: id }, sessionSha256: run.sessionSha256, runStatus: run.runStatus, scenarios: [], events: releaseState.events[id] ?? [], unlinkedCommandIds: [], unlinkedDecisionIds: [] }
    check(params.child === 'events', 404, 'RESOURCE_NOT_FOUND')
    const query = new URL(request.url).searchParams
    for (const [key, value] of query) check(['after', 'limit'].includes(key) && value && query.getAll(key).length === 1, 400, 'INVALID_QUERY')
    const after = Number(query.get('after') ?? 0), limit = Number(query.get('limit') ?? 50)
    check(Number.isInteger(after) && after >= 0 && Number.isInteger(limit) && limit >= 1 && limit <= 200, 400, 'INVALID_QUERY')
    const selected = (releaseState.events[id] ?? []).filter((event) => event.sequence > after).sort((a, b) => a.sequence - b.sequence)
    const items = selected.slice(0, limit)
    return { items, nextAfter: selected.length > limit ? items[items.length - 1].sequence : null }
  })),
]

const registrationPermissions: Partial<Record<ReleaseCollection, Permission>> = {
  models: 'model.manage', datasets: 'dataset.manage', 'decision-policies': 'policy.draft', 'release-bundles': 'bundle.request',
  capabilities: 'bundle.request', 'evaluation-plans': 'evaluation.run', 'replay-runs': 'evaluation.run', 'lab-validation-runs': 'evaluation.run',
}
function register(collection: ReleaseCollection, body: Record<string, unknown>) {
  const id = crypto.randomUUID(), now = new Date().toISOString()
  const row: Row = { id, createdAt: now }
  const seed = structuredClone(rows(collection)[0] ?? createReleaseFixture().rows[collection][0])
  Object.assign(row, seed, { id, createdAt: now })
  if (collection === 'models' || collection === 'datasets') {
    fields(body, ['manifestRef', 'manifestSha256'], ['displayName', 'notes'])
    check(typeof body.manifestRef === 'string' && isSha256(String(body.manifestSha256)), 400, 'INVALID_REQUEST')
    Object.assign(row, body, { revision: 1, updatedAt: null, ...(collection === 'models' ? { validationStatus: 'pending', validation: null } : { status: 'active' }) })
  } else if (collection === 'decision-policies') {
    let policy
    try { policy = requireDecisionPolicy(body) } catch { throw new FixtureError(422, 'SCHEMA_INVALID') }
    check(!rows(collection).some((row) => row.id === policy.policyId), 409, 'IDEMPOTENCY_CONFLICT')
    Object.assign(row, { id: policy.policyId, modelId: policy.modelId, policyKey: policy.policyId, version: policy.policyVersion, definition: policy, status: 'draft', revision: 1 })
  } else if (collection === 'release-bundles') {
    fields(body, ['modelId', 'policyId', 'featureProfileSha256', 'extractorSha256', 'protocolVersions', 'evaluationPlanId', 'capabilityIds', 'environment'])
    Object.assign(row, { modelId: body.modelId, policyId: body.policyId, planId: body.evaluationPlanId, environment: body.environment, subject: body, bundleKey: id, status: 'candidate', revision: 1, sealedManifestSha256: null, sealedManifest: null })
  } else if (collection === 'evaluation-plans') {
    if ('planRef' in body) fields(body, ['planRef', 'planSha256'])
    else check(body.planKey && body.version, 400, 'INVALID_REQUEST')
    Object.assign(row, { planKey: body.planKey ?? `p6:fixture-${id}`, planSha256: body.planSha256 ?? RELEASE_SHA, payload: body })
  } else if (collection === 'capabilities') {
    check(body.capabilityKey && body.level, 400, 'INVALID_REQUEST')
    Object.assign(row, { capabilityKey: body.capabilityKey, version: body.version, platform: body.platform, level: body.level, scope: body.scope ?? 'peer_service', payload: body })
  } else if (collection === 'replay-runs') {
    fields(body, ['scenarioId', 'scenarioSha256', 'modelId', 'policyId', 'speed'])
    check(body.speed === 1, 422, 'REPLAY_SPEED_FIXED')
    Object.assign(row, body, { status: 'queued', payload: body })
  } else if (collection === 'lab-validation-runs') {
    fields(body, ['sessionRef', 'sha256', 'runnerIdentity'])
    Object.assign(row, { revision: 1, eligibilityStatus: 'pending', effectiveEligibility: 'pending', runStatus: 'registered', startedAt: null, endedAt: null, executionAuthority: false, cleanupStatus: 'not_asserted' })
  }
  rows(collection).unshift(row)
  releaseState.owners[row.id] = currentUser()!.id
  if (collection === 'models') return { id: row.id, candidateOnly: true, validationStatus: 'pending', revision: 1 }
  if (collection === 'lab-validation-runs') return row
  return { id: row.id, status: row.status, revision: row.revision, planSha256: row.planSha256, subjectSha256: row.subjectSha256, level: row.level, scope: row.scope, speed: row.speed, bundleId: row.bundleId }
}
const createHandlers = RELEASE_COLLECTIONS.filter((collection) => registrationPermissions[collection]).map((collection) =>
  http.post(`/api/v2/${collection}`, ({ request }) => reply(() => write(request, registrationPermissions[collection]!, undefined, (body) => register(collection, body)), collection === 'replay-runs' ? 202 : 201)),
)

const editHandlers = (['models', 'datasets'] as const).map((collection) =>
  http.patch(`/api/v2/${collection}/:id`, ({ request, params }) => reply(() => {
    authorize(collection === 'models' ? 'model.manage' : 'dataset.manage')
    const row = find(collection, String(params.id))
    return write(request, collection === 'models' ? 'model.manage' : 'dataset.manage', row, (body) => {
      fields(body, [], ['displayName', 'notes']); check(Object.keys(body).length, 400, 'INVALID_REQUEST')
      for (const [key, value] of Object.entries(body)) check(value === null || (typeof value === 'string' && value.length <= (key === 'notes' ? 1000 : 128)), 400, 'INVALID_REQUEST')
      Object.assign(row, body); touch(row)
      return { id: row.id, revision: row.revision, displayName: row.displayName, notes: row.notes }
    })
  })),
)
const deleteHandler = http.delete('/api/v2/decision-policies/:id', ({ request, params }) => reply(() => {
  authorize('policy.draft')
  const row = rows('decision-policies').find((row) => row.id === String(params.id)) ?? deletedPolicies.get(String(params.id))
  check(row, 404, 'RESOURCE_NOT_FOUND')
  return write(request, 'policy.draft', row, () => {
    check(rows('decision-policies').some((item) => item.id === row.id), 404, 'RESOURCE_NOT_FOUND')
    check(releaseState.owners[row.id] === currentUser()!.id, 403, 'SCOPE_DENIED')
    check(row.status === 'draft' && !releaseState.referenced.has(row.id), 409, 'RESOURCE_IN_USE')
    deletedPolicies.set(row.id, structuredClone(row))
    releaseState.rows['decision-policies'] = releaseState.rows['decision-policies'].filter((item) => item.id !== row.id)
    return { id: row.id, status: 'deleted' }
  })
}))

function catalogOperation(collection: ReleaseCollection, operation: string, row: Row, body: Record<string, unknown>) {
  if (operation === 'retirements') {
    fields(body, ['reason']); reason(body)
    check(!releaseState.referenced.has(row.id) && !(releaseState.bindings[row.id] ?? []).some((binding) => binding.status === 'active'), 409, 'RESOURCE_IN_USE')
    check((row.validationStatus ?? row.status) !== 'retired' && !(collection === 'release-bundles' && row.status === 'active'), 409, 'STATE_CONFLICT')
    if (collection === 'models') row.validationStatus = 'retired'; else row.status = 'retired'
  } else if (operation === 'validations') {
    fields(body, ['validationProfileId'])
    check(body.validationProfileId === MODEL_VALIDATION_PROFILE_ID, 422, 'VALIDATION_PROFILE_UNSUPPORTED')
    check(row.validationStatus !== 'retired', 409, 'STATE_CONFLICT')
    row.validationStatus = 'validated'; row.validation = { status: 'validated' }
    releaseState.validations[row.id] = { status: 'validated' }; touch(row)
    return row.validation
  } else if (operation === 'reviews' || operation === 'decisions') {
    fields(body, ['decision', 'reason']); review(body, row.id)
    check(row.status === (collection === 'decision-policies' ? 'draft' : 'evaluated'), 422, 'STATE_CONFLICT')
    row.status = body.decision === 'approve' ? (collection === 'decision-policies' ? 'reviewed' : 'approved') : 'retired'
  } else if (operation === 'imports') {
    fields(body, ['reportRef', 'sha256', 'runnerIdentity'])
    check(row.status === 'candidate', 422, 'STATE_CONFLICT')
    const evaluation = { ...createReleaseFixture().rows.evaluations[0], id: crypto.randomUUID(), bundleId: row.id, reportRef: String(body.reportRef), reportSha256: String(body.sha256), runnerIdentity: String(body.runnerIdentity) }
    releaseState.rows.evaluations.unshift(evaluation)
    return { id: evaluation.id, status: evaluation.status }
  } else if (operation === 'sealings') {
    fields(body, ['evaluationIds']); check(row.status === 'candidate', 422, 'STATE_CONFLICT')
    check(Array.isArray(body.evaluationIds) && body.evaluationIds.length, 422, 'EVALUATION_PLAN_MISMATCH')
    const reports = body.evaluationIds.map((id) => releaseState.rows.evaluations.find((evaluation) => evaluation.id === id))
    check(reports.every((report) => report?.bundleId === row.id && report.status === 'passed'), 422, 'EVALUATION_PLAN_MISMATCH')
    check(reports.some((report) => report?.runKind === 'final'), 422, 'FINAL_EVALUATION_REQUIRED')
    row.status = 'evaluated'; row.sealedManifestSha256 = RELEASE_SHA; row.sealedManifest = { reports }
  } else if (operation === 'activations') {
    fields(body, ['assetIds', 'authorizationIds']); check(['approved', 'active'].includes(String(row.status)), 422, 'STATE_CONFLICT')
    check(Array.isArray(body.assetIds) && body.assetIds.length && Array.isArray(body.authorizationIds) && body.assetIds.length === body.authorizationIds.length, 400, 'INVALID_REQUEST')
    check(body.assetIds.every((id) => id === RELEASE_IDS.asset) && body.authorizationIds.every((id) => id === RELEASE_IDS.authorization), 404, 'RESOURCE_NOT_FOUND')
    row.status = 'active'
    const binding = { ...createReleaseFixture().bindings[RELEASE_IDS.approvedBundle][0], id: crypto.randomUUID(), bundleId: row.id, status: 'active' as const }
    releaseState.bindings[row.id] = [binding]; touch(row)
    return { ...result(row), bindingIds: [binding.id] }
  } else if (operation === 'suspensions') {
    fields(body, ['reason', 'revokeExisting']); reason(body); check(typeof body.revokeExisting === 'boolean', 400, 'INVALID_REQUEST')
    check(['approved', 'active'].includes(String(row.status)), 422, 'STATE_CONFLICT')
    row.status = 'suspended'
    for (const binding of releaseState.bindings[row.id] ?? []) { binding.status = 'suspended'; binding.revision++ }
  }
  touch(row)
  return collection === 'models' ? { id: row.id, validationStatus: row.validationStatus, revision: row.revision } : { ...result(row), ...(operation === 'sealings' ? { sealedManifestSha256: row.sealedManifestSha256 } : {}) }
}

const operations: Partial<Record<ReleaseCollection, Record<string, Permission>>> = {
  models: { validations: 'model.validate', retirements: 'model.manage' }, datasets: { retirements: 'dataset.manage' },
  'decision-policies': { reviews: 'policy.approve' },
  'release-bundles': { imports: 'evaluation.run', sealings: 'bundle.request', decisions: 'bundle.approve', activations: 'bundle.approve', suspensions: 'automation.stop', retirements: 'bundle.approve' },
  'replay-runs': { starts: 'evaluation.run', completions: 'evaluation.run', failures: 'evaluation.run' },
  'lab-validation-runs': { decisions: 'authorization.approve', revocations: 'automation.stop', starts: 'evaluation.run', interruptions: 'evaluation.run', resumptions: 'evaluation.run', completions: 'evaluation.run', reconciliations: 'evaluation.run', events: 'evaluation.run', reports: 'evaluation.run' },
}
function replayOperation(operation: string, row: Row, body: Record<string, unknown>) {
  const permitted = operation === 'starts' ? ['queued'] : operation === 'completions' ? ['running'] : ['queued', 'running']
  check(permitted.includes(String(row.status)), 422, 'STATE_CONFLICT')
  if (operation === 'starts') fields(body, ['scenarioRef', 'closeoutRef', 'bindings'])
  if (operation === 'completions') fields(body, ['reportRef', 'reportSha256'])
  if (operation === 'failures') { fields(body, ['reasonCode', 'reason']); reason(body) }
  row.status = operation === 'starts' ? 'running' : operation === 'completions' ? 'completed' : 'failed'
  row.payload = { ...row.payload as object, [operation]: body }
  return { id: row.id, status: row.status }
}
function labOperation(operation: string, row: Row, body: Record<string, unknown>) {
  const terminal = ['completed', 'failed', 'cancelled'].includes(String(row.runStatus))
  if (operation === 'decisions') {
    fields(body, ['decision', 'reason']); review(body, row.id)
    check(row.eligibilityStatus === 'pending', 422, 'STATE_CONFLICT')
    row.eligibilityStatus = row.effectiveEligibility = body.decision === 'approve' ? 'active' : 'rejected'
  } else if (operation === 'revocations') {
    fields(body, ['reason']); reason(body)
    row.eligibilityStatus = row.effectiveEligibility = 'revoked'
    if (!terminal) row.runStatus = 'cancelled'
    row.stopRequestedAt = new Date().toISOString()
  } else if (operation === 'starts' || operation === 'resumptions') {
    fields(body, [])
    check(row.effectiveEligibility === 'active', 422, 'AUTHORIZATION_INACTIVE')
    check(row.runStatus === (operation === 'starts' ? 'registered' : 'interrupted'), 422, 'STATE_CONFLICT')
    row.runStatus = 'running'; row.startedAt ??= new Date().toISOString()
  } else if (operation === 'interruptions') {
    fields(body, ['reason']); reason(body); check(row.runStatus === 'running', 422, 'STATE_CONFLICT'); row.runStatus = 'interrupted'
  } else if (operation === 'completions') {
    fields(body, ['outcome', 'reason']); reason(body)
    check(['running', 'interrupted'].includes(String(row.runStatus)) && ['completed', 'failed'].includes(String(body.outcome)), 422, 'STATE_CONFLICT')
    row.runStatus = body.outcome; row.endedAt = new Date().toISOString()
  } else if (operation === 'reconciliations') fields(body, [])
  else if (operation === 'events') {
    check(row.startedAt, 422, 'STATE_CONFLICT')
    check(typeof body.eventId === 'string' && isUuid(body.eventId), 400, 'INVALID_UUID')
    fields(body, body.kind === 'scenario_result' ? ['eventId', 'scenarioId', 'kind', 'reportRef', 'sha256'] : ['eventId', 'scenarioId', 'kind', 'referenceId'])
    check(['scenario_result', 'observation', 'decision', 'command', 'receipt', 'verified_receipt'].includes(String(body.kind)), 422, 'LAB_EVENT_KIND_INVALID')
    const events = releaseState.events[row.id] ??= []
    const old = events.find((event) => event.eventId === body.eventId)
    if (old) return { eventId: old.eventId, revision: row.revision, duplicate: true }
    events.push({ eventId: body.eventId, sequence: (events[events.length - 1]?.sequence ?? 0) + 1, sha256: RELEASE_SHA, fact: body }); touch(row)
    return { eventId: body.eventId, revision: row.revision, duplicate: false, fact: body }
  } else if (operation === 'reports') {
    fields(body, ['reportRef', 'sha256', 'runnerIdentity']); check(terminal, 422, 'STATE_CONFLICT')
    touch(row)
    const evaluationId = crypto.randomUUID()
    releaseState.rows.evaluations.unshift({ ...createReleaseFixture().rows.evaluations[0], id: evaluationId, bundleId: String(row.bundleId), runKind: 'canary', status: 'failed', reportRef: String(body.reportRef), reportSha256: String(body.sha256), payload: { sessionId: row.id, evidenceKind: 'synthetic', passed: false } })
    return { evaluationId, sessionId: row.id, status: 'unverified', passed: false, qualifiedSources: [], qualificationEffect: 'none' }
  }
  touch(row)
  return row
}
const operationHandlers = Object.entries(operations).map(([name, permissionMap]) => {
  const collection = name as ReleaseCollection
  return http.post(`/api/v2/${collection}/:id/:operation`, ({ request, params }) => {
    const operation = String(params.operation)
    const status = collection === 'lab-validation-runs' ? 200 : ['validations', 'activations', 'suspensions'].includes(operation) ? 202 : ['imports', 'sealings'].includes(operation) ? 201 : 200
    return reply(() => {
      let permission = permissionMap[operation]
      check(permission, 404, 'RESOURCE_NOT_FOUND')
      // candidate/evaluated 的退役由申请方执行；其他状态要求审批权限。
      if (collection === 'release-bundles' && operation === 'retirements') {
        const user = currentUser(); check(user, 401, 'UNAUTHENTICATED')
        check(user.permissions.some((permission) => permission === 'bundle.request' || permission === 'bundle.approve'), 403, 'SCOPE_DENIED')
        if (['candidate', 'evaluated'].includes(String(find(collection, String(params.id)).status))) permission = 'bundle.request'
      }
      authorize(permission)
      const row = find(collection, String(params.id))
      const concurrent = collection === 'lab-validation-runs' || !['validations', 'imports', 'starts', 'completions', 'failures'].includes(operation)
      return write(request, permission, concurrent ? row : undefined, (body) => collection === 'lab-validation-runs' ? labOperation(operation, row, body) : collection === 'replay-runs' ? replayOperation(operation, row, body) : catalogOperation(collection, operation, row, body))
    }, status)
  })
})

export const releaseHandlers = [...readHandlers, ...childHandlers, ...createHandlers, ...editHandlers, deleteHandler, ...operationHandlers]

/** 测试可按集合读取强类型状态，用于验证重新拉取后的事实变化。 */
export const releaseRows = <K extends ReleaseCollection>(collection: K): ReleaseCollections[K][] => releaseState.rows[collection]
export const labRow = (id = RELEASE_IDS.lab): GuardLabRun => releaseState.rows['lab-validation-runs'].find((row) => row.id === id)!
