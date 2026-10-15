/**
 * F4 资产与接入接口（/api/v2，接口设计第 2、3.2、11 节）：资产、授权、传感器、执行器、采集配置、机器凭据与健康窗口。
 *
 * - 资料编辑与状态变更带 If-Match（读取到的 revision），所有写入默认生成新的幂等键；
 *   登记传感器/执行器与轮换凭据的响应含一次性机器凭据，页面只在响应抽屉里显示一次，不写入任何持久状态。
 * - 列表与授权、配置不返回申请人/起草人；`requestedBy` 为可选字段，后端放出后页面自动按本人隐藏审批入口，
 *   缺失时入口照常显示，自批与越权由后端 403 拒绝。
 * - 资产集合只支持 status、q、时间与排序筛选；环境筛选由页面对已加载的当前页进行。
 */
import { guard, idempotencyKey, type Cursor } from '@/api/client'
import type {
  GuardCapability, GuardExecutor, GuardHealthWindow, GuardHeartbeat, GuardReadPage, GuardReleaseBundle, GuardSensor,
} from '@/api/types'

type WriteKey = ReturnType<typeof idempotencyKey>

export type AssetStatus = 'active' | 'disabled' | 'retired'
export type Criticality = 'low' | 'medium' | 'high' | 'critical'
export type AssetEnv = 'research' | 'lab' | 'authorized'
export type Platform = 'macos' | 'windows'

/** 资产（GET /assets）：B4 起带可编辑显示名与说明；平台记录在 labels.platform。 */
export interface Asset {
  id: string; assetKey: string; assetType: string; environment: string; criticality: string; owner: string
  status: string; labels: { platform?: string } | null; revision: number; createdAt: string; updatedAt: string | null
  displayName?: string | null; notes?: string | null
}

/** 授权（GET /authorizations）：validity 已按服务端 asOf 计算生效、未生效或到期，status 是存储状态。 */
export interface ExecutionScope {
  scope: string | null; direction: string | null; transport: string | null; addressFamily: string | null
  capabilityId: string | null; servicePort: number | null
}
export interface Authorization {
  id: string; assetId: string; status: string; revision: number; createdAt: string
  validFrom: string; validUntil: string; validity: 'valid' | 'not_yet_valid' | 'expired'
  scope: { interfaces: string[] | null; observationAllowed: boolean | null; executionScopes: ExecutionScope[] | null }
  requestedBy?: number | string | null
}

/** 采集配置（GET /sensor-configs）；definition 只含白名单字段。 */
export interface SensorConfig {
  id: string; assetId: string; sensorId: string; status: string; revision: number; createdAt: string
  configVersion: string; featureContractVersion: string | null; activatedAt: string | null; contentSha256: string | null
  definition: {
    contractVersion: string | null; profileSha256: string | null; captureHealthVersion: string | null; captureScopeId: string | null
    addressFamily: string | null; buildSha256: string | null; interfaceIds: string[] | null; limits: { maxBatchSize: number | null }
  } | null
  requestedBy?: number | string | null
}

/** 机器凭据台账（GET /machine-clients）：不返回凭据明文或摘要。 */
export interface MachineClient {
  id: string; assetId: string | null; sensorId: string | null; executorId: string | null; clientType: string
  status: string; createdAt: string; lastUsedAt: string | null; expiresAt: string | null
}

/** 发布组合在资产上的绑定（GET /release-bundles/{id}/bindings）。 */
export interface AssetBinding {
  id: string; assetId: string; bundleId: string; authorizationId: string | null; authorizationRevision: number | null
  status: string; revision: number; createdAt: string
}

export type Sensor = GuardSensor & { displayName?: string | null; notes?: string | null; updatedAt?: string | null }
export type Executor = GuardExecutor & { displayName?: string | null; notes?: string | null; createdAt?: string; updatedAt?: string | null }

/** 登记与轮换的唯一一次凭据交付；重放同一幂等键返回 409 CREDENTIAL_ALREADY_ISSUED。 */
export interface IssuedCredential { id: string; clientId: string; credential: string; status: string; rotatedAt?: string; revision?: number }
export interface MachineStatusResult { id: string; status: string; revision: number; credentialRotationRequired: boolean }

/* ---------------- 请求体字段（前端设计文档第 9 节第 6 条） ---------------- */
export const ASSET_FIELDS = { assetKey: 'assetKey', platform: 'platform', environment: 'environment', owner: 'owner', displayName: 'displayName', notes: 'notes', criticality: 'criticality', status: 'status' } as const
export const AUTHORIZATION_FIELDS = { interfaces: 'interfaces', observationAllowed: 'observationAllowed', executionScopes: 'executionScopes', validFrom: 'validFrom', validUntil: 'validUntil', evidenceRef: 'evidenceRef' } as const
export const CONFIG_FIELDS = {
  contractVersion: 'contractVersion', profileSha256: 'profileSha256', captureHealthVersion: 'captureHealthVersion', interfaceIds: 'interfaceIds',
  limits: 'limits', captureScopeId: 'captureScopeId', addressFamily: 'addressFamily', buildSha256: 'buildSha256',
} as const

/** 后端只接受的采集契约与健康版本（GuardJson.CONTRACT、HEALTH_VERSIONS），用于下拉与只读显示。 */
export const CAPTURE_CONTRACT = 'host-guard/5.0.0-rc.2'
export const CAPTURE_HEALTH_VERSIONS = ['host-guard-capture-health/1.0.0', 'host-guard-capture-health/1.1.0'] as const
export const MAX_BATCH_SIZE = 512
export const SHA256_RE = /^[0-9a-f]{64}$/
export const INTERFACE_RE = /^[A-Za-z0-9_.:-]{1,96}$/

export interface AssetQuery { status?: string; q?: string; cursor?: string; limit?: number }
export interface ScopedQuery { assetId?: string; status?: string; cursor?: string; limit?: number }

export interface AssetCreate { assetKey: string; platform: Platform; environment: AssetEnv; owner: string; displayName?: string; notes?: string }
export interface AssetUpdate { displayName?: string | null; notes?: string | null; criticality?: Criticality; owner?: string; status?: AssetStatus }
export interface AuthorizationRequest {
  interfaces: string[]; observationAllowed: boolean; executionScopes: Record<string, unknown>[]
  validFrom: string; validUntil: string; evidenceRef: string
}
export interface SensorCreate { assetId: string; platform: Platform; captureScopeId: string; displayName?: string; notes?: string }
export interface ExecutorCreate { assetId: string; platform: Platform; capabilityProbeRef: string; displayName?: string; notes?: string }
export interface ConfigDraft {
  contractVersion: string; profileSha256: string; captureHealthVersion: string; interfaceIds: string[]
  limits: { maxBatchSize: number }; captureScopeId: string; addressFamily: 'ipv4' | 'ipv6'; buildSha256: string
}

const page = (q: ScopedQuery) => ({ assetId: q.assetId, status: q.status, cursor: q.cursor, limit: q.limit ?? 50 })

export const assetsApi = {
  /* 资产 */
  listAssets: (q: AssetQuery = {}): Promise<Cursor<Asset>> => guard.read('assets', { status: q.status, q: q.q, cursor: q.cursor, limit: q.limit ?? 50 }),
  getAsset: (id: string): Promise<Asset> => guard.get('assets', id),
  /** asset.manage（全局）；登记不授予执行权。 */
  createAsset: (body: AssetCreate, key?: WriteKey): Promise<{ id: string; revision: number }> => guard.create('assets', body, key),
  /** asset.manage；status=disabled/retired 同时暂停该资产新命令与活动绑定，retired 为终态。 */
  updateAsset: (id: string, revision: number, body: AssetUpdate, key?: WriteKey): Promise<{ id: string; status: string; revision: number }> => guard.patch('assets', id, body, revision, key),

  /* 授权 */
  listAuthorizations: (q: ScopedQuery = {}): Promise<GuardReadPage<Authorization>> => guard.read('authorizations', page(q)),
  /** authorization.request；201 pending，不创建防火墙规则。 */
  requestAuthorization: (assetId: string, body: AuthorizationRequest, key?: WriteKey): Promise<{ id: string; status: string; revision: number }> =>
    guard.op('assets', assetId, 'authorizations', body, undefined, key),
  /** authorization.approve；申请人本人 403。 */
  decideAuthorization: (id: string, revision: number, decision: 'approve' | 'reject', reason: string, key?: WriteKey) =>
    guard.op<{ id: string; status: string; revision: number }>('authorizations', id, 'decisions', { decision, reason }, revision, key),
  /** authorization.approve；202 只表示受理：拒绝新命令并排队撤销已有规则。 */
  revokeAuthorization: (id: string, revision: number, reason: string, key?: WriteKey) =>
    guard.op<unknown>('authorizations', id, 'revocations', { reason }, revision, key),
  /** authorization.request；只撤回本人 pending 申请。 */
  withdrawAuthorization: (id: string, revision: number, reason: string, key?: WriteKey) =>
    guard.op<{ id: string; status: string; revision: number }>('authorizations', id, 'withdrawals', { reason }, revision, key),

  /* 传感器与执行器 */
  listSensors: (q: ScopedQuery & { q?: string } = {}): Promise<Cursor<Sensor>> => guard.read('sensors', { ...page(q), q: q.q }),
  getSensor: (id: string): Promise<Sensor> => guard.get('sensors', id),
  listExecutors: (q: ScopedQuery & { q?: string } = {}): Promise<Cursor<Executor>> => guard.read('executors', { ...page(q), q: q.q }),
  getExecutor: (id: string): Promise<Executor> => guard.get('executors', id),
  createSensor: (body: SensorCreate, key?: WriteKey): Promise<IssuedCredential> => guard.create('sensors', body, key),
  createExecutor: (body: ExecutorCreate, key?: WriteKey): Promise<IssuedCredential> => guard.create('executors', body, key),
  updateMachine: (kind: 'sensors' | 'executors', id: string, revision: number, body: { displayName?: string | null; notes?: string | null }, key?: WriteKey) =>
    guard.patch<{ id: string; revision: number }>(kind, id, body, revision, key),
  /** 停用即吊销旧凭据；启用不恢复旧凭据，响应 credentialRotationRequired=true 时须再轮换。 */
  changeMachineStatus: (kind: 'sensors' | 'executors', id: string, revision: number, status: 'active' | 'disabled', reason: string, key?: WriteKey): Promise<MachineStatusResult> =>
    guard.op(kind, id, 'status-changes', { status, reason }, revision, key),
  /** 生成新的一次性凭据，旧凭据立即失效。 */
  rotateCredential: (kind: 'sensors' | 'executors', id: string, reason: string, key?: WriteKey): Promise<IssuedCredential> =>
    guard.op(kind, id, 'credential-rotations', reason ? { reason } : {}, undefined, key),
  /** 心跳投影（ops.read）：只表示存活，不代表采集健康。 */
  listSensorHeartbeats: (q: ScopedQuery = {}): Promise<GuardReadPage<GuardHeartbeat>> => guard.read('sensor-heartbeats', page(q)),
  listExecutorHeartbeats: (q: ScopedQuery = {}): Promise<GuardReadPage<GuardHeartbeat>> => guard.read('executor-heartbeats', page(q)),

  /* 采集配置 */
  listConfigs: (q: ScopedQuery & { sensorId?: string } = {}): Promise<GuardReadPage<SensorConfig>> => guard.read('sensor-configs', { ...page(q), sensorId: q.sensorId }),
  getConfig: (id: string): Promise<SensorConfig> => guard.get('sensor-configs', id),
  draftConfig: (sensorId: string, body: ConfigDraft, key?: WriteKey): Promise<{ id: string; revision: number; status: string }> =>
    guard.op('sensors', sensorId, 'configs', body, undefined, key),
  /** authorization.approve；起草人本人 403，批准仍需代理验证。 */
  decideConfig: (id: string, revision: number, decision: 'approve' | 'reject', reason: string, key?: WriteKey) =>
    guard.op<{ id: string; status: string; revision: number }>('sensor-configs', id, 'decisions', { decision, reason }, revision, key),
  /** 只限本人起草且未被引用的草稿，否则 403 / 409 RESOURCE_IN_USE。 */
  deleteConfig: (id: string, revision: number, key?: WriteKey) => guard.remove<{ id: string; status: string }>('sensor-configs', id, revision, key),

  /* 机器凭据 */
  listMachineClients: (q: ScopedQuery & { clientType?: string } = {}): Promise<GuardReadPage<MachineClient>> =>
    guard.read('machine-clients', { ...page(q), clientType: q.clientType }),
  /** 202：吊销凭据并同时吊销关联传感器/执行器，不可恢复。 */
  revokeMachineClient: (id: string, reason: string, key?: WriteKey) => guard.op<{ id: string; status: string }>('machine-clients', id, 'revocations', { reason }, undefined, key),

  /* 健康窗口（ops.read） */
  listHealthWindows: (q: ScopedQuery & { sensorId?: string; verificationStatus?: string } = {}): Promise<GuardReadPage<GuardHealthWindow>> =>
    guard.read('health-windows', { assetId: q.assetId, sensorId: q.sensorId, verificationStatus: q.verificationStatus, cursor: q.cursor, limit: q.limit ?? 50 }),

  /* 活动发布：没有按资产的绑定集合，按活动与已暂停组合读取绑定后筛出本资产（全局 resource.read）。 */
  listBundles: (status: 'active' | 'suspended'): Promise<Cursor<GuardReleaseBundle>> => guard.read('release-bundles', { status, limit: 50 }),
  listBundleBindings: (bundleId: string): Promise<{ items: AssetBinding[] }> => guard.child('release-bundles', bundleId, 'bindings'),
  listCapabilities: (): Promise<Cursor<GuardCapability>> => guard.read('capabilities', { limit: 200 }),
}

/* ---------------- 显示标签（未知值原样显示） ---------------- */
export const assetStatusLabel: Record<string, string> = { active: '运行中', disabled: '已停用', retired: '已退役' }
export const criticalityLabel: Record<string, string> = { low: '低', medium: '中', high: '高', critical: '关键' }
export const CRITICALITIES: readonly Criticality[] = ['low', 'medium', 'high', 'critical']
export const platformLabel: Record<string, string> = { macos: 'macOS', windows: 'Windows' }
export const authorizationStatusLabel: Record<string, string> = { pending: '待批准', active: '已批准', expired: '已到期', revoked: '已撤销' }
export const validityLabel: Record<string, string> = { valid: '有效期内', not_yet_valid: '未到生效时间', expired: '已过有效期' }
export const configStatusLabel: Record<string, string> = { draft: '草稿', pending: '待批准', approved: '已批准', active: '生效中', retired: '已替换', rejected: '已驳回' }
export const clientStatusLabel: Record<string, string> = { active: '有效', disabled: '已停用', revoked: '已吊销' }
export const bindingStatusLabel: Record<string, string> = { active: '生效中', suspended: '已暂停', retired: '已退役' }
export const scopeLabel: Record<string, string> = { peer_service: '对端 + 服务端口', peer_inbound: '对端全部入站' }
export const directionLabel: Record<string, string> = { inbound: '入站', outbound: '出站' }

/** 资产名称：显示名优先，退回资产键，界面不显示 UUID。 */
export const assetTitle = (a: Pick<Asset, 'displayName' | 'assetKey'>) => a.displayName || a.assetKey
export const assetPlatform = (a: Asset) => a.labels?.platform ?? null
