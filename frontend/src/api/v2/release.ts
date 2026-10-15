/**
 * F3 模型与发布分组的 v2 接口。只封装 GuardController / GuardLabController 已实现的路由。
 *
 * 写操作每次提交生成幂等键，可传 key 重试同一次提交；并发操作必须传当前 revision。
 * 失败原样抛出 ApiError，页面用 errText 显示 request-id，成功后重新读取事实。
 * bindings 是发布组合子资源；evaluations 只读，报告由组合 imports 或 lab reports 登记。
 */
import { guard, type Cursor } from '@/api/client'
import type {
  GuardCapability, GuardDataset, GuardDecisionPolicy, GuardEvaluation, GuardEvaluationPlan,
  GuardLabEventPage, GuardLabQualifications, GuardLabRun, GuardModel, GuardReleaseBundle,
} from '@/api/types'
import { requireDecisionPolicy, type AttackFamily, type DecisionPolicy, type FlowProfile } from './release-policy'

export { DecisionPolicyValidationError, validateDecisionPolicy } from './release-policy'
export type { AttackFamily, DecisionPolicy, FamilyPolicy, PolicyCheck, PolicyIssue, RulePolicy } from './release-policy'

export const MODEL_VALIDATION_PROFILE_ID = 'host-guard-onnx-v1' as const
export const SHA256_RE = /^[0-9a-f]{64}$/
export const isSha256 = (value: string) => SHA256_RE.test(value)

/** 新页面表单可共用这些字段名；制品引用为受控制品根内的相对路径，不是任意 URL。 */
export const RELEASE_FIELDS = {
  manifest: { manifestRef: 'manifestRef', manifestSha256: 'manifestSha256', displayName: 'displayName', notes: 'notes' },
  metadata: { displayName: 'displayName', notes: 'notes' },
  review: { decision: 'decision', reason: 'reason' },
  validation: { validationProfileId: 'validationProfileId' },
  plan: { planRef: 'planRef', planSha256: 'planSha256' },
  bundle: { modelId: 'modelId', policyId: 'policyId', featureProfileSha256: 'featureProfileSha256', extractorSha256: 'extractorSha256', protocolVersions: 'protocolVersions', evaluationPlanId: 'evaluationPlanId', capabilityIds: 'capabilityIds', environment: 'environment' },
  report: { reportRef: 'reportRef', sha256: 'sha256', runnerIdentity: 'runnerIdentity' },
  sealing: { evaluationIds: 'evaluationIds' },
  activation: { assetIds: 'assetIds', authorizationIds: 'authorizationIds' },
  suspension: { reason: 'reason', revokeExisting: 'revokeExisting' },
  retirement: { reason: 'reason' },
  replay: { scenarioId: 'scenarioId', scenarioSha256: 'scenarioSha256', modelId: 'modelId', policyId: 'policyId', speed: 'speed' },
  lab: { sessionRef: 'sessionRef', sha256: 'sha256', runnerIdentity: 'runnerIdentity' },
} as const

export type ModelStatus = 'pending' | 'validated' | 'failed' | 'retired'
export type DatasetStatus = 'active' | 'retired'
export type BundleStatus = 'candidate' | 'evaluated' | 'approved' | 'active' | 'suspended' | 'retired'
export type PolicyStatus = 'draft' | 'reviewed' | 'retired'
export type ReplayStatus = 'queued' | 'running' | 'completed' | 'failed'
export type LabRunStatus = 'registered' | 'running' | 'interrupted' | 'completed' | 'failed' | 'cancelled'

/** 全局目录不接受 assetId；有搜索列的集合才额外提供 q。时间为 UTC，区间为 [from, until)。 */
export interface ReleaseQuery { cursor?: string; limit?: number; from?: string; until?: string; sort?: 'createdAt' | 'updatedAt' }
export interface SearchQuery extends ReleaseQuery { q?: string }
export interface ModelQuery extends SearchQuery { status?: ModelStatus }
export interface DatasetQuery extends SearchQuery { status?: DatasetStatus }
export interface BundleQuery extends SearchQuery { status?: BundleStatus }
export interface PolicyQuery extends SearchQuery { status?: PolicyStatus }
export interface ReplayQuery extends ReleaseQuery { status?: ReplayStatus }
/** 当前后端的筛选白名单与返回状态不同：通过的导入报告返回 passed，不支持按 passed 筛选。 */
export interface EvaluationQuery extends ReleaseQuery { status?: 'pending' | 'running' | 'completed' | 'failed' }
/** lab 列表由独立控制器处理，只接受运行状态、游标与页大小。 */
export interface LabQuery { cursor?: string; limit?: number; status?: LabRunStatus }

export interface ResourceMetadata { displayName: string | null; notes: string | null }
export interface MutableCatalog extends ResourceMetadata { revision: number; updatedAt: string | null }
export interface ReleaseModel extends GuardModel, MutableCatalog { validationStatus: ModelStatus }
export interface ReleaseDataset extends GuardDataset, MutableCatalog { status: DatasetStatus }
export interface ReleasePolicy extends GuardDecisionPolicy, MutableCatalog { status: PolicyStatus; definition: DecisionPolicy }
export interface ReleaseBundle extends GuardReleaseBundle { status: BundleStatus; updatedAt: string | null }
export interface ReleaseCapability extends GuardCapability {
  level: 'research' | 'alert_only' | 'lab_auto' | 'authorized_auto'
  scope: 'peer_service' | 'peer_inbound'
  protectionSetSha256: string | null
  exemptionEvidenceSha256: string | null
}
export type EvaluationPlan = GuardEvaluationPlan
export type Evaluation = GuardEvaluation
/** 校验尚未执行时 GET 子资源返回 null；202 的响应本体是校验报告，不是模型详情。 */
export interface ModelValidation { status: 'validated' | 'failed'; reasonCode?: string; [key: string]: unknown }
export interface AssetBinding {
  id: string; assetId: string; bundleId: string; authorizationId: string; authorizationRevision: number
  status: 'active' | 'suspended'; revision: number; createdAt: string
}
export interface ReplayRun {
  id: string; scenarioId: string; scenarioSha256: string; modelId: string; policyId: string; bundleId: string
  speed: 1; status: ReplayStatus; payload: Record<string, unknown>; contentSha256: string; createdAt: string
}
export interface MutationResult { id: string; status?: string; revision?: number }
export interface ModelMutation extends MutationResult { validationStatus: ModelStatus; candidateOnly?: true }
export interface LabMutation extends MutationResult { eligibilityStatus: string; runStatus: string; revision: number }
export interface LabReportImport {
  evaluationId: string; sessionId: string; status: string; passed: boolean
  qualifiedSources: unknown[]; qualificationEffect: 'none' | 'registered'; [key: string]: unknown
}

export interface ManifestRegistration extends Partial<ResourceMetadata> { manifestRef: string; manifestSha256: string }
export interface Review { decision: 'approve' | 'reject'; reason: string }
export interface ReportImport { reportRef: string; sha256: string; runnerIdentity: string }
export interface FrozenPlanRegistration { planRef: string; planSha256: string }
/** 兼容已有结构化计划登记；新 P6 冻结计划优先使用原文件引用，保持原字节摘要。 */
export interface StructuredPlanRegistration {
  planKey: string; version: string; protocolVersions: Record<string, string>; datasetRefs: string[]
  splitHashes: Record<string, string>; behaviorSourceScope: unknown[]; scenarioMappingSha256: string
  labelTimelineSha256: string; captureHealthSha256: string; latencyRegistration: Record<string, unknown>
  metrics: Record<string, unknown>; budget: Record<string, unknown>; scenarioRefs: unknown[]
}
export interface BundleRequest {
  modelId: string; policyId: string; featureProfileSha256: string; extractorSha256: string
  protocolVersions: Record<string, string>; evaluationPlanId: string; capabilityIds: string[]
  environment: 'research' | 'lab' | 'authorized'
}
export interface CapabilityRegistration {
  capabilityKey: string; version: string; platform: string; adapterVersion: string; addressFamily: string
  transport: string; direction: string; family: AttackFamily; profile: FlowProfile
  behaviorScope: unknown; latencyLimits: Record<string, unknown>; level: ReleaseCapability['level']
  evidenceRef: string; evidenceSha256: string; runnerIdentity: string
  scope?: 'peer_service' | 'peer_inbound'; protectionSetSha256?: string
  exemptionEvidenceRef?: string; exemptionEvidenceSha256?: string
}
export interface ReplayRequest { scenarioId: string; scenarioSha256: string; modelId: string; policyId: string; speed: 1 }
export interface ReplayStart { scenarioRef: string; closeoutRef: string; bindings: { segmentId: string; sensorId: string; bootId: string }[] }
export interface LabRegistration { sessionRef: string; sha256: string; runnerIdentity: string }
/** runner 追加的是受控事实引用；不接受任意事件 JSON 或客户端声明的执行结果。 */
export type LabFact = { eventId: string; scenarioId: string } & (
  | { kind: 'scenario_result'; reportRef: string; sha256: string }
  | { kind: 'observation' | 'decision' | 'command' | 'receipt' | 'verified_receipt'; referenceId: string }
)

const collection = <T>(path: string, query: ReleaseQuery | LabQuery = {}) =>
  guard.read<Cursor<T>>(path, { ...query, limit: query.limit ?? 50 })
const operate = <T>(path: string, id: string, operation: string, body: unknown, revision: number, key?: string) =>
  guard.op<T>(path, id, operation, body, revision, key)

export const releaseApi = {
  // 模型 / 数据集：登记不可变 manifest，只编辑资料；退役及删除冲突由后端返回 409。
  listModels: (query?: ModelQuery) => collection<ReleaseModel>('models', query),
  getModel: (id: string) => guard.get<ReleaseModel>('models', id),
  registerModel: (body: ManifestRegistration, key?: string) => guard.create<ModelMutation>('models', body, key),
  updateModel: (id: string, revision: number, body: Partial<ResourceMetadata>, key?: string) => guard.patch<MutationResult>('models', id, body, revision, key),
  retireModel: (id: string, revision: number, reason: string, key?: string) => operate<ModelMutation>('models', id, 'retirements', { reason }, revision, key),
  validateModel: (id: string, key?: string) => guard.op<ModelValidation>('models', id, 'validations', { validationProfileId: MODEL_VALIDATION_PROFILE_ID }, undefined, key),
  getModelValidations: (id: string) => guard.child<ModelValidation | null>('models', id, 'validations'),
  listDatasets: (query?: DatasetQuery) => collection<ReleaseDataset>('datasets', query),
  getDataset: (id: string) => guard.get<ReleaseDataset>('datasets', id),
  registerDataset: (body: ManifestRegistration, key?: string) => guard.create<MutationResult>('datasets', body, key),
  updateDataset: (id: string, revision: number, body: Partial<ResourceMetadata>, key?: string) => guard.patch<MutationResult>('datasets', id, body, revision, key),
  retireDataset: (id: string, revision: number, reason: string, key?: string) => operate<MutationResult>('datasets', id, 'retirements', { reason }, revision, key),

  // 发布组合：批准、激活是独立操作；激活只是请求，202 不代表真实执行成功。
  listBundles: (query?: BundleQuery) => collection<ReleaseBundle>('release-bundles', query),
  getBundle: (id: string) => guard.get<ReleaseBundle>('release-bundles', id),
  requestBundle: (body: BundleRequest, key?: string) => guard.create<MutationResult>('release-bundles', body, key),
  importBundleReport: (id: string, body: ReportImport, key?: string) => guard.op<MutationResult>('release-bundles', id, 'imports', body, undefined, key),
  sealBundle: (id: string, revision: number, evaluationIds: string[], key?: string) => operate<MutationResult & { sealedManifestSha256: string }>('release-bundles', id, 'sealings', { evaluationIds }, revision, key),
  decideBundle: (id: string, revision: number, body: Review, key?: string) => operate<MutationResult>('release-bundles', id, 'decisions', body, revision, key),
  activateBundle: (id: string, revision: number, body: { assetIds: string[]; authorizationIds: string[] }, key?: string) =>
    operate<MutationResult & { bindingIds: string[] }>('release-bundles', id, 'activations', body, revision, key),
  suspendBundle: (id: string, revision: number, body: { reason: string; revokeExisting: boolean }, key?: string) => operate<MutationResult>('release-bundles', id, 'suspensions', body, revision, key),
  retireBundle: (id: string, revision: number, reason: string, key?: string) => operate<MutationResult>('release-bundles', id, 'retirements', { reason }, revision, key),
  listBundleBindings: (id: string) => guard.child<{ items: AssetBinding[] }>('release-bundles', id, 'bindings'),

  // 策略原文先经过同一 Schema 和静态不变量预校验；错误不会发出起草请求。
  listPolicies: (query?: PolicyQuery) => collection<ReleasePolicy>('decision-policies', query),
  getPolicy: (id: string) => guard.get<ReleasePolicy>('decision-policies', id),
  draftPolicy: (input: unknown, key?: string) => guard.create<MutationResult>('decision-policies', requireDecisionPolicy(input), key),
  deletePolicy: (id: string, revision: number, key?: string) => guard.remove<MutationResult>('decision-policies', id, revision, key),
  reviewPolicy: (id: string, revision: number, body: Review, key?: string) => operate<MutationResult>('decision-policies', id, 'reviews', body, revision, key),
  listCapabilities: (query?: SearchQuery) => collection<ReleaseCapability>('capabilities', query),
  getCapability: (id: string) => guard.get<ReleaseCapability>('capabilities', id),
  registerCapability: (body: CapabilityRegistration, key?: string) => guard.create<MutationResult & { level: ReleaseCapability['level']; scope: ReleaseCapability['scope'] }>('capabilities', body, key),

  // 验证记录：没有独立 POST /evaluations；签名报告导入后才能读取评价事实。
  listEvaluationPlans: (query?: SearchQuery) => collection<EvaluationPlan>('evaluation-plans', query),
  getEvaluationPlan: (id: string) => guard.get<EvaluationPlan>('evaluation-plans', id),
  registerEvaluationPlan: (body: FrozenPlanRegistration | StructuredPlanRegistration, key?: string) => guard.create<MutationResult & { planSha256: string }>('evaluation-plans', body, key),
  listEvaluations: (query?: EvaluationQuery) => collection<Evaluation>('evaluations', query),
  getEvaluation: (id: string) => guard.get<Evaluation>('evaluations', id),
  listReplayRuns: (query?: ReplayQuery) => collection<ReplayRun>('replay-runs', query),
  getReplayRun: (id: string) => guard.get<ReplayRun>('replay-runs', id),
  createReplayRun: (body: ReplayRequest, key?: string) => guard.create<MutationResult & { speed: 1; bundleId: string }>('replay-runs', body, key),
  /** 以下回放推进供受控 runner 对接；页面只建立研究回放，不在浏览器重放流量。 */
  startReplayRun: (id: string, body: ReplayStart, key?: string) => guard.op<MutationResult>('replay-runs', id, 'starts', body, undefined, key),
  completeReplayRun: (id: string, body: { reportRef: string; reportSha256: string }, key?: string) => guard.op<MutationResult>('replay-runs', id, 'completions', body, undefined, key),
  failReplayRun: (id: string, body: { reasonCode: string; reason: string }, key?: string) => guard.op<MutationResult>('replay-runs', id, 'failures', body, undefined, key),

  // lab 资格与运行状态分开读取；浏览器能批准/作废，生命周期推进和报告导入归 runner。
  listLabRuns: (query?: LabQuery) => collection<GuardLabRun>('lab-validation-runs', query),
  getLabRun: (id: string) => guard.get<GuardLabRun>('lab-validation-runs', id),
  createLabRun: (body: LabRegistration, key?: string) => guard.create<LabMutation>('lab-validation-runs', body, key),
  decideLabRun: (id: string, revision: number, body: Review, key?: string) => operate<LabMutation>('lab-validation-runs', id, 'decisions', body, revision, key),
  revokeLabRun: (id: string, revision: number, reason: string, key?: string) => operate<LabMutation>('lab-validation-runs', id, 'revocations', { reason }, revision, key),
  getLabEvents: (id: string, query: { after?: number; limit?: number } = {}) =>
    guard.read<GuardLabEventPage>(`lab-validation-runs/${encodeURIComponent(id)}/events`, { after: query.after ?? 0, limit: query.limit ?? 50 }),
  getLabReportInput: (id: string) => guard.child<Record<string, unknown>>('lab-validation-runs', id, 'report-input'),
  getLabQualifications: (id: string) => guard.child<GuardLabQualifications>('lab-validation-runs', id, 'qualifications'),
  startLabRun: (id: string, revision: number, key?: string) => operate<LabMutation>('lab-validation-runs', id, 'starts', {}, revision, key),
  interruptLabRun: (id: string, revision: number, reason: string, key?: string) => operate<LabMutation>('lab-validation-runs', id, 'interruptions', { reason }, revision, key),
  resumeLabRun: (id: string, revision: number, key?: string) => operate<LabMutation>('lab-validation-runs', id, 'resumptions', {}, revision, key),
  completeLabRun: (id: string, revision: number, body: { outcome: 'completed' | 'failed'; reason: string }, key?: string) => operate<LabMutation>('lab-validation-runs', id, 'completions', body, revision, key),
  reconcileLabRun: (id: string, revision: number, key?: string) => operate<LabMutation>('lab-validation-runs', id, 'reconciliations', {}, revision, key),
  appendLabFact: (id: string, revision: number, body: LabFact, key?: string) => operate<{ eventId: string; revision: number; duplicate: boolean }>('lab-validation-runs', id, 'events', body, revision, key),
  importLabReport: (id: string, revision: number, body: ReportImport, key?: string) => operate<LabReportImport>('lab-validation-runs', id, 'reports', body, revision, key),
}
