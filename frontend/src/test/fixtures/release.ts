/** F3 的合成资源夹具，仅用于 msw；不含真实制品、主机信息、签名或执行授权。 */
import example from '../../../../docs/contracts/examples/decision-policy.json'
import type {
  AssetBinding, DecisionPolicy, Evaluation, EvaluationPlan, ModelValidation, ReleaseBundle,
  ReleaseCapability, ReleaseDataset, ReleaseModel, ReleasePolicy, ReplayRun,
} from '@/api/v2/release'
import type { GuardLabEvent, GuardLabQualifications, GuardLabRun } from '@/api/types'
import { singleRoleUsers } from '@/test/roles'

const fixtureId = (n: number) => `f3000000-0000-4000-8000-${String(n).padStart(12, '0')}`
export const RELEASE_IDS = {
  model: fixtureId(1), dataset: fixtureId(2), policy: fixtureId(3), bundle: fixtureId(4),
  capability: fixtureId(5), plan: fixtureId(6), evaluation: fixtureId(7), replay: fixtureId(8), lab: fixtureId(9),
  validatedModel: fixtureId(11), retiredDataset: fixtureId(12), reviewedPolicy: fixtureId(13), approvedBundle: fixtureId(14),
  labCapability: fixtureId(15), completedLab: fixtureId(19), binding: fixtureId(20),
  asset: '10000000-0000-4000-8000-000000000001', authorization: fixtureId(22),
} as const
export const RELEASE_SHA = 'a'.repeat(64)
export const RELEASE_TIME = '2026-10-15T01:00:00Z'

export function policyFixture(): DecisionPolicy {
  return { ...structuredClone(example) as DecisionPolicy, policyId: RELEASE_IDS.policy, modelId: RELEASE_IDS.model, supportedCapabilityIds: [RELEASE_IDS.capability], evaluationPlanSha256: RELEASE_SHA }
}

export interface ReleaseCollections {
  models: ReleaseModel
  datasets: ReleaseDataset
  'decision-policies': ReleasePolicy
  'release-bundles': ReleaseBundle
  capabilities: ReleaseCapability
  'evaluation-plans': EvaluationPlan
  evaluations: Evaluation
  'replay-runs': ReplayRun
  'lab-validation-runs': GuardLabRun
}
export type ReleaseCollection = keyof ReleaseCollections
export const RELEASE_COLLECTIONS: ReleaseCollection[] = ['models', 'datasets', 'decision-policies', 'release-bundles', 'capabilities', 'evaluation-plans', 'evaluations', 'replay-runs', 'lab-validation-runs']
export interface ReleaseWrite {
  method: string; path: string; body: unknown; ifMatch: string | null; idempotencyKey: string | null
}
export interface ReleaseFixtureState {
  rows: { [K in ReleaseCollection]: ReleaseCollections[K][] }
  bindings: Record<string, AssetBinding[]>
  events: Record<string, GuardLabEvent[]>
  qualifications: Record<string, GuardLabQualifications>
  validations: Record<string, ModelValidation | null>
  owners: Record<string, number>
  referenced: Set<string>
  writes: ReleaseWrite[]
}

export function createReleaseFixture(): ReleaseFixtureState {
  const model: ReleaseModel = {
    id: RELEASE_IDS.model, modelKey: 'fixture-model', version: 'fixture-v1', manifestRef: 'fixtures/model/manifest.json',
    manifestSha256: RELEASE_SHA, artifactSha256: RELEASE_SHA, contractId: null,
    manifest: { candidateOnly: true, modelVersion: 'fixture-v1' }, validationStatus: 'pending', validation: null,
    displayName: '合成模型候选', notes: '仅测试资源，不具备发布资格。', revision: 1, updatedAt: null, createdAt: RELEASE_TIME,
  }
  const dataset: ReleaseDataset = {
    id: RELEASE_IDS.dataset, datasetKey: 'fixture-dataset', version: 'fixture-v1', manifestRef: 'fixtures/dataset/manifest.json',
    manifestSha256: RELEASE_SHA, payload: {}, displayName: '合成数据集', notes: null, status: 'active', revision: 1, updatedAt: null, createdAt: RELEASE_TIME,
  }
  const policy: ReleasePolicy = {
    id: RELEASE_IDS.policy, policyKey: 'fixture-policy', version: 'fixture-v1', modelId: RELEASE_IDS.model,
    planId: RELEASE_IDS.plan, definition: policyFixture(), definitionSha256: RELEASE_SHA, status: 'draft',
    displayName: '只告警策略', notes: null, revision: 1, updatedAt: null, createdAt: RELEASE_TIME,
  }
  const bundle: ReleaseBundle = {
    id: RELEASE_IDS.bundle, bundleKey: 'fixture-bundle', version: '1', modelId: RELEASE_IDS.model, policyId: RELEASE_IDS.policy,
    contractId: null, planId: RELEASE_IDS.plan, environment: 'lab', subjectSha256: RELEASE_SHA,
    subject: { mode: 'alert_only', capabilityIds: [RELEASE_IDS.capability] }, sealedManifestSha256: null,
    sealedManifest: null, status: 'candidate', revision: 1, updatedAt: null, createdAt: RELEASE_TIME,
  }
  const capability: ReleaseCapability = {
    id: RELEASE_IDS.capability, capabilityKey: 'fixture-alert-only', version: '1', platform: 'macos', level: 'alert_only',
    scope: 'peer_service', protectionSetSha256: null, exemptionEvidenceSha256: null,
    payload: { family: 'brute_force', profile: 'flow-prefix-v1' }, createdAt: RELEASE_TIME,
  }
  const plan: EvaluationPlan = { id: RELEASE_IDS.plan, planKey: 'fixture-frozen-plan', version: 'fixture-v1', planSha256: RELEASE_SHA, payload: { kind: 'p6-frozen', digest: 'raw-bytes-sha256' }, createdAt: RELEASE_TIME }
  const evaluation: Evaluation = {
    id: RELEASE_IDS.evaluation, planId: RELEASE_IDS.plan, bundleId: RELEASE_IDS.bundle, runKind: 'final', runnerIdentity: 'fixture-runner',
    status: 'passed', reportRef: 'fixtures/report.json', reportSha256: RELEASE_SHA, payload: { evidenceKind: 'synthetic', passed: true }, createdAt: RELEASE_TIME,
  }
  const replay: ReplayRun = {
    id: RELEASE_IDS.replay, scenarioId: fixtureId(30), scenarioSha256: RELEASE_SHA, modelId: RELEASE_IDS.model, policyId: RELEASE_IDS.policy,
    bundleId: RELEASE_IDS.bundle, speed: 1, status: 'queued', payload: {}, contentSha256: RELEASE_SHA, createdAt: RELEASE_TIME,
  }
  const lab: GuardLabRun = {
    id: RELEASE_IDS.lab, eligibilityStatus: 'pending', effectiveEligibility: 'pending', blockedReason: null,
    runStatus: 'registered', timedOut: false, revision: 1, assetId: RELEASE_IDS.asset, bundleId: RELEASE_IDS.approvedBundle,
    sessionSha256: RELEASE_SHA, manifestSha256: RELEASE_SHA, evidenceKind: 'synthetic', validUntil: '2026-10-16T01:00:00Z',
    startedAt: null, endedAt: null, stopRequestedAt: null, cleanupStatus: 'not_asserted', executionAuthority: false,
  }
  return {
    rows: {
      models: [model, { ...structuredClone(model), id: RELEASE_IDS.validatedModel, modelKey: 'validated-model', displayName: '已校验合成模型', validationStatus: 'validated', validation: { status: 'validated' } }],
      datasets: [dataset, { ...dataset, id: RELEASE_IDS.retiredDataset, datasetKey: 'retired-dataset', status: 'retired' }],
      'decision-policies': [policy, { ...structuredClone(policy), id: RELEASE_IDS.reviewedPolicy, status: 'reviewed' }],
      'release-bundles': [bundle, { ...structuredClone(bundle), id: RELEASE_IDS.approvedBundle, modelId: RELEASE_IDS.validatedModel, policyId: RELEASE_IDS.reviewedPolicy, bundleKey: 'fixture-approved-bundle', status: 'approved', sealedManifestSha256: RELEASE_SHA, sealedManifest: { reports: [RELEASE_IDS.evaluation] } }],
      capabilities: [capability, { ...capability, id: RELEASE_IDS.labCapability, capabilityKey: 'fixture-lab-only', level: 'lab_auto' }],
      'evaluation-plans': [plan], evaluations: [evaluation], 'replay-runs': [replay],
      'lab-validation-runs': [lab, { ...lab, id: RELEASE_IDS.completedLab, eligibilityStatus: 'active', effectiveEligibility: 'active', runStatus: 'completed', startedAt: RELEASE_TIME, endedAt: '2026-10-15T01:01:00Z' }],
    },
    bindings: { [RELEASE_IDS.approvedBundle]: [{ id: RELEASE_IDS.binding, assetId: RELEASE_IDS.asset, bundleId: RELEASE_IDS.approvedBundle, authorizationId: RELEASE_IDS.authorization, authorizationRevision: 1, status: 'suspended', revision: 1, createdAt: RELEASE_TIME }] },
    events: { [RELEASE_IDS.lab]: [{ eventId: fixtureId(40), sequence: 1, sha256: RELEASE_SHA, fact: { kind: 'lifecycle', operation: 'registered' } }] },
    qualifications: { [RELEASE_IDS.completedLab]: { sessionId: RELEASE_IDS.completedLab, bundleId: RELEASE_IDS.approvedBundle, bundleUsable: true, sources: [] } },
    validations: { [RELEASE_IDS.model]: null, [RELEASE_IDS.validatedModel]: { status: 'validated' } },
    owners: Object.fromEntries([policy.id, RELEASE_IDS.reviewedPolicy, bundle.id, RELEASE_IDS.approvedBundle, lab.id, RELEASE_IDS.completedLab].map((id) => [id, singleRoleUsers.model_operator.id])),
    referenced: new Set([RELEASE_IDS.validatedModel, RELEASE_IDS.reviewedPolicy]), writes: [],
  }
}
