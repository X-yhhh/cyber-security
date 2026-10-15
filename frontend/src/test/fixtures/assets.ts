/** F4 合成资产接入事实；只用于协议与页面回归，不代表真实采集、授权或防火墙状态。 */
import type { Authorization, ConfigDraft, Executor, MachineClient, Sensor, SensorConfig } from '@/api/v2/assets'
import { CAPTURE_CONTRACT, CAPTURE_HEALTH_VERSIONS } from '@/api/v2/assets'
import type { GuardHealthWindow, GuardHeartbeat } from '@/api/types'
import { ASSET_1, ASSET_2 } from '@/test/handlers/detect'
import { singleRoleUsers } from '@/test/roles'

export const F4_IDS = {
  sensor: 'f4000000-0000-4000-8000-000000000001', executor: 'f4000000-0000-4000-8000-000000000002',
  ownAuthorization: 'f4000000-0000-4000-8000-000000000003', authorization: 'f4000000-0000-4000-8000-000000000004',
  activeAuthorization: 'f4000000-0000-4000-8000-000000000005', ownConfig: 'f4000000-0000-4000-8000-000000000006',
  config: 'f4000000-0000-4000-8000-000000000007', sensorClient: 'f4000000-0000-4000-8000-000000000008',
  executorClient: 'f4000000-0000-4000-8000-000000000009', scope: 'f4000000-0000-4000-8000-000000000010',
  otherSensor: 'f4000000-0000-4000-8000-000000000011', otherConfig: 'f4000000-0000-4000-8000-000000000012',
} as const
export const F4_TIME = '2026-10-15T03:00:00Z'

/** 摘要为合成值；真实后端还会核验已冻结的特征档案摘要。 */
export function configDefinition(): ConfigDraft {
  return { contractVersion: CAPTURE_CONTRACT, profileSha256: 'a'.repeat(64), captureHealthVersion: CAPTURE_HEALTH_VERSIONS[1], interfaceIds: ['fixture0'], limits: { maxBatchSize: 256 }, captureScopeId: F4_IDS.scope, addressFamily: 'ipv4', buildSha256: 'b'.repeat(64) }
}

export function createAssetsFixture() {
  const now = new Date().toISOString()
  const sensor: Sensor = { id: F4_IDS.sensor, assetId: ASSET_1, agentKey: F4_IDS.sensor, platform: 'macos', agentVersion: 'fixture-v5', capabilities: [], status: 'active', registeredAt: F4_TIME, lastHeartbeatAt: now, revision: 1, guardBootId: null, createdAt: F4_TIME, displayName: '合成采集器', notes: null }
  const executor: Executor = { id: F4_IDS.executor, assetId: ASSET_1, platform: 'macos', adapterVersion: 'fixture', capabilityHash: 'c'.repeat(64), bootId: null, status: 'active', lastHeartbeat: now, health: null, revision: 1, createdAt: F4_TIME, displayName: '合成执行器', notes: null }
  const authorization: Authorization = { id: F4_IDS.authorization, assetId: ASSET_1, status: 'pending', revision: 1, createdAt: F4_TIME, validFrom: new Date(Date.now() - 86_400_000).toISOString(), validUntil: new Date(Date.now() + 30 * 86_400_000).toISOString(), validity: 'valid', scope: { interfaces: ['fixture0'], observationAllowed: true, executionScopes: [] }, requestedBy: 999 }
  const config: SensorConfig = { id: F4_IDS.config, assetId: ASSET_1, sensorId: F4_IDS.sensor, status: 'draft', revision: 1, createdAt: F4_TIME, configVersion: F4_IDS.config, featureContractVersion: CAPTURE_CONTRACT, activatedAt: null, contentSha256: 'd'.repeat(64), definition: configDefinition(), requestedBy: 999 }
  const client = (id: string, sensorId: string | null, executorId: string | null): MachineClient => ({ id, assetId: ASSET_1, sensorId, executorId, clientType: sensorId ? 'sensor' : 'executor', status: 'active', createdAt: F4_TIME, lastUsedAt: null, expiresAt: null })
  const heartbeat: GuardHeartbeat = { id: sensor.id, assetId: ASSET_1, status: 'active', revision: 1, receivedAt: now, bootId: null, freshness: 'fresh', healthState: 'healthy', agentVersion: sensor.agentVersion, currentConfig: null }
  const window = (healthState: string, i: number): GuardHealthWindow => ({
    id: `f4100000-0000-4000-8000-${String(i).padStart(12, '0')}`, assetId: ASSET_1, sensorId: sensor.id, captureScopeId: F4_IDS.scope, sequence: i,
    observerSessionId: null, intervalStart: now, intervalEnd: now, receivedAt: now,
    verificationStatus: healthState === 'unknown' ? 'COUNTER_UNKNOWN' : healthState === 'unhealthy' ? 'CAPTURE_GAP' : healthState === 'replay_healthy' ? 'replay_healthy' : 'healthy',
    serverVerifiedHealthy: healthState === 'healthy' || healthState === 'stale', failureReason: healthState === 'unknown' ? 'COUNTER_UNKNOWN' : null,
    freshness: healthState === 'stale' ? 'stale' : 'fresh', healthState, healthBasis: healthState === 'replay_healthy' ? 'server_verified_file_replay_window' : 'server_verified_window',
    healthVersion: CAPTURE_HEALTH_VERSIONS[1], captureSource: healthState === 'replay_healthy' ? 'file_replay' : 'live_pcap', captureGap: healthState === 'unhealthy', clockSkewMs: null,
    counterStart: { packetsSeen: 0, kernelDrops: null, capacityDrops: 0 }, counterEnd: { packetsSeen: 12, kernelDrops: null, capacityDrops: 0 },
  })
  return {
    sensors: [sensor, { ...sensor, id: F4_IDS.otherSensor, agentKey: F4_IDS.otherSensor, assetId: ASSET_2, displayName: '范围外采集器' }], executors: [executor],
    authorizations: [{ ...authorization, id: F4_IDS.ownAuthorization, requestedBy: singleRoleUsers.platform_admin.id }, authorization, { ...authorization, id: F4_IDS.activeAuthorization, status: 'active' }],
    configs: [{ ...config, id: F4_IDS.ownConfig, requestedBy: singleRoleUsers.platform_admin.id }, config, { ...config, id: F4_IDS.otherConfig, sensorId: F4_IDS.otherSensor, assetId: ASSET_2 }],
    clients: [client(F4_IDS.sensorClient, sensor.id, null), client(F4_IDS.executorClient, null, executor.id)],
    sensorHeartbeats: [heartbeat, { ...heartbeat, id: F4_IDS.otherSensor, assetId: ASSET_2, freshness: 'stale', healthState: 'stale', receivedAt: new Date(Date.now() - 20_000).toISOString() }], executorHeartbeats: [{ ...heartbeat, id: executor.id, adapterVersion: executor.adapterVersion }],
    healthWindows: ['unknown', 'stale', 'unhealthy', 'healthy', 'replay_healthy'].map(window),
  }
}
