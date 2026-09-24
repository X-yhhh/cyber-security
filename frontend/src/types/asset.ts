export type AssetEnvironment = 'authorized' | 'lab';
export type AssetCriticality = 'critical' | 'high' | 'medium' | 'low';
export type AssetStatus = 'active' | 'maintenance' | 'decommissioned';

export interface Asset {
  id: number;
  assetKey: string;
  name: string;
  ipAddress: string;
  macAddress?: string;
  osType: 'macos' | 'windows' | 'linux';
  osVersion?: string;
  environment: AssetEnvironment;
  criticality: AssetCriticality;
  owner: string;
  status: AssetStatus;
  labels: Record<string, string>;
  createdAt: string;
  updatedAt: string;
  activeAuthorization?: AssetAuthorization;
}

export type AuthorizationStatus = 'pending' | 'active' | 'expired' | 'revoked' | 'rejected';

export interface AssetAuthorization {
  id: number;
  assetId: number;
  assetKey: string;
  authorizationRef: string;
  scope: string[];
  validFrom: string;
  validUntil: string;
  status: AuthorizationStatus;
  requestedBy: string;
  approvedBy?: string;
  approvedAt?: string;
  createdAt: string;
}

export interface SensorAgent {
  id: number;
  agentKey: string;
  assetId: number;
  assetKey: string;
  assetName: string;
  platform: 'macos' | 'windows';
  agentVersion: string;
  status: 'online' | 'degraded' | 'offline';
  interfaceScope: string[];
  lastHeartbeatAt: string;
  registeredAt: string;
  flowWindowSeconds: number;
  featureContractVersion: string;
  // 健康统计指标
  flowsSeen: number;
  flowsEmitted: number;
  flowsDropped: number;
  queueDepth: number;
  cpuPercent: number;
  memoryMb: number;
}
