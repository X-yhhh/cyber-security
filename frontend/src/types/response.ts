export type ActionType = 'temporary_block_ip' | 'rate_limit_flow' | 'isolate_host';
export type ApprovalStatus = 'pending' | 'approved' | 'rejected' | 'expired' | 'cancelled';
export type ExecutionStatus = 'queued' | 'running' | 'succeeded' | 'failed' | 'timed_out' | 'rolled_back';

export interface ResponsePolicy {
  id: number;
  policyKey: string;
  version: string;
  name: string;
  environment: 'authorized' | 'lab';
  actionType: ActionType;
  allowedTargets: string[];
  maxDurationSeconds: number;
  approvalRequired: boolean;
  status: 'active' | 'inactive';
}

export interface ApprovalTask {
  id: number;
  taskKey: string;
  eventId: number;
  eventTitle: string;
  policyId: number;
  policyKey: string;
  assetId: number;
  assetKey: string;
  assetName: string;
  targetIp: string;
  actionType: ActionType;
  durationSeconds: number; // TTL
  status: ApprovalStatus;
  requestedBy: string; // 申请人
  requestedAt: string;
  idempotencyKey: string;
  requestDigest: string;
  reason: string;
  reviewedBy?: string; // 独立审批人（申请人与审批人分离）
  reviewedAt?: string;
  decisionReason?: string;
  expiresAt: string;
}

export interface ActionExecution {
  id: number;
  executionKey: string;
  eventId: number;
  approvalTaskId?: number;
  assetId: number;
  assetName: string;
  targetIp: string;
  actionType: ActionType;
  durationSeconds: number;
  expiresAt: string;
  status: ExecutionStatus;
  adapterKey: string;
  startedAt: string;
  finishedAt?: string;
  rollbackRef?: string;
  canRollback: boolean;
  resultReceipt?: string;
}
