export type DataSourceType = 'benchmark_unsw' | 'replay_file' | 'host_sensor' | 'network_mirror';

export interface DataSource {
  id: number;
  sourceKey: string;
  name: string;
  sourceType: DataSourceType;
  environment: 'authorized' | 'lab';
  schemaVersion: string;
  status: 'active' | 'paused' | 'error';
  lastSuccessAt: string;
  recordCount: number;
  description: string;
}

export interface SourceMapping {
  id: number;
  dataSourceId: number;
  mappingVersion: string;
  status: 'draft' | 'approved' | 'active';
  approvedBy?: string;
  fieldCount: number;
  createdAt: string;
  mappingRules: Array<{
    sourceField: string;
    targetField: string;
    dataType: string;
    unitConversion?: string;
    isRequired: boolean;
  }>;
}

export interface IngestBatch {
  id: number;
  batchKey: string;
  dataSourceKey: string;
  status: 'completed' | 'processing' | 'rejected' | 'completed_with_errors';
  totalCount: number;
  acceptedCount: number;
  rejectedCount: number;
  startedAt: string;
  finishedAt?: string;
  rejectionReasons?: Record<string, number>;
}

export interface AuditLog {
  id: number;
  occurredAt: string;
  actorType: 'user' | 'system' | 'connector';
  actorName: string;
  action: string;
  resourceType: string;
  resourceId: string;
  requestId: string;
  outcome: 'success' | 'failure' | 'denied';
  reason?: string;
  beforeHash?: string;
  afterHash?: string;
}
