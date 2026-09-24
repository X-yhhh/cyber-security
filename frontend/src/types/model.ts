export type ModelTaskType = 'binary_classification' | 'multiclass_classification';
export type ModelApprovalStatus = 'candidate' | 'validated' | 'approved' | 'active' | 'retired' | 'rejected';
export type DeploymentMode = 'local' | 'remote';

export interface ModelManifest {
  manifestVersion: string;
  modelKey: string;
  version: string;
  algorithm: string;
  dataset: string;
  datasetSplitFingerprint: string;
  featureOrder: string[];
  metrics: {
    accuracy: number;
    f1Score: number;
    precision: number;
    recall: number;
    aucRoc: number;
    dosRecall: number;
    falseAlarmRate: number;
  };
  thresholdStrategy: {
    optimalThreshold: number;
    strategy: string;
  };
  runtime: {
    framework: string;
    targetRuntime: string;
    sha256: string;
  };
}

export interface ModelVersion {
  id: number;
  modelKey: string;
  version: string;
  taskType: ModelTaskType;
  manifestVersion: string;
  manifest: ModelManifest;
  artifactRef: string;
  artifactSha256: string;
  featureContractVersion: string;
  approvalStatus: ModelApprovalStatus;
  deploymentMode: DeploymentMode;
  approvedBy?: string;
  createdAt: string;
}

export interface ModelReleaseRecord {
  id: number;
  modelVersionId: number;
  modelKey: string;
  version: string;
  releaseStatus: 'pending_review' | 'approved' | 'rejected';
  requestedBy: string;
  requestReason: string;
  requestedAt: string;
  approvedBy?: string;
  decisionReason?: string;
  reviewedAt?: string;
}

export interface DriftMetricWindow {
  id: number;
  dataSourceKey: string;
  modelVersion: string;
  windowStart: string;
  windowEnd: string;
  qualityRejectRate: number;
  driftStatus: 'normal' | 'slight_drift' | 'severe_drift';
  featureStats: Record<string, { ksStatistic: number; pValue: number; drifted: boolean }>;
  scoreStats: { mean: number; std: number };
}

export interface FeedbackSample {
  id: number;
  sourceRecordKey: string;
  alertId?: number;
  groundTruthLabel: string;
  labelSource: string;
  evidenceRef: string;
  reviewedBy: string;
  reviewedAt: string;
  datasetVersion: string;
  trainingEligible: boolean;
}

export interface ModelTrainingJob {
  id: number;
  jobKey: string;
  datasetVersion: string;
  sampleManifestRef: string;
  algorithm: string;
  trainHostRef: string; // 'Windows-CUDA-01'
  status: 'requested' | 'approved' | 'running' | 'completed' | 'failed';
  requestedBy: string;
  approvedBy?: string;
  startedAt?: string;
  finishedAt?: string;
  resultManifestRef?: string;
}
