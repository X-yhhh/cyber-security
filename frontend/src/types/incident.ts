export type EventSeverity = 'critical' | 'high' | 'medium' | 'low';
export type EventStatus = 'open' | 'investigating' | 'contained' | 'resolved' | 'false_positive' | 'closed';

export interface SecurityEvent {
  id: number;
  eventKey: string;
  title: string;
  category: string; // 如 'DoS', 'Exploits', 'Reconnaissance', 'Generic', 'Fuzzers'
  severity: EventSeverity;
  status: EventStatus;
  riskScore: number; // 0-100
  riskRuleVersion: string;
  firstSeenAt: string;
  lastSeenAt: string;
  assigneeName?: string;
  assigneeId?: number;
  closedAt?: string;
  impactedAssets: Array<{
    assetId: number;
    assetKey: string;
    assetName: string;
    ipAddress: string;
    criticality: string;
  }>;
  alertCount: number;
  evidenceCount: number;
  summary: string;
}

export interface DetectionAlert {
  id: number;
  alertKey: string;
  ingestRecordId: number;
  inferenceRequestId?: number;
  alertType: string;
  severity: EventSeverity;
  score: number; // 模型输出 0.0 - 1.0
  thresholdVersion: string;
  status: 'new' | 'correlated' | 'suppressed';
  detectedAt: string;
  sourceIp: string;
  sourcePort: number;
  destIp: string;
  destPort: number;
  protocol: string;
  flowDuration: number;
  flowBytes: number;
  flowPackets: number;
  attackCategory?: string;
  featureSnippet?: Record<string, any>;
}

export interface EventTimelineEntry {
  id: number;
  eventId: number;
  occurredAt: string;
  entryType: 'alert_linked' | 'investigation_note' | 'status_change' | 'action_requested' | 'action_executed';
  actorType: 'system' | 'user' | 'model';
  actorName: string;
  summary: string;
  evidenceRef?: string;
  details?: Record<string, any>;
}

export interface EventNoteRequest {
  summary: string;
  evidenceRef?: string;
  conclusion?: string;
}
