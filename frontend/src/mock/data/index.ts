import { Asset, SensorAgent } from '@/types/asset';
import { SecurityEvent, DetectionAlert, EventTimelineEntry } from '@/types/incident';
import { ApprovalTask, ActionExecution, ResponsePolicy } from '@/types/response';
import { ModelVersion, ModelReleaseRecord, DriftMetricWindow, FeedbackSample, ModelTrainingJob } from '@/types/model';
import { DataSource, SourceMapping, IngestBatch, AuditLog } from '@/types/datasource';
import { User, RoleInfo } from '@/types/iam';

// 1. 7大内置角色定义（只读权限模板）
export const initialRoles: RoleInfo[] = [
  {
    id: 1,
    roleKey: 'platform_admin',
    name: '平台管理员',
    description: '用户管理与预定义角色分配、系统全局配置、资产/授权独立审批与数据源维护；安全事件与审计全局只读',
    isBuiltin: true,
    permissions: ['iam.user.read', 'iam.user.manage', 'iam.role.read', 'iam.role.assign', 'asset.manage', 'asset.authorization.approve', 'source.manage', 'event.read', 'audit.read']
  },
  {
    id: 2,
    roleKey: 'asset_source_admin',
    name: '资产与数据源管理员',
    description: '资产/授权申请、数据源/映射及关联传感器登记、配置和健康状态维护',
    isBuiltin: true,
    permissions: ['asset.read', 'asset.authorization.manage', 'source.read', 'source.manage', 'sensor.manage']
  },
  {
    id: 3,
    roleKey: 'security_analyst',
    name: '安全分析员',
    description: '查看告警/事件/证据，添加研判并按状态机更新事件，提交受控阻断处置申请',
    isBuiltin: true,
    permissions: ['alert.read', 'event.read', 'event.investigate', 'action.request']
  },
  {
    id: 4,
    roleKey: 'response_approver',
    name: '响应审批员',
    description: '查看审批所需目标和影响摘要，依据职责分离原则批准或拒绝待审批动作',
    isBuiltin: true,
    permissions: ['approval.read', 'approval.decide', 'event.read']
  },
  {
    id: 5,
    roleKey: 'model_operator',
    name: '模型操作员',
    description: '登记候选模型元数据、提交验证并查看指标，发起模型发布申请',
    isBuiltin: true,
    permissions: ['model.validation.read', 'model.candidate.manage', 'model.release.request']
  },
  {
    id: 6,
    roleKey: 'model_releaser',
    name: '模型发布审批员',
    description: '独立审查模型发布申请的不可变 Manifest 元数据并作出决策',
    isBuiltin: true,
    permissions: ['model.validation.read', 'model.release.approve']
  },
  {
    id: 7,
    roleKey: 'auditor',
    name: '合规审计员',
    description: '只读查询全关联范围审计和复盘信息，导出合规安全报告',
    isBuiltin: true,
    permissions: ['audit.read', 'report.export']
  }
];

// 预设用户主体
export const initialUsers: User[] = [
  {
    id: 1,
    userKey: 'usr_admin',
    username: 'admin',
    displayName: '系统管理员 (Admin)',
    email: 'admin@secops.local',
    status: 'active',
    createdAt: '2026-09-01T08:00:00Z',
    lastLoginAt: '2026-09-24T09:15:00Z',
    roles: [{ roleKey: 'platform_admin', scopeType: 'global', scopeId: 'global/*' }]
  },
  {
    id: 2,
    userKey: 'usr_analyst_chen',
    username: 'chen_analyst',
    displayName: '陈工 (安全研判)',
    email: 'chen@secops.local',
    status: 'active',
    createdAt: '2026-09-05T09:30:00Z',
    lastLoginAt: '2026-09-24T08:50:00Z',
    roles: [{ roleKey: 'security_analyst', scopeType: 'global', scopeId: 'global/*' }]
  },
  {
    id: 3,
    userKey: 'usr_approver_wang',
    username: 'wang_approver',
    displayName: '王主管 (应急响应审批)',
    email: 'wang@secops.local',
    status: 'active',
    createdAt: '2026-09-06T10:00:00Z',
    lastLoginAt: '2026-09-24T09:05:00Z',
    roles: [{ roleKey: 'response_approver', scopeType: 'global', scopeId: 'global/*' }]
  },
  {
    id: 4,
    userKey: 'usr_model_li',
    username: 'li_modeler',
    displayName: '李研究员 (模型开发)',
    email: 'li@secops.local',
    status: 'active',
    createdAt: '2026-09-08T11:00:00Z',
    lastLoginAt: '2026-09-23T17:20:00Z',
    roles: [{ roleKey: 'model_operator', scopeType: 'model_registry', scopeId: 'model_registry/unsw-flow' }]
  },
  {
    id: 5,
    userKey: 'usr_releaser_zhang',
    username: 'zhang_lead',
    displayName: '张总工 (模型发布审查)',
    email: 'zhang@secops.local',
    status: 'active',
    createdAt: '2026-09-08T14:00:00Z',
    lastLoginAt: '2026-09-24T07:45:00Z',
    roles: [{ roleKey: 'model_releaser', scopeType: 'model_registry', scopeId: 'model_registry/unsw-flow' }]
  },
  {
    id: 6,
    userKey: 'usr_asset_zhao',
    username: 'zhao_ops',
    displayName: '赵运维 (资产管理员)',
    email: 'zhao@secops.local',
    status: 'active',
    createdAt: '2026-09-10T10:00:00Z',
    lastLoginAt: '2026-09-24T08:30:00Z',
    roles: [{ roleKey: 'asset_source_admin', scopeType: 'global', scopeId: 'global/*' }]
  },
  {
    id: 7,
    userKey: 'usr_auditor_sun',
    username: 'sun_audit',
    displayName: '孙审计 (合规审查)',
    email: 'sun@secops.local',
    status: 'active',
    createdAt: '2026-09-12T09:00:00Z',
    lastLoginAt: '2026-09-24T09:10:00Z',
    roles: [{ roleKey: 'auditor', scopeType: 'global', scopeId: 'global/*' }]
  }
];

// 2. 资产台账与授权
export const initialAssets: Asset[] = [
  {
    id: 1,
    assetKey: 'ast_mac_gateway',
    name: 'Mac 主机传感器节点 #1 (开发工作站)',
    ipAddress: '192.168.1.101',
    macAddress: 'F0:18:98:3A:BC:11',
    osType: 'macos',
    osVersion: 'macOS Sequoia 15.2 (Darwin 24.2.0)',
    environment: 'authorized',
    criticality: 'critical',
    owner: '网络安全实验室',
    status: 'active',
    labels: { role: 'sensor-host', network: 'intranet-vlan-10' },
    createdAt: '2026-09-10T00:00:00Z',
    updatedAt: '2026-09-23T10:00:00Z',
    activeAuthorization: {
      id: 101,
      assetId: 1,
      assetKey: 'ast_mac_gateway',
      authorizationRef: 'SEC-AUTH-2026-001',
      scope: ['traffic:read', 'firewall:block_narrow'],
      validFrom: '2026-09-01T00:00:00Z',
      validUntil: '2026-12-31T23:59:59Z',
      status: 'active',
      requestedBy: 'zhao_ops',
      approvedBy: 'admin',
      approvedAt: '2026-09-01T02:00:00Z',
      createdAt: '2026-09-01T01:30:00Z'
    }
  },
  {
    id: 2,
    assetKey: 'ast_win_cuda',
    name: 'Windows 训练兼传感器节点 #2 (CUDA 离线站)',
    ipAddress: '192.168.1.102',
    macAddress: 'B4:2E:99:A1:78:2F',
    osType: 'windows',
    osVersion: 'Windows 11 Pro 24H2 (WSL2 + CUDA 12.6)',
    environment: 'authorized',
    criticality: 'high',
    owner: '机器学习组',
    status: 'active',
    labels: { role: 'training-and-sensor', gpu: 'RTX-4090' },
    createdAt: '2026-09-10T00:00:00Z',
    updatedAt: '2026-09-22T08:00:00Z',
    activeAuthorization: {
      id: 102,
      assetId: 2,
      assetKey: 'ast_win_cuda',
      authorizationRef: 'SEC-AUTH-2026-002',
      scope: ['traffic:read', 'firewall:block_narrow'],
      validFrom: '2026-09-01T00:00:00Z',
      validUntil: '2026-11-30T23:59:59Z',
      status: 'active',
      requestedBy: 'zhao_ops',
      approvedBy: 'admin',
      approvedAt: '2026-09-01T02:30:00Z',
      createdAt: '2026-09-01T01:45:00Z'
    }
  },
  {
    id: 3,
    assetKey: 'ast_lab_target',
    name: '隔离靶场 Web 业务模拟靶标 (靶场专用)',
    ipAddress: '10.0.99.15',
    macAddress: '00:50:56:C0:00:08',
    osType: 'linux',
    osVersion: 'Ubuntu 24.04 LTS (Air-gapped)',
    environment: 'lab',
    criticality: 'medium',
    owner: '演练攻防组',
    status: 'active',
    labels: { role: 'target-vm', sandbox: 'airgap-vlan-99' },
    createdAt: '2026-09-12T00:00:00Z',
    updatedAt: '2026-09-20T11:00:00Z',
    activeAuthorization: {
      id: 103,
      assetId: 3,
      assetKey: 'ast_lab_target',
      authorizationRef: 'LAB-AUTH-2026-015',
      scope: ['traffic:read', 'replay:target'],
      validFrom: '2026-09-10T00:00:00Z',
      validUntil: '2026-10-31T23:59:59Z',
      status: 'active',
      requestedBy: 'zhao_ops',
      approvedBy: 'admin',
      approvedAt: '2026-09-10T04:00:00Z',
      createdAt: '2026-09-10T03:00:00Z'
    }
  }
];

// 3. 软件传感器列表
export const initialSensors: SensorAgent[] = [
  {
    id: 1,
    agentKey: 'snr_mac_en0',
    assetId: 1,
    assetKey: 'ast_mac_gateway',
    assetName: 'Mac 主机传感器节点 #1',
    platform: 'macos',
    agentVersion: 'v1.4.2-darwin-arm64',
    status: 'online',
    interfaceScope: ['en0', 'ap1'],
    lastHeartbeatAt: '2026-09-24T09:28:45Z',
    registeredAt: '2026-09-10T09:00:00Z',
    flowWindowSeconds: 15,
    featureContractVersion: 'unsw-flow-v1',
    flowsSeen: 184520,
    flowsEmitted: 184518,
    flowsDropped: 2,
    queueDepth: 4,
    cpuPercent: 3.2,
    memoryMb: 86.4
  },
  {
    id: 2,
    agentKey: 'snr_win_eth0',
    assetId: 2,
    assetKey: 'ast_win_cuda',
    assetName: 'Windows 训练兼传感器节点 #2',
    platform: 'windows',
    agentVersion: 'v1.4.2-win-x64-npcap',
    status: 'online',
    interfaceScope: ['Ethernet0'],
    lastHeartbeatAt: '2026-09-24T09:28:50Z',
    registeredAt: '2026-09-10T09:15:00Z',
    flowWindowSeconds: 15,
    featureContractVersion: 'unsw-flow-v1',
    flowsSeen: 95420,
    flowsEmitted: 95415,
    flowsDropped: 5,
    queueDepth: 8,
    cpuPercent: 5.8,
    memoryMb: 112.0
  }
];

// 4. 安全事件与威胁研判
export const initialEvents: SecurityEvent[] = [
  {
    id: 1,
    eventKey: 'SEC-EVT-20260924-001',
    title: '持续 DoS SYN Flood 与异常连接突增告警',
    category: 'DoS',
    severity: 'critical',
    status: 'investigating',
    riskScore: 92,
    riskRuleVersion: 'risk-rule-v2.1',
    firstSeenAt: '2026-09-24T08:45:10Z',
    lastSeenAt: '2026-09-24T09:20:00Z',
    assigneeName: '陈工 (安全研判)',
    assigneeId: 2,
    impactedAssets: [
      {
        assetId: 1,
        assetKey: 'ast_mac_gateway',
        assetName: 'Mac 主机传感器节点 #1',
        ipAddress: '192.168.1.101',
        criticality: 'critical'
      }
    ],
    alertCount: 14,
    evidenceCount: 6,
    summary: '检测到来自外部可疑 IP 203.0.113.88 对本机服务端口的高频畸形 SYN 数据流，模型判定为 DoS 概率 98.4%，已触发速率超限规则，建议下发临时窄范围阻断。'
  },
  {
    id: 2,
    eventKey: 'SEC-EVT-20260924-002',
    title: 'Exploits 漏洞利用攻击载荷探测行为',
    category: 'Exploits',
    severity: 'high',
    status: 'open',
    riskScore: 78,
    riskRuleVersion: 'risk-rule-v2.1',
    firstSeenAt: '2026-09-24T07:15:00Z',
    lastSeenAt: '2026-09-24T08:10:00Z',
    assigneeName: undefined,
    impactedAssets: [
      {
        assetId: 2,
        assetKey: 'ast_win_cuda',
        assetName: 'Windows 训练兼传感器节点 #2',
        ipAddress: '192.168.1.102',
        criticality: 'high'
      }
    ],
    alertCount: 5,
    evidenceCount: 3,
    summary: '捕获特征匹配 CVE 格式签名与非常规 HTTP 方法请求，模型多分类指向 Exploits 分类（置信度 0.89），暂未造成服务中断，待分析员接单研判。'
  },
  {
    id: 3,
    eventKey: 'SEC-EVT-20260923-005',
    title: '端口扫描与服务探测行为 (Reconnaissance)',
    category: 'Reconnaissance',
    severity: 'medium',
    status: 'contained',
    riskScore: 54,
    riskRuleVersion: 'risk-rule-v2.1',
    firstSeenAt: '2026-09-23T18:30:00Z',
    lastSeenAt: '2026-09-23T19:00:00Z',
    assigneeName: '陈工 (安全研判)',
    assigneeId: 2,
    impactedAssets: [
      {
        assetId: 1,
        assetKey: 'ast_mac_gateway',
        assetName: 'Mac 主机传感器节点 #1',
        ipAddress: '192.168.1.101',
        criticality: 'critical'
      }
    ],
    alertCount: 8,
    evidenceCount: 4,
    summary: '对常见管理端口（22, 3389, 8080）执行水平探测扫描，已由主机防火墙自动阻断 600 秒，威胁已遏制。'
  },
  {
    id: 4,
    eventKey: 'SEC-EVT-20260922-001',
    title: '基准数据重放演练产生的异常突发流量',
    category: 'Generic',
    severity: 'low',
    status: 'resolved',
    riskScore: 25,
    riskRuleVersion: 'risk-rule-v2.0',
    firstSeenAt: '2026-09-22T14:00:00Z',
    lastSeenAt: '2026-09-22T14:30:00Z',
    assigneeName: '陈工 (安全研判)',
    assigneeId: 2,
    closedAt: '2026-09-22T15:00:00Z',
    impactedAssets: [
      {
        assetId: 3,
        assetKey: 'ast_lab_target',
        assetName: '隔离靶场 Web 业务模拟靶标',
        ipAddress: '10.0.99.15',
        criticality: 'medium'
      }
    ],
    alertCount: 3,
    evidenceCount: 2,
    summary: '隔离靶场回放 UNSW-NB15 测试流产生的低危告警，经人工核验为演练流量，已正常归档闭环。'
  }
];

// 5. 原始告警池
export const initialAlerts: DetectionAlert[] = [
  {
    id: 1,
    alertKey: 'ALT-20260924-00101',
    ingestRecordId: 1001,
    alertType: 'dos_syn_flood_burst',
    severity: 'critical',
    score: 0.984,
    thresholdVersion: 'thresh-v1.3',
    status: 'correlated',
    detectedAt: '2026-09-24T09:19:45Z',
    sourceIp: '203.0.113.88',
    sourcePort: 49152,
    destIp: '192.168.1.101',
    destPort: 80,
    protocol: 'tcp',
    flowDuration: 0.42,
    flowBytes: 154200,
    flowPackets: 2850,
    attackCategory: 'DoS',
    featureSnippet: { sbytes: 154200, dbytes: 0, sttl: 64, ct_srv_src: 48, rate: 6785.7 }
  },
  {
    id: 2,
    alertKey: 'ALT-20260924-00102',
    ingestRecordId: 1002,
    alertType: 'dos_rate_limit_exceeded',
    severity: 'critical',
    score: 0.952,
    thresholdVersion: 'thresh-v1.3',
    status: 'correlated',
    detectedAt: '2026-09-24T09:18:30Z',
    sourceIp: '203.0.113.88',
    sourcePort: 49153,
    destIp: '192.168.1.101',
    destPort: 80,
    protocol: 'tcp',
    flowDuration: 0.35,
    flowBytes: 128400,
    flowPackets: 2400,
    attackCategory: 'DoS',
    featureSnippet: { sbytes: 128400, dbytes: 0, sttl: 64, ct_srv_src: 42, rate: 6857.1 }
  },
  {
    id: 3,
    alertKey: 'ALT-20260924-00201',
    ingestRecordId: 1003,
    alertType: 'exploit_malformed_header',
    severity: 'high',
    score: 0.887,
    thresholdVersion: 'thresh-v1.3',
    status: 'new',
    detectedAt: '2026-09-24T08:08:15Z',
    sourceIp: '198.51.100.42',
    sourcePort: 54321,
    destIp: '192.168.1.102',
    destPort: 8080,
    protocol: 'tcp',
    flowDuration: 1.25,
    flowBytes: 4280,
    flowPackets: 18,
    attackCategory: 'Exploits',
    featureSnippet: { sbytes: 3500, dbytes: 780, sttl: 128, ct_state_ttl: 2 }
  }
];

// 6. 研判时间线与笔记
export const initialTimelines: Record<number, EventTimelineEntry[]> = {
  1: [
    {
      id: 1,
      eventId: 1,
      occurredAt: '2026-09-24T08:45:10Z',
      entryType: 'alert_linked',
      actorType: 'system',
      actorName: '规则与推理引擎',
      summary: '初次检测到 203.0.113.88 发起的畸形 TCP SYN 流量，归并关联创建事件'
    },
    {
      id: 2,
      eventId: 1,
      occurredAt: '2026-09-24T08:50:00Z',
      entryType: 'status_change',
      actorType: 'user',
      actorName: '陈工 (安全研判)',
      summary: '事件状态从 [open] 迁入 [investigating]，分析员开始介入研判'
    },
    {
      id: 3,
      eventId: 1,
      occurredAt: '2026-09-24T09:00:22Z',
      entryType: 'investigation_note',
      actorType: 'user',
      actorName: '陈工 (安全研判)',
      summary: '提取流特征对比 UNSW-NB15 DoS 基准，发现源地址无正常握手回包且速率突破 6000 pps，确认攻击特征明确。'
    },
    {
      id: 4,
      eventId: 1,
      occurredAt: '2026-09-24T09:10:00Z',
      entryType: 'action_requested',
      actorType: 'user',
      actorName: '陈工 (安全研判)',
      summary: '提交主机防火墙窄范围阻断申请：临时封禁来源 IP 203.0.113.88，时效 1800 秒。等待独立审批人裁决。'
    }
  ]
};

// 7. 防御响应策略库
export const initialPolicies: ResponsePolicy[] = [
  {
    id: 1,
    policyKey: 'pol_narrow_block_ipv4',
    version: '1.2.0',
    name: '主机防火墙 IPv4 窄范围临时阻断策略',
    environment: 'authorized',
    actionType: 'temporary_block_ip',
    allowedTargets: ['203.0.113.0/24', '198.51.100.0/24', 'any_external_ip'],
    maxDurationSeconds: 7200,
    approvalRequired: true,
    status: 'active'
  },
  {
    id: 2,
    policyKey: 'pol_lab_auto_isolate',
    version: '1.0.0',
    name: '隔离靶场快速自动隔离策略 (仅靶场)',
    environment: 'lab',
    actionType: 'isolate_host',
    allowedTargets: ['10.0.99.0/24'],
    maxDurationSeconds: 3600,
    approvalRequired: false,
    status: 'active'
  }
];

// 8. 待审批动作工单（申请人与审批人职责分离）
export const initialApprovalTasks: ApprovalTask[] = [
  {
    id: 1,
    taskKey: 'TSK-APP-20260924-001',
    eventId: 1,
    eventTitle: '持续 DoS SYN Flood 与异常连接突增告警',
    policyId: 1,
    policyKey: 'pol_narrow_block_ipv4',
    assetId: 1,
    assetKey: 'ast_mac_gateway',
    assetName: 'Mac 主机传感器节点 #1',
    targetIp: '203.0.113.88',
    actionType: 'temporary_block_ip',
    durationSeconds: 1800,
    status: 'pending',
    requestedBy: 'chen_analyst', // 申请人：陈工
    requestedAt: '2026-09-24T09:10:00Z',
    idempotencyKey: 'idem_blk_203_0_113_88_1800',
    requestDigest: 'sha256:8f4b23c9118e9d12a64c456f91d087b3a98a0f81a7b1b3e8c22d141e57c6b901',
    reason: '缓解对 80 端口的高频 SYN Flood 攻击，排除控制面与网关保护范围，动作限时 30 分钟。',
    expiresAt: '2026-09-24T10:10:00Z'
  }
];

// 9. 执行台账
export const initialExecutions: ActionExecution[] = [
  {
    id: 1,
    executionKey: 'ACT-EXEC-20260923-01',
    eventId: 3,
    assetId: 1,
    assetName: 'Mac 主机传感器节点 #1',
    targetIp: '198.51.100.99',
    actionType: 'temporary_block_ip',
    durationSeconds: 600,
    expiresAt: '2026-09-23T19:40:00Z',
    status: 'succeeded',
    adapterKey: 'pfctl_macos_narrow_v1',
    startedAt: '2026-09-23T19:30:00Z',
    finishedAt: '2026-09-23T19:30:01Z',
    rollbackRef: 'rb_handle_pfctl_anchor_198_51_100_99',
    canRollback: true,
    resultReceipt: 'PF anchor table "secops_temp_blocks" rule appended: block in quick from 198.51.100.99 to any'
  }
];

// 10. 模型版本库与不可变 Manifest
export const initialModels: ModelVersion[] = [
  {
    id: 1,
    modelKey: 'unsw-nb15-flow-classifier',
    version: 'v1.2.0',
    taskType: 'binary_classification',
    manifestVersion: '1.0.0',
    artifactRef: 'model://artifacts/unsw-classifier-v1.2.0.onnx',
    artifactSha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    featureContractVersion: 'unsw-flow-v1',
    approvalStatus: 'active',
    deploymentMode: 'local',
    approvedBy: 'zhang_lead',
    createdAt: '2026-09-18T10:00:00Z',
    manifest: {
      manifestVersion: '1.0.0',
      modelKey: 'unsw-nb15-flow-classifier',
      version: 'v1.2.0',
      algorithm: 'LightGBM-ONNX-Quantized',
      dataset: 'UNSW-NB15-Official-Predefined-Subset',
      datasetSplitFingerprint: 'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      featureOrder: ['dur', 'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate', 'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss'],
      metrics: {
        accuracy: 0.948,
        f1Score: 0.942,
        precision: 0.935,
        recall: 0.950,
        aucRoc: 0.982,
        dosRecall: 0.978,
        falseAlarmRate: 0.038
      },
      thresholdStrategy: {
        optimalThreshold: 0.65,
        strategy: 'Max-F1-with-FAR-Constraint-3%'
      },
      runtime: {
        framework: 'ONNXRuntime 1.20',
        targetRuntime: 'x86_64 / arm64 SIMD CPU',
        sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
      }
    }
  },
  {
    id: 2,
    modelKey: 'unsw-nb15-flow-classifier',
    version: 'v1.3.0-candidate',
    taskType: 'binary_classification',
    manifestVersion: '1.0.0',
    artifactRef: 'model://artifacts/unsw-classifier-v1.3.0-rc1.onnx',
    artifactSha256: 'e2b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b999',
    featureContractVersion: 'unsw-flow-v1',
    approvalStatus: 'candidate',
    deploymentMode: 'remote',
    createdAt: '2026-09-23T14:30:00Z',
    manifest: {
      manifestVersion: '1.0.0',
      modelKey: 'unsw-nb15-flow-classifier',
      version: 'v1.3.0-candidate',
      algorithm: 'XGBoost-CUDA-Enhanced',
      dataset: 'UNSW-NB15-Augmented-with-Feedback-Set-v1',
      datasetSplitFingerprint: 'sha256:7a4c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b777',
      featureOrder: ['dur', 'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate', 'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss'],
      metrics: {
        accuracy: 0.956,
        f1Score: 0.951,
        precision: 0.948,
        recall: 0.955,
        aucRoc: 0.988,
        dosRecall: 0.985,
        falseAlarmRate: 0.029
      },
      thresholdStrategy: {
        optimalThreshold: 0.62,
        strategy: 'Max-F1-with-FAR-Constraint-3%'
      },
      runtime: {
        framework: 'ONNXRuntime 1.20',
        targetRuntime: 'CUDA 12.6 or High Performance CPU',
        sha256: 'e2b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b999'
      }
    }
  }
];

// 11. 独立模型发布审查台账
export const initialReleaseReviews: ModelReleaseRecord[] = [
  {
    id: 1,
    modelVersionId: 2,
    modelKey: 'unsw-nb15-flow-classifier',
    version: 'v1.3.0-candidate',
    releaseStatus: 'pending_review',
    requestedBy: 'li_modeler',
    requestReason: '在 Windows CUDA 离线训练环境完成验证，综合 F1 达到 0.951，DoS 检出率提升至 98.5%，误报率降至 2.9%，请求独立审查发布。',
    requestedAt: '2026-09-24T08:15:00Z'
  }
];

// 12. 漂移监控与人工反馈
export const initialDriftWindows: DriftMetricWindow[] = [
  {
    id: 1,
    dataSourceKey: 'ds_unsw_stream',
    modelVersion: 'v1.2.0',
    windowStart: '2026-09-24T00:00:00Z',
    windowEnd: '2026-09-24T08:00:00Z',
    qualityRejectRate: 0.002,
    driftStatus: 'normal',
    featureStats: {
      dur: { ksStatistic: 0.024, pValue: 0.88, drifted: false },
      sbytes: { ksStatistic: 0.031, pValue: 0.72, drifted: false },
      rate: { ksStatistic: 0.045, pValue: 0.61, drifted: false }
    },
    scoreStats: { mean: 0.12, std: 0.18 }
  }
];

export const initialFeedbackSamples: FeedbackSample[] = [
  {
    id: 1,
    sourceRecordKey: 'rec_unsw_20260923_0991',
    alertId: 1,
    groundTruthLabel: 'DoS',
    labelSource: 'analyst_pcap_verified',
    evidenceRef: 'pcap://evidence/20260924_synflood.pcap#pkt1-150',
    reviewedBy: 'chen_analyst',
    reviewedAt: '2026-09-24T09:05:00Z',
    datasetVersion: 'feedback-set-202609-v1',
    trainingEligible: true
  }
];

// 13. 离线训练任务
export const initialTrainingJobs: ModelTrainingJob[] = [
  {
    id: 1,
    jobKey: 'TRN-JOB-20260923-01',
    datasetVersion: 'UNSW-NB15-Augmented-v1',
    sampleManifestRef: 'dataset://manifests/unsw_aug_v1.json',
    algorithm: 'XGBoost + LightGBM Ensemble',
    trainHostRef: 'Windows-CUDA-01 (RTX 4090)',
    status: 'completed',
    requestedBy: 'li_modeler',
    approvedBy: 'zhang_lead',
    startedAt: '2026-09-23T10:00:00Z',
    finishedAt: '2026-09-23T14:15:00Z',
    resultManifestRef: 'manifest://unsw-flow-v1.3.0.json'
  }
];

// 14. 数据源与接入
export const initialDataSources: DataSource[] = [
  {
    id: 1,
    sourceKey: 'ds_unsw_stream',
    name: 'UNSW-NB15 基准流数据集接入源',
    sourceType: 'benchmark_unsw',
    environment: 'lab',
    schemaVersion: 'unsw-csv-v2',
    status: 'active',
    lastSuccessAt: '2026-09-24T09:25:00Z',
    recordCount: 2540044,
    description: '公开经典网络安全流量基准，用于模型基线训练与基准回放对照。'
  },
  {
    id: 2,
    sourceKey: 'ds_sensor_telemetry',
    name: '主机软件传感器授权遥测管道',
    sourceType: 'host_sensor',
    environment: 'authorized',
    schemaVersion: 'sensor-flow-v1',
    status: 'active',
    lastSuccessAt: '2026-09-24T09:28:50Z',
    recordCount: 279940,
    description: 'Mac 与 Windows 两台终端软件传感器在线上报的本机可见流量流记录。'
  }
];

// 15. 审计日志
export const initialAuditLogs: AuditLog[] = [
  {
    id: 1,
    occurredAt: '2026-09-24T09:10:00Z',
    actorType: 'user',
    actorName: 'chen_analyst',
    action: 'action.request',
    resourceType: 'asset',
    resourceId: 'ast_mac_gateway',
    requestId: 'req_01j8k9m0n1p2q3r4s5t6',
    outcome: 'success',
    reason: '提交对 203.0.113.88 的临时限时阻断申请'
  },
  {
    id: 2,
    occurredAt: '2026-09-24T08:50:00Z',
    actorType: 'user',
    actorName: 'chen_analyst',
    action: 'event.transition',
    resourceType: 'security_event',
    resourceId: 'SEC-EVT-20260924-001',
    requestId: 'req_01j8k8a2b3c4d5e6f7g8',
    outcome: 'success',
    reason: '事件状态从 open 更新为 investigating'
  },
  {
    id: 3,
    occurredAt: '2026-09-24T08:15:00Z',
    actorType: 'user',
    actorName: 'li_modeler',
    action: 'model.release.request',
    resourceType: 'model_version',
    resourceId: 'unsw-nb15-flow-classifier:v1.3.0-candidate',
    requestId: 'req_01j8k7x9y8z7w6v5u4t3',
    outcome: 'success',
    reason: '模型操作员提交 v1.3.0-candidate 独立发布审查申请'
  }
];
