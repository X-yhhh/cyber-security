import { reactive } from 'vue';
import { initialUsers, initialRoles, initialAssets, initialSensors, initialEvents, initialAlerts, initialTimelines, initialPolicies, initialApprovalTasks, initialExecutions, initialModels, initialReleaseReviews, initialDriftWindows, initialFeedbackSamples, initialTrainingJobs, initialDataSources, initialAuditLogs } from './data';
import { ApiEnvelope, PagedResult } from '@/types/api';
import { User, BuiltinRoleKey } from '@/types/iam';
import { SecurityEvent, EventStatus, EventTimelineEntry, DetectionAlert } from '@/types/incident';
import { ApprovalTask, ApprovalStatus, ActionExecution } from '@/types/response';
import { ModelReleaseRecord, ModelVersion, DriftMetricWindow, FeedbackSample, ModelTrainingJob } from '@/types/model';
import { DataSource, AuditLog } from '@/types/datasource';

// 响应式内存数据源
const state = reactive({
  currentUser: initialUsers[1], // 默认以安全分析员 (chen_analyst) 登录，体验感最丰富
  users: [...initialUsers],
  roles: [...initialRoles],
  assets: [...initialAssets],
  sensors: [...initialSensors],
  events: [...initialEvents],
  alerts: [...initialAlerts],
  timelines: { ...initialTimelines },
  policies: [...initialPolicies],
  approvalTasks: [...initialApprovalTasks],
  executions: [...initialExecutions],
  models: [...initialModels],
  releaseReviews: [...initialReleaseReviews],
  driftWindows: [...initialDriftWindows],
  feedbackSamples: [...initialFeedbackSamples],
  trainingJobs: [...initialTrainingJobs],
  dataSources: [...initialDataSources],
  auditLogs: [...initialAuditLogs]
});

// 生成 Request ID
function genRequestId(): string {
  return 'req_' + Math.random().toString(36).substring(2, 12);
}

// 统一包装响应
function wrapSuccess<T>(data: T): ApiEnvelope<T> {
  return {
    success: true,
    data,
    error: null,
    requestId: genRequestId()
  };
}

function wrapError<T>(code: string, message: string): ApiEnvelope<T> {
  return {
    success: false,
    data: null,
    error: { code, message },
    requestId: genRequestId()
  };
}

// 记录审计日志
function recordAudit(action: string, resourceType: string, resourceId: string, outcome: 'success' | 'failure' | 'denied', reason?: string) {
  const newLog = {
    id: state.auditLogs.length + 1,
    occurredAt: new Date().toISOString(),
    actorType: 'user' as const,
    actorName: state.currentUser.username,
    action,
    resourceType,
    resourceId,
    requestId: genRequestId(),
    outcome,
    reason
  };
  state.auditLogs.unshift(newLog);
}

export const mockService = {
  // 1. 认证与角色模拟切换
  getCurrentUser(): ApiEnvelope<User> {
    return wrapSuccess(state.currentUser);
  },

  switchRole(roleKey: BuiltinRoleKey): ApiEnvelope<User> {
    const matchedUser = state.users.find(u => u.roles.some(r => r.roleKey === roleKey));
    if (matchedUser) {
      state.currentUser = matchedUser;
      recordAudit('iam.session.switch_role', 'user', matchedUser.username, 'success', `切换至预设角色: ${roleKey}`);
      return wrapSuccess(matchedUser);
    }
    return wrapError('USER_NOT_FOUND', '未找到匹配该角色的模拟账号');
  },

  getUsers(): ApiEnvelope<User[]> {
    return wrapSuccess(state.users);
  },

  getRoles(): ApiEnvelope<typeof state.roles> {
    return wrapSuccess(state.roles);
  },

  // 2. 资产与传感器
  getAssets(): ApiEnvelope<typeof state.assets> {
    return wrapSuccess(state.assets);
  },

  getSensors(): ApiEnvelope<typeof state.sensors> {
    return wrapSuccess(state.sensors);
  },

  approveAssetAuthorization(assetId: number, authorizationId: number): ApiEnvelope<boolean> {
    const asset = state.assets.find(a => a.id === assetId);
    if (!asset || !asset.activeAuthorization || asset.activeAuthorization.id !== authorizationId) {
      return wrapError('AUTHORIZATION_NOT_FOUND', '未找到对应的资产授权申请');
    }
    // 检查申请人与审批人职责分离
    if (asset.activeAuthorization.requestedBy === state.currentUser.username) {
      recordAudit('asset.authorization.approve', 'asset', asset.assetKey, 'denied', '职责分离校验失败：申请人不能审批自己的授权');
      return wrapError('SEPARATION_OF_DUTY_VIOLATION', '根据安全合规规则，授权申请人与审批人必须不同');
    }
    asset.activeAuthorization.status = 'active';
    asset.activeAuthorization.approvedBy = state.currentUser.username;
    asset.activeAuthorization.approvedAt = new Date().toISOString();
    recordAudit('asset.authorization.approve', 'asset', asset.assetKey, 'success', `审批批准资产 ${asset.name} 的授权申请`);
    return wrapSuccess(true);
  },

  // 3. 事件与研判
  getEvents(filter?: { status?: string; category?: string; severity?: string; search?: string }): ApiEnvelope<SecurityEvent[]> {
    let result = [...state.events];
    if (filter?.status) {
      result = result.filter(e => e.status === filter.status);
    }
    if (filter?.category) {
      result = result.filter(e => e.category === filter.category);
    }
    if (filter?.severity) {
      result = result.filter(e => e.severity === filter.severity);
    }
    if (filter?.search) {
      const q = filter.search.toLowerCase();
      result = result.filter(e => e.title.toLowerCase().includes(q) || e.eventKey.toLowerCase().includes(q) || e.summary.toLowerCase().includes(q));
    }
    return wrapSuccess(result);
  },

  getEventById(id: number): ApiEnvelope<SecurityEvent> {
    const found = state.events.find(e => e.id === id);
    if (!found) return wrapError('EVENT_NOT_FOUND', '安全事件不存在');
    return wrapSuccess(found);
  },

  getTimelineByEventId(eventId: number): ApiEnvelope<EventTimelineEntry[]> {
    return wrapSuccess(state.timelines[eventId] || []);
  },

  updateEventStatus(eventId: number, newStatus: EventStatus, reason?: string): ApiEnvelope<SecurityEvent> {
    const event = state.events.find(e => e.id === eventId);
    if (!event) return wrapError('EVENT_NOT_FOUND', '安全事件不存在');

    const oldStatus = event.status;
    event.status = newStatus;
    if (newStatus === 'resolved' || newStatus === 'closed') {
      event.closedAt = new Date().toISOString();
    }

    // 追加时间线
    const newEntry: EventTimelineEntry = {
      id: Date.now(),
      eventId,
      occurredAt: new Date().toISOString(),
      entryType: 'status_change',
      actorType: 'user',
      actorName: state.currentUser.displayName,
      summary: `事件状态由 [${oldStatus}] 更新为 [${newStatus}]${reason ? `，原因: ${reason}` : ''}`
    };
    if (!state.timelines[eventId]) state.timelines[eventId] = [];
    state.timelines[eventId].push(newEntry);

    recordAudit('event.transition', 'security_event', event.eventKey, 'success', `状态变更为 ${newStatus}`);
    return wrapSuccess(event);
  },

  addEventInvestigationNote(eventId: number, note: string, conclusion?: string): ApiEnvelope<boolean> {
    const event = state.events.find(e => e.id === eventId);
    if (!event) return wrapError('EVENT_NOT_FOUND', '安全事件不存在');

    const newEntry: EventTimelineEntry = {
      id: Date.now(),
      eventId,
      occurredAt: new Date().toISOString(),
      entryType: 'investigation_note',
      actorType: 'user',
      actorName: state.currentUser.displayName,
      summary: note + (conclusion ? ` [研判结论: ${conclusion}]` : '')
    };
    if (!state.timelines[eventId]) state.timelines[eventId] = [];
    state.timelines[eventId].push(newEntry);
    event.evidenceCount += 1;

    recordAudit('event.investigation.note', 'security_event', event.eventKey, 'success', '追加研判证据分析记录');
    return wrapSuccess(true);
  },

  // 4. 告警池
  getAlerts(filter?: { severity?: string; search?: string }): ApiEnvelope<DetectionAlert[]> {
    let result = [...state.alerts];
    if (filter?.severity) {
      result = result.filter(a => a.severity === filter.severity);
    }
    if (filter?.search) {
      const q = filter.search.toLowerCase();
      result = result.filter(a => a.alertKey.toLowerCase().includes(q) || a.sourceIp.includes(q) || a.destIp.includes(q) || (a.attackCategory && a.attackCategory.toLowerCase().includes(q)));
    }
    return wrapSuccess(result);
  },

  // 5. 受控响应与审批
  getApprovalTasks(): ApiEnvelope<ApprovalTask[]> {
    return wrapSuccess(state.approvalTasks);
  },

  getPolicies(): ApiEnvelope<typeof state.policies> {
    return wrapSuccess(state.policies);
  },

  getExecutions(): ApiEnvelope<ActionExecution[]> {
    return wrapSuccess(state.executions);
  },

  requestAction(params: { eventId: number; assetId: number; targetIp: string; durationSeconds: number; reason: string }): ApiEnvelope<ApprovalTask> {
    const event = state.events.find(e => e.id === params.eventId);
    const asset = state.assets.find(a => a.id === params.assetId);
    if (!event || !asset) return wrapError('INVALID_TARGET', '关联事件或资产不存在');

    const newTask: ApprovalTask = {
      id: state.approvalTasks.length + 1,
      taskKey: `TSK-APP-${Date.now().toString().slice(-6)}`,
      eventId: params.eventId,
      eventTitle: event.title,
      policyId: 1,
      policyKey: 'pol_narrow_block_ipv4',
      assetId: params.assetId,
      assetKey: asset.assetKey,
      assetName: asset.name,
      targetIp: params.targetIp,
      actionType: 'temporary_block_ip',
      durationSeconds: params.durationSeconds,
      status: 'pending',
      requestedBy: state.currentUser.username,
      requestedAt: new Date().toISOString(),
      idempotencyKey: `idem_${Date.now()}`,
      requestDigest: 'sha256:custom_' + Math.random().toString(36).substring(2, 10),
      reason: params.reason,
      expiresAt: new Date(Date.now() + 3600 * 1000).toISOString()
    };
    state.approvalTasks.unshift(newTask);

    // 时间线记录
    if (!state.timelines[params.eventId]) state.timelines[params.eventId] = [];
    state.timelines[params.eventId].push({
      id: Date.now(),
      eventId: params.eventId,
      occurredAt: new Date().toISOString(),
      entryType: 'action_requested',
      actorType: 'user',
      actorName: state.currentUser.displayName,
      summary: `提交临时阻断申请 (目标: ${params.targetIp}，时效: ${params.durationSeconds}s)，等待审批`
    });

    recordAudit('action.request', 'asset', asset.assetKey, 'success', `提交临时防火墙阻断申请: ${params.targetIp}`);
    return wrapSuccess(newTask);
  },

  decideApproval(taskId: number, decision: 'approve' | 'reject', reason?: string): ApiEnvelope<boolean> {
    const task = state.approvalTasks.find(t => t.id === taskId);
    if (!task) return wrapError('TASK_NOT_FOUND', '审批任务不存在');

    // 核心安全红线：职责分离 (Separation of Duties)
    if (task.requestedBy === state.currentUser.username) {
      recordAudit('approval.decide', 'approval_task', task.taskKey, 'denied', '职责分离拒绝：申请人尝试自我审批');
      return wrapError('SEPARATION_OF_DUTY_VIOLATION', '安全合规拦截：动作申请人不可同时担任审批人，必须由独立审批员审核！');
    }

    task.status = decision === 'approve' ? 'approved' : 'rejected';
    task.reviewedBy = state.currentUser.username;
    task.reviewedAt = new Date().toISOString();
    task.decisionReason = reason || (decision === 'approve' ? '经核验告警特征属实，批准窄范围限时阻断' : '证据不足，驳回阻断动作');

    if (decision === 'approve') {
      // 模拟自动生成执行台账
      const newExec: ActionExecution = {
        id: state.executions.length + 1,
        executionKey: `ACT-EXEC-${Date.now().toString().slice(-6)}`,
        eventId: task.eventId,
        approvalTaskId: task.id,
        assetId: task.assetId,
        assetName: task.assetName,
        targetIp: task.targetIp,
        actionType: task.actionType,
        durationSeconds: task.durationSeconds,
        expiresAt: new Date(Date.now() + task.durationSeconds * 1000).toISOString(),
        status: 'succeeded',
        adapterKey: task.assetKey.includes('mac') ? 'pfctl_macos_narrow_v1' : 'netsh_windows_narrow_v1',
        startedAt: new Date().toISOString(),
        finishedAt: new Date().toISOString(),
        rollbackRef: `rb_handle_${Date.now()}`,
        canRollback: true,
        resultReceipt: `Host firewall rule applied with TTL ${task.durationSeconds}s`
      };
      state.executions.unshift(newExec);

      // 事件时间线追加
      if (state.timelines[task.eventId]) {
        state.timelines[task.eventId].push({
          id: Date.now(),
          eventId: task.eventId,
          occurredAt: new Date().toISOString(),
          entryType: 'action_executed',
          actorType: 'user',
          actorName: state.currentUser.displayName,
          summary: `审批员已核准阻断动作并下发主机适配器生效，规则已绑定 TTL 倒计时`
        });
      }
    }

    recordAudit('approval.decide', 'approval_task', task.taskKey, 'success', `决策结果: ${decision}`);
    return wrapSuccess(true);
  },

  rollbackExecution(executionId: number): ApiEnvelope<boolean> {
    const exec = state.executions.find(e => e.id === executionId);
    if (!exec) return wrapError('EXECUTION_NOT_FOUND', '执行记录不存在');
    exec.status = 'rolled_back';
    recordAudit('action.rollback', 'action_execution', exec.executionKey, 'success', `安全回滚主机防火墙规则: ${exec.targetIp}`);
    return wrapSuccess(true);
  },

  // 6. 模型治理与审查
  getModels(): ApiEnvelope<ModelVersion[]> {
    return wrapSuccess(state.models);
  },

  getReleaseReviews(): ApiEnvelope<ModelReleaseRecord[]> {
    return wrapSuccess(state.releaseReviews);
  },

  decideReleaseReview(reviewId: number, decision: 'approved' | 'rejected', reason?: string): ApiEnvelope<boolean> {
    const review = state.releaseReviews.find(r => r.id === reviewId);
    if (!review) return wrapError('REVIEW_NOT_FOUND', '审查记录不存在');

    // 职责分离校验
    if (review.requestedBy === state.currentUser.username) {
      recordAudit('model.release.approve', 'model_version', review.version, 'denied', '职责分离拒绝：模型申请人不能审批自己的模型发布');
      return wrapError('SEPARATION_OF_DUTY_VIOLATION', '职责分离规则：模型开发提交人不能独立审批发布申请');
    }

    review.releaseStatus = decision;
    review.approvedBy = state.currentUser.username;
    review.decisionReason = reason || (decision === 'approved' ? 'Manifest 与测试集指标核对一致，准予发布' : '指标不达标');
    review.reviewedAt = new Date().toISOString();

    if (decision === 'approved') {
      const model = state.models.find(m => m.id === review.modelVersionId);
      if (model) {
        model.approvalStatus = 'approved';
      }
    }

    recordAudit('model.release.approve', 'model_release_record', review.version, 'success', `发布审查决策: ${decision}`);
    return wrapSuccess(true);
  },

  getDriftWindows(): ApiEnvelope<DriftMetricWindow[]> {
    return wrapSuccess(state.driftWindows);
  },

  getFeedbackSamples(): ApiEnvelope<FeedbackSample[]> {
    return wrapSuccess(state.feedbackSamples);
  },

  getTrainingJobs(): ApiEnvelope<ModelTrainingJob[]> {
    return wrapSuccess(state.trainingJobs);
  },

  // 7. 数据源与审计
  getDataSources(): ApiEnvelope<DataSource[]> {
    return wrapSuccess(state.dataSources);
  },

  getAuditLogs(): ApiEnvelope<AuditLog[]> {
    return wrapSuccess(state.auditLogs);
  }
};
