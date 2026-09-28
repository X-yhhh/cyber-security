package com.xyh.cybersecurity.response.domain;

/**
 * 受控响应适配器的最小接口预留。实现必须由策略服务提供已校验的快照、TTL、幂等键和回滚句柄，
 * 不能由模型或控制器直接调用；首期没有实现，响应执行端点保持 fail-closed。
 */
public interface ActionExecutor {

    ExecutionResult execute(ActionCommand command);

    record ActionCommand(long approvalTaskId, long assetId, String actionType, String targetScopeJson,
                         java.time.Instant expiresAt, String idempotencyKey) { }

    record ExecutionResult(String status, String rollbackRef, String resultSummary) { }
}
