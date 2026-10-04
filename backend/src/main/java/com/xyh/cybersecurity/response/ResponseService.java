package com.xyh.cybersecurity.response;

import com.fasterxml.jackson.databind.JsonNode;

import java.time.LocalDateTime;
import java.util.List;

/**
 * 响应 API 的稳定 DTO 命名空间。业务编排已拆到 application 包，保留这些记录以避免改变既有接口 JSON 契约。
 */
public final class ResponseService {
    private ResponseService() { }

    public record ActionRequest(long assetId, long policyId, String actionType,
                                JsonNode parameters, String reason) { }

    public record RequestResult(ApprovalView approval, boolean created) { }

    public record ApprovalView(long id, long eventId, long assetId, JsonNode actionRequest, String status,
                               long requestedBy, Long reviewedBy, LocalDateTime expiresAt,
                               LocalDateTime createdAt, boolean executionSupported) { }

    public record Page(long totalElements, int page, int size, List<ApprovalView> items) { }
}
