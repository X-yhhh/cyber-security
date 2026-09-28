package com.xyh.cybersecurity.response.application;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import com.xyh.cybersecurity.response.ResponseService;
import com.xyh.cybersecurity.response.domain.ActionSnapshotFactory;
import com.xyh.cybersecurity.response.domain.AuthorizationGuard;
import com.xyh.cybersecurity.response.domain.PolicyGuard;
import com.xyh.cybersecurity.response.infra.ResponseMapper;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;

/**
 * 响应应用服务共用的规范化、领域门禁和视图映射。数据库锁与 SQL 保留在 ResponseMapper，
 * 这里不接受来自客户端的风险、自动执行或适配器参数覆盖。
 */
@Component
public class ResponseSupport {

    private final ObjectMapper objectMapper;
    private final Clock clock;
    private final PolicyGuard policyGuard;
    private final AuthorizationGuard authorizationGuard;
    private final ActionSnapshotFactory snapshotFactory;

    public ResponseSupport(ObjectMapper objectMapper, Clock clock) {
        this.objectMapper = objectMapper;
        this.clock = clock;
        this.policyGuard = new PolicyGuard(objectMapper);
        this.authorizationGuard = new AuthorizationGuard(objectMapper);
        this.snapshotFactory = new ActionSnapshotFactory(objectMapper);
    }

    public Clock clock() { return clock; }

    public JsonNode canonicalNode(JsonNode node) {
        if (node == null || !node.isObject()) throw ApiRequestException.badRequest("动作参数必须是 JSON 对象");
        ObjectNode result = objectMapper.createObjectNode();
        List<String> names = new ArrayList<>();
        node.fieldNames().forEachRemaining(names::add);
        names.sort(Comparator.naturalOrder());
        for (String name : names) {
            JsonNode value = node.get(name);
            if (value.isObject()) result.set(name, canonicalNode(value));
            else if (value.isArray()) {
                ArrayNode array = objectMapper.createArrayNode();
                for (JsonNode element : value) {
                    array.add(element.isObject() ? canonicalNode(element) : element.deepCopy());
                }
                result.set(name, array);
            } else result.set(name, value.deepCopy());
        }
        return result;
    }

    public void validateTemporaryBlockParameters(String actionType, JsonNode parameters) {
        if (!"temporary_block".equals(actionType)
                || parameters.size() != 2 || !parameters.has("targetAddress") || !parameters.has("ttlSeconds")
                || !parameters.path("targetAddress").isTextual()
                || !parameters.path("ttlSeconds").isIntegralNumber()
                || !parameters.path("ttlSeconds").canConvertToInt()) {
            throw ApiRequestException.badRequest("首期仅接受受策略约束的 temporary_block 目标与 TTL 参数");
        }
    }

    public String validateIdempotencyKey(String value) {
        if (value == null || !value.matches("[A-Za-z0-9._:-]{8,160}")) {
            throw ApiRequestException.badRequest("Idempotency-Key 格式无效");
        }
        return value;
    }

    public String validatedReason(String reason) {
        if (reason == null) throw ApiRequestException.badRequest("申请或审批理由不能为空");
        String value = reason.trim();
        if (value.isEmpty() || value.length() > 1000 || value.chars().anyMatch(Character::isISOControl)) {
            throw ApiRequestException.badRequest("申请或审批理由长度或字符无效");
        }
        return value;
    }

    public boolean policyMatches(ResponseMapper.PolicyRow policy, String actionType,
                                 ResponseMapper.AssetRow asset, JsonNode parameters) {
        return policy != null && policyGuard.matches(new PolicyGuard.Policy(policy.status(), policy.approvedBy(),
                        policy.autoExecute(), policy.approvalRequired(), policy.actionType(), policy.environment(),
                        policy.matchJson(), policy.actionParamsJson(), policy.maxDurationSeconds()), actionType,
                asset == null ? null : new PolicyGuard.Asset(asset.environment()), parameters);
    }

    public boolean authorizationScopeAllows(String scopeJson, String actionType) {
        return authorizationGuard.scopeAllows(scopeJson, actionType);
    }

    public String actionSnapshot(long eventId, ResponseService.ActionRequest input, JsonNode parameters,
                                 String reason, ResponseMapper.PolicyRow policy) {
        try {
            return snapshotFactory.create(eventId, input.assetId(), input.policyId(), input.actionType(), parameters,
                    reason, policy == null ? null : new ActionSnapshotFactory.PolicySnapshot(
                            policy.policyKey(), policy.version(), policy.environment(), policy.maxDurationSeconds()));
        } catch (RuntimeException exception) {
            throw ApiRequestException.badRequest(policy == null ? "响应申请无法规范化" : "响应策略快照无法规范化");
        }
    }

    public JsonNode parseJson(String value) {
        try {
            return objectMapper.readTree(value);
        } catch (Exception exception) {
            return objectMapper.getNodeFactory().nullNode();
        }
    }

    public String sha256(String content) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(content.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception exception) {
            throw new IllegalStateException("SHA-256 is not available", exception);
        }
    }

    public ResponseService.ApprovalView view(ResponseMapper.ApprovalRow row) {
        if (row == null) return null;
        try {
            return new ResponseService.ApprovalView(row.id(), row.eventId(), row.assetId(),
                    objectMapper.readTree(row.actionRequestJson()), row.status(), row.requestedBy(), row.reviewedBy(),
                    row.expiresAt(), row.createdAt(), false);
        } catch (Exception exception) {
            throw new IllegalStateException("Stored action request is invalid JSON", exception);
        }
    }

    public ResponseService.Page page(long total, int page, int size, List<ResponseService.ApprovalView> items) {
        return new ResponseService.Page(total, page, size, items);
    }

    public int checkedOffset(int page, int size) {
        if (page < 0 || size < 1 || size > 100 || (long) page * size > Integer.MAX_VALUE) {
            throw ApiRequestException.badRequest("分页参数超出允许范围");
        }
        return page * size;
    }

    public LocalDateTime utcNowPlusSeconds(long seconds) {
        return LocalDateTime.ofInstant(clock.instant().plusSeconds(seconds), ZoneOffset.UTC);
    }

    public java.time.Instant toInstant(LocalDateTime value) {
        return value.toInstant(ZoneOffset.UTC);
    }
}
