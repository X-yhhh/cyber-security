package com.xyh.cybersecurity.response.domain;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

/** 生成不可变响应申请快照；快照包含策略版本和环境，供审批时重新比对。 */
public final class ActionSnapshotFactory {

    private final ObjectMapper objectMapper;

    public ActionSnapshotFactory(ObjectMapper objectMapper) { this.objectMapper = objectMapper; }

    public String create(long eventId, long assetId, long policyId, String actionType, JsonNode parameters,
                         String reason, PolicySnapshot policy) {
        ObjectNode snapshot = objectMapper.createObjectNode().put("eventId", eventId).put("assetId", assetId)
                .put("policyId", policyId).put("actionType", actionType).put("reason", reason);
        snapshot.set("parameters", parameters);
        if (policy != null) snapshot.put("policyKey", policy.policyKey()).put("policyVersion", policy.version())
                .put("policyEnvironment", policy.environment()).put("policyMaxDurationSeconds", policy.maxDurationSeconds());
        try { return objectMapper.writeValueAsString(snapshot); }
        catch (Exception exception) { throw new IllegalArgumentException("响应申请无法规范化", exception); }
    }

    public record PolicySnapshot(String policyKey, String version, String environment, int maxDurationSeconds) { }
}
