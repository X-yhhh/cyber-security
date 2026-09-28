package com.xyh.cybersecurity.response.domain;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * 纯响应策略门禁：只根据已读取的策略、资产环境和请求参数判断是否匹配。
 * 不访问数据库、不执行动作，调用方必须在进入本门禁前完成资源范围和授权校验。
 */
public final class PolicyGuard {

    private final ObjectMapper objectMapper;

    public PolicyGuard(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public boolean matches(Policy policy, String actionType, Asset asset, JsonNode parameters) {
        if (policy == null || asset == null || parameters == null
                || !"active".equals(policy.status()) || policy.approvedBy() == null
                || policy.autoExecute() || !policy.approvalRequired()
                || !policy.actionType().equals(actionType) || !policy.environment().equals(asset.environment())) {
            return false;
        }
        JsonNode match = parse(policy.matchJson());
        if (!match.isObject() || match.size() != 1 || !match.has("environment")
                || !asset.environment().equals(match.path("environment").asText())) return false;

        JsonNode configured = parse(policy.actionParamsJson());
        if (!configured.isObject() || configured.size() != 2
                || !configured.has("maxTtlSeconds") || !configured.has("allowedTargets")) return false;
        int policyTtl = configured.path("maxTtlSeconds").asInt(-1);
        int requestedTtl = parameters.path("ttlSeconds").asInt(-1);
        JsonNode allowedTargets = configured.path("allowedTargets");
        String target = parameters.path("targetAddress").asText("");
        if (policyTtl < 1 || requestedTtl < 1 || requestedTtl > policyTtl
                || requestedTtl > policy.maxDurationSeconds() || !isIpv4Literal(target)
                || !allowedTargets.isArray()) return false;
        for (JsonNode allowed : allowedTargets) if (target.equals(allowed.asText())) return true;
        return false;
    }

    private JsonNode parse(String value) {
        try { return objectMapper.readTree(value); }
        catch (Exception ignored) { return objectMapper.getNodeFactory().nullNode(); }
    }

    private static boolean isIpv4Literal(String value) {
        String[] parts = value.split("\\.", -1);
        if (parts.length != 4) return false;
        for (String part : parts) {
            if (part.isEmpty() || !part.matches("[0-9]{1,3}")) return false;
            int octet = Integer.parseInt(part);
            if (octet > 255 || (part.length() > 1 && part.charAt(0) == '0')) return false;
        }
        return true;
    }

    public record Policy(String status, Long approvedBy, boolean autoExecute, boolean approvalRequired,
                         String actionType, String environment, String matchJson, String actionParamsJson,
                         int maxDurationSeconds) { }

    public record Asset(String environment) { }
}
