package com.xyh.cybersecurity.response.domain;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/** 资产授权范围的无副作用校验；数据库有效期和行锁由应用服务负责。 */
public final class AuthorizationGuard {

    private final ObjectMapper objectMapper;

    public AuthorizationGuard(ObjectMapper objectMapper) { this.objectMapper = objectMapper; }

    public boolean scopeAllows(String scopeJson, String actionType) {
        if (scopeJson == null || actionType == null || actionType.isBlank()) return false;
        try {
            JsonNode actions = objectMapper.readTree(scopeJson).path("actionTypes");
            if (!actions.isArray()) return false;
            for (JsonNode action : actions) if (actionType.equals(action.asText())) return true;
            return false;
        } catch (Exception ignored) {
            return false;
        }
    }
}
