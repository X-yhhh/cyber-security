package com.xyh.cybersecurity.ingest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/** 由有权人工主体登记传感器、批准首个配置，并一次性签发 sensor 机器凭据。 */
@Service
public class SensorManagementService {
    private static final SecureRandom RANDOM = new SecureRandom();
    private final JdbcTemplate jdbc;
    private final ObjectMapper objectMapper;

    public SensorManagementService(JdbcTemplate jdbc, ObjectMapper objectMapper) {
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
    }

    @Transactional
    public IssuedSensor register(RegisterRequest request, IdentityPrincipal actor, HttpServletRequest httpRequest) {
        requireManageScope(actor.id(), request.assetId());
        requireSourceScope(actor.id(), request.dataSourceId());
        if (request.agentKey() == null || !request.agentKey().matches("[A-Za-z0-9._:-]{3,128}")
                || request.platform() == null || request.agentVersion() == null || request.config() == null
                || request.config().configVersion() == null || request.config().featureContractVersion() == null
                || request.config().flowWindowSeconds() < 1 || request.dataSourceId() < 1) {
            throw ApiRequestException.badRequest("传感器登记参数无效");
        }
        requireAuthorizedAsset(request.assetId());
        Boolean sourceActive = jdbc.queryForObject("SELECT EXISTS (SELECT 1 FROM data_source WHERE id=? AND status='active')", Boolean.class, request.dataSourceId());
        if (!Boolean.TRUE.equals(sourceActive)) throw ApiRequestException.badRequest("数据源不存在或不可用");
        String capabilities = json(request.capabilities());
        String interfaceScope = json(request.config().interfaceScope());
        String filterPolicy = json(request.config().filterPolicy());
        String samplingPolicy = json(request.config().samplingPolicy());
        GeneratedKeyHolder sensorKey = new GeneratedKeyHolder();
        try {
            jdbc.update(connection -> {
                PreparedStatement statement = connection.prepareStatement("INSERT INTO sensor_agent (agent_key,asset_id,platform,agent_version,capabilities_json,credential_ref,status,registered_at) VALUES (?,?,?,?,?,'pending','active',?)", Statement.RETURN_GENERATED_KEYS);
                statement.setString(1, request.agentKey()); statement.setLong(2, request.assetId()); statement.setString(3, request.platform()); statement.setString(4, request.agentVersion()); statement.setString(5, capabilities); statement.setTimestamp(6, java.sql.Timestamp.from(Instant.now())); return statement;
            }, sensorKey);
        } catch (org.springframework.dao.DuplicateKeyException e) {
            throw ApiRequestException.conflict("传感器标识已存在");
        }
        long sensorId = sensorKey.getKey().longValue();
        byte[] bytes = new byte[32]; RANDOM.nextBytes(bytes);
        String secret = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        String digest = sha256(secret);
        String scopes = json(List.of(Map.of("type", "asset", "id", Long.toString(request.assetId())), Map.of("type", "data_source", "id", Long.toString(request.dataSourceId()))));
        GeneratedKeyHolder clientKey = new GeneratedKeyHolder();
        jdbc.update(connection -> {
            PreparedStatement statement = connection.prepareStatement("INSERT INTO api_client (client_key,client_type,sensor_id,secret_ref,credential_sha256,scope_json,status,expires_at) VALUES (?, 'sensor', ?, 'database-sha256-verifier', ?, ?, 'active', DATE_ADD(UTC_TIMESTAMP(3), INTERVAL 30 DAY))", Statement.RETURN_GENERATED_KEYS);
            statement.setString(1, "sensor-" + sha256(request.agentKey()).substring(0, 32)); statement.setLong(2, sensorId); statement.setString(3, digest); statement.setString(4, scopes); return statement;
        }, clientKey);
        long machineId = clientKey.getKey().longValue();
        jdbc.update("UPDATE sensor_agent SET credential_ref=? WHERE id=?", "api-client:" + machineId, sensorId);
        jdbc.update("INSERT INTO api_client_scope (client_id,scope_type,scope_id) VALUES (?, 'asset', ?),(?, 'data_source', ?)", machineId, Long.toString(request.assetId()), machineId, Long.toString(request.dataSourceId()));
        jdbc.update("INSERT INTO api_client_source_asset_scope (client_id,data_source_id,asset_id) VALUES (?,?,?)", machineId, request.dataSourceId(), request.assetId());
        jdbc.update("INSERT INTO api_client_permission (client_id,permission_id) SELECT ?,id FROM sys_permission WHERE permission_key IN ('machine.sensor.heartbeat','machine.sensor.config.read','machine.sensor.ingest')", machineId);
        jdbc.update("INSERT INTO sensor_config (sensor_id,config_version,interface_scope_json,filter_policy_json,flow_window_seconds,feature_contract_version,sampling_policy_json,status,approved_by,activated_at) VALUES (?,?,?,?,?,?,?,'active',?,UTC_TIMESTAMP(3))",
                sensorId, request.config().configVersion(), interfaceScope, filterPolicy, request.config().flowWindowSeconds(), request.config().featureContractVersion(), samplingPolicy, actor.id());
        writeAudit(actor.id(), sensorId, request.assetId(), request.dataSourceId(), requestId(httpRequest));
        Instant issuedAt = Instant.now();
        return new IssuedSensor(sensorId, machineId, request.agentKey(), "mch_" + machineId + "." + secret, request.config().configVersion(), issuedAt, issuedAt.plusSeconds(30L * 24 * 3600));
    }

    private void requireManageScope(long userId, long assetId) {
        Boolean allowed = jdbc.queryForObject("SELECT EXISTS (SELECT 1 FROM sys_user_role ur JOIN sys_role r ON r.id=ur.role_id AND r.status='active' JOIN sys_role_permission rp ON rp.role_id=r.id JOIN sys_permission p ON p.id=rp.permission_id AND p.permission_key='sensor.manage' AND p.status='active' WHERE ur.user_id=? AND ((ur.scope_type='global' AND ur.scope_id='*') OR (ur.scope_type='asset' AND ur.scope_id=?)))", Boolean.class, userId, Long.toString(assetId));
        if (!Boolean.TRUE.equals(allowed)) throw new AccessDeniedException("Sensor scope denied");
    }

    private void requireAuthorizedAsset(long assetId) {
        Boolean exists = jdbc.queryForObject("SELECT EXISTS (SELECT 1 FROM asset a JOIN asset_authorization aa ON aa.asset_id=a.id AND aa.status='active' AND aa.valid_from<=UTC_TIMESTAMP(3) AND aa.valid_until>UTC_TIMESTAMP(3) WHERE a.id=? AND a.status='active')", Boolean.class, assetId);
        if (!Boolean.TRUE.equals(exists)) throw ApiRequestException.badRequest("资产未登记有效授权");
    }

    private void requireSourceScope(long userId, long sourceId) {
        Boolean allowed = jdbc.queryForObject("SELECT EXISTS (SELECT 1 FROM sys_user_role ur JOIN sys_role r ON r.id=ur.role_id AND r.status='active' JOIN sys_role_permission rp ON rp.role_id=r.id JOIN sys_permission p ON p.id=rp.permission_id AND p.permission_key='sensor.manage' AND p.status='active' WHERE ur.user_id=? AND ((ur.scope_type='global' AND ur.scope_id='*') OR (ur.scope_type='data_source' AND ur.scope_id=?)))", Boolean.class, userId, Long.toString(sourceId));
        if (!Boolean.TRUE.equals(allowed)) throw new AccessDeniedException("Sensor data source scope denied");
    }

    private void writeAudit(long actorId, long sensorId, long assetId, long sourceId, String requestId) {
        jdbc.update("INSERT INTO audit_log (occurred_at,actor_type,actor_id,action,resource_type,resource_id,request_id,outcome,reason) VALUES (UTC_TIMESTAMP(3),'human',?,'sensor.registered','sensor_agent',?,?, 'success','sensor credential issued once')", Long.toString(actorId), Long.toString(sensorId), requestId);
        Long id = jdbc.queryForObject("SELECT LAST_INSERT_ID()", Long.class);
        jdbc.update("INSERT INTO audit_resource_scope (audit_id,scope_type,scope_id) VALUES (?, 'asset', ?),(?, 'data_source', ?)", id, Long.toString(assetId), id, Long.toString(sourceId));
    }

    private String requestId(HttpServletRequest request) { Object value = request.getAttribute(com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE); return value instanceof String s ? s : "unknown"; }
    private String json(JsonNode value) {
        try {
            if (value == null || !value.isContainerNode() || value.toString().getBytes(StandardCharsets.UTF_8).length > 65_536
                    || containsExecutableField(value)) throw new IllegalArgumentException();
            return objectMapper.writeValueAsString(value);
        } catch (Exception e) { throw ApiRequestException.badRequest("配置字段必须为有限结构化 JSON，不能包含命令或外部地址"); }
    }
    private boolean containsExecutableField(JsonNode node) {
        if (node.isObject()) {
            var fields = node.fields();
            while (fields.hasNext()) {
                var field = fields.next();
                if (java.util.Set.of("command", "shell", "script", "exec", "url", "endpoint", "download").contains(field.getKey().toLowerCase(java.util.Locale.ROOT))) return true;
                if (containsExecutableField(field.getValue())) return true;
            }
        } else if (node.isArray()) {
            for (JsonNode child : node) if (containsExecutableField(child)) return true;
        }
        return false;
    }
    private String json(Object value) { try { return objectMapper.writeValueAsString(value); } catch (Exception e) { throw new IllegalStateException(e); } }
    private static String sha256(String value) { try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); } catch (Exception e) { throw new IllegalStateException(e); } }

    public record RegisterRequest(String agentKey, long assetId, long dataSourceId, String platform, String agentVersion,
                                  JsonNode capabilities, ConfigRequest config) { }
    public record ConfigRequest(String configVersion, JsonNode interfaceScope, JsonNode filterPolicy, int flowWindowSeconds,
                                 String featureContractVersion, JsonNode samplingPolicy) { }
    public record IssuedSensor(long sensorId, long machineClientId, String agentKey, String credential,
                               String configVersion, Instant issuedAt, Instant expiresAt) { }
}
