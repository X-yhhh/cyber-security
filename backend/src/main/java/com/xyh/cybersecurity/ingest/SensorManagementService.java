package com.xyh.cybersecurity.ingest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import com.xyh.cybersecurity.audit.AuditMapper;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/** 由有权人工主体登记传感器、批准首个配置，并一次性签发 sensor 机器凭据。 */
@Service
public class SensorManagementService {
    private static final SecureRandom RANDOM = new SecureRandom();
    private final IngestMapper mapper;
    private final AuditMapper auditMapper;
    private final ObjectMapper objectMapper;

    public SensorManagementService(IngestMapper mapper, AuditMapper auditMapper, ObjectMapper objectMapper) {
        this.mapper = mapper;
        this.auditMapper = auditMapper;
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
        if (!mapper.activeSource(request.dataSourceId())) throw ApiRequestException.badRequest("数据源不存在或不可用");
        String capabilities = json(request.capabilities());
        String interfaceScope = json(request.config().interfaceScope());
        String filterPolicy = json(request.config().filterPolicy());
        String samplingPolicy = json(request.config().samplingPolicy());
        try {
            mapper.insertSensor(new IngestMapper.SensorInsert(request.agentKey(), request.assetId(), request.platform(),
                    request.agentVersion(), capabilities, Instant.now()));
        } catch (org.springframework.dao.DuplicateKeyException e) {
            throw ApiRequestException.conflict("传感器标识已存在");
        }
        long sensorId = mapper.findSensorId(request.agentKey());
        byte[] bytes = new byte[32]; RANDOM.nextBytes(bytes);
        String secret = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        String digest = sha256(secret);
        String scopes = json(List.of(Map.of("type", "asset", "id", Long.toString(request.assetId())), Map.of("type", "data_source", "id", Long.toString(request.dataSourceId()))));
        String machineKey = "sensor-" + sha256(request.agentKey()).substring(0, 32);
        mapper.insertSensorClient(new IngestMapper.SensorClientInsert(machineKey, sensorId, digest, scopes));
        long machineId = mapper.findClientId(machineKey);
        mapper.updateCredentialRef(sensorId, "api-client:" + machineId);
        mapper.insertClientAssetScope(machineId, request.assetId());
        mapper.insertClientSourceScope(machineId, request.dataSourceId());
        mapper.insertClientPair(machineId, request.dataSourceId(), request.assetId());
        mapper.grantSensorPermissions(machineId);
        mapper.insertSensorConfig(new IngestMapper.SensorConfigInsert(sensorId, request.config().configVersion(),
                interfaceScope, filterPolicy, request.config().flowWindowSeconds(), request.config().featureContractVersion(),
                samplingPolicy, actor.id()));
        writeAudit(actor.id(), sensorId, request.assetId(), request.dataSourceId(), requestId(httpRequest));
        Instant issuedAt = Instant.now();
        return new IssuedSensor(sensorId, machineId, request.agentKey(), "mch_" + machineId + "." + secret, request.config().configVersion(), issuedAt, issuedAt.plusSeconds(30L * 24 * 3600));
    }

    private void requireManageScope(long userId, long assetId) {
        if (!mapper.hasSensorManageAsset(userId, assetId)) throw new AccessDeniedException("Sensor scope denied");
    }

    private void requireAuthorizedAsset(long assetId) {
        if (!mapper.hasAuthorizedAsset(assetId)) throw ApiRequestException.badRequest("资产未登记有效授权");
    }

    private void requireSourceScope(long userId, long sourceId) {
        if (!mapper.hasSensorManageSource(userId, sourceId)) throw new AccessDeniedException("Sensor data source scope denied");
    }

    private void writeAudit(long actorId, long sensorId, long assetId, long sourceId, String requestId) {
        AuditMapper.AuditInsert audit = new AuditMapper.AuditInsert(LocalDateTime.now(), "human", Long.toString(actorId),
                "sensor.registered", "sensor_agent", Long.toString(sensorId), requestId, "success",
                "sensor credential issued once");
        auditMapper.insertAudit(audit);
        auditMapper.insertResourceScope(audit.getId(), "asset", Long.toString(assetId));
        auditMapper.insertResourceScope(audit.getId(), "data_source", Long.toString(sourceId));
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
