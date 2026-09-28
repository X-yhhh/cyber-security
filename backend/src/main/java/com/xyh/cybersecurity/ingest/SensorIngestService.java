package com.xyh.cybersecurity.ingest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import com.xyh.cybersecurity.audit.AuditMapper;
import com.xyh.cybersecurity.ingest.contract.FeatureContract;
import com.xyh.cybersecurity.ingest.contract.FeatureContractRegistry;
import com.xyh.cybersecurity.ingest.contract.FeatureContractValidator;
import com.xyh.cybersecurity.ingest.contract.FeatureValidationResult;
import com.xyh.cybersecurity.identity.MachinePrincipal;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/** 传感器专用流批次接入：服务端解析身份、配置、授权和 raw feature 契约后才写入 outbox。 */
@Service
public class SensorIngestService {
    private final IngestMapper mapper;
    private final AuditMapper auditMapper;
    private final ObjectMapper objectMapper;
    private final FeatureContractRegistry contracts;
    private final FeatureContractValidator validator;

    public SensorIngestService(IngestMapper mapper, AuditMapper auditMapper, ObjectMapper objectMapper, FeatureContractRegistry contracts,
                               FeatureContractValidator validator) {
        this.mapper = mapper;
        this.auditMapper = auditMapper;
        this.objectMapper = objectMapper;
        this.contracts = contracts;
        this.validator = validator;
    }

    @Transactional
    public Submission submit(long pathSensorId, MachinePrincipal principal, String idempotencyKey,
                             SensorBatchRequest request, String requestId) {
        requireSensorPrincipal(pathSensorId, principal);
        validateRequest(idempotencyKey, request);
        SensorIdentity sensor = loadSensor(pathSensorId, principal.id());
        if (sensor == null) throw new ApiRequestException(HttpStatus.UNAUTHORIZED, "MACHINE_IDENTITY_REJECTED", "传感器身份已失效");
        if (!sensor.active()) throw new ApiRequestException(HttpStatus.UNAUTHORIZED, "MACHINE_IDENTITY_REJECTED", "传感器身份已失效");
        lockActiveSensor(pathSensorId);
        if (!hasSensorPermission(principal.id(), "machine.sensor.ingest")) {
            throw new ApiRequestException(HttpStatus.FORBIDDEN, "SCOPE_OR_ASSET_REJECTED", "传感器主体未获批流接入权限");
        }
        requireSourceScope(principal.id(), request.dataSourceId(), sensor.assetId());
        requireAssetAuthorization(sensor.assetId());
        requireActiveConfig(pathSensorId, request.configVersion(), request.featureContractVersion());
        requireApprovedMapping(request.dataSourceId(), request.sourceMappingVersion());

        String canonical = canonicalRequest(request);
        if (canonical.getBytes(StandardCharsets.UTF_8).length > 1_048_576) {
            throw new ApiRequestException(HttpStatus.PAYLOAD_TOO_LARGE, "BATCH_TOO_LARGE", "规范化批次不能超过 1 MiB");
        }
        String requestHash = sha256(canonical);
        ExistingBatch existing = findByIdempotency(request.dataSourceId(), idempotencyKey);
        if (existing != null) return idempotent(existing, requestHash);
        ExistingBatch sequence = findBySequence(pathSensorId, request.configVersion(), request.sequence());
        if (sequence != null) {
            if (MessageDigest.isEqual(bytes(sequence.requestSha256()), bytes(requestHash))) return idempotent(sequence, requestHash);
            throw new ApiRequestException(HttpStatus.CONFLICT, "SEQUENCE_CONFLICT", "同一传感器序号对应了不同批次内容");
        }
        Long previousSequence = mapper.previousSequence(pathSensorId, request.configVersion());
        if (previousSequence != null && request.sequence() < previousSequence) {
            throw new ApiRequestException(HttpStatus.CONFLICT, "SEQUENCE_CONFLICT", "传感器序号不能回退");
        }
        boolean sequenceGap = previousSequence != null && request.sequence() > previousSequence
                && request.sequence() - previousSequence > 1;

        List<RecordCheck> checks = new ArrayList<>();
        for (FlowRecordRequest record : request.records()) {
            checks.add(validateRecord(record, request.featureContractVersion(), sequenceGap));
        }
        int accepted = (int) checks.stream().filter(RecordCheck::accepted).count();
        int rejected = checks.size() - accepted;
        String status = rejected == 0 ? "received" : (accepted == 0 ? "rejected" : "completed_with_errors");
        InsertedBatch inserted = insertBatch(request, pathSensorId, idempotencyKey, requestHash, status, accepted, rejected, sequenceGap);
        long batchId = inserted.id();
        for (int i = 0; i < request.records().size(); i++) {
            FlowRecordRequest record = request.records().get(i);
            RecordCheck check = checks.get(i);
            mapper.insertSensorRecord(batchId, record.recordKey(), record.flowEndAt(), sensor.assetId(),
                    writeJson(recordPayload(record)), check.accepted() ? "accepted" : "rejected",
                    check.issuesJson(), request.sourceMappingVersion());
        }
        if (accepted > 0) insertOutbox(batchId, request.dataSourceId(), accepted);
        audit(batchId, request.dataSourceId(), sensor.assetId(), principal.clientKey(), requestId,
                accepted > 0 ? "success" : "rejected", accepted + " accepted, " + rejected + " rejected" + (sequenceGap ? ", sequence gap" : ""));
        BatchReceipt receipt = new BatchReceipt(batchId, inserted.batchKey(), request.dataSourceId(), status,
                request.records().size(), accepted, rejected, sequenceGap);
        return new Submission(true, receipt);
    }

    @Transactional
    public void heartbeat(long sensorId, MachinePrincipal principal, HeartbeatRequest heartbeat, String requestId) {
        requireSensorPrincipal(sensorId, principal);
        if (!hasSensorPermission(principal.id(), "machine.sensor.heartbeat")) {
            throw new ApiRequestException(HttpStatus.FORBIDDEN, "SCOPE_OR_ASSET_REJECTED", "传感器主体未获批心跳权限");
        }
        SensorIdentity sensor = loadSensor(sensorId, principal.id());
        if (sensor == null) throw new ApiRequestException(HttpStatus.UNAUTHORIZED, "MACHINE_IDENTITY_REJECTED", "传感器身份已失效");
        if (!sensor.active()) throw new ApiRequestException(HttpStatus.UNAUTHORIZED, "MACHINE_IDENTITY_REJECTED", "传感器身份已失效");
        if (heartbeat == null || heartbeat.observedAt() == null || heartbeat.observedAt().isAfter(Instant.now().plusSeconds(300))) {
            throw ApiRequestException.badRequest("心跳时间无效");
        }
        mapper.updateHeartbeat(sensorId, heartbeat.observedAt(), heartbeat.agentVersion(), writeJson(heartbeat.capabilities()));
        audit(0, 0, sensor.assetId(), principal.clientKey(), requestId, "success", "sensor heartbeat");
    }

    public ConfigView config(long sensorId, MachinePrincipal principal) {
        requireSensorPrincipal(sensorId, principal);
        if (!hasSensorPermission(principal.id(), "machine.sensor.config.read")) {
            throw new ApiRequestException(HttpStatus.FORBIDDEN, "SCOPE_OR_ASSET_REJECTED", "传感器主体未获批配置读取权限");
        }
        SensorIdentity sensor = loadSensor(sensorId, principal.id());
        if (sensor == null) throw new ApiRequestException(HttpStatus.UNAUTHORIZED, "MACHINE_IDENTITY_REJECTED", "传感器身份已失效");
        if (!sensor.active()) throw new ApiRequestException(HttpStatus.UNAUTHORIZED, "MACHINE_IDENTITY_REJECTED", "传感器身份已失效");
        IngestMapper.SensorConfigRow config = mapper.findActiveConfig(sensor.id());
        return config == null ? null : new ConfigView(config.configVersion(), config.interfaceScopeJson(),
                config.filterPolicyJson(), config.flowWindowSeconds(), config.featureContractVersion(),
                config.samplingPolicyJson(), config.activatedAt());
    }

    @Transactional
    public void healthWindow(long sensorId, MachinePrincipal principal, HealthWindowRequest window, String requestId) {
        requireSensorPrincipal(sensorId, principal);
        if (!hasSensorPermission(principal.id(), "machine.sensor.heartbeat")) {
            throw new ApiRequestException(HttpStatus.FORBIDDEN, "SCOPE_OR_ASSET_REJECTED", "传感器主体未获批健康摘要权限");
        }
        SensorIdentity sensor = loadSensor(sensorId, principal.id());
        if (sensor == null || !sensor.active()) throw new ApiRequestException(HttpStatus.UNAUTHORIZED, "MACHINE_IDENTITY_REJECTED", "传感器身份已失效");
        if (window == null || window.windowStart() == null || window.windowEnd() == null
                || !window.windowEnd().isAfter(window.windowStart()) || window.flowsSeen() < 0
                || window.flowsEmitted() < 0 || window.flowsDropped() < 0 || window.queueDepthMax() < 0
                || window.flowsEmitted() > window.flowsSeen()
                || window.flowsDropped() > window.flowsSeen() - window.flowsEmitted()
                || (window.cpuPercent() != null && (!Double.isFinite(window.cpuPercent()) || window.cpuPercent() < 0 || window.cpuPercent() > 100))) {
            throw ApiRequestException.badRequest("健康窗口或资源摘要无效");
        }
        JsonNode sanitizedErrors = sanitizeHealthErrors(window.errors());
        lockActiveSensor(sensorId);
        if (mapper.overlapsHealthWindow(sensorId, window.windowStart(), window.windowEnd())) {
            throw new ApiRequestException(HttpStatus.CONFLICT, "HEALTH_WINDOW_OVERLAP", "健康窗口与已提交窗口重叠");
        }
        try {
            mapper.insertHealthWindow(new IngestMapper.HealthWindowInsert(sensorId, window.windowStart(), window.windowEnd(),
                    window.flowsSeen(), window.flowsEmitted(), window.flowsDropped(), window.queueDepthMax(), window.cpuPercent(),
                    window.memoryBytes(), writeJson(sanitizedErrors)));
        } catch (org.springframework.dao.DuplicateKeyException e) {
            throw new ApiRequestException(HttpStatus.CONFLICT, "IDEMPOTENCY_CONFLICT", "健康窗口已提交");
        }
        audit(0, 0, sensor.assetId(), principal.clientKey(), requestId, "success", "sensor health window");
    }

    private RecordCheck validateRecord(FlowRecordRequest record, String version, boolean sequenceGap) {
        List<FeatureValidationResult.Issue> issues = new ArrayList<>();
        if (record == null || record.recordKey() == null || record.flowStartAt() == null || record.flowEndAt() == null
                || record.observedAt() == null || record.features() == null) {
            issues.add(new FeatureValidationResult.Issue("REQUIRED_FIELD_MISSING", "record", "complete flow record", "missing"));
        } else {
            if (record.flowEndAt().isBefore(record.flowStartAt())) issues.add(new FeatureValidationResult.Issue(
                    "FLOW_RECORD_INVALID", "flowEndAt", "not before flowStartAt", "before start"));
            if (record.flowEndAt().isAfter(Instant.now().plusSeconds(300))) issues.add(new FeatureValidationResult.Issue(
                    "FLOW_RECORD_INVALID", "flowEndAt", "within future skew", "future"));
            if (record.observedAt().isAfter(Instant.now().plusSeconds(300))) issues.add(new FeatureValidationResult.Issue(
                    "FLOW_RECORD_INVALID", "observedAt", "within future skew", "future"));
            if (!"initiator_to_responder".equals(record.directionBasis())) issues.add(new FeatureValidationResult.Issue(
                    "FLOW_RECORD_INVALID", "directionBasis", "initiator_to_responder", record.directionBasis()));
            FeatureValidationResult result = validator.validate(version, record.features());
            issues.addAll(result.issues());
            int blockingIssueCount = issues.size();
            if (sequenceGap) {
                issues.add(new FeatureValidationResult.Issue("EXPORT_SEQUENCE_GAP", "sequence", "contiguous batch sequence", "gap"));
                blockingIssueCount++;
            }
            result.categoryDrift().forEach(value -> issues.add(new FeatureValidationResult.Issue(
                    "CATEGORY_OUT_OF_VOCABULARY", value.substring(0, value.indexOf('=')), "manifest vocabulary", value)));
            FeatureContract contract = contracts.find(version);
            if (contract == null || !contract.onlineEnabled()) {
                issues.add(new FeatureValidationResult.Issue("FEATURE_CONTRACT_MISMATCH", "featureContractVersion",
                        "online-enabled contract", version));
                blockingIssueCount++;
            }
            return new RecordCheck(blockingIssueCount == 0, issuesJson(issues));
        }
        return new RecordCheck(false, issuesJson(issues));
    }

    private void requireActiveConfig(long sensorId, String version, String contractVersion) {
        if (!mapper.hasActiveConfig(sensorId, version, contractVersion)) throw new ApiRequestException(HttpStatus.CONFLICT, "CONFIG_VERSION_STALE", "传感器配置版本无效或已失效");
    }

    private void requireApprovedMapping(long sourceId, String mappingVersion) {
        if (!mapper.hasApprovedSourceMapping(sourceId, mappingVersion)) throw new ApiRequestException(HttpStatus.CONFLICT, "MAPPING_NOT_APPROVED", "来源映射未批准或已失效");
    }

    private void requireSourceScope(long clientId, long sourceId, long assetId) {
        if (!mapper.hasSensorSourcePair(clientId, sourceId, assetId)) throw new ApiRequestException(HttpStatus.NOT_FOUND, "SCOPE_OR_ASSET_REJECTED", "来源或资产不在传感器授权范围内");
    }

    private void requireAssetAuthorization(long assetId) {
        if (!mapper.hasAssetAuthorization(assetId)) throw new ApiRequestException(HttpStatus.FORBIDDEN, "SCOPE_OR_ASSET_REJECTED", "资产授权已过期或不存在");
    }

    private SensorIdentity loadSensor(long sensorId, long clientId) {
        IngestMapper.SensorIdentityRow row = mapper.findSensor(sensorId, clientId);
        return row == null ? null : new SensorIdentity(row.id(), row.assetId(), "active".equals(row.status()));
    }

    /** 串行化同一传感器的序号检查和健康窗口检查，避免并发写绕过服务层时序约束。 */
    private void lockActiveSensor(long sensorId) {
        if (mapper.lockActiveSensor(sensorId) == null) throw new ApiRequestException(HttpStatus.UNAUTHORIZED, "MACHINE_IDENTITY_REJECTED", "传感器身份已失效");
    }

    private void requireSensorPrincipal(long pathSensorId, MachinePrincipal principal) {
        if (principal == null || !"sensor".equals(principal.clientType())) {
            throw new ApiRequestException(HttpStatus.UNAUTHORIZED, "MACHINE_IDENTITY_REJECTED", "需要传感器机器主体");
        }
        if (!mapper.isClientBound(principal.id(), pathSensorId)) throw new ApiRequestException(HttpStatus.NOT_FOUND, "MACHINE_IDENTITY_REJECTED", "传感器身份与请求路径不匹配");
    }

    private boolean hasSensorPermission(long clientId, String permission) {
        return mapper.hasSensorPermission(clientId, permission);
    }

    private InsertedBatch insertBatch(SensorBatchRequest request, long sensorId, String idempotencyKey, String hash,
                             String status, int accepted, int rejected, boolean sequenceGap) {
        String key = "bat_" + UUID.randomUUID().toString().replace("-", "");
        mapper.insertSensorBatch(new IngestMapper.SensorBatchInsert(key, request.dataSourceId(), sensorId, request.configVersion(),
                request.sequence(), sequenceGap, request.featureContractVersion(), idempotencyKey, hash, status,
                request.records().size(), accepted, rejected, Instant.now()));
        return new InsertedBatch(mapper.findBatchIdByKey(key), key);
    }

    private void insertOutbox(long batchId, long sourceId, int count) {
        mapper.insertOutbox("sensor.ingest.batch:" + batchId, "ingest_batch", Long.toString(batchId), "ingest.batch.received",
                "{\"batchId\":" + batchId + ",\"dataSourceId\":" + sourceId + ",\"recordCount\":" + count + "}");
    }

    private void audit(long batchId, long sourceId, long assetId, String actor, String requestId, String outcome, String reason) {
        AuditMapper.AuditInsert audit = new AuditMapper.AuditInsert(LocalDateTime.now(), "machine", actor,
                "sensor.ingest", "ingest_batch", batchId == 0 ? null : Long.toString(batchId), requestId, outcome, reason);
        auditMapper.insertAudit(audit);
        if (sourceId > 0) auditMapper.insertResourceScope(audit.getId(), "data_source", Long.toString(sourceId));
        if (assetId > 0) auditMapper.insertResourceScope(audit.getId(), "asset", Long.toString(assetId));
    }

    private ExistingBatch findByIdempotency(long sourceId, String key) { return convert(mapper.findBatchBySourceKey(sourceId, key)); }
    private ExistingBatch findBySequence(long sensorId, String configVersion, long sequence) {
        return convert(mapper.findBatchBySequence(sensorId, configVersion, sequence));
    }

    private ExistingBatch convert(IngestMapper.BatchRow row) {
        return row == null ? null : new ExistingBatch(row.id(), row.batchKey(), row.sourceId(), row.status(), row.totalCount(),
                row.acceptedCount(), row.rejectedCount(), row.requestSha256(), row.sequenceGap());
    }

    private Submission idempotent(ExistingBatch existing, String hash) {
        if (existing.requestSha256() == null || !MessageDigest.isEqual(bytes(existing.requestSha256()), bytes(hash))) {
            throw new ApiRequestException(HttpStatus.CONFLICT, "IDEMPOTENCY_CONFLICT", "相同幂等键对应了不同批次内容");
        }
        return new Submission(false, new BatchReceipt(existing.id(), existing.batchKey(), existing.sourceId(), existing.status(), existing.totalCount(), existing.acceptedCount(), existing.rejectedCount(), existing.sequenceGap()));
    }

    private void validateRequest(String key, SensorBatchRequest request) {
        if (key == null || !key.matches("[A-Za-z0-9._:-]{1,160}")) throw ApiRequestException.badRequest("Idempotency-Key 格式无效");
        if (request == null || request.dataSourceId() < 1 || request.sequence() < 0 || request.configVersion() == null
                || request.sourceMappingVersion() == null || request.featureContractVersion() == null
                || request.observedAt() == null || request.observedAt().isAfter(Instant.now().plusSeconds(300))
                || request.records() == null || request.records().isEmpty() || request.records().size() > 500) {
            throw ApiRequestException.badRequest("传感器批次字段无效");
        }
        Set<String> recordKeys = new HashSet<>();
        for (FlowRecordRequest record : request.records()) {
            if (record == null || record.recordKey() == null || !record.recordKey().matches("[A-Za-z0-9._:-]{1,160}")
                    || !recordKeys.add(record.recordKey())) {
                throw ApiRequestException.badRequest("批次记录标识缺失、格式无效或重复");
            }
            if (record.features() != null && record.features().toString().getBytes(StandardCharsets.UTF_8).length > 65_536) {
                throw new ApiRequestException(HttpStatus.PAYLOAD_TOO_LARGE, "RECORD_TOO_LARGE", "单条流记录不能超过 64 KiB");
            }
        }
    }

    /** 仅接受字段名到计数的错误摘要，避免将任意日志、地址或凭据持久化。 */
    private JsonNode sanitizeHealthErrors(JsonNode errors) {
        ObjectNode sanitized = objectMapper.createObjectNode();
        if (errors == null || errors.isNull()) return sanitized;
        if (!errors.isObject() || errors.toString().getBytes(StandardCharsets.UTF_8).length > 16_384) {
            throw ApiRequestException.badRequest("健康错误摘要必须是有限的错误码计数对象");
        }
        errors.fields().forEachRemaining(entry -> {
            JsonNode count = entry.getValue();
            if (!entry.getKey().matches("[A-Z0-9_]{1,64}") || !count.isIntegralNumber()
                    || !count.canConvertToLong() || count.longValue() < 0) {
                throw ApiRequestException.badRequest("健康错误摘要仅接受错误码到非负计数的映射");
            }
            sanitized.put(entry.getKey(), count.longValue());
        });
        return sanitized;
    }

    private ObjectNode recordPayload(FlowRecordRequest record) {
        ObjectNode node = objectMapper.createObjectNode();
        node.put("recordKey", record.recordKey()); node.put("flowStartAt", record.flowStartAt().toString());
        node.put("flowEndAt", record.flowEndAt().toString()); node.put("observedAt", record.observedAt().toString());
        node.put("directionBasis", record.directionBasis()); node.set("features", record.features()); return node;
    }

    private String canonicalRequest(SensorBatchRequest request) {
        try { return objectMapper.writeValueAsString(canonicalize(objectMapper.valueToTree(request))); }
        catch (Exception e) { throw new IllegalStateException("无法规范化传感器批次", e); }
    }
    private JsonNode canonicalize(JsonNode node) {
        if (node.isObject()) { ObjectNode out = objectMapper.createObjectNode(); List<String> names = new ArrayList<>(); node.fieldNames().forEachRemaining(names::add); names.stream().sorted().forEach(n -> out.set(n, canonicalize(node.get(n)))); return out; }
        if (node.isArray()) { ArrayNode out = objectMapper.createArrayNode(); node.forEach(v -> out.add(canonicalize(v))); return out; }
        return node.deepCopy();
    }
    private String writeJson(JsonNode node) { try { return objectMapper.writeValueAsString(node == null ? objectMapper.createObjectNode() : node); } catch (Exception e) { throw new IllegalStateException(e); } }
    private static String issuesJson(List<FeatureValidationResult.Issue> issues) { try { return new ObjectMapper().writeValueAsString(issues); } catch (Exception e) { throw new IllegalStateException(e); } }
    private static String sha256(String value) { try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); } catch (Exception e) { throw new IllegalStateException(e); } }
    private static byte[] bytes(String value) { return value == null ? new byte[0] : value.getBytes(StandardCharsets.US_ASCII); }

    public record SensorBatchRequest(long dataSourceId, String configVersion, long sequence, Instant observedAt,
                                     String sourceMappingVersion, String featureContractVersion, List<FlowRecordRequest> records) { }
    public record FlowRecordRequest(String recordKey, Instant flowStartAt, Instant flowEndAt, Instant observedAt,
                                    String directionBasis, JsonNode features) { }
    public record HeartbeatRequest(Instant observedAt, String agentVersion, JsonNode capabilities) { }
    public record HealthWindowRequest(Instant windowStart, Instant windowEnd, long flowsSeen, long flowsEmitted,
                                      long flowsDropped, long queueDepthMax, Double cpuPercent, Long memoryBytes,
                                      JsonNode errors) { }
    public record ConfigView(String configVersion, String interfaceScope, String filterPolicy, int flowWindowSeconds,
                             String featureContractVersion, String samplingPolicy, Instant activatedAt) { }
    public record BatchReceipt(long id, String batchKey, long dataSourceId, String status, long totalCount, long acceptedCount, long rejectedCount, boolean sequenceGap) { }
    public record Submission(boolean created, BatchReceipt receipt) { }
    private record SensorIdentity(long id, long assetId, boolean active) { }
    private record ExistingBatch(long id, String batchKey, long sourceId, String status, long totalCount, long acceptedCount, long rejectedCount, String requestSha256, boolean sequenceGap) { }
    private record InsertedBatch(long id, String batchKey) { }
    private record RecordCheck(boolean accepted, String issuesJson) { }
}
