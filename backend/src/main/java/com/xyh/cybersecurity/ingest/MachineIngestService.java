package com.xyh.cybersecurity.ingest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import com.xyh.cybersecurity.audit.AuditMapper;
import com.xyh.cybersecurity.ingest.outbox.OutboxAppended;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.HexFormat;

/** 按机器主体的数据源和资产范围写入幂等批次、规范记录、outbox 与追加审计。 */
@Service
public class MachineIngestService {

    private final IngestMapper mapper;
    private final AuditMapper auditMapper;
    private final ObjectMapper objectMapper;
    private final ApplicationEventPublisher events;

    public MachineIngestService(IngestMapper mapper, AuditMapper auditMapper, ObjectMapper objectMapper,
                                ApplicationEventPublisher events) {
        this.mapper = mapper;
        this.auditMapper = auditMapper;
        this.objectMapper = objectMapper;
        this.events = events;
    }

    @Transactional
    public Submission submit(long clientId, String clientKey, String idempotencyKey, BatchRequest input, String requestId) {
        if (idempotencyKey == null || !idempotencyKey.matches("[A-Za-z0-9._:-]{1,160}")) {
            throw ApiRequestException.badRequest("Idempotency-Key 格式无效");
        }
        validateRecords(input.records());
        requireSourceScope(clientId, input.dataSourceId());
        String canonical = canonicalRequest(input);
        if (canonical.getBytes(StandardCharsets.UTF_8).length > 1_048_576) {
            throw new ApiRequestException(org.springframework.http.HttpStatus.PAYLOAD_TOO_LARGE,
                    "BATCH_TOO_LARGE", "规范化批次不能超过 1 MiB");
        }
        String requestHash = sha256(canonical);
        ExistingBatch existing = findByIdempotency(input.dataSourceId(), idempotencyKey);
        if (existing != null) return idempotentResult(existing, requestHash);
        requireActiveApprovedMapping(input.dataSourceId(), input.mappingVersion());
        Set<Long> assetIds = validateAssetScopes(clientId, input.dataSourceId(), input.records());

        String batchKey = "bat_" + UUID.randomUUID().toString().replace("-", "");
        try {
            mapper.insertMachineBatch(new IngestMapper.MachineBatchInsert(batchKey, input.dataSourceId(), idempotencyKey,
                    requestHash, input.records().size(), Instant.now()));
        } catch (org.springframework.dao.DuplicateKeyException exception) {
            ExistingBatch concurrent = findByIdempotency(input.dataSourceId(), idempotencyKey);
            if (concurrent != null) return idempotentResult(concurrent, requestHash);
            throw ApiRequestException.conflict("批次幂等鍵已被其他接入請求使用");
        }
        long batchId = mapper.findBatchIdByKey(batchKey);
        for (RecordRequest record : input.records()) {
            mapper.insertMachineRecord(batchId, record.recordKey(), record.eventType(), record.eventTime(), record.assetId(),
                    writeJson(record.payload()), input.mappingVersion());
        }
        insertOutbox(batchId, input.dataSourceId(), input.records().size());
        insertAudit(batchId, input.dataSourceId(), assetIds, clientKey, requestId);
        return new Submission(true, new BatchReceipt(batchId, batchKey, input.dataSourceId(), "received",
                input.records().size(), input.records().size(), 0));
    }

    private void validateRecords(List<RecordRequest> records) {
        if (records == null || records.isEmpty() || records.size() > 500) {
            throw ApiRequestException.badRequest("批次必须包含 1 至 500 条记录");
        }
        Set<String> keys = new HashSet<>();
        for (RecordRequest record : records) {
            if (record == null || record.recordKey() == null || !record.recordKey().matches("[A-Za-z0-9._:-]{1,160}")
                    || record.eventType() == null || !record.eventType().matches("[A-Za-z0-9._-]{1,64}")
                    || record.eventTime() == null || record.assetId() == null || record.payload() == null
                    || !record.payload().isObject()) {
                throw ApiRequestException.badRequest("记录字段无效；assetId 必填，payload 必须为规范化 JSON 对象");
            }
            if (!keys.add(record.recordKey())) throw ApiRequestException.badRequest("同一批次不能重复 source record key");
            if (record.eventTime().isAfter(Instant.now().plusSeconds(300))) {
                throw ApiRequestException.badRequest("记录时间不能超出允许的未来偏差");
            }
            if (record.payload().toString().getBytes(StandardCharsets.UTF_8).length > 65_536) {
                throw new ApiRequestException(org.springframework.http.HttpStatus.PAYLOAD_TOO_LARGE,
                        "RECORD_TOO_LARGE", "单条规范化记录不能超过 64 KiB");
            }
        }
    }

    private void requireSourceScope(long clientId, long sourceId) {
        if (!mapper.hasConnectorSourceScope(clientId, sourceId)) throw ApiRequestException.notFound();
    }

    private void requireActiveApprovedMapping(long sourceId, String mappingVersion) {
        if (!mapper.hasApprovedMapping(sourceId, mappingVersion)) throw ApiRequestException.conflict("数据源不存在活动且已批准的映射版本");
    }

    private Set<Long> validateAssetScopes(long clientId, long sourceId, List<RecordRequest> records) {
        Set<Long> assetIds = new HashSet<>();
        for (RecordRequest record : records) {
            if (!mapper.hasConnectorAssetScope(clientId, sourceId, record.assetId())) throw ApiRequestException.notFound();
            assetIds.add(record.assetId());
        }
        return Set.copyOf(assetIds);
    }

    private ExistingBatch findByIdempotency(long sourceId, String idempotencyKey) {
        IngestMapper.BatchRow row = mapper.findBatchBySourceKey(sourceId, idempotencyKey);
        return row == null ? null : new ExistingBatch(row.id(), row.batchKey(), row.sourceId(), row.status(),
                row.totalCount(), row.acceptedCount(), row.rejectedCount(), row.requestSha256());
    }

    private Submission idempotentResult(ExistingBatch existing, String requestHash) {
        if (existing.requestSha256() == null || !MessageDigest.isEqual(
                existing.requestSha256().getBytes(StandardCharsets.US_ASCII), requestHash.getBytes(StandardCharsets.US_ASCII))) {
            throw ApiRequestException.conflict("相同幂等鍵对应了不同批次内容");
        }
        return new Submission(false, new BatchReceipt(existing.id(), existing.batchKey(), existing.sourceId(),
                existing.status(), existing.totalCount(), existing.acceptedCount(), existing.rejectedCount()));
    }

    private String canonicalRequest(BatchRequest request) {
        try {
            JsonNode tree = objectMapper.valueToTree(request);
            return objectMapper.writeValueAsString(canonicalize(tree));
        } catch (Exception exception) {
            throw new IllegalStateException("Unable to canonicalize ingest request", exception);
        }
    }

    private JsonNode canonicalize(JsonNode node) {
        if (node.isObject()) {
            ObjectNode result = objectMapper.createObjectNode();
            List<String> names = new ArrayList<>();
            node.fieldNames().forEachRemaining(names::add);
            names.stream().sorted().forEach(name -> result.set(name, canonicalize(node.get(name))));
            return result;
        }
        if (node.isArray()) {
            ArrayNode result = objectMapper.createArrayNode();
            node.forEach(child -> result.add(canonicalize(child)));
            return result;
        }
        return node.deepCopy();
    }

    private String writeJson(JsonNode node) {
        try {
            return objectMapper.writeValueAsString(node);
        } catch (Exception exception) {
            throw new IllegalArgumentException("Invalid normalized payload", exception);
        }
    }

    private void insertOutbox(long batchId, long sourceId, int count) {
        mapper.insertOutbox("ingest.batch:" + batchId, "ingest_batch", Long.toString(batchId), "ingest.batch.received",
                "{\"batchId\":" + batchId + ",\"dataSourceId\":" + sourceId + ",\"recordCount\":" + count + "}");
        // 提交后唤醒 relay；接入成功即记为数据源最近成功时间（HTTP 已持久化，推理结论由批次状态另行体现）。
        mapper.touchSourceSuccess(sourceId);
        events.publishEvent(new OutboxAppended(batchId));
    }

    private void insertAudit(long batchId, long sourceId, Set<Long> assetIds, String clientKey, String requestId) {
        AuditMapper.AuditInsert audit = new AuditMapper.AuditInsert(LocalDateTime.now(ZoneOffset.UTC), "machine", clientKey,
                "ingest.batch.received", "ingest_batch", Long.toString(batchId), requestId, "success",
                "scoped normalized batch accepted");
        auditMapper.insertAudit(audit);
        auditMapper.insertResourceScope(audit.getId(), "data_source", Long.toString(sourceId));
        for (long assetId : assetIds) {
            auditMapper.insertResourceScope(audit.getId(), "asset", Long.toString(assetId));
        }
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    public record RecordRequest(String recordKey, String eventType, Instant eventTime, Long assetId, JsonNode payload) { }
    public record BatchRequest(long dataSourceId, String mappingVersion, List<RecordRequest> records) { }
    public record BatchReceipt(long id, String batchKey, long dataSourceId, String status,
                               long totalCount, long acceptedCount, long rejectedCount) { }
    public record Submission(boolean created, BatchReceipt receipt) { }
    private record ExistingBatch(long id, String batchKey, long sourceId, String status, long totalCount,
                                 long acceptedCount, long rejectedCount, String requestSha256) { }
}
