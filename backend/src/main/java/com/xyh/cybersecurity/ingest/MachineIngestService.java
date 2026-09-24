package com.xyh.cybersecurity.ingest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.HexFormat;

/** 按机器主体的数据源和资产范围写入幂等批次、规范记录、outbox 与追加审计。 */
@Service
public class MachineIngestService {

    private final JdbcTemplate jdbc;
    private final ObjectMapper objectMapper;

    public MachineIngestService(JdbcTemplate jdbc, ObjectMapper objectMapper) {
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
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
        GeneratedKeyHolder key = new GeneratedKeyHolder();
        try {
            jdbc.update(connection -> {
                PreparedStatement statement = connection.prepareStatement("INSERT INTO ingest_batch "
                        + "(batch_key,data_source_id,idempotency_key,request_sha256,status,total_count,accepted_count,rejected_count,started_at) "
                        + "VALUES (?,?,?,?,'received',?,?,0,?)", Statement.RETURN_GENERATED_KEYS);
                statement.setString(1, batchKey);
                statement.setLong(2, input.dataSourceId());
                statement.setString(3, idempotencyKey);
                statement.setString(4, requestHash);
                statement.setLong(5, input.records().size());
                statement.setLong(6, input.records().size());
                statement.setTimestamp(7, Timestamp.from(Instant.now()));
                return statement;
            }, key);
        } catch (org.springframework.dao.DuplicateKeyException exception) {
            ExistingBatch concurrent = findByIdempotency(input.dataSourceId(), idempotencyKey);
            if (concurrent != null) return idempotentResult(concurrent, requestHash);
            throw ApiRequestException.conflict("批次幂等鍵已被其他接入請求使用");
        }
        long batchId = key.getKey().longValue();
        for (RecordRequest record : input.records()) {
            jdbc.update("INSERT INTO ingest_record (batch_id,source_record_key,event_type,event_time,asset_id,"
                            + "normalized_payload,quality_status,mapping_version) VALUES (?,?,?,?,?,?,'accepted',?)",
                    batchId, record.recordKey(), record.eventType(), Timestamp.from(record.eventTime()), record.assetId(),
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
        Boolean allowed = jdbc.queryForObject("SELECT EXISTS (SELECT 1 FROM api_client c "
                        + "JOIN api_client_permission cp ON cp.client_id=c.id "
                        + "JOIN sys_permission p ON p.id=cp.permission_id AND p.permission_key='machine.ingest.submit' AND p.status='active' "
                        + "JOIN api_client_scope s ON s.client_id=c.id AND s.scope_type='data_source' AND s.scope_id=CAST(? AS CHAR) "
                        + "JOIN data_source ds ON ds.id=CAST(s.scope_id AS UNSIGNED) AND ds.status='active' "
                        + "WHERE c.id=? AND c.client_type='connector' AND c.status='active' "
                        + "AND (c.expires_at IS NULL OR c.expires_at>UTC_TIMESTAMP(3)))", Boolean.class, sourceId, clientId);
        if (!Boolean.TRUE.equals(allowed)) throw ApiRequestException.notFound();
    }

    private void requireActiveApprovedMapping(long sourceId, String mappingVersion) {
        Boolean active = jdbc.queryForObject("SELECT EXISTS (SELECT 1 FROM source_mapping sm "
                        + "JOIN data_source ds ON ds.id=sm.data_source_id AND ds.status='active' "
                        + "WHERE sm.data_source_id=? AND sm.mapping_version=? AND sm.status='approved')",
                Boolean.class, sourceId, mappingVersion);
        if (!Boolean.TRUE.equals(active)) throw ApiRequestException.conflict("数据源不存在活动且已批准的映射版本");
    }

    private Set<Long> validateAssetScopes(long clientId, long sourceId, List<RecordRequest> records) {
        Set<Long> assetIds = new HashSet<>();
        for (RecordRequest record : records) {
            Boolean allowed = jdbc.queryForObject("SELECT EXISTS (SELECT 1 FROM api_client_scope s "
                            + "JOIN asset a ON a.id=CAST(s.scope_id AS UNSIGNED) AND a.status='active' "
                            + "JOIN api_client_source_asset_scope pair ON pair.client_id=s.client_id "
                            + "AND pair.asset_id=a.id AND pair.data_source_id=? "
                            + "WHERE s.client_id=? AND s.scope_type='asset' AND s.scope_id=CAST(? AS CHAR))",
                    Boolean.class, sourceId, clientId, record.assetId());
            if (!Boolean.TRUE.equals(allowed)) throw ApiRequestException.notFound();
            assetIds.add(record.assetId());
        }
        return Set.copyOf(assetIds);
    }

    private ExistingBatch findByIdempotency(long sourceId, String idempotencyKey) {
        return jdbc.query("SELECT id,batch_key,data_source_id,status,total_count,accepted_count,rejected_count,request_sha256 "
                        + "FROM ingest_batch WHERE data_source_id=? AND idempotency_key=?",
                rs -> rs.next() ? new ExistingBatch(rs.getLong("id"), rs.getString("batch_key"),
                        rs.getLong("data_source_id"), rs.getString("status"), rs.getLong("total_count"),
                        rs.getLong("accepted_count"), rs.getLong("rejected_count"), rs.getString("request_sha256")) : null,
                sourceId, idempotencyKey);
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
        jdbc.update("INSERT INTO outbox_event (event_key,aggregate_type,aggregate_id,topic,payload_json,status) "
                        + "VALUES (?,?,?,?,?,'pending')", "ingest.batch:" + batchId, "ingest_batch",
                Long.toString(batchId), "ingest.batch.received",
                "{\"batchId\":" + batchId + ",\"dataSourceId\":" + sourceId + ",\"recordCount\":" + count + "}");
    }

    private void insertAudit(long batchId, long sourceId, Set<Long> assetIds, String clientKey, String requestId) {
        GeneratedKeyHolder auditKey = new GeneratedKeyHolder();
        jdbc.update(connection -> {
            PreparedStatement statement = connection.prepareStatement("INSERT INTO audit_log "
                    + "(occurred_at,actor_type,actor_id,action,resource_type,resource_id,request_id,outcome,reason) "
                    + "VALUES (?, 'machine', ?, 'ingest.batch.received', 'ingest_batch', ?, ?, 'success', 'scoped normalized batch accepted')",
                    Statement.RETURN_GENERATED_KEYS);
            statement.setTimestamp(1, Timestamp.from(Instant.now()));
            statement.setString(2, clientKey);
            statement.setString(3, Long.toString(batchId));
            statement.setString(4, requestId);
            return statement;
        }, auditKey);
        long auditId = auditKey.getKey().longValue();
        jdbc.update("INSERT INTO audit_resource_scope (audit_id,scope_type,scope_id) VALUES (?, 'data_source', ?)",
                auditId, Long.toString(sourceId));
        for (long assetId : assetIds) {
            jdbc.update("INSERT INTO audit_resource_scope (audit_id,scope_type,scope_id) VALUES (?, 'asset', ?)",
                    auditId, Long.toString(assetId));
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
