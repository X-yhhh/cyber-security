package com.xyh.cybersecurity.ingest;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.time.Instant;
import java.util.List;

/** 接入、传感器和 outbox 的持久化边界；业务服务不直接拼接 JDBC SQL。 */
@Mapper
public interface IngestMapper {
    boolean hasConnectorSourceScope(@Param("clientId") long clientId, @Param("sourceId") long sourceId);
    boolean hasApprovedMapping(@Param("sourceId") long sourceId, @Param("mappingVersion") String mappingVersion);
    boolean hasConnectorAssetScope(@Param("clientId") long clientId, @Param("sourceId") long sourceId,
                                   @Param("assetId") long assetId);
    BatchRow findBatchBySourceKey(@Param("sourceId") long sourceId, @Param("key") String key);
    int insertMachineBatch(MachineBatchInsert input);
    Long findBatchIdByKey(@Param("batchKey") String batchKey);
    int insertMachineRecord(@Param("batchId") long batchId, @Param("recordKey") String recordKey,
                            @Param("eventType") String eventType, @Param("eventTime") Instant eventTime,
                            @Param("assetId") long assetId, @Param("payload") String payload,
                            @Param("mappingVersion") String mappingVersion);
    int insertOutbox(@Param("eventKey") String eventKey, @Param("aggregateType") String aggregateType,
                     @Param("aggregateId") String aggregateId, @Param("topic") String topic,
                     @Param("payload") String payload);

    Long previousSequence(@Param("sensorId") long sensorId, @Param("configVersion") String configVersion);
    int insertSensorRecord(@Param("batchId") long batchId, @Param("recordKey") String recordKey,
                           @Param("eventTime") Instant eventTime, @Param("assetId") long assetId,
                           @Param("payload") String payload, @Param("qualityStatus") String qualityStatus,
                           @Param("issues") String issues, @Param("mappingVersion") String mappingVersion);
    int updateHeartbeat(@Param("sensorId") long sensorId, @Param("observedAt") Instant observedAt,
                        @Param("agentVersion") String agentVersion, @Param("capabilities") String capabilities);
    SensorConfigRow findActiveConfig(@Param("sensorId") long sensorId);
    boolean overlapsHealthWindow(@Param("sensorId") long sensorId, @Param("windowStart") Instant windowStart,
                                 @Param("windowEnd") Instant windowEnd);
    int insertHealthWindow(HealthWindowInsert input);
    boolean hasActiveConfig(@Param("sensorId") long sensorId, @Param("configVersion") String configVersion,
                            @Param("contractVersion") String contractVersion);
    boolean hasApprovedSourceMapping(@Param("sourceId") long sourceId, @Param("mappingVersion") String mappingVersion);
    boolean hasSensorSourcePair(@Param("clientId") long clientId, @Param("sourceId") long sourceId,
                                @Param("assetId") long assetId);
    boolean hasAssetAuthorization(@Param("assetId") long assetId);
    SensorIdentityRow findSensor(@Param("sensorId") long sensorId, @Param("clientId") long clientId);
    Long lockActiveSensor(@Param("sensorId") long sensorId);
    boolean isClientBound(@Param("clientId") long clientId, @Param("sensorId") long sensorId);
    boolean hasSensorPermission(@Param("clientId") long clientId, @Param("permission") String permission);
    int insertSensorBatch(SensorBatchInsert input);
    BatchRow findBatchBySequence(@Param("sensorId") long sensorId, @Param("configVersion") String configVersion,
                                 @Param("sequence") long sequence);

    boolean activeSource(@Param("sourceId") long sourceId);
    int insertSensor(SensorInsert input);
    Long findSensorId(@Param("agentKey") String agentKey);
    int insertSensorClient(SensorClientInsert input);
    Long findClientId(@Param("clientKey") String clientKey);
    int updateCredentialRef(@Param("sensorId") long sensorId, @Param("credentialRef") String credentialRef);
    int insertClientAssetScope(@Param("clientId") long clientId, @Param("assetId") long assetId);
    int insertClientSourceScope(@Param("clientId") long clientId, @Param("sourceId") long sourceId);
    int insertClientPair(@Param("clientId") long clientId, @Param("sourceId") long sourceId, @Param("assetId") long assetId);
    int grantSensorPermissions(@Param("clientId") long clientId);
    int insertSensorConfig(SensorConfigInsert input);
    boolean hasSensorManageAsset(@Param("userId") long userId, @Param("assetId") long assetId);
    boolean hasAuthorizedAsset(@Param("assetId") long assetId);
    boolean hasSensorManageSource(@Param("userId") long userId, @Param("sourceId") long sourceId);

    List<OutboxRow> listPendingOutbox(@Param("limit") int limit);
    int markOutboxPublished(@Param("id") long id);
    int markOutboxFailed(@Param("id") long id, @Param("status") String status,
                         @Param("attempts") int attempts, @Param("nextAttemptAt") Instant nextAttemptAt);

    /**
     * 查询某个批次中已通过接入门禁的记录；消费者只把 accepted 记录交给后续推理任务边界。
     */
    List<AcceptedRecord> findAcceptedRecords(@Param("batchId") long batchId);

    ConsumedMessageRow findConsumedMessageForUpdate(@Param("consumer") String consumer,
                                                    @Param("messageKey") String messageKey);

    int insertConsumedMessage(@Param("consumer") String consumer, @Param("messageKey") String messageKey);

    int markConsumedProcessing(@Param("consumer") String consumer, @Param("messageKey") String messageKey);

    int markConsumed(@Param("consumer") String consumer, @Param("messageKey") String messageKey);

    int recordConsumedFailure(@Param("consumer") String consumer, @Param("messageKey") String messageKey,
                              @Param("status") String status, @Param("errorCode") String errorCode,
                              @Param("errorMessage") String errorMessage);

    int insertConsumedFailureRow(@Param("consumer") String consumer, @Param("messageKey") String messageKey,
                                 @Param("status") String status, @Param("errorCode") String errorCode,
                                 @Param("errorMessage") String errorMessage);

    record BatchRow(long id, String batchKey, long sourceId, String status, long totalCount,
                    long acceptedCount, long rejectedCount, String requestSha256, boolean sequenceGap) { }
    record SensorIdentityRow(long id, long assetId, String status) { }
    record SensorConfigRow(String configVersion, String interfaceScopeJson, String filterPolicyJson,
                           int flowWindowSeconds, String featureContractVersion, String samplingPolicyJson,
                           Instant activatedAt) { }
    record OutboxRow(long id, String eventKey, String topic, String payload, int attempts) { }
    record AcceptedRecord(long id, long batchId, long dataSourceId, String recordKey, Instant eventTime,
                          long assetId, String normalizedPayload) { }
    record ConsumedMessageRow(long id, String consumer, String messageKey, String status, int attempts,
                              String errorCode, String errorMessage, Instant consumedAt) { }
    record MachineBatchInsert(String batchKey, long dataSourceId, String idempotencyKey, String requestSha256,
                              int totalCount, Instant startedAt) { }
    record SensorBatchInsert(String batchKey, long dataSourceId, long sensorId, String configVersion, long sequence,
                             boolean sequenceGap, String contractVersion, String idempotencyKey, String requestSha256,
                             String status, int totalCount, int acceptedCount, int rejectedCount, Instant startedAt) { }
    record HealthWindowInsert(long sensorId, Instant windowStart, Instant windowEnd, long flowsSeen, long flowsEmitted,
                              long flowsDropped, long queueDepthMax, Double cpuPercent, Long memoryBytes, String errors) { }
    record SensorInsert(String agentKey, long assetId, String platform, String agentVersion,
                        String capabilities, Instant registeredAt) { }
    record SensorClientInsert(String clientKey, long sensorId, String credentialSha256, String scopeJson) { }
    record SensorConfigInsert(long sensorId, String configVersion, String interfaceScope, String filterPolicy,
                              int flowWindowSeconds, String contractVersion, String samplingPolicy, long approvedBy) { }
}
