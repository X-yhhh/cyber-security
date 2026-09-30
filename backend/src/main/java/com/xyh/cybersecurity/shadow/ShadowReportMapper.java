package com.xyh.cybersecurity.shadow;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;

/**
 * 影子验证汇总的只读查询（路线 B §13.2）。时间口径：批次按 {@code ingest_batch.started_at}（应用以 UTC 写入），
 * 告警按 {@code detected_at}，健康窗口按窗口起止；均为 UTC。只返回计数与聚合值，不返回记录内容或地址。
 */
@Mapper
public interface ShadowReportMapper {

    boolean hasSourcePermission(@Param("userId") long userId, @Param("sourceId") long sourceId,
                                @Param("permission") String permission);

    /** 与该数据源批次关联过的传感器在范围内的健康窗口（按起点排序，已裁剪到范围内）。 */
    List<HealthWindow> listHealthWindows(@Param("sourceId") long sourceId, @Param("from") Instant from,
                                         @Param("to") Instant to);

    /** 按质量状态、推理状态与错误码分组的记录数。未推理的记录 {@code inferenceStatus} 为空。 */
    List<RecordCount> countRecords(@Param("sourceId") long sourceId, @Param("from") Instant from,
                                   @Param("to") Instant to);

    /** 接入拒绝记录的问题码计数（一条记录可有多个问题码）。 */
    List<CodeCount> countIngestIssues(@Param("sourceId") long sourceId, @Param("from") Instant from,
                                      @Param("to") Instant to);

    /** 推理成功记录中带某类别词表外遥测的条数，按字段分组。 */
    List<CodeCount> countOutOfVocabulary(@Param("sourceId") long sourceId, @Param("from") Instant from,
                                         @Param("to") Instant to);

    /** 模型告警按资产与 UTC 小时分组计数。 */
    List<AlertHour> countModelAlertsByHour(@Param("sourceId") long sourceId, @Param("from") Instant from,
                                           @Param("to") Instant to);

    /** 范围内全部模型告警及其有效标注（抽检样本从中确定性选取）。 */
    List<AlertLabel> listModelAlertLabels(@Param("sourceId") long sourceId, @Param("from") Instant from,
                                          @Param("to") Instant to);

    /** 范围内推理成功记录所用的模型版本与制品哈希。 */
    List<ScoredModel> listScoredModels(@Param("sourceId") long sourceId, @Param("from") Instant from,
                                       @Param("to") Instant to);

    /** 与给定制品哈希相同的模型版本（新版本在前）；同一 ONNX 的不同版本只可能在 manifest 附加信息上不同。 */
    List<Long> listModelIdsByArtifact(@Param("artifactSha256") String artifactSha256);

    String findManifest(@Param("modelId") long modelId);

    /** 同一制品哈希的推理成功记录特征，按推理请求 id 递增分页。 */
    List<FeatureRow> listScoredFeatures(@Param("sourceId") long sourceId, @Param("artifactSha256") String artifactSha256,
                                        @Param("from") Instant from, @Param("to") Instant to,
                                        @Param("afterId") long afterId, @Param("limit") int limit);

    /** 含推理成功记录的批次的端到端耗时（毫秒）：批次接收 → 该批最后一条推理完成。 */
    List<Long> listBatchLatencies(@Param("sourceId") long sourceId, @Param("from") Instant from,
                                  @Param("to") Instant to);

    /** 范围内批次对应的消费死信与 outbox 死信数。 */
    long countDeadLetters(@Param("sourceId") long sourceId, @Param("from") Instant from, @Param("to") Instant to);

    /** 当前仍在重试的消费消息与待发布 outbox 行（队列积压快照，不限范围）。 */
    Backlog backlog(@Param("sourceId") long sourceId);

    record HealthWindow(long sensorId, LocalDateTime windowStart, LocalDateTime windowEnd, long flowsSeen,
                        long flowsEmitted, long flowsDropped, long queueDepthMax) { }

    record RecordCount(String qualityStatus, String inferenceStatus, String errorCode, String rejectReason,
                       String binaryLabel, long count) { }

    record CodeCount(String code, long count) { }

    record AlertHour(long assetId, LocalDateTime hour, long count) { }

    record AlertLabel(long alertId, String alertKey, LocalDateTime detectedAt, String severity, Double score,
                      String label, String reviewStatus) { }

    record ScoredModel(long modelVersionId, String version, String artifactSha256, long count) { }

    record FeatureRow(long id, String features) { }

    record Backlog(long consumerRetrying, long outboxPending, Double oldestPendingSeconds) { }
}
