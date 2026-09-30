package com.xyh.cybersecurity.drift;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;

/**
 * M8 漂移窗口读写。窗口以 {@code inference_request.completed_at} 所在的 UTC 整点小时划分；
 * 只读已完成的推理结论与接入记录中的特征，写入追加式窗口行（唯一键防重复）。
 */
@Mapper
public interface DriftMapper {

    /** 已结束、尚未计算的 (数据源, 模型版本, 小时) 组合；{@code before} 之后开始的窗口不返回。 */
    List<DueWindow> findDueWindows(@Param("since") Instant since, @Param("before") Instant before,
                                   @Param("limit") int limit);

    /** 窗口内全部推理请求按状态计数（含拒绝与范围外）。 */
    List<StatusCount> countStatuses(@Param("sourceId") long sourceId, @Param("modelId") long modelId,
                                    @Param("from") LocalDateTime from, @Param("to") LocalDateTime to);

    /** 窗口内推理成功的记录：特征 JSON 与分数，按 id 递增分页。 */
    List<ScoredSample> listScored(@Param("sourceId") long sourceId, @Param("modelId") long modelId,
                                  @Param("from") LocalDateTime from, @Param("to") LocalDateTime to,
                                  @Param("afterId") long afterId, @Param("limit") int limit);

    /** 窗口内该模型产生的告警与其有效人工标注计数。 */
    FeedbackCount countFeedback(@Param("sourceId") long sourceId, @Param("modelId") long modelId,
                                @Param("from") LocalDateTime from, @Param("to") LocalDateTime to);

    String findManifest(@Param("modelId") long modelId);

    int insertWindow(WindowInsert window);

    record DueWindow(long dataSourceId, long modelVersionId, LocalDateTime windowStart) { }

    record StatusCount(String status, long count) { }

    record ScoredSample(long id, String features, double attackProbability, String binaryLabel) { }

    record FeedbackCount(long alerts, long labeled, long falsePositive, long truePositive) { }

    record WindowInsert(long dataSourceId, long modelVersionId, LocalDateTime windowStart, LocalDateTime windowEnd,
                        long sampleCount, long requestCount, String baselineRef, String featureStatsJson,
                        String scoreStatsJson, String labelFeedbackStatsJson, java.math.BigDecimal qualityRejectRate,
                        String driftStatus, String computedBy) { }
}
