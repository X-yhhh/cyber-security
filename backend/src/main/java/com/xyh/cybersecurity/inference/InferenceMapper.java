package com.xyh.cybersecurity.inference;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.time.Instant;
import java.util.Collection;
import java.util.List;

/** M3 推理台账的持久化边界；业务代码不直接拼接 SQL。 */
@Mapper
public interface InferenceMapper {

    /**
     * 读取批次的契约上下文：批次声明的契约版本，以及同一传感器、同一配置版本的配置契约绑定。
     * 配置不存在时配置相关列为 {@code null}；connector 批次没有传感器，配置列同样为 {@code null}。
     */
    BatchContext findBatchContext(@Param("batchId") long batchId);

    /** 返回已存在的推理请求键，用于重复投递时跳过已推理记录。 */
    List<String> findExistingRequestKeys(@Param("keys") Collection<String> keys);

    int insertRequest(RequestInsert input);

    long countVisible(@Param("userId") long userId, @Param("filter") ListFilter filter);

    List<RequestRow> listVisible(@Param("userId") long userId, @Param("filter") ListFilter filter,
                                 @Param("offset") int offset, @Param("limit") int limit);

    /** 批次所属数据源及其类型；批次不存在时为 {@code null}。 */
    BatchSource findBatchSource(@Param("batchId") long batchId);

    /** 用户是否在该数据源范围内持有指定权限（数据源范围或平台管理员全局范围）。 */
    boolean hasSourcePermission(@Param("userId") long userId, @Param("sourceId") long sourceId,
                                @Param("permission") String permission);

    /**
     * @param recordContractVersion 批次声明的契约版本；connector 批次为 {@code null}
     * @param sensorId              批次来源传感器；connector 批次为 {@code null}
     * @param configContractVersion 同一配置版本绑定的契约；配置不存在时为 {@code null}
     * @param configContractSha256  配置批准时登记的契约文件哈希（V11）
     * @param configStatus          配置状态；推理要求 {@code active}
     */
    record BatchContext(long batchId, long dataSourceId, String recordContractVersion, Long sensorId,
                        String configVersion, String configContractVersion, String configContractSha256,
                        String configStatus) { }

    record BatchSource(long batchId, long dataSourceId, String sourceType, String sourceStatus) { }

    record RequestInsert(String requestKey, long ingestRecordId, Long modelVersionId, String contractVersion,
                         String contractSha256, String deploymentMode, String status, Double attackProbability,
                         String binaryLabel, Double decisionThreshold, String thresholdPolicyVersion,
                         Long latencyMs, String errorCode, String rejectReason, Instant requestedAt,
                         Instant completedAt) { }

    /** 列表过滤条件；除时间范围外均可为空。 */
    record ListFilter(Long dataSourceId, Long assetId, String status, Long modelVersionId, Instant from, Instant to) { }

    record RequestRow(long id, String requestKey, long ingestRecordId, String recordKey, long batchId,
                      long dataSourceId, Long assetId, Long modelVersionId, String modelKey, String modelVersion,
                      String contractVersion, String contractSha256, String deploymentMode, String status,
                      Double attackProbability, String binaryLabel, Double decisionThreshold,
                      String thresholdPolicyVersion, Long latencyMs, String errorCode, String rejectReason,
                      Instant requestedAt, Instant completedAt) { }
}
