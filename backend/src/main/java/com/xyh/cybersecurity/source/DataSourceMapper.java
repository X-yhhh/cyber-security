package com.xyh.cybersecurity.source;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

/** 在 SQL 中按显式 data_source 授权过滤来源与映射版本。 */
@Mapper
public interface DataSourceMapper {

    int insertSource(SourceInsert input);

    Long findIdByKey(@Param("sourceKey") String sourceKey);

    int insertMapping(MappingInsert input);

    Long findMappingId(@Param("sourceId") long sourceId, @Param("mappingVersion") String mappingVersion);

    boolean hasManageScope(@Param("userId") long userId, @Param("sourceId") long sourceId);

    long countVisible(@Param("userId") long userId);

    List<DataSourceView> listVisible(@Param("userId") long userId,
                                     @Param("offset") int offset,
                                     @Param("limit") int limit);

    DataSourceView findVisible(@Param("userId") long userId, @Param("sourceId") long sourceId);

    boolean canManage(@Param("userId") long userId, @Param("sourceId") long sourceId);

    int updateVisible(@Param("userId") long userId, @Param("sourceId") long sourceId,
                      @Param("environment") String environment, @Param("schemaVersion") String schemaVersion,
                      @Param("status") String status);

    List<MappingView> listMappingsVisible(@Param("userId") long userId, @Param("sourceId") long sourceId);

    Long findActiveGlobalPlatformAdminId(@Param("userId") long userId);

    /** 映射批准范围（V14）：{@code source.mapping.approve} 的全局平台管理员或该数据源范围绑定。 */
    boolean hasMappingApproveScope(@Param("userId") long userId, @Param("sourceId") long sourceId);

    /** 锁定待批准映射行；不属于该数据源时为 {@code null}。 */
    MappingRow findMappingForUpdate(@Param("sourceId") long sourceId, @Param("mappingId") long mappingId);

    int approveMapping(@Param("mappingId") long mappingId, @Param("approvedBy") long approvedBy);

    /** {@code draft/pending → rejected}；驳回人不能是登记人（V17 CHECK 兜底）。 */
    int rejectMapping(@Param("mappingId") long mappingId, @Param("reviewedBy") long reviewedBy,
                      @Param("reason") String reason);

    /** {@code approved → retired}。 */
    int retireMapping(@Param("mappingId") long mappingId, @Param("retiredBy") long retiredBy,
                      @Param("reason") String reason);

    /** 锁定数据源行并返回当前状态；不存在时为 {@code null}。 */
    String lockStatus(@Param("sourceId") long sourceId);

    record DataSourceView(long id, String sourceKey, String sourceType, String environment,
                          String schemaVersion, String status, java.time.LocalDateTime lastSuccessAt) { }

    /**
     * @param featureContractVersion 映射绑定的特征契约（V11）；历史映射为 {@code null}
     * @param requestedBy            登记用户（V14）；V14 之前的映射为 {@code null}
     * @param reviewedBy             驳回用户（V17）；批准人见 {@code approvedBy}
     * @param decisionReason         驳回或退役理由（V17）
     */
    record MappingView(long id, String mappingVersion, String sourceSchemaJson, String mappingJson,
                       String status, Long approvedBy, String featureContractVersion, String featureContractSha256,
                       Long requestedBy, Long reviewedBy, String decisionReason, Long retiredBy,
                       java.time.Instant retiredAt, java.time.Instant createdAt) { }

    record MappingRow(long id, String status, Long requestedBy) { }

    record SourceInsert(String sourceKey, String sourceType, String environment, String schemaVersion) { }

    /** 契约版本与哈希成对出现或同时为空；哈希由服务端按注册表写入。 */
    record MappingInsert(long sourceId, String mappingVersion, String sourceSchemaJson, String mappingJson,
                         String contractVersion, String contractSha256, long requestedBy) { }
}
