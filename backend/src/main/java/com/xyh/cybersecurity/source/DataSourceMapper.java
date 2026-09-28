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

    record DataSourceView(long id, String sourceKey, String sourceType, String environment,
                          String schemaVersion, String status, java.time.LocalDateTime lastSuccessAt) { }

    record MappingView(long id, String mappingVersion, String sourceSchemaJson, String mappingJson,
                       String status, Long approvedBy) { }

    record SourceInsert(String sourceKey, String sourceType, String environment, String schemaVersion) { }

    record MappingInsert(long sourceId, String mappingVersion, String sourceSchemaJson, String mappingJson) { }
}
