package com.xyh.cybersecurity.audit;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.time.LocalDateTime;
import java.util.List;

/** 只读审计查询会隐藏无范围记录并要求所有关联范围均可见。 */
@Mapper
public interface AuditMapper {

    long countVisible(@Param("userId") long userId);

    List<AuditView> listVisible(@Param("userId") long userId,
                                @Param("offset") int offset,
                                @Param("limit") int limit);

    record AuditView(long id, LocalDateTime occurredAt, String actorType, String action,
                     String resourceType, String resourceId, String requestId, String outcome) { }
}
