package com.xyh.cybersecurity.detection;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import java.time.Instant;
import java.util.List;

/** 检测策略不可变内容及审批状态持久化；同类型版本修改前必须持有类型锁。 */
@Mapper
public interface DetectionPolicyMapper {
    List<Row> list();
    Row find(@Param("id") long id);
    String lockType(@Param("type") String type);
    List<Row> versions(@Param("type") String type);
    int insert(@Param("type") String type, @Param("version") String version, @Param("config") String config,
               @Param("actor") long actor, @Param("base") Long base, @Param("reason") String reason, @Param("hash") String hash);
    Long findId(@Param("type") String type, @Param("version") String version);
    int submit(@Param("id") long id);
    int decide(@Param("id") long id, @Param("status") String status, @Param("actor") long actor, @Param("reason") String reason);
    int retire(@Param("id") long id, @Param("actor") long actor);
    int audit(@Param("actor") long actor, @Param("action") String action, @Param("id") long id,
              @Param("requestId") String requestId, @Param("reason") String reason, @Param("hash") String hash);

    record Row(long id, String policyType, String version, String configJson, String status, Long createdBy,
               Long basedOnPolicyId, String changeReason, String contentSha256, Instant submittedAt,
               Long reviewedBy, Instant reviewedAt, String decisionReason, Long retiredBy, Instant retiredAt,
               Instant createdAt) { }
}
