package com.xyh.cybersecurity.ingest;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.time.Instant;
import java.util.List;

/**
 * 传感器生命周期管理（开发路线 §4.1）的持久化边界：详情、资料修改、配置版本起草/审批/启用、机器凭据轮换与吊销、下线。
 *
 * <p>状态迁移全部以条件更新实现（WHERE 当前状态），调用方检查影响行数；范围判定在 SQL 内按
 * “功能权限 + 资产范围”执行。不返回凭据摘要或密钥引用。</p>
 */
@Mapper
public interface SensorAdminMapper {

    /** 锁定传感器行；不存在时为 {@code null}。 */
    SensorRow lockSensor(@Param("sensorId") long sensorId);

    SensorRow findSensor(@Param("sensorId") long sensorId);

    /** 用户对传感器所属资产持有指定权限（资产范围或全局平台管理员）。 */
    boolean hasAssetPermission(@Param("userId") long userId, @Param("assetId") long assetId,
                               @Param("permission") String permission);

    int updatePlatform(@Param("sensorId") long sensorId, @Param("platform") String platform);

    /** {@code pending/active/offline → revoked}（下线）。 */
    int decommission(@Param("sensorId") long sensorId);

    List<ConfigRow> listConfigs(@Param("sensorId") long sensorId);

    ConfigRow lockConfig(@Param("sensorId") long sensorId, @Param("configId") long configId);

    int insertConfig(ConfigInsert input);

    Long findConfigId(@Param("sensorId") long sensorId, @Param("configVersion") String configVersion);

    /** {@code pending → approved}；批准人不能是起草人。 */
    int approveConfig(@Param("configId") long configId, @Param("approvedBy") long approvedBy,
                      @Param("reason") String reason);

    /** {@code pending → rejected}；驳回人不能是起草人。 */
    int rejectConfig(@Param("configId") long configId, @Param("reviewedBy") long reviewedBy,
                     @Param("reason") String reason);

    /** 该传感器除 {@code exceptId} 外的 active 配置转 retired。 */
    int retireActiveConfigs(@Param("sensorId") long sensorId, @Param("exceptId") long exceptId);

    /** {@code approved → active}。 */
    int activateConfig(@Param("configId") long configId, @Param("activatedBy") long activatedBy);

    /** 传感器绑定的机器凭据（不含摘要）；没有时为 {@code null}。 */
    ClientRow lockClient(@Param("sensorId") long sensorId);

    ClientRow findClient(@Param("sensorId") long sensorId);

    /** 只轮换 active 凭据：替换摘要、顺延 30 天有效期；旧凭据随即失效。 */
    int rotateCredential(@Param("clientId") long clientId, @Param("credentialSha256") String credentialSha256);

    /** {@code active/disabled → revoked}。 */
    int revokeClient(@Param("clientId") long clientId, @Param("revokedBy") long revokedBy,
                     @Param("reason") String reason);

    record SensorRow(long id, String agentKey, long assetId, String assetKey, String platform, String agentVersion,
                     String capabilitiesJson, String status, Instant registeredAt, Instant lastHeartbeatAt,
                     Instant createdAt, Instant updatedAt) { }

    /**
     * @param requestedBy 起草人；V17 之前经登记接口写入的首个配置为 {@code null}
     */
    record ConfigRow(long id, long sensorId, String configVersion, String interfaceScopeJson, String filterPolicyJson,
                     int flowWindowSeconds, String featureContractVersion, String featureContractSha256,
                     String samplingPolicyJson, String status, Long requestedBy, String requestedByName,
                     String changeReason, Long approvedBy, String approvedByName, Long reviewedBy, Instant reviewedAt,
                     String decisionReason, Instant activatedAt, Long activatedBy, Instant retiredAt,
                     Instant createdAt) { }

    record ConfigInsert(long sensorId, String configVersion, String interfaceScope, String filterPolicy,
                        int flowWindowSeconds, String contractVersion, String contractSha256, String samplingPolicy,
                        long requestedBy, String changeReason) { }

    record ClientRow(long id, String clientKey, String status, Instant expiresAt, Instant rotatedAt, Instant revokedAt,
                     String revokeReason, Instant createdAt) { }
}
