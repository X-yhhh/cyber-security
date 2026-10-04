package com.xyh.cybersecurity.identity;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

/** 读取身份、内置角色和角色权限模板，不提供模板写入方法。 */
@Mapper
public interface IdentityMapper {
    /** 串行化管理员角色变更和冻结，保护最后一名有效管理员，统一加锁顺序。 */
    Long lockPlatformAdminRole();

    PrincipalRow findPrincipalByUsername(@Param("username") String username);

    List<String> listUserRoles(@Param("userId") long userId);

    List<String> listUserPermissions(@Param("userId") long userId);

    AdminRow findAdmin();

    int insertAdmin(@Param("userKey") String userKey, @Param("displayName") String displayName,
                    @Param("passwordHash") String passwordHash);

    Long findUserIdByUsername(@Param("username") String username);

    Long findPlatformAdminRoleId();

    int ensureGlobalPlatformAdminBinding(@Param("userId") long userId, @Param("roleId") long roleId);

    int updateLastLogin(@Param("userId") long userId, @Param("loggedAt") java.time.Instant loggedAt);

    int deleteSession(@Param("username") String username);

    int countBlockedThrottle(@Param("keyHash") String keyHash, @Param("now") java.time.Instant now);

    int upsertThrottleFailure(@Param("keyHash") String keyHash, @Param("now") java.time.Instant now);

    int clearThrottle(@Param("keyHash") String keyHash);

    int insertUser(@Param("userKey") String userKey, @Param("username") String username,
                   @Param("displayName") String displayName, @Param("passwordHash") String passwordHash);

    Long findUserIdByKey(@Param("userKey") String userKey);

    int deleteUserRoles(@Param("userId") long userId);

    int insertUserRole(@Param("userId") long userId, @Param("roleId") long roleId,
                       @Param("scopeType") String scopeType, @Param("scopeId") String scopeId);

    boolean hasGlobalConfigAdmin(@Param("userId") long userId);

    int insertMachineClient(@Param("clientKey") String clientKey, @Param("credentialSha256") String credentialSha256,
                            @Param("scopeJson") String scopeJson);

    Long findMachineClientId(@Param("clientKey") String clientKey);

    int insertClientScope(@Param("clientId") long clientId, @Param("scopeType") String scopeType,
                          @Param("scopeId") String scopeId);

    int insertClientBinding(@Param("clientId") long clientId, @Param("dataSourceId") long dataSourceId,
                            @Param("assetId") long assetId);

    int grantMachineIngestPermission(@Param("clientId") long clientId);

    boolean activeSourceAssetPair(@Param("dataSourceId") long dataSourceId, @Param("assetId") long assetId);

    MachineClientRow findActiveMachineClient(@Param("clientId") long clientId);

    List<String> listMachinePermissions(@Param("clientId") long clientId);

    long countUsers();

    List<UserView> listUsers(@Param("offset") int offset, @Param("limit") int limit);

    UserView findUser(@Param("id") long id);

    List<RoleView> listRoles();

    List<String> listRolePermissions(@Param("roleId") long roleId);

    Long findActiveBuiltinRoleId(@Param("roleKey") String roleKey);

    boolean existsScope(@Param("scopeType") String scopeType, @Param("scopeId") String scopeId);

    List<Long> lockActiveGlobalPlatformAdministratorIds();

    List<RoleBinding> listRoleBindings(@Param("userId") long userId);

    // ---- 机器客户端台账（开发路线 §4.1）：列表不返回任何凭据信息 ----

    long countMachineClients();

    List<MachineClientView> listMachineClients(@Param("offset") int offset, @Param("limit") int limit);

    MachineClientView lockMachineClient(@Param("clientId") long clientId);

    /** {@code active/disabled → revoked}，返回影响行数。 */
    int revokeMachineClient(@Param("clientId") long clientId, @Param("revokedBy") long revokedBy,
                            @Param("reason") String reason);

    // ---- 用户生命周期（开发路线 §4.1）：资料、冻结/解冻、改密；状态迁移以条件更新保证 ----

    UserDetail findUserDetail(@Param("id") long id);

    /** 锁定用户行，串行化同一用户的状态与口令变更。 */
    UserView lockUser(@Param("id") long id);

    int updateDisplayName(@Param("id") long id, @Param("displayName") String displayName);

    /** 仅当当前状态在 {@code fromStatuses} 内时迁移，返回影响行数。 */
    int transitionUserStatus(@Param("id") long id, @Param("fromStatuses") List<String> fromStatuses,
                             @Param("toStatus") String toStatus);

    String findPasswordHash(@Param("id") long id);

    int updatePasswordHash(@Param("id") long id, @Param("passwordHash") String passwordHash);

    /** 该用户是否持有 active 的全局平台管理员绑定。 */
    boolean isGlobalPlatformAdmin(@Param("userId") long userId);

    record UserView(long id, String userKey, String username, String displayName, String status) { }

    /** 机器客户端台账行；不含 credential_sha256、secret_ref。 */
    record MachineClientView(long id, String clientKey, String clientType, Long sensorId, String status,
                             java.time.Instant expiresAt, java.time.Instant rotatedAt, java.time.Instant revokedAt,
                             String revokeReason, java.time.Instant createdAt) { }

    record UserDetail(long id, String userKey, String username, String displayName, String status,
                      java.time.Instant lastLoginAt, java.time.Instant passwordChangedAt, java.time.Instant createdAt,
                      java.time.Instant updatedAt) { }

    record RoleView(long id, String roleKey, String name, String description) { }

    record RoleBinding(String roleKey, String scopeType, String scopeId) { }

    record PrincipalRow(long id, String userKey, String username, String displayName,
                        String passwordHash, String status) { }

    record AdminRow(long id, String passwordHash) { }

    record MachineClientRow(String clientKey, String clientType, String credentialSha256) { }
}
