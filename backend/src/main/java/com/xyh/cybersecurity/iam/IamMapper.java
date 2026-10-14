package com.xyh.cybersecurity.iam;

import org.apache.ibatis.annotations.*;
import java.util.List;
import java.util.Map;

/** v2 身份事实访问；口令只由专用更新语句写入，所有对外查询使用明确列集。 */
@Mapper
public interface IamMapper {
    String USER_COLUMNS = "id,username,display_name,status,revision,created_at,updated_at";
    String ROLE_COLUMNS = "id,role_key,name,description,status,builtin,revision,created_at,updated_at";
    String EFFECTIVE = """
        FROM sys_user u JOIN sys_user_role ur ON ur.user_id=u.id
        JOIN sys_role r ON r.id=ur.role_id AND r.status='active'
        JOIN sys_role_permission rp ON rp.role_id=r.id
        JOIN sys_permission p ON p.id=rp.permission_id AND p.status='active'
        WHERE u.id=#{user} AND u.status='active'
        AND ((ur.scope_type='global' AND ur.scope_id='*') OR
             (ur.scope_type='asset' AND EXISTS(SELECT 1 FROM asset a WHERE CAST(a.id AS CHAR)=ur.scope_id)))
        """;

    @Select("SELECT " + USER_COLUMNS + " FROM sys_user WHERE id=#{id}")
    Map<String,Object> user(long id);

    @Select("SELECT " + USER_COLUMNS + " FROM sys_user WHERE id=#{id} FOR UPDATE")
    Map<String,Object> lockUser(long id);

    /** 功能权限检测不扩大资源范围；对象级授权仍使用 GuardMapper.permitted。 */
    @Select("SELECT DISTINCT p.permission_key " + EFFECTIVE + " ORDER BY p.permission_key")
    List<String> permissions(long user);

    @Select("""
        SELECT DISTINCT r.role_key FROM sys_user u JOIN sys_user_role ur ON ur.user_id=u.id
        JOIN sys_role r ON r.id=ur.role_id AND r.status='active'
        WHERE u.id=#{user} AND u.status='active'
        AND ((ur.scope_type='global' AND ur.scope_id='*') OR
             (ur.scope_type='asset' AND EXISTS(SELECT 1 FROM asset a WHERE CAST(a.id AS CHAR)=ur.scope_id)))
        ORDER BY r.role_key
        """)
    List<String> roles(long user);

    @Select("""
        SELECT ur.id,r.role_key,ur.scope_type,ur.scope_id,r.status role_status
        FROM sys_user_role ur JOIN sys_role r ON r.id=ur.role_id WHERE ur.user_id=#{user} ORDER BY ur.id
        """)
    List<Map<String,Object>> bindings(long user);

    @Select("""
        SELECT ur.id,ur.user_id,ur.role_id,r.role_key,ur.scope_type,ur.scope_id
        FROM sys_user_role ur JOIN sys_role r ON r.id=ur.role_id WHERE ur.id=#{id}
        """)
    Map<String,Object> binding(long id);

    @Select("SELECT " + ROLE_COLUMNS + " FROM sys_role WHERE role_key=#{key}")
    Map<String,Object> role(String key);

    @Select("SELECT " + ROLE_COLUMNS + " FROM sys_role WHERE role_key=#{key} FOR UPDATE")
    Map<String,Object> lockRole(String key);

    @Select("""
        <script>SELECT id,role_key,name,description,status,builtin,revision,created_at,updated_at FROM sys_role
        WHERE (role_key IN ('platform_admin','security_analyst','security_reviewer','model_operator','evidence_reviewer','auditor') OR builtin=FALSE)
        <if test="status != null">AND status=#{status}</if>
        <if test="filter.prefix != null">AND (name LIKE #{filter.prefix} ESCAPE '!' OR role_key LIKE #{filter.prefix} ESCAPE '!')</if>
        <if test="filter.from != null">AND created_at &gt;= #{filter.from}</if>
        <if test="filter.until != null">AND created_at &lt; #{filter.until}</if>
        <choose><when test="filter.sort == 'updatedAt'">ORDER BY updated_at DESC,id DESC</when>
        <otherwise>ORDER BY created_at DESC,id DESC</otherwise></choose></script>
        """)
    List<Map<String,Object>> directory(@Param("status") String status,@Param("filter") Map<String,Object> filter);

    @Select("""
        SELECT p.permission_key FROM sys_role_permission rp JOIN sys_permission p ON p.id=rp.permission_id
        WHERE rp.role_id=#{id} AND p.status='active' ORDER BY p.permission_key
        """)
    List<String> rolePermissions(long id);

    @Select("""
        <script>SELECT id,username,display_name,status,revision,created_at,updated_at,
        <choose><when test="filter.sort == 'updatedAt'">updated_at</when><otherwise>created_at</otherwise></choose> sort_time
        FROM sys_user WHERE id &lt;= #{ceiling} AND created_at &lt;= #{asOf}
        <if test="status != null">AND status=#{status}</if>
        <if test="filter.prefix != null">AND (username LIKE #{filter.prefix} ESCAPE '!' OR display_name LIKE #{filter.prefix} ESCAPE '!')</if>
        <if test="filter.from != null">AND created_at &gt;= #{filter.from}</if>
        <if test="filter.until != null">AND created_at &lt; #{filter.until}</if>
        <if test="beforeId != null">AND (
          <choose><when test="filter.sort == 'updatedAt'">updated_at</when><otherwise>created_at</otherwise></choose>
          &lt; #{beforeTime} OR (
          <choose><when test="filter.sort == 'updatedAt'">updated_at</when><otherwise>created_at</otherwise></choose>
          = #{beforeTime} AND id &lt; #{beforeId}))</if>
        <choose><when test="filter.sort == 'updatedAt'">ORDER BY updated_at DESC,id DESC</when>
        <otherwise>ORDER BY created_at DESC,id DESC</otherwise></choose> LIMIT #{limit}</script>
        """)
    List<Map<String,Object>> users(@Param("status") String status,@Param("filter") Map<String,Object> filter,
            @Param("ceiling") long ceiling,@Param("beforeId") Long beforeId,
            @Param("beforeTime") java.time.LocalDateTime beforeTime,@Param("asOf") java.time.LocalDateTime asOf,@Param("limit") int limit);

    @Select("SELECT COALESCE(MAX(id),0) FROM sys_user")
    long ceiling();

    @Select("SELECT EXISTS(SELECT 1 FROM asset WHERE CAST(id AS CHAR)=#{id})")
    boolean assetExists(String id);

    @Update("UPDATE sys_user SET username=COALESCE(#{username},username),display_name=COALESCE(#{name},display_name),revision=revision+1 WHERE id=#{id}")
    int rename(@Param("id") long id,@Param("username") String username,@Param("name") String name);

    /** 审计引用含主体与用户对象；其余业务外键由 RESTRICT 拒绝，不能级联删除历史事实。 */
    @Select("""
        SELECT EXISTS(SELECT 1 FROM sys_user_role WHERE user_id=#{id}) OR EXISTS(
          SELECT 1 FROM audit_log WHERE (actor_type='human' AND actor_id=CAST(#{id} AS CHAR))
          OR (resource_id=CAST(#{id} AS CHAR) AND (resource_type IN ('user','sys_user') OR action LIKE 'iam.user.%')))
        """)
    boolean userInUse(long id);

    @Delete("DELETE FROM sys_user WHERE id=#{id}")
    int deleteUser(long id);

    @Insert("INSERT INTO sys_role(role_key,name,description,status,builtin) VALUES(#{key},#{name},#{description},'active',FALSE)")
    int createRole(@Param("key") String key,@Param("name") String name,@Param("description") String description);

    @Update("UPDATE sys_role SET name=#{name},description=#{description},revision=revision+1 WHERE id=#{id}")
    int editRole(@Param("id") long id,@Param("name") String name,@Param("description") String description);

    @Update("UPDATE sys_role SET status=#{status},revision=revision+1 WHERE id=#{id}")
    int roleStatus(@Param("id") long id,@Param("status") String status);

    @Select("SELECT COUNT(*) FROM sys_role WHERE status='active' AND (builtin=FALSE OR role_key IN ('platform_admin','security_analyst','security_reviewer','model_operator','evidence_reviewer','auditor'))")
    long activeRoles();

    @Select("SELECT DISTINCT user_id FROM sys_user_role WHERE role_id=#{id} ORDER BY user_id")
    List<Long> roleUsers(long id);

    @Delete("DELETE FROM sys_role_permission WHERE role_id=#{id}")
    int clearRolePermissions(long id);

    @Insert("INSERT INTO sys_role_permission(role_id,permission_id) SELECT #{id},id FROM sys_permission WHERE permission_key=#{permission} AND status='active'")
    int grantRole(@Param("id") long id,@Param("permission") String permission);

    @Delete("DELETE FROM sys_role WHERE id=#{id}")
    int deleteRole(long id);

    @Select("SELECT permission_key,description FROM sys_permission WHERE status='active' ORDER BY permission_key")
    List<Map<String,Object>> permissionDirectory();

    @Select("SELECT COALESCE(MAX(id),0) FROM sys_user_role WHERE role_id=#{role}")
    long memberCeiling(long role);

    @Select("""
        <script>SELECT u.id,u.username,u.display_name,u.status,ur.scope_type,ur.scope_id,ur.id binding_id
        FROM sys_user_role ur JOIN sys_user u ON u.id=ur.user_id
        WHERE ur.role_id=#{role} AND ur.id &lt;= #{ceiling}
        <if test="before != null">AND ur.id &lt; #{before}</if>
        ORDER BY ur.id DESC LIMIT #{limit}</script>
        """)
    List<Map<String,Object>> members(@Param("role") long role,@Param("ceiling") long ceiling,
                                    @Param("before") Long before,@Param("limit") int limit);

    @Update("UPDATE sys_user SET status=#{status},revision=revision+1 WHERE id=#{id}")
    int status(@Param("id") long id,@Param("status") String status);

    @Update("UPDATE sys_user SET password_hash=#{hash},password_changed_at=UTC_TIMESTAMP(3),revision=revision+1 WHERE id=#{id}")
    int password(@Param("id") long id,@Param("hash") String hash);

    @Update("UPDATE sys_user SET revision=revision+1 WHERE id=#{id}")
    int touch(long id);

    @Insert("INSERT INTO sys_user_role(user_id,role_id,scope_type,scope_id) VALUES(#{user_id},#{role_id},#{scope_type},#{scope_id})")
    @Options(useGeneratedKeys=true,keyProperty="id")
    int bind(Map<String,Object> row);

    /** 撤销当前授权关联；删除前将完整绑定快照写入追加审计，用户和角色原行不删除。 */
    @Delete("DELETE FROM sys_user_role WHERE id=#{id}")
    int revoke(long id);

    /** 为复用组件产生的 auth 审计补齐全局范围，不改写审计原行。 */
    @Insert("""
        INSERT IGNORE INTO audit_resource_scope(audit_id,scope_type,scope_id)
        SELECT a.id,'global','*' FROM audit_log a WHERE a.request_id=#{requestId} AND a.action LIKE 'auth.%'
        AND NOT EXISTS(SELECT 1 FROM audit_resource_scope s WHERE s.audit_id=a.id)
        """)
    int scopeAuth(String requestId);
}
