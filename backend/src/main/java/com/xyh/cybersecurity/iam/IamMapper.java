package com.xyh.cybersecurity.iam;

import org.apache.ibatis.annotations.*;
import java.util.List;
import java.util.Map;

/** v2 身份事实访问；口令只由专用更新语句写入，所有对外查询使用明确列集。 */
@Mapper
public interface IamMapper {
    String USER_COLUMNS = "id,username,display_name,status,revision";
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

    @Select("SELECT id,role_key,name,description,status FROM sys_role WHERE role_key=#{key}")
    Map<String,Object> role(String key);

    @Select("""
        SELECT id,role_key,name,description FROM sys_role WHERE status='active'
        AND role_key IN ('platform_admin','security_analyst','security_reviewer','model_operator','evidence_reviewer','auditor')
        ORDER BY id
        """)
    List<Map<String,Object>> directory();

    @Select("""
        SELECT p.permission_key FROM sys_role_permission rp JOIN sys_permission p ON p.id=rp.permission_id
        WHERE rp.role_id=#{id} AND p.status='active' ORDER BY p.permission_key
        """)
    List<String> rolePermissions(long id);

    @Select("""
        <script>SELECT id,username,display_name,status,revision FROM sys_user
        WHERE id &lt;= #{ceiling}
        <if test="before != null">AND id &lt; #{before}</if>
        <if test="status != null">AND status=#{status}</if>
        <if test="prefix != null">AND (username LIKE #{prefix} ESCAPE '!' OR display_name LIKE #{prefix} ESCAPE '!')</if>
        ORDER BY id DESC LIMIT #{limit}</script>
        """)
    List<Map<String,Object>> users(@Param("status") String status, @Param("prefix") String prefix,
                                  @Param("ceiling") long ceiling, @Param("before") Long before, @Param("limit") int limit);

    @Select("SELECT COALESCE(MAX(id),0) FROM sys_user")
    long ceiling();

    @Select("SELECT EXISTS(SELECT 1 FROM asset WHERE CAST(id AS CHAR)=#{id})")
    boolean assetExists(String id);

    @Update("UPDATE sys_user SET display_name=#{name},revision=revision+1 WHERE id=#{id}")
    int rename(@Param("id") long id,@Param("name") String name);

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
