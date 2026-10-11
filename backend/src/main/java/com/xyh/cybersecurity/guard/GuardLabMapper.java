package com.xyh.cybersecurity.guard;

import org.apache.ibatis.annotations.*;
import java.util.List;
import java.util.Map;

/** lab 专属 SQL；不扩展共享动态表白名单，全部参数使用绑定变量。 */
@Mapper
public interface GuardLabMapper {
    @Insert("""
        INSERT INTO guard_lab_run(session_id,sensor_id,boot_id,manifest_ref,manifest_sha256,manifest_jcs,scenarios_jcs,mapping_jcs)
        VALUES(#{session},#{sensor},#{boot},#{ref},#{sha},#{manifest},#{scenarios},#{mapping})
        """)
    void insertRun(Map<String,Object> row);

    @Select("SELECT * FROM guard_lab_run WHERE session_id=#{id}")
    Map<String,Object> run(long id);

    /**
     * lab 会话列表：只列出已有 V25 运行投影的 V20 资格，按内部主键倒序游标分页。
     * 资产范围谓词在 LIMIT 之前执行，口径与 GuardMapper 通用 select 的 IAM 判定一致（全局或同资产授权）。
     * before 无游标时传 Long.MAX_VALUE；status 为空串表示不过滤，避免可空绑定参数。
     */
    @Select("""
        SELECT s.* FROM guard_validation_session s JOIN guard_lab_run r ON r.session_id=s.id
        WHERE s.id<#{before} AND (#{status}='' OR r.status=#{status})
          AND EXISTS(SELECT 1 FROM sys_user_role ur JOIN sys_role ro ON ro.id=ur.role_id AND ro.status='active'
            JOIN sys_role_permission rp ON rp.role_id=ro.id JOIN sys_permission p ON p.id=rp.permission_id AND p.status='active'
            JOIN sys_user u ON u.id=ur.user_id AND u.status='active'
            WHERE ur.user_id=#{actor} AND p.permission_key='evaluation.read'
              AND ((ur.scope_type='global' AND ur.scope_id='*') OR (ur.scope_type='asset' AND ur.scope_id=CAST(s.asset_id AS CHAR))))
        ORDER BY s.id DESC LIMIT #{limit}
        """)
    List<Map<String,Object>> visibleSessions(@Param("actor") long actor,@Param("before") long before,
                                             @Param("status") String status,@Param("limit") int limit);

    @Select("SELECT * FROM guard_lab_run WHERE session_id=#{id} FOR UPDATE")
    Map<String,Object> lock(long id);

    @Select("SELECT session_id FROM guard_lab_run WHERE sensor_id=#{sensor} AND boot_id=#{boot}")
    Long owner(@Param("sensor") long sensor,@Param("boot") String boot);

    @Select("SELECT COUNT(*) FROM guard_lab_run WHERE sensor_id=#{sensor}")
    int managedSensor(long sensor);

    @Update("""
        UPDATE guard_lab_run SET status=#{status},started_at=#{started},ended_at=#{ended},
        last_activity_at=#{activity},stop_requested_at=#{stop} WHERE session_id=#{session}
        """)
    void updateRun(Map<String,Object> row);

    @Select("SELECT * FROM guard_lab_event WHERE public_id=#{id}")
    Map<String,Object> event(String id);

    @Select("SELECT * FROM guard_lab_event WHERE session_id=#{session} AND fact_key=#{key}")
    Map<String,Object> fact(@Param("session") long session,@Param("key") String key);

    @Insert("""
        INSERT INTO guard_lab_event(public_id,session_id,fact_key,scenario_id,kind,occurred_at,payload_jcs,content_sha256,request_sha256)
        VALUES(#{public_id},#{session},#{fact},#{scenario},#{kind},#{occurred},#{payload},#{sha},#{request})
        """)
    @Options(useGeneratedKeys=true,keyProperty="id")
    void insertEvent(Map<String,Object> row);

    @Select("SELECT * FROM guard_lab_event WHERE session_id=#{session} AND id>#{after} ORDER BY id LIMIT #{limit}")
    List<Map<String,Object>> events(@Param("session") long session,@Param("after") long after,@Param("limit") int limit);

    /** 汇总只读取会话固定的 sensor/boot/peer/时间窗，保留未知 quality，不能用缺省零值判健康。 */
    @Select("""
        SELECT payload_json,created_at FROM guard_observation
        WHERE asset_id=#{asset} AND sensor_id=#{sensor} AND boot_id=#{boot} AND environment='lab'
          AND peer_key=#{peer} AND key_epoch=#{epoch} AND as_of>=#{start} AND as_of<=#{end}
        ORDER BY id LIMIT 100001
        """)
    List<Map<String,Object>> observations(Map<String,Object> binding);

    @Select("""
        SELECT c.public_id FROM guard_command c JOIN guard_action a ON a.id=c.action_id
        JOIN guard_decision d ON d.id=a.decision_id JOIN guard_episode e ON e.id=d.episode_id
        WHERE e.sensor_id=#{sensor} AND e.boot_id=#{boot} ORDER BY c.id LIMIT 20001
        """)
    List<String> commands(@Param("sensor") long sensor,@Param("boot") String boot);

    @Select("""
        SELECT d.public_id,o.as_of,o.peer_key,o.key_epoch FROM guard_decision d JOIN guard_episode e ON e.id=d.episode_id
        LEFT JOIN guard_observation o ON o.public_id=JSON_UNQUOTE(JSON_EXTRACT(d.evidence_json,'$.triggerObservationId'))
        WHERE e.sensor_id=#{sensor} AND e.boot_id=#{boot} ORDER BY d.id LIMIT 20001
        """)
    List<Map<String,Object>> decisions(@Param("sensor") long sensor,@Param("boot") String boot);
}
