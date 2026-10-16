package com.xyh.cybersecurity.guard;

import org.apache.ibatis.annotations.*;
import java.util.*;

/** 所有 SQL 标识符来自内部白名单；请求值只以 MyBatis 绑定参数进入 SQL。 */
@Mapper
public interface GuardMapper {
    @SelectProvider(type=Sql.class,method="select")
    List<Map<String,Object>> select(@Param("table") String table,@Param("where") Map<String,Object> where,
            @Param("lock") boolean lock,@Param("limit") int limit,@Param("actor") Long actor,
            @Param("permission") String permission,@Param("before") Long before);
    /** 控制台筛选与资源范围在 LIMIT 前执行；分页按排序时间和主键共同推进。 */
    @SelectProvider(type=Sql.class,method="consoleList")
    List<Map<String,Object>> consoleList(@Param("table") String table,@Param("where") Map<String,Object> where,
            @Param("actor") long actor,@Param("permission") String permission,@Param("filter") Map<String,Object> filter,
            @Param("ceiling") long ceiling,@Param("asOf") java.time.LocalDateTime asOf,
            @Param("beforeTime") java.time.LocalDateTime beforeTime,@Param("beforeId") Long beforeId,
            @Param("active") boolean active,@Param("limit") int limit);
    @SelectProvider(type=Sql.class,method="ceiling")
    long consoleCeiling(@Param("table") String table);
    @InsertProvider(type=Sql.class,method="insert")
    @Options(useGeneratedKeys=true,keyProperty="values.id")
    int insert(@Param("table") String table,@Param("values") Map<String,Object> values);
    /** 同表多行追加；计划已完成标识符白名单校验，业务值由静态参数映射绑定。 */
    @Lang(GuardFlatPlanLanguageDriver.class)
    @Insert(GuardFlatPlanLanguageDriver.MARKER)
    int insertAll(@Param("plan") FlatPlan plan);
    /** 严格批量新增并回填各行主键；不使用 IGNORE/UPSERT，唯一键冲突由事务回滚处理。 */
    @Lang(GuardFlatPlanLanguageDriver.class)
    @Insert(GuardFlatPlanLanguageDriver.MARKER)
    @Options(useGeneratedKeys=true,keyProperty="rows.id")
    int insertAllReturning(@Param("plan") FlatPlan plan,@Param("rows") List<Map<String,Object>> rows);
    /** 仅按内部白名单组合键读取有限集合；用于持有资产锁后的 episode 批量投影，不作无界扫描。 */
    @SelectProvider(type=Sql.class,method="selectKeys")
    List<Map<String,Object>> selectKeys(@Param("table") String table,@Param("keys") List<Map<String,Object>> keys,@Param("lock") boolean lock);
    /** 同批 parent 投影一次回读；观察 UUID 只用于替换审计，事实仍由外键绑定。 */
    @SelectProvider(type=Sql.class,method="evidenceKeys")
    List<Map<String,Object>> evidenceKeys(@Param("keys") List<Map<String,Object>> keys);
    /** 只接收内部白名单生成的精确索引计划；查询和锁与其他 mapper 共用事务与一级缓存。 */
    @Lang(GuardFlatPlanLanguageDriver.class)
    @Select(GuardFlatPlanLanguageDriver.MARKER)
    List<Map<String,Object>> indexedKeys(@Param("plan") FlatPlan plan);
    @UpdateProvider(type=Sql.class,method="update")
    int update(@Param("table") String table,@Param("id") long id,@Param("values") Map<String,Object> values);
    /** 已持有资产锁时批量更新投影，各行列集一致且 id 唯一；不改变事实表只追加的边界。 */
    @Lang(GuardFlatPlanLanguageDriver.class)
    @Update(GuardFlatPlanLanguageDriver.MARKER)
    int updateAll(@Param("plan") FlatPlan plan);
    /** 数据库时钟不能复用事务内的旧结果，否则批量推理完成时刻会早于真实完成。 */
    @Select("SELECT UTC_TIMESTAMP(6)")
    @Options(useCache=false,flushCache=Options.FlushCachePolicy.TRUE)
    java.time.LocalDateTime now();
    @Select("""
        SELECT EXISTS(SELECT 1 FROM sys_user_role ur JOIN sys_role r ON r.id=ur.role_id AND r.status='active'
        JOIN sys_role_permission rp ON rp.role_id=r.id JOIN sys_permission p ON p.id=rp.permission_id AND p.status='active'
        JOIN sys_user u ON u.id=ur.user_id AND u.status='active'
        WHERE ur.user_id=#{actor} AND p.permission_key=#{permission}
        AND ((ur.scope_type='global' AND ur.scope_id='*') OR (ur.scope_type=#{scopeType} AND ur.scope_id=#{scopeId})))
        """)
    boolean permitted(@Param("actor") long actor,@Param("permission") String permission,
                      @Param("scopeType") String scopeType,@Param("scopeId") String scopeId);
    /** 功能校验与范围校验分开；非法遗留范围不产生任何 v2 权限。 */
    @Select("""
        SELECT EXISTS(SELECT 1 FROM sys_user_role ur JOIN sys_role r ON r.id=ur.role_id AND r.status='active'
        JOIN sys_role_permission rp ON rp.role_id=r.id JOIN sys_permission p ON p.id=rp.permission_id AND p.status='active'
        JOIN sys_user u ON u.id=ur.user_id AND u.status='active'
        WHERE ur.user_id=#{actor} AND p.permission_key=#{permission}
        AND ((ur.scope_type='global' AND ur.scope_id='*') OR
             (ur.scope_type='asset' AND EXISTS(SELECT 1 FROM asset a WHERE CAST(a.id AS CHAR)=ur.scope_id))))
        """)
    boolean hasFeature(@Param("actor") long actor,@Param("permission") String permission);

    /** 使用锁定读检查活动组合或资产绑定，与激活持有的模型锁共同阻止退役/激活竞态。 */
    @Select("""
        SELECT b.id FROM guard_release_bundle b LEFT JOIN guard_asset_binding ab ON ab.bundle_id=b.id
        WHERE b.model_id=#{model} AND (b.status='active' OR ab.status='active') ORDER BY b.id LIMIT 1 FOR UPDATE
        """)
    Long activeModelReference(long model);

    @Select("SELECT EXISTS(SELECT 1 FROM guard_capture_scope WHERE config_id=#{id}) OR EXISTS(SELECT 1 FROM guard_observation_batch WHERE config_id=#{id})")
    boolean configInUse(long id);
    @Select("SELECT EXISTS(SELECT 1 FROM guard_release_bundle WHERE policy_id=#{id}) OR EXISTS(SELECT 1 FROM guard_replay_run WHERE policy_id=#{id}) OR EXISTS(SELECT 1 FROM guard_rule_evaluation WHERE policy_id=#{id})")
    boolean policyInUse(long id);
    @Delete("DELETE FROM sensor_config WHERE id=#{id}")
    int deleteConfig(long id);
    @Delete("DELETE FROM guard_decision_policy WHERE id=#{id}")
    int deletePolicy(long id);
    @Insert("INSERT INTO api_client_permission(client_id,permission_id) SELECT #{client},id FROM sys_permission WHERE permission_key=#{permission} AND status='active'")
    int grant(@Param("client") long client,@Param("permission") String permission);
    @Select("""
        SELECT EXISTS(SELECT 1 FROM api_client c JOIN api_client_permission cp ON cp.client_id=c.id
        JOIN sys_permission p ON p.id=cp.permission_id WHERE c.id=#{client} AND c.status='active'
        AND (c.expires_at IS NULL OR c.expires_at>UTC_TIMESTAMP(6)) AND p.status='active' AND p.permission_key=#{permission})
        """) boolean machinePermission(@Param("client") long client,@Param("permission") String permission);
    @Select("SELECT role_id FROM sys_user_role WHERE user_id=#{userId} ORDER BY role_id,scope_type,scope_id FOR SHARE")
    List<Long> lockUserRoles(@Param("userId") long userId);
    @Select("SELECT COUNT(*)<>COALESCE(MAX(sequence_no),0) FROM guard_observation_batch WHERE sensor_id=#{sensor} AND boot_id=#{boot}")
    boolean batchGap(@Param("sensor") long sensor,@Param("boot") String boot);
    /** 研究完成只引用已经落库的事实，不接受客户端自报执行完成作为唯一依据。 */
    @Select("SELECT COUNT(*) batches,COALESCE(MAX(sequence_no),0) last_sequence FROM guard_observation_batch WHERE sensor_id=#{sensor} AND boot_id=#{boot}")
    Map<String,Object> replayBatches(@Param("sensor") long sensor,@Param("boot") String boot);
    @Select("""
        SELECT COUNT(*) observations,COUNT(i.id) inferences
        FROM guard_observation o LEFT JOIN guard_inference i ON i.observation_id=o.id AND i.model_id=#{model}
        WHERE o.sensor_id=#{sensor} AND o.boot_id=#{boot}
        """)
    Map<String,Object> replayObservations(@Param("sensor") long sensor,@Param("boot") String boot,@Param("model") long model);
    /** 跨 episode/时间桶复核同一连接的最新已到达快照，不能使用插入顺序代替因果时间。 */
    @Select("SELECT * FROM guard_observation FORCE INDEX (idx_guard_observation_parent) WHERE asset_id=#{asset} AND sensor_id=#{sensor} AND boot_id=#{boot} AND parent_connection_id=#{parent} ORDER BY as_of DESC,snapshot_index DESC,id DESC LIMIT 1")
    Map<String,Object> latestParent(@Param("asset") long asset,@Param("sensor") long sensor,@Param("boot") String boot,@Param("parent") String parent);
    /** 批量复核最新已到达快照；跨桶排序与 latestParent 相同，不以当前批次内的最大值代替全库事实。 */
    @Select("""
        <script>SELECT o.id FROM guard_observation o WHERE o.id IN
        <foreach collection="ids" item="id" open="(" separator="," close=")">#{id}</foreach>
        AND o.id=(SELECT n.id FROM guard_observation n FORCE INDEX (idx_guard_observation_parent)
          WHERE n.asset_id=o.asset_id AND n.sensor_id=o.sensor_id AND n.boot_id=o.boot_id AND n.parent_connection_id=o.parent_connection_id
          ORDER BY n.as_of DESC,n.snapshot_index DESC,n.id DESC LIMIT 1)</script>
        """)
    Set<Long> latestObservationIds(@Param("ids") List<Long> ids);
    /** 一次读出最新投影、不可变观察和推理状态，保留原有跨桶 latest 及 10000 条上限。 */
    @Select("""
        SELECT e.*,o.payload_json observation_payload_json,o.content_sha256 observation_content_sha256,i.status inference_status
        FROM guard_episode_evidence e JOIN guard_observation o ON o.id=e.observation_id
        JOIN guard_inference i ON i.id=e.inference_id
        WHERE e.episode_id=#{episode} AND o.id=(
          SELECT n.id FROM guard_observation n FORCE INDEX (idx_guard_observation_parent)
          WHERE n.asset_id=o.asset_id AND n.sensor_id=o.sensor_id AND n.boot_id=o.boot_id AND n.parent_connection_id=o.parent_connection_id
          ORDER BY n.as_of DESC,n.snapshot_index DESC,n.id DESC LIMIT 1)
        ORDER BY e.id DESC LIMIT 10000
        """)
    List<Map<String,Object>> episodeEvidence(@Param("episode") long episode);
    /** 批内多条 episode 一次读取，仍逐条保留原有最新性复核和 10000 行上限。 */
    @Select("""
        <script>SELECT e.*,o.content_sha256 observation_content_sha256,i.status inference_status
        FROM (SELECT evidence_id FROM (
          SELECT e.id evidence_id,ROW_NUMBER() OVER(PARTITION BY e.episode_id ORDER BY e.id DESC) evidence_rank
          FROM guard_episode_evidence e FORCE INDEX (uk_guard_episode_parent)
          STRAIGHT_JOIN guard_observation o ON o.id=e.observation_id
          WHERE e.episode_id IN <foreach collection="episodes" item="id" open="(" separator="," close=")">#{id}</foreach>
          AND o.id=(SELECT n.id FROM guard_observation n FORCE INDEX (idx_guard_observation_parent) WHERE n.asset_id=o.asset_id AND n.sensor_id=o.sensor_id
            AND n.boot_id=o.boot_id AND n.parent_connection_id=o.parent_connection_id
            ORDER BY n.as_of DESC,n.snapshot_index DESC,n.id DESC LIMIT 1)
        ) ranked WHERE evidence_rank&lt;=10000) selected
        STRAIGHT_JOIN guard_episode_evidence e ON e.id=selected.evidence_id
        STRAIGHT_JOIN guard_observation o ON o.id=e.observation_id
        STRAIGHT_JOIN guard_inference i ON i.id=e.inference_id</script>
        """)
    List<Map<String,Object>> episodesEvidence(@Param("episodes") List<Long> episodes);
    /**
     * 内部批量语句的不可变扁平计划。构造器仅向包内白名单生成器开放，SQL 只能包含与参数数目相同的
     * 原生问号占位符；执行时由 GuardFlatPlanLanguageDriver 为每个值创建独立参数映射。
     */
    final class FlatPlan {
        private final String sql;
        private final List<Object> arguments;

        private FlatPlan(String sql,List<Object> arguments) {
            if (sql == null || sql.contains("#{") || sql.contains("${")
                    || sql.chars().filter(character -> character == '?').count() != arguments.size()) {
                throw new IllegalArgumentException("Invalid flat SQL plan");
            }
            this.sql=sql;
            this.arguments=Collections.unmodifiableList(new ArrayList<>(arguments));
        }

        public String sql(){return sql;}
        public List<Object> arguments(){return arguments;}
    }
    final class Sql {
        private static final Map<String,Set<String>> COLUMNS=new HashMap<>();
        private static final List<String> EPISODE_KEY_COLUMNS=List.of("asset_id","sensor_id","boot_id","peer_key","key_epoch","direction","transport","service_port_key","family","scope","source","rule_id","bundle_id","bucket_start");
        static {
            COLUMNS.put("security_event",Set.of("id","public_id","guard_asset_id","revision","event_key","title","category","severity","status","risk_score","risk_rule_version","first_seen_at","last_seen_at","assignee_id","created_at","updated_at","closed_at"));
            COLUMNS.put("sys_user",Set.of("id","user_key","username","display_name","status"));
            COLUMNS.put("event_timeline",Set.of("id","event_id","occurred_at","entry_type","actor_type","actor_id","summary","evidence_ref","details_json","created_at"));
            COLUMNS.put("guard_feedback",Set.of("id","public_id","created_at","asset_id","observation_id","label","evidence_ref","created_by","reviewed_by","status","review_reason","revision"));
            COLUMNS.put("guard_validation_session",Set.of("id","public_id","created_at","asset_id","bundle_id","authorization_id","requested_by","approved_by","status","payload_json","content_sha256","valid_until","revision"));

            COLUMNS.put("guard_idempotency",Set.of("id","public_id","created_at","request_scope","idempotency_key","request_sha256","response_json","http_status"));
            COLUMNS.put("guard_contract",Set.of("id","public_id","created_at","contract_version","profile_sha256","schema_set_sha256","extractor_sha256","status"));
            COLUMNS.put("guard_dataset",Set.of("id","public_id","created_at","dataset_key","version","manifest_ref","manifest_sha256","payload_json","display_name","notes","status","revision","updated_at"));
            COLUMNS.put("guard_model",Set.of("id","public_id","created_at","model_key","version","manifest_ref","manifest_sha256","artifact_sha256","contract_id","manifest_json","validation_status","validation_json","created_by","display_name","notes","revision","updated_at"));
            COLUMNS.put("guard_evaluation_plan",Set.of("id","public_id","created_at","plan_key","version","plan_sha256","payload_json","created_by"));
            COLUMNS.put("guard_capability",Set.of("id","public_id","created_at","capability_key","version","platform","level","payload_json","created_by","scope","protection_set_sha256","exemption_evidence_sha256"));
            COLUMNS.put("guard_decision_policy",Set.of("id","public_id","created_at","policy_key","version","model_id","plan_id","decision_contract_version","definition_json","definition_sha256","status","created_by","reviewed_by","revision","display_name","notes","updated_at"));
            COLUMNS.put("guard_release_bundle",Set.of("id","public_id","created_at","bundle_key","version","model_id","policy_id","contract_id","plan_id","environment","subject_sha256","subject_json","sealed_manifest_sha256","sealed_manifest_json","status","requested_by","approved_by","revision","updated_at","display_name","notes"));
            COLUMNS.put("guard_bundle_capability",Set.of("id","public_id","created_at","bundle_id","capability_id"));
            COLUMNS.put("guard_evaluation_run",Set.of("id","public_id","created_at","plan_id","bundle_id","run_kind","runner_identity","status","report_ref","report_sha256","payload_json"));
            COLUMNS.put("guard_replay_run",Set.of("id","public_id","created_at","scenario_id","scenario_sha256","model_id","policy_id","bundle_id","speed","status","requested_by","payload_json","content_sha256"));
            COLUMNS.put("guard_asset_binding",Set.of("id","public_id","created_at","asset_id","bundle_id","authorization_id","authorization_revision","status","activated_by","revision","active_asset"));
            COLUMNS.put("guard_capture_scope",Set.of("id","public_id","created_at","asset_id","sensor_id","scope_key","address_family","config_id","status","active_asset"));
            COLUMNS.put("guard_observation_batch",Set.of("id","public_id","created_at","sensor_id","asset_id","boot_id","sequence_no","config_id","request_sha256","result_json"));
            COLUMNS.put("guard_observation",Set.of("id","public_id","created_at","batch_id","sensor_id","asset_id","boot_id","capture_scope_id","flow_id","parent_connection_id","snapshot_index","profile","as_of","last_packet_at","peer_key","key_epoch","direction","transport","service_port","environment","payload_json","content_sha256"));
            COLUMNS.put("guard_ingest_rejection",Set.of("id","public_id","created_at","batch_id","observation_external_id","reason_code","content_sha256"));
            COLUMNS.put("guard_inference",Set.of("id","public_id","created_at","observation_id","asset_id","model_id","status","score","family","family_scores_json","applicability","manifest_sha256","completed_at","error_code"));
            COLUMNS.put("guard_capture_health_window",Set.of("id","public_id","created_at","sensor_id","asset_id","capture_scope_id","observer_session_id","sequence_no","interval_start","interval_end","previous_sha256","content_sha256","payload_json","verification_status","received_at"));
            COLUMNS.put("guard_executor",Set.of("id","public_id","created_at","asset_id","api_client_id","platform","adapter_version","capability_hash","boot_id","status","last_heartbeat","health_json","revision","display_name","notes","updated_at"));
            COLUMNS.put("guard_budget_target",Set.of("id","public_id","created_at","asset_id","environment","stable_target_token","resolver_executor_id","scope_digest","identity_status"));
            COLUMNS.put("guard_target_binding",Set.of("id","public_id","created_at","target_ref","budget_target_id","executor_id","executor_boot_id","sensor_id","collector_boot_id","capture_scope_id","peer_key","key_epoch","scope_digest","expires_at","payload_json","content_sha256"));
            COLUMNS.put("guard_target_budget",Set.of("id","public_id","created_at","budget_target_id","charged_ms","last_block_end_at","last_evidence_at","health_proof_sha256","cycle_started_at","revision"));
            COLUMNS.put("guard_asset_budget",Set.of("id","public_id","created_at","asset_id","last_monotonic_at","revision"));
            COLUMNS.put("guard_episode",Set.of("id","public_id","created_at","asset_id","sensor_id","boot_id","peer_key","key_epoch","direction","transport","service_port","service_port_key","family","scope","source","rule_id","bundle_id","bucket_start","revision"));
            COLUMNS.put("guard_episode_evidence",Set.of("id","public_id","created_at","episode_id","parent_connection_id","observation_id","inference_id","score","family","source","rule_id","rule_matched","family_scores_json","as_of"));
            COLUMNS.put("guard_rule_evaluation",Set.of("id","public_id","created_at","asset_id","observation_id","policy_id","rule_version","rule_id","family","matched","applicable","payload_json"));
            COLUMNS.put("guard_decision",Set.of("id","public_id","created_at","episode_id","asset_id","bundle_id","decision_revision","decision_contract_version","decision","reason_code","budget_target_id","budget_revision","evidence_sha256","evidence_json","decided_at"));
            COLUMNS.put("guard_event_episode",Set.of("id","public_id","created_at","event_id","episode_id"));
            COLUMNS.put("guard_action",Set.of("id","public_id","created_at","decision_id","asset_id","executor_id","budget_target_id","budget_revision","bundle_id","authorization_id","authorization_revision","mode","desired_state","desired_revision","observed_state","idempotency_key","target_snapshot","block_until","created_by","approved_by","revision"));
            COLUMNS.put("guard_budget_interval",Set.of("id","public_id","created_at","budget_target_id","action_id","reserved_start","reserved_end","verified_end","status","proof_sha256"));
            COLUMNS.put("guard_budget_event",Set.of("id","public_id","created_at","budget_target_id","event_kind","old_revision","new_revision","before_json","after_json","proof_json","proof_sha256"));
            COLUMNS.put("guard_command",Set.of("id","public_id","created_at","action_id","executor_boot_id","payload_json","payload_sha256","key_id","signature","issued_at","apply_by","lease_expires_at"));
            COLUMNS.put("guard_authorization_lease",Set.of("id","public_id","created_at","command_id","authorization_id","revision","expires_at","status"));
            COLUMNS.put("guard_revocation",Set.of("id","public_id","created_at","action_id","command_id","executor_id","desired_revision","payload_json","content_sha256","status"));
            COLUMNS.put("guard_action_receipt",Set.of("id","public_id","created_at","command_id","executor_id","asset_id","revocation_id","status","observed_at","state_digest","content_sha256","payload_json","projected"));
            COLUMNS.put("guard_reconciliation",Set.of("id","public_id","created_at","executor_id","asset_id","boot_id","observed_at","owned_state_sha256","payload_json","error_count"));
            COLUMNS.put("guard_automation_stop",Set.of("id","public_id","created_at","asset_id","bundle_id","reason","requested_by","revoke_existing"));
            COLUMNS.put("asset",Set.of("id","public_id","asset_key","asset_type","environment","criticality","owner","status","labels_json","platform","guard_environment","revision","created_at","updated_at","display_name","notes"));
            COLUMNS.put("asset_authorization",Set.of("id","public_id","asset_id","authorization_ref","scope_json","valid_from","valid_until","status","approved_by","requested_by","revision","created_at","revoked_by","revoked_at","revoke_reason"));
            COLUMNS.put("sensor_agent",Set.of("id","public_id","agent_key","asset_id","platform","agent_version","capabilities_json","credential_ref","status","registered_at","last_heartbeat_at","revision","guard_boot_id","created_at","updated_at","display_name","notes"));
            COLUMNS.put("sensor_config",Set.of("id","public_id","sensor_id","config_version","interface_scope_json","filter_policy_json","flow_window_seconds","feature_contract_version","sampling_policy_json","status","approved_by","activated_at","requested_by","revision","guard_definition_json","content_sha256","created_at"));
            COLUMNS.put("api_client",Set.of("id","public_id","client_key","client_type","sensor_id","secret_ref","credential_sha256","scope_json","status","expires_at","rotated_at","revoked_by","revoked_at","revoke_reason","created_at","updated_at"));
            COLUMNS.put("outbox_event",Set.of("id","event_key","aggregate_type","aggregate_id","topic","payload_json","status","attempts","next_attempt_at","created_at","published_at"));
            COLUMNS.put("consumed_message",Set.of("id","consumer","message_key","status","attempts","last_error_code","last_error_message","consumed_at","updated_at"));
        }
        private static String table(Map<String,Object> p) {
            String t=(String)p.get("table");if(!COLUMNS.containsKey(t))throw new IllegalArgumentException("Unknown table");return t;
        }
        private static String col(String t,String c) {if(!COLUMNS.get(t).contains(c))throw new IllegalArgumentException("Unknown column");return "`"+c+"`";}
        @SuppressWarnings("unchecked")
        private static String keysWhere(String t,String alias,Map<String,Object> p){
            var keys=(List<Map<String,Object>>)p.get("keys");
            if(keys.isEmpty()||keys.size()>800)throw new IllegalArgumentException("Invalid key count");
            var columns=new ArrayList<>(keys.getFirst().keySet());
            if(t.equals("guard_episode")){
                var indexed=List.of("asset_id","sensor_id","boot_id","peer_key","key_epoch","direction","transport","service_port_key","family","scope","source","rule_id","bundle_id","bucket_start");
                if(keys.getFirst().keySet().equals(new HashSet<>(indexed)))columns=new ArrayList<>(indexed);
            }
            if(!columns.isEmpty()&&keys.stream().allMatch(k->k.keySet().equals(keys.getFirst().keySet())&&k.values().stream().noneMatch(Objects::isNull))){
                // 非空复合键用行值 IN，避免 OR 表达式对每个候选行重复解释全部键；含 NULL 保留 IS NULL 语义。
                var names=columns.stream().map(k->alias+"."+col(t,k)).toList();var tuples=new ArrayList<String>();
                for(int i=0;i<keys.size();i++){var values=new ArrayList<String>();for(String k:columns)values.add("#{keys["+i+"]."+k+"}");tuples.add("("+String.join(",",values)+")");}
                return "("+String.join(",",names)+") IN ("+String.join(",",tuples)+")";
            }
            List<String> alternatives=new ArrayList<>();
            for(int i=0;i<keys.size();i++){
                if(keys.get(i).isEmpty())throw new IllegalArgumentException("Empty key");
                List<String> terms=new ArrayList<>();
                for(String k:keys.get(i).keySet())terms.add(alias+"."+col(t,k)+(keys.get(i).get(k)==null?" IS NULL":"=#{keys["+i+"]."+k+"}"));
                alternatives.add("("+String.join(" AND ",terms)+")");
            }
            return "("+String.join(" OR ",alternatives)+")";
        }
        public static String selectKeys(Map<String,Object> p){
            String t=table(p);
            @SuppressWarnings("unchecked") var keys=(List<Map<String,Object>>)p.get("keys");
            if(t.equals("guard_episode")&&!keys.isEmpty()&&keys.size()<=800){
                var indexed=List.of("asset_id","sensor_id","boot_id","peer_key","key_epoch","direction","transport","service_port_key","family","scope","source","rule_id","bundle_id","bucket_start");
                if(keys.stream().allMatch(k->k.keySet().equals(new HashSet<>(indexed))&&k.values().stream().noneMatch(Objects::isNull))){
                    // 常量键表驱动唯一索引点查；避免新 schema 统计尚未收敛时将行值 IN 退化为全表逐项比较。
                    var selects=new ArrayList<String>();
                    for(int i=0;i<keys.size();i++){var values=new ArrayList<String>();for(String k:indexed)values.add("#{keys["+i+"]."+k+"} AS "+col(t,k));selects.add("SELECT "+String.join(",",values));}
                    var joins=indexed.stream().map(k->"t."+col(t,k)+"=k."+col(t,k)).toList();
                    return "SELECT t.* FROM ("+String.join(" UNION ALL ",selects)+") k STRAIGHT_JOIN guard_episode t FORCE INDEX (uk_guard_episode) ON "+String.join(" AND ",joins)
                            +(Boolean.TRUE.equals(p.get("lock"))?" FOR UPDATE":"");
                }
            }
            return "SELECT t.* FROM "+t+" t WHERE "+keysWhere(t,"t",p)+(Boolean.TRUE.equals(p.get("lock"))?" FOR UPDATE":"");
        }
        public static String evidenceKeys(Map<String,Object> p){
            @SuppressWarnings("unchecked") var keys=(List<Map<String,Object>>)p.get("keys");
            var indexed=List.of("episode_id","parent_connection_id","source","rule_id");
            if(!keys.isEmpty()&&keys.size()<=800&&keys.stream().allMatch(k->k.keySet().equals(new HashSet<>(indexed))&&k.values().stream().noneMatch(Objects::isNull))){
                // 由完整唯一键驱动锁定，避免全表锁定其他资产的 evidence 后再等待 episode 形成死锁。
                var selects=new ArrayList<String>();
                for(int i=0;i<keys.size();i++){var values=new ArrayList<String>();for(String k:indexed)values.add("#{keys["+i+"]."+k+"} AS "+col("guard_episode_evidence",k));selects.add("SELECT "+String.join(",",values));}
                var joins=indexed.stream().map(k->"e."+col("guard_episode_evidence",k)+"=k."+col("guard_episode_evidence",k)).toList();
                return "SELECT e.*,o.public_id observation_public_id FROM ("+String.join(" UNION ALL ",selects)+") k "
                        +"STRAIGHT_JOIN guard_episode_evidence e FORCE INDEX (uk_guard_episode_parent) ON "+String.join(" AND ",joins)
                        +" STRAIGHT_JOIN guard_observation o ON o.id=e.observation_id FOR UPDATE";
            }
            return "SELECT e.*,o.public_id observation_public_id FROM guard_episode_evidence e JOIN guard_observation o ON o.id=e.observation_id WHERE "+keysWhere("guard_episode_evidence","e",p)+" FOR UPDATE";
        }
        /** 先压缩同页复合键公共列，再通过 MyBatis 扁平绑定独立参数；查询范围、索引与锁语义不变。 */
        public static FlatPlan indexedKeysPlan(String t,List<Map<String,Object>> keys,boolean lock){
            var indexed=switch(t){
                case "guard_episode"->EPISODE_KEY_COLUMNS;
                case "guard_episode_evidence"->List.of("episode_id","parent_connection_id","source","rule_id");
                default->throw new IllegalArgumentException("Unknown indexed query");
            };
            var expectedColumns=new HashSet<>(indexed);
            if(keys.isEmpty()||keys.size()>500||keys.stream().anyMatch(k->!k.keySet().equals(expectedColumns)||k.values().stream().anyMatch(Objects::isNull)))
                throw new IllegalArgumentException("Invalid indexed keys");
            var columns=indexed.stream().map(column->col(t,column)).toList();
            String rowSql="SELECT "+String.join(",",columns.stream().map(column->"? AS "+column).toList());
            if(t.equals("guard_episode")){
                var compact=compactEpisodeKeys(keys,columns,rowSql,lock);if(compact!=null)return compact;
            }
            var arguments=new ArrayList<Object>(keys.size()*indexed.size());
            for(var key:keys)for(String column:indexed)arguments.add(key.get(column));
            return plan(indexedKeySql(t,columns,String.join(" UNION ALL ",Collections.nCopies(keys.size(),rowSql)),lock),arguments);
        }
        /**
         * 页内仅合并另外十三列完全相同的键，把原有端口逐个保留在派生表中；不扩展端口范围、不省略未命中路径。
         * 每页仍只有一次完整唯一索引点查与原 FOR UPDATE，常量在 SQL 中只绑定一次。
         * 只有参数与 SQL 均变小时启用；高基数组回退原十四列键表，避免增加解析开销。
         */
        private static FlatPlan compactEpisodeKeys(List<Map<String,Object>> keys,List<String> columns,String rowSql,boolean lock){
            var fixed=EPISODE_KEY_COLUMNS.stream().filter(c->!c.equals("service_port_key")).toList();
            var groups=new LinkedHashMap<List<Object>,List<Object>>();
            for(var key:keys){
                var values=new ArrayList<Object>(fixed.size());for(String column:fixed)values.add(key.get(column));
                groups.computeIfAbsent(List.copyOf(values),k->new ArrayList<>()).add(key.get("service_port_key"));
            }
            if(groups.size()==keys.size())return null;
            String constants="SELECT "+String.join(",",fixed.stream().map(c->"? AS "+col("guard_episode",c)).toList());
            String projection=String.join(",",columns.stream().map(c->(c.equals("`service_port_key`")?"p.":"c.")+c).toList());
            String portSql="SELECT ? AS `service_port_key`";
            var branches=new ArrayList<String>(groups.size());
            var arguments=new ArrayList<Object>(keys.size()+fixed.size()*groups.size());
            for(var group:groups.entrySet()){
                branches.add("SELECT "+projection+" FROM ("+constants+") c CROSS JOIN ("
                        +String.join(" UNION ALL ",Collections.nCopies(group.getValue().size(),portSql))+") p");
                arguments.addAll(group.getKey());arguments.addAll(group.getValue());
            }
            String derived=String.join(" UNION ALL ",branches);
            int originalLength=keys.size()*rowSql.length()+(keys.size()-1)*" UNION ALL ".length();
            if(derived.length()>=originalLength)return null;
            return plan(indexedKeySql("guard_episode",columns,derived,lock),arguments);
        }
        private static String indexedKeySql(String t,List<String> columns,String derived,boolean lock){
            String alias=t.equals("guard_episode")?"t":"e";
            String index=t.equals("guard_episode")?"uk_guard_episode":"uk_guard_episode_parent";
            var joins=columns.stream().map(column->alias+"."+column+"=k."+column).toList();
            String selection=t.equals("guard_episode")?"t.*":"e.*,o.public_id observation_public_id";
            String suffix=t.equals("guard_episode")?"":" STRAIGHT_JOIN guard_observation o ON o.id=e.observation_id";
            return "SELECT "+selection+" FROM ("+derived+") k STRAIGHT_JOIN "+t+" "+alias+" FORCE INDEX ("+index+") ON "+String.join(" AND ",joins)+suffix+(lock?" FOR UPDATE":"");
        }
        @SuppressWarnings("unchecked")
        private static StringBuilder selection(Map<String,Object> p,String projection) {
            String t=table(p);Map<String,Object> w=(Map<String,Object>)p.get("where");
            StringBuilder sql=new StringBuilder("SELECT "+projection+" FROM "+t+" t WHERE 1=1");
            for(String k:w.keySet())sql.append(" AND t.").append(col(t,k)).append(w.get(k)==null?" IS NULL":"=#{where."+k+"}");
            if(p.containsKey("before")&&p.get("before")!=null)sql.append(" AND t.id<#{before}");
            if(p.get("actor")!=null) {
                String resource=t.equals("asset")?"t.id":COLUMNS.get(t).contains("asset_id")?"t.asset_id":t.equals("security_event")?"t.guard_asset_id":null;
                sql.append(" AND EXISTS(SELECT 1 FROM sys_user_role ur JOIN sys_role r ON r.id=ur.role_id AND r.status='active' JOIN sys_role_permission rp ON rp.role_id=r.id JOIN sys_permission p ON p.id=rp.permission_id AND p.status='active' JOIN sys_user u ON u.id=ur.user_id AND u.status='active' WHERE ur.user_id=#{actor} AND p.permission_key=#{permission} AND ((ur.scope_type='global' AND ur.scope_id='*')");
                if(resource!=null)sql.append(" OR (ur.scope_type='asset' AND ur.scope_id=CAST(").append(resource).append(" AS CHAR))");
                sql.append("))");
            }
            return sql;
        }
        public static String select(Map<String,Object> p) {
            var sql=selection(p,"t.*");sql.append(" ORDER BY t.id DESC LIMIT #{limit}");
            if(Boolean.TRUE.equals(p.get("lock")))sql.append(" FOR UPDATE");
            return sql.toString();
        }
        private static final Map<String,List<String>> SEARCH=Map.ofEntries(
                Map.entry("asset",List.of("display_name","asset_key")),Map.entry("sensor_agent",List.of("display_name","agent_key")),
                Map.entry("guard_executor",List.of("display_name")),Map.entry("guard_dataset",List.of("display_name","dataset_key")),
                Map.entry("guard_model",List.of("display_name","model_key")),Map.entry("guard_decision_policy",List.of("display_name","policy_key")),
                Map.entry("guard_release_bundle",List.of("display_name","bundle_key")),Map.entry("security_event",List.of("title")),
                Map.entry("guard_evaluation_plan",List.of("plan_key")),Map.entry("guard_capability",List.of("capability_key")));
        public static boolean searchable(String table) { return SEARCH.containsKey(table); }
        public static String ceiling(Map<String,Object> p) { return "SELECT COALESCE(MAX(id),0) FROM "+table(p); }
        @SuppressWarnings("unchecked")
        public static String consoleList(Map<String,Object> p) {
            String t=table(p);var filter=(Map<String,Object>)p.get("filter");
            String sort=Objects.toString(filter.get("sort"));
            if(!Set.of("createdAt","updatedAt").contains(sort)) throw new IllegalArgumentException("Unknown sort");
            String time=sort.equals("updatedAt")&&COLUMNS.get(t).contains("updated_at")
                    ?"COALESCE(t.updated_at,t.created_at)":"t.created_at";
            // 延迟关联：内层只排序主键与时间，避免大 JSON 行进入 filesort 缓冲区；外层按主键回表并保持同一顺序。
            var sql=selection(p,"t.id,"+time+" query_sort_time");
            sql.append(" AND t.id<=#{ceiling} AND t.created_at<=#{asOf}");
            if(filter.get("from")!=null)sql.append(" AND t.created_at>=#{filter.from}");
            if(filter.get("until")!=null)sql.append(" AND t.created_at<#{filter.until}");
            if(filter.get("prefix")!=null){
                var columns=SEARCH.get(t);if(columns==null)throw new IllegalArgumentException("Unsupported search");
                sql.append(" AND (").append(String.join(" OR ",columns.stream()
                        .map(c->"t."+col(t,c)+" LIKE #{filter.prefix} ESCAPE '!'").toList())).append(')');
            }
            if(Boolean.TRUE.equals(p.get("active"))){
                if(!t.equals("guard_action"))throw new IllegalArgumentException("Unsupported active filter");
                sql.append(" AND t.desired_state='active' AND t.block_until>UTC_TIMESTAMP(6)");
            }
            if(p.get("beforeId")!=null)sql.append(" AND (").append(time).append("<#{beforeTime} OR (")
                    .append(time).append("=#{beforeTime} AND t.id<#{beforeId}))");
            sql.append(" ORDER BY ").append(time).append(" DESC,t.id DESC LIMIT #{limit}");
            return "SELECT t.*,k.query_sort_time FROM ("+sql+") k STRAIGHT_JOIN "+t+" t ON t.id=k.id ORDER BY k.query_sort_time DESC,k.id DESC";
        }
        @SuppressWarnings("unchecked")
        public static String insert(Map<String,Object> p) {
            String t=table(p);Map<String,Object> v=(Map<String,Object>)p.get("values");
            List<String> cols=new ArrayList<>(),params=new ArrayList<>();
            for(String k:v.keySet()){cols.add(col(t,k));params.add("#{values."+k+"}");}
            return "INSERT INTO "+t+" ("+String.join(",",cols)+") VALUES ("+String.join(",",params)+")";
        }
        /** 有界批量 INSERT 的扁平参数计划；列和表名都经当前 mapper 白名单校验。 */
        public static FlatPlan insertAllPlan(String t,List<Map<String,Object>> rows) {
            table(Map.of("table",t));
            if(rows.isEmpty()||rows.size()>500)throw new IllegalArgumentException("Invalid insert count");
            var keys=List.copyOf(rows.getFirst().keySet());
            if(keys.isEmpty()||rows.stream().anyMatch(r->!r.keySet().equals(rows.getFirst().keySet())))throw new IllegalArgumentException("Row columns differ");
            var columns=keys.stream().map(k->col(t,k)).toList();
            String values="("+String.join(",",Collections.nCopies(keys.size(),"?"))+")";
            var arguments=new ArrayList<Object>(rows.size()*keys.size());
            for(var row:rows)for(String key:keys)arguments.add(row.get(key));
            return plan("INSERT INTO "+t+" ("+String.join(",",columns)+") VALUES "+String.join(",",Collections.nCopies(rows.size(),values)),arguments);
        }
        /**
         * 常量派生表驱动主键点查更新，避免每行计算整份 CASE；所有值仍使用占位符。
         * 只生成不超过 500 个不同主键的计划，不更新主键本身；可变表边界由 GuardStore 再校验。
         */
        public static FlatPlan updateAllPlan(String t,List<Map<String,Object>> rows){
            table(Map.of("table",t));
            if(rows.isEmpty()||rows.size()>500)throw new IllegalArgumentException("Invalid update count");
            var updates=new ArrayList<>(rows.getFirst().keySet());updates.remove("id");
            var ids=new HashSet<Long>();
            if(updates.isEmpty()||rows.stream().anyMatch(r->!r.keySet().equals(rows.getFirst().keySet())
                    ||!(r.get("id") instanceof Number n)||!ids.add(n.longValue())))
                throw new IllegalArgumentException("Invalid update rows");
            var columns=new ArrayList<String>();columns.add("id");columns.addAll(updates);
            var quoted=columns.stream().map(c->col(t,c)).toList();
            String rowSql="SELECT "+String.join(",",quoted.stream().map(column->"? AS "+column).toList());
            var arguments=new ArrayList<Object>(rows.size()*columns.size());
            for(var row:rows)for(String column:columns)arguments.add(row.get(column));
            var sets=updates.stream().map(c->"t."+col(t,c)+"=k."+col(t,c)).toList();
            return plan("UPDATE ("+String.join(" UNION ALL ",Collections.nCopies(rows.size(),rowSql))+") k "
                    +"STRAIGHT_JOIN "+t+" t FORCE INDEX (PRIMARY) ON t.`id`=k.`id` SET "+String.join(",",sets),arguments);
        }
        private static FlatPlan plan(String sql,List<Object> arguments){return new FlatPlan(sql,arguments);}
        @SuppressWarnings("unchecked")
        public static String update(Map<String,Object> p) {
            String t=table(p);Map<String,Object> v=(Map<String,Object>)p.get("values");List<String> set=new ArrayList<>();
            for(String k:v.keySet())set.add(col(t,k)+"=#{values."+k+"}");
            return "UPDATE "+t+" SET "+String.join(",",set)+" WHERE id=#{id}";
        }
    }
}
