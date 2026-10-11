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
    @InsertProvider(type=Sql.class,method="insert")
    @Options(useGeneratedKeys=true,keyProperty="values.id")
    int insert(@Param("table") String table,@Param("values") Map<String,Object> values);
    @UpdateProvider(type=Sql.class,method="update")
    int update(@Param("table") String table,@Param("id") long id,@Param("values") Map<String,Object> values);
    @Select("SELECT UTC_TIMESTAMP(6)") java.time.LocalDateTime now();
    @Select("""
        SELECT EXISTS(SELECT 1 FROM sys_user_role ur JOIN sys_role r ON r.id=ur.role_id AND r.status='active'
        JOIN sys_role_permission rp ON rp.role_id=r.id JOIN sys_permission p ON p.id=rp.permission_id AND p.status='active'
        JOIN sys_user u ON u.id=ur.user_id AND u.status='active'
        WHERE ur.user_id=#{actor} AND p.permission_key=#{permission}
        AND ((ur.scope_type='global' AND ur.scope_id='*') OR (ur.scope_type=#{scopeType} AND ur.scope_id=#{scopeId})))
        """)
    boolean permitted(@Param("actor") long actor,@Param("permission") String permission,
                      @Param("scopeType") String scopeType,@Param("scopeId") String scopeId);
    @Insert("INSERT INTO api_client_permission(client_id,permission_id) SELECT #{client},id FROM sys_permission WHERE permission_key=#{permission} AND status='active'")
    int grant(@Param("client") long client,@Param("permission") String permission);
    @Select("""
        SELECT EXISTS(SELECT 1 FROM api_client c JOIN api_client_permission cp ON cp.client_id=c.id
        JOIN sys_permission p ON p.id=cp.permission_id WHERE c.id=#{client} AND c.status='active'
        AND (c.expires_at IS NULL OR c.expires_at>UTC_TIMESTAMP(6)) AND p.status='active' AND p.permission_key=#{permission})
        """) boolean machinePermission(@Param("client") long client,@Param("permission") String permission);
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
    @Select("SELECT * FROM guard_observation WHERE asset_id=#{asset} AND sensor_id=#{sensor} AND boot_id=#{boot} AND parent_connection_id=#{parent} ORDER BY as_of DESC,snapshot_index DESC,id DESC LIMIT 1")
    Map<String,Object> latestParent(@Param("asset") long asset,@Param("sensor") long sensor,@Param("boot") String boot,@Param("parent") String parent);
    /** 一次读出最新投影、不可变观察和推理状态，保留原有跨桶 latest 及 10000 条上限。 */
    @Select("""
        SELECT e.*,o.payload_json observation_payload_json,o.content_sha256 observation_content_sha256,i.status inference_status
        FROM guard_episode_evidence e JOIN guard_observation o ON o.id=e.observation_id
        JOIN guard_inference i ON i.id=e.inference_id
        WHERE e.episode_id=#{episode} AND o.id=(
          SELECT n.id FROM guard_observation n
          WHERE n.asset_id=o.asset_id AND n.sensor_id=o.sensor_id AND n.boot_id=o.boot_id AND n.parent_connection_id=o.parent_connection_id
          ORDER BY n.as_of DESC,n.snapshot_index DESC,n.id DESC LIMIT 1)
        ORDER BY e.id DESC LIMIT 10000
        """)
    List<Map<String,Object>> episodeEvidence(@Param("episode") long episode);
    final class Sql {
        private static final Map<String,Set<String>> COLUMNS=new HashMap<>();
        static {
            COLUMNS.put("security_event",Set.of("id","public_id","guard_asset_id","revision","event_key","title","category","severity","status","risk_score","risk_rule_version","first_seen_at","last_seen_at","created_at","closed_at"));
            COLUMNS.put("event_timeline",Set.of("id","event_id","occurred_at","entry_type","actor_type","actor_id","summary","evidence_ref","details_json","created_at"));
            COLUMNS.put("guard_feedback",Set.of("id","public_id","created_at","asset_id","observation_id","label","evidence_ref","created_by","reviewed_by","status","review_reason","revision"));
            COLUMNS.put("guard_validation_session",Set.of("id","public_id","created_at","asset_id","bundle_id","authorization_id","requested_by","approved_by","status","payload_json","content_sha256","valid_until","revision"));

            COLUMNS.put("guard_idempotency",Set.of("id","public_id","created_at","request_scope","idempotency_key","request_sha256","response_json","http_status"));
            COLUMNS.put("guard_contract",Set.of("id","public_id","created_at","contract_version","profile_sha256","schema_set_sha256","extractor_sha256","status"));
            COLUMNS.put("guard_dataset",Set.of("id","public_id","created_at","dataset_key","version","manifest_ref","manifest_sha256","payload_json"));
            COLUMNS.put("guard_model",Set.of("id","public_id","created_at","model_key","version","manifest_ref","manifest_sha256","artifact_sha256","contract_id","manifest_json","validation_status","validation_json","created_by"));
            COLUMNS.put("guard_evaluation_plan",Set.of("id","public_id","created_at","plan_key","version","plan_sha256","payload_json","created_by"));
            COLUMNS.put("guard_capability",Set.of("id","public_id","created_at","capability_key","version","platform","level","payload_json","created_by","scope","protection_set_sha256","exemption_evidence_sha256"));
            COLUMNS.put("guard_decision_policy",Set.of("id","public_id","created_at","policy_key","version","model_id","plan_id","decision_contract_version","definition_json","definition_sha256","status","created_by","reviewed_by","revision"));
            COLUMNS.put("guard_release_bundle",Set.of("id","public_id","created_at","bundle_key","version","model_id","policy_id","contract_id","plan_id","environment","subject_sha256","subject_json","sealed_manifest_sha256","sealed_manifest_json","status","requested_by","approved_by","revision"));
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
            COLUMNS.put("guard_executor",Set.of("id","public_id","created_at","asset_id","api_client_id","platform","adapter_version","capability_hash","boot_id","status","last_heartbeat","health_json","revision"));
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
            COLUMNS.put("asset",Set.of("id","public_id","asset_key","asset_type","environment","criticality","owner","status","labels_json","revision","created_at","updated_at"));
            COLUMNS.put("asset_authorization",Set.of("id","public_id","asset_id","authorization_ref","scope_json","valid_from","valid_until","status","approved_by","requested_by","revision","created_at","revoked_by","revoked_at","revoke_reason"));
            COLUMNS.put("sensor_agent",Set.of("id","public_id","agent_key","asset_id","platform","agent_version","capabilities_json","credential_ref","status","registered_at","last_heartbeat_at","revision","guard_boot_id","created_at"));
            COLUMNS.put("sensor_config",Set.of("id","public_id","sensor_id","config_version","interface_scope_json","filter_policy_json","flow_window_seconds","feature_contract_version","sampling_policy_json","status","approved_by","activated_at","requested_by","revision","guard_definition_json","content_sha256","created_at"));
            COLUMNS.put("api_client",Set.of("id","public_id","client_key","client_type","sensor_id","secret_ref","credential_sha256","scope_json","status","expires_at","created_at"));
            COLUMNS.put("outbox_event",Set.of("id","event_key","aggregate_type","aggregate_id","topic","payload_json","status","attempts","next_attempt_at","created_at","published_at"));
            COLUMNS.put("consumed_message",Set.of("id","consumer","message_key","status","attempts","last_error_code","last_error_message","consumed_at","updated_at"));
        }
        private static String table(Map<String,Object> p) {
            String t=(String)p.get("table");if(!COLUMNS.containsKey(t))throw new IllegalArgumentException("Unknown table");return t;
        }
        private static String col(String t,String c) {if(!COLUMNS.get(t).contains(c))throw new IllegalArgumentException("Unknown column");return "`"+c+"`";}
        @SuppressWarnings("unchecked")
        public static String select(Map<String,Object> p) {
            String t=table(p);Map<String,Object> w=(Map<String,Object>)p.get("where");
            StringBuilder sql=new StringBuilder("SELECT t.* FROM "+t+" t WHERE 1=1");
            for(String k:w.keySet())sql.append(" AND t.").append(col(t,k)).append(w.get(k)==null?" IS NULL":"=#{where."+k+"}");
            if(p.get("before")!=null)sql.append(" AND t.id<#{before}");
            if(p.get("actor")!=null) {
                String resource=t.equals("asset")?"t.id":COLUMNS.get(t).contains("asset_id")?"t.asset_id":t.equals("security_event")?"t.guard_asset_id":null;
                sql.append(" AND EXISTS(SELECT 1 FROM sys_user_role ur JOIN sys_role r ON r.id=ur.role_id AND r.status='active' JOIN sys_role_permission rp ON rp.role_id=r.id JOIN sys_permission p ON p.id=rp.permission_id AND p.status='active' JOIN sys_user u ON u.id=ur.user_id AND u.status='active' WHERE ur.user_id=#{actor} AND p.permission_key=#{permission} AND ((ur.scope_type='global' AND ur.scope_id='*')");
                if(resource!=null)sql.append(" OR (ur.scope_type='asset' AND ur.scope_id=CAST(").append(resource).append(" AS CHAR))");
                sql.append("))");
            }
            sql.append(" ORDER BY t.id DESC LIMIT #{limit}");
            if(Boolean.TRUE.equals(p.get("lock")))sql.append(" FOR UPDATE");
            return sql.toString();
        }
        @SuppressWarnings("unchecked")
        public static String insert(Map<String,Object> p) {
            String t=table(p);Map<String,Object> v=(Map<String,Object>)p.get("values");
            List<String> cols=new ArrayList<>(),params=new ArrayList<>();
            for(String k:v.keySet()){cols.add(col(t,k));params.add("#{values."+k+"}");}
            return "INSERT INTO "+t+" ("+String.join(",",cols)+") VALUES ("+String.join(",",params)+")";
        }
        @SuppressWarnings("unchecked")
        public static String update(Map<String,Object> p) {
            String t=table(p);Map<String,Object> v=(Map<String,Object>)p.get("values");List<String> set=new ArrayList<>();
            for(String k:v.keySet())set.add(col(t,k)+"=#{values."+k+"}");
            return "UPDATE "+t+" SET "+String.join(",",set)+" WHERE id=#{id}";
        }
    }
}
