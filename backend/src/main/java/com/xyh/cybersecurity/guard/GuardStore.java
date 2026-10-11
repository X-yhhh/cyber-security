package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import com.xyh.cybersecurity.audit.AuditMapper;
import org.springframework.stereotype.Repository;
import java.time.*;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/** MyBatis 事实访问；行锁由应用事务持有，证据表仅追加，更新只开放给可变投影。 */
@Repository
public class GuardStore {
    private final GuardMapper mapper;
    private final AuditMapper audit;
    private static final Set<String> MUTABLE=Set.of("asset","asset_authorization","sensor_agent","sensor_config","api_client",
            "guard_idempotency","guard_model","guard_decision_policy","guard_release_bundle","guard_asset_binding",
            "guard_capture_scope","guard_observation_batch","guard_executor","guard_target_budget","guard_asset_budget",
            "guard_episode","guard_episode_evidence","guard_action","guard_budget_interval","guard_revocation","guard_action_receipt",
            "guard_authorization_lease","consumed_message","security_event","guard_feedback","guard_validation_session","guard_replay_run");
    public GuardStore(GuardMapper mapper,AuditMapper audit){this.mapper=mapper;this.audit=audit;}
    public Instant now(){return mapper.now().toInstant(ZoneOffset.UTC);}
    public Map<String,Object> insert(String t,Map<String,Object> v){mapper.insert(t,v);return v;}
    public Map<String,Object> add(String t,Map<String,Object> v){v.putIfAbsent("public_id",id());return insert(t,v);}
    /** 批量追加不需回读主键的事实行；每行补 public_id，按 500 行分段。 */
    public void addAll(String t,List<Map<String,Object>> rows){for(var r:rows)r.putIfAbsent("public_id",id());for(int i=0;i<rows.size();i+=500)mapper.insertAll(t,rows.subList(i,Math.min(rows.size(),i+500)));}
    /** 同表严格批量新增并回填主键；校验每行独立主键后才允许建立外键关联，失败由外层事务回滚。 */
    public void addAllReturning(String t,List<Map<String,Object>> rows){
        for(var r:rows)r.putIfAbsent("public_id",id());
        for(int i=0;i<rows.size();i+=500)mapper.insertAllReturning(t,rows.subList(i,Math.min(rows.size(),i+500)));
        require(rows.stream().allMatch(r->r.get("id") instanceof Number)&&rows.stream().map(r->r.get("id")).distinct().count()==rows.size(),"BATCH_KEYS_UNAVAILABLE");
    }
    public void update(String t,long id,Map<String,Object> v){if(!MUTABLE.contains(t))throw new IllegalArgumentException("Immutable fact");mapper.update(t,id,v);}
    public List<Map<String,Object>> rows(String t,Map<String,Object> w,boolean lock,int limit){return mapper.select(t,w,lock,limit,null,null,null);}
    public List<Map<String,Object>> visible(String t,Map<String,Object> w,long actor,String permission,int limit,Long before){return mapper.select(t,w,false,limit,actor,permission,before);}
    public Map<String,Object> one(String t,Map<String,Object> w,boolean lock){var r=rows(t,w,lock,1);return r.isEmpty()?null:r.getFirst();}
    public Map<String,Object> get(String t,long id){var r=one(t,map("id",id),false);if(r==null)throw error(404,"RESOURCE_NOT_FOUND");return r;}
    public Map<String,Object> external(String t,String id,boolean lock){var r=one(t,map("public_id",uuid(id)),lock);if(r==null)throw error(404,"RESOURCE_NOT_FOUND");return r;}
    public void outbox(String topic,String aggregate,JsonNode payload){insert("outbox_event",map("event_key",id(),"aggregate_type","guard","aggregate_id",aggregate,"topic",topic,"payload_json",canonical(payload),"status","pending"));}
    public void audit(Long actor,String action,String resource,Long asset,String requestId,JsonNode proof){
        var a=new AuditMapper.AuditInsert(LocalDateTime.now(ZoneOffset.UTC),actor==null?"system":"human",actor==null?"guard":actor.toString(),
                action,"guard",resource,requestId,"success",hash(proof));audit.insertAudit(a);
        if(asset!=null)audit.insertResourceScope(a.getId(),"asset",asset.toString());
    }
    /** 先锁资产再锁额度，后续绑定/目标/episode/action 统一按此顺序。 */
    public Map<String,Object> lockAsset(long asset){var r=one("asset",map("id",asset),true);if(r==null)throw error(404,"RESOURCE_NOT_FOUND");return r;}
}
