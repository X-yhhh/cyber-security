package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import com.xyh.cybersecurity.audit.AuditMapper;
import org.springframework.stereotype.Repository;
import java.time.*;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/** MyBatis 事务内的事实访问；行锁由应用事务持有，更新只开放给可变投影。 */
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
    /**
     * 批内判定的只读作用域：同一事务且已持资产锁期间，对判定不写入的配置/身份表复用非加锁读取与 JSON 解析结果。
     * 这些表的写入方（授权、组合、执行器、会话等）都先锁同一资产，作用域内不会被并发修改；经本类写入缓存表时清掉该表。
     * VOLATILE 中的表（目标租约、健康窗口、执行器心跳）由每次判定开始时 forgetVolatile 清空，只在单次判定内复用。
     * 加锁读取与其他表始终直达数据库。作用域不可嵌套复用，关闭即丢弃。
     */
    private static final Set<String> READ_CACHE=Set.of("guard_decision_policy","guard_model","guard_capability","guard_bundle_capability",
            "guard_release_bundle","asset_authorization","guard_asset_binding","sensor_agent","guard_executor","guard_budget_target",
            "guard_capture_scope","guard_validation_session","guard_target_binding","guard_capture_health_window");
    private static final Set<String> VOLATILE=Set.of("guard_executor","guard_target_binding","guard_capture_health_window");
    private static final ThreadLocal<Map<String,List<Map<String,Object>>>> READS=new ThreadLocal<>();
    private static final ThreadLocal<Map<String,Optional<Object>>> VALUES=new ThreadLocal<>();
    public interface ReadScope extends AutoCloseable {@Override void close();}
    public ReadScope readScope(){
        if(READS.get()!=null)return ()->{};
        READS.set(new HashMap<>());VALUES.set(new HashMap<>());GuardJson.PARSED.set(new IdentityHashMap<>());
        return ()->{READS.remove();VALUES.remove();GuardJson.PARSED.remove();};
    }
    /** 单次判定开始时丢弃易变表的缓存；不变配置继续复用。 */
    public void forgetVolatile(){var reads=READS.get();if(reads!=null){reads.keySet().removeIf(k->VOLATILE.contains(k.substring(0,k.indexOf('|'))));VALUES.get().keySet().removeIf(k->k.startsWith("volatile:"));}}
    /** 作用域内按键复用调用方给出的只读结果（含 null）；作用域外直接计算。键以 volatile: 开头的随 forgetVolatile 清空。 */
    /** 静态工具：作用域内复用，作用域外直接计算；不经实例方法，便于纯领域测试替身。 */
    @SuppressWarnings("unchecked")
    public static <T> T scoped(String key,java.util.function.Supplier<T> load){var values=VALUES.get();if(values==null)return load.get();
        var hit=values.get(key);if(hit==null){hit=Optional.ofNullable(load.get());values.put(key,hit);}return (T)hit.orElse(null);}
    @SuppressWarnings("unchecked")
    public <T> T cached(String key,java.util.function.Supplier<T> load){var values=VALUES.get();if(values==null)return load.get();
        var hit=values.get(key);if(hit==null){hit=Optional.ofNullable(load.get());values.put(key,hit);}return (T)hit.orElse(null);}
    /** 预算事实的写入使 budget: 缓存失效（预算写入方都先锁同一资产，作用域内只有本事务能写）。 */
    private static final Set<String> BUDGET_TABLES=Set.of("guard_target_budget","guard_asset_budget","guard_budget_event","guard_budget_interval","guard_action","guard_budget_target");
    private static void written(String t){var values=VALUES.get();if(values!=null&&BUDGET_TABLES.contains(t))values.keySet().removeIf(k->k.startsWith("budget:"));
        var reads=READS.get();if(reads!=null&&READ_CACHE.contains(t)){reads.keySet().removeIf(k->k.startsWith(t+"|"));VALUES.get().clear();GuardJson.PARSED.get().clear();}}
    public Instant now(){return mapper.now().toInstant(ZoneOffset.UTC);}
    public Map<String,Object> insert(String t,Map<String,Object> v){written(t);mapper.insert(t,v);return v;}
    public Map<String,Object> add(String t,Map<String,Object> v){v.putIfAbsent("public_id",id());return insert(t,v);}
    /** 批量追加不需回读主键的事实行；每行补 public_id，按 500 行分段。 */
    public void addAll(String t,List<Map<String,Object>> rows){written(t);for(var r:rows)r.putIfAbsent("public_id",id());for(int i=0;i<rows.size();i+=500)insertPart(t,rows.subList(i,Math.min(rows.size(),i+500)),false);}
    /** 同表严格批量新增并回填主键；校验每行独立主键后才允许建立外键关联，失败由外层事务回滚。 */
    public void addAllReturning(String t,List<Map<String,Object>> rows){
        written(t);for(var r:rows)r.putIfAbsent("public_id",id());
        for(int i=0;i<rows.size();i+=500)insertPart(t,rows.subList(i,Math.min(rows.size(),i+500)),true);
        require(rows.stream().allMatch(r->r.get("id") instanceof Number)&&rows.stream().map(r->r.get("id")).distinct().count()==rows.size(),"BATCH_KEYS_UNAVAILABLE");
    }
    public void update(String t,long id,Map<String,Object> v){written(t);if(!MUTABLE.contains(t))throw new IllegalArgumentException("Immutable fact");mapper.update(t,id,v);}
    /** 批内投影按主键批量更新，沿用同一可变表白名单和事务；调用方须持有原资产锁。 */
    public void updateAll(String t,List<Map<String,Object>> rows){
        written(t);if(!MUTABLE.contains(t))throw new IllegalArgumentException("Immutable fact");
        var ids=new HashSet<Long>();
        if(rows.stream().anyMatch(r->!(r.get("id") instanceof Number n)||!ids.add(n.longValue())))
            throw new IllegalArgumentException("Invalid update rows");
        for(int i=0;i<rows.size();i+=500){
            // 未命中主键和写入相同值沿用旧 UPDATE 语义；MyBatis 写入自动使事务一级缓存失效。
            mapper.updateAll(GuardMapper.Sql.updateAllPlan(t,rows.subList(i,Math.min(i+500,rows.size()))));
        }
    }
    /** 不带 public_id 的表也可严格多行新增；不忽略冲突，不提前提交。 */
    public void insertAll(String t,List<Map<String,Object>> rows){written(t);for(int i=0;i<rows.size();i+=500)insertPart(t,rows.subList(i,Math.min(i+500,rows.size())),false);}
    /** 单条多行 INSERT 参加调用方 Spring 事务；不忽略冲突，所需主键由 MyBatis 逐行回填。 */
    private void insertPart(String t,List<Map<String,Object>> rows,boolean returning){
        var plan=GuardMapper.Sql.insertAllPlan(t,rows);
        int inserted=returning?mapper.insertAllReturning(plan,rows):mapper.insertAll(plan);
        require(inserted==rows.size(),"BATCH_WRITE_INCOMPLETE");
    }
    /** 内部精确键固定按 500 行分页；episode 只在同页内压缩公共列，不增加查询次数或扩大锁定键集。 */
    public List<Map<String,Object>> byKeys(String t,List<Map<String,Object>> keys,boolean lock){
        var rows=new ArrayList<Map<String,Object>>();
        for(int i=0;i<keys.size();i+=500){var part=keys.subList(i,Math.min(i+500,keys.size()));
            rows.addAll(t.equals("guard_episode")?indexedKeys(t,part,lock):mapper.selectKeys(t,part,lock));}
        return rows;
    }
    /** 已持有资产锁后，按完整唯一键锁定证据投影；返回原观察 UUID 用于替换审计。 */
    public List<Map<String,Object>> evidenceKeys(List<Map<String,Object>> keys){
        var rows=new ArrayList<Map<String,Object>>();for(int i=0;i<keys.size();i+=500)rows.addAll(indexedKeys("guard_episode_evidence",keys.subList(i,Math.min(i+500,keys.size())),true));return rows;
    }
    private List<Map<String,Object>> indexedKeys(String table,List<Map<String,Object>> keys,boolean lock){
        return mapper.indexedKeys(GuardMapper.Sql.indexedKeysPlan(table,keys,lock));
    }
    public List<Map<String,Object>> rows(String t,Map<String,Object> w,boolean lock,int limit){
        var reads=READS.get();
        if(lock||reads==null||!READ_CACHE.contains(t))return mapper.select(t,w,lock,limit,null,null,null);
        return reads.computeIfAbsent(t+"|"+limit+"|"+w,k->List.copyOf(mapper.select(t,w,false,limit,null,null,null)));
    }
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
    /** 批量审计的每一项仍持有独立资源与证据摘要，不能只留下一个批次总摘要。 */
    public record AuditProof(String resource,long asset,JsonNode proof){}
    public void auditSystemAll(String action,List<AuditProof> proofs){
        for(int start=0;start<proofs.size();start+=500){
            var part=proofs.subList(start,Math.min(start+500,proofs.size()));var rows=new ArrayList<AuditMapper.AuditInsert>();
            for(var p:part)rows.add(new AuditMapper.AuditInsert(LocalDateTime.now(ZoneOffset.UTC),"system","guard",action,"guard",p.resource(),null,"success",sha(canonicalFact(p.proof()).getBytes(java.nio.charset.StandardCharsets.UTF_8))));
            audit.insertAudits(rows);
            require(rows.stream().allMatch(r->r.getId()>0)&&rows.stream().map(AuditMapper.AuditInsert::getId).distinct().count()==rows.size(),"BATCH_KEYS_UNAVAILABLE");
            var scopes=new ArrayList<Map<String,Object>>();for(int i=0;i<rows.size();i++)scopes.add(map("auditId",rows.get(i).getId(),"assetId",Long.toString(part.get(i).asset())));
            audit.insertAssetScopes(scopes);
        }
    }
    /** 先锁资产再锁额度，后续绑定/目标/episode/action 统一按此顺序。 */
    public Map<String,Object> lockAsset(long asset){var r=one("asset",map("id",asset),true);if(r==null)throw error(404,"RESOURCE_NOT_FOUND");return r;}
    public List<Long> lockUserRoles(long userId){return mapper.lockUserRoles(userId);}
    public boolean permitted(long actor,String permission,Long asset){return mapper.permitted(actor,permission,asset==null?"global":"asset",asset==null?"*":asset.toString());}
}
