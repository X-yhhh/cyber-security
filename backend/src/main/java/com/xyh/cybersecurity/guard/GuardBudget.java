package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.stereotype.Service;
import java.time.*;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/** T3/T7 共享资产→目标锁：稳定目标区间并集计费；实际清理与连续健康冷却共同恢复。 */
@Service
public class GuardBudget {
    public static final Set<String> TERMINAL=Set.of("revoked","expired","rejected");
    /** 新演示策略显式选择独立恢复协议；旧策略与历史发布组合不改变恢复口径。 */
    public static final String DEMO_POLICY_VERSION=DECISION+"+demo-budget-20261017";
    public static final String RECOVERY_VERSION="host-guard-budget-recovery/2026-10-17.1";
    private final GuardStore store;private final GuardAccess access;private final GuardHealth health;
    public GuardBudget(GuardStore store,GuardAccess access,GuardHealth health){this.store=store;this.access=access;this.health=health;}
    /** 向所属执行器返回已持久化的预算恢复事实；只读查询不清零、不扩大授权。
     * 本地执行器仍须核验实际规则已清理，不能用本接口替代 OS 核对。
     */
    public JsonNode proof(String executorId,JsonNode body){
        fields(body,"stableTargetToken","");
        var executor=access.executor(executorId,"machine.target.bind");
        long assetId=number(executor,"asset_id");store.lockAsset(assetId);
        String token=digest(body,"stableTargetToken");
        var target=store.one("guard_budget_target",map("asset_id",assetId,"resolver_executor_id",executor.get("id"),"stable_target_token",token),false);
        if(target==null)throw error(404,"RESOURCE_NOT_FOUND");
        var state=store.one("guard_target_budget",map("budget_target_id",target.get("id")),false);
        require(state!=null,"BUDGET_IDENTITY_UNVERIFIED");
        return object("stableTargetToken",token,"budgetTargetId",target.get("public_id"),
                "revision",state.get("revision"),"chargedMs",state.get("charged_ms"),
                "cycleStartedAt",instant(state.get("cycle_started_at")).toString(),
                "healthProofSha256",state.get("health_proof_sha256"));
    }
    public JsonNode bind(String executorId,JsonNode b){fields(b,"bindingId executorBootId sensorId collectorBootId captureScopeId targetRef peerKey keyEpoch direction transport servicePort addressFamily stableTargetToken scopeDigest expiresAt","scope");
        var executor=access.executor(executorId,"machine.target.bind");long aid=number(executor,"asset_id");var asset=store.lockAsset(aid);require(!"research".equals(str(asset,"environment"))&&"active".equals(str(asset,"status")),"AUTHORIZATION_INACTIVE");
        require(uuid(b,"executorBootId").equals(str(executor,"boot_id")),"BOOT_ID_MISMATCH");var sensor=store.external("sensor_agent",uuid(b,"sensorId"),false);var scope=store.external("guard_capture_scope",uuid(b,"captureScopeId"),false);
        require(number(sensor,"asset_id")==aid&&number(scope,"sensor_id")==number(sensor,"id")&&"active".equals(str(scope,"status"))&&uuid(b,"collectorBootId").equals(str(sensor,"guard_boot_id")),"SCOPE_DENIED");
        require(Set.of("inbound","outbound").contains(text(b,"direction"))&&"tcp".equals(text(b,"transport"))&&"ipv4".equals(text(b,"addressFamily")),"CAPABILITY_NOT_SUPPORTED");GuardAdministration.executionScope(b);integer(b,"keyEpoch",1,Long.MAX_VALUE);digest(b,"peerKey");String token=digest(b,"stableTargetToken"),scopeDigest=digest(b,"scopeDigest");String target=uuid(b,"targetRef");uuid(b,"bindingId");Instant now=store.now(),expires=time(b,"expiresAt");require(expires.isAfter(now)&&!expires.isAfter(now.plusSeconds(15)),"TARGET_REF_STALE");
        var old=store.one("guard_target_binding",map("target_ref",target),false);if(old!=null){if(!hash(b).equals(str(old,"content_sha256")))throw error(409,"TARGET_BINDING_CONFLICT");return object("bindingId",old.get("public_id"),"budgetTargetId",store.get("guard_budget_target",number(old,"budget_target_id")).get("public_id"),"revision",1);}
        var identity=store.one("guard_budget_target",map("asset_id",aid,"environment",asset.get("environment"),"stable_target_token",token),false);
        var priorScope=store.one("guard_budget_target",map("asset_id",aid,"environment",asset.get("environment"),"scope_digest",scopeDigest),false);
        require(priorScope==null||token.equals(str(priorScope,"stable_target_token")),"BUDGET_IDENTITY_UNVERIFIED");
        for(var previous:store.rows("guard_target_binding",map("sensor_id",sensor.get("id"),"peer_key",text(b,"peerKey"),"key_epoch",b.get("keyEpoch").longValue()),false,1000)){
            var p=json(previous,"payload_json");if(p.path("scope").asText("peer_service").equals(b.path("scope").asText("peer_service"))&&p.path("direction").equals(b.get("direction"))&&p.path("transport").equals(b.get("transport"))&&p.path("servicePort").equals(b.get("servicePort"))&&p.path("addressFamily").equals(b.get("addressFamily")))require(identity!=null&&number(previous,"budget_target_id")==number(identity,"id"),"BUDGET_IDENTITY_UNVERIFIED");
        }
        if(identity==null){identity=store.add("guard_budget_target",map("asset_id",aid,"environment",asset.get("environment"),"stable_target_token",token,"resolver_executor_id",executor.get("id"),"scope_digest",scopeDigest));store.add("guard_target_budget",map("budget_target_id",identity.get("id"),"cycle_started_at",db(now)));}
        else require(number(identity,"resolver_executor_id")==number(executor,"id")&&scopeDigest.equals(str(identity,"scope_digest"))&&"verified".equals(str(identity,"identity_status")),"BUDGET_IDENTITY_UNVERIFIED");
        var row=store.insert("guard_target_binding",map("public_id",text(b,"bindingId"),"target_ref",target,"budget_target_id",identity.get("id"),"executor_id",executor.get("id"),"executor_boot_id",text(b,"executorBootId"),"sensor_id",sensor.get("id"),"collector_boot_id",text(b,"collectorBootId"),"capture_scope_id",scope.get("id"),"peer_key",text(b,"peerKey"),"key_epoch",b.get("keyEpoch").longValue(),"scope_digest",scopeDigest,"expires_at",db(expires),"payload_json",canonical(b),"content_sha256",hash(b)));
        store.audit(null,"guard.target.bound",target,aid,null,object("bindingId",row.get("public_id"),"budgetTargetId",identity.get("public_id")));
        return object("bindingId",row.get("public_id"),"budgetTargetId",identity.get("public_id"),"revision",1);}
    /** 批内判定作用域中，同一事务已持资产锁且无预算写入时复用加锁读取结果；任何预算写入都使其失效。 */
    public Map<String,Object> lock(long asset,long target){return store.cached("budget:lock:"+asset+":"+target,()->lockNow(asset,target));}
    private Map<String,Object> lockNow(long asset,long target){store.lockAsset(asset);var a=store.one("guard_asset_budget",map("asset_id",asset),true);if(a==null)a=store.add("guard_asset_budget",map("asset_id",asset,"last_monotonic_at",db(store.now())));
        var b=store.one("guard_target_budget",map("budget_target_id",target),true);if(b==null)throw error(422,"BUDGET_IDENTITY_UNVERIFIED");return b;}
    public Instant monotonic(long asset){var b=store.cached("budget:asset:"+asset,()->store.one("guard_asset_budget",map("asset_id",asset),true));Instant now=store.now();if(b!=null&&instant(b.get("last_monotonic_at")).isAfter(now))return instant(b.get("last_monotonic_at"));return now;}
    public void evidence(long target,Instant at){var b=store.one("guard_target_budget",map("budget_target_id",target),true);Instant old=instant(b.get("last_evidence_at"));if(old!=null&&!at.isAfter(old))return;
        var after=map("last_evidence_at",db(at),"revision",number(b,"revision")+1);event(b,after,"evidence",object("evidenceAt",at.toString()));store.update("guard_target_budget",number(b,"id"),after);}
    /** 撤销事实绑定稳定目标的预算周期；策略、签名密钥和短期引用轮换不解除墓碑。 */
    public boolean revoked(long target){
        var b=store.cached("budget:target:"+target,()->store.one("guard_target_budget",map("budget_target_id",target),false));
        var tombstone=store.cached("budget:tombstone:"+target,()->store.one("guard_budget_event",map("budget_target_id",target,"event_kind","revoked"),false));
        return b!=null&&tombstone!=null&&instant(b.get("cycle_started_at")).toString().equals(json(tombstone,"proof_json").path("cycleStartedAt").asText());
    }
    /** 在资产→目标锁内追加撤销墓碑；未签发动作也保留事实，重复撤销不重复写入。 */
    public void revoke(Map<String,Object> action,String reason){
        long target=number(action,"budget_target_id");var b=lock(number(action,"asset_id"),target);
        if(revoked(target))return;
        var next=map("revision",number(b,"revision")+1);
        event(b,next,"revoked",object("actionId",action.get("public_id"),"reasonCode",reason,
                "cycleStartedAt",instant(b.get("cycle_started_at")).toString()));
        store.update("guard_target_budget",number(b,"id"),next);
    }
    /** 先周期墓碑与 TTL 去重，再连续时长、资产并发、资产速率；返回明确细分原因。 */
    public String check(long asset,long target,JsonNode policy,Instant now,Instant until){
        if(revoked(target))return "TARGET_REVOKED";
        var actions=store.rows("guard_action",map("asset_id",asset),false,10000);int active=0,recent=0;
        for(var a:actions){if(!TERMINAL.contains(str(a,"observed_state"))){active++;if(number(a,"budget_target_id")==target)return "TTL_OR_UNCERTAIN_DEDUP";}
            if(instant(a.get("created_at")).isAfter(now.minusSeconds(60)))recent++;}
        long proposed=charge(target,now,until);if(proposed>Math.min(120,policy.path("maxContinuousBlockSeconds").asLong())*1000)return "TARGET_CONTINUOUS_BUDGET";
        if(active>=Math.min(10,policy.path("maxActiveRulesPerAsset").asInt()))return "ASSET_CONCURRENT_LIMIT";
        if(recent>=Math.min(5,policy.path("maxNewActionsPerMinute").asInt()))return "ASSET_RATE_LIMIT";
        return null;
    }
    public long charge(long target,Instant start,Instant end){var budget=store.one("guard_target_budget",map("budget_target_id",target),false);Instant cycle=instant(budget.get("cycle_started_at"));List<Interval> intervals=new ArrayList<>();
        for(var r:store.rows("guard_budget_interval",map("budget_target_id",target),false,10000)){
            Instant a=instant(r.get("reserved_start")),b=instant(r.get("reserved_end"));if(a.isBefore(cycle)||"not_applied".equals(str(r,"status")))continue;
            // 已发生时间只有可信清零才能缩短；未知区间保守保留全部预留。
            Instant actual=instant(r.get("verified_end"));if(actual!=null)b=actual;
            if(b.isAfter(a))intervals.add(new Interval(a,b));
        }
        if(start!=null)intervals.add(new Interval(start,end));return unionMillis(intervals);}
    public static long unionMillis(List<Interval> input){var xs=new ArrayList<>(input);xs.sort(Comparator.comparing(Interval::start));Instant left=null,right=null;long ms=0;
        for(var x:xs){if(left==null){left=x.start;right=x.end;}else if(!x.start.isAfter(right)){if(x.end.isAfter(right))right=x.end;}else{ms+=Duration.between(left,right).toMillis();left=x.start;right=x.end;}}
        return left==null?0:ms+Duration.between(left,right).toMillis();}
    public void reserve(long asset,long target,long action,Instant start,Instant end){var b=lock(asset,target);long value=charge(target,start,end);require(value<=120000,"PROTECTION_OR_BUDGET_BLOCKED");
        store.add("guard_budget_interval",map("budget_target_id",target,"action_id",action,"reserved_start",db(start),"reserved_end",db(end),"status","reserved"));
        var next=map("charged_ms",value,"revision",number(b,"revision")+1);event(b,next,"reserve",object("actionId",store.get("guard_action",action).get("public_id"),"start",start.toString(),"end",end.toString()));store.update("guard_target_budget",number(b,"id"),next);
        var a=store.one("guard_asset_budget",map("asset_id",asset),true);store.update("guard_asset_budget",number(a,"id"),map("last_monotonic_at",db(start),"revision",number(a,"revision")+1));}
    public void ended(Map<String,Object> action,Instant at,String proof,boolean neverApplied){long target=number(action,"budget_target_id");var b=lock(number(action,"asset_id"),target);var interval=store.one("guard_budget_interval",map("action_id",action.get("id")),true);if(interval==null||!"reserved".equals(str(interval,"status")))return;
        require(!at.isBefore(instant(interval.get("reserved_start"))),"INVALID_RECONCILIATION_TIME");
        store.update("guard_budget_interval",number(interval,"id"),map("verified_end",db(at),"status",neverApplied?"not_applied":"ended","proof_sha256",proof));
        Instant last=instant(b.get("last_block_end_at"));if(last!=null&&last.isAfter(at))at=last;
        var next=map("last_block_end_at",db(at),"charged_ms",Math.min(120000,charge(target,null,null)),"revision",number(b,"revision")+1);event(b,next,"reconcile",object("stateSha256",proof,"notApplied",neverApplied));store.update("guard_target_budget",number(b,"id"),next);}
    /** 仅由健康处理/核对事务触发；没有任意客户端清零入口。 */
    public boolean recover(long asset,long target,Instant now){var b=lock(asset,target);if((number(b,"charged_ms")==0&&!revoked(target))||b.get("last_block_end_at")==null)return false;
        for(var a:store.rows("guard_action",map("budget_target_id",target),true,10000))if(!TERMINAL.contains(str(a,"observed_state")))return false;
        Instant end=instant(b.get("last_block_end_at")),last=instant(b.get("last_evidence_at"));Instant anchor=last!=null&&last.isAfter(end)?last:end;if(now.isBefore(anchor.plusSeconds(120)))return false;
        // 仅已激活的新 lab 策略允许断采后的新完整链；其余组合保持原 lastBlockEnd 起点。
        var recoveryPolicy=recoveryPolicy(asset);Instant from=end,earliestEnd=anchor.plusSeconds(120);
        if(recoveryPolicy!=null){from=now.minusSeconds(130);if(from.isBefore(anchor))from=anchor;earliestEnd=from.plusSeconds(120);}
        JsonNode proof;try{proof=health.proof(asset,from,earliestEnd,now);}catch(com.xyh.cybersecurity.common.api.ApiRequestException e){return false;}
        if(recoveryPolicy!=null)proof=object("recoveryVersion",RECOVERY_VERSION,"policyId",recoveryPolicy.get("public_id"),"policySha256",recoveryPolicy.get("definition_sha256"),"from",proof.path("from"),"through",proof.path("through"),"healthProof",proof);
        Instant through=time(proof,"through");var next=map("charged_ms",0,"cycle_started_at",db(through),"health_proof_sha256",hash(proof),"revision",number(b,"revision")+1);
        event(b,next,"reset",proof);store.update("guard_target_budget",number(b,"id"),next);store.audit(null,"guard.budget.recovered",str(b,"public_id"),asset,null,proof);return true;}
    /** 在同一资产锁内读取已激活组合，未登记/未激活/非 lab/旧策略均不能选择新协议。 */
    private Map<String,Object> recoveryPolicy(long asset){
        var binding=store.one("guard_asset_binding",map("asset_id",asset,"status","active"),false);if(binding==null)return null;
        var bundle=store.get("guard_release_bundle",number(binding,"bundle_id"));
        if(bundle==null||!"active".equals(str(bundle,"status"))||!"lab".equals(str(bundle,"environment")))return null;
        var policy=store.get("guard_decision_policy",number(bundle,"policy_id"));
        return policy!=null&&DEMO_POLICY_VERSION.equals(json(policy,"definition_json").path("policyVersion").asText())?policy:null;
    }
    private void event(Map<String,Object> before,Map<String,Object> after,String kind,JsonNode proof){store.add("guard_budget_event",map("budget_target_id",before.get("budget_target_id"),"event_kind",kind,"old_revision",before.get("revision"),"new_revision",after.get("revision"),"before_json",canonical(snapshot(before)),"after_json",canonical(snapshot(after)),"proof_json",canonical(proof),"proof_sha256",hash(proof)));}
    private JsonNode snapshot(Map<String,Object> row){var o=JSON.createObjectNode();row.forEach((k,v)->o.set(k,node(v instanceof LocalDateTime t?t.toInstant(ZoneOffset.UTC).toString():v)));return o;}
    public record Interval(Instant start,Instant end){}
}
