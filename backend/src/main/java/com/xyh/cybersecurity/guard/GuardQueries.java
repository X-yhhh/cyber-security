package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import java.time.*;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/** 资源范围谓词在 SQL LIMIT 之前执行；API 只暴露外部 UUID，不返回目标 token 或机器凭据。 */
@Service
public class GuardQueries {
    private final GuardStore store;private final GuardAccess access;private final GuardMapper mapper;private final GuardReadCursor cursors;
    public GuardQueries(GuardStore store,GuardAccess access,GuardMapper mapper,GuardReadCursor cursors){this.store=store;this.access=access;this.mapper=mapper;this.cursors=cursors;}
    private static final Map<String,String> TABLES=Map.ofEntries(Map.entry("assets","asset"),Map.entry("sensors","sensor_agent"),Map.entry("executors","guard_executor"),Map.entry("models","guard_model"),Map.entry("datasets","guard_dataset"),Map.entry("evaluation-plans","guard_evaluation_plan"),Map.entry("evaluations","guard_evaluation_run"),Map.entry("replay-runs","guard_replay_run"),Map.entry("decision-policies","guard_decision_policy"),Map.entry("release-bundles","guard_release_bundle"),Map.entry("capabilities","guard_capability"),Map.entry("observation-batches","guard_observation_batch"),Map.entry("observations","guard_observation"),Map.entry("detections","guard_inference"),Map.entry("evidence-episodes","guard_episode"),Map.entry("decisions","guard_decision"),Map.entry("actions","guard_action"),Map.entry("budget-targets","guard_budget_target"),Map.entry("events","security_event"),Map.entry("feedback","guard_feedback"));
    public static String permission(String collection){return switch(collection){case "observation-batches","observations","detections","evidence-episodes","decisions","events","feedback"->"detection.read";case "actions","budget-targets"->"action.read";case "evaluations","evaluation-plans","replay-runs"->"evaluation.read";default->"resource.read";};}
    private static Set<String> statuses(String collection){
        return switch(collection){
            case "assets"->Set.of("active","disabled","retired");
            case "sensors"->Set.of("pending","active","offline","revoked");
            case "executors"->Set.of("pending","active","suspended","revoked");
            case "events"->Set.of("open","investigating","contained","resolved","false_positive","closed");
            case "actions"->Set.of("pending","dispatched","applied","revoked","expired","rejected","uncertain","recovery_failed");
            case "release-bundles"->Set.of("candidate","evaluated","approved","active","suspended","retired");
            case "decision-policies"->Set.of("draft","reviewed","retired");
            case "feedback"->Set.of("pending","reviewed","rejected");
            case "models"->Set.of("pending","validated","failed","retired");
            case "datasets"->Set.of("active","retired");
            case "replay-runs"->Set.of("queued","running","completed","failed");
            case "evaluations"->Set.of("pending","running","completed","failed");
            default->Set.of();
        };
    }
    private static String statusColumn(String collection){
        return switch(collection){
            case "actions"->"observed_state";
            case "models"->"validation_status";
            default->"status";
        };
    }
    public JsonNode list(String collection,String assetId,String status,String cursor,int limit){
        return list(collection,assetId,status,GuardCollectionFilter.parse(null,null,null,null),null,cursor,limit);
    }
    /** 查询谓词先于 LIMIT，排序时间与主键组成稳定游标，换筛选、换集合或换主体不能复用。 */
    @Transactional(readOnly=true,isolation=Isolation.REPEATABLE_READ)
    public JsonNode list(String collection,String assetId,String status,GuardCollectionFilter filter,String active,String cursor,int limit){
        String table=table(collection);if(limit<1||limit>200)throw error(400,"INVALID_PAGE_SIZE");
        long actor=access.human();String perm=permission(collection);access.feature(perm);Map<String,Object> where=map();
        boolean global=Set.of("models","datasets","evaluation-plans","evaluations","replay-runs","decision-policies","release-bundles","capabilities").contains(collection);
        if(global){if(assetId!=null)throw error(400,"INVALID_QUERY");access.permission(perm,null);}
        if(assetId!=null){var asset=store.external("asset",uuid(assetId),false);access.visible(perm,number(asset,"id"));
            where.put(collection.equals("assets")?"id":collection.equals("events")?"guard_asset_id":"asset_id",asset.get("id"));}
        if(status!=null){if(!statuses(collection).contains(status))throw error(400,"INVALID_QUERY");where.put(statusColumn(collection),status);}
        if(filter.q()!=null&&!GuardMapper.Sql.searchable(table))throw error(400,"INVALID_QUERY");
        if(active!=null&&(!collection.equals("actions")||!active.equals("true")))throw error(400,"INVALID_QUERY");
        String binding=filter.binding(actor,collection,assetId,status,active);
        var position=cursor==null?null:cursors.decode(cursor,binding);
        long ceiling=position==null?mapper.consoleCeiling(table):position.ceiling();
        LocalDateTime asOf=position==null?LocalDateTime.ofInstant(store.now(),ZoneOffset.UTC):position.asOf();
        var rows=mapper.consoleList(table,where,actor,perm,filter.values(),ceiling,asOf,
                position==null?null:position.time(),position==null?null:position.id(),active!=null,limit+1);
        var page=rows.subList(0,Math.min(limit,rows.size()));
        String next=rows.size()>limit?cursors.encode(new GuardReadCursor.Position(ceiling,number(page.getLast(),"id"),
                (LocalDateTime)page.getLast().get("query_sort_time"),asOf),binding):null;
        return object("items",page.stream().map(r->view(table,r)).toList(),"nextCursor",next);
    }
    public JsonNode list(String collection,String assetId,String cursor,int limit){return list(collection,assetId,null,cursor,limit);}
    public JsonNode get(String collection,String id){String table=table(collection);var r=store.external(table,id,false);check(r,permission(collection));
        if(collection.equals("budget-targets")){var b=store.one("guard_target_budget",map("budget_target_id",r.get("id")),false);var v=(com.fasterxml.jackson.databind.node.ObjectNode)view("guard_target_budget",b);v.put("id",id);return v;}
        if(collection.equals("events")){
            require(r.get("guard_asset_id")!=null,"RESOURCE_NOT_FOUND");
            return enrichEvent((com.fasterxml.jackson.databind.node.ObjectNode)view(table,r),r);
        }
        return view(table,r);}
    private JsonNode enrichEvent(com.fasterxml.jackson.databind.node.ObjectNode v,Map<String,Object> event){
        var episodeIds=JSON.createArrayNode();var decisionIds=JSON.createArrayNode();
        Map<String,Object> latestCandidateDecision=null;Map<String,Object> latestCandidateEpisode=null;Map<String,Object> latestDecision=null;
        var links=store.rows("guard_event_episode",map("event_id",event.get("id")),false,200);
        for(var link:links){
            var ep=store.get("guard_episode",number(link,"episode_id"));
            episodeIds.add(str(ep,"public_id"));
            for(var d:store.rows("guard_decision",map("episode_id",ep.get("id")),false,200)){
                decisionIds.add(str(d,"public_id"));
                if(latestDecision==null||number(d,"id")>number(latestDecision,"id"))latestDecision=d;
                if("block_candidate".equals(str(d,"decision"))&&(latestCandidateDecision==null||number(d,"id")>number(latestCandidateDecision,"id"))){
                    latestCandidateDecision=d;latestCandidateEpisode=ep;
                }
            }
        }
        v.set("episodeIds",episodeIds);v.set("decisionIds",decisionIds);
        String eventStatus=str(event,"status");
        if(Set.of("resolved","false_positive","closed").contains(eventStatus))
            return putActionability(v,false,null,null,null,null,"EVENT_NOT_OPEN");
        if(latestCandidateDecision==null){
            String code=latestDecision!=null&&latestDecision.get("reason_code")!=null?str(latestDecision,"reason_code"):"ACTION_EVIDENCE_REQUIRED";
            return putActionability(v,false,null,null,null,null,code);
        }
        var bundle=store.get("guard_release_bundle",number(latestCandidateDecision,"bundle_id"));
        var policy=store.get("guard_decision_policy",number(bundle,"policy_id"));
        String policyId=str(policy,"public_id");
        String episodeId=str(latestCandidateEpisode,"public_id");
        if(latestCandidateDecision.get("budget_target_id")==null)
            return putActionability(v,false,null,policyId,episodeId,null,"TARGET_REF_STALE");
        long btid=number(latestCandidateDecision,"budget_target_id");
        var budgetTarget=store.get("guard_budget_target",btid);
        String budgetTargetId=str(budgetTarget,"public_id");
        String targetRef=json(latestCandidateDecision,"evidence_json").path("targetRef").asText("");
        if(targetRef.isBlank()){
            for(var tb:store.rows("guard_target_binding",map("budget_target_id",btid),false,1)){targetRef=str(tb,"target_ref");}
        }
        var activeBinding=store.one("guard_asset_binding",map("asset_id",event.get("guard_asset_id"),"bundle_id",bundle.get("id"),"status","active"),false);
        if(activeBinding==null)
            return putActionability(v,false,budgetTargetId,policyId,episodeId,targetRef.isBlank()?null:targetRef,"AUTHORIZATION_INACTIVE");
        for(var act:store.rows("guard_action",map("decision_id",latestCandidateDecision.get("id")),false,20)){
            if("active".equals(str(act,"desired_state"))&&Set.of("pending","dispatched","applied").contains(str(act,"observed_state")))
                return putActionability(v,false,budgetTargetId,policyId,episodeId,targetRef.isBlank()?null:targetRef,"ACTION_ALREADY_ACTIVE");
        }
        if(targetRef.isBlank())
            return putActionability(v,false,budgetTargetId,policyId,episodeId,null,"TARGET_REF_STALE");
        return putActionability(v,true,budgetTargetId,policyId,episodeId,targetRef,null);
    }
    private static JsonNode putActionability(com.fasterxml.jackson.databind.node.ObjectNode v,boolean actionable,String budgetTargetId,String policyId,String episodeId,String targetRef,String reasonCode){
        v.put("actionable",actionable);
        if(budgetTargetId==null)v.putNull("budgetTargetId");else v.put("budgetTargetId",budgetTargetId);
        if(policyId==null)v.putNull("policyId");else v.put("policyId",policyId);
        if(episodeId==null)v.putNull("actionEpisodeId");else v.put("actionEpisodeId",episodeId);
        if(targetRef==null)v.putNull("targetRef");else v.put("targetRef",targetRef);
        if(reasonCode==null)v.putNull("actionableReasonCode");else v.put("actionableReasonCode",reasonCode);
        return v;
    }
    public JsonNode child(String collection,String id,String child){var r=store.external(table(collection),id,false);check(r,permission(collection));List<Map<String,Object>> rows;String table;
        if(collection.equals("actions")&&child.equals("receipts")){var c=store.one("guard_command",map("action_id",r.get("id")),false);if(c==null)return object("items",List.of());table="guard_action_receipt";rows=store.rows(table,map("command_id",c.get("id")),false,200);}
        else if(collection.equals("events")&&child.equals("timeline")){require(r.get("guard_asset_id")!=null,"RESOURCE_NOT_FOUND");table="event_timeline";rows=store.rows(table,map("event_id",r.get("id")),false,200);}
        else if(collection.equals("events")&&child.equals("episodes")){require(r.get("guard_asset_id")!=null,"RESOURCE_NOT_FOUND");table="guard_episode";rows=new ArrayList<>();for(var link:store.rows("guard_event_episode",map("event_id",r.get("id")),false,200))rows.add(store.get("guard_episode",number(link,"episode_id")));}
        else if(collection.equals("events")&&child.equals("actions")){require(r.get("guard_asset_id")!=null,"RESOURCE_NOT_FOUND");access.visible("action.read",number(r,"guard_asset_id"));table="guard_action";rows=new ArrayList<>();var seen=new HashSet<Long>();
            for(var link:store.rows("guard_event_episode",map("event_id",r.get("id")),false,200))for(var d:store.rows("guard_decision",map("episode_id",link.get("episode_id")),false,200))for(var a:store.rows("guard_action",map("decision_id",d.get("id")),false,200))if(seen.add(number(a,"id")))rows.add(a);
            rows.sort((a,b)->Long.compare(number(b,"id"),number(a,"id")));}
        else if(collection.equals("release-bundles")&&child.equals("bindings")){table="guard_asset_binding";rows=store.visible(table,map("bundle_id",r.get("id")),access.human(),"resource.read",200,null);}
        else if(collection.equals("models")&&child.equals("validations"))return json(r,"validation_json");
        else if(collection.equals("evidence-episodes")&&child.equals("evidence")){table="guard_episode_evidence";rows=store.rows(table,map("episode_id",r.get("id")),false,200);}
        else throw error(404,"RESOURCE_NOT_FOUND");
        return object("items",rows.stream().map(x->view(table,x)).toList());}
    private String table(String key){var t=TABLES.get(key);if(t==null)throw error(404,"RESOURCE_NOT_FOUND");return t;}
    private void check(Map<String,Object> r,String permission){
        // 全局目录与 research 会话没有资产；显式分支避免嵌套三元表达式将 null 拆箱。
        Long aid=null;
        if(r.get("asset_id")!=null)aid=number(r,"asset_id");
        else if(r.get("guard_asset_id")!=null)aid=number(r,"guard_asset_id");
        if(r.containsKey("asset_key"))aid=number(r,"id");access.visible(permission,aid);
    }
    private static final Set<String> HIDDEN=Set.of("id","query_sort_time","api_client_id","credential_ref","credential_sha256","secret_ref","stable_target_token","scope_digest","requested_by","created_by","reviewed_by","approved_by","activated_by","active_asset");
    private static final Map<String,String> REFERENCES=Map.ofEntries(Map.entry("asset_id","asset"),Map.entry("guard_asset_id","asset"),Map.entry("sensor_id","sensor_agent"),Map.entry("capture_scope_id","guard_capture_scope"),Map.entry("config_id","sensor_config"),Map.entry("batch_id","guard_observation_batch"),Map.entry("observation_id","guard_observation"),Map.entry("inference_id","guard_inference"),Map.entry("episode_id","guard_episode"),Map.entry("model_id","guard_model"),Map.entry("policy_id","guard_decision_policy"),Map.entry("plan_id","guard_evaluation_plan"),Map.entry("contract_id","guard_contract"),Map.entry("bundle_id","guard_release_bundle"),Map.entry("authorization_id","asset_authorization"),Map.entry("decision_id","guard_decision"),Map.entry("executor_id","guard_executor"),Map.entry("resolver_executor_id","guard_executor"),Map.entry("budget_target_id","guard_budget_target"),Map.entry("command_id","guard_command"),Map.entry("revocation_id","guard_revocation"),Map.entry("event_id","security_event"));
    public JsonNode view(String table,Map<String,Object> row){var n=JSON.createObjectNode();row.forEach((k,v)->{
        if(HIDDEN.contains(k))return;String name=k.equals("public_id")?"id":camel(k.endsWith("_json")?k.substring(0,k.length()-5):k);
        if(v!=null&&REFERENCES.containsKey(k))n.put(name,str(store.get(REFERENCES.get(k),((Number)v).longValue()),"public_id"));
        else if(v!=null&&k.equals("assignee_id"))n.put("assigneeId",str(store.get("sys_user",((Number)v).longValue()),"user_key"));
        else if(k.equals("assignee_id"))n.putNull("assigneeId");
        else if(v instanceof LocalDateTime t)n.put(name,t.toInstant(ZoneOffset.UTC).toString());else if(v instanceof java.util.Date t)n.put(name,t.toInstant().toString());
        else if(k.endsWith("_json")||k.equals("target_snapshot"))n.set(name,v==null?node(null):redact(parse(v.toString())));else n.set(name,node(v));});return n;}
    private static String camel(String s){StringBuilder out=new StringBuilder();boolean upper=false;for(char c:s.toCharArray()){if(c=='_')upper=true;else{out.append(upper?Character.toUpperCase(c):c);upper=false;}}return out.toString();}
    private static JsonNode redact(JsonNode n){if(n.isObject()){var copy=(com.fasterxml.jackson.databind.node.ObjectNode)n.deepCopy();copy.remove(List.of("stableTargetToken","scopeDigest","credential","privateKey"));copy.fields().forEachRemaining(e->copy.set(e.getKey(),redact(e.getValue())));return copy;}if(n.isArray()){var a=JSON.createArrayNode();n.forEach(v->a.add(redact(v)));return a;}return n;}
}
