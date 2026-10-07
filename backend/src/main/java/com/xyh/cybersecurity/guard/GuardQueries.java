package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.stereotype.Service;
import java.time.*;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/** 资源范围谓词在 SQL LIMIT 之前执行；API 只暴露外部 UUID，不返回目标 token 或机器凭据。 */
@Service
public class GuardQueries {
    private final GuardStore store;private final GuardAccess access;
    public GuardQueries(GuardStore store,GuardAccess access){this.store=store;this.access=access;}
    private static final Map<String,String> TABLES=Map.ofEntries(Map.entry("assets","asset"),Map.entry("sensors","sensor_agent"),Map.entry("executors","guard_executor"),Map.entry("models","guard_model"),Map.entry("datasets","guard_dataset"),Map.entry("evaluation-plans","guard_evaluation_plan"),Map.entry("evaluations","guard_evaluation_run"),Map.entry("decision-policies","guard_decision_policy"),Map.entry("release-bundles","guard_release_bundle"),Map.entry("capabilities","guard_capability"),Map.entry("observation-batches","guard_observation_batch"),Map.entry("observations","guard_observation"),Map.entry("detections","guard_inference"),Map.entry("evidence-episodes","guard_episode"),Map.entry("decisions","guard_decision"),Map.entry("actions","guard_action"),Map.entry("budget-targets","guard_budget_target"),Map.entry("events","security_event"),Map.entry("feedback","guard_feedback"));
    public static String permission(String collection){return switch(collection){case "observation-batches","observations","detections","evidence-episodes","decisions","events","feedback"->"detection.read";case "actions","budget-targets"->"action.read";case "evaluations","evaluation-plans"->"evaluation.read";default->"resource.read";};}
    public JsonNode list(String collection,String assetId,String cursor,int limit){String table=table(collection);require(limit>=1&&limit<=200,"INVALID_PAGE_SIZE");long actor=access.human();String perm=permission(collection);Map<String,Object> where=map();
        if(assetId!=null){var asset=store.external("asset",uuid(assetId),false);access.visible(perm,number(asset,"id"));where.put(collection.equals("assets")?"id":collection.equals("events")?"guard_asset_id":"asset_id",asset.get("id"));}
        if(Set.of("models","datasets","evaluation-plans","evaluations","decision-policies","release-bundles","capabilities").contains(collection))access.permission(perm,null);
        Long before=null;if(cursor!=null){var c=store.external(table,uuid(cursor),false);check(c,perm);before=number(c,"id");}
        var rows=store.visible(table,where,actor,perm,limit+1,before);List<JsonNode> items=new ArrayList<>();for(int i=0;i<Math.min(limit,rows.size());i++)items.add(view(table,rows.get(i)));
        return object("items",items,"nextCursor",rows.size()>limit?str(rows.get(limit-1),"public_id"):null);}
    public JsonNode get(String collection,String id){String table=table(collection);var r=store.external(table,id,false);check(r,permission(collection));
        if(collection.equals("budget-targets")){var b=store.one("guard_target_budget",map("budget_target_id",r.get("id")),false);var v=(com.fasterxml.jackson.databind.node.ObjectNode)view("guard_target_budget",b);v.put("id",id);return v;}
        return view(table,r);}
    public JsonNode child(String collection,String id,String child){var r=store.external(table(collection),id,false);check(r,permission(collection));List<Map<String,Object>> rows;String table;
        if(collection.equals("actions")&&child.equals("receipts")){var c=store.one("guard_command",map("action_id",r.get("id")),false);if(c==null)return object("items",List.of());table="guard_action_receipt";rows=store.rows(table,map("command_id",c.get("id")),false,200);}
        else if(collection.equals("events")&&child.equals("timeline")){table="event_timeline";rows=store.rows(table,map("event_id",r.get("id")),false,200);}
        else if(collection.equals("models")&&child.equals("validations"))return json(r,"validation_json");
        else if(collection.equals("evidence-episodes")&&child.equals("evidence")){table="guard_episode_evidence";rows=store.rows(table,map("episode_id",r.get("id")),false,200);}
        else throw error(404,"RESOURCE_NOT_FOUND");
        return object("items",rows.stream().map(x->view(table,x)).toList());}
    private String table(String key){var t=TABLES.get(key);if(t==null)throw error(404,"RESOURCE_NOT_FOUND");return t;}
    private void check(Map<String,Object> r,String permission){Long aid=r.get("asset_id")==null?(r.get("guard_asset_id")==null?null:number(r,"guard_asset_id")):number(r,"asset_id");if(r.containsKey("asset_key"))aid=number(r,"id");access.visible(permission,aid);}
    private static final Set<String> HIDDEN=Set.of("id","api_client_id","credential_ref","credential_sha256","secret_ref","stable_target_token","scope_digest","requested_by","created_by","reviewed_by","approved_by","activated_by","active_asset");
    private static final Map<String,String> REFERENCES=Map.ofEntries(Map.entry("asset_id","asset"),Map.entry("guard_asset_id","asset"),Map.entry("sensor_id","sensor_agent"),Map.entry("capture_scope_id","guard_capture_scope"),Map.entry("config_id","sensor_config"),Map.entry("batch_id","guard_observation_batch"),Map.entry("observation_id","guard_observation"),Map.entry("inference_id","guard_inference"),Map.entry("episode_id","guard_episode"),Map.entry("model_id","guard_model"),Map.entry("policy_id","guard_decision_policy"),Map.entry("plan_id","guard_evaluation_plan"),Map.entry("contract_id","guard_contract"),Map.entry("bundle_id","guard_release_bundle"),Map.entry("authorization_id","asset_authorization"),Map.entry("decision_id","guard_decision"),Map.entry("executor_id","guard_executor"),Map.entry("resolver_executor_id","guard_executor"),Map.entry("budget_target_id","guard_budget_target"),Map.entry("command_id","guard_command"),Map.entry("revocation_id","guard_revocation"),Map.entry("event_id","security_event"));
    public JsonNode view(String table,Map<String,Object> row){var n=JSON.createObjectNode();row.forEach((k,v)->{
        if(HIDDEN.contains(k))return;String name=k.equals("public_id")?"id":camel(k.endsWith("_json")?k.substring(0,k.length()-5):k);
        if(v!=null&&REFERENCES.containsKey(k))n.put(name,str(store.get(REFERENCES.get(k),((Number)v).longValue()),"public_id"));
        else if(v instanceof LocalDateTime t)n.put(name,t.toInstant(ZoneOffset.UTC).toString());else if(v instanceof java.util.Date t)n.put(name,t.toInstant().toString());
        else if(k.endsWith("_json")||k.equals("target_snapshot"))n.set(name,v==null?node(null):redact(parse(v.toString())));else n.set(name,node(v));});return n;}
    private static String camel(String s){StringBuilder out=new StringBuilder();boolean upper=false;for(char c:s.toCharArray()){if(c=='_')upper=true;else{out.append(upper?Character.toUpperCase(c):c);upper=false;}}return out.toString();}
    private static JsonNode redact(JsonNode n){if(n.isObject()){var copy=(com.fasterxml.jackson.databind.node.ObjectNode)n.deepCopy();copy.remove(List.of("stableTargetToken","scopeDigest","credential","privateKey"));copy.fields().forEachRemaining(e->copy.set(e.getKey(),redact(e.getValue())));return copy;}if(n.isArray()){var a=JSON.createArrayNode();n.forEach(v->a.add(redact(v)));return a;}return n;}
}
