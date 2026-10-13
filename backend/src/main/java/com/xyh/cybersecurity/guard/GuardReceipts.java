package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.stereotype.Service;
import java.time.*;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/** T5 回执先追加，再由完整实态摘要核对投影；乱序不逆转终态，未知规则先停用。 */
@Service
public class GuardReceipts {
    private final GuardStore store;private final GuardAccess access;private final GuardContracts contracts;private final GuardBudget budget;private final GuardActions actions;
    public GuardReceipts(GuardStore store,GuardAccess access,GuardContracts contracts,GuardBudget budget,GuardActions actions){this.store=store;this.access=access;this.contracts=contracts;this.budget=budget;this.actions=actions;}
    /** 断连后的历史清零证据只作追加审计；预算仍等待当前核对及连续健康证明。
     * 不用调用方声称的历史时间提前恢复额度，也不静默改写已有规则事实。
     */
    public JsonNode clearance(String executorId,JsonNode body){
        fields(body,"commandId clearedAt stateDigest","");
        var executor=access.executor(executorId,"machine.receipt.write");
        long assetId=number(executor,"asset_id");store.lockAsset(assetId);
        var command=store.external("guard_command",uuid(body,"commandId"),false);
        var action=store.get("guard_action",number(command,"action_id"));
        require(number(action,"executor_id")==number(executor,"id"),"SCOPE_DENIED");
        Instant cleared=time(body,"clearedAt");
        require(!cleared.isBefore(instant(command.get("issued_at")))&&!cleared.isAfter(store.now()),"INVALID_RECEIPT_TIME");
        digest(body,"stateDigest");
        store.audit(null,"guard.executor.clearance_reported",str(command,"public_id"),assetId,null,body);
        return object("persisted",true,"budgetReset",false);
    }
    public JsonNode heartbeat(String id,JsonNode b){fields(b,"bootId adapterVersion capabilityHash pendingRecovery activeRuleCount clockSkewMs","");var e=access.executor(id,"machine.executor.health");long aid=number(e,"asset_id");store.lockAsset(aid);e=store.external("guard_executor",id,true);uuid(b,"bootId");digest(b,"capabilityHash");bool(b,"pendingRecovery");
        if(!b.path("activeRuleCount").isNull())integer(b,"activeRuleCount",0,1000);
        boolean changed=!Objects.equals(str(e,"boot_id"),text(b,"bootId"));boolean untrusted=!b.path("clockSkewMs").isNumber()||Math.abs(b.path("clockSkewMs").asDouble())>1000||b.path("activeRuleCount").isNull()||b.path("pendingRecovery").asBoolean();
        if(changed)for(var a:store.rows("guard_action",map("executor_id",e.get("id")),true,10000))if(Set.of("dispatched","applied").contains(str(a,"observed_state")))store.update("guard_action",number(a,"id"),map("observed_state","uncertain","revision",number(a,"revision")+1));
        // 新 boot 必须先提交一次完整核对，即使自报 zero 也不能直接激活。
        String status=changed||untrusted?"pending":str(e,"status");store.update("guard_executor",number(e,"id"),map("boot_id",text(b,"bootId"),"adapter_version",text(b,"adapterVersion"),"capability_hash",text(b,"capabilityHash"),"health_json",canonical(b),"last_heartbeat",db(store.now()),"status",status,"revision",number(e,"revision")+1));
        if(untrusted)actions.stop(aid,"EXECUTOR_HEALTH_UNTRUSTED",false,null,null);return object("serverTime",store.now().toString(),"status",status);}
    public JsonNode receipt(String executorId,JsonNode b){contracts.validate("action-receipt",b);var e=access.executor(executorId,"machine.receipt.write");long aid=number(e,"asset_id");store.lockAsset(aid);require(executorId.equals(uuid(b,"executorId")),"SCOPE_DENIED");
        var command=store.external("guard_command",uuid(b,"commandId"),false);var a=store.get("guard_action",number(command,"action_id"));require(number(a,"executor_id")==number(e,"id"),"SCOPE_DENIED");
        Instant observed=time(b,"observedAt");require(!observed.isAfter(store.now())&&!observed.isBefore(instant(command.get("issued_at"))),"INVALID_RECEIPT_TIME");String hash=hash(b);
        var old=store.one("guard_action_receipt",map("public_id",uuid(b,"receiptId")),false);if(old!=null){if(!hash.equals(str(old,"content_sha256")))throw error(409,"IDEMPOTENCY_CONFLICT");return object("receiptId",old.get("public_id"),"persisted",true,"projected",old.get("projected"));}
        Map<String,Object> rev=null;if(!b.get("revocationId").isNull()){rev=store.external("guard_revocation",uuid(b,"revocationId"),false);require(number(rev,"command_id")==number(command,"id")&&number(rev,"action_id")==number(a,"id")&&number(rev,"executor_id")==number(e,"id"),"SCOPE_DENIED");}
        var row=store.insert("guard_action_receipt",map("public_id",text(b,"receiptId"),"command_id",command.get("id"),"executor_id",e.get("id"),"asset_id",aid,"revocation_id",rev==null?null:rev.get("id"),"status",text(b,"status"),"observed_at",db(observed),"state_digest",text(b,"stateDigest"),"content_sha256",hash,"payload_json",canonical(b)));
        var rec=store.one("guard_reconciliation",map("executor_id",e.get("id"),"owned_state_sha256",text(b,"stateDigest")),false);boolean projected=rec!=null&&project(row,rec,e);
        if(Set.of("uncertain","recovery_failed").contains(text(b,"status"))&&!GuardBudget.TERMINAL.contains(str(a,"observed_state"))){store.update("guard_action",number(a,"id"),map("observed_state",text(b,"status"),"revision",number(a,"revision")+1));actions.stop(aid,"RECOVERY_PENDING",false,null,null);}
        store.audit(null,"guard.receipt.persisted",str(row,"public_id"),aid,null,object("contentSha256",hash,"projected",projected));return object("receiptId",row.get("public_id"),"persisted",true,"projected",projected);}
    public JsonNode reconcile(String executorId,JsonNode b){fields(b,"executorBootId observedAt digestVersion stateDigest ownedRules pendingRevocations recoveryErrors","");var e=access.executor(executorId,"machine.receipt.write");long aid=number(e,"asset_id");var asset=store.lockAsset(aid);e=store.external("guard_executor",executorId,true);
        require(uuid(b,"executorBootId").equals(str(e,"boot_id"))&&"guard-state/1".equals(text(b,"digestVersion")),"BOOT_ID_MISMATCH");
        Instant observed=time(b,"observedAt"),now=store.now();require(!observed.isAfter(now)&&Duration.between(observed,now).toMillis()<=10000,"INVALID_RECONCILIATION_TIME");
        require(b.path("ownedRules").isArray()&&b.get("ownedRules").size()<=1000&&b.path("pendingRevocations").isArray()&&b.get("pendingRevocations").size()<=1000&&b.path("recoveryErrors").isArray()&&b.get("recoveryErrors").size()<=1000,"CAPACITY_EXCEEDED");
        var rules=new ArrayList<JsonNode>();var pending=new ArrayList<JsonNode>();var handles=new HashSet<String>();var actionIds=new HashSet<String>();int errors=b.get("recoveryErrors").size();
        for(var r:b.get("ownedRules")){fields(r,"actionId commandId ruleHandle effectiveBlockUntil normalizedScopeSha256","");uuid(r,"actionId");uuid(r,"commandId");digest(r,"normalizedScopeSha256");time(r,"effectiveBlockUntil");require(handles.add(text(r,"ruleHandle"))&&actionIds.add(text(r,"actionId")),"STATE_CONFLICT");rules.add(r);}
        for(var r:b.get("pendingRevocations")){fields(r,"revocationId actionId desiredRevision","");uuid(r,"revocationId");uuid(r,"actionId");integer(r,"desiredRevision",1,Long.MAX_VALUE);pending.add(r);}
        rules.sort(Comparator.comparing(r->r.path("ruleHandle").asText()));pending.sort(Comparator.comparing(r->r.path("revocationId").asText()));
        var normalized=object("digestVersion","guard-state/1","assetId",asset.get("public_id"),"executorId",executorId,"executorBootId",e.get("boot_id"),"rules",rules,"pendingRevocations",pending);
        require(hash(normalized).equals(digest(b,"stateDigest")),"STATE_DIGEST_MISMATCH");
        var latest=store.one("guard_reconciliation",map("executor_id",e.get("id")),false);
        if(latest!=null&&observed.isBefore(instant(latest.get("observed_at"))))throw error(409,"STALE_RECONCILIATION");
        for(var r:rules){var a=store.one("guard_action",map("public_id",text(r,"actionId")),false);var c=store.one("guard_command",map("public_id",text(r,"commandId")),false);
            if(a==null||c==null||number(a,"executor_id")!=number(e,"id")||number(c,"action_id")!=number(a,"id")||GuardBudget.TERMINAL.contains(str(a,"observed_state"))||!scopeHash(json(c,"payload_json")).equals(text(r,"normalizedScopeSha256"))||!time(r,"effectiveBlockUntil").equals(instant(a.get("block_until"))))errors++;
        }
        for(var p:pending){var r=store.one("guard_revocation",map("public_id",text(p,"revocationId")),false);if(r==null||number(r,"executor_id")!=number(e,"id")||number(r,"desired_revision")!=p.path("desiredRevision").asLong()||!str(store.get("guard_action",number(r,"action_id")),"public_id").equals(text(p,"actionId")))errors++;}
        var rec=store.add("guard_reconciliation",map("executor_id",e.get("id"),"asset_id",aid,"boot_id",e.get("boot_id"),"observed_at",db(observed),"owned_state_sha256",text(b,"stateDigest"),"payload_json",canonical(b),"error_count",errors));
        if(errors>0){store.update("guard_executor",number(e,"id"),map("status","suspended","revision",number(e,"revision")+1));actions.stop(aid,"STATE_RECONCILIATION_FAILED",false,null,null);}
        else {
            JsonNode hb=json(e,"health_json");boolean healthy=!hb.path("pendingRecovery").asBoolean(true)&&hb.path("clockSkewMs").isNumber()&&Math.abs(hb.path("clockSkewMs").asDouble())<=1000&&hb.path("activeRuleCount").isIntegralNumber()&&hb.path("activeRuleCount").asInt()==rules.size();
            if(healthy&&e.get("last_heartbeat")!=null&&Duration.between(instant(e.get("last_heartbeat")),now).toMillis()<=10000)store.update("guard_executor",number(e,"id"),map("status","active","revision",number(e,"revision")+1));
            for(var receipt:store.rows("guard_action_receipt",map("executor_id",e.get("id"),"state_digest",text(b,"stateDigest"),"projected",false),true,10000))project(receipt,rec,e);
            // 不存在规则仍不能撤销尚可应用的命令；越过 applyBy 的完整枚举才证明后续不会迟到应用。
            for(var a:store.rows("guard_action",map("executor_id",e.get("id")),true,10000)){
                if(GuardBudget.TERMINAL.contains(str(a,"observed_state"))||actionIds.contains(str(a,"public_id")))continue;
                var c=store.one("guard_command",map("action_id",a.get("id")),false);if(c==null||observed.isBefore(instant(c.get("apply_by"))))continue;
                String status="revoked".equals(str(a,"desired_state"))?"revoked":"expired";
                if(status.equals("expired")&&observed.isBefore(instant(a.get("block_until"))))continue;
                terminal(a,status,observed,text(b,"stateDigest"),false);
            }
        }
        store.audit(null,"guard.executor.reconciled",str(rec,"public_id"),aid,null,object("stateDigest",text(b,"stateDigest"),"errorCount",errors));return object("id",rec.get("public_id"),"errorCount",errors,"status",errors==0?"verified":"suspended");}
    public static String scopeHash(JsonNode payload){return hash(object("assetId",payload.get("assetId"),"sensorId",payload.get("sensorId"),"bootId",payload.get("bootId"),"captureScopeId",payload.get("captureScopeId"),"targetRef",payload.get("targetRef"),"peerKey",payload.get("peerKey"),"keyEpoch",payload.get("keyEpoch"),"environment",payload.get("environment"),"scope",payload.get("scope"),"addressFamily",payload.get("addressFamily"),"direction",payload.get("direction"),"transport",payload.get("transport"),"servicePort",payload.get("servicePort")));}
    private boolean project(Map<String,Object> receipt,Map<String,Object> rec,Map<String,Object> executor){
        if(number(rec,"error_count")!=0||instant(rec.get("observed_at")).isBefore(instant(receipt.get("observed_at")))||!str(rec,"boot_id").equals(str(executor,"boot_id")))return false;
        var command=store.get("guard_command",number(receipt,"command_id"));var a=store.get("guard_action",number(command,"action_id"));
        String status=str(receipt,"status");JsonNode payload=json(receipt,"payload_json"),rule=null;for(var r:json(rec,"payload_json").path("ownedRules"))if(str(a,"public_id").equals(r.path("actionId").asText())&&str(command,"public_id").equals(r.path("commandId").asText()))rule=r;
        if(GuardBudget.TERMINAL.contains(str(a,"observed_state"))){
            // 执行器取出待发回执后、核对前，独立恢复器可能按 TTL 清除规则：核对先按完整枚举把动作判为终态，
            // 同一清除的回执晚一轮到达。与动作终态相同、核对中规则已不存在的回执只补记已核验，不重复终止或计费。
            if(!status.equals(str(a,"observed_state"))||rule!=null||status.equals("expired")&&instant(receipt.get("observed_at")).isBefore(instant(a.get("block_until"))))return false;
            if(status.equals("revoked")&&receipt.get("revocation_id")==null)return false;
            store.update("guard_action_receipt",number(receipt,"id"),map("projected",true));return true;
        }
        if(status.equals("applied")){
            if(rule==null||"revoked".equals(str(a,"desired_state"))||!str(command,"executor_boot_id").equals(str(executor,"boot_id"))||!payload.path("ruleHandle").equals(rule.path("ruleHandle"))||!payload.path("effectiveBlockUntil").equals(rule.path("effectiveBlockUntil")))return false;
            if(!Set.of("dispatched","uncertain","applied").contains(str(a,"observed_state")))return false;
            store.update("guard_action",number(a,"id"),map("observed_state","applied","revision",number(a,"revision")+1));
        }else if(GuardBudget.TERMINAL.contains(status)){
            if(rule!=null)return false;
            if(status.equals("expired")&&instant(receipt.get("observed_at")).isBefore(instant(a.get("block_until"))))return false;
            if(status.equals("revoked")&&(receipt.get("revocation_id")==null||!"revoked".equals(str(a,"desired_state"))))return false;
            terminal(a,status,instant(rec.get("observed_at")),str(rec,"owned_state_sha256"),status.equals("rejected"));
        }else return false;
        store.update("guard_action_receipt",number(receipt,"id"),map("projected",true));return true;
    }
    private void terminal(Map<String,Object> action,String status,Instant at,String proof,boolean neverApplied){
        store.update("guard_action",number(action,"id"),map("observed_state",status,"revision",number(action,"revision")+1));
        for(var r:store.rows("guard_revocation",map("action_id",action.get("id"),"status","pending"),true,100))store.update("guard_revocation",number(r,"id"),map("status","confirmed"));
        budget.ended(action,at,proof,neverApplied);store.outbox("guard.action.observed",str(action,"public_id"),object("actionId",action.get("public_id"),"observedState",status));store.audit(null,"guard.action."+status,str(action,"public_id"),number(action,"asset_id"),null,object("stateDigest",proof));
    }
}
