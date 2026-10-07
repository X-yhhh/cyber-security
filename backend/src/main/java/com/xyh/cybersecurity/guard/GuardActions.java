package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.stereotype.Service;
import java.time.*;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/** 动作/预算/outbox 原子预留、独立批准及固定租约命令；无 OS 证明不发布成功终态。 */
@Service
public class GuardActions {
    private final GuardMapper mapper;private final GuardStore store;private final GuardAccess access;private final GuardBudget budget;private final GuardEligibility eligibility;private final GuardHealth health;private final GuardSignatures signatures;private final GuardContracts contracts;
    public GuardActions(GuardMapper mapper,GuardStore store,GuardAccess access,GuardBudget budget,GuardEligibility eligibility,GuardHealth health,GuardSignatures signatures,GuardContracts contracts){this.mapper=mapper;this.store=store;this.access=access;this.budget=budget;this.eligibility=eligibility;this.health=health;this.signatures=signatures;this.contracts=contracts;}
    public Map<String,Object> create(Map<String,Object> decision,Map<String,Object> bundle,Map<String,Object> binding,Map<String,Object> target,JsonNode policy,String mode,Long creator){
        long aid=number(decision,"asset_id"),tid=number(target,"budget_target_id");var state=budget.lock(aid,tid);Instant now=budget.monotonic(aid),until=now.plusSeconds(Math.min(60,policy.path("maxTtlSeconds").asLong()));
        require("block_candidate".equals(str(decision,"decision")),"ACTION_EVIDENCE_REQUIRED");String reason=budget.check(aid,tid,policy,now,until);require(reason==null,"PROTECTION_OR_BUDGET_BLOCKED");
        JsonNode proof=json(decision,"evidence_json");require(proof.path("selectedObservations").isArray()&&!proof.get("selectedObservations").isEmpty(),"ACTION_EVIDENCE_REQUIRED");
        String id=id();var row=store.insert("guard_action",map("public_id",id,"decision_id",decision.get("id"),"asset_id",aid,"executor_id",target.get("executor_id"),"budget_target_id",tid,"budget_revision",number(state,"revision")+1,"bundle_id",bundle.get("id"),"authorization_id",binding.get("authorization_id"),"authorization_revision",binding.get("authorization_revision"),"mode",mode,"idempotency_key",id,"target_snapshot",canonical(json(target,"payload_json")),"block_until",db(until),"created_at",db(now),"created_by",creator));
        budget.reserve(aid,tid,number(row,"id"),now,until);store.outbox("guard.action.requested",id,object("actionId",id));store.audit(creator,"guard.action.reserved",id,aid,null,object("evidenceSha256",decision.get("evidence_sha256")));return row;
    }
    public JsonNode manual(JsonNode b){fields(b,"episodeId targetRef policyId reason","");var episode=store.external("guard_episode",uuid(b,"episodeId"),false);long aid=number(episode,"asset_id");access.permission("action.request",aid);store.lockAsset(aid);text(b,"reason");var bundle=store.get("guard_release_bundle",number(episode,"bundle_id"));var p=store.external("guard_decision_policy",uuid(b,"policyId"),false);require(number(p,"id")==number(bundle,"policy_id"),"RELEASE_COMBINATION_INVALID");
        var d=store.one("guard_decision",map("episode_id",episode.get("id")),false);require(d!=null&&"block_candidate".equals(str(d,"decision")),"ACTION_EVIDENCE_REQUIRED");
        var target=store.one("guard_target_binding",map("target_ref",uuid(b,"targetRef")),false);require(target!=null&&Objects.equals(d.get("budget_target_id"),target.get("budget_target_id")),"SCOPE_DENIED");
        var binding=store.one("guard_asset_binding",map("asset_id",aid,"bundle_id",bundle.get("id"),"status","active"),false);require(binding!=null,"AUTHORIZATION_INACTIVE");
        recheck(d,bundle,binding,target,json(p,"definition_json"),store.now());var action=create(d,bundle,binding,target,json(p,"definition_json"),"manual",access.human());return object("id",action.get("public_id"),"observedState","pending","desiredState","active","revision",1);}
    public JsonNode approve(String id,JsonNode b,String revision){var a=store.external("guard_action",id,false);long aid=number(a,"asset_id");access.permission("authorization.approve",aid);store.lockAsset(aid);a=store.external("guard_action",id,true);access.revision(a,revision);GuardAdministration.decisionBody(b);require("manual".equals(str(a,"mode"))&&"pending".equals(str(a,"observed_state"))&&a.get("approved_by")==null,"STATE_CONFLICT");access.different(a,"created_by");
        if("reject".equals(text(b,"decision"))){terminateUnsigned(a,"rejected");return object("id",id,"observedState","rejected");}
        checkedAction(a,store.now());store.update("guard_action",number(a,"id"),map("approved_by",access.human(),"revision",number(a,"revision")+1));store.audit(access.human(),"guard.action.approved",id,aid,null,b);return object("id",id,"observedState","pending","revision",number(a,"revision")+1);}
    public JsonNode revoke(String id,JsonNode b,String revision){fields(b,"reason","");text(b,"reason");var a=store.external("guard_action",id,false);long aid=number(a,"asset_id");access.permission("action.revoke",aid);store.lockAsset(aid);a=store.external("guard_action",id,true);access.revision(a,revision);revoke(a,"USER_REVOKED",access.human());return object("id",id,"desiredState","revoked","observedState",store.get("guard_action",number(a,"id")).get("observed_state"));}
    public void revoke(Map<String,Object> a,String reason,Long actor){if("revoked".equals(str(a,"desired_state")))return;long rev=number(a,"desired_revision")+1;store.update("guard_action",number(a,"id"),map("desired_state","revoked","desired_revision",rev,"revision",number(a,"revision")+1));
        var command=store.one("guard_command",map("action_id",a.get("id")),true);
        if(command==null){terminateUnsigned(a,"revoked");return;}
        var executor=store.get("guard_executor",number(a,"executor_id"));var asset=store.get("asset",number(a,"asset_id"));String id=id();var payload=object("revocationId",id,"actionId",a.get("public_id"),"commandId",command.get("public_id"),"executorId",executor.get("public_id"),"assetId",asset.get("public_id"),"environment",asset.get("environment"),"desiredRevision",rev,"issuedAt",store.now().toString(),"reasonCode",reason);
        store.insert("guard_revocation",map("public_id",id,"action_id",a.get("id"),"command_id",command.get("id"),"executor_id",a.get("executor_id"),"desired_revision",rev,"payload_json",canonical(payload),"content_sha256",hash(payload)));
        store.outbox("guard.action.revoked",str(a,"public_id"),object("actionId",a.get("public_id"),"revocationId",id));store.audit(actor,"guard.action.revocation_requested",str(a,"public_id"),number(a,"asset_id"),null,payload);
    }
    public void stop(long aid,String reason,boolean revoke,Long actor,Long bundleId){store.lockAsset(aid);
        store.add("guard_automation_stop",map("asset_id",aid,"bundle_id",bundleId,"reason",reason,"requested_by",actor,"revoke_existing",revoke));
        for(var b:store.rows("guard_asset_binding",map("asset_id",aid,"status","active"),true,100)){if(bundleId==null||number(b,"bundle_id")==bundleId)store.update("guard_asset_binding",number(b,"id"),map("status","suspended","revision",number(b,"revision")+1));}
        if(revoke)for(var a:store.rows("guard_action",map("asset_id",aid),true,10000))if(!GuardBudget.TERMINAL.contains(str(a,"observed_state"))&&(bundleId==null||number(a,"bundle_id")==bundleId))revoke(a,"AUTOMATION_STOPPED",actor);
        store.audit(actor,"guard.automation.stopped",store.get("asset",aid).get("public_id").toString(),aid,null,object("reason",reason,"revokeExisting",revoke));}
    public JsonNode stop(JsonNode b){fields(b,"assetIds reason revokeExisting","");text(b,"reason");bool(b,"revokeExisting");require(b.path("assetIds").isArray()&&!b.get("assetIds").isEmpty()&&b.get("assetIds").size()<=32,"INVALID_REQUEST");var assets=new TreeSet<Long>();for(var id:b.get("assetIds")){var a=store.external("asset",uuid(id.asText()),false);access.permission("automation.stop",number(a,"id"));assets.add(number(a,"id"));}
        for(long id:assets)stop(id,text(b,"reason"),bool(b,"revokeExisting"),access.human(),null);return object("status","accepted");}
    public JsonNode suspend(String id,JsonNode b,String revision){fields(b,"reason revokeExisting","");access.permission("automation.stop",null);text(b,"reason");bool(b,"revokeExisting");var bundle=store.external("guard_release_bundle",id,false);access.revision(bundle,revision);
        var bindings=store.rows("guard_asset_binding",map("bundle_id",bundle.get("id")),false,10000);var assets=new TreeSet<Long>();bindings.forEach(x->assets.add(number(x,"asset_id")));for(long aid:assets)stop(aid,text(b,"reason"),bool(b,"revokeExisting"),access.human(),number(bundle,"id"));
        bundle=store.external("guard_release_bundle",id,true);access.revision(bundle,revision);store.update("guard_release_bundle",number(bundle,"id"),map("status","suspended","revision",number(bundle,"revision")+1));return object("id",id,"status","suspended","revision",number(bundle,"revision")+1);}
    public JsonNode revokeAuthorization(String id,JsonNode b,String revision){fields(b,"reason","");var a=store.external("asset_authorization",id,false);long aid=number(a,"asset_id");access.permission("authorization.approve",aid);store.lockAsset(aid);a=store.external("asset_authorization",id,true);access.revision(a,revision);text(b,"reason");
        store.update("asset_authorization",number(a,"id"),map("status","revoked","revision",number(a,"revision")+1,"revoked_by",access.human(),"revoked_at",db(store.now()),"revoke_reason",text(b,"reason")));stop(aid,"AUTHORIZATION_REVOKED",true,access.human(),null);return object("id",id,"status","revoked","revision",number(a,"revision")+1);}
    public JsonNode claims(String executorId,JsonNode b){fields(b,"bootId capabilityHash maxItems waitSeconds","");var e=access.executor(executorId,"machine.command.claim");long aid=number(e,"asset_id");store.lockAsset(aid);e=store.external("guard_executor",executorId,true);require(uuid(b,"bootId").equals(str(e,"boot_id")),"BOOT_ID_MISMATCH");require(digest(b,"capabilityHash").equals(str(e,"capability_hash")),"CAPABILITY_NOT_SUPPORTED");int limit=(int)integer(b,"maxItems",1,10);integer(b,"waitSeconds",0,5);
        var revocations=JSON.createArrayNode();for(var r:store.rows("guard_revocation",map("executor_id",e.get("id"),"status","pending"),true,limit))revocations.add(json(r,"payload_json"));var commands=JSON.createArrayNode();
        if(revocations.size()<limit)for(var a:store.rows("guard_action",map("executor_id",e.get("id"),"desired_state","active"),true,1000)){
            if(commands.size()+revocations.size()>=limit)break;if(GuardBudget.TERMINAL.contains(str(a,"observed_state"))||"uncertain".equals(str(a,"observed_state"))||"recovery_failed".equals(str(a,"observed_state")))continue;
            if("manual".equals(str(a,"mode"))&&a.get("approved_by")==null)continue;
            Instant now=store.now();var old=store.one("guard_command",map("action_id",a.get("id")),true);
            if(old!=null){
                if(!instant(old.get("apply_by")).isAfter(now)||!Objects.equals(str(old,"executor_boot_id"),str(e,"boot_id"))){if("dispatched".equals(str(a,"observed_state")))store.update("guard_action",number(a,"id"),map("observed_state","uncertain","revision",number(a,"revision")+1));continue;}
                try{checkedAction(a,now);commands.add(envelope(old));}
                catch(com.xyh.cybersecurity.common.api.ApiRequestException ex){revoke(a,ex.code(),null);}
                continue;
            }
            try{
                if(!instant(a.get("block_until")).isAfter(now.plusMillis(1))){terminateUnsigned(a,"expired");continue;}
                Checked checked=checkedAction(a,now);var auth=store.get("asset_authorization",number(a,"authorization_id"));Instant until=instant(a.get("block_until"));require(!until.isAfter(instant(auth.get("valid_until"))),"AUTHORIZATION_INACTIVE");
                Instant apply=now.plusSeconds(5);if(!apply.isBefore(until))apply=until.minusMillis(1);require(!apply.isBefore(now),"COMMAND_EXPIRED");
                var target=json(a,"target_snapshot");String commandId=id();JsonNode policyBody=json(checked.policyRow,"definition_json");String scope=GuardDecisionEngine.familyPolicy(policyBody,decisionFamily(checked.decision,policyBody)).path("scope").asText("peer_service");Object servicePort=scope.equals("peer_inbound")?null:target.get("servicePort");var payload=object("contractVersion",ACTION_CONTRACT,"commandId",commandId,"actionId",a.get("public_id"),"executorId",executorId,"executorBootId",e.get("boot_id"),"assetId",checked.asset.get("public_id"),"sensorId",target.get("sensorId"),"bootId",target.get("collectorBootId"),"captureScopeId",target.get("captureScopeId"),"targetRef",target.get("targetRef"),"peerKey",target.get("peerKey"),"keyEpoch",target.get("keyEpoch"),"environment",checked.asset.get("environment"),"actionType","temporary_block","scope",scope,"addressFamily",target.get("addressFamily"),"direction",target.get("direction"),"transport",target.get("transport"),"servicePort",servicePort,"capabilityId",checked.capability.get("public_id"),"bundleId",checked.bundle.get("public_id"),"policySha256",checked.policyRow.get("definition_sha256"),"evidenceSha256",checked.decision.get("evidence_sha256"),"authorizationId",auth.get("public_id"),"authorizationRevision",auth.get("revision"),"issuedAt",now.toString(),"applyBy",apply.toString(),"leaseExpiresAt",until.toString(),"blockUntil",until.toString(),"idempotencyKey",a.get("idempotency_key"));
                JsonNode signed=signatures.sign(payload);contracts.validate("action-command",signed);
                var command=store.insert("guard_command",map("public_id",commandId,"action_id",a.get("id"),"executor_boot_id",e.get("boot_id"),"payload_json",canonical(payload),"payload_sha256",hash(payload),"key_id",text(signed,"keyId"),"signature",text(signed,"signature"),"issued_at",db(now),"apply_by",db(apply),"lease_expires_at",db(until)));
                store.add("guard_authorization_lease",map("command_id",command.get("id"),"authorization_id",auth.get("id"),"revision",auth.get("revision"),"expires_at",db(until),"status","active"));
                store.update("guard_action",number(a,"id"),map("observed_state","dispatched","revision",number(a,"revision")+1));store.audit(null,"guard.command.issued",commandId,aid,null,payload);commands.add(signed);
            }catch(com.xyh.cybersecurity.common.api.ApiRequestException ex){terminateUnsigned(a,"rejected");store.audit(null,"guard.command.rejected",str(a,"public_id"),aid,null,object("reasonCode",ex.code()));}
        }
        return object("commands",commands,"revocations",revocations,"serverTime",store.now().toString());}
    /** 重放领取响应前再次裁剪已经过期、撤销、换 boot 或失去范围的命令；签名原件不变。 */
    @org.springframework.transaction.annotation.Transactional
    public JsonNode filterClaims(String executorId,JsonNode response){
        var executor=access.executor(executorId,"machine.command.claim");store.lockAsset(number(executor,"asset_id"));var valid=JSON.createArrayNode();
        for(var envelope:response.path("commands")){
            var c=store.external("guard_command",envelope.path("payload").path("commandId").asText(),false);var a=store.get("guard_action",number(c,"action_id"));
            if(number(a,"executor_id")!=number(executor,"id")||!"active".equals(str(a,"desired_state"))||!Set.of("dispatched","applied").contains(str(a,"observed_state"))||!instant(c.get("apply_by")).isAfter(store.now())||!Objects.equals(c.get("executor_boot_id"),executor.get("boot_id")))continue;
            try{checkedAction(a,store.now());valid.add(envelope);}catch(com.xyh.cybersecurity.common.api.ApiRequestException ignored){}
        }
        return object("commands",valid,"revocations",response.path("revocations"),"serverTime",store.now().toString());
    }
    private JsonNode envelope(Map<String,Object> c){return object("payload",json(c,"payload_json"),"keyId",c.get("key_id"),"algorithm","Ed25519","signature",c.get("signature"));}
    private Checked checkedAction(Map<String,Object> action,Instant now){var asset=store.get("asset",number(action,"asset_id"));var bundle=store.get("guard_release_bundle",number(action,"bundle_id"));var decision=store.get("guard_decision",number(action,"decision_id"));var p=store.get("guard_decision_policy",number(bundle,"policy_id"));
        var binding=store.one("guard_asset_binding",map("asset_id",asset.get("id"),"bundle_id",bundle.get("id"),"status","active"),false);require(binding!=null&&number(binding,"authorization_id")==number(action,"authorization_id")&&number(binding,"authorization_revision")==number(action,"authorization_revision"),"AUTHORIZATION_INACTIVE");
        var target=store.one("guard_target_binding",map("target_ref",json(action,"target_snapshot").path("targetRef").asText()),false);require(target!=null,"TARGET_REF_STALE");JsonNode obs=recheck(decision,bundle,binding,target,json(p,"definition_json"),now);String family=decisionFamily(decision,json(p,"definition_json"));return new Checked(asset,bundle,decision,p,eligibility.matchingCapability(bundle,json(p,"definition_json"),obs,family));}
    private JsonNode recheck(Map<String,Object> decision,Map<String,Object> bundle,Map<String,Object> binding,Map<String,Object> target,JsonNode policy,Instant now){
        var references=json(decision,"evidence_json").path("selectedObservations");List<GuardDecisionEngine.Evidence> selected=new ArrayList<>();JsonNode current=null;
        String family=decisionFamily(decision,policy),source=json(decision,"evidence_json").path("source").asText("model"),ruleId=json(decision,"evidence_json").path("ruleId").asText("");
        var asset=store.get("asset",number(decision,"asset_id"));var executor=store.get("guard_executor",number(target,"executor_id"));
        boolean capable=true,healthy=true,validTarget=true,authorized=true;String protectionReason=null;
        for(var ref:references){
            var row=store.external("guard_observation",ref.path("observationId").asText(),false);require(str(row,"content_sha256").equals(ref.path("contentSha256").asText()),"EVIDENCE_STALE");
            var newest=mapper.latestParent(number(row,"asset_id"),number(row,"sensor_id"),str(row,"boot_id"),str(row,"parent_connection_id"));require(newest!=null&&number(newest,"id")==number(row,"id"),"EVIDENCE_STALE");
            var inf=store.one("guard_inference",map("observation_id",row.get("id"),"model_id",bundle.get("model_id")),false);require(inf!=null&&"succeeded".equals(str(inf,"status")),"MODEL_UNAVAILABLE");current=json(row,"payload_json");
            var latest=store.one("guard_episode_evidence",map("episode_id",decision.get("episode_id"),"parent_connection_id",row.get("parent_connection_id"),"source",source,"rule_id",ruleId),false);
            require(latest!=null&&number(latest,"observation_id")==number(row,"id")&&family.equals(str(latest,"family")),"EVIDENCE_STALE");
            boolean matched=GuardDetection.flag(latest.get("rule_matched"));
            if(source.equals("rule")){var fact=store.one("guard_rule_evaluation",map("observation_id",row.get("id"),"policy_id",bundle.get("policy_id"),"rule_id",ruleId),false);require(fact!=null&&GuardDetection.flag(fact.get("matched"))&&matched&&family.equals(str(fact,"family")),"EVIDENCE_STALE");}
            // 每条选中证据均须在领取时仍满足范围；汇总后由判定器保持 T1—T9 拒绝顺序。
            capable&=eligibility.capability(bundle,policy,current,family);
            healthy&=health.current(number(row,"capture_scope_id"),now)&&!mapper.batchGap(number(row,"sensor_id"),str(row,"boot_id"));
            validTarget&=eligibility.target(target,current,now,policy,family);
            authorized&=eligibility.authorized(asset,bundle,binding,policy,current,executor,now,family);
            String protection=eligibility.protection(policy,target,current,family);if(protectionReason==null)protectionReason=protection;
            selected.add(new GuardDecisionEngine.Evidence(current,latest.get("score")==null?null:((Number)latest.get("score")).doubleValue(),str(latest,"family"),source,ruleId,matched,str(row,"content_sha256")));
        }
        require(current!=null,"EVIDENCE_STALE");
        var gates=new GuardDecisionEngine.Gates(capable,healthy,validTarget,authorized,protectionReason);
        var outcome=GuardDecisionEngine.evaluate(policy,selected,now,gates,family,source,ruleId);require(outcome.reason()==null,outcome.reason()==null?"STATE_CONFLICT":outcome.reason());return current;}
    private static String decisionFamily(Map<String,Object> decision,JsonNode policy){for(JsonNode ref:json(decision,"evidence_json").path("selectedObservations"))if(ref.path("family").isTextual())return ref.path("family").asText();return policy.path("family").asText();}
    public void terminateUnsigned(Map<String,Object> a,String status){require(store.one("guard_command",map("action_id",a.get("id")),false)==null,"RECOVERY_PENDING");store.update("guard_action",number(a,"id"),map("observed_state",status,"revision",number(a,"revision")+1));budget.ended(a,store.now(),hash(object("actionId",a.get("public_id"),"neverIssued",true)),true);store.audit(null,"guard.action."+status,str(a,"public_id"),number(a,"asset_id"),null,object("neverIssued",true));}
    private record Checked(Map<String,Object> asset,Map<String,Object> bundle,Map<String,Object> decision,Map<String,Object> policyRow,Map<String,Object> capability){}
}
