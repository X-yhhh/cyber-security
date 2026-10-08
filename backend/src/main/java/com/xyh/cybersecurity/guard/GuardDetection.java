package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.*;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/** T2：消费、推理、对象 episode、完整决策及动作预留同一事务；重复消息不重复推理/动作。 */
@Service
public class GuardDetection {
    private final GuardStore store;private final GuardMapper mapper;private final GuardModelRuntime runtime;private final GuardBudget budget;
    private final GuardCases cases;private final GuardHealth health;private final GuardEligibility eligibility;private final GuardActions actions;
    public GuardDetection(GuardStore store,GuardMapper mapper,GuardModelRuntime runtime,GuardBudget budget,GuardHealth health,GuardEligibility eligibility,GuardActions actions,GuardCases cases){this.store=store;this.mapper=mapper;this.runtime=runtime;this.budget=budget;this.health=health;this.eligibility=eligibility;this.actions=actions;this.cases=cases;}
    @Transactional public void consume(String eventKey,String topic,JsonNode payload){
        uuid(eventKey);Map<String,Object> batch=null;
        if(topic.equals("guard.observation.accepted")){fields(payload,"batchId","");batch=store.external("guard_observation_batch",uuid(payload,"batchId"),false);store.lockAsset(number(batch,"asset_id"));}
        var prior=store.one("consumed_message",map("consumer","guard-v5","message_key",eventKey),true);if(prior!=null&&"consumed".equals(str(prior,"status")))return;
        if(prior==null)prior=store.insert("consumed_message",map("consumer","guard-v5","message_key",eventKey,"status","processing"));
        if(batch!=null){var binding=store.one("guard_asset_binding",map("asset_id",batch.get("asset_id"),"status","active"),false);
            if(binding!=null){var bundle=store.get("guard_release_bundle",number(binding,"bundle_id"));var model=store.get("guard_model",number(bundle,"model_id"));
                var observations=new ArrayList<>(store.rows("guard_observation",map("batch_id",batch.get("id")),false,100));observations.sort(Comparator.comparing(r->instant(r.get("as_of"))));
                for(var o:observations){if(store.one("guard_inference",map("observation_id",o.get("id"),"model_id",model.get("id")),false)!=null)continue;
                    JsonNode observation=json(o,"payload_json");var result=runtime.infer(model,observation,store.now());var inf=store.add("guard_inference",map("observation_id",o.get("id"),"asset_id",o.get("asset_id"),"model_id",model.get("id"),"status",result.status(),"score",result.score(),"family",result.family(),"family_scores_json",result.familyScores().isEmpty()?null:canonical(node(result.familyScores())),"applicability",result.applicability(),"manifest_sha256",model.get("manifest_sha256"),"completed_at",db(store.now()),"error_code",result.error()));
                    correlate(o,inf,bundle,binding);
                }
            }
        }
        store.update("consumed_message",number(prior,"id"),map("status","consumed","consumed_at",db(store.now())));
    }
    /** 模型类别与每条规则独立成桶；未命中事实也保留，降分和改类覆盖旧投影。 */
    public JsonNode correlate(Map<String,Object> observation,Map<String,Object> inference,Map<String,Object> bundle,Map<String,Object> binding){
        JsonNode policy=json(store.get("guard_decision_policy",number(bundle,"policy_id")),"definition_json"),o=json(observation,"payload_json");JsonNode result=object("decision","observe");
        for(JsonNode fp:policy.path("familyPolicies")){
            String family=fp.path("family").asText();JsonNode d=project(observation,inference,bundle,binding,family,"model","",false,family.equals(str(inference,"family")));if(d!=null)result=d;
        }
        for(JsonNode rule:policy.path("rulePolicies")){
            var evaluation=GuardRules.evaluate(rule,o);String ruleId=rule.path("ruleId").asText(),family=rule.path("family").asText();
            store.add("guard_rule_evaluation",map("asset_id",observation.get("asset_id"),"observation_id",observation.get("id"),"policy_id",bundle.get("policy_id"),"rule_version","host-guard-rules/1","rule_id",ruleId,"family",family,"matched",evaluation.matched(),"applicable",evaluation.applicable(),"payload_json",canonical(object("rule",rule,"value",evaluation.value(),"asOf",o.get("asOf"),"matched",evaluation.matched(),"applicable",evaluation.applicable()))));
            JsonNode d=project(observation,inference,bundle,binding,family,"rule",ruleId,evaluation.matched(),evaluation.matched());if(d!=null)result=d;
        }return result;
    }
    private JsonNode project(Map<String,Object> observation,Map<String,Object> inference,Map<String,Object> bundle,Map<String,Object> binding,String family,String detectionSource,String ruleId,boolean matched,boolean create){
        long aid=number(observation,"asset_id");var asset=store.lockAsset(aid);JsonNode o=json(observation,"payload_json");var p=store.get("guard_decision_policy",number(bundle,"policy_id"));JsonNode policy=json(p,"definition_json");Instant now=store.now();
        var target=o.path("targetRef").isNull()?null:store.one("guard_target_binding",map("target_ref",o.path("targetRef").asText()),false);Map<String,Object> targetBudget=null;
        if(target!=null){long tid=number(target,"budget_target_id");targetBudget=budget.lock(aid,tid);budget.recover(aid,tid,now);targetBudget=budget.lock(aid,tid);now=budget.monotonic(aid);}
        String scope=GuardDecisionEngine.familyPolicy(policy,family).path("scope").asText("peer_service");
        if(!latest(observation))return null;
        // 出站扫描只能按原服务记录告警；不能创建仅允许入站的全端口处置作用域。
        if(scope.equals("peer_inbound")&&!"inbound".equals(str(observation,"direction")))scope="peer_service";
        Object servicePort=scope.equals("peer_inbound")?null:observation.get("service_port");if(servicePort==null&&!scope.equals("peer_inbound"))servicePort=0;
        var key=map("asset_id",aid,"sensor_id",observation.get("sensor_id"),"boot_id",observation.get("boot_id"),"peer_key",observation.get("peer_key"),"key_epoch",observation.get("key_epoch"),"direction",observation.get("direction"),"transport",observation.get("transport"),"service_port",servicePort,"family",family,"scope",scope,"source",detectionSource,"rule_id",ruleId,"bundle_id",bundle.get("id"),"bucket_start",db(Instant.ofEpochSecond(time(o,"asOf").getEpochSecond()/30*30)));
        var episode=store.one("guard_episode",key,true);if(episode==null){if(!create)return null;episode=store.add("guard_episode",key);episode=store.get("guard_episode",number(episode,"id"));}
        var prev=store.one("guard_episode_evidence",map("episode_id",episode.get("id"),"parent_connection_id",observation.get("parent_connection_id"),"source",detectionSource,"rule_id",ruleId),true);
        var values=map("episode_id",episode.get("id"),"parent_connection_id",observation.get("parent_connection_id"),"observation_id",observation.get("id"),"inference_id",inference.get("id"),"score",detectionSource.equals("model")?inference.get("score"):null,"family",detectionSource.equals("model")?inference.get("family"):family,"source",detectionSource,"rule_id",ruleId,"rule_matched",matched,"family_scores_json",detectionSource.equals("model")?inference.get("family_scores_json"):null,"as_of",observation.get("as_of"));
        if(prev==null)store.add("guard_episode_evidence",values);else store.update("guard_episode_evidence",number(prev,"id"),values);
        store.audit(null,"guard.episode.evidence_selected",str(episode,"public_id"),aid,null,object("observationId",observation.get("public_id"),"source",detectionSource,"ruleId",ruleId,"replacedObservationId",prev==null?null:store.get("guard_observation",number(prev,"observation_id")).get("public_id")));
        List<GuardDecisionEngine.Evidence> evidence=new ArrayList<>();boolean modelAvailable=true;for(var e:store.rows("guard_episode_evidence",map("episode_id",episode.get("id")),false,10000)){
            var source=store.get("guard_observation",number(e,"observation_id"));if(!latest(source))continue;modelAvailable&="succeeded".equals(str(store.get("guard_inference",number(e,"inference_id")),"status"));evidence.add(new GuardDecisionEngine.Evidence(json(source,"payload_json"),e.get("score")==null?null:((Number)e.get("score")).doubleValue(),str(e,"family"),str(e,"source"),str(e,"rule_id"),flag(e.get("rule_matched")),str(source,"content_sha256")));}
        var executor=target==null?null:store.get("guard_executor",number(target,"executor_id"));boolean healthy=health.current(number(observation,"capture_scope_id"),now)&&!mapper.batchGap(number(observation,"sensor_id"),str(observation,"boot_id"));
        String budgetReason=target==null?null:eligibility.protection(bundle,policy,target,o,family);
        if(budgetReason==null&&target!=null)budgetReason=budget.check(aid,number(target,"budget_target_id"),policy,now,now.plusSeconds(policy.path("maxTtlSeconds").asLong()));
        boolean capable=eligibility.capability(bundle,policy,o,family)&&modelAvailable;
        boolean validTarget=eligibility.target(target,o,now,policy,family);
        boolean authorized=eligibility.authorized(asset,bundle,binding,policy,o,executor,now,family);
        // 汇总的每条快照都须满足同一目标和运行资格，不能由最后一条观察替其余证据放行。
        for(var e:evidence){JsonNode selected=e.observation();
            capable&=eligibility.capability(bundle,policy,selected,family);
            validTarget&=eligibility.target(target,selected,now,policy,family);
            healthy&=health.current(number(store.external("guard_capture_scope",selected.path("captureScopeId").asText(),false),"id"),now)
                    &&!mapper.batchGap(number(store.external("sensor_agent",selected.path("sensorId").asText(),false),"id"),selected.path("bootId").asText());
            authorized&=eligibility.authorized(asset,bundle,binding,policy,selected,executor,now,family);
        }
        var gates=new GuardDecisionEngine.Gates(capable,healthy,validTarget,authorized,budgetReason);
        var outcome=GuardDecisionEngine.evaluate(policy,evidence,now,gates,family,detectionSource,ruleId);
        if(outcome.qualifiedEvidence()&&target!=null){Instant latest=outcome.selected().stream().map(e->time(e.observation(),"asOf")).max(Comparator.naturalOrder()).orElseThrow();budget.evidence(number(target,"budget_target_id"),latest);targetBudget=budget.lock(aid,number(target,"budget_target_id"));}
        String decisionId=id();var refs=new ArrayList<JsonNode>();for(var e:outcome.selected())refs.add(object("observationId",e.observation().get("observationId"),"contentSha256",e.contentHash(),"parentConnectionId",e.observation().get("parentConnectionId"),"asOf",e.observation().get("asOf"),"family",e.family(),"source",e.source(),"ruleId",e.ruleId()));
        var auth=store.get("asset_authorization",number(binding,"authorization_id"));var model=store.get("guard_model",number(bundle,"model_id"));var capability=eligibility.matchingCapability(bundle,policy,o,family);
        JsonNode proof=object("digestVersion","guard-evidence/1","decisionContractVersion",DECISION,"protocolVersions",versions(),"decisionId",decisionId,"decisionAt",now.toString(),"family",family,"source",detectionSource,"ruleId",ruleId,"scope",scope,"environment",o.get("environment"),"modelId",model.get("public_id"),"manifestSha256",model.get("manifest_sha256"),"policySha256",p.get("definition_sha256"),"bundleId",bundle.get("public_id"),"bundleSubjectSha256",bundle.get("subject_sha256"),"capabilityId",capability==null?null:capability.get("public_id"),"capabilitySha256",capability==null?null:hash(json(capability,"payload_json")),"authorizationId",auth.get("public_id"),"authorizationRevision",auth.get("revision"),"targetBinding",target==null?null:json(target,"payload_json"),"budgetTargetId",target==null?null:store.get("guard_budget_target",number(target,"budget_target_id")).get("public_id"),"budgetRevision",targetBudget==null?null:targetBudget.get("revision"),"healthProofSha256",targetBudget==null?null:targetBudget.get("health_proof_sha256"),"labSession",null,"selectedObservations",refs,"reasonCode",outcome.reason(),"detailCode",outcome.detail());
        var decision=store.insert("guard_decision",map("public_id",decisionId,"episode_id",episode.get("id"),"asset_id",aid,"bundle_id",bundle.get("id"),"decision_revision",episode.get("revision"),"decision_contract_version",DECISION,"decision",outcome.decision(),"reason_code",outcome.reason(),"budget_target_id",target==null?null:target.get("budget_target_id"),"budget_revision",targetBudget==null?null:targetBudget.get("revision"),"evidence_sha256",hash(proof),"evidence_json",canonical(proof),"decided_at",db(now)));
        cases.detected(episode,decision);
        store.update("guard_episode",number(episode,"id"),map("revision",number(episode,"revision")+1));store.outbox("guard.decision.recorded",decisionId,object("decisionId",decisionId));
        if(outcome.reason()==null&&"block_candidate".equals(outcome.decision()))actions.create(decision,bundle,binding,target,policy,"auto",null);
        return object("id",decisionId,"episodeId",episode.get("public_id"),"decision",outcome.decision(),"reasonCode",outcome.reason(),"detailCode",outcome.detail());
    }
    /** 因果排序跨桶复核；新快照尚未消费时也使旧动作失效。 */
    private boolean latest(Map<String,Object> row){var newest=mapper.latestParent(number(row,"asset_id"),number(row,"sensor_id"),str(row,"boot_id"),str(row,"parent_connection_id"));return newest!=null&&number(newest,"id")==number(row,"id");}
    static boolean flag(Object value){return Boolean.TRUE.equals(value)||(value instanceof Number n&&n.intValue()!=0);}
}
