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
                    JsonNode observation=json(o,"payload_json");var result=runtime.infer(model,observation,store.now());var inf=store.add("guard_inference",map("observation_id",o.get("id"),"asset_id",o.get("asset_id"),"model_id",model.get("id"),"status",result.status(),"score",result.score(),"family",null,"applicability",result.applicability(),"manifest_sha256",model.get("manifest_sha256"),"completed_at",db(store.now()),"error_code",result.error()));
                    correlate(o,inf,bundle,binding);
                }
            }
        }
        store.update("consumed_message",number(prior,"id"),map("status","consumed","consumed_at",db(store.now())));
    }
    public JsonNode correlate(Map<String,Object> observation,Map<String,Object> inference,Map<String,Object> bundle,Map<String,Object> binding){
        long aid=number(observation,"asset_id");var asset=store.lockAsset(aid);JsonNode o=json(observation,"payload_json");var p=store.get("guard_decision_policy",number(bundle,"policy_id"));JsonNode policy=json(p,"definition_json");Instant now=store.now();
        var target=o.path("targetRef").isNull()?null:store.one("guard_target_binding",map("target_ref",o.path("targetRef").asText()),false);Map<String,Object> targetBudget=null;
        if(target!=null){long tid=number(target,"budget_target_id");targetBudget=budget.lock(aid,tid);budget.recover(aid,tid,now);targetBudget=budget.lock(aid,tid);now=budget.monotonic(aid);}
        var key=map("asset_id",aid,"sensor_id",observation.get("sensor_id"),"boot_id",observation.get("boot_id"),"peer_key",observation.get("peer_key"),"key_epoch",observation.get("key_epoch"),"direction",observation.get("direction"),"transport",observation.get("transport"),"service_port",observation.get("service_port")==null?0:observation.get("service_port"),"family",text(policy,"family"),"bundle_id",bundle.get("id"),"bucket_start",db(Instant.ofEpochSecond(time(o,"asOf").getEpochSecond()/30*30)));
        var episode=store.one("guard_episode",key,true);if(episode==null){episode=store.add("guard_episode",key);episode=store.get("guard_episode",number(episode,"id"));}
        var prev=store.one("guard_episode_evidence",map("episode_id",episode.get("id"),"parent_connection_id",observation.get("parent_connection_id")),true);
        if(prev==null||time(o,"asOf").isAfter(instant(prev.get("as_of")))){
            var values=map("episode_id",episode.get("id"),"parent_connection_id",observation.get("parent_connection_id"),"observation_id",observation.get("id"),"inference_id",inference.get("id"),"score",inference.get("score"),"as_of",observation.get("as_of"));
            if(prev==null)store.add("guard_episode_evidence",values);else store.update("guard_episode_evidence",number(prev,"id"),values);
            store.audit(null,"guard.episode.evidence_selected",str(episode,"public_id"),aid,null,object("observationId",observation.get("public_id"),"replacedObservationId",prev==null?null:store.get("guard_observation",number(prev,"observation_id")).get("public_id")));
        }
        List<GuardDecisionEngine.Evidence> evidence=new ArrayList<>();for(var e:store.rows("guard_episode_evidence",map("episode_id",episode.get("id")),false,10000)){
            var source=store.get("guard_observation",number(e,"observation_id"));evidence.add(new GuardDecisionEngine.Evidence(json(source,"payload_json"),e.get("score")==null?null:((Number)e.get("score")).doubleValue(),str(source,"content_sha256")));}
        var executor=target==null?null:store.get("guard_executor",number(target,"executor_id"));boolean healthy=health.current(number(observation,"capture_scope_id"),now)&&!mapper.batchGap(number(observation,"sensor_id"),str(observation,"boot_id"));
        String budgetReason=target==null?null:eligibility.protection(policy,target,o);
        if(budgetReason==null&&target!=null)budgetReason=budget.check(aid,number(target,"budget_target_id"),policy,now,now.plusSeconds(policy.path("maxTtlSeconds").asLong()));
        var gates=new GuardDecisionEngine.Gates(eligibility.capability(bundle,policy,o),healthy,eligibility.target(target,o,now),eligibility.authorized(asset,bundle,binding,policy,o,executor,now),budgetReason);
        var outcome=GuardDecisionEngine.evaluate(policy,evidence,now,gates);
        if(outcome.qualifiedEvidence()&&target!=null){Instant latest=outcome.selected().stream().map(e->time(e.observation(),"asOf")).max(Comparator.naturalOrder()).orElseThrow();budget.evidence(number(target,"budget_target_id"),latest);targetBudget=budget.lock(aid,number(target,"budget_target_id"));}
        String decisionId=id();var refs=new ArrayList<JsonNode>();for(var e:outcome.selected())refs.add(object("observationId",e.observation().get("observationId"),"contentSha256",e.contentHash(),"parentConnectionId",e.observation().get("parentConnectionId"),"asOf",e.observation().get("asOf")));
        var auth=store.get("asset_authorization",number(binding,"authorization_id"));var model=store.get("guard_model",number(bundle,"model_id"));var capability=eligibility.matchingCapability(bundle,policy,o);
        JsonNode proof=object("digestVersion","guard-evidence/1","decisionContractVersion",DECISION,"protocolVersions",versions(),"decisionId",decisionId,"decisionAt",now.toString(),"environment",o.get("environment"),"modelId",model.get("public_id"),"manifestSha256",model.get("manifest_sha256"),"policySha256",p.get("definition_sha256"),"bundleId",bundle.get("public_id"),"bundleSubjectSha256",bundle.get("subject_sha256"),"capabilityId",capability==null?null:capability.get("public_id"),"capabilitySha256",capability==null?null:hash(json(capability,"payload_json")),"authorizationId",auth.get("public_id"),"authorizationRevision",auth.get("revision"),"targetBinding",target==null?null:json(target,"payload_json"),"budgetTargetId",target==null?null:store.get("guard_budget_target",number(target,"budget_target_id")).get("public_id"),"budgetRevision",targetBudget==null?null:targetBudget.get("revision"),"healthProofSha256",targetBudget==null?null:targetBudget.get("health_proof_sha256"),"labSession",null,"selectedObservations",refs,"reasonCode",outcome.reason(),"detailCode",outcome.detail());
        var decision=store.insert("guard_decision",map("public_id",decisionId,"episode_id",episode.get("id"),"asset_id",aid,"bundle_id",bundle.get("id"),"decision_revision",episode.get("revision"),"decision_contract_version",DECISION,"decision",outcome.decision(),"reason_code",outcome.reason(),"budget_target_id",target==null?null:target.get("budget_target_id"),"budget_revision",targetBudget==null?null:targetBudget.get("revision"),"evidence_sha256",hash(proof),"evidence_json",canonical(proof),"decided_at",db(now)));
        cases.detected(episode,decision);
        store.update("guard_episode",number(episode,"id"),map("revision",number(episode,"revision")+1));store.outbox("guard.decision.recorded",decisionId,object("decisionId",decisionId));
        if(outcome.reason()==null&&"block_candidate".equals(outcome.decision()))actions.create(decision,bundle,binding,target,policy,"auto",null);
        return object("id",decisionId,"episodeId",episode.get("public_id"),"decision",outcome.decision(),"reasonCode",outcome.reason(),"detailCode",outcome.detail());
    }
}
