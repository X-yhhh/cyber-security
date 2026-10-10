package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/**
 * research 回放 T2：只消费预登记片段及 sensor/boot，使用已批准 research 包。
 * T1 经 mTLS/机器凭据正常入库后独立事务处理；重试通过不可变推理事实去重。
 * 不激活发布包、不登记 executor/target、不创建动作，不借用 lab 授权。
 */
@Service
public class GuardReplay {
    private final GuardStore store;private final GuardAccess access;private final GuardArtifacts artifacts;
    private final GuardSignatures signatures;private final GuardModelRuntime runtime;private final GuardDetection detection;
    private final GuardAdministration administration;
    private final GuardMapper mapper;
    public GuardReplay(GuardStore store,GuardAccess access,GuardArtifacts artifacts,GuardSignatures signatures,
            GuardModelRuntime runtime,GuardDetection detection,GuardAdministration administration,GuardMapper mapper) {
        this.store=store;this.access=access;this.artifacts=artifacts;this.signatures=signatures;
        this.runtime=runtime;this.detection=detection;this.administration=administration;
        this.mapper=mapper;
    }

    /** 清单原字节摘要锁定片段；绑定只接受 research 传感器，拒绝任何真实目标或执行字段。 */
    public JsonNode start(String id,JsonNode b) {
        access.permission("evaluation.run",null);fields(b,"scenarioRef closeoutRef bindings","");
        var row=store.external("guard_replay_run",id,true);require("queued".equals(str(row,"status")),"STATE_CONFLICT");
        var bundle=approved(row);JsonNode scenario=artifacts.json(text(b,"scenarioRef"),str(row,"scenario_sha256"));
        var model=store.get("guard_model",number(bundle,"model_id"));var policy=store.get("guard_decision_policy",number(bundle,"policy_id"));
        require(str(row,"scenario_id").equals(uuid(scenario,"scenarioId"))&&scenario.path("segments").isArray()
                &&!scenario.path("segments").isEmpty()&&scenario.path("segments").size()<=64,"REPLAY_SCENARIO_INVALID");
        require("research".equals(text(scenario,"environment"))&&scenario.path("speed").asDouble()==1
                &&str(model,"public_id").equals(uuid(scenario,"modelId"))&&str(policy,"public_id").equals(uuid(scenario,"policyId"))
                &&str(model,"artifact_sha256").equals(digest(scenario,"modelSha256"))
                &&str(model,"manifest_sha256").equals(digest(scenario,"manifestSha256"))
                &&str(policy,"definition_sha256").equals(digest(scenario,"policySha256")),"REPLAY_BUILD_MISMATCH");
        Map<String,JsonNode> segments=new HashMap<>();
        for(JsonNode segment:scenario.path("segments")) {
            String segmentId=text(segment,"segmentId");require(segments.put(segmentId,segment)==null,"REPLAY_SCENARIO_INVALID");
            artifacts.read(text(segment,"pcapRef"),digest(segment,"pcapSha256"),256L*1024*1024);
        }
        require(b.path("bindings").isArray()&&b.path("bindings").size()==segments.size(),"REPLAY_SCENARIO_INVALID");
        Set<String> assigned=new HashSet<>(),sensors=new HashSet<>();
        for(JsonNode binding:b.path("bindings")) {
            fields(binding,"segmentId sensorId bootId","");String sid=uuid(binding,"sensorId");uuid(binding,"bootId");
            require(segments.containsKey(text(binding,"segmentId"))&&assigned.add(text(binding,"segmentId"))&&sensors.add(sid),"REPLAY_SCENARIO_INVALID");
            var sensor=store.external("sensor_agent",sid,false);long aid=number(sensor,"asset_id");access.permission("sensor.manage",aid);
            require("research".equals(str(store.get("asset",aid),"environment"))&&"active".equals(str(sensor,"status")),"REPLAY_REAL_TARGET_FORBIDDEN");
            var config=store.one("sensor_config",map("sensor_id",sensor.get("id"),"status","active"),false);
            require(config!=null,"CONFIG_INACTIVE");JsonNode def=json(config,"guard_definition_json");
            require(def.path("buildSha256").asText().equals(scenario.path("sensorSha256").asText()),"REPLAY_BUILD_MISMATCH");
            var authorization=administration.observationAuthorization(aid,def.path("interfaceIds").get(0).asText());
            require(json(authorization,"scope_json").path("executionScopes").isEmpty()
                    &&store.one("guard_executor",map("asset_id",aid),false)==null
                    &&store.one("guard_asset_binding",map("asset_id",aid,"status","active"),false)==null,"REPLAY_REAL_TARGET_FORBIDDEN");
            require(uuid(binding,"bootId").equals(str(sensor,"guard_boot_id")),"BOOT_ID_MISMATCH");
            require(number(mapper.replayBatches(number(sensor,"id"),text(binding,"bootId")),"batches")==0,"REPLAY_ALREADY_UPLOADED");
            for(var prior:store.rows("guard_replay_run",map("status","running"),false,10000))
                for(JsonNode priorBinding:json(prior,"payload_json").path("runtime").path("bindings"))
                    require(!sid.equals(priorBinding.path("sensorId").asText()),"REPLAY_SENSOR_BUSY");
        }
        String closeoutSha=closeoutSha(bundle);JsonNode closeout=artifacts.json(text(b,"closeoutRef"),closeoutSha);
        require(str(model,"artifact_sha256").equals(text(closeout,"modelSha256")),"REPLAY_ELIGIBILITY_UNVERIFIED");
        GuardReplayReadiness.policy(json(store.get("guard_decision_policy",number(bundle,"policy_id")),"definition_json"),closeout);
        ObjectNode payload=json(row,"payload_json").deepCopy();payload.set("runtime",object("scenarioRef",text(b,"scenarioRef"),
                "closeoutRef",text(b,"closeoutRef"),"closeoutSha256",closeoutSha,"bindings",b.get("bindings"),"startedAt",store.now().toString()));
        store.update("guard_replay_run",number(row,"id"),map("status","running","payload_json",canonical(payload)));
        store.audit(access.human(),"guard.replay.started",id,null,null,payload);
        return object("id",id,"status","running","segments",assigned.size());
    }

    /** 无 running 会话的 research 批次保持原有 T1 行为；仅已登记会话进入本研究 T2。 */
    @Transactional public void consume(String batchId) {
        var batch=store.external("guard_observation_batch",batchId,false);long aid=number(batch,"asset_id");
        if(!"research".equals(str(store.get("asset",aid),"environment")))return;
        store.lockAsset(aid);String sensorId=str(store.get("sensor_agent",number(batch,"sensor_id")),"public_id");
        Map<String,Object> run=null;
        for(var candidate:store.rows("guard_replay_run",map("status","running"),false,10000))
            for(JsonNode binding:json(candidate,"payload_json").path("runtime").path("bindings"))
                if(sensorId.equals(binding.path("sensorId").asText())&&str(batch,"boot_id").equals(binding.path("bootId").asText())) {
                    require(run==null,"REPLAY_SENSOR_BUSY");run=candidate;
                }
        if(run==null)return;
        var bundle=approved(run);var model=store.get("guard_model",number(bundle,"model_id"));
        JsonNode metadata=json(run,"payload_json").path("runtime");
        JsonNode closeout=artifacts.json(metadata.path("closeoutRef").asText(),metadata.path("closeoutSha256").asText());
        JsonNode hypothetical=GuardReplayReadiness.policy(json(store.get("guard_decision_policy",number(bundle,"policy_id")),"definition_json"),closeout);
        var observations=new ArrayList<>(store.rows("guard_observation",map("batch_id",batch.get("id")),false,100));
        observations.sort(Comparator.comparing((Map<String,Object> r)->instant(r.get("as_of"))).thenComparingLong(r->number(r,"id")));
        for(var observation:observations) {
            JsonNode o=json(observation,"payload_json");require("research".equals(text(o,"environment"))&&o.path("targetRef").isNull(),"REPLAY_REAL_TARGET_FORBIDDEN");
            if(store.one("guard_inference",map("observation_id",observation.get("id"),"model_id",model.get("id")),false)!=null)continue;
            var result=runtime.infer(model,o,store.now());
            var inference=store.add("guard_inference",map("observation_id",observation.get("id"),"asset_id",aid,"model_id",model.get("id"),
                    "status",result.status(),"score",result.score(),"family",result.family(),
                    "family_scores_json",result.familyScores().isEmpty()?null:canonical(node(result.familyScores())),
                    "applicability",result.applicability(),"manifest_sha256",model.get("manifest_sha256"),"completed_at",db(store.now()),"error_code",result.error()));
            detection.correlate(observation,inference,bundle,null,hypothetical);
        }
    }

    /** 运行完成与 J1 验收通过分开；报告原件须绑定本会话及冻结清单，结束后不再消费。 */
    public JsonNode finish(String id,JsonNode b) {
        access.permission("evaluation.run",null);fields(b,"reportRef reportSha256","");
        var row=store.external("guard_replay_run",id,true);require("running".equals(str(row,"status")),"STATE_CONFLICT");
        JsonNode report=artifacts.json(text(b,"reportRef"),digest(b,"reportSha256"));
        require(id.equals(uuid(report,"replayRunId"))&&str(row,"scenario_sha256").equals(digest(report,"scenarioSha256"))
                &&report.path("executionCompleted").asBoolean(),"REPLAY_REPORT_MISMATCH");
        ObjectNode payload=json(row,"payload_json").deepCopy();ObjectNode metadata=(ObjectNode)payload.get("runtime");
        require(report.path("segmentResults").isArray()&&report.path("segmentResults").size()==metadata.path("bindings").size(),"REPLAY_REPORT_MISMATCH");
        Set<String> accounted=new HashSet<>();
        for(JsonNode binding:metadata.path("bindings")){
            var sensor=store.external("sensor_agent",text(binding,"sensorId"),false);JsonNode result=null;
            for(JsonNode candidate:report.path("segmentResults"))if(text(binding,"segmentId").equals(candidate.path("segmentId").asText())){require(result==null,"REPLAY_REPORT_MISMATCH");result=candidate;}
            require(result!=null&&accounted.add(text(result,"segmentId"))&&text(binding,"sensorId").equals(text(result,"sensorId"))
                    &&text(binding,"bootId").equals(text(result,"bootId")),"REPLAY_REPORT_MISMATCH");
            var batches=mapper.replayBatches(number(sensor,"id"),text(binding,"bootId"));
            var observations=mapper.replayObservations(number(sensor,"id"),text(binding,"bootId"),number(row,"model_id"));
            require(number(batches,"batches")==integer(result,"batches",0,Long.MAX_VALUE)
                    &&number(batches,"last_sequence")==integer(result,"lastSequence",0,Long.MAX_VALUE)
                    &&number(observations,"observations")==integer(result,"observations",0,Long.MAX_VALUE)
                    &&number(observations,"inferences")==number(observations,"observations"),"REPLAY_INCOMPLETE");
        }
        metadata.set("result",b);metadata.put("finishedAt",store.now().toString());
        store.update("guard_replay_run",number(row,"id"),map("status","completed","payload_json",canonical(payload)));
        store.audit(access.human(),"guard.replay.completed",id,null,null,b);return object("id",id,"status","completed");
    }

    private Map<String,Object> approved(Map<String,Object> run) {
        var bundle=store.get("guard_release_bundle",number(run,"bundle_id"));
        require("research".equals(str(bundle,"environment"))&&"approved".equals(str(bundle,"status")),"REPLAY_BUNDLE_NOT_APPROVED");
        require("validated".equals(str(store.get("guard_model",number(bundle,"model_id")),"validation_status"))
                &&"reviewed".equals(str(store.get("guard_decision_policy",number(bundle,"policy_id")),"status")),"REPLAY_BUNDLE_NOT_APPROVED");
        return bundle;
    }
    private String closeoutSha(Map<String,Object> bundle) {
        for(var evaluation:store.rows("guard_evaluation_run",map("bundle_id",bundle.get("id")),false,100)) {
            if(!"final".equals(str(evaluation,"run_kind")))continue;
            JsonNode report=signatures.report(artifacts.json(str(evaluation,"report_ref"),str(evaluation,"report_sha256")),str(evaluation,"runner_identity"));
            require(str(bundle,"subject_sha256").equals(report.path("subjectSha256").asText()),"REPLAY_ELIGIBILITY_UNVERIFIED");
            return digest(report.path("evaluation"),"closeoutSha256");
        }
        throw error(422,"REPLAY_ELIGIBILITY_UNVERIFIED");
    }
}
