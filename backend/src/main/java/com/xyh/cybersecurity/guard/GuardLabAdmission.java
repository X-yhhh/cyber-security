package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.stereotype.Service;
import java.time.Instant;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;
import static com.xyh.cybersecurity.guard.GuardLabContract.*;

/** 只判断本次 lab 评价准入；与现有平台执行能力及正式类别自动资格分别核验。 */
@Service
public class GuardLabAdmission {
    private final GuardStore store;
    private final GuardArtifacts artifacts;
    private final GuardSignatures signatures;
    private final GuardMapper mapper;
    public GuardLabAdmission(GuardStore store,GuardArtifacts artifacts,GuardSignatures signatures,GuardMapper mapper) {
        this.store=store;this.artifacts=artifacts;this.signatures=signatures;this.mapper=mapper;
    }
    public record Input(JsonNode manifest,JsonNode scenarios,JsonNode mapping,Map<String,Object> asset,
                        Map<String,Object> bundle,Map<String,Object> authorization,Map<String,Object> sensor) { }

    /** 原字节摘要先验，再验 JCS 签名；重试也重新核对受控原件和当前授权。 */
    public Input read(String ref,String sha,String runner) {
        JsonNode p=signatures.report(artifacts.json(ref,sha),runner);manifest(p);
        require(runner.equals(text(p,"runnerIdentity")),"LAB_RUNNER_INVALID");
        var s=artifacts.json(text(p,"scenarioRef"),text(p,"scenarioSha256"));scenarios(p,s);
        var m=artifacts.json(text(p,"mappingRef"),text(p,"mappingSha256"));mapping(p,s,m);
        for(var scenario:s.path("scenarios"))artifacts.read(text(scenario,"pcapRef"),text(scenario,"pcapSha256"),256L*1024*1024);
        var asset=store.external("asset",text(p,"assetId"),true);
        var bundle=store.external("guard_release_bundle",text(p,"bundleId"),true);
        var auth=store.external("asset_authorization",text(p,"authorizationId"),true);
        var sensor=store.external("sensor_agent",text(p,"sensorId"),true);
        Input input=new Input(p,s,m,asset,bundle,auth,sensor);current(input,true,true);proofs(input);return input;
    }

    /** 机器轮询只读复核当前授权/身份/组合及签名元数据，短租约由接入链路逐包复核。 */
    public void machineCurrent(Map<String,Object> run) {
        var p=json(run,"manifest_jcs");
        var signed=signatures.report(artifacts.json(str(run,"manifest_ref"),str(run,"manifest_sha256")),text(p,"runnerIdentity"));
        require(hash(signed).equals(hash(p)),"LAB_MANIFEST_CHANGED");
        var scenarios=artifacts.json(text(p,"scenarioRef"),text(p,"scenarioSha256"));
        var mapping=artifacts.json(text(p,"mappingRef"),text(p,"mappingSha256"));
        require(hash(scenarios).equals(hash(json(run,"scenarios_jcs")))&&hash(mapping).equals(hash(json(run,"mapping_jcs"))),"LAB_MANIFEST_CHANGED");
        var input=new Input(p,scenarios,mapping,store.external("asset",text(p,"assetId"),false),
                store.external("guard_release_bundle",text(p,"bundleId"),false),store.external("asset_authorization",text(p,"authorizationId"),false),
                store.external("sensor_agent",text(p,"sensorId"),false));
        current(input,false,false);proofs(input);
    }

    private void current(Input in,boolean leases,boolean lock) {
        var p=in.manifest();var now=store.now();long aid=number(in.asset(),"id");
        require("lab".equals(str(in.asset(),"environment"))&&"active".equals(str(in.asset(),"status"))
                &&"lab".equals(str(in.bundle(),"environment")),"LAB_ENVIRONMENT_INVALID");
        // 任务单 6.2：发布组合必须已独立批准（approved，或批准后已激活 active）；candidate/evaluated/suspended/retired 一律拒绝。
        // research 组合已在上一行按环境拒绝，lab 会话不能借用 research 批准。
        require(Set.of("approved","active").contains(str(in.bundle(),"status"))&&in.bundle().get("approved_by")!=null,"LAB_BUNDLE_NOT_APPROVED");
        require(number(in.authorization(),"asset_id")==aid&&"active".equals(str(in.authorization(),"status"))
                &&number(in.authorization(),"revision")==p.path("authorizationRevision").asLong()
                &&in.authorization().get("approved_by")!=null&&!Objects.equals(in.authorization().get("approved_by"),in.authorization().get("requested_by"))
                &&!now.isBefore(instant(in.authorization().get("valid_from")))&&now.isBefore(instant(in.authorization().get("valid_until")))
                &&!time(p,"validFrom").isBefore(instant(in.authorization().get("valid_from")))
                &&!time(p,"validUntil").isAfter(instant(in.authorization().get("valid_until")))&&now.isBefore(time(p,"validUntil")),"AUTHORIZATION_INACTIVE");
        require(bool(json(in.authorization(),"scope_json"),"observationAllowed"),"AUTHORIZATION_INACTIVE");
        require(number(in.sensor(),"asset_id")==aid&&"active".equals(str(in.sensor(),"status"))
                &&text(p,"bootId").equals(str(in.sensor(),"guard_boot_id")),"LAB_SENSOR_MISMATCH");
        var client=store.one("api_client",map("sensor_id",in.sensor().get("id"),"status","active"),false);
        require(client!=null&&mapper.machinePermission(number(client,"id"),"machine.observation.write"),"LAB_SENSOR_MISMATCH");
        var executor=store.external("guard_executor",text(p,"executorId"),lock);
        require(number(executor,"asset_id")==aid&&"active".equals(str(executor,"status"))
                &&text(p,"executorBootId").equals(str(executor,"boot_id"))
                &&mapper.machinePermission(number(executor,"api_client_id"),"machine.receipt.write"),"LAB_EXECUTOR_MISMATCH");
        var model=store.get("guard_model",number(in.bundle(),"model_id"));
        var policy=store.get("guard_decision_policy",number(in.bundle(),"policy_id"));
        var contract=store.get("guard_contract",number(in.bundle(),"contract_id"));
        var plan=store.get("guard_evaluation_plan",number(in.bundle(),"plan_id"));
        require("validated".equals(str(model,"validation_status"))&&"reviewed".equals(str(policy,"status"))
                &&text(p,"subjectSha256").equals(str(in.bundle(),"subject_sha256"))
                &&text(p,"evaluationPlanSha256").equals(str(plan,"plan_sha256"))
                &&p.at("/provenance/modelSha256").asText().equals(str(model,"artifact_sha256"))
                &&p.at("/provenance/policySha256").asText().equals(str(policy,"definition_sha256"))
                &&p.at("/provenance/extractorSha256").asText().equals(str(contract,"extractor_sha256")),"LAB_BUNDLE_MISMATCH");
        if(leases) {
            var targets=new HashSet<Long>();
            for(var e:in.mapping().path("entries"))require(targets.add(binding(p,e,in.authorization(),executor,in.bundle(),now)),"LAB_MAPPING_MISMATCH");
        }
    }

    private long binding(JsonNode p,JsonNode entry,Map<String,Object> auth,Map<String,Object> executor,Map<String,Object> bundle,Instant now) {
        var initial=store.external("guard_target_binding",text(entry,"targetBindingId"),false);
        require(text(entry,"targetRef").equals(str(initial,"target_ref"))&&hash(json(initial,"payload_json")).equals(str(initial,"content_sha256")),"LAB_MAPPING_MISMATCH");
        // 初始租约只锚定稳定目标；恢复时读取同一目标/启动身份的新租约，不能把 15 秒租约拉长到整个会话。
        var b=store.one("guard_target_binding",map("budget_target_id",initial.get("budget_target_id"),"sensor_id",initial.get("sensor_id"),
                "collector_boot_id",text(p,"bootId"),"executor_boot_id",text(p,"executorBootId")),false);
        require(b!=null&&Objects.equals(initial.get("scope_digest"),b.get("scope_digest")),"LAB_MAPPING_MISMATCH");
        var v=json(b,"payload_json");var target=store.get("guard_budget_target",number(b,"budget_target_id"));
        require(number(target,"asset_id")==number(auth,"asset_id")&&"lab".equals(str(target,"environment"))
                &&"verified".equals(str(target,"identity_status"))&&number(b,"executor_id")==number(executor,"id")
                &&text(p,"executorBootId").equals(str(b,"executor_boot_id"))&&text(p,"bootId").equals(str(b,"collector_boot_id"))
                &&text(p,"sensorId").equals(v.path("sensorId").asText())&&instant(b.get("expires_at")).isAfter(now),"LAB_MAPPING_MISMATCH");
        for(String f:List.of("peerKey","keyEpoch","captureScopeId"))require(entry.path(f).equals(v.path(f)),"LAB_MAPPING_MISMATCH");
        var scope=store.external("guard_capture_scope",text(entry,"captureScopeId"),false);
        require("active".equals(str(scope,"status"))&&number(scope,"asset_id")==number(auth,"asset_id")
                &&GuardAdministration.contains(json(auth,"scope_json").path("interfaces"),str(scope,"scope_key")),"LAB_MAPPING_MISMATCH");
        boolean covered=false;
        for(var allowed:json(auth,"scope_json").path("executionScopes")) {
            boolean matches=true;for(String f:List.of("direction","transport","addressFamily","servicePort"))matches&=allowed.path(f).equals(v.path(f));
            matches&=allowed.path("scope").asText("peer_service").equals(v.path("scope").asText("peer_service"));
            if(matches) {
                var cap=store.external("guard_capability",uuid(allowed,"capabilityId"),false);
                matches=str(executor,"platform").equals(str(cap,"platform"))
                        &&str(executor,"adapter_version").equals(json(cap,"payload_json").path("adapterVersion").asText())
                        &&!"suspended".equals(str(cap,"level"))
                        &&store.one("guard_bundle_capability",map("bundle_id",bundle.get("id"),"capability_id",cap.get("id")),false)!=null;
                covered|=matches;
            }
        }
        require(covered,"LAB_EXECUTION_SCOPE_DENIED");
        return number(target,"id");
    }

    private JsonNode proof(JsonNode p,String name) {
        var r=p.path("proofs").path(name);
        return signatures.report(artifacts.json(text(r,"ref"),text(r,"sha256")),text(r,"runnerIdentity"));
    }
    private void proofs(Input in) {
        var p=in.manifest();var p5=proof(p,"p5");var p6=proof(p,"p6");
        platformVersions(p5.path("protocolVersions"));versions(p6.path("protocolVersions"));
        for(var item:List.of(p5,p6)) {
            require(bool(item,"passed")&&text(p,"subjectSha256").equals(text(item,"subjectSha256")),"LAB_EVIDENCE_INVALID");
        }
        require("platform".equals(text(p5,"runKind"))&&"final".equals(text(p6,"runKind"))
                &&text(p,"evaluationPlanSha256").equals(text(p6,"evaluationPlanSha256"))
                &&p.at("/provenance/executorSha256").equals(p5.path("executorSha256")),"LAB_EVIDENCE_INVALID");
        for(String f:List.of("datasetSha256","splitSha256","labelRulesSha256"))require(p.path("provenance").path(f).equals(p6.path("provenance").path(f)),"LAB_EVIDENCE_INVALID");
        for(var s:in.scenarios().path("scenarios"))if(s.path("trialAutoEligible").asBoolean())
            require(GuardAdministration.contains(p6.path("sourceEligibility"),sourceKey(s)),"LAB_SOURCE_INELIGIBLE");
        var isolation=proof(p,"isolation");
        require(!p.at("/proofs/isolation/runnerIdentity").asText().equals(text(p,"runnerIdentity")),"LAB_ISOLATION_UNVERIFIED");
        for(String f:List.of("sessionId","assetId","mappingSha256","executorId"))require(p.path(f).equals(isolation.path(f)),"LAB_ISOLATION_UNVERIFIED");
        require(bool(isolation,"networkIsolationVerified")&&!time(isolation,"validUntil").isBefore(time(p,"validUntil")),"LAB_ISOLATION_UNVERIFIED");
        var admission=proof(p,"admission");
        require(p.path("sessionId").equals(admission.path("sessionId"))&&p.path("subjectSha256").equals(admission.path("subjectSha256")),"LAB_EVIDENCE_INVALID");
        if("lab".equals(text(p,"evidenceKind"))) {
            Set<String> classes=new HashSet<>();for(var s:in.scenarios().path("scenarios"))if(s.path("trialAutoEligible").asBoolean())classes.add(text(s,"family"));
            require(bool(admission,"j1Passed")&&bool(admission,"j2Registered")&&classes.size()>=2&&classes.contains("brute_force"),"LAB_STAGE_GATE_CLOSED");
        }
    }
}
