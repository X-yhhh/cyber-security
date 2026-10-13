package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import static com.xyh.cybersecurity.guard.GuardJson.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/** 用真实领取复核、T1—T9 与会话门检验回放准入；所有事实为隔离内存夹具，不签发或执行新命令。 */
class GuardReplayClaimsTest {
    @TempDir Path directory;
    final Instant now=Instant.parse("2030-01-01T00:00:00Z");
    GuardStore store;GuardMapper mapper;GuardLabMapper labMapper;GuardAccess access;
    GuardBudget budget;GuardActions actions;GuardSignatures signatures;
    ObjectNode observation,manifest,policy,subject;
    JsonNode envelope,response;
    Map<String,Object> asset,bundle,authorization,executor,binding,target,action,command,observationRow,evidence,healthRow,run,session,inference;
    String executorId,commandId;

    @BeforeEach void fixture()throws Exception {
        store=mock(GuardStore.class);mapper=mock(GuardMapper.class);labMapper=mock(GuardLabMapper.class);
        access=mock(GuardAccess.class);budget=mock(GuardBudget.class);signatures=mock(GuardSignatures.class);
        observation=GuardDomainTest.observation(now);observation.put("environment","lab").put("targetRef",id())
                .put("targetExpiresAt",now.plusSeconds(60).toString());
        String sensor=observation.path("sensorId").asText(),boot=observation.path("bootId").asText();
        executorId=id();commandId=id();String executorBoot=id(),capabilityId=id(),initialTarget=id();
        var protection=object("protectedBudgetTargetIds",List.of(),"protectedServicePorts",List.of(22,53,3389));
        Path protectionFile=directory.resolve("protection.json");Files.writeString(protectionFile,canonical(protection));
        policy=GuardDomainTest.autoPolicy(1);policy.put("mode","auto").put("minEvidenceSpanMs",0).put("protectionSetSha256",hash(protection));
        policy.set("supportedCapabilityIds",node(List.of(capabilityId)));
        ObjectNode versions=(ObjectNode)versions();versions.put("health",HEALTH_REPLAY);subject=object("protocolVersions",versions);
        asset=map("id",10L,"public_id",observation.path("assetId").asText(),"environment","lab","status","active");
        bundle=map("id",20L,"public_id",id(),"model_id",11L,"policy_id",9L,"environment","lab","status","active","subject_json",canonical(subject));
        var scope=object("capabilityId",capabilityId,"scope","peer_service","direction",observation.get("direction"),
                "transport",observation.get("transport"),"addressFamily",observation.get("addressFamily"),"servicePort",observation.get("servicePort"));
        authorization=map("id",30L,"public_id",id(),"status","active","revision",1L,"valid_from",db(now.minusSeconds(1)),
                "valid_until",db(now.plusSeconds(120)),"scope_json",canonical(object("executionScopes",List.of(scope))));
        executor=map("id",4L,"public_id",executorId,"asset_id",10L,"status","active","boot_id",executorBoot,
                "platform","macos","adapter_version","fixture-adapter","last_heartbeat",db(now),"health_json",canonical(object("pendingRecovery",false)));
        binding=map("bundle_id",20L,"asset_id",10L,"status","active","authorization_id",30L,"authorization_revision",1L);
        var targetPayload=observation.deepCopy().put("scope","peer_service").put("collectorBootId",boot);
        target=map("target_ref",observation.path("targetRef").asText(),"budget_target_id",40L,"sensor_id",1L,"executor_id",4L,
                "collector_boot_id",boot,"executor_boot_id",executorBoot,"expires_at",db(now.plusSeconds(60)),
                "scope_digest","fixed-scope","payload_json",canonical(targetPayload));
        var selected=object("observationId",observation.get("observationId"),"contentSha256",hash(observation),"family","dos_slow");
        var decision=map("id",8L,"asset_id",10L,"episode_id",14L,"evidence_json",canonical(object("source","model","triggerObservationId",observation.get("observationId"),"selectedObservations",List.of(selected))));
        action=map("id",6L,"public_id",id(),"asset_id",10L,"executor_id",4L,"bundle_id",20L,"decision_id",8L,
                "authorization_id",30L,"authorization_revision",1L,"mode","automatic","desired_state","active",
                "observed_state","dispatched","revision",1L,"desired_revision",1L,"block_until",db(now.plusSeconds(30)),"target_snapshot",canonical(targetPayload));
        envelope=object("payload",object("commandId",commandId),"keyId","fixture-control","algorithm","Ed25519","signature","fixture-signature");
        response=object("commands",List.of(envelope),"revocations",List.of(),"serverTime",now.toString());
        command=map("id",7L,"public_id",commandId,"action_id",6L,"executor_boot_id",executorBoot,"apply_by",db(now.plusSeconds(5)),
                "payload_json",canonical(envelope.path("payload")),"key_id","fixture-control","signature","fixture-signature");
        observationRow=map("id",13L,"asset_id",10L,"sensor_id",1L,"boot_id",boot,"parent_connection_id",observation.path("parentConnectionId").asText(),
                "capture_scope_id",15L,"content_sha256",hash(observation),"payload_json",canonical(observation));
        evidence=map("observation_id",13L,"family","dos_slow","score",1d,"rule_matched",false);
        inference=map("status","succeeded");healthRow=map("verification_status","replay_healthy","interval_end",db(now));
        session=map("id",2L,"status","active","asset_id",10L,"bundle_id",20L,"authorization_id",30L);
        manifest=object("evidenceKind","lab","validFrom",now.minusSeconds(1).toString(),"validUntil",now.plusSeconds(100).toString(),"timeoutSeconds",60,"authorizationRevision",1);
        var mapping=object("targetBindingId",initialTarget,"peerKey",observation.get("peerKey"),"keyEpoch",observation.get("keyEpoch"),"captureScopeId",observation.get("captureScopeId"));
        run=map("status","running","manifest_jcs",canonical(manifest),"last_activity_at",db(now),"mapping_jcs",canonical(object("entries",List.of(mapping))));
        when(store.now()).thenReturn(now);when(access.executor(executorId,"machine.command.claim")).thenReturn(executor);
        when(store.external("guard_executor",executorId,true)).thenReturn(executor);
        when(store.external("guard_command",commandId,false)).thenReturn(command);when(store.get("guard_action",6L)).thenReturn(action);
        when(store.get("asset",10L)).thenReturn(asset);when(store.get("guard_release_bundle",20L)).thenReturn(bundle);
        when(store.get("guard_decision",8L)).thenReturn(decision);
        when(store.get("guard_decision_policy",9L)).thenReturn(map("id",9L,"model_id",11L,"status","reviewed","decision_contract_version",DECISION,"definition_json",canonical(policy)));
        when(store.get("guard_model",11L)).thenReturn(map("id",11L,"validation_status","validated","manifest_json",canonical(GuardDomainTest.example("model-manifest"))));
        when(store.one(eq("guard_asset_binding"),anyMap(),eq(false))).thenReturn(binding);
        when(store.rows(eq("guard_asset_binding"),anyMap(),eq(false),eq(100))).thenReturn(List.of(binding));
        when(store.one(eq("guard_target_binding"),anyMap(),eq(false))).thenReturn(target);
        when(store.external("guard_target_binding",initialTarget,false)).thenReturn(target);
        when(store.get("sensor_agent",1L)).thenReturn(map("guard_boot_id",boot));
        when(store.external("sensor_agent",sensor,false)).thenReturn(map("id",1L,"asset_id",10L));
        when(store.get("guard_executor",4L)).thenReturn(executor);
        when(store.get("guard_budget_target",40L)).thenReturn(map("public_id",id(),"identity_status","verified","environment","lab"));
        when(store.get("asset_authorization",30L)).thenReturn(authorization);
        when(store.external("guard_observation",observation.path("observationId").asText(),false)).thenReturn(observationRow);
        when(mapper.latestParent(10L,1L,boot,observation.path("parentConnectionId").asText())).thenReturn(observationRow);
        when(store.one(eq("guard_inference"),anyMap(),eq(false))).thenReturn(inference);
        when(store.one(eq("guard_episode_evidence"),anyMap(),eq(false))).thenReturn(evidence);
        when(store.one(eq("guard_capture_health_window"),anyMap(),eq(false))).thenReturn(healthRow);
        when(store.rows(eq("guard_bundle_capability"),anyMap(),eq(false),eq(100))).thenReturn(List.of(map("capability_id",12L)));
        var capability=map("public_id",capabilityId,"level","lab_auto","platform","macos","scope","peer_service","protection_set_sha256",hash(protection),
                "payload_json",canonical(object("profile",observation.get("profile"),"family","dos_slow","addressFamily",observation.get("addressFamily"),
                        "transport",observation.get("transport"),"direction",observation.get("direction"),"adapterVersion","fixture-adapter")));
        when(store.get("guard_capability",12L)).thenReturn(capability);
        when(labMapper.owner(1L,boot)).thenReturn(2L);when(store.get("guard_validation_session",2L)).thenReturn(session);when(labMapper.run(2L)).thenReturn(run);
        var eligibility=new GuardEligibility(store,true,protectionFile.toString());eligibility.labGate(new GuardLabExecutionGate(store,labMapper));
        executor.put("capability_hash",eligibility.executorCapabilityHash(executor));
        when(store.rows(eq("guard_action"),anyMap(),eq(true),eq(1000))).thenReturn(List.of(action));
        when(store.one("guard_command",map("action_id",6L),true)).thenReturn(command);
        actions=new GuardActions(mapper,store,access,budget,eligibility,new GuardHealth(store,access),signatures,mock(GuardContracts.class));
    }

    @Test void publicClaimAndFilterAcceptReplayWithoutChangingTheSignedEnvelope() {
        var claim=actions.claims(executorId,object("bootId",executor.get("boot_id"),"capabilityHash",executor.get("capability_hash"),"maxItems",10,"waitSeconds",0));
        assertThat(claim.path("commands")).containsExactly(envelope);
        assertThat(actions.filterClaims(executorId,claim).path("commands")).containsExactly(envelope);
        verifyNoInteractions(signatures);verify(store,never()).insert(eq("guard_command"),anyMap());
    }

    @ParameterizedTest
    @ValueSource(strings={"executor_identity","executor_boot","action_revoked","action_uncertain","command_expired","bundle_inactive","bundle_v10",
            "authorization_revision","authorization_revoked","authorization_expired","asset_inactive","target_expired","target_changed",
            "evidence_hash","newer_parent","inference_failed","selected_evidence_changed","health_expired","batch_gap",
            "session_completed","session_wrong_asset","session_wrong_bundle","synthetic_session","research_observation"})
    void cachedClaimsFailClosedWhenCurrentFactsChange(String change) {
        assertThat(actions.filterClaims(executorId,response).path("commands")).containsExactly(envelope);
        switch(change) {
            case "executor_identity"->executor.put("id",99L);
            case "executor_boot"->executor.put("boot_id",id());
            case "action_revoked"->action.put("desired_state","revoked");
            case "action_uncertain"->action.put("observed_state","uncertain");
            case "command_expired"->command.put("apply_by",db(now));
            case "bundle_inactive"->bundle.put("status","suspended");
            case "bundle_v10"->{((ObjectNode)subject.path("protocolVersions")).put("health",HEALTH);bundle.put("subject_json",canonical(subject));}
            case "authorization_revision"->authorization.put("revision",2L);
            case "authorization_revoked"->authorization.put("status","revoked");
            case "authorization_expired"->authorization.put("valid_until",db(now));
            case "asset_inactive"->asset.put("status","inactive");
            case "target_expired"->target.put("expires_at",db(now));
            case "target_changed"->target.put("target_ref",id());
            case "evidence_hash"->observationRow.put("content_sha256","b".repeat(64));
            case "newer_parent"->when(mapper.latestParent(anyLong(),anyLong(),anyString(),anyString())).thenReturn(map("id",99L));
            case "inference_failed"->inference.put("status","failed");
            case "selected_evidence_changed"->evidence.put("observation_id",99L);
            case "health_expired"->healthRow.put("interval_end",db(now.minusMillis(10001)));
            case "batch_gap"->when(mapper.batchGap(anyLong(),anyString())).thenReturn(true);
            case "session_completed"->run.put("status","completed");
            case "session_wrong_asset"->session.put("asset_id",99L);
            case "session_wrong_bundle"->session.put("bundle_id",99L);
            case "synthetic_session"->{manifest.put("evidenceKind","synthetic");run.put("manifest_jcs",canonical(manifest));}
            case "research_observation"->{observation.put("environment","research");observationRow.put("payload_json",canonical(observation));}
            default->throw new IllegalArgumentException(change);
        }
        var filtered=actions.filterClaims(executorId,response);
        assertThat(filtered.path("commands")).isEmpty();assertThat(response.path("commands")).containsExactly(envelope);
        verifyNoInteractions(signatures);verify(store,never()).update(anyString(),anyLong(),anyMap());
    }

    @Test void machineControllerRefiltersIdempotentClaimsAfterLabSessionEnds() {
        var idem=mock(GuardIdempotency.class);
        when(idem.executeWithDigest(anyString(),anyString(),any(),eq(200),eq(false),any())).thenReturn(response);
        var controller=new GuardMachineController(access,idem,null,null,budget,actions,null,store,null,null);
        var request=new MockHttpServletRequest("POST","/api/v2/machine/executors/"+executorId+"/command-claims");
        var accepted=controller.write("executors",executorId,"command-claims",id(),"{}",request);
        assertThat(accepted.getBody().at("/data/commands")).containsExactly(envelope);
        run.put("status","completed");
        var rejected=controller.write("executors",executorId,"command-claims",id(),"{}",request);
        assertThat(rejected.getBody().at("/data/commands")).isEmpty();
        verifyNoInteractions(signatures);
    }

    /** D6：选证与触发观察可用不同租约；公共领取及幂等重放都须使用同一目标规则。 */
    @ParameterizedTest
    @ValueSource(strings={"missing_reference","different_reference","expired_reference"})
    void claimsAcceptSameTargetEvidenceWithoutSharingTriggerLease(String change) {
        var trigger=independentTrigger();
        switch(change){
            case "missing_reference"->observation.putNull("targetRef").putNull("targetExpiresAt");
            case "different_reference"->observation.put("targetRef",id());
            case "expired_reference"->observation.put("targetRef",id()).put("targetExpiresAt",now.minusSeconds(1).toString()).put("lastPacketAt",now.minusSeconds(20).toString());
        }
        updateSelectedObservation();
        assertThat(trigger.path("targetRef").asText()).isEqualTo(str(target,"target_ref"));
        assertThat(actions.claims(executorId,object("bootId",executor.get("boot_id"),"capabilityHash",executor.get("capability_hash"),"maxItems",10,"waitSeconds",0)).path("commands")).containsExactly(envelope);
        assertThat(actions.filterClaims(executorId,response).path("commands")).containsExactly(envelope);
        verifyNoInteractions(signatures);
    }

    /** 缺少租约、租约到期和最后包过期仍拒绝；其他选证不能替触发观察续租。 */
    @ParameterizedTest
    @ValueSource(strings={"missing_reference","expired_reference","old_packet","missing_trigger"})
    void claimsRejectInvalidTriggerEvenWhenSelectedEvidenceHasValidLease(String change) {
        var trigger=independentTrigger();
        switch(change){
            case "missing_reference"->trigger.putNull("targetRef").putNull("targetExpiresAt");
            case "expired_reference"->trigger.put("targetExpiresAt",now.toString());
            case "old_packet"->trigger.put("lastPacketAt",now.minusSeconds(15).toString());
            case "missing_trigger"->{var d=store.get("guard_decision",8L);var proof=(ObjectNode)json(d,"evidence_json");proof.remove("triggerObservationId");d.put("evidence_json",canonical(proof));}
        }
        store.external("guard_observation",trigger.path("observationId").asText(),false).put("payload_json",canonical(trigger));
        assertThat(actions.filterClaims(executorId,response).path("commands")).isEmpty();
        var claimed=actions.claims(executorId,object("bootId",executor.get("boot_id"),"capabilityHash",executor.get("capability_hash"),"maxItems",10,"waitSeconds",0));
        assertThat(claimed.path("commands")).isEmpty();
        verify(store).audit(isNull(),eq("guard.action.revocation_requested"),eq(str(action,"public_id")),eq(10L),isNull(),argThat(p->"TARGET_REF_STALE".equals(p.path("reasonCode").asText())));
    }

    /** 有效触发租约不能替跨目标选证放行；哈希、parent 与推理事实均保持匹配以单独验证 T4。 */
    @ParameterizedTest
    @ValueSource(strings={"peerKey","keyEpoch","sensorId","captureScopeId","servicePort"})
    void claimsRejectEvidenceForAnotherTarget(String field) {
        independentTrigger();
        if(field.equals("keyEpoch")||field.equals("servicePort"))observation.put(field,observation.path(field).asInt()+1);
        else observation.put(field,field.equals("peerKey")?"e".repeat(64):id());
        updateSelectedObservation();
        // 关闭会话门替身，避免其先按变化后的身份拒绝；T1/T2/T8 固定为真，T4 使用真实实现。
        var eligibility=spy(new GuardEligibility(store,true,directory.resolve("protection.json").toString()));
        doReturn(true).when(eligibility).capability(anyMap(),any(),any(),anyString());
        doReturn(true).when(eligibility).authorized(anyMap(),anyMap(),anyMap(),any(),any(),anyMap(),any(),anyString(),anyMap());
        doReturn(true).when(eligibility).replayAllowed(any(),anyMap());
        doReturn(null).when(eligibility).protection(anyMap(),any(),anyMap(),any(),anyString());
        doReturn(str(executor,"capability_hash")).when(eligibility).executorCapabilityHash(anyMap());
        actions=new GuardActions(mapper,store,access,budget,eligibility,new GuardHealth(store,access),signatures,mock(GuardContracts.class));
        assertThat(actions.filterClaims(executorId,response).path("commands")).isEmpty();
        assertThat(actions.claims(executorId,object("bootId",executor.get("boot_id"),"capabilityHash",executor.get("capability_hash"),"maxItems",10,"waitSeconds",0)).path("commands")).isEmpty();
        verify(store).audit(isNull(),eq("guard.action.revocation_requested"),eq(str(action,"public_id")),eq(10L),isNull(),argThat(p->"TARGET_REF_STALE".equals(p.path("reasonCode").asText())));
    }

    /** BE-13：执行器已回执 applied 后，选证被同 parent 新快照取代时既不重发也不撤销；规则保持到 TTL。 */
    @ParameterizedTest
    @ValueSource(strings={"receipt_applied","observed_applied"})
    void appliedCommandsAreNeitherResentNorRevokedWhenEvidenceIsSuperseded(String state) {
        if(state.equals("receipt_applied"))when(store.rows(eq("guard_action_receipt"),anyMap(),eq(false),eq(1))).thenReturn(List.of(map("status","applied")));
        else action.put("observed_state","applied");
        when(mapper.latestParent(anyLong(),anyLong(),anyString(),anyString())).thenReturn(map("id",99L));
        var claimed=actions.claims(executorId,object("bootId",executor.get("boot_id"),"capabilityHash",executor.get("capability_hash"),"maxItems",10,"waitSeconds",0));
        assertThat(claimed.path("commands")).isEmpty();assertThat(claimed.path("revocations")).isEmpty();
        assertThat(actions.filterClaims(executorId,response).path("commands")).isEmpty();
        verify(store,never()).insert(eq("guard_revocation"),anyMap());verify(budget,never()).revoke(anyMap(),anyString());
        verifyNoInteractions(signatures);
    }

    /** 尚无 applied 回执时保持签发前复核：选证被取代即撤销。 */
    @Test void unappliedCommandIsStillRevokedWhenEvidenceIsSuperseded() {
        when(mapper.latestParent(anyLong(),anyLong(),anyString(),anyString())).thenReturn(map("id",99L));
        assertThat(actions.claims(executorId,object("bootId",executor.get("boot_id"),"capabilityHash",executor.get("capability_hash"),"maxItems",10,"waitSeconds",0)).path("commands")).isEmpty();
        verify(store).audit(isNull(),eq("guard.action.revocation_requested"),eq(str(action,"public_id")),eq(10L),isNull(),argThat(p->"EVIDENCE_STALE".equals(p.path("reasonCode").asText())));
    }

    /** 已生效动作仍可经自动化停止等显式路径撤销。 */
    @Test void explicitStopStillRevokesAppliedCommand() {
        action.put("observed_state","applied");
        when(store.rows(eq("guard_action_receipt"),anyMap(),eq(false),eq(1))).thenReturn(List.of(map("status","applied")));
        when(store.rows(eq("guard_action"),eq(map("asset_id",10L)),eq(true),eq(10000))).thenReturn(List.of(action));
        actions.stop(10L,"fixture stop",true,null,null);
        verify(store).insert(eq("guard_revocation"),anyMap());
        verify(store).audit(isNull(),eq("guard.action.revocation_requested"),eq(str(action,"public_id")),eq(10L),isNull(),argThat(p->"AUTOMATION_STOPPED".equals(p.path("reasonCode").asText())));
    }

    private ObjectNode independentTrigger(){
        var trigger=observation.deepCopy().put("observationId",id()).put("parentConnectionId",id());
        var row=map("id",16L,"asset_id",10L,"payload_json",canonical(trigger));
        when(store.external("guard_observation",trigger.path("observationId").asText(),false)).thenReturn(row);
        var d=store.get("guard_decision",8L);var proof=(ObjectNode)json(d,"evidence_json");proof.put("triggerObservationId",trigger.path("observationId").asText());d.put("evidence_json",canonical(proof));
        return trigger;
    }
    private void updateSelectedObservation(){
        observationRow.put("payload_json",canonical(observation));observationRow.put("content_sha256",hash(observation));
        var d=store.get("guard_decision",8L);var proof=(ObjectNode)json(d,"evidence_json");((ObjectNode)proof.path("selectedObservations").get(0)).put("contentSha256",hash(observation));d.put("evidence_json",canonical(proof));
    }
}
