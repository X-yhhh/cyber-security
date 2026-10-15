package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.xyh.cybersecurity.database.IsolatedDatabaseSchemas;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.*;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.*;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.*;
import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.doAnswer;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;

/** 随机隔离 MySQL + 真实签名 + MVC/IAM/事务；时钟可控，合成事实不连接防火墙或模型。 */
@SpringBootTest(properties={"cyber.ingest.consumer.enabled=false","cyber.ingest.outbox-relay.enabled=false","cyber.drift.enabled=false",
        "cyber.guard.automation-enabled=false","cyber.security.local-admin-bootstrap.enabled=false"})
@AutoConfigureMockMvc(print=MockMvcPrint.NONE)
@EnabledIfEnvironmentVariable(named="DB_TEST_BASE_URL",matches=".+")
@ExtendWith(IsolatedDatabaseSchemas.class)
class GuardLabIntegrationTest {
    static final String SCHEMA=IsolatedDatabaseSchemas.name(GuardLabIntegrationTest.class,"lab");
    static final Path ROOT=Path.of("target/lab-fixtures-"+UUID.randomUUID()).toAbsolutePath();
    static KeyPair signer,isolation;
    static final Instant BASE=Instant.parse("2030-01-01T00:00:00Z");
    static final String H="a".repeat(64);
    volatile Instant now=BASE;
    @Autowired MockMvc mvc;
    @Autowired JdbcTemplate jdbc;
    @Autowired GuardMapper mapper;
    @Autowired GuardLabSessions sessions;
    @Autowired GuardLabExecutionGate executionGate;
    @Autowired org.springframework.security.crypto.password.PasswordEncoder passwordEncoder;
    @MockitoSpyBean GuardStore store;
    IdentityPrincipal operator,reviewer,outsider;
    Map<String,Object> asset,sensor,executor,auth,scope,config,bundle,target;
    ObjectNode manifest,scenarios,mapping;
    String folder;
    record Client(Cookie cookie,String csrf) { }
    Map<Long,Client> clients=new HashMap<>();

    @DynamicPropertySource static void properties(DynamicPropertyRegistry r) throws Exception {
        Files.createDirectories(ROOT);signer=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();isolation=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        Files.writeString(ROOT.resolve("trust.json"),canonical(object("fixture-runner",Base64.getEncoder().encodeToString(signer.getPublic().getEncoded()),
                "fixture-isolation",Base64.getEncoder().encodeToString(isolation.getPublic().getEncoded()))));
        r.add("spring.datasource.url",()->System.getenv("DB_TEST_BASE_URL").replaceAll("/+$","")+"/"+SCHEMA+"?connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true");
        r.add("spring.datasource.username",()->System.getenv("DB_TEST_USERNAME"));r.add("spring.datasource.password",()->System.getenv("DB_TEST_PASSWORD"));
        r.add("cyber.guard.artifact-root",ROOT::toString);r.add("cyber.guard.report-trust-file",()->ROOT.resolve("trust.json").toString());
        r.add("cyber.security.login-throttle.hmac-key",()->"isolated-lab-test-key-with-at-least-thirty-two-bytes");
    }
    Map<String,Object> add(String table,Object... values) {return store.add(table,map(values));}
    IdentityPrincipal identity(String role) {
        String key=id();jdbc.update("INSERT INTO sys_user(user_key,username,display_name,password_hash,status) VALUES (?,?,?,?,'active')",key,key,"隔离测试",passwordEncoder.encode("isolated-lab-password"));
        long uid=jdbc.queryForObject("SELECT id FROM sys_user WHERE user_key=?",Long.class,key);
        for(String name:role.split(" "))jdbc.update("INSERT INTO sys_user_role(user_id,role_id,scope_type,scope_id) SELECT ?,id,'global','*' FROM sys_role WHERE role_key=?",uid,name);
        return new IdentityPrincipal(uid,key,key,"隔离测试","synthetic-hash","active",List.of(),List.of());
    }
    @BeforeEach void fixture() throws Exception {
        now=BASE;doAnswer(i->now).when(store).now();
        operator=identity("platform_admin model_operator security_analyst");reviewer=identity("security_reviewer");outsider=identity("none");
        asset=add("asset","asset_key",id(),"asset_type","host","environment","lab","criticality","medium","owner","fixture","status","active","labels_json","{}");
        sensor=add("sensor_agent","agent_key",id(),"asset_id",asset.get("id"),"platform","macos","agent_version","fixture","capabilities_json","[]","credential_ref","fixture",
                "status","active","registered_at",db(BASE),"guard_boot_id",id());
        var client=add("api_client","client_key",id(),"client_type","sensor","sensor_id",sensor.get("id"),"secret_ref","fixture","credential_sha256",H,"scope_json","{}","status","active");
        mapper.grant(number(client,"id"),"machine.observation.write");mapper.grant(number(client,"id"),"machine.sensor.read");
        var ec=add("api_client","client_key",id(),"client_type","executor","secret_ref","fixture","credential_sha256",H,"scope_json","{}","status","active");mapper.grant(number(ec,"id"),"machine.receipt.write");
        executor=add("guard_executor","asset_id",asset.get("id"),"api_client_id",ec.get("id"),"platform","macos","adapter_version","fixture","boot_id",id(),"status","active");
        config=add("sensor_config","sensor_id",sensor.get("id"),"config_version",id(),"interface_scope_json","[]","filter_policy_json","{}","flow_window_seconds",30,
                "feature_contract_version",CONTRACT,"sampling_policy_json","{}","status","active");
        scope=add("guard_capture_scope","asset_id",asset.get("id"),"sensor_id",sensor.get("id"),"scope_key","lab0","address_family","ipv4","status","active","config_id",config.get("id"));
        var cap=add("guard_capability","capability_key",id(),"version","fixture","platform","macos","level","alert_only","payload_json",canonical(object("adapterVersion","fixture")),"created_by",operator.id());
        var as=object("interfaces",List.of("lab0"),"observationAllowed",true,"executionScopes",List.of(object("direction","inbound","transport","tcp","addressFamily","ipv4","servicePort",443,"capabilityId",cap.get("public_id"))));
        auth=add("asset_authorization","asset_id",asset.get("id"),"authorization_ref","fixture","scope_json",canonical(as),"valid_from",db(BASE.minusSeconds(60)),
                "valid_until",db(BASE.plusSeconds(7200)),"status","active","requested_by",operator.id(),"approved_by",reviewer.id());
        var contract=add("guard_contract","contract_version",MODEL_CONTRACT,"profile_sha256",hash(object("unique",id())),"schema_set_sha256",H,"extractor_sha256",H,"status","frozen");
        var model=add("guard_model","model_key",id(),"version","fixture","manifest_ref","fixture","manifest_sha256",H,"artifact_sha256",H,"contract_id",contract.get("id"),
                "manifest_json","{\"candidateOnly\":true}","created_by",operator.id(),"validation_status","validated");
        var plan=add("guard_evaluation_plan","plan_key",id(),"version","fixture","plan_sha256",H,"payload_json","{}","created_by",operator.id());
        var policy=add("guard_decision_policy","policy_key",id(),"version","fixture","model_id",model.get("id"),"plan_id",plan.get("id"),"decision_contract_version",DECISION,
                "definition_json","{}","definition_sha256",H,"status","reviewed","created_by",operator.id(),"reviewed_by",reviewer.id());
        bundle=add("guard_release_bundle","bundle_key",id(),"version","fixture","model_id",model.get("id"),"policy_id",policy.get("id"),"contract_id",contract.get("id"),
                "plan_id",plan.get("id"),"environment","lab","subject_json","{}","subject_sha256",H,"requested_by",operator.id(),
                "status","approved","approved_by",reviewer.id());
        add("guard_bundle_capability","bundle_id",bundle.get("id"),"capability_id",cap.get("id"));
        var budget=add("guard_budget_target","asset_id",asset.get("id"),"environment","lab","stable_target_token",H,"resolver_executor_id",executor.get("id"),"scope_digest",H,"identity_status","verified");
        var binding=object("sensorId",sensor.get("public_id"),"peerKey",H,"keyEpoch",1,"captureScopeId",scope.get("public_id"),"targetRef",id(),"direction","inbound","transport","tcp","addressFamily","ipv4","servicePort",443);
        target=add("guard_target_binding","target_ref",binding.get("targetRef").asText(),"budget_target_id",budget.get("id"),"executor_id",executor.get("id"),"executor_boot_id",executor.get("boot_id"),
                "sensor_id",sensor.get("id"),"collector_boot_id",sensor.get("guard_boot_id"),"capture_scope_id",scope.get("id"),"peer_key",H,"key_epoch",1,"scope_digest",H,
                "expires_at",db(BASE.plusSeconds(7200)),"payload_json",canonical(binding),"content_sha256",hash(binding));
        folder=id();Files.createDirectories(ROOT.resolve(folder));
        manifest=(ObjectNode)parse(Files.readString(Path.of("../docs/contracts/examples/lab-session.json")));
        manifest.put("sessionId",id()).put("assetId",str(asset,"public_id")).put("bundleId",str(bundle,"public_id")).put("authorizationId",str(auth,"public_id"));
        manifest.put("sensorId",str(sensor,"public_id")).put("bootId",str(sensor,"guard_boot_id")).put("executorId",str(executor,"public_id")).put("executorBootId",str(executor,"boot_id"));
        manifest.put("validFrom",BASE.minusSeconds(60).toString()).put("validUntil",BASE.plusSeconds(7200).toString()).put("timeoutSeconds",60).put("subjectSha256",H).put("evaluationPlanSha256",H);
        for(String f:GuardLabContract.PROVENANCE)((ObjectNode)manifest.get("provenance")).put(f,H);
        manifest.set("time",object("sourceStart",BASE.toString(),"labStart",BASE.toString(),"offsetMicros",0,"warmupStart",BASE.toString(),"scoringStart",BASE.toString(),"scoringEnd",BASE.plusSeconds(1800).toString()));
        var scenario=object("scenarioId","normal-1","family","normal","source","model","ruleId",null,"trialAutoEligible",false,"autoIneligibleReason","synthetic only",
                "pcapRef",folder+"/tiny.pcap","pcapSha256",sha(new byte[]{1,2,3}),"sourceStart",BASE.toString(),"sourceEnd",BASE.plusSeconds(1800).toString());
        Files.write(ROOT.resolve(folder+"/tiny.pcap"),new byte[]{1,2,3});scenarios=object("contractVersion",GuardLabContract.VERSION,"scenarios",List.of(scenario));
        mapping=object("contractVersion",GuardLabContract.VERSION,"mappingId",manifest.get("mappingId"),"sessionId",manifest.get("sessionId"),"entries",List.of(object("scenarioId","normal-1",
                "targetBindingId",target.get("public_id"),"peerKey",H,"keyEpoch",1,"captureScopeId",scope.get("public_id"),"targetRef",target.get("target_ref"))));
        writeInputs();
        for(var actor:List.of(operator,reviewer,outsider))clients.put(actor.id(),login(actor));
    }
    Client login(IdentityPrincipal actor) throws Exception {
        var bootstrap=mvc.perform(get("/api/v2/auth/csrf")).andReturn();var cookie=bootstrap.getResponse().getCookie("SESSION");
        var csrfValue=parse(bootstrap.getResponse().getContentAsString()).at("/data/token").asText();
        var login=mvc.perform(post("/api/v2/auth/login").header("Idempotency-Key",id()).cookie(cookie).header("X-CSRF-TOKEN",csrfValue).contentType("application/json")
                .content(canonical(object("username",actor.getUsername(),"password","isolated-lab-password")))).andReturn();
        assertThat(login.getResponse().getStatus()).isEqualTo(200);cookie=login.getResponse().getCookie("SESSION");
        var csrf=mvc.perform(get("/api/v2/auth/csrf").cookie(cookie)).andReturn();
        return new Client(cookie,parse(csrf.getResponse().getContentAsString()).at("/data/token").asText());
    }
    JsonNode write(String name,JsonNode value,boolean signed,String runner) throws Exception {
        String ref=folder+"/"+name+".json";var data=signed?GuardSignatures.sign(value,runner,(runner.equals("fixture-isolation")?isolation:signer).getPrivate()):value;
        Files.writeString(ROOT.resolve(ref),canonical(data));return object("ref",ref,"sha256",sha(Files.readAllBytes(ROOT.resolve(ref))),"runnerIdentity",runner);
    }
    void writeInputs() throws Exception {
        var sr=write("scenarios",scenarios,false,"fixture-runner");var mr=write("mapping",mapping,false,"fixture-runner");
        manifest.put("scenarioRef",sr.path("ref").asText()).put("scenarioSha256",sr.path("sha256").asText()).put("mappingRef",mr.path("ref").asText()).put("mappingSha256",mr.path("sha256").asText());
        var p5=object("protocolVersions",versions(),"subjectSha256",H,"runKind","platform","passed",true,"executorSha256",H);
        var p6=object("protocolVersions",versions(),"subjectSha256",H,"evaluationPlanSha256",H,"runKind","final","passed",true,"provenance",manifest.get("provenance"),"sourceEligibility",List.of());
        var isolationProof=object("sessionId",manifest.get("sessionId"),"assetId",manifest.get("assetId"),"executorId",manifest.get("executorId"),"mappingSha256",manifest.get("mappingSha256"),"networkIsolationVerified",true,"validUntil",manifest.get("validUntil"));
        manifest.set("proofs",object("p5",write("p5",p5,true,"fixture-runner"),"p6",write("p6",p6,true,"fixture-runner"),"isolation",write("isolation",isolationProof,true,"fixture-isolation"),
                "admission",write("admission",object("sessionId",manifest.get("sessionId"),"subjectSha256",H,"j1Passed",false,"j2Registered",false),true,"fixture-runner")));
    }
    JsonNode body() throws Exception {var ref=write("session",manifest,true,"fixture-runner");return object("sessionRef",ref.get("ref"),"sha256",ref.get("sha256"),"runnerIdentity","fixture-runner");}
    MvcResult call(String route,JsonNode body,IdentityPrincipal actor,String rev,String key) throws Exception {
        var client=clients.get(actor.id());
        var request=post("/api/v2/lab-validation-runs"+route).cookie(client.cookie()).header("X-CSRF-TOKEN",client.csrf()).header("Idempotency-Key",key).contentType("application/json").content(canonical(body));
        if(rev!=null)request.header("If-Match",rev);return mvc.perform(request).andReturn();
    }
    JsonNode ok(MvcResult r) throws Exception {assertThat(r.getResponse().getStatus()).withFailMessage(r.getResponse().getContentAsString()).isBetween(200,201);return parse(r.getResponse().getContentAsString()).get("data");}
    JsonNode create() throws Exception {return ok(call("",body(),operator,null,id()));}
    JsonNode op(String operation,JsonNode b,String rev) throws Exception {return ok(call("/"+manifest.path("sessionId").asText()+"/"+operation,b,Set.of("decisions","revocations").contains(operation)?reviewer:operator,rev,id()));}
    String route(String op) {return "/"+manifest.path("sessionId").asText()+"/"+op;}
    JsonNode machineState() throws Exception {
        var client=store.one("api_client",map("sensor_id",sensor.get("id")),false);String machineKey="x".repeat(43);
        jdbc.update("UPDATE api_client SET credential_sha256=? WHERE id=?",sha(machineKey.getBytes(java.nio.charset.StandardCharsets.UTF_8)),client.get("id"));
        return ok(mvc.perform(get("/api/v2/machine/sensors/"+str(sensor,"public_id")+"/lab-validation-runs/"+manifest.path("sessionId").asText())
                .header("Authorization","Bearer mch_"+client.get("id")+"."+machineKey)).andReturn()).get("state");
    }
    JsonNode executionObservation() {
        var o=(ObjectNode)json(target,"payload_json");o.put("bootId",str(sensor,"guard_boot_id")).put("environment","lab");return o;
    }

    /** 默认关闭的导入闸门按已验签 payload 拒绝引导和合成类别，正式类别仍可进入候选组合。 */
    @Test void candidateImportRejectsBootstrapAndSyntheticByDefault() throws Exception {
        jdbc.update("UPDATE guard_release_bundle SET status='candidate' WHERE id=?",bundle.get("id"));
        String route="/api/v2/release-bundles/"+str(bundle,"public_id")+"/imports";
        var client=clients.get(operator.id());
        for(String kind:List.of("bootstrap","synthetic","real_pf")) {
            var payload=object("protocolVersions",versions(),"subjectSha256",H,"evaluationPlanSha256",H,
                    "runKind","platform","passed",true,"evidenceKind",kind);
            var file=write("import-"+kind,payload,true,"fixture-runner");
            var request=post(route).cookie(client.cookie()).header("X-CSRF-TOKEN",client.csrf())
                    .header("Idempotency-Key",id()).contentType("application/json").content(canonical(object(
                            "reportRef",file.get("ref"),"sha256",file.get("sha256"),"runnerIdentity","fixture-runner")));
            var result=mvc.perform(request).andReturn();
            if(kind.equals("real_pf"))assertThat(result.getResponse().getStatus()).isBetween(200,201);
            else {
                assertThat(result.getResponse().getStatus()).isEqualTo(422);
                assertThat(parse(result.getResponse().getContentAsString()).at("/error/code").asText())
                        .isEqualTo("REPORT_EVIDENCE_KIND_NOT_ALLOWED");
            }
        }
        var unknown=write("import-unknown",object("protocolVersions",versions(),"subjectSha256",H,
                "evaluationPlanSha256",H,"runKind","platform","passed",true,"evidenceKind","real_pf"),true,"fixture-runner");
        var untrusted=mvc.perform(post(route).cookie(client.cookie()).header("X-CSRF-TOKEN",client.csrf())
                .header("Idempotency-Key",id()).contentType("application/json").content(canonical(object(
                        "reportRef",unknown.get("ref"),"sha256",unknown.get("sha256"),"runnerIdentity","untrusted-runner")))).andReturn();
        assertThat(untrusted.getResponse().getStatus()).isEqualTo(422);
        assertThat(parse(untrusted.getResponse().getContentAsString()).at("/error/code").asText())
                .isEqualTo("REPORT_IDENTITY_UNTRUSTED");
    }

    @Test void lifecycleIsIndependentAndHasNoExecutionSideEffects() throws Exception {
        assertThat(create().path("eligibilityStatus").asText()).isEqualTo("pending");
        op("decisions",object("decision","approve","reason","fixture"),"1");op("starts",object(),"2");
        assertThat(executionGate.permits(executionObservation(),bundle,now)).isFalse(); // 合成资格永不开放真实动作。
        op("interruptions",object("reason","interrupted"),"3");op("resumptions",object(),"4");
        var result=op("completions",object("outcome","completed","reason","ended"),"5");
        assertThat(result.path("runStatus").asText()).isEqualTo("completed");assertThat(result.path("eligibilityStatus").asText()).isEqualTo("active");
        assertThat(executionGate.permits(executionObservation(),bundle,now)).isFalse();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM guard_command",Long.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM guard_lab_event WHERE session_id=(SELECT id FROM guard_validation_session WHERE public_id=?)",Long.class,manifest.path("sessionId").asText())).isEqualTo(6);
        assertThat(call(route("resumptions"),object(),operator,"6",id()).getResponse().getStatus()).isEqualTo(422);
    }
    @Test void retriesAndCurrentPermissionsAreEnforced() throws Exception {
        String key=id();var b=body();var created=ok(call("",b,operator,null,key));assertThat(ok(call("",b,operator,null,key))).isEqualTo(created);
        assertThat(ok(call("",b,operator,null,id())).path("id")).isEqualTo(created.path("id"));
        assertThat(call(route("decisions"),object("decision","approve","reason","self"),operator,"1",id()).getResponse().getStatus()).isEqualTo(403);
        assertThat(call(route("decisions"),object("decision","approve","reason","stale"),reviewer,"9",id()).getResponse().getStatus()).isEqualTo(409);
        jdbc.update("DELETE FROM sys_user_role WHERE user_id=?",operator.id());assertThat(call("",b,operator,null,key).getResponse().getStatus()).isEqualTo(403);
    }
    @Test void rejectsResearchExpiredTamperedUnknownRunnerAndStageGate() throws Exception {
        var b=body();((ObjectNode)b).put("runnerIdentity","unknown");assertThat(call("",b,operator,null,id()).getResponse().getStatus()).isEqualTo(422);
        manifest.put("evidenceKind","lab");assertThat(call("",body(),operator,null,id()).getResponse().getStatus()).isEqualTo(422);manifest.put("evidenceKind","synthetic");
        jdbc.update("UPDATE asset SET environment='research' WHERE id=?",asset.get("id"));assertThat(call("",body(),operator,null,id()).getResponse().getStatus()).isEqualTo(422);
        jdbc.update("UPDATE asset SET environment='lab' WHERE id=?",asset.get("id"));now=BASE.plusSeconds(8000);assertThat(call("",body(),operator,null,id()).getResponse().getStatus()).isEqualTo(422);
        now=BASE;var signedBody=body();Files.writeString(ROOT.resolve(folder+"/tiny.pcap"),"changed");assertThat(call("",signedBody,operator,null,id()).getResponse().getStatus()).isEqualTo(422);
    }
    @Test void expiryTimeoutAndRevocationNeverClaimCleanup() throws Exception {
        create();op("decisions",object("decision","approve","reason","fixture"),"1");op("starts",object(),"2");
        now=BASE.plusSeconds(61);assertThat(executionGate.permits(executionObservation(),bundle,now)).isFalse();
        assertThat(op("reconciliations",object(),"3").path("runStatus").asText()).isEqualTo("interrupted");
        now=BASE.plusSeconds(8000);var expired=op("reconciliations",object(),"4");assertThat(expired.path("runStatus").asText()).isEqualTo("expired");
        assertThat(expired.path("cleanupStatus").asText()).isEqualTo("not_asserted");assertThat(expired.path("effectiveEligibility").asText()).isEqualTo("expired");
    }
    @Test void revokedSessionOrNewBootCannotRegainLegacyExecution() throws Exception {
        create();op("decisions",object("decision","approve","reason","fixture"),"1");op("starts",object(),"2");
        var changed=(ObjectNode)executionObservation();changed.put("bootId",id());assertThat(executionGate.permits(changed,bundle,now)).isFalse();
        var stopped=op("revocations",object("reason","fixture stop"),"3");
        assertThat(stopped.path("runStatus").asText()).isEqualTo("cancelled");assertThat(stopped.path("cleanupStatus").asText()).isEqualTo("not_asserted");
        assertThat(executionGate.permits(executionObservation(),bundle,now)).isFalse();
    }
    @Test void independentApprovalRechecksRevokedAuthorization() throws Exception {
        create();jdbc.update("UPDATE asset_authorization SET status='revoked',revision=revision+1 WHERE id=?",auth.get("id"));
        assertThat(call(route("decisions"),object("decision","approve","reason","fixture"),reviewer,"1",id()).getResponse().getStatus()).isEqualTo(422);
    }
    @Test void cachedStartDoesNotOutliveAuthorization() throws Exception {
        create();op("decisions",object("decision","approve","reason","fixture"),"1");String key=id();
        ok(call(route("starts"),object(),operator,"2",key));
        jdbc.update("UPDATE asset_authorization SET status='revoked',revision=revision+1 WHERE id=?",auth.get("id"));
        assertThat(call(route("starts"),object(),operator,"2",key).getResponse().getStatus()).isEqualTo(422);
        assertThat(executionGate.permits(executionObservation(),bundle,now)).isFalse();
    }
    @ParameterizedTest @ValueSource(strings={"authorization","revision","asset","executor","bundle","policy","artifact"})
    void machinePollFailsClosedOnCurrentInvalidState(String change) throws Exception {
        create();op("decisions",object("decision","approve","reason","fixture"),"1");op("starts",object(),"2");
        String expected;
        switch(change) {
            case "authorization" -> {jdbc.update("UPDATE asset_authorization SET status='revoked' WHERE id=?",auth.get("id"));expected="AUTHORIZATION_INACTIVE";}
            case "revision" -> {jdbc.update("UPDATE asset_authorization SET revision=revision+1 WHERE id=?",auth.get("id"));expected="AUTHORIZATION_INACTIVE";}
            case "asset" -> {jdbc.update("UPDATE asset SET environment='research' WHERE id=?",asset.get("id"));expected="LAB_ENVIRONMENT_INVALID";}
            case "executor" -> {jdbc.update("UPDATE guard_executor SET status='pending' WHERE id=?",executor.get("id"));expected="LAB_EXECUTOR_MISMATCH";}
            case "bundle" -> {jdbc.update("UPDATE guard_release_bundle SET status='suspended' WHERE id=?",bundle.get("id"));expected="LAB_BUNDLE_NOT_APPROVED";}
            case "policy" -> {jdbc.update("UPDATE guard_decision_policy SET status='retired' WHERE id=?",bundle.get("policy_id"));expected="LAB_BUNDLE_MISMATCH";}
            case "artifact" -> {Files.writeString(ROOT.resolve(folder+"/session.json"),"{}");expected="ARTIFACT_HASH_MISMATCH";}
            default -> throw new IllegalArgumentException(change);
        }
        var state=machineState();assertThat(state.path("runnable").asBoolean(true)).isFalse();
        assertThat(state.path("reasonCodes").toString()).contains(expected);
    }
    @Test void machinePollDoesNotTreatOrdinaryLeaseExpiryAsMetadataFailure() throws Exception {
        create();op("decisions",object("decision","approve","reason","fixture"),"1");op("starts",object(),"2");
        jdbc.update("UPDATE guard_target_binding SET expires_at=? WHERE id=?",db(BASE.minusSeconds(1)),target.get("id"));
        assertThat(machineState().path("reasonCodes")).isEqualTo(node(List.of("LAB_SYNTHETIC_ONLY")));
    }
    @Test void renewedTargetKeepsIdentityAndEventsRemainAppendOnly() throws Exception {
        create();op("decisions",object("decision","approve","reason","fixture"),"1");op("starts",object(),"2");
        jdbc.update("UPDATE guard_target_binding SET expires_at=? WHERE id=?",db(BASE.plusSeconds(1)),target.get("id"));
        var renewed=new LinkedHashMap<String,Object>(target);renewed.remove("id");renewed.remove("public_id");renewed.remove("created_at");
        var binding=(ObjectNode)json(target,"payload_json");binding.put("targetRef",id());renewed.put("target_ref",binding.path("targetRef").asText());
        renewed.put("expires_at",db(BASE.plusSeconds(60)));renewed.put("payload_json",canonical(binding));renewed.put("content_sha256",hash(binding));
        var lease=store.add("guard_target_binding",renewed);now=BASE.plusSeconds(10);
        var batch=add("guard_observation_batch","sensor_id",sensor.get("id"),"asset_id",asset.get("id"),"boot_id",sensor.get("guard_boot_id"),
                "sequence_no",1,"config_id",config.get("id"),"request_sha256",H,"result_json","{}");
        var o=(ObjectNode)parse(Files.readString(Path.of("../docs/contracts/examples/observation.json")));String observation=id();
        o.put("observationId",observation).put("assetId",str(asset,"public_id")).put("sensorId",str(sensor,"public_id")).put("bootId",str(sensor,"guard_boot_id"))
                .put("captureScopeId",str(scope,"public_id")).put("peerKey",H).put("environment","lab").put("direction","inbound")
                .put("targetRef",str(lease,"target_ref")).put("targetExpiresAt",BASE.plusSeconds(60).toString()).put("asOf",now.toString()).put("lastPacketAt",now.toString());
        store.insert("guard_observation",map("public_id",observation,"batch_id",batch.get("id"),"asset_id",asset.get("id"),"sensor_id",sensor.get("id"),"boot_id",sensor.get("guard_boot_id"),
                "capture_scope_id",scope.get("id"),"flow_id",o.path("flowId").asText(),"parent_connection_id",o.path("parentConnectionId").asText(),"snapshot_index",0,
                "profile","flow-prefix-v1","as_of",db(now),"last_packet_at",db(now),"peer_key",H,"key_epoch",1,"direction","inbound","transport","tcp","service_port",443,
                "environment","lab","payload_json",canonical(o),"content_sha256",hash(o),"created_at",db(now.plusSeconds(1))));
        var event=object("eventId",id(),"scenarioId","normal-1","kind","observation","referenceId",observation);
        assertThat(op("events",event,"3").at("/fact/occurredAt").asText()).isEqualTo(now.toString());
        assertThat(op("events",event,"4").path("duplicate").asBoolean()).isTrue();
        ((ObjectNode)event).put("eventId",id());assertThat(op("events",event,"4").path("duplicate").asBoolean()).isTrue();
        var client=clients.get(operator.id());var read=ok(mvc.perform(get("/api/v2/lab-validation-runs/"+manifest.path("sessionId").asText()+"/report-input").cookie(client.cookie())).andReturn());
        assertThat(read.at("/scenarios/0/quality/qualified").asInt()).isEqualTo(1);
        assertThat(read.at("/scenarios/0/quality/executionQualified").asInt()).isEqualTo(1);
        var nullRow=new LinkedHashMap<>(store.external("guard_observation",observation,false));nullRow.remove("id");nullRow.put("public_id",id());
        var nullPayload=o.deepCopy();nullPayload.put("observationId",str(nullRow,"public_id")).put("snapshotIndex",1).putNull("targetRef").putNull("targetExpiresAt");
        nullRow.put("snapshot_index",1);nullRow.put("payload_json",canonical(nullPayload));nullRow.put("content_sha256",hash(nullPayload));store.insert("guard_observation",nullRow);
        read=ok(mvc.perform(get("/api/v2/lab-validation-runs/"+manifest.path("sessionId").asText()+"/report-input").cookie(client.cookie())).andReturn());
        assertThat(read.at("/scenarios/0/quality/snapshots").asInt()).isEqualTo(2);
        assertThat(read.at("/scenarios/0/quality/missingTargetRef").asInt()).isEqualTo(1);
        assertThat(read.at("/scenarios/0/quality/executionQualified").asInt()).isEqualTo(1);
        op("interruptions",object("reason","test renewal"),"4");op("resumptions",object(),"5");
        jdbc.update("UPDATE guard_target_binding SET scope_digest=? WHERE id=?","f".repeat(64),lease.get("id"));
        ((ObjectNode)event).put("eventId",id());((ObjectNode)event).put("referenceId",id());
        assertThat(call(route("events"),event,operator,"6",id()).getResponse().getStatus()).isEqualTo(404);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM audit_log WHERE action='guard.lab.denied'",Long.class)).isGreaterThan(0);
    }
    @Test void concurrentApprovalHasOnlyOneWinner() throws Exception {
        create();try(var pool=Executors.newFixedThreadPool(2)) {
            var tasks=List.<Callable<Integer>>of(()->call(route("decisions"),object("decision","approve","reason","fixture"),reviewer,"1",id()).getResponse().getStatus(),
                    ()->call(route("decisions"),object("decision","approve","reason","fixture"),reviewer,"1",id()).getResponse().getStatus());
            var results=new ArrayList<Integer>();for(var f:pool.invokeAll(tasks))results.add(f.get());assertThat(results).containsExactlyInAnyOrder(200,409);
        }
    }
    @ParameterizedTest @ValueSource(strings={"approved","active"})
    void signedScenarioEventsAndReportCannotBeReusedAcrossSessions(String bundleStatus) throws Exception {
        create();op("decisions",object("decision","approve","reason","fixture"),"1");op("starts",object(),"2");now=BASE.plusSeconds(1801);
        var result=object("contractVersion",GuardLabContract.VERSION,"sessionId",manifest.get("sessionId"),"sessionSha256",hash(manifest),"scenarioId","normal-1",
                "mappingSha256",manifest.get("mappingSha256"),"startedAt",BASE.toString(),"endedAt",BASE.plusSeconds(1800).toString(),"completed",true);
        var file=write("result",result,true,"fixture-runner");var event=object("eventId",id(),"scenarioId","normal-1","kind","scenario_result","reportRef",file.get("ref"),"sha256",file.get("sha256"));
        op("events",event,"3");assertThat(op("events",event,"4").path("duplicate").asBoolean()).isTrue();
        op("completions",object("outcome","completed","reason","ended"),"4");
        var read=mvc.perform(get("/api/v2/lab-validation-runs/"+manifest.path("sessionId").asText()+"/report-input").cookie(clients.get(operator.id()).cookie())).andReturn();var input=ok(read);
        var report=GuardLabReport.generate(input);assertThat(report.path("passed").asBoolean()).isFalse();
        var reportFile=write("g3",report,true,"fixture-runner");var reportBody=object("reportRef",reportFile.get("ref"),"sha256",reportFile.get("sha256"),"runnerIdentity","fixture-runner");
        var client=clients.get(operator.id());
        // 通用导入只接受 candidate 组合；临时切回 candidate 以证明 G3 报告版本在通用入口被分流拒绝，随后恢复已批准状态。
        jdbc.update("UPDATE guard_release_bundle SET status='candidate' WHERE id=?",bundle.get("id"));
        var generic=mvc.perform(post("/api/v2/release-bundles/"+str(bundle,"public_id")+"/imports").cookie(client.cookie()).header("X-CSRF-TOKEN",client.csrf())
                .header("Idempotency-Key",id()).contentType("application/json").content(canonical(reportBody))).andReturn();
        assertThat(parse(generic.getResponse().getContentAsString()).at("/error/code").asText()).isEqualTo("LAB_REPORT_REQUIRES_SESSION_IMPORT");
        jdbc.update("UPDATE guard_release_bundle SET status=? WHERE id=?",bundleStatus,bundle.get("id"));
        var imported=op("reports",reportBody,"5");assertThat(imported.path("signatureVerified").asBoolean()).isTrue();assertThat(imported.path("passed").asBoolean()).isFalse();
        var qualifications=ok(mvc.perform(get("/api/v2/lab-validation-runs/"+manifest.path("sessionId").asText()+"/qualifications").cookie(client.cookie())).andReturn());
        assertThat(qualifications.path("sources")).isEmpty();assertThat(qualifications.path("bundleUsable").asBoolean()).isTrue();
        assertThat(mvc.perform(get("/api/v2/lab-validation-runs/"+manifest.path("sessionId").asText()+"/qualifications")
                .cookie(clients.get(outsider.id()).cookie())).andReturn().getResponse().getStatus()).isEqualTo(404);
        ((ObjectNode)report).put("sessionId",id());reportFile=write("g3-changed",report,true,"fixture-runner");((ObjectNode)reportBody).set("reportRef",reportFile.get("ref"));((ObjectNode)reportBody).set("sha256",reportFile.get("sha256"));
        assertThat(call(route("reports"),reportBody,operator,"6",id()).getResponse().getStatus()).isEqualTo(422);
        jdbc.update("UPDATE guard_release_bundle SET status='suspended' WHERE id=?",bundle.get("id"));
        assertThat(ok(mvc.perform(get("/api/v2/lab-validation-runs/"+manifest.path("sessionId").asText()+"/qualifications").cookie(client.cookie())).andReturn())
                .path("bundleUsable").asBoolean()).isFalse();
        assertThat(call(route("reports"),reportBody,operator,"6",id()).getResponse().getStatus()).isEqualTo(422);
        var denied=mvc.perform(get("/api/v2/lab-validation-runs/"+manifest.path("sessionId").asText()).cookie(clients.get(outsider.id()).cookie())).andReturn();assertThat(denied.getResponse().getStatus()).isEqualTo(404);
    }

    // ---- 任务单 6.2 补充覆盖：列表、批准组合、越权、篡改、非法迁移、research/lab 混用、授权过期、倍速与隔离证明 ----

    String code(MvcResult r) throws Exception {return parse(r.getResponse().getContentAsString()).at("/error/code").asText();}
    MvcResult listRuns(String query,IdentityPrincipal actor,Client client) throws Exception {
        return mvc.perform(get("/api/v2/lab-validation-runs"+query).cookie(client.cookie())).andReturn();
    }
    MvcResult v2(String path,JsonNode body,IdentityPrincipal actor) throws Exception {
        var client=clients.get(actor.id());
        return mvc.perform(post("/api/v2"+path).cookie(client.cookie()).header("X-CSRF-TOKEN",client.csrf()).header("Idempotency-Key",id())
                .contentType("application/json").content(canonical(body))).andReturn();
    }

    /** 列表只返回资产范围可见的会话；按运行状态过滤；不可见游标 404，非法状态 422，越权创建 403。 */
    @Test void listIsAssetScopedFilteredAndCreateRequiresPermission() throws Exception {
        assertThat(call("",body(),outsider,null,id()).getResponse().getStatus()).isEqualTo(403);
        String id=create().path("id").asText();
        var scoped=identity("none");
        jdbc.update("INSERT INTO sys_user_role(user_id,role_id,scope_type,scope_id) SELECT ?,id,'asset',? FROM sys_role WHERE role_key='auditor'",scoped.id(),Long.toString(number(asset,"id")));
        var scopedClient=login(scoped);
        var mine=ok(listRuns("?limit=1",scoped,scopedClient));
        assertThat(mine.path("items").size()).isEqualTo(1);assertThat(mine.at("/items/0/id").asText()).isEqualTo(id);
        assertThat(mine.at("/items/0/runStatus").asText()).isEqualTo("registered");assertThat(mine.path("nextCursor").isNull()).isTrue();
        assertThat(ok(listRuns("?status=registered",scoped,scopedClient)).path("items").size()).isEqualTo(1);
        assertThat(ok(listRuns("?status=running",scoped,scopedClient)).path("items").size()).isZero();
        assertThat(ok(listRuns("",outsider,clients.get(outsider.id()))).path("items").size()).isZero();
        assertThat(code(listRuns("?status=applied",scoped,scopedClient))).isEqualTo("INVALID_RUN_STATUS");
        assertThat(listRuns("?cursor="+id,outsider,clients.get(outsider.id())).getResponse().getStatus()).isEqualTo(404);
        assertThat(ok(listRuns("?cursor="+id,scoped,scopedClient)).path("items").size()).isZero();
    }

    /** 组合必须是已批准的 lab 组合：candidate 拒绝，research 组合即使已批准也拒绝。 */
    @Test void onlyApprovedLabBundleIsAdmitted() throws Exception {
        jdbc.update("UPDATE guard_release_bundle SET status='candidate',approved_by=NULL WHERE id=?",bundle.get("id"));
        assertThat(code(call("",body(),operator,null,id()))).isEqualTo("LAB_BUNDLE_NOT_APPROVED");
        jdbc.update("UPDATE guard_release_bundle SET status='approved',approved_by=?,environment='research' WHERE id=?",reviewer.id(),bundle.get("id"));
        assertThat(code(call("",body(),operator,null,id()))).isEqualTo("LAB_ENVIRONMENT_INVALID");
    }

    /** 场景/映射原件被替换（原字节哈希不符）或映射 ID、场景 ID 不一致时拒绝创建。 */
    @Test void tamperedScenarioOrMappingIsRejected() throws Exception {
        var b=body();Files.writeString(ROOT.resolve(folder+"/scenarios.json"),"{}");
        assertThat(code(call("",b,operator,null,id()))).isEqualTo("ARTIFACT_HASH_MISMATCH");
        writeInputs();b=body();Files.writeString(ROOT.resolve(folder+"/mapping.json"),"{}");
        assertThat(code(call("",b,operator,null,id()))).isEqualTo("ARTIFACT_HASH_MISMATCH");
        mapping.put("mappingId",id());writeInputs();
        assertThat(code(call("",body(),operator,null,id()))).isEqualTo("LAB_MAPPING_MISMATCH");
        mapping.set("mappingId",manifest.get("mappingId"));((ObjectNode)mapping.at("/entries/0")).put("scenarioId","unregistered-1");writeInputs();
        assertThat(code(call("",body(),operator,null,id()))).isEqualTo("LAB_SCENARIO_UNKNOWN");
    }

    /** 非法迁移：未开始就完成、完成后再开始/中断，均 422 STATE_CONFLICT 且不改 revision。 */
    @Test void illegalTransitionsAreRejected() throws Exception {
        create();op("decisions",object("decision","approve","reason","fixture"),"1");
        assertThat(code(call(route("completions"),object("outcome","completed","reason","early"),operator,"2",id()))).isEqualTo("STATE_CONFLICT");
        op("starts",object(),"2");op("completions",object("outcome","completed","reason","ended"),"3");
        assertThat(code(call(route("starts"),object(),operator,"4",id()))).isEqualTo("STATE_CONFLICT");
        assertThat(code(call(route("interruptions"),object("reason","late"),operator,"4",id()))).isEqualTo("STATE_CONFLICT");
        assertThat(code(call(route("completions"),object("outcome","failed","reason","again"),operator,"4",id()))).isEqualTo("STATE_CONFLICT");
        assertThat(ok(mvc.perform(get("/api/v2/lab-validation-runs/"+manifest.path("sessionId").asText()).cookie(clients.get(operator.id()).cookie())).andReturn())
                .path("revision").asLong()).isEqualTo(4);
    }

    /** research 接口不能携带 lab 运行类型或使用 lab 组合；lab 接口不能接收 research 清单；两类 ID 不互通。 */
    @Test void researchAndLabRunsCannotBeMixed() throws Exception {
        String modelId=str(store.get("guard_model",number(bundle,"model_id")),"public_id"),policyId=str(store.get("guard_decision_policy",number(bundle,"policy_id")),"public_id");
        var research=object("scenarioId",id(),"scenarioSha256",H,"modelId",modelId,"policyId",policyId,"speed",1);
        assertThat(code(v2("/replay-runs",research,operator))).isEqualTo("REPLAY_BUNDLE_NOT_APPROVED");
        for(String field:List.of("environment","runKind")) {
            var withLab=research.deepCopy();withLab.put(field,field.equals("environment")?"lab":"canary");
            assertThat(code(v2("/replay-runs",withLab,operator))).isEqualTo("UNKNOWN_FIELD");
        }
        String labId=create().path("id").asText();
        var client=clients.get(operator.id());
        assertThat(mvc.perform(get("/api/v2/replay-runs/"+labId).cookie(client.cookie())).andReturn().getResponse().getStatus()).isEqualTo(404);
        assertThat(v2("/replay-runs/"+labId+"/starts",object("scenarioRef","x","closeoutRef","y","bindings",List.of()),operator).getResponse().getStatus()).isEqualTo(404);
        manifest.put("sessionId",id()).put("environment","research");
        assertThat(code(call("",body(),operator,null,id()))).isEqualTo("LAB_CONTRACT_INVALID");
    }

    /** lab 执行授权过期后不能开始；evaluation.run 本身不补足授权。 */
    @Test void expiredAuthorizationBlocksStart() throws Exception {
        create();op("decisions",object("decision","approve","reason","fixture"),"1");
        jdbc.update("UPDATE asset_authorization SET valid_until=? WHERE id=?",db(BASE.minusSeconds(1)),auth.get("id"));
        assertThat(code(call(route("starts"),object(),operator,"2",id()))).isEqualTo("AUTHORIZATION_INACTIVE");
        assertThat(executionGate.permits(executionObservation(),bundle,now)).isFalse();
    }

    /** 固定 1 倍速；隔离证明必须由独立身份签署、声明网络隔离且有效期覆盖整个会话。 */
    @Test void speedIsFixedAndIsolationProofMustCoverSession() throws Exception {
        manifest.put("speed",2);assertThat(call("",body(),operator,null,id()).getResponse().getStatus()).isEqualTo(400);
        manifest.put("speed",1);
        var isolationProof=object("sessionId",manifest.get("sessionId"),"assetId",manifest.get("assetId"),"executorId",manifest.get("executorId"),
                "mappingSha256",manifest.get("mappingSha256"),"networkIsolationVerified",true,"validUntil",BASE.plusSeconds(3600).toString());
        ((ObjectNode)manifest.get("proofs")).set("isolation",write("isolation-short",isolationProof,true,"fixture-isolation"));
        assertThat(code(call("",body(),operator,null,id()))).isEqualTo("LAB_ISOLATION_UNVERIFIED");
        isolationProof.put("validUntil",manifest.path("validUntil").asText()).put("networkIsolationVerified",false);
        ((ObjectNode)manifest.get("proofs")).set("isolation",write("isolation-unverified",isolationProof,true,"fixture-isolation"));
        assertThat(code(call("",body(),operator,null,id()))).isEqualTo("LAB_ISOLATION_UNVERIFIED");
        isolationProof.put("networkIsolationVerified",true);
        ((ObjectNode)manifest.get("proofs")).set("isolation",write("isolation-self",isolationProof,true,"fixture-runner"));
        assertThat(code(call("",body(),operator,null,id()))).isEqualTo("LAB_ISOLATION_UNVERIFIED");
    }
}
