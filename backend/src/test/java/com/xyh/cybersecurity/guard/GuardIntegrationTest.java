package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import jakarta.servlet.http.Cookie;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.*;
import org.springframework.test.web.servlet.*;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.sql.DriverManager;
import java.time.*;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;

/** 固定 ONNX、隔离 MySQL、专用测试身份完成 P4 API/事务闭环，不调用真实防火墙。 */
@SpringBootTest(properties={"cyber.ingest.consumer.enabled=false","cyber.ingest.outbox-relay.enabled=false","cyber.drift.enabled=false","cyber.guard.automation-enabled=true","cyber.security.local-admin-bootstrap.enabled=false"})
@AutoConfigureMockMvc
@EnabledIfEnvironmentVariable(named="DB_TEST_BASE_URL",matches=".+")
class GuardIntegrationTest {
    static final String SCHEMA="cyber_guard_api_p4_"+UUID.randomUUID().toString().replace("-","");
    static final Path ROOT=Path.of("target/guard-fixtures").toAbsolutePath();
    static final JsonNode PROTECTION=object("protectedBudgetTargetIds",List.of(),"protectedServicePorts",List.of(22,3389));
    static KeyPair signing;
    @DynamicPropertySource static void props(DynamicPropertyRegistry r)throws Exception{
        Files.createDirectories(ROOT);signing=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();Files.write(ROOT.resolve("signing.der"),signing.getPrivate().getEncoded());Files.setPosixFilePermissions(ROOT.resolve("signing.der"),PosixFilePermissions.fromString("rw-------"));
        Files.writeString(ROOT.resolve("trust.json"),canonical(object("fixture-runner",Base64.getEncoder().encodeToString(signing.getPublic().getEncoded()))));Files.writeString(ROOT.resolve("protection.json"),canonical(PROTECTION));
        String base=System.getenv("DB_TEST_BASE_URL").replaceAll("/+$","");String username=System.getenv("DB_TEST_USERNAME"),password=System.getenv("DB_TEST_PASSWORD");
        try(var c=DriverManager.getConnection(base,username,password);var s=c.createStatement()){s.execute("CREATE DATABASE "+SCHEMA+" CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin");}
        String url=base+"/"+SCHEMA+"?connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true";Flyway.configure().dataSource(url,username,password).load().migrate();
        r.add("spring.datasource.url",()->url);r.add("spring.datasource.username",()->username);r.add("spring.datasource.password",()->password);r.add("spring.flyway.enabled",()->false);r.add("cyber.security.login-throttle.hmac-key",()->"isolated-test-key-with-more-than-thirty-two-bytes");
        r.add("cyber.guard.artifact-root",()->ROOT.toString());r.add("cyber.guard.signing-key-id",()->"fixture-control");r.add("cyber.guard.signing-key-file",()->ROOT.resolve("signing.der").toString());r.add("cyber.guard.report-trust-file",()->ROOT.resolve("trust.json").toString());r.add("cyber.guard.protection-file",()->ROOT.resolve("protection.json").toString());
    }
    @AfterAll static void dropOwnSchema()throws Exception{
        String base=System.getenv("DB_TEST_BASE_URL").replaceAll("/+$","");
        try(var c=DriverManager.getConnection(base,System.getenv("DB_TEST_USERNAME"),System.getenv("DB_TEST_PASSWORD"));var st=c.createStatement()){st.execute("DROP DATABASE IF EXISTS "+SCHEMA);}
    }
    static final String TEST_PASSWORD="isolated-test-password";
    @Autowired MockMvc mvc;@Autowired JdbcTemplate jdbc;@Autowired GuardDetection detection;@Autowired GuardStore store;@Autowired GuardContracts contracts;@Autowired GuardBudget budget;@Autowired GuardModelRuntime runtime;@Autowired PlatformTransactionManager manager;@Autowired PasswordEncoder passwordEncoder;
    IdentityPrincipal operator,reviewer;
    @BeforeEach void identities(){operator=identity("operator",List.of("platform_admin","model_operator","security_analyst"));reviewer=identity("reviewer",List.of("security_reviewer"));}
    IdentityPrincipal identity(String suffix,List<String> roles){String key=id(),username=suffix+"-"+key;jdbc.update("INSERT INTO sys_user(user_key,username,display_name,password_hash,status) VALUES (?,?,?,?, 'active')",key,username,"隔离测试身份",passwordEncoder.encode(TEST_PASSWORD));Long uid=jdbc.queryForObject("SELECT id FROM sys_user WHERE user_key=?",Long.class,key);for(String role:roles)jdbc.update("INSERT INTO sys_user_role(user_id,role_id,scope_type,scope_id) SELECT ?,id,'global','*' FROM sys_role WHERE role_key=?",uid,role);return new IdentityPrincipal(uid,key,username,"隔离测试身份","test-only-no-login","active",roles,List.of());}
    JsonNode human(String path,JsonNode body,IdentityPrincipal actor,String revision)throws Exception{return human(path,body,actor,revision,id());}
    record HumanSession(Cookie cookie,String csrfToken){}
    HumanSession humanSession(IdentityPrincipal actor)throws Exception{
        var bootstrap=mvc.perform(get("/api/v1/auth/csrf")).andReturn();
        assertThat(bootstrap.getResponse().getStatus()).isEqualTo(200);
        Cookie bootstrapCookie=bootstrap.getResponse().getCookie("SESSION");
        String bootstrapToken=parse(bootstrap.getResponse().getContentAsString()).path("data").path("token").asText();
        assertThat(bootstrapCookie).isNotNull();assertThat(bootstrapToken).isNotBlank();
        var login=mvc.perform(post("/api/v1/auth/login").cookie(bootstrapCookie).header("X-CSRF-TOKEN",bootstrapToken).contentType("application/json").content(canonical(object("username",actor.getUsername(),"password",TEST_PASSWORD)))).andReturn();
        assertThat(login.getResponse().getStatus()).isEqualTo(200);
        Cookie sessionCookie=login.getResponse().getCookie("SESSION");
        assertThat(sessionCookie).isNotNull();
        var csrfResult=mvc.perform(get("/api/v1/auth/csrf").cookie(sessionCookie)).andReturn();
        assertThat(csrfResult.getResponse().getStatus()).isEqualTo(200);
        String csrfToken=parse(csrfResult.getResponse().getContentAsString()).path("data").path("token").asText();
        assertThat(csrfToken).isNotBlank();
        return new HumanSession(sessionCookie,csrfToken);
    }
    JsonNode human(String path,JsonNode body,IdentityPrincipal actor,String revision,String key)throws Exception{
        var session=humanSession(actor);var req=post("/api/v2"+path).cookie(session.cookie()).header("X-CSRF-TOKEN",session.csrfToken()).header("Idempotency-Key",key).contentType("application/json").content(canonical(body));if(revision!=null)req.header("If-Match",revision);
        return result(mvc.perform(req).andReturn());}
    JsonNode machine(String path,JsonNode body,String credential)throws Exception{return machine(path,body,credential,id());}
    JsonNode machine(String path,JsonNode body,String credential,String key)throws Exception{return result(mvc.perform(post("/api/v2/machine"+path).header("Authorization","Bearer "+credential).header("Idempotency-Key",key).contentType("application/json").content(canonical(body))).andReturn());}
    JsonNode result(MvcResult r) throws Exception {JsonNode n=parse(r.getResponse().getContentAsString());assertThat(r.getResponse().getStatus()).withFailMessage("HTTP %s: %s",r.getResponse().getStatus(),n).isBetween(200,299);assertThat(n.path("requestId").asText()).isNotBlank();return n.get("data");}
    record Fixture(String asset,String sensor,String sensorCredential,String executor,String executorCredential,String scope,String config,String configHash,String boot,String executorBoot,String capability,String model,String policy,String bundle,String authorization,String target,String token,String targetId,String capabilityHash){}
    Fixture setup()throws Exception{return setup("dos_slow",List.of());}
    Fixture setup(String family,List<JsonNode> rules)throws Exception{return setup(family,rules,false);}
    /** exempt=true 时登记带签名豁免报告的 macOS PF 全入站能力（B1.2），其余步骤与普通夹具相同。 */
    Fixture setup(String family,List<JsonNode> rules,boolean exempt)throws Exception{
        boolean scan=family.equals("port_scan");String direction=scan?"inbound":"outbound";
        String folder=id();Path dir=ROOT.resolve(folder);Files.createDirectories(dir);
        String asset=human("/assets",object("assetKey",id(),"platform","macos","environment","lab","owner","isolated-p4-test"),operator,null).path("id").asText();
        ObjectNode cap=object("capabilityKey",id(),"version","fixture-v1","platform","macos","adapterVersion","fixture-1","addressFamily","ipv4","transport","tcp","direction",direction,"family",family,"profile","flow-prefix-v1","behaviorScope",List.of("slowloris","slowhttptest"),"latencyLimits",object("maxMs",10000),"level","lab_auto");
        if(exempt){write(dir,"exemption.json",GuardSignatures.sign(object("passed",true,"scope","peer_inbound","platform","macos-pf","protectionSetSha256",hash(PROTECTION)),"fixture-runner",signing.getPrivate()));
            cap.put("scope","peer_inbound").put("protectionSetSha256",hash(PROTECTION)).put("exemptionEvidenceSha256",sha(Files.readAllBytes(dir.resolve("exemption.json"))));}
        JsonNode signed=GuardSignatures.sign(object("passed",true,"protocolVersions",versions(),"capability",cap),"fixture-runner",signing.getPrivate());write(dir,"capability.json",signed);cap.put("evidenceRef",folder+"/capability.json").put("evidenceSha256",sha(Files.readAllBytes(dir.resolve("capability.json")))).put("runnerIdentity","fixture-runner");if(exempt)cap.put("exemptionEvidenceRef",folder+"/exemption.json");
        String capability=human("/capabilities",cap,operator,null).path("id").asText();
        Instant now=Instant.now().truncatedTo(ChronoUnit.MILLIS);
        String auth=human("/assets/"+asset+"/authorizations",object("interfaces",List.of("fixture0"),"observationAllowed",true,"executionScopes",List.of(object("scope",scan?"peer_inbound":"peer_service","direction",direction,"transport","tcp","servicePort",scan?null:443,"addressFamily","ipv4","capabilityId",capability)),"validFrom",now.minusSeconds(60).toString(),"validUntil",now.plusSeconds(3600).toString(),"evidenceRef","fixture:isolated-test"),operator,null).path("id").asText();
        human("/authorizations/"+auth+"/decisions",object("decision","approve","reason","隔离测试批准"),reviewer,"1");
        String scope=id();JsonNode sensor=human("/sensors",object("assetId",asset,"platform","macos","captureScopeId",scope),operator,null);JsonNode executor=human("/executors",object("assetId",asset,"platform","macos","capabilityProbeRef","fixture:probe"),operator,null);
        JsonNode config=object("contractVersion",CONTRACT,"profileSha256",contracts.profileHash(),"captureHealthVersion",HEALTH,"interfaceIds",List.of("fixture0"),"limits",object("maxBatchSize",100),"captureScopeId",scope,"addressFamily","ipv4","buildSha256","b".repeat(64));
        String configId=human("/sensors/"+sensor.path("id").asText()+"/configs",config,operator,null).path("id").asText();human("/sensor-configs/"+configId+"/decisions",object("decision","approve","reason","隔离测试配置"),reviewer,"1");
        String boot=id(),eboot=id();machine("/sensors/"+sensor.path("id").asText()+"/heartbeats",object("bootId",boot,"version","fixture-1","configHash",hash(config),"lastSequence",0,"clockSkewMs",0),sensor.path("credential").asText());
        machine("/executors/"+executor.path("id").asText()+"/heartbeats",object("bootId",eboot,"adapterVersion","fixture-1","capabilityHash","c".repeat(64),"pendingRecovery",false,"activeRuleCount",0,"clockSkewMs",0),executor.path("credential").asText());
        String eid=executor.path("id").asText();JsonNode normalized=object("digestVersion","guard-state/1","assetId",asset,"executorId",eid,"executorBootId",eboot,"rules",List.of(),"pendingRevocations",List.of());
        machine("/executors/"+eid+"/reconciliations",object("executorBootId",eboot,"observedAt",Instant.now().truncatedTo(ChronoUnit.MICROS).toString(),"digestVersion","guard-state/1","stateDigest",hash(normalized),"ownedRules",List.of(),"pendingRevocations",List.of(),"recoveryErrors",List.of()),executor.path("credential").asText());
        write(dir,"dataset.json",object("datasetKey",id(),"version","fixture"));String dataset=human("/datasets",object("manifestRef",folder+"/dataset.json","manifestSha256",sha(Files.readAllBytes(dir.resolve("dataset.json")))),operator,null).path("id").asText();
        ObjectNode plan=object("planKey",id(),"version","fixture","protocolVersions",versions(),"datasetRefs",List.of(dataset),"splitHashes",object("train","1".repeat(64),"selection","2".repeat(64),"calibration","3".repeat(64),"development","4".repeat(64)),"behaviorSourceScope",List.of(object("source","fixture","behaviors",List.of("slowloris","slowhttptest"))),"scenarioMappingSha256","a".repeat(64),"labelTimelineSha256","a".repeat(64),"captureHealthSha256","a".repeat(64),"latencyRegistration",object("maxMs",10000),"metrics",object("unit","episode"),"budget",object("maxSeconds",120),"scenarioRefs",List.of("fixture"));
        JsonNode registeredPlan=human("/evaluation-plans",plan,operator,null);
        Files.write(dir.resolve("model.onnx"),GuardOnnxFixture.model(.999f,scan?.999f:0,0,0,scan?0:.999f));write(dir,"preprocessing.json",object("fitRole","train","vocabularies",List.of(List.of("tcp"),List.of("outbound"),List.of("web"))));write(dir,"calibration.json",object("fitRole","calibration","kind","fixed-test-only"));
        ObjectNode manifest=(ObjectNode)GuardDomainTest.example("model-manifest");String model=id();for(var supported:manifest.path("supportedScope"))((ObjectNode)supported).put("direction",direction);manifest.put("modelId",model).put("modelVersion",folder).put("featureProfileSha256",contracts.profileHash()).put("evaluationPlanSha256",registeredPlan.path("planSha256").asText());
        for(var pair:Map.of("artifactSha256","model.onnx","preprocessingSha256","preprocessing.json","calibrationSha256","calibration.json").entrySet())manifest.put(pair.getKey(),sha(Files.readAllBytes(dir.resolve(pair.getValue()))));((ObjectNode)manifest.get("runtime")).put("runtimeVersion","1.23.2");write(dir,"manifest.json",manifest);
        human("/models",object("manifestRef",folder+"/manifest.json","manifestSha256",sha(Files.readAllBytes(dir.resolve("manifest.json")))),operator,null);assertThat(human("/models/"+model+"/validations",object("validationProfileId","host-guard-onnx-v1"),operator,null).path("status").asText()).isEqualTo("validated");
        ObjectNode policy=(ObjectNode)GuardDomainTest.example("decision-policy");String pid=id();policy.put("policyId",pid).put("modelId",model).put("policyVersion",folder).put("mode","auto").put("minDistinctFlows",1).put("minEvidenceSpanMs",0).put("protectionSetSha256",hash(PROTECTION)).put("evaluationPlanSha256",registeredPlan.path("planSha256").asText());policy.put("family",family);for(var fp:policy.path("familyPolicies"))if(fp.path("family").asText().equals(family))((ObjectNode)fp).put("autoEligible",true).put("modelAutoEligible",true).put("minDistinctFlows",scan?2:1);
        policy.set("rulePolicies",node(rules));policy.set("supportedCapabilityIds",node(List.of(capability)));human("/decision-policies",policy,operator,null);human("/decision-policies/"+pid+"/reviews",object("decision","approve","reason","隔离测试策略"),reviewer,"1");
        JsonNode bundle=human("/release-bundles",object("modelId",model,"policyId",pid,"featureProfileSha256",contracts.profileHash(),"extractorSha256",manifest.get("extractorSha256"),"protocolVersions",versions(),"evaluationPlanId",registeredPlan.get("id"),"capabilityIds",List.of(capability),"environment","lab"),operator,null);String bid=bundle.path("id").asText();var evaluationIds=new ArrayList<String>();
        for(String kind:List.of("final","platform","canary")){write(dir,kind+".json",GuardSignatures.sign(object("protocolVersions",versions(),"subjectSha256",bundle.get("subjectSha256"),"evaluationPlanSha256",registeredPlan.get("planSha256"),"runKind",kind,"passed",true),"fixture-runner",signing.getPrivate()));evaluationIds.add(human("/release-bundles/"+bid+"/imports",object("reportRef",folder+"/"+kind+".json","sha256",sha(Files.readAllBytes(dir.resolve(kind+".json"))),"runnerIdentity","fixture-runner"),operator,null).path("id").asText());}
        human("/release-bundles/"+bid+"/sealings",object("evaluationIds",evaluationIds),operator,"1");human("/release-bundles/"+bid+"/decisions",object("decision","approve","reason","隔离固定夹具批准"),reviewer,"2");human("/release-bundles/"+bid+"/activations",object("assetIds",List.of(asset),"authorizationIds",List.of(auth)),reviewer,"3");
        // 执行器按本机登记上报能力集合摘要；控制面领取时按 guard_capability 独立重算（B1.4）。
        JsonNode item=exempt?object("capabilityId",capability,"scope","peer_inbound","protectionSetSha256",hash(PROTECTION),"protectedPortsSha256",GuardEligibility.protectedPortsSha256(PROTECTION.get("protectedServicePorts")))
                :object("capabilityId",capability,"scope","peer_service","protectionSetSha256",null,"protectedPortsSha256",null);String capabilityHash=GuardEligibility.capabilitySetSha256(List.of(item));
        machine("/executors/"+eid+"/heartbeats",object("bootId",eboot,"adapterVersion","fixture-1","capabilityHash",capabilityHash,"pendingRecovery",false,"activeRuleCount",0,"clockSkewMs",0),executor.path("credential").asText());
        String target=id(),token=sha(id().getBytes());ObjectNode binding=(ObjectNode)targetBody(eid,sensor.path("id").asText(),scope,boot,eboot,target,token);binding.put("scope",scan?"peer_inbound":"peer_service").put("direction",direction);if(scan)binding.putNull("servicePort");
        String targetId=machine("/executors/"+eid+"/target-bindings",binding,executor.path("credential").asText()).path("budgetTargetId").asText();
        Fixture f=new Fixture(asset,sensor.path("id").asText(),sensor.path("credential").asText(),eid,executor.path("credential").asText(),scope,configId,hash(config),boot,eboot,capability,model,pid,bid,auth,target,token,targetId,capabilityHash);
        var h=GuardDomainTest.health(Instant.now().truncatedTo(ChronoUnit.MICROS),1,null);h.put("assetId",asset).put("sensorId",f.sensor).put("captureScopeId",scope).put("configSha256",hash(config));machine("/sensors/"+f.sensor+"/health-windows",h,f.sensorCredential);return f;
    }
    JsonNode targetBody(String eid,String sensor,String scope,String boot,String eboot,String target,String token){return object("bindingId",id(),"executorBootId",eboot,"sensorId",sensor,"collectorBootId",boot,"captureScopeId",scope,"targetRef",target,"peerKey","d".repeat(64),"keyEpoch",1,"direction","outbound","transport","tcp","servicePort",443,"addressFamily","ipv4","stableTargetToken",token,"scopeDigest",sha(token.getBytes()),"expiresAt",Instant.now().plusSeconds(14).truncatedTo(ChronoUnit.MICROS).toString());}
    void write(Path dir,String name,JsonNode n)throws Exception{Files.writeString(dir.resolve(name),canonical(n));}
    ObjectNode observation(Fixture f,Instant at,String parent,int index)throws Exception{var o=GuardDomainTest.observation(at);o.put("observationId",id()).put("assetId",f.asset).put("sensorId",f.sensor).put("bootId",f.boot).put("captureScopeId",f.scope).put("flowId",parent).put("parentConnectionId",parent).put("snapshotIndex",index).put("environment","lab").put("peerKey","d".repeat(64)).put("targetRef",f.target).put("targetExpiresAt",at.plusSeconds(14).toString());return o;}
    JsonNode batch(Fixture f,List<? extends JsonNode> os,long sequence){return object("batchId",id(),"bootId",f.boot,"sequence",sequence,"configId",f.config,"contractVersion",CONTRACT,"profileSha256",contracts.profileHash(),"observations",os);}
    @Test void completeIngestInferenceDecisionClaimRevocationAndReceiptOrdering()throws Exception{
        Fixture f=setup();Instant at=Instant.now().truncatedTo(ChronoUnit.MICROS);JsonNode b=batch(f,List.of(observation(f,at,id(),0)),1);String requestKey=id();JsonNode accepted=machine("/sensors/"+f.sensor+"/observation-batches",b,f.sensorCredential,requestKey);assertThat(accepted.path("acceptedCount").asInt()).isEqualTo(1);assertThat(machine("/sensors/"+f.sensor+"/observation-batches",b,f.sensorCredential,requestKey)).isEqualTo(accepted);
        String event=id();detection.consume(event,"guard.observation.accepted",object("batchId",b.get("batchId")));detection.consume(event,"guard.observation.accepted",object("batchId",b.get("batchId")));
        var asset=store.external("asset",f.asset,false);var decisions=store.rows("guard_decision",map("asset_id",asset.get("id")),false,20);assertThat(decisions).hasSize(1);assertThat(str(decisions.getFirst(),"decision")).withFailMessage("decision: %s",json(decisions.getFirst(),"evidence_json")).isEqualTo("block_candidate");
        var action=store.one("guard_action",map("asset_id",asset.get("id")),false);assertThat(action).isNotNull();JsonNode claimBody=object("bootId",f.executorBoot,"capabilityHash",f.capabilityHash(),"maxItems",10,"waitSeconds",0);String claimKey=id();var claims=machine("/executors/"+f.executor+"/command-claims",claimBody,f.executorCredential,claimKey);assertThat(claims.path("commands")).hasSize(1);JsonNode command=claims.path("commands").get(0);contracts.validate("action-command",command);
        assertThat(machine("/executors/"+f.executor+"/command-claims",claimBody,f.executorCredential,claimKey).get("commands")).isEqualTo(claims.get("commands"));
        String aid=str(action,"public_id");human("/actions/"+aid+"/revocations",object("reason","隔离测试撤销"),reviewer,"2");assertThat(machine("/executors/"+f.executor+"/command-claims",claimBody,f.executorCredential,claimKey).get("commands")).isEmpty();
        var revoked=machine("/executors/"+f.executor+"/command-claims",claimBody,f.executorCredential);assertThat(revoked.path("revocations")).hasSize(1);assertThat(str(store.external("guard_action",aid,false),"observed_state")).isEqualTo("dispatched");
        JsonNode empty=object("digestVersion","guard-state/1","assetId",f.asset,"executorId",f.executor,"executorBootId",f.executorBoot,"rules",List.of(),"pendingRevocations",List.of());String digest=hash(empty);Instant time=Instant.now().truncatedTo(ChronoUnit.MICROS);JsonNode receipt=object("contractVersion",CONTRACT,"receiptId",id(),"commandId",command.at("/payload/commandId"),"revocationId",revoked.path("revocations").get(0).get("revocationId"),"executorId",f.executor,"status","revoked","observedAt",time.toString(),"ruleHandle",null,"effectiveBlockUntil",null,"errorCode",null,"stateDigest",digest);
        machine("/executors/"+f.executor+"/receipts",receipt,f.executorCredential);
        machine("/executors/"+f.executor+"/reconciliations",object("executorBootId",f.executorBoot,"observedAt",time.toString(),"digestVersion","guard-state/1","stateDigest",digest,"ownedRules",List.of(),"pendingRevocations",List.of(),"recoveryErrors",List.of()),f.executorCredential);
        assertThat(str(store.external("guard_action",aid,false),"observed_state")).isEqualTo("revoked");assertThat(number(store.one("guard_target_budget",map("budget_target_id",store.external("guard_budget_target",f.targetId,false).get("id")),false),"charged_ms")).isPositive();
        var clearance=machine("/executors/"+f.executor+"/clearance-proofs",object("commandId",command.at("/payload/commandId"),"clearedAt",time.toString(),"stateDigest",digest),f.executorCredential);
        assertThat(clearance.path("persisted").asBoolean()).isTrue();assertThat(clearance.path("budgetReset").asBoolean()).isFalse();
        ObjectNode late=(ObjectNode)receipt.deepCopy();late.put("receiptId",id()).put("status","applied").put("ruleHandle","fixture-rule").set("effectiveBlockUntil",command.at("/payload/blockUntil"));late.putNull("revocationId");machine("/executors/"+f.executor+"/receipts",late,f.executorCredential);assertThat(str(store.external("guard_action",aid,false),"observed_state")).isEqualTo("revoked");
    }
    void accept(Fixture f,List<? extends JsonNode> observations,long sequence,boolean consume)throws Exception{
        var b=batch(f,observations,sequence);assertThat(machine("/sensors/"+f.sensor+"/observation-batches",b,f.sensorCredential).path("acceptedCount").asInt()).isEqualTo(observations.size());
        if(consume)detection.consume(id(),"guard.observation.accepted",object("batchId",b.get("batchId")));
    }
    @Test void scanGroupsPortsButKeepsModelRuleAndIdentitySeparate()throws Exception{
        var rule=object("ruleId","scan-context","family","port_scan","field","features.elapsedMs","operator","gte","threshold",4000,"autoEligible",false);
        Fixture f=setup("port_scan",List.of(rule));Instant at=Instant.now().truncatedTo(ChronoUnit.MICROS);
        var first=observation(f,at,id(),0).put("direction","inbound").put("servicePort",80);
        var second=observation(f,at,id(),0).put("direction","inbound").put("servicePort",443);
        accept(f,List.of(first,second),1,true);var asset=store.external("asset",f.asset,false);
        var episodes=store.rows("guard_episode",map("asset_id",asset.get("id")),false,20);assertThat(episodes).hasSize(2);
        for(var e:episodes){assertThat(e.get("service_port")).isNull();assertThat(str(e,"scope")).isEqualTo("peer_inbound");assertThat(store.rows("guard_episode_evidence",map("episode_id",e.get("id")),false,10)).hasSize(2);}
        var model=episodes.stream().filter(e->str(e,"source").equals("model")).findFirst().orElseThrow();var decision=store.one("guard_decision",map("episode_id",model.get("id")),false);
        assertThat(str(decision,"reason_code")).isEqualTo("PROTECTION_OR_BUDGET_BLOCKED");assertThat(json(decision,"evidence_json").path("detailCode").asText()).isEqualTo("PROTECTED_SERVICE");assertThat(store.rows("guard_action",map("asset_id",asset.get("id")),false,10)).isEmpty();
        // NULL 端口经生成列归一化后同样受唯一键约束。
        assertThatThrownBy(()->jdbc.update("INSERT INTO guard_episode(public_id,asset_id,sensor_id,boot_id,peer_key,key_epoch,direction,transport,service_port,family,scope,source,rule_id,bundle_id,bucket_start) SELECT UUID(),asset_id,sensor_id,boot_id,peer_key,key_epoch,direction,transport,service_port,family,scope,source,rule_id,bundle_id,bucket_start FROM guard_episode WHERE id=?",model.get("id"))).isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
        var different=observation(f,Instant.now().truncatedTo(ChronoUnit.MICROS),id(),0).put("direction","inbound").put("servicePort",8080).put("keyEpoch",2);
        accept(f,List.of(different),2,true);var isolated=store.one("guard_episode",map("asset_id",asset.get("id"),"key_epoch",2,"source","model"),false);assertThat(store.rows("guard_episode_evidence",map("episode_id",isolated.get("id")),false,10)).hasSize(1);
        var target=store.one("guard_target_binding",map("target_ref",f.target),false);var policy=json(store.external("guard_decision_policy",f.policy,false),"definition_json");
        assertThat(new GuardEligibility(store,true,ROOT.resolve("protection.json").toString()).target(target,first,store.now(),policy,"dos_slow")).isFalse();
    }
    /** B1：全入站豁免五条件满足时 lab 可签发全入站命令并审计预期区间；能力集合不符只下发撤销。 */
    @Test void exemptInboundCapabilityIssuesCommandWithAuditedRangesInLab()throws Exception{
        Fixture f=setup("port_scan",List.of(),true);var cap=store.external("guard_capability",f.capability(),false);
        assertThat(str(cap,"scope")).isEqualTo("peer_inbound");assertThat(str(cap,"protection_set_sha256")).isEqualTo(hash(PROTECTION));assertThat(str(cap,"exemption_evidence_sha256")).isNotNull();
        Instant at=Instant.now().truncatedTo(ChronoUnit.MICROS);
        accept(f,List.of(observation(f,at,id(),0).put("direction","inbound").put("servicePort",80),observation(f,at,id(),0).put("direction","inbound").put("servicePort",22)),1,true);
        var asset=store.external("asset",f.asset(),false);var actions=store.rows("guard_action",map("asset_id",asset.get("id")),false,10);
        assertThat(actions).withFailMessage("decisions: %s",store.rows("guard_decision",map("asset_id",asset.get("id")),false,10)).hasSize(1);
        JsonNode body=object("bootId",f.executorBoot(),"capabilityHash",f.capabilityHash(),"maxItems",10,"waitSeconds",0);
        var claims=machine("/executors/"+f.executor()+"/command-claims",body,f.executorCredential());assertThat(claims.path("commands")).hasSize(1);
        JsonNode command=claims.path("commands").get(0);contracts.validate("action-command",command);var payload=command.path("payload");
        assertThat(payload.path("scope").asText()).isEqualTo("peer_inbound");assertThat(payload.path("servicePort").isNull()).isTrue();assertThat(payload.path("capabilityId").asText()).isEqualTo(f.capability());
        // 审计只存摘要：用对拍向量同一算法重算 P4 预期区间，P5 侧由同一保护端口得到相同结果。
        String commandId=payload.path("commandId").asText();var ports=PROTECTION.get("protectedServicePorts");
        JsonNode expected=object("commandId",commandId,"capabilityId",f.capability(),"protectionSetSha256",hash(PROTECTION),"protectedPortsSha256",GuardEligibility.protectedPortsSha256(ports),"ranges",List.of(List.of(1,21),List.of(23,52),List.of(54,3388),List.of(3390,65535)));
        assertThat(jdbc.queryForList("SELECT reason FROM audit_log WHERE action='guard.command.inbound_ranges' AND resource_id=?",String.class,commandId)).containsExactly(hash(expected));
        // 上报摘要与控制面重算不符：不再签发或重放命令，但撤销照常下发。
        machine("/executors/"+f.executor()+"/heartbeats",object("bootId",f.executorBoot(),"adapterVersion","fixture-1","capabilityHash","c".repeat(64),"pendingRecovery",false,"activeRuleCount",1,"clockSkewMs",0),f.executorCredential());
        JsonNode drifted=object("bootId",f.executorBoot(),"capabilityHash","c".repeat(64),"maxItems",10,"waitSeconds",0);
        assertThat(machine("/executors/"+f.executor()+"/command-claims",drifted,f.executorCredential()).path("commands")).isEmpty();
        human("/actions/"+str(actions.getFirst(),"public_id")+"/revocations",object("reason","隔离测试撤销"),reviewer,"2");
        var revoked=machine("/executors/"+f.executor()+"/command-claims",drifted,f.executorCredential());assertThat(revoked.path("commands")).isEmpty();assertThat(revoked.path("revocations")).hasSize(1);
    }
    /** B1.2：全入站能力须为 macOS 入站并带签名豁免报告，单服务能力不得夹带保护集或豁免字段。 */
    @Test void inboundCapabilityRegistrationRequiresSignedExemptionForSameProtectionSet()throws Exception{
        String folder=id();Path dir=ROOT.resolve(folder);Files.createDirectories(dir);
        ObjectNode valid=object("passed",true,"scope","peer_inbound","platform","macos-pf","protectionSetSha256",hash(PROTECTION));
        Map<String,ObjectNode> exemptions=new LinkedHashMap<>(),changes=new LinkedHashMap<>();
        exemptions.put("otherProtection",valid.deepCopy().put("protectionSetSha256","f".repeat(64)));exemptions.put("failedReport",valid.deepCopy().put("passed",false));
        exemptions.put("serviceReport",valid.deepCopy().put("scope","peer_service"));exemptions.put("windowsReport",valid.deepCopy().put("platform","windows-wfp"));
        changes.put("windows",object("platform","windows"));changes.put("outbound",object("direction","outbound"));changes.put("serviceWithProtection",object("scope","peer_service"));
        int before=jdbc.queryForObject("SELECT COUNT(*) FROM guard_capability",Integer.class);
        for(String name:List.of("otherProtection","failedReport","serviceReport","windowsReport","windows","outbound","serviceWithProtection","missingExemption")){
            ObjectNode cap=object("capabilityKey",id(),"version","fixture-v1","platform","macos","adapterVersion","fixture-1","addressFamily","ipv4","transport","tcp","direction","inbound","family","port_scan","profile","flow-prefix-v1","behaviorScope",List.of("scan"),"latencyLimits",object("maxMs",10000),"level","lab_auto","scope","peer_inbound","protectionSetSha256",hash(PROTECTION));
            write(dir,name+"-exemption.json",GuardSignatures.sign(exemptions.getOrDefault(name,valid),"fixture-runner",signing.getPrivate()));
            if(!name.equals("missingExemption"))cap.put("exemptionEvidenceSha256",sha(Files.readAllBytes(dir.resolve(name+"-exemption.json"))));cap.setAll(changes.getOrDefault(name,object()));
            // 平台报告签名覆盖完整能力声明，确保拒绝来自豁免规则本身而不是平台报告不符。
            write(dir,name+"-capability.json",GuardSignatures.sign(object("passed",true,"protocolVersions",versions(),"capability",cap.deepCopy()),"fixture-runner",signing.getPrivate()));
            cap.put("evidenceRef",folder+"/"+name+"-capability.json").put("evidenceSha256",sha(Files.readAllBytes(dir.resolve(name+"-capability.json")))).put("runnerIdentity","fixture-runner").put("exemptionEvidenceRef",folder+"/"+name+"-exemption.json");
            var session=humanSession(operator);var r=mvc.perform(post("/api/v2/capabilities").cookie(session.cookie()).header("X-CSRF-TOKEN",session.csrfToken()).header("Idempotency-Key",id()).contentType("application/json").content(canonical(cap))).andReturn();
            boolean missing=name.equals("missingExemption");assertThat(r.getResponse().getStatus()).as(name).isEqualTo(missing?400:422);
            assertThat(parse(r.getResponse().getContentAsString()).at("/error/code").asText()).as(name).isEqualTo(missing?"INVALID_REQUEST":"CAPABILITY_NOT_SUPPORTED");}
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM guard_capability",Integer.class)).isEqualTo(before);
        // 绕过服务直接写库同样受 V22 约束：全入站缺保护集或豁免摘要的行无法落库。
        assertThatThrownBy(()->jdbc.update("INSERT INTO guard_capability(public_id,capability_key,version,platform,level,payload_json,created_by,scope) SELECT UUID(),?,'v','macos','lab_auto','{}',MIN(id),'peer_inbound' FROM sys_user",id())).hasMessageContaining("ck_guard_capability_scope");
    }
    @Test void rulesAlertOnInferenceFailureAndNonHitInvalidatesPriorEvidence()throws Exception{
        var rule=object("ruleId","slow-duration","family","dos_slow","field","features.elapsedMs","operator","gte","threshold",4000,"autoEligible",false);
        Fixture f=setup("dos_slow",List.of(rule));jdbc.update("UPDATE guard_model SET validation_status='failed' WHERE public_id=?",f.model);
        String parent=id();var first=observation(f,Instant.now().truncatedTo(ChronoUnit.MICROS),parent,0);accept(f,List.of(first),1,true);
        var asset=store.external("asset",f.asset,false);var decision=store.one("guard_decision",map("asset_id",asset.get("id")),false);assertThat(str(decision,"decision")).isEqualTo("alert");assertThat(str(decision,"reason_code")).isEqualTo("CAPABILITY_NOT_SUPPORTED");
        var second=observation(f,Instant.now().truncatedTo(ChronoUnit.MICROS),parent,1);second.put("firstSeenAt",time(second,"asOf").minusSeconds(1).toString());((ObjectNode)second.path("features")).put("elapsedMs",1000);
        accept(f,List.of(second),2,true);var facts=store.rows("guard_rule_evaluation",map("asset_id",asset.get("id")),false,10);assertThat(facts).hasSize(2);assertThat(facts.stream().filter(e->GuardDetection.flag(e.get("matched")))).hasSize(1);
        var episode=store.one("guard_episode",map("asset_id",asset.get("id"),"source","rule"),false);assertThat(str(store.one("guard_decision",map("episode_id",episode.get("id")),false),"decision")).isEqualTo("observe");assertThat(GuardDetection.flag(store.one("guard_episode_evidence",map("episode_id",episode.get("id")),false).get("rule_matched"))).isFalse();
    }
    @Test void newlyArrivedSnapshotRejectsOldCommandBeforeInferenceConsumption()throws Exception{
        Fixture f=setup();String parent=id();accept(f,List.of(observation(f,Instant.now().truncatedTo(ChronoUnit.MICROS),parent,0)),1,true);
        var asset=store.external("asset",f.asset,false);var action=store.one("guard_action",map("asset_id",asset.get("id")),false);assertThat(action).isNotNull();
        accept(f,List.of(observation(f,Instant.now().truncatedTo(ChronoUnit.MICROS),parent,1)),2,false);
        var claim=machine("/executors/"+f.executor+"/command-claims",object("bootId",f.executorBoot,"capabilityHash",f.capabilityHash(),"maxItems",10,"waitSeconds",0),f.executorCredential);
        assertThat(claim.path("commands")).isEmpty();assertThat(str(store.get("guard_action",number(action,"id")),"observed_state")).isEqualTo("rejected");assertThat(store.rows("guard_command",map("action_id",action.get("id")),false,10)).isEmpty();
    }
    @Test void outboundScanRuleRemainsAlertOnly()throws Exception{
        var rule=object("ruleId","scan-outside-scope","family","port_scan","field","features.elapsedMs","operator","gte","threshold",4000,"autoEligible",true);
        Fixture f=setup("dos_slow",List.of(rule));accept(f,List.of(observation(f,Instant.now().truncatedTo(ChronoUnit.MICROS),id(),0)),1,true);
        var asset=store.external("asset",f.asset,false);var episode=store.one("guard_episode",map("asset_id",asset.get("id"),"source","rule"),false);
        assertThat(str(episode,"scope")).isEqualTo("peer_service");assertThat(str(store.one("guard_decision",map("episode_id",episode.get("id")),false),"decision")).isEqualTo("alert");
    }
    @Test void validLatestTargetCannotAuthorizeOtherSelectedParent()throws Exception{
        Fixture f=setup();Instant at=Instant.now().truncatedTo(ChronoUnit.MICROS);
        var unbound=observation(f,at,id(),0);unbound.putNull("targetRef").putNull("targetExpiresAt");
        var bound=observation(f,at.plusNanos(1000),id(),0);accept(f,List.of(unbound,bound),1,true);
        var asset=store.external("asset",f.asset,false);var episode=store.one("guard_episode",map("asset_id",asset.get("id")),false);
        var decisions=store.rows("guard_decision",map("episode_id",episode.get("id")),false,10);assertThat(decisions).hasSize(2);
        assertThat(decisions).allSatisfy(d->assertThat(str(d,"reason_code")).isEqualTo("TARGET_REF_STALE"));
        assertThat(store.rows("guard_action",map("asset_id",asset.get("id")),false,10)).isEmpty();
    }
    @Test void scopesUnknownFieldsMachineSeparationAndApprovalSeparation()throws Exception{
        Fixture f=setup();var crossConfig=mvc.perform(get("/api/v2/machine/sensors/"+f.sensor+"/config").header("Authorization","Bearer "+f.executorCredential)).andReturn();assertThat(crossConfig.getResponse().getStatus()).isEqualTo(403);assertThat(result(mvc.perform(get("/api/v2/machine/sensors/"+f.sensor+"/config").header("Authorization","Bearer "+f.sensorCredential)).andReturn()).path("configId").asText()).isEqualTo(f.config);
        var outsider=identity("outsider",List.of());var outsiderSession=humanSession(outsider);var request=get("/api/v2/observations/"+id()).cookie(outsiderSession.cookie());assertThat(mvc.perform(request).andReturn().getResponse().getStatus()).isEqualTo(404);
        var forged=batch(f,List.of(observation(f,Instant.now().truncatedTo(ChronoUnit.MICROS),id(),0)),1);((ObjectNode)forged.path("observations").get(0)).put("assetId",id());var r=mvc.perform(post("/api/v2/machine/sensors/"+f.sensor+"/observation-batches").header("Authorization","Bearer "+f.sensorCredential).header("Idempotency-Key",id()).contentType("application/json").content(canonical(forged))).andReturn();assertThat(r.getResponse().getStatus()).isEqualTo(422);assertThat(parse(r.getResponse().getContentAsString()).at("/error/code").asText()).isEqualTo("SCOPE_DENIED");
        var asExecutor=mvc.perform(post("/api/v2/machine/executors/"+f.executor+"/command-claims").header("Authorization","Bearer "+f.sensorCredential).header("Idempotency-Key",id()).contentType("application/json").content("{}")).andReturn();assertThat(asExecutor.getResponse().getStatus()).isEqualTo(403);
        var sessionOnly=humanSession(operator);var machineRequest=mvc.perform(post("/api/v2/machine/sensors/"+f.sensor+"/heartbeats").cookie(sessionOnly.cookie()).contentType("application/json").content("{}")).andReturn();assertThat(machineRequest.getResponse().getStatus()).isEqualTo(401);
        var body=object("assetKey",id(),"platform","macos","environment","lab","owner","fixture","autoApproved",true);var validSession=humanSession(operator);var unknown=mvc.perform(post("/api/v2/assets").cookie(validSession.cookie()).header("X-CSRF-TOKEN",validSession.csrfToken()).header("Idempotency-Key",id()).contentType("application/json").content(canonical(body))).andReturn();assertThat(unknown.getResponse().getStatus()).isEqualTo(400);
    }
    /** P5 只能查询本机预算事实；查询本身不得恢复额度或泄露其他执行器目标。 */
    @Test void budgetProofIsExecutorScopedAndDoesNotResetBudget()throws Exception{
        Fixture f=setup();
        var target=store.external("guard_budget_target",f.targetId,false);
        jdbc.update("UPDATE guard_target_budget SET charged_ms=30000 WHERE budget_target_id=?",target.get("id"));
        JsonNode proof=machine("/executors/"+f.executor+"/budget-proofs",object("stableTargetToken",f.token),f.executorCredential);
        assertThat(proof.path("chargedMs").asLong()).isEqualTo(30000);
        assertThat(proof.path("healthProofSha256").isNull()).isTrue();
        assertThat(number(store.one("guard_target_budget",map("budget_target_id",target.get("id")),false),"charged_ms")).isEqualTo(30000);
        var denied=mvc.perform(post("/api/v2/machine/executors/"+f.executor+"/budget-proofs")
                .header("Authorization","Bearer "+f.sensorCredential).header("Idempotency-Key",id())
                .contentType("application/json").content(canonical(object("stableTargetToken",f.token)))).andReturn();
        assertThat(denied.getResponse().getStatus()).isEqualTo(403);
        var missing=mvc.perform(post("/api/v2/machine/executors/"+f.executor+"/budget-proofs")
                .header("Authorization","Bearer "+f.executorCredential).header("Idempotency-Key",id())
                .contentType("application/json").content(canonical(object("stableTargetToken","9".repeat(64))))).andReturn();
        assertThat(missing.getResponse().getStatus()).isEqualTo(404);
    }
}
