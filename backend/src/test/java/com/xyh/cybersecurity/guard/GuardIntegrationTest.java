package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import jakarta.servlet.http.Cookie;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.MockMvcPrint;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.*;
import org.springframework.test.web.servlet.*;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
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
@SpringBootTest(properties={"cyber.ingest.consumer.enabled=false","cyber.ingest.outbox-relay.enabled=false","cyber.drift.enabled=false","cyber.guard.automation-enabled=true","cyber.security.local-admin-bootstrap.enabled=false","cyber.guard.bootstrap-reports-enabled=true"})
@AutoConfigureMockMvc(print=MockMvcPrint.NONE)
@EnabledIfEnvironmentVariable(named="DB_TEST_BASE_URL",matches=".+")
class GuardIntegrationTest {
    /** K9：仅 E3 subject 入口复用编排器建好的业务库克隆，不新建、不删除，其余用例仍用随机 schema。 */
    static final String SUBJECT_SCHEMA=System.getenv("P5_SUBJECT_SCHEMA");
    static final String SCHEMA=SUBJECT_SCHEMA!=null?subjectSchema(SUBJECT_SCHEMA):"cyber_guard_api_p4_"+UUID.randomUUID().toString().replace("-","");
    static String subjectSchema(String name){if(!name.matches("cyber_guard_k9_[0-9a-f]{32}"))throw new IllegalStateException("K9_SUBJECT_SCHEMA_INVALID");return name;}
    static final Path ROOT=Path.of(System.getenv().getOrDefault("P5_RUN_DIR","target/guard-fixtures")).toAbsolutePath();
    static final JsonNode PROTECTION=object("protectedBudgetTargetIds",List.of(),"protectedServicePorts",List.of(22,53,3389));
    static KeyPair signing;
    @DynamicPropertySource static void props(DynamicPropertyRegistry r)throws Exception{
        Files.createDirectories(ROOT);signing=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();Files.write(ROOT.resolve("signing.der"),signing.getPrivate().getEncoded());Files.setPosixFilePermissions(ROOT.resolve("signing.der"),PosixFilePermissions.fromString("rw-------"));
        Files.writeString(ROOT.resolve("trust.json"),canonical(object("fixture-runner",Base64.getEncoder().encodeToString(signing.getPublic().getEncoded()))));Files.writeString(ROOT.resolve("protection.json"),canonical(PROTECTION));
        String base=System.getenv("DB_TEST_BASE_URL").replaceAll("/+$","");String username=System.getenv("DB_TEST_USERNAME"),password=System.getenv("DB_TEST_PASSWORD");
        if(SUBJECT_SCHEMA==null)try(var c=DriverManager.getConnection(base,username,password);var s=c.createStatement()){s.execute("CREATE DATABASE "+SCHEMA+" CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin");}
        String url=base+"/"+SCHEMA+"?connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true";Flyway.configure().dataSource(url,username,password).load().migrate();
        r.add("spring.datasource.url",()->url);r.add("spring.datasource.username",()->username);r.add("spring.datasource.password",()->password);r.add("spring.flyway.enabled",()->false);r.add("cyber.security.login-throttle.hmac-key",()->"isolated-test-key-with-more-than-thirty-two-bytes");
        r.add("cyber.guard.artifact-root",()->SUBJECT_SCHEMA==null?ROOT.toString():System.getenv("P5_SUBJECT_ARTIFACT_ROOT"));if(SUBJECT_SCHEMA!=null)r.add("cyber.model-artifact.root",()->System.getenv("P5_SUBJECT_MODEL_ARTIFACT_ROOT"));r.add("cyber.guard.signing-key-id",()->"fixture-control");r.add("cyber.guard.signing-key-file",()->ROOT.resolve("signing.der").toString());r.add("cyber.guard.report-trust-file",()->SUBJECT_SCHEMA==null?ROOT.resolve("trust.json").toString():System.getenv("P5_SUBJECT_REPORT_TRUST"));r.add("cyber.guard.protection-file",()->ROOT.resolve("protection.json").toString());
    }
    @AfterAll static void dropOwnSchema()throws Exception{
        if(SUBJECT_SCHEMA!=null)return;
        String base=System.getenv("DB_TEST_BASE_URL").replaceAll("/+$","");
        try(var c=DriverManager.getConnection(base,System.getenv("DB_TEST_USERNAME"),System.getenv("DB_TEST_PASSWORD"));var st=c.createStatement()){st.execute("DROP DATABASE IF EXISTS "+SCHEMA);}
    }
    static final String TEST_PASSWORD="isolated-test-password";
    @Autowired MockMvc mvc;@Autowired JdbcTemplate jdbc;@Autowired GuardDetection detection;@Autowired GuardStore store;@Autowired GuardContracts contracts;@Autowired GuardBudget budget;@Autowired GuardModelRuntime runtime;@Autowired PlatformTransactionManager manager;@Autowired PasswordEncoder passwordEncoder;
    @Autowired GuardMapper guardMapper;@Autowired GuardHealth guardHealth;@Autowired GuardActions guardActions;@Autowired GuardCases guardCases;@Autowired GuardLabExecutionGate labExecutionGate;
    IdentityPrincipal operator,reviewer;
    @BeforeEach void identities(){operator=identity("operator",List.of("platform_admin","model_operator","security_analyst"));reviewer=identity("reviewer",List.of("security_reviewer"));}
    IdentityPrincipal identity(String suffix,List<String> roles){String key=id(),username=suffix+"-"+key;jdbc.update("INSERT INTO sys_user(user_key,username,display_name,password_hash,status) VALUES (?,?,?,?, 'active')",key,username,"隔离测试身份",passwordEncoder.encode(TEST_PASSWORD));Long uid=jdbc.queryForObject("SELECT id FROM sys_user WHERE user_key=?",Long.class,key);for(String role:roles)jdbc.update("INSERT INTO sys_user_role(user_id,role_id,scope_type,scope_id) SELECT ?,id,'global','*' FROM sys_role WHERE role_key=?",uid,role);return new IdentityPrincipal(uid,key,username,"隔离测试身份","test-only-no-login","active",roles,List.of());}
    JsonNode human(String path,JsonNode body,IdentityPrincipal actor,String revision)throws Exception{return human(path,body,actor,revision,id());}
    record HumanSession(Cookie cookie,String csrfToken){}
    HumanSession humanSession(IdentityPrincipal actor)throws Exception{
        var bootstrap=mvc.perform(get("/api/v2/auth/csrf")).andReturn();
        assertThat(bootstrap.getResponse().getStatus()).isEqualTo(200);
        Cookie bootstrapCookie=bootstrap.getResponse().getCookie("SESSION");
        String bootstrapToken=parse(bootstrap.getResponse().getContentAsString()).path("data").path("token").asText();
        assertThat(bootstrapCookie).isNotNull();assertThat(bootstrapToken).isNotBlank();
        var login=mvc.perform(post("/api/v2/auth/login").header("Idempotency-Key",id()).cookie(bootstrapCookie).header("X-CSRF-TOKEN",bootstrapToken).contentType("application/json").content(canonical(object("username",actor.getUsername(),"password",TEST_PASSWORD)))).andReturn();
        assertThat(login.getResponse().getStatus()).isEqualTo(200);
        Cookie sessionCookie=login.getResponse().getCookie("SESSION");
        assertThat(sessionCookie).isNotNull();
        var csrfResult=mvc.perform(get("/api/v2/auth/csrf").cookie(sessionCookie)).andReturn();
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
    String fixtureDirection(boolean scan){return scan?"inbound":"outbound";}
    String fixtureInterface(){return "fixture0";}
    String fixtureAdapterVersion(){return "fixture-1";}
    /** exempt=true 时登记带签名豁免报告的 macOS PF 全入站能力（B1.2），其余步骤与普通夹具相同。 */
    Fixture setup(String family,List<JsonNode> rules,boolean exempt)throws Exception{return setup(family,rules,exempt,100);}
    Fixture setup(String family,List<JsonNode> rules,boolean exempt,int maxBatchSize)throws Exception{
        return setup(family,rules,exempt,maxBatchSize,"auto","lab");
    }
    /** 只告警夹具也经真实登记、签名报告、封存和独立审批；仅隔离 schema 内生效。 */
    Fixture setup(String family,List<JsonNode> rules,boolean exempt,int maxBatchSize,String mode,String environment)throws Exception{
        return setup(family,rules,exempt,maxBatchSize,mode,environment,true);
    }
    /** closeSources=false 只供模式门反例：保留高分和来源自动资格，避免前置关闭门掩盖 alert_only 授权门。 */
    Fixture setup(String family,List<JsonNode> rules,boolean exempt,int maxBatchSize,String mode,String environment,boolean closeSources)throws Exception{
        boolean scan=family.equals("port_scan");String direction=fixtureDirection(scan);
        String folder=id();Path dir=ROOT.resolve(folder);Files.createDirectories(dir);
        String asset=human("/assets",object("assetKey",id(),"platform","macos","environment",environment,"owner","isolated-p4-test"),operator,null).path("id").asText();
        ObjectNode cap=object("capabilityKey",id(),"version","fixture-v1","platform","macos","adapterVersion",fixtureAdapterVersion(),"addressFamily","ipv4","transport","tcp","direction",direction,"family",family,"profile","flow-prefix-v1","behaviorScope",List.of("slowloris","slowhttptest"),"latencyLimits",object("maxMs",10000),"level","lab_auto");
        if(exempt){write(dir,"exemption.json",GuardSignatures.sign(object("passed",true,"scope","peer_inbound","platform","macos-pf","protectionSetSha256",hash(PROTECTION)),"fixture-runner",signing.getPrivate()));
            cap.put("scope","peer_inbound").put("protectionSetSha256",hash(PROTECTION)).put("exemptionEvidenceSha256",sha(Files.readAllBytes(dir.resolve("exemption.json"))));}
        JsonNode signed=GuardSignatures.sign(object("passed",true,"protocolVersions",versions(),"capability",cap),"fixture-runner",signing.getPrivate());write(dir,"capability.json",signed);cap.put("evidenceRef",folder+"/capability.json").put("evidenceSha256",sha(Files.readAllBytes(dir.resolve("capability.json")))).put("runnerIdentity","fixture-runner");if(exempt)cap.put("exemptionEvidenceRef",folder+"/exemption.json");
        String capability=human("/capabilities",cap,operator,null).path("id").asText();
        Instant now=Instant.now().truncatedTo(ChronoUnit.MILLIS);
        String auth=human("/assets/"+asset+"/authorizations",object("interfaces",List.of(fixtureInterface()),"observationAllowed",true,"executionScopes",List.of(object("scope",scan?"peer_inbound":"peer_service","direction",direction,"transport","tcp","servicePort",scan?null:443,"addressFamily","ipv4","capabilityId",capability)),"validFrom",now.minusSeconds(60).toString(),"validUntil",now.plusSeconds(3600).toString(),"evidenceRef","fixture:isolated-test"),operator,null).path("id").asText();
        human("/authorizations/"+auth+"/decisions",object("decision","approve","reason","隔离测试批准"),reviewer,"1");
        String scope=id();JsonNode sensor=human("/sensors",object("assetId",asset,"platform","macos","captureScopeId",scope),operator,null);JsonNode executor=human("/executors",object("assetId",asset,"platform","macos","capabilityProbeRef","fixture:probe"),operator,null);
        JsonNode config=object("contractVersion",CONTRACT,"profileSha256",contracts.profileHash(),"captureHealthVersion",HEALTH,"interfaceIds",List.of(fixtureInterface()),"limits",object("maxBatchSize",maxBatchSize),"captureScopeId",scope,"addressFamily","ipv4","buildSha256","b".repeat(64));
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
        policy.set("rulePolicies",node(rules));policy.set("supportedCapabilityIds",node(List.of(capability)));
        policy.put("mode",mode);
        if(mode.equals("alert_only")&&closeSources) {
            for(var fp:policy.path("familyPolicies"))((ObjectNode)fp).put("autoEligible",false).put("modelAutoEligible",false);
            for(var rp:policy.path("rulePolicies"))((ObjectNode)rp).put("autoEligible",false);
        }
        human("/decision-policies",policy,operator,null);human("/decision-policies/"+pid+"/reviews",object("decision","approve","reason","隔离测试策略"),reviewer,"1");
        JsonNode bundle=human("/release-bundles",object("modelId",model,"policyId",pid,"featureProfileSha256",contracts.profileHash(),"extractorSha256",manifest.get("extractorSha256"),"protocolVersions",versions(),"evaluationPlanId",registeredPlan.get("id"),"capabilityIds",List.of(capability),"environment",environment),operator,null);String bid=bundle.path("id").asText();var evaluationIds=new ArrayList<String>();
        for(String kind:mode.equals("alert_only")?List.of("final"):List.of("final","platform","canary")){write(dir,kind+".json",GuardSignatures.sign(object("protocolVersions",versions(),"subjectSha256",bundle.get("subjectSha256"),"evaluationPlanSha256",registeredPlan.get("planSha256"),"runKind",kind,"passed",true),"fixture-runner",signing.getPrivate()));evaluationIds.add(human("/release-bundles/"+bid+"/imports",object("reportRef",folder+"/"+kind+".json","sha256",sha(Files.readAllBytes(dir.resolve(kind+".json"))),"runnerIdentity","fixture-runner"),operator,null).path("id").asText());}
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

    /** BE-15：final 单报告组合可独立批准、激活；自动化开启时仍仅告警，不产生动作或命令。 */
    @ParameterizedTest @ValueSource(strings={"authorized","lab"})
    void alertOnlyFinalBundleActivatesWithoutAutomaticActions(String environment)throws Exception {
        Fixture f=setup("dos_slow",List.of(),false,100,"alert_only",environment);
        var bundle=store.external("guard_release_bundle",f.bundle(),false);
        assertThat(str(bundle,"status")).isEqualTo("active");
        assertThat(json(bundle,"sealed_manifest_json").path("reports")).hasSize(1);
        // T1-R2：冻结策略和报告成功导入各有可追溯审计，不以封存记录替代原始写入。
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM audit_log WHERE action='guard.policy.drafted' AND resource_id=?",Long.class,f.policy())).isEqualTo(1);
        String reportId=json(bundle,"sealed_manifest_json").at("/reports/0/evaluationId").asText();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM audit_log WHERE action='guard.report.imported' AND resource_id=?",Long.class,reportId)).isEqualTo(1);
        Instant at=Instant.now().truncatedTo(ChronoUnit.MICROS);
        accept(f,List.of(observation(f,at,id(),0).put("environment",environment)),1,true);
        var asset=store.external("asset",f.asset(),false);
        var decisions=store.rows("guard_decision",map("asset_id",asset.get("id")),false,20);
        assertThat(decisions).isNotEmpty().allSatisfy(d->assertThat(str(d,"decision")).isEqualTo("alert"));
        assertThat(store.rows("guard_action",map("asset_id",asset.get("id")),false,20)).isEmpty();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM guard_command c JOIN guard_action a ON a.id=c.action_id WHERE a.asset_id=?",Long.class,
                asset.get("id"))).isZero();
    }

    /** BE-14d：同一生产服务构造和真实事务分别注入自动化开/关；authorized 只告警且人工入口也不能产生动作。 */
    @ParameterizedTest @ValueSource(booleans={true,false})
    void authorizedAlertOnlyRejectsManualActionAndExposesNoCapabilities(boolean automation)throws Exception {
        Fixture f=setup("dos_slow",List.of(),false,100,"alert_only","authorized");
        GuardEligibility gate=deploymentEligibility(automation);
        acceptForDeployment(f,gate,"authorized");
        assertAlertOnly(f,"CAPABILITY_NOT_SUPPORTED",gate);
    }

    /** BE-14d 独立模式门：lab 能力、质量、目标及高分来源可通过，只能由 alert_only 的授权门拒绝。 */
    @Test void labAlertOnlyModeAloneRejectsExecution()throws Exception {
        Fixture f=setup("dos_slow",List.of(),false,100,"alert_only","lab",false);
        GuardEligibility gate=deploymentEligibility(true);
        acceptForDeployment(f,gate,"lab");
        assertAlertOnly(f,"AUTHORIZATION_INACTIVE",gate);
    }

    GuardEligibility deploymentEligibility(boolean automation) {
        var gate=new GuardEligibility(store,automation,ROOT.resolve("protection.json").toString());
        gate.labGate(labExecutionGate);return gate;
    }
    void acceptForDeployment(Fixture f,GuardEligibility gate,String environment)throws Exception {
        var request=batch(f,List.of(observation(f,Instant.now().truncatedTo(ChronoUnit.MICROS),id(),0).put("environment",environment)),1);
        machine("/sensors/"+f.sensor()+"/observation-batches",request,f.sensorCredential());
        var service=new GuardDetection(store,guardMapper,runtime,budget,guardHealth,gate,guardActions,guardCases);
        new TransactionTemplate(manager).executeWithoutResult(tx->service.consume(id(),"guard.observation.accepted",object("batchId",request.get("batchId"))));
    }
    void assertAlertOnly(Fixture f,String reason,GuardEligibility gate)throws Exception {
        var asset=store.external("asset",f.asset(),false);
        var decisions=store.rows("guard_decision",map("asset_id",asset.get("id")),false,20).stream().filter(d->{
            var e=store.get("guard_episode",number(d,"episode_id"));return "dos_slow".equals(str(e,"family"))&&"model".equals(str(e,"source"));}).toList();
        assertThat(decisions).isNotEmpty().allSatisfy(d->{assertThat(str(d,"decision")).isEqualTo("alert");assertThat(str(d,"reason_code")).isEqualTo(reason);});
        var episode=store.get("guard_episode",number(decisions.getFirst(),"episode_id"));
        assertThat(rejectedHuman("/actions",object("episodeId",episode.get("public_id"),"targetRef",f.target(),"policyId",f.policy(),"reason","隔离只告警人工入口验收"),operator,null,422)
                .at("/error/code").asText()).isEqualTo("ACTION_EVIDENCE_REQUIRED");
        assertThat(store.rows("guard_action",map("asset_id",asset.get("id")),false,20)).isEmpty();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM guard_command c JOIN guard_action a ON a.id=c.action_id WHERE a.asset_id=?",Long.class,asset.get("id"))).isZero();
        assertThat(gate.executorCapabilityHash(store.external("guard_executor",f.executor(),false))).isEqualTo(GuardEligibility.capabilitySetSha256(List.of()));
    }

    /** broker 验收由 Python 编排显式开启；专用 vhost、随机 schema 与同一生产 listener/消费者实现。 */
    @Test @EnabledIfEnvironmentVariable(named="P8_BROKER_IT_ENABLED",matches="true")
    void deploymentBrokerAcceptance()throws Exception { new GuardBrokerAcceptance(this).run(); }

    /** K5 方案 B：联合评价先封存，缺任一前置时不得批准或激活；合成夹具不产生 G3 资格。 */
    @Test void labBundleRequiresJointEvidenceBeforeIndependentApproval() throws Exception {
        Fixture f=setup();var original=store.external("guard_release_bundle",f.bundle(),false);
        var subject=json(original,"subject_json");
        var created=human("/release-bundles",object("modelId",f.model(),"policyId",f.policy(),
                "featureProfileSha256",contracts.profileHash(),"extractorSha256",subject.get("extractorSha256"),
                "protocolVersions",versions(),"evaluationPlanId",store.get("guard_evaluation_plan",number(original,"plan_id")).get("public_id"),
                "capabilityIds",List.of(f.capability()),"environment","lab"),operator,null);
        String bid=created.path("id").asText(),base="/release-bundles/"+bid;
        var approval=object("decision","approve","reason","synthetic Scheme B lifecycle");
        var activation=object("assetIds",List.of(f.asset()),"authorizationIds",List.of(f.authorization()));
        rejectedHuman(base+"/decisions",approval,reviewer,"1",422);
        rejectedHuman(base+"/activations",activation,reviewer,"1",422);
        String folder=id();Path dir=ROOT.resolve(folder);Files.createDirectories(dir);var ids=new ArrayList<String>();
        for(String kind:List.of("final","platform","canary")) {
            if(!ids.isEmpty())assertThat(rejectedHuman(base+"/sealings",object("evaluationIds",ids),operator,"1",422)
                    .at("/error/code").asText()).isEqualTo("JOINT_EVALUATION_REQUIRED");
            var payload=object("protocolVersions",versions(),"subjectSha256",created.get("subjectSha256"),
                    "evaluationPlanSha256",subject.get("evaluationPlanSha256"),"runKind",kind,"passed",true,"evidenceKind","synthetic");
            write(dir,kind+".json",GuardSignatures.sign(payload,"fixture-runner",signing.getPrivate()));
            ids.add(human(base+"/imports",object("reportRef",folder+"/"+kind+".json",
                    "sha256",sha(Files.readAllBytes(dir.resolve(kind+".json"))),"runnerIdentity","fixture-runner"),operator,null).path("id").asText());
        }
        assertThat(human(base+"/sealings",object("evaluationIds",ids),operator,"1").path("status").asText()).isEqualTo("evaluated");
        rejectedHuman(base+"/decisions",approval,operator,"2",403);
        assertThat(human(base+"/decisions",approval,reviewer,"2").path("status").asText()).isEqualTo("approved");
        assertThat(human(base+"/activations",activation,reviewer,"3").path("status").asText()).isEqualTo("active");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM guard_validation_session WHERE bundle_id=(SELECT id FROM guard_release_bundle WHERE public_id=?)",Integer.class,bid)).isZero();
    }
    /** 引导开关只影响报告类别，封存、独立批准及资产绑定仍由原链路核验。 */
    @Test void bootstrapReportsRequireSealIndependentApprovalAndLabBinding() throws Exception {
        Fixture f=setup();var original=store.external("guard_release_bundle",f.bundle(),false);
        var subject=json(original,"subject_json");
        var created=human("/release-bundles",object("modelId",f.model(),"policyId",f.policy(),
                "featureProfileSha256",contracts.profileHash(),"extractorSha256",subject.get("extractorSha256"),
                "protocolVersions",versions(),"evaluationPlanId",store.get("guard_evaluation_plan",number(original,"plan_id")).get("public_id"),
                "capabilityIds",List.of(f.capability()),"environment","lab"),operator,null);
        String bid=created.path("id").asText(),base="/release-bundles/"+bid;
        String folder=id();Path dir=ROOT.resolve(folder);Files.createDirectories(dir);var ids=new ArrayList<String>();
        for(String kind:List.of("final","platform","canary")) {
            var payload=object("protocolVersions",versions(),"subjectSha256",created.get("subjectSha256"),
                    "evaluationPlanSha256",subject.get("evaluationPlanSha256"),"runKind",kind,"passed",true,
                    "evidenceKind",kind.equals("final")?"real_pf":"bootstrap");
            write(dir,kind+".json",GuardSignatures.sign(payload,"fixture-runner",signing.getPrivate()));
            ids.add(human(base+"/imports",object("reportRef",folder+"/"+kind+".json",
                    "sha256",sha(Files.readAllBytes(dir.resolve(kind+".json"))),"runnerIdentity","fixture-runner"),operator,null).path("id").asText());
        }
        assertThat(human(base+"/sealings",object("evaluationIds",ids),operator,"1").path("status").asText()).isEqualTo("evaluated");
        var approval=object("decision","approve","reason","isolated bootstrap lifecycle");
        rejectedHuman(base+"/decisions",approval,operator,"2",403);
        assertThat(human(base+"/decisions",approval,reviewer,"2").path("status").asText()).isEqualTo("approved");
        assertThat(human(base+"/activations",object("assetIds",List.of(f.asset()),
                "authorizationIds",List.of(f.authorization())),reviewer,"3").path("status").asText()).isEqualTo("active");
    }
    /** B4：research 回放只能引用已批准 research 组合，且请求模型无法携带任何真实目标字段。 */
    @Test void researchReplayRejectsRealTargetReferencesAndRequiresResearchBundle()throws Exception{
        Fixture f=setup();
        JsonNode replay=object("scenarioId",id(),"scenarioSha256","a".repeat(64),"modelId",f.model(),"policyId",f.policy(),"speed",1);
        var session=humanSession(operator);var rejected=mvc.perform(post("/api/v2/replay-runs").cookie(session.cookie()).header("X-CSRF-TOKEN",session.csrfToken()).header("Idempotency-Key",id()).contentType("application/json").content(canonical(replay))).andReturn();
        assertThat(rejected.getResponse().getStatus()).isEqualTo(422);assertThat(parse(rejected.getResponse().getContentAsString()).at("/error/code").asText()).isEqualTo("REPLAY_BUNDLE_NOT_APPROVED");
        var old=store.external("guard_release_bundle",f.bundle(),false);var subject=json(old,"subject_json");
        JsonNode body=object("modelId",f.model(),"policyId",f.policy(),"featureProfileSha256",contracts.profileHash(),"extractorSha256",subject.get("extractorSha256"),"protocolVersions",versions(),"evaluationPlanId",store.get("guard_evaluation_plan",number(old,"plan_id")).get("public_id"),"capabilityIds",List.of(f.capability()),"environment","research");
        var research=human("/release-bundles",body,operator,null);String bid=research.path("id").asText();
        rejectedHuman("/replay-runs",replay,operator,null,422);
        String folder=id();Path dir=ROOT.resolve(folder);Files.createDirectories(dir);
        write(dir,"replay-final.json",GuardSignatures.sign(object("protocolVersions",versions(),"subjectSha256",research.get("subjectSha256"),"evaluationPlanSha256",subject.get("evaluationPlanSha256"),"runKind","final","passed",true),"fixture-runner",signing.getPrivate()));
        var report=human("/release-bundles/"+bid+"/imports",object("reportRef",folder+"/replay-final.json","sha256",sha(Files.readAllBytes(dir.resolve("replay-final.json"))),"runnerIdentity","fixture-runner"),operator,null);
        human("/release-bundles/"+bid+"/sealings",object("evaluationIds",List.of(report.path("id").asText())),operator,"1");
        human("/release-bundles/"+bid+"/decisions",object("decision","approve","reason","独立研究回放批准"),reviewer,"2");
        human("/release-bundles",body,operator,null); // 后登记候选不能遮蔽已批准 research 组合。
        long commands=jdbc.queryForObject("SELECT COUNT(*) FROM guard_command",Long.class);
        String key=id();var accepted=human("/replay-runs",replay,operator,null,key);
        assertThat(accepted.path("status").asText()).isEqualTo("queued");assertThat(accepted.path("bundleId").asText()).isEqualTo(bid);
        assertThat(human("/replay-runs",replay,operator,null,key)).isEqualTo(accepted);
        session=humanSession(operator);
        var detail=result(mvc.perform(get("/api/v2/replay-runs/"+accepted.path("id").asText()).cookie(session.cookie())).andReturn());
        assertThat(detail.path("scenarioSha256").asText()).isEqualTo(replay.path("scenarioSha256").asText());
        assertThat(detail.has("assetId")||detail.has("authorizationId")||detail.has("executorId")||detail.has("targetRef")).isFalse();
        for(String field:List.of("assetId","authorizationId","executorId","targetRef","environment")){
            ObjectNode withTarget=(ObjectNode)replay.deepCopy();withTarget.put(field,id());
            rejectedHuman("/replay-runs",withTarget,operator,null,400);
        }
        var outsider=identity("replay-outsider",List.of());rejectedHuman("/replay-runs",replay,outsider,null,403);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM guard_command",Long.class)).isEqualTo(commands);
        ObjectNode speed=(ObjectNode)replay.deepCopy();speed.put("speed",2);
        session=humanSession(operator);var fast=mvc.perform(post("/api/v2/replay-runs").cookie(session.cookie()).header("X-CSRF-TOKEN",session.csrfToken()).header("Idempotency-Key",id()).contentType("application/json").content(canonical(speed))).andReturn();
        assertThat(fast.getResponse().getStatus()).isEqualTo(422);assertThat(parse(fast.getResponse().getContentAsString()).at("/error/code").asText()).isEqualTo("REPLAY_SPEED_FIXED");
    }
    void write(Path dir,String name,JsonNode n)throws Exception{Files.writeString(dir.resolve(name),canonical(n));}

    /** J1：真实隔离 MySQL 的 queued/running/completed、绑定校验、T1/T2 重试和零动作边界。 */
    @Test void researchReplayLifecycleConsumesOnceAndCannotClaimCompletionWithoutFacts()throws Exception{
        Fixture f=setup();var old=store.external("guard_release_bundle",f.bundle(),false);var subject=json(old,"subject_json");
        String folder=id();Path dir=ROOT.resolve(folder);Files.createDirectories(dir);
        var closeout=object("completed",true,"gates",object("G1",true,"G2",true),"modelSha256",store.external("guard_model",f.model(),false).get("artifact_sha256"),"classEligibility",object());
        for(JsonNode fp:json(store.external("guard_decision_policy",f.policy(),false),"definition_json").path("familyPolicies"))
            ((ObjectNode)closeout.get("classEligibility")).set(fp.path("family").asText(),object("offlineEligible",true,"modelOnly",object("offlineEligible",true),"ruleOnly",object()));
        write(dir,"closeout.json",closeout);String closeoutSha=sha(Files.readAllBytes(dir.resolve("closeout.json")));
        var research=human("/release-bundles",object("modelId",f.model(),"policyId",f.policy(),"featureProfileSha256",contracts.profileHash(),"extractorSha256",subject.get("extractorSha256"),"protocolVersions",versions(),"evaluationPlanId",store.get("guard_evaluation_plan",number(old,"plan_id")).get("public_id"),"capabilityIds",List.of(f.capability()),"environment","research"),operator,null);
        String bid=research.path("id").asText();
        write(dir,"final.json",GuardSignatures.sign(object("protocolVersions",versions(),"subjectSha256",research.get("subjectSha256"),"evaluationPlanSha256",subject.get("evaluationPlanSha256"),"runKind","final","passed",true,"evaluation",object("closeoutSha256",closeoutSha)),"fixture-runner",signing.getPrivate()));
        var imported=human("/release-bundles/"+bid+"/imports",object("reportRef",folder+"/final.json","sha256",sha(Files.readAllBytes(dir.resolve("final.json"))),"runnerIdentity","fixture-runner"),operator,null);
        human("/release-bundles/"+bid+"/sealings",object("evaluationIds",List.of(imported.path("id").asText())),operator,"1");human("/release-bundles/"+bid+"/decisions",object("decision","approve","reason","隔离研究组合"),reviewer,"2");
        String asset=human("/assets",object("assetKey",id(),"platform","macos","environment","research","owner","isolated-j1-test"),operator,null).path("id").asText();
        Instant at=Instant.now().truncatedTo(ChronoUnit.MICROS);
        String auth=human("/assets/"+asset+"/authorizations",object("interfaces",List.of("replay0"),"observationAllowed",true,"executionScopes",List.of(),"validFrom",at.minusSeconds(60).toString(),"validUntil",at.plusSeconds(3600).toString(),"evidenceRef","fixture:j1-only"),operator,null).path("id").asText();
        human("/authorizations/"+auth+"/decisions",object("decision","approve","reason","仅研究观察"),reviewer,"1");
        String scope=id(),boot=id();var sensor=human("/sensors",object("assetId",asset,"platform","macos","captureScopeId",scope),operator,null);String sid=sensor.path("id").asText(),credential=sensor.path("credential").asText();
        var config=object("contractVersion",CONTRACT,"profileSha256",contracts.profileHash(),"captureHealthVersion",HEALTH,"interfaceIds",List.of("replay0"),"limits",object("maxBatchSize",100),"captureScopeId",scope,"addressFamily","ipv4","buildSha256","b".repeat(64));
        String configId=human("/sensors/"+sid+"/configs",config,operator,null).path("id").asText();human("/sensor-configs/"+configId+"/decisions",object("decision","approve","reason","研究配置"),reviewer,"1");
        machine("/sensors/"+sid+"/heartbeats",object("bootId",boot,"version","fixture-1","configHash",hash(config),"lastSequence",0,"clockSkewMs",0),credential);
        Files.write(dir.resolve("segment.pcap"),new byte[]{1,2,3});
        var model=store.external("guard_model",f.model(),false);var policy=store.external("guard_decision_policy",f.policy(),false);
        var scenario=object("scenarioId",id(),"environment","research","speed",1,"modelId",f.model(),"policyId",f.policy(),"modelSha256",model.get("artifact_sha256"),"manifestSha256",model.get("manifest_sha256"),"policySha256",policy.get("definition_sha256"),"sensorSha256","b".repeat(64),"segments",List.of(object("segmentId","segment-1","pcapRef",folder+"/segment.pcap","pcapSha256",sha(Files.readAllBytes(dir.resolve("segment.pcap"))))));
        write(dir,"scenario.json",scenario);String scenarioSha=sha(Files.readAllBytes(dir.resolve("scenario.json")));
        var request=object("scenarioId",scenario.get("scenarioId"),"scenarioSha256",scenarioSha,"modelId",f.model(),"policyId",f.policy(),"speed",1);
        var queued=human("/replay-runs",request,operator,null);String rid=queued.path("id").asText();
        var start=object("scenarioRef",folder+"/scenario.json","closeoutRef",folder+"/closeout.json","bindings",List.of(object("segmentId","segment-1","sensorId",sid,"bootId",boot)));
        var outsider=identity("j1-outsider",List.of());rejectedHuman("/replay-runs/"+rid+"/starts",start,outsider,null,403);
        var withTarget=start.deepCopy().put("targetRef",id());rejectedHuman("/replay-runs/"+rid+"/starts",withTarget,operator,null,400);
        Files.write(dir.resolve("segment.pcap"),new byte[]{4});assertThat(rejectedHuman("/replay-runs/"+rid+"/starts",start,operator,null,422).at("/error/code").asText()).isEqualTo("ARTIFACT_HASH_MISMATCH");Files.write(dir.resolve("segment.pcap"),new byte[]{1,2,3});
        String key=id();var running=human("/replay-runs/"+rid+"/starts",start,operator,null,key);assertThat(running.path("status").asText()).isEqualTo("running");assertThat(human("/replay-runs/"+rid+"/starts",start,operator,null,key)).isEqualTo(running);
        var o=GuardDomainTest.observation(Instant.now().truncatedTo(ChronoUnit.MICROS));o.put("assetId",asset).put("sensorId",sid).put("bootId",boot).put("captureScopeId",scope).put("environment","research").putNull("targetRef").putNull("targetExpiresAt");
        var batch=object("batchId",id(),"bootId",boot,"sequence",1,"configId",configId,"contractVersion",CONTRACT,"profileSha256",contracts.profileHash(),"observations",List.of(o));
        long commands=jdbc.queryForObject("SELECT COUNT(*) FROM guard_command",Long.class),actions=jdbc.queryForObject("SELECT COUNT(*) FROM guard_action",Long.class);
        String uploadKey=id();var accepted=machine("/sensors/"+sid+"/observation-batches",batch,credential,uploadKey);assertThat(accepted.path("acceptedCount").asInt()).isEqualTo(1);assertThat(machine("/sensors/"+sid+"/observation-batches",batch,credential,uploadKey)).isEqualTo(accepted);
        long aid=number(store.external("asset",asset,false),"id");assertThat(store.rows("guard_inference",map("asset_id",aid),false,10)).hasSize(1);assertThat(store.rows("guard_decision",map("asset_id",aid),false,10)).isNotEmpty();
        for(var decision:store.rows("guard_decision",map("asset_id",aid),false,10))assertThat(json(decision,"evidence_json").at("/hypothetical/actionable").asBoolean()).isFalse();
        var result=object("replayRunId",rid,"scenarioSha256",scenarioSha,"executionCompleted",true,"j1Passed",false,"segmentResults",List.of(object("segmentId","segment-1","sensorId",sid,"bootId",boot,"batches",1,"lastSequence",1,"observations",2)));
        write(dir,"invalid-result.json",result);var finish=object("reportRef",folder+"/invalid-result.json","reportSha256",sha(Files.readAllBytes(dir.resolve("invalid-result.json"))));
        assertThat(rejectedHuman("/replay-runs/"+rid+"/completions",finish,operator,null,422).at("/error/code").asText()).isEqualTo("REPLAY_INCOMPLETE");
        ((ObjectNode)result.at("/segmentResults/0")).put("observations",1);write(dir,"result.json",result);finish.put("reportRef",folder+"/result.json").put("reportSha256",sha(Files.readAllBytes(dir.resolve("result.json"))));
        assertThat(human("/replay-runs/"+rid+"/completions",finish,operator,null).path("status").asText()).isEqualTo("completed");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM guard_command",Long.class)).isEqualTo(commands);assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM guard_action",Long.class)).isEqualTo(actions);
        assertThat(store.rows("guard_executor",map("asset_id",aid),false,10)).isEmpty();assertThat(store.rows("guard_asset_binding",map("asset_id",aid),false,10)).isEmpty();
    }

    /** B2：资产更新、机器凭据轮换与吊销、事件指派、回放失败收口及发布组合/事件子列表闭合验证。 */
    @Test void b2AssetUpdateMachineRotateEventAssignmentReplayFailAndChildLists()throws Exception{
        Fixture f=setup();
        var s0=humanSession(operator);
        var patchRes=mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch("/api/v2/assets/"+f.asset()).cookie(s0.cookie()).header("X-CSRF-TOKEN",s0.csrfToken()).header("Idempotency-Key",id()).header("If-Match","1").contentType("application/json").content(canonical(object("owner","updated-owner","criticality","high","status","disabled","labels",object("zone","dmz"))))).andReturn();
        assertThat(patchRes.getResponse().getStatus()).isEqualTo(200);
        var updatedAsset=result(patchRes);
        assertThat(updatedAsset.path("revision").asLong()).isEqualTo(2L);
        assertThat(updatedAsset.path("status").asText()).isEqualTo("disabled");
        assertThat(updatedAsset.path("owner").asText()).isEqualTo("updated-owner");
        assertThat(updatedAsset.path("criticality").asText()).isEqualTo("high");
        assertThat(store.one("guard_asset_binding",map("asset_id",number(store.external("asset",f.asset(),false),"id")),false).get("status")).isEqualTo("suspended");
        rejectedHuman("/assets/"+f.asset()+"/updates",object("environment","authorized"),operator,"2",400);
        rejectedHuman("/assets/"+f.asset()+"/updates",object("labels",object("platform","windows")),operator,"2",422);
        rejectedHuman("/assets/"+f.asset()+"/updates",object("owner","conflict"),operator,"1",409);
        human("/assets/"+f.asset()+"/updates",object("status","active"),operator,"2");

        String rotateKey=id();
        var rotatedSensor=human("/sensors/"+f.sensor()+"/credential-rotations",object("reason","定期轮换"),operator,null,rotateKey);
        assertThat(rotatedSensor.path("credential").asText()).startsWith("mch_").isNotEqualTo(f.sensorCredential());
        assertThat(rotatedSensor.path("rotatedAt").isTextual()).isTrue();
        assertThat(rejectedHuman("/sensors/"+f.sensor()+"/credential-rotations",object("reason","定期轮换"),operator,null,409,rotateKey).at("/error/code").asText()).isEqualTo("CREDENTIAL_ALREADY_ISSUED");
        var oldAuth=mvc.perform(get("/api/v2/machine/sensors/"+f.sensor()+"/config").header("Authorization","Bearer "+f.sensorCredential())).andReturn();
        assertThat(oldAuth.getResponse().getStatus()).isEqualTo(401);
        var newAuth=mvc.perform(get("/api/v2/machine/sensors/"+f.sensor()+"/config").header("Authorization","Bearer "+rotatedSensor.path("credential").asText())).andReturn();
        assertThat(newAuth.getResponse().getStatus()).isEqualTo(200);

        String clientId=rotatedSensor.path("clientId").asText();
        var revokedClient=human("/machine-clients/"+clientId+"/revocations",object("reason","退役吊销"),operator,null);
        assertThat(revokedClient.path("status").asText()).isEqualTo("revoked");
        var afterRevoke=mvc.perform(get("/api/v2/machine/sensors/"+f.sensor()+"/config").header("Authorization","Bearer "+rotatedSensor.path("credential").asText())).andReturn();
        assertThat(afterRevoke.getResponse().getStatus()).isEqualTo(401);

        var session=humanSession(operator);
        var bindings=result(mvc.perform(get("/api/v2/release-bundles/"+f.bundle()+"/bindings").cookie(session.cookie())).andReturn());
        assertThat(bindings.path("items")).hasSize(1);
        assertThat(bindings.at("/items/0/assetId").asText()).isEqualTo(f.asset());

        long aid=number(store.external("asset",f.asset(),false),"id");
        String eventId=id();
        jdbc.update("INSERT INTO security_event(public_id,guard_asset_id,revision,event_key,title,category,severity,status,risk_score,risk_rule_version,first_seen_at,last_seen_at,created_at) VALUES (?,?,1,?,'B2事件','dos_slow','high','open',80,'v5',UTC_TIMESTAMP(3),UTC_TIMESTAMP(3),UTC_TIMESTAMP(3))",eventId,aid,id());
        var putRes=mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put("/api/v2/events/"+eventId+"/assignee").cookie(session.cookie()).header("X-CSRF-TOKEN",session.csrfToken()).header("Idempotency-Key",id()).header("If-Match","1").contentType("application/json").content(canonical(object("userId",operator.userKey(),"reason","指派跟进")))).andReturn();
        assertThat(putRes.getResponse().getStatus()).isEqualTo(200);
        var assigned=result(putRes);
        assertThat(assigned.path("userId").asText()).isEqualTo(operator.userKey());
        assertThat(assigned.path("revision").asLong()).isEqualTo(2L);
        var noEventPerm=identity("no-event",List.of());
        assertThat(rejectedHuman("/events/"+eventId+"/assignments",object("userId",noEventPerm.userKey(),"reason","无权指派"),operator,"2",422).at("/error/code").asText()).isEqualTo("ASSIGNEE_NOT_ELIGIBLE");
        human("/events/"+eventId+"/transitions",object("expectedRevision",2,"to","investigating","reason","开始研判"),operator,"2");
        human("/events/"+eventId+"/transitions",object("expectedRevision",3,"to","resolved","reason","确认缓解"),operator,"3");
        var closed=human("/events/"+eventId+"/transitions",object("expectedRevision",4,"to","closed","reason","演练结案"),operator,"4");
        assertThat(closed.path("status").asText()).isEqualTo("closed");
        session=humanSession(operator);
        var eventDetail=result(mvc.perform(get("/api/v2/events/"+eventId).cookie(session.cookie())).andReturn());
        assertThat(eventDetail.path("closedAt").isTextual()).isTrue();
        assertThat(eventDetail.path("assigneeId").asText()).isEqualTo(operator.userKey());
        assertThat(eventDetail.path("episodeIds").isArray()).isTrue();
        assertThat(eventDetail.path("decisionIds").isArray()).isTrue();
        assertThat(eventDetail.path("actionable").asBoolean()).isFalse();
        assertThat(eventDetail.path("actionableReasonCode").asText()).isEqualTo("EVENT_NOT_OPEN");
        var closedEvents=result(mvc.perform(get("/api/v2/events").param("status","closed").cookie(session.cookie())).andReturn());
        assertThat(closedEvents.path("items").findValuesAsText("id")).contains(eventId);
        var invalidStatus=mvc.perform(get("/api/v2/events").param("status","invalid_state").cookie(session.cookie())).andReturn();
        assertThat(invalidStatus.getResponse().getStatus()).isEqualTo(400);
        assertThat(result(mvc.perform(get("/api/v2/events/"+eventId+"/episodes").cookie(session.cookie())).andReturn()).path("items").isArray()).isTrue();
        assertThat(result(mvc.perform(get("/api/v2/events/"+eventId+"/actions").cookie(session.cookie())).andReturn()).path("items").isArray()).isTrue();

        var oldBundle=store.external("guard_release_bundle",f.bundle(),false);var subject=json(oldBundle,"subject_json");
        var research=human("/release-bundles",object("modelId",f.model(),"policyId",f.policy(),"featureProfileSha256",contracts.profileHash(),"extractorSha256",subject.get("extractorSha256"),"protocolVersions",versions(),"evaluationPlanId",store.get("guard_evaluation_plan",number(oldBundle,"plan_id")).get("public_id"),"capabilityIds",List.of(f.capability()),"environment","research"),operator,null);
        String rbid=research.path("id").asText(),rfolder=id();Path rdir=ROOT.resolve(rfolder);Files.createDirectories(rdir);
        write(rdir,"r-final.json",GuardSignatures.sign(object("protocolVersions",versions(),"subjectSha256",research.get("subjectSha256"),"evaluationPlanSha256",subject.get("evaluationPlanSha256"),"runKind","final","passed",true),"fixture-runner",signing.getPrivate()));
        var rimport=human("/release-bundles/"+rbid+"/imports",object("reportRef",rfolder+"/r-final.json","sha256",sha(Files.readAllBytes(rdir.resolve("r-final.json"))),"runnerIdentity","fixture-runner"),operator,null);
        human("/release-bundles/"+rbid+"/sealings",object("evaluationIds",List.of(rimport.path("id").asText())),operator,"1");
        human("/release-bundles/"+rbid+"/decisions",object("decision","approve","reason","回放失败测试批准"),reviewer,"2");
        var queuedReplay=human("/replay-runs",object("scenarioId",id(),"scenarioSha256","a".repeat(64),"modelId",f.model(),"policyId",f.policy(),"speed",1),operator,null);
        String rid=queuedReplay.path("id").asText();
        var failedReplay=human("/replay-runs/"+rid+"/failures",object("reasonCode","REPLAY_PROCESS_ABORTED","reason","进程中断"),operator,null);
        assertThat(failedReplay.path("status").asText()).isEqualTo("failed");
        assertThat(rejectedHuman("/replay-runs/"+rid+"/failures",object("reasonCode","REPLAY_PROCESS_ABORTED","reason","重复失败"),operator,null,422).at("/error/code").asText()).isEqualTo("STATE_CONFLICT");
    }

    /** B3：P6 冻结计划按原字节摘要登记，不能内联改写；发布组合须与计划登记的候选和提取器一致。 */
    @Test void frozenP6PlanRegistersByRawDigestAndBindsCandidate()throws Exception{
        String folder=id();Path dir=ROOT.resolve(folder);Files.createDirectories(dir);
        Files.write(dir.resolve("model.onnx"),GuardOnnxFixture.model(.999f,0,0,0,.999f));write(dir,"preprocessing.json",object("fitRole","train","vocabularies",List.of(List.of("tcp"),List.of("outbound"),List.of("web"))));write(dir,"calibration.json",object("fitRole","calibration","kind","fixed-test-only"));
        ObjectNode manifest=(ObjectNode)GuardDomainTest.example("model-manifest");String onnx=sha(Files.readAllBytes(dir.resolve("model.onnx")));
        java.util.function.BiFunction<String,String,ObjectNode> frozen=(candidate,version)->object("stage","P6","plan","fixture-"+folder,"evaluationVersion",version,"featureProfileSha256",contracts.profileHash(),"candidateSha256",candidate,"extractorSha256",manifest.path("extractorSha256").asText(),"splitManifestSha256","5".repeat(64),"evaluationIds",List.of("p6-l1-01"),"noTestReadBeforeP6",true);
        // 原件刻意带缩进，原字节摘要与 JCS 摘要不同；后端必须保存前者。
        Files.writeString(dir.resolve("plan.json"),JSON.writerWithDefaultPrettyPrinter().writeValueAsString(frozen.apply(onnx,EVALUATION)));
        String raw=sha(Files.readAllBytes(dir.resolve("plan.json")));assertThat(raw).isNotEqualTo(hash(parse(Files.readString(dir.resolve("plan.json")))));
        assertThat(rejectedHuman("/evaluation-plans",object("planRef",folder+"/plan.json","planSha256","0".repeat(64)),operator,null,422).at("/error/code").asText()).isEqualTo("ARTIFACT_HASH_MISMATCH");
        rejectedHuman("/evaluation-plans",object("planRef",folder+"/plan.json","planSha256",raw,"planKey","inline"),operator,null,400);
        Files.writeString(dir.resolve("old.json"),canonical(frozen.apply(onnx,LEGACY_PLATFORM_EVALUATION)));
        assertThat(rejectedHuman("/evaluation-plans",object("planRef",folder+"/old.json","planSha256",sha(Files.readAllBytes(dir.resolve("old.json")))),operator,null,422).at("/error/code").asText()).isEqualTo("EVALUATION_PLAN_MISMATCH");
        JsonNode plan=human("/evaluation-plans",object("planRef",folder+"/plan.json","planSha256",raw),operator,null);assertThat(plan.path("planSha256").asText()).isEqualTo(raw);
        var row=store.external("guard_evaluation_plan",plan.path("id").asText(),false);assertThat(json(row,"payload_json").path("kind").asText()).isEqualTo("p6-frozen");
        Files.writeString(dir.resolve("other.json"),canonical(frozen.apply("6".repeat(64),EVALUATION).put("plan","other-"+folder)));String otherRaw=sha(Files.readAllBytes(dir.resolve("other.json")));JsonNode other=human("/evaluation-plans",object("planRef",folder+"/other.json","planSha256",otherRaw),operator,null);
        String capability=human("/capabilities",object("capabilityKey",id(),"version","fixture-v1","platform","macos","adapterVersion","fixture-1","addressFamily","ipv4","transport","tcp","direction","outbound","family","dos_slow","profile","flow-prefix-v1","behaviorScope",List.of("slowloris"),"latencyLimits",object("maxMs",10000),"level","research","evidenceRef","fixture:none","evidenceSha256","a".repeat(64),"runnerIdentity","fixture-runner"),operator,null).path("id").asText();
        var bundles=new ArrayList<JsonNode>();
        for(var bound:List.of(Map.entry(raw,plan),Map.entry(otherRaw,other))){
            ObjectNode m=manifest.deepCopy();String model=id();m.put("modelId",model).put("modelVersion",id()).put("featureProfileSha256",contracts.profileHash()).put("evaluationPlanSha256",bound.getKey()).put("artifactSha256",onnx);
            for(var pair:Map.of("preprocessingSha256","preprocessing.json","calibrationSha256","calibration.json").entrySet())m.put(pair.getKey(),sha(Files.readAllBytes(dir.resolve(pair.getValue()))));((ObjectNode)m.get("runtime")).put("runtimeVersion","1.23.2");write(dir,model+".json",m);
            human("/models",object("manifestRef",folder+"/"+model+".json","manifestSha256",sha(Files.readAllBytes(dir.resolve(model+".json")))),operator,null);
            assertThat(human("/models/"+model+"/validations",object("validationProfileId","host-guard-onnx-v1"),operator,null).path("status").asText()).isEqualTo("validated");
            ObjectNode policy=(ObjectNode)GuardDomainTest.example("decision-policy");String pid=id();policy.put("policyId",pid).put("modelId",model).put("policyVersion",DECISION).put("mode","alert_only").put("protectionSetSha256",hash(PROTECTION)).put("evaluationPlanSha256",bound.getKey());policy.set("supportedCapabilityIds",node(List.of(capability)));
            human("/decision-policies",policy,operator,null);human("/decision-policies/"+pid+"/reviews",object("decision","approve","reason","冻结计划测试"),reviewer,"1");
            ObjectNode body=object("modelId",model,"policyId",pid,"featureProfileSha256",contracts.profileHash(),"extractorSha256",m.path("extractorSha256").asText(),"protocolVersions",versions(),"evaluationPlanId",bound.getValue().path("id").asText(),"capabilityIds",List.of(capability),"environment","research");
            if(bound.getKey().equals(raw))bundles.add(human("/release-bundles",body,operator,null));
            else assertThat(rejectedHuman("/release-bundles",body,operator,null,422).at("/error/code").asText()).isEqualTo("EVALUATION_PLAN_MISMATCH");
        }
        var bundle=store.external("guard_release_bundle",bundles.get(0).path("id").asText(),false);
        assertThat(json(bundle,"subject_json").path("evaluationPlanSha256").asText()).isEqualTo(raw);
        assertThat(json(bundle,"subject_json").at("/protocolVersions/evaluation").asText()).isEqualTo("host-guard-evaluation/2026-10-08.1");
    }

    /** B3：CLI 经本机 HTTP 桥进入真实 MVC/鉴权/事务链，制品与报告均在隔离测试目录合成。 */
    @ParameterizedTest
    @ValueSource(booleans={false,true})
    @EnabledIfEnvironmentVariable(named="P7_IMPORT_IT_ENABLED",matches="true")
    void syntheticBundleCliRequiresIndependentReviewAndStopsBeforeApproval(boolean reuseCapabilities)throws Exception{
        String folder=id();Path dir=ROOT.resolve(folder);Files.createDirectories(dir);
        ObjectNode plan=(ObjectNode)parse(Files.readString(Path.of("../scripts/p7/testdata/import-bundle-plan.json")));
        write(dir,"dataset.json",object("datasetKey",id(),"version","synthetic-b3"));
        String dataset=human("/datasets",object("manifestRef",folder+"/dataset.json","manifestSha256",sha(Files.readAllBytes(dir.resolve("dataset.json")))),operator,null).path("id").asText();
        ObjectNode evaluation=(ObjectNode)plan.get("evaluationPlan");evaluation.put("planKey",id()).set("datasetRefs",node(List.of(dataset)));evaluation.set("protocolVersions",versions());
        Files.write(dir.resolve("model.onnx"),GuardOnnxFixture.model(.99f,0,0,0,.99f));
        write(dir,"preprocessing.json",object("fitRole","train","vocabularies",List.of(List.of("tcp"),List.of("outbound"),List.of("web"))));
        write(dir,"calibration.json",object("fitRole","calibration","kind","fixed-test-only"));
        ObjectNode manifest=(ObjectNode)GuardDomainTest.example("model-manifest");
        manifest.put("modelId",id()).put("modelVersion",folder).put("featureProfileSha256",contracts.profileHash()).put("evaluationPlanSha256",hash(evaluation));
        for(var pair:Map.of("artifactSha256","model.onnx","preprocessingSha256","preprocessing.json","calibrationSha256","calibration.json").entrySet())manifest.put(pair.getKey(),sha(Files.readAllBytes(dir.resolve(pair.getValue()))));
        ((ObjectNode)manifest.get("runtime")).put("runtimeVersion","1.23.2");write(dir,"manifest.json",manifest);
        plan.set("model",object("manifestRef",folder+"/manifest.json","manifestSha256",sha(Files.readAllBytes(dir.resolve("manifest.json")))));
        ((ObjectNode)plan.get("capability")).put("capabilityKey",id());
        if(reuseCapabilities){
            var refs=node(List.of());
            for(String family:List.of("port_scan","bruteforce","dos_flood","dos_slow")){
                ObjectNode cap=(ObjectNode)plan.get("capability").deepCopy();
                cap.put("capabilityKey",id()).put("family",family).put("level","lab_auto").put("direction","inbound");
                if(family.equals("port_scan")){
                    write(dir,"exemption.json",GuardSignatures.sign(object("passed",true,"scope","peer_inbound","platform","macos-pf","protectionSetSha256",hash(PROTECTION)),"fixture-runner",signing.getPrivate()));
                    cap.put("scope","peer_inbound").put("protectionSetSha256",hash(PROTECTION)).put("exemptionEvidenceSha256",sha(Files.readAllBytes(dir.resolve("exemption.json"))));
                }
                ObjectNode signedPayload=cap.deepCopy();signedPayload.remove(List.of("evidenceRef","evidenceSha256","runnerIdentity"));
                write(dir,family+"-capability.json",GuardSignatures.sign(object("passed",true,"protocolVersions",versions(),"capability",signedPayload),"fixture-runner",signing.getPrivate()));
                cap.put("evidenceRef",folder+"/"+family+"-capability.json").put("evidenceSha256",sha(Files.readAllBytes(dir.resolve(family+"-capability.json")))).put("runnerIdentity","fixture-runner");
                if(family.equals("port_scan"))cap.put("exemptionEvidenceRef",folder+"/exemption.json");
                String cid=human("/capabilities",cap,operator,null).path("id").asText();
                ((com.fasterxml.jackson.databind.node.ArrayNode)refs).add(object("id",cid,"payload",cap,"payloadSha256",hash(cap)));
            }
            plan.remove("capability");plan.set("existingCapabilities",refs);
            ((ObjectNode)plan.get("decisionPolicy")).put("supportedCapabilityIds","${capabilityIds}");
            ((ObjectNode)plan.get("releaseBundle")).put("capabilityIds","${capabilityIds}");
        }
        ((ObjectNode)plan.get("decisionPolicy")).put("policyId",id()).put("policyVersion",folder).put("protectionSetSha256",hash(PROTECTION));
        ObjectNode release=(ObjectNode)plan.get("releaseBundle");release.put("featureProfileSha256",contracts.profileHash()).put("extractorSha256",manifest.path("extractorSha256").asText()).set("protocolVersions",versions());
        write(dir,"plan.json",plan);
        var session=humanSession(operator);
        Files.writeString(dir.resolve("cookie"),"SESSION="+session.cookie().getValue());Files.writeString(dir.resolve("csrf"),session.csrfToken());
        for(String name:List.of("cookie","csrf"))Files.setPosixFilePermissions(dir.resolve(name),PosixFilePermissions.fromString("rw-------"));
        List<String> writes=new CopyOnWriteArrayList<>();
        var server=com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress("127.0.0.1",0),0);
        server.createContext("/api/v2",exchange->{
            try{
                String path=exchange.getRequestURI().getPath();
                var request=org.springframework.test.web.servlet.request.MockMvcRequestBuilders.request(org.springframework.http.HttpMethod.valueOf(exchange.getRequestMethod()),path);
                exchange.getRequestHeaders().forEach((name,values)->{if(!name.equalsIgnoreCase("Cookie"))request.header(name,values.toArray());});
                String cookies=exchange.getRequestHeaders().getFirst("Cookie");
                if(cookies!=null)for(String item:cookies.split(";")){String[] pair=item.trim().split("=",2);if(pair.length==2)request.cookie(new Cookie(pair[0],pair[1]));}
                request.content(exchange.getRequestBody().readAllBytes());
                if(exchange.getRequestMethod().equals("POST"))writes.add(path.substring("/api/v2".length()));
                var response=mvc.perform(request).andReturn().getResponse();byte[] bytes=response.getContentAsByteArray();
                exchange.getResponseHeaders().set("Content-Type","application/json");exchange.sendResponseHeaders(response.getStatus(),bytes.length);exchange.getResponseBody().write(bytes);
            }catch(Exception e){exchange.sendResponseHeaders(500,-1);}finally{exchange.close();}
        });
        server.start();
        try{
            String base="http://127.0.0.1:"+server.getAddress().getPort()+"/api/v2";
            runImportCli(dir,base,0,"--plan",dir.resolve("plan.json").toString(),"--state",dir.resolve("state.json").toString());
            JsonNode state=parse(Files.readString(dir.resolve("state.json")));String model=state.path("modelId").asText(),policy=state.path("policyId").asText();
            JsonNode capabilities=state.get("capabilityIds");
            int prepareWrites=reuseCapabilities?4:5;
            if(reuseCapabilities){assertThat(writes).containsExactly("/models","/models/"+model+"/validations","/evaluation-plans","/decision-policies");assertThat(capabilities).hasSize(4);}
            else assertThat(writes).containsExactly("/models","/models/"+model+"/validations","/evaluation-plans","/capabilities","/decision-policies");
            assertThat(state.path("phase").asText()).isEqualTo("awaiting-policy-review");
            // 未审核恢复、直接跳到发布组合、自审和无权身份均由真实权限/状态服务拒绝。
            runImportCli(dir,base,1,"--resume-state",dir.resolve("state.json").toString());assertThat(writes).hasSize(prepareWrites);
            ObjectNode bundleBody=release.deepCopy();bundleBody.put("modelId",model).put("policyId",policy).put("evaluationPlanId",state.path("evaluationPlanId").asText()).set("capabilityIds",capabilities);
            assertThat(rejectedHuman("/release-bundles",bundleBody,operator,null,422).at("/error/code").asText()).isEqualTo("RELEASE_COMBINATION_INVALID");
            jdbc.update("INSERT INTO sys_user_role(user_id,role_id,scope_type,scope_id) SELECT ?,id,'global','*' FROM sys_role WHERE role_key='security_reviewer'",operator.id());
            assertThat(rejectedHuman("/decision-policies/"+policy+"/reviews",object("decision","approve","reason","拒绝自审"),operator,"1",403).at("/error/code").asText()).isEqualTo("APPROVAL_SEPARATION_REQUIRED");
            var outsider=identity("b3-outsider",List.of());rejectedHuman("/models",plan.get("model"),outsider,null,403);
            ObjectNode badManifest=(ObjectNode)plan.get("model").deepCopy();badManifest.put("manifestSha256","0".repeat(64));assertThat(rejectedHuman("/models",badManifest,operator,null,422).at("/error/code").asText()).isEqualTo("ARTIFACT_HASH_MISMATCH");
            human("/decision-policies/"+policy+"/reviews",object("decision","approve","reason","独立测试审查"),reviewer,"1");
            JsonNode subject=object("contractVersion",MODEL_CONTRACT,"protocolVersions",versions(),"modelId",model,"manifestSha256",plan.at("/model/manifestSha256"),"policyId",policy,"policySha256",state.get("policySha256"),"featureProfileSha256",contracts.profileHash(),"extractorSha256",manifest.get("extractorSha256"),"evaluationPlanSha256",hash(evaluation),"capabilityIds",capabilities,"environment","research");
            write(dir,"final.json",GuardSignatures.sign(object("protocolVersions",versions(),"subjectSha256",hash(subject),"evaluationPlanSha256",hash(evaluation),"runKind","final","passed",true),"fixture-runner",signing.getPrivate()));
            write(dir,"reports.json",object("imports",List.of(object("reportRef",folder+"/final.json","sha256",sha(Files.readAllBytes(dir.resolve("final.json"))),"runnerIdentity","fixture-runner"))));
            session=humanSession(operator);Files.writeString(dir.resolve("cookie"),"SESSION="+session.cookie().getValue());Files.writeString(dir.resolve("csrf"),session.csrfToken());
            runImportCli(dir,base,0,"--resume-state",dir.resolve("state.json").toString(),"--reports",dir.resolve("reports.json").toString());
            state=parse(Files.readString(dir.resolve("state.json")));String bundle=state.path("bundleId").asText();
            assertThat(writes.subList(prepareWrites,writes.size())).containsExactly("/release-bundles","/release-bundles/"+bundle+"/imports","/release-bundles/"+bundle+"/sealings");
            assertThat(state.path("phase").asText()).isEqualTo("awaiting-bundle-decision");
            assertThat(str(store.external("guard_release_bundle",bundle,false),"status")).isEqualTo("evaluated");
            assertThat(rejectedHuman("/release-bundles/"+bundle+"/decisions",object("decision","approve","reason","拒绝自审"),operator,"2",403).at("/error/code").asText()).isEqualTo("APPROVAL_SEPARATION_REQUIRED");
            assertThat(store.rows("guard_asset_binding",map("bundle_id",store.external("guard_release_bundle",bundle,false).get("id")),false,10)).isEmpty();
        }finally{server.stop(0);Files.deleteIfExists(dir.resolve("cookie"));Files.deleteIfExists(dir.resolve("csrf"));}
    }
    /** 测试专用的失败断言保留真实会话、CSRF 和请求幂等头。 */
    JsonNode rejectedHuman(String path,JsonNode body,IdentityPrincipal actor,String revision,int expected)throws Exception{
        return rejectedHuman(path,body,actor,revision,expected,id());
    }
    JsonNode rejectedHuman(String path,JsonNode body,IdentityPrincipal actor,String revision,int expected,String key)throws Exception{
        var session=humanSession(actor);var request=post("/api/v2"+path).cookie(session.cookie()).header("X-CSRF-TOKEN",session.csrfToken()).header("Idempotency-Key",key).contentType("application/json").content(canonical(body));
        if(revision!=null)request.header("If-Match",revision);
        var response=mvc.perform(request).andReturn().getResponse();assertThat(response.getStatus()).withFailMessage("HTTP %s: %s",response.getStatus(),response.getContentAsString()).isEqualTo(expected);
        return parse(response.getContentAsString());
    }
    /** Python 包装器可显式指向已有环境；日志只含接口状态，不输出会话凭据。 */
    void runImportCli(Path dir,String base,int expected,String... arguments)throws Exception{
        List<String> command=new ArrayList<>(List.of("sh",System.getenv().getOrDefault("P7_PYTHON_WRAPPER",Path.of("../executor/python.sh").toAbsolutePath().toString()),"-B",Path.of("../scripts/p7/import_bundle.py").toAbsolutePath().toString(),"--base-url",base,"--cookie-file",dir.resolve("cookie").toString(),"--csrf-file",dir.resolve("csrf").toString()));command.addAll(List.of(arguments));
        Path log=dir.resolve("cli-"+id()+".log");var process=new ProcessBuilder(command).redirectErrorStream(true).redirectOutput(log.toFile()).start();
        try{assertThat(process.waitFor(60,TimeUnit.SECONDS)).isTrue();assertThat(process.exitValue()).withFailMessage("CLI: %s",Files.readString(log)).isEqualTo(expected);}finally{if(process.isAlive())process.destroyForcibly().waitFor();}
    }
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
    /** 恢复器在回执取出后、核对前按 TTL 清除规则：核对先把动作判为 expired，晚到的同一清除回执仍补记已核验；状态不一致的回执不补记。 */
    @Test void lateExpiredReceiptAfterEnumerationTerminalIsStillVerified()throws Exception{
        Fixture f=setup();Instant at=Instant.now().truncatedTo(ChronoUnit.MICROS);accept(f,List.of(observation(f,at,id(),0)),1,true);
        var asset=store.external("asset",f.asset,false);var action=store.one("guard_action",map("asset_id",asset.get("id")),false);assertThat(action).isNotNull();
        JsonNode claimBody=object("bootId",f.executorBoot,"capabilityHash",f.capabilityHash(),"maxItems",10,"waitSeconds",0);
        JsonNode command=machine("/executors/"+f.executor+"/command-claims",claimBody,f.executorCredential).path("commands").get(0);String aid=str(action,"public_id");
        jdbc.update("UPDATE guard_command SET apply_by=issued_at WHERE action_id=?",action.get("id"));
        jdbc.update("UPDATE guard_action a JOIN guard_command c ON c.action_id=a.id SET a.block_until=c.issued_at+INTERVAL 1000 MICROSECOND WHERE a.id=?",action.get("id"));
        Thread.sleep(20);
        JsonNode empty=object("digestVersion","guard-state/1","assetId",f.asset,"executorId",f.executor,"executorBootId",f.executorBoot,"rules",List.of(),"pendingRevocations",List.of());String digest=hash(empty);
        Instant time=Instant.now().truncatedTo(ChronoUnit.MICROS);
        machine("/executors/"+f.executor+"/reconciliations",object("executorBootId",f.executorBoot,"observedAt",time.toString(),"digestVersion","guard-state/1","stateDigest",digest,"ownedRules",List.of(),"pendingRevocations",List.of(),"recoveryErrors",List.of()),f.executorCredential);
        assertThat(str(store.external("guard_action",aid,false),"observed_state")).isEqualTo("expired");
        long charged=number(store.one("guard_target_budget",map("budget_target_id",store.external("guard_budget_target",f.targetId,false).get("id")),false),"charged_ms");
        JsonNode receipt=object("contractVersion",CONTRACT,"receiptId",id(),"commandId",command.at("/payload/commandId"),"revocationId",null,"executorId",f.executor,"status","expired","observedAt",time.toString(),"ruleHandle",null,"effectiveBlockUntil",null,"errorCode",null,"stateDigest",digest);
        assertThat(machine("/executors/"+f.executor+"/receipts",receipt,f.executorCredential).path("projected").asBoolean()).isTrue();
        ObjectNode mismatch=(ObjectNode)receipt.deepCopy();mismatch.put("receiptId",id()).put("status","rejected").put("errorCode","SCOPE_DENIED");
        assertThat(machine("/executors/"+f.executor+"/receipts",mismatch,f.executorCredential).path("projected").asBoolean()).isFalse();
        assertThat(str(store.external("guard_action",aid,false),"observed_state")).isEqualTo("expired");
        assertThat(number(store.one("guard_target_budget",map("budget_target_id",store.external("guard_budget_target",f.targetId,false).get("id")),false),"charged_ms")).isEqualTo(charged);
    }
    void accept(Fixture f,List<? extends JsonNode> observations,long sequence,boolean consume)throws Exception{
        var b=batch(f,observations,sequence);var receipt=machine("/sensors/"+f.sensor+"/observation-batches",b,f.sensorCredential);assertThat(receipt.path("acceptedCount").asInt()).withFailMessage("receipt=%s",receipt).isEqualTo(observations.size());
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
    /** JDBC 批写须立即对同事务 MyBatis 读可见，时钟不得缓存；回滚不能留下批写事实。 */
    @Test void jdbcBatchSharesTransactionAndInvalidatesCachedReads(){
        String key=id();
        new TransactionTemplate(manager).executeWithoutResult(status->{
            var where=map("event_key",key);
            assertThat(store.rows("outbox_event",where,false,10)).isEmpty();
            store.insertAll("outbox_event",List.of(map("event_key",key,"aggregate_type","guard","aggregate_id",id(),"topic","guard.test","payload_json","{}","status","pending")));
            assertThat(store.rows("outbox_event",where,false,10)).hasSize(1);
            Instant before=store.now();jdbc.queryForObject("SELECT SLEEP(0.02)",Integer.class);
            assertThat(store.now()).isAfter(before);
            status.setRollbackOnly();
        });
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event WHERE event_key=?",Integer.class,key)).isZero();
    }
    /** 不同资产的缺失 episode 查询必须可并行提交，不能在同一个空索引区间互持 gap 锁。 */
    @Test void researchReadCommittedAllowsConcurrentMissingEpisodeInserts()throws Exception{
        assertThat(GuardReplay.class.getMethod("consume",String.class).getAnnotation(Transactional.class).isolation())
                .isEqualTo(Isolation.READ_COMMITTED);
        var first=episodeInsert(setup());var second=episodeInsert(setup());
        var bothMissing=new CyclicBarrier(2);var workers=Executors.newFixedThreadPool(2);
        try{
            var commits=new ArrayList<Future<Long>>();
            for(var values:List.of(first,second))commits.add(workers.submit(()->readCommittedTransaction().execute(status->{
                assertThat(jdbc.queryForObject("SELECT @@transaction_isolation",String.class)).isEqualTo("READ-COMMITTED");
                store.lockAsset(number(values,"asset_id"));
                assertThat(store.byKeys("guard_episode",List.of(episodeLookup(values)),true)).isEmpty();
                awaitBarrier(bothMissing);
                store.addAllReturning("guard_episode",List.of(values));
                return number(values,"id");
            })));
            var ids=new HashSet<Long>();for(var commit:commits)ids.add(commit.get(20,TimeUnit.SECONDS));
            assertThat(ids).hasSize(2);
            for(var values:List.of(first,second))assertThat(store.byKeys("guard_episode",List.of(episodeLookup(values)),false))
                    .singleElement().satisfies(row->assertThat(number(row,"id")).isEqualTo(number(values,"id")));
        }finally{workers.shutdownNow();assertThat(workers.awaitTermination(10,TimeUnit.SECONDS)).isTrue();}
    }
    /** 先普通读再等待资产锁的事务，获锁后须看到上一事务新提交的 episode，而非旧的 RR 快照。 */
    @Test void researchReadCommittedSeesEpisodeCommittedWhileWaitingForAssetLock()throws Exception{
        var values=episodeInsert(setup());long aid=number(values,"asset_id");var lookup=episodeLookup(values);
        var writerLocked=new CountDownLatch(1);var readerRead=new CountDownLatch(1);var releaseWriter=new CountDownLatch(1);
        var workers=Executors.newFixedThreadPool(2);
        try{
            Future<Long> writer=workers.submit(()->readCommittedTransaction().execute(status->{
                store.lockAsset(aid);store.addAllReturning("guard_episode",List.of(values));writerLocked.countDown();
                awaitLatch(releaseWriter);return number(values,"id");
            }));
            Future<Long> reader=workers.submit(()->{
                awaitLatch(writerLocked);
                return readCommittedTransaction().execute(status->{
                    // JDBC 普通读建立数据库快照，不把空结果留在 MyBatis 一级缓存中。
                    assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM guard_episode WHERE asset_id=?",Long.class,aid)).isZero();
                    readerRead.countDown();store.lockAsset(aid);
                    var rows=store.byKeys("guard_episode",List.of(lookup),false);assertThat(rows).hasSize(1);
                    return number(rows.getFirst(),"id");
                });
            });
            awaitLatch(readerRead);releaseWriter.countDown();
            assertThat(reader.get(20,TimeUnit.SECONDS)).isEqualTo(writer.get(20,TimeUnit.SECONDS));
        }finally{releaseWriter.countDown();workers.shutdownNow();assertThat(workers.awaitTermination(10,TimeUnit.SECONDS)).isTrue();}
    }
    /** 测试使用与 research T2 相同的隔离级别和真实事务连接，等待均有界。 */
    private TransactionTemplate readCommittedTransaction(){
        var tx=new TransactionTemplate(manager);tx.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED);tx.setTimeout(15);return tx;
    }
    /** 只构造真实表必需字段；新资产没有任何 episode，不借用或清理其他测试的事实。 */
    private Map<String,Object> episodeInsert(Fixture f){
        var now=store.now();return map("asset_id",store.external("asset",f.asset(),false).get("id"),
                "sensor_id",store.external("sensor_agent",f.sensor(),false).get("id"),"boot_id",f.boot(),"peer_key","e".repeat(64),
                "key_epoch",1L,"direction","outbound","transport","tcp","service_port",443,"family","dos_slow",
                "scope","peer_service","source","model","rule_id","","bundle_id",store.external("guard_release_bundle",f.bundle(),false).get("id"),
                "bucket_start",db(Instant.ofEpochSecond(now.getEpochSecond()/30*30)),"revision",1L);
    }
    /** 使用生产唯一键查询路径，排除插入专用字段及运行时回填的主键。 */
    private static Map<String,Object> episodeLookup(Map<String,Object> values){
        var key=new LinkedHashMap<>(values);key.remove("id");key.remove("public_id");key.remove("revision");
        key.put("service_port_key",key.remove("service_port"));return key;
    }
    private static void awaitLatch(CountDownLatch latch){
        try{assertThat(latch.await(10,TimeUnit.SECONDS)).as("并发测试协调超时").isTrue();}
        catch(InterruptedException ex){Thread.currentThread().interrupt();throw new AssertionError("并发测试被中断",ex);}
    }
    private static void awaitBarrier(CyclicBarrier barrier){
        try{barrier.await(10,TimeUnit.SECONDS);}
        catch(InterruptedException ex){Thread.currentThread().interrupt();throw new AssertionError("并发测试被中断",ex);}
        catch(BrokenBarrierException|TimeoutException ex){throw new AssertionError("并发测试协调失败",ex);}
    }
    /** 整批与分批最终证据相同；分批仅多出各自批末判定，不能复用被 final 替换的 prefix。 */
    @Test void splitBatchesHaveEquivalentTerminalDecisionsAndKeepLatestSnapshots()throws Exception{
        var rule=object("ruleId","slow-duration","family","dos_slow","field","features.elapsedMs","operator","gte","threshold",4000,"autoEligible",false);
        // 预置快照在 at 前 1ms；保持二者位于同一 30 秒分桶，避免墙钟恰逢边界时误造两个 episode。
        Fixture f=setup("dos_slow",List.of(rule),false,GuardContracts.MAX_BATCH_SIZE);Instant at=store.now().minusSeconds(2).truncatedTo(ChronoUnit.SECONDS).plusMillis(2);
        long aid=number(store.external("asset",f.asset(),false),"id");
        List<List<JsonNode>> outcomes=new ArrayList<>();long sequence=1;
        for(int size:List.of(512,256)){
            String peer=(size==512?"a":"b").repeat(64);var observations=new ArrayList<ObjectNode>();
            var prefixes=new ArrayList<ObjectNode>();var finals=new ArrayList<ObjectNode>();
            for(int i=0;i<256;i++){
                String parent=id();prefixes.add(observation(f,at,parent,1).put("peerKey",peer));
                var last=observation(f,at.plusMillis(1),parent,2).put("peerKey",peer).put("profile","flow-final-v1").put("closeReason","eof");
                if(i%2==0){last.put("firstSeenAt",time(last,"asOf").minusSeconds(1).toString());((ObjectNode)last.path("features")).put("elapsedMs",1000);}
                finals.add(last);
            }
            // 两种切分从相同已存在路径开始；否则中间 prefix 曾创建路径而整批只见 final，episode 数本就可以不同。
            accept(f,List.of(observation(f,at.minusMillis(1),prefixes.getFirst().path("parentConnectionId").asText(),0).put("peerKey",peer)),sequence++,true);
            observations.addAll(prefixes);observations.addAll(finals);
            for(int start=0;start<observations.size();start+=size)accept(f,observations.subList(start,Math.min(start+size,observations.size())),sequence++,true);
            var normalized=new ArrayList<JsonNode>();
            for(var episode:store.rows("guard_episode",map("asset_id",aid,"peer_key",peer),false,100)){
                var decisions=store.rows("guard_decision",map("episode_id",episode.get("id")),false,100);
                assertThat(decisions).hasSize(size==512?2:3);
                var decision=decisions.getFirst();var proof=json(decision,"evidence_json");
                assertThat(proof.path("selectedObservations")).hasSize(256);
                for(var selected:proof.path("selectedObservations")){
                    var o=store.external("guard_observation",selected.path("observationId").asText(),false);
                    assertThat(o.get("profile")).isEqualTo("flow-final-v1");
                    assertThat(number(o,"snapshot_index")).isEqualTo(2);
                }
                normalized.add(object("family",episode.get("family"),"source",episode.get("source"),"ruleId",episode.get("rule_id"),"decision",decision.get("decision"),"reason",decision.get("reason_code"),"detail",proof.path("detailCode"),"selected",proof.path("selectedObservations").size()));
            }
            normalized.sort(Comparator.comparing(GuardJson::canonical));outcomes.add(normalized);
        }
        assertThat(outcomes.get(0)).isNotEmpty().isEqualTo(outcomes.get(1));
        assertThat(store.rows("guard_action",map("asset_id",aid),false,100)).isEmpty();
    }
    /** 多行插入保留批内去重；冲突必须回滚整个 T1，不能留下之前验证过的部分行。 */
    @Test void batchIngestPreservesDuplicateAndConflictAtomicity()throws Exception{
        Fixture f=setup();var at=Instant.now().truncatedTo(ChronoUnit.MICROS);var original=observation(f,at,id(),0);
        var request=batch(f,List.of(original,original.deepCopy()),1);
        var accepted=machine("/sensors/"+f.sensor()+"/observation-batches",request,f.sensorCredential());
        assertThat(accepted.path("acceptedCount").asInt()).isEqualTo(1);assertThat(accepted.path("duplicateCount").asInt()).isEqualTo(1);
        assertThat(str(store.external("guard_observation_batch",request.path("batchId").asText(),false),"request_sha256")).isEqualTo(hash(request));
        assertThat(machine("/sensors/"+f.sensor()+"/observation-batches",request,f.sensorCredential())).isEqualTo(accepted);
        var next=observation(f,at,id(),0);var conflict=next.deepCopy().put("observationId",id());var body=batch(f,List.of(next,conflict),2);
        var response=mvc.perform(post("/api/v2/machine/sensors/"+f.sensor()+"/observation-batches").header("Authorization","Bearer "+f.sensorCredential()).header("Idempotency-Key",id()).contentType("application/json").content(canonical(body))).andReturn();
        assertThat(response.getResponse().getStatus()).isEqualTo(409);
        assertThat(parse(response.getResponse().getContentAsString()).at("/error/code").asText()).isEqualTo("IDEMPOTENCY_CONFLICT");
        assertThat(store.one("guard_observation",map("public_id",next.path("observationId").asText()),false)).isNull();
        assertThat(store.one("guard_observation_batch",map("public_id",body.path("batchId").asText()),false)).isNull();
    }
    /** 多服务端口批次不能交叉关联生成键；下一批 final/规则未命中必须覆盖旧命中证据。 */
    @Test void manyServicePortsKeepTheirOwnEvidenceAndFinalReplacesEachRuleHit()throws Exception{
        var rule=object("ruleId","brute-duration","family","brute_force","field","features.elapsedMs","operator","gte","threshold",4000,"autoEligible",false);
        Fixture f=setup("brute_force",List.of(rule));Instant at=Instant.now().truncatedTo(ChronoUnit.SECONDS);
        var first=new ArrayList<ObjectNode>();var second=new ArrayList<ObjectNode>();
        for(int port=2000;port<2020;port++){
            String parent=id();first.add(observation(f,at,parent,0).put("servicePort",port));
            var updated=observation(f,at.plusMillis(1),parent,1).put("servicePort",port).put("profile","flow-final-v1").put("closeReason","eof");
            updated.put("firstSeenAt",time(updated,"asOf").minusSeconds(1).toString());((ObjectNode)updated.path("features")).put("elapsedMs",1000);second.add(updated);
        }
        Instant started=store.now();accept(f,first,1,true);Instant finished=store.now();var asset=store.external("asset",f.asset,false);
        var inferences=store.rows("guard_inference",map("asset_id",asset.get("id")),false,100);
        assertThat(inferences).hasSize(first.size());
        assertThat(inferences.stream().map(i->instant(i.get("completed_at"))).distinct().toList()).hasSize(1);
        for(var inference:inferences)assertThat(instant(inference.get("completed_at"))).isBetween(started,finished);
        var before=store.rows("guard_episode",map("asset_id",asset.get("id"),"source","rule"),false,100);assertThat(before).hasSize(20);
        for(var episode:before){var e=store.one("guard_episode_evidence",map("episode_id",episode.get("id")),false);
            var o=store.get("guard_observation",number(e,"observation_id"));assertThat(o.get("service_port")).isEqualTo(episode.get("service_port"));assertThat(GuardDetection.flag(e.get("rule_matched"))).isTrue();}
        accept(f,second,2,true);
        assertThat(store.rows("guard_episode",map("asset_id",asset.get("id"),"source","rule"),false,100)).hasSize(20);
        for(var episode:before){var e=store.one("guard_episode_evidence",map("episode_id",episode.get("id")),false);
            assertThat(GuardDetection.flag(e.get("rule_matched"))).isFalse();assertThat(store.get("guard_observation",number(e,"observation_id")).get("profile")).isEqualTo("flow-final-v1");
            assertThat(str(store.one("guard_decision",map("episode_id",episode.get("id")),false),"decision")).isEqualTo("observe");}
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
    /** C1a：策略版本带 inbound 标记时，非 inbound 观察的规则事实为不适用且不形成规则 episode；inbound 照常命中。 */
    @Test void inboundOnlyPolicyGatesRuleEpisodesByDirection()throws Exception{
        var rule=object("ruleId","brute-starts","family","dos_slow","field","contexts.30.peerFlowStarts","operator","gte","threshold",3,"autoEligible",false);
        Fixture f=setup("dos_slow",List.of(rule));jdbc.update("UPDATE guard_model SET validation_status='failed' WHERE public_id=?",f.model);
        var row=store.external("guard_decision_policy",f.policy,false);var policy=(ObjectNode)json(row,"definition_json");
        policy.put("policyVersion",policy.path("policyVersion").asText()+"+"+GuardRules.INBOUND_ONLY_TOKEN);
        jdbc.update("UPDATE guard_decision_policy SET definition_json=? WHERE id=?",canonical(policy),row.get("id"));
        var asset=store.external("asset",f.asset,false);
        var unknown=observation(f,Instant.now().truncatedTo(ChronoUnit.MICROS),id(),0);unknown.put("direction","unknown").put("serviceClass","other").putNull("servicePort").putNull("targetRef").putNull("targetExpiresAt");accept(f,List.of(unknown),1,true);
        var facts=store.rows("guard_rule_evaluation",map("asset_id",asset.get("id")),false,10);assertThat(facts).hasSize(1);
        assertThat(GuardDetection.flag(facts.getFirst().get("applicable"))).isFalse();assertThat(GuardDetection.flag(facts.getFirst().get("matched"))).isFalse();
        assertThat(str(facts.getFirst(),"rule_version")).isEqualTo(GuardRules.INBOUND_ONLY_RULE_VERSION);
        assertThat(json(facts.getFirst(),"payload_json").path("reason").asText()).isEqualTo(GuardRules.DIRECTION_NOT_APPLICABLE);
        assertThat(store.rows("guard_episode",map("asset_id",asset.get("id"),"source","rule"),false,10)).isEmpty();
        var inbound=observation(f,Instant.now().truncatedTo(ChronoUnit.MICROS),id(),0);inbound.put("direction","inbound");accept(f,List.of(inbound),2,true);
        facts=store.rows("guard_rule_evaluation",map("asset_id",asset.get("id")),false,10);
        assertThat(facts.stream().filter(e->GuardDetection.flag(e.get("matched"))&&GuardDetection.flag(e.get("applicable")))).hasSize(1);
        var episode=store.one("guard_episode",map("asset_id",asset.get("id"),"source","rule"),false);assertThat(episode).isNotNull();assertThat(str(episode,"direction")).isEqualTo("inbound");
        assertThat(str(store.one("guard_decision",map("episode_id",episode.get("id")),false),"decision")).isEqualTo("alert");
    }
    @Test void outboundScanRuleRemainsAlertOnly()throws Exception{
        var rule=object("ruleId","scan-outside-scope","family","port_scan","field","features.elapsedMs","operator","gte","threshold",4000,"autoEligible",true);
        Fixture f=setup("dos_slow",List.of(rule));accept(f,List.of(observation(f,Instant.now().truncatedTo(ChronoUnit.MICROS),id(),0)),1,true);
        var asset=store.external("asset",f.asset,false);var episode=store.one("guard_episode",map("asset_id",asset.get("id"),"source","rule"),false);
        assertThat(str(episode,"scope")).isEqualTo("peer_service");assertThat(str(store.one("guard_decision",map("episode_id",episode.get("id")),false),"decision")).isEqualTo("alert");
    }
    /** V24：观察与策略按原文存储；MySQL JSON 解析会改动末位的十进制数须逐字节保留，推理读回同一数值。 */
    @Test void observationAndPolicyTextKeepExactDoubles()throws Exception{
        Fixture f=setup();Instant at=Instant.now().truncatedTo(ChronoUnit.MICROS);
        var o=observation(f,at,id(),0);((ObjectNode)o.path("features")).put("iatStdUs",12683.157738600517).put("lengthStd",12.088791870525725);
        accept(f,List.of(o),1,false);
        var row=store.one("guard_observation",map("public_id",o.path("observationId").asText()),false);
        assertThat(str(row,"payload_json")).isEqualTo(canonical(o));
        assertThat(json(row,"payload_json").at("/features/iatStdUs").asDouble()).isEqualTo(12683.157738600517);
        var types=jdbc.queryForList("SELECT table_name t,data_type d FROM information_schema.columns WHERE table_schema=DATABASE() AND ((table_name='guard_observation' AND column_name='payload_json') OR (table_name='guard_decision_policy' AND column_name='definition_json'))");
        assertThat(types).hasSize(2).allSatisfy(t->assertThat(String.valueOf(t.get("d"))).isEqualTo("longtext"));
    }
    @ParameterizedTest
    @ValueSource(strings={"missing_reference","different_reference"})
    void validTriggerLeaseAuthorizesSameTargetEvidence(String change)throws Exception{
        Fixture f=setup();Instant at=Instant.now().truncatedTo(ChronoUnit.MICROS);
        var unbound=observation(f,at,id(),0);unbound.putNull("targetRef").putNull("targetExpiresAt");
        if(change.equals("different_reference"))unbound.put("targetRef",id()).put("targetExpiresAt",at.plusSeconds(10).toString());
        var bound=observation(f,at.plusNanos(1000),id(),0);accept(f,List.of(unbound,bound),1,true);
        var asset=store.external("asset",f.asset,false);var episode=store.one("guard_episode",map("asset_id",asset.get("id")),false);
        // 同批在批末判定一次：触发观察持有效租约，其余同对端证据无需共享这份租约。
        var decisions=store.rows("guard_decision",map("episode_id",episode.get("id")),false,10);assertThat(decisions).hasSize(1);
        assertThat(decisions).allSatisfy(d->{assertThat(str(d,"reason_code")).isNull();assertThat(str(d,"decision")).isEqualTo("block_candidate");});
        assertThat(json(decisions.getFirst(),"evidence_json").path("selectedObservations")).hasSize(2);
        assertThat(store.rows("guard_action",map("asset_id",asset.get("id")),false,10)).hasSize(1);
    }
    /** 触发观察本身不可执行时，即使其他选证仍有租约也须停在 T4。 */
    @ParameterizedTest
    @ValueSource(strings={"missing_reference","expired_reference","old_packet"})
    void otherEvidenceCannotReplaceInvalidTriggerLease(String change)throws Exception{
        Fixture f=setup();Instant at=Instant.now().truncatedTo(ChronoUnit.MICROS);
        var earlier=observation(f,at,id(),0);var trigger=observation(f,at.plusNanos(1000),id(),0);
        switch(change){
            case "missing_reference"->trigger.putNull("targetRef").putNull("targetExpiresAt");
            case "expired_reference"->trigger.put("targetExpiresAt",at.toString());
            case "old_packet"->{trigger.put("firstSeenAt",time(trigger,"asOf").minusSeconds(20).toString()).put("lastPacketAt",at.minusSeconds(16).toString()).put("targetExpiresAt",at.minusSeconds(1).toString());((ObjectNode)trigger.path("features")).put("elapsedMs",20000);}
        }
        accept(f,List.of(earlier,trigger),1,true);var asset=store.external("asset",f.asset,false);
        var decision=store.one("guard_decision",map("asset_id",asset.get("id")),false);
        assertThat(str(decision,"reason_code")).isEqualTo("TARGET_REF_STALE");
        assertThat(store.rows("guard_action",map("asset_id",asset.get("id")),false,10)).isEmpty();
    }
    /** 隔离库内注入跨目标历史选证：即使触发租约有效，也不能替另一个 parent 放行。 */
    @ParameterizedTest
    @ValueSource(strings={"peerKey","keyEpoch","servicePort"})
    void validLatestTargetCannotAuthorizeOtherSelectedParent(String field)throws Exception{
        Fixture f=setup();Instant at=Instant.now().truncatedTo(ChronoUnit.MICROS);
        var earlier=observation(f,at,id(),0).putNull("targetRef").putNull("targetExpiresAt");accept(f,List.of(earlier),1,true);
        // 人为保留 episode 索引、仅改变不可变观察夹具，以覆盖通常已被上游身份隔离阻止的边界。
        if(field.equals("peerKey"))earlier.put(field,"e".repeat(64));else earlier.put(field,earlier.path(field).asInt()+1);
        jdbc.update("UPDATE guard_observation SET payload_json=?,content_sha256=? WHERE public_id=?",canonical(earlier),hash(earlier),earlier.path("observationId").asText());
        accept(f,List.of(observation(f,Instant.now().truncatedTo(ChronoUnit.MICROS),id(),0)),2,true);
        var asset=store.external("asset",f.asset,false);var decision=store.one("guard_decision",map("asset_id",asset.get("id")),false);
        assertThat(json(decision,"evidence_json").path("selectedObservations")).hasSize(2);
        assertThat(str(decision,"reason_code")).isEqualTo("TARGET_REF_STALE");
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
    /** 周期墓碑覆盖有/无签名撤销；换引用、keyEpoch、策略或签名身份不清零预算。 */
    @Test void revokedStableTargetSurvivesRotationAndZeroChargeRecoversOnlyWithHealth()throws Exception{
        for(boolean signed:List.of(false,true)){
            Fixture f=setup();accept(f,List.of(observation(f,Instant.now().truncatedTo(ChronoUnit.MICROS),id(),0)),1,true);
            var asset=store.external("asset",f.asset,false);long aid=number(asset,"id");
            var action=store.one("guard_action",map("asset_id",aid),false);
            if(signed)assertThat(machine("/executors/"+f.executor+"/command-claims",object("bootId",f.executorBoot,"capabilityHash",f.capabilityHash,"maxItems",10,"waitSeconds",0),f.executorCredential).path("commands")).hasSize(1);
            human("/actions/"+action.get("public_id")+"/revocations",object("reason","周期墓碑验证"),reviewer,signed?"2":"1");
            long tid=number(action,"budget_target_id");assertThat(budget.revoked(tid)).isTrue();
            var state=store.one("guard_target_budget",map("budget_target_id",tid),false);long charged=number(state,"charged_ms");
            ObjectNode rebinding=(ObjectNode)targetBody(f.executor,f.sensor,f.scope,f.boot,f.executorBoot,id(),f.token);rebinding.put("keyEpoch",2);
            assertThat(machine("/executors/"+f.executor+"/target-bindings",rebinding,f.executorCredential).path("budgetTargetId").asText()).isEqualTo(f.targetId);
            var policy=(ObjectNode)json(store.external("guard_decision_policy",f.policy,false),"definition_json");policy.put("policyVersion","rotated");
            assertThat(budget.check(aid,tid,policy,store.now(),store.now().plusSeconds(30))).isEqualTo("TARGET_REVOKED");
            var rotated=new GuardSignatures("rotated-key",ROOT.resolve("signing.der").toString(),ROOT.resolve("trust.json").toString());
            assertThat(rotated.sign(object("rotation",true)).path("keyId").asText()).isEqualTo("rotated-key");
            assertThat(number(store.one("guard_target_budget",map("budget_target_id",tid),false),"charged_ms")).isEqualTo(charged);
            accept(f,List.of(observation(f,Instant.now().truncatedTo(ChronoUnit.MICROS),id(),0)),2,true);
            assertThat(store.rows("guard_action",map("asset_id",aid),false,10)).hasSize(1);
            assertThat(store.rows("guard_command",map("action_id",action.get("id")),false,10)).hasSize(signed?1:0);
            var tx=new TransactionTemplate(manager);assertThat(tx.<Boolean>execute(s->budget.recover(aid,tid,store.now()))).isFalse();
            if(!signed){
                assertThat(charged).isZero();Instant end=store.now().minusSeconds(125),through=store.now();
                jdbc.update("UPDATE guard_target_budget SET last_block_end_at=?,last_evidence_at=? WHERE budget_target_id=?",db(end),db(end),tid);
                var health=org.mockito.Mockito.mock(GuardHealth.class);
                org.mockito.Mockito.when(health.proof(org.mockito.ArgumentMatchers.eq(aid),org.mockito.ArgumentMatchers.any(),org.mockito.ArgumentMatchers.any(),org.mockito.ArgumentMatchers.any())).thenReturn(object("through",through.toString(),"windows",List.of("authenticated-test-proof")));
                var recovered=new GuardBudget(store,null,health);
                assertThat(tx.<Boolean>execute(s->recovered.recover(aid,tid,through))).isTrue();assertThat(budget.revoked(tid)).isFalse();
                assertThat(tx.<Boolean>execute(s->recovered.recover(aid,tid,through))).isFalse();
                assertThat(budget.check(aid,tid,policy,through,through.plusSeconds(30))).isNull();
            }
        }
    }
}
