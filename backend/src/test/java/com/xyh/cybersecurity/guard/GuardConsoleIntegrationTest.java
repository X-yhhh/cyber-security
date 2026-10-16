package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import com.xyh.cybersecurity.database.IsolatedDatabaseSchemas;
import com.xyh.cybersecurity.iam.IamFixtures;
import com.xyh.cybersecurity.iam.ConsoleHttpTestSupport.Session;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.*;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.*;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;
import static com.xyh.cybersecurity.iam.ConsoleHttpTestSupport.*;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;

/** B4 的资源 HTTP 与并发验收；仅登记隔离库合成事实，不加载权重、不接入真实主机或执行防火墙。 */
@SpringBootTest(properties={"cyber.security.local-admin-bootstrap.enabled=false","cyber.ingest.consumer.enabled=false",
        "cyber.ingest.outbox-relay.enabled=false","cyber.drift.enabled=false"})
@AutoConfigureMockMvc(print=MockMvcPrint.NONE)
@EnabledIfEnvironmentVariable(named="DB_TEST_BASE_URL",matches=".+")
@org.junit.jupiter.api.extension.ExtendWith(IsolatedDatabaseSchemas.class)
class GuardConsoleIntegrationTest {
    static final String SCHEMA=IsolatedDatabaseSchemas.name(GuardConsoleIntegrationTest.class,"console_resource");
    static final String FIXTURE_LOGIN="isolated-console-resource-password";
    static String url(){return System.getenv("DB_TEST_BASE_URL").replaceAll("/+$","")+"/"+SCHEMA+"?connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true";}
    @BeforeAll static void migrate(){Flyway.configure().dataSource(url(),System.getenv("DB_TEST_USERNAME"),System.getenv("DB_TEST_PASSWORD")).load().migrate();}
    @DynamicPropertySource static void properties(DynamicPropertyRegistry r){
        r.add("spring.datasource.url",GuardConsoleIntegrationTest::url);r.add("spring.datasource.username",()->System.getenv("DB_TEST_USERNAME"));
        r.add("spring.datasource.password",()->System.getenv("DB_TEST_PASSWORD"));r.add("spring.flyway.enabled",()->false);
        r.add("cyber.security.login-throttle.hmac-key",()->"isolated-resource-hmac-key-at-least-32-bytes");
    }
    @Autowired MockMvc mvc;
    @Autowired JdbcTemplate jdbc;
    @Autowired PasswordEncoder encoder;
    @Autowired GuardStore store;
    @Autowired GuardMapper mapper;
    static Map<String,IamFixtures.Account> accounts;
    @BeforeEach void seed(){if(accounts==null)accounts=IamFixtures.seed(jdbc,encoder,FIXTURE_LOGIN);}
    Session role(String role) throws Exception{return login(mvc,accounts.get(role).username(),FIXTURE_LOGIN);}
    record Entity(String table,long key,String id){ }
    record Fixture(Entity asset,Entity sensor,Entity executor,Entity dataset,Entity model,Entity policy,
                   Entity bundle,Entity config,Entity authorization,long contract,long plan){ }
    Entity add(String table,Map<String,Object> values){var row=store.add(table,values);return new Entity(table,number(row,"id"),str(row,"public_id"));}
    String digest(){return sha(id().getBytes(StandardCharsets.UTF_8));}
    Map<String,Object> snapshot(Entity e){return jdbc.queryForMap("SELECT * FROM "+e.table()+" WHERE id=?",e.key());}
    Entity asset(String display){return add("asset",map("asset_key","b4-"+id(),"asset_type","host","environment","lab","criticality","medium",
            "owner","fixture","status","active","labels_json","{}","display_name",display));}
    Entity policy(Entity model,long plan,long creator){return add("guard_decision_policy",map("policy_key",id(),"version","1","model_id",model.key(),
            "plan_id",plan,"decision_contract_version",DECISION,"definition_json","{\"fixture\":\"immutable\"}","definition_sha256",digest(),"created_by",creator));}
    Fixture fixture(){
        Entity asset=asset("资源验收");
        Entity sensor=add("sensor_agent",map("agent_key",id(),"asset_id",asset.key(),"platform","macos","agent_version","fixture",
                "capabilities_json","[]","credential_ref","test-reference","status","active","registered_at",db(store.now())));
        add("api_client",map("client_key",id(),"client_type","sensor","sensor_id",sensor.key(),"secret_ref","test-reference",
                "scope_json","{}","status","active","credential_sha256",digest()));
        Entity client=add("api_client",map("client_key",id(),"client_type","executor","secret_ref","test-reference","scope_json","{}","status","active","credential_sha256",digest()));
        Entity executor=add("guard_executor",map("asset_id",asset.key(),"api_client_id",client.key(),"platform","macos","adapter_version","fixture","status","active"));
        Entity contract=add("guard_contract",map("contract_version",MODEL_CONTRACT,"profile_sha256",digest(),"schema_set_sha256",digest(),"extractor_sha256",digest(),"status","frozen"));
        Entity dataset=add("guard_dataset",map("dataset_key",id(),"version","1","manifest_ref","fixture.json","manifest_sha256",digest(),"payload_json","{\"fixture\":\"immutable\"}"));
        Entity model=add("guard_model",map("model_key",id(),"version","1","manifest_ref","fixture.json","manifest_sha256",digest(),"artifact_sha256",digest(),
                "contract_id",contract.key(),"manifest_json","{\"candidateOnly\":true}","validation_status","validated","created_by",accounts.get("model_operator").id()));
        Entity plan=add("guard_evaluation_plan",map("plan_key",id(),"version","1","plan_sha256",digest(),"payload_json","{}","created_by",accounts.get("model_operator").id()));
        Entity policy=policy(model,plan.key(),accounts.get("model_operator").id());
        Entity bundle=add("guard_release_bundle",map("bundle_key",id(),"version","1","model_id",model.key(),"policy_id",policy.key(),"contract_id",contract.key(),
                "plan_id",plan.key(),"environment","lab","subject_sha256",digest(),"subject_json","{\"fixture\":\"immutable\"}","requested_by",accounts.get("model_operator").id()));
        Entity auth=add("asset_authorization",map("asset_id",asset.key(),"authorization_ref","test-reference","scope_json","{}","valid_from",db(store.now().minusSeconds(10)),
                "valid_until",db(store.now().plus(Duration.ofDays(1))),"status","pending","requested_by",accounts.get("platform_admin").id()));
        Entity config=add("sensor_config",map("sensor_id",sensor.key(),"config_version",id(),"interface_scope_json","[]","filter_policy_json","{}","flow_window_seconds",30,
                "feature_contract_version",CONTRACT,"sampling_policy_json","{}","status","draft","requested_by",accounts.get("platform_admin").id(),"guard_definition_json","{}","content_sha256",digest()));
        return new Fixture(asset,sensor,executor,dataset,model,policy,bundle,config,auth,contract.key(),plan.key());
    }

    /** T1-R2：原子追加时间线和资产范围审计；同一幂等键重试不复制写入，越权不产生事实。 */
    @Test void caseNotesAreAuditedOnceAndReadOnlyRolesCannotAppend() throws Exception {
        Fixture f=fixture();
        Entity event=add("security_event",map("guard_asset_id",f.asset().key(),"event_key",id(),"title","合成研判",
                "category","dos_slow","severity","medium","status","open","risk_rule_version",DECISION,
                "first_seen_at",db(store.now()),"last_seen_at",db(store.now())));
        String path="/api/v2/events/"+event.id()+"/notes",key=id();JsonNode body=object("note","仅写入时间线的合成研判记录");
        Session analyst=role("security_analyst");
        JsonNode added=expect(send(mvc,post(path),analyst,body,key,null),201);
        assertThat(added.path("accepted").asBoolean()).isTrue();
        assertThat(expect(send(mvc,post(path),analyst,body,key,null),201)).isEqualTo(added);
        code(send(mvc,post(path),role("auditor"),body,id(),null),403,"SCOPE_DENIED");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM event_timeline WHERE event_id=? AND entry_type='guard.note'",Long.class,event.key())).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM audit_log a JOIN audit_resource_scope s ON s.audit_id=a.id WHERE a.resource_id=? AND a.action='guard.event.noted' AND s.scope_type='asset' AND s.scope_id=?",Long.class,event.id(),Long.toString(f.asset().key()))).isEqualTo(1);
    }

    @Test void metadataWritesAreRevisionCheckedAuditedAndNeverChangeFrozenFields() throws Exception {
        Fixture f=fixture();Session admin=role("platform_admin"),operator=role("model_operator");
        for(Entity e:List.of(f.asset(),f.sensor(),f.executor(),f.dataset(),f.model())){
            String collection=collection(e),path="/api/v2/"+collection+"/"+e.id();
            Session actor=Set.of("datasets","models").contains(collection)?operator:admin;
            var before=snapshot(e);String key=id();JsonNode body=object("displayName","资源显示名称","notes","资料说明");
            JsonNode changed=expect(send(mvc,patch(path),actor,body,key,"1"),200);
            assertThat(changed.path("revision").asLong()).isEqualTo(2);
            assertThat(expect(send(mvc,patch(path),actor,body,key,"1"),200)).isEqualTo(changed);
            code(send(mvc,patch(path),actor,object("notes","不同载荷"),key,"1"),409,"IDEMPOTENCY_CONFLICT");
            code(send(mvc,patch(path),actor,body,id(),"1"),409,"REVISION_CONFLICT");
            code(send(mvc,patch(path),actor,body,id(),null),409,"REVISION_CONFLICT");
            code(send(mvc,patch(path),actor,object("manifestSha256",digest()),id(),"2"),400,"UNKNOWN_FIELD");
            var after=snapshot(e);after.keySet().removeAll(Set.of("display_name","notes","revision","updated_at"));
            before.keySet().removeAll(Set.of("display_name","notes","revision","updated_at"));assertThat(after).isEqualTo(before);
            assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM audit_log WHERE resource_id=? AND action LIKE 'guard.%.updated'",Long.class,e.id())).isEqualTo(1);
            JsonNode clear=expect(send(mvc,patch(path),actor,object("notes",null),id(),"2"),200);
            assertThat(clear.path("notes").isNull()).isTrue();
            JsonNode read=expect(send(mvc,get(path),actor,null,null,null),200);
            assertThat(read.path("displayName").asText()).isEqualTo("资源显示名称");assertThat(read.path("revision").asLong()).isEqualTo(3);
        }
    }

    @Test void assetRetirementIsTerminalAndSuspendsActiveBindingsWithoutRemovingFacts() throws Exception {
        Fixture f=fixture();Session admin=role("platform_admin");
        Entity binding=add("guard_asset_binding",map("asset_id",f.asset().key(),"bundle_id",f.bundle().key(),"authorization_id",f.authorization().key(),
                "authorization_revision",1,"status","active","activated_by",accounts.get("security_reviewer").id()));
        long bindings=jdbc.queryForObject("SELECT COUNT(*) FROM guard_asset_binding",Long.class);
        expect(send(mvc,patch("/api/v2/assets/"+f.asset().id()),admin,object("status","retired"),id(),"1"),200);
        assertThat(snapshot(binding).get("status")).isEqualTo("suspended");
        code(send(mvc,patch("/api/v2/assets/"+f.asset().id()),admin,object("status","active"),id(),"2"),409,"STATE_CONFLICT");
        assertThat(snapshot(f.asset()).get("status")).isEqualTo("retired");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM guard_asset_binding",Long.class)).isEqualTo(bindings);
    }

    @ParameterizedTest @ValueSource(booleans={false,true})
    void disabledMachineCredentialsStayInvalidUntilEnableAndFreshRotation(boolean executor) throws Exception {
        Fixture f=fixture();Session admin=role("platform_admin");String collection=executor?"executors":"sensors";
        JsonNode create=object("assetId",f.asset().id(),"platform","macos",executor?"capabilityProbeRef":"captureScopeId",executor?"test-reference":id());
        JsonNode registered=expect(send(mvc,post("/api/v2/"+collection),admin,create,id(),null),201);
        String machine=registered.path("id").asText(),old=registered.path("credential").asText(),client=registered.path("clientId").asText();
        long clientKey=jdbc.queryForObject("SELECT id FROM api_client WHERE public_id=?",Long.class,client);
        String permission=executor?"machine.command.claim":"machine.sensor.read";
        assertThat(mapper.machinePermission(clientKey,permission)).isTrue();
        String statusPath="/api/v2/"+collection+"/"+machine+"/status-changes",changeKey=id();
        JsonNode stop=object("status","disabled","reason","隔离停用验收");
        JsonNode disabled=expect(send(mvc,post(statusPath),admin,stop,changeKey,"1"),200);
        assertThat(disabled.path("status").asText()).isEqualTo(executor?"suspended":"offline");
        assertThat(expect(send(mvc,post(statusPath),admin,stop,changeKey,"1"),200)).isEqualTo(disabled);
        assertThat(jdbc.queryForObject("SELECT credential_sha256 FROM api_client WHERE id=?",String.class,clientKey)).isNull();
        assertThat(mapper.machinePermission(clientKey,permission)).isFalse();
        expect(mvc.perform(machineRequest(executor,machine,old)).andReturn(),401);
        JsonNode enabled=expect(send(mvc,post(statusPath),admin,object("status","active","reason","只启用登记状态"),id(),"2"),200);
        assertThat(enabled.path("credentialRotationRequired").asBoolean()).isTrue();
        assertThat(mapper.machinePermission(clientKey,permission)).isFalse();
        expect(mvc.perform(machineRequest(executor,machine,old)).andReturn(),401);
        JsonNode fresh=expect(send(mvc,post("/api/v2/"+collection+"/"+machine+"/credential-rotations"),admin,object("reason","显式换凭据"),id(),null),200);
        assertThat(mapper.machinePermission(clientKey,permission)).isTrue();
        expect(mvc.perform(machineRequest(executor,machine,old)).andReturn(),401);
        // 新凭据进入契约层：没有配置的传感器返回 422，空领取请求返回 400；均证明不会继续使用旧凭据。
        var verified=mvc.perform(machineRequest(executor,machine,fresh.path("credential").asText())).andReturn();
        code(verified,executor?400:422,executor?"MISSING_FIELD":"CONFIG_INACTIVE");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM audit_log WHERE resource_id=? AND action LIKE 'guard.%.status.changed'",Long.class,machine)).isEqualTo(2);
    }
    MockHttpServletRequestBuilder machineRequest(boolean executor,String id,String credential){
        var request=executor?post("/api/v2/machine/executors/"+id+"/command-claims").contentType("application/json").content("{}")
                :get("/api/v2/machine/sensors/"+id+"/config");
        return request.header("Authorization","Bearer "+credential).header("Idempotency-Key",id());
    }

    @Test void permanentlyRevokedMachineCannotBeReenabled() throws Exception {
        Fixture f=fixture();Session admin=role("platform_admin");
        String client=jdbc.queryForObject("SELECT public_id FROM api_client WHERE sensor_id=?",String.class,f.sensor().key());
        expect(send(mvc,post("/api/v2/machine-clients/"+client+"/revocations"),admin,object("reason","永久吊销"),id(),null),202);
        code(send(mvc,post("/api/v2/sensors/"+f.sensor().id()+"/status-changes"),admin,object("status","active","reason","拒绝恢复"),id(),"2"),409,"STATE_CONFLICT");
    }

    @ParameterizedTest @ValueSource(booleans={false,true})
    void resourceRetirementKeepsManifestAndCannotBeReactivatedByValidation(boolean model) throws Exception {
        Fixture f=fixture();Entity e=model?f.model():f.dataset();var before=snapshot(e);Session operator=role("model_operator");
        String path="/api/v2/"+collection(e)+"/"+e.id()+"/retirements",key=id();JsonNode body=object("reason","退出使用");
        JsonNode result=expect(send(mvc,post(path),operator,body,key,"1"),200);
        assertThat(expect(send(mvc,post(path),operator,body,key,"1"),200)).isEqualTo(result);
        assertThat(snapshot(e).get(model?"validation_status":"status")).isEqualTo("retired");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM audit_log WHERE action=? AND resource_id=?",Long.class,
                model?"guard.model.retired":"guard.dataset.retired",e.id())).isEqualTo(1);
        var after=snapshot(e);for(String column:List.of("status","validation_status","revision","updated_at")){before.remove(column);after.remove(column);}
        assertThat(after).isEqualTo(before);
        code(send(mvc,post(path),operator,body,id(),"2"),409,"STATE_CONFLICT");
        if(model)code(send(mvc,post("/api/v2/models/"+e.id()+"/validations"),operator,object("validationProfileId","host-guard-onnx-v1"),id(),null),409,"STATE_CONFLICT");
    }

    @ParameterizedTest @ValueSource(booleans={false,true})
    void activeBundleOrBindingPreventsModelRetirement(boolean binding) throws Exception {
        Fixture f=fixture();Session operator=role("model_operator");
        if(binding)add("guard_asset_binding",map("asset_id",f.asset().key(),"bundle_id",f.bundle().key(),"authorization_id",f.authorization().key(),
                "authorization_revision",1,"status","active","activated_by",accounts.get("security_reviewer").id()));
        else jdbc.update("UPDATE guard_release_bundle SET status='active' WHERE id=?",f.bundle().key());
        var before=snapshot(f.model());long bundles=jdbc.queryForObject("SELECT COUNT(*) FROM guard_release_bundle",Long.class);
        code(send(mvc,post("/api/v2/models/"+f.model().id()+"/retirements"),operator,object("reason","被使用的模型"),id(),"1"),409,"RESOURCE_IN_USE");
        assertThat(snapshot(f.model())).isEqualTo(before);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM guard_release_bundle",Long.class)).isEqualTo(bundles);
    }

    @ParameterizedTest @ValueSource(booleans={false,true})
    void activationAndRetirementSerializeInsteadOfActivatingRetiredResource(boolean bundleRetirement) throws Exception {
        Fixture f=fixture();Session operator=role("model_operator"),reviewer=role("security_reviewer");
        jdbc.update("UPDATE guard_decision_policy SET status='reviewed' WHERE id=?",f.policy().key());
        jdbc.update("UPDATE guard_release_bundle SET status='approved' WHERE id=?",f.bundle().key());
        jdbc.update("UPDATE asset_authorization SET status='active' WHERE id=?",f.authorization().key());
        var start=new CountDownLatch(1);
        try(var pool=Executors.newFixedThreadPool(2)){
            var retire=pool.submit(()->{start.await();return send(mvc,post("/api/v2/"+(bundleRetirement?"release-bundles/"+f.bundle().id():"models/"+f.model().id())+"/retirements"),
                    bundleRetirement?reviewer:operator,object("reason","并发退役"),id(),"1");});
            var activate=pool.submit(()->{start.await();return send(mvc,post("/api/v2/release-bundles/"+f.bundle().id()+"/activations"),reviewer,
                    object("assetIds",List.of(f.asset().id()),"authorizationIds",List.of(f.authorization().id())),id(),"1");});
            start.countDown();var retired=retire.get(30,TimeUnit.SECONDS);var activated=activate.get(30,TimeUnit.SECONDS);
            assertThat(List.of(retired.getResponse().getStatus(),activated.getResponse().getStatus())).isIn(List.of(200,409),List.of(409,202));
        }
        assertThat("retired".equals(snapshot(f.model()).get("validation_status"))&&"active".equals(snapshot(f.bundle()).get("status"))).isFalse();
        if(bundleRetirement&&"retired".equals(snapshot(f.bundle()).get("status")))
            assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM guard_asset_binding WHERE bundle_id=? AND status='active'",Long.class,f.bundle().key())).isZero();
    }

    @Test void modelRetirementAndBundleSuspensionUseTheSameLockOrder() throws Exception {
        Fixture f=fixture();Session operator=role("model_operator"),reviewer=role("security_reviewer");
        jdbc.update("UPDATE guard_release_bundle SET status='active' WHERE id=?",f.bundle().key());
        Entity binding=add("guard_asset_binding",map("asset_id",f.asset().key(),"bundle_id",f.bundle().key(),"authorization_id",f.authorization().key(),
                "authorization_revision",1,"status","active","activated_by",accounts.get("security_reviewer").id()));
        var start=new CountDownLatch(1);
        try(var pool=Executors.newFixedThreadPool(2)){
            var retire=pool.submit(()->{start.await();return send(mvc,post("/api/v2/models/"+f.model().id()+"/retirements"),operator,object("reason","并发退役"),id(),"1");});
            var suspend=pool.submit(()->{start.await();return send(mvc,post("/api/v2/release-bundles/"+f.bundle().id()+"/suspensions"),reviewer,
                    object("reason","先退出使用","revokeExisting",false),id(),"1");});
            start.countDown();var retired=retire.get(30,TimeUnit.SECONDS);expect(suspend.get(30,TimeUnit.SECONDS),202);
            assertThat(retired.getResponse().getStatus()).isIn(200,409);
        }
        assertThat(snapshot(f.bundle()).get("status")).isEqualTo("suspended");assertThat(snapshot(binding).get("status")).isEqualTo("suspended");
    }

    @ParameterizedTest @ValueSource(strings={"disabled","retired"})
    void inactiveAssetCannotReceiveNewReleaseBinding(String status) throws Exception {
        Fixture f=fixture();Session admin=role("platform_admin"),reviewer=role("security_reviewer");
        jdbc.update("UPDATE guard_decision_policy SET status='reviewed' WHERE id=?",f.policy().key());
        jdbc.update("UPDATE guard_release_bundle SET status='approved' WHERE id=?",f.bundle().key());
        jdbc.update("UPDATE asset_authorization SET status='active' WHERE id=?",f.authorization().key());
        expect(send(mvc,patch("/api/v2/assets/"+f.asset().id()),admin,object("status",status),id(),"1"),200);
        code(send(mvc,post("/api/v2/release-bundles/"+f.bundle().id()+"/activations"),reviewer,
                object("assetIds",List.of(f.asset().id()),"authorizationIds",List.of(f.authorization().id())),id(),"1"),422,"AUTHORIZATION_INACTIVE");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM guard_asset_binding WHERE bundle_id=?",Long.class,f.bundle().key())).isZero();
        assertThat(snapshot(f.asset()).get("status")).isEqualTo(status);
    }

    @Test void draftDeletionRejectsReferencesAndOtherCreatorsAndIsIdempotentAfterDeletion() throws Exception {
        Fixture f=fixture();Session operator=role("model_operator"),admin=role("platform_admin"),combined=role("combined");
        long bundles=jdbc.queryForObject("SELECT COUNT(*) FROM guard_release_bundle",Long.class);
        code(send(mvc,delete("/api/v2/decision-policies/"+f.policy().id()),operator,null,id(),"1"),409,"RESOURCE_IN_USE");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM guard_release_bundle",Long.class)).isEqualTo(bundles);
        Entity orphan=policy(f.model(),f.plan(),accounts.get("model_operator").id());
        code(send(mvc,delete("/api/v2/decision-policies/"+orphan.id()),combined,null,id(),"1"),403,"SCOPE_DENIED");
        String key=id();JsonNode result=expect(send(mvc,delete("/api/v2/decision-policies/"+orphan.id()),operator,null,key,"1"),200);
        assertThat(expect(send(mvc,delete("/api/v2/decision-policies/"+orphan.id()),operator,null,key,"1"),200)).isEqualTo(result);
        add("guard_capture_scope",map("asset_id",f.asset().key(),"sensor_id",f.sensor().key(),"scope_key","fixture0","address_family","ipv4","config_id",f.config().key(),"status","pending"));
        long scopes=jdbc.queryForObject("SELECT COUNT(*) FROM guard_capture_scope",Long.class);
        code(send(mvc,delete("/api/v2/sensor-configs/"+f.config().id()),admin,null,id(),"1"),409,"RESOURCE_IN_USE");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM guard_capture_scope",Long.class)).isEqualTo(scopes);
        Entity config=add("sensor_config",map("sensor_id",f.sensor().key(),"config_version",id(),"interface_scope_json","[]","filter_policy_json","{}","flow_window_seconds",30,
                "feature_contract_version",CONTRACT,"sampling_policy_json","{}","status","draft","requested_by",accounts.get("platform_admin").id()));
        code(send(mvc,delete("/api/v2/sensor-configs/"+config.id()),combined,null,id(),"1"),403,"SCOPE_DENIED");
        key=id();result=expect(send(mvc,delete("/api/v2/sensor-configs/"+config.id()),admin,null,key,"1"),200);
        assertThat(expect(send(mvc,delete("/api/v2/sensor-configs/"+config.id()),admin,null,key,"1"),200)).isEqualTo(result);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM audit_log WHERE action IN ('guard.policy.deleted','guard.config.deleted') AND resource_id IN (?,?)",Long.class,orphan.id(),config.id())).isEqualTo(2);
    }

    @ParameterizedTest @ValueSource(strings={"candidate","evaluated","approved","suspended"})
    void bundleRetirementUsesOriginalStatePermissionEvenOnReplay(String status) throws Exception {
        Fixture f=fixture();jdbc.update("UPDATE guard_release_bundle SET status=? WHERE id=?",status,f.bundle().key());
        boolean request=Set.of("candidate","evaluated").contains(status);Session actor=role(request?"model_operator":"security_reviewer");
        Session wrong=role(request?"security_reviewer":"model_operator");String path="/api/v2/release-bundles/"+f.bundle().id()+"/retirements";
        code(send(mvc,post(path),wrong,object("reason","错误职责"),id(),"1"),403,"SCOPE_DENIED");
        String key=id();JsonNode body=object("reason","组合退役"),result=expect(send(mvc,post(path),actor,body,key,"1"),200);
        assertThat(expect(send(mvc,post(path),actor,body,key,"1"),200)).isEqualTo(result);
        assertThat(snapshot(f.bundle()).get("status")).isEqualTo("retired");assertThat(result.path("previousStatus").asText()).isEqualTo(status);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM audit_log WHERE action='guard.bundle.retired' AND resource_id=?",Long.class,f.bundle().id())).isEqualTo(1);
    }

    @Test void activeBundleMustBeSuspendedAndOnlyRequesterCanWithdrawPendingAuthorization() throws Exception {
        Fixture f=fixture();Session admin=role("platform_admin"),reviewer=role("security_reviewer"),combined=role("combined");
        jdbc.update("UPDATE guard_release_bundle SET status='active' WHERE id=?",f.bundle().key());
        code(send(mvc,post("/api/v2/release-bundles/"+f.bundle().id()+"/retirements"),reviewer,object("reason","必须先暂停"),id(),"1"),409,"STATE_CONFLICT");
        String path="/api/v2/authorizations/"+f.authorization().id()+"/withdrawals";
        code(send(mvc,post(path),combined,object("reason","不是申请人"),id(),"1"),403,"SCOPE_DENIED");
        String key=id();JsonNode body=object("reason","撤回申请"),result=expect(send(mvc,post(path),admin,body,key,"1"),200);
        assertThat(expect(send(mvc,post(path),admin,body,key,"1"),200)).isEqualTo(result);
        assertThat(snapshot(f.authorization()).get("status")).isEqualTo("revoked");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM audit_log WHERE action='guard.authorization.withdrawn' AND resource_id=?",Long.class,f.authorization().id())).isEqualTo(1);
        jdbc.update("UPDATE asset_authorization SET status='active' WHERE id=?",f.authorization().key());
        code(send(mvc,post(path),admin,body,id(),"2"),409,"STATE_CONFLICT");
    }

    @Test void allNewResourceEndpointsRequireSessionPermissionAndRevision() throws Exception {
        Fixture f=fixture();Session auditor=role("auditor"),admin=role("platform_admin"),operator=role("model_operator");
        record Request(String method,String path,JsonNode body,Session actor){ }
        List<Request> requests=new ArrayList<>();
        for(Entity e:List.of(f.asset(),f.sensor(),f.executor(),f.dataset(),f.model())){
            String collection=collection(e);Session actor=Set.of("datasets","models").contains(collection)?operator:admin;
            requests.add(new Request("PATCH","/api/v2/"+collection+"/"+e.id(),object("displayName","权限负例"),actor));
        }
        for(Entity e:List.of(f.sensor(),f.executor()))requests.add(new Request("POST","/api/v2/"+collection(e)+"/"+e.id()+"/status-changes",object("status","disabled","reason","负例"),admin));
        for(Entity e:List.of(f.dataset(),f.model(),f.bundle()))requests.add(new Request("POST","/api/v2/"+collection(e)+"/"+e.id()+"/retirements",object("reason","负例"),operator));
        requests.add(new Request("POST","/api/v2/authorizations/"+f.authorization().id()+"/withdrawals",object("reason","负例"),admin));
        requests.add(new Request("DELETE","/api/v2/sensor-configs/"+f.config().id(),null,admin));
        requests.add(new Request("DELETE","/api/v2/decision-policies/"+f.policy().id(),null,operator));
        for(Request r:requests){
            expect(send(mvc,request(r.method(),r.path()).with(csrf()),null,r.body(),id(),"1"),401);
            code(send(mvc,request(r.method(),r.path()),auditor,r.body(),id(),"1"),403,"SCOPE_DENIED");
            code(send(mvc,request(r.method(),r.path()),r.actor(),r.body(),id(),null),409,"REVISION_CONFLICT");
            code(send(mvc,request(r.method(),r.path()),r.actor(),r.body(),id(),"0"),409,"REVISION_CONFLICT");
            code(send(mvc,request(r.method(),r.path()),r.actor(),r.body(),"invalid-key","1"),400,"INVALID_UUID");
            String missing=r.path().replaceFirst("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",id());
            code(send(mvc,request(r.method(),missing),r.actor(),r.body(),id(),"1"),404,"RESOURCE_NOT_FOUND");
            if(!r.method().equals("DELETE"))code(send(mvc,request(r.method(),r.path()),r.actor(),object("unexpected",true),id(),"1"),400,"UNKNOWN_FIELD");
        }
    }

    @Test void resourceScopeIsCheckedBeforeWritesAndBeforeLimitAndOnDeletionReplay() throws Exception {
        Fixture allowed=fixture(),hidden=fixture();var account=IamFixtures.account(jdbc,encoder,FIXTURE_LOGIN,List.of());
        jdbc.update("INSERT INTO sys_user_role(user_id,role_id,scope_type,scope_id) SELECT ?,id,'asset',? FROM sys_role WHERE role_key='platform_admin'",account.id(),Long.toString(allowed.asset().key()));
        Session scoped=login(mvc,account.username(),FIXTURE_LOGIN);
        code(send(mvc,patch("/api/v2/sensors/"+hidden.sensor().id()),scoped,object("displayName","越界"),id(),"1"),404,"RESOURCE_NOT_FOUND");
        code(send(mvc,post("/api/v2/executors/"+hidden.executor().id()+"/status-changes"),scoped,object("status","disabled","reason","越界"),id(),"1"),404,"RESOURCE_NOT_FOUND");
        code(send(mvc,delete("/api/v2/sensor-configs/"+hidden.config().id()),scoped,null,id(),"1"),404,"RESOURCE_NOT_FOUND");
        code(send(mvc,post("/api/v2/authorizations/"+hidden.authorization().id()+"/withdrawals"),scoped,object("reason","越界"),id(),"1"),404,"RESOURCE_NOT_FOUND");
        JsonNode rows=expect(send(mvc,get("/api/v2/assets").param("q","资源验收").param("limit","1"),scoped,null,null,null),200);
        assertThat(rows.path("items").get(0).path("id").asText()).isEqualTo(allowed.asset().id());
        Entity own=add("sensor_config",map("sensor_id",allowed.sensor().key(),"config_version",id(),"interface_scope_json","[]","filter_policy_json","{}","flow_window_seconds",30,
                "feature_contract_version",CONTRACT,"sampling_policy_json","{}","status","draft","requested_by",account.id()));
        String key=id(),path="/api/v2/sensor-configs/"+own.id();expect(send(mvc,delete(path),scoped,null,key,"1"),200);
        // 删除后撤掉原范围、保留另一个资产上的同功能权限，缓存不能泄漏原资产的响应。
        jdbc.update("DELETE FROM sys_user_role WHERE user_id=?",account.id());
        jdbc.update("INSERT INTO sys_user_role(user_id,role_id,scope_type,scope_id) SELECT ?,id,'asset',? FROM sys_role WHERE role_key='platform_admin'",account.id(),Long.toString(hidden.asset().key()));
        code(send(mvc,delete(path),scoped,null,key,"1"),404,"RESOURCE_NOT_FOUND");
    }

    @Test void listSearchTimeOrderingAndEncryptedCursorsMatchTheWholeFilter() throws Exception {
        Session admin=role("platform_admin");String prefix="列表%_"+id();List<Entity> assets=new ArrayList<>();
        for(int i=0;i<3;i++){
            Entity asset=asset(prefix+i);assets.add(asset);
            jdbc.update("UPDATE asset SET created_at=?,updated_at=? WHERE id=?","2026-01-0"+(i+1)+" 00:00:00","2026-02-0"+(3-i)+" 00:00:00",asset.key());
        }
        asset("列表NOISE"+id());
        JsonNode first=expect(send(mvc,get("/api/v2/assets").param("q",prefix).param("from","2026-01-01T00:00:00Z")
                .param("until","2026-01-04T00:00:00Z").param("sort","updatedAt").param("limit","1"),admin,null,null,null),200);
        assertThat(first.path("items").get(0).path("id").asText()).isEqualTo(assets.getFirst().id());
        assertThat(first.path("items").get(0).has("querySortTime")).isFalse();
        String cursor=first.path("nextCursor").asText();
        JsonNode next=expect(send(mvc,get("/api/v2/assets").param("q",prefix).param("from","2026-01-01T00:00:00Z")
                .param("until","2026-01-04T00:00:00Z").param("sort","updatedAt").param("cursor",cursor).param("limit","2"),admin,null,null,null),200);
        assertThat(next.path("items").size()).isEqualTo(2);
        assertThat(next.path("items").get(0).path("id").asText()).isEqualTo(assets.get(1).id());
        for(String value:List.of("createdAt","updatedAt"))code(send(mvc,get("/api/v2/assets").param("q",prefix+"changed").param("sort",value).param("cursor",cursor),admin,null,null,null),400,"INVALID_CURSOR");
        code(send(mvc,get("/api/v2/assets").param("from","2026-01-01T00:00:00+08:00"),admin,null,null,null),400,"INVALID_QUERY");
        code(send(mvc,get("/api/v2/assets").param("sort","id DESC; DROP TABLE asset"),admin,null,null,null),400,"INVALID_QUERY");
        code(send(mvc,get("/api/v2/assets").param("active","true"),admin,null,null,null),400,"INVALID_QUERY");
        code(send(mvc,get("/api/v2/assets").param("q",prefix).param("q","duplicate"),admin,null,null,null),400,"INVALID_QUERY");
        Fixture f=fixture();jdbc.update("UPDATE asset SET display_name=? WHERE id=?",prefix+"关联",f.asset().key());
        for(String path:List.of("/api/v2/authorizations","/api/v2/sensor-configs","/api/v2/machine-clients")){
            JsonNode page=expect(send(mvc,get(path).param("q",prefix+"关联").param("sort","updatedAt"),admin,null,null,null),200);
            assertThat(page.path("items").size()).isPositive();
        }
    }

    @Test void activeActionsMeanActiveIntentAndUnexpiredTime() throws Exception {
        Fixture f=fixture();Session analyst=role("security_analyst");
        Entity target=add("guard_budget_target",map("asset_id",f.asset().key(),"environment","lab","stable_target_token",digest(),
                "resolver_executor_id",f.executor().key(),"scope_digest",digest()));
        Entity episode=add("guard_episode",map("asset_id",f.asset().key(),"sensor_id",f.sensor().key(),"boot_id",id(),"peer_key",digest(),"key_epoch",1,
                "direction","inbound","transport","tcp","service_port",80,"family","port_scan","bundle_id",f.bundle().key(),"bucket_start",db(store.now())));
        Entity decision=add("guard_decision",map("episode_id",episode.key(),"asset_id",f.asset().key(),"bundle_id",f.bundle().key(),"decision_revision",1,
                "decision_contract_version",DECISION,"decision","alert","evidence_sha256",digest(),"evidence_json","{}","decided_at",db(store.now())));
        List<Entity> actions=new ArrayList<>();
        for(int i=0;i<3;i++)actions.add(add("guard_action",map("decision_id",decision.key(),"asset_id",f.asset().key(),"executor_id",f.executor().key(),
                "budget_target_id",target.key(),"budget_revision",1,"bundle_id",f.bundle().key(),"authorization_id",f.authorization().key(),"authorization_revision",1,
                "mode","manual","desired_state",i==1?"revoked":"active","observed_state","applied","idempotency_key",id(),"target_snapshot","{}",
                "block_until",db(store.now().plusSeconds(i==2?-60:60)))));
        JsonNode active=expect(send(mvc,get("/api/v2/actions").param("assetId",f.asset().id()).param("active","true"),analyst,null,null,null),200);
        assertThat(active.path("items").size()).isEqualTo(1);assertThat(active.path("items").get(0).path("id").asText()).isEqualTo(actions.getFirst().id());
        code(send(mvc,get("/api/v2/actions").param("active","false"),analyst,null,null,null),400,"INVALID_QUERY");
        code(send(mvc,get("/api/v2/actions").param("q","unsupported"),analyst,null,null,null),400,"INVALID_QUERY");
    }

    /** W4 回归：单行证据远超服务器 sort_buffer_size（256KB）时，全局列表与游标翻页仍按时间和主键稳定返回。 */
    @Test void globalListsPageRowsLargerThanTheSortBuffer() throws Exception {
        Fixture f=fixture();Session analyst=role("security_analyst");List<Entity> decisions=new ArrayList<>();
        String large="{\"source\":\"model\",\"padding\":\""+"x".repeat(600_000)+"\"}";
        for(int i=0;i<3;i++){
            Entity episode=add("guard_episode",map("asset_id",f.asset().key(),"sensor_id",f.sensor().key(),"boot_id",id(),"peer_key",digest(),"key_epoch",1,
                    "direction","inbound","transport","tcp","service_port",22,"family","brute_force","bundle_id",f.bundle().key(),"bucket_start",db(store.now())));
            decisions.add(add("guard_decision",map("episode_id",episode.key(),"asset_id",f.asset().key(),"bundle_id",f.bundle().key(),"decision_revision",1,
                    "decision_contract_version",DECISION,"decision","alert","evidence_sha256",digest(),"evidence_json",i==2?"{}":large,
                    "decided_at",db(store.now()),"created_at",db(java.time.Instant.parse("2025-03-01T0"+(i+1)+":00:00Z")))));
        }
        expect(send(mvc,get("/api/v2/decisions").param("limit","1"),analyst,null,null,null),200);
        List<String> seen=new ArrayList<>();String cursor=null;
        for(int page=0;page<3;page++){
            var request=get("/api/v2/decisions").param("from","2025-03-01T00:00:00Z").param("until","2025-03-02T00:00:00Z").param("limit","1");
            JsonNode body=expect(send(mvc,cursor==null?request:request.param("cursor",cursor),analyst,null,null,null),200);
            assertThat(body.path("items").size()).isEqualTo(1);seen.add(body.path("items").get(0).path("id").asText());
            cursor=body.path("nextCursor").isTextual()?body.path("nextCursor").asText():null;assertThat(cursor==null).isEqualTo(page==2);
        }
        assertThat(seen).containsExactly(decisions.get(2).id(),decisions.get(1).id(),decisions.get(0).id());
    }

    /** F1R 四段通过真实 HTTP 检验筛选先于分页、UTC 半开区间与固定读取上界。 */
    @ParameterizedTest
    @ValueSource(strings={"observation-batches","observations","detections","decisions"})
    void detectionRecordsFilterTimeAndScopeBeforePaging(String collection) throws Exception {
        Fixture visible=fixture(),hidden=fixture();
        var account=IamFixtures.account(jdbc,encoder,FIXTURE_LOGIN,List.of());
        grantAssetRole(account.id(),"security_analyst",visible.asset().key());
        // 另一资产只有资源管理权限，不能借用该范围扩大 detection.read。
        grantAssetRole(account.id(),"platform_admin",hidden.asset().key());
        Session reader=login(mvc,account.username(),FIXTURE_LOGIN),auditor=role("auditor"),admin=role("platform_admin");
        detectionChain(visible,"2026-01-01T00:00:00Z");
        var lower=detectionChain(visible,"2026-01-02T00:00:00Z").get(collection);
        var equal=detectionChain(visible,"2026-01-02T00:00:00Z").get(collection);
        detectionChain(visible,"2026-01-03T00:00:00Z");
        var outside=detectionChain(hidden,"2026-01-02T12:00:00Z").get(collection);
        String path="/api/v2/"+collection;
        JsonNode first=expect(send(mvc,recordRange(path).param("limit","1"),reader,null,null,null),200);
        assertThat(first.path("items").findValuesAsText("id")).containsExactly(equal.id());
        assertThat(first.at("/items/0/createdAt").asText()).isEqualTo("2026-01-02T00:00:00Z");
        String cursor=first.path("nextCursor").asText();assertThat(cursor).isNotBlank();
        var appended=detectionChain(visible,"2026-01-02T18:00:00Z").get(collection);
        JsonNode second=expect(send(mvc,recordRange(path).param("cursor",cursor).param("limit","10"),reader,null,null,null),200);
        assertThat(second.path("items").findValuesAsText("id")).containsExactly(lower.id()).doesNotContain(appended.id(),outside.id());
        assertThat(second.path("nextCursor").isNull()).isTrue();
        assertThat(expect(send(mvc,recordRange(path).param("cursor",cursor).param("limit","10"),reader,null,null,null),200)).isEqualTo(second);
        code(send(mvc,recordRange(path).param("cursor",cursor),auditor,null,null,null),400,"INVALID_CURSOR");
        code(send(mvc,get(path).param("from","2026-01-01T00:00:00Z").param("until","2026-01-03T00:00:00Z")
                .param("sort","updatedAt").param("cursor",cursor),reader,null,null,null),400,"INVALID_CURSOR");
        code(send(mvc,recordRange(path).param("q","unsupported"),reader,null,null,null),400,"INVALID_QUERY");
        code(send(mvc,get(path).param("from","2026-01-02T00:00:00+08:00"),reader,null,null,null),400,"INVALID_QUERY");
        code(send(mvc,get(path).param("assetId",hidden.asset().id()),reader,null,null,null),404,"RESOURCE_NOT_FOUND");
        code(send(mvc,get(path+"/"+outside.id()),reader,null,null,null),404,"RESOURCE_NOT_FOUND");
        code(send(mvc,get(path),admin,null,null,null),403,"SCOPE_DENIED");
        code(send(mvc,get(path),null,null,null,null),401,"UNAUTHENTICATED");
    }

    /** 反馈本人识别必须来自真实查询；刷新、复核和幂等重试均不能绕过职责分离。 */
    @Test void feedbackQueriesIdentifyAuthorAndKeepIndependentReviewEnforced() throws Exception {
        Fixture f=fixture();var observation=detectionChain(f,"2026-01-02T00:00:00Z").get("observations");
        Session analyst=role("security_analyst"),reviewer=role("evidence_reviewer");
        JsonNode labelled=expect(send(mvc,post("/api/v2/feedback"),analyst,
                object("observationId",observation.id(),"label","benign","evidenceRef","fixture://reviewed-sample"),id(),null),201);
        String feedbackId=labelled.path("id").asText();
        JsonNode author=expect(send(mvc,get("/api/v2/auth/me"),analyst,null,null,null),200);
        JsonNode detail=expect(send(mvc,get("/api/v2/feedback/"+feedbackId),reviewer,null,null,null),200);
        assertThat(detail.path("createdBy").asLong(-1)).isEqualTo(author.path("id").asLong());
        JsonNode page=expect(send(mvc,get("/api/v2/feedback").param("assetId",f.asset().id()).param("status","pending"),analyst,null,null,null),200);
        assertThat(page.at("/items/0/createdBy").asLong(-1)).isEqualTo(author.path("id").asLong());
        assertThat(detail.has("reviewedBy")).isFalse();
        code(send(mvc,post("/api/v2/feedback/"+feedbackId+"/reviews"),reviewer,
                object("decision","approve","reason","独立核验"),id(),"9"),409,"REVISION_CONFLICT");
        String key=id();JsonNode decision=object("decision","approve","reason","独立核验");
        JsonNode reviewed=expect(send(mvc,post("/api/v2/feedback/"+feedbackId+"/reviews"),reviewer,decision,key,"1"),200);
        assertThat(reviewed.path("status").asText()).isEqualTo("reviewed");
        assertThat(reviewed.path("trainingEligible").asBoolean()).isFalse();
        assertThat(expect(send(mvc,post("/api/v2/feedback/"+feedbackId+"/reviews"),reviewer,decision,key,"1"),200)).isEqualTo(reviewed);
        assertThat(expect(send(mvc,get("/api/v2/feedback/"+feedbackId),analyst,null,null,null),200).path("createdBy")).isEqualTo(author.path("id"));
        // 历史标注人转为复核角色后，页面仍可识别本人，服务端仍拒绝自审。
        Entity own=add("guard_feedback",map("asset_id",f.asset().key(),"observation_id",observation.key(),"label","ambiguous",
                "evidence_ref","fixture://historical-label","created_by",accounts.get("evidence_reviewer").id()));
        assertThat(expect(send(mvc,get("/api/v2/feedback/"+own.id()),reviewer,null,null,null),200).path("createdBy").asLong())
                .isEqualTo(accounts.get("evidence_reviewer").id());
        code(send(mvc,post("/api/v2/feedback/"+own.id()+"/reviews"),reviewer,decision,id(),"1"),403,"APPROVAL_SEPARATION_REQUIRED");
        assertThat(jdbc.queryForObject("SELECT revision FROM guard_feedback WHERE id=?",Long.class,own.key())).isEqualTo(1);
        assertThat(expect(send(mvc,get("/api/v2/models/"+f.model().id()),reviewer,null,null,null),200).has("createdBy")).isFalse();
    }

    private void grantAssetRole(long user,String role,long asset){
        jdbc.update("INSERT INTO sys_user_role(user_id,role_id,scope_type,scope_id) SELECT ?,id,'asset',? FROM sys_role WHERE role_key=?",
                user,Long.toString(asset),role);
    }

    private static MockHttpServletRequestBuilder recordRange(String path){
        return get(path).param("from","2026-01-02T00:00:00Z").param("until","2026-01-03T00:00:00Z").param("sort","updatedAt");
    }

    /** 仅追加隔离库合成事实，业务时间故意早于登记时间，避免把两种时间口径混用。 */
    private Map<String,Entity> detectionChain(Fixture f,String createdAt){
        var at=db(java.time.Instant.parse(createdAt));var evidenceAt=at.minusDays(10);String boot=id();
        Entity scope=add("guard_capture_scope",map("asset_id",f.asset().key(),"sensor_id",f.sensor().key(),"scope_key",id(),"address_family","ipv4","status","pending"));
        Entity batch=add("guard_observation_batch",map("asset_id",f.asset().key(),"sensor_id",f.sensor().key(),"config_id",f.config().key(),
                "boot_id",boot,"sequence_no",1,"request_sha256",digest(),"result_json","{\"acceptedCount\":1,\"rejectedCount\":0}","created_at",at));
        Entity observation=add("guard_observation",map("batch_id",batch.key(),"sensor_id",f.sensor().key(),"asset_id",f.asset().key(),"boot_id",boot,
                "capture_scope_id",scope.key(),"flow_id",id(),"parent_connection_id",id(),"snapshot_index",1,"profile","final","as_of",evidenceAt,
                "last_packet_at",evidenceAt,"peer_key",digest(),"key_epoch",1,"direction","inbound","transport","tcp","service_port",22,
                "environment","lab","payload_json","{}","content_sha256",digest(),"created_at",at));
        Entity inference=add("guard_inference",map("observation_id",observation.key(),"asset_id",f.asset().key(),"model_id",f.model().key(),
                "status","succeeded","score",0.96,"family","brute_force","family_scores_json","{\"benign\":0.04,\"brute_force\":0.96}",
                "applicability","supported","manifest_sha256",digest(),"completed_at",evidenceAt,"created_at",at));
        Entity episode=add("guard_episode",map("asset_id",f.asset().key(),"sensor_id",f.sensor().key(),"boot_id",boot,"peer_key",digest(),"key_epoch",1,
                "direction","inbound","transport","tcp","service_port",22,"family","brute_force","bundle_id",f.bundle().key(),"bucket_start",evidenceAt));
        Entity decision=add("guard_decision",map("episode_id",episode.key(),"asset_id",f.asset().key(),"bundle_id",f.bundle().key(),"decision_revision",1,
                "decision_contract_version",DECISION,"decision","alert","reason_code","SCORE_BELOW_AUTO","evidence_sha256",digest(),
                "evidence_json","{\"source\":\"model\",\"family\":\"brute_force\"}","decided_at",evidenceAt,"created_at",at));
        return Map.of("observation-batches",batch,"observations",observation,"detections",inference,"decisions",decision);
    }

    static String collection(Entity entity){return switch(entity.table()){
        case "asset"->"assets";case "sensor_agent"->"sensors";case "guard_executor"->"executors";case "guard_dataset"->"datasets";
        case "guard_model"->"models";case "guard_release_bundle"->"release-bundles";default->throw new IllegalArgumentException();};}
    static MockHttpServletRequestBuilder request(String method,String path){return switch(method){case "PATCH"->patch(path);case "POST"->post(path);case "DELETE"->delete(path);default->throw new IllegalArgumentException();};}
}
