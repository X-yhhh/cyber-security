package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.AutowireCapableBeanFactory;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.MockMvcPrint;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPairGenerator;
import java.sql.DriverManager;
import java.time.*;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;

import static com.xyh.cybersecurity.guard.GuardJson.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.doAnswer;

/** Go S4 合成窗口→真实机器接口/MySQL→实态替身→预算恢复；绝不接触真实 PF 或业务 schema。 */
@SpringBootTest(properties={"cyber.ingest.consumer.enabled=false","cyber.ingest.outbox-relay.enabled=false","cyber.drift.enabled=false","cyber.guard.automation-enabled=true","cyber.security.local-admin-bootstrap.enabled=false"})
@AutoConfigureMockMvc(print=MockMvcPrint.NONE)
@EnabledIfEnvironmentVariable(named="DB_TEST_BASE_URL",matches=".+")
class GuardSensorHealthIntegrationTest {
    static final String SCHEMA="cyber_sensor_health_"+UUID.randomUUID().toString().replace("-","");
    @Autowired AutowireCapableBeanFactory factory;
    @SpyBean GuardStore store;
    GuardIntegrationTest h;

    @DynamicPropertySource static void properties(DynamicPropertyRegistry r)throws Exception {
        var root=GuardIntegrationTest.ROOT;Files.createDirectories(root);
        GuardIntegrationTest.signing=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        Files.write(root.resolve("signing.der"),GuardIntegrationTest.signing.getPrivate().getEncoded());
        Files.setPosixFilePermissions(root.resolve("signing.der"),PosixFilePermissions.fromString("rw-------"));
        Files.writeString(root.resolve("trust.json"),canonical(object("fixture-runner",Base64.getEncoder().encodeToString(GuardIntegrationTest.signing.getPublic().getEncoded()))));
        Files.writeString(root.resolve("protection.json"),canonical(GuardIntegrationTest.PROTECTION));
        String base=System.getenv("DB_TEST_BASE_URL").replaceAll("/+$","");String user=System.getenv("DB_TEST_USERNAME"),dbCredential=System.getenv("DB_TEST_PASSWORD");
        try(var connection=DriverManager.getConnection(base,user,dbCredential);var statement=connection.createStatement()){statement.execute("CREATE DATABASE "+SCHEMA+" CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin");}
        String url=base+"/"+SCHEMA+"?connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true";
        Flyway.configure().dataSource(url,user,dbCredential).load().migrate();
        r.add("spring.datasource.url",()->url);r.add("spring.datasource.username",()->user);r.add("spring.datasource.password",()->dbCredential);r.add("spring.flyway.enabled",()->false);
        r.add("cyber.security.login-throttle.hmac-key",()->"synthetic-health-only-key-more-than-thirty-two-bytes");
        r.add("cyber.guard.artifact-root",()->root.toString());r.add("cyber.guard.signing-key-id",()->"fixture-control");r.add("cyber.guard.signing-key-file",()->root.resolve("signing.der").toString());
        r.add("cyber.guard.report-trust-file",()->root.resolve("trust.json").toString());r.add("cyber.guard.protection-file",()->root.resolve("protection.json").toString());
    }
    @AfterAll static void removeOnlySyntheticSchema()throws Exception {
        String base=System.getenv("DB_TEST_BASE_URL").replaceAll("/+$","");
        try(var connection=DriverManager.getConnection(base,System.getenv("DB_TEST_USERNAME"),System.getenv("DB_TEST_PASSWORD"));var statement=connection.createStatement()){statement.execute("DROP DATABASE IF EXISTS "+SCHEMA);}
    }
    @BeforeEach void helpers(){h=new GuardIntegrationTest();factory.autowireBean(h);h.identities();}

    /** 实际执行 Go 观察器并检查 JCS 摘要；测试时钟只影响 GuardStore，不改变宿主机时间。 */
    JsonNode windows(GuardIntegrationTest.Fixture f,Instant start,int count)throws Exception {
        Path dir=Files.createTempDirectory(GuardIntegrationTest.ROOT,"synthetic-health-");Path input=dir.resolve("request.json"),output=dir.resolve("windows.json"),log=dir.resolve("go.log");
        Files.writeString(input,canonical(object("identity",object("AssetID",f.asset(),"SensorID",f.sensor(),"CaptureScopeID",f.scope(),"ConfigSha256",f.configHash(),"BuildSha256","b".repeat(64)),"start",start.toString(),"count",count)));
        Files.setPosixFilePermissions(input,PosixFilePermissions.fromString("rw-------"));
        var builder=new ProcessBuilder(System.getenv().getOrDefault("GO_TEST_BINARY","go"),"test","-p","1","./internal/guardlab","-run","^TestExportHealthFixture$","-count=1").directory(Path.of("../sensor").toFile()).redirectErrorStream(true).redirectOutput(log.toFile());
        builder.environment().put("GUARD_HEALTH_FIXTURE_REQUEST",input.toString());builder.environment().put("GUARD_HEALTH_FIXTURE_OUTPUT",output.toString());builder.environment().put("GOMAXPROCS","2");
        var process=builder.start();try{assertThat(process.waitFor(45,TimeUnit.SECONDS)).isTrue();assertThat(process.exitValue()).withFailMessage("Go fixture failed; inspect isolated go.log").isZero();}finally{if(process.isAlive())process.destroyForcibly().waitFor();}
        var result=parse(Files.readString(output));assertThat(result.path("synthetic").asBoolean()).isTrue();
        for(int i=0;i<count;i++)assertThat(hash(result.path("windows").get(i))).isEqualTo(result.path("hashes").get(i).asText());
        return result.path("windows");
    }
    long resets(long target){return h.jdbc.queryForObject("SELECT COUNT(*) FROM guard_budget_event WHERE budget_target_id=? AND event_kind='reset'",Long.class,target);}
    long charged(long target){return h.jdbc.queryForObject("SELECT charged_ms FROM guard_target_budget WHERE budget_target_id=?",Long.class,target);}

    @Test void goHealthToMachineApiAndVerifiedCleanupRecoversExactlyOnce()throws Exception {
        var f=h.setup();Instant base=store.now().truncatedTo(ChronoUnit.MICROS);var clock=new AtomicReference<>(base);
        doAnswer(invocation->clock.get()).when(store).now();
        h.accept(f,List.of(h.observation(f,base,id(),0)),1,true);
        long asset=number(store.external("asset",f.asset(),false),"id");var action=store.one("guard_action",map("asset_id",asset),false);assertThat(action).isNotNull();
        long target=number(action,"budget_target_id");assertThat(charged(target)).isPositive();
        var claims=h.machine("/executors/"+f.executor()+"/command-claims",object("bootId",f.executorBoot(),"capabilityHash",f.capabilityHash(),"maxItems",10,"waitSeconds",0),f.executorCredential());
        JsonNode command=claims.path("commands").get(0);assertThat(command).isNotNull();
        var rows=windows(f,base,72);
        for(int i=0;i<25;i++){var w=rows.get(i);clock.set(time(w,"intervalEnd"));assertThat(h.machine("/sensors/"+f.sensor()+"/health-windows",w,f.sensorCredential()).path("verificationStatus").asText()).isEqualTo("healthy");assertThat(charged(target)).isPositive();}
        // 已完整健康超过 120 秒但命令尚未核验清理，额度必须保留。
        assertThat(resets(target)).isZero();
        h.human("/actions/"+action.get("public_id")+"/revocations",object("reason","合成防火墙替身清理"),h.reviewer,"2");
        var rev=h.machine("/executors/"+f.executor()+"/command-claims",object("bootId",f.executorBoot(),"capabilityHash",f.capabilityHash(),"maxItems",10,"waitSeconds",0),f.executorCredential()).path("revocations").get(0);
        var empty=object("digestVersion","guard-state/1","assetId",f.asset(),"executorId",f.executor(),"executorBootId",f.executorBoot(),"rules",List.of(),"pendingRevocations",List.of());String digest=hash(empty);
        h.machine("/executors/"+f.executor()+"/receipts",object("contractVersion",CONTRACT,"receiptId",id(),"commandId",command.at("/payload/commandId"),"revocationId",rev.path("revocationId"),"executorId",f.executor(),"status","revoked","observedAt",clock.get().toString(),"ruleHandle",null,"effectiveBlockUntil",null,"errorCode",null,"stateDigest",digest),f.executorCredential());
        h.machine("/executors/"+f.executor()+"/reconciliations",object("executorBootId",f.executorBoot(),"observedAt",clock.get().toString(),"digestVersion","guard-state/1","stateDigest",digest,"ownedRules",List.of(),"pendingRevocations",List.of(),"recoveryErrors",List.of()),f.executorCredential());
        assertThat(str(store.get("guard_action",number(action,"id")),"observed_state")).isEqualTo("revoked");
        var tx=new TransactionTemplate(h.manager);
        for(int i=25;i<72;i++){
            JsonNode w=rows.get(i);clock.set(time(w,"intervalEnd"));
            // 冷却未结束前出现新的合格证据，恢复起点必须顺延到该证据后 120 秒。
            if(i==44)tx.executeWithoutResult(status->h.budget.evidence(target,clock.get()));
            assertThat(h.machine("/sensors/"+f.sensor()+"/health-windows",w,f.sensorCredential()).path("verificationStatus").asText()).isEqualTo("healthy");
            if(i<68)assertThat(charged(target)).isPositive();
        }
        assertThat(charged(target)).isZero();assertThat(resets(target)).isEqualTo(1);
        h.machine("/sensors/"+f.sensor()+"/health-windows",rows.get(71),f.sensorCredential());
        try(var pool=Executors.newFixedThreadPool(2)){
            var one=pool.submit(()->tx.<Boolean>execute(status->h.budget.recover(asset,target,clock.get())));
            var two=pool.submit(()->tx.<Boolean>execute(status->h.budget.recover(asset,target,clock.get())));
            assertThat(one.get(5,TimeUnit.SECONDS)).isFalse();assertThat(two.get(5,TimeUnit.SECONDS)).isFalse();
        }
        assertThat(resets(target)).isEqualTo(1);
        // 真实 Go 窗口的失败变体不能提供健康证明。
        JsonNode previous=rows.get(0);String previousHash=hash(previous);
        for(String failure:List.of("drops","unknown","chain","clock","late","identity")){
            ObjectNode bad=rows.get(1).deepCopy();Instant received=time(bad,"intervalEnd");
            switch(failure){case "drops"->((ObjectNode)bad.path("counterEnd")).put("kernelDrops",1);case "unknown"->((ObjectNode)bad.path("counterEnd")).putNull("kernelDrops");case "chain"->bad.put("previousSha256","0".repeat(64));case "clock"->bad.putNull("clockSkewMs");case "late"->received=received.plusMillis(10001);case "identity"->bad.put("buildSha256","c".repeat(64));}
            assertThat(GuardHealth.verify(bad,previous,previousHash,received)).isNotEqualTo("healthy");
        }
    }
}
