package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.*;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;
import static org.assertj.core.api.Assertions.*;

/** E3 隔离夹具：人工登记走现有完整审批夹具，机器领取/回执经真实 HTTPS，Go 解析使用 mTLS。
 * 合成模型与签名报告只用于协议验证，不构成发布资格；PF 模式必须由外层每轮 A4 授权。
 */
@SpringBootTest(webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT,properties={
        "cyber.ingest.consumer.enabled=false","cyber.ingest.outbox-relay.enabled=false",
        "cyber.guard.automation-enabled=true","cyber.security.local-admin-bootstrap.enabled=false",
        "server.address=127.0.0.1","server.ssl.enabled=true","server.ssl.enabled-protocols=TLSv1.3"})
@EnabledIfEnvironmentVariable(named="P5_JOINT_LAB",matches="true")
@ActiveProfiles("lab")
class GuardJointLabTest extends GuardIntegrationTest {
    @LocalServerPort int port;
    @Autowired Environment environment;
    @DynamicPropertySource static void tls(DynamicPropertyRegistry r){
        r.add("server.ssl.certificate",()->ROOT.resolve("backend-pki/server.pem").toString());
        r.add("server.ssl.certificate-private-key",()->ROOT.resolve("backend-pki/server.key").toString());
        r.add("lab.executor.trust-file",()->ROOT.resolve("command-trust.json").toString());
    }
    @Override String fixtureDirection(boolean scan){return "inbound";}
    @Override String fixtureInterface(){return "lo0";}
    @Override String fixtureAdapterVersion(){return "hostguard-executor/1";}
    void privateJson(Path path,JsonNode value)throws IOException{
        Files.writeString(path,canonical(value),StandardOpenOption.CREATE_NEW);
        Files.setPosixFilePermissions(path,PosixFilePermissions.fromString("rw-------"));
    }
    /** 固定顺序与独立资产隔离故障，避免前一轮撤销墓碑或暂停状态污染后一轮。 */
    @Test void jointMatrix()throws Exception{
        assertThat(SCHEMA).startsWith("cyber_guard_api_p4_");
        Path commandTrust=Path.of(environment.getRequiredProperty("lab.executor.trust-file"));
        Instant trustedAt=Instant.now().truncatedTo(ChronoUnit.MICROS);
        privateJson(commandTrust,object("fixture-control",object("status","active","publicKeyDer",Base64.getEncoder().encodeToString(signing.getPublic().getEncoded()),
                "notBefore",trustedAt.minusSeconds(60).toString(),"notAfter",trustedAt.plusSeconds(3600).toString())));
        String selectedScope=System.getenv("P5_SCOPE"),selectedScenario=System.getenv("P5_SCENARIO");
        if("pf".equals(System.getenv("P5_FIREWALL"))){
            assertThat(selectedScope).isIn("peer_service","peer_inbound");assertThat(selectedScenario).isIn("revoke","disconnect","receipt_loss");
        }
        for(String scope:List.of("peer_service","peer_inbound"))for(String scenario:List.of("revoke","disconnect","receipt_loss")){
            if(selectedScope!=null&&!selectedScope.equals(scope)||selectedScenario!=null&&!selectedScenario.equals(scenario))continue;
            Fixture f=setup(scope.equals("peer_inbound")?"port_scan":"dos_slow",List.of(),scope.equals("peer_inbound"));
            Path dir=ROOT.resolve(scope+"-"+scenario);Files.createDirectory(dir);Files.setPosixFilePermissions(dir,PosixFilePermissions.fromString("rwx------"));
            var policy=store.external("guard_decision_policy",f.policy(),false);
            var auth=store.external("asset_authorization",f.authorization(),false);
            privateJson(dir.resolve("input.json"),object("assetId",f.asset(),"sensorId",f.sensor(),"executorId",f.executor(),
                    "captureScopeId",f.scope(),"capabilityId",f.capability(),"capabilityHash",f.capabilityHash(),"bundleId",f.bundle(),
                    "policySha256",policy.get("definition_sha256"),"protection",PROTECTION,"credential",f.executorCredential(),
                    "controlPlaneURL","https://127.0.0.1:"+port,"controlPlaneCA",ROOT.resolve("backend-pki/ca.pem").toString(),
                    "commandTrustFile",commandTrust.toString(),
                    "authorization",object("id",f.authorization(),"revision",auth.get("revision"),"status","active",
                            "validFrom",instant(auth.get("valid_from")).toString(),"validUntil",instant(auth.get("valid_until")).toString()),
                    "scope",scope,"scenario",scenario));
            // 真实 PF 时执行端在 root 暂存副本中运行，本进程只启动用户态中继；协议与演练模式相同。
            String endpoint="true".equals(System.getenv("P5_EXTERNAL_EXECUTOR"))?"scripts/p5/joint_relay.py":"scripts/p5/joint_executor.py";
            Process process=new ProcessBuilder("/bin/bash","executor/python.sh","-u",endpoint,"--directory",dir.toString())
                    .directory(Path.of("..").toFile()).redirectError(dir.resolve("executor.log").toFile()).start();
            try(var reader=new BufferedReader(new InputStreamReader(process.getInputStream(),StandardCharsets.UTF_8));
                var writer=new BufferedWriter(new OutputStreamWriter(process.getOutputStream(),StandardCharsets.UTF_8))){
                JsonNode ready=receive(reader);String eboot=ready.path("executorBoot").asText(),boot=ready.path("collectorBoot").asText();
                machine("/sensors/"+f.sensor()+"/heartbeats",object("bootId",boot,"version","joint-fixture","configHash",f.configHash(),"lastSequence",0,"clockSkewMs",0),f.sensorCredential());
                JsonNode leased=exchange(reader,writer,"lease");JsonNode binding=leased.get("binding");
                String targetId=leased.path("registration").path("budgetTargetId").asText();
                Fixture live=new Fixture(f.asset(),f.sensor(),f.sensorCredential(),f.executor(),f.executorCredential(),f.scope(),f.config(),f.configHash(),boot,eboot,f.capability(),f.model(),f.policy(),f.bundle(),f.authorization(),binding.path("targetRef").asText(),binding.path("stableTargetToken").asText(),targetId,f.capabilityHash());
                var health=GuardDomainTest.health(Instant.now().truncatedTo(ChronoUnit.MICROS),1,null);health.put("assetId",f.asset()).put("sensorId",f.sensor()).put("captureScopeId",f.scope()).put("configSha256",f.configHash());machine("/sensors/"+f.sensor()+"/health-windows",health,f.sensorCredential());
                Instant at=Instant.now().truncatedTo(ChronoUnit.MICROS);var observations=new ArrayList<JsonNode>();
                for(int i=0;i<(scope.equals("peer_inbound")?2:1);i++)observations.add(observation(live,at,id(),0).put("direction","inbound").put("servicePort",443).put("peerKey",binding.path("peerKey").asText()));
                accept(live,observations,1,true);
                var asset=store.external("asset",f.asset(),false);var action=store.one("guard_action",map("asset_id",asset.get("id")),false);
                assertThat(action).withFailMessage("No action: %s",store.rows("guard_decision",map("asset_id",asset.get("id")),false,10)).isNotNull();
                var applied=exchange(reader,writer,"apply");assertThat(applied.path("installed").asBoolean()).isTrue();
                action=store.get("guard_action",number(action,"id"));
                human("/actions/"+action.get("public_id")+"/revocations",object("reason","E3 隔离联合撤销"),reviewer,str(action,"revision"));
                var done=exchange(reader,writer,"finish");assertThat(done.path("cleaned").asBoolean()).isTrue();
                JsonNode result=parse(Files.readString(dir.resolve("result.json")));
                if(scenario.equals("receipt_loss")){
                    String receipt=result.path("fault").path("receiptId").asText();
                    assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM guard_action_receipt WHERE public_id=?",Integer.class,receipt)).isEqualTo(1);
                }
                action=store.get("guard_action",number(action,"id"));assertThat(str(action,"observed_state")).isEqualTo("revoked");
                var target=store.external("guard_budget_target",targetId,false);assertThat(budget.revoked(number(target,"id"))).isTrue();
                privateJson(dir.resolve("database-facts.json"),object("schema",SCHEMA,"actionId",action.get("public_id"),"desiredState",action.get("desired_state"),
                        "observedState",action.get("observed_state"),"budget",budgetSnapshot(number(target,"id")),
                        "commandCount",store.rows("guard_command",map("action_id",action.get("id")),false,10).size(),
                        "receiptCount",jdbc.queryForObject("SELECT COUNT(*) FROM guard_action_receipt WHERE asset_id=?",Integer.class,asset.get("id"))));
                assertThat(process.waitFor(15,TimeUnit.SECONDS)).isTrue();assertThat(process.exitValue()).isZero();
            }finally{
                if(process.isAlive()){process.destroy();if(!process.waitFor(180,TimeUnit.SECONDS)){process.destroyForcibly();process.waitFor();}}
            }
        }
    }
    JsonNode budgetSnapshot(long target){var b=store.one("guard_target_budget",map("budget_target_id",target),false);return object("chargedMs",b.get("charged_ms"),"revision",b.get("revision"),"cycleStartedAt",instant(b.get("cycle_started_at")).toString(),"tombstone",budget.revoked(target));}
    JsonNode exchange(BufferedReader reader,BufferedWriter writer,String operation)throws Exception{writer.write(canonical(object("operation",operation)));writer.newLine();writer.flush();return receive(reader);}
    JsonNode receive(BufferedReader reader)throws Exception{
        var task=Executors.newSingleThreadExecutor(r->{var t=new Thread(r,"joint-lab-read");t.setDaemon(true);return t;});try{String line=task.submit(reader::readLine).get(45,TimeUnit.SECONDS);assertThat(line).isNotNull();JsonNode result=parse(line);assertThat(result.path("error").isMissingNode()).withFailMessage("Executor failure: %s",result).isTrue();return result;}finally{task.shutdownNow();}
    }
}
