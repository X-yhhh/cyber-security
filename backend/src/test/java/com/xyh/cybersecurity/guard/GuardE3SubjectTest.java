package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.SecureRandom;
import java.time.*;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.TimeUnit;
import static com.xyh.cybersecurity.guard.GuardJson.*;
import static org.assertj.core.api.Assertions.*;

/** K9 E3 subject 入口：在编排器建好的业务库克隆中复用既有组合，不新建或修改模型、策略与组合。
 * 观察由 guardlive 以 research 模式 1 倍速实时回放冻结片段产生，特征原样保留，只把身份、环境、
 * 对端键和目标引用映射到回环 canary 租约（与 lab 映射相同的字段集合）。引导报告只在克隆内由开关放行。
 */
@SpringBootTest(webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT,properties={
        "cyber.ingest.consumer.enabled=false","cyber.ingest.outbox-relay.enabled=false","cyber.drift.enabled=false",
        "cyber.guard.automation-enabled=true","cyber.security.local-admin-bootstrap.enabled=false","cyber.guard.bootstrap-reports-enabled=true",
        "server.address=127.0.0.1","server.ssl.enabled=true","server.ssl.enabled-protocols=TLSv1.3"})
@EnabledIfEnvironmentVariable(named="P5_SUBJECT_SCHEMA",matches="cyber_guard_k9_[0-9a-f]{32}")
@ActiveProfiles("lab")
class GuardE3SubjectTest extends GuardJointLabTest {
    @Autowired GuardEligibility eligibility;
    /** 契约上限 512；扫描突发时较大批次可复用同批判定缓存，减少积压。 */
    static final int BATCH=500;
    static final Set<String> MAPPED=Set.of("environment","peerKey","targetRef","targetExpiresAt","quality.clockSkewMs");

    static String env(String name){String v=System.getenv(name);assertThat(v).withFailMessage("missing %s",name).isNotBlank();return v;}

    /** 克隆中 candidate → 导入引导 platform/canary（与既有 final 一起）→ 封存 → 独立批准；不激活。 */
    @Test void subjectBootstrap()throws Exception{
        JsonNode input=parse(Files.readString(Path.of(env("P5_SUBJECT_BOOTSTRAP"))));
        String bid=input.path("bundleId").asText();var bundle=store.external("guard_release_bundle",bid,false);
        assertThat(str(bundle,"status")).isEqualTo("candidate");assertThat(str(bundle,"environment")).isEqualTo("lab");
        assertThat(str(bundle,"subject_sha256")).isEqualTo(input.path("subjectSha256").asText());
        var ids=new ArrayList<String>();
        for(var r:store.rows("guard_evaluation_run",map("bundle_id",bundle.get("id"),"run_kind","final","status","passed"),false,10))ids.add(str(r,"public_id"));
        assertThat(ids).withFailMessage("克隆中 r4 尚无已导入的 final").isNotEmpty();
        var kinds=new TreeSet<String>();
        for(var r:input.path("reports")){
            JsonNode imported=human("/release-bundles/"+bid+"/imports",object("reportRef",r.path("reportRef").asText(),"sha256",r.path("sha256").asText(),"runnerIdentity",r.path("runnerIdentity").asText()),operator,null);
            assertThat(imported.path("status").asText()).isEqualTo("passed");ids.add(imported.path("id").asText());kinds.add(r.path("kind").asText());
        }
        assertThat(kinds).containsExactly("canary","platform");
        JsonNode sealed=human("/release-bundles/"+bid+"/sealings",object("evaluationIds",ids),operator,str(bundle,"revision"));
        JsonNode approved=human("/release-bundles/"+bid+"/decisions",object("decision","approve","reason","K9 克隆内引导批准，仅供 E3 产出 subject 证据"),reviewer,sealed.path("revision").asText());
        assertThat(approved.path("status").asText()).isEqualTo("approved");
        privateJson(ROOT.resolve("bootstrap-result.json"),object("schema",SCHEMA,"bundleId",bid,"subjectSha256",str(bundle,"subject_sha256"),"evaluationIds",ids,
                "sealedManifestSha256",sealed.path("sealedManifestSha256").asText(),"status",approved.path("status").asText(),"revision",approved.path("revision").asText()));
    }

    record Round(String asset,String sensor,String sensorCredential,String executor,String executorCredential,String scope,String config,String configHash,String capability,String authorization){}

    /** 每轮新建 lab 回环资产、执行授权、传感器与执行器，并只把既有已批准组合激活到该资产。 */
    Round prepare(String bid,String scope,JsonNode segment,String capability,String build)throws Exception{
        Instant now=Instant.now().truncatedTo(ChronoUnit.MILLIS);
        String asset=human("/assets",object("assetKey",id(),"platform","macos","environment","lab","owner","k9-e3-subject-clone"),operator,null).path("id").asText();
        ObjectNode execution=object("scope",scope,"direction","inbound","transport","tcp","addressFamily","ipv4","capabilityId",capability);
        if(scope.equals("peer_inbound"))execution.putNull("servicePort");else execution.put("servicePort",segment.path("servicePort").asInt());
        String auth=human("/assets/"+asset+"/authorizations",object("interfaces",List.of("lo0"),"observationAllowed",true,"executionScopes",List.of(execution),
                "validFrom",now.minusSeconds(60).toString(),"validUntil",now.plusSeconds(3600).toString(),"evidenceRef","k9:e3-subject-clone"),operator,null).path("id").asText();
        human("/authorizations/"+auth+"/decisions",object("decision","approve","reason","K9 克隆内回环 E3"),reviewer,"1");
        String captureScope=id();JsonNode sensor=human("/sensors",object("assetId",asset,"platform","macos","captureScopeId",captureScope),operator,null);
        JsonNode executor=human("/executors",object("assetId",asset,"platform","macos","capabilityProbeRef","k9:e3-subject"),operator,null);
        JsonNode config=object("contractVersion",CONTRACT,"profileSha256",contracts.profileHash(),"captureHealthVersion",HEALTH,"interfaceIds",List.of("lo0"),"limits",object("maxBatchSize",BATCH),"captureScopeId",captureScope,"addressFamily","ipv4","buildSha256",build);
        String configId=human("/sensors/"+sensor.path("id").asText()+"/configs",config,operator,null).path("id").asText();
        human("/sensor-configs/"+configId+"/decisions",object("decision","approve","reason","K9 冻结片段回放构建"),reviewer,"1");
        var current=store.external("guard_release_bundle",bid,false);assertThat(str(current,"status")).isIn("approved","active");
        human("/release-bundles/"+bid+"/activations",object("assetIds",List.of(asset),"authorizationIds",List.of(auth)),reviewer,str(current,"revision"));
        return new Round(asset,sensor.path("id").asText(),sensor.path("credential").asText(),executor.path("id").asText(),executor.path("credential").asText(),captureScope,configId,hash(config),capability,auth);
    }

    /** 片段由编排器冻结并给出原件摘要；回放前逐文件核对，不接受任意路径。 */
    static Path segmentPcap(JsonNode segment)throws Exception{
        Path pcap=Path.of(segment.path("pcap").asText());assertThat(sha(Files.readAllBytes(pcap))).isEqualTo(segment.path("sha256").asText());return pcap;
    }

    @Test void subjectMatrix()throws Exception{
        assertThat(SCHEMA).startsWith("cyber_guard_k9_");
        JsonNode binding=parse(Files.readString(Path.of(env("HOSTGUARD_SUBJECT_BINDING"))));JsonNode segments=parse(Files.readString(Path.of(env("P5_SUBJECT_SEGMENTS"))));
        String bid=binding.path("bundleId").asText();var bundle=store.external("guard_release_bundle",bid,false);
        assertThat(str(bundle,"subject_sha256")).isEqualTo(binding.path("subjectSha256").asText());assertThat(str(bundle,"status")).isIn("approved","active");
        Path guardlive=Path.of(env("P5_GUARDLIVE"));String build=sha(Files.readAllBytes(guardlive));
        // 组合登记的全部能力进入执行器配置，capabilityHash 才与控制面按 active 绑定重算的结果一致。
        var capabilities=new TreeMap<String,JsonNode>();
        for(var link:store.rows("guard_bundle_capability",map("bundle_id",bundle.get("id")),false,100)){var c=store.get("guard_capability",number(link,"capability_id"));capabilities.put(str(c,"public_id"),((ObjectNode)json(c,"payload_json")).put("scopeRegistered",str(c,"scope")==null?"peer_service":str(c,"scope")));}
        var policy=store.get("guard_decision_policy",number(bundle,"policy_id"));
        Path commandTrust=Path.of(environment.getRequiredProperty("lab.executor.trust-file"));Instant trustedAt=Instant.now().truncatedTo(ChronoUnit.MICROS);
        privateJson(commandTrust,object("fixture-control",object("status","active","publicKeyDer",Base64.getEncoder().encodeToString(signing.getPublic().getEncoded()),
                "notBefore",trustedAt.minusSeconds(60).toString(),"notAfter",trustedAt.plusSeconds(7200).toString())));
        String selectedScope=System.getenv("P5_SCOPE"),selectedScenario=System.getenv("P5_SCENARIO");
        if("pf".equals(System.getenv("P5_FIREWALL"))){assertThat(selectedScope).isIn("peer_service","peer_inbound");assertThat(selectedScenario).isIn("revoke","disconnect","receipt_loss");}
        for(String scope:List.of("peer_service","peer_inbound"))for(String scenario:List.of("revoke","disconnect","receipt_loss")){
            if(selectedScope!=null&&!selectedScope.equals(scope)||selectedScenario!=null&&!selectedScenario.equals(scenario))continue;
            // 诊断用：只跑指定轮次；K6 覆盖检查会拒绝不完整矩阵，因此不能借此产出报告。
            String rounds=System.getenv("P5_SUBJECT_ROUNDS");if(rounds!=null&&!Arrays.asList(rounds.split(",")).contains(scope+"-"+scenario))continue;
            JsonNode segment=segments.get(scope);Path pcap=segmentPcap(segment);String family=segment.path("family").asText();
            String capability=capabilities.entrySet().stream().filter(e->e.getValue().path("family").asText().equals(family)&&e.getValue().path("scopeRegistered").asText().equals(scope)).map(Map.Entry::getKey).findFirst().orElseThrow();
            Round r=prepare(bid,scope,segment,capability,build);
            Path dir=ROOT.resolve(scope+"-"+scenario);Files.createDirectory(dir);Files.setPosixFilePermissions(dir,java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
            var auth=store.external("asset_authorization",r.authorization(),false);
            var inbound=capabilities.entrySet().stream().filter(e->e.getValue().path("scopeRegistered").asText().equals("peer_inbound")).map(Map.Entry::getKey).toList();
            int leasePort=scope.equals("peer_service")?segment.path("servicePort").asInt():443;
            String expectedHash=eligibility.executorCapabilityHash(store.external("guard_executor",r.executor(),false));
            privateJson(dir.resolve("input.json"),object("assetId",r.asset(),"sensorId",r.sensor(),"executorId",r.executor(),
                    "captureScopeId",r.scope(),"capabilityId",capability,"capabilityIds",new ArrayList<>(capabilities.keySet()),"inboundCapabilityIds",inbound,"servicePort",leasePort,
                    "capabilityHash",expectedHash,"bundleId",bid,"policySha256",policy.get("definition_sha256"),"protection",PROTECTION,"credential",r.executorCredential(),
                    "controlPlaneURL","https://127.0.0.1:"+port,"controlPlaneCA",ROOT.resolve("backend-pki/ca.pem").toString(),"commandTrustFile",commandTrust.toString(),
                    "authorization",object("id",r.authorization(),"revision",auth.get("revision"),"status","active",
                            "validFrom",instant(auth.get("valid_from")).toString(),"validUntil",instant(auth.get("valid_until")).toString()),
                    "scope",scope,"scenario",scenario));
            String endpoint="true".equals(System.getenv("P5_EXTERNAL_EXECUTOR"))?"scripts/p5/joint_relay.py":"scripts/p5/joint_executor.py";
            Process process=new ProcessBuilder("/bin/bash","executor/python.sh","-u",endpoint,"--directory",dir.toString())
                    .directory(Path.of("..").toFile()).redirectError(dir.resolve("executor.log").toFile()).start();
            Process live=null;
            try(var reader=new BufferedReader(new InputStreamReader(process.getInputStream(),StandardCharsets.UTF_8));
                var writer=new BufferedWriter(new OutputStreamWriter(process.getOutputStream(),StandardCharsets.UTF_8))){
                JsonNode ready=receive(reader);String boot=ready.path("collectorBoot").asText();
                Feed feed=new Feed(r,boot,dir,reader,writer,build);feed.peerKey=ready.path("canaryPeerKey").asText();assertThat(feed.peerKey).matches("[0-9a-f]{64}");feed.sensorHeartbeat();feed.health();
                // 租约在首条观察出现时才申请，与传感器按报文取租约一致；预热期间没有执行引用。
                live=feed.start(guardlive,pcap,segment);
                var asset=store.external("asset",r.asset(),false);
                Map<String,Object> action;
                try{action=feed.run(live,()->store.one("guard_action",map("asset_id",asset.get("id")),false));}
                finally{privateJson(dir.resolve("feed-timing.json"),node(feed.timing));}
                assertThat(action).withFailMessage("No action from frozen replay: %s",feed.diagnostics(asset.get("id"))).isNotNull();
                live.destroy();if(!live.waitFor(10,TimeUnit.SECONDS))live.destroyForcibly();
                var applied=exchange(reader,writer,"apply");assertThat(applied.path("installed").asBoolean()).isTrue();
                action=store.get("guard_action",number(action,"id"));
                human("/actions/"+action.get("public_id")+"/revocations",object("reason","K9 E3 克隆联合撤销"),reviewer,str(action,"revision"));
                var done=exchange(reader,writer,"finish");assertThat(done.path("cleaned").asBoolean()).isTrue();
                JsonNode result=parse(Files.readString(dir.resolve("result.json")));
                assertThat(result.path("runtimeSubjectBinding").path("verifiedBeforeExecution").asBoolean()).isTrue();
                if(scenario.equals("receipt_loss")){String receipt=result.path("fault").path("receiptId").asText();assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM guard_action_receipt WHERE public_id=?",Integer.class,receipt)).isEqualTo(1);}
                action=store.get("guard_action",number(action,"id"));assertThat(str(action,"observed_state")).isEqualTo("revoked");
                long target=number(action,"budget_target_id");assertThat(budget.revoked(target)).isTrue();
                var decision=store.get("guard_decision",number(action,"decision_id"));
                privateJson(dir.resolve("database-facts.json"),object("schema",SCHEMA,"bundleId",bid,"actionId",action.get("public_id"),"desiredState",action.get("desired_state"),
                        "observedState",action.get("observed_state"),"budget",budgetSnapshot(target),"decisionFamily",json(decision,"evidence_json").path("family"),
                        "decisionSource",json(decision,"evidence_json").path("source"),"bundleSubjectSha256",json(decision,"evidence_json").path("bundleSubjectSha256"),
                        "commandCount",store.rows("guard_command",map("action_id",action.get("id")),false,10).size(),
                        "receiptCount",jdbc.queryForObject("SELECT COUNT(*) FROM guard_action_receipt WHERE asset_id=?",Integer.class,asset.get("id"))));
                privateJson(dir.resolve("subject-feed.json"),feed.summary(segment));
                assertThat(process.waitFor(15,TimeUnit.SECONDS)).isTrue();assertThat(process.exitValue()).isZero();
            }finally{
                if(live!=null&&live.isAlive()){live.destroyForcibly();live.waitFor();}
                if(process.isAlive()){process.destroy();if(!process.waitFor(180,TimeUnit.SECONDS)){process.destroyForcibly();process.waitFor();}}
            }
        }
    }

    /** 实时回放的上传侧：映射字段、续租、心跳与连续健康窗；不改任何特征或上下文值。 */
    final class Feed{
        final Round r;final String boot,build;final Path dir;final BufferedReader reader;final BufferedWriter writer;
        String targetRef,peerKey;Instant expiresAt;long sequence=0,healthSequence=0,posted=0,leases=0;String healthPrevious;Instant healthEnd;final String observer=id();
        Instant firstPosted,actionSeenAt;final List<String> skipped=new ArrayList<>();final List<JsonNode> timing=new ArrayList<>();
        Feed(Round r,String boot,Path dir,BufferedReader reader,BufferedWriter writer,String build){this.r=r;this.boot=boot;this.dir=dir;this.reader=reader;this.writer=writer;this.build=build;}
        Double skewMs;
        /** 上传侧心跳顺带按服务端时间测偏差（与 guardup 相同口径：响应时间减往返中点）。 */
        void sensorHeartbeat()throws Exception{
            Instant before=Instant.now();
            JsonNode reply=machine("/sensors/"+r.sensor()+"/heartbeats",object("bootId",boot,"version","k9-e3-subject","configHash",r.configHash(),"lastSequence",sequence,"clockSkewMs",skewMs),r.sensorCredential());
            Instant after=Instant.now();
            if(reply.hasNonNull("serverTime")){Instant middle=before.plus(Duration.between(before,after).dividedBy(2));skewMs=Duration.between(middle,Instant.parse(reply.path("serverTime").asText())).toNanos()/1e6;}
        }
        /** 健康窗必须首尾相接且每窗不超过 5 秒；批量处理占用较久时按 4 秒分段补齐，不留间断。 */
        void health()throws Exception{
            Instant now=Instant.now().truncatedTo(ChronoUnit.MICROS);Instant start=healthEnd==null?now.minusSeconds(1):healthEnd;
            while(start.isBefore(now)){Instant end=start.plusSeconds(4).isBefore(now)?start.plusSeconds(4):now;healthWindow(start,end);start=end;}
        }
        void healthWindow(Instant start,Instant end)throws Exception{
            ObjectNode h=GuardDomainTest.health(end,++healthSequence,healthPrevious);h.put("intervalStart",start.toString()).put("assetId",r.asset()).put("sensorId",r.sensor()).put("captureScopeId",r.scope())
                    .put("observerSessionId",observer).put("configSha256",r.configHash()).put("buildSha256",build);
            JsonNode accepted=machine("/sensors/"+r.sensor()+"/health-windows",h,r.sensorCredential());assertThat(accepted.path("verificationStatus").asText()).isEqualTo("healthy");
            healthPrevious=accepted.path("contentSha256").asText();healthEnd=end;
        }
        /** guardtargets 租约截止固定；过期后才换引用，与 lab 传感器语义一致。 */
        Instant lastRefresh,refreshedPacket,nextBeat=Instant.MIN;long refreshes=0;
        /** 每 2 秒补健康窗、传感器心跳与执行器心跳（不领取命令）。 */
        void beat()throws Exception{if(Instant.now().isBefore(nextBeat))return;health();sensorHeartbeat();exchange(reader,writer,"heartbeat");nextBeat=Instant.now().plusSeconds(2);}
        void lease()throws Exception{lease(null);}
        /** packet 为触发本次租约的报文时刻（首条可执行观察）；缺省为现在。截止 = packet + 15 秒，与观察契约一致。 */
        void lease(Instant packet)throws Exception{
            String previous=targetRef;Instant deadline=Instant.now().plusSeconds(20);
            while(true){
                if(expiresAt!=null){Instant wait=expiresAt.plusMillis(20);while(Instant.now().isBefore(wait))Thread.sleep(10);}
                ObjectNode request=object("operation","lease");if(packet!=null)request.put("lastPacketAt",packet.toString());
                writer.write(canonical(request));writer.newLine();writer.flush();JsonNode leased=receive(reader);JsonNode b=leased.get("binding");
                // 回环 canary 解析器在最近报文后 15 秒内沿用原引用；控制面登记截止已过时等它换新引用，期间观察不带执行引用。
                if(previous==null||!previous.equals(b.path("targetRef").asText())){targetRef=b.path("targetRef").asText();peerKey=b.path("peerKey").asText();
                    expiresAt=Instant.parse(b.path("leaseExpiresAt").asText());leases++;lastRefresh=Instant.now();refreshedPacket=null;return;}
                assertThat(Instant.now()).isBefore(deadline);Thread.sleep(500);
            }
        }
        /** 与传感器逐包取租约一致：同一引用只刷新解析器的最近报文时刻，不延长控制面登记的截止。 */
        void refresh(List<JsonNode> batch)throws Exception{
            Instant now=Instant.now();if(expiresAt==null||lastRefresh!=null&&Duration.between(lastRefresh,now).toMillis()<1000||!now.plusSeconds(1).isBefore(expiresAt))return;
            Instant latest=null;for(var o:batch)if(targetRef.equals(o.path("targetRef").asText(null))){Instant at=Instant.parse(o.path("lastPacketAt").asText());if(latest==null||at.isAfter(latest))latest=at;}
            if(latest==null||refreshedPacket!=null&&!latest.isAfter(refreshedPacket))return;
            writer.write(canonical(object("operation","lease","lastPacketAt",latest.toString())));writer.newLine();writer.flush();JsonNode b=receive(reader).get("binding");
            assertThat(b.path("targetRef").asText()).isEqualTo(targetRef);assertThat(Instant.parse(b.path("leaseExpiresAt").asText())).isEqualTo(expiresAt);
            lastRefresh=now;refreshedPacket=latest;refreshes++;
        }
        Process start(Path guardlive,Path pcap,JsonNode segment)throws Exception{
            byte[] secret=new byte[32];new SecureRandom().nextBytes(secret);Path key=dir.resolve("replay-peer.key");Files.write(key,secret);
            ObjectNode cfg=object("assetId",r.asset(),"sensorId",r.sensor(),"bootId",boot,"captureScopeId",r.scope(),"localAddresses",List.of(segment.path("host").asText()),
                    "secretFile",key.toString(),"keyEpoch",1,"environment","research","captureScope","all_inbound_tcp","interface","replay0","allowedInterfaces",List.of("replay0"),
                    "authorizedUntil",Instant.now().plusSeconds(3600).truncatedTo(ChronoUnit.SECONDS).toString());
            privateJson(dir.resolve("replay-config.json"),cfg);
            return new ProcessBuilder(guardlive.toString(),"-config",dir.resolve("replay-config.json").toString(),"-pcap",pcap.toString(),"-out",dir.resolve("replay.jsonl").toString(),
                    "-report",dir.resolve("replay-report.json").toString(),"-capture-start",segment.path("captureStart").asText()).redirectOutput(dir.resolve("replay.stdout").toFile()).redirectError(dir.resolve("replay.log").toFile()).start();
        }
        ObjectNode mapped(JsonNode raw){
            ObjectNode o=(ObjectNode)raw.deepCopy();
            // 身份字段须与本轮登记一致；其余特征字段原样上送。
            for(String k:List.of("assetId","sensorId","captureScopeId"))assertThat(o.path(k).asText()).isEqualTo(switch(k){case "assetId"->r.asset();case "sensorId"->r.sensor();default->r.scope();});
            assertThat(o.path("bootId").asText()).isEqualTo(boot);
            o.put("environment","lab").put("peerKey",peerKey);
            // research 回放不上传，偏差由本上传侧心跳实测后填写；未测到保持 null。
            if(skewMs!=null)((ObjectNode)o.get("quality")).put("clockSkewMs",skewMs);else((ObjectNode)o.get("quality")).putNull("clockSkewMs");
            // 与 guardlab.MapEmission 相同：方向、服务端口、质量、偏差或新鲜度不满足时只保留遥测、清空执行引用。
            JsonNode q=o.get("quality");Instant now=Instant.now();
            boolean defective=q.path("capacityDrop").asBoolean()||q.path("captureGap").asBoolean()||q.path("latePacket").asBoolean()||q.path("offloadSuspected").asBoolean()||q.path("truncated").asBoolean();
            boolean executable=o.path("direction").asText().equals("inbound")&&o.path("servicePort").isNumber()&&!defective&&q.path("clockSkewMs").isNumber()
                    &&Math.abs(q.path("clockSkewMs").asDouble())<=1000&&Duration.between(Instant.parse(o.path("lastPacketAt").asText()),now).toMillis()<=10000&&expiresAt!=null&&expiresAt.isAfter(now)
                    // 观察契约：targetExpiresAt 位于 [lastPacketAt, lastPacketAt+15s]；租约之前的报文不携带该引用。
                    &&!expiresAt.isAfter(Instant.parse(o.path("lastPacketAt").asText()).plusSeconds(15))&&!expiresAt.isBefore(Instant.parse(o.path("lastPacketAt").asText()));
            if(executable)o.put("targetRef",targetRef).put("targetExpiresAt",expiresAt.toString());else o.putNull("targetRef").putNull("targetExpiresAt");
            return o;
        }
        Map<String,Object> run(Process live,java.util.concurrent.Callable<Map<String,Object>> action)throws Exception{
            Path out=dir.resolve("replay.jsonl");long offset=0;StringBuilder partial=new StringBuilder();
            Instant deadline=Instant.now().plusSeconds(Long.parseLong(System.getenv().getOrDefault("P5_SUBJECT_FEED_SECONDS","180")));
            try(var mapped=Files.newBufferedWriter(dir.resolve("mapped.jsonl"),StandardOpenOption.CREATE_NEW)){
                while(Instant.now().isBefore(deadline)){
                    beat();
                    if(expiresAt!=null&&Instant.now().plusMillis(300).isAfter(expiresAt))lease();
                    var lines=new ArrayList<JsonNode>();
                    if(Files.exists(out)){try(var ch=Files.newByteChannel(out)){ch.position(offset);var buf=java.nio.ByteBuffer.allocate(1<<20);int n=ch.read(buf);if(n>0){offset+=n;partial.append(new String(buf.array(),0,n,StandardCharsets.UTF_8));}}}
                    int nl;while((nl=partial.indexOf("\n"))>=0){String line=partial.substring(0,nl);partial.delete(0,nl+1);if(!line.isBlank())lines.add(parse(line));}
                    if(expiresAt==null){Instant first=null;for(var o:lines)if(o.path("direction").asText().equals("inbound")&&o.path("servicePort").isNumber()){Instant at=Instant.parse(o.path("lastPacketAt").asText());if(first==null||at.isBefore(first))first=at;}
                        if(first!=null)lease(first);}
                    for(int i=0;i<lines.size();i+=BATCH){
                        var batch=new ArrayList<JsonNode>();for(var raw:lines.subList(i,Math.min(lines.size(),i+BATCH))){var o=mapped(raw);batch.add(o);mapped.write(canonical(o));mapped.newLine();}
                        if(firstPosted==null)firstPosted=Instant.now();
                        refresh(batch);
                        beat();Instant began=Instant.now();var b=batch(fixture(),batch,++sequence);var receipt=machine("/sensors/"+r.sensor()+"/observation-batches",b,r.sensorCredential());
                        assertThat(receipt.path("acceptedCount").asInt()).withFailMessage("receipt=%s",receipt).isEqualTo(batch.size());Instant accepted=Instant.now();
                        Instant consumeStart=Instant.now();
                        try(var profiled=GuardBatchProfile.batch(b.get("batchId").asText())){detection.consume(id(),"guard.observation.accepted",object("batchId",b.get("batchId")));}
                        Instant consumed=Instant.now();posted+=batch.size();
                        var found=action.call();
                        timing.add(object("sequence",sequence,"size",batch.size(),"startedAt",began.toString(),"millis",Duration.between(began,Instant.now()).toMillis(),"acceptMillis",Duration.between(began,accepted).toMillis(),"consumeMillis",Duration.between(consumeStart,consumed).toMillis(),
                                "maxLastPacketAt",batch.stream().map(o->o.path("lastPacketAt").asText()).max(String::compareTo).orElse(null),"targetExpiresAt",String.valueOf(expiresAt),"action",found!=null));
                        if(found!=null){actionSeenAt=Instant.now();mapped.flush();return found;}
                    }
                    if(lines.isEmpty()&&!live.isAlive()&&partial.isEmpty()){var found=action.call();return found;}
                    Thread.sleep(50);
                }
            }
            return action.call();
        }
        Fixture fixture(){return new Fixture(r.asset(),r.sensor(),r.sensorCredential(),r.executor(),r.executorCredential(),r.scope(),r.config(),r.configHash(),boot,null,r.capability(),null,null,null,r.authorization(),targetRef,null,null,null);}
        JsonNode diagnostics(Object assetId){
            var counts=new TreeMap<String,Integer>();
            for(var d:store.rows("guard_decision",map("asset_id",assetId),false,5000)){var e=json(d,"evidence_json");counts.merge(e.path("family").asText()+"/"+str(d,"decision")+"/"+e.path("reasonCode").asText(),1,Integer::sum);}
            return object("posted",posted,"leases",leases,"decisions",node(counts));
        }
        JsonNode summary(JsonNode segment)throws Exception{
            return object("segmentId",segment.path("segmentId"),"pcapSha256",segment.path("sha256"),"family",segment.path("family"),"servicePort",segment.path("servicePort"),
                    "observationsPosted",posted,"batches",sequence,"leases",leases,"leaseRefreshes",refreshes,"healthWindows",healthSequence,"firstPostedAt",String.valueOf(firstPosted),"actionSeenAt",String.valueOf(actionSeenAt),
                    "replayJsonlSha256",sha(Files.readAllBytes(dir.resolve("replay.jsonl"))),"mappedJsonlSha256",sha(Files.readAllBytes(dir.resolve("mapped.jsonl"))),
                    "mappedFields",node(new TreeSet<>(MAPPED)),"guardliveSha256",build);
        }
    }
}
