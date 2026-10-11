package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import java.nio.file.*;
import java.io.*;
import java.time.Instant;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/**
 * J1 离线参照 CLI：用同一 ONNX、规则和纯决策器按事件时间计算。
 * latest 跨桶淘汰旧 parent，保留未命中/降分/改类/final 替换事实；
 * 不使用数据库、标签、网络、执行器或未来快照，输出仅为研究证据。
 */
public final class GuardReplayReference {
    private GuardReplayReference() {}
    public static final class Projection {
        private final JsonNode policy,manifest,hypothetical;
        private final Map<String,JsonNode> latest=new HashMap<>();
        private final Map<String,String> latestStatus=new HashMap<>();
        private final Map<String,LinkedHashMap<String,GuardDecisionEngine.Evidence>> episodes=new LinkedHashMap<>();
        public Projection(JsonNode policy,JsonNode manifest,JsonNode closeout) {
            this.policy=policy;this.manifest=manifest;this.hypothetical=GuardReplayReadiness.policy(policy,closeout);
        }
        public JsonNode accept(JsonNode o,GuardModelRuntime.Result inference) {
            String parent=text(o,"parentConnectionId");latest.put(parent,o);latestStatus.put(parent,inference.status());
            var decisions=JSON.createArrayNode();
            for(JsonNode fp:policy.path("familyPolicies")) {
                String family=fp.path("family").asText();
                project(decisions,o,inference,family,"model","",false,family.equals(inference.family()));
            }
            var rules=JSON.createArrayNode();
            for(JsonNode rule:policy.path("rulePolicies")) {
                var result=GuardRules.evaluate(rule,o);String family=rule.path("family").asText(),ruleId=rule.path("ruleId").asText();
                rules.add(object("ruleId",ruleId,"family",family,"matched",result.matched(),"applicable",result.applicable(),"value",result.value()));
                project(decisions,o,inference,family,"rule",ruleId,result.matched(),result.matched());
            }
            return object("observationId",o.get("observationId"),"parentConnectionId",parent,"asOf",o.get("asOf"),
                    "inference",object("status",inference.status(),"score",inference.score(),"family",inference.family(),
                    "familyScores",inference.familyScores(),"applicability",inference.applicability(),"errorCode",inference.error()),
                    "rules",rules,"decisions",decisions);
        }
        private void project(com.fasterxml.jackson.databind.node.ArrayNode out,JsonNode o,GuardModelRuntime.Result inference,
                String family,String source,String ruleId,boolean matched,boolean create) {
            String scope=GuardDecisionEngine.familyPolicy(policy,family).path("scope").asText("peer_service");
            if(scope.equals("peer_inbound")&&!"inbound".equals(o.path("direction").asText()))scope="peer_service";
            String port=scope.equals("peer_inbound")?"":o.path("servicePort").asText("0");
            String key=String.join("|",o.path("assetId").asText(),o.path("sensorId").asText(),o.path("bootId").asText(),
                    o.path("peerKey").asText(),o.path("keyEpoch").asText(),o.path("direction").asText(),
                    o.path("transport").asText(),port,family,scope,source,ruleId,
                    Long.toString(time(o,"asOf").getEpochSecond()/30));
            var bucket=episodes.get(key);if(bucket==null){if(!create)return;bucket=new LinkedHashMap<>();episodes.put(key,bucket);}
            bucket.put(o.path("parentConnectionId").asText(),new GuardDecisionEngine.Evidence(o,
                    source.equals("model")?inference.score():null,source.equals("model")?inference.family():family,
                    source,ruleId,matched,hash(o)));
            var evidence=bucket.values().stream().filter(e->latest.get(e.observation().path("parentConnectionId").asText())
                    .path("observationId").equals(e.observation().path("observationId"))).toList();
            Instant now=time(o,"asOf");
            var actual=GuardDecisionEngine.evaluate(policy,evidence,now,
                    new GuardDecisionEngine.Gates(false,false,false,false,null),family,source,ruleId);
            boolean modelAvailable=evidence.stream().allMatch(e->"succeeded".equals(latestStatus.get(e.observation().path("parentConnectionId").asText())));
            var readiness=GuardReplayReadiness.evaluate(hypothetical,manifest,evidence,now,family,source,ruleId,modelAvailable);
            out.add(object("family",family,"source",source,"ruleId",ruleId,"scope",scope,
                    "decision",actual.decision(),"reasonCode",actual.reason(),"hypothetical",GuardReplayReadiness.proof(readiness),
                    "selected",evidence.stream().map(e->e.observation().path("observationId").asText()).toList()));
        }
    }
    public static void main(String[] args)throws Exception {
        if(args.length!=6)throw new IllegalArgumentException("参数: artifactRoot manifestRef policyRef closeoutRef observations output");
        var artifacts=new GuardArtifacts(args[0]);JsonNode manifest=artifacts.json(args[1],null);
        JsonNode policy=artifacts.json(args[2],null),closeout=artifacts.json(args[3],null);
        var model=map("manifest_ref",args[1],"manifest_sha256",hashFile(Path.of(args[0]).resolve(args[1])),
                "manifest_json",canonical(manifest),"artifact_sha256",text(manifest,"artifactSha256"),"validation_status","validated");
        var runtime=new GuardModelRuntime(artifacts,new GuardContracts(),2000);var projection=new Projection(policy,manifest,closeout);
        long count=0;Map<String,Integer> statuses=new TreeMap<>();
        try(var input=Files.newBufferedReader(Path.of(args[4]));var output=Files.newBufferedWriter(Path.of(args[5]),StandardOpenOption.CREATE_NEW)) {
            runtime.validate(model);String line;
            while((line=input.readLine())!=null) {
                JsonNode o=parse(line);require("research".equals(text(o,"environment"))&&o.path("targetRef").isNull(),"REPLAY_REAL_TARGET_FORBIDDEN");
                var result=runtime.infer(model,o,time(o,"asOf"));statuses.merge(result.status(),1,Integer::sum);
                output.write(canonical(projection.accept(o,result)));output.newLine();count++;
            }
        }finally{runtime.close();}
        System.out.println(canonical(object("observations",count,"statuses",statuses,"actionable",false)));
    }
    private static String hashFile(Path path)throws IOException{return sha(Files.readAllBytes(path));}
}
