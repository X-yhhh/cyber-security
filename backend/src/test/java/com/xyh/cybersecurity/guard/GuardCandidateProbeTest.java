package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;
import static org.assertj.core.api.Assertions.*;

/**
 * T1.7 接口探针：用后端真实加载路径打开 scripts/p3/probe_candidate_interface.py 生成的探针目录。
 * 只在显式给出 -Dguard.probe.dir 时运行；探针制品位于忽略的 .cache，不进仓库，也不是可激活候选。
 * 抽样观察来自 validation，逐条对照 Python ONNX Runtime 输出，验证 43+3 张量构造与输出解释一致。
 */
@EnabledIfSystemProperty(named="guard.probe.dir",matches=".+")
class GuardCandidateProbeTest {
    @Test void probeLoadsAndMatchesPythonOutputs()throws Exception{
        Path root=Path.of(System.getProperty("guard.probe.dir")).toAbsolutePath();
        String manifest=Files.readString(root.resolve("manifest.json"));
        Map<String,Object> model=map("manifest_ref","manifest.json","manifest_sha256",sha(Files.readAllBytes(root.resolve("manifest.json"))),
                "manifest_json",manifest,"artifact_sha256",parse(manifest).path("artifactSha256").asText(),"validation_status","validated");
        var runtime=new GuardModelRuntime(new GuardArtifacts(root.toString()),new GuardContracts(),2000);
        try{
            JsonNode validated=runtime.validate(model);
            assertThat(validated.path("status").asText()).isEqualTo("validated");
            var families=List.of("port_scan","brute_force","dos_flood","dos_slow");
            int count=0;double maxError=0;
            for(String line:Files.readAllLines(root.resolve("backend-samples.jsonl"))){
                JsonNode sample=parse(line);
                var result=runtime.infer(model,sample.path("observation"),Instant.EPOCH);
                assertThat(result.status()).as("sample %d error %s",count,result.error()).isEqualTo("succeeded");
                maxError=Math.max(maxError,Math.abs(result.score()-sample.path("attackScore").asDouble()));
                int selected=0;
                for(int i=0;i<4;i++){double expected=sample.path("familyScores").path(i).asDouble();
                    maxError=Math.max(maxError,Math.abs(result.familyScores().get(families.get(i))-expected));
                    if(expected>sample.path("familyScores").path(selected).asDouble())selected=i;}
                assertThat(result.family()).isEqualTo(families.get(selected));
                count++;
            }
            assertThat(count).isPositive();
            assertThat(maxError).isLessThanOrEqualTo(1e-5);
            System.out.printf("T1.7 backend probe: validated, samples=%d, maxAbsError=%.3g%n",count,maxError);
        }finally{runtime.close();}
    }
}
