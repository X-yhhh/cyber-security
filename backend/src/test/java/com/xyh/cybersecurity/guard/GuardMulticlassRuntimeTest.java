package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;
import static org.assertj.core.api.Assertions.*;

/** 仅使用固定双输出 ONNX 夹具；验证输出解释与失败边界，不读取训练/锁定测试集。 */
class GuardMulticlassRuntimeTest {
    @TempDir Path root;
    Map<String,Object> model(byte[] bytes)throws Exception{
        var manifest=(ObjectNode)GuardDomainTest.example("model-manifest");manifest.put("featureProfileSha256",new GuardContracts().profileHash());
        Files.write(root.resolve("model.onnx"),bytes);String pre=canonical(object("fitRole","train","vocabularies",List.of(List.of("tcp"),List.of("outbound"),List.of("web")))),cal="{}";
        Files.writeString(root.resolve("preprocessing.json"),pre);Files.writeString(root.resolve("calibration.json"),cal);
        manifest.put("artifactSha256",sha(bytes)).put("preprocessingSha256",sha(pre.getBytes(java.nio.charset.StandardCharsets.UTF_8))).put("calibrationSha256",sha(cal.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        ((ObjectNode)manifest.path("runtime")).put("runtimeVersion","1.23.2");Files.writeString(root.resolve("manifest.json"),canonical(manifest));
        return map("manifest_ref","manifest.json","manifest_sha256",sha(Files.readAllBytes(root.resolve("manifest.json"))),"manifest_json",canonical(manifest),"artifact_sha256",sha(bytes),"validation_status","validated");
    }
    @Test void fourOutputsFollowFrozenOrderAndSelectArgmax()throws Exception{
        var runtime=new GuardModelRuntime(new GuardArtifacts(root.toString()),new GuardContracts(),2000);
        try{
            var families=List.of("port_scan","brute_force","dos_flood","dos_slow");
            for(int i=0;i<4;i++){float[] scores=new float[4];scores[i]=.9f;var model=model(GuardOnnxFixture.model(.9f,scores));runtime.validate(model);
                var result=runtime.infer(model,GuardDomainTest.observation(Instant.EPOCH),Instant.EPOCH);assertThat(result.status()).isEqualTo("succeeded");assertThat(result.family()).isEqualTo(families.get(i));assertThat(result.familyScores()).hasSize(4);assertThat(result.score()).isCloseTo(.9,within(1e-6));}
        }finally{runtime.close();}
    }
    @Test void invalidProbabilityShapeAndArtifactNeverReturnRisk()throws Exception{
        var runtime=new GuardModelRuntime(new GuardArtifacts(root.toString()),new GuardContracts(),2000);
        try{
            for(float[] scores:List.of(new float[]{.4f,.4f,.4f,.4f},new float[]{Float.NaN,0,0,0},new float[]{-.1f,0,0,1},new float[]{1.1f,0,0,0})){
                var result=runtime.infer(model(GuardOnnxFixture.model(.9f,scores)),GuardDomainTest.observation(Instant.EPOCH),Instant.EPOCH);
                assertThat(result.error()).isEqualTo("MODEL_OUTPUT_INVALID");assertThat(result.score()).isNull();assertThat(result.familyScores()).isEmpty();
            }
            var badShape=model(GuardOnnxFixture.model(.9f,.9f));assertThatThrownBy(()->runtime.validate(badShape)).hasMessageContaining("ONNX_CONTRACT_INVALID");
            var valid=model(GuardOnnxFixture.model(.9f));Files.write(root.resolve("model.onnx"),new byte[]{1,2,3});assertThat(runtime.infer(valid,GuardDomainTest.observation(Instant.EPOCH),Instant.EPOCH).error()).isEqualTo("ARTIFACT_HASH_MISMATCH");
        }finally{runtime.close();}
    }
}
