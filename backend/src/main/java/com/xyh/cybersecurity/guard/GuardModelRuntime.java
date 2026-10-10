package com.xyh.cybersecurity.guard;

import ai.onnxruntime.*;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.annotation.PreDestroy;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/** 冻结的 43+3 ONNX 入口；有界并发/超时，缺失 mask 独立，失败不切换模型或返回零风险。 */
@Component
public class GuardModelRuntime {
    private final GuardArtifacts artifacts;private final GuardContracts contracts;private final long timeoutMs;
    private final Semaphore slots=new Semaphore(2);
    private final ScheduledExecutorService timer=Executors.newSingleThreadScheduledExecutor(Thread.ofPlatform().daemon().name("guard-onnx-timeout").factory());
    public GuardModelRuntime(GuardArtifacts artifacts,GuardContracts contracts,@Value("${cyber.guard.inference-timeout-ms:2000}") long timeoutMs){this.artifacts=artifacts;this.contracts=contracts;require(timeoutMs>=1&&timeoutMs<=10000,"INVALID_INFERENCE_TIMEOUT");this.timeoutMs=timeoutMs;}
    @PreDestroy public void close(){timer.shutdownNow();}
    public JsonNode validate(Map<String,Object> model){Loaded l=load(model);try(var options=options();var session=OrtEnvironment.getEnvironment().createSession(l.onnx,options)){shape(session,l.manifest);return object("status","validated","runtimeVersion","1.23.2","numericFeatures",43,"categoricalFeatures",3,"familyScoreOrder",l.familyOrder,"artifactSha256",str(model,"artifact_sha256"));}catch(OrtException e){throw error(422,"ONNX_CONTRACT_INVALID");}}
    public Result infer(Map<String,Object> model,JsonNode observation,Instant now){
        JsonNode manifest=json(model,"manifest_json");String applicability=applicable(manifest,observation);
        if(applicability!=null)return new Result("not_applicable",null,null,Map.of(),applicability,applicability);
        if(!"validated".equals(str(model,"validation_status")))return new Result("failed",null,null,Map.of(),"unavailable","MODEL_UNAVAILABLE");
        if(!slots.tryAcquire())return new Result("failed",null,null,Map.of(),"unavailable","MODEL_CAPACITY_EXCEEDED");
        try {Loaded l=load(model);var env=OrtEnvironment.getEnvironment();
            try(var options=options();var session=env.createSession(l.onnx,options);var run=new OrtSession.RunOptions()){
                shape(session,manifest);Tensors t=tensors(observation,manifest,l.preprocessing);
                try(var values=OnnxTensor.createTensor(env,new float[][]{t.values});var missing=OnnxTensor.createTensor(env,new float[][]{t.missing});var codes=OnnxTensor.createTensor(env,new long[][]{t.codes})){
                    AtomicBoolean expired=new AtomicBoolean();ScheduledFuture<?> deadline=timer.schedule(()->{expired.set(true);try{run.setTerminate(true);}catch(OrtException ignored){}},timeoutMs,TimeUnit.MILLISECONDS);
                    try(var result=session.run(Map.of("numeric_values",values,"numeric_missing",missing,"categorical_codes",codes),Set.of("attack_score","family_scores"),run)){
                        if(expired.get())return new Result("failed",null,null,Map.of(),"unavailable","MODEL_TIMEOUT");
                        Object attack=result.get("attack_score").orElseThrow().getValue();Object families=result.get("family_scores").orElseThrow().getValue();
                        if(!(attack instanceof float[][] score)||score.length!=1||score[0].length!=1||!Float.isFinite(score[0][0])||score[0][0]<0||score[0][0]>1)return new Result("failed",null,null,Map.of(),"unavailable","MODEL_OUTPUT_INVALID");
                        if(!(families instanceof float[][] family)||family.length!=1||family[0].length!=l.familyOrder.size())return new Result("failed",null,null,Map.of(),"unavailable","MODEL_OUTPUT_INVALID");
                        Map<String,Double> familyScores=new LinkedHashMap<>();int selected=0;double sum=0;for(int i=0;i<family[0].length;i++){float v=family[0][i];if(!Float.isFinite(v)||v<0||v>1)return new Result("failed",null,null,Map.of(),"unavailable","MODEL_OUTPUT_INVALID");familyScores.put(l.familyOrder.get(i),(double)v);sum+=v;if(v>family[0][selected])selected=i;}
                        if(Math.abs(sum-score[0][0])>1e-5)return new Result("failed",null,null,Map.of(),"unavailable","MODEL_OUTPUT_INVALID");
                        return new Result("succeeded",(double)score[0][0],l.familyOrder.get(selected),Map.copyOf(familyScores),"supported",null);
                    }catch(OrtException e){return new Result("failed",null,null,Map.of(),"unavailable",expired.get()?"MODEL_TIMEOUT":"MODEL_UNAVAILABLE");}
                    finally{deadline.cancel(false);}
                }
            }
        }catch(com.xyh.cybersecurity.common.api.ApiRequestException e){return new Result("failed",null,null,Map.of(),"unavailable",e.code());}
        catch(Exception e){return new Result("failed",null,null,Map.of(),"unavailable","MODEL_UNAVAILABLE");}finally{slots.release();}
    }
    /** 后端始终以 ORT Java 1.23.2 加载；manifest 记录冻结时的导出/核验运行时，只接受已做 1.23.2 全量对拍的版本（P6 p6-l1-02：1.27.0 对 1.23.2）。 */
    static final Set<String> VERIFIED_EXPORT_RUNTIMES=Set.of("1.23.2","1.27.0");
    private Loaded load(Map<String,Object> model){String ref=str(model,"manifest_ref");JsonNode manifest=artifacts.json(ref,str(model,"manifest_sha256"));contracts.manifest(manifest);require(manifest.equals(json(model,"manifest_json")),"MODEL_MANIFEST_MISMATCH");
        require(VERIFIED_EXPORT_RUNTIMES.contains(manifest.at("/runtime/runtimeVersion").asText())&&manifest.at("/runtime/opset").asInt()==17,"MODEL_RUNTIME_UNSUPPORTED");
        JsonNode preprocessing=artifacts.json(GuardArtifacts.sibling(ref,"preprocessing.json"),text(manifest,"preprocessingSha256"));artifacts.read(GuardArtifacts.sibling(ref,"calibration.json"),text(manifest,"calibrationSha256"),1024*1024);
        require("train".equals(preprocessing.path("fitRole").asText())&&preprocessing.path("vocabularies").isArray()&&preprocessing.path("vocabularies").size()==3,"PREPROCESSING_INVALID");
        var order=new ArrayList<String>();for(JsonNode f:manifest.at("/outputContract/familyScoreOrder"))order.add(f.asText());
        byte[] onnx=artifacts.read(GuardArtifacts.sibling(ref,"model.onnx"),text(manifest,"artifactSha256"),128L*1024*1024);
        require(Long.valueOf(manifest.at("/runtime/opset").asLong()).equals(opsetImports(onnx).get("")),"ONNX_CONTRACT_INVALID");
        return new Loaded(onnx,preprocessing,manifest,order);}
    /** 只读 ModelProto.opset_import（字段 8）。ORT Java 不暴露图内 opset，manifest 声明须与图一致；同域重复声明（含同版本）即拒绝，"ai.onnx" 视同默认域。 */
    static Map<String,Long> opsetImports(byte[] b){
        var result=new LinkedHashMap<String,Long>();int[] p={0};
        while(p[0]<b.length){long key=varint(b,p,b.length);int wire=(int)(key&7);
            if(key>>>3!=8){skip(b,p,wire,b.length);continue;}
            require(wire==2,"ONNX_CONTRACT_INVALID");int size=length(b,p,b.length),end=p[0]+size;String domain="";Long version=null;
            while(p[0]<end){long k=varint(b,p,end);int w=(int)(k&7);
                if(k>>>3==1&&w==2){int n=length(b,p,end);domain=new String(b,p[0],n,java.nio.charset.StandardCharsets.UTF_8);p[0]+=n;}
                else if(k>>>3==2&&w==0)version=varint(b,p,end);
                else skip(b,p,w,end);}
            require(version!=null&&result.put(domain.equals("ai.onnx")?"":domain,version)==null,"ONNX_CONTRACT_INVALID");}
        return result;}
    private static long varint(byte[] b,int[] p,int end){long v=0;
        for(int shift=0;shift<64;shift+=7){require(p[0]<end,"ONNX_CONTRACT_INVALID");int x=b[p[0]++]&0xff;v|=(long)(x&127)<<shift;if(x<128)return v;}
        throw error(422,"ONNX_CONTRACT_INVALID");}
    private static int length(byte[] b,int[] p,int end){long n=varint(b,p,end);require(n>=0&&n<=end-p[0],"ONNX_CONTRACT_INVALID");return (int)n;}
    /** 组（3/4）已废弃且无法安全跳过，与非法线型一并拒绝。长度须先读出再移动位置，不能写成 p[0]+=length(...)。 */
    private static void skip(byte[] b,int[] p,int wire,int end){
        switch(wire){case 0->varint(b,p,end);case 1->{require(end-p[0]>=8,"ONNX_CONTRACT_INVALID");p[0]+=8;}
            case 2->{int n=length(b,p,end);p[0]+=n;}case 5->{require(end-p[0]>=4,"ONNX_CONTRACT_INVALID");p[0]+=4;}
            default->throw error(422,"ONNX_CONTRACT_INVALID");}}
    private OrtSession.SessionOptions options()throws OrtException{var o=new OrtSession.SessionOptions();o.setIntraOpNumThreads(1);o.setInterOpNumThreads(1);return o;}
    private void shape(OrtSession session,JsonNode manifest)throws OrtException{
        require(session.getInputNames().equals(Set.of("numeric_values","numeric_missing","categorical_codes"))&&session.getOutputNames().equals(Set.of("attack_score","family_scores")),"ONNX_CONTRACT_INVALID");
        for(var e:Map.of("numeric_values",43,"numeric_missing",43,"categorical_codes",3).entrySet()){
            var info=session.getInputInfo().get(e.getKey()).getInfo();require(info instanceof TensorInfo,"ONNX_CONTRACT_INVALID");var t=(TensorInfo)info;
            require(t.getShape().length==2&&(t.getShape()[0]<0||t.getShape()[0]==1)&&t.getShape()[1]==e.getValue()&&t.type==(e.getKey().equals("categorical_codes")?OnnxJavaType.INT64:OnnxJavaType.FLOAT),"ONNX_CONTRACT_INVALID");
        }
        outputShape(session,"attack_score",1);
        outputShape(session,"family_scores",manifest.at("/outputContract/familyScoreOrder").size());
    }
    /** 输出必须是单快照或动态 batch 的 float 张量，序列或额外 batch 不可解释为分数。 */
    private static void outputShape(OrtSession session,String name,int width)throws OrtException{
        var info=session.getOutputInfo().get(name).getInfo();require(info instanceof TensorInfo,"ONNX_CONTRACT_INVALID");var t=(TensorInfo)info;
        require(t.type==OnnxJavaType.FLOAT&&t.getShape().length==2&&(t.getShape()[0]<0||t.getShape()[0]==1)&&t.getShape()[1]==width,"ONNX_CONTRACT_INVALID");
    }
    public static String applicable(JsonNode manifest,JsonNode o){if(!GuardAdministration.contains(manifest.path("profiles"),o.path("profile").asText()))return "PROFILE_UNSUPPORTED";
        for(var s:manifest.path("supportedScope")){if(!s.path("addressFamily").equals(o.path("addressFamily"))||!s.path("transport").equals(o.path("transport"))||!s.path("direction").equals(o.path("direction")))continue;
            for(var c:o.path("contexts"))if(c.path("windowSeconds").asInt()==s.path("coverageWindowSeconds").asInt()&&c.path("coverageMs").asLong()>=s.path("minimumCoverageMs").asLong())return null;}
        return "MODEL_NOT_APPLICABLE";}
    public static Tensors tensors(JsonNode o,JsonNode manifest,JsonNode pre){float[] values=new float[43],missing=new float[43];long[] codes=new long[3];int i=0;
        for(var name:manifest.path("numericFeatures")){String[] part=name.asText().split("\\.");JsonNode v;if(part[0].equals("features"))v=o.path("features").path(part[1]);else{v=null;for(var c:o.path("contexts"))if(c.path("windowSeconds").asText().equals(part[1]))v=c.path(part[2]);}
            require(v!=null&&!v.isMissingNode(),"PROFILE_HASH_MISMATCH");if(v.isNull())missing[i]=1;else{values[i]=v.isBoolean()?(v.asBoolean()?1:0):(float)v.asDouble();require(Float.isFinite(values[i]),"MODEL_INPUT_INVALID");}i++;}
        i=0;for(var name:manifest.path("categoricalFeatures")){var vocab=pre.path("vocabularies").path(i);String value=o.path(name.asText()).asText();if(vocab.isObject()){codes[i]=vocab.path(value).asLong(0);require(codes[i]>=0&&codes[i]<=vocab.size(),"PREPROCESSING_INVALID");}else{int j=1;for(var entry:vocab){if(entry.asText().equals(value))codes[i]=j;j++;}}i++;}
        return new Tensors(values,missing,codes);}
    private record Loaded(byte[] onnx,JsonNode preprocessing,JsonNode manifest,List<String> familyOrder){}
    public record Tensors(float[] values,float[] missing,long[] codes){}
    public record Result(String status,Double score,String family,Map<String,Double> familyScores,String applicability,String error){}
}
