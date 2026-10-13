package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.stereotype.Service;
import java.time.*;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/** 健康旁证不属于特征：未知计数、迟到、间断与身份变化均不能证明冷却。 */
@Service
public class GuardHealth {
    private final GuardStore store;private final GuardAccess access;
    public GuardHealth(GuardStore store,GuardAccess access){this.store=store;this.access=access;}
    /** 版本决定字段白名单；旧版本不接受来源，新版本必须显式声明，不能默认补值。 */
    static void windowFields(JsonNode b){
        boolean v11=HEALTH_REPLAY.equals(b.path("healthVersion").asText());
        fields(b,"healthVersion healthWindowId assetId sensorId observerSessionId captureScopeId sequence intervalStart intervalEnd previousSha256 counterStart counterEnd captureGap clockSkewMs configSha256 buildSha256"+(v11?" captureSource":""),"metrics");
        require(HEALTH_VERSIONS.contains(text(b,"healthVersion")),"CONTRACT_UNSUPPORTED");
        if(v11)require(Set.of("live","file_replay").contains(text(b,"captureSource")),"CAPTURE_SOURCE_INVALID");
    }
    public JsonNode accept(String id,JsonNode b){
        windowFields(b);
        var sensor=access.sensor(id,"machine.sensor.health");long aid=number(sensor,"asset_id");var asset=store.lockAsset(aid);
        require(id.equals(uuid(b,"sensorId"))&&str(asset,"public_id").equals(uuid(b,"assetId")),"SCOPE_DENIED");
        var scope=store.external("guard_capture_scope",uuid(b,"captureScopeId"),false);require(number(scope,"sensor_id")==number(sensor,"id")&&"active".equals(str(scope,"status")),"SCOPE_DENIED");
        var config=store.get("sensor_config",number(scope,"config_id"));digest(b,"configSha256");digest(b,"buildSha256");
        require(text(b,"configSha256").equals(str(config,"content_sha256"))&&text(b,"buildSha256").equals(json(config,"guard_definition_json").path("buildSha256").asText()),"CONFIG_INACTIVE");
        String session=uuid(b,"observerSessionId"),publicId=uuid(b,"healthWindowId");long seq=integer(b,"sequence",1,Long.MAX_VALUE);Instant start=time(b,"intervalStart"),end=time(b,"intervalEnd"),now=store.now();
        require(start.isBefore(end)&&Duration.between(start,end).toNanos()<=5_000_000_000L,"INVALID_HEALTH_WINDOW");bool(b,"captureGap");
        require(b.path("previousSha256").isNull()||b.path("previousSha256").asText().matches("[0-9a-f]{64}"),"INVALID_HASH");
        for(String key:List.of("counterStart","counterEnd")){fields(b.get(key),"packetsSeen kernelDrops capacityDrops","");for(String f:List.of("packetsSeen","kernelDrops","capacityDrops"))if(!b.get(key).get(f).isNull())integer(b.get(key),f,0,9_007_199_254_740_991L);}
        if(b.has("metrics"))fields(b.get("metrics"),"","lateCount queueMax memoryBytes cpuPercent qualityCounts");
        String digest=hash(b);var old=store.one("guard_capture_health_window",map("public_id",publicId),false);if(old==null)old=store.one("guard_capture_health_window",map("sensor_id",sensor.get("id"),"observer_session_id",session,"sequence_no",seq),false);
        if(old!=null){if(!digest.equals(str(old,"content_sha256")))throw error(409,"IDEMPOTENCY_CONFLICT");return object("healthWindowId",old.get("public_id"),"verificationStatus",old.get("verification_status"),"contentSha256",digest);}
        var previous=store.one("guard_capture_health_window",map("sensor_id",sensor.get("id"),"observer_session_id",session,"sequence_no",seq-1),false);
        String status=verify(b,previous==null?null:json(previous,"payload_json"),previous==null?null:str(previous,"content_sha256"),now);
        store.insert("guard_capture_health_window",map("public_id",publicId,"sensor_id",sensor.get("id"),"asset_id",aid,"capture_scope_id",scope.get("id"),"observer_session_id",session,"sequence_no",seq,"interval_start",db(start),"interval_end",db(end),"previous_sha256",b.get("previousSha256").isNull()?null:b.get("previousSha256").asText(),"content_sha256",digest,"payload_json",canonical(b),"verification_status",status,"received_at",db(now)));
        if(!Set.of("healthy","replay_healthy").contains(status))store.audit(null,"guard.health.rejected",publicId,aid,null,object("reasonCode",status));
        return object("healthWindowId",publicId,"verificationStatus",status,"contentSha256",digest,"serverTime",now.toString());
    }
    public static String verify(JsonNode b,JsonNode previous,String previousHash,Instant now){
        boolean replay=HEALTH_REPLAY.equals(b.path("healthVersion").asText())&&"file_replay".equals(b.path("captureSource").asText());
        String accepted=replay?"replay_healthy":"healthy";
        Instant end=time(b,"intervalEnd");if(end.isAfter(now)||Duration.between(end,now).toMillis()>10000)return "HEALTH_DELAY_EXCEEDED";
        if(!b.path("clockSkewMs").isNumber()||Math.abs(b.path("clockSkewMs").asDouble())>1000)return "CLOCK_UNTRUSTED";
        if(b.path("captureGap").asBoolean())return "CAPTURE_GAP";
        for(String f:List.of("packetsSeen","kernelDrops","capacityDrops")){
            var start=b.path("counterStart").path(f);var finish=b.path("counterEnd").path(f);
            if(replay&&f.equals("kernelDrops")){if(!start.isNull()||!finish.isNull())return "REPLAY_KERNEL_DROPS_INVALID";continue;}
            if(start.isNull()||finish.isNull())return "COUNTER_UNKNOWN";
            if(finish.asLong()<start.asLong()||(!f.equals("packetsSeen")&&finish.asLong()!=start.asLong()))return "CAPTURE_DROPS";
        }
        if(b.path("sequence").asLong()==1)return b.path("previousSha256").isNull()?accepted:"HEALTH_CHAIN_INCOMPLETE";
        if(previous==null||!Objects.equals(previousHash,b.path("previousSha256").asText())||!time(previous,"intervalEnd").equals(time(b,"intervalStart")))return "HEALTH_CHAIN_INCOMPLETE";
        for(String f:List.of("observerSessionId","sensorId","assetId","captureScopeId","configSha256","buildSha256"))if(!previous.path(f).equals(b.path(f)))return "HEALTH_IDENTITY_CHANGED";
        if(!previous.path("healthVersion").equals(b.path("healthVersion"))||!previous.path("captureSource").equals(b.path("captureSource")))return "HEALTH_IDENTITY_CHANGED";
        if(!previous.path("counterEnd").equals(b.path("counterStart")))return "HEALTH_CHAIN_INCOMPLETE";
        return accepted;
    }
    public boolean current(long scope,Instant now){return current(scope,now,false);}
    /** 仅 T2 调用方可按已核验的正式 lab 归属启用回放状态；两参入口仍只认 healthy。 */
    public boolean current(long scope,Instant now,boolean replayAllowed){var r=store.one("guard_capture_health_window",map("capture_scope_id",scope),false);return r!=null&&("healthy".equals(str(r,"verification_status"))||(replayAllowed&&"replay_healthy".equals(str(r,"verification_status"))))&&!instant(r.get("interval_end")).isAfter(now)&&Duration.between(instant(r.get("interval_end")),now).toMillis()<=10000;}
    /** 返回覆盖 [from,through] 的完整认证链证明；不能拼接不同观察器、配置或捕获域。 */
    public JsonNode proof(long asset,Instant from,Instant earliestEnd,Instant now){
        var rows=new ArrayList<>(store.rows("guard_capture_health_window",map("asset_id",asset),false,10000));Collections.reverse(rows);
        List<JsonNode> chain=new ArrayList<>();Instant through=null;String session=null,scope=null,previousHash=null;JsonNode previous=null;
        for(var r:rows){JsonNode b=json(r,"payload_json");Instant start=time(b,"intervalStart"),end=time(b,"intervalEnd");if(end.isBefore(from)||end.equals(from))continue;
            boolean continuous=previous!=null&&Objects.equals(session,text(b,"observerSessionId"))&&Objects.equals(scope,text(b,"captureScopeId"))&&start.equals(through)&&Objects.equals(previousHash,b.path("previousSha256").asText())&&previous.path("counterEnd").equals(b.path("counterStart"));
            if(!"healthy".equals(str(r,"verification_status"))||(!chain.isEmpty()&&!continuous)){chain.clear();previous=null;through=null;}
            if(!"healthy".equals(str(r,"verification_status")))continue;
            if(chain.isEmpty()&&start.isAfter(from))continue;
            chain.add(object("healthWindowId",r.get("public_id"),"contentSha256",r.get("content_sha256")));through=end;previous=b;session=text(b,"observerSessionId");scope=text(b,"captureScopeId");previousHash=str(r,"content_sha256");
            if(!through.isBefore(earliestEnd)&&!through.isAfter(now)&&Duration.between(through,now).toMillis()<=10000)return object("healthVersion",HEALTH,"from",from.toString(),"through",through.toString(),"captureScopeId",scope,"observerSessionId",session,"windows",chain);
        }
        throw error(422,"HEALTH_CHAIN_INCOMPLETE");
    }
}
