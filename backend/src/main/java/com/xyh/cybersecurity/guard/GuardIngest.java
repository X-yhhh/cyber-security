package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import org.springframework.stereotype.Service;
import java.time.*;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/** 机器观测 T1 事务：身份/版本整批拒绝，合法业务记录局部受理，证据与 outbox 原子落库。 */
@Service
public class GuardIngest {
    private final GuardStore store;private final GuardAccess access;private final GuardContracts contracts;private final GuardAdministration admin;
    public GuardIngest(GuardStore store,GuardAccess access,GuardContracts contracts,GuardAdministration admin){this.store=store;this.access=access;this.contracts=contracts;this.admin=admin;}
    public JsonNode config(String id){var s=access.sensor(id,"machine.sensor.read");var c=store.one("sensor_config",map("sensor_id",s.get("id"),"status","active"),false);
        require(c!=null&&!json(c,"guard_definition_json").isNull(),"CONFIG_INACTIVE");return object("configId",c.get("public_id"),"config",json(c,"guard_definition_json"),"configHash",c.get("content_sha256"),"serverTime",store.now().toString());}
    public JsonNode heartbeat(String id,JsonNode b){fields(b,"bootId version configHash lastSequence clockSkewMs","");var s=access.sensor(id,"machine.sensor.health");store.lockAsset(number(s,"asset_id"));uuid(b,"bootId");digest(b,"configHash");integer(b,"lastSequence",0,Long.MAX_VALUE);
        var c=store.one("sensor_config",map("sensor_id",s.get("id"),"status","active"),false);require(c!=null&&text(b,"configHash").equals(str(c,"content_sha256")),"CONFIG_INACTIVE");
        require(b.path("clockSkewMs").isNull()||b.path("clockSkewMs").isNumber(),"CLOCK_UNTRUSTED");
        store.update("sensor_agent",number(s,"id"),map("guard_boot_id",text(b,"bootId"),"agent_version",text(b,"version"),"last_heartbeat_at",db(store.now()),"revision",number(s,"revision")+1));return object("serverTime",store.now().toString());}
    public JsonNode batches(String id,JsonNode b){fields(b,"batchId bootId sequence configId contractVersion profileSha256 observations","");var s=access.sensor(id,"machine.observation.write");long aid=number(s,"asset_id");var a=store.lockAsset(aid);String boot=uuid(b,"bootId");String batchId=uuid(b,"batchId");long seq=integer(b,"sequence",1,Long.MAX_VALUE);
        require(boot.equals(str(s,"guard_boot_id")),"BOOT_ID_MISMATCH");
        var c=store.external("sensor_config",uuid(b,"configId"),false);require(number(c,"sensor_id")==number(s,"id")&&"active".equals(str(c,"status"))&&!json(c,"guard_definition_json").isNull(),"CONFIG_INACTIVE");
        require(CONTRACT.equals(text(b,"contractVersion"))&&contracts.profileHash().equals(text(b,"profileSha256")),"CONTRACT_UNSUPPORTED");
        require(b.path("observations").isArray()&&!b.get("observations").isEmpty()&&b.get("observations").size()<=json(c,"guard_definition_json").at("/limits/maxBatchSize").asInt(),"CAPACITY_EXCEEDED");
        String digest=hash(b);var old=store.one("guard_observation_batch",map("public_id",batchId),false);if(old==null)old=store.one("guard_observation_batch",map("sensor_id",s.get("id"),"boot_id",boot,"sequence_no",seq),false);
        if(old!=null){if(!digest.equals(str(old,"request_sha256")))throw error(409,"IDEMPOTENCY_CONFLICT");return json(old,"result_json");}
        JsonNode def=json(c,"guard_definition_json");var scope=store.external("guard_capture_scope",text(def,"captureScopeId"),false);require("active".equals(str(scope,"status")),"CAPTURE_SCOPE_INACTIVE");admin.observationAuthorization(aid,str(scope,"scope_key"));
        var batch=store.insert("guard_observation_batch",map("public_id",batchId,"sensor_id",s.get("id"),"asset_id",aid,"boot_id",boot,"sequence_no",seq,"config_id",c.get("id"),"request_sha256",digest,"result_json","{}"));
        int accepted=0,duplicates=0;ArrayNode rejects=JSON.createArrayNode();
        for(var o:b.get("observations")){
            // 身份属于整批安全边界，不可吞为部分失败。
            require(id.equals(o.path("sensorId").asText())&&str(a,"public_id").equals(o.path("assetId").asText())&&boot.equals(o.path("bootId").asText())
                    &&str(scope,"public_id").equals(o.path("captureScopeId").asText())&&str(a,"environment").equals(o.path("environment").asText()),"SCOPE_DENIED");
            try{contracts.observation(o);require(text(def,"addressFamily").equals(text(o,"addressFamily")),"SCOPE_DENIED");}
            catch(ApiRequestException ex){String oid=o.path("observationId").asText();if(!oid.matches("[0-9a-f-]{36}"))oid=null;
                store.add("guard_ingest_rejection",map("batch_id",batch.get("id"),"observation_external_id",oid,"reason_code",ex.code(),"content_sha256",hash(o)));rejects.add(object("observationId",oid,"code",ex.code()));continue;}
            var duplicate=store.one("guard_observation",map("public_id",text(o,"observationId")),false);
            if(duplicate==null)duplicate=store.one("guard_observation",map("sensor_id",s.get("id"),"boot_id",boot,"flow_id",text(o,"flowId"),"snapshot_index",o.get("snapshotIndex").longValue()),false);
            if(duplicate!=null){if(!hash(o).equals(str(duplicate,"content_sha256")))throw error(409,"IDEMPOTENCY_CONFLICT");duplicates++;continue;}
            store.insert("guard_observation",map("public_id",text(o,"observationId"),"batch_id",batch.get("id"),"sensor_id",s.get("id"),"asset_id",aid,"boot_id",boot,"capture_scope_id",scope.get("id"),"flow_id",text(o,"flowId"),"parent_connection_id",text(o,"parentConnectionId"),"snapshot_index",o.get("snapshotIndex").longValue(),"profile",text(o,"profile"),"as_of",db(time(o,"asOf")),"last_packet_at",db(time(o,"lastPacketAt")),"peer_key",text(o,"peerKey"),"key_epoch",o.get("keyEpoch").longValue(),"direction",text(o,"direction"),"transport",text(o,"transport"),"service_port",o.get("servicePort").isNull()?null:o.get("servicePort").intValue(),"environment",text(o,"environment"),"payload_json",canonical(o),"content_sha256",hash(o)));
            accepted++;
        }
        var result=object("batchId",batchId,"status","accepted","acceptedCount",accepted,"duplicateCount",duplicates,"rejectedCount",rejects.size(),"rejections",rejects);
        store.update("guard_observation_batch",number(batch,"id"),map("result_json",canonical(result)));if(accepted>0)store.outbox("guard.observation.accepted",batchId,object("batchId",batchId));return result;
    }
}
