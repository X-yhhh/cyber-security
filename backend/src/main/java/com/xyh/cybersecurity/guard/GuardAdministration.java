package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.stereotype.Service;
import java.security.SecureRandom;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/** v2 资产、观察/执行授权及专用机器身份；登记与独立批准分离，不自动授予真实动作。 */
@Service
public class GuardAdministration {
    private final GuardStore store;private final GuardMapper mapper;private final GuardAccess access;private final GuardContracts contracts;
    public GuardAdministration(GuardStore store,GuardMapper mapper,GuardAccess access,GuardContracts contracts){this.store=store;this.mapper=mapper;this.access=access;this.contracts=contracts;}
    public JsonNode asset(JsonNode b){access.permission("asset.manage",null);fields(b,"assetKey platform environment owner","");
        require(Set.of("macos","windows").contains(text(b,"platform"))&&Set.of("research","lab","authorized").contains(text(b,"environment")),"INVALID_ASSET_SCOPE");
        var row=store.add("asset",map("asset_key",text(b,"assetKey"),"asset_type","host","environment",text(b,"environment"),"criticality","medium","owner",text(b,"owner"),"status","active","labels_json",canonical(object("platform",text(b,"platform")))));
        store.audit(access.human(),"guard.asset.created",str(row,"public_id"),number(row,"id"),null,b);return object("id",row.get("public_id"),"revision",1);}
    public JsonNode authorization(String assetId,JsonNode b){var a=store.external("asset",assetId,false);long aid=number(a,"id");access.permission("authorization.request",aid);store.lockAsset(aid);
        fields(b,"interfaces observationAllowed executionScopes validFrom validUntil evidenceRef","");
        require(b.path("interfaces").isArray()&&!b.path("interfaces").isEmpty()&&b.path("interfaces").size()<=16,"INVALID_AUTHORIZATION_SCOPE");
        for(var i:b.get("interfaces"))require(i.isTextual()&&i.asText().matches("[A-Za-z0-9_.:-]{1,96}"),"INVALID_INTERFACE_REFERENCE");
        bool(b,"observationAllowed");require(b.path("executionScopes").isArray()&&b.path("executionScopes").size()<=32,"INVALID_AUTHORIZATION_SCOPE");
        for(var s:b.get("executionScopes")){fields(s,"direction transport servicePort addressFamily capabilityId","scope");uuid(s,"capabilityId");executionScope(s);
            require(Set.of("inbound","outbound").contains(text(s,"direction"))&&"tcp".equals(text(s,"transport"))&&"ipv4".equals(text(s,"addressFamily")),"CAPABILITY_NOT_SUPPORTED");}
        var from=time(b,"validFrom");var until=time(b,"validUntil");require(until.isAfter(from)&&until.isAfter(store.now()),"AUTHORIZATION_INACTIVE");
        var row=store.add("asset_authorization",map("asset_id",aid,"authorization_ref",text(b,"evidenceRef"),"scope_json",canonical(b),"valid_from",db(from),"valid_until",db(until),"status","pending","requested_by",access.human()));
        store.audit(access.human(),"guard.authorization.requested",str(row,"public_id"),aid,null,b);return object("id",row.get("public_id"),"status","pending","revision",1);}
    public JsonNode approveAuthorization(String id,JsonNode b,String revision){var r=store.external("asset_authorization",id,false);long aid=number(r,"asset_id");access.permission("authorization.approve",aid);store.lockAsset(aid);r=store.external("asset_authorization",id,true);access.revision(r,revision);access.different(r,"requested_by");decisionBody(b);
        require("pending".equals(str(r,"status")),"STATE_CONFLICT");String status="approve".equals(text(b,"decision"))?"active":"revoked";
        store.update("asset_authorization",number(r,"id"),map("status",status,"approved_by",access.human(),"revision",number(r,"revision")+1));
        store.audit(access.human(),"guard.authorization."+status,id,aid,null,b);return object("id",id,"status",status,"revision",number(r,"revision")+1);}
    public JsonNode machine(JsonNode b,boolean executor){fields(b,executor?"assetId platform capabilityProbeRef":"assetId platform captureScopeId","");
        var a=store.external("asset",uuid(b,"assetId"),false);long aid=number(a,"id");access.permission("sensor.manage",aid);store.lockAsset(aid);String publicId=id();
        require(Set.of("macos","windows").contains(text(b,"platform")),"CAPABILITY_NOT_SUPPORTED");
        var secret=new byte[32];new SecureRandom().nextBytes(secret);String token=Base64.getUrlEncoder().withoutPadding().encodeToString(secret);
        Map<String,Object> sensor=null;
        if(!executor)sensor=store.insert("sensor_agent",map("public_id",publicId,"agent_key",publicId,"asset_id",aid,"platform",text(b,"platform"),"agent_version","v5-pending","capabilities_json","[]","credential_ref","database-sha256-verifier","status","active","registered_at",db(store.now())));
        var client=store.add("api_client",map("client_key",publicId,"client_type",executor?"executor":"sensor","sensor_id",sensor==null?null:number(sensor,"id"),"secret_ref","database-sha256-verifier","credential_sha256",sha(token.getBytes(java.nio.charset.StandardCharsets.UTF_8)),"scope_json",canonical(object("assetId",a.get("public_id"))),"status","active"));
        for(String p:(executor?"machine.target.bind machine.command.claim machine.receipt.write machine.executor.health":"machine.observation.write machine.sensor.read machine.sensor.health").split(" "))mapper.grant(number(client,"id"),p);
        if(executor)store.insert("guard_executor",map("public_id",publicId,"asset_id",aid,"api_client_id",number(client,"id"),"platform",text(b,"platform"),"adapter_version","unverified","status","pending"));
        store.audit(access.human(),executor?"guard.executor.created":"guard.sensor.created",publicId,aid,null,object("clientId",client.get("public_id")));
        return object("id",publicId,"clientId",client.get("public_id"),"credential","mch_"+client.get("id")+"."+token,"status",executor?"pending":"active");}
    public JsonNode config(String sensorId,JsonNode b){var s=store.external("sensor_agent",sensorId,false);long aid=number(s,"asset_id");access.permission("sensor.manage",aid);store.lockAsset(aid);
        fields(b,"contractVersion profileSha256 captureHealthVersion interfaceIds limits captureScopeId addressFamily buildSha256","");
        require(CONTRACT.equals(text(b,"contractVersion"))&&HEALTH_VERSIONS.contains(text(b,"captureHealthVersion"))&&contracts.profileHash().equals(digest(b,"profileSha256")),"CONTRACT_UNSUPPORTED");digest(b,"buildSha256");uuid(b,"captureScopeId");
        require(b.get("interfaceIds").isArray()&&b.get("interfaceIds").size()==1&&Set.of("ipv4","ipv6").contains(text(b,"addressFamily")),"INVALID_CAPTURE_SCOPE");
        fields(b.get("limits"),"maxBatchSize","");integer(b.get("limits"),"maxBatchSize",1,GuardContracts.MAX_BATCH_SIZE);
        String scopeKey=b.get("interfaceIds").get(0).asText();require(scopeKey.matches("[A-Za-z0-9_.:-]{1,96}"),"INVALID_INTERFACE_REFERENCE");
        var old=store.one("guard_capture_scope",map("public_id",text(b,"captureScopeId")),false);
        if(old!=null)require(number(old,"sensor_id")==number(s,"id")&&scopeKey.equals(str(old,"scope_key"))&&text(b,"addressFamily").equals(str(old,"address_family")),"SCOPE_DENIED");
        var row=store.add("sensor_config",map("sensor_id",number(s,"id"),"config_version",id(),"interface_scope_json",canonical(b.get("interfaceIds")),"filter_policy_json","{}","flow_window_seconds",30,"feature_contract_version",CONTRACT,"sampling_policy_json","{}","status","draft","requested_by",access.human(),"guard_definition_json",canonical(b),"content_sha256",hash(b)));
        if(old==null)store.insert("guard_capture_scope",map("public_id",text(b,"captureScopeId"),"asset_id",aid,"sensor_id",number(s,"id"),"scope_key",scopeKey,"address_family",text(b,"addressFamily"),"status","pending"));
        store.audit(access.human(),"guard.config.drafted",str(row,"public_id"),aid,null,b);return object("id",row.get("public_id"),"revision",1,"status","draft");}
    public JsonNode approveConfig(String id,JsonNode b,String revision){var c=store.external("sensor_config",id,false);var s=store.get("sensor_agent",number(c,"sensor_id"));long aid=number(s,"asset_id");access.permission("authorization.approve",aid);store.lockAsset(aid);c=store.external("sensor_config",id,true);access.revision(c,revision);access.different(c,"requested_by");decisionBody(b);require("draft".equals(str(c,"status"))&&!json(c,"guard_definition_json").isNull(),"STATE_CONFLICT");
        String status="approve".equals(text(b,"decision"))?"active":"rejected";
        if(status.equals("active")){
            JsonNode def=json(c,"guard_definition_json");observationAuthorization(aid,def.get("interfaceIds").get(0).asText());
            for(var old:store.rows("sensor_config",map("sensor_id",s.get("id"),"status","active"),true,100))store.update("sensor_config",number(old,"id"),map("status","retired","revision",number(old,"revision")+1));
            var scope=store.external("guard_capture_scope",text(def,"captureScopeId"),true);store.update("guard_capture_scope",number(scope,"id"),map("status","active","config_id",c.get("id")));
        }
        store.update("sensor_config",number(c,"id"),map("status",status,"approved_by",access.human(),"revision",number(c,"revision")+1));store.audit(access.human(),"guard.config."+status,id,aid,null,b);return object("id",id,"status",status,"revision",number(c,"revision")+1);}
    public Map<String,Object> observationAuthorization(long asset,String scopeKey){var now=store.now();for(var a:store.rows("asset_authorization",map("asset_id",asset,"status","active"),false,1000)){
        var s=json(a,"scope_json");if(!now.isBefore(instant(a.get("valid_from")))&&now.isBefore(instant(a.get("valid_until")))&&s.path("observationAllowed").asBoolean()&&contains(s.path("interfaces"),scopeKey))return a;}
        throw error(422,"AUTHORIZATION_INACTIVE");}
    /** 省略 scope 只兼容单服务；全部入站必须显式登记，且端口为空、方向为 inbound。 */
    public static void executionScope(JsonNode b){
        String scope=b.path("scope").asText("peer_service");require(Set.of("peer_service","peer_inbound").contains(scope),"INVALID_AUTHORIZATION_SCOPE");
        if(b.has("scope"))require(b.path("scope").isTextual(),"INVALID_AUTHORIZATION_SCOPE");
        if(scope.equals("peer_inbound"))require("inbound".equals(b.path("direction").asText())&&b.path("servicePort").isNull(),"INVALID_AUTHORIZATION_SCOPE");
        else integer(b,"servicePort",1,65535);
    }
    public static boolean contains(JsonNode a,String value){for(var v:a)if(value.equals(v.asText()))return true;return false;}
    public static void decisionBody(JsonNode b){fields(b,"decision reason","");require(Set.of("approve","reject").contains(text(b,"decision")),"INVALID_DECISION");text(b,"reason");}
}
