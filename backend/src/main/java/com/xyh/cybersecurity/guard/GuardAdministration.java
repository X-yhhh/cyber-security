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
    public JsonNode asset(JsonNode b){access.permission("asset.manage",null);fields(b,"assetKey platform environment owner","displayName notes");
        require(Set.of("macos","windows","linux").contains(text(b,"platform"))&&Set.of("research","lab","authorized").contains(text(b,"environment")),"INVALID_ASSET_SCOPE");
        var values=map("asset_key",text(b,"assetKey"),"asset_type","host","environment",text(b,"environment"),"criticality","medium","owner",text(b,"owner"),"status","active","labels_json",canonical(object("platform",text(b,"platform"))));values.putAll(GuardMetadata.values(b));
        var row=store.add("asset",values);
        store.audit(access.human(),"guard.asset.created",str(row,"public_id"),number(row,"id"),null,b);return object("id",row.get("public_id"),"revision",1);}
    public JsonNode updateAsset(String id,JsonNode b,String revision){
        var a=store.external("asset",id,false);long aid=number(a,"id");access.permission("asset.manage",aid);a=store.lockAsset(aid);
        access.revision(a,revision);fields(b,"","owner criticality status labels displayName notes");
        var values=GuardMetadata.values(b);
        if(b.has("owner"))values.put("owner",text(b,"owner"));
        if(b.has("criticality")){require(Set.of("low","medium","high","critical").contains(text(b,"criticality")),"INVALID_ASSET_SCOPE");values.put("criticality",text(b,"criticality"));}
        String newStatus=null;
        if(b.has("status")){newStatus=text(b,"status");require(Set.of("active","disabled","retired").contains(newStatus),"INVALID_ASSET_SCOPE");
            if("retired".equals(str(a,"status"))&&!"retired".equals(newStatus))throw error(409,"STATE_CONFLICT");values.put("status",newStatus);}
        if(b.has("labels")){
            require(b.get("labels").isObject(),"INVALID_ASSET_SCOPE");
            var labels=((com.fasterxml.jackson.databind.node.ObjectNode)b.get("labels")).deepCopy();
            String platform=json(a,"labels_json").path("platform").asText("");
            if(labels.has("platform"))require(platform.equals(labels.path("platform").asText()),"INVALID_ASSET_SCOPE");
            else if(!platform.isEmpty())labels.put("platform",platform);
            values.put("labels_json",canonical(labels));
        }
        require(!values.isEmpty(),"INVALID_REQUEST");
        long nextRevision=number(a,"revision")+1;values.put("revision",nextRevision);values.put("updated_at",db(store.now()));
        store.update("asset",aid,values);
        if(newStatus!=null&&!"active".equals(newStatus)){
            for(var binding:store.rows("guard_asset_binding",map("asset_id",aid,"status","active"),true,100))
                store.update("guard_asset_binding",number(binding,"id"),map("status","suspended","revision",number(binding,"revision")+1));
        }
        store.audit(access.human(),"guard.asset.updated",id,aid,null,b);
        return object("id",id,"status",values.getOrDefault("status",a.get("status")),"criticality",values.getOrDefault("criticality",a.get("criticality")),"owner",values.getOrDefault("owner",a.get("owner")),
                "displayName",values.getOrDefault("display_name",a.get("display_name")),"notes",values.getOrDefault("notes",a.get("notes")),"revision",nextRevision);
    }
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
    public JsonNode machine(JsonNode b,boolean executor){fields(b,executor?"assetId platform capabilityProbeRef":"assetId platform captureScopeId","displayName notes");
        var a=store.external("asset",uuid(b,"assetId"),false);long aid=number(a,"id");access.permission("sensor.manage",aid);store.lockAsset(aid);String publicId=id();
        require(Set.of("macos","windows","linux").contains(text(b,"platform")),"CAPABILITY_NOT_SUPPORTED");
        var secret=new byte[32];new SecureRandom().nextBytes(secret);String token=Base64.getUrlEncoder().withoutPadding().encodeToString(secret);
        Map<String,Object> sensor=null;
        if(!executor){var values=map("public_id",publicId,"agent_key",publicId,"asset_id",aid,"platform",text(b,"platform"),"agent_version","v5-pending","capabilities_json","[]","credential_ref","database-sha256-verifier","status","active","registered_at",db(store.now()));values.putAll(GuardMetadata.values(b));sensor=store.insert("sensor_agent",values);}
        var client=store.add("api_client",map("client_key",publicId,"client_type",executor?"executor":"sensor","sensor_id",sensor==null?null:number(sensor,"id"),"secret_ref","database-sha256-verifier","credential_sha256",sha(token.getBytes(java.nio.charset.StandardCharsets.UTF_8)),"scope_json",canonical(object("assetId",a.get("public_id"))),"status","active"));
        for(String p:(executor?"machine.target.bind machine.command.claim machine.receipt.write machine.executor.health":"machine.observation.write machine.sensor.read machine.sensor.health").split(" "))mapper.grant(number(client,"id"),p);
        if(executor){var values=map("public_id",publicId,"asset_id",aid,"api_client_id",number(client,"id"),"platform",text(b,"platform"),"adapter_version","unverified","status","pending");values.putAll(GuardMetadata.values(b));store.insert("guard_executor",values);}
        store.audit(access.human(),executor?"guard.executor.created":"guard.sensor.created",publicId,aid,null,object("clientId",client.get("public_id")));
        return object("id",publicId,"clientId",client.get("public_id"),"credential","mch_"+client.get("id")+"."+token,"status",executor?"pending":"active","revision",1);}
    public JsonNode rotateMachine(String id,JsonNode b,boolean executor){
        fields(b,"","reason");String reason=b.has("reason")?text(b,"reason"):"credential_rotation";
        var machine=store.external(executor?"guard_executor":"sensor_agent",id,false);
        long aid=number(machine,"asset_id");access.permission("sensor.manage",aid);store.lockAsset(aid);
        machine=store.external(executor?"guard_executor":"sensor_agent",id,true);
        require(!"revoked".equals(str(machine,"status")),"STATE_CONFLICT");
        var client=executor?store.one("api_client",map("id",number(machine,"api_client_id")),true)
                :store.one("api_client",map("sensor_id",number(machine,"id")),true);
        require(client!=null&&("active".equals(str(client,"status"))||("revoked".equals(str(client,"status"))&&"active".equals(str(machine,"status")))),"STATE_CONFLICT");
        var randomBytes=new byte[32];new SecureRandom().nextBytes(randomBytes);String encoded=Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
        var nowInstant=store.now();var now=db(nowInstant);
        store.update("api_client",number(client,"id"),map("credential_sha256",sha(encoded.getBytes(java.nio.charset.StandardCharsets.UTF_8)),"rotated_at",now,"updated_at",now,
                "status","active","revoked_by",null,"revoked_at",null,"revoke_reason",null));
        store.audit(access.human(),executor?"guard.executor.credential.rotated":"guard.sensor.credential.rotated",id,aid,null,object("clientId",client.get("public_id"),"reason",reason));
        return object("id",id,"clientId",client.get("public_id"),"credential","mch_"+client.get("id")+"."+encoded,"rotatedAt",nowInstant.toString(),"status",machine.get("status"));
    }
    public JsonNode revokeClient(String id,JsonNode b){
        fields(b,"reason","");text(b,"reason");
        var client=store.external("api_client",id,false);
        Long aid=clientAsset(client);access.permission("sensor.manage",aid);
        if(aid!=null)store.lockAsset(aid);
        client=store.external("api_client",id,true);
        require(Set.of("active","disabled").contains(str(client,"status")),"STATE_CONFLICT");
        var now=db(store.now());
        store.update("api_client",number(client,"id"),map("status","revoked","revoked_by",access.human(),"revoked_at",now,"revoke_reason",text(b,"reason"),"updated_at",now));
        if(client.get("sensor_id")!=null){
            var sensor=store.one("sensor_agent",map("id",number(client,"sensor_id")),true);
            if(sensor!=null&&!"revoked".equals(str(sensor,"status")))
                store.update("sensor_agent",number(sensor,"id"),map("status","revoked","revision",number(sensor,"revision")+1));
        }
        var executor=store.one("guard_executor",map("api_client_id",number(client,"id")),true);
        if(executor!=null&&!"revoked".equals(str(executor,"status")))
            store.update("guard_executor",number(executor,"id"),map("status","revoked","revision",number(executor,"revision")+1));
        store.audit(access.human(),"guard.machine_client.revoked",id,aid,null,b);
        return object("id",id,"status","revoked");
    }
    private Long clientAsset(Map<String,Object> client){
        if(client.get("sensor_id")!=null)return number(store.get("sensor_agent",number(client,"sensor_id")),"asset_id");
        var executor=store.one("guard_executor",map("api_client_id",number(client,"id")),false);
        if(executor!=null)return number(executor,"asset_id");
        String assetId=json(client,"scope_json").path("assetId").asText("");
        return assetId.isEmpty()?null:number(store.external("asset",uuid(assetId),false),"id");
    }

    /** 机器资料只修改展示列；资产锁在机器行锁之前，避免与心跳、登记和凭据操作交错。 */
    public JsonNode updateMachine(String id,JsonNode body,String revision,boolean executor) {
        fields(body,"","displayName notes");var values=GuardMetadata.values(body);
        if(values.isEmpty())throw error(400,"INVALID_REQUEST");
        String table=executor?"guard_executor":"sensor_agent";
        var row=store.external(table,id,false);long aid=number(row,"asset_id");access.consolePermission("sensor.manage",aid);
        store.lockAsset(aid);row=store.external(table,id,true);access.revision(row,revision);
        long next=number(row,"revision")+1;values.put("revision",next);values.put("updated_at",db(store.now()));
        store.update(table,number(row,"id"),values);
        store.audit(access.human(),executor?"guard.executor.updated":"guard.sensor.updated",id,aid,null,body);
        return object("id",id,"revision",next,"status",row.get("status"),"displayName",values.getOrDefault("display_name",row.get("display_name")),
                "notes",values.getOrDefault("notes",row.get("notes")));
    }

    /** 停用同事务清除旧凭据校验值；启用只恢复登记状态，必须再轮换凭据，绝不复活旧令牌。 */
    public JsonNode machineStatus(String id,JsonNode body,String revision,boolean executor) {
        fields(body,"status reason","");String requested=text(body,"status");GuardMetadata.reason(body);
        if(!Set.of("active","disabled").contains(requested))throw error(400,"INVALID_REQUEST");
        String table=executor?"guard_executor":"sensor_agent";
        var row=store.external(table,id,false);long aid=number(row,"asset_id");access.consolePermission("sensor.manage",aid);
        var asset=store.lockAsset(aid);row=store.external(table,id,true);access.revision(row,revision);
        if("revoked".equals(str(row,"status")))throw error(409,"STATE_CONFLICT");
        var client=executor?store.one("api_client",map("id",number(row,"api_client_id")),true)
                :store.one("api_client",map("sensor_id",number(row,"id")),true);
        if(client==null)throw error(409,"STATE_CONFLICT");
        String status=requested.equals("active")?"active":executor?"suspended":"offline";
        if(status.equals(str(row,"status"))&&(requested.equals("active")||"revoked".equals(str(client,"status"))))
            throw error(409,"STATE_CONFLICT");
        if(requested.equals("active")&&!"active".equals(str(asset,"status")))throw error(409,"STATE_CONFLICT");
        var now=db(store.now());long next=number(row,"revision")+1;
        store.update(table,number(row,"id"),map("status",status,"revision",next,"updated_at",now,
                executor?"last_heartbeat":"last_heartbeat_at",null));
        store.update("api_client",number(client,"id"),map("status","revoked","credential_sha256",null,"revoked_by",access.human(),
                "revoked_at",now,"revoke_reason",GuardMetadata.reason(body),"updated_at",now));
        store.audit(access.human(),executor?"guard.executor.status.changed":"guard.sensor.status.changed",id,aid,null,body);
        return object("id",id,"status",status,"revision",next,"credentialRotationRequired",requested.equals("active"));
    }

    /** 只撤回本人的待批申请，不借撤回接口替代批准人对已生效授权的撤销职责。 */
    public JsonNode withdrawAuthorization(String id,JsonNode body,String revision) {
        fields(body,"reason","");GuardMetadata.reason(body);
        var row=store.external("asset_authorization",id,false);long aid=number(row,"asset_id");
        access.consolePermission("authorization.request",aid);store.lockAsset(aid);row=store.external("asset_authorization",id,true);
        access.revision(row,revision);
        if(number(row,"requested_by")!=access.human())throw error(403,"SCOPE_DENIED");
        if(!"pending".equals(str(row,"status")))throw error(409,"STATE_CONFLICT");
        long next=number(row,"revision")+1;
        store.update("asset_authorization",number(row,"id"),map("status","revoked","revision",next,"revoked_by",access.human(),
                "revoked_at",db(store.now()),"revoke_reason",GuardMetadata.reason(body)));
        store.audit(access.human(),"guard.authorization.withdrawn",id,aid,null,body);
        return object("id",id,"status","revoked","revision",next);
    }

    public JsonNode deleteConfig(String id,String revision) {
        var row=store.external("sensor_config",id,false);var sensor=store.get("sensor_agent",number(row,"sensor_id"));
        long aid=number(sensor,"asset_id");access.consolePermission("sensor.manage",aid);store.lockAsset(aid);
        row=store.external("sensor_config",id,true);access.revision(row,revision);
        if(row.get("requested_by")==null||number(row,"requested_by")!=access.human())throw error(403,"SCOPE_DENIED");
        if(!"draft".equals(str(row,"status")))throw error(409,"RESOURCE_IN_USE");
        store.deleteDraft("sensor_config",number(row,"id"));
        store.audit(access.human(),"guard.config.deleted",id,aid,null,object("contentSha256",row.get("content_sha256")));
        return object("id",id,"status","deleted","assetId",store.get("asset",aid).get("public_id"));
    }
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
