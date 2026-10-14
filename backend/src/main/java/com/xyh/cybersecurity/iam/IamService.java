package com.xyh.cybersecurity.iam;

import com.fasterxml.jackson.databind.JsonNode;
import com.xyh.cybersecurity.guard.GuardAccess;
import com.xyh.cybersecurity.guard.GuardMapper;
import com.xyh.cybersecurity.guard.GuardReadCursor;
import com.xyh.cybersecurity.identity.IdentityMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;
import java.util.function.Supplier;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/**
 * 身份应用边界：数据库现算权限、全局对象隐藏、互斥角色、本人保护与最后管理员保护。
 * 写入统一先锁平台管理员角色，再锁目标用户；幂等响应、修订、撤权和审计在同一事务提交。
 */
@Service
public class IamService {
    public static final Set<String> ROLES=Set.of("platform_admin","security_analyst","security_reviewer",
            "model_operator","evidence_reviewer","auditor");
    private final IamMapper mapper;
    private final IdentityMapper identity;
    private final GuardMapper guard;
    private final GuardAccess access;
    private final IamIdempotency idempotency;
    private final IamAudit audit;
    private final PasswordEncoder encoder;
    private final GuardReadCursor cursors;

    public IamService(IamMapper mapper,IdentityMapper identity,GuardMapper guard,GuardAccess access,
                      IamIdempotency idempotency,IamAudit audit,PasswordEncoder encoder,GuardReadCursor cursors) {
        this.mapper=mapper;this.identity=identity;this.guard=guard;this.access=access;
        this.idempotency=idempotency;this.audit=audit;this.encoder=encoder;this.cursors=cursors;
    }

    /** 摘要不信任登录时的 authority 快照；停用用户、角色、权限立即失效。 */
    public JsonNode me() {
        long actor=activeHuman();
        var user=mapper.user(actor);
        var roles=mapper.roles(actor);
        var bindings=mapper.bindings(actor).stream()
                .filter(b -> "active".equals(str(b,"role_status")) && validScope(b))
                .map(IamService::bindingView).toList();
        return object("id",actor,"username",str(user,"username"),"displayName",str(user,"display_name"),
                "roles",roles,"bindings",bindings,"permissions",mapper.permissions(actor));
    }

    public long activeHuman() {
        long actor=access.human();
        var user=mapper.user(actor);
        if(user==null || !"active".equals(str(user,"status"))) throw error(401,"UNAUTHENTICATED");
        return actor;
    }

    public JsonNode roles() {
        var permissions=mapper.permissions(activeHuman());
        if(!permissions.contains("iam.manage") && !permissions.contains("audit.read")) throw error(403,"SCOPE_DENIED");
        return node(mapper.directory().stream().map(r -> object("roleKey",str(r,"role_key"),"name",str(r,"name"),
                "description",str(r,"description"),"permissions",mapper.rolePermissions(number(r,"id")))).toList());
    }

    /** 前缀转义 LIKE 通配符；主体和全部筛选绑定加密游标，过滤发生在 LIMIT 之前。 */
    public JsonNode users(String status,String q,String cursor,int limit) {
        requireAdmin(false);
        if(limit<1 || limit>200) throw error(400,"INVALID_PAGE_SIZE");
        if(status!=null && !Set.of("active","disabled","locked").contains(status)) throw error(400,"INVALID_QUERY");
        if(q!=null && (q.isBlank() || q.length()>128)) throw error(400,"INVALID_QUERY");
        String binding=canonical(object("actor",access.human(),"collection","iam.users","status",status,"q",q));
        GuardReadCursor.Position position=cursor==null?null:cursors.decode(cursor,binding);
        long ceiling=position==null?mapper.ceiling():position.ceiling();
        String prefix=q==null?null:q.replace("!","!!").replace("%","!%").replace("_","!_")+"%";
        if(position!=null && mapper.user(position.id())==null) throw error(404,"RESOURCE_NOT_FOUND");
        var rows=mapper.users(status,prefix,ceiling,position==null?null:position.id(),limit+1);
        boolean more=rows.size()>limit;
        var page=rows.subList(0,Math.min(limit,rows.size()));
        LocalDateTime asOf=position==null?LocalDateTime.now(ZoneOffset.UTC):position.asOf();
        String next=more?cursors.encode(new GuardReadCursor.Position(ceiling,number(page.getLast(),"id"),asOf,asOf),binding):null;
        return object("items",page.stream().map(IamService::userView).toList(),"nextCursor",next);
    }

    public JsonNode user(long id) { requireAdmin(true);return userView(existingUser(id,false)); }
    public JsonNode bindings(long id) {
        requireAdmin(true);existingUser(id,false);
        return node(mapper.bindings(id).stream().map(IamService::bindingView).toList());
    }

    public JsonNode create(JsonNode body,String key,HttpServletRequest request) {
        fields(body,"username displayName password","");
        return write(key,body,null,201,false,request,() -> {
            String username=bounded(body,"username",64),display=bounded(body,"displayName",128);
            if(!username.matches("[A-Za-z0-9._-]{3,64}")) throw error(400,"INVALID_REQUEST");
            String password=password(body,"password"),userKey="usr_"+id().replace("-","");
            try { identity.insertUser(userKey,username,display,encoder.encode(password)); }
            catch(DuplicateKeyException e) { throw error(409,"CONFLICT"); }
            long user=identity.findUserIdByKey(userKey);
            audit.success(access.human(),"iam.user.create",Long.toString(user),"global","*","created_without_roles",request);
            return userView(existingUser(user,false));
        });
    }

    public JsonNode rename(long id,JsonNode body,String revision,String key,HttpServletRequest request) {
        fields(body,"displayName","");
        return write(key,body,revision,200,true,request,() -> {
            var row=mutableUser(id);checkRevision(row,revision);
            mapper.rename(id,bounded(body,"displayName",128));
            audit.success(access.human(),"iam.user.profile.update",Long.toString(id),"global","*","display_name_updated",request);
            return userView(existingUser(id,false));
        });
    }

    public JsonNode status(long id,JsonNode body,String revision,String key,HttpServletRequest request) {
        fields(body,"status reason","");
        return write(key,body,revision,200,true,request,() -> {
            var row=mutableUser(id);checkRevision(row,revision);
            String status=bounded(body,"status",24),reason=bounded(body,"reason",1000);
            if(!Set.of("active","disabled").contains(status)) throw error(400,"INVALID_REQUEST");
            if(status.equals(str(row,"status"))) throw error(409,"USER_STATUS_CONFLICT");
            if(status.equals("disabled")) protectLastAdmin(id);
            mapper.status(id,status);identity.deleteSession(str(row,"username"));
            audit.success(access.human(),"iam.user."+(status.equals("active")?"enabled":"disabled"),Long.toString(id),
                    "global","*",reason,request);
            return userView(existingUser(id,false));
        });
    }

    public JsonNode reset(long id,JsonNode body,String key,HttpServletRequest request) {
        fields(body,"newPassword reason","");
        return write(key,body,null,200,true,request,() -> {
            var row=mutableUser(id);
            String reason=bounded(body,"reason",1000);
            mapper.password(id,encoder.encode(password(body,"newPassword")));
            identity.deleteSession(str(row,"username"));
            audit.success(access.human(),"iam.user.password.reset",Long.toString(id),"global","*",reason,request);
            return userView(existingUser(id,false));
        });
    }

    public JsonNode bind(long user,JsonNode body,String key,HttpServletRequest request) {
        fields(body,"roleKey scopeType scopeId","");
        return write(key,body,null,201,true,request,() -> {
            var target=mutableUser(user);
            String role=bounded(body,"roleKey",64),scope=bounded(body,"scopeType",32),scopeId=bounded(body,"scopeId",128);
            var row=mapper.role(role);
            if(row==null) throw error(422,"ROLE_UNKNOWN");
            if(!"active".equals(str(row,"status"))) throw error(422,"ROLE_DISABLED");
            if(!ROLES.contains(role)) throw error(422,"ROLE_UNKNOWN");
            if(!((scope.equals("global") && scopeId.equals("*")) ||
                    (scope.equals("asset") && scopeId.matches("[1-9][0-9]{0,18}")))) throw error(400,"INVALID_SCOPE");
            if(scope.equals("asset") && !mapper.assetExists(scopeId)) throw error(404,"RESOURCE_NOT_FOUND");
            for(var existing:mapper.bindings(user)) {
                if("active".equals(str(existing,"role_status")) && conflicts(role,str(existing,"role_key")))
                    throw error(409,"ROLE_CONFLICT");
            }
            var inserted=map("user_id",user,"role_id",number(row,"id"),"scope_type",scope,"scope_id",scopeId);
            try { mapper.bind(inserted); }
            catch(DuplicateKeyException e) { throw error(409,"BINDING_EXISTS"); }
            mapper.touch(user);identity.deleteSession(str(target,"username"));
            long binding=number(inserted,"id");
            audit.success(access.human(),"iam.binding.create",Long.toString(binding),scope,scopeId,
                    canonical(object("userId",user,"roleKey",role,"scopeType",scope,"scopeId",scopeId)),request);
            return bindingView(mapper.binding(binding));
        });
    }

    public JsonNode revoke(long binding,JsonNode body,String key,HttpServletRequest request) {
        fields(body,"reason","");
        return write(key,body,null,200,true,request,() -> {
            var row=mapper.binding(binding);
            if(row==null) throw error(404,"RESOURCE_NOT_FOUND");
            long user=number(row,"user_id");
            var target=mutableUser(user);
            String reason=bounded(body,"reason",1000);
            if("platform_admin".equals(str(row,"role_key")) && "global".equals(str(row,"scope_type"))
                    && "*".equals(str(row,"scope_id"))) protectLastAdmin(user);
            audit.success(access.human(),"iam.binding.revoke",Long.toString(binding),str(row,"scope_type"),str(row,"scope_id"),
                    canonical(object("userId",user,"roleKey",str(row,"role_key"),"reasonSha256",sha(reason.getBytes(StandardCharsets.UTF_8)))),request);
            mapper.revoke(binding);mapper.touch(user);identity.deleteSession(str(target,"username"));
            return object("id",binding,"status","revoked");
        });
    }

    private JsonNode write(String key,JsonNode body,String revision,int status,boolean single,HttpServletRequest request,
                           Supplier<JsonNode> work) {
        return idempotency.execute("human:"+access.human(),request.getMethod()+":"+request.getRequestURI(),key,body,revision,status,
                () -> { identity.lockPlatformAdminRole();requireAdmin(single); },work);
    }

    private void requireAdmin(boolean single) {
        long actor=activeHuman();
        if(!mapper.permissions(actor).contains("iam.manage")) throw error(403,"SCOPE_DENIED");
        if(!guard.permitted(actor,"iam.manage","global","*")) throw error(single?404:403,single?"RESOURCE_NOT_FOUND":"SCOPE_DENIED");
    }

    private Map<String,Object> existingUser(long id,boolean lock) {
        var row=lock?mapper.lockUser(id):mapper.user(id);
        if(row==null) throw error(404,"RESOURCE_NOT_FOUND");
        return row;
    }

    private Map<String,Object> mutableUser(long id) {
        if(access.human()==id) throw error(403,"SELF_ADMINISTRATION_FORBIDDEN");
        return existingUser(id,true);
    }

    private void protectLastAdmin(long user) {
        if(identity.isGlobalPlatformAdmin(user) && identity.lockActiveGlobalPlatformAdministratorIds().size()<=1)
            throw error(409,"LAST_ADMIN_REQUIRED");
    }

    private static void checkRevision(Map<String,Object> row,String revision) {
        if(revision==null || !revision.equals(str(row,"revision"))) throw error(409,"REVISION_CONFLICT");
    }

    private boolean validScope(Map<String,Object> row) {
        return ("global".equals(str(row,"scope_type")) && "*".equals(str(row,"scope_id"))) ||
                ("asset".equals(str(row,"scope_type")) && mapper.assetExists(str(row,"scope_id")));
    }

    static boolean conflicts(String left,String right) {
        if(left.equals(right)) return false;
        if(left.equals("auditor") || right.equals("auditor")) return true;
        Set<String> pair=Set.of(left,right);
        return (pair.contains("security_reviewer") && pair.stream().anyMatch(Set.of("platform_admin","security_analyst","model_operator")::contains))
                || pair.equals(Set.of("evidence_reviewer","security_analyst"));
    }

    static String bounded(JsonNode body,String field,int max) {
        String value=text(body,field).trim();
        if(value.isEmpty() || value.length()>max) throw error(400,"INVALID_REQUEST");
        return value;
    }

    static String password(JsonNode body,String field) {
        String value=text(body,field);
        if(value.isBlank() || value.length()<12 || value.length()>128 || value.getBytes(StandardCharsets.UTF_8).length>72)
            throw error(400,"INVALID_REQUEST");
        return value;
    }

    private static JsonNode userView(Map<String,Object> row) {
        return object("id",number(row,"id"),"username",str(row,"username"),"displayName",str(row,"display_name"),
                "status",str(row,"status"),"revision",number(row,"revision"));
    }

    private static JsonNode bindingView(Map<String,Object> row) {
        return object("id",number(row,"id"),"roleKey",str(row,"role_key"),"scopeType",str(row,"scope_type"),"scopeId",str(row,"scope_id"));
    }
}
