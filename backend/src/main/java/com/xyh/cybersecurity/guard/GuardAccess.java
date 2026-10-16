package com.xyh.cybersecurity.guard;

import com.xyh.cybersecurity.identity.*;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/** 每次事务读取有效 IAM 事实；不凭客户端权限、旧 session 或独立范围笛卡尔积授权。 */
@Service
public class GuardAccess {
    private final GuardMapper mapper;private final GuardStore store;
    public GuardAccess(GuardMapper mapper,GuardStore store){this.mapper=mapper;this.store=store;}
    public long human(){var a=SecurityContextHolder.getContext().getAuthentication();if(a==null||!(a.getPrincipal() instanceof IdentityPrincipal p))throw error(403,"HUMAN_IDENTITY_REQUIRED");return p.id();}
    public void permission(String permission,Long asset){long actor=human();if(!mapper.permitted(actor,permission,asset==null?"global":"asset",asset==null?"*":asset.toString()))throw error(403,"SCOPE_DENIED");}
    public void feature(String permission){if(!mapper.hasFeature(human(),permission))throw error(403,"SCOPE_DENIED");}
    public void anyFeature(String... permissions){long actor=human();if(Arrays.stream(permissions).noneMatch(p->mapper.hasFeature(actor,p)))throw error(403,"SCOPE_DENIED");}
    /** 返回当前人工主体持有的第一个功能权限；都没有时 403，供“任一权限即可”的全局资料写入定位可见范围。 */
    public String firstFeature(String... permissions){long actor=human();return Arrays.stream(permissions).filter(p->mapper.hasFeature(actor,p)).findFirst().orElseThrow(()->error(403,"SCOPE_DENIED"));}
    /** B4 两级写鉴权：功能不足为 403，有功能但对象范围不覆盖为 404。 */
    public void consolePermission(String permission,Long asset){feature(permission);visible(permission,asset);}
    public void visible(String permission,Long asset){try{permission(permission,asset);}catch(com.xyh.cybersecurity.common.api.ApiRequestException e){throw error(404,"RESOURCE_NOT_FOUND");}}
    public MachinePrincipal machine(String kind,String permission){
        var a=SecurityContextHolder.getContext().getAuthentication();if(a==null||!(a.getPrincipal() instanceof MachinePrincipal p)||!kind.equals(p.clientType())||!mapper.machinePermission(p.id(),permission))throw error(403,"MACHINE_IDENTITY_REQUIRED");return p;
    }
    public Map<String,Object> sensor(String external,String permission){var p=machine("sensor",permission);var c=store.get("api_client",p.id());var s=store.external("sensor_agent",external,false);
        require(Objects.equals(c.get("sensor_id"),s.get("id")),"SCOPE_DENIED");require("active".equals(str(s,"status")),"SENSOR_INACTIVE");activeAsset(number(s,"asset_id"));return s;}
    public Map<String,Object> executor(String external,String permission){var p=machine("executor",permission);var e=store.external("guard_executor",external,false);
        require(number(e,"api_client_id")==p.id(),"SCOPE_DENIED");require(!"revoked".equals(str(e,"status")),"EXECUTOR_UNAVAILABLE");return e;}
    public Map<String,Object> activeAsset(long id){var a=store.get("asset",id);require("active".equals(str(a,"status")),"AUTHORIZATION_INACTIVE");return a;}
    public String subject(){var a=SecurityContextHolder.getContext().getAuthentication();if(a!=null&&a.getPrincipal() instanceof MachinePrincipal p)return "machine:"+p.id();return "human:"+human();}
    public void revision(Map<String,Object> row,String expected){if(expected==null||!expected.matches("[1-9][0-9]*")||!expected.equals(str(row,"revision")))throw error(409,"REVISION_CONFLICT");}
    public void different(Map<String,Object> row,String creator){if(number(row,creator)==human())throw error(403,"APPROVAL_SEPARATION_REQUIRED");}
}
