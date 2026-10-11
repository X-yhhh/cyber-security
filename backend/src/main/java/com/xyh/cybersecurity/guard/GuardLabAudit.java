package com.xyh.cybersecurity.guard;

import com.xyh.cybersecurity.audit.AuditMapper;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/** 业务事务回滚后单独追加拒绝审计，只记录稳定错误码和已解析的资源范围。 */
@Service
public class GuardLabAudit {
    private final AuditMapper audit;
    private final GuardStore store;
    public GuardLabAudit(AuditMapper audit,GuardStore store) {this.audit=audit;this.store=store;}
    @Transactional(propagation=Propagation.REQUIRES_NEW)
    public void denied(String sessionId,String requestId,String code) {
        var auth=SecurityContextHolder.getContext().getAuthentication();
        if(auth==null||!(auth.getPrincipal() instanceof IdentityPrincipal actor))return;
        var row=sessionId==null?null:store.one("guard_validation_session",map("public_id",sessionId),false);
        var entry=new AuditMapper.AuditInsert(LocalDateTime.now(ZoneOffset.UTC),"human",Long.toString(actor.id()),
                "guard.lab.denied","guard",sessionId,requestId,"denied",code);
        audit.insertAudit(entry);
        if(row!=null)audit.insertResourceScope(entry.getId(),"asset",str(row,"asset_id"));
    }
}
