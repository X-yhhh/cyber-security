package com.xyh.cybersecurity.iam;

import com.xyh.cybersecurity.audit.AuditMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 只追加脱敏动作事实及资源范围；调用方不得传入口令或整个请求载荷。 */
@Service
public class IamAudit {
    private final AuditMapper mapper;
    public IamAudit(AuditMapper mapper) { this.mapper=mapper; }

    public void success(long actor,String action,String resource,String scopeType,String scopeId,
                        String proof,HttpServletRequest request) {
        append(actor,action,resource,scopeType,scopeId,"success",proof,request);
    }

    /** 登录失败不能随成功路径的幂等事务回滚；只记录稳定原因码。 */
    @Transactional(propagation=Propagation.REQUIRES_NEW)
    public void loginDenied(String reason,HttpServletRequest request) {
        append(null,"auth.login",null,"global","*","denied",reason,request);
    }

    private void append(Long actor,String action,String resource,String scopeType,String scopeId,
                        String outcome,String proof,HttpServletRequest request) {
        var row=new AuditMapper.AuditInsert(LocalDateTime.now(ZoneOffset.UTC),"human",
                actor==null?null:actor.toString(),action,"iam",resource,
                (String)request.getAttribute(REQUEST_ID_ATTRIBUTE),outcome,proof);
        mapper.insertAudit(row);
        mapper.insertResourceScope(row.getId(),scopeType,scopeId);
    }
}
