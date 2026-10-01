package com.xyh.cybersecurity.response.application;

import com.fasterxml.jackson.databind.JsonNode;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import com.xyh.cybersecurity.response.ResponseService;
import com.xyh.cybersecurity.response.domain.ApprovalStateMachine;
import com.xyh.cybersecurity.response.infra.ResponseMapper;
import com.xyh.cybersecurity.security.SecurityAuditWriter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Set;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 审批决策事务边界；使用行锁和条件更新保证并发审批至多成功一次。 */
@Service
public class ApprovalDecisionService {

    private final ResponseMapper mapper;
    private final ResponseSupport support;
    private final SecurityAuditWriter securityAuditWriter;

    public ApprovalDecisionService(ResponseMapper mapper, ResponseSupport support,
                                   SecurityAuditWriter securityAuditWriter) {
        this.mapper = mapper;
        this.support = support;
        this.securityAuditWriter = securityAuditWriter;
    }

    @Transactional
    public ResponseService.ApprovalView decide(long id, String decision, String reason,
                                               IdentityPrincipal actor, HttpServletRequest request) {
        try {
            return decideInternal(id, decision, reason, actor, request);
        } catch (ApiRequestException exception) {
            securityAuditWriter.denied(request, SecurityContextHolder.getContext().getAuthentication(),
                    "response.approval.denied", exception.code());
            throw exception;
        }
    }

    /** 本人撤回待审申请。原审批列不伪造，条件更新与审批竞争时仅一方成功，审计和时间线同事务。 */
    @Transactional
    public ResponseService.ApprovalView withdraw(long id, String reason, IdentityPrincipal actor, HttpServletRequest request) {
        String summary = support.validatedReason(reason);
        var row = mapper.findApproval(id);
        if (row == null || !mapper.hasAssetPermission(actor.id(), "action.request", row.assetId())) throw ApiRequestException.notFound();
        if (row.requestedBy() != actor.id()) throw new AccessDeniedException("只有申请人可撤回");
        // 审批路径先锁事件再写审批行；撤回也遵守同一顺序，避免 timeline 的事件外键与审批行反向死锁。
        mapper.eventStatusForUpdate(row.eventId());
        if (mapper.withdraw(id, actor.id(), summary) != 1) throw ApiRequestException.conflict("仅待审批申请可以撤回");
        audit(actor.id(), "action.request.withdrawn", id, row.assetId(), request, summary);
        mapper.insertTimeline(row.eventId(), actor.id(), "action_request_withdrawn", id, "申请人撤回处置申请");
        return support.view(mapper.findApproval(id));
    }

    private ResponseService.ApprovalView decideInternal(long id, String decision, String reason,
                                                         IdentityPrincipal actor, HttpServletRequest request) {
        String summary = support.validatedReason(reason);
        if (!Set.of("approve", "reject").contains(decision)) throw ApiRequestException.badRequest("审批决定无效");
        ResponseMapper.ApprovalRow row = mapper.findApproval(id);
        if (row == null || !mapper.hasAssetPermission(actor.id(), "approval.decide", row.assetId())) {
            throw ApiRequestException.notFound();
        }
        if (row.requestedBy() == actor.id()) throw new AccessDeniedException("Action requester cannot review their own request");
        if (ApprovalStateMachine.isTerminal(row.status())) throw ApiRequestException.conflict("审批任务已被处理");
        if (!"pending".equals(row.status())) throw ApiRequestException.conflict("审批任务状态不允许该决定");
        if (!row.expiresAt().atOffset(ZoneOffset.UTC).toInstant().isAfter(support.clock().instant())) {
            throw ApiRequestException.conflict("审批任务已过期");
        }
        if (!mapper.eventContainsAssetForUpdate(row.eventId(), row.assetId())
                || !isOpenEvent(mapper.eventStatusForUpdate(row.eventId()))) {
            throw ApiRequestException.conflict("事件已变化，不能审批此动作");
        }
        JsonNode snapshot = support.parseJson(row.actionRequestJson());
        String actionType = snapshot.path("actionType").asText();
        long policyId = snapshot.path("policyId").asLong(-1);
        ResponseMapper.PolicyRow policy = mapper.findPolicyForUpdate(policyId);
        ResponseMapper.AssetRow asset = mapper.findAssetForUpdate(row.assetId());
        if (!support.policyMatches(policy, actionType, asset, snapshot.path("parameters"))
                || !policy.policyKey().equals(snapshot.path("policyKey").asText())
                || !policy.version().equals(snapshot.path("policyVersion").asText())
                || policy.maxDurationSeconds() != snapshot.path("policyMaxDurationSeconds").asInt(-1)
                || !policy.environment().equals(snapshot.path("policyEnvironment").asText())) {
            throw ApiRequestException.conflict("审批策略已失效");
        }
        if (!mapper.hasAssetPermission(actor.id(), "approval.decide", row.assetId())) {
            throw ApiRequestException.notFound();
        }
        requireCurrentAuthorization(row.assetId(), actionType);
        String status;
        try {
            status = ApprovalStateMachine.decide(row.status(), decision);
        } catch (IllegalArgumentException exception) {
            throw ApiRequestException.badRequest("审批决定无效");
        } catch (IllegalStateException exception) {
            throw ApiRequestException.conflict("审批任务已被处理");
        }
        int updated = mapper.updateApproval(id, status, actor.id(), summary, actor.id(), row.assetId(),
                actionType, policyId, row.eventId());
        if (updated != 1) throw ApiRequestException.conflict("审批任务已被其他请求更新");
        audit(actor.id(), "approval." + status, id, row.assetId(), request, "response request reviewed");
        mapper.insertTimeline(row.eventId(), actor.id(), "action_approval_" + status, id,
                "响应申请审批状态已更新");
        ResponseMapper.ApprovalRow result = mapper.findApproval(id);
        if (result == null) throw ApiRequestException.notFound();
        return support.view(result);
    }

    private void requireCurrentAuthorization(long assetId, String actionType) {
        ResponseMapper.AuthorizationRow authorization = mapper.findCurrentAuthorization(assetId, actionType);
        if (authorization == null || !support.authorizationScopeAllows(authorization.scopeJson(), actionType)) {
            throw ApiRequestException.conflict("目标资产当前没有覆盖该动作的有效授权");
        }
    }

    private void audit(long actorId, String action, long approvalId, long assetId,
                       HttpServletRequest request, String reason) {
        Object requestId = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        ResponseMapper.AuditInsert audit = new ResponseMapper.AuditInsert(
                LocalDateTime.ofInstant(support.clock().instant(), ZoneOffset.UTC), Long.toString(actorId),
                action, approvalId, requestId instanceof String value ? value : null, reason);
        mapper.insertAudit(audit);
        mapper.insertAuditResourceScope(audit.getId(), assetId);
    }

    private static boolean isOpenEvent(String status) {
        return Set.of("open", "investigating", "contained").contains(status);
    }
}
