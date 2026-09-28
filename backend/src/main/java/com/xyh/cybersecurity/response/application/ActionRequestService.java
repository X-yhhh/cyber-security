package com.xyh.cybersecurity.response.application;

import com.fasterxml.jackson.databind.JsonNode;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import com.xyh.cybersecurity.incident.IncidentMapper;
import com.xyh.cybersecurity.response.ResponseService;
import com.xyh.cybersecurity.response.infra.ResponseMapper;
import com.xyh.cybersecurity.security.SecurityAuditWriter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Set;
import java.util.UUID;

import org.springframework.security.core.context.SecurityContextHolder;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/**
 * 响应申请编排与执行拒绝边界。申请只创建审批台账，不调用外部适配器；所有安全条件由
 * ResponseMapper 在事务中再次复核，避免仅依赖控制器或客户端输入。
 */
@Service
public class ActionRequestService {

    private final ResponseMapper mapper;
    private final IncidentMapper incidentMapper;
    private final ResponseSupport support;
    private final SecurityAuditWriter securityAuditWriter;
    private final TransactionTemplate requiresNew;

    public ActionRequestService(ResponseMapper mapper, IncidentMapper incidentMapper,
                                ResponseSupport support, SecurityAuditWriter securityAuditWriter,
                                PlatformTransactionManager transactionManager) {
        this.mapper = mapper;
        this.incidentMapper = incidentMapper;
        this.support = support;
        this.securityAuditWriter = securityAuditWriter;
        this.requiresNew = new TransactionTemplate(transactionManager);
        this.requiresNew.setPropagationBehavior(org.springframework.transaction.TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    @Transactional
    public ResponseService.RequestResult request(long eventId, ResponseService.ActionRequest input,
                                                 String idempotencyKey, IdentityPrincipal actor,
                                                 HttpServletRequest request) {
        try {
            return requestInternal(eventId, input, idempotencyKey, actor, request);
        } catch (ApiRequestException exception) {
            securityAuditWriter.denied(request, SecurityContextHolder.getContext().getAuthentication(),
                    "response.request.denied", exception.code());
            throw exception;
        }
    }

    private ResponseService.RequestResult requestInternal(long eventId, ResponseService.ActionRequest input,
                                                           String idempotencyKey, IdentityPrincipal actor,
                                                           HttpServletRequest request) {
        String key = support.validateIdempotencyKey(idempotencyKey);
        String reason = support.validatedReason(input.reason());
        JsonNode parameters = support.canonicalNode(input.parameters());
        support.validateTemporaryBlockParameters(input.actionType(), parameters);
        requireAssetPermission(actor.id(), "action.request", input.assetId());
        if (incidentMapper.findVisibleEvent(actor.id(), eventId) == null
                || !mapper.eventContainsAsset(eventId, input.assetId())) {
            throw ApiRequestException.notFound();
        }
        if (!isOpenEvent(mapper.eventStatus(eventId))) {
            throw ApiRequestException.conflict("当前事件状态不允许提交响应申请");
        }

        String digest = support.sha256(support.actionSnapshot(eventId, input, parameters, reason, null));
        ResponseMapper.ApprovalRow existing = mapper.findByIdempotency(actor.id(), key);
        if (existing != null) return replayOrConflict(existing, digest);

        ResponseMapper.PolicyRow policy = mapper.findPolicy(input.policyId());
        ResponseMapper.AssetRow asset = mapper.findAsset(input.assetId());
        if (!support.policyMatches(policy, input.actionType(), asset, parameters)) {
            throw ApiRequestException.conflict("没有匹配且已批准的响应策略；申请未登记");
        }
        requireCurrentAuthorization(input.assetId(), input.actionType());
        String snapshot = support.actionSnapshot(eventId, input, parameters, reason, policy);
        ResponseMapper.ApprovalInsert insert = new ResponseMapper.ApprovalInsert(
                "action:" + UUID.randomUUID(), eventId, input.policyId(), snapshot, actor.id(), key,
                digest, support.utcNowPlusSeconds(15 * 60));
        try {
            mapper.insertApproval(insert);
        } catch (DuplicateKeyException exception) {
            ResponseMapper.ApprovalRow raced = mapper.findByIdempotency(actor.id(), key);
            if (raced == null) throw ApiRequestException.conflict("响应申请幂等键冲突");
            return replayOrConflict(raced, digest);
        }
        audit(actor.id(), "action.requested", insert.getId(), input.assetId(), request,
                "approval ledger only; execution unavailable");
        mapper.insertTimeline(eventId, actor.id(), "action_requested", insert.getId(),
                "响应申请已登记待审批；尚未执行");
        return new ResponseService.RequestResult(support.view(mapper.findApproval(insert.getId())), true);
    }

    /** 经过身份、请求者和资产范围校验后，明确拒绝；不创建 action_execution 记录。 */
    public RuntimeException rejectExecution(long id, IdentityPrincipal actor, HttpServletRequest request) {
        ResponseMapper.ApprovalRow row = mapper.findApproval(id);
        if (row == null || row.requestedBy() != actor.id()
                || !mapper.hasAssetPermission(actor.id(), "action.request", row.assetId())) {
            throw ApiRequestException.notFound();
        }
        requiresNew.executeWithoutResult(status -> audit(actor.id(), "action.execution.unavailable", id,
                row.assetId(), request, "adapter not configured; no action was executed"));
        return new ApiRequestException(HttpStatus.SERVICE_UNAVAILABLE, "ACTION_EXECUTION_UNAVAILABLE",
                "当前部署未配置经验证的响应适配器；动作未执行");
    }

    private ResponseService.RequestResult replayOrConflict(ResponseMapper.ApprovalRow existing, String digest) {
        if (!MessageDigest.isEqual(existing.requestDigest().getBytes(StandardCharsets.US_ASCII),
                digest.getBytes(StandardCharsets.US_ASCII))) {
            throw ApiRequestException.conflict("相同幂等键不能提交不同的响应申请");
        }
        return new ResponseService.RequestResult(support.view(existing), false);
    }

    private void requireCurrentAuthorization(long assetId, String actionType) {
        ResponseMapper.AuthorizationRow authorization = mapper.findCurrentAuthorization(assetId, actionType);
        if (authorization == null || !support.authorizationScopeAllows(authorization.scopeJson(), actionType)) {
            throw ApiRequestException.conflict("目标资产当前没有覆盖该动作的有效授权");
        }
    }

    private void requireAssetPermission(long userId, String permission, long assetId) {
        if (!mapper.hasAssetPermission(userId, permission, assetId)) throw ApiRequestException.notFound();
    }

    private void audit(long actorId, String action, long approvalId, long assetId,
                       HttpServletRequest request, String reason) {
        Object requestId = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        ResponseMapper.AuditInsert audit = new ResponseMapper.AuditInsert(
                LocalDateTime.ofInstant(support.clock().instant(), ZoneOffset.UTC),
                Long.toString(actorId), action, approvalId,
                requestId instanceof String value ? value : null, reason);
        mapper.insertAudit(audit);
        mapper.insertAuditResourceScope(audit.getId(), assetId);
    }

    private static boolean isOpenEvent(String status) {
        return Set.of("open", "investigating", "contained").contains(status);
    }
}
