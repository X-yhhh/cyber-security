package com.xyh.cybersecurity.asset;

import com.xyh.cybersecurity.common.api.ApiRequestException;
import com.xyh.cybersecurity.audit.AuditMapper;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 处理资产登记、范围内变更和需要独立审批的资产授权。 */
@Service
public class AssetService {

    private final AssetMapper mapper;
    private final AuditMapper auditMapper;

    public AssetService(AssetMapper mapper, AuditMapper auditMapper) {
        this.mapper = mapper;
        this.auditMapper = auditMapper;
    }

    @Transactional
    public AssetMapper.AssetView create(CreateAssetRequest input, IdentityPrincipal actor, HttpServletRequest request) {
        requireGlobalPlatformAdmin(actor.id(), "asset.manage");
        if (input.assetKey().isBlank() || input.assetKey().length() > 128) {
            throw ApiRequestException.badRequest("资产标识无效");
        }
        try {
            mapper.insertAsset(new AssetMapper.AssetInsert(input.assetKey(), input.assetType(), input.environment(),
                    input.criticality(), input.owner(), input.labelsJson() == null ? "{}" : input.labelsJson()));
        } catch (org.springframework.dao.DuplicateKeyException exception) {
            throw ApiRequestException.conflict("资产标识已存在");
        }
        long id = mapper.findIdByKey(input.assetKey());
        audit(request, actor.id(), "asset.created", "asset", id, id, "success", "asset registered");
        return mapper.findVisible(actor.id(), id);
    }

    @Transactional
    public AssetMapper.AssetView update(long assetId, UpdateAssetRequest input, IdentityPrincipal actor,
                                        HttpServletRequest request) {
        if (mapper.updateVisible(actor.id(), assetId, input.criticality(), input.owner(), input.status()) == 0) {
            throw ApiRequestException.notFound();
        }
        if (mapper.findVisible(actor.id(), assetId) == null) throw ApiRequestException.notFound();
        audit(request, actor.id(), "asset.updated", "asset", assetId, assetId, "success", "scoped asset update");
        return mapper.findVisible(actor.id(), assetId);
    }

    @Transactional
    public AuthorizationView requestAuthorization(long assetId, AuthorizationRequest input, IdentityPrincipal actor,
                                                  HttpServletRequest request) {
        requireScoped(actor.id(), "asset.authorization.manage", assetId);
        if (input.authorizationRef() == null || input.authorizationRef().isBlank() || input.scopeJson() == null
                || input.validFrom() == null || input.validUntil() == null || !input.validUntil().isAfter(input.validFrom())) {
            throw ApiRequestException.badRequest("授权引用或有效期无效");
        }
        mapper.insertAuthorization(new AssetMapper.AuthorizationInsert(assetId, input.authorizationRef(), input.scopeJson(),
                input.validFrom(), input.validUntil(), actor.id()));
        long id = mapper.findAuthorizationId(assetId, actor.id(), input.authorizationRef());
        audit(request, actor.id(), "authorization.requested", "asset_authorization", id, assetId, "success", "pending approval");
        return findAuthorization(id);
    }

    @Transactional
    public AuthorizationView approveAuthorization(long assetId, long authorizationId, IdentityPrincipal actor,
                                                   HttpServletRequest request) {
        requireScoped(actor.id(), "asset.authorization.approve", assetId);
        AssetMapper.AuthorizationRow row = mapper.findAuthorizationForUpdate(authorizationId, assetId);
        if (row == null) throw ApiRequestException.notFound();
        if (row.requestedBy() == actor.id()) throw new org.springframework.security.access.AccessDeniedException("Self approval denied");
        if (!"pending".equals(row.status())) throw ApiRequestException.conflict("授权状态不可审批");
        Instant now = Instant.now();
        if (!row.validUntil().isAfter(now) || row.validFrom().isAfter(now)) {
            throw new ApiRequestException(org.springframework.http.HttpStatus.CONFLICT, "AUTHORIZATION_EXPIRED", "授权有效期已失效");
        }
        if (mapper.approveAuthorization(authorizationId, actor.id()) != 1) {
            throw ApiRequestException.conflict("授权状态已被其他请求更新");
        }
        audit(request, actor.id(), "authorization.approved", "asset_authorization", authorizationId, assetId, "success", "approved");
        return findAuthorization(authorizationId);
    }

    private AuthorizationView findAuthorization(long id) {
        AssetMapper.AuthorizationView value = mapper.findAuthorization(id);
        return value == null ? null : new AuthorizationView(value.id(), value.assetId(), value.status(),
                value.requestedBy(), value.approvedBy(), value.validFrom(), value.validUntil());
    }

    private void requireGlobalPlatformAdmin(long userId, String permission) {
        if (!mapper.hasGlobalPlatformAdmin(userId, permission)) {
            throw new org.springframework.security.access.AccessDeniedException("Global platform administrator required");
        }
    }

    private void requireScoped(long userId, String permission, long resourceId) {
        if (!hasScope(userId, permission, "asset", Long.toString(resourceId))
                && !hasScope(userId, permission, "global", "*")) throw ApiRequestException.notFound();
    }

    private boolean hasScope(long userId, String permission, String type, String id) {
        return mapper.hasScope(userId, permission, type, id);
    }

    private void audit(HttpServletRequest request, long actorId, String action, String resourceType, long resourceId,
                       long scopeId, String outcome, String reason) {
        Object requestId = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        AuditMapper.AuditInsert audit = new AuditMapper.AuditInsert(LocalDateTime.now(ZoneOffset.UTC), "human",
                Long.toString(actorId), action, resourceType, Long.toString(resourceId),
                requestId instanceof String value ? value : null, outcome, reason);
        auditMapper.insertAudit(audit);
        auditMapper.insertResourceScope(audit.getId(), "asset", Long.toString(scopeId));
    }

    public record CreateAssetRequest(String assetKey, String assetType, String environment, String criticality,
                                     String owner, String labelsJson) { }
    public record UpdateAssetRequest(String criticality, String owner, String status) { }
    public record AuthorizationRequest(String authorizationRef, String scopeJson, Instant validFrom, Instant validUntil) { }
    public record AuthorizationView(long id, long assetId, String status, long requestedBy, Long approvedBy,
                                    Instant validFrom, Instant validUntil) { }
}
