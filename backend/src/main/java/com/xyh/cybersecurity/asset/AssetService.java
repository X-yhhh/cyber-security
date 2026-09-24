package com.xyh.cybersecurity.asset;

import com.xyh.cybersecurity.common.api.ApiRequestException;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.core.PreparedStatementCreator;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.time.Instant;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 处理资产登记、范围内变更和需要独立审批的资产授权。 */
@Service
public class AssetService {

    private final JdbcTemplate jdbc;
    private final AssetMapper mapper;

    public AssetService(JdbcTemplate jdbc, AssetMapper mapper) {
        this.jdbc = jdbc;
        this.mapper = mapper;
    }

    @Transactional
    public AssetMapper.AssetView create(CreateAssetRequest input, IdentityPrincipal actor, HttpServletRequest request) {
        requireGlobalPlatformAdmin(actor.id(), "asset.manage");
        if (input.assetKey().isBlank() || input.assetKey().length() > 128) {
            throw ApiRequestException.badRequest("资产标识无效");
        }
        try {
            jdbc.update("INSERT INTO asset (asset_key, asset_type, environment, criticality, owner, status, labels_json) "
                            + "VALUES (?, ?, ?, ?, ?, 'active', ?)", input.assetKey(), input.assetType(), input.environment(),
                    input.criticality(), input.owner(), input.labelsJson() == null ? "{}" : input.labelsJson());
        } catch (org.springframework.dao.DuplicateKeyException exception) {
            throw ApiRequestException.conflict("资产标识已存在");
        }
        long id = jdbc.queryForObject("SELECT id FROM asset WHERE asset_key=?", Long.class, input.assetKey());
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
        jdbc.update("INSERT INTO asset_authorization (asset_id, authorization_ref, scope_json, valid_from, valid_until, "
                        + "status, requested_by) VALUES (?, ?, ?, ?, ?, 'pending', ?)", assetId,
                input.authorizationRef(), input.scopeJson(), Timestamp.from(input.validFrom()),
                Timestamp.from(input.validUntil()), actor.id());
        long id = jdbc.queryForObject("SELECT LAST_INSERT_ID()", Long.class);
        audit(request, actor.id(), "authorization.requested", "asset_authorization", id, assetId, "success", "pending approval");
        return findAuthorization(id);
    }

    @Transactional
    public AuthorizationView approveAuthorization(long assetId, long authorizationId, IdentityPrincipal actor,
                                                   HttpServletRequest request) {
        requireScoped(actor.id(), "asset.authorization.approve", assetId);
        AuthorizationRow row = jdbc.query("SELECT requested_by, valid_from, valid_until, status FROM asset_authorization "
                        + "WHERE id=? AND asset_id=?", rs -> rs.next() ? new AuthorizationRow(rs.getLong("requested_by"),
                        rs.getTimestamp("valid_from").toInstant(), rs.getTimestamp("valid_until").toInstant(),
                        rs.getString("status")) : null, authorizationId, assetId);
        if (row == null) throw ApiRequestException.notFound();
        if (row.requestedBy() == actor.id()) throw new org.springframework.security.access.AccessDeniedException("Self approval denied");
        if (!"pending".equals(row.status())) throw ApiRequestException.conflict("授权状态不可审批");
        Instant now = Instant.now();
        if (!row.validUntil().isAfter(now) || row.validFrom().isAfter(now)) {
            throw new ApiRequestException(org.springframework.http.HttpStatus.CONFLICT, "AUTHORIZATION_EXPIRED", "授权有效期已失效");
        }
        jdbc.update("UPDATE asset_authorization SET status='active', approved_by=?, updated_at=CURRENT_TIMESTAMP(3) "
                        + "WHERE id=? AND status='pending'", actor.id(), authorizationId);
        audit(request, actor.id(), "authorization.approved", "asset_authorization", authorizationId, assetId, "success", "approved");
        return findAuthorization(authorizationId);
    }

    private AuthorizationView findAuthorization(long id) {
        return jdbc.queryForObject("SELECT id, asset_id, status, requested_by, approved_by, valid_from, valid_until "
                        + "FROM asset_authorization WHERE id=?", (rs, n) -> new AuthorizationView(rs.getLong("id"),
                        rs.getLong("asset_id"), rs.getString("status"), rs.getLong("requested_by"),
                        rs.getObject("approved_by", Long.class), rs.getTimestamp("valid_from").toInstant(),
                        rs.getTimestamp("valid_until").toInstant()), id);
    }

    private void requireGlobalPlatformAdmin(long userId, String permission) {
        if (!hasScope(userId, permission, "global", "*") || jdbc.queryForObject("SELECT COUNT(*) FROM sys_user_role ur "
                        + "JOIN sys_role r ON r.id=ur.role_id WHERE ur.user_id=? AND r.role_key='platform_admin' "
                        + "AND ur.scope_type='global' AND ur.scope_id='*'", Integer.class, userId) == 0) {
            throw new org.springframework.security.access.AccessDeniedException("Global platform administrator required");
        }
    }

    private void requireScoped(long userId, String permission, long resourceId) {
        if (!hasScope(userId, permission, "asset", Long.toString(resourceId))
                && !hasScope(userId, permission, "global", "*")) throw ApiRequestException.notFound();
    }

    private boolean hasScope(long userId, String permission, String type, String id) {
        return Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS (SELECT 1 FROM sys_user_role ur "
                        + "JOIN sys_role r ON r.id=ur.role_id AND r.status='active' "
                        + "JOIN sys_role_permission rp ON rp.role_id=r.id JOIN sys_permission p ON p.id=rp.permission_id "
                        + "AND p.status='active' WHERE ur.user_id=? AND p.permission_key=? AND ur.scope_type=? AND ur.scope_id=?)",
                Boolean.class, userId, permission, type, id));
    }

    private void audit(HttpServletRequest request, long actorId, String action, String resourceType, long resourceId,
                       long scopeId, String outcome, String reason) {
        Object requestId = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        GeneratedKeyHolder keyHolder = new GeneratedKeyHolder();
        jdbc.update((Connection connection) -> {
            PreparedStatement statement = connection.prepareStatement("INSERT INTO audit_log "
                    + "(occurred_at, actor_type, actor_id, action, resource_type, resource_id, request_id, outcome, reason) "
                    + "VALUES (?, 'human', ?, ?, ?, ?, ?, ?, ?)", Statement.RETURN_GENERATED_KEYS);
            statement.setTimestamp(1, Timestamp.from(Instant.now()));
            statement.setString(2, Long.toString(actorId));
            statement.setString(3, action);
            statement.setString(4, resourceType);
            statement.setString(5, Long.toString(resourceId));
            statement.setString(6, requestId instanceof String value ? value : null);
            statement.setString(7, outcome);
            statement.setString(8, reason);
            return statement;
        }, keyHolder);
        jdbc.update("INSERT INTO audit_resource_scope (audit_id, scope_type, scope_id) VALUES (?, 'asset', ?)",
                keyHolder.getKey().longValue(), Long.toString(scopeId));
    }

    public record CreateAssetRequest(String assetKey, String assetType, String environment, String criticality,
                                     String owner, String labelsJson) { }
    public record UpdateAssetRequest(String criticality, String owner, String status) { }
    public record AuthorizationRequest(String authorizationRef, String scopeJson, Instant validFrom, Instant validUntil) { }
    public record AuthorizationView(long id, long assetId, String status, long requestedBy, Long approvedBy,
                                    Instant validFrom, Instant validUntil) { }
    private record AuthorizationRow(long requestedBy, Instant validFrom, Instant validUntil, String status) { }
}
