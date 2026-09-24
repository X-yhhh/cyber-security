package com.xyh.cybersecurity.model;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.URI;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 登记不可变候选模型及分离的发布审查请求；不读取制品引用的内容。 */
@Service
public class ModelService {

    private final JdbcTemplate jdbc;
    private final ObjectMapper objectMapper;

    public ModelService(JdbcTemplate jdbc, ObjectMapper objectMapper) {
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
    }

    public Page list(long userId, int page, int size) {
        int offset = checkedOffset(page, size);
        long total = jdbc.queryForObject("SELECT COUNT(*) FROM model_version mv WHERE EXISTS ("
                + scopedModelPermissionSql() + ")", Long.class, userId, "model.validation.read");
        List<ModelView> items = jdbc.query("SELECT mv.id,mv.model_key,mv.version,mv.task_type,mv.manifest_version,"
                        + "CAST(mv.manifest_json AS CHAR) manifest_json,mv.artifact_ref,mv.artifact_sha256,"
                        + "mv.feature_contract_version,mv.approval_status,mv.created_at FROM model_version mv WHERE EXISTS ("
                        + scopedModelPermissionSql() + ") ORDER BY mv.created_at DESC,mv.id DESC LIMIT ? OFFSET ?",
                (rs, row) -> modelView(rs.getLong("id"), rs.getString("model_key"), rs.getString("version"),
                        rs.getString("task_type"), rs.getString("manifest_version"), rs.getString("manifest_json"),
                        rs.getString("artifact_ref"), rs.getString("artifact_sha256"),
                        rs.getString("feature_contract_version"), rs.getString("approval_status"),
                        rs.getTimestamp("created_at").toLocalDateTime()), userId, "model.validation.read", size, offset);
        return new Page(total, page, size, items);
    }

    public ModelView get(long userId, long modelId) {
        ModelRow row = findVisibleModel(userId, modelId, "model.validation.read");
        if (row == null) throw ApiRequestException.notFound();
        return row.view();
    }

    @Transactional
    public ModelView register(CandidateRequest input, IdentityPrincipal actor, HttpServletRequest request) {
        validateCandidate(input);
        requireModelScope(actor.id(), "model.candidate.manage", input.modelKey());
        String manifest = canonicalObject(input.manifest());
        try {
            jdbc.update("INSERT INTO model_version (model_key,version,task_type,manifest_version,manifest_json,"
                            + "artifact_ref,artifact_sha256,feature_contract_version,approval_status) "
                            + "VALUES (?,?,?,?,?,?,?,?, 'candidate')", input.modelKey(), input.version(), input.taskType(),
                    input.manifestVersion(), manifest, input.artifactRef(), input.artifactSha256().toLowerCase(Locale.ROOT),
                    input.featureContractVersion());
        } catch (org.springframework.dao.DuplicateKeyException exception) {
            throw ApiRequestException.conflict("该模型版本已登记；候选元数据不可覆盖");
        }
        long id = jdbc.queryForObject("SELECT id FROM model_version WHERE model_key=? AND version=?", Long.class,
                input.modelKey(), input.version());
        audit(actor.id(), "model.candidate.registered", "model_version", id, input.modelKey(), request,
                "candidate metadata registered");
        return findVisibleModel(actor.id(), id, "model.validation.read").view();
    }

    @Transactional
    public ReleaseView requestRelease(long modelId, String reason, IdentityPrincipal actor, HttpServletRequest request) {
        String summary = validatedReason(reason);
        ModelRow model = findVisibleModel(actor.id(), modelId, "model.release.request");
        if (model == null) throw ApiRequestException.notFound();
        if (!"candidate".equals(model.approvalStatus())) {
            throw ApiRequestException.conflict("只有候选模型可提交审查");
        }
        if (jdbc.queryForObject("SELECT COUNT(*) FROM model_release_record WHERE model_version_id=? "
                + "AND review_status='pending'", Integer.class, modelId) > 0) {
            throw ApiRequestException.conflict("该模型已有待审查申请");
        }
        jdbc.update("INSERT INTO model_release_record (model_version_id,release_status,review_status,requested_by,request_reason) "
                + "VALUES (?,'candidate','pending',?,?)", modelId, actor.id(), summary);
        long requestId = jdbc.queryForObject("SELECT LAST_INSERT_ID()", Long.class);
        audit(actor.id(), "model.release.requested", "model_release_record", requestId, model.modelKey(), request,
                "release metadata review requested");
        return findRelease(requestId);
    }

    @Transactional
    public ReleaseView decideRelease(long requestId, String decision, String reason, IdentityPrincipal actor,
                                     HttpServletRequest request) {
        String summary = validatedReason(reason);
        if (!Set.of("approve", "reject").contains(decision)) {
            throw ApiRequestException.badRequest("发布审查决定无效");
        }
        ReleaseRow row = findReleaseRow(requestId);
        if (row == null || !hasModelPermission(actor.id(), "model.release.approve", row.modelKey())) {
            throw ApiRequestException.notFound();
        }
        if (row.requestedBy() == actor.id()) {
            throw new AccessDeniedException("Release requester cannot review their own request");
        }
        if (!"pending".equals(row.reviewStatus())) {
            throw ApiRequestException.conflict("发布审查请求已被处理");
        }
        if (!hasModelPermissionForUpdate(actor.id(), "model.release.approve", row.modelKey())) {
            throw ApiRequestException.notFound();
        }
        String status = "approve".equals(decision) ? "approved" : "rejected";
        int updated = jdbc.update("UPDATE model_release_record rr SET review_status=?,approved_by=?,decision_reason=?,"
                        + "reviewed_at=UTC_TIMESTAMP(3) WHERE rr.id=? AND rr.review_status='pending' "
                        + "AND rr.requested_by<>? AND EXISTS (SELECT 1 FROM model_version mv WHERE mv.id=rr.model_version_id "
                        + "AND EXISTS (SELECT 1 FROM sys_user u JOIN sys_user_role ur ON ur.user_id=u.id "
                        + "JOIN sys_role r ON r.id=ur.role_id AND r.status='active' "
                        + "JOIN sys_role_permission rp ON rp.role_id=r.id JOIN sys_permission p "
                        + "ON p.id=rp.permission_id AND p.status='active' WHERE u.id=? AND u.status='active' "
                        + "AND p.permission_key='model.release.approve' AND ur.scope_type='model_registry' "
                        + "AND ur.scope_id=mv.model_key))",
                status, actor.id(), summary, requestId, actor.id(), actor.id());
        if (updated != 1) throw ApiRequestException.conflict("发布审查请求已被其他请求更新");
        audit(actor.id(), "model.release." + status, "model_release_record", requestId, row.modelKey(), request,
                "model lifecycle remains candidate");
        return findRelease(requestId);
    }

    private ModelRow findVisibleModel(long userId, long modelId, String permission) {
        return jdbc.query("SELECT mv.id,mv.model_key,mv.version,mv.task_type,mv.manifest_version,"
                        + "CAST(mv.manifest_json AS CHAR) manifest_json,mv.artifact_ref,mv.artifact_sha256,"
                        + "mv.feature_contract_version,mv.approval_status,mv.created_at FROM model_version mv "
                        + "WHERE mv.id=? AND EXISTS (" + scopedModelPermissionSql() + ")",
                rs -> rs.next() ? new ModelRow(rs.getLong("id"), rs.getString("model_key"), rs.getString("version"),
                        rs.getString("task_type"), rs.getString("manifest_version"), rs.getString("manifest_json"),
                        rs.getString("artifact_ref"), rs.getString("artifact_sha256"),
                        rs.getString("feature_contract_version"), rs.getString("approval_status"),
                        rs.getTimestamp("created_at").toLocalDateTime()) : null,
                modelId, userId, permission);
    }

    private ReleaseView findRelease(long id) {
        return jdbc.query("SELECT id,model_version_id,review_status,requested_by,approved_by,request_reason,"
                        + "decision_reason,reviewed_at,created_at FROM model_release_record WHERE id=?",
                rs -> rs.next() ? new ReleaseView(rs.getLong("id"), rs.getLong("model_version_id"),
                        rs.getString("review_status"), rs.getLong("requested_by"),
                        rs.getObject("approved_by", Long.class), rs.getString("request_reason"),
                        rs.getString("decision_reason"), timestamp(rs, "reviewed_at"),
                        rs.getTimestamp("created_at").toLocalDateTime()) : null, id);
    }

    private ReleaseRow findReleaseRow(long id) {
        return jdbc.query("SELECT rr.id,rr.model_version_id,rr.review_status,rr.requested_by,mv.model_key "
                        + "FROM model_release_record rr JOIN model_version mv ON mv.id=rr.model_version_id WHERE rr.id=?",
                rs -> rs.next() ? new ReleaseRow(rs.getLong("id"), rs.getLong("model_version_id"),
                        rs.getString("review_status"), rs.getLong("requested_by"), rs.getString("model_key")) : null, id);
    }

    private boolean hasModelPermission(long userId, String permission, String modelKey) {
        return Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS (SELECT 1 FROM sys_user u "
                        + "JOIN sys_user_role ur ON ur.user_id=u.id JOIN sys_role r ON r.id=ur.role_id AND r.status='active' "
                        + "JOIN sys_role_permission rp ON rp.role_id=r.id JOIN sys_permission p "
                        + "ON p.id=rp.permission_id AND p.status='active' WHERE u.id=? AND u.status='active' "
                        + "AND p.permission_key=? AND ur.scope_type='model_registry' AND ur.scope_id=?)",
                Boolean.class, userId, permission, modelKey));
    }

    private boolean hasModelPermissionForUpdate(long userId, String permission, String modelKey) {
        List<Long> scopedRoles = jdbc.query("SELECT role_id FROM sys_user_role WHERE user_id=? "
                        + "AND scope_type='model_registry' AND scope_id=? FOR UPDATE",
                (rs, row) -> rs.getLong("role_id"), userId, modelKey);
        return !scopedRoles.isEmpty() && hasModelPermission(userId, permission, modelKey);
    }

    private void requireModelScope(long userId, String permission, String modelKey) {
        if (!hasModelPermission(userId, permission, modelKey)) throw ApiRequestException.notFound();
    }

    private static String scopedModelPermissionSql() {
        return "SELECT 1 FROM sys_user u JOIN sys_user_role ur ON ur.user_id=u.id "
                + "JOIN sys_role r ON r.id=ur.role_id AND r.status='active' "
                + "JOIN sys_role_permission rp ON rp.role_id=r.id "
                + "JOIN sys_permission p ON p.id=rp.permission_id AND p.status='active' "
                + "WHERE u.id=? AND u.status='active' AND p.permission_key=? "
                + "AND ur.scope_type='model_registry' AND ur.scope_id=mv.model_key";
    }

    private void validateCandidate(CandidateRequest input) {
        if (input.modelKey() == null || !input.modelKey().matches("[A-Za-z0-9._-]{3,128}")
                || input.version() == null || !input.version().matches("[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")
                || input.taskType() == null || input.taskType().isBlank() || input.taskType().length() > 48
                || input.manifestVersion() == null || input.manifestVersion().isBlank()
                || input.featureContractVersion() == null || input.featureContractVersion().isBlank()
                || input.artifactSha256() == null || !input.artifactSha256().matches("(?i)[0-9a-f]{64}")) {
            throw ApiRequestException.badRequest("模型标识、版本或 SHA-256 格式无效");
        }
        if (input.manifest() == null || !input.manifest().isObject()) {
            throw ApiRequestException.badRequest("模型 manifest 必须是 JSON 对象");
        }
        validateArtifactRef(input.artifactRef());
    }

    private static void validateArtifactRef(String value) {
        try {
            URI uri = URI.create(value);
            if (!"model".equals(uri.getScheme()) || uri.getHost() == null || uri.getPath() == null
                    || uri.getPath().isBlank() || uri.getUserInfo() != null || uri.getQuery() != null
                    || uri.getFragment() != null || value.length() > 512) throw new IllegalArgumentException();
        } catch (RuntimeException exception) {
            throw ApiRequestException.badRequest("模型制品必须使用受控 model:// 引用");
        }
    }

    private String canonicalObject(JsonNode value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception exception) {
            throw ApiRequestException.badRequest("模型 manifest 无法序列化");
        }
    }

    private String validatedReason(String reason) {
        if (reason == null) throw ApiRequestException.badRequest("审查理由不能为空");
        String value = reason.trim();
        if (value.isEmpty() || value.length() > 1000 || value.chars().anyMatch(Character::isISOControl)) {
            throw ApiRequestException.badRequest("审查理由长度或字符无效");
        }
        return value;
    }

    private void audit(long actorId, String action, String resourceType, long resourceId, String modelKey,
                       HttpServletRequest request, String reason) {
        Object requestId = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        GeneratedKeyHolder key = new GeneratedKeyHolder();
        jdbc.update(connection -> {
            PreparedStatement statement = connection.prepareStatement("INSERT INTO audit_log "
                    + "(occurred_at,actor_type,actor_id,action,resource_type,resource_id,request_id,outcome,reason) "
                    + "VALUES (?,'human',?,?,?,?,?,'success',?)", Statement.RETURN_GENERATED_KEYS);
            statement.setTimestamp(1, Timestamp.from(Instant.now()));
            statement.setString(2, Long.toString(actorId));
            statement.setString(3, action);
            statement.setString(4, resourceType);
            statement.setString(5, Long.toString(resourceId));
            statement.setString(6, requestId instanceof String value ? value : null);
            statement.setString(7, reason);
            return statement;
        }, key);
        jdbc.update("INSERT INTO audit_resource_scope (audit_id,scope_type,scope_id) VALUES (?,'model_registry',?)",
                key.getKey().longValue(), modelKey);
    }

    private static ModelView modelView(long id, String key, String version, String taskType, String manifestVersion,
                                       String manifestJson, String artifactRef, String sha, String contract,
                                       String approvalStatus, LocalDateTime createdAt) {
        try {
            return new ModelView(id, key, version, taskType, manifestVersion,
                    new ObjectMapper().readTree(manifestJson), artifactRef, sha, contract, approvalStatus, createdAt);
        } catch (Exception exception) {
            throw new IllegalStateException("Stored model manifest is invalid JSON", exception);
        }
    }

    private static int checkedOffset(int page, int size) {
        if (page < 0 || size < 1 || size > 100 || (long) page * size > Integer.MAX_VALUE) {
            throw ApiRequestException.badRequest("分页参数超出允许范围");
        }
        return page * size;
    }

    private static LocalDateTime timestamp(java.sql.ResultSet rs, String column) throws java.sql.SQLException {
        Timestamp value = rs.getTimestamp(column);
        return value == null ? null : value.toLocalDateTime();
    }

    public record CandidateRequest(String modelKey, String version, String taskType, String manifestVersion,
                                   JsonNode manifest, String artifactRef, String artifactSha256,
                                   String featureContractVersion) { }
    public record ModelView(long id, String modelKey, String version, String taskType, String manifestVersion,
                            JsonNode manifest, String artifactRef, String artifactSha256,
                            String featureContractVersion, String approvalStatus, LocalDateTime createdAt) { }
    public record ReleaseView(long id, long modelVersionId, String reviewStatus, long requestedBy, Long approvedBy,
                              String requestReason, String decisionReason, LocalDateTime reviewedAt,
                              LocalDateTime createdAt) { }
    public record Page(long totalElements, int page, int size, List<ModelView> items) { }
    private record ModelRow(long id, String modelKey, String version, String taskType, String manifestVersion,
                            String manifestJson, String artifactRef, String artifactSha256,
                            String featureContractVersion, String approvalStatus, LocalDateTime createdAt) {
        ModelView view() { return modelView(id, modelKey, version, taskType, manifestVersion, manifestJson,
                artifactRef, artifactSha256, featureContractVersion, approvalStatus, createdAt); }
    }
    private record ReleaseRow(long id, long modelVersionId, String reviewStatus, long requestedBy, String modelKey) { }
}
