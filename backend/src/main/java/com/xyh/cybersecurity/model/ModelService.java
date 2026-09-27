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
    private final OnnxModelManager onnx;

    public ModelService(JdbcTemplate jdbc, ObjectMapper objectMapper, OnnxModelManager onnx) {
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
        this.onnx = onnx;
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
        if (!"validated".equals(model.approvalStatus())) {
            throw ApiRequestException.conflict("模型必须先通过制品与 ONNX 契约校验");
        }
        if (jdbc.queryForObject("SELECT COUNT(*) FROM model_release_record WHERE model_version_id=? "
                + "AND review_status='pending'", Integer.class, modelId) > 0) {
            throw ApiRequestException.conflict("该模型已有待审查申请");
        }
        jdbc.update("INSERT INTO model_release_record (model_version_id,release_status,review_status,requested_by,request_reason) "
                + "VALUES (?,'validated','pending',?,?)", modelId, actor.id(), summary);
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
        if (!hasModelPermissionForUpdate(actor.id(), "model.release.approve", row.modelKey())) {
            throw ApiRequestException.notFound();
        }
        // 兼容旧版本已记录独立批准、但尚未推进 release_status 的事务结果；修复仍须由同一审批人通过服务完成。
        if ("approved".equals(row.reviewStatus()) && row.approvedBy() != null
                && row.approvedBy() == actor.id() && "validated".equals(row.releaseStatus())) {
            jdbc.update("UPDATE model_release_record SET release_status='approved' WHERE id=? "
                    + "AND review_status='approved' AND approved_by=? AND release_status='validated'",
                    requestId, actor.id());
            audit(actor.id(), "model.release.approved.reconciled", "model_release_record", requestId,
                    row.modelKey(), request, "completed approved release status transition");
            return findRelease(requestId);
        }
        if (!"pending".equals(row.reviewStatus())) {
            throw ApiRequestException.conflict("发布审查请求已被处理");
        }
        String status = "approve".equals(decision) ? "approved" : "rejected";
        int updated = jdbc.update("UPDATE model_release_record rr JOIN model_version mv ON mv.id=rr.model_version_id "
                        + "SET rr.review_status=?,rr.approved_by=?,rr.decision_reason=?,rr.reviewed_at=UTC_TIMESTAMP(3),"
                        + "rr.release_status=CASE WHEN ?='approved' THEN 'approved' ELSE rr.release_status END,"
                        + "mv.approval_status=CASE WHEN ?='approved' THEN 'approved' ELSE 'rejected' END "
                        + "WHERE rr.id=? AND rr.review_status='pending' AND rr.requested_by<>? "
                        + "AND mv.approval_status='validated' AND EXISTS (SELECT 1 FROM sys_user u JOIN sys_user_role ur ON ur.user_id=u.id "
                        + "JOIN sys_role r ON r.id=ur.role_id AND r.status='active' "
                        + "JOIN sys_role_permission rp ON rp.role_id=r.id JOIN sys_permission p "
                        + "ON p.id=rp.permission_id AND p.status='active' WHERE u.id=? AND u.status='active' "
                        + "AND p.permission_key='model.release.approve' AND ur.scope_type='model_registry' "
                        + "AND ur.scope_id=mv.model_key)",
                status, actor.id(), summary, status, status, requestId, actor.id(), actor.id());
        // MySQL 多表 UPDATE 会同时计入发布审查记录和模型版本两行；0 行才表示请求已被并发处理。
        if (updated < 1) throw ApiRequestException.conflict("发布审查请求已被其他请求更新");
        audit(actor.id(), "model.release." + status, "model_release_record", requestId, row.modelKey(), request,
                "model release approval recorded; deployment requires separate activation");
        return findRelease(requestId);
    }

    /** 重新读取并核验 ONNX 制品后才记录验证状态；任何检查失败都保留 candidate。 */
    @Transactional
    public OnnxModelManager.ValidationResult validate(long modelId, IdentityPrincipal actor,
                                                       HttpServletRequest request) {
        ModelRow model = findVisibleModel(actor.id(), modelId, "model.candidate.validate");
        if (model == null) throw ApiRequestException.notFound();
        if (!"candidate".equals(model.approvalStatus())) throw ApiRequestException.conflict("只有候选状态可执行模型验证");
        OnnxModelManager.ValidationResult result;
        try { result = onnx.validate(model.view()); }
        catch (RuntimeException exception) {
            throw ApiRequestException.conflict("模型制品或 ONNX 契约校验失败");
        }
        int changed = jdbc.update("UPDATE model_version SET approval_status='validated' WHERE id=? "
                + "AND approval_status='candidate' AND artifact_sha256=?", modelId, result.artifactSha256());
        if (changed != 1) throw ApiRequestException.conflict("模型状态或制品摘要已变化，请重新读取");
        audit(actor.id(), "model.candidate.validated", "model_version", modelId, model.modelKey(), request,
                "model hash, manifest, ONNX contract and smoke inference passed");
        return result;
    }

    /** 仅独立批准的模型可切换为本机活动部署；数据库提交后才切换内存运行时。 */
    @Transactional
    public DeploymentView activate(long modelId, String reason, IdentityPrincipal actor, HttpServletRequest request) {
        String summary = validatedReason(reason);
        ModelRow model = findVisibleModel(actor.id(), modelId, "model.deployment.activate");
        if (model == null) throw ApiRequestException.notFound();
        if (!"approved".equals(model.approvalStatus())) throw ApiRequestException.conflict("模型尚未通过独立发布审批");
        int approvalCount = jdbc.queryForObject("SELECT COUNT(*) FROM model_release_record WHERE model_version_id=? "
                + "AND review_status='approved' AND release_status IN ('approved','active','retired')", Integer.class, modelId);
        if (approvalCount == 0) throw ApiRequestException.conflict("缺少已批准的发布审查记录");

        OnnxModelRuntime prepared;
        try { prepared = onnx.prepare(model.view()); }
        catch (RuntimeException exception) { throw ApiRequestException.conflict("激活前模型制品复核失败"); }
        try {
            jdbc.query("SELECT id FROM model_deployment WHERE environment='local' FOR UPDATE", rs -> { while (rs.next()) { /* acquire environment deployment locks */ } });
            jdbc.update("UPDATE model_deployment SET status='inactive' WHERE environment='local' AND status='active'");
            jdbc.update("UPDATE model_release_record SET release_status='retired' "
                    + "WHERE release_status='active' AND model_version_id<>?", modelId);
            jdbc.update("INSERT INTO model_deployment (environment,mode,model_version_id,runtime_type,status,activated_at,activated_by) "
                    + "VALUES ('local','local',?,'onnxruntime-java-1.23.2','active',UTC_TIMESTAMP(3),?)", modelId, actor.id());
            jdbc.update("UPDATE model_release_record SET release_status='active',released_by=?,released_at=UTC_TIMESTAMP(3) "
                    + "WHERE model_version_id=? AND review_status='approved' AND release_status='approved'", actor.id(), modelId);
            audit(actor.id(), "model.deployment.activated", "model_version", modelId, model.modelKey(), request, summary);
            onnx.activateAfterCommit(modelId, prepared);
        } catch (RuntimeException exception) {
            try { prepared.close(); } catch (Exception ignored) { }
            throw exception;
        }
        return new DeploymentView(modelId, model.modelKey(), model.version(), "local", "active",
                "onnxruntime-java-1.23.2", LocalDateTime.now());
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
        return jdbc.query("SELECT rr.id,rr.model_version_id,rr.review_status,rr.requested_by,rr.approved_by,"
                        + "rr.release_status,mv.model_key "
                        + "FROM model_release_record rr JOIN model_version mv ON mv.id=rr.model_version_id WHERE rr.id=?",
                rs -> rs.next() ? new ReleaseRow(rs.getLong("id"), rs.getLong("model_version_id"),
                        rs.getString("review_status"), rs.getLong("requested_by"), rs.getObject("approved_by", Long.class),
                        rs.getString("release_status"), rs.getString("model_key")) : null, id);
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
            if (!"model".equals(uri.getScheme()) || uri.getRawAuthority() == null
                    || !uri.getRawAuthority().matches("[A-Za-z0-9._-]{1,128}") || uri.getPath() == null
                    || uri.getPath().isBlank() || uri.getUserInfo() != null || uri.getPort() != -1
                    || uri.getQuery() != null || uri.getFragment() != null || value.length() > 512) {
                throw new IllegalArgumentException();
            }
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
    public record DeploymentView(long modelVersionId, String modelKey, String version, String environment,
                                 String status, String runtimeType, LocalDateTime activatedAt) { }
    private record ModelRow(long id, String modelKey, String version, String taskType, String manifestVersion,
                            String manifestJson, String artifactRef, String artifactSha256,
                            String featureContractVersion, String approvalStatus, LocalDateTime createdAt) {
        ModelView view() { return modelView(id, modelKey, version, taskType, manifestVersion, manifestJson,
                artifactRef, artifactSha256, featureContractVersion, approvalStatus, createdAt); }
    }
    private record ReleaseRow(long id, long modelVersionId, String reviewStatus, long requestedBy, Long approvedBy,
                              String releaseStatus, String modelKey) { }
}
