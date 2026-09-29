package com.xyh.cybersecurity.model.release;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.audit.AuditMapper;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import com.xyh.cybersecurity.model.runtime.OnnxModelManager;
import com.xyh.cybersecurity.model.runtime.OnnxModelRuntime;
import com.xyh.cybersecurity.model.validation.ModelContractException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 登记不可变候选模型及分离的发布审查请求；不读取制品引用的内容。 */
@Service
public class ModelService {

    private final ModelMapper mapper;
    private final AuditMapper auditMapper;
    private final ObjectMapper objectMapper;
    private final OnnxModelManager onnx;

    public ModelService(ModelMapper mapper, AuditMapper auditMapper, ObjectMapper objectMapper, OnnxModelManager onnx) {
        this.mapper = mapper;
        this.auditMapper = auditMapper;
        this.objectMapper = objectMapper;
        this.onnx = onnx;
    }

    public Page list(long userId, int page, int size) {
        int offset = checkedOffset(page, size);
        long total = mapper.countVisible(userId, "model.validation.read");
        List<ModelView> items = mapper.listVisible(userId, "model.validation.read", offset, size).stream()
                .map(row -> modelView(row.id(), row.modelKey(), row.version(), row.taskType(), row.manifestVersion(),
                        row.manifestJson(), row.artifactRef(), row.artifactSha256(), row.featureContractVersion(),
                        row.approvalStatus(), row.createdAt()))
                .toList();
        return new Page(total, page, size, items);
    }

    public ModelView get(long userId, long modelId) {
        ModelMapper.ModelRow row = findVisibleModel(userId, modelId, "model.validation.read");
        if (row == null) throw ApiRequestException.notFound();
        return modelView(row.id(), row.modelKey(), row.version(), row.taskType(), row.manifestVersion(),
                row.manifestJson(), row.artifactRef(), row.artifactSha256(), row.featureContractVersion(),
                row.approvalStatus(), row.createdAt());
    }

    @Transactional
    public ModelView register(CandidateRequest input, IdentityPrincipal actor, HttpServletRequest request) {
        validateCandidate(input);
        requireModelScope(actor.id(), "model.candidate.manage", input.modelKey());
        String manifest = canonicalObject(input.manifest());
        try {
            mapper.insertModel(new ModelMapper.ModelInsert(input.modelKey(), input.version(), input.taskType(),
                    input.manifestVersion(), manifest, input.artifactRef(),
                    input.artifactSha256().toLowerCase(Locale.ROOT), input.featureContractVersion()));
        } catch (org.springframework.dao.DuplicateKeyException exception) {
            throw ApiRequestException.conflict("该模型版本已登记；候选元数据不可覆盖");
        }
        long id = mapper.findModelId(input.modelKey(), input.version());
        audit(actor.id(), "model.candidate.registered", "model_version", id, input.modelKey(), request,
                "candidate metadata registered");
        ModelMapper.ModelRow row = findVisibleModel(actor.id(), id, "model.validation.read");
        return modelView(row.id(), row.modelKey(), row.version(), row.taskType(), row.manifestVersion(),
                row.manifestJson(), row.artifactRef(), row.artifactSha256(), row.featureContractVersion(),
                row.approvalStatus(), row.createdAt());
    }

    @Transactional
    public ReleaseView requestRelease(long modelId, String reason, IdentityPrincipal actor, HttpServletRequest request) {
        String summary = validatedReason(reason);
        ModelMapper.ModelRow model = findVisibleModel(actor.id(), modelId, "model.release.request");
        if (model == null) throw ApiRequestException.notFound();
        if (!"validated".equals(model.approvalStatus())) {
            throw ApiRequestException.conflict("模型必须先通过制品与 ONNX 契约校验");
        }
        if (mapper.countPendingRelease(modelId) > 0) {
            throw ApiRequestException.conflict("该模型已有待审查申请");
        }
        mapper.insertRelease(modelId, actor.id(), summary);
        long requestId = mapper.findReleaseId(modelId, actor.id());
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
            mapper.reconcileRelease(requestId, actor.id());
            audit(actor.id(), "model.release.approved.reconciled", "model_release_record", requestId,
                    row.modelKey(), request, "completed approved release status transition");
            return findRelease(requestId);
        }
        if (!"pending".equals(row.reviewStatus())) {
            throw ApiRequestException.conflict("发布审查请求已被处理");
        }
        String status = "approve".equals(decision) ? "approved" : "rejected";
        int updated = mapper.decideRelease(requestId, status, actor.id(), summary);
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
        ModelMapper.ModelRow model = findVisibleModel(actor.id(), modelId, "model.candidate.validate");
        if (model == null) throw ApiRequestException.notFound();
        if (!"candidate".equals(model.approvalStatus())) throw ApiRequestException.conflict("只有候选状态可执行模型验证");
        OnnxModelManager.ValidationResult result;
        try { result = onnx.validate(modelView(model.id(), model.modelKey(), model.version(), model.taskType(),
                model.manifestVersion(), model.manifestJson(), model.artifactRef(), model.artifactSha256(),
                model.featureContractVersion(), model.approvalStatus(), model.createdAt())); }
        catch (RuntimeException exception) {
            throw ApiRequestException.conflict("模型制品或 ONNX 契约校验失败");
        }
        int changed = mapper.markValidated(modelId, result.artifactSha256());
        if (changed != 1) throw ApiRequestException.conflict("模型状态或制品摘要已变化，请重新读取");
        audit(actor.id(), "model.candidate.validated", "model_version", modelId, model.modelKey(), request,
                "model hash, manifest, ONNX contract and smoke inference passed");
        return result;
    }

    /** 仅独立批准的模型可切换为本机活动部署；数据库提交后才切换内存运行时。 */
    @Transactional
    public DeploymentView activate(long modelId, String reason, IdentityPrincipal actor, HttpServletRequest request) {
        String summary = validatedReason(reason);
        ModelMapper.ModelRow model = findVisibleModel(actor.id(), modelId, "model.deployment.activate");
        if (model == null) throw ApiRequestException.notFound();
        if (!"approved".equals(model.approvalStatus())) throw ApiRequestException.conflict("模型尚未通过独立发布审批");
        int approvalCount = mapper.countApprovedReleases(modelId);
        if (approvalCount == 0) throw ApiRequestException.conflict("缺少已批准的发布审查记录");

        ModelView view = modelView(model.id(), model.modelKey(), model.version(), model.taskType(),
                model.manifestVersion(), model.manifestJson(), model.artifactRef(), model.artifactSha256(),
                model.featureContractVersion(), model.approvalStatus(), model.createdAt());
        OnnxModelRuntime prepared;
        OnnxModelManager.ActiveModel descriptor;
        try {
            prepared = onnx.prepare(view);
            // 描述在数据库写入前生成（prepare 已校验过阈值策略），提交后的内存切换不会再因校验失败而中断。
            descriptor = OnnxModelManager.describe(view, prepared);
        }
        catch (RuntimeException exception) { throw ApiRequestException.conflict("激活前模型制品复核失败"); }
        try {
            mapper.lockLocalDeployments();
            mapper.deactivateLocalDeployments();
            mapper.retireOtherReleases(modelId);
            mapper.insertDeployment(modelId, actor.id());
            mapper.activateRelease(modelId, actor.id());
            audit(actor.id(), "model.deployment.activated", "model_version", modelId, model.modelKey(), request, summary);
            onnx.activateAfterCommit(descriptor, prepared);
        } catch (RuntimeException exception) {
            try { prepared.close(); } catch (Exception ignored) { }
            throw exception;
        }
        return new DeploymentView(modelId, model.modelKey(), model.version(), "local", "active",
                "onnxruntime-java-1.23.2", LocalDateTime.now());
    }

    private ModelMapper.ModelRow findVisibleModel(long userId, long modelId, String permission) {
        ModelMapper.ModelRow row = mapper.findVisible(userId, modelId, permission);
        return row == null ? null : row;
    }

    private ReleaseView findRelease(long id) {
        ModelMapper.ReleaseView row = mapper.findRelease(id);
        return row == null ? null : new ReleaseView(row.id(), row.modelVersionId(), row.reviewStatus(),
                row.requestedBy(), row.approvedBy(), row.requestReason(), row.decisionReason(),
                row.reviewedAt(), row.createdAt());
    }

    private ReleaseRow findReleaseRow(long id) {
        ModelMapper.ReleaseRow row = mapper.findReleaseRow(id);
        return row == null ? null : new ReleaseRow(row.id(), row.modelVersionId(), row.reviewStatus(),
                row.requestedBy(), row.approvedBy(), row.releaseStatus(), row.modelKey());
    }

    private boolean hasModelPermission(long userId, String permission, String modelKey) {
        return mapper.hasPermission(userId, permission, modelKey);
    }

    private boolean hasModelPermissionForUpdate(long userId, String permission, String modelKey) {
        List<Long> scopedRoles = mapper.lockScopedRoles(userId, modelKey);
        return !scopedRoles.isEmpty() && hasModelPermission(userId, permission, modelKey);
    }

    private void requireModelScope(long userId, String permission, String modelKey) {
        if (!hasModelPermission(userId, permission, modelKey)) throw ApiRequestException.notFound();
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
        AuditMapper.AuditInsert audit = new AuditMapper.AuditInsert(LocalDateTime.now(), "human",
                Long.toString(actorId), action, resourceType, Long.toString(resourceId),
                requestId instanceof String value ? value : null, "success", reason);
        auditMapper.insertAudit(audit);
        auditMapper.insertResourceScope(audit.getId(), "model_registry", modelKey);
    }

    private ModelView modelView(long id, String key, String version, String taskType, String manifestVersion,
                                String manifestJson, String artifactRef, String sha, String contract,
                                String approvalStatus, LocalDateTime createdAt) {
        try {
            return new ModelView(id, key, version, taskType, manifestVersion,
                    objectMapper.readTree(manifestJson), artifactRef, sha, contract, approvalStatus, createdAt);
        } catch (Exception exception) {
            throw new ModelContractException("MODEL_MANIFEST_INVALID", exception);
        }
    }

    private static int checkedOffset(int page, int size) {
        if (page < 0 || size < 1 || size > 100 || (long) page * size > Integer.MAX_VALUE) {
            throw ApiRequestException.badRequest("分页参数超出允许范围");
        }
        return page * size;
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
    private record ReleaseRow(long id, long modelVersionId, String reviewStatus, long requestedBy, Long approvedBy,
                              String releaseStatus, String modelKey) { }
}
