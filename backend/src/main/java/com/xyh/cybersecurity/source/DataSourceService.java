package com.xyh.cybersecurity.source;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.audit.AuditMapper;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import com.xyh.cybersecurity.ingest.contract.FeatureContract;
import com.xyh.cybersecurity.ingest.contract.FeatureContractRegistry;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 维护有显式 data_source 范围的数据源及不可变版本映射。 */
@Service
public class DataSourceService {

    private final DataSourceMapper mapper;
    private final AuditMapper auditMapper;
    private final ObjectMapper objectMapper;
    private final FeatureContractRegistry contracts;

    public DataSourceService(DataSourceMapper mapper, AuditMapper auditMapper, ObjectMapper objectMapper,
                             FeatureContractRegistry contracts) {
        this.mapper = mapper;
        this.auditMapper = auditMapper;
        this.objectMapper = objectMapper;
        this.contracts = contracts;
    }

    public Page list(long userId, int page, int size) {
        int offset = checkedOffset(page, size);
        return new Page(mapper.countVisible(userId), page, size, mapper.listVisible(userId, offset, size));
    }

    @Transactional
    public DataSourceMapper.DataSourceView create(CreateRequest input, IdentityPrincipal actor, HttpServletRequest request) {
        if (mapper.findActiveGlobalPlatformAdminId(actor.id()) == null) {
            throw new AccessDeniedException("Source creation requires a global platform administrator");
        }
        validateKey(input.sourceKey());
        validateName(input.environment(), "environment");
        validateName(input.schemaVersion(), "schemaVersion");
        try {
            mapper.insertSource(new DataSourceMapper.SourceInsert(input.sourceKey(), input.sourceType(),
                    input.environment(), input.schemaVersion()));
        } catch (org.springframework.dao.DuplicateKeyException exception) {
            throw ApiRequestException.conflict("数据源标识已存在");
        }
        long id = mapper.findIdByKey(input.sourceKey());
        audit(request, actor.id(), "source.created", "data_source", id, id, "success", "source registered");
        return mapper.findVisible(actor.id(), id);
    }

    @Transactional
    public DataSourceMapper.DataSourceView update(long sourceId, UpdateRequest input, IdentityPrincipal actor,
                                                  HttpServletRequest request) {
        if (mapper.findVisible(actor.id(), sourceId) == null) throw ApiRequestException.notFound();
        if (!mapper.canManage(actor.id(), sourceId)) {
            throw new org.springframework.security.access.AccessDeniedException("Source manage denied");
        }
        validateName(input.environment(), "environment");
        validateName(input.schemaVersion(), "schemaVersion");
        if (!List.of("active", "disabled", "retired").contains(input.status())) {
            throw ApiRequestException.badRequest("数据源状态无效");
        }
        // 状态迁移：active ↔ disabled，active/disabled → retired；retired 为终态。停用或退役后接入只认 active，
        // 新批次立即被拒绝，历史批次与记录保留。
        String current = mapper.lockStatus(sourceId);
        if ("retired".equals(current)) {
            throw new ApiRequestException(org.springframework.http.HttpStatus.CONFLICT, "SOURCE_STATUS_CONFLICT",
                    "数据源已退役，不能再修改");
        }
        mapper.updateVisible(actor.id(), sourceId, input.environment(), input.schemaVersion(), input.status());
        boolean statusChanged = !input.status().equals(current);
        audit(request, actor.id(), statusChanged ? "source.status.changed" : "source.updated", "data_source", sourceId,
                sourceId, "success", statusChanged ? "status " + current + " -> " + input.status() : "scoped source update");
        return mapper.findVisible(actor.id(), sourceId);
    }

    @Transactional
    public DataSourceMapper.MappingView createMapping(long sourceId, MappingRequest input, IdentityPrincipal actor,
                                                       HttpServletRequest request) {
        if (mapper.findVisible(actor.id(), sourceId) == null) throw ApiRequestException.notFound();
        requireSourceManage(actor.id(), sourceId);
        validateName(input.mappingVersion(), "mappingVersion");
        String sourceSchema = canonicalObject(input.sourceSchema());
        String mapping = canonicalObject(input.mapping());
        // 可选绑定特征契约：版本必须已注册，哈希由服务端按注册表写入（V11），绑定后映射只服务该契约的批次。
        String contractVersion = null;
        String contractSha256 = null;
        if (input.featureContractVersion() != null) {
            FeatureContract contract = contracts.find(input.featureContractVersion());
            if (contract == null) throw ApiRequestException.badRequest("特征契约版本未登记");
            contractVersion = contract.version();
            contractSha256 = contract.fileSha256();
        }
        try {
            mapper.insertMapping(new DataSourceMapper.MappingInsert(sourceId, input.mappingVersion(), sourceSchema, mapping,
                    contractVersion, contractSha256, actor.id()));
        } catch (org.springframework.dao.DuplicateKeyException exception) {
            throw ApiRequestException.conflict("该映射版本已存在");
        }
        long mappingId = mapper.findMappingId(sourceId, input.mappingVersion());
        audit(request, actor.id(), "source.mapping.created", "source_mapping", mappingId, sourceId,
                "success", "draft mapping version created");
        return mapper.listMappingsVisible(actor.id(), sourceId).stream().filter(row -> row.id() == mappingId)
                .findFirst().orElseThrow();
    }

    /**
     * 独立批准映射（V14）：批准人须有 {@code source.mapping.approve} 且在该数据源范围内，不能是登记人。
     * V14 之前登记的映射没有登记人记录，无法证明职责分离，拒绝经接口批准。
     */
    @Transactional
    public DataSourceMapper.MappingView approveMapping(long sourceId, long mappingId, IdentityPrincipal actor,
                                                        HttpServletRequest request) {
        if (mapper.findVisible(actor.id(), sourceId) == null || !mapper.hasMappingApproveScope(actor.id(), sourceId)) {
            throw ApiRequestException.notFound();
        }
        DataSourceMapper.MappingRow row = mapper.findMappingForUpdate(sourceId, mappingId);
        if (row == null) throw ApiRequestException.notFound();
        if (row.requestedBy() == null) {
            throw new ApiRequestException(org.springframework.http.HttpStatus.CONFLICT, "MAPPING_REQUESTER_UNKNOWN",
                    "映射缺少登记人记录，不能经接口批准");
        }
        if (row.requestedBy() == actor.id()) throw new AccessDeniedException("Self approval denied");
        if (!"draft".equals(row.status()) && !"pending".equals(row.status())) {
            throw ApiRequestException.conflict("映射状态不可审批");
        }
        if (mapper.approveMapping(mappingId, actor.id()) != 1) {
            throw ApiRequestException.conflict("映射状态已被其他请求更新");
        }
        audit(request, actor.id(), "source.mapping.approved", "source_mapping", mappingId, sourceId,
                "success", "mapping version approved");
        return mapper.listMappingsVisible(actor.id(), sourceId).stream().filter(item -> item.id() == mappingId)
                .findFirst().orElseThrow();
    }

    /**
     * 驳回待批准映射（{@code draft/pending → rejected}）。驳回人须有 {@code source.mapping.approve} 且不是登记人；
     * 被驳回的版本号不能复用，修正后须登记新版本。
     */
    @Transactional
    public DataSourceMapper.MappingView rejectMapping(long sourceId, long mappingId, String reason, IdentityPrincipal actor,
                                                       HttpServletRequest request) {
        String why = reason(reason);
        DataSourceMapper.MappingRow row = lockMappingForDecision(sourceId, mappingId, actor);
        if (row.requestedBy() != null && row.requestedBy() == actor.id()) throw new AccessDeniedException("Self review denied");
        if (!"draft".equals(row.status()) && !"pending".equals(row.status())) {
            throw mappingConflict("映射状态不可驳回");
        }
        if (mapper.rejectMapping(mappingId, actor.id(), why) != 1) throw mappingConflict("映射状态已被其他请求更新");
        audit(request, actor.id(), "source.mapping.rejected", "source_mapping", mappingId, sourceId, "success", why);
        return findMapping(actor.id(), sourceId, mappingId);
    }

    /**
     * 退役已批准映射（{@code approved → retired}）。退役后使用该映射版本的新批次被拒绝（接入只认 approved），
     * 已接入的记录保留原映射版本引用。
     */
    @Transactional
    public DataSourceMapper.MappingView retireMapping(long sourceId, long mappingId, String reason, IdentityPrincipal actor,
                                                       HttpServletRequest request) {
        String why = reason(reason);
        DataSourceMapper.MappingRow row = lockMappingForDecision(sourceId, mappingId, actor);
        if (!"approved".equals(row.status())) throw mappingConflict("只有已批准的映射可以退役");
        if (mapper.retireMapping(mappingId, actor.id(), why) != 1) throw mappingConflict("映射状态已被其他请求更新");
        audit(request, actor.id(), "source.mapping.retired", "source_mapping", mappingId, sourceId, "success", why);
        return findMapping(actor.id(), sourceId, mappingId);
    }

    private DataSourceMapper.MappingRow lockMappingForDecision(long sourceId, long mappingId, IdentityPrincipal actor) {
        if (mapper.findVisible(actor.id(), sourceId) == null || !mapper.hasMappingApproveScope(actor.id(), sourceId)) {
            throw ApiRequestException.notFound();
        }
        DataSourceMapper.MappingRow row = mapper.findMappingForUpdate(sourceId, mappingId);
        if (row == null) throw ApiRequestException.notFound();
        return row;
    }

    private DataSourceMapper.MappingView findMapping(long userId, long sourceId, long mappingId) {
        return mapper.listMappingsVisible(userId, sourceId).stream().filter(item -> item.id() == mappingId)
                .findFirst().orElseThrow();
    }

    private static ApiRequestException mappingConflict(String message) {
        return new ApiRequestException(org.springframework.http.HttpStatus.CONFLICT, "MAPPING_STATUS_CONFLICT", message);
    }

    private static String reason(String reason) {
        if (reason == null || reason.isBlank() || reason.length() > 1000) {
            throw ApiRequestException.badRequest("须填写 1-1000 字的理由");
        }
        return reason.trim();
    }

    private void requireSourceManage(long userId, long sourceId) {
        if (!mapper.hasManageScope(userId, sourceId)) throw ApiRequestException.notFound();
    }

    private String canonicalObject(String json) {
        try {
            JsonNode node = objectMapper.readTree(json);
            if (node == null || !node.isObject()) throw new IllegalArgumentException();
            return objectMapper.writeValueAsString(node);
        } catch (Exception exception) {
            throw ApiRequestException.badRequest("模式和映射定义必须是合法 JSON 对象");
        }
    }

    private void audit(HttpServletRequest request, long actorId, String action, String resourceType, long resourceId,
                       long sourceId, String outcome, String reason) {
        Object requestId = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        AuditMapper.AuditInsert audit = new AuditMapper.AuditInsert(LocalDateTime.now(ZoneOffset.UTC), "human",
                Long.toString(actorId), action, resourceType, Long.toString(resourceId),
                requestId instanceof String value ? value : null, outcome, reason);
        auditMapper.insertAudit(audit);
        auditMapper.insertResourceScope(audit.getId(), "data_source", Long.toString(sourceId));
    }

    private static int checkedOffset(int page, int size) {
        if (page < 0 || size < 1 || size > 100 || (long) page * size > Integer.MAX_VALUE) {
            throw ApiRequestException.badRequest("分页参数超出允许范围");
        }
        return page * size;
    }

    private static void validateKey(String value) {
        if (value == null || !value.matches("[A-Za-z0-9._-]{3,128}")) {
            throw ApiRequestException.badRequest("数据源标识格式无效");
        }
    }

    private static void validateName(String value, String field) {
        if (value == null || value.isBlank() || value.length() > 64) {
            throw ApiRequestException.badRequest(field + " 无效");
        }
    }

    public record CreateRequest(String sourceKey, String sourceType, String environment, String schemaVersion) { }
    public record UpdateRequest(String environment, String schemaVersion, String status) { }
    /** @param featureContractVersion 可选；为空表示不绑定契约（在线契约的批次不能使用此类映射） */
    public record MappingRequest(String mappingVersion, String sourceSchema, String mapping, String featureContractVersion) {
        public MappingRequest(String mappingVersion, String sourceSchema, String mapping) {
            this(mappingVersion, sourceSchema, mapping, null);
        }
    }
    public record Page(long totalElements, int page, int size, List<DataSourceMapper.DataSourceView> items) { }
}
