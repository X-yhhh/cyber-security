package com.xyh.cybersecurity.source;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.audit.AuditMapper;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 维护有显式 data_source 范围的数据源及不可变版本映射。 */
@Service
public class DataSourceService {

    private final DataSourceMapper mapper;
    private final AuditMapper auditMapper;
    private final ObjectMapper objectMapper;

    public DataSourceService(DataSourceMapper mapper, AuditMapper auditMapper, ObjectMapper objectMapper) {
        this.mapper = mapper;
        this.auditMapper = auditMapper;
        this.objectMapper = objectMapper;
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
        mapper.updateVisible(actor.id(), sourceId, input.environment(), input.schemaVersion(), input.status());
        audit(request, actor.id(), "source.updated", "data_source", sourceId, sourceId, "success", "scoped source update");
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
        try {
            mapper.insertMapping(new DataSourceMapper.MappingInsert(sourceId, input.mappingVersion(), sourceSchema, mapping));
        } catch (org.springframework.dao.DuplicateKeyException exception) {
            throw ApiRequestException.conflict("该映射版本已存在");
        }
        long mappingId = mapper.findMappingId(sourceId, input.mappingVersion());
        audit(request, actor.id(), "source.mapping.created", "source_mapping", mappingId, sourceId,
                "success", "draft mapping version created");
        return mapper.listMappingsVisible(actor.id(), sourceId).stream().filter(row -> row.id() == mappingId)
                .findFirst().orElseThrow();
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
        AuditMapper.AuditInsert audit = new AuditMapper.AuditInsert(LocalDateTime.now(), "human",
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
    public record MappingRequest(String mappingVersion, String sourceSchema, String mapping) { }
    public record Page(long totalElements, int page, int size, List<DataSourceMapper.DataSourceView> items) { }
}
