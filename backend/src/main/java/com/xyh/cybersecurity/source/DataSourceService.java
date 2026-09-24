package com.xyh.cybersecurity.source;

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

import java.sql.PreparedStatement;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 维护有显式 data_source 范围的数据源及不可变版本映射。 */
@Service
public class DataSourceService {

    private final DataSourceMapper mapper;
    private final JdbcTemplate jdbc;
    private final ObjectMapper objectMapper;

    public DataSourceService(DataSourceMapper mapper, JdbcTemplate jdbc, ObjectMapper objectMapper) {
        this.mapper = mapper;
        this.jdbc = jdbc;
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
            jdbc.update("INSERT INTO data_source (source_key, source_type, environment, schema_version, scope_json, status) "
                            + "VALUES (?, ?, ?, ?, '{}', 'active')", input.sourceKey(), input.sourceType(),
                    input.environment(), input.schemaVersion());
        } catch (org.springframework.dao.DuplicateKeyException exception) {
            throw ApiRequestException.conflict("数据源标识已存在");
        }
        long id = jdbc.queryForObject("SELECT id FROM data_source WHERE source_key=?", Long.class, input.sourceKey());
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
        GeneratedKeyHolder key = new GeneratedKeyHolder();
        try {
            jdbc.update(connection -> {
                PreparedStatement statement = connection.prepareStatement("INSERT INTO source_mapping "
                        + "(data_source_id, mapping_version, source_schema_json, mapping_json, status) "
                        + "VALUES (?, ?, ?, ?, 'draft')", Statement.RETURN_GENERATED_KEYS);
                statement.setLong(1, sourceId);
                statement.setString(2, input.mappingVersion());
                statement.setString(3, sourceSchema);
                statement.setString(4, mapping);
                return statement;
            }, key);
        } catch (org.springframework.dao.DuplicateKeyException exception) {
            throw ApiRequestException.conflict("该映射版本已存在");
        }
        long mappingId = key.getKey().longValue();
        audit(request, actor.id(), "source.mapping.created", "source_mapping", mappingId, sourceId,
                "success", "draft mapping version created");
        return mapper.listMappingsVisible(actor.id(), sourceId).stream().filter(row -> row.id() == mappingId)
                .findFirst().orElseThrow();
    }

    private void requireSourceManage(long userId, long sourceId) {
        Boolean allowed = jdbc.queryForObject("SELECT EXISTS (SELECT 1 FROM sys_user_role ur "
                        + "JOIN sys_role r ON r.id=ur.role_id AND r.status='active' "
                        + "JOIN sys_role_permission rp ON rp.role_id=r.id JOIN sys_permission p ON p.id=rp.permission_id "
                        + "AND p.status='active' WHERE ur.user_id=? AND p.permission_key='source.manage' "
                        + "AND ((r.role_key='platform_admin' AND ur.scope_type='global' AND ur.scope_id='*') "
                        + "OR (ur.scope_type='data_source' AND ur.scope_id=?)))", Boolean.class,
                userId, Long.toString(sourceId));
        if (!Boolean.TRUE.equals(allowed)) throw ApiRequestException.notFound();
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
        GeneratedKeyHolder key = new GeneratedKeyHolder();
        jdbc.update(connection -> {
            PreparedStatement statement = connection.prepareStatement("INSERT INTO audit_log "
                    + "(occurred_at,actor_type,actor_id,action,resource_type,resource_id,request_id,outcome,reason) "
                    + "VALUES (?,'human',?,?,?,?,?,?,?)", Statement.RETURN_GENERATED_KEYS);
            statement.setTimestamp(1, Timestamp.from(Instant.now()));
            statement.setString(2, Long.toString(actorId));
            statement.setString(3, action);
            statement.setString(4, resourceType);
            statement.setString(5, Long.toString(resourceId));
            statement.setString(6, requestId instanceof String value ? value : null);
            statement.setString(7, outcome);
            statement.setString(8, reason);
            return statement;
        }, key);
        jdbc.update("INSERT INTO audit_resource_scope (audit_id, scope_type, scope_id) VALUES (?, 'data_source', ?)",
                key.getKey().longValue(), Long.toString(sourceId));
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
