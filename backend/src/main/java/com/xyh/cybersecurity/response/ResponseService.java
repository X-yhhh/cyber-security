package com.xyh.cybersecurity.response;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import com.xyh.cybersecurity.incident.IncidentMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 管理带幂等键的响应申请快照和独立审批；不调用任何外部响应适配器。 */
@Service
public class ResponseService {

    private final JdbcTemplate jdbc;
    private final ObjectMapper objectMapper;
    private final IncidentMapper incidentMapper;
    private final Clock clock;
    private final TransactionTemplate requiresNew;

    public ResponseService(JdbcTemplate jdbc, ObjectMapper objectMapper, IncidentMapper incidentMapper,
                           Clock clock, PlatformTransactionManager transactionManager) {
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
        this.incidentMapper = incidentMapper;
        this.clock = clock;
        this.requiresNew = new TransactionTemplate(transactionManager);
        this.requiresNew.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    @Transactional
    public RequestResult requestAction(long eventId, ActionRequest input, String idempotencyKey,
                                       IdentityPrincipal actor, HttpServletRequest request) {
        String key = validateIdempotencyKey(idempotencyKey);
        String reason = validatedReason(input.reason());
        JsonNode parameters = canonicalNode(input.parameters());
        validateTemporaryBlockParameters(input.actionType(), parameters);
        requireAssetPermission(actor.id(), "action.request", input.assetId());
        if (incidentMapper.findVisibleEvent(actor.id(), eventId) == null || !eventContainsAsset(eventId, input.assetId())) {
            throw ApiRequestException.notFound();
        }
        if (!Set.of("open", "investigating", "contained").contains(eventStatus(eventId))) {
            throw ApiRequestException.conflict("当前事件状态不允许提交响应申请");
        }

        String digest = sha256(actionSnapshot(eventId, input, parameters, reason));
        ApprovalRow existing = findByIdempotency(actor.id(), key);
        if (existing != null) return replayOrConflict(existing, digest);

        PolicyRow policy = findPolicy(input.policyId());
        AssetRow asset = findAsset(input.assetId());
        if (!policyMatches(policy, input.actionType(), asset, parameters)) {
            throw ApiRequestException.conflict("没有匹配且已批准的响应策略；申请未登记");
        }
        requireCurrentAuthorization(input.assetId(), input.actionType());
        String snapshot = actionSnapshot(eventId, input, parameters, reason, policy);

        long approvalId;
        try {
            GeneratedKeyHolder keyHolder = new GeneratedKeyHolder();
            jdbc.update(connection -> {
                PreparedStatement statement = connection.prepareStatement("INSERT INTO approval_task "
                        + "(task_key,event_id,policy_id,action_request_json,status,requested_by,idempotency_key,"
                        + "request_digest,expires_at) VALUES (?,?,?,?,'pending',?,?,?,?)", Statement.RETURN_GENERATED_KEYS);
                statement.setString(1, "action:" + UUID.randomUUID());
                statement.setLong(2, eventId);
                statement.setLong(3, input.policyId());
                statement.setString(4, snapshot);
                statement.setLong(5, actor.id());
                statement.setString(6, key);
                statement.setString(7, digest);
                statement.setTimestamp(8, Timestamp.from(clock.instant().plusSeconds(15 * 60)));
                return statement;
            }, keyHolder);
            approvalId = keyHolder.getKey().longValue();
        } catch (org.springframework.dao.DuplicateKeyException exception) {
            ApprovalRow raced = findByIdempotency(actor.id(), key);
            if (raced == null) throw ApiRequestException.conflict("响应申请幂等键冲突");
            return replayOrConflict(raced, digest);
        }
        audit(actor.id(), "action.requested", approvalId, input.assetId(), request,
                "approval ledger only; execution unavailable");
        addTimeline(eventId, actor.id(), "action_requested", approvalId, "响应申请已登记待审批；尚未执行");
        return new RequestResult(findApprovalRow(approvalId).view(), true);
    }

    public Page listApprovals(long userId, int page, int size) {
        int offset = checkedOffset(page, size);
        String scope = assetScopePredicate("approval.decide", "eal.asset_id");
        long total = jdbc.queryForObject("SELECT COUNT(*) FROM approval_task at "
                + "JOIN event_asset_link eal ON eal.event_id=at.event_id "
                + "JOIN JSON_TABLE(at.action_request_json, '$' COLUMNS(asset_id BIGINT PATH '$.assetId')) req "
                + "ON req.asset_id=eal.asset_id WHERE at.status='pending' AND EXISTS (" + scope + ")",
                Long.class, userId);
        List<ApprovalView> items = jdbc.query("SELECT at.id,at.event_id,req.asset_id,"
                        + "CAST(at.action_request_json AS CHAR) action_request_json,at.status,at.requested_by,"
                        + "at.reviewed_by,at.expires_at,at.created_at FROM approval_task at "
                        + "JOIN JSON_TABLE(at.action_request_json, '$' COLUMNS(asset_id BIGINT PATH '$.assetId')) req "
                        + "JOIN event_asset_link eal ON eal.event_id=at.event_id AND eal.asset_id=req.asset_id "
                        + "WHERE at.status='pending' AND EXISTS (" + scope + ") "
                        + "ORDER BY at.created_at DESC,at.id DESC LIMIT ? OFFSET ?",
                (rs, row) -> approvalView(rs.getLong("id"), rs.getLong("event_id"), rs.getLong("asset_id"),
                        rs.getString("action_request_json"), rs.getString("status"), rs.getLong("requested_by"),
                        rs.getObject("reviewed_by", Long.class), rs.getTimestamp("expires_at").toLocalDateTime(),
                        rs.getTimestamp("created_at").toLocalDateTime()), userId, size, offset);
        return new Page(total, page, size, items);
    }

    public ApprovalView getApproval(long userId, long id) {
        ApprovalRow row = findApprovalRow(id);
        if (row == null || !hasAssetPermission(userId, "approval.decide", row.assetId())) {
            throw ApiRequestException.notFound();
        }
        return row.view();
    }

    public ApprovalView getAction(long userId, long id) {
        ApprovalRow row = findApprovalRow(id);
        if (row == null || row.requestedBy() != userId
                || !hasAssetPermission(userId, "action.request", row.assetId())) {
            throw ApiRequestException.notFound();
        }
        return row.view();
    }

    @Transactional
    public ApprovalView decide(long id, String decision, String reason, IdentityPrincipal actor,
                               HttpServletRequest request) {
        String summary = validatedReason(reason);
        if (!Set.of("approve", "reject").contains(decision)) {
            throw ApiRequestException.badRequest("审批决定无效");
        }
        ApprovalRow row = findApprovalRow(id);
        if (row == null || !hasAssetPermission(actor.id(), "approval.decide", row.assetId())) {
            throw ApiRequestException.notFound();
        }
        if (row.requestedBy() == actor.id()) throw new AccessDeniedException("Action requester cannot review their own request");
        if (!"pending".equals(row.status())) throw ApiRequestException.conflict("审批任务已被处理");
        if (!row.expiresAt().isAfter(clock.instant())) throw ApiRequestException.conflict("审批任务已过期");
        if (!eventContainsAssetForUpdate(row.eventId(), row.assetId())
                || !Set.of("open", "investigating", "contained").contains(eventStatusForUpdate(row.eventId()))) {
            throw ApiRequestException.conflict("事件已变化，不能审批此动作");
        }
        JsonNode snapshot = parseJson(row.actionRequestJson());
        String actionType = snapshot.path("actionType").asText();
        long policyId = snapshot.path("policyId").asLong(-1);
        JsonNode parameters = snapshot.path("parameters");
        PolicyRow policy = findPolicyForUpdate(policyId);
        AssetRow asset = findAssetForUpdate(row.assetId());
        if (!policyMatches(policy, actionType, asset, parameters)
                || !policy.policyKey().equals(snapshot.path("policyKey").asText())
                || !policy.version().equals(snapshot.path("policyVersion").asText())
                || policy.maxDurationSeconds() != snapshot.path("policyMaxDurationSeconds").asInt(-1)
                || !policy.environment().equals(snapshot.path("policyEnvironment").asText())) {
            throw ApiRequestException.conflict("审批策略已失效");
        }
        if (!hasAssetPermissionForUpdate(actor.id(), "approval.decide", row.assetId())) {
            throw ApiRequestException.notFound();
        }
        requireCurrentAuthorization(row.assetId(), actionType);
        String status = "approve".equals(decision) ? "approved" : "rejected";
        int updated = jdbc.update("UPDATE approval_task at SET status=?,reviewed_by=?,reviewed_at=UTC_TIMESTAMP(3),"
                        + "decision_reason=? WHERE id=? AND status='pending' AND requested_by<>? "
                        + "AND expires_at>UTC_TIMESTAMP(3) AND EXISTS (SELECT 1 FROM sys_user u "
                        + "JOIN sys_user_role ur ON ur.user_id=u.id JOIN sys_role r ON r.id=ur.role_id AND r.status='active' "
                        + "JOIN sys_role_permission rp ON rp.role_id=r.id JOIN sys_permission p "
                        + "ON p.id=rp.permission_id AND p.status='active' WHERE u.id=? AND u.status='active' "
                        + "AND p.permission_key='approval.decide' AND ((ur.scope_type='asset' AND ur.scope_id=?) "
                        + "OR (r.role_key='platform_admin' AND ur.scope_type='global' AND ur.scope_id='*'))) "
                        + "AND EXISTS (SELECT 1 FROM asset_authorization aa WHERE aa.asset_id=? AND aa.status='active' "
                        + "AND aa.valid_from<=UTC_TIMESTAMP(3) AND aa.valid_until>UTC_TIMESTAMP(3) "
                        + "AND JSON_CONTAINS(aa.scope_json,JSON_QUOTE(?),'$.actionTypes')) "
                        + "AND EXISTS (SELECT 1 FROM response_policy rp WHERE rp.id=? AND rp.status='active' "
                        + "AND rp.approved_by IS NOT NULL AND rp.auto_execute=FALSE AND rp.approval_required=TRUE "
                        + "AND rp.action_type=?) AND EXISTS (SELECT 1 FROM event_asset_link eal "
                        + "JOIN security_event se ON se.id=eal.event_id WHERE eal.event_id=? AND eal.asset_id=? "
                        + "AND se.status IN ('open','investigating','contained')) "
                        + "AND EXISTS (SELECT 1 FROM asset a WHERE a.id=? AND a.status='active')",
                status, actor.id(), summary, id, actor.id(), actor.id(), Long.toString(row.assetId()), row.assetId(),
                actionType, policyId, actionType, row.eventId(), row.assetId(), row.assetId());
        if (updated != 1) throw ApiRequestException.conflict("审批任务已被其他请求更新");
        audit(actor.id(), "approval." + status, id, row.assetId(), request, "response request reviewed");
        addTimeline(row.eventId(), actor.id(), "action_approval_" + status, id, "响应申请审批状态已更新");
        return findApproval(actor.id(), id, "approval.read");
    }

    /** 经过身份、请求者和资产范围校验后，明确拒绝；不创建 action_execution 记录。 */
    public ApiRequestException rejectExecution(long id, IdentityPrincipal actor, HttpServletRequest request) {
        ApprovalRow row = findApprovalRow(id);
        if (row == null || row.requestedBy() != actor.id()
                || !hasAssetPermission(actor.id(), "action.request", row.assetId())) {
            throw ApiRequestException.notFound();
        }
        requiresNew.executeWithoutResult(status -> audit(actor.id(), "action.execution.unavailable", id,
                row.assetId(), request, "adapter not configured; no action was executed"));
        return new ApiRequestException(HttpStatus.SERVICE_UNAVAILABLE, "ACTION_EXECUTION_UNAVAILABLE",
                "当前部署未配置经验证的响应适配器；动作未执行");
    }

    private RequestResult replayOrConflict(ApprovalRow existing, String digest) {
        if (!MessageDigest.isEqual(existing.requestDigest().getBytes(StandardCharsets.US_ASCII),
                digest.getBytes(StandardCharsets.US_ASCII))) {
            throw ApiRequestException.conflict("相同幂等键不能提交不同的响应申请");
        }
        return new RequestResult(existing.view(), false);
    }

    private ApprovalRow findByIdempotency(long userId, String key) {
        return jdbc.query("SELECT at.id,at.event_id,req.asset_id,CAST(at.action_request_json AS CHAR) action_request_json,"
                        + "at.status,at.requested_by,at.reviewed_by,at.expires_at,at.created_at,at.request_digest "
                        + "FROM approval_task at JOIN JSON_TABLE(at.action_request_json, '$' "
                        + "COLUMNS(asset_id BIGINT PATH '$.assetId')) req WHERE at.requested_by=? AND at.idempotency_key=?",
                rs -> rs.next() ? new ApprovalRow(rs.getLong("id"), rs.getLong("event_id"), rs.getLong("asset_id"),
                        rs.getString("action_request_json"), rs.getString("status"), rs.getLong("requested_by"),
                        rs.getObject("reviewed_by", Long.class), rs.getTimestamp("expires_at").toInstant(),
                        rs.getTimestamp("created_at").toLocalDateTime(), rs.getString("request_digest")) : null,
                userId, key);
    }

    private ApprovalRow findApprovalRow(long id) {
        return jdbc.query("SELECT at.id,at.event_id,req.asset_id,CAST(at.action_request_json AS CHAR) action_request_json,"
                        + "at.status,at.requested_by,at.reviewed_by,at.expires_at,at.created_at,at.request_digest "
                        + "FROM approval_task at JOIN JSON_TABLE(at.action_request_json, '$' "
                        + "COLUMNS(asset_id BIGINT PATH '$.assetId')) req JOIN event_asset_link eal "
                        + "ON eal.event_id=at.event_id AND eal.asset_id=req.asset_id WHERE at.id=?",
                rs -> rs.next() ? new ApprovalRow(rs.getLong("id"), rs.getLong("event_id"), rs.getLong("asset_id"),
                        rs.getString("action_request_json"), rs.getString("status"), rs.getLong("requested_by"),
                        rs.getObject("reviewed_by", Long.class), rs.getTimestamp("expires_at").toInstant(),
                        rs.getTimestamp("created_at").toLocalDateTime(), rs.getString("request_digest")) : null, id);
    }

    private ApprovalView findApproval(long userId, long id, String permission) {
        ApprovalRow row = findApprovalRow(id);
        if (row == null || !hasAssetPermission(userId, permission, row.assetId())) throw ApiRequestException.notFound();
        return row.view();
    }

    private PolicyRow findPolicy(long policyId) {
        return findPolicy(policyId, false);
    }

    private PolicyRow findPolicyForUpdate(long policyId) {
        return findPolicy(policyId, true);
    }

    private PolicyRow findPolicy(long policyId, boolean lockForUpdate) {
        if (policyId < 1) return null;
        return jdbc.query("SELECT id,policy_key,version,environment,CAST(match_json AS CHAR) match_json,action_type,"
                        + "CAST(action_params_json AS CHAR) action_params_json,auto_execute,approval_required,"
                        + "max_duration_seconds,status,approved_by FROM response_policy WHERE id=?"
                        + (lockForUpdate ? " FOR UPDATE" : ""),
                rs -> rs.next() ? new PolicyRow(rs.getLong("id"), rs.getString("policy_key"),
                        rs.getString("version"), rs.getString("environment"),
                        rs.getString("match_json"), rs.getString("action_type"),
                        rs.getString("action_params_json"), rs.getBoolean("auto_execute"),
                        rs.getBoolean("approval_required"), rs.getInt("max_duration_seconds"),
                        rs.getString("status"), rs.getObject("approved_by", Long.class)) : null, policyId);
    }

    private AssetRow findAsset(long assetId) {
        return findAsset(assetId, false);
    }

    private AssetRow findAssetForUpdate(long assetId) {
        return findAsset(assetId, true);
    }

    private AssetRow findAsset(long assetId, boolean lockForUpdate) {
        return jdbc.query("SELECT id,environment FROM asset WHERE id=? AND status='active'"
                        + (lockForUpdate ? " FOR UPDATE" : ""),
                rs -> rs.next() ? new AssetRow(rs.getLong("id"), rs.getString("environment")) : null, assetId);
    }

    private boolean policyMatches(PolicyRow policy, String actionType, AssetRow asset, JsonNode parameters) {
        if (policy == null || asset == null || !"active".equals(policy.status()) || policy.approvedBy() == null
                || policy.autoExecute() || !policy.approvalRequired() || !policy.actionType().equals(actionType)
                || !policy.environment().equals(asset.environment())) return false;
        JsonNode match = parseJson(policy.matchJson());
        if (!match.isObject() || match.size() != 1 || !match.has("environment")
                || !asset.environment().equals(match.path("environment").asText())) {
            return false;
        }
        JsonNode configured = parseJson(policy.actionParamsJson());
        if (!configured.isObject() || configured.size() != 2 || !configured.has("maxTtlSeconds")
                || !configured.has("allowedTargets")) return false;
        int policyTtl = configured.path("maxTtlSeconds").asInt(-1);
        int requestedTtl = parameters.path("ttlSeconds").asInt(-1);
        JsonNode allowedTargets = configured.path("allowedTargets");
        String target = parameters.path("targetAddress").asText("");
        if (policyTtl < 1 || requestedTtl < 1 || requestedTtl > policyTtl
                || requestedTtl > policy.maxDurationSeconds() || !isIpv4Literal(target)
                || !allowedTargets.isArray()) return false;
        for (JsonNode allowed : allowedTargets) {
            if (target.equals(allowed.asText())) return true;
        }
        return false;
    }

    private void requireCurrentAuthorization(long assetId, String actionType) {
        AuthorizationRow authorization = jdbc.query("SELECT scope_json,valid_from,valid_until FROM asset_authorization "
                        + "WHERE asset_id=? AND status='active' AND valid_from<=UTC_TIMESTAMP(3) "
                        + "AND valid_until>UTC_TIMESTAMP(3) "
                        + "AND JSON_CONTAINS(scope_json,JSON_QUOTE(?),'$.actionTypes') "
                        + "ORDER BY valid_until DESC LIMIT 1 FOR UPDATE",
                rs -> rs.next() ? new AuthorizationRow(rs.getString("scope_json"),
                        rs.getTimestamp("valid_from").toInstant(), rs.getTimestamp("valid_until").toInstant()) : null,
                assetId, actionType);
        if (authorization == null || !authorizationScopeAllows(authorization.scopeJson(), actionType)) {
            throw ApiRequestException.conflict("目标资产当前没有覆盖该动作的有效授权");
        }
    }

    private boolean authorizationScopeAllows(String scopeJson, String actionType) {
        try {
            JsonNode actions = objectMapper.readTree(scopeJson).path("actionTypes");
            if (!actions.isArray()) return false;
            for (JsonNode action : actions) if (actionType.equals(action.asText())) return true;
            return false;
        } catch (Exception exception) {
            return false;
        }
    }

    private boolean eventContainsAsset(long eventId, long assetId) {
        return Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS (SELECT 1 FROM event_asset_link "
                + "WHERE event_id=? AND asset_id=?)", Boolean.class, eventId, assetId));
    }

    private boolean eventContainsAssetForUpdate(long eventId, long assetId) {
        return Boolean.TRUE.equals(jdbc.query("SELECT event_id FROM event_asset_link WHERE event_id=? AND asset_id=? "
                + "FOR UPDATE", (org.springframework.jdbc.core.ResultSetExtractor<Boolean>) rs -> rs.next(),
                eventId, assetId));
    }

    private String eventStatus(long eventId) {
        return jdbc.query("SELECT status FROM security_event WHERE id=?", rs -> rs.next() ? rs.getString(1) : null,
                eventId);
    }

    private String eventStatusForUpdate(long eventId) {
        return jdbc.query("SELECT status FROM security_event WHERE id=? FOR UPDATE",
                rs -> rs.next() ? rs.getString(1) : null, eventId);
    }

    private boolean hasAssetPermission(long userId, String permission, long assetId) {
        return Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS (SELECT 1 FROM sys_user u "
                        + "JOIN sys_user_role ur ON ur.user_id=u.id JOIN sys_role r ON r.id=ur.role_id AND r.status='active' "
                        + "JOIN sys_role_permission rp ON rp.role_id=r.id JOIN sys_permission p "
                        + "ON p.id=rp.permission_id AND p.status='active' WHERE u.id=? AND u.status='active' "
                        + "AND p.permission_key=? AND ((ur.scope_type='asset' AND ur.scope_id=?) "
                        + "OR (r.role_key='platform_admin' AND ur.scope_type='global' AND ur.scope_id='*'))) ",
                Boolean.class, userId, permission, Long.toString(assetId)));
    }

    private boolean hasAssetPermissionForUpdate(long userId, String permission, long assetId) {
        List<Long> scopedRoles = jdbc.query("SELECT role_id FROM sys_user_role WHERE user_id=? AND "
                        + "((scope_type='asset' AND scope_id=?) OR (scope_type='global' AND scope_id='*')) FOR UPDATE",
                (rs, row) -> rs.getLong("role_id"), userId, Long.toString(assetId));
        return !scopedRoles.isEmpty() && hasAssetPermission(userId, permission, assetId);
    }

    private static String assetScopePredicate(String permission, String assetExpression) {
        return "SELECT 1 FROM sys_user u JOIN sys_user_role ur ON ur.user_id=u.id "
                + "JOIN sys_role r ON r.id=ur.role_id AND r.status='active' "
                + "JOIN sys_role_permission rp ON rp.role_id=r.id JOIN sys_permission p "
                + "ON p.id=rp.permission_id AND p.status='active' WHERE u.id=? AND u.status='active' "
                + "AND p.permission_key='" + permission + "' AND ((ur.scope_type='asset' AND ur.scope_id=CAST("
                + assetExpression + " AS CHAR)) OR (r.role_key='platform_admin' AND ur.scope_type='global' AND ur.scope_id='*'))";
    }

    private void requireAssetPermission(long userId, String permission, long assetId) {
        if (!hasAssetPermission(userId, permission, assetId)) throw ApiRequestException.notFound();
    }

    private String actionSnapshot(long eventId, ActionRequest input, JsonNode parameters, String reason) {
        ObjectNode snapshot = objectMapper.createObjectNode().put("eventId", eventId).put("assetId", input.assetId())
                .put("policyId", input.policyId()).put("actionType", input.actionType()).put("reason", reason);
        snapshot.set("parameters", parameters);
        try {
            return objectMapper.writeValueAsString(snapshot);
        } catch (Exception exception) {
            throw ApiRequestException.badRequest("响应申请无法规范化");
        }
    }

    private String actionSnapshot(long eventId, ActionRequest input, JsonNode parameters, String reason,
                                  PolicyRow policy) {
        ObjectNode snapshot = (ObjectNode) parseJson(actionSnapshot(eventId, input, parameters, reason));
        snapshot.put("policyKey", policy.policyKey()).put("policyVersion", policy.version())
                .put("policyEnvironment", policy.environment()).put("policyMaxDurationSeconds", policy.maxDurationSeconds());
        try {
            return objectMapper.writeValueAsString(snapshot);
        } catch (Exception exception) {
            throw ApiRequestException.badRequest("响应策略快照无法规范化");
        }
    }

    private JsonNode canonicalNode(JsonNode node) {
        if (node == null || !node.isObject()) throw ApiRequestException.badRequest("动作参数必须是 JSON 对象");
        ObjectNode result = objectMapper.createObjectNode();
        List<String> names = new ArrayList<>();
        node.fieldNames().forEachRemaining(names::add);
        names.sort(Comparator.naturalOrder());
        for (String name : names) {
            JsonNode value = node.get(name);
            if (value.isObject()) result.set(name, canonicalNode(value));
            else if (value.isArray()) {
                ArrayNode array = objectMapper.createArrayNode();
                for (JsonNode element : value) array.add(element.isObject() ? canonicalNode(element) : element.deepCopy());
                result.set(name, array);
            } else result.set(name, value.deepCopy());
        }
        return result;
    }

    private void validateTemporaryBlockParameters(String actionType, JsonNode parameters) {
        if (!"temporary_block".equals(actionType)
                || parameters.size() != 2 || !parameters.has("targetAddress") || !parameters.has("ttlSeconds")
                || !parameters.path("targetAddress").isTextual() || !parameters.path("ttlSeconds").isIntegralNumber()
                || !parameters.path("ttlSeconds").canConvertToInt()) {
            throw ApiRequestException.badRequest("首期仅接受受策略约束的 temporary_block 目标与 TTL 参数");
        }
    }

    private String validateIdempotencyKey(String value) {
        if (value == null || !value.matches("[A-Za-z0-9._:-]{8,160}")) {
            throw ApiRequestException.badRequest("Idempotency-Key 格式无效");
        }
        return value;
    }

    private String validatedReason(String reason) {
        if (reason == null) throw ApiRequestException.badRequest("申请或审批理由不能为空");
        String value = reason.trim();
        if (value.isEmpty() || value.length() > 1000 || value.chars().anyMatch(Character::isISOControl)) {
            throw ApiRequestException.badRequest("申请或审批理由长度或字符无效");
        }
        return value;
    }

    private JsonNode parseJson(String value) {
        try {
            return objectMapper.readTree(value);
        } catch (Exception exception) {
            return objectMapper.getNodeFactory().nullNode();
        }
    }

    private void audit(long actorId, String action, long approvalId, long assetId, HttpServletRequest request,
                       String reason) {
        Object requestId = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        GeneratedKeyHolder keyHolder = new GeneratedKeyHolder();
        jdbc.update(connection -> {
            PreparedStatement statement = connection.prepareStatement("INSERT INTO audit_log "
                    + "(occurred_at,actor_type,actor_id,action,resource_type,resource_id,request_id,outcome,reason) "
                    + "VALUES (?,'human',?,?, 'approval_task', ?, ?, 'success', ?)", Statement.RETURN_GENERATED_KEYS);
            statement.setTimestamp(1, Timestamp.from(clock.instant()));
            statement.setString(2, Long.toString(actorId));
            statement.setString(3, action);
            statement.setString(4, Long.toString(approvalId));
            statement.setString(5, requestId instanceof String value ? value : null);
            statement.setString(6, reason);
            return statement;
        }, keyHolder);
        jdbc.update("INSERT INTO audit_resource_scope (audit_id,scope_type,scope_id) VALUES (?,'asset',?)",
                keyHolder.getKey().longValue(), Long.toString(assetId));
    }

    private void addTimeline(long eventId, long actorId, String entryType, long taskId, String summary) {
        jdbc.update("INSERT INTO event_timeline (event_id,occurred_at,entry_type,actor_type,actor_id,summary,details_json) "
                        + "VALUES (?,UTC_TIMESTAMP(3),?,'human',?,?,JSON_OBJECT('approvalTaskId',?))",
                eventId, entryType, Long.toString(actorId), summary, taskId);
    }

    private static ApprovalView approvalView(long id, long eventId, long assetId, String snapshotJson, String status,
                                              long requestedBy, Long reviewedBy, LocalDateTime expiresAt,
                                              LocalDateTime createdAt) {
        try {
            return new ApprovalView(id, eventId, assetId, new ObjectMapper().readTree(snapshotJson), status,
                    requestedBy, reviewedBy, expiresAt, createdAt, false);
        } catch (Exception exception) {
            throw new IllegalStateException("Stored action request is invalid JSON", exception);
        }
    }

    private static int checkedOffset(int page, int size) {
        if (page < 0 || size < 1 || size > 100 || (long) page * size > Integer.MAX_VALUE) {
            throw ApiRequestException.badRequest("分页参数超出允许范围");
        }
        return page * size;
    }

    private static String sha256(String content) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(content.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception exception) {
            throw new IllegalStateException("SHA-256 is not available", exception);
        }
    }

    private static boolean isIpv4Literal(String value) {
        String[] parts = value.split("\\.", -1);
        if (parts.length != 4) return false;
        for (String part : parts) {
            if (part.isEmpty() || !part.matches("[0-9]{1,3}")) return false;
            int octet = Integer.parseInt(part);
            if (octet > 255 || (part.length() > 1 && part.charAt(0) == '0')) return false;
        }
        return true;
    }

    private record PolicyRow(long id, String policyKey, String version, String environment,
                             String matchJson, String actionType,
                             String actionParamsJson, boolean autoExecute, boolean approvalRequired,
                             int maxDurationSeconds, String status, Long approvedBy) { }
    private record AssetRow(long id, String environment) { }
    private record AuthorizationRow(String scopeJson, Instant validFrom, Instant validUntil) { }
    private record ApprovalRow(long id, long eventId, long assetId, String actionRequestJson, String status,
                               long requestedBy, Long reviewedBy, Instant expiresAt, LocalDateTime createdAt,
                               String requestDigest) {
        ApprovalView view() {
            return approvalView(id, eventId, assetId, actionRequestJson, status, requestedBy, reviewedBy,
                    expiresAt.atOffset(java.time.ZoneOffset.UTC).toLocalDateTime(), createdAt);
        }
    }

    public record ActionRequest(long assetId, long policyId, String actionType, JsonNode parameters, String reason) { }
    public record RequestResult(ApprovalView approval, boolean created) { }
    public record ApprovalView(long id, long eventId, long assetId, JsonNode actionRequest, String status,
                               long requestedBy, Long reviewedBy, LocalDateTime expiresAt,
                               LocalDateTime createdAt, boolean executionSupported) { }
    public record Page(long totalElements, int page, int size, List<ApprovalView> items) { }
}
