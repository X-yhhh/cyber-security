package com.xyh.cybersecurity.detection;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import com.xyh.cybersecurity.response.application.ResponseSupport;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;
import java.util.Set;
import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/**
 * 检测策略版本化事务边界。内容不可覆盖，起草人和审批人分离；同类型批准串行并原子替换 active。
 * 退役最后一个 active 后消费显式失败，禁止使用未批准草稿或默认参数。所有迁移追加内容哈希审计。
 */
@Service
public class DetectionPolicyService {
    private static final Set<String> TYPES = Set.of("severity_mapping", "correlation", "risk_score");
    private final DetectionPolicyMapper mapper;
    private final ResponseSupport support;
    private final ObjectMapper json;
    public DetectionPolicyService(DetectionPolicyMapper mapper, ResponseSupport support, ObjectMapper json) {
        this.mapper = mapper; this.support = support; this.json = json;
    }
    public List<DetectionPolicyMapper.Row> list() { return mapper.list(); }
    public DetectionPolicyMapper.Row get(long id) {
        var row = mapper.find(id);
        if (row == null) throw ApiRequestException.notFound();
        return row;
    }
    public record Draft(String policyType, JsonNode config, String reason) { }

    /** 版本号由服务端分配；复制旧版时必须显式提交新内容，以免误复制已废弃的分层语义。 */
    @Transactional
    public DetectionPolicyMapper.Row create(Long baseId, Draft input, IdentityPrincipal actor, HttpServletRequest request) {
        String reason = support.validatedReason(input.reason());
        String type = baseId == null ? input.policyType() : get(baseId).policyType();
        if (type == null || !TYPES.contains(type) || (input.policyType() != null && !input.policyType().equals(type))) {
            throw ApiRequestException.badRequest("检测策略类型无效或与来源不一致");
        }
        validate(type, input.config());
        mapper.lockType(type);
        List<DetectionPolicyMapper.Row> versions = mapper.versions(type);
        if (versions.stream().anyMatch(r -> Set.of("draft", "pending").contains(r.status()))) {
            throw ApiRequestException.conflict("该类型已有未决版本");
        }
        long next = versions.stream().map(DetectionPolicyMapper.Row::version).filter(v -> v.matches("[1-9][0-9]{0,8}"))
                .mapToLong(Long::parseLong).max().orElse(0) + 1;
        String config = support.canonicalNode(input.config()).toString();
        String version = Long.toString(next);
        String hash = hash(type, version, config);
        mapper.insert(type, version, config, actor.id(), baseId, reason, hash);
        long id = mapper.findId(type, version);
        audit(id, actor, "drafted", reason, hash, request);
        return get(id);
    }

    @Transactional
    public DetectionPolicyMapper.Row submit(long id, IdentityPrincipal actor, HttpServletRequest request) {
        var row = lock(id);
        owned(row, actor); state(row, "draft"); revalidate(row);
        mapper.submit(id);
        audit(id, actor, "submitted", "提交独立审批", row.contentSha256(), request);
        return get(id);
    }

    @Transactional
    public DetectionPolicyMapper.Row decide(long id, String decision, String reasonText, IdentityPrincipal actor,
                                             HttpServletRequest request) {
        String reason = support.validatedReason(reasonText);
        if (decision == null || !Set.of("approve", "reject").contains(decision)) throw ApiRequestException.badRequest("审批决定无效");
        var row = lock(id);
        state(row, "pending");
        if (row.createdBy() == null || row.createdBy() == actor.id()) throw new AccessDeniedException("独立审批要求起草人与审批人不同");
        revalidate(row);
        if (decision.equals("approve")) {
            for (var old : mapper.versions(row.policyType())) {
                if (old.status().equals("active")) {
                    mapper.retire(old.id(), actor.id());
                    audit(old.id(), actor, "superseded", "由版本 " + id + " 替代", contentHash(old), request);
                }
            }
        }
        mapper.decide(id, decision.equals("approve") ? "active" : "rejected", actor.id(), reason);
        audit(id, actor, decision.equals("approve") ? "approved" : "rejected", reason, row.contentSha256(), request);
        return get(id);
    }

    @Transactional
    public DetectionPolicyMapper.Row retire(long id, String reasonText, boolean withdraw, IdentityPrincipal actor,
                                             HttpServletRequest request) {
        String reason = support.validatedReason(reasonText);
        var row = lock(id);
        if (withdraw) { owned(row, actor); state(row, "draft", "pending"); }
        else state(row, "active");
        mapper.retire(id, actor.id());
        audit(id, actor, withdraw ? "withdrawn" : "retired", reason, contentHash(row), request);
        return get(id);
    }

    private DetectionPolicyMapper.Row lock(long id) {
        var found = get(id);
        mapper.lockType(found.policyType());
        return mapper.versions(found.policyType()).stream().filter(r -> r.id() == id).findFirst().orElseThrow(ApiRequestException::notFound);
    }
    private void revalidate(DetectionPolicyMapper.Row row) {
        validate(row.policyType(), support.parseJson(row.configJson()));
        if (!contentHash(row).equals(row.contentSha256())) throw ApiRequestException.conflict("检测策略内容哈希不一致");
    }
    private void validate(String type, JsonNode config) {
        try { DetectionPolicies.validate(type, config); }
        catch (DetectionUnavailableException exception) { throw ApiRequestException.badRequest("检测策略参数不合规"); }
    }
    private String contentHash(DetectionPolicyMapper.Row row) { return hash(row.policyType(), row.version(), row.configJson()); }
    private String hash(String type, String version, String config) {
        var node = json.createObjectNode().put("policyType", type).put("version", version);
        node.set("config", support.canonicalNode(support.parseJson(config)));
        return support.sha256(node.toString());
    }
    private static void owned(DetectionPolicyMapper.Row row, IdentityPrincipal actor) {
        if (row.createdBy() == null || row.createdBy() != actor.id()) throw new AccessDeniedException("只有起草人可操作该版本");
    }
    private static void state(DetectionPolicyMapper.Row row, String... allowed) {
        if (!Set.of(allowed).contains(row.status())) throw ApiRequestException.conflict("检测策略状态不允许此操作");
    }
    private void audit(long id, IdentityPrincipal actor, String action, String reason, String hash, HttpServletRequest request) {
        mapper.audit(actor.id(), "detection.policy." + action, id, (String) request.getAttribute(REQUEST_ID_ATTRIBUTE), reason, hash);
    }
}
