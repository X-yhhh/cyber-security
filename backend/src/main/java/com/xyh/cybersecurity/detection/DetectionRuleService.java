package com.xyh.cybersecurity.detection;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.xyh.cybersecurity.audit.AuditMapper;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import com.xyh.cybersecurity.ingest.contract.FeatureContractRegistry;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/**
 * 确定性检测规则的登记与批准（路线 B §11）。规则只检测、不执行动作；条件为受限结构（{@link RuleCondition}），
 * 登记时校验，登记人不能批准本人规则，批准后同一规则键的旧 active 版本自动退役。
 */
@Service
public class DetectionRuleService {
    private static final Pattern RULE_KEY = Pattern.compile("^[a-z0-9][a-z0-9._-]{2,63}$");
    private static final Pattern VERSION = Pattern.compile("^[A-Za-z0-9._-]{1,32}$");

    private final DetectionMapper mapper;
    private final AuditMapper auditMapper;
    private final FeatureContractRegistry contracts;
    private final ObjectMapper json;

    public DetectionRuleService(DetectionMapper mapper, AuditMapper auditMapper, FeatureContractRegistry contracts,
                                ObjectMapper json) {
        this.mapper = mapper;
        this.auditMapper = auditMapper;
        this.contracts = contracts;
        this.json = json;
    }

    public List<DetectionMapper.RuleView> list() { return mapper.listRules(); }

    /** 只读详情不持有写锁；版本内容不会被覆盖。 */
    public DetectionMapper.RuleView get(long id) {
        var row = mapper.findRule(id);
        if (row == null) throw ApiRequestException.notFound();
        return row;
    }

    /** 从任意旧版本复制内容；新版本仍为 pending，必须由另一人批准。 */
    @Transactional
    public DetectionMapper.RuleView createVersion(long baseId, CreateRule input, IdentityPrincipal actor, HttpServletRequest request) {
        var base = get(baseId);
        if (input.ruleKey() != null && !input.ruleKey().equals(base.ruleKey())) throw ApiRequestException.badRequest("不可更改规则键");
        mapper.lockRuleVersions(base.ruleKey());
        var result = create(new CreateRule(base.ruleKey(), input.version(), input.severity() == null ? base.severity() : input.severity(),
                input.condition() == null ? parse(base.conditionJson()) : input.condition(),
                input.scope() == null ? parse(base.scopeJson()) : input.scope(), input.reason()), actor, request);
        audit(actor.id(), "detection.rule.version.based_on", result.id(), request, "来源版本 " + baseId);
        return result;
    }

    @Transactional
    public DetectionMapper.RuleView retire(long id, String reasonText, IdentityPrincipal actor, HttpServletRequest request) {
        String reason = reason(reasonText);
        var found = get(id);
        mapper.lockRuleVersions(found.ruleKey());
        if (mapper.retireRule(id) != 1) throw ApiRequestException.conflict("只允许退役 active 规则");
        audit(actor.id(), "detection.rule.retired", id, request, reason);
        return get(id);
    }

    private JsonNode parse(String text) {
        try { return json.readTree(text); }
        catch (Exception e) { throw ApiRequestException.conflict("来源规则内容损坏"); }
    }

    public record CreateRule(String ruleKey, String version, String severity, JsonNode condition, JsonNode scope,
                             String reason) { }

    @Transactional
    public DetectionMapper.RuleView create(CreateRule input, IdentityPrincipal actor, HttpServletRequest request) {
        if (input.ruleKey() == null || !RULE_KEY.matcher(input.ruleKey()).matches()) {
            throw ApiRequestException.badRequest("规则键须为 3-64 位小写字母、数字、点、下划线或连字符");
        }
        if (input.version() == null || !VERSION.matcher(input.version()).matches()) {
            throw ApiRequestException.badRequest("规则版本格式无效");
        }
        if (input.severity() == null || !DetectionPolicies.SEVERITIES.contains(input.severity())) throw ApiRequestException.badRequest("严重度无效");
        String reason = reason(input.reason());
        try {
            RuleCondition.parse(input.condition());
        } catch (IllegalArgumentException exception) {
            throw ApiRequestException.badRequest("规则条件不合规：" + exception.getMessage());
        }
        String scope = scope(input.scope());
        try {
            mapper.insertRule(input.ruleKey(), input.version(), scope, input.condition().toString(), input.severity(),
                    actor.id());
        } catch (DuplicateKeyException exception) {
            throw ApiRequestException.conflict("同一规则键与版本已登记");
        }
        long id = mapper.findRuleId(input.ruleKey(), input.version());
        audit(actor.id(), "detection.rule.requested", id, request, reason);
        return mapper.findRuleForUpdate(id);
    }

    @Transactional
    public DetectionMapper.RuleView decide(long id, String decision, String reasonText, IdentityPrincipal actor,
                                           HttpServletRequest request) {
        if (!Set.of("approve", "reject").contains(decision)) throw ApiRequestException.badRequest("规则审批决定无效");
        String reason = reason(reasonText);
        var found = get(id);
        mapper.lockRuleVersions(found.ruleKey());
        DetectionMapper.RuleView rule = mapper.findRuleForUpdate(id);
        if (rule == null) throw ApiRequestException.notFound();
        if (rule.requestedBy() != null && rule.requestedBy() == actor.id()) {
            throw new AccessDeniedException("Rule requester cannot decide their own rule");
        }
        if (!"pending".equals(rule.status())) throw ApiRequestException.conflict("规则已被处理");
        if ("approve".equals(decision)) {
            mapper.retireOtherActiveVersions(rule.ruleKey(), id);
            if (mapper.activateRule(id, actor.id()) != 1) throw ApiRequestException.conflict("规则已被其他请求更新");
            audit(actor.id(), "detection.rule.approved", id, request, reason);
        } else {
            if (mapper.rejectRule(id) != 1) throw ApiRequestException.conflict("规则已被其他请求更新");
            audit(actor.id(), "detection.rule.rejected", id, request, reason);
        }
        return mapper.findRuleForUpdate(id);
    }

    /** 范围只允许声明特征契约版本（须已注册）；其他键拒绝，避免规则携带未解释的配置。 */
    private String scope(JsonNode scope) {
        ObjectNode normalized = json.createObjectNode();
        if (scope == null || scope.isNull()) return normalized.toString();
        if (!scope.isObject()) throw ApiRequestException.badRequest("规则范围须为对象");
        scope.fieldNames().forEachRemaining(name -> {
            if (!"featureContractVersion".equals(name)) throw ApiRequestException.badRequest("规则范围含未知字段");
        });
        JsonNode version = scope.get("featureContractVersion");
        if (version != null) {
            if (!version.isTextual() || contracts.find(version.asText()) == null) {
                throw ApiRequestException.badRequest("规则范围引用了未注册的特征契约");
            }
            normalized.put("featureContractVersion", version.asText());
        }
        return normalized.toString();
    }

    private static String reason(String reason) {
        if (reason == null || reason.isBlank() || reason.length() > 1000) {
            throw ApiRequestException.badRequest("须填写 1-1000 字的理由");
        }
        return reason.trim();
    }

    private void audit(long actorId, String action, long ruleId, HttpServletRequest request, String reason) {
        Object requestId = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        auditMapper.insertAudit(new AuditMapper.AuditInsert(LocalDateTime.now(ZoneOffset.UTC), "human", Long.toString(actorId), action,
                "detection_rule", Long.toString(ruleId), requestId instanceof String value ? value : null, "success",
                reason));
    }
}
