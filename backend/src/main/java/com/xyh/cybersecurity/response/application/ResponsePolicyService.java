package com.xyh.cybersecurity.response.application;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import com.xyh.cybersecurity.response.domain.PolicyDefinitionValidator;
import com.xyh.cybersecurity.response.domain.PolicyLifecycle;
import com.xyh.cybersecurity.response.domain.PolicyLifecycle.Transition;
import com.xyh.cybersecurity.response.infra.ResponsePolicyMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/**
 * 响应策略版本化管理（M6，路线 B §14.1）。
 *
 * <p>契约：</p>
 * <ul>
 *   <li>版本不可原地修改。{@link #createDraft} 新建策略键的首个版本；{@link #createVersion} 以已有版本为基础新建
 *       下一个版本号的草稿，旧版本不变。版本号由服务端按策略键递增分配。</li>
 *   <li>状态迁移按 {@link PolicyLifecycle}：起草人提交/撤回本人版本；审批人批准或拒绝他人提交的版本；
 *       批准即生效，同一策略键的旧 active 版本在同一事务内退役；审批人可退役 active 版本。</li>
 *   <li>审批分离：起草人不能批准或拒绝本人版本（403，数据库 CHECK 兜底）；V15 前缺起草人的历史版本不能经接口审批。</li>
 *   <li>内容校验（白名单、Schema、TTL 上限、自动执行能力）在起草与批准时都执行，批准时不信任起草时的结论。</li>
 *   <li>每次迁移写追加审计，{@code after_hash} 为版本内容哈希。</li>
 * </ul>
 *
 * <p>副作用只限 {@code response_policy} 与 {@code audit_log}。本服务不创建审批任务、不调用适配器；
 * 退役策略后，引用它的待审批动作在审批时因策略不再 active 被拒绝（{@code ResponseMapper.updateApproval} 复核）。</p>
 */
@Service
public class ResponsePolicyService {
    private static final Set<String> LIST_STATUSES = Set.of("draft", "pending", "approved", "active", "rejected", "retired");
    private static final int LIST_LIMIT = 200;

    private final ResponsePolicyMapper mapper;
    private final ResponseSupport support;
    private final ObjectMapper json;
    private final PolicyDefinitionValidator validator;

    public ResponsePolicyService(ResponsePolicyMapper mapper, ResponseSupport support, ObjectMapper json) {
        this.mapper = mapper;
        this.support = support;
        this.json = json;
        this.validator = new PolicyDefinitionValidator(json);
    }

    /** 起草内容；JSON 字段由控制器原样传入，服务端规范化后再计算哈希。 */
    public record DraftInput(String policyKey, String environment, JsonNode match, String actionType,
                             JsonNode actionParams, BigDecimal riskLimit, Boolean autoExecute, Boolean approvalRequired,
                             Integer maxDurationSeconds, String reason) { }

    /** 返回给调用方的版本视图。{@code approved} 保留给既有前端，含义为已有批准人。 */
    public record PolicyView(long id, String policyKey, String version, String environment, JsonNode match,
                             String actionType, JsonNode actionParams, BigDecimal riskLimit, boolean autoExecute,
                             boolean approvalRequired, int maxDurationSeconds, String status, boolean approved,
                             Long createdBy, Long basedOnPolicyId, String changeReason, String contentSha256,
                             LocalDateTime submittedAt, Long approvedBy, Long reviewedBy, LocalDateTime reviewedAt,
                             String decisionReason, LocalDateTime retiredAt, Long retiredBy, LocalDateTime createdAt) { }

    public List<PolicyView> list(String status, String policyKey) {
        if (status != null && !LIST_STATUSES.contains(status)) throw ApiRequestException.badRequest("状态筛选值无效");
        return mapper.list(status, policyKey, LIST_LIMIT).stream().map(this::view).toList();
    }

    public PolicyView get(long id) {
        ResponsePolicyMapper.PolicyRow row = mapper.find(id);
        if (row == null) throw ApiRequestException.notFound();
        return view(row);
    }

    @Transactional
    public PolicyView createDraft(DraftInput input, IdentityPrincipal actor, HttpServletRequest request) {
        String reason = support.validatedReason(input.reason());
        if (input.policyKey() != null && !mapper.lockKey(input.policyKey()).isEmpty()) {
            throw new ApiRequestException(HttpStatus.CONFLICT, "POLICY_KEY_EXISTS", "策略键已存在；请基于已有版本新建版本");
        }
        return insertDraft(input, "1", null, reason, actor, request);
    }

    @Transactional
    public PolicyView createVersion(long baseId, DraftInput input, IdentityPrincipal actor, HttpServletRequest request) {
        String reason = support.validatedReason(input.reason());
        ResponsePolicyMapper.PolicyRow base = mapper.find(baseId);
        if (base == null) throw ApiRequestException.notFound();
        if (input.policyKey() != null && !input.policyKey().equals(base.policyKey())) {
            throw ApiRequestException.badRequest("新版本不能更改策略键");
        }
        List<ResponsePolicyMapper.PolicyRow> versions = mapper.lockKey(base.policyKey());
        if (versions.stream().anyMatch(v -> Set.of("draft", "pending").contains(v.status()))) {
            throw new ApiRequestException(HttpStatus.CONFLICT, "POLICY_VERSION_IN_PROGRESS",
                    "该策略键已有未决版本；请先提交审批或撤回");
        }
        DraftInput merged = new DraftInput(base.policyKey(),
                input.environment() != null ? input.environment() : base.environment(),
                input.match() != null ? input.match() : support.parseJson(base.matchJson()),
                input.actionType() != null ? input.actionType() : base.actionType(),
                input.actionParams() != null ? input.actionParams() : support.parseJson(base.actionParamsJson()),
                input.riskLimit() != null ? input.riskLimit() : base.riskLimit(),
                input.autoExecute() != null ? input.autoExecute() : base.autoExecute(),
                input.approvalRequired() != null ? input.approvalRequired() : base.approvalRequired(),
                input.maxDurationSeconds() != null ? input.maxDurationSeconds() : base.maxDurationSeconds(),
                input.reason());
        return insertDraft(merged, nextVersion(versions), base.id(), reason, actor, request);
    }

    @Transactional
    public PolicyView submit(long id, IdentityPrincipal actor, HttpServletRequest request) {
        ResponsePolicyMapper.PolicyRow row = lockOwned(id, actor);
        requireTransition(row, Transition.SUBMIT);
        revalidate(row);
        if (mapper.submit(id, actor.id()) != 1) throw ApiRequestException.conflict("策略版本已被其他请求更新");
        audit(actor.id(), "response.policy.submitted", id, request, "submitted for review", row.contentSha256());
        return get(id);
    }

    @Transactional
    public PolicyView withdraw(long id, IdentityPrincipal actor, HttpServletRequest request) {
        ResponsePolicyMapper.PolicyRow row = lockOwned(id, actor);
        requireTransition(row, Transition.WITHDRAW);
        if (mapper.withdraw(id, actor.id()) != 1) throw ApiRequestException.conflict("策略版本已被其他请求更新");
        audit(actor.id(), "response.policy.withdrawn", id, request, "withdrawn by author", row.contentSha256());
        return get(id);
    }

    /**
     * 审批他人提交的版本。批准前按策略键锁定全部版本，重新校验内容，退役旧 active 版本后激活本版本。
     *
     * @throws org.springframework.security.access.AccessDeniedException 起草人审批本人版本
     */
    @Transactional
    public PolicyView decide(long id, String decision, String reasonText, IdentityPrincipal actor,
                             HttpServletRequest request) {
        if (!Set.of("approve", "reject").contains(decision)) throw ApiRequestException.badRequest("策略审批决定无效");
        String reason = support.validatedReason(reasonText);
        ResponsePolicyMapper.PolicyRow found = mapper.find(id);
        if (found == null) throw ApiRequestException.notFound();
        List<ResponsePolicyMapper.PolicyRow> versions = mapper.lockKey(found.policyKey());
        ResponsePolicyMapper.PolicyRow row = versions.stream().filter(v -> v.id() == id).findFirst()
                .orElseThrow(ApiRequestException::notFound);
        if (row.createdBy() == null) {
            throw new ApiRequestException(HttpStatus.CONFLICT, "POLICY_AUTHOR_UNKNOWN", "历史策略缺少起草人，不能经接口审批");
        }
        if (row.createdBy() == actor.id()) {
            throw new org.springframework.security.access.AccessDeniedException("Policy author cannot decide own version");
        }
        if ("approve".equals(decision)) {
            requireTransition(row, Transition.APPROVE);
            revalidate(row);
            for (ResponsePolicyMapper.PolicyRow other : versions) {
                if (other.id() != id && "active".equals(other.status())) {
                    if (mapper.retireActive(other.id(), actor.id()) != 1) {
                        throw ApiRequestException.conflict("旧 active 版本已被其他请求更新");
                    }
                    audit(actor.id(), "response.policy.superseded", other.id(), request,
                            "superseded by policy " + id, other.contentSha256());
                }
            }
            if (mapper.approve(id, actor.id(), reason) != 1) throw ApiRequestException.conflict("策略版本已被其他请求更新");
            audit(actor.id(), "response.policy.approved", id, request, reason, row.contentSha256());
        } else {
            requireTransition(row, Transition.REJECT);
            if (mapper.reject(id, actor.id(), reason) != 1) throw ApiRequestException.conflict("策略版本已被其他请求更新");
            audit(actor.id(), "response.policy.rejected", id, request, reason, row.contentSha256());
        }
        return get(id);
    }

    /** 审批人退役 active 版本；draft/pending 由起草人经 {@link #withdraw} 撤回。 */
    @Transactional
    public PolicyView retire(long id, String reasonText, IdentityPrincipal actor, HttpServletRequest request) {
        String reason = support.validatedReason(reasonText);
        ResponsePolicyMapper.PolicyRow row = mapper.findForUpdate(id);
        if (row == null) throw ApiRequestException.notFound();
        requireTransition(row, Transition.RETIRE);
        if (mapper.retireActive(id, actor.id()) != 1) throw ApiRequestException.conflict("策略版本已被其他请求更新");
        audit(actor.id(), "response.policy.retired", id, request, reason, row.contentSha256());
        return get(id);
    }

    private PolicyView insertDraft(DraftInput input, String version, Long basedOn, String reason,
                                   IdentityPrincipal actor, HttpServletRequest request) {
        if (input.autoExecute() == null || input.approvalRequired() == null || input.maxDurationSeconds() == null) {
            throw ApiRequestException.badRequest("须声明自动执行、人工审批与最大持续时间");
        }
        // 非对象输入原样交给 Schema 报类型错误；对象才规范化键序。
        JsonNode match = input.match() != null && input.match().isObject() ? support.canonicalNode(input.match()) : input.match();
        JsonNode params = input.actionParams() != null && input.actionParams().isObject()
                ? support.canonicalNode(input.actionParams()) : input.actionParams();
        PolicyDefinitionValidator.Definition definition = new PolicyDefinitionValidator.Definition(input.policyKey(),
                input.environment(), match, input.actionType(), params, input.riskLimit(), input.autoExecute(),
                input.approvalRequired(), input.maxDurationSeconds());
        validate(definition);
        String hash = contentHash(definition);
        ResponsePolicyMapper.PolicyInsert insert = new ResponsePolicyMapper.PolicyInsert(input.policyKey(), version,
                input.environment(), match.toString(), input.actionType(), params.toString(), input.riskLimit(),
                input.autoExecute(), input.approvalRequired(), input.maxDurationSeconds(), actor.id(), basedOn,
                reason, hash);
        try {
            mapper.insert(insert);
        } catch (DuplicateKeyException exception) {
            throw new ApiRequestException(HttpStatus.CONFLICT, "POLICY_KEY_EXISTS", "策略键与版本已存在");
        }
        audit(actor.id(), "response.policy.drafted", insert.getId(), request, reason, hash);
        return get(insert.getId());
    }

    /** 批准/提交前重新校验已入库内容，并核对内容哈希未被库外修改。 */
    private void revalidate(ResponsePolicyMapper.PolicyRow row) {
        PolicyDefinitionValidator.Definition definition = definition(row);
        validate(definition);
        if (row.contentSha256() == null || !row.contentSha256().equals(contentHash(definition))) {
            throw new ApiRequestException(HttpStatus.CONFLICT, "POLICY_CONTENT_MISMATCH", "策略内容与登记哈希不一致，拒绝处理");
        }
    }

    private void validate(PolicyDefinitionValidator.Definition definition) {
        try {
            validator.validate(definition);
        } catch (PolicyDefinitionValidator.PolicyViolation violation) {
            HttpStatus status = "POLICY_DEFINITION_INVALID".equals(violation.code())
                    ? HttpStatus.BAD_REQUEST : HttpStatus.UNPROCESSABLE_ENTITY;
            throw new ApiRequestException(status, violation.code(), violation.getMessage());
        }
    }

    private PolicyDefinitionValidator.Definition definition(ResponsePolicyMapper.PolicyRow row) {
        return new PolicyDefinitionValidator.Definition(row.policyKey(), row.environment(),
                support.canonicalNode(support.parseJson(row.matchJson())), row.actionType(),
                support.canonicalNode(support.parseJson(row.actionParamsJson())), row.riskLimit(), row.autoExecute(),
                row.approvalRequired(), row.maxDurationSeconds());
    }

    /** 规范化内容哈希：键有序 JSON，风险门槛按去尾零的十进制字符串，避免数据库 DECIMAL 标度影响哈希。 */
    private String contentHash(PolicyDefinitionValidator.Definition d) {
        ObjectNode node = json.createObjectNode();
        node.put("actionType", d.actionType());
        node.set("actionParams", d.actionParams());
        node.put("approvalRequired", d.approvalRequired());
        node.put("autoExecute", d.autoExecute());
        node.put("environment", d.environment());
        node.set("match", d.match());
        node.put("maxDurationSeconds", d.maxDurationSeconds());
        node.put("policyKey", d.policyKey());
        if (d.riskLimit() == null) node.putNull("riskLimit");
        else node.put("riskLimit", d.riskLimit().stripTrailingZeros().toPlainString());
        return support.sha256(node.toString());
    }

    private ResponsePolicyMapper.PolicyRow lockOwned(long id, IdentityPrincipal actor) {
        ResponsePolicyMapper.PolicyRow row = mapper.findForUpdate(id);
        if (row == null) throw ApiRequestException.notFound();
        if (row.createdBy() == null || row.createdBy() != actor.id()) {
            throw new org.springframework.security.access.AccessDeniedException("Only the author may change this version");
        }
        return row;
    }

    private static void requireTransition(ResponsePolicyMapper.PolicyRow row, Transition transition) {
        if (!PolicyLifecycle.allowed(row.status(), transition)) {
            throw new ApiRequestException(HttpStatus.CONFLICT, "POLICY_STATE_CONFLICT",
                    "当前状态 " + row.status() + " 不允许该操作");
        }
    }

    /** 下一个版本号：已有纯数字版本的最大值 + 1；历史非数字版本不参与计算。 */
    static String nextVersion(List<ResponsePolicyMapper.PolicyRow> versions) {
        long max = 0;
        for (ResponsePolicyMapper.PolicyRow v : versions) {
            if (v.version() != null && v.version().matches("[1-9][0-9]{0,8}")) max = Math.max(max, Long.parseLong(v.version()));
        }
        return Long.toString(max + 1);
    }

    private void audit(long actorId, String action, long policyId, HttpServletRequest request, String reason,
                       String hash) {
        Object requestId = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        mapper.insertAudit(new ResponsePolicyMapper.PolicyAudit(LocalDateTime.now(ZoneOffset.UTC), actorId, action,
                policyId, requestId instanceof String value ? value : null, reason, hash));
    }

    private PolicyView view(ResponsePolicyMapper.PolicyRow r) {
        return new PolicyView(r.id(), r.policyKey(), r.version(), r.environment(), support.parseJson(r.matchJson()),
                r.actionType(), support.parseJson(r.actionParamsJson()), r.riskLimit(), r.autoExecute(),
                r.approvalRequired(), r.maxDurationSeconds(), r.status(), r.approvedBy() != null, r.createdBy(),
                r.basedOnPolicyId(), r.changeReason(), r.contentSha256(), r.submittedAt(), r.approvedBy(),
                r.reviewedBy(), r.reviewedAt(), r.decisionReason(), r.retiredAt(), r.retiredBy(), r.createdAt());
    }
}
