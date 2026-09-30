package com.xyh.cybersecurity.response.domain;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * 响应策略版本内容的纯校验（M6）：白名单动作、JSON Schema、TTL 上限、自动执行能力与语义约束。
 *
 * <p>不访问数据库、不修改输入；违规抛 {@link PolicyViolation}，由应用层映射为稳定错误码。
 * 起草时与批准时都调用：批准时重新校验，保证能力声明或上限收紧后旧草稿不能被批准生效。</p>
 */
public final class PolicyDefinitionValidator {
    private static final Pattern POLICY_KEY = Pattern.compile("^[a-z0-9][a-z0-9._-]{2,63}$");
    private static final Pattern ENVIRONMENT = Pattern.compile("^[a-z][a-z0-9_-]{1,31}$");
    private static final BigDecimal ONE = BigDecimal.ONE;

    private final RestrictedJsonSchema matchSchema;
    private final Map<String, RestrictedJsonSchema> paramSchemas;

    public PolicyDefinitionValidator(ObjectMapper json) {
        this.matchSchema = RestrictedJsonSchema.load(json, "response-policy/schema/match.json");
        this.paramSchemas = Map.of("temporary_block", RestrictedJsonSchema.load(json,
                ResponseActionCatalog.find("temporary_block").orElseThrow().paramsSchema()));
    }

    /**
     * @throws PolicyViolation 任一约束不满足。{@code code} 取值：{@code POLICY_DEFINITION_INVALID}（格式/Schema/语义）、
     *                         {@code ACTION_NOT_WHITELISTED}、{@code POLICY_TTL_EXCEEDED}、{@code AUTO_EXECUTE_NOT_ALLOWED}
     */
    public void validate(Definition d) {
        if (d.policyKey() == null || !POLICY_KEY.matcher(d.policyKey()).matches()) {
            throw invalid("策略键须为 3-64 位小写字母、数字、点、下划线或连字符");
        }
        if (d.environment() == null || !ENVIRONMENT.matcher(d.environment()).matches()) {
            throw invalid("环境标识格式无效");
        }
        ResponseActionCatalog.ActionCapability capability = ResponseActionCatalog.find(d.actionType())
                .orElseThrow(() -> new PolicyViolation("ACTION_NOT_WHITELISTED", "动作类型不在适配器白名单内"));
        requireSchema(matchSchema, d.match(), "匹配范围");
        if (!d.environment().equals(d.match().path("environment").asText())) {
            throw invalid("匹配范围的 environment 必须与策略环境一致");
        }
        requireSchema(paramSchemas.get(capability.actionType()), d.actionParams(), "动作参数");
        if (d.maxDurationSeconds() < 1 || d.maxDurationSeconds() > ResponseActionCatalog.SYSTEM_MAX_DURATION_SECONDS) {
            throw new PolicyViolation("POLICY_TTL_EXCEEDED",
                    "最大持续时间须在 1-" + ResponseActionCatalog.SYSTEM_MAX_DURATION_SECONDS + " 秒内");
        }
        if ("temporary_block".equals(capability.actionType())) validateTemporaryBlock(d);
        if (d.autoExecute() && !capability.autoExecuteAllowed()) {
            throw new PolicyViolation("AUTO_EXECUTE_NOT_ALLOWED", "该动作尚无经验证的回滚证据，不能配置为自动执行");
        }
        if (d.autoExecute() == d.approvalRequired()) {
            throw invalid("自动执行与人工审批必须二选一");
        }
        if (d.riskLimit() != null && (d.riskLimit().signum() < 0 || d.riskLimit().compareTo(ONE) > 0
                || d.riskLimit().scale() > 8)) {
            throw invalid("风险门槛须在 0-1 之间且最多 8 位小数");
        }
    }

    private static void validateTemporaryBlock(Definition d) {
        int ttl = d.actionParams().path("maxTtlSeconds").asInt();
        if (ttl > d.maxDurationSeconds()) {
            throw new PolicyViolation("POLICY_TTL_EXCEEDED", "动作 TTL 上限不能超过策略最大持续时间");
        }
        for (JsonNode target : d.actionParams().path("allowedTargets")) {
            if (!isUnicastTarget(target.asText())) {
                throw invalid("允许目标只能是单播 IPv4 地址，不接受回环、未指定、多播、广播或保留地址");
            }
        }
    }

    /** Schema 已保证点分十进制无前导零；这里排除非单播与不可作为阻断对象的地址段。 */
    static boolean isUnicastTarget(String literal) {
        String[] parts = literal.split("\\.", -1);
        if (parts.length != 4) return false;
        int a = Integer.parseInt(parts[0]);
        int b = Integer.parseInt(parts[1]);
        if (a == 0 || a == 127 || a >= 224) return false;          // 本网络、回环、多播 224/4、保留 240/4 与广播
        if (a == 169 && b == 254) return false;                     // 链路本地
        return !literal.equals("255.255.255.255");
    }

    private static void requireSchema(RestrictedJsonSchema schema, JsonNode value, String label) {
        if (value == null) throw invalid(label + "不能为空");
        List<String> errors = schema.validate(value);
        if (!errors.isEmpty()) {
            throw invalid(label + "不符合 Schema：" + errors.stream().limit(5).collect(Collectors.joining("；")));
        }
    }

    private static PolicyViolation invalid(String message) {
        return new PolicyViolation("POLICY_DEFINITION_INVALID", message);
    }

    /** 待校验的策略版本内容；JSON 字段为已解析的树。 */
    public record Definition(String policyKey, String environment, JsonNode match, String actionType,
                             JsonNode actionParams, BigDecimal riskLimit, boolean autoExecute,
                             boolean approvalRequired, int maxDurationSeconds) { }

    /** 稳定错误码 + 可返回给调用方的脱敏说明。 */
    public static final class PolicyViolation extends RuntimeException {
        private final String code;

        public PolicyViolation(String code, String message) {
            super(message);
            this.code = code;
        }

        public String code() { return code; }
    }
}
