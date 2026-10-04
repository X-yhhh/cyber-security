package com.xyh.cybersecurity.response;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.response.domain.PolicyDefinitionValidator;
import com.xyh.cybersecurity.response.domain.PolicyDefinitionValidator.Definition;
import com.xyh.cybersecurity.response.domain.PolicyDefinitionValidator.PolicyViolation;
import com.xyh.cybersecurity.response.domain.PolicyLifecycle;
import com.xyh.cybersecurity.response.domain.PolicyLifecycle.Transition;
import com.xyh.cybersecurity.response.domain.RestrictedJsonSchema;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThatCode;

/** M6 策略内容校验：白名单、Schema、TTL 上限、自动执行能力与状态机。 */
class PolicyDefinitionValidatorTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final PolicyDefinitionValidator validator = new PolicyDefinitionValidator(JSON);

    private static JsonNode json(String text) {
        try { return JSON.readTree(text); } catch (Exception e) { throw new IllegalStateException(e); }
    }

    private static Definition valid() {
        return new Definition("lab-block", "lab", json("{\"environment\":\"lab\"}"), "temporary_block",
                json("{\"allowedTargets\":[\"192.0.2.25\"],\"maxTtlSeconds\":120}"), null, false, true, 120);
    }

    private static Definition with(String params, int maxDuration) {
        Definition d = valid();
        return new Definition(d.policyKey(), d.environment(), d.match(), d.actionType(), json(params), d.riskLimit(),
                d.autoExecute(), d.approvalRequired(), maxDuration);
    }

    private String code(Definition d) {
        try { validator.validate(d); return null; } catch (PolicyViolation v) { return v.code(); }
    }

    @Test
    void acceptsNarrowTemporaryBlock() {
        assertThatCode(() -> validator.validate(valid())).doesNotThrowAnyException();
    }

    @Test
    void rejectsActionOutsideWhitelist() {
        Definition d = valid();
        assertThat(code(new Definition(d.policyKey(), d.environment(), d.match(), "rate_limit", d.actionParams(),
                null, false, true, 120))).isEqualTo("ACTION_NOT_WHITELISTED");
        assertThat(code(new Definition(d.policyKey(), d.environment(), d.match(), "shell", d.actionParams(),
                null, false, true, 120))).isEqualTo("ACTION_NOT_WHITELISTED");
    }

    @Test
    void autoExecuteRejectedWhileRollbackUnverified() {
        Definition d = valid();
        assertThat(code(new Definition(d.policyKey(), d.environment(), d.match(), d.actionType(), d.actionParams(),
                null, true, false, 120))).isEqualTo("AUTO_EXECUTE_NOT_ALLOWED");
        // 既不自动执行又不要求审批：无意义组合，按定义无效处理。
        assertThat(code(new Definition(d.policyKey(), d.environment(), d.match(), d.actionType(), d.actionParams(),
                null, false, false, 120))).isEqualTo("POLICY_DEFINITION_INVALID");
    }

    @Test
    void enforcesTtlCeilings() {
        assertThat(code(with("{\"allowedTargets\":[\"192.0.2.25\"],\"maxTtlSeconds\":120}", 3601)))
                .isEqualTo("POLICY_TTL_EXCEEDED");
        assertThat(code(with("{\"allowedTargets\":[\"192.0.2.25\"],\"maxTtlSeconds\":300}", 120)))
                .isEqualTo("POLICY_TTL_EXCEEDED");
        assertThat(code(with("{\"allowedTargets\":[\"192.0.2.25\"],\"maxTtlSeconds\":3601}", 3600)))
                .isEqualTo("POLICY_DEFINITION_INVALID");
    }

    @Test
    void schemaRejectsUnknownFieldsBadTypesAndNonLiteralTargets() {
        for (String params : new String[] {
                "{\"allowedTargets\":[\"192.0.2.25\"],\"maxTtlSeconds\":120,\"command\":\"pfctl\"}",
                "{\"allowedTargets\":[\"192.0.2.0/24\"],\"maxTtlSeconds\":120}",
                "{\"allowedTargets\":[\"example.com\"],\"maxTtlSeconds\":120}",
                "{\"allowedTargets\":[\"192.0.2.025\"],\"maxTtlSeconds\":120}",
                "{\"allowedTargets\":[],\"maxTtlSeconds\":120}",
                "{\"allowedTargets\":[\"192.0.2.25\",\"192.0.2.25\"],\"maxTtlSeconds\":120}",
                "{\"allowedTargets\":[\"192.0.2.25\"],\"maxTtlSeconds\":120.5}",
                "{\"allowedTargets\":[\"192.0.2.25\"]}",
                "[]"}) {
            assertThat(code(with(params, 120))).as(params).isEqualTo("POLICY_DEFINITION_INVALID");
        }
    }

    @Test
    void rejectsNonUnicastTargets() {
        for (String target : new String[] {"127.0.0.1", "0.0.0.0", "224.0.0.251", "255.255.255.255", "169.254.1.1",
                "240.0.0.1"}) {
            assertThat(code(with("{\"allowedTargets\":[\"" + target + "\"],\"maxTtlSeconds\":60}", 120)))
                    .as(target).isEqualTo("POLICY_DEFINITION_INVALID");
        }
    }

    @Test
    void matchMustEqualEnvironmentAndHaveNoOtherKeys() {
        Definition d = valid();
        assertThat(code(new Definition(d.policyKey(), "lab", json("{\"environment\":\"authorized\"}"), d.actionType(),
                d.actionParams(), null, false, true, 120))).isEqualTo("POLICY_DEFINITION_INVALID");
        assertThat(code(new Definition(d.policyKey(), "lab", json("{\"environment\":\"lab\",\"assetId\":1}"),
                d.actionType(), d.actionParams(), null, false, true, 120))).isEqualTo("POLICY_DEFINITION_INVALID");
    }

    @Test
    void riskLimitBounds() {
        Definition d = valid();
        for (String risk : new String[] {"-0.1", "1.5", "0.123456789"}) {
            assertThat(code(new Definition(d.policyKey(), d.environment(), d.match(), d.actionType(), d.actionParams(),
                    new BigDecimal(risk), false, true, 120))).as(risk).isEqualTo("POLICY_DEFINITION_INVALID");
        }
        assertThat(code(new Definition(d.policyKey(), d.environment(), d.match(), d.actionType(), d.actionParams(),
                new BigDecimal("0.9"), false, true, 120))).isNull();
    }

    @Test
    void restrictedSchemaFailsClosedOnUnsupportedKeywords() {
        assertThatThrownBy(() -> RestrictedJsonSchema.of(json("{\"type\":\"object\",\"oneOf\":[]}")))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("oneOf");
        assertThatThrownBy(() -> RestrictedJsonSchema.of(json("{\"type\":\"object\",\"additionalProperties\":{}}")))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void lifecycleTransitions() {
        assertThat(PolicyLifecycle.allowed("draft", Transition.SUBMIT)).isTrue();
        assertThat(PolicyLifecycle.allowed("pending", Transition.APPROVE)).isTrue();
        assertThat(PolicyLifecycle.allowed("draft", Transition.APPROVE)).isFalse();
        assertThat(PolicyLifecycle.allowed("rejected", Transition.SUBMIT)).isFalse();
        assertThat(PolicyLifecycle.allowed("retired", Transition.RETIRE)).isFalse();
        assertThat(PolicyLifecycle.allowed("approved", Transition.APPROVE)).isFalse();
        assertThat(PolicyLifecycle.allowed("active", Transition.WITHDRAW)).isFalse();
        assertThat(PolicyLifecycle.target(Transition.APPROVE)).isEqualTo("active");
    }
}
