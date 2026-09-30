package com.xyh.cybersecurity.detection;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** 版本化策略解析、受限规则条件与可解释风险评分（路线 B §11）。 */
class DetectionRulesAndPoliciesTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    /** 与 V13 写入的默认策略相同。 */
    private static final String SEVERITY = "{\"model\":[{\"minScore\":0.9,\"severity\":\"critical\"},"
            + "{\"minScore\":0.7,\"severity\":\"high\"},{\"minScore\":0.0,\"severity\":\"medium\"}]}";
    private static final String CORRELATION = "{\"windowSeconds\":900,\"dimensions\":[\"asset\"]}";
    private static final String RISK = "{\"severityWeight\":{\"low\":0.25,\"medium\":0.5,\"high\":0.75,\"critical\":1.0},"
            + "\"criticalityWeight\":{\"low\":0.5,\"medium\":0.75,\"high\":0.9,\"critical\":1.0},"
            + "\"repeatStep\":0.05,\"repeatCap\":0.2}";

    private static DetectionMapper mapper(String severity, String correlation, String risk) {
        DetectionMapper mapper = mock(DetectionMapper.class);
        when(mapper.findActivePolicy("severity_mapping")).thenReturn(
                severity == null ? null : new DetectionMapper.PolicyRow("severity-v1", severity));
        when(mapper.findActivePolicy("correlation")).thenReturn(new DetectionMapper.PolicyRow("correlation-v1", correlation));
        when(mapper.findActivePolicy("risk_score")).thenReturn(new DetectionMapper.PolicyRow("risk-v1", risk));
        return mapper;
    }

    @Test
    void defaultPoliciesMapScoresToBandsAndWindow() {
        DetectionPolicies policies = DetectionPolicies.load(mapper(SEVERITY, CORRELATION, RISK), JSON);
        assertThat(policies.severity().map(0.95)).isEqualTo("critical");
        assertThat(policies.severity().map(0.9)).isEqualTo("critical");
        assertThat(policies.severity().map(0.75)).isEqualTo("high");
        assertThat(policies.severity().map(0.36)).isEqualTo("medium");
        assertThat(policies.severity().bandFloor(0.75)).isEqualTo(0.7);
        assertThat(policies.correlation().windowSeconds()).isEqualTo(900);
        assertThat(policies.risk().version()).isEqualTo("risk-v1");
    }

    @Test
    void missingOrMalformedPolicyFailsInsteadOfFallingBack() {
        assertThatThrownBy(() -> DetectionPolicies.load(mapper(null, CORRELATION, RISK), JSON))
                .isInstanceOf(DetectionUnavailableException.class).hasMessage("DETECTION_POLICY_UNAVAILABLE");
        String unordered = "{\"model\":[{\"minScore\":0.5,\"severity\":\"high\"},{\"minScore\":0.7,\"severity\":\"critical\"}]}";
        assertThatThrownBy(() -> DetectionPolicies.load(mapper(unordered, CORRELATION, RISK), JSON))
                .hasMessage("DETECTION_POLICY_INVALID");
        String noFloor = "{\"model\":[{\"minScore\":0.5,\"severity\":\"high\"}]}";
        assertThatThrownBy(() -> DetectionPolicies.load(mapper(noFloor, CORRELATION, RISK), JSON))
                .hasMessage("DETECTION_POLICY_INVALID");
        String ipDimension = "{\"windowSeconds\":900,\"dimensions\":[\"asset\",\"peer_ip\"]}";
        assertThatThrownBy(() -> DetectionPolicies.load(mapper(SEVERITY, ipDimension, RISK), JSON))
                .hasMessage("DETECTION_POLICY_INVALID");
    }

    @Test
    void ruleConditionMatchesOnlyWhenAllClausesHold() throws Exception {
        RuleCondition condition = RuleCondition.parse(JSON.readTree("{\"all\":["
                + "{\"field\":\"features.ct_srv_src\",\"op\":\"gte\",\"value\":50},"
                + "{\"field\":\"features.proto\",\"op\":\"eq\",\"value\":\"tcp\"},"
                + "{\"field\":\"metadata.viewpoint\",\"op\":\"eq\",\"value\":\"responder\"}]}"));
        String hit = "{\"metadata\":{\"viewpoint\":\"responder\"},\"features\":{\"ct_srv_src\":64,\"proto\":\"tcp\"}}";
        assertThat(condition.match(JSON.readTree(hit), JSON).toString())
                .isEqualTo("{\"features.ct_srv_src\":64,\"features.proto\":\"tcp\",\"metadata.viewpoint\":\"responder\"}");
        String below = "{\"metadata\":{\"viewpoint\":\"responder\"},\"features\":{\"ct_srv_src\":49,\"proto\":\"tcp\"}}";
        assertThat(condition.match(JSON.readTree(below), JSON)).isNull();
        String wrongType = "{\"metadata\":{\"viewpoint\":\"responder\"},\"features\":{\"ct_srv_src\":\"64\",\"proto\":\"tcp\"}}";
        assertThat(condition.match(JSON.readTree(wrongType), JSON)).isNull();
        assertThat(condition.match(JSON.readTree("{\"features\":{}}"), JSON)).isNull();
    }

    @Test
    void ruleConditionRejectsScriptsUnknownFieldsAndOperators() {
        for (String bad : new String[] {
                "{\"any\":[]}",
                "{\"all\":[]}",
                "{\"all\":[{\"field\":\"payload.raw\",\"op\":\"eq\",\"value\":1}]}",
                "{\"all\":[{\"field\":\"features.dur\",\"op\":\"regex\",\"value\":\".*\"}]}",
                "{\"all\":[{\"field\":\"features.dur\",\"op\":\"gt\",\"value\":\"1\"}]}",
                "{\"all\":[{\"field\":\"features.dur\",\"op\":\"gt\",\"value\":{\"script\":\"x\"}}]}",
                "{\"all\":[{\"field\":\"features.dur\",\"op\":\"gt\",\"value\":1,\"extra\":true}]}"}) {
            assertThatThrownBy(() -> RuleCondition.parse(JSON.readTree(bad))).as(bad)
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    void riskScoreIsReproducibleFromItsBasis() {
        DetectionPolicies.Risk risk = DetectionPolicies.load(mapper(SEVERITY, CORRELATION, RISK), JSON).risk();
        EventCorrelator.Risk single = EventCorrelator.compute(risk, "high", 1, "high");
        assertThat(single.score().doubleValue()).isEqualTo(0.675);
        assertThat(single.repeatBonus()).isZero();
        EventCorrelator.Risk repeated = EventCorrelator.compute(risk, "critical", 10, "critical");
        assertThat(repeated.repeatBonus()).isEqualTo(0.2);
        assertThat(repeated.score().doubleValue()).isEqualTo(1.0);
        EventCorrelator.Risk unknown = EventCorrelator.compute(risk, "medium", 3, "tier-1");
        assertThat(unknown.criticalityDefaulted()).isTrue();
        assertThat(unknown.criticalityWeight()).isEqualTo(0.75);
        assertThat(unknown.score().doubleValue()).isCloseTo(0.475, org.assertj.core.api.Assertions.within(1e-9));
        assertThat(unknown.basis(JSON).path("formula").asText()).isEqualTo(EventCorrelator.FORMULA);
    }
}
