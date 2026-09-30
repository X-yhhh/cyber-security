package com.xyh.cybersecurity.detection;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.audit.AuditMapper;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import com.xyh.cybersecurity.ingest.contract.FeatureContractRegistry;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** 规则登记校验与申请人/批准人分离（路线 B §11）。 */
class DetectionRuleServiceTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final DetectionMapper mapper = mock(DetectionMapper.class);
    private final AuditMapper audit = mock(AuditMapper.class);
    private final DetectionRuleService service = new DetectionRuleService(mapper, audit,
            FeatureContractRegistry.fromClasspath(), JSON);
    private final HttpServletRequest request = mock(HttpServletRequest.class);

    private static IdentityPrincipal user(long id) {
        return new IdentityPrincipal(id, "u-" + id, "user" + id, "user" + id, "", "active", List.of(), List.of());
    }

    private static DetectionMapper.RuleView pending(long requestedBy) {
        return new DetectionMapper.RuleView(9, "scan-watch", "2", "{}", "{\"all\":[]}", "medium", "pending",
                requestedBy, null, Instant.EPOCH, Instant.EPOCH);
    }

    @Test
    void requesterCannotApproveOwnRule() {
        when(mapper.findRuleForUpdate(9)).thenReturn(pending(3));
        assertThatThrownBy(() -> service.decide(9, "approve", "ok", user(3), request))
                .isInstanceOf(AccessDeniedException.class);
        verify(mapper, never()).activateRule(anyLong(), anyLong());
        verify(mapper, never()).retireOtherActiveVersions(anyString(), anyLong());
    }

    @Test
    void approvalRetiresOtherActiveVersionsThenActivatesAndAudits() {
        when(mapper.findRuleForUpdate(9)).thenReturn(pending(3));
        when(mapper.activateRule(9, 4)).thenReturn(1);
        service.decide(9, "approve", "independent review", user(4), request);
        var order = inOrder(mapper);
        order.verify(mapper).retireOtherActiveVersions("scan-watch", 9);
        order.verify(mapper).activateRule(9, 4);
        verify(audit).insertAudit(any());
    }

    @Test
    void alreadyDecidedRuleIsConflict() {
        DetectionMapper.RuleView active = new DetectionMapper.RuleView(9, "scan-watch", "2", "{}", "{}", "medium",
                "active", 3L, 5L, Instant.EPOCH, Instant.EPOCH);
        when(mapper.findRuleForUpdate(9)).thenReturn(active);
        assertThatThrownBy(() -> service.decide(9, "reject", "no", user(4), request))
                .isInstanceOf(ApiRequestException.class);
        verify(mapper, never()).rejectRule(anyLong());
    }

    @Test
    void registrationRejectsNonCompliantConditionScopeAndSeverity() throws Exception {
        var valid = JSON.readTree("{\"all\":[{\"field\":\"features.ct_srv_src\",\"op\":\"gte\",\"value\":50}]}");
        var script = JSON.readTree("{\"all\":[{\"field\":\"features.dur\",\"op\":\"eval\",\"value\":\"1\"}]}");
        var unknownScope = JSON.readTree("{\"environment\":\"lab\"}");
        var unregistered = JSON.readTree("{\"featureContractVersion\":\"unsw-nb15-flow-v9\"}");
        for (DetectionRuleService.CreateRule bad : List.of(
                new DetectionRuleService.CreateRule("scan-watch", "1", "medium", script, null, "r"),
                new DetectionRuleService.CreateRule("scan-watch", "1", "medium", valid, unknownScope, "r"),
                new DetectionRuleService.CreateRule("scan-watch", "1", "medium", valid, unregistered, "r"),
                new DetectionRuleService.CreateRule("scan-watch", "1", "urgent", valid, null, "r"),
                new DetectionRuleService.CreateRule("Scan Watch", "1", "medium", valid, null, "r"))) {
            assertThatThrownBy(() -> service.create(bad, user(3), request)).isInstanceOf(ApiRequestException.class);
        }
        verify(mapper, never()).insertRule(anyString(), anyString(), anyString(), anyString(), anyString(), anyLong());
    }
}
