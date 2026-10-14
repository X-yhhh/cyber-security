package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.MultiValueMap;

import java.time.LocalDateTime;
import java.time.ZoneOffset;

import static com.xyh.cybersecurity.guard.GuardJson.error;
import static com.xyh.cybersecurity.guard.GuardJson.instant;
import static com.xyh.cybersecurity.guard.GuardJson.object;

/** B2.5 工作台汇总：按当前会话持有的权限与可见范围分别计算，无权限的字段不返回，只读不写审计。 */
@Service
@Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)
public class GuardSummary {
    private final GuardReadMapper mapper;
    private final GuardAccess access;

    public GuardSummary(GuardReadMapper mapper, GuardAccess access) {
        this.mapper = mapper;
        this.access = access;
    }

    public JsonNode summary(MultiValueMap<String, String> parameters) {
        if (parameters != null && !parameters.isEmpty()) throw error(400, "INVALID_QUERY");
        long actor = access.human();
        LocalDateTime now = mapper.now();
        ObjectNode out = object();

        boolean eventManage = mapper.hasPermission(actor, "event.manage");
        boolean detectionRead = mapper.hasPermission(actor, "detection.read");
        if (eventManage || detectionRead) {
            out.put("openEvents", mapper.summaryOpenEvents(actor));
        }

        boolean authApprove = mapper.hasPermission(actor, "authorization.approve");
        boolean policyApprove = mapper.hasPermission(actor, "policy.approve");
        boolean bundleApprove = mapper.hasPermission(actor, "bundle.approve");
        if (authApprove || policyApprove || bundleApprove) {
            ObjectNode pending = object();
            if (authApprove) {
                pending.put("authorizations", mapper.summaryPendingAuthorizations(actor));
                pending.put("sensorConfigs", mapper.summaryPendingSensorConfigs(actor));
                pending.put("actions", mapper.summaryPendingActions(actor));
                pending.put("labRuns", mapper.summaryPendingLabRuns(actor));
            }
            if (policyApprove) {
                pending.put("policies", mapper.summaryPendingPolicies(actor));
            }
            if (bundleApprove) {
                pending.put("bundles", mapper.summaryPendingBundles(actor));
            }
            out.set("pendingApprovals", pending);
        }

        if (mapper.hasPermission(actor, "feedback.review")) {
            out.put("pendingFeedbackReviews", mapper.summaryPendingFeedbackReviews(actor));
        }

        if (mapper.hasPermission(actor, "bundle.request")
                || bundleApprove
                || mapper.hasPermission(actor, "evaluation.read")) {
            ObjectNode pipeline = object();
            pipeline.put("candidate", mapper.summaryBundlesByStatus("candidate"));
            pipeline.put("evaluated", mapper.summaryBundlesByStatus("evaluated"));
            pipeline.put("approved", mapper.summaryBundlesByStatus("approved"));
            pipeline.put("active", mapper.summaryBundlesByStatus("active"));
            out.set("releasePipeline", pipeline);
        }

        if (mapper.hasPermission(actor, "model.manage") || mapper.hasPermission(actor, "model.validate")) {
            out.put("modelsPendingValidation", mapper.summaryModelsPendingValidation());
        }

        if (mapper.hasPermission(actor, "ops.read")) {
            ObjectNode ops = object();
            LocalDateTime heartbeatFloor = now.minusSeconds(300);
            ops.put("sensorsUnhealthy", mapper.summarySensorsUnhealthy(actor, heartbeatFloor));
            ops.put("executorsUnhealthy", mapper.summaryExecutorsUnhealthy(actor, heartbeatFloor));
            Object lastHealth = mapper.summaryLastHealthAt(actor);
            if (lastHealth == null) ops.putNull("lastHealthAt");
            else ops.put("lastHealthAt", instant(lastHealth).toString());
            out.set("ops", ops);
        }

        if (mapper.hasPermission(actor, "audit.read")) {
            out.put("recentAuditCount24h", mapper.summaryRecentAuditCount24h(actor, now.minusHours(24)));
        }

        return out;
    }
}
