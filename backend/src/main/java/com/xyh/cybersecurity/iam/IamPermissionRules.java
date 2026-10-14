package com.xyh.cybersecurity.iam;

import java.util.Collection;
import java.util.List;
import java.util.Set;

/** rbac-v2 唯一人工权限白名单与七组职责冲突；范围不同也不能让同一用户兼任申请和批准。 */
final class IamPermissionRules {
    static final Set<String> HUMAN = Set.of("resource.read", "detection.read", "event.manage", "feedback.label",
            "feedback.review", "action.read", "action.request", "action.revoke", "automation.stop",
            "authorization.request", "authorization.approve", "asset.manage", "sensor.manage", "dataset.manage",
            "model.manage", "model.validate", "evaluation.read", "evaluation.run", "policy.draft", "policy.approve",
            "bundle.request", "bundle.approve", "audit.read", "ops.read", "iam.manage");
    private static final List<Set<String>> CONFLICTS = List.of(
            Set.of("authorization.request", "authorization.approve"), Set.of("sensor.manage", "authorization.approve"),
            Set.of("policy.draft", "policy.approve"), Set.of("bundle.request", "bundle.approve"),
            Set.of("action.request", "authorization.approve"), Set.of("feedback.label", "feedback.review"),
            Set.of("evaluation.run", "authorization.approve"));

    private IamPermissionRules() { }

    static boolean conflicts(Collection<String> permissions) {
        return CONFLICTS.stream().anyMatch(permissions::containsAll);
    }
}
