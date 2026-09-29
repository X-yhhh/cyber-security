package com.xyh.cybersecurity.response.domain;

import java.util.Map;
import java.util.Set;

/**
 * 响应策略版本状态机（M6）。版本内容不可变，只有状态沿下表迁移：
 *
 * <pre>
 * draft ──submit──► pending ──approve──► active ──retire / 被新版本取代──► retired
 *   │                  │ ──reject───► rejected
 *   └──withdraw──► retired ◄──withdraw──┘
 * </pre>
 *
 * <p>V1 的 {@code approved} 状态只为兼容历史行保留，本状态机不产生也不接受它作为起点。
 * 迁移的参与者约束（起草人才能提交/撤回、审批人不能是起草人）由应用服务与数据库 CHECK 共同保证。</p>
 */
public final class PolicyLifecycle {
    public enum Transition { SUBMIT, APPROVE, REJECT, WITHDRAW, RETIRE, SUPERSEDE }

    private static final Map<Transition, Set<String>> FROM = Map.of(
            Transition.SUBMIT, Set.of("draft"),
            Transition.APPROVE, Set.of("pending"),
            Transition.REJECT, Set.of("pending"),
            Transition.WITHDRAW, Set.of("draft", "pending"),
            Transition.RETIRE, Set.of("active"),
            Transition.SUPERSEDE, Set.of("active"));

    private static final Map<Transition, String> TO = Map.of(
            Transition.SUBMIT, "pending",
            Transition.APPROVE, "active",
            Transition.REJECT, "rejected",
            Transition.WITHDRAW, "retired",
            Transition.RETIRE, "retired",
            Transition.SUPERSEDE, "retired");

    private PolicyLifecycle() { }

    public static boolean allowed(String from, Transition transition) {
        return FROM.get(transition).contains(from);
    }

    public static String target(Transition transition) { return TO.get(transition); }
}
