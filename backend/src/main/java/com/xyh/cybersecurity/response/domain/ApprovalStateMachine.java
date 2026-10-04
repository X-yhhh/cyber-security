package com.xyh.cybersecurity.response.domain;

import java.util.Set;

/** 审批状态机；数据库更新必须同时带上 expected 状态并检查影响行数。 */
public final class ApprovalStateMachine {

    private static final Set<String> TERMINAL = Set.of("approved", "rejected", "expired");

    private ApprovalStateMachine() { }

    public static String decide(String current, String decision) {
        if (!"pending".equals(current)) throw new IllegalStateException("审批任务已被处理");
        if (!"approve".equals(decision) && !"reject".equals(decision)) {
            throw new IllegalArgumentException("审批决定无效");
        }
        return "approve".equals(decision) ? "approved" : "rejected";
    }

    public static boolean isTerminal(String status) { return TERMINAL.contains(status); }
}
