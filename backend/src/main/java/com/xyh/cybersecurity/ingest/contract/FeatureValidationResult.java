package com.xyh.cybersecurity.ingest.contract;

import java.util.List;

/**
 * 服务端重新计算的字段级质量结论。
 *
 * @param valid      没有阻断问题时为 true
 * @param issues     阻断问题；任一存在即记录 rejected，不进入 outbox
 * @param advisories 非阻断遥测（{@code CATEGORY_OUT_OF_VOCABULARY}、{@code VOCABULARY_UNAVAILABLE}、
 *                   {@code NOT_IN_MODEL_SCOPE}），随记录落库，但不改变接收结论
 */
public record FeatureValidationResult(boolean valid, List<Issue> issues, List<Issue> advisories) {
    public FeatureValidationResult {
        issues = List.copyOf(issues);
        advisories = List.copyOf(advisories);
    }

    /**
     * 单条质量问题；只含字段名与期望/实际的类型或枚举描述，不回显传感器提供的任意字符串，避免把可疑内容写入质量记录。
     */
    public record Issue(String code, String field, String expected, String actual) { }

    public static FeatureValidationResult rejected(Issue issue) {
        return new FeatureValidationResult(false, List.of(issue), List.of());
    }
}
