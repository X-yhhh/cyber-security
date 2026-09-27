package com.xyh.cybersecurity.ingest.contract;

import java.util.List;

/** 服务端重新计算的字段级质量结论。 */
public record FeatureValidationResult(boolean valid, List<Issue> issues, List<String> categoryDrift) {
    public record Issue(String code, String field, String expected, String actual) { }

    public static FeatureValidationResult valid(List<String> categoryDrift) {
        return new FeatureValidationResult(true, List.of(), List.copyOf(categoryDrift));
    }
}
