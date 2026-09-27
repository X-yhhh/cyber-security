package com.xyh.cybersecurity.ingest.contract;

import com.fasterxml.jackson.databind.JsonNode;

import java.time.Instant;

/** 不含地址、端口和 payload 的规范双向流记录。 */
public record FlowRecordContract(String recordKey, Instant flowStartAt, Instant flowEndAt, Instant observedAt,
                                 String directionBasis, JsonNode features, String qualityStatus) {
    public FlowRecordContract {
        if (recordKey == null || !recordKey.matches("[A-Za-z0-9._:-]{1,160}")) {
            throw new IllegalArgumentException("recordKey 格式无效");
        }
    }
}
