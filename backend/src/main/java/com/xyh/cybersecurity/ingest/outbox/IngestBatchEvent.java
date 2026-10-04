package com.xyh.cybersecurity.ingest.outbox;

/** 已通过 envelope 校验的接入批次事件；只保留后续任务需要的最小字段。 */
public record IngestBatchEvent(String eventKey, String eventType, long batchId,
                               long dataSourceId, int recordCount) { }
