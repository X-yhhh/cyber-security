package com.xyh.cybersecurity.ingest.outbox;

import com.xyh.cybersecurity.ingest.IngestMapper;

import java.util.List;

/**
 * M2 到 M3 的事务内交接边界。M3 提供实现后，其数据库写入会与消费幂等台账加入同一事务。
 */
@FunctionalInterface
public interface InferenceTaskSubmitter {
    /**
     * 提交一个已通过接入门禁的批次；实现不得把未通过门禁的记录重新加入推理链路。
     */
    void submit(IngestBatchEvent event, List<IngestMapper.AcceptedRecord> records);
}
