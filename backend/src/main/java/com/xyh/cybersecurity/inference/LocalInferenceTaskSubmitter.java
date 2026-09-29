package com.xyh.cybersecurity.inference;

import com.xyh.cybersecurity.detection.DetectionService;
import com.xyh.cybersecurity.detection.DetectionUnavailableException;
import com.xyh.cybersecurity.ingest.IngestMapper;
import com.xyh.cybersecurity.ingest.outbox.IngestBatchEvent;
import com.xyh.cybersecurity.ingest.outbox.InferenceTaskSubmitter;
import com.xyh.cybersecurity.ingest.outbox.RetryableConsumerException;
import com.xyh.cybersecurity.model.validation.ModelContractException;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * M2 → M3 交接端口的本机实现（路线 B §10.1 第 1 项）。在 M2 消费事务内同步推理并写 {@code inference_request}，
 * 与消费幂等台账同一事务提交。
 *
 * <p>单条记录的门禁拒绝、超时、会话错误都已写成显式结论，消息正常 ack；只有暂时性故障（容量耗尽、版本切换、
 * 激活状态异常）抛 {@link RetryableConsumerException}，整批回滚，按 M2 既有策略延迟重试直至死信。</p>
 *
 * <p>{@code cyber.inference.local.enabled=false} 时不注册，M2 保持“端口不可用即 fail-closed”的行为。</p>
 */
@Component
@ConditionalOnProperty(name = "cyber.inference.local.enabled", havingValue = "true", matchIfMissing = true)
public class LocalInferenceTaskSubmitter implements InferenceTaskSubmitter {
    private final InferenceService service;
    private final DetectionService detection;

    public LocalInferenceTaskSubmitter(InferenceService service, DetectionService detection) {
        this.service = service;
        this.detection = detection;
    }

    /**
     * 推理后在同一事务内生成告警并关联事件（路线 B §11）。告警以数据库中的推理结论为准，
     * 消费台账被清后重放时推理返回为空，也不会漏生成告警。
     */
    @Override
    public void submit(IngestBatchEvent event, List<IngestMapper.AcceptedRecord> records) {
        try {
            service.inferBatch(event.batchId(), records);
            detection.processBatch(event.batchId(), records);
        } catch (DetectionUnavailableException exception) {
            // 缺少 active 策略：不能确认消息后让推理结论与告警永久脱节，整批回滚重试。
            throw new RetryableConsumerException(exception.code(), exception);
        } catch (InferenceUnavailableException exception) {
            throw new RetryableConsumerException(exception.code(), exception);
        } catch (ModelContractException exception) {
            // 例如 ACTIVE_MODEL_AMBIGUOUS：激活不变量被破坏，不能挑一个版本继续，等运维修复后重试。
            throw new RetryableConsumerException(exception.code(), exception);
        }
    }
}
