package com.xyh.cybersecurity.inference;

import com.xyh.cybersecurity.ingest.outbox.IngestBatchEvent;
import com.xyh.cybersecurity.ingest.outbox.RetryableConsumerException;
import com.xyh.cybersecurity.model.runtime.OnnxModelManager;
import com.xyh.cybersecurity.model.runtime.OnnxModelRuntime;
import com.xyh.cybersecurity.model.validation.ModelContractException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** 单批超时、版本切换重试、容量耗尽与提交端口的异常映射（路线 B §10.1 第 3、4 项）。 */
class LocalInferenceRunnerTest {
    private static final List<OnnxModelRuntime.FlowInput> INPUT = List.of(
            new OnnxModelRuntime.FlowInput(new double[17], new String[] {"tcp", "http"}));
    private final OnnxModelManager models = mock(OnnxModelManager.class);
    private final LocalInferenceRunner runner = new LocalInferenceRunner(models, 100, 1, 4);

    @AfterEach
    void shutdown() { runner.destroy(); }

    @Test
    void slowBatchTimesOutExplicitlyInsteadOfWaiting() throws Exception {
        when(models.runOnActive(eq(5L), any())).thenAnswer(invocation -> {
            Thread.sleep(1_000);
            return List.of();
        });
        LocalInferenceRunner.Outcome outcome = runner.run(5, INPUT);
        assertThat(outcome.kind()).isEqualTo(LocalInferenceRunner.Kind.TIMED_OUT);
        assertThat(outcome.errorCode()).isEqualTo("INFERENCE_TIMEOUT");
        assertThat(outcome.latencyMs()).isBetween(100L, 900L);
    }

    @Test
    void versionChangeIsRetryableButOtherContractAndRuntimeErrorsAreFailures() throws Exception {
        when(models.runOnActive(eq(5L), any())).thenThrow(new ModelContractException("ACTIVE_MODEL_CHANGED"));
        assertThatThrownBy(() -> runner.run(5, INPUT)).isInstanceOf(InferenceUnavailableException.class)
                .hasMessage("ACTIVE_MODEL_CHANGED");

        when(models.runOnActive(eq(6L), any())).thenThrow(new ModelContractException("MODEL_INPUT_CONTRACT_MISMATCH"));
        assertThat(runner.run(6, INPUT)).extracting(LocalInferenceRunner.Outcome::kind, LocalInferenceRunner.Outcome::errorCode)
                .containsExactly(LocalInferenceRunner.Kind.FAILED, "MODEL_INPUT_CONTRACT_MISMATCH");

        when(models.runOnActive(eq(7L), any())).thenThrow(new IllegalStateException("/private/path/model.onnx"));
        assertThat(runner.run(7, INPUT)).extracting(LocalInferenceRunner.Outcome::kind, LocalInferenceRunner.Outcome::errorCode)
                .containsExactly(LocalInferenceRunner.Kind.FAILED, "MODEL_RUNTIME_FAILED");
    }

    @Test
    void rejectedSubmissionIsCapacityExhaustion() {
        runner.destroy();
        assertThatThrownBy(() -> runner.run(5, INPUT)).isInstanceOf(InferenceUnavailableException.class)
                .hasMessage("INFERENCE_CAPACITY_EXHAUSTED");
    }

    @Test
    void invalidConfigurationFailsAtStartup() {
        assertThatThrownBy(() -> new LocalInferenceRunner(models, 0, 1, 1)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new LocalInferenceRunner(models, 100, 0, 1)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void submitterTurnsTransientFailuresIntoConsumerRetries() {
        InferenceService service = mock(InferenceService.class);
        LocalInferenceTaskSubmitter submitter = new LocalInferenceTaskSubmitter(service,
                mock(com.xyh.cybersecurity.detection.DetectionService.class));
        IngestBatchEvent event = new IngestBatchEvent("e-1", "ingest.batch.received", 7, 3, 1);
        when(service.inferBatch(anyLong(), anyList()))
                .thenThrow(new InferenceUnavailableException("INFERENCE_CAPACITY_EXHAUSTED", null))
                .thenThrow(new ModelContractException("ACTIVE_MODEL_AMBIGUOUS"));
        assertThatThrownBy(() -> submitter.submit(event, List.of())).isInstanceOf(RetryableConsumerException.class)
                .hasMessage("INFERENCE_CAPACITY_EXHAUSTED");
        assertThatThrownBy(() -> submitter.submit(event, List.of())).isInstanceOf(RetryableConsumerException.class)
                .hasMessage("ACTIVE_MODEL_AMBIGUOUS");
    }
}
