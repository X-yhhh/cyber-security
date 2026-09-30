package com.xyh.cybersecurity.inference;

import com.xyh.cybersecurity.model.runtime.FeatureContractModelGate;
import com.xyh.cybersecurity.model.runtime.OnnxModelManager;
import com.xyh.cybersecurity.model.runtime.OnnxModelRuntime;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import static com.xyh.cybersecurity.inference.InferenceResult.*;
import static com.xyh.cybersecurity.inference.InferenceTestSupport.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** M3 推理服务：门禁、结果快照、失败语义与重复投递（路线 B §10.2 测试覆盖）。 */
class InferenceServiceTest {
    private final InferenceMapper mapper = mock(InferenceMapper.class);
    private final OnnxModelManager models = mock(OnnxModelManager.class);
    private final LocalInferenceRunner runner = mock(LocalInferenceRunner.class);
    private final InferenceService service = new InferenceService(mapper, models, new FeatureContractModelGate(REGISTRY),
            REGISTRY, JSON, runner, Clock.fixed(Instant.parse("2026-09-29T12:00:00Z"), ZoneOffset.UTC));

    @BeforeEach
    void defaults() {
        when(mapper.findBatchContext(7)).thenReturn(context(V4, V4, "active"));
        when(mapper.findExistingRequestKeys(anyCollection())).thenReturn(List.of());
        when(models.activeLocal()).thenReturn(Optional.of(MODEL));
    }

    @Test
    void succeededResultCarriesModelThresholdAndContractSnapshot() {
        outcome(LocalInferenceRunner.Kind.SUCCEEDED, null, new OnnxModelRuntime.Prediction(0.9f, true));
        InferenceResult result = service.inferBatch(7, List.of(record(9, "responder", null))).getFirst();
        assertThat(result.status()).isEqualTo(SUCCEEDED);
        assertThat(result.requestKey()).isEqualTo("local:record:9");
        assertThat(result.modelVersionId()).isEqualTo(5L);
        assertThat(result.attackProbability()).isEqualTo((double) 0.9f);
        assertThat(result.binaryLabel()).isEqualTo("Attack");
        assertThat(result.decisionThreshold()).isEqualTo(0.35);
        assertThat(result.thresholdPolicyVersion()).isEqualTo("fixed:unsw-binary-2026.10.0");
        assertThat(result.contractVersion()).isEqualTo(V4);
        assertThat(result.contractSha256()).isEqualTo(CONTRACT.fileSha256());
        assertThat(result.latencyMs()).isEqualTo(3L);
        assertThat(result.errorCode()).isNull();
        verify(mapper).insertRequest(result.toInsert());
    }

    @Test
    void redeliveredRecordsAreNotInferredAgain() {
        when(mapper.findExistingRequestKeys(anyCollection())).thenReturn(List.of("local:record:9"));
        assertThat(service.inferBatch(7, List.of(record(9, "responder", null)))).isEmpty();
        verify(runner, never()).run(anyLong(), any());
        verify(mapper, never()).insertRequest(any());
    }

    @Test
    void noActiveModelIsRejectedWithoutScoringOrFallback() {
        when(models.activeLocal()).thenReturn(Optional.empty());
        InferenceResult result = service.inferBatch(7, List.of(record(9, "responder", null))).getFirst();
        assertThat(result.status()).isEqualTo(REJECTED);
        assertThat(result.errorCode()).isEqualTo("ACTIVE_MODEL_UNAVAILABLE");
        assertThat(result.modelVersionId()).isNull();
        assertThat(result.attackProbability()).isNull();
        verify(runner, never()).run(anyLong(), any());
    }

    @Test
    void batchWithoutContractInactiveConfigOrMismatchedConfigIsRejected() {
        when(mapper.findBatchContext(7)).thenReturn(context(null, null, null));
        assertReject("record_contract_missing");
        when(mapper.findBatchContext(7)).thenReturn(context(V4, V4, "retired"));
        assertReject("config_not_active");
        when(mapper.findBatchContext(7)).thenReturn(context(V4, "unsw-nb15-flow-v3.1", "active"));
        assertReject("record_config_mismatch");
        verify(runner, never()).run(anyLong(), any());
    }

    @Test
    void perRecordScopeAndInputFailuresAreExplicitAndOnlyValidRecordsAreScored() {
        outcome(LocalInferenceRunner.Kind.SUCCEEDED, null, new OnnxModelRuntime.Prediction(0.1f, false));
        List<InferenceResult> results = service.dryRun(7, List.of(record(1, "responder", null),
                record(2, "initiator", null), record(3, "responder", "dur"), rawRecord(4, "not json")));
        assertThat(results).extracting(InferenceResult::status)
                .containsExactly(SUCCEEDED, NOT_IN_MODEL_SCOPE, REJECTED, REJECTED);
        assertThat(results.getFirst().binaryLabel()).isEqualTo("Normal");
        assertThat(results.get(1).errorCode()).isNull();
        assertThat(results.get(1).rejectReason()).isEqualTo("not_in_model_scope");
        assertThat(results.get(2).errorCode()).isEqualTo("MODEL_INPUT_CONTRACT_MISMATCH");
        assertThat(results.get(2).rejectReason()).isEqualTo("feature_missing:dur");
        assertThat(results.get(3).rejectReason()).isEqualTo("payload_invalid");
        verify(runner).run(eq(5L), argThat(inputs -> inputs.size() == 1));
        verify(mapper, never()).insertRequest(any());
    }

    @Test
    void timeoutRuntimeFailureAndInconsistentLabelAreExplicitFailures() {
        outcome(LocalInferenceRunner.Kind.TIMED_OUT, "INFERENCE_TIMEOUT");
        InferenceResult timedOut = service.dryRun(7, List.of(record(1, "responder", null))).getFirst();
        assertThat(timedOut.status()).isEqualTo(TIMED_OUT);
        assertThat(timedOut.errorCode()).isEqualTo("INFERENCE_TIMEOUT");
        assertThat(timedOut.attackProbability()).isNull();

        outcome(LocalInferenceRunner.Kind.FAILED, "MODEL_RUNTIME_FAILED");
        assertThat(service.dryRun(7, List.of(record(1, "responder", null))).getFirst())
                .extracting(InferenceResult::status, InferenceResult::errorCode)
                .containsExactly(FAILED, "MODEL_RUNTIME_FAILED");

        outcome(LocalInferenceRunner.Kind.SUCCEEDED, null, new OnnxModelRuntime.Prediction(0.1f, true));
        assertThat(service.dryRun(7, List.of(record(1, "responder", null))).getFirst())
                .extracting(InferenceResult::status, InferenceResult::errorCode, InferenceResult::rejectReason)
                .containsExactly(FAILED, "MODEL_OUTPUT_CONTRACT_MISMATCH", "label_threshold_inconsistent");
    }

    @Test
    void versionSwitchAfterGateRollsBackWholeBatch() {
        when(runner.run(eq(5L), any())).thenThrow(new InferenceUnavailableException("ACTIVE_MODEL_CHANGED", null));
        assertThatThrownBy(() -> service.inferBatch(7, List.of(record(1, "responder", null))))
                .isInstanceOf(InferenceUnavailableException.class).hasMessage("ACTIVE_MODEL_CHANGED");
        verify(mapper, never()).insertRequest(any());
    }

    private void assertReject(String reason) {
        InferenceResult result = service.dryRun(7, List.of(record(9, "responder", null))).getFirst();
        assertThat(result.status()).isEqualTo(REJECTED);
        assertThat(result.errorCode()).isEqualTo(FeatureContractModelGate.MISMATCH);
        assertThat(result.rejectReason()).isEqualTo(reason);
    }

    private void outcome(LocalInferenceRunner.Kind kind, String errorCode, OnnxModelRuntime.Prediction... predictions) {
        when(runner.run(eq(5L), any())).thenReturn(new LocalInferenceRunner.Outcome(kind, List.of(predictions),
                errorCode, kind == LocalInferenceRunner.Kind.TIMED_OUT ? 2000 : 3));
    }
}
