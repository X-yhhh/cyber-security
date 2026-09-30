package com.xyh.cybersecurity.model.runtime;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.model.artifact.ModelArtifactStore;
import com.xyh.cybersecurity.model.release.ModelService;
import com.xyh.cybersecurity.model.validation.ModelContractException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

/** 激活描述、阈值策略与版本切换期间的读写锁语义（路线 B §10.1 第 4 项、§10.2 “切换期间不混用版本”）。 */
class OnnxModelManagerActivationTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final ModelInputContract INPUTS = new ModelInputContract("unsw-nb15-flow-v4", null, List.of("dur"),
            List.of("proto"), Set.of(), Map.of(), List.of("responder"), List.of("ipv4"));
    private final OnnxModelManager manager = new OnnxModelManager(mock(ModelRuntimeMapper.class), JSON,
            mock(ModelArtifactStore.class));

    @AfterEach
    void clear() { if (TransactionSynchronizationManager.isSynchronizationActive()) TransactionSynchronizationManager.clearSynchronization(); }

    @Test
    void describeSnapshotsFixedThresholdAndRejectsAdjustablePolicy() throws Exception {
        OnnxModelRuntime runtime = runtime();
        OnnxModelManager.ActiveModel model = OnnxModelManager.describe(view(1,
                "{\"model_version\":\"unsw-binary-2026.10.0\",\"decision\":{\"threshold\":0.35,\"adjustable\":false}}"), runtime);
        assertThat(model.decisionThreshold()).isEqualTo(0.35);
        assertThat(model.thresholdPolicyVersion()).isEqualTo("fixed:unsw-binary-2026.10.0");
        assertThatThrownBy(() -> OnnxModelManager.describe(view(1, "{\"decision\":{\"threshold\":0.35,\"adjustable\":true}}"),
                runtime)).isInstanceOf(ModelContractException.class).hasMessage("MODEL_THRESHOLD_POLICY_UNSUPPORTED");
        assertThatThrownBy(() -> OnnxModelManager.describe(view(1, "{\"decision\":{}}"), runtime))
                .hasMessage("MODEL_THRESHOLD_CONTRACT_MISMATCH");
    }

    @Test
    void runOnActiveRequiresTheVersionSeenByTheGate() throws Exception {
        assertThat(manager.activeLocal()).isEmpty();
        assertThatThrownBy(() -> manager.runOnActive(1, rt -> rt)).hasMessage("ACTIVE_MODEL_UNAVAILABLE");
        OnnxModelRuntime first = runtime();
        commit(1, first).forEach(TransactionSynchronization::afterCommit);
        assertThat(manager.activeLocal()).map(OnnxModelManager.ActiveModel::modelId).contains(1L);
        OnnxModelRuntime used = manager.runOnActive(1, rt -> rt);
        assertThat(used).isSameAs(first);
        assertThatThrownBy(() -> manager.runOnActive(2, rt -> rt)).hasMessage("ACTIVE_MODEL_CHANGED");
    }

    @Test
    void switchWaitsForInFlightInferenceBeforeClosingOldSession() throws Exception {
        OnnxModelRuntime first = runtime();
        OnnxModelRuntime second = runtime();
        commit(1, first).forEach(TransactionSynchronization::afterCommit);
        CountDownLatch inCall = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        Thread inference = Thread.ofPlatform().start(() -> {
            try {
                manager.runOnActive(1, rt -> {
                    inCall.countDown();
                    try { release.await(); } catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
                    return rt;
                });
            } catch (Exception exception) { throw new IllegalStateException(exception); }
        });
        assertThat(inCall.await(5, TimeUnit.SECONDS)).isTrue();
        List<TransactionSynchronization> switchToSecond = commit(2, second);
        Thread activation = Thread.ofPlatform().start(() -> switchToSecond.forEach(TransactionSynchronization::afterCommit));
        activation.join(300);
        assertThat(activation.isAlive()).as("切换等待进行中的推理").isTrue();
        verify(first, never()).close();

        release.countDown();
        inference.join(5_000);
        activation.join(5_000);
        verify(first).close();
        verify(second, never()).close();
        assertThat(manager.activeLocal()).map(OnnxModelManager.ActiveModel::modelId).contains(2L);
        assertThatThrownBy(() -> manager.runOnActive(1, rt -> rt)).hasMessage("ACTIVE_MODEL_CHANGED");
    }

    /** 模拟一次已提交的激活事务，返回待在任意线程执行的提交回调。 */
    private List<TransactionSynchronization> commit(long modelId, OnnxModelRuntime runtime) {
        TransactionSynchronizationManager.initSynchronization();
        try {
            manager.activateAfterCommit(new OnnxModelManager.ActiveModel(modelId, "unsw-binary", "v" + modelId, 0.5,
                    "fixed:v" + modelId, INPUTS), runtime);
            return List.copyOf(TransactionSynchronizationManager.getSynchronizations());
        } finally { TransactionSynchronizationManager.clearSynchronization(); }
    }

    private static OnnxModelRuntime runtime() {
        OnnxModelRuntime runtime = mock(OnnxModelRuntime.class);
        when(runtime.inputs()).thenReturn(INPUTS);
        return runtime;
    }

    private static ModelService.ModelView view(long id, String manifest) throws Exception {
        return new ModelService.ModelView(id, "unsw-binary", "2026.10.0", "binary_flow_classification", "v4",
                JSON.readTree(manifest), "model://unsw-binary/2026.10.0/model.onnx", "0".repeat(64),
                "unsw-nb15-flow-v4", "approved", LocalDateTime.now());
    }
}
