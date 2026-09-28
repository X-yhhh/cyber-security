package com.xyh.cybersecurity.model.runtime;

import ai.onnxruntime.OrtException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.model.artifact.ModelArtifactStore;
import com.xyh.cybersecurity.model.release.ModelMapper;
import com.xyh.cybersecurity.model.release.ModelService;
import com.xyh.cybersecurity.model.validation.ModelContractException;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/** 验证并缓存明确批准的 ONNX 版本；进程重启时只恢复数据库标记为 active 的本机版本。 */
@Component
public class OnnxModelManager implements DisposableBean {

    private final ModelRuntimeMapper mapper;
    private final ObjectMapper objectMapper;
    private final ModelArtifactStore artifacts;
    private final ConcurrentMap<Long, OnnxModelRuntime> active = new ConcurrentHashMap<>();
    private final ReentrantReadWriteLock activeLock = new ReentrantReadWriteLock();

    public OnnxModelManager(ModelRuntimeMapper mapper, ObjectMapper objectMapper, ModelArtifactStore artifacts) {
        this.mapper = mapper;
        this.objectMapper = objectMapper;
        this.artifacts = artifacts;
    }

    public ValidationResult validate(ModelService.ModelView model) {
        ModelArtifactStore.VerifiedArtifact artifact = artifacts.verify(model);
        OnnxModelRuntime runtime = open(artifact);
        try (runtime) {
            List<OnnxModelRuntime.Prediction> results = smokePredict(runtime);
            double threshold = artifact.manifest().at("/decision/threshold").asDouble(Double.NaN);
            if (!Double.isFinite(threshold) || threshold < 0 || threshold > 1) {
                throw new ModelContractException("MODEL_THRESHOLD_CONTRACT_MISMATCH");
            }
            if (results.size() != 1 || results.getFirst().isAttack() != (results.getFirst().attackProbability() >= threshold)) {
                throw new ModelContractException("MODEL_SMOKE_TEST_FAILED");
            }
        } catch (OrtException exception) {
            throw new ModelContractException("MODEL_SMOKE_TEST_FAILED");
        }
        return new ValidationResult("passed", artifact.sha256(), OnnxModelRuntime.RUNTIME_VERSION,
                "ONNX inputs/outputs and one-record CPU smoke inference passed");
    }

    public OnnxModelRuntime prepare(ModelService.ModelView model) {
        OnnxModelRuntime runtime = open(artifacts.verify(model));
        try {
            smokePredict(runtime);
            return runtime;
        } catch (RuntimeException exception) {
            closeQuietly(runtime);
            throw exception;
        }
    }

    public void activateAfterCommit(long modelId, OnnxModelRuntime newRuntime) {
        org.springframework.transaction.support.TransactionSynchronizationManager.registerSynchronization(
                new org.springframework.transaction.support.TransactionSynchronization() {
                    @Override public void afterCommit() {
                        activeLock.writeLock().lock();
                        try {
                            active.forEach((id, previous) -> { if (id != modelId && active.remove(id, previous)) closeQuietly(previous); });
                            OnnxModelRuntime previous = active.put(modelId, newRuntime);
                            if (previous != null && previous != newRuntime) closeQuietly(previous);
                        } finally { activeLock.writeLock().unlock(); }
                    }
                    @Override public void afterCompletion(int status) {
                        if (status != STATUS_COMMITTED) closeQuietly(newRuntime);
                    }
                });
    }

    public OnnxModelRuntime active(long modelId) {
        activeLock.readLock().lock();
        try {
            OnnxModelRuntime runtime = active.get(modelId);
            if (runtime == null) throw new ModelContractException("ACTIVE_MODEL_RUNTIME_UNAVAILABLE");
            return runtime;
        } finally { activeLock.readLock().unlock(); }
    }

    @EventListener(ApplicationReadyEvent.class)
    public void restoreActiveDeployments() {
        List<ActiveDeployment> deployments = mapper.listActiveDeployments().stream()
                .map(row -> new ActiveDeployment(modelView(row), row.id()))
                .toList();
        activeLock.writeLock().lock();
        try {
            for (ActiveDeployment deployment : deployments) {
                OnnxModelRuntime runtime = prepare(deployment.model());
                OnnxModelRuntime previous = active.put(deployment.id(), runtime);
                if (previous != null && previous != runtime) closeQuietly(previous);
            }
        }
        finally { activeLock.writeLock().unlock(); }
    }

    /** 激活前使用契约允许的零值样本预热，并要求运行时返回恰好一条完整预测。 */
    private static List<OnnxModelRuntime.Prediction> smokePredict(OnnxModelRuntime runtime) {
        try {
            double[] numeric = new double[OnnxModelRuntime.NUMERIC_FEATURE_COUNT];
            List<OnnxModelRuntime.Prediction> results = runtime.predict(List.of(new OnnxModelRuntime.FlowInput(
                    numeric, new String[]{"tcp", "-"})));
            if (results.size() != 1) throw new ModelContractException("MODEL_OUTPUT_CONTRACT_MISMATCH");
            return results;
        } catch (OrtException exception) {
            throw new ModelContractException("MODEL_SMOKE_TEST_FAILED", exception);
        }
    }

    private OnnxModelRuntime open(ModelArtifactStore.VerifiedArtifact artifact) {
        try { return OnnxModelRuntime.open(artifact.modelPath()); }
        catch (OrtException | IllegalArgumentException exception) {
            throw new ModelContractException("MODEL_ONNX_CONTRACT_MISMATCH");
        }
    }

    private ModelService.ModelView modelView(ModelMapper.ModelRow row) {
        try {
            JsonNode manifest = objectMapper.readTree(row.manifestJson());
            return new ModelService.ModelView(row.id(), row.modelKey(), row.version(), row.taskType(),
                    row.manifestVersion(), manifest, row.artifactRef(), row.artifactSha256(),
                    row.featureContractVersion(), row.approvalStatus(), row.createdAt());
        } catch (java.io.IOException exception) {
            throw new ModelContractException("MODEL_MANIFEST_INVALID", exception);
        }
    }

    private static void closeQuietly(OnnxModelRuntime runtime) {
        try { runtime.close(); } catch (OrtException ignored) { }
    }

    @Override public void destroy() {
        activeLock.writeLock().lock();
        try { active.values().forEach(OnnxModelManager::closeQuietly); active.clear(); }
        finally { activeLock.writeLock().unlock(); }
    }

    public record ValidationResult(String status, String artifactSha256, String runtimeVersion, String summary) { }
    private record ActiveDeployment(ModelService.ModelView model, long id) { }
}
