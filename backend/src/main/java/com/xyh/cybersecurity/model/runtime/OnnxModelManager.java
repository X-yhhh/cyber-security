package com.xyh.cybersecurity.model.runtime;

import ai.onnxruntime.OrtException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.ingest.contract.ActiveModelInputs;
import com.xyh.cybersecurity.model.artifact.ModelArtifactStore;
import com.xyh.cybersecurity.model.release.ModelMapper;
import com.xyh.cybersecurity.model.release.ModelService;
import com.xyh.cybersecurity.model.validation.ModelContractException;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * 验证并缓存明确批准的 ONNX 版本；进程重启时只恢复数据库标记为 active 的本机版本。
 *
 * <p>同时实现 {@link ActiveModelInputs}：向接入层提供激活模型的类别词表与评估范围，仅用于非阻断遥测。</p>
 *
 * <p>并发语义（路线 B §10.1 第 4 项）：{@link #runOnActive} 在读锁内执行推理，版本切换在写锁内替换并关闭旧会话，
 * 因此一次推理要么完整使用旧版本、要么完整使用新版本，不会在会话关闭后继续调用，也不会在一个批次内混用版本。</p>
 */
@Component
public class OnnxModelManager implements DisposableBean, ActiveModelInputs {

    private final ModelRuntimeMapper mapper;
    private final ObjectMapper objectMapper;
    private final ModelArtifactStore artifacts;
    private final ConcurrentMap<Long, Loaded> active = new ConcurrentHashMap<>();
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

    /**
     * 复核制品并打开会话，同时核对阈值策略可被本机推理如实执行；任何检查失败都关闭会话并抛出稳定错误码。
     */
    public OnnxModelRuntime prepare(ModelService.ModelView model) {
        OnnxModelRuntime runtime = open(artifacts.verify(model));
        try {
            smokePredict(runtime);
            describe(model, runtime);
            return runtime;
        } catch (RuntimeException exception) {
            closeQuietly(runtime);
            throw exception;
        }
    }

    /**
     * 由已登记模型与已打开的运行时生成激活描述（模型标识、阈值快照、阈值策略版本、输入契约）。
     *
     * <p>manifest {@code decision.adjustable=true} 表示阈值可在模型之外调整；本期没有阈值策略登记，
     * 无法证明线上使用的是哪一版阈值，因此拒绝（{@code MODEL_THRESHOLD_POLICY_UNSUPPORTED}）。
     * 阈值固定时，阈值策略版本即 {@code fixed:<manifest model_version>}，随模型版本不可变。</p>
     */
    public static ActiveModel describe(ModelService.ModelView model, OnnxModelRuntime runtime) {
        JsonNode decision = model.manifest().path("decision");
        double threshold = decision.path("threshold").asDouble(Double.NaN);
        if (!decision.path("threshold").isNumber() || !Double.isFinite(threshold) || threshold < 0 || threshold > 1) {
            throw new ModelContractException("MODEL_THRESHOLD_CONTRACT_MISMATCH");
        }
        if (decision.path("adjustable").asBoolean(false)) {
            throw new ModelContractException("MODEL_THRESHOLD_POLICY_UNSUPPORTED");
        }
        String manifestVersion = model.manifest().path("model_version").asText("");
        String policyVersion = "fixed:" + (manifestVersion.isBlank() ? model.modelKey() + "-" + model.version() : manifestVersion);
        if (policyVersion.length() > 96) throw new ModelContractException("MODEL_THRESHOLD_POLICY_UNSUPPORTED");
        return new ActiveModel(model.id(), model.modelKey(), model.version(), threshold, policyVersion, runtime.inputs());
    }

    /**
     * 事务提交后切换本机激活版本；事务回滚时关闭新会话。写锁等待进行中的推理结束后才关闭旧会话。
     *
     * @param descriptor 由 {@link #describe} 在数据库写入前生成，保证提交后的切换不会再因校验失败而中断
     */
    public void activateAfterCommit(ActiveModel descriptor, OnnxModelRuntime newRuntime) {
        long modelId = descriptor.modelId();
        Loaded loaded = new Loaded(descriptor, newRuntime);
        org.springframework.transaction.support.TransactionSynchronizationManager.registerSynchronization(
                new org.springframework.transaction.support.TransactionSynchronization() {
                    @Override public void afterCommit() {
                        activeLock.writeLock().lock();
                        try {
                            active.forEach((id, previous) -> { if (id != modelId && active.remove(id, previous)) closeQuietly(previous.runtime()); });
                            Loaded previous = active.put(modelId, loaded);
                            if (previous != null && previous.runtime() != newRuntime) closeQuietly(previous.runtime());
                        } finally { activeLock.writeLock().unlock(); }
                    }
                    @Override public void afterCompletion(int status) {
                        if (status != STATUS_COMMITTED) closeQuietly(newRuntime);
                    }
                });
    }

    /** 返回绑定该契约版本的激活模型输入范围；没有激活模型或契约不同时为空。 */
    @Override
    public Optional<ActiveModelInputs.Scope> forContract(String contractVersion) {
        activeLock.readLock().lock();
        try {
            return active.entrySet().stream()
                    .filter(entry -> entry.getValue().descriptor().inputs().contractVersion().equals(contractVersion))
                    .findFirst()
                    .map(entry -> {
                        ModelInputContract inputs = entry.getValue().descriptor().inputs();
                        return new ActiveModelInputs.Scope("model-" + entry.getKey(), inputs.vocabularies(),
                                inputs.supportedViewpoints(), inputs.supportedAddressFamilies(),
                                inputs.supportedProtocols(), inputs.requiresHandshakeSeen());
                    });
        } finally { activeLock.readLock().unlock(); }
    }

    /**
     * 当前本机激活模型的描述快照；没有激活模型时为空。同时存在多个激活版本属于不变量被破坏，
     * 显式失败（{@code ACTIVE_MODEL_AMBIGUOUS}），不挑选其中之一。
     */
    public Optional<ActiveModel> activeLocal() {
        activeLock.readLock().lock();
        try {
            if (active.size() > 1) throw new ModelContractException("ACTIVE_MODEL_AMBIGUOUS");
            return active.values().stream().findFirst().map(Loaded::descriptor);
        } finally { activeLock.readLock().unlock(); }
    }

    /**
     * 在读锁内用指定版本的激活会话执行一次调用。调用期间版本切换会等待其结束，旧会话不会被提前关闭。
     *
     * @param expectedModelId 调用方做门禁判定时看到的激活版本
     * @throws ModelContractException {@code ACTIVE_MODEL_UNAVAILABLE}（已无激活模型）或
     *                                {@code ACTIVE_MODEL_CHANGED}（判定后版本已切换，调用方须整批重来，不得混用版本）
     */
    public <T> T runOnActive(long expectedModelId, RuntimeCall<T> call) throws OrtException {
        activeLock.readLock().lock();
        try {
            if (active.isEmpty()) throw new ModelContractException("ACTIVE_MODEL_UNAVAILABLE");
            Loaded loaded = active.get(expectedModelId);
            if (loaded == null || active.size() != 1) throw new ModelContractException("ACTIVE_MODEL_CHANGED");
            return call.apply(loaded.runtime());
        } finally { activeLock.readLock().unlock(); }
    }

    @EventListener(ApplicationReadyEvent.class)
    public void restoreActiveDeployments() {
        List<ModelService.ModelView> deployments = mapper.listActiveDeployments().stream()
                .map(this::modelView)
                .toList();
        activeLock.writeLock().lock();
        try {
            for (ModelService.ModelView model : deployments) {
                OnnxModelRuntime runtime = prepare(model);
                Loaded previous = active.put(model.id(), new Loaded(describe(model, runtime), runtime));
                if (previous != null && previous.runtime() != runtime) closeQuietly(previous.runtime());
            }
        }
        finally { activeLock.writeLock().unlock(); }
    }

    /**
     * 激活前按模型输入契约的维度构造一条图冒烟样本（数值全 0、类别取各自词表内的确定值），
     * 并要求运行时返回恰好一条完整预测。该样本只验证图可执行，不代表合法流记录。
     */
    private static List<OnnxModelRuntime.Prediction> smokePredict(OnnxModelRuntime runtime) {
        try {
            ModelInputContract inputs = runtime.inputs();
            double[] numeric = new double[inputs.numericCount()];
            String[] categorical = inputs.categoricalFields().stream()
                    .map(field -> smokeCategory(field, inputs.vocabularies().getOrDefault(field, Set.of())))
                    .toArray(String[]::new);
            List<OnnxModelRuntime.Prediction> results = runtime.predict(List.of(new OnnxModelRuntime.FlowInput(
                    numeric, categorical)));
            if (results.size() != 1) throw new ModelContractException("MODEL_OUTPUT_CONTRACT_MISMATCH");
            return results;
        } catch (OrtException exception) {
            throw new ModelContractException("MODEL_SMOKE_TEST_FAILED", exception);
        }
    }

    /** 优先使用常见取值，保证冒烟样本在不同 JVM 间确定；词表缺失时交给图按 −1 编码。 */
    private static String smokeCategory(String field, Set<String> vocabulary) {
        if ("proto".equals(field) && vocabulary.contains("tcp")) return "tcp";
        if ("service".equals(field) && vocabulary.contains("-")) return "-";
        return vocabulary.stream().sorted().findFirst().orElse("-");
    }

    private OnnxModelRuntime open(ModelArtifactStore.VerifiedArtifact artifact) {
        try { return OnnxModelRuntime.open(artifact.modelPath(), artifact.inputs()); }
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
        try { active.values().forEach(loaded -> closeQuietly(loaded.runtime())); active.clear(); }
        finally { activeLock.writeLock().unlock(); }
    }

    public record ValidationResult(String status, String artifactSha256, String runtimeVersion, String summary) { }

    /**
     * 本机激活模型的不可变描述；推理结果以此为模型版本、阈值与阈值策略版本快照。
     *
     * @param modelId                {@code model_version.id}
     * @param decisionThreshold      manifest {@code decision.threshold}；ONNX 图内的 {@code is_attack} 已按它判定
     * @param thresholdPolicyVersion 阈值策略版本（阈值固定时为 {@code fixed:<model_version>}）
     */
    public record ActiveModel(long modelId, String modelKey, String version, double decisionThreshold,
                              String thresholdPolicyVersion, ModelInputContract inputs) { }

    /** 在激活会话上执行的调用；实现不得保存会话引用到调用之外。 */
    @FunctionalInterface
    public interface RuntimeCall<T> {
        T apply(OnnxModelRuntime runtime) throws OrtException;
    }

    private record Loaded(ActiveModel descriptor, OnnxModelRuntime runtime) { }
}
