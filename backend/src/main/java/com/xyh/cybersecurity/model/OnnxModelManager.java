package com.xyh.cybersecurity.model;

import ai.onnxruntime.OrtException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/** 验证并缓存明确批准的 ONNX 版本；进程重启时只恢复数据库标记为 active 的本机版本。 */
@Component
public class OnnxModelManager implements DisposableBean {

    private final JdbcTemplate jdbc;
    private final ObjectMapper objectMapper;
    private final ModelArtifactStore artifacts;
    private final ConcurrentMap<Long, OnnxModelRuntime> active = new ConcurrentHashMap<>();

    public OnnxModelManager(JdbcTemplate jdbc, ObjectMapper objectMapper, ModelArtifactStore artifacts) {
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
        this.artifacts = artifacts;
    }

    public ValidationResult validate(ModelService.ModelView model) {
        ModelArtifactStore.VerifiedArtifact artifact = artifacts.verify(model);
        OnnxModelRuntime runtime = open(artifact);
        try (runtime) {
            double[] numeric = new double[OnnxModelRuntime.NUMERIC_FEATURE_COUNT];
            List<OnnxModelRuntime.Prediction> results = runtime.predict(List.of(new OnnxModelRuntime.FlowInput(
                    numeric, new String[]{"tcp", "-"})));
            double threshold = artifact.manifest().at("/decision/threshold").asDouble(Double.NaN);
            if (!Double.isFinite(threshold) || threshold < 0 || threshold > 1) {
                throw new IllegalStateException("MODEL_THRESHOLD_CONTRACT_MISMATCH");
            }
            if (results.size() != 1 || results.getFirst().isAttack() != (results.getFirst().attackProbability() >= threshold)) {
                throw new IllegalStateException("MODEL_SMOKE_TEST_FAILED");
            }
        } catch (OrtException exception) {
            throw new IllegalStateException("MODEL_SMOKE_TEST_FAILED");
        }
        return new ValidationResult("passed", artifact.sha256(), OnnxModelRuntime.RUNTIME_VERSION,
                "ONNX inputs/outputs and one-record CPU smoke inference passed");
    }

    public OnnxModelRuntime prepare(ModelService.ModelView model) {
        return open(artifacts.verify(model));
    }

    public void activateAfterCommit(long modelId, OnnxModelRuntime newRuntime) {
        org.springframework.transaction.support.TransactionSynchronizationManager.registerSynchronization(
                new org.springframework.transaction.support.TransactionSynchronization() {
                    @Override public void afterCommit() {
                        active.forEach((id, previous) -> { if (id != modelId && active.remove(id, previous)) closeQuietly(previous); });
                        OnnxModelRuntime previous = active.put(modelId, newRuntime);
                        if (previous != null && previous != newRuntime) closeQuietly(previous);
                    }
                    @Override public void afterCompletion(int status) {
                        if (status != STATUS_COMMITTED) closeQuietly(newRuntime);
                    }
                });
    }

    public OnnxModelRuntime active(long modelId) {
        OnnxModelRuntime runtime = active.get(modelId);
        if (runtime == null) throw new IllegalStateException("ACTIVE_MODEL_RUNTIME_UNAVAILABLE");
        return runtime;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void restoreActiveDeployments() {
        List<ActiveDeployment> deployments = jdbc.query("SELECT mv.id,mv.model_key,mv.version,mv.task_type,"
                        + "mv.manifest_version,CAST(mv.manifest_json AS CHAR) manifest_json,mv.artifact_ref,"
                        + "mv.artifact_sha256,mv.feature_contract_version,mv.approval_status,mv.created_at "
                        + "FROM model_deployment md JOIN model_version mv ON mv.id=md.model_version_id "
                        + "WHERE md.status='active' AND md.mode='local' AND mv.approval_status='approved'",
                (rs, row) -> new ActiveDeployment(modelView(rs), rs.getLong("id")));
        for (ActiveDeployment deployment : deployments) active.put(deployment.id(), prepare(deployment.model()));
    }

    private OnnxModelRuntime open(ModelArtifactStore.VerifiedArtifact artifact) {
        try { return OnnxModelRuntime.open(artifact.modelPath()); }
        catch (OrtException | IllegalArgumentException exception) {
            throw new IllegalStateException("MODEL_ONNX_CONTRACT_MISMATCH");
        }
    }

    private ModelService.ModelView modelView(ResultSet rs) throws SQLException {
        try {
            JsonNode manifest = objectMapper.readTree(rs.getString("manifest_json"));
            return new ModelService.ModelView(rs.getLong("id"), rs.getString("model_key"), rs.getString("version"),
                    rs.getString("task_type"), rs.getString("manifest_version"), manifest, rs.getString("artifact_ref"),
                    rs.getString("artifact_sha256"), rs.getString("feature_contract_version"),
                    rs.getString("approval_status"), rs.getTimestamp("created_at").toLocalDateTime());
        } catch (java.io.IOException exception) {
            throw new IllegalStateException("Stored model manifest is invalid JSON", exception);
        }
    }

    private static void closeQuietly(OnnxModelRuntime runtime) {
        try { runtime.close(); } catch (OrtException ignored) { }
    }

    @Override public void destroy() { active.values().forEach(OnnxModelManager::closeQuietly); }

    public record ValidationResult(String status, String artifactSha256, String runtimeVersion, String summary) { }
    private record ActiveDeployment(ModelService.ModelView model, long id) { }
}
