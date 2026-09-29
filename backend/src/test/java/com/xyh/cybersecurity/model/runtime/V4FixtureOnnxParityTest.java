package com.xyh.cybersecurity.model.runtime;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.ingest.contract.FeatureContract;
import com.xyh.cybersecurity.ingest.contract.FeatureContractRegistry;
import com.xyh.cybersecurity.ingest.feature.FeatureBuilder;
import com.xyh.cybersecurity.ingest.feature.V4Fixtures;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * golden fixtures 端到端推理对拍（路线 B §9.2「Golden fixtures」「运行时」）：
 * {@code raw-flows →（Java Feature Builder）→ features →（ONNX Runtime Java）→ expected-outputs}。
 *
 * <p>模型制品不入库，由环境变量 {@code MODEL_DELIVERY_V4_DIR} 指向交付包目录；未设置时跳过。读取前核对
 * manifest 与 checksums.json 中登记的 model.onnx、preprocessing.json 哈希。概率容差 1e-5，标签必须完全一致。</p>
 */
@EnabledIfEnvironmentVariable(named = "MODEL_DELIVERY_V4_DIR", matches = ".+")
class V4FixtureOnnxParityTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final double MAX_PROBABILITY_DELTA = 1e-5;

    @Test
    void javaFeaturesThroughDeliveryModelMatchExpectedOutputs() throws Exception {
        Path delivery = Path.of(System.getenv("MODEL_DELIVERY_V4_DIR")).toRealPath();
        JsonNode manifest = JSON.readTree(delivery.resolve("model_manifest.json").toFile());
        JsonNode checksums = JSON.readTree(delivery.resolve("checksums.json").toFile());
        Path model = delivery.resolve("model.onnx");
        Path preprocessing = delivery.resolve("preprocessing.json");
        assertThat(sha256(model)).isEqualTo(manifest.at("/artifact/sha256").asText()).isEqualTo(declared(checksums, "model.onnx"));
        assertThat(sha256(preprocessing)).isEqualTo(declared(checksums, "preprocessing.json"));
        // 交付包 fixtures 与仓库内 fixtures 必须是同一份。
        assertThat(manifest.at("/fixtures/checksums_sha256").asText())
                .isEqualTo(V4Fixtures.contract().goldenFixtures().checksumsSha256());

        FeatureContract contract = FeatureContractRegistry.fromClasspath().require(V4Fixtures.CONTRACT);
        ModelInputContract inputs = ModelInputContract.from(manifest, JSON.readTree(preprocessing.toFile()), contract);
        double threshold = manifest.at("/decision/threshold").asDouble(Double.NaN);
        assertThat(threshold).isBetween(0.0, 1.0);

        V4Fixtures.verifyChecksums();
        Map<Long, FeatureBuilder.BuildResult> built = V4Fixtures.buildAll();
        List<JsonNode> expected = V4Fixtures.jsonl("expected-outputs.jsonl");
        List<OnnxModelRuntime.FlowInput> batch = new ArrayList<>();
        for (JsonNode row : expected) {
            FeatureBuilder.BuildResult result = built.get(row.get("seq").asLong());
            assertThat(result.ready()).as("seq %d", row.get("seq").asLong()).isTrue();
            assertThat(result.viewpoint()).isEqualTo("responder");
            batch.add(toInput(result.features(), inputs));
        }

        List<OnnxModelRuntime.Prediction> predictions;
        try (OnnxModelRuntime runtime = OnnxModelRuntime.open(model, inputs)) {
            predictions = runtime.predict(batch);
        }
        assertThat(predictions).hasSize(expected.size());
        double maxDelta = 0;
        for (int i = 0; i < expected.size(); i++) {
            JsonNode want = expected.get(i);
            OnnxModelRuntime.Prediction got = predictions.get(i);
            maxDelta = Math.max(maxDelta, Math.abs(got.attackProbability() - want.get("attack_probability").asDouble()));
            assertThat(got.isAttack()).as("seq %d is_attack", want.get("seq").asLong()).isEqualTo(want.get("is_attack").asBoolean());
            assertThat(got.isAttack()).isEqualTo(got.attackProbability() >= threshold);
        }
        assertThat(maxDelta).as("最大概率绝对误差").isLessThanOrEqualTo(MAX_PROBABILITY_DELTA);
    }

    /** 按模型输入契约的列顺序取特征；Builder 输出字段集已由 GoldenFixturesTest 核对。 */
    private static OnnxModelRuntime.FlowInput toInput(JsonNode features, ModelInputContract inputs) {
        double[] numeric = inputs.numericFields().stream().mapToDouble(name -> features.get(name).asDouble()).toArray();
        String[] categorical = inputs.categoricalFields().stream().map(name -> features.get(name).asText()).toArray(String[]::new);
        return new OnnxModelRuntime.FlowInput(numeric, categorical);
    }

    private static String declared(JsonNode checksums, String name) {
        JsonNode value = checksums.path(name);
        if (value.isMissingNode()) value = checksums.path("files").path(name);
        if (value.isObject()) value = value.path("sha256");
        return value.asText();
    }

    private static String sha256(Path path) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path)));
    }
}
