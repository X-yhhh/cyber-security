package com.xyh.cybersecurity.ingest.replay;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.ingest.contract.ActiveModelInputs;
import com.xyh.cybersecurity.ingest.contract.FeatureContract;
import com.xyh.cybersecurity.ingest.contract.FeatureContractRegistry;
import com.xyh.cybersecurity.ingest.contract.FeatureContractValidator;
import com.xyh.cybersecurity.ingest.contract.RecordMetadata;
import com.xyh.cybersecurity.ingest.feature.AddressPolicy;
import com.xyh.cybersecurity.ingest.feature.FeatureBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * UNSW 原始 CSV 回放 1 万条端到端对拍（路线 B §9.2「端到端特征」）。
 *
 * <p>参考数据由训练端 {@code feature_audit.recompute_ct} 生成（仅读特征与地址列，不读标签、切分或 holdout），
 * 存放在仓库外，由环境变量 {@code FEATURE_E2E_REFERENCE_DIR} 指定；未设置时跳过。读取前核对
 * {@code reference.json} 中登记的文件哈希。</p>
 *
 * <p>比对口径：{@code ct_*}、{@code service}、{@code proto} 完全相等；逐流数值按训练端 float32 口径比较
 * （Java 从 CSV 解析为 double，转 float 后与参考值相等）。前 99 个窗口成员只做预热，不参与比对。</p>
 */
@EnabledIfEnvironmentVariable(named = "FEATURE_E2E_REFERENCE_DIR", matches = ".+")
class UnswRawReplayEndToEndTest {
    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    void javaReplayMatchesTrainingReferenceFieldByField() throws Exception {
        Path dir = Path.of(System.getenv("FEATURE_E2E_REFERENCE_DIR"));
        JsonNode info = JSON.readTree(dir.resolve("reference.json").toFile());
        for (String name : List.of("raw-segment.csv", "expected-reference.jsonl")) {
            assertThat(sha256(dir.resolve(name))).as(name).isEqualTo(info.at("/files/" + name).asText());
        }
        FeatureContract contract = FeatureContractRegistry.fromClasspath().require("unsw-nb15-flow-v4");
        assertThat(info.get("window").asInt()).isEqualTo(contract.window().size());

        // 片段按原始行号升序保存；文件内位置与原始行号同序，可直接作为导出序号 tie-break。
        List<UnswRawFlowReplayAdapter.RawFlow> rows = new UnswRawFlowReplayAdapter().read(dir.resolve("raw-segment.csv"), 0);
        List<JsonNode> refs = new ArrayList<>();
        for (String line : Files.readAllLines(dir.resolve("expected-reference.jsonl"), StandardCharsets.UTF_8)) {
            if (!line.isBlank()) refs.add(JSON.readTree(line));
        }
        assertThat(rows).hasSize(refs.size()).hasSize(info.get("rows").asInt());

        FeatureBuilder builder = new FeatureBuilder(contract, AddressPolicy.unswReplay(info.get("sensor_host").asText()));
        Map<UnswRawFlowReplayAdapter.RawFlow, FeatureBuilder.BuildResult> results = new IdentityHashMap<>();
        for (UnswRawFlowReplayAdapter.RawFlow row : UnswRawFlowReplayAdapter.inWindowOrder(rows)) {
            results.put(row, builder.accept(row.flow()));
        }

        FeatureContractValidator validator = new FeatureContractValidator(FeatureContractRegistry.fromClasspath(),
                ActiveModelInputs.NONE);
        int compared = 0;
        int validatorRejects = 0;
        for (int i = 0; i < rows.size(); i++) {
            JsonNode ref = refs.get(i);
            FeatureBuilder.BuildResult result = results.get(rows.get(i));
            if ("excluded".equals(ref.path("status").asText())) {
                assertThat(result.status()).as("row %d", i).isEqualTo(FeatureBuilder.Status.EXCLUDED);
                continue;
            }
            assertThat(result.viewpoint()).as("row %d viewpoint", i).isEqualTo(ref.get("viewpoint").asText());
            if (result.ready()) {
                FeatureBuilder.FlowInput flow = rows.get(i).flow();
                boolean handshake = "tcp".equals(flow.proto()) && flow.synack() > 0 && flow.ackdat() > 0;
                if (!validator.validate(contract.version(), result.features(),
                        new RecordMetadata(result.viewpoint(), result.addressFamily(), handshake)).valid()) {
                    validatorRejects++;
                }
            }
            if (!ref.get("compare").asBoolean()) continue;
            compared++;
            assertThat(result.status()).as("row %d status", i).isEqualTo(FeatureBuilder.Status.READY);
            JsonNode actual = result.features();
            for (FeatureContract.NumericField field : contract.numericFields()) {
                if (field.source() == FeatureContract.FieldSource.WINDOW) {
                    assertThat(actual.get(field.name()).asLong()).as("row %d %s", i, field.name())
                            .isEqualTo(ref.get(field.name()).asLong());
                } else {
                    assertThat((float) actual.get(field.name()).asDouble()).as("row %d %s", i, field.name())
                            .isEqualTo((float) ref.get(field.name()).asDouble());
                }
            }
            for (String field : contract.categoricalFieldNames()) {
                assertThat(actual.get(field).asText()).as("row %d %s", i, field).isEqualTo(ref.get(field).asText());
            }
        }
        assertThat(compared).isEqualTo(info.get("compare_rows").asInt());
        assertThat(validatorRejects).as("Builder 输出被校验器误拒的条数").isZero();
    }

    private static String sha256(Path path) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path)));
    }
}
