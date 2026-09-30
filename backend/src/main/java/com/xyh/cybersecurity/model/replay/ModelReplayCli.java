package com.xyh.cybersecurity.model.replay;

import ai.onnxruntime.OrtException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.ingest.contract.FeatureContractRegistry;
import com.xyh.cybersecurity.model.runtime.ModelInputContract;
import com.xyh.cybersecurity.model.runtime.OnnxModelRuntime;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVPrinter;
import org.apache.commons.csv.CSVRecord;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/**
 * 离线回放训练端交付的 10,000 条样本，不连接数据库或网络。
 *
 * <p>输入维度与字段顺序来自 {@link ModelInputContract}（manifest + preprocessing.json + 已注册特征契约），
 * 同时支持 v3.1 与 v4 交付包。结果只写入独立的输出目录：交付包内的文件（含 {@code evaluation-report.md}）
 * 都登记在 {@code checksums.json} 中，原地追加会使后续制品校验报 {@code MODEL_CHECKSUMS_MISMATCH}。</p>
 */
public final class ModelReplayCli {
    private static final int EXPECTED_ROWS = 10_000;
    /** 路线 B §10.2：Java 回放与训练端概率最大误差 ≤ 1e-5（严于训练端导出门槛 1e-4）。 */
    private static final double MAX_PROBABILITY_DELTA = 1e-5;
    private static final int BATCH = 1024;

    private ModelReplayCli() { }

    public static void main(String[] args) throws Exception {
        if (args.length != 2) throw new IllegalArgumentException("用法: ModelReplayCli <delivery-directory> <output-directory>");
        Path delivery = Path.of(args[0]).toRealPath();
        Path output = Path.of(args[1]).toAbsolutePath().normalize();
        if (output.startsWith(delivery)) throw new IllegalArgumentException("输出目录不能位于交付目录内，避免破坏 checksums.json");
        Files.createDirectories(output);
        Path results = output.resolve("backend-replay-results.csv");
        Path reportPath = output.resolve("backend-replay-report.md");
        if (Files.exists(results) || Files.exists(reportPath)) throw new IllegalStateException("输出已存在，拒绝覆盖");

        Path model = inside(delivery, "model.onnx");
        Path sample = inside(delivery, "replay-sample.csv");
        ObjectMapper mapper = new ObjectMapper();
        JsonNode manifest = mapper.readTree(inside(delivery, "model_manifest.json").toFile());
        JsonNode checksums = mapper.readTree(inside(delivery, "checksums.json").toFile());
        String modelSha = sha256(model);
        if (!modelSha.equalsIgnoreCase(manifest.at("/artifact/sha256").asText())) throw new IllegalStateException("manifest model hash mismatch");
        requireChecksum(checksums, "model.onnx", modelSha);
        Path preprocessingPath = inside(delivery, "preprocessing.json");
        requireChecksum(checksums, "preprocessing.json", sha256(preprocessingPath));
        if (!"1.23.2".equals(manifest.at("/runtime/onnxruntime").asText()) || manifest.at("/artifact/opset/").asInt(-1) != 17) {
            throw new IllegalStateException("manifest runtime must require ONNX Runtime 1.23.2 and opset 17");
        }
        double threshold = manifest.at("/decision/threshold").asDouble(Double.NaN);
        if (!Double.isFinite(threshold) || threshold < 0 || threshold > 1) throw new IllegalStateException("invalid threshold");
        String version = manifest.at("/feature_contract/version").asText();
        ModelInputContract inputs = ModelInputContract.from(manifest, mapper.readTree(preprocessingPath.toFile()),
                FeatureContractRegistry.fromClasspath().find(version));

        long startedAt = System.nanoTime();
        Summary summary;
        try (OnnxModelRuntime runtime = OnnxModelRuntime.open(model, inputs);
             CSVParser parser = CSVParser.parse(sample, StandardCharsets.UTF_8,
                     CSVFormat.DEFAULT.builder().setHeader().setSkipHeaderRecord(true).setIgnoreEmptyLines(false).get())) {
            summary = replay(runtime, parser, inputs, threshold, results);
        } catch (OrtException exception) {
            throw new IllegalStateException("ONNX Runtime failed to load or execute the delivery model");
        }
        double seconds = (System.nanoTime() - startedAt) / 1e9;
        boolean passed = summary.rows == EXPECTED_ROWS && summary.maxDelta <= MAX_PROBABILITY_DELTA && summary.mismatches == 0;
        String report = "# 本机 Java 后端回放验证\n\n"
                + "- 交付包：`" + manifest.path("model_version").asText() + "`（契约 `" + version + "`，"
                + inputs.numericCount() + " 数值 + " + inputs.categoricalCount() + " 类别）\n"
                + "- 样本数：" + summary.rows + "\n- ONNX Runtime Java：" + OnnxModelRuntime.RUNTIME_VERSION + "\n"
                + "- 模型 SHA-256：`" + modelSha + "`\n- 最大概率绝对误差：" + summary.maxDelta + "\n"
                + "- 平均概率绝对误差：" + (summary.totalDelta / Math.max(1, summary.rows)) + "\n"
                + "- 逐位概率相同：" + summary.bitwise + "/" + summary.rows + "\n- 标签不一致：" + summary.mismatches + "\n"
                + "- 总运行时间：" + seconds + " 秒；吞吐：" + (summary.rows / seconds) + " 条/秒\n"
                + "- " + MAX_PROBABILITY_DELTA + " 门限及 100% 标签一致：" + (passed ? "通过" : "失败") + "\n"
                + "- 逐行记录：`backend-replay-results.csv`（SHA-256 `" + sha256(results) + "`）\n";
        Files.writeString(reportPath, report, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
        System.out.println(report);
        if (!passed) throw new IllegalStateException("Java replay did not meet the 10,000-row parity gate; report is marked failed");
    }

    private static Summary replay(OnnxModelRuntime runtime, CSVParser parser, ModelInputContract inputs, double threshold,
                                  Path resultFile) throws IOException, OrtException {
        Map<String, Integer> header = parser.getHeaderMap();
        for (String name : inputs.numericFields()) if (!header.containsKey(name)) throw new IllegalArgumentException("missing numeric input column: " + name);
        for (String name : inputs.categoricalFields()) if (!header.containsKey(name)) throw new IllegalArgumentException("missing categorical input column: " + name);
        String probabilityColumn = firstColumn(header, "expected_probability", "remote_attack_probability", "remote_probability", "attack_probability");
        String labelColumn = firstColumn(header, "expected_is_attack", "remote_is_attack", "remote_label", "is_attack");
        if (probabilityColumn == null || labelColumn == null) throw new IllegalArgumentException("replay CSV must contain remote probability and binary label columns");
        Summary summary = new Summary();
        try (BufferedWriter writer = Files.newBufferedWriter(resultFile, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
             CSVPrinter printer = new CSVPrinter(writer, CSVFormat.DEFAULT.builder().setHeader("row_number", "remote_probability",
                     "java_probability", "absolute_delta", "remote_is_attack", "java_is_attack", "label_match").get())) {
            List<CSVRecord> records = new ArrayList<>(BATCH);
            List<OnnxModelRuntime.FlowInput> batch = new ArrayList<>(BATCH);
            for (CSVRecord record : parser) {
                if (++summary.rows > EXPECTED_ROWS) throw new IllegalArgumentException("replay CSV contains more than 10,000 rows");
                records.add(record);
                batch.add(input(record, inputs));
                if (records.size() == BATCH) { evaluate(runtime, records, batch, threshold, probabilityColumn, labelColumn, printer, summary); records.clear(); batch.clear(); }
            }
            if (!records.isEmpty()) evaluate(runtime, records, batch, threshold, probabilityColumn, labelColumn, printer, summary);
        }
        return summary;
    }

    private static void evaluate(OnnxModelRuntime runtime, List<CSVRecord> records, List<OnnxModelRuntime.FlowInput> batch,
                                 double threshold, String probabilityColumn, String labelColumn, CSVPrinter printer,
                                 Summary summary) throws IOException, OrtException {
        List<OnnxModelRuntime.Prediction> predictions = runtime.predict(batch);
        for (int i = 0; i < predictions.size(); i++) {
            CSVRecord record = records.get(i);
            OnnxModelRuntime.Prediction prediction = predictions.get(i);
            double remote = Double.parseDouble(record.get(probabilityColumn));
            boolean remoteLabel = parseLabel(record.get(labelColumn));
            double delta = Math.abs(remote - prediction.attackProbability());
            boolean match = remoteLabel == prediction.isAttack() && prediction.isAttack() == (prediction.attackProbability() >= threshold);
            summary.maxDelta = Math.max(summary.maxDelta, delta);
            summary.totalDelta += delta;
            if (Double.doubleToLongBits(remote) == Double.doubleToLongBits(prediction.attackProbability())) summary.bitwise++;
            if (!match) summary.mismatches++;
            printer.printRecord(record.getRecordNumber(), remote, prediction.attackProbability(), delta, remoteLabel, prediction.isAttack(), match);
        }
    }

    /** 空白/{@code nan} 按 NaN 传入，由运行时 fail-closed 拒绝；不补值。 */
    private static OnnxModelRuntime.FlowInput input(CSVRecord record, ModelInputContract inputs) {
        try {
            double[] numeric = new double[inputs.numericCount()];
            for (int i = 0; i < numeric.length; i++) {
                String value = record.get(inputs.numericFields().get(i)).trim();
                numeric[i] = value.isEmpty() || "nan".equalsIgnoreCase(value) || "null".equalsIgnoreCase(value) ? Double.NaN : Double.parseDouble(value);
            }
            String[] categorical = new String[inputs.categoricalCount()];
            for (int i = 0; i < categorical.length; i++) {
                String value = record.get(inputs.categoricalFields().get(i));
                if (value.isBlank()) throw new IllegalArgumentException("missing categorical feature");
                categorical[i] = value;
            }
            return new OnnxModelRuntime.FlowInput(numeric, categorical);
        } catch (RuntimeException exception) {
            throw new IllegalArgumentException("invalid replay sample at row " + record.getRecordNumber(), exception);
        }
    }

    private static Path inside(Path delivery, String name) throws IOException {
        Path path = delivery.resolve(name).toRealPath();
        if (!path.startsWith(delivery) || !Files.isRegularFile(path)) throw new IllegalArgumentException("交付文件必须位于同一交付目录内: " + name);
        return path;
    }

    private static void requireChecksum(JsonNode checksums, String name, String actual) {
        JsonNode value = checksums.path(name);
        if (value.isMissingNode()) value = checksums.path("files").path(name);
        if (value.isObject()) value = value.path("sha256");
        if (!value.isTextual() || !value.asText().equalsIgnoreCase(actual)) throw new IllegalStateException(name + " SHA-256 does not match checksums.json");
    }

    private static boolean parseLabel(String value) {
        return switch (value.trim().toLowerCase(java.util.Locale.ROOT)) {
            case "1", "true", "attack" -> true;
            case "0", "false", "normal" -> false;
            default -> throw new IllegalArgumentException("remote label must be binary");
        };
    }

    private static String firstColumn(Map<String, Integer> header, String... names) {
        for (String name : names) if (header.containsKey(name)) return name;
        return null;
    }

    private static String sha256(Path path) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (var input = Files.newInputStream(path)) {
                byte[] buffer = new byte[64 * 1024];
                for (int count; (count = input.read(buffer)) >= 0;) digest.update(buffer, 0, count);
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (java.security.NoSuchAlgorithmException exception) {
            throw new IllegalStateException(exception);
        }
    }

    private static final class Summary {
        long rows, bitwise, mismatches;
        double maxDelta, totalDelta;
    }
}
