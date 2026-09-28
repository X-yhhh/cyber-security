package com.xyh.cybersecurity.model.replay;

import ai.onnxruntime.OrtException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.model.runtime.OnnxModelRuntime;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVPrinter;
import org.apache.commons.csv.CSVRecord;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

/** 离线回放训练端交付的 10,000 条样本，不连接数据库或网络。 */
public final class ModelReplayCli {
    private static final int EXPECTED_ROWS = 10_000;
    private static final double MAX_PROBABILITY_DELTA = 1e-4;

    private ModelReplayCli() { }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("用法: ModelReplayCli <delivery-directory>");
        Path delivery = Path.of(args[0]).toRealPath();
        Path model = delivery.resolve("model.onnx").toRealPath();
        Path manifestPath = delivery.resolve("model_manifest.json").toRealPath();
        Path sample = delivery.resolve("replay-sample.csv").toRealPath();
        if (!model.startsWith(delivery) || !manifestPath.startsWith(delivery) || !sample.startsWith(delivery)) {
            throw new IllegalArgumentException("交付文件必须位于同一交付目录内");
        }
        ObjectMapper mapper = new ObjectMapper();
        JsonNode manifest = mapper.readTree(manifestPath.toFile());
        String modelSha = sha256(model);
        if (!modelSha.equalsIgnoreCase(manifest.at("/artifact/sha256").asText())) throw new IllegalStateException("manifest model hash mismatch");
        verifyDeclaredModelHash(delivery.resolve("checksums.json"), modelSha);
        if (!"1.23.2".equals(runtimeVersion(manifest)) || manifest.path("artifact").path("opset").path("").asInt(-1) != 17) {
            throw new IllegalStateException("manifest runtime must require ONNX Runtime 1.23.2 and opset 17");
        }
        double threshold = manifest.at("/decision/threshold").asDouble(Double.NaN);
        if (!Double.isFinite(threshold) || threshold < 0 || threshold > 1) throw new IllegalStateException("invalid threshold");
        List<String> numericNames = featureNames(manifest, true);
        List<String> categoricalNames = featureNames(manifest, false);
        if (numericNames.size() != OnnxModelRuntime.NUMERIC_FEATURE_COUNT
                || categoricalNames.size() != OnnxModelRuntime.CATEGORICAL_FEATURE_COUNT
                || !categoricalNames.containsAll(List.of("proto", "service"))) {
            throw new IllegalStateException("manifest feature order does not match ONNX input contract");
        }

        Path resultsPath = delivery.resolve("backend-replay-results.csv");
        Path reportPath = delivery.resolve("evaluation-report.md");
        String marker = "## 本机 Java 后端回放验证";
        if (Files.exists(resultsPath) || !Files.isRegularFile(reportPath)
                || Files.readString(reportPath).contains(marker)) {
            throw new IllegalStateException("replay output already exists or evaluation report is unavailable; refusing to overwrite");
        }
        long startedAt = System.nanoTime();
        ReplaySummary summary;
        try (OnnxModelRuntime runtime = OnnxModelRuntime.open(model);
             CSVParser parser = CSVParser.parse(sample, java.nio.charset.StandardCharsets.UTF_8,
                     CSVFormat.DEFAULT.builder().setHeader().setSkipHeaderRecord(true).setIgnoreEmptyLines(false).get())) {
            summary = replay(runtime, parser, numericNames, categoricalNames, threshold, resultsPath);
        } catch (OrtException exception) {
            throw new IllegalStateException("ONNX Runtime failed to load or execute the delivery model");
        }
        double elapsedSeconds = (System.nanoTime() - startedAt) / 1_000_000_000d;
        String report = "\n\n" + marker + "\n\n"
                + "- 样本数：" + summary.rows + "\n"
                + "- ONNX Runtime Java：1.23.2\n"
                + "- 模型 SHA-256：`" + modelSha + "`\n"
                + "- 最大概率绝对误差：" + summary.maxDelta + "\n"
                + "- 平均概率绝对误差：" + (summary.totalDelta / summary.rows) + "\n"
                + "- 逐位概率相同：" + summary.bitwiseMatches + "/" + summary.rows + "\n"
                + "- 标签不一致：" + summary.labelMismatches + "\n"
                + "- 总运行时间：" + elapsedSeconds + " 秒；吞吐：" + (summary.rows / elapsedSeconds) + " 条/秒\n"
                + "- 1e-4 门限及 100% 标签一致：" + (summary.maxDelta <= MAX_PROBABILITY_DELTA && summary.labelMismatches == 0 ? "通过" : "失败") + "\n"
                + "- 逐行记录：`backend-replay-results.csv`\n";
        Files.writeString(reportPath, report, java.nio.charset.StandardCharsets.UTF_8, StandardOpenOption.APPEND);
        if (summary.rows != EXPECTED_ROWS || summary.maxDelta > MAX_PROBABILITY_DELTA || summary.labelMismatches != 0) {
            throw new IllegalStateException("Java replay did not meet the 10,000-row parity gate; report is marked failed");
        }
        System.out.println(report);
    }

    private static ReplaySummary replay(OnnxModelRuntime runtime, CSVParser parser, List<String> numericNames,
                                        List<String> categoricalNames, double threshold, Path resultFile) throws IOException, OrtException {
        var header = parser.getHeaderMap();
        for (String name : numericNames) if (!header.containsKey(name)) throw new IllegalArgumentException("missing numeric input column: " + name);
        for (String name : categoricalNames) if (!header.containsKey(name)) throw new IllegalArgumentException("missing categorical input column: " + name);
        String probabilityColumn = firstColumn(header, "expected_probability", "remote_attack_probability", "remote_probability", "attack_probability");
        String labelColumn = firstColumn(header, "expected_is_attack", "remote_is_attack", "remote_label", "is_attack");
        if (probabilityColumn == null || labelColumn == null) throw new IllegalArgumentException("replay CSV must contain remote probability and binary label columns");

        long rows = 0, bitwise = 0, mismatches = 0;
        double maxDelta = 0, totalDelta = 0;
        List<String> resultRows = new ArrayList<>(1024);
        try (BufferedWriter writer = Files.newBufferedWriter(resultFile, java.nio.charset.StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
             CSVPrinter printer = new CSVPrinter(writer, CSVFormat.DEFAULT.builder().setHeader(
                     "row_number", "remote_probability", "java_probability", "absolute_delta", "remote_is_attack", "java_is_attack", "label_match").get())) {
            List<CSVRecord> batchRecords = new ArrayList<>(1024);
            List<OnnxModelRuntime.FlowInput> batchInputs = new ArrayList<>(1024);
            for (CSVRecord record : parser) {
                if (++rows > EXPECTED_ROWS) throw new IllegalArgumentException("replay CSV contains more than 10,000 rows");
                batchRecords.add(record);
                batchInputs.add(input(record, numericNames, categoricalNames));
                if (batchRecords.size() == 1024) {
                    Stats stats = evaluateBatch(runtime, batchRecords, batchInputs, threshold, printer);
                    maxDelta = Math.max(maxDelta, stats.maxDelta); totalDelta += stats.totalDelta;
                    bitwise += stats.bitwiseMatches; mismatches += stats.labelMismatches;
                    batchRecords.clear(); batchInputs.clear();
                }
            }
            if (!batchRecords.isEmpty()) {
                Stats stats = evaluateBatch(runtime, batchRecords, batchInputs, threshold, printer);
                maxDelta = Math.max(maxDelta, stats.maxDelta); totalDelta += stats.totalDelta;
                bitwise += stats.bitwiseMatches; mismatches += stats.labelMismatches;
            }
        }
        if (rows != EXPECTED_ROWS) throw new IllegalArgumentException("replay CSV must contain exactly 10,000 rows");
        return new ReplaySummary(rows, maxDelta, totalDelta, bitwise, mismatches);
    }

    private static Stats evaluateBatch(OnnxModelRuntime runtime, List<CSVRecord> records,
                                       List<OnnxModelRuntime.FlowInput> inputs, double threshold,
                                       CSVPrinter printer) throws IOException, OrtException {
        List<OnnxModelRuntime.Prediction> predictions = runtime.predict(inputs);
        double max = 0, total = 0;
        long bitwise = 0, mismatches = 0;
        for (int index = 0; index < predictions.size(); index++) {
            CSVRecord record = records.get(index);
            OnnxModelRuntime.Prediction prediction = predictions.get(index);
            double remote = Double.parseDouble(record.get(firstColumn(record.getParser().getHeaderMap(),
                    "expected_probability", "remote_attack_probability", "remote_probability", "attack_probability")));
            boolean remoteLabel = parseLabel(record.get(firstColumn(record.getParser().getHeaderMap(),
                    "expected_is_attack", "remote_is_attack", "remote_label", "is_attack")));
            double delta = Math.abs(remote - prediction.attackProbability());
            boolean labelMatch = remoteLabel == prediction.isAttack() && prediction.isAttack() == (prediction.attackProbability() >= threshold);
            max = Math.max(max, delta); total += delta;
            if (Double.doubleToLongBits(remote) == Double.doubleToLongBits((double) prediction.attackProbability())) bitwise++;
            if (!labelMatch) mismatches++;
            printer.printRecord(record.getRecordNumber(), remote, prediction.attackProbability(), delta,
                    remoteLabel, prediction.isAttack(), labelMatch);
        }
        return new Stats(max, total, bitwise, mismatches);
    }

    private static OnnxModelRuntime.FlowInput input(CSVRecord record, List<String> numericNames, List<String> categoricalNames) {
        double[] numeric = new double[numericNames.size()];
        String[] categorical = new String[categoricalNames.size()];
        try {
            for (int i = 0; i < numeric.length; i++) {
                String value = record.get(numericNames.get(i));
                numeric[i] = parseNumeric(value);
            }
            for (int i = 0; i < categorical.length; i++) {
                String value = record.get(categoricalNames.get(i));
                if (value.isBlank()) throw new IllegalArgumentException("missing categorical feature");
                categorical[i] = value;
            }
        } catch (RuntimeException exception) {
            throw new IllegalArgumentException("invalid replay sample at row " + record.getRecordNumber(), exception);
        }
        return new OnnxModelRuntime.FlowInput(numeric, categorical);
    }

    private static double parseNumeric(String value) {
        String normalized = value.trim();
        if (normalized.isEmpty() || "null".equalsIgnoreCase(normalized)
                || "nan".equalsIgnoreCase(normalized)) return Double.NaN;
        return Double.parseDouble(normalized);
    }

    private static List<String> featureNames(JsonNode manifest, boolean numeric) {
        JsonNode inputs = manifest.path("feature_contract").path("inputs");
        JsonNode fields = inputs.path(numeric ? "flow_numeric" : "flow_categorical");
        if (!fields.isArray()) throw new IllegalArgumentException("manifest feature contract inputs are missing");
        List<String> names = new ArrayList<>();
        fields.forEach(field -> { if (field.isTextual()) names.add(field.asText()); });
        return names;
    }

    private static boolean parseLabel(String value) {
        return switch (value.trim().toLowerCase(java.util.Locale.ROOT)) {
            case "1", "true", "attack" -> true;
            case "0", "false", "normal" -> false;
            default -> throw new IllegalArgumentException("remote label must be binary");
        };
    }

    private static String firstColumn(java.util.Map<String, Integer> header, String... names) {
        for (String name : names) if (header.containsKey(name)) return name;
        return null;
    }

    private static String runtimeVersion(JsonNode manifest) {
        JsonNode runtime = manifest.path("runtime");
        if (runtime.isTextual()) return runtime.asText();
        for (String path : List.of("/runtime/onnxruntime", "/runtime/name", "/runtime/version", "/onnxruntime")) {
            JsonNode value = manifest.at(path);
            if (value.isTextual()) return value.asText();
        }
        return "";
    }

    private static void verifyDeclaredModelHash(Path checksumsFile, String actual) throws IOException {
        if (!Files.isRegularFile(checksumsFile)) throw new IllegalStateException("checksums.json is required");
        JsonNode checksums = new ObjectMapper().readTree(checksumsFile.toFile());
        JsonNode value = checksums.path("model.onnx");
        if (value.isMissingNode()) value = checksums.path("files").path("model.onnx");
        if (value.isObject()) value = value.path("sha256");
        if (!value.isTextual() || !value.asText().equalsIgnoreCase(actual)) throw new IllegalStateException("model SHA-256 does not match checksums.json");
    }

    private static String sha256(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (var input = Files.newInputStream(path)) {
            byte[] buffer = new byte[64 * 1024];
            for (int count; (count = input.read(buffer)) >= 0;) digest.update(buffer, 0, count);
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private record Stats(double maxDelta, double totalDelta, long bitwiseMatches, long labelMismatches) { }
    private record ReplaySummary(long rows, double maxDelta, double totalDelta, long bitwiseMatches, long labelMismatches) { }
}
