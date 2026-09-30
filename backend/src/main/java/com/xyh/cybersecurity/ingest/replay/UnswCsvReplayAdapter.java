package com.xyh.cybersecurity.ingest.replay;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.xyh.cybersecurity.ingest.contract.FeatureContract;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 读取「已是契约 raw fields」的带表头 CSV（如交付包 {@code replay-sample.csv}）的确定性回放适配器。
 * 只输出契约字段，不把 label 或地址写入规范特征。
 *
 * <p>此适配器按契约字段名逐列读取，适用于 v3.1 与 v4 的交付包样例；它不重算窗口或 {@code service}。
 * 从 UNSW-NB15 原始 CSV 回放 v4 时，必须使用 {@link UnswRawFlowReplayAdapter}，让 {@code ct_*} 与
 * {@code service} 走和在线相同的 Feature Builder 路径（路线 B §9.1 第 5 项）。</p>
 */
public final class UnswCsvReplayAdapter {
    private final ObjectMapper mapper;
    private final FeatureContract contract;

    public UnswCsvReplayAdapter(ObjectMapper mapper, FeatureContract contract) {
        this.mapper = mapper;
        this.contract = contract;
    }

    public List<ReplayRecord> read(Path csv) throws IOException {
        if (csv == null || !Files.isRegularFile(csv)) throw new IOException("回放文件不存在");
        try (Reader reader = Files.newBufferedReader(csv, StandardCharsets.UTF_8)) {
            CSVFormat format = CSVFormat.DEFAULT.builder().setHeader().setSkipHeaderRecord(true).setIgnoreEmptyLines(true).get();
            var parser = format.parse(reader);
            Set<String> headers = parser.getHeaderMap().keySet();
            requireHeaders(headers);
            List<ReplayRecord> rows = new ArrayList<>();
            for (CSVRecord row : parser) rows.add(new ReplayRecord(row.getRecordNumber(), toFeatures(row), optional(row, "label")));
            return List.copyOf(rows);
        }
    }

    private void requireHeaders(Set<String> headers) {
        Set<String> required = new HashSet<>();
        required.addAll(contract.numericFieldNames()); required.addAll(contract.categoricalFieldNames());
        required.removeIf(headers::contains);
        if (!required.isEmpty()) throw new IllegalArgumentException("回放缺少契约字段: " + required);
    }

    private ObjectNode toFeatures(CSVRecord row) {
        ObjectNode features = mapper.createObjectNode();
        for (FeatureContract.NumericField field : contract.numericFields()) {
            String value = row.get(field.name());
            if (value == null || value.isBlank()) {
                if (field.nullable()) features.putNull(field.name());
                else throw invalid(row, field.name(), "missing");
                continue;
            }
            final double parsed;
            try { parsed = Double.parseDouble(value.trim()); }
            catch (NumberFormatException e) { throw invalid(row, field.name(), "number"); }
            if (!Double.isFinite(parsed) || parsed < 0) throw invalid(row, field.name(), "finite non-negative number");
            features.put(field.name(), parsed);
        }
        for (String field : contract.categoricalFieldNames()) {
            String value = row.get(field);
            if (value == null || value.isBlank() || !value.equals(value.toLowerCase(java.util.Locale.ROOT))) throw invalid(row, field, "lower-case string");
            features.put(field, value);
        }
        return features;
    }

    private static String optional(CSVRecord row, String field) { return row.isMapped(field) ? row.get(field) : null; }
    private static IllegalArgumentException invalid(CSVRecord row, String field, String expected) {
        return new IllegalArgumentException("第 " + row.getRecordNumber() + " 行字段 " + field + " 无效，应为 " + expected);
    }

    public record ReplayRecord(long rowNumber, ObjectNode features, String label) { }
}
