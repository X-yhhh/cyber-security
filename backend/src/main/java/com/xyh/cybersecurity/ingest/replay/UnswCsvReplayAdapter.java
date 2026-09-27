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
 * 读取 UNSW raw CSV 的确定性回放适配器。它只输出契约 raw fields，不把 label 或地址写入规范特征。
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
        required.addAll(contract.numericFields()); required.addAll(contract.categoricalFields());
        required.removeIf(headers::contains);
        if (!required.isEmpty()) throw new IllegalArgumentException("回放缺少契约字段: " + required);
    }

    private ObjectNode toFeatures(CSVRecord row) {
        ObjectNode features = mapper.createObjectNode();
        for (String field : contract.numericFields()) {
            String value = row.get(field);
            if (value == null || value.isBlank()) {
                if (contract.nullableNumericFields().contains(field)) features.putNull(field);
                else throw invalid(row, field, "missing");
                continue;
            }
            final double parsed;
            try { parsed = Double.parseDouble(value.trim()); }
            catch (NumberFormatException e) { throw invalid(row, field, "number"); }
            if (!Double.isFinite(parsed) || parsed < 0) throw invalid(row, field, "finite non-negative number");
            features.put(field, parsed);
        }
        for (String field : contract.categoricalFields()) {
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
