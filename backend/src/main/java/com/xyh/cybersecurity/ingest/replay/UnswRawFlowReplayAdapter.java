package com.xyh.cybersecurity.ingest.replay;

import com.xyh.cybersecurity.ingest.feature.FeatureBuilder;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/**
 * UNSW-NB15 原始流 CSV（{@code UNSW-NB15_1..4.csv}，无表头 49 列）→ v4 {@link FeatureBuilder.FlowInput} 的回放映射
 * （路线 B §9.1 第 5 项）。
 *
 * <p>只读取规格 §2.1 训练端列所需的逐流值与流标识；TTL 类、Argus 内部字段、HTTP 字段以及 CSV 自带的
 * {@code service}、{@code ct_*} 一律不读取——{@code service} 与 {@code ct_*} 由 Feature Builder 按规格重算，
 * 保证回放走的是在线同一路径。标签只随记录返回供离线评估，不进入特征。</p>
 *
 * <p>与训练端 {@code register.load_d1_raw} / {@code feature_audit.recompute_ct} 同口径：类别去空白转小写；
 * 端口支持十进制与 {@code 0x} 十六进制，{@code -}、空白或无法解析记为缺失（{@code null}）；
 * {@code Stime}/{@code Ltime} 为秒级时间戳；导出序号取全局行号，作为排序键的最终 tie-break。</p>
 */
public final class UnswRawFlowReplayAdapter {
    /** UNSW-NB15 原始 CSV 的列数（{@code NUSW-NB15_features.csv} 定义 49 个字段）。 */
    public static final int COLUMNS = 49;
    private static final int SRCIP = 0, SPORT = 1, DSTIP = 2, DSPORT = 3, PROTO = 4, DUR = 6, SBYTES = 7, DBYTES = 8,
            SLOAD = 14, DLOAD = 15, SPKTS = 16, DPKTS = 17, SMEANSZ = 22, DMEANSZ = 23, STIME = 28, LTIME = 29,
            TCPRTT = 32, SYNACK = 33, ACKDAT = 34, LABEL = 48;

    /** 训练端窗口排序键 {@code (Ltime, Stime, 原始行号)}（规格 §3）。 */
    public static final Comparator<RawFlow> WINDOW_ORDER = Comparator
            .comparing((RawFlow row) -> row.flow().flowEndAt())
            .thenComparing(row -> row.flow().flowStartAt())
            .thenComparingLong(row -> row.flow().exportSeq());

    /**
     * 读取一段原始 CSV，按文件顺序返回。
     *
     * @param firstRowNumber 文件第一行在原始数据中的全局行号；用作导出序号，保证与训练端 tie-break 一致
     * @throws IllegalArgumentException 列数不符或必需数值无法解析（fail-closed，报告行号，不回显内容）
     */
    public List<RawFlow> read(Path csv, long firstRowNumber) throws IOException {
        if (csv == null || !Files.isRegularFile(csv)) throw new IOException("回放文件不存在");
        List<RawFlow> rows = new ArrayList<>();
        try (Reader reader = Files.newBufferedReader(csv, StandardCharsets.UTF_8)) {
            for (CSVRecord record : CSVFormat.DEFAULT.builder().setIgnoreEmptyLines(true).get().parse(reader)) {
                rows.add(toFlow(record, firstRowNumber + record.getRecordNumber() - 1));
            }
        }
        return List.copyOf(rows);
    }

    /** 按窗口排序键重排；Feature Builder 的迟到阈值为 0，必须按此顺序送入。 */
    public static List<RawFlow> inWindowOrder(List<RawFlow> rows) {
        return rows.stream().sorted(WINDOW_ORDER).toList();
    }

    private static RawFlow toFlow(CSVRecord record, long rowNumber) {
        if (record.size() != COLUMNS) throw invalid(rowNumber, "列数应为 " + COLUMNS);
        String proto = stripBom(record.get(PROTO)).trim().toLowerCase(Locale.ROOT);
        FeatureBuilder.FlowInput flow = new FeatureBuilder.FlowInput("unsw-row-" + rowNumber,
                Instant.ofEpochSecond(integer(record, STIME, rowNumber)), Instant.ofEpochSecond(integer(record, LTIME, rowNumber)),
                rowNumber, stripBom(record.get(SRCIP)).trim(), record.get(DSTIP).trim(), port(record.get(DSPORT)), proto,
                decimal(record, DUR, rowNumber), integer(record, SBYTES, rowNumber), integer(record, DBYTES, rowNumber),
                decimal(record, SLOAD, rowNumber), decimal(record, DLOAD, rowNumber), decimal(record, TCPRTT, rowNumber),
                decimal(record, ACKDAT, rowNumber), decimal(record, SYNACK, rowNumber), integer(record, SMEANSZ, rowNumber),
                integer(record, DMEANSZ, rowNumber), integer(record, SPKTS, rowNumber), integer(record, DPKTS, rowNumber));
        String label = record.get(LABEL).trim();
        return new RawFlow(flow, port(record.get(SPORT)), label.isEmpty() ? null : label);
    }

    /** 与训练端 {@code parse_port} 相同：十进制或 {@code 0x} 十六进制；{@code -}、空白、无法解析为缺失。 */
    static Integer port(String value) {
        String text = value == null ? "" : value.trim();
        if (text.isEmpty() || "-".equals(text)) return null;
        try {
            long parsed = text.toLowerCase(Locale.ROOT).startsWith("0x") ? Long.parseLong(text.substring(2), 16) : Long.parseLong(text);
            return parsed < 0 || parsed > Integer.MAX_VALUE ? null : (int) parsed;
        } catch (NumberFormatException exception) {
            return null;
        }
    }

    private static double decimal(CSVRecord record, int column, long row) {
        try {
            double value = Double.parseDouble(record.get(column).trim());
            if (!Double.isFinite(value)) throw invalid(row, "第 " + column + " 列不是有限数");
            return value;
        } catch (NumberFormatException exception) {
            throw invalid(row, "第 " + column + " 列不是数值");
        }
    }

    private static long integer(CSVRecord record, int column, long row) {
        try {
            return Long.parseLong(record.get(column).trim());
        } catch (NumberFormatException exception) {
            throw invalid(row, "第 " + column + " 列不是整数");
        }
    }

    private static String stripBom(String value) {
        return value != null && !value.isEmpty() && value.charAt(0) == '﻿' ? value.substring(1) : value;
    }

    private static IllegalArgumentException invalid(long row, String reason) {
        return new IllegalArgumentException("UNSW 原始行 " + row + " 无效：" + reason);
    }

    /**
     * @param flow          送入 Feature Builder 的流
     * @param initiatorPort 发起方端口，仅保留作审计对照，不参与 v4 特征
     * @param label         CSV {@code Label} 列（0/1），仅供离线评估
     */
    public record RawFlow(FeatureBuilder.FlowInput flow, Integer initiatorPort, String label) { }
}
