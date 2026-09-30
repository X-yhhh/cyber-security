package com.xyh.cybersecurity.detection;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * 离线规则回放（开发路线 §4.2 出口条件）：用与在线告警生成相同的 {@link RuleCondition} 与 {@link WindowAggregation}，
 * 在已导出的流记录上求规则告警，并按场景日志统计每个攻击场景是否检出、良性时段逐条列出误报。
 *
 * <p>不连接数据库或网络。输入记录只含 {@code features}/{@code metadata} 与事件时间，不含地址或端口；
 * 输出写入独立目录，拒绝覆盖已有文件。</p>
 *
 * <pre>
 * 用法: RuleReplayCli &lt;rules.json&gt; &lt;records.jsonl&gt; &lt;scenarios.jsonl|-&gt; &lt;output-directory&gt; [preSeconds] [postSeconds]
 *   rules.json      [{"ruleKey","version","severity","condition"}...]
 *   records.jsonl   每行 {"id","assetId","eventTime","payload":{features,metadata}}
 *   scenarios.jsonl 每行 {"start","end","category":"benign|attack_feature","scenario","result"}；"-" 表示不按场景统计
 * </pre>
 */
public final class RuleReplayCli {
    private static final ObjectMapper JSON = new ObjectMapper();

    private RuleReplayCli() { }

    public static void main(String[] args) throws IOException {
        if (args.length < 4 || args.length > 6) {
            throw new IllegalArgumentException("用法: RuleReplayCli <rules.json> <records.jsonl> <scenarios.jsonl|-> <output-directory> [preSeconds] [postSeconds]");
        }
        Path output = Path.of(args[3]).toAbsolutePath().normalize();
        Path alertsPath = output.resolve("rule-replay-alerts.jsonl");
        Path reportPath = output.resolve("rule-replay-report.json");
        if (Files.exists(alertsPath) || Files.exists(reportPath)) throw new IllegalStateException("输出已存在，拒绝覆盖");
        long pre = args.length > 4 ? Long.parseLong(args[4]) : 60;
        long post = args.length > 5 ? Long.parseLong(args[5]) : 180;

        List<Rule> rules = readRules(Path.of(args[0]));
        List<Record> records = readRecords(Path.of(args[1]));
        List<Scenario> scenarios = "-".equals(args[2]) ? List.of() : readScenarios(Path.of(args[2]));
        List<Alert> alerts = replay(rules, records);
        ObjectNode report = report(rules, records, scenarios, alerts, pre, post);

        Files.createDirectories(output);
        try (BufferedWriter writer = Files.newBufferedWriter(alertsPath, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW)) {
            for (Alert alert : alerts) {
                ObjectNode line = JSON.createObjectNode().put("ruleKey", alert.rule().ruleKey())
                        .put("ruleVersion", alert.rule().version()).put("recordId", alert.recordId())
                        .put("assetId", alert.assetId()).put("eventTime", alert.eventTime().toString())
                        .put("aggregate", alert.aggregate()).put("records", alert.records())
                        .put("scenario", label(alert, scenarios, pre, post));
                writer.write(JSON.writeValueAsString(line));
                writer.newLine();
            }
        }
        Files.writeString(reportPath, JSON.writerWithDefaultPrettyPrinter().writeValueAsString(report) + "\n",
                StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
        System.out.println(JSON.writerWithDefaultPrettyPrinter().writeValueAsString(report.get("summary")));
    }

    record Rule(String ruleKey, String version, String severity, RuleCondition condition) { }

    record Record(long id, long assetId, Instant eventTime, JsonNode payload) { }

    record Scenario(Instant start, Instant end, String category, String scenario) { }

    record Alert(Rule rule, long recordId, long assetId, Instant eventTime, double aggregate, int records) { }

    /** 与在线路径同口径：按资产分组，窗口规则用 {@link WindowAggregation}，逐条规则每条命中记录一条告警。 */
    static List<Alert> replay(List<Rule> rules, List<Record> records) {
        Map<Long, List<Record>> byAsset = new TreeMap<>();
        for (Record record : records) byAsset.computeIfAbsent(record.assetId(), key -> new ArrayList<>()).add(record);
        List<Alert> alerts = new ArrayList<>();
        for (Rule rule : rules) {
            RuleCondition.Window window = rule.condition().window();
            for (Map.Entry<Long, List<Record>> entry : byAsset.entrySet()) {
                List<WindowAggregation.Point> points = new ArrayList<>();
                for (Record record : entry.getValue()) {
                    if (rule.condition().match(record.payload(), JSON) == null) continue;
                    if (window == null) {
                        alerts.add(new Alert(rule, record.id(), record.assetId(), record.eventTime(), 1, 1));
                        continue;
                    }
                    Double value = window.contribution(record.payload());
                    if (value != null) points.add(new WindowAggregation.Point(record.id(), record.eventTime(), value));
                }
                if (window == null) continue;
                for (WindowAggregation.Firing firing : WindowAggregation.evaluate(window, points, points, List.of())) {
                    alerts.add(new Alert(rule, firing.recordId(), entry.getKey(), firing.eventTime(), firing.aggregate(),
                            firing.records()));
                }
            }
        }
        alerts.sort(Comparator.comparing(Alert::eventTime).thenComparingLong(Alert::recordId));
        return alerts;
    }

    static ObjectNode report(List<Rule> rules, List<Record> records, List<Scenario> scenarios, List<Alert> alerts,
                             long pre, long post) {
        ObjectNode report = JSON.createObjectNode();
        ObjectNode summary = report.putObject("summary");
        summary.put("records", records.size()).put("alerts", alerts.size()).put("scenarioMarginPreSeconds", pre)
                .put("scenarioMarginPostSeconds", post);
        ArrayNode perRule = report.putArray("rules");
        for (Rule rule : rules) {
            List<Alert> own = alerts.stream().filter(alert -> alert.rule() == rule).toList();
            ObjectNode node = perRule.addObject().put("ruleKey", rule.ruleKey()).put("version", rule.version())
                    .put("severity", rule.severity()).put("alerts", own.size());
            if (rule.condition().window() != null) node.set("window", rule.condition().window().describe(JSON));
            ArrayNode attacks = node.putArray("attackScenarios");
            for (Scenario scenario : scenarios) {
                if (!"attack_feature".equals(scenario.category())) continue;
                long hits = own.stream().filter(alert -> within(alert.eventTime(), scenario, pre, post)).count();
                attacks.addObject().put("scenario", scenario.scenario()).put("start", scenario.start().toString())
                        .put("end", scenario.end().toString()).put("alerts", hits);
            }
            ArrayNode outside = node.putArray("alertsOutsideAttackScenarios");
            own.stream().filter(alert -> scenarios.stream().noneMatch(s -> "attack_feature".equals(s.category())
                    && within(alert.eventTime(), s, pre, post))).forEach(alert -> outside.addObject()
                    .put("recordId", alert.recordId()).put("assetId", alert.assetId())
                    .put("eventTime", alert.eventTime().toString()).put("aggregate", alert.aggregate())
                    .put("records", alert.records()));
            Map<String, Long> byScenario = new LinkedHashMap<>();
            for (Scenario scenario : scenarios) {
                if (!"attack_feature".equals(scenario.category())) continue;
                byScenario.merge(scenario.scenario(), own.stream()
                        .anyMatch(alert -> within(alert.eventTime(), scenario, pre, post)) ? 1L : 0L, Long::sum);
            }
            node.set("detectedRunsByScenario", JSON.valueToTree(byScenario));
        }
        return report;
    }

    private static String label(Alert alert, List<Scenario> scenarios, long pre, long post) {
        for (Scenario scenario : scenarios) {
            if ("attack_feature".equals(scenario.category()) && within(alert.eventTime(), scenario, pre, post)) {
                return scenario.scenario() + "@" + scenario.start();
            }
        }
        return "outside_attack_scenarios";
    }

    private static boolean within(Instant at, Scenario scenario, long pre, long post) {
        return !at.isBefore(scenario.start().minusSeconds(pre)) && !at.isAfter(scenario.end().plusSeconds(post));
    }

    static List<Rule> readRules(Path path) throws IOException {
        JsonNode root = JSON.readTree(path.toFile());
        if (!root.isArray() || root.isEmpty()) throw new IllegalArgumentException("rules.json 必须是非空数组");
        List<Rule> rules = new ArrayList<>();
        for (JsonNode node : root) {
            rules.add(new Rule(node.path("ruleKey").asText(), node.path("version").asText(),
                    node.path("severity").asText(), RuleCondition.parse(node.get("condition"))));
        }
        return List.copyOf(rules);
    }

    static List<Record> readRecords(Path path) throws IOException {
        List<Record> records = new ArrayList<>();
        try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank()) continue;
                JsonNode node = JSON.readTree(line);
                JsonNode payload = node.get("payload");
                if (payload == null || !payload.isObject()) throw new IllegalArgumentException("记录缺少 payload 对象");
                records.add(new Record(node.path("id").asLong(), node.path("assetId").asLong(),
                        Instant.parse(node.path("eventTime").asText()), payload));
            }
        }
        return List.copyOf(records);
    }

    static List<Scenario> readScenarios(Path path) throws IOException {
        List<Scenario> scenarios = new ArrayList<>();
        try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank()) continue;
                JsonNode node = JSON.readTree(line);
                // 执行失败的场景没有产生流量，不作为检出目标。
                if (!"ok".equals(node.path("result").asText())) continue;
                scenarios.add(new Scenario(Instant.parse(node.path("start").asText()), Instant.parse(node.path("end").asText()),
                        node.path("category").asText(), node.path("scenario").asText()));
            }
        }
        return List.copyOf(scenarios);
    }
}
