package com.xyh.cybersecurity.detection;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 仓库内登记的 4 条时间窗规则（{@code detection-rules/window-rules-v1.json}）在合成流上的行为：
 * 每类攻击特征突发检出一次，良性流量不告警。合成数据按路线 B §13.7 各场景的流形态构造，不含地址。
 */
class RuleReplayCliTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Instant T0 = Instant.parse("2026-09-30T10:00:00Z");

    @Test
    void registeredWindowRulesDetectEachBurstOnceAndIgnoreBenignTraffic(@TempDir Path dir) throws Exception {
        Path rulesPath = Path.of(getClass().getResource("/detection-rules/window-rules-v1.json").toURI());
        List<RuleReplayCli.Rule> rules = RuleReplayCli.readRules(rulesPath);
        assertThat(rules).extracting(RuleReplayCli.Rule::ruleKey)
                .containsExactly("tcp-port-scan", "ssh-login-failure-burst", "web-short-request-burst", "udp-inbound-burst");
        assertThat(rules).allSatisfy(rule -> assertThat(rule.condition().window()).isNotNull());

        List<RuleReplayCli.Record> records = new ArrayList<>();
        long[] id = {1};
        // 良性背景：每 30 秒一次 HTTP 短请求、一次 SSH 长会话片段、一次 UDP 问答，持续 1 小时。
        for (int s = 0; s < 3600; s += 30) {
            records.add(record(id[0]++, s, flow("tcp", "-", true, 0.02, 0.3, 6, 5)));
            records.add(record(id[0]++, s + 1, flow("tcp", "ssh", true, 0.02, 45, 40, 38)));
            records.add(record(id[0]++, s + 2, flow("udp", "-", false, 0, 0.01, 1, 1)));
        }
        // 端口扫描：95 个端口，握手失败（synack=0），25 秒内。
        for (int i = 0; i < 95; i++) records.add(record(id[0]++, 600 + i / 4, flow("tcp", "-", true, 0, 0, 1, 1)));
        // SSH 登录失败：20 次，每 3 秒一次，握手完整、约 0.2 秒。
        for (int i = 0; i < 20; i++) records.add(record(id[0]++, 1200 + i * 3, flow("tcp", "ssh", true, 0.02, 0.2, 12, 10)));
        // 路径探测：144 个请求，每个一条短连接。
        for (int i = 0; i < 144; i++) records.add(record(id[0]++, 1800 + i / 4, flow("tcp", "-", true, 0.02, 0.05, 6, 5)));
        // UDP 突发：单个源端口 1600 包，只形成一条流。
        records.add(record(id[0]++, 2424, flow("udp", "-", false, 0, 24, 1600, 0)));

        List<RuleReplayCli.Alert> alerts = RuleReplayCli.replay(rules, records);
        assertThat(alerts).extracting(alert -> alert.rule().ruleKey())
                .containsExactly("tcp-port-scan", "ssh-login-failure-burst", "web-short-request-burst", "udp-inbound-burst");

        Path scenarios = dir.resolve("scenarios.jsonl");
        Files.writeString(scenarios, String.join("\n",
                scenario(600, 624, "attack_feature", "port_scan", "ok"),
                scenario(1200, 1257, "attack_feature", "ssh_fail", "ok"),
                scenario(1800, 1836, "attack_feature", "web_probe", "ok"),
                scenario(2400, 2424, "attack_feature", "udp_burst", "ok"),
                scenario(3000, 3000, "attack_feature", "web_probe", "error:ValueError"),
                scenario(0, 3600, "benign", "http_short", "ok")) + "\n", StandardCharsets.UTF_8);
        Path recordsPath = dir.resolve("records.jsonl");
        StringBuilder lines = new StringBuilder();
        for (RuleReplayCli.Record record : records) {
            lines.append(JSON.writeValueAsString(Map.of("id", record.id(), "assetId", record.assetId(),
                    "eventTime", record.eventTime().toString(), "payload", record.payload()))).append('\n');
        }
        Files.writeString(recordsPath, lines, StandardCharsets.UTF_8);
        Path out = dir.resolve("out");
        RuleReplayCli.main(new String[] {rulesPath.toString(), recordsPath.toString(), scenarios.toString(), out.toString()});

        JsonNode report = JSON.readTree(out.resolve("rule-replay-report.json").toFile());
        for (JsonNode rule : report.path("rules")) {
            assertThat(rule.path("alertsOutsideAttackScenarios")).as(rule.path("ruleKey").asText()).isEmpty();
            // 执行失败的场景不作为检出目标。
            assertThat(rule.path("attackScenarios")).hasSize(4);
        }
        assertThat(Files.readAllLines(out.resolve("rule-replay-alerts.jsonl"))).hasSize(4)
                .noneMatch(line -> line.contains("outside_attack_scenarios"));
        assertThatThrownBy(() -> RuleReplayCli.main(new String[] {rulesPath.toString(), recordsPath.toString(), "-",
                out.toString()})).isInstanceOf(IllegalStateException.class);
    }

    private static RuleReplayCli.Record record(long id, int second, ObjectNode payload) {
        return new RuleReplayCli.Record(id, 3, T0.plusSeconds(second), payload);
    }

    private static ObjectNode flow(String proto, String service, boolean handshake, double rtt, double dur,
                                   int spkts, int dpkts) {
        ObjectNode payload = JSON.createObjectNode();
        ObjectNode features = payload.putObject("features");
        features.put("proto", proto).put("service", service).put("tcprtt", rtt).put("synack", rtt / 2)
                .put("dur", dur).put("spkts", spkts).put("dpkts", dpkts);
        payload.putObject("metadata").put("viewpoint", "responder").put("addressFamily", "ipv4")
                .put("handshakeSeen", handshake);
        return payload;
    }

    private static String scenario(int start, int end, String category, String name, String result) throws Exception {
        return JSON.writeValueAsString(Map.of("start", T0.plusSeconds(start).toString(),
                "end", T0.plusSeconds(end).toString(), "category", category, "scenario", name, "result", result));
    }
}
