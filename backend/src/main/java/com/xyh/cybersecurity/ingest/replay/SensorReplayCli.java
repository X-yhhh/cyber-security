package com.xyh.cybersecurity.ingest.replay;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.xyh.cybersecurity.ingest.contract.FeatureContractRegistry;
import com.xyh.cybersecurity.ingest.feature.AddressPolicy;
import com.xyh.cybersecurity.ingest.feature.FeatureBuilder;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 以传感器身份回放 UNSW-NB15 原始 CSV（路线 B §11 R1 收口）：原始行 → Feature Builder（地址只在内存中用于窗口计数）
 * → 传感器批次接口 → outbox → M2 消费 → 推理 → 告警 → 事件。
 *
 * <p>时间整体平移到锚点前 120 秒，流间间隔不变（平移不影响窗口计数）。锚点、序号与幂等键前缀相同即可重放，
 * 服务端按幂等键返回原批次。只提交 READY 记录；窗口预热、排除与非法流只计数。传感器凭据从环境变量
 * {@code SENSOR_CREDENTIAL} 读取，只经 HTTPS 或本机回环地址发送，不打印。</p>
 */
public final class SensorReplayCli {
    static final String CONTRACT = "unsw-nb15-flow-v4";
    static final int MAX_BATCH = 500;
    /** 低于服务端 1 MiB 规范化批次上限，给批次头与转义留余量。 */
    static final int MAX_BATCH_BYTES = 900_000;
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Set<String> LOOPBACK = Set.of("localhost", "127.0.0.1", "[::1]", "::1");

    private SensorReplayCli() { }

    record Options(Path csv, long firstRow, long skip, int limit, URI baseUrl, long sensorId, long dataSourceId,
                   String configVersion, String mappingVersion, String sensorHost, int batchSize, long startSequence,
                   String keyPrefix, Instant anchor, boolean dryRun) { }

    record Built(List<ObjectNode> records, Map<FeatureBuilder.Status, Integer> counts, long shiftSeconds) { }

    public static void main(String[] args) throws Exception {
        Options o = parse(args);
        List<UnswRawFlowReplayAdapter.RawFlow> rows = new UnswRawFlowReplayAdapter().read(o.csv(), o.firstRow(), o.skip(), o.limit());
        FeatureBuilder builder = new FeatureBuilder(FeatureContractRegistry.fromClasspath().require(CONTRACT),
                AddressPolicy.unswReplay(o.sensorHost()));
        Built built = build(rows, builder, o.anchor());
        List<List<ObjectNode>> batches = chunk(built.records(), o.batchSize());
        Set<String> submitted = new java.util.HashSet<>();
        for (ObjectNode record : built.records()) submitted.add(record.path("recordKey").asText());
        // 标签只用于离线对照（不上报）：待提交记录中 CSV Label=1 的条数。
        long labeled = rows.stream().filter(row -> submitted.contains(row.flow().recordKey()) && "1".equals(row.label())).count();
        System.out.println("读取 " + rows.size() + " 行；构造结论 " + built.counts() + "；时间平移 " + built.shiftSeconds()
                + " 秒；锚点 " + o.anchor() + "；待提交 " + built.records().size() + " 条 / " + batches.size() + " 批；"
                + "其中 CSV 标签为攻击 " + labeled + " 条（仅供对照，不上报）");
        if (o.dryRun() || batches.isEmpty()) return;
        String credential = System.getenv("SENSOR_CREDENTIAL");
        if (credential == null || credential.isBlank()) throw new IllegalStateException("未设置 SENSOR_CREDENTIAL");
        HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
        URI endpoint = o.baseUrl().resolve("/api/v1/machine/sensors/" + o.sensorId() + "/flow-batches");
        long sequence = o.startSequence();
        for (List<ObjectNode> batch : batches) {
            ObjectNode body = JSON.createObjectNode().put("dataSourceId", o.dataSourceId())
                    .put("configVersion", o.configVersion()).put("sequence", sequence)
                    .put("observedAt", batch.getLast().path("observedAt").asText())
                    .put("sourceMappingVersion", o.mappingVersion()).put("featureContractVersion", CONTRACT);
            body.putArray("records").addAll(batch);
            HttpRequest request = HttpRequest.newBuilder(endpoint).timeout(Duration.ofSeconds(30))
                    .header("Authorization", "Machine " + credential).header("Idempotency-Key", o.keyPrefix() + ":" + sequence)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body.toString(), StandardCharsets.UTF_8)).build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            JsonNode envelope = JSON.readTree(response.body().isBlank() ? "{}" : response.body());
            if (response.statusCode() / 100 != 2) {
                // 只输出状态码与稳定错误码，不回显请求内容或凭据。
                throw new IllegalStateException("序号 " + sequence + " 提交失败：HTTP " + response.statusCode() + " "
                        + envelope.at("/error/code").asText("UNKNOWN"));
            }
            JsonNode data = envelope.path("data");
            System.out.println("序号 " + sequence + " → 批次 " + data.path("id").asLong() + "，接收 "
                    + data.path("acceptedCount").asLong() + "，拒绝 " + data.path("rejectedCount").asLong()
                    + (response.statusCode() == 201 ? "" : "（幂等重放）"));
            sequence++;
        }
    }

    /** 按窗口顺序构造；只保留 READY 记录，时间整体平移到锚点前 120 秒。 */
    static Built build(List<UnswRawFlowReplayAdapter.RawFlow> rows, FeatureBuilder builder, Instant anchor) {
        if (rows.isEmpty()) throw new IllegalArgumentException("回放范围内没有记录");
        Instant latest = rows.stream().map(row -> row.flow().flowEndAt()).max(Comparator.naturalOrder()).orElseThrow();
        long shift = Duration.between(latest, anchor.minusSeconds(120)).getSeconds();
        Map<FeatureBuilder.Status, Integer> counts = new EnumMap<>(FeatureBuilder.Status.class);
        List<ObjectNode> out = new ArrayList<>();
        for (UnswRawFlowReplayAdapter.RawFlow row : UnswRawFlowReplayAdapter.inWindowOrder(rows)) {
            FeatureBuilder.BuildResult result = builder.accept(row.flow());
            counts.merge(result.status(), 1, Integer::sum);
            if (!result.ready()) continue;
            FeatureBuilder.FlowInput flow = row.flow();
            Instant end = flow.flowEndAt().plusSeconds(shift);
            ObjectNode node = JSON.createObjectNode().put("recordKey", flow.recordKey())
                    .put("flowStartAt", flow.flowStartAt().plusSeconds(shift).toString()).put("flowEndAt", end.toString())
                    .put("observedAt", end.plusSeconds(1).toString()).put("directionBasis", "initiator_to_responder")
                    .put("viewpoint", result.viewpoint()).put("addressFamily", result.addressFamily())
                    .put("handshakeSeen", "tcp".equals(flow.proto()) && flow.synack() > 0 && flow.ackdat() > 0);
            node.set("features", result.features());
            out.add(node);
        }
        return new Built(List.copyOf(out), Map.copyOf(counts), shift);
    }

    /** 按条数与字节上限切批，批内顺序与窗口顺序一致。 */
    static List<List<ObjectNode>> chunk(List<ObjectNode> records, int size) {
        List<List<ObjectNode>> batches = new ArrayList<>();
        List<ObjectNode> current = new ArrayList<>();
        int bytes = 0;
        for (ObjectNode record : records) {
            int length = record.toString().getBytes(StandardCharsets.UTF_8).length + 1;
            if (!current.isEmpty() && (current.size() == size || bytes + length > MAX_BATCH_BYTES)) {
                batches.add(List.copyOf(current));
                current.clear();
                bytes = 0;
            }
            current.add(record);
            bytes += length;
        }
        if (!current.isEmpty()) batches.add(List.copyOf(current));
        return batches;
    }

    /** 凭据只经 HTTPS，或经明文 HTTP 发往本机回环地址。 */
    static URI requireSafeBaseUrl(String text) {
        URI uri = URI.create(text);
        String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase();
        if ("https".equals(uri.getScheme()) && !host.isEmpty()) return uri;
        if ("http".equals(uri.getScheme()) && LOOPBACK.contains(host)) return uri;
        throw new IllegalArgumentException("传感器凭据只能经 HTTPS 或本机回环地址发送");
    }

    static Options parse(String[] args) {
        Map<String, String> values = new HashMap<>();
        boolean dryRun = false;
        for (int i = 0; i < args.length; i++) {
            if ("--dry-run".equals(args[i])) { dryRun = true; continue; }
            if (!args[i].startsWith("--") || i + 1 >= args.length) throw new IllegalArgumentException("参数格式：--名称 值");
            values.put(args[i].substring(2), args[++i]);
        }
        String csv = values.get("csv");
        if (csv == null) throw new IllegalArgumentException("用法：--csv <UNSW-NB15_N.csv> [--first-row 0] [--skip 0] "
                + "[--limit 20000] [--base-url http://127.0.0.1:18080] --sensor-id N --data-source-id N "
                + "[--config-version cfg-1] [--mapping-version 1.0] [--sensor-host 149.171.126.3] [--batch-size 200] "
                + "[--start-sequence 1] [--key-prefix unsw-replay] [--anchor ISO-8601] [--dry-run]");
        int batchSize = Integer.parseInt(values.getOrDefault("batch-size", "200"));
        if (batchSize < 1 || batchSize > MAX_BATCH) throw new IllegalArgumentException("--batch-size 须为 1-" + MAX_BATCH);
        String prefix = values.getOrDefault("key-prefix", "unsw-replay");
        if (!prefix.matches("[A-Za-z0-9._-]{1,120}")) throw new IllegalArgumentException("--key-prefix 格式无效");
        Instant anchor = values.containsKey("anchor") ? Instant.parse(values.get("anchor")) : Instant.now();
        if (anchor.isAfter(Instant.now().plusSeconds(60))) throw new IllegalArgumentException("--anchor 不能晚于当前时间");
        return new Options(Path.of(csv), Long.parseLong(values.getOrDefault("first-row", "0")),
                Long.parseLong(values.getOrDefault("skip", "0")), Integer.parseInt(values.getOrDefault("limit", "20000")),
                requireSafeBaseUrl(values.getOrDefault("base-url", "http://127.0.0.1:18080")),
                dryRun ? Long.parseLong(values.getOrDefault("sensor-id", "0")) : Long.parseLong(values.get("sensor-id")),
                dryRun ? Long.parseLong(values.getOrDefault("data-source-id", "0")) : Long.parseLong(values.get("data-source-id")),
                values.getOrDefault("config-version", "cfg-1"), values.getOrDefault("mapping-version", "1.0"),
                values.getOrDefault("sensor-host", "149.171.126.3"), batchSize,
                Long.parseLong(values.getOrDefault("start-sequence", "1")), prefix, anchor, dryRun);
    }
}
