package com.xyh.cybersecurity.ingest.feature;

import com.xyh.cybersecurity.ingest.contract.FeatureContract;
import com.xyh.cybersecurity.ingest.contract.FeatureContractRegistry;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** v4 Feature Builder 的 fail-closed 行为（路线 B §9.1 第 3 项、§9.2「fail-closed」）。地址均为 RFC 5737/3849 文档地址。 */
class FeatureBuilderTest {
    private static final String LOCAL = "192.0.2.10";
    private static final String LOCAL_V6 = "2001:db8::10";
    private static final Instant T0 = Instant.parse("2026-09-29T00:00:00Z");

    private final FeatureContract contract = V4Fixtures.contract();

    private FeatureBuilder sensorBuilder() {
        return new FeatureBuilder(contract, AddressPolicy.forSensor(Set.of(LOCAL, LOCAL_V6), List.of("192.0.2.0/24")));
    }

    @Test
    void windowSizeComesFromContractAndWarmingIsFailClosed() {
        FeatureBuilder builder = sensorBuilder();
        int size = contract.window().size();
        for (int i = 0; i < size - 1; i++) {
            FeatureBuilder.BuildResult result = builder.accept(inbound(i, "198.51.100.1", 80));
            assertThat(result.status()).isEqualTo(FeatureBuilder.Status.WINDOW_NOT_READY);
            assertThat(result.features()).isNull();
        }
        FeatureBuilder.BuildResult ready = builder.accept(inbound(size - 1, "198.51.100.1", 80));
        assertThat(ready.status()).isEqualTo(FeatureBuilder.Status.READY);
        assertThat(ready.windowSize()).isEqualTo(size);
        assertThat(ready.features().get("ct_dst_ltm").asInt()).isEqualTo(size);
        assertThat(ready.features().get("ct_src_ltm").asInt()).isEqualTo(size);
        assertThat(ready.features().get("service").asText()).isEqualTo("http");
        // 输出字段集与顺序严格等于契约。
        List<String> names = new java.util.ArrayList<>();
        ready.features().fieldNames().forEachRemaining(names::add);
        List<String> declared = new java.util.ArrayList<>(contract.numericFieldNames());
        declared.addAll(contract.categoricalFieldNames());
        assertThat(names).containsExactlyElementsOf(declared);
    }

    @Test
    void countsIncludeCurrentFlowAndUseInitiatorResponderAndResponderPort() {
        FeatureBuilder builder = sensorBuilder();
        for (int i = 0; i < 99; i++) builder.accept(inbound(i, i % 2 == 0 ? "198.51.100.1" : "198.51.100.2", i < 60 ? 80 : 22));
        FeatureBuilder.BuildResult result = builder.accept(inbound(99, "198.51.100.1", 22));
        assertThat(result.ready()).isTrue();
        // 源 198.51.100.1：i 为偶数的 50 条 + 当前流。
        assertThat(result.features().get("ct_src_ltm").asInt()).isEqualTo(51);
        // 源相同且响应方端口 22：i∈[60,98] 且为偶数的 20 条 + 当前流。
        assertThat(result.features().get("ct_src_dport_ltm").asInt()).isEqualTo(21);
        // service=ssh 且目的相同：i∈[60,98] 的 39 条 + 当前流。
        assertThat(result.features().get("ct_srv_dst").asInt()).isEqualTo(40);
        assertThat(result.features().get("ct_srv_src").asInt()).isEqualTo(21);
    }

    @Test
    void lateAndDuplicateRecordsAreRejectedAndDoNotEnterWindow() {
        FeatureBuilder builder = sensorBuilder();
        builder.accept(inbound(10, "198.51.100.1", 80));
        FeatureBuilder.BuildResult late = builder.accept(inbound(5, "198.51.100.1", 80));
        assertThat(late.status()).isEqualTo(FeatureBuilder.Status.REJECTED);
        assertThat(late.reason()).isEqualTo("late_event");
        FeatureBuilder.BuildResult duplicate = builder.accept(inbound(10, "198.51.100.1", 80));
        assertThat(duplicate.reason()).isEqualTo("duplicate_record");
        assertThat(builder.windowSnapshot("ipv4")).hasSize(1);
    }

    @Test
    void excludedFlowsNeverEnterWindow() {
        FeatureBuilder builder = sensorBuilder();
        assertThat(reason(builder, "198.51.100.1", "224.0.0.251")).isEqualTo("multicast_destination");
        assertThat(reason(builder, LOCAL, "255.255.255.255")).isEqualTo("broadcast_destination");
        assertThat(reason(builder, LOCAL, "192.0.2.255")).isEqualTo("broadcast_destination");
        assertThat(reason(builder, LOCAL, "127.0.0.1")).isEqualTo("loopback_destination");
        assertThat(reason(builder, LOCAL, "0.0.0.0")).isEqualTo("unspecified_destination");
        assertThat(reason(builder, "198.51.100.1", "203.0.113.5")).isEqualTo("no_local_endpoint");
        assertThat(reason(builder, "not-an-ip", LOCAL)).isEqualTo("invalid_address");
        assertThat(reason(builder, "198.51.100.1", LOCAL_V6)).isEqualTo("invalid_address");
        assertThat(builder.windowSnapshot("ipv4")).isEmpty();
        // 传感器口径下非本机子网的 .255 不是定向广播；UNSW 回放口径才按末字节 255 排除。
        assertThat(AddressPolicy.forSensor(Set.of(LOCAL), List.of("192.0.2.0/24")).classify(LOCAL, "198.51.100.255").exclusion())
                .isEmpty();
        assertThat(AddressPolicy.unswReplay(LOCAL).classify(LOCAL, "198.51.100.255").exclusion()).contains("broadcast_destination");
    }

    @Test
    void outboundFlowsGetInitiatorViewpointAndBothLocalCountsAsResponder() {
        FeatureBuilder builder = sensorBuilder();
        FeatureBuilder.BuildResult outbound = builder.accept(flow(0, LOCAL, "198.51.100.1", 443, "tcp", 1.0, 3, 2));
        assertThat(outbound.viewpoint()).isEqualTo("initiator");
        FeatureBuilder.BuildResult selfLoop = builder.accept(flow(1, LOCAL, LOCAL, 80, "tcp", 1.0, 3, 2));
        assertThat(selfLoop.viewpoint()).isEqualTo("responder");
    }

    @Test
    void invalidValuesAreRejectedButStillOccupyWindow() {
        FeatureBuilder builder = sensorBuilder();
        FeatureBuilder.BuildResult zeroPackets = builder.accept(flow(0, "198.51.100.1", LOCAL, 80, "tcp", 1.0, 0, 2));
        assertThat(zeroPackets.status()).isEqualTo(FeatureBuilder.Status.REJECTED);
        assertThat(zeroPackets.reason()).isEqualTo("value_invalid");
        FeatureBuilder.BuildResult udpHandshake = builder.accept(flowWithHandshake(1, "udp", 53));
        assertThat(udpHandshake.reason()).isEqualTo("handshake_on_non_tcp");
        FeatureBuilder.BuildResult nan = builder.accept(flow(2, "198.51.100.1", LOCAL, 80, "tcp", Double.NaN, 3, 2));
        assertThat(nan.reason()).isEqualTo("value_invalid");
        // 与训练端 recompute_ct 一致：窗口成员资格只看流元数据。
        assertThat(builder.windowSnapshot("ipv4")).hasSize(3);
        FeatureBuilder.BuildResult badTime = builder.accept(new FeatureBuilder.FlowInput("bad-time", T0.plusSeconds(10), T0,
                3, "198.51.100.1", LOCAL, 80, "tcp", 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1));
        assertThat(badTime.reason()).isEqualTo("flow_time_invalid");
        assertThat(builder.windowSnapshot("ipv4")).hasSize(3);
    }

    @Test
    void addressFamiliesUseSeparateWindows() {
        FeatureBuilder builder = sensorBuilder();
        for (int i = 0; i < 50; i++) builder.accept(inbound(i, "198.51.100.1", 80));
        FeatureBuilder.BuildResult v6 = builder.accept(flow(50, "2001:db8::1", LOCAL_V6, 443, "tcp", 1.0, 3, 2));
        assertThat(v6.addressFamily()).isEqualTo("ipv6");
        assertThat(v6.windowSize()).isEqualTo(1);
        assertThat(builder.windowSnapshot("ipv4")).hasSize(50);
    }

    @Test
    void boundaryRulesZeroLoadWithoutPacketsOrDuration() {
        FeatureBuilder builder = sensorBuilder();
        for (int i = 0; i < 99; i++) builder.accept(inbound(i, "198.51.100.1", 80));
        FeatureBuilder.BuildResult single = builder.accept(flow(99, "198.51.100.1", LOCAL, 80, "tcp", 0.0, 1, 0));
        assertThat(single.ready()).isTrue();
        assertThat(single.features().get("sload").asDouble()).isZero();
        assertThat(single.features().get("dload").asDouble()).isZero();
        assertThat(single.features().get("dmean").asLong()).isZero();
    }

    @Test
    void contractWithoutWindowIsRejected() {
        FeatureContract v31 = FeatureContractRegistry.fromClasspath().require("unsw-nb15-flow-v3.1");
        assertThatThrownBy(() -> new FeatureBuilder(v31, AddressPolicy.unswReplay(LOCAL)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static String reason(FeatureBuilder builder, String src, String dst) {
        FeatureBuilder.BuildResult result = builder.accept(flow(0, src, dst, 80, "tcp", 1.0, 3, 2));
        assertThat(result.status()).isEqualTo(FeatureBuilder.Status.EXCLUDED);
        return result.reason();
    }

    private static FeatureBuilder.FlowInput inbound(long seq, String src, int port) {
        return flow(seq, src, LOCAL, port, "tcp", 1.0, 3, 2);
    }

    /** 一条逐流值自洽的流：spkts/dpkts 由参数给出，其余按规格边界取值。 */
    private static FeatureBuilder.FlowInput flow(long seq, String src, String dst, int port, String proto, double dur,
                                                 long spkts, long dpkts) {
        long dbytes = dpkts == 0 ? 0 : 200;
        return new FeatureBuilder.FlowInput("flow-" + seq, T0.plusSeconds(seq), T0.plusSeconds(seq), seq, src, dst, port,
                proto, dur, 100, dbytes, 400.0, dpkts == 0 ? 0 : 800.0, 0, 0, 0, spkts == 0 ? 0 : 50,
                dpkts == 0 ? 0 : 100, spkts, dpkts);
    }

    private static FeatureBuilder.FlowInput flowWithHandshake(long seq, String proto, int port) {
        return new FeatureBuilder.FlowInput("flow-" + seq, T0.plusSeconds(seq), T0.plusSeconds(seq), seq, "198.51.100.1",
                LOCAL, port, proto, 1.0, 100, 200, 400, 800, 0.0003, 0.0001, 0.0002, 50, 100, 2, 2);
    }
}
