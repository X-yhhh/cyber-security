package com.xyh.cybersecurity.ingest.contract;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** 契约加载与 fail-fast（路线 B §9.1 第 1 项、§9.2「契约加载」）。 */
class FeatureContractLoaderTest {
    private static final String V4 = "unsw-nb15-flow-v4.json";
    /** v3.1 资源文件发布后的字节哈希；任何原位修改都会使本测试失败（§3.1 约定 3）。 */
    private static final String V31_FILE_SHA256 = "2a21364cf5cf1b777d818a54fdf56e1ce8a1564cf89b07eaf70392cf6f7b202a";

    private final ObjectMapper mapper = new ObjectMapper();
    private final FeatureContractLoader loader = new FeatureContractLoader(mapper);

    @Test
    void registryLoadsV4AndV31AndReturnsNullForUnknownVersion() {
        FeatureContractRegistry registry = FeatureContractRegistry.fromClasspath();
        FeatureContract v4 = registry.find("unsw-nb15-flow-v4");
        assertThat(v4).isNotNull();
        assertThat(v4.numericFieldNames()).containsExactly("dur", "sbytes", "dbytes", "sload", "dload", "tcprtt",
                "ackdat", "synack", "smean", "dmean", "spkts", "dpkts", "ct_srv_src", "ct_srv_dst", "ct_dst_ltm",
                "ct_src_ltm", "ct_src_dport_ltm");
        assertThat(v4.categoricalFieldNames()).containsExactly("proto", "service");
        assertThat(v4.window().size()).isEqualTo(100);
        assertThat(v4.window().allowedLatenessSeconds()).isZero();
        assertThat(v4.numericFields()).allSatisfy(field -> {
            assertThat(field.unit()).isNotNull();
            assertThat(field.unitVerified()).isTrue();
            assertThat(field.nullable()).isFalse();
        });
        assertThat(registry.find("unsw-nb15-flow-v3.1")).isNotNull();
        assertThat(registry.find("future-contract")).isNull();
        assertThat(registry.find(null)).isNull();
    }

    @Test
    void v31ResourceBytesAreUnchanged() {
        FeatureContract v31 = FeatureContractRegistry.fromClasspath().require("unsw-nb15-flow-v3.1");
        assertThat(v31.fileSha256()).isEqualTo(V31_FILE_SHA256);
        assertThat(v31.onlineEnabled()).isFalse();
    }

    @Test
    void specDocumentHashMatchesContractAndManifest() throws Exception {
        FeatureContract v4 = FeatureContractRegistry.fromClasspath().require("unsw-nb15-flow-v4");
        Path spec = Path.of(System.getProperty("user.dir")).getParent().resolve(v4.specDocument());
        assertThat(spec).isRegularFile();
        assertThat(FeatureContractLoader.sha256(Files.readAllBytes(spec))).isEqualTo(v4.specSha256());
    }

    @Test
    void serviceRulesFollowSpecTable() {
        FeatureContract.ServiceRules rules = FeatureContractRegistry.fromClasspath().require("unsw-nb15-flow-v4").serviceRules();
        assertThat(rules.resolve("tcp", 443)).isEqualTo("ssl");
        assertThat(rules.resolve("udp", 443)).isEqualTo("-");
        assertThat(rules.resolve("udp", 53)).isEqualTo("dns");
        assertThat(rules.resolve("icmp", 0)).isEqualTo("-");
        assertThat(rules.resolve("tcp", null)).isEqualTo("-");
        assertThat(rules.resolve("tcp", 20)).isEqualTo("ftp-data");
    }

    @Test
    void validV4BytesLoad() throws Exception {
        assertThat(loader.load(V4, v4Bytes()).version()).isEqualTo("unsw-nb15-flow-v4");
    }

    @Test
    void duplicateFieldFailsFast() {
        assertRejected(root -> ((ArrayNode) root.get("numericFields")).add(root.get("numericFields").get(0).deepCopy()),
                "重复");
    }

    @Test
    void missingOrUnknownUnitFailsFast() {
        assertRejected(root -> ((ObjectNode) root.get("numericFields").get(0)).remove("unit"), "unit");
        assertRejected(root -> ((ObjectNode) root.get("numericFields").get(0)).put("unit", "millisecond"), "未知单位");
    }

    @Test
    void malformedSpecHashFailsFast() {
        assertRejected(root -> root.put("specSha256", "DBBA110432"), "specSha256");
        assertRejected(root -> root.remove("specSha256"), "specSha256");
    }

    @Test
    void unverifiedUnitCannotBeOnline() {
        assertRejected(root -> ((ObjectNode) root.get("numericFields").get(3)).put("unitVerified", false), "单位未核实");
    }

    @Test
    void unknownTopLevelKeyAndMismatchedFileNameFailFast() {
        assertRejected(root -> root.put("onlineEnabeld", true), "未知顶层键");
        assertThatThrownBy(() -> loader.load("unsw-nb15-flow-v5.json", v4Bytes()))
                .isInstanceOf(FeatureContractLoader.FeatureContractLoadException.class)
                .hasMessageContaining("文件名");
    }

    @Test
    void windowCountAboveWindowSizeAndUnknownRuleFailFast() {
        assertRejected(root -> ((ObjectNode) root.get("numericFields").get(12)).put("max", 101), "window.size");
        assertRejected(root -> ((ArrayNode) root.get("consistencyRules")).add("handshake_all_or_none"), "consistencyRules");
        assertRejected(root -> ((ObjectNode) root.get("window")).put("allowedLatenessSeconds", -1), "allowedLatenessSeconds");
    }

    @Test
    void duplicateVersionInRegistryFailsFast() throws Exception {
        FeatureContract v4 = loader.load(V4, v4Bytes());
        assertThatThrownBy(() -> FeatureContractRegistry.of(v4, v4))
                .isInstanceOf(FeatureContractLoader.FeatureContractLoadException.class)
                .hasMessageContaining("版本重复");
    }

    private void assertRejected(Consumer<ObjectNode> mutation, String reason) {
        ObjectNode root;
        try {
            root = (ObjectNode) mapper.readTree(v4Bytes());
        } catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
        mutation.accept(root);
        assertThatThrownBy(() -> loader.load(V4, mapper.writeValueAsBytes(root)))
                .isInstanceOf(FeatureContractLoader.FeatureContractLoadException.class)
                .hasMessageContaining(reason);
    }

    private static byte[] v4Bytes() throws Exception {
        try (InputStream input = FeatureContractLoaderTest.class.getResourceAsStream("/feature-contract/" + V4)) {
            return input.readAllBytes();
        }
    }
}
