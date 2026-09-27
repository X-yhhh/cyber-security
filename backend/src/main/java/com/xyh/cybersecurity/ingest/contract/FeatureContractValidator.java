package com.xyh.cybersecurity.ingest.contract;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** 严格校验 v3.1 raw fields，任何缺失、非法数值或错误类型都 fail-closed。 */
@Component
public final class FeatureContractValidator {
    private final FeatureContractRegistry registry;

    public FeatureContractValidator(FeatureContractRegistry registry) {
        this.registry = registry;
    }

    public FeatureValidationResult validate(String version, JsonNode features) {
        FeatureContract contract = registry.find(version);
        if (contract == null) {
            return new FeatureValidationResult(false,
                    List.of(new FeatureValidationResult.Issue("FEATURE_CONTRACT_MISMATCH", "featureContractVersion",
                            FeatureContract.V3_1, version == null ? "null" : version)), List.of());
        }
        if (features == null || !features.isObject()) {
            return new FeatureValidationResult(false,
                    List.of(new FeatureValidationResult.Issue("REQUIRED_FIELD_MISSING", "features", "object", type(features))), List.of());
        }
        List<FeatureValidationResult.Issue> issues = new ArrayList<>();
        java.util.Set<String> allowedFields = new java.util.HashSet<>();
        allowedFields.addAll(contract.numericFields());
        allowedFields.addAll(contract.categoricalFields());
        features.fieldNames().forEachRemaining(field -> {
            if (!allowedFields.contains(field)) {
                issues.add(issue("FEATURE_CONTRACT_MISMATCH", field, "declared contract field", "unknown"));
            }
        });
        for (String field : contract.numericFields()) {
            JsonNode node = features.get(field);
            if (node == null) {
                issues.add(issue("REQUIRED_FIELD_MISSING", field, "finite non-negative number or explicit null", "missing"));
                continue;
            }
            if (node.isNull()) {
                if (!contract.nullableNumericFields().contains(field)) {
                    issues.add(issue("REQUIRED_FIELD_MISSING", field, "finite non-negative number", "null"));
                }
                continue;
            }
            if (!node.isNumber() || !Double.isFinite(node.asDouble()) || node.asDouble() < 0) {
                issues.add(issue("FEATURE_VALUE_INVALID", field, "finite non-negative number", type(node)));
            }
        }
        List<String> categoryDrift = new ArrayList<>();
        for (String field : contract.categoricalFields()) {
            JsonNode node = features.get(field);
            if (node == null || !node.isTextual() || node.textValue().isBlank() || node.textValue().length() > 64
                    || !node.textValue().equals(node.textValue().toLowerCase(java.util.Locale.ROOT))) {
                issues.add(issue("FEATURE_VALUE_INVALID", field, "lower-case non-empty string of at most 64 characters", type(node)));
            } else if (!KNOWN_VALUES.getOrDefault(field, Set.of()).contains(node.textValue())) {
                // OOV 由模型图按 manifest 处理，但必须作为质量遥测显式记录。
                // 仅记录字段级漂移，不把传感器提供的任意类别字符串写入质量记录。
                categoryDrift.add(field + "=out_of_vocabulary");
            }
        }
        return new FeatureValidationResult(issues.isEmpty(), List.copyOf(issues), List.copyOf(categoryDrift));
    }

    /** 与审批制品 preprocessing.json 一致的完整词表；OOV 仍交给 ONNX 编码为 -1，但必须留痕。 */
    private static final java.util.Map<String, Set<String>> KNOWN_VALUES = java.util.Map.of(
            "proto", Set.of("3pc", "a/n", "aes-sp3-d", "any", "argus", "aris", "arp", "ax.25", "bbn-rcc", "bna", "br-sat-mon", "cbt", "cftp", "chaos", "compaq-peer", "cphb", "cpnx", "crtp", "crudp", "dcn", "ddp", "ddx", "dgp", "egp", "eigrp", "emcon", "encap", "esp", "etherip", "fc", "fire", "ggp", "gmtp", "gre", "hmp", "i-nlsp", "iatp", "ib", "icmp", "idpr", "idpr-cmtp", "idrp", "ifmp", "igmp", "igp", "il", "ip", "ipcomp", "ipcv", "ipip", "iplt", "ipnip", "ippc", "ipv6", "ipv6-frag", "ipv6-no", "ipv6-opts", "ipv6-route", "ipx-n-ip", "irtp", "isis", "iso-ip", "iso-tp4", "kryptolan", "l2tp", "larp", "leaf-1", "leaf-2", "merit-inp", "mfe-nsp", "mhrp", "micp", "mobile", "mtp", "mux", "narp", "netblt", "nsfnet-igp", "nvp", "ospf", "pgm", "pim", "pipe", "pnni", "pri-enc", "prm", "ptp", "pup", "pvp", "qnx", "rdp", "rsvp", "rtp", "rvd", "sat-expak", "sat-mon", "sccopmce", "scps", "sctp", "sdrp", "secure-vmtp", "sep", "skip", "sm", "smp", "snp", "sprite-rpc", "sps", "srp", "st2", "stp", "sun-nd", "swipe", "tcf", "tcp", "tlsp", "tp++", "trunk-1", "trunk-2", "ttp", "udp", "udt", "unas", "uti", "vines", "visa", "vmtp", "vrrp", "wb-expak", "wb-mon", "wsn", "xnet", "xns-idp", "xtp", "zero"),
            "service", Set.of("-", "dhcp", "dns", "ftp", "ftp-data", "http", "irc", "pop3", "radius", "smtp", "snmp", "ssh", "ssl"));

    private static FeatureValidationResult.Issue issue(String code, String field, String expected, String actual) {
        return new FeatureValidationResult.Issue(code, field, expected, actual);
    }

    private static String type(JsonNode node) {
        if (node == null || node.isNull()) return "null";
        if (node.isNumber()) return "number";
        if (node.isTextual()) return "string";
        if (node.isBoolean()) return "boolean";
        return node.getNodeType().name().toLowerCase(java.util.Locale.ROOT);
    }
}
