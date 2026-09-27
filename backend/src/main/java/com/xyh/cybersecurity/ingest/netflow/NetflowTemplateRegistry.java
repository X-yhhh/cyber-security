package com.xyh.cybersecurity.ingest.netflow;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** NetFlow v9/IPFIX 模板生命周期；未知或过期模板绝不猜解数据报。 */
public final class NetflowTemplateRegistry {
    private final Duration ttl;
    private final Map<TemplateKey, Template> templates = new HashMap<>();

    public NetflowTemplateRegistry(Duration ttl) {
        if (ttl == null || ttl.isZero() || ttl.isNegative()) throw new IllegalArgumentException("template TTL 必须为正数");
        this.ttl = ttl;
    }

    public synchronized void register(Template template, Instant now) {
        Objects.requireNonNull(template, "template");
        templates.put(template.key(), template.withRefreshedAt(now == null ? Instant.now() : now));
    }

    public synchronized void remove(TemplateKey key) {
        templates.remove(key);
    }

    public synchronized Template require(TemplateKey key, Instant now) {
        Template template = templates.get(key);
        if (template == null) throw new TemplateException("NETFLOW_TEMPLATE_MISSING", key);
        Instant observedAt = now == null ? Instant.now() : now;
        if (!observedAt.isBefore(template.refreshedAt().plus(ttl))) {
            templates.remove(key);
            throw new TemplateException("NETFLOW_TEMPLATE_EXPIRED", key);
        }
        return template;
    }

    public synchronized int size() { return templates.size(); }

    public record Template(TemplateKey key, List<Field> fields, Instant refreshedAt) {
        public Template {
            if (key == null || fields == null || fields.isEmpty()) throw new IllegalArgumentException("模板字段不能为空");
            fields = List.copyOf(fields);
        }
        Template withRefreshedAt(Instant at) { return new Template(key, fields, at); }
    }

    public record TemplateKey(String protocolVersion, String exporterIdentity, long observationDomain, int templateId) {
        public TemplateKey {
            if (!("netflow-v9".equals(protocolVersion) || "ipfix".equals(protocolVersion))
                    || exporterIdentity == null || exporterIdentity.isBlank() || observationDomain < 0 || templateId < 0) {
                throw new IllegalArgumentException("模板身份不合法");
            }
        }
    }

    public record Field(long enterpriseId, long informationElementId, int length, String unit, String semanticName) {
        public Field {
            if (enterpriseId < 0 || informationElementId < 0 || length < 0 || semanticName == null || semanticName.isBlank()) {
                throw new IllegalArgumentException("模板字段不合法");
            }
        }
    }

    public static final class TemplateException extends RuntimeException {
        private final String code;
        private final TemplateKey key;
        TemplateException(String code, TemplateKey key) { super(code); this.code = code; this.key = key; }
        public String code() { return code; }
        public TemplateKey key() { return key; }
    }
}
