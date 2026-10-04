package com.xyh.cybersecurity.ingest;

import com.xyh.cybersecurity.ingest.netflow.NetflowTemplateRegistry;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class NetflowTemplateRegistryTest {
    @Test
    void refusesMissingAndExpiredTemplates() {
        var registry = new NetflowTemplateRegistry(Duration.ofSeconds(10));
        var key = new NetflowTemplateRegistry.TemplateKey("ipfix", "exporter-1", 1, 256);
        var template = new NetflowTemplateRegistry.Template(key,
                List.of(new NetflowTemplateRegistry.Field(0, 8, 4, "bytes", "source_bytes")), Instant.parse("2026-09-27T00:00:00Z"));
        assertThatThrownBy(() -> registry.require(key, template.refreshedAt())).isInstanceOf(NetflowTemplateRegistry.TemplateException.class);
        registry.register(template, template.refreshedAt());
        registry.require(key, template.refreshedAt().plusSeconds(1));
        assertThatThrownBy(() -> registry.require(key, template.refreshedAt().plusSeconds(11)))
                .isInstanceOf(NetflowTemplateRegistry.TemplateException.class)
                .hasMessage("NETFLOW_TEMPLATE_EXPIRED");
    }
}
