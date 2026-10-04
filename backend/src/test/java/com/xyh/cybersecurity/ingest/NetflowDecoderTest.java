package com.xyh.cybersecurity.ingest;

import com.xyh.cybersecurity.ingest.netflow.NetflowDecoder;
import com.xyh.cybersecurity.ingest.netflow.NetflowTemplateRegistry;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class NetflowDecoderTest {
    @Test
    void ipfixTemplateMustBeLearnedBeforeDataAndUnknownFieldsStayOpaque() {
        var decoder = new NetflowDecoder(new NetflowTemplateRegistry(Duration.ofMinutes(1)),
                (protocol, enterprise, id) -> enterprise == 0 && id == 8 ? "source_bytes" : null);
        byte[] template = ByteBuffer.allocate(28).order(ByteOrder.BIG_ENDIAN)
                .putShort((short) 10).putShort((short) 28).putInt(1).putInt(0).putInt(1)
                .putShort((short) 2).putShort((short) 12).putShort((short) 256).putShort((short) 1)
                .putShort((short) 8).putShort((short) 4).array();
        var learned = decoder.decode(template, "ipfix", "exp", Instant.parse("2026-09-28T00:00:00Z"));
        assertThat(learned.learnedTemplates()).hasSize(1);
        byte[] data = ByteBuffer.allocate(24).order(ByteOrder.BIG_ENDIAN)
                .putShort((short) 10).putShort((short) 24).putInt(2).putInt(1).putInt(1)
                .putShort((short) 256).putShort((short) 8).putInt(42).array();
        var decoded = decoder.decode(data, "ipfix", "exp", Instant.parse("2026-09-28T00:00:01Z"));
        assertThat(decoded.records()).singleElement().extracting(map -> map.get("source_bytes")).isEqualTo(42L);
        assertThat(decoded.sequenceGap()).isFalse();
        byte[] gap = data.clone();
        java.nio.ByteBuffer.wrap(gap).order(ByteOrder.BIG_ENDIAN).putInt(8, 3);
        assertThat(decoder.decode(gap, "ipfix", "exp", Instant.parse("2026-09-28T00:00:02Z")).sequenceGap()).isTrue();
    }
}
