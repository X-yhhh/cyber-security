package com.xyh.cybersecurity.guard;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

class MachineCertificateExpiryTest {
    private static final Instant NOT_AFTER = Instant.parse("2030-01-01T00:00:00Z");

    private static Path fixture() throws Exception {
        return Path.of(MachineCertificateExpiryTest.class.getResource("/guard/machine-certificate-fixture.pem").toURI());
    }

    @Test
    void reportsRemainingDaysAndWarnsWithinSevenDays() throws Exception {
        var expiry = new MachineCertificateExpiry(fixture().toString());
        var far = expiry.status(Instant.parse("2029-12-01T00:00:00Z"));
        assertEquals(NOT_AFTER, far.notAfter());
        assertEquals(31.0, far.daysRemaining());
        assertFalse(far.expiring());
        var near = expiry.status(Instant.parse("2029-12-26T00:00:00Z"));
        assertEquals(6.0, near.daysRemaining());
        assertTrue(near.expiring());
        var expired = expiry.status(Instant.parse("2030-01-02T00:00:00Z"));
        assertTrue(expired.daysRemaining() < 0 && expired.expiring());
    }

    @Test
    void acceptsFilePrefixAndReturnsUnknownOtherwise(@TempDir Path temp) throws Exception {
        assertEquals(NOT_AFTER, new MachineCertificateExpiry("file:" + fixture()).status(Instant.EPOCH).notAfter());
        Path broken = Files.writeString(temp.resolve("broken.pem"), "not a certificate");
        for (String location : new String[]{"", "classpath:server.pem", "relative/server.pem",
                temp.resolve("missing.pem").toString(), broken.toString()}) {
            assertNull(new MachineCertificateExpiry(location).status(Instant.EPOCH), location);
        }
        assertNull(new MachineCertificateExpiry(null).status(Instant.EPOCH));
    }
}
