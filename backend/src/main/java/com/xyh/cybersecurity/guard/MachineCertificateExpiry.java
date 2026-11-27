package com.xyh.cybersecurity.guard;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;

/**
 * BE-30：读取后端当前使用的服务端证书（{@code server.ssl.certificate}）的到期时间，供运维汇总提示。
 * 本机机器证书整套同时签发与轮换，服务端证书到期即代表整套到期；读取失败或未启用 TLS 时返回未知，不影响业务。
 */
@Component
public class MachineCertificateExpiry {
    static final long WARN_DAYS = 7;
    private final String location;

    public MachineCertificateExpiry(@Value("${server.ssl.certificate:}") String location) {
        this.location = location == null ? "" : location.trim();
    }

    public record Status(Instant notAfter, double daysRemaining, boolean expiring) {}

    /** 未配置、非文件位置或无法解析时返回 null。 */
    public Status status(Instant now) {
        Path path = path(location);
        if (path == null) return null;
        try (InputStream in = Files.newInputStream(path)) {
            X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
            Instant notAfter = certificate.getNotAfter().toInstant();
            double days = Duration.between(now, notAfter).toSeconds() / 86400.0;
            return new Status(notAfter, Math.round(days * 100) / 100.0, days <= WARN_DAYS);
        } catch (Exception unreadable) {
            return null;
        }
    }

    static Path path(String location) {
        if (location.isEmpty() || location.startsWith("classpath:")) return null;
        String value = location.startsWith("file:") ? location.substring(5) : location;
        Path path = Path.of(value);
        return path.isAbsolute() && Files.isRegularFile(path) ? path : null;
    }
}
