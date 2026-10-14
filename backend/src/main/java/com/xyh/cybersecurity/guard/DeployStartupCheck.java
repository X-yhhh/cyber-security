package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.core.Ordered;
import org.springframework.core.PriorityOrdered;
import org.springframework.core.env.Environment;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/**
 * deploy 的启动前置门：只读检查运行用户、0700 目录、0600 文件及固定告警配置。
 * BeanFactoryPostProcessor 在数据源/Flyway/监听器实例化前执行；失败不改权限、不迁移、不启动。
 * 输出只含配置及公开配置材料的摘要，不把私钥、密码、HMAC 或文件内容写进审计。
 */
public final class DeployStartupCheck implements BeanFactoryPostProcessor, PriorityOrdered {
    private final Environment environment;
    private JsonNode proof;

    public DeployStartupCheck(Environment environment) { this.environment = environment; }
    @Override public int getOrder() { return Ordered.HIGHEST_PRECEDENCE; }

    @Override public void postProcessBeanFactory(ConfigurableListableBeanFactory factory) throws BeansException {
        proof = verify(environment, runtimeOwner());
    }

    public JsonNode proof() {
        if (proof == null) throw failure("PREFLIGHT_NOT_RUN");
        return proof.deepCopy();
    }

    /** 使用进程的实际用户而非可被 -Duser.name 覆盖的 JVM 属性。 */
    static UserPrincipal runtimeOwner() {
        try {
            String user = ProcessHandle.current().info().user().orElseThrow(() -> failure("OWNER_UNKNOWN"));
            return FileSystems.getDefault().getUserPrincipalLookupService().lookupPrincipalByName(user);
        } catch (IOException | UnsupportedOperationException e) { throw failure("OWNER_UNKNOWN"); }
    }

    static JsonNode verify(Environment env, UserPrincipal owner) {
        try {
            if (!Set.of(env.getActiveProfiles()).equals(Set.of("deploy"))) throw failure("PROFILE_CONFLICT");
            expect(env, "server.address", "127.0.0.1");
            expect(env, "server.ssl.enabled", "true");
            expect(env, "server.ssl.enabled-protocols", "TLSv1.3");
            expect(env, "server.servlet.session.cookie.secure", "true");
            expect(env, "cyber.guard.automation-enabled", "false");
            if (env.getProperty("cyber.guard.bootstrap-reports-enabled", Boolean.class, false)
                    || env.getProperty("cyber.security.local-admin-bootstrap.enabled", Boolean.class, false))
                throw failure("BOOTSTRAP_FORBIDDEN");
            if (setting(env, "cyber.security.login-throttle.hmac-key").length() < 32)
                throw failure("HMAC_REQUIRED");
            String database = setting(env, "spring.datasource.url");
            if (!database.startsWith("jdbc:mysql://127.0.0.1:")
                    || database.matches("(?is).*([?&](user|password)=|@).*")) throw failure("DATABASE_REFERENCE_INVALID");
            setting(env, "spring.datasource.username");
            setting(env, "spring.datasource.password");
            setting(env, "cyber.guard.signing-key-id");
            String vhost = setting(env, "cyber.ingest.rabbitmq.virtual-host");
            if (vhost.equals("/")) throw failure("DEDICATED_VHOST_REQUIRED");
            expect(env, "cyber.ingest.rabbitmq.host", "127.0.0.1");
            setting(env, "cyber.ingest.rabbitmq.username");
            setting(env, "cyber.ingest.rabbitmq.password");
            for (String property : List.of("cyber.guard.queue-prefix", "cyber.ingest.consumer.queue",
                    "cyber.ingest.consumer.dead-letter-queue", "cyber.ingest.consumer.retry-queue-prefix",
                    "cyber.ingest.rabbitmq.exchange", "cyber.ingest.rabbitmq.dead-letter-exchange"))
                if (!setting(env, property).matches("[A-Za-z0-9][A-Za-z0-9_.-]{0,180}"))
                    throw failure("QUEUE_REFERENCE_INVALID");

            var paths = new LinkedHashMap<String, Path>();
            for (var entry : Map.of("config", "cyber.guard.deploy.config-file", "signing", "cyber.guard.signing-key-file",
                    "trust", "cyber.guard.report-trust-file", "protection", "cyber.guard.protection-file",
                    "certificate", "server.ssl.certificate", "tlsKey", "server.ssl.certificate-private-key").entrySet()) {
                Path path = absolute(setting(env, entry.getValue()));
                verifyPath(path.getParent(), true, owner);
                verifyPath(path, false, owner);
                paths.put(entry.getKey(), path);
            }
            Path artifacts = absolute(setting(env, "cyber.guard.artifact-root"));
            Path ledger = absolute(setting(env, "cyber.guard.deploy.ledger-root"));
            verifyPath(artifacts, true, owner);
            verifyTree(ledger, owner);
            KeyFactory keys = KeyFactory.getInstance("Ed25519");
            keys.generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(paths.get("signing"))));
            JsonNode trust = parse(Files.readString(paths.get("trust")));
            if (!trust.isObject() || trust.isEmpty()) throw failure("TRUST_INVALID");
            for (JsonNode encoded : trust) {
                if (!encoded.isTextual()) throw failure("TRUST_INVALID");
                keys.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(encoded.asText())));
            }
            JsonNode protection = parse(Files.readString(paths.get("protection")));
            fields(protection, "protectedBudgetTargetIds protectedServicePorts", "");
            if (!protection.path("protectedBudgetTargetIds").isArray() || !protection.path("protectedServicePorts").isArray())
                throw failure("PROTECTION_INVALID");
            GuardEligibility.protectedPorts(protection.path("protectedServicePorts"));
            for (JsonNode target : protection.path("protectedBudgetTargetIds")) uuid(target.asText());
            var fileHashes = new TreeMap<String, String>();
            for (String name : List.of("config", "trust", "protection", "certificate"))
                fileHashes.put(name, sha(Files.readAllBytes(paths.get(name))));
            JsonNode effective = object("profile", "deploy", "automation", false, "address", "127.0.0.1",
                    "tls", "TLSv1.3", "secureCookie", true, "queuePrefix", setting(env, "cyber.guard.queue-prefix"),
                    "vhost", vhost, "relay", env.getProperty("cyber.ingest.outbox-relay.enabled", Boolean.class, false),
                    "consumer", env.getProperty("cyber.ingest.consumer.enabled", Boolean.class, false),
                    "configFiles", fileHashes);
            return object("configSha256", fileHashes.get("config"), "effectiveConfigSha256", hash(effective),
                    "files", fileHashes, "profile", "deploy", "automationEnabled", false);
        } catch (IllegalStateException e) { throw e; }
        catch (Exception e) { throw failure("MATERIAL_INVALID"); }
    }

    /** 账本可能包含重启恢复事实；全树逐项检查，不跟随符号链接、不自动修复。 */
    static void verifyTree(Path root, UserPrincipal owner) throws IOException {
        verifyPath(root, true, owner);
        try (var walk = Files.walk(root)) {
            for (Path path : (Iterable<Path>) walk::iterator)
                verifyPath(path, Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS), owner);
        }
    }

    static void verifyPath(Path path, boolean directory, UserPrincipal owner) throws IOException {
        if (path == null || Files.isSymbolicLink(path)
                || !(directory ? Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) : Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)))
            throw failure("PATH_MISSING_OR_UNSAFE");
        if (!Files.getOwner(path, LinkOption.NOFOLLOW_LINKS).equals(owner)) throw failure("OWNER_MISMATCH");
        String required = directory ? "rwx------" : "rw-------";
        if (!Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS).equals(PosixFilePermissions.fromString(required)))
            throw failure("PERMISSIONS_INVALID");
    }

    private static Path absolute(String value) {
        Path path = Path.of(value);
        if (!path.isAbsolute()) throw failure("ABSOLUTE_PATH_REQUIRED");
        return path.normalize();
    }
    private static String setting(Environment env, String property) {
        try {
            String value = env.getProperty(property);
            if (value == null || value.isBlank() || value.contains("${")) throw failure("SETTING_REQUIRED:" + property);
            return value;
        } catch (IllegalArgumentException e) { throw failure("SETTING_REQUIRED:" + property); }
    }
    private static void expect(Environment env, String property, String value) {
        if (!setting(env, property).equals(value)) throw failure("SETTING_FORBIDDEN:" + property);
    }
    private static IllegalStateException failure(String code) {
        return new IllegalStateException("部署启动自检失败：" + code);
    }
}
