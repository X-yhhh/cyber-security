package com.xyh.cybersecurity.guard;

import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPairGenerator;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.*;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.SimpleTransactionStatus;
import static com.xyh.cybersecurity.guard.GuardJson.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/** 用受控临时材料加载真实 deploy YAML，覆盖启动前拒绝与摘要审计；无服务和业务库副作用。 */
class DeployStartupCheckTest {
    @TempDir Path root;
    Map<String, String> variables;

    @BeforeEach void files() throws Exception {
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"));
        var pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        file("signing.der", pair.getPrivate().getEncoded());
        file("trust.json", canonical(object("fixture", Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()))).getBytes());
        file("protection.json", canonical(object("protectedBudgetTargetIds", List.of(), "protectedServicePorts", List.of(22))).getBytes());
        file("index.html", "<html>fixture</html>".getBytes());
        file("tls.pem", "context-only-certificate".getBytes());
        file("tls.key", "context-only-key".getBytes());
        file("deployment.properties", "# fixture contains no credentials\n".getBytes());
        for (String name : List.of("artifacts", "ledger")) {
            Files.createDirectory(root.resolve(name));
            Files.setPosixFilePermissions(root.resolve(name), PosixFilePermissions.fromString("rwx------"));
        }
        variables = new LinkedHashMap<>(Map.ofEntries(
                Map.entry("DEPLOY_WEB_ROOT", root.toString()),
                Map.entry("DEPLOY_CONFIG_FILE", root.resolve("deployment.properties").toString()),
                Map.entry("DEPLOY_DB_URL", "jdbc:mysql://127.0.0.1:3306/context_only"),
                Map.entry("DEPLOY_DB_USERNAME", "fixture"), Map.entry("DEPLOY_DB_PASSWORD", "fixture-value"),
                Map.entry("DEPLOY_LOGIN_THROTTLE_HMAC_KEY", "context-only-hmac-at-least-thirty-two-bytes"),
                Map.entry("DEPLOY_SIGNING_KEY_ID", "fixture"), Map.entry("DEPLOY_SIGNING_KEY_FILE", root.resolve("signing.der").toString()),
                Map.entry("DEPLOY_REPORT_TRUST_FILE", root.resolve("trust.json").toString()),
                Map.entry("DEPLOY_PROTECTION_FILE", root.resolve("protection.json").toString()),
                Map.entry("DEPLOY_TLS_CLIENT_CA", root.resolve("tls.pem").toString()),
                Map.entry("DEPLOY_TLS_CERTIFICATE", root.resolve("tls.pem").toString()),
                Map.entry("DEPLOY_TLS_KEY", root.resolve("tls.key").toString()),
                Map.entry("DEPLOY_ARTIFACT_ROOT", root.resolve("artifacts").toString()),
                Map.entry("DEPLOY_LEDGER_ROOT", root.resolve("ledger").toString()),
                Map.entry("DEPLOY_QUEUE_PREFIX", "q.guard.deploy.fixture"), Map.entry("DEPLOY_RABBITMQ_VHOST", "deploy-fixture"),
                Map.entry("DEPLOY_RABBITMQ_USERNAME", "fixture"), Map.entry("DEPLOY_RABBITMQ_PASSWORD", "fixture-value"),
                Map.entry("DEPLOY_RABBITMQ_EXCHANGE", "fixture.events"), Map.entry("DEPLOY_RABBITMQ_DEAD_LETTER_EXCHANGE", "fixture.dlx"),
                Map.entry("DEPLOY_INGEST_QUEUE", "fixture.ingest"), Map.entry("DEPLOY_INGEST_DEAD_LETTER_QUEUE", "fixture.ingest.dead"),
                Map.entry("DEPLOY_INGEST_RETRY_QUEUE_PREFIX", "fixture.ingest.retry.")));
    }

    void file(String name, byte[] data) throws Exception {
        Files.write(root.resolve(name), data);
        Files.setPosixFilePermissions(root.resolve(name), PosixFilePermissions.fromString("rw-------"));
    }
    ApplicationContextRunner context(String... overrides) {
        var settings = new ArrayList<String>();
        settings.add("spring.profiles.active=deploy");
        variables.forEach((key, value) -> settings.add(key + "=" + value));
        return new ApplicationContextRunner().withInitializer(new ConfigDataApplicationContextInitializer())
                .withUserConfiguration(DeployConfiguration.class, AuditFixture.class)
                .withPropertyValues(settings.toArray(String[]::new)).withPropertyValues(overrides);
    }
    @Configuration(proxyBeanMethods = false) static class AuditFixture {
        @Bean GuardStore store() { return mock(GuardStore.class); }
        @Bean PlatformTransactionManager transactions() {
            var manager = mock(PlatformTransactionManager.class);
            when(manager.getTransaction(any())).thenReturn(new SimpleTransactionStatus());
            return manager;
        }
    }

    @Test void deployLoadsWithAutomationClosedAndAuditsConfigDigest() throws Exception {
        String configHash = sha(Files.readAllBytes(root.resolve("deployment.properties")));
        context().run(ctx -> {
            assertThat(ctx).hasNotFailed();
            assertThat(ctx.getEnvironment().getProperty("cyber.guard.automation-enabled", Boolean.class)).isFalse();
            var proof = ctx.getBean(DeployStartupCheck.class).proof();
            assertThat(proof.path("configSha256").asText()).isEqualTo(configHash);
            verify(ctx.getBean(GuardStore.class)).audit(isNull(), eq("guard.deploy.startup"), eq(configHash), isNull(),
                    anyString(), argThat(p -> p.equals(proof) && !p.toString().contains("fixture-value")));
        });
    }
    @Test void missingRequiredVariableRefusesContext() {
        variables.remove("DEPLOY_QUEUE_PREFIX");
        context().run(ctx -> assertThat(ctx).hasFailed());
    }
    @ParameterizedTest @ValueSource(strings = {"signing.der", "trust.json", "protection.json", "tls.key", "deployment.properties", "ledger"})
    void broadPermissionsRefuseContext(String name) throws Exception {
        Files.setPosixFilePermissions(root.resolve(name), PosixFilePermissions.fromString(name.equals("ledger") ? "rwxr-x---" : "rw-r-----"));
        context().run(ctx -> assertThat(ctx).hasFailed());
    }
    @Test void missingFileRefusesContext() throws Exception {
        Files.delete(root.resolve("signing.der"));
        context().run(ctx -> assertThat(ctx).hasFailed());
    }
    @Test void symbolicLedgerEntryRefusesContext() throws Exception {
        Files.createSymbolicLink(root.resolve("ledger/state"), root.resolve("signing.der"));
        context().run(ctx -> assertThat(ctx).hasFailed());
    }
    @Test void foreignOwnerIsRejectedWithoutChangingOwnership() throws Exception {
        var foreign = FileSystems.getDefault().getUserPrincipalLookupService().lookupPrincipalByName("root");
        assertThatThrownBy(() -> DeployStartupCheck.verifyPath(root.resolve("signing.der"), false, foreign))
                .hasMessageContaining("OWNER_MISMATCH");
    }
    @ParameterizedTest @ValueSource(strings = {"cyber.guard.automation-enabled=true", "server.address=0.0.0.0",
            "server.ssl.enabled=false", "server.ssl.enabled-protocols=TLSv1.2", "server.servlet.session.cookie.secure=false",
            "cyber.guard.bootstrap-reports-enabled=true", "cyber.ingest.rabbitmq.virtual-host=/", "spring.profiles.active=deploy,lab"})
    void unsafeOverridesRefuseContext(String override) {
        context(override).run(ctx -> assertThat(ctx).hasFailed());
    }
    @Test void auditFailureRefusesReadyContext() {
        context().withUserConfiguration(FailingAuditFixture.class).run(ctx -> {
            assertThat(ctx).hasFailed();
            assertThat(ctx.getStartupFailure()).hasMessage("fixture audit unavailable");
        });
    }
    @Configuration(proxyBeanMethods = false) static class FailingAuditFixture {
        @Bean @Primary GuardStore failingStore() {
            var store = mock(GuardStore.class);
            doThrow(new IllegalStateException("fixture audit unavailable")).when(store).audit(any(), anyString(), anyString(), any(), anyString(), any());
            return store;
        }
    }
    @Test void defaultProfileDoesNotInstallDeployGate() {
        new ApplicationContextRunner().withUserConfiguration(DeployConfiguration.class)
                .withInitializer(new ConfigDataApplicationContextInitializer())
                .withPropertyValues("DB_URL=jdbc:mysql://127.0.0.1:3306/fixture", "DB_USERNAME=fixture", "DB_PASSWORD=fixture",
                        "LOGIN_THROTTLE_HMAC_KEY=context-only-hmac-at-least-thirty-two-bytes")
                .run(ctx -> { assertThat(ctx).hasNotFailed(); assertThat(ctx).doesNotHaveBean(DeployStartupCheck.class); });
    }
}
