package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
import static com.xyh.cybersecurity.guard.GuardJson.*;
import static org.assertj.core.api.Assertions.*;

/** 直接调用 P5 验签代码，验证跨语言 JCS、Ed25519 和作用域摘要；不接触真实规则。 */
@EnabledIfEnvironmentVariable(named="P5_EXECUTOR_INTEROP",matches="true")
class GuardExecutorProtocolTest {
    @TempDir Path temporary;

    @ParameterizedTest
    @ValueSource(strings={"peer_service","peer_inbound"})
    void javaSignedCommandIsVerifiedAndIdenticallySignedByPython(String scope) throws Exception {
        KeyPair key=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        ObjectNode payload=(ObjectNode)GuardDomainTest.example("action-command").get("payload");
        payload.put("scope",scope);
        if(scope.equals("peer_inbound"))payload.putNull("servicePort").put("direction","inbound");
        Instant now=Instant.now().truncatedTo(ChronoUnit.MICROS);
        payload.put("issuedAt",now.toString()).put("applyBy",now.plusSeconds(5).toString())
                .put("blockUntil",now.plusSeconds(30).toString()).put("leaseExpiresAt",now.plusSeconds(30).toString());
        var command=GuardSignatures.sign(payload,"interop-control",key.getPrivate());
        var trust=object("interop-control",object("status","active","notBefore",now.minusSeconds(10).toString(),
                "notAfter",now.plusSeconds(120).toString(),"publicKeyDer",Base64.getEncoder().encodeToString(key.getPublic().getEncoded())));
        var vector=object("中文","命令","fraction",0.002,"large",1e22,"small",1e-7,"line","a\nb","boolean",true);
        Files.writeString(temporary.resolve("command.json"),canonical(command));
        Files.writeString(temporary.resolve("trust.json"),canonical(trust));
        Files.writeString(temporary.resolve("vector.json"),canonical(vector));
        Files.write(temporary.resolve("key.der"),key.getPrivate().getEncoded());
        Path root=Path.of("..").toAbsolutePath().normalize();
        var process=new ProcessBuilder("/bin/sh",root.resolve("executor/python.sh").toString(),
                "-m","executor.interop",temporary.toString()).directory(root.toFile()).redirectErrorStream(true).start();
        assertThat(process.waitFor(15,TimeUnit.SECONDS)).isTrue();
        String output=new String(process.getInputStream().readAllBytes(),java.nio.charset.StandardCharsets.UTF_8);
        assertThat(process.exitValue()).withFailMessage("P5 compatibility runner failed: %s",output).isZero();
        var result=parse(output);
        assertThat(result.path("signature")).isEqualTo(command.path("signature"));
        assertThat(result.path("scopeHash").asText()).isEqualTo(GuardReceipts.scopeHash(payload));
        assertThat(result.path("vectorHash").asText()).isEqualTo(hash(vector));
    }
}
