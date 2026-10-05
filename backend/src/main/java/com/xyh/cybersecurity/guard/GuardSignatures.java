package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/** 控制面 Ed25519 私钥由受控存储注入；无密钥不签命令，报告只信任预配公钥。 */
@Component
public class GuardSignatures {
    private final String keyId;private final Path keyFile;private final Path trustFile;
    public GuardSignatures(@Value("${cyber.guard.signing-key-id:}") String keyId,@Value("${cyber.guard.signing-key-file:}") String keyFile,
                           @Value("${cyber.guard.report-trust-file:}") String trustFile){this.keyId=keyId;this.keyFile=keyFile.isBlank()?null:Path.of(keyFile);this.trustFile=trustFile.isBlank()?null:Path.of(trustFile);}
    public boolean configured(){return keyFile!=null&&!keyId.isBlank();}
    public JsonNode sign(JsonNode payload){
        require(configured(),"SIGNING_KEY_UNAVAILABLE");
        try {var perms=Files.getPosixFilePermissions(keyFile);require(perms.stream().noneMatch(p->p.name().startsWith("GROUP_")||p.name().startsWith("OTHERS_")),"SIGNING_KEY_PERMISSIONS_INVALID");
            var key=KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(keyFile)));
            return sign(payload,keyId,key);
        }catch(java.io.IOException|GeneralSecurityException e){throw error(503,"SIGNING_KEY_UNAVAILABLE");}
    }
    public static JsonNode sign(JsonNode payload,String id,PrivateKey key)throws GeneralSecurityException {var signer=Signature.getInstance("Ed25519");signer.initSign(key);signer.update(canonical(payload).getBytes(StandardCharsets.UTF_8));return object("payload",payload,"keyId",id,"algorithm","Ed25519","signature",Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign()));}
    public JsonNode report(JsonNode envelope,String runner){
        fields(envelope,"payload keyId algorithm signature","");require(trustFile!=null&&runner.equals(text(envelope,"keyId"))&&"Ed25519".equals(text(envelope,"algorithm")),"REPORT_IDENTITY_UNTRUSTED");
        try{var trust=parse(Files.readString(trustFile));var encoded=trust.path(runner);require(encoded.isTextual(),"REPORT_IDENTITY_UNTRUSTED");
            var key=KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(encoded.asText())));
            var verifier=Signature.getInstance("Ed25519");verifier.initVerify(key);verifier.update(canonical(envelope.get("payload")).getBytes(StandardCharsets.UTF_8));require(verifier.verify(Base64.getUrlDecoder().decode(text(envelope,"signature"))),"SIGNATURE_INVALID");return envelope.get("payload");
        }catch(java.io.IOException|GeneralSecurityException|IllegalArgumentException e){throw error(422,"SIGNATURE_INVALID");}
    }
}
