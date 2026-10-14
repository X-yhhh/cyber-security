package com.xyh.cybersecurity.iam;

import com.fasterxml.jackson.databind.JsonNode;
import com.xyh.cybersecurity.guard.GuardStore;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.Map;
import java.util.function.Supplier;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/**
 * 身份写入与响应同事务，重放前仍须当前授权。复用现有幂等表，含口令请求使用域分离 HMAC，
 * 避免持久化原文或可离线猜解的无密钥摘要；响应必须由白名单投影构造。
 */
@Service
public class IamIdempotency {
    private final GuardStore store;
    private final TransactionTemplate tx;
    private final byte[] secret;
    public IamIdempotency(GuardStore store,PlatformTransactionManager manager,
                          @Value("${cyber.security.login-throttle.hmac-key}") String secret) {
        this.store=store;this.tx=new TransactionTemplate(manager);
        this.secret=secret.getBytes(StandardCharsets.UTF_8);
        if(this.secret.length<32) throw new IllegalArgumentException("IAM HMAC key must contain at least 32 bytes");
    }

    public JsonNode execute(String subject,String route,String key,JsonNode body,String revision,int status,
                            Runnable authorize,Supplier<JsonNode> work) {
        uuid(key);
        String scope=hash(object("iamSubject",subject,"route",route));
        String digest=fingerprint(object("body",body,"ifMatch",revision));
        try {
            return tx.execute(s -> {
                authorize.run();
                var old=store.one("guard_idempotency",map("request_scope",scope,"idempotency_key",key),true);
                if(old!=null) return replay(old,digest);
                var row=store.add("guard_idempotency",map("request_scope",scope,"idempotency_key",key,"request_sha256",digest));
                JsonNode result=work.get();
                store.update("guard_idempotency",number(row,"id"),map("response_json",canonical(result),"http_status",status));
                return result;
            });
        } catch(DuplicateKeyException e) {
            return tx.execute(s -> {
                authorize.run();
                var old=store.one("guard_idempotency",map("request_scope",scope,"idempotency_key",key),true);
                if(old==null) throw error(409,"IDEMPOTENCY_CONFLICT");
                return replay(old,digest);
            });
        }
    }

    private JsonNode replay(Map<String,Object> row,String digest) {
        if(!digest.equals(str(row,"request_sha256"))) throw error(409,"IDEMPOTENCY_CONFLICT");
        return json(row,"response_json");
    }

    private String fingerprint(JsonNode body) {
        try {
            Mac mac=Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret,"HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(("iam-idempotency-v1\n"+canonical(body)).getBytes(StandardCharsets.UTF_8)));
        } catch(java.security.GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-SHA-256 unavailable",e);
        }
    }
}
