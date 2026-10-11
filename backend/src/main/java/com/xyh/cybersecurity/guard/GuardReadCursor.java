package com.xyh.cybersecurity.guard;

import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;

import static com.xyh.cybersecurity.guard.GuardJson.*;

/** 进程生命周期内的认证加密游标：隐藏内部主键，拒绝篡改、换主体和换筛选。重启后须重读首屏。 */
@Component
public final class GuardReadCursor {
    record Position(long ceiling, long id, LocalDateTime time, LocalDateTime asOf) { }
    private final SecureRandom random = new SecureRandom();
    private final SecretKeySpec key;

    public GuardReadCursor() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        key = new SecretKeySpec(bytes, "AES");
    }

    String encode(Position position, String binding) {
        try {
            byte[] iv = new byte[12];
            random.nextBytes(iv);
            Cipher cipher = cipher(Cipher.ENCRYPT_MODE, iv, binding);
            byte[] plain = object("ceiling", position.ceiling, "id", position.id,
                    "time", position.time.toString(), "asOf", position.asOf.toString()).toString().getBytes(StandardCharsets.UTF_8);
            byte[] encrypted = cipher.doFinal(plain);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(
                    ByteBuffer.allocate(1 + iv.length + encrypted.length).put((byte) 1).put(iv).put(encrypted).array());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("无法生成查询游标", e);
        }
    }

    Position decode(String token, String binding) {
        try {
            if (token.length() > 2048 || !token.matches("[A-Za-z0-9_-]+")) throw new IllegalArgumentException();
            byte[] raw = Base64.getUrlDecoder().decode(token);
            if (raw.length < 30 || raw[0] != 1 || !Base64.getUrlEncoder().withoutPadding().encodeToString(raw).equals(token)) {
                throw new IllegalArgumentException();
            }
            ByteBuffer data = ByteBuffer.wrap(raw);
            data.get();
            byte[] iv = new byte[12];
            data.get(iv);
            byte[] encrypted = new byte[data.remaining()];
            data.get(encrypted);
            var value = JSON.readTree(cipher(Cipher.DECRYPT_MODE, iv, binding).doFinal(encrypted));
            long ceiling = value.path("ceiling").longValue(), id = value.path("id").longValue();
            if (id < 1 || ceiling < id) throw new IllegalArgumentException();
            return new Position(ceiling, id, LocalDateTime.parse(value.path("time").asText()),
                    LocalDateTime.parse(value.path("asOf").asText()));
        } catch (Exception e) {
            throw error(400, "INVALID_CURSOR");
        }
    }

    private Cipher cipher(int mode, byte[] iv, String binding) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, key, new GCMParameterSpec(128, iv));
        cipher.updateAAD(binding.getBytes(StandardCharsets.UTF_8));
        return cipher;
    }
}
