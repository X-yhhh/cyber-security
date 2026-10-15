package com.xyh.cybersecurity.ingest;

import com.xyh.cybersecurity.identity.IdentityMapper;
import com.xyh.cybersecurity.ingest.contract.FeatureContractRegistry;
import org.springframework.jdbc.core.JdbcTemplate;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;

/**
 * BE-11 保留链路的隔离库夹具。C1 删除人工登记端点后，直接建立机器身份与已批准配置，
 * 测试仍经过真实凭据过滤器、范围校验、接入与 outbox；不会恢复任何业务登记入口。
 * 仅允许本次测试的随机 schema，凭据只返回内存，不写日志。
 */
public final class LegacyMachineFixtures {
    private LegacyMachineFixtures() { }
    public record Credential(long id, String credential) { }

    /** 建立连接器的明确来源/资产配对；额外资产只有独立范围，用于验证未配对请求被拒绝。 */
    public static Credential connector(JdbcTemplate jdbc, IdentityMapper mapper, long source, long asset,
                                       long unpairedAsset) throws Exception {
        isolated(jdbc);
        String secret = secret();
        mapper.insertMachineClient("machine-test-connector", digest(secret), "[]");
        long client = mapper.findMachineClientId("machine-test-connector");
        mapper.insertClientScope(client, "data_source", Long.toString(source));
        mapper.insertClientScope(client, "asset", Long.toString(asset));
        mapper.insertClientScope(client, "asset", Long.toString(unpairedAsset));
        mapper.insertClientBinding(client, source, asset);
        mapper.grantMachineIngestPermission(client);
        return new Credential(client, "mch_" + client + "." + secret);
    }

    /** 建立旧传感器及其契约哈希绑定；配置格式仍由现存机器接入服务校验。 */
    public static Credential sensor(JdbcTemplate jdbc, IngestMapper mapper, FeatureContractRegistry contracts,
                                    String key, long asset, long source, String version) throws Exception {
        isolated(jdbc);
        var contract = contracts.find(version);
        if (contract == null) throw new IllegalArgumentException("测试契约不存在");
        mapper.insertSensor(new IngestMapper.SensorInsert(key, asset, "macos", "0.1.0", "{}", Instant.now()));
        long sensor = mapper.findSensorId(key);
        String secret = secret();
        String clientKey = "sensor-" + digest(key).substring(0, 32);
        mapper.insertSensorClient(new IngestMapper.SensorClientInsert(clientKey, sensor, digest(secret), "[]"));
        long client = mapper.findClientId(clientKey);
        mapper.updateCredentialRef(sensor, "api-client:" + client);
        mapper.insertClientAssetScope(client, asset);
        mapper.insertClientSourceScope(client, source);
        mapper.insertClientPair(client, source, asset);
        mapper.grantSensorPermissions(client);
        long approver = jdbc.queryForObject("SELECT MIN(id) FROM sys_user WHERE status='active'", Long.class);
        mapper.insertSensorConfig(new IngestMapper.SensorConfigInsert(sensor, "cfg-1", "{}", "{}", 60,
                contract.version(), contract.fileSha256(), "{}", approver));
        return new Credential(sensor, "mch_" + client + "." + secret);
    }

    private static void isolated(JdbcTemplate jdbc) {
        String schema = jdbc.queryForObject("SELECT DATABASE()", String.class);
        if (schema == null || !schema.matches("cyber_it_[a-z0-9_]+_[0-9a-f]{32}"))
            throw new IllegalStateException("机器夹具仅允许写入随机隔离测试库");
    }

    private static String secret() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String digest(String value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    }
}
