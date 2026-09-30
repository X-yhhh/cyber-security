package com.xyh.cybersecurity.ingest;

import com.fasterxml.jackson.databind.JsonNode;
import com.xyh.cybersecurity.audit.AuditMapper;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import com.xyh.cybersecurity.ingest.contract.FeatureContract;
import com.xyh.cybersecurity.ingest.contract.FeatureContractRegistry;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.regex.Pattern;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/**
 * 传感器登记之后的生命周期（开发路线 §4.1）：详情、资料修改、配置版本起草 → 他人审批 → 启用、
 * 机器凭据轮换与吊销、下线。
 *
 * <p>权限：读取需 {@code sensor.read}，变更需 {@code sensor.manage}，审批配置需 {@code sensor.config.approve}，
 * 均在传感器所属资产范围内二次校验；范围外返回 404。配置审批要求起草人 ≠ 审批人（服务层 403 + V17 CHECK）。
 * 所有迁移写追加审计并关联资产范围。凭据只在签发/轮换时返回一次，数据库只保存 SHA-256 验证值。</p>
 *
 * <p>失败边界：已下线（{@code revoked}）的传感器不可再变更；吊销后的凭据不可轮换（须重新登记传感器）；
 * 配置绑定的契约文件哈希与当前注册表不一致时拒绝审批或启用（409 {@code CONFIG_VERSION_STALE}）。</p>
 */
@Service
public class SensorLifecycleService {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Pattern VERSION = Pattern.compile("^[A-Za-z0-9._-]{1,64}$");
    private static final Pattern PLATFORM = Pattern.compile("^[A-Za-z0-9._-]{1,32}$");

    private final SensorAdminMapper mapper;
    private final SensorManagementService registration;
    private final AuditMapper auditMapper;
    private final FeatureContractRegistry contracts;

    public SensorLifecycleService(SensorAdminMapper mapper, SensorManagementService registration,
                                  AuditMapper auditMapper, FeatureContractRegistry contracts) {
        this.mapper = mapper;
        this.registration = registration;
        this.auditMapper = auditMapper;
        this.contracts = contracts;
    }

    /** 传感器详情：身份、配置版本历史与凭据状态（不含任何凭据值或摘要）。 */
    public SensorDetail detail(long sensorId, IdentityPrincipal actor) {
        SensorAdminMapper.SensorRow sensor = mapper.findSensor(sensorId);
        if (sensor == null || !mapper.hasAssetPermission(actor.id(), sensor.assetId(), "sensor.read")) {
            throw ApiRequestException.notFound();
        }
        SensorAdminMapper.ClientRow client = mapper.findClient(sensorId);
        return new SensorDetail(sensor, mapper.listConfigs(sensorId), client == null ? null : CredentialStatus.from(client));
    }

    @Transactional
    public SensorDetail updatePlatform(long sensorId, String platform, IdentityPrincipal actor, HttpServletRequest request) {
        SensorAdminMapper.SensorRow sensor = lockManageable(sensorId, actor);
        if (platform == null || !PLATFORM.matcher(platform).matches()) throw ApiRequestException.badRequest("平台标识无效");
        if (mapper.updatePlatform(sensorId, platform) != 1) throw sensorConflict("传感器已下线，不能修改");
        audit(request, actor.id(), "sensor.updated", "sensor_agent", sensorId, sensor.assetId(), "platform updated");
        return detail(sensorId, actor);
    }

    /** 起草配置新版本（{@code pending}）；契约版本须已注册，契约文件哈希由服务端按注册表写入。 */
    @Transactional
    public SensorAdminMapper.ConfigRow draftConfig(long sensorId, ConfigDraft draft, IdentityPrincipal actor,
                                                   HttpServletRequest request) {
        SensorAdminMapper.SensorRow sensor = lockManageable(sensorId, actor);
        requireNotRevoked(sensor);
        String reason = reason(draft.reason());
        if (draft.configVersion() == null || !VERSION.matcher(draft.configVersion()).matches()
                || draft.flowWindowSeconds() < 1 || draft.flowWindowSeconds() > 3600) {
            throw ApiRequestException.badRequest("配置版本或流时间窗无效");
        }
        FeatureContract contract = draft.featureContractVersion() == null ? null : contracts.find(draft.featureContractVersion());
        if (contract == null) {
            throw new ApiRequestException(HttpStatus.valueOf(422), "FEATURE_CONTRACT_MISMATCH", "特征契约版本未登记");
        }
        try {
            mapper.insertConfig(new SensorAdminMapper.ConfigInsert(sensorId, draft.configVersion(),
                    registration.json(draft.interfaceScope()), registration.json(draft.filterPolicy()),
                    draft.flowWindowSeconds(), contract.version(), contract.fileSha256(),
                    registration.json(draft.samplingPolicy()), actor.id(), reason));
        } catch (org.springframework.dao.DuplicateKeyException exception) {
            throw ApiRequestException.conflict("该配置版本已存在");
        }
        long configId = mapper.findConfigId(sensorId, draft.configVersion());
        audit(request, actor.id(), "sensor.config.drafted", "sensor_config", configId, sensor.assetId(), reason);
        return mapper.lockConfig(sensorId, configId);
    }

    /**
     * 他人审批配置版本：{@code approve} 使 {@code pending → approved}（尚未生效，须显式启用），
     * {@code reject} 使 {@code pending → rejected}。起草人本人 403；缺起草人的历史配置 409。
     */
    @Transactional
    public SensorAdminMapper.ConfigRow decideConfig(long sensorId, long configId, String decision, String reasonText,
                                                    IdentityPrincipal actor, HttpServletRequest request) {
        if (!"approve".equals(decision) && !"reject".equals(decision)) throw ApiRequestException.badRequest("审批决定无效");
        String reason = reason(reasonText);
        SensorAdminMapper.SensorRow sensor = mapper.lockSensor(sensorId);
        if (sensor == null || !mapper.hasAssetPermission(actor.id(), sensor.assetId(), "sensor.config.approve")) {
            throw ApiRequestException.notFound();
        }
        requireNotRevoked(sensor);
        SensorAdminMapper.ConfigRow config = mapper.lockConfig(sensorId, configId);
        if (config == null) throw ApiRequestException.notFound();
        if (config.requestedBy() == null) {
            throw new ApiRequestException(HttpStatus.CONFLICT, "CONFIG_REQUESTER_UNKNOWN", "配置缺少起草人记录，不能经接口审批");
        }
        if (config.requestedBy() == actor.id()) throw new AccessDeniedException("Config requester cannot decide");
        if (!"pending".equals(config.status())) throw configConflict("配置版本已被处理");
        if ("approve".equals(decision)) {
            requireCurrentContract(config);
            if (mapper.approveConfig(configId, actor.id(), reason) != 1) throw configConflict("配置状态已被其他请求更新");
        } else if (mapper.rejectConfig(configId, actor.id(), reason) != 1) {
            throw configConflict("配置状态已被其他请求更新");
        }
        audit(request, actor.id(), "approve".equals(decision) ? "sensor.config.approved" : "sensor.config.rejected",
                "sensor_config", configId, sensor.assetId(), reason);
        return mapper.lockConfig(sensorId, configId);
    }

    /**
     * 启用已批准配置：{@code approved → active}，同事务退役该传感器其他 active 版本。启用后传感器须以新配置版本上报，
     * 旧版本的批次被接入门禁拒绝（{@code requireActiveConfig}），批次序号在新版本内重新计数。
     */
    @Transactional
    public SensorAdminMapper.ConfigRow activateConfig(long sensorId, long configId, IdentityPrincipal actor,
                                                      HttpServletRequest request) {
        SensorAdminMapper.SensorRow sensor = lockManageable(sensorId, actor);
        requireNotRevoked(sensor);
        SensorAdminMapper.ConfigRow config = mapper.lockConfig(sensorId, configId);
        if (config == null) throw ApiRequestException.notFound();
        if (!"approved".equals(config.status())) throw configConflict("只有已批准的配置可以启用");
        requireCurrentContract(config);
        mapper.retireActiveConfigs(sensorId, configId);
        if (mapper.activateConfig(configId, actor.id()) != 1) throw configConflict("配置状态已被其他请求更新");
        audit(request, actor.id(), "sensor.config.activated", "sensor_config", configId, sensor.assetId(),
                "config " + config.configVersion() + " activated");
        return mapper.lockConfig(sensorId, configId);
    }

    /** 轮换机器凭据：旧凭据立即失效，新凭据只在本次响应中返回一次，有效期顺延 30 天。 */
    @Transactional
    public RotatedCredential rotateCredential(long sensorId, IdentityPrincipal actor, HttpServletRequest request) {
        SensorAdminMapper.SensorRow sensor = lockManageable(sensorId, actor);
        requireNotRevoked(sensor);
        SensorAdminMapper.ClientRow client = mapper.lockClient(sensorId);
        if (client == null) throw ApiRequestException.notFound();
        if (!"active".equals(client.status())) {
            throw new ApiRequestException(HttpStatus.CONFLICT, "CREDENTIAL_STATUS_CONFLICT", "凭据已吊销或停用，不能轮换");
        }
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        String secret = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        if (mapper.rotateCredential(client.id(), sha256(secret)) != 1) {
            throw new ApiRequestException(HttpStatus.CONFLICT, "CREDENTIAL_STATUS_CONFLICT", "凭据状态已被其他请求更新");
        }
        audit(request, actor.id(), "sensor.credential.rotated", "api_client", client.id(), sensor.assetId(),
                "sensor credential rotated, previous credential invalidated");
        SensorAdminMapper.ClientRow rotated = mapper.findClient(sensorId);
        return new RotatedCredential(sensorId, client.id(), "mch_" + client.id() + "." + secret, rotated.rotatedAt(),
                rotated.expiresAt());
    }

    /** 吊销机器凭据：立即失效（机器过滤器只认 active），不可恢复；传感器本身保留，须重新登记才能再上报。 */
    @Transactional
    public SensorDetail revokeCredential(long sensorId, String reasonText, IdentityPrincipal actor,
                                         HttpServletRequest request) {
        String reason = reason(reasonText);
        SensorAdminMapper.SensorRow sensor = lockManageable(sensorId, actor);
        SensorAdminMapper.ClientRow client = mapper.lockClient(sensorId);
        if (client == null) throw ApiRequestException.notFound();
        if (mapper.revokeClient(client.id(), actor.id(), reason) != 1) {
            throw new ApiRequestException(HttpStatus.CONFLICT, "CREDENTIAL_STATUS_CONFLICT", "凭据已吊销");
        }
        audit(request, actor.id(), "sensor.credential.revoked", "api_client", client.id(), sensor.assetId(), reason);
        return detail(sensorId, actor);
    }

    /** 下线：传感器 → {@code revoked}，同事务吊销凭据并退役 active 配置；登记、批次与健康窗口记录保留。 */
    @Transactional
    public SensorDetail decommission(long sensorId, String reasonText, IdentityPrincipal actor, HttpServletRequest request) {
        String reason = reason(reasonText);
        SensorAdminMapper.SensorRow sensor = lockManageable(sensorId, actor);
        if (mapper.decommission(sensorId) != 1) throw sensorConflict("传感器已下线");
        SensorAdminMapper.ClientRow client = mapper.lockClient(sensorId);
        if (client != null) mapper.revokeClient(client.id(), actor.id(), reason);
        mapper.retireActiveConfigs(sensorId, 0);
        audit(request, actor.id(), "sensor.decommissioned", "sensor_agent", sensorId, sensor.assetId(), reason);
        return detail(sensorId, actor);
    }

    private SensorAdminMapper.SensorRow lockManageable(long sensorId, IdentityPrincipal actor) {
        SensorAdminMapper.SensorRow sensor = mapper.lockSensor(sensorId);
        if (sensor == null || !mapper.hasAssetPermission(actor.id(), sensor.assetId(), "sensor.read")) {
            throw ApiRequestException.notFound();
        }
        if (!mapper.hasAssetPermission(actor.id(), sensor.assetId(), "sensor.manage")) {
            throw new AccessDeniedException("Sensor manage scope denied");
        }
        return sensor;
    }

    private static void requireNotRevoked(SensorAdminMapper.SensorRow sensor) {
        if ("revoked".equals(sensor.status())) throw sensorConflict("传感器已下线，不能变更");
    }

    private void requireCurrentContract(SensorAdminMapper.ConfigRow config) {
        FeatureContract contract = contracts.find(config.featureContractVersion());
        if (contract == null || !contract.fileSha256().equals(config.featureContractSha256())) {
            throw new ApiRequestException(HttpStatus.CONFLICT, "CONFIG_VERSION_STALE", "配置绑定的契约文件已变化，须重新起草");
        }
    }

    private static ApiRequestException sensorConflict(String message) {
        return new ApiRequestException(HttpStatus.CONFLICT, "SENSOR_STATUS_CONFLICT", message);
    }

    private static ApiRequestException configConflict(String message) {
        return new ApiRequestException(HttpStatus.CONFLICT, "CONFIG_STATUS_CONFLICT", message);
    }

    private static String reason(String reason) {
        if (reason == null || reason.isBlank() || reason.length() > 1000) {
            throw ApiRequestException.badRequest("须填写 1-1000 字的理由");
        }
        return reason.trim();
    }

    private void audit(HttpServletRequest request, long actorId, String action, String resourceType, long resourceId,
                       long assetId, String reason) {
        Object requestId = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        AuditMapper.AuditInsert audit = new AuditMapper.AuditInsert(LocalDateTime.now(ZoneOffset.UTC), "human",
                Long.toString(actorId), action, resourceType, Long.toString(resourceId),
                requestId instanceof String value ? value : null, "success", reason);
        auditMapper.insertAudit(audit);
        auditMapper.insertResourceScope(audit.getId(), "asset", Long.toString(assetId));
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
    }

    public record ConfigDraft(String configVersion, JsonNode interfaceScope, JsonNode filterPolicy, int flowWindowSeconds,
                              String featureContractVersion, JsonNode samplingPolicy, String reason) { }

    /** 凭据状态；不含凭据值、摘要或密钥引用。 */
    public record CredentialStatus(long clientId, String clientKey, String status, Instant expiresAt, Instant rotatedAt,
                                   Instant revokedAt, String revokeReason, Instant createdAt) {
        static CredentialStatus from(SensorAdminMapper.ClientRow row) {
            return new CredentialStatus(row.id(), row.clientKey(), row.status(), row.expiresAt(), row.rotatedAt(),
                    row.revokedAt(), row.revokeReason(), row.createdAt());
        }
    }

    public record SensorDetail(SensorAdminMapper.SensorRow sensor, List<SensorAdminMapper.ConfigRow> configs,
                               CredentialStatus credential) { }

    /** 轮换后的新凭据，只返回这一次。 */
    public record RotatedCredential(long sensorId, long machineClientId, String credential, Instant rotatedAt,
                                    Instant expiresAt) { }
}
