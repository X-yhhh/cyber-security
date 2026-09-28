package com.xyh.cybersecurity.identity;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import com.xyh.cybersecurity.audit.AuditMapper;
import com.xyh.cybersecurity.identity.MachineClientController.ScopeBody;
import com.xyh.cybersecurity.identity.MachineClientController.SourceAssetBindingBody;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** 一次性签发高熵机器凭据，并只保存不可逆验证摘要和白名单权限/范围。 */
@Service
public class MachineClientService {

    private static final SecureRandom RANDOM = new SecureRandom();
    private final IdentityMapper identityMapper;
    private final AuditMapper auditMapper;
    private final ObjectMapper objectMapper;

    public MachineClientService(IdentityMapper identityMapper, AuditMapper auditMapper, ObjectMapper objectMapper) {
        this.identityMapper = identityMapper;
        this.auditMapper = auditMapper;
        this.objectMapper = objectMapper;
    }

    @Transactional
    public IssuedClient create(String clientKey, String clientType, List<ScopeBody> requestedScopes,
                               List<SourceAssetBindingBody> requestedBindings,
                               IdentityPrincipal actor, HttpServletRequest request, String requestId) {
        if (!"connector".equals(clientType)) {
            throw ApiRequestException.badRequest("当前仅允许登记 connector 主体");
        }
        requireGlobalPlatformAdmin(actor.id());
        List<IssuedScope> scopes = normalizeScopes(requestedScopes);
        List<SourceAssetBinding> bindings = normalizeBindings(requestedBindings, scopes);
        byte[] randomBytes = new byte[32];
        RANDOM.nextBytes(randomBytes);
        String secret = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
        String digest = sha256(secret);
        String scopesJson;
        try {
            scopesJson = objectMapper.writeValueAsString(scopes.stream()
                    .map(scope -> java.util.Map.of("type", scope.scopeType(), "id", scope.scopeId())).toList());
        } catch (Exception exception) {
            throw new IllegalStateException("Unable to serialize machine scopes", exception);
        }

        try {
            identityMapper.insertMachineClient(clientKey, digest, scopesJson);
        } catch (org.springframework.dao.DuplicateKeyException exception) {
            throw ApiRequestException.conflict("机器客户端标识已存在");
        }
        long clientId = identityMapper.findMachineClientId(clientKey);
        for (IssuedScope scope : scopes) {
            identityMapper.insertClientScope(clientId, scope.scopeType(), scope.scopeId());
        }
        for (SourceAssetBinding binding : bindings) {
            identityMapper.insertClientBinding(clientId, binding.dataSourceId(), binding.assetId());
        }
        identityMapper.grantMachineIngestPermission(clientId);
        writeAudit(actor.id(), clientId, scopes, bindings, requestId);
        return new IssuedClient(clientId, clientKey, clientType, scopes, bindings, "mch_" + clientId + "." + secret,
                Instant.now());
    }

    private List<SourceAssetBinding> normalizeBindings(List<SourceAssetBindingBody> requestedBindings,
                                                        List<IssuedScope> scopes) {
        if (requestedBindings == null || requestedBindings.isEmpty() || requestedBindings.size() > 32) {
            throw ApiRequestException.badRequest("connector 必须配置 1 至 32 个数据源-资产配对");
        }
        Set<String> grantedScopes = scopes.stream()
                .map(scope -> scope.scopeType() + ":" + scope.scopeId()).collect(java.util.stream.Collectors.toSet());
        Set<String> unique = new HashSet<>();
        List<SourceAssetBinding> result = new ArrayList<>();
        for (SourceAssetBindingBody binding : requestedBindings) {
            if (binding == null || binding.dataSourceId() < 1 || binding.assetId() < 1) {
                throw ApiRequestException.badRequest("数据源-资产配对标识无效");
            }
            String sourceId = Long.toString(binding.dataSourceId());
            String assetId = Long.toString(binding.assetId());
            if (!grantedScopes.contains("data_source:" + sourceId)
                    || !grantedScopes.contains("asset:" + assetId)) {
                throw ApiRequestException.badRequest("配对资源必须同时位于机器主体范围内");
            }
            if (!identityMapper.activeSourceAssetPair(binding.dataSourceId(), binding.assetId())) {
                throw ApiRequestException.badRequest("配对资源不存在或不可用");
            }
            String key = sourceId + ":" + assetId;
            if (!unique.add(key)) throw ApiRequestException.badRequest("数据源-资产配对不能重复");
            result.add(new SourceAssetBinding(binding.dataSourceId(), binding.assetId()));
        }
        return List.copyOf(result);
    }

    private List<IssuedScope> normalizeScopes(List<ScopeBody> requestedScopes) {
        if (requestedScopes == null || requestedScopes.isEmpty() || requestedScopes.size() > 32) {
            throw ApiRequestException.badRequest("机器主体必须绑定 1 至 32 个资源范围");
        }
        Set<String> unique = new HashSet<>();
        List<IssuedScope> result = new ArrayList<>();
        for (ScopeBody scope : requestedScopes) {
            if (scope == null || scope.scopeType() == null || scope.scopeId() == null
                    || !("asset".equals(scope.scopeType()) || "data_source".equals(scope.scopeType()))
                    || !scope.scopeId().matches("[1-9][0-9]{0,18}")) {
                throw ApiRequestException.badRequest("机器客户端范围仅支持已登记资产或数据源");
            }
            if (!identityMapper.existsScope(scope.scopeType(), scope.scopeId())) {
                throw ApiRequestException.badRequest("授权资源不存在");
            }
            String normalized = scope.scopeType() + ":" + Long.parseLong(scope.scopeId());
            if (!unique.add(normalized)) throw ApiRequestException.badRequest("机器客户端范围不能重复");
            result.add(new IssuedScope(scope.scopeType(), Long.toString(Long.parseLong(scope.scopeId()))));
        }
        if (result.stream().noneMatch(scope -> "data_source".equals(scope.scopeType()))) {
            throw ApiRequestException.badRequest("connector 必须至少绑定一个数据源范围");
        }
        return List.copyOf(result);
    }

    private void requireGlobalPlatformAdmin(long userId) {
        if (!identityMapper.hasGlobalConfigAdmin(userId)) {
            throw new AccessDeniedException("Global platform administration required");
        }
    }

    private void writeAudit(long actorId, long clientId, List<IssuedScope> scopes,
                            List<SourceAssetBinding> bindings, String requestId) {
        AuditMapper.AuditInsert audit = new AuditMapper.AuditInsert(LocalDateTime.now(), "human",
                Long.toString(actorId), "machine_client.created", "api_client", Long.toString(clientId),
                requestId, "success", "connector credential issued once");
        auditMapper.insertAudit(audit);
        for (IssuedScope scope : scopes) {
            auditMapper.insertResourceScope(audit.getId(), scope.scopeType(), scope.scopeId());
        }
        for (SourceAssetBinding binding : bindings) {
            auditMapper.insertResourceScope(audit.getId(), "data_source", Long.toString(binding.dataSourceId()));
            auditMapper.insertResourceScope(audit.getId(), "asset", Long.toString(binding.assetId()));
        }
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    public record IssuedScope(String scopeType, String scopeId) { }
    public record SourceAssetBinding(long dataSourceId, long assetId) { }
    public record IssuedClient(long id, String clientKey, String clientType, List<IssuedScope> scopes,
                               List<SourceAssetBinding> sourceAssetBindings,
                               String credential, Instant issuedAt) { }
}
