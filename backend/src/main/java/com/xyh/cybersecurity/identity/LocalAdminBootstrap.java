package com.xyh.cybersecurity.identity;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Profile;
import com.xyh.cybersecurity.audit.AuditMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

/** 仅本机 local profile 确保联调管理员存在；不得重置既有密码、状态或用户标识。 */
@Component
@Profile("local")
@ConditionalOnProperty(prefix = "cyber.security.local-admin-bootstrap", name = "enabled", havingValue = "true")
public class LocalAdminBootstrap implements ApplicationRunner {

    private static final Logger logger = LoggerFactory.getLogger(LocalAdminBootstrap.class);
    private final IdentityMapper identityMapper;
    private final AuditMapper auditMapper;
    private final PasswordEncoder passwordEncoder;

    public LocalAdminBootstrap(IdentityMapper identityMapper, AuditMapper auditMapper, PasswordEncoder passwordEncoder) {
        this.identityMapper = identityMapper;
        this.auditMapper = auditMapper;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        IdentityMapper.AdminRow existing = identityMapper.findAdmin();
        long adminId;
        if (existing == null) {
            identityMapper.insertAdmin("bootstrap-admin", "本机测试管理员", passwordEncoder.encode("admin"));
            adminId = identityMapper.findUserIdByUsername("admin");
        } else {
            adminId = existing.id();
            if (existing.passwordHash() == null || !passwordEncoder.matches("admin", existing.passwordHash())) {
                logger.warn("Existing admin password hash was preserved; local credentials may differ from admin/admin.");
            }
        }

        Long roleId = identityMapper.findPlatformAdminRoleId();
        int added = identityMapper.ensureGlobalPlatformAdminBinding(adminId, roleId);
        if (added > 0) {
            auditMapper.insertAudit(new AuditMapper.AuditInsert(LocalDateTime.now(), "system", "local-bootstrap",
                    "iam.admin.bootstrap", "user", Long.toString(adminId), null, "success",
                    "local profile added platform_admin role binding"));
        }
    }
}
