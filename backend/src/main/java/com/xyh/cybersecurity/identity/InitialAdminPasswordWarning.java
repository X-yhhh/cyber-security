package com.xyh.cybersecurity.identity;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.dao.DataAccessException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/** 非 local 环境只检查并告警默认 admin/admin，绝不改写既存账号或密码哈希。 */
@Component
@Profile("!local")
public class InitialAdminPasswordWarning implements ApplicationRunner {

    private static final Logger logger = LoggerFactory.getLogger(InitialAdminPasswordWarning.class);

    private final IdentityMapper mapper;
    private final PasswordEncoder passwordEncoder;

    public InitialAdminPasswordWarning(IdentityMapper mapper, PasswordEncoder passwordEncoder) {
        this.mapper = mapper;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(ApplicationArguments args) {
        try {
            IdentityMapper.AdminRow admin = mapper.findAdmin();
            String hash = admin == null ? null : admin.passwordHash();
            if (hash != null && passwordEncoder.matches("admin", hash)) {
                logger.warn("非 local 环境检测到 admin 仍使用初始化口令；请在受控密钥流程中完成改密后再对外提供服务。");
            }
        } catch (DataAccessException exception) {
            // Flyway/数据库异常由就绪探针和启动流程处理；这里不得输出连接信息或阻断回滚路径。
            logger.warn("无法完成初始化管理员口令检查；未修改任何账号数据。");
        }
    }
}
