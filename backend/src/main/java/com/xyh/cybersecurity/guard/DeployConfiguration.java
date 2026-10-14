package com.xyh.cybersecurity.guard;

import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.context.annotation.*;
import org.springframework.core.env.Environment;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/** 部署前置检查与启动审计只在显式 deploy profile 下装配，默认和 lab 配置不受影响。 */
@Configuration(proxyBeanMethods = false)
@Profile("deploy")
public class DeployConfiguration {
    /** static 避免在前置门执行前实例化数据源或普通配置 Bean。 */
    @Bean static DeployStartupCheck deployStartupCheck(Environment environment) {
        return new DeployStartupCheck(environment);
    }

    /**
     * 监听服务就绪前追加启动审计：resourceId 为外部配置原字节 SHA-256，details 为公开配置摘要。
     * 审计事务失败即拒绝启动；不创建资产、发布绑定或任何动作。
     */
    @Bean SmartInitializingSingleton deployStartupAudit(DeployStartupCheck check, GuardStore store,
                                                        PlatformTransactionManager transactions) {
        return () -> new TransactionTemplate(transactions).executeWithoutResult(status -> {
            var proof = check.proof();
            store.audit(null, "guard.deploy.startup", proof.path("configSha256").asText(), null, id(), proof);
        });
    }
}
