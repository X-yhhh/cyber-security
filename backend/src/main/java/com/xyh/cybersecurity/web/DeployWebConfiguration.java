package com.xyh.cybersecurity.web;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.context.annotation.*;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/** deploy 专用静态站点；只放行浏览器 GET/HEAD，API、运维与错误入口仍由原安全链处理。 */
@Configuration(proxyBeanMethods = false)
@Profile("deploy")
public class DeployWebConfiguration {
    public static boolean reserved(String path) {
        return path.equals("/api") || path.startsWith("/api/") || path.equals("/actuator")
                || path.startsWith("/actuator/") || path.equals("/error") || path.equals("/health") || path.startsWith("/health/");
    }

    /** 在数据源/Flyway 创建前验证外部 web 根，不修复权限、不跟随符号链接。 */
    @Bean static BeanFactoryPostProcessor deployWebPreflight(Environment env) {
        return factory -> verify(env.getProperty("cyber.guard.deploy.web-root"));
    }

    public static Path verify(String value) {
        try {
            if (value == null || value.isBlank() || value.contains("${")) throw new IOException();
            Path root = Path.of(value);
            if (!root.isAbsolute() || !root.normalize().equals(root) || Files.isSymbolicLink(root)
                    || !Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)
                    || !Files.getPosixFilePermissions(root).equals(PosixFilePermissions.fromString("rwx------"))) throw new IOException();
            var owner = FileSystems.getDefault().getUserPrincipalLookupService().lookupPrincipalByName(
                    ProcessHandle.current().info().user().orElseThrow());
            if (!Files.getOwner(root).equals(owner)) throw new IOException();
            try (var walk = Files.walk(root)) {
                for (Path p : (Iterable<Path>) walk::iterator) {
                    if (Files.isSymbolicLink(p) || !Files.getOwner(p).equals(owner)
                            || !(Files.isDirectory(p) || Files.isRegularFile(p))
                            || Files.getPosixFilePermissions(p).stream().anyMatch(v -> v.name().startsWith("GROUP_") || v.name().startsWith("OTHERS_"))) throw new IOException();
                }
            }
            if (!Files.isRegularFile(root.resolve("index.html"))) throw new IOException();
            return root;
        } catch (Exception e) { throw new IllegalStateException("部署启动自检失败：WEB_ROOT_INVALID"); }
    }

    @Bean @Order(2)
    SecurityFilterChain deployWebSecurity(HttpSecurity http) throws Exception {
        http.securityMatcher(request -> !reserved(request.getServletPath()))
                .authorizeHttpRequests(a -> a.requestMatchers(org.springframework.http.HttpMethod.GET, "/**").permitAll()
                        .requestMatchers(org.springframework.http.HttpMethod.HEAD, "/**").permitAll().anyRequest().denyAll())
                .requestCache(c -> c.disable());
        return http.build();
    }
}
