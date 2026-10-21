package com.xyh.cybersecurity.web;

import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.core.type.filter.AnnotationTypeFilter;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** 接口退役回归：扫描真实控制器映射，v1 人工与机器端点均已删除，防止旧端点被重新暴露。 */
class ApiSurfaceTest {
    @Test
    void noV1EndpointsRemainAndProbesUseHealthRoot() throws Exception {
        var scanner = new ClassPathScanningCandidateComponentProvider(false);
        scanner.addIncludeFilter(new AnnotationTypeFilter(RestController.class));
        List<String> legacy = new ArrayList<>();
        List<String> health = new ArrayList<>();
        for (var bean : scanner.findCandidateComponents("com.xyh.cybersecurity")) {
            Class<?> type = Class.forName(bean.getBeanClassName());
            RequestMapping mapping = AnnotatedElementUtils.findMergedAnnotation(type, RequestMapping.class);
            String[] prefixes = mapping == null ? new String[]{""} : mapping.path();
            if (type.getSimpleName().equals("HealthController")) health.addAll(List.of(prefixes));
            for (var method : type.getDeclaredMethods()) {
                RequestMapping endpoint = AnnotatedElementUtils.findMergedAnnotation(method, RequestMapping.class);
                if (endpoint == null) continue;
                String[] suffixes = endpoint.path().length == 0 ? new String[]{""} : endpoint.path();
                for (String prefix : prefixes) for (String suffix : suffixes) {
                    String path = prefix + suffix;
                    if (path.startsWith("/api/v1")) legacy.add(path);
                }
            }
        }
        assertThat(legacy).isEmpty();
        assertThat(health).containsExactly("/health");
    }
}
