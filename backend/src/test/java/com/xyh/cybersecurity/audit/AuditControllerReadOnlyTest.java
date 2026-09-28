package com.xyh.cybersecurity.audit;

import org.junit.jupiter.api.Test;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.lang.reflect.Method;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

/** 防止审计控制器意外增加更新或删除入口；审计记录只能由业务写入器追加。 */
class AuditControllerReadOnlyTest {

    @Test
    void exposesOnlyGetEndpoint() {
        Method[] methods = AuditController.class.getDeclaredMethods();
        assertThat(Arrays.stream(methods).filter(method -> method.isAnnotationPresent(GetMapping.class)).count())
                .isEqualTo(1);
        assertThat(Arrays.stream(methods).anyMatch(method -> method.isAnnotationPresent(PostMapping.class)
                || method.isAnnotationPresent(PutMapping.class)
                || method.isAnnotationPresent(PatchMapping.class)
                || method.isAnnotationPresent(DeleteMapping.class))).isFalse();
        assertThat(AuditController.class.getAnnotation(RequestMapping.class).value())
                .containsExactly("/api/v1/audit");
    }
}
