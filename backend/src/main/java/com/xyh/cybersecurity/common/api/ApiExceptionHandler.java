package com.xyh.cybersecurity.common.api;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.resource.NoResourceFoundException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import com.xyh.cybersecurity.security.SecurityAuditWriter;
import org.springframework.beans.factory.ObjectProvider;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 将输入错误和未处理异常映射为不包含 SQL、堆栈或秘密的稳定错误响应。 */
@RestControllerAdvice
public class ApiExceptionHandler {

    private final ObjectProvider<SecurityAuditWriter> securityAuditWriter;

    public ApiExceptionHandler(ObjectProvider<SecurityAuditWriter> securityAuditWriter) {
        this.securityAuditWriter = securityAuditWriter;
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiEnvelope<Void>> forbidden(AccessDeniedException exception, HttpServletRequest request) {
        SecurityAuditWriter auditWriter = securityAuditWriter.getIfAvailable();
        if (auditWriter != null) {
            auditWriter.denied(request, SecurityContextHolder.getContext().getAuthentication(),
                    "authorization.denied", "permission_denied");
        }
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ApiEnvelope.failure(
                "FORBIDDEN", "当前身份无权执行此操作", requestId(request)));
    }

    @ExceptionHandler(ApiRequestException.class)
    public ResponseEntity<ApiEnvelope<Void>> requestError(ApiRequestException exception, HttpServletRequest request) {
        return ResponseEntity.status(exception.status()).body(ApiEnvelope.failure(
                exception.code(), exception.getMessage(), requestId(request)));
    }

    @ExceptionHandler({MethodArgumentNotValidException.class, HttpMessageNotReadableException.class})
    public ResponseEntity<ApiEnvelope<Void>> badRequest(Exception exception, HttpServletRequest request) {
        return ResponseEntity.badRequest().body(ApiEnvelope.failure(
                "INVALID_REQUEST", "请求参数无效", requestId(request)));
    }

    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<ApiEnvelope<Void>> routeNotFound(NoResourceFoundException exception,
                                                            HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(ApiEnvelope.failure(
                "NOT_FOUND", "请求的资源不存在", requestId(request)));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiEnvelope<Void>> internalError(Exception exception, HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(ApiEnvelope.failure(
                "INTERNAL_ERROR", "服务暂时无法处理请求", requestId(request)));
    }

    private String requestId(HttpServletRequest request) {
        Object requestId = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        return requestId instanceof String value ? value : "unknown";
    }
}
