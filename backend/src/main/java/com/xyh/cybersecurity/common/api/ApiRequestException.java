package com.xyh.cybersecurity.common.api;

import org.springframework.http.HttpStatus;

/** 表示可安全返回给调用方的稳定业务错误。 */
public final class ApiRequestException extends RuntimeException {

    private final HttpStatus status;
    private final String code;

    public ApiRequestException(HttpStatus status, String code, String message) {
        super(message);
        this.status = status;
        this.code = code;
    }

    public HttpStatus status() { return status; }
    public String code() { return code; }

    public static ApiRequestException badRequest(String message) {
        return new ApiRequestException(HttpStatus.BAD_REQUEST, "INVALID_REQUEST", message);
    }

    public static ApiRequestException notFound() {
        return new ApiRequestException(HttpStatus.NOT_FOUND, "NOT_FOUND", "请求的资源不存在");
    }

    public static ApiRequestException conflict(String message) {
        return new ApiRequestException(HttpStatus.CONFLICT, "CONFLICT", message);
    }
}
