package com.xyh.cybersecurity.common.api;

/** 提供稳定且不暴露内部异常细节的 API 响应结构。 */
public record ApiEnvelope<T>(boolean success, T data, ApiError error, String requestId) {

    public static <T> ApiEnvelope<T> success(T data, String requestId) {
        return new ApiEnvelope<>(true, data, null, requestId);
    }

    public static <T> ApiEnvelope<T> failure(String code, String message, String requestId) {
        return new ApiEnvelope<>(false, null, new ApiError(code, message), requestId);
    }

    public record ApiError(String code, String message) {
    }
}
