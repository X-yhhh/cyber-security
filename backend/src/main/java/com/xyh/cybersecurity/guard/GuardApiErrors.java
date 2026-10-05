package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.annotation.Order;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/** v2 稳定脱敏错误，与 v1 的历史返回结构隔离。 */
@RestControllerAdvice(basePackageClasses=GuardController.class)
@Order(-100)
public class GuardApiErrors {
    @ExceptionHandler(Exception.class) public ResponseEntity<JsonNode> errorResponse(Exception ex,HttpServletRequest request){
        int status=500;String code="INTERNAL_ERROR";
        if(ex instanceof ApiRequestException e){status=e.status().value();code=e.code();}
        else if(ex instanceof org.springframework.security.access.AccessDeniedException){status=403;code="SCOPE_DENIED";}
        else if(ex instanceof org.springframework.dao.DuplicateKeyException){status=409;code="IDEMPOTENCY_CONFLICT";}
        else if(ex instanceof org.springframework.web.bind.MissingRequestHeaderException||ex instanceof org.springframework.http.converter.HttpMessageNotReadableException||ex instanceof org.springframework.web.method.annotation.MethodArgumentTypeMismatchException){status=400;code="INVALID_REQUEST";}
        return ResponseEntity.status(status).body(object("requestId",request.getAttribute(com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE),"data",null,"error",object("code",code,"message","请求未通过校验或暂时无法处理","retryable",status>=500,"details",object())));
    }
}
