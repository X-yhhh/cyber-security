package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import com.xyh.cybersecurity.common.web.RequestIdFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.sql.SQLException;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/** v2 稳定脱敏错误，与 v1 的历史返回结构隔离。 */
@RestControllerAdvice(basePackageClasses=GuardController.class)
@Order(-100)
public class GuardApiErrors {
    private static final Logger LOGGER = LoggerFactory.getLogger(GuardApiErrors.class);

    @ExceptionHandler(Exception.class) public ResponseEntity<JsonNode> errorResponse(Exception ex,HttpServletRequest request){
        int status=500;String code="INTERNAL_ERROR";
        if(ex instanceof ApiRequestException e){status=e.status().value();code=e.code();}
        else if(ex instanceof org.springframework.security.access.AccessDeniedException){status=403;code="SCOPE_DENIED";}
        else if(ex instanceof org.springframework.dao.DuplicateKeyException){status=409;code="IDEMPOTENCY_CONFLICT";}
        else if(ex instanceof org.springframework.web.bind.MissingRequestHeaderException||ex instanceof org.springframework.http.converter.HttpMessageNotReadableException||ex instanceof org.springframework.web.method.annotation.MethodArgumentTypeMismatchException){status=400;code="INVALID_REQUEST";}
        if(status>=500) logServerError(ex,status,request);
        return ResponseEntity.status(status).body(object("requestId",request.getAttribute(com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE),"data",null,"error",object("code",code,"message","请求未通过校验或暂时无法处理","retryable",status>=500,"details",object())));
    }

    /**
     * 服务器故障只记录可关联的诊断白名单；JDBC 类型、SQLState 与数字码足以区分排序内存等故障。
     * 原因链最多检查 16 层，避免循环链阻塞错误响应；不向 logger 传 Throwable、异常消息或请求原文。
     */
    private static void logServerError(Exception exception,int status,HttpServletRequest request) {
        Object attribute=request.getAttribute(RequestIdFilter.REQUEST_ID_ATTRIBUTE);
        String requestId=attribute instanceof String value&&value.matches("[A-Za-z0-9._:-]{1,64}")?value:"unknown";
        Throwable cause=exception,current=exception;
        SQLException sql=null;
        for(int depth=0;current!=null&&depth<16;depth++) {
            cause=current;
            if(current instanceof SQLException jdbc) sql=jdbc;
            current=current.getCause();
        }
        String sqlState=sql!=null&&sql.getSQLState()!=null&&sql.getSQLState().matches("[A-Z0-9]{5}")?sql.getSQLState():null;
        LOGGER.error("v2 API 服务器错误，requestId={}, status={}, exceptionType={}, causeType={}, sqlState={}, vendorCode={}",
                requestId,status,exception.getClass().getSimpleName(),cause.getClass().getSimpleName(),sqlState,
                sql==null?null:sql.getErrorCode());
    }
}
