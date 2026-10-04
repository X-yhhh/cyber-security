package com.xyh.cybersecurity.identity;

/** 独立于人工用户和浏览器会话的机器主体。 */
public record MachinePrincipal(long id, String clientKey, String clientType) { }
