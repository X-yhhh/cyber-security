package com.xyh.cybersecurity.detection;

/**
 * 告警生成暂不可用：缺少 active 策略或策略参数不合规。
 *
 * <p>调用方必须整批回滚并重试，不能跳过告警生成后仍确认消息，否则推理结论与告警会永久脱节。
 * {@link #code()} 是稳定错误码，不携带记录内容。</p>
 */
public final class DetectionUnavailableException extends RuntimeException {
    private final String code;

    public DetectionUnavailableException(String code) {
        super(code);
        this.code = code;
    }

    public String code() { return code; }
}
