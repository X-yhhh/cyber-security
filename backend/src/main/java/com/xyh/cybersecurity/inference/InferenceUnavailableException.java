package com.xyh.cybersecurity.inference;

/**
 * 推理暂时不可用：工作线程容量耗尽、门禁判定后激活版本切换、调用线程被中断。
 *
 * <p>调用方必须整批回滚并稍后重试，不得把这类故障写成单条记录的失败结论，也不得换用其他模型。
 * {@link #code()} 是稳定错误码，不携带记录内容。</p>
 */
public final class InferenceUnavailableException extends RuntimeException {
    private final String code;

    public InferenceUnavailableException(String code, Throwable cause) {
        super(code, cause);
        this.code = code;
    }

    public String code() { return code; }
}
