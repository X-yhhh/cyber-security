package com.xyh.cybersecurity.model.validation;

/** 模型制品或运行时契约失败；code 可安全映射到 API，不携带路径、堆栈或制品内容。 */
public final class ModelContractException extends RuntimeException {

    private final String code;

    public ModelContractException(String code) { super(code); this.code = code; }

    public ModelContractException(String code, Throwable cause) { super(code, cause); this.code = code; }

    public String code() { return code; }
}
