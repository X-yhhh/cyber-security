package com.xyh.cybersecurity.response.domain;

import java.util.Map;
import java.util.Optional;

/**
 * 响应动作白名单与适配器能力声明（M6，路线 B §14.1）。
 *
 * <p>只有列在这里的 {@code action_type} 可以写入策略；每个动作绑定一份参数 JSON Schema（资源文件）和
 * 适配器能力。{@code rollbackVerified} 表示该动作已有经验证的撤销/回滚证据（M7 在隔离靶场实测后才能置为
 * {@code true}）。在此之前任何策略都不能设置 {@code auto_execute=true}（CLAUDE.md §3：不能证明安全回滚的动作
 * 不得配置为自动执行）。</p>
 *
 * <p>能力声明是代码常量而不是可写配置：放宽能力必须经过代码评审与回滚证据，不能由接口或配置文件打开。</p>
 */
public final class ResponseActionCatalog {

    /** 系统级 TTL 上限（秒）。策略的 {@code max_duration_seconds} 与参数中的 {@code maxTtlSeconds} 都不得超过它。 */
    public static final int SYSTEM_MAX_DURATION_SECONDS = 3600;

    private static final Map<String, ActionCapability> ACTIONS = Map.of(
            "temporary_block", new ActionCapability("temporary_block",
                    "response-policy/schema/temporary-block-params.json", false, false));

    private ResponseActionCatalog() { }

    public static Optional<ActionCapability> find(String actionType) {
        return actionType == null ? Optional.empty() : Optional.ofNullable(ACTIONS.get(actionType));
    }

    /**
     * @param paramsSchema      参数 JSON Schema 的 classpath 位置
     * @param rollbackVerified  是否已有经验证的撤销/回滚证据；为 {@code false} 时禁止自动执行
     * @param rateLimitSupported 主机限速能力；首期不实现，恒为 {@code false}
     */
    public record ActionCapability(String actionType, String paramsSchema, boolean rollbackVerified,
                                   boolean rateLimitSupported) {
        public boolean autoExecuteAllowed() { return rollbackVerified; }
    }
}
