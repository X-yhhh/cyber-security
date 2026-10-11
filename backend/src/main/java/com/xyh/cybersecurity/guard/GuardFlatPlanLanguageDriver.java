package com.xyh.cybersecurity.guard;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.apache.ibatis.builder.StaticSqlSource;
import org.apache.ibatis.mapping.BoundSql;
import org.apache.ibatis.mapping.ParameterMapping;
import org.apache.ibatis.mapping.SqlSource;
import org.apache.ibatis.parsing.XNode;
import org.apache.ibatis.scripting.xmltags.XMLLanguageDriver;
import org.apache.ibatis.session.Configuration;

/**
 * 只为 GuardMapper 的内部批量计划创建静态 SQL 源。
 *
 * <p>计划由白名单 SQL 生成器构造，业务值作为 BoundSql 附加参数按顺序绑定。这样避免批量热路径
 * 重新解析动态 provider SQL 或遍历 {@code rows[i].field} 属性，同时仍使用 MyBatis 的事务、
 * 参数处理器和生成键机制。</p>
 */
public final class GuardFlatPlanLanguageDriver extends XMLLanguageDriver {
    public static final String MARKER = "/* guard-flat-plan */";

    @Override
    public SqlSource createSqlSource(Configuration configuration, String script, Class<?> parameterType) {
        if (!MARKER.equals(script)) {
            throw new IllegalArgumentException("Guard flat plan marker required");
        }
        return new FlatPlanSqlSource(configuration);
    }

    @Override
    public SqlSource createSqlSource(Configuration configuration, XNode script, Class<?> parameterType) {
        return super.createSqlSource(configuration, script, parameterType);
    }

    private static final class FlatPlanSqlSource implements SqlSource {
        private final Configuration configuration;

        private FlatPlanSqlSource(Configuration configuration) {
            this.configuration = configuration;
        }

        @Override
        public BoundSql getBoundSql(Object parameterObject) {
            if (!(parameterObject instanceof Map<?, ?> parameters)
                    || !(parameters.get("plan") instanceof GuardMapper.FlatPlan plan)) {
                throw new IllegalArgumentException("Guard flat plan parameter required");
            }
            var mappings = new ArrayList<ParameterMapping>(plan.arguments().size());
            for (int index = 0; index < plan.arguments().size(); index++) {
                mappings.add(new ParameterMapping.Builder(configuration, "p" + index, Object.class).build());
            }
            BoundSql boundSql = new StaticSqlSource(configuration, plan.sql(), mappings).getBoundSql(parameterObject);
            for (int index = 0; index < plan.arguments().size(); index++) {
                boundSql.setAdditionalParameter("p" + index, plan.arguments().get(index));
            }
            return boundSql;
        }
    }
}
