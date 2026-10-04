package com.xyh.cybersecurity.ingest.contract;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 已评审契约快照的注册表。
 *
 * <p>启动时从 {@code classpath:feature-contract/*.json} 加载全部契约；任一文件不合法或版本重复都会使启动失败
 * （fail-fast）。查询未知版本返回 {@code null}，调用方必须 fail-closed，不回退到其他契约。</p>
 *
 * <p>注册表不感知模型：契约是否与激活模型一致由 {@code FeatureContractModelGate} 在推理入口判定。</p>
 */
@Component
public final class FeatureContractRegistry {
    static final String LOCATION = "classpath*:feature-contract/*.json";

    private final Map<String, FeatureContract> contracts;

    /** Spring 使用的构造器：扫描类路径并加载全部契约。本类有多个构造器，必须显式标注注入入口。 */
    @Autowired
    public FeatureContractRegistry(ObjectMapper objectMapper) {
        this(loadAll(new FeatureContractLoader(objectMapper)));
    }

    private FeatureContractRegistry(List<FeatureContract> loaded) {
        Map<String, FeatureContract> byVersion = new LinkedHashMap<>();
        for (FeatureContract contract : loaded) {
            if (byVersion.putIfAbsent(contract.version(), contract) != null) {
                throw new FeatureContractLoader.FeatureContractLoadException(contract.resourceName(), "契约版本重复");
            }
        }
        if (byVersion.isEmpty()) {
            throw new FeatureContractLoader.FeatureContractLoadException(LOCATION, "未找到任何特征契约");
        }
        this.contracts = Map.copyOf(byVersion);
    }

    /** 测试用：由给定契约构造注册表，同样执行版本唯一性检查。 */
    public static FeatureContractRegistry of(FeatureContract... contracts) {
        return new FeatureContractRegistry(List.of(contracts));
    }

    /** 测试与工具用：加载类路径上的真实契约（与 Spring 构造器行为一致）。 */
    public static FeatureContractRegistry fromClasspath() {
        return new FeatureContractRegistry(new ObjectMapper());
    }

    /** 返回已注册契约；版本为空或未知时返回 {@code null}。 */
    public FeatureContract find(String version) {
        return version == null ? null : contracts.get(version);
    }

    /** 与 {@link #find} 相同，但未知版本抛出异常；用于调用方已确认版本存在的内部路径。 */
    public FeatureContract require(String version) {
        FeatureContract contract = find(version);
        if (contract == null) throw new IllegalArgumentException("未登记的特征契约: " + version);
        return contract;
    }

    public Collection<FeatureContract> all() {
        return contracts.values();
    }

    private static List<FeatureContract> loadAll(FeatureContractLoader loader) {
        try {
            Resource[] resources = new PathMatchingResourcePatternResolver().getResources(LOCATION);
            return java.util.Arrays.stream(resources).map(resource -> {
                String name = resource.getFilename();
                try (InputStream input = resource.getInputStream()) {
                    return loader.load(name, input.readAllBytes());
                } catch (IOException exception) {
                    throw new FeatureContractLoader.FeatureContractLoadException(name, "无法读取资源");
                }
            }).toList();
        } catch (IOException exception) {
            throw new FeatureContractLoader.FeatureContractLoadException(LOCATION, "无法扫描契约资源");
        }
    }
}
