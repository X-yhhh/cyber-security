package com.xyh.cybersecurity.ingest.contract;

import org.springframework.stereotype.Component;

import java.util.Map;

/** 只注册经过评审的契约快照；未知版本不会回退到旧契约。 */
@Component
public final class FeatureContractRegistry {
    private final Map<String, FeatureContract> contracts = Map.of(FeatureContract.V3_1, FeatureContract.UNSW_NB15_V3_1);

    public FeatureContract find(String version) {
        return version == null ? null : contracts.get(version);
    }
}
