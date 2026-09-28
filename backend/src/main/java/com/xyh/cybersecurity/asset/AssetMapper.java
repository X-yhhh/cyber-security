package com.xyh.cybersecurity.asset;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

/** 在 SQL 内将资产结果限定为主体对 asset.read 明确获授的范围。 */
@Mapper
public interface AssetMapper {

    int insertAsset(AssetInsert input);

    Long findIdByKey(@Param("assetKey") String assetKey);

    int insertAuthorization(AuthorizationInsert input);

    Long findAuthorizationId(@Param("assetId") long assetId, @Param("requestedBy") long requestedBy,
                             @Param("authorizationRef") String authorizationRef);

    AuthorizationView findAuthorization(@Param("id") long id);

    AuthorizationRow findAuthorizationForUpdate(@Param("id") long id, @Param("assetId") long assetId);

    int approveAuthorization(@Param("id") long id, @Param("approvedBy") long approvedBy);

    boolean hasScope(@Param("userId") long userId, @Param("permission") String permission,
                     @Param("scopeType") String scopeType, @Param("scopeId") String scopeId);

    boolean hasGlobalPlatformAdmin(@Param("userId") long userId, @Param("permission") String permission);

    long countVisible(@Param("userId") long userId);

    List<AssetView> listVisible(@Param("userId") long userId,
                                @Param("offset") int offset,
                                @Param("limit") int limit);

    AssetView findVisible(@Param("userId") long userId, @Param("assetId") long assetId);

    int updateVisible(@Param("userId") long userId, @Param("assetId") long assetId,
                      @Param("criticality") String criticality, @Param("owner") String owner,
                      @Param("status") String status);

    record AssetView(long id, String assetKey, String assetType, String environment,
                     String criticality, String owner, String status) { }

    final class AssetInsert {
        private final String assetKey;
        private final String assetType;
        private final String environment;
        private final String criticality;
        private final String owner;
        private final String labelsJson;

        public AssetInsert(String assetKey, String assetType, String environment, String criticality,
                           String owner, String labelsJson) {
            this.assetKey = assetKey;
            this.assetType = assetType;
            this.environment = environment;
            this.criticality = criticality;
            this.owner = owner;
            this.labelsJson = labelsJson;
        }
        public String getAssetKey() { return assetKey; }
        public String getAssetType() { return assetType; }
        public String getEnvironment() { return environment; }
        public String getCriticality() { return criticality; }
        public String getOwner() { return owner; }
        public String getLabelsJson() { return labelsJson; }
    }

    final class AuthorizationInsert {
        private final long assetId;
        private final String authorizationRef;
        private final String scopeJson;
        private final java.time.Instant validFrom;
        private final java.time.Instant validUntil;
        private final long requestedBy;

        public AuthorizationInsert(long assetId, String authorizationRef, String scopeJson,
                                   java.time.Instant validFrom, java.time.Instant validUntil, long requestedBy) {
            this.assetId = assetId;
            this.authorizationRef = authorizationRef;
            this.scopeJson = scopeJson;
            this.validFrom = validFrom;
            this.validUntil = validUntil;
            this.requestedBy = requestedBy;
        }
        public long getAssetId() { return assetId; }
        public String getAuthorizationRef() { return authorizationRef; }
        public String getScopeJson() { return scopeJson; }
        public java.time.Instant getValidFrom() { return validFrom; }
        public java.time.Instant getValidUntil() { return validUntil; }
        public long getRequestedBy() { return requestedBy; }
    }

    record AuthorizationView(long id, long assetId, String status, long requestedBy, Long approvedBy,
                             java.time.Instant validFrom, java.time.Instant validUntil) { }

    record AuthorizationRow(long requestedBy, java.time.Instant validFrom, java.time.Instant validUntil,
                            String status) { }
}
