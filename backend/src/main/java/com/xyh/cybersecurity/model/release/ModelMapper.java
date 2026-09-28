package com.xyh.cybersecurity.model.release;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.time.LocalDateTime;
import java.util.List;

/** 模型登记、审查与本机激活台账的 MyBatis 持久化边界。 */
@Mapper
public interface ModelMapper {
    long countVisible(@Param("userId") long userId, @Param("permission") String permission);
    List<ModelRow> listVisible(@Param("userId") long userId, @Param("permission") String permission,
                               @Param("offset") int offset, @Param("limit") int limit);
    ModelRow findVisible(@Param("userId") long userId, @Param("modelId") long modelId, @Param("permission") String permission);
    int insertModel(ModelInsert input);
    Long findModelId(@Param("modelKey") String modelKey, @Param("version") String version);
    int countPendingRelease(@Param("modelId") long modelId);
    int insertRelease(@Param("modelId") long modelId, @Param("requestedBy") long requestedBy, @Param("reason") String reason);
    Long findReleaseId(@Param("modelId") long modelId, @Param("requestedBy") long requestedBy);
    ReleaseView findRelease(@Param("id") long id);
    ReleaseRow findReleaseRow(@Param("id") long id);
    int reconcileRelease(@Param("id") long id, @Param("actorId") long actorId);
    int decideRelease(@Param("id") long id, @Param("status") String status, @Param("actorId") long actorId,
                      @Param("reason") String reason);
    int markValidated(@Param("id") long id, @Param("sha256") String sha256);
    int countApprovedReleases(@Param("modelId") long modelId);
    List<Long> lockLocalDeployments();
    int deactivateLocalDeployments();
    int retireOtherReleases(@Param("modelId") long modelId);
    int insertDeployment(@Param("modelId") long modelId, @Param("actorId") long actorId);
    int activateRelease(@Param("modelId") long modelId, @Param("actorId") long actorId);
    boolean hasPermission(@Param("userId") long userId, @Param("permission") String permission,
                          @Param("modelKey") String modelKey);
    List<Long> lockScopedRoles(@Param("userId") long userId, @Param("modelKey") String modelKey);

    record ModelRow(long id, String modelKey, String version, String taskType, String manifestVersion,
                    String manifestJson, String artifactRef, String artifactSha256,
                    String featureContractVersion, String approvalStatus, LocalDateTime createdAt) { }
    record ReleaseView(long id, long modelVersionId, String reviewStatus, long requestedBy, Long approvedBy,
                       String requestReason, String decisionReason, LocalDateTime reviewedAt, LocalDateTime createdAt) { }
    record ReleaseRow(long id, long modelVersionId, String reviewStatus, long requestedBy, Long approvedBy,
                      String releaseStatus, String modelKey) { }
    /** 候选模型登记参数；显式 JavaBean 访问器保证 MyBatis 在不同版本下稳定绑定。 */
    final class ModelInsert {
        private final String modelKey;
        private final String version;
        private final String taskType;
        private final String manifestVersion;
        private final String manifestJson;
        private final String artifactRef;
        private final String artifactSha256;
        private final String featureContractVersion;

        public ModelInsert(String modelKey, String version, String taskType, String manifestVersion,
                           String manifestJson, String artifactRef, String artifactSha256,
                           String featureContractVersion) {
            this.modelKey = modelKey;
            this.version = version;
            this.taskType = taskType;
            this.manifestVersion = manifestVersion;
            this.manifestJson = manifestJson;
            this.artifactRef = artifactRef;
            this.artifactSha256 = artifactSha256;
            this.featureContractVersion = featureContractVersion;
        }

        public String getModelKey() { return modelKey; }
        public String getVersion() { return version; }
        public String getTaskType() { return taskType; }
        public String getManifestVersion() { return manifestVersion; }
        public String getManifestJson() { return manifestJson; }
        public String getArtifactRef() { return artifactRef; }
        public String getArtifactSha256() { return artifactSha256; }
        public String getFeatureContractVersion() { return featureContractVersion; }
    }
}
