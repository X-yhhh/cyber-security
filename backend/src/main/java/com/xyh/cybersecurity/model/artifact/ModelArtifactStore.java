package com.xyh.cybersecurity.model.artifact;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.ingest.contract.FeatureContractRegistry;
import com.xyh.cybersecurity.model.release.ModelService;
import com.xyh.cybersecurity.model.runtime.ModelInputContract;
import com.xyh.cybersecurity.model.validation.ModelContractException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Locale;

/** 只从管理员配置的制品根目录读取模型；拒绝穿越、越界链接、哈希或快照不一致。 */
@Component
public class ModelArtifactStore {

    private final Path configuredRoot;
    private final ObjectMapper objectMapper;
    private final FeatureContractRegistry contracts;

    public ModelArtifactStore(@Value("${cyber.model-artifact.root:}") String root, ObjectMapper objectMapper,
                              FeatureContractRegistry contracts) {
        this.configuredRoot = root.isBlank() ? null : Path.of(root).toAbsolutePath().normalize();
        this.objectMapper = objectMapper;
        this.contracts = contracts;
    }

    public VerifiedArtifact verify(ModelService.ModelView model) {
        if (configuredRoot == null) throw new ModelContractException("MODEL_ARTIFACT_ROOT_NOT_CONFIGURED");
        try {
            Path root = configuredRoot.toRealPath();
            Path artifact = resolveWithinRoot(model.artifactRef(), root).toRealPath();
            if (!artifact.startsWith(root) || !Files.isRegularFile(artifact) || !Files.isReadable(artifact)) {
                throw new ModelContractException("MODEL_ARTIFACT_UNAVAILABLE");
            }
            String sha256 = sha256(artifact);
            if (!sha256.equalsIgnoreCase(model.artifactSha256())) throw new ModelContractException("MODEL_HASH_MISMATCH");

            Path manifestPath = artifact.resolveSibling("model_manifest.json").toRealPath();
            if (!manifestPath.startsWith(root) || !Files.isRegularFile(manifestPath)) {
                throw new ModelContractException("MODEL_MANIFEST_UNAVAILABLE");
            }
            JsonNode manifest = objectMapper.readTree(manifestPath.toFile());
            // MySQL JSON stores浮点数时可能发生 1-2 ULP 的重编码；结构、字符串和关键契约仍须完全一致。
            if (!jsonEquivalent(manifest, model.manifest())) {
                throw new ModelContractException("MODEL_MANIFEST_SNAPSHOT_MISMATCH");
            }
            validateManifest(model, manifest);

            Path checksumsPath = artifact.resolveSibling("checksums.json");
            Path realChecksums = checksumsPath.toRealPath();
            if (!realChecksums.startsWith(root)) throw new ModelContractException("MODEL_CHECKSUMS_PATH_INVALID");
            JsonNode checksums = objectMapper.readTree(realChecksums.toFile());
            // checksums.json 的路径相对于本次交付目录；交付目录本身仍必须位于受控根目录内。
            verifyChecksums(checksums, artifact.getParent(), root, artifact);
            ModelInputContract inputs = verifyPreprocessingContract(artifact, root, manifest);
            return new VerifiedArtifact(artifact, manifest, sha256, inputs);
        } catch (IOException | SecurityException exception) {
            throw new ModelContractException("MODEL_ARTIFACT_UNAVAILABLE");
        }
    }

    private static Path resolveWithinRoot(String artifactRef, Path root) {
        java.net.URI uri;
        try { uri = java.net.URI.create(artifactRef); }
        catch (RuntimeException exception) { throw new ModelContractException("MODEL_ARTIFACT_REFERENCE_INVALID"); }
        String path = uri.getPath();
        String authority = uri.getRawAuthority();
        if (!"model".equals(uri.getScheme()) || authority == null
                || !authority.matches("[A-Za-z0-9._-]{1,128}") || path == null || path.isBlank()
                || uri.getUserInfo() != null || uri.getPort() != -1 || uri.getQuery() != null
                || uri.getFragment() != null) {
            throw new ModelContractException("MODEL_ARTIFACT_REFERENCE_INVALID");
        }
        Path relative = Path.of(authority).resolve(path.startsWith("/") ? path.substring(1) : path).normalize();
        if (relative.isAbsolute() || relative.startsWith("..")) throw new ModelContractException("MODEL_ARTIFACT_REFERENCE_INVALID");
        return root.resolve(relative).normalize();
    }

    private static void validateManifest(ModelService.ModelView model, JsonNode manifest) {
        String declaredVersion = manifest.path("model_version").asText();
        boolean versionMatches = declaredVersion.equals(model.version())
                || declaredVersion.equals(model.modelKey() + "-" + model.version());
        String runtime = firstText(manifest.at("/runtime/onnxruntime"), manifest.at("/runtime/name"),
                manifest.at("/runtime/version"), manifest.path("onnxruntime"));
        if (!versionMatches || !"binary_flow_classification".equals(manifest.path("task").asText())
                || !manifest.at("/feature_contract/version").asText().equals(model.featureContractVersion())
                || !"1.23.2".equals(runtime) || !hasOpset17(manifest.path("artifact").path("opset"))) {
            throw new ModelContractException("MODEL_MANIFEST_CONTRACT_MISMATCH");
        }
        if (!model.artifactSha256().equalsIgnoreCase(manifest.at("/artifact/sha256").asText())) {
            throw new ModelContractException("MODEL_MANIFEST_HASH_MISMATCH");
        }
        JsonNode labels = manifest.has("label_mapping") ? manifest.path("label_mapping") : manifest.path("labels");
        String normal = labels.isObject() ? labels.path("0").asText() : "";
        String attack = labels.isObject() ? labels.path("1").asText() : "";
        if (!"Normal".equalsIgnoreCase(normal) || !"Attack".equalsIgnoreCase(attack)) {
            throw new ModelContractException("MODEL_LABEL_CONTRACT_MISMATCH");
        }
        JsonNode threshold = manifest.has("threshold") ? manifest.path("threshold") : manifest.at("/decision/threshold");
        if (!threshold.isNumber() || threshold.asDouble() < 0 || threshold.asDouble() > 1) {
            throw new ModelContractException("MODEL_THRESHOLD_CONTRACT_MISMATCH");
        }
        // 输入维度、字段顺序与单位由 ModelInputContract 与已注册契约交叉核对，不再使用固定常量。
    }

    private void verifyChecksums(JsonNode checksums, Path delivery, Path root, Path model) throws IOException {
        if (!checksums.isObject() || checksums.isEmpty()) throw new ModelContractException("MODEL_CHECKSUMS_INVALID");
        java.util.Iterator<java.util.Map.Entry<String, JsonNode>> entries = checksums.fields();
        boolean modelFound = false;
        while (entries.hasNext()) {
            var entry = entries.next();
            String relative = entry.getKey();
            JsonNode declared = entry.getValue().isObject() ? entry.getValue().path("sha256") : entry.getValue();
            if (!declared.isTextual() || !relative.matches("[A-Za-z0-9._/-]{1,512}")) {
                throw new ModelContractException("MODEL_CHECKSUMS_INVALID");
            }
            Path path = delivery.resolve(relative).normalize().toRealPath();
            if (!path.startsWith(delivery) || !path.startsWith(root) || !Files.isRegularFile(path)
                    || !sha256(path).equalsIgnoreCase(declared.asText())) {
                throw new ModelContractException("MODEL_CHECKSUMS_MISMATCH");
            }
            if (path.equals(model)) modelFound = true;
        }
        if (!modelFound) throw new ModelContractException("MODEL_CHECKSUMS_MISMATCH");
    }

    /**
     * 核对 preprocessing.json：文件须位于受控根目录、哈希与 manifest {@code files} 声明一致（若声明），
     * 再与 manifest、已注册特征契约交叉核对，产出模型输入契约（路线 B §9.1 第 2、4 项）。
     */
    private ModelInputContract verifyPreprocessingContract(Path model, Path root, JsonNode manifest) throws IOException {
        Path file = model.resolveSibling("preprocessing.json").toRealPath();
        if (!file.startsWith(root) || !Files.isRegularFile(file)) throw new ModelContractException("MODEL_PREPROCESSING_CONTRACT_MISMATCH");
        JsonNode declared = manifest.at("/files/preprocessing.json");
        if (!declared.isMissingNode() && (!declared.isTextual() || !declared.asText().equalsIgnoreCase(sha256(file)))) {
            throw new ModelContractException("MODEL_PREPROCESSING_HASH_MISMATCH");
        }
        JsonNode preprocessing = objectMapper.readTree(file.toFile());
        String version = manifest.at("/feature_contract/version").asText("");
        return ModelInputContract.from(manifest, preprocessing, contracts.find(version));
    }

    private static boolean hasOpset17(JsonNode opset) {
        return opset.isNumber() && opset.asInt() == 17
                || opset.isObject() && (opset.path("").asInt(-1) == 17 || opset.path("ai.onnx").asInt(-1) == 17);
    }

    private static boolean jsonEquivalent(JsonNode left, JsonNode right) {
        if (left == right) return true;
        if (left == null || right == null || left.isMissingNode() || right.isMissingNode()
                || left.getNodeType() != right.getNodeType()) return false;
        if (left.isNumber()) {
            double a = left.asDouble();
            double b = right.asDouble();
            if (!Double.isFinite(a) || !Double.isFinite(b)) return left.equals(right);
            double scale = Math.max(Math.abs(a), Math.abs(b));
            return Math.abs(a - b) <= Math.max(Math.ulp(scale) * 4, 1e-15);
        }
        if (left.isObject()) {
            if (left.size() != right.size()) return false;
            var fields = left.fieldNames();
            while (fields.hasNext()) {
                String name = fields.next();
                if (!jsonEquivalent(left.get(name), right.get(name))) return false;
            }
            return true;
        }
        if (left.isArray()) {
            if (left.size() != right.size()) return false;
            for (int i = 0; i < left.size(); i++) {
                if (!jsonEquivalent(left.get(i), right.get(i))) return false;
            }
            return true;
        }
        return left.equals(right);
    }

    private static String firstText(JsonNode... values) {
        for (JsonNode value : values) if (value.isTextual()) return value.asText();
        return "";
    }

    private static String sha256(Path file) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (var stream = Files.newInputStream(file)) {
                byte[] buffer = new byte[64 * 1024];
                for (int count; (count = stream.read(buffer)) >= 0;) digest.update(buffer, 0, count);
            }
            return HexFormat.of().formatHex(digest.digest()).toLowerCase(Locale.ROOT);
        } catch (java.security.NoSuchAlgorithmException exception) {
            throw new IllegalStateException(exception);
        }
    }

    /** @param inputs 已与 preprocessing.json、注册契约交叉核对的模型输入契约 */
    public record VerifiedArtifact(Path modelPath, JsonNode manifest, String sha256, ModelInputContract inputs) { }
}
