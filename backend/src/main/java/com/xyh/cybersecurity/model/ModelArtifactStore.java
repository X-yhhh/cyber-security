package com.xyh.cybersecurity.model;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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

    public ModelArtifactStore(@Value("${cyber.model-artifact.root:}") String root, ObjectMapper objectMapper) {
        this.configuredRoot = root.isBlank() ? null : Path.of(root).toAbsolutePath().normalize();
        this.objectMapper = objectMapper;
    }

    public VerifiedArtifact verify(ModelService.ModelView model) {
        if (configuredRoot == null) throw new IllegalStateException("MODEL_ARTIFACT_ROOT_NOT_CONFIGURED");
        try {
            Path root = configuredRoot.toRealPath();
            Path artifact = resolveWithinRoot(model.artifactRef(), root).toRealPath();
            if (!artifact.startsWith(root) || !Files.isRegularFile(artifact) || !Files.isReadable(artifact)) {
                throw new IllegalStateException("MODEL_ARTIFACT_UNAVAILABLE");
            }
            String sha256 = sha256(artifact);
            if (!sha256.equalsIgnoreCase(model.artifactSha256())) throw new IllegalStateException("MODEL_HASH_MISMATCH");

            Path manifestPath = artifact.resolveSibling("model_manifest.json").toRealPath();
            if (!manifestPath.startsWith(root) || !Files.isRegularFile(manifestPath)) {
                throw new IllegalStateException("MODEL_MANIFEST_UNAVAILABLE");
            }
            JsonNode manifest = objectMapper.readTree(manifestPath.toFile());
            // MySQL JSON stores浮点数时可能发生 1-2 ULP 的重编码；结构、字符串和关键契约仍须完全一致。
            if (!jsonEquivalent(manifest, model.manifest())) {
                throw new IllegalStateException("MODEL_MANIFEST_SNAPSHOT_MISMATCH");
            }
            validateManifest(model, manifest);

            Path checksumsPath = artifact.resolveSibling("checksums.json");
            Path realChecksums = checksumsPath.toRealPath();
            if (!realChecksums.startsWith(root)) throw new IllegalStateException("MODEL_CHECKSUMS_PATH_INVALID");
            JsonNode checksums = objectMapper.readTree(realChecksums.toFile());
            // checksums.json 的路径相对于本次交付目录；交付目录本身仍必须位于受控根目录内。
            verifyChecksums(checksums, artifact.getParent(), root, artifact);
            verifyPreprocessingContract(artifact, manifest);
            return new VerifiedArtifact(artifact, manifest, sha256);
        } catch (IOException | SecurityException exception) {
            throw new IllegalStateException("MODEL_ARTIFACT_UNAVAILABLE");
        }
    }

    private static Path resolveWithinRoot(String artifactRef, Path root) {
        java.net.URI uri;
        try { uri = java.net.URI.create(artifactRef); }
        catch (RuntimeException exception) { throw new IllegalStateException("MODEL_ARTIFACT_REFERENCE_INVALID"); }
        String path = uri.getPath();
        String authority = uri.getRawAuthority();
        if (!"model".equals(uri.getScheme()) || authority == null
                || !authority.matches("[A-Za-z0-9._-]{1,128}") || path == null || path.isBlank()
                || uri.getUserInfo() != null || uri.getPort() != -1 || uri.getQuery() != null
                || uri.getFragment() != null) {
            throw new IllegalStateException("MODEL_ARTIFACT_REFERENCE_INVALID");
        }
        Path relative = Path.of(authority).resolve(path.startsWith("/") ? path.substring(1) : path).normalize();
        if (relative.isAbsolute() || relative.startsWith("..")) throw new IllegalStateException("MODEL_ARTIFACT_REFERENCE_INVALID");
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
            throw new IllegalStateException("MODEL_MANIFEST_CONTRACT_MISMATCH");
        }
        if (!model.artifactSha256().equalsIgnoreCase(manifest.at("/artifact/sha256").asText())) {
            throw new IllegalStateException("MODEL_MANIFEST_HASH_MISMATCH");
        }
        JsonNode labels = manifest.has("label_mapping") ? manifest.path("label_mapping") : manifest.path("labels");
        String normal = labels.isObject() ? labels.path("0").asText() : "";
        String attack = labels.isObject() ? labels.path("1").asText() : "";
        if (!"Normal".equalsIgnoreCase(normal) || !"Attack".equalsIgnoreCase(attack)) {
            throw new IllegalStateException("MODEL_LABEL_CONTRACT_MISMATCH");
        }
        JsonNode threshold = manifest.has("threshold") ? manifest.path("threshold") : manifest.at("/decision/threshold");
        if (!threshold.isNumber() || threshold.asDouble() < 0 || threshold.asDouble() > 1) {
            throw new IllegalStateException("MODEL_THRESHOLD_CONTRACT_MISMATCH");
        }
        JsonNode inputs = manifest.at("/feature_contract/inputs");
        if (!inputs.path("flow_numeric").isArray() || inputs.path("flow_numeric").size() != OnnxModelRuntime.NUMERIC_FEATURE_COUNT
                || !inputs.path("flow_categorical").isArray() || inputs.path("flow_categorical").size() != OnnxModelRuntime.CATEGORICAL_FEATURE_COUNT
                || !"proto".equals(inputs.at("/flow_categorical/0").asText())
                || !"service".equals(inputs.at("/flow_categorical/1").asText())) {
            throw new IllegalStateException("MODEL_INPUT_CONTRACT_MISMATCH");
        }
    }

    private void verifyChecksums(JsonNode checksums, Path delivery, Path root, Path model) throws IOException {
        if (!checksums.isObject() || checksums.isEmpty()) throw new IllegalStateException("MODEL_CHECKSUMS_INVALID");
        java.util.Iterator<java.util.Map.Entry<String, JsonNode>> entries = checksums.fields();
        boolean modelFound = false;
        while (entries.hasNext()) {
            var entry = entries.next();
            String relative = entry.getKey();
            JsonNode declared = entry.getValue().isObject() ? entry.getValue().path("sha256") : entry.getValue();
            if (!declared.isTextual() || !relative.matches("[A-Za-z0-9._/-]{1,512}")) {
                throw new IllegalStateException("MODEL_CHECKSUMS_INVALID");
            }
            Path path = delivery.resolve(relative).normalize().toRealPath();
            if (!path.startsWith(delivery) || !path.startsWith(root) || !Files.isRegularFile(path)
                    || !sha256(path).equalsIgnoreCase(declared.asText())) {
                throw new IllegalStateException("MODEL_CHECKSUMS_MISMATCH");
            }
            if (path.equals(model)) modelFound = true;
        }
        if (!modelFound) throw new IllegalStateException("MODEL_CHECKSUMS_MISMATCH");
    }

    private void verifyPreprocessingContract(Path model, JsonNode manifest) throws IOException {
        Path file = model.resolveSibling("preprocessing.json").toRealPath();
        JsonNode preprocessing = objectMapper.readTree(file.toFile());
        if (!manifest.at("/feature_contract/version").asText().equals(preprocessing.path("contract_version").asText())) {
            throw new IllegalStateException("MODEL_PREPROCESSING_CONTRACT_MISMATCH");
        }
        JsonNode declaredInputs = manifest.at("/feature_contract/inputs");
        for (String name : java.util.List.of("flow_numeric", "flow_categorical")) {
            JsonNode manifestFields = declaredInputs.path(name);
            JsonNode prepFields = preprocessing.at("/inputs/" + name + "/fields");
            if (!prepFields.isArray() || prepFields.size() != manifestFields.size()) {
                throw new IllegalStateException("MODEL_PREPROCESSING_CONTRACT_MISMATCH");
            }
            for (int i = 0; i < manifestFields.size(); i++) {
                if (!manifestFields.get(i).asText().equals(prepFields.get(i).path("name").asText())
                        || prepFields.get(i).path("index").asInt(-1) != i) {
                    throw new IllegalStateException("MODEL_PREPROCESSING_CONTRACT_MISMATCH");
                }
            }
        }
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

    public record VerifiedArtifact(Path modelPath, JsonNode manifest, String sha256) { }
}
