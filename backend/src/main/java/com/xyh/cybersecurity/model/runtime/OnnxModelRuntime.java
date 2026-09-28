package com.xyh.cybersecurity.model.runtime;

import ai.onnxruntime.OnnxJavaType;
import ai.onnxruntime.OnnxTensor;
import ai.onnxruntime.NodeInfo;
import ai.onnxruntime.OrtEnvironment;
import ai.onnxruntime.OrtException;
import ai.onnxruntime.OrtSession;
import ai.onnxruntime.TensorInfo;
import com.xyh.cybersecurity.model.validation.ModelContractException;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** 以固定 CPU Runtime 执行 UNSW 二分类 ONNX 契约；不做缺失字段填充或模型回退。 */
public final class OnnxModelRuntime implements AutoCloseable {

    public static final String RUNTIME_VERSION = "1.23.2";
    public static final int NUMERIC_FEATURE_COUNT = 26;
    public static final int CATEGORICAL_FEATURE_COUNT = 2;
    private static final OrtEnvironment ENVIRONMENT = OrtEnvironment.getEnvironment();

    private final OrtSession session;

    private OnnxModelRuntime(OrtSession session) {
        this.session = session;
    }

    public static OnnxModelRuntime open(Path modelPath) throws OrtException {
        OrtSession.SessionOptions options = new OrtSession.SessionOptions();
        options.setIntraOpNumThreads(1);
        options.setInterOpNumThreads(1);
        options.setExecutionMode(OrtSession.SessionOptions.ExecutionMode.SEQUENTIAL);
        OrtSession session = ENVIRONMENT.createSession(modelPath.toString(), options);
        validateGraph(session);
        return new OnnxModelRuntime(session);
    }

    public List<Prediction> predict(List<FlowInput> inputs) throws OrtException {
        if (inputs.isEmpty() || inputs.size() > 1024) throw new ModelContractException("MODEL_BATCH_SIZE_INVALID");
        double[][] numeric = new double[inputs.size()][NUMERIC_FEATURE_COUNT];
        String[][] categorical = new String[inputs.size()][CATEGORICAL_FEATURE_COUNT];
        for (int row = 0; row < inputs.size(); row++) {
            FlowInput input = inputs.get(row);
            if (input.numeric().length != NUMERIC_FEATURE_COUNT || input.categorical().length != CATEGORICAL_FEATURE_COUNT) {
                throw new ModelContractException("MODEL_INPUT_CONTRACT_MISMATCH");
            }
            for (int column = 0; column < NUMERIC_FEATURE_COUNT; column++) {
                double value = input.numeric()[column];
                if (!Double.isFinite(value)) throw new ModelContractException("MODEL_INPUT_CONTRACT_MISMATCH");
                numeric[row][column] = value;
            }
            for (int column = 0; column < CATEGORICAL_FEATURE_COUNT; column++) {
                String value = input.categorical()[column];
                if (value == null || value.length() > 128) throw new ModelContractException("MODEL_INPUT_CONTRACT_MISMATCH");
                categorical[row][column] = value;
            }
        }
        try (OnnxTensor numericTensor = OnnxTensor.createTensor(ENVIRONMENT, numeric);
             OnnxTensor categoricalTensor = OnnxTensor.createTensor(ENVIRONMENT, categorical);
             OrtSession.Result result = session.run(Map.of("flow_numeric", numericTensor,
                     "flow_categorical", categoricalTensor))) {
            float[][] probabilities = matrix(result.get("attack_probability").orElseThrow().getValue(), inputs.size());
            Object labelValue = result.get("is_attack").orElseThrow().getValue();
            List<Prediction> predictions = new ArrayList<>(inputs.size());
            for (int row = 0; row < inputs.size(); row++) {
                float probability = probabilities[row][probabilities[row].length - 1];
                if (!Float.isFinite(probability) || probability < 0f || probability > 1f) {
                    throw new ModelContractException("MODEL_OUTPUT_CONTRACT_MISMATCH");
                }
                boolean label = scalar(labelValue, row) != 0;
                predictions.add(new Prediction(probability, label));
            }
            return List.copyOf(predictions);
        }
    }

    private static void validateGraph(OrtSession session) throws OrtException {
        Map<String, NodeInfo> inputs = session.getInputInfo();
        Map<String, NodeInfo> outputs = session.getOutputInfo();
        if (!inputs.keySet().equals(java.util.Set.of("flow_numeric", "flow_categorical"))
                || !outputs.keySet().containsAll(java.util.Set.of("attack_probability", "is_attack"))) {
            throw new IllegalArgumentException("MODEL_CONTRACT_MISMATCH");
        }
        TensorInfo numeric = tensorInfo(inputs.get("flow_numeric"));
        TensorInfo categorical = tensorInfo(inputs.get("flow_categorical"));
        long[] numericShape = numeric.getShape();
        long[] categoricalShape = categorical.getShape();
        if (numeric.type != OnnxJavaType.DOUBLE || numericShape.length != 2
                || numericShape[1] != NUMERIC_FEATURE_COUNT
                || categorical.type != OnnxJavaType.STRING || categoricalShape.length != 2
                || categoricalShape[1] != CATEGORICAL_FEATURE_COUNT) {
            throw new IllegalArgumentException("MODEL_CONTRACT_MISMATCH");
        }
        TensorInfo probability = tensorInfo(outputs.get("attack_probability"));
        TensorInfo label = tensorInfo(outputs.get("is_attack"));
        if (probability.type != OnnxJavaType.FLOAT || probability.getShape().length < 1
                || probability.getShape().length > 2 || label.getShape().length < 1
                || label.getShape().length > 2
                || (label.type != OnnxJavaType.BOOL && label.type != OnnxJavaType.INT32
                && label.type != OnnxJavaType.INT64)) {
            throw new IllegalArgumentException("MODEL_CONTRACT_MISMATCH");
        }
    }

    private static TensorInfo tensorInfo(NodeInfo info) {
        if (info == null || !(info.getInfo() instanceof TensorInfo tensorInfo)) {
            throw new IllegalArgumentException("MODEL_CONTRACT_MISMATCH");
        }
        return tensorInfo;
    }

    private static float[][] matrix(Object value, int expectedRows) {
        if (value instanceof float[][] matrix && matrix.length == expectedRows) return matrix;
        if (value instanceof float[] vector && vector.length == expectedRows) {
            float[][] matrix = new float[expectedRows][1];
            for (int i = 0; i < expectedRows; i++) matrix[i][0] = vector[i];
            return matrix;
        }
        throw new ModelContractException("MODEL_OUTPUT_CONTRACT_MISMATCH");
    }

    private static int scalar(Object value, int row) {
        if (value instanceof long[][] matrix) return Math.toIntExact(matrix[row][matrix[row].length - 1]);
        if (value instanceof int[][] matrix) return matrix[row][matrix[row].length - 1];
        if (value instanceof boolean[][] matrix) return matrix[row][matrix[row].length - 1] ? 1 : 0;
        if (value instanceof boolean[] vector) return vector[row] ? 1 : 0;
        if (value instanceof long[] vector) return Math.toIntExact(vector[row]);
        if (value instanceof int[] vector) return vector[row];
        throw new ModelContractException("MODEL_OUTPUT_CONTRACT_MISMATCH");
    }

    @Override public void close() throws OrtException { session.close(); }

    public record FlowInput(double[] numeric, String[] categorical) { }
    public record Prediction(float attackProbability, boolean isAttack) { }

}
