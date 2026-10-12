package com.spinids.detection;

import ai.onnxruntime.OnnxTensor;
import ai.onnxruntime.OrtEnvironment;
import ai.onnxruntime.OrtException;
import ai.onnxruntime.OrtSession;
import com.spinids.image.CicIdsBytePreprocessor;
import com.spinids.image.PacketImageBuilder;
import com.spinids.image.SequentialPacketWindow;

import java.awt.image.BufferedImage;
import java.io.File;
import java.io.FileNotFoundException;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.Date;
import java.util.Map;

/**
 * Executes CNN inference using ONNX Runtime for 2D RGB packet images (default),
 * 1D sequential byte streams (CIC-IDS2017 Byte 1D CNN), and HYBRID dual-branch score fusion.
 */
public class OnnxDetector implements AutoCloseable {

    public static final String DEFAULT_MODEL_PATH = "ml/models/spin_ids_cnn.onnx";
    public static final String DEFAULT_BYTE_MODEL_PATH = "ml/models/cic_ids2017_byte/best_byte_cnn.onnx";
    public static final String LABEL_NORMAL = "NORMAL";
    public static final String LABEL_MALICIOUS = "MALICIOUS";

    public static final int IMAGE_WIDTH = 27;
    public static final int IMAGE_HEIGHT = 27;
    public static final int CHANNELS = 3;
    public static final int BYTE_TENSOR_LENGTH = CicIdsBytePreprocessor.WINDOW_BYTES; // 2,187 bytes

    public static final double DEFAULT_FUSION_ALPHA = 1.0;
    public static final double DEFAULT_FUSION_THRESHOLD = 0.9;

    public enum ModelType {
        RGB_IMAGE,
        BYTE_1D,
        HYBRID
    }

    private final OrtEnvironment env;
    private final OrtSession session;
    private final String inputName;
    private final ModelType modelType;
    private final String modelPath;

    // Dual-branch secondary session and fusion configuration
    private final OrtSession byteSession;
    private final String byteInputName;
    private final String byteModelPath;
    private final double fusionAlpha;
    private final double fusionThreshold;

    /**
     * Initializes the detector using the default RGB model path (ml/models/spin_ids_cnn.onnx).
     *
     * @throws OrtException if ONNX Runtime fails to initialize
     * @throws FileNotFoundException if the model file does not exist
     */
    public OnnxDetector() throws OrtException, FileNotFoundException {
        this(resolveModelPath(DEFAULT_MODEL_PATH), ModelType.RGB_IMAGE);
    }

    /**
     * Initializes the detector with a custom ONNX model path, automatically inferring
     * model type from file name (defaults to RGB_IMAGE unless path contains 'byte').
     *
     * @param modelPath path to the .onnx model file
     * @throws OrtException if ONNX Runtime fails to initialize
     * @throws FileNotFoundException if the model file does not exist
     */
    public OnnxDetector(String modelPath) throws OrtException, FileNotFoundException {
        this(modelPath, (modelPath != null && (modelPath.toLowerCase().contains("byte")))
                ? ModelType.BYTE_1D
                : ModelType.RGB_IMAGE);
    }

    /**
     * Initializes the detector with an explicit model path and model type.
     *
     * @param modelPath path to the .onnx model file
     * @param modelType type of model (RGB_IMAGE, BYTE_1D, or HYBRID)
     * @throws OrtException if ONNX Runtime fails to initialize
     * @throws FileNotFoundException if the model file does not exist
     */
    public OnnxDetector(String modelPath, ModelType modelType) throws OrtException, FileNotFoundException {
        this(modelPath,
             (modelType == ModelType.HYBRID) ? resolveModelPath(DEFAULT_BYTE_MODEL_PATH) : null,
             modelType,
             parseDoubleProperty("spinids.fusion.alpha", DEFAULT_FUSION_ALPHA),
             parseDoubleProperty("spinids.fusion.threshold", DEFAULT_FUSION_THRESHOLD));
    }

    /**
     * Initializes a dual-branch HYBRID detector with custom model paths and fusion parameters.
     *
     * @param rgbModelPath    path to the 2D RGB ONNX model
     * @param byteModelPath   path to the 1D Byte ONNX model
     * @param fusionAlpha     score fusion weight for RGB branch [0.0, 1.0]
     * @param fusionThreshold decision threshold for malicious classification [0.0, 1.0]
     * @throws OrtException if ONNX Runtime fails to initialize
     * @throws FileNotFoundException if a model file does not exist
     */
    public OnnxDetector(String rgbModelPath, String byteModelPath, double fusionAlpha, double fusionThreshold)
            throws OrtException, FileNotFoundException {
        this(rgbModelPath, byteModelPath, ModelType.HYBRID, fusionAlpha, fusionThreshold);
    }

    /**
     * Initializes a dual-branch HYBRID detector with custom model paths and default fusion parameters.
     *
     * @param rgbModelPath  path to the 2D RGB ONNX model
     * @param byteModelPath path to the 1D Byte ONNX model
     * @throws OrtException if ONNX Runtime fails to initialize
     * @throws FileNotFoundException if a model file does not exist
     */
    public OnnxDetector(String rgbModelPath, String byteModelPath) throws OrtException, FileNotFoundException {
        this(rgbModelPath, byteModelPath,
                parseDoubleProperty("spinids.fusion.alpha", DEFAULT_FUSION_ALPHA),
                parseDoubleProperty("spinids.fusion.threshold", DEFAULT_FUSION_THRESHOLD));
    }

    private OnnxDetector(String modelPath, String byteModelPath, ModelType modelType,
                         double fusionAlpha, double fusionThreshold) throws OrtException, FileNotFoundException {
        this.modelType = (modelType != null) ? modelType : ModelType.RGB_IMAGE;
        this.fusionAlpha = fusionAlpha;
        this.fusionThreshold = fusionThreshold;
        this.env = OrtEnvironment.getEnvironment();
        OrtSession.SessionOptions options = new OrtSession.SessionOptions();

        if (this.modelType == ModelType.HYBRID) {
            String resolvedRgb = resolveModelPath(modelPath != null ? modelPath : DEFAULT_MODEL_PATH);
            File rgbFile = new File(resolvedRgb);
            if (!rgbFile.exists()) {
                throw new FileNotFoundException("RGB ONNX model not found at: " + rgbFile.getAbsolutePath());
            }
            this.modelPath = resolvedRgb;
            this.session = env.createSession(rgbFile.getAbsolutePath(), options);
            if (session.getInputNames().isEmpty()) {
                throw new IllegalStateException("RGB ONNX model has no inputs");
            }
            this.inputName = session.getInputNames().iterator().next();

            String resolvedByte = resolveModelPath(byteModelPath != null ? byteModelPath : DEFAULT_BYTE_MODEL_PATH);
            File byteFile = new File(resolvedByte);
            if (!byteFile.exists()) {
                session.close();
                throw new FileNotFoundException("Byte ONNX model not found at: " + byteFile.getAbsolutePath());
            }
            this.byteModelPath = resolvedByte;
            this.byteSession = env.createSession(byteFile.getAbsolutePath(), options);
            if (byteSession.getInputNames().isEmpty()) {
                session.close();
                byteSession.close();
                throw new IllegalStateException("Byte ONNX model has no inputs");
            }
            this.byteInputName = byteSession.getInputNames().iterator().next();
        } else {
            String resolvedPath = resolveModelPath(modelPath);
            File modelFile = new File(resolvedPath);
            if (!modelFile.exists()) {
                throw new FileNotFoundException("ONNX model not found at: " + modelFile.getAbsolutePath());
            }
            this.modelPath = resolvedPath;
            this.byteModelPath = null;
            this.session = env.createSession(modelFile.getAbsolutePath(), options);
            if (session.getInputNames().isEmpty()) {
                throw new IllegalStateException("ONNX model has no inputs");
            }
            this.inputName = session.getInputNames().iterator().next();
            this.byteSession = null;
            this.byteInputName = null;
        }
    }

    /**
     * Creates an ONNX detector configured for 2D RGB packet images (default).
     */
    public static OnnxDetector createRgbDetector() throws OrtException, FileNotFoundException {
        return new OnnxDetector(resolveModelPath(DEFAULT_MODEL_PATH), ModelType.RGB_IMAGE);
    }

    /**
     * Creates an ONNX detector configured for the 1D Byte CNN model (CIC-IDS2017).
     */
    public static OnnxDetector createByteDetector() throws OrtException, FileNotFoundException {
        return new OnnxDetector(resolveModelPath(DEFAULT_BYTE_MODEL_PATH), ModelType.BYTE_1D);
    }

    /**
     * Creates an ONNX detector configured for HYBRID dual-branch score fusion.
     * Uses system properties "spinids.fusion.alpha" (default 1.0) and "spinids.fusion.threshold" (default 0.9).
     */
    public static OnnxDetector createHybridDetector() throws OrtException, FileNotFoundException {
        double alpha = parseDoubleProperty("spinids.fusion.alpha", DEFAULT_FUSION_ALPHA);
        double threshold = parseDoubleProperty("spinids.fusion.threshold", DEFAULT_FUSION_THRESHOLD);
        return new OnnxDetector(resolveModelPath(DEFAULT_MODEL_PATH), resolveModelPath(DEFAULT_BYTE_MODEL_PATH), alpha, threshold);
    }

    /**
     * Creates an ONNX detector configured for HYBRID dual-branch score fusion with explicit weights.
     */
    public static OnnxDetector createHybridDetector(double alpha, double threshold) throws OrtException, FileNotFoundException {
        return new OnnxDetector(resolveModelPath(DEFAULT_MODEL_PATH), resolveModelPath(DEFAULT_BYTE_MODEL_PATH), alpha, threshold);
    }

    /**
     * Creates an ONNX detector configured for HYBRID dual-branch score fusion with custom model paths and weights.
     */
    public static OnnxDetector createHybridDetector(String rgbPath, String bytePath, double alpha, double threshold)
            throws OrtException, FileNotFoundException {
        return new OnnxDetector(rgbPath, bytePath, alpha, threshold);
    }

    /**
     * Creates an ONNX detector using the default configuration (RGB image model).
     */
    public static OnnxDetector createDefaultDetector() throws OrtException, FileNotFoundException {
        return new OnnxDetector();
    }

    public static String resolveModelPath(String defaultPath) {
        if (defaultPath == null) return null;
        File f = new File(defaultPath);
        if (f.exists()) return defaultPath;

        // Try parent directory lookup if running from child directory
        File parentAttempt = new File("..", defaultPath);
        if (parentAttempt.exists()) return parentAttempt.getPath();

        return defaultPath;
    }

    private static double parseDoubleProperty(String propName, double defaultValue) {
        String val = System.getProperty(propName);
        if (val != null) {
            try {
                return Double.parseDouble(val.trim());
            } catch (NumberFormatException ignored) {}
        }
        return defaultValue;
    }

    /**
     * Runs CNN inference on a 27x27 RGB BufferedImage (RGB_IMAGE mode).
     *
     * @param image       27x27 BufferedImage
     * @param windowIndex index of the sequential window
     * @param flowKey     identifier of the packet conversation
     * @param pcapFile    source PCAP filename
     * @return DetectionResult containing predictions, probabilities, and confidence
     * @throws OrtException if inference fails
     */
    public DetectionResult detect(BufferedImage image, int windowIndex, String flowKey, String pcapFile) throws OrtException {
        if (image == null) {
            throw new IllegalArgumentException("Image cannot be null");
        }
        if (modelType != ModelType.RGB_IMAGE) {
            throw new UnsupportedOperationException("Detector is configured for " + modelType
                    + " (" + modelPath + "). Use detect(SequentialPacketWindow, ...) or detectBytes(...) instead.");
        }

        float[] probs = runRgbInference(image);
        return createDetectionResult(probs[0], probs[1], windowIndex, flowKey, pcapFile);
    }

    private float[] runRgbInference(BufferedImage image) throws OrtException {
        if (image == null) {
            throw new IllegalArgumentException("Image cannot be null");
        }
        float[][][][] inputTensor = new float[1][IMAGE_HEIGHT][IMAGE_WIDTH][CHANNELS];

        for (int y = 0; y < IMAGE_HEIGHT; y++) {
            for (int x = 0; x < IMAGE_WIDTH; x++) {
                int rgb = (x < image.getWidth() && y < image.getHeight()) ? image.getRGB(x, y) : 0;
                float r = ((rgb >> 16) & 0xFF) / 255.0f;
                float g = ((rgb >> 8) & 0xFF) / 255.0f;
                float b = (rgb & 0xFF) / 255.0f;

                inputTensor[0][y][x][0] = r;
                inputTensor[0][y][x][1] = g;
                inputTensor[0][y][x][2] = b;
            }
        }

        try (OnnxTensor tensor = OnnxTensor.createTensor(env, inputTensor)) {
            Map<String, OnnxTensor> inputs = Collections.singletonMap(inputName, tensor);
            try (OrtSession.Result result = session.run(inputs)) {
                float[][] probabilities = (float[][]) result.get(0).getValue();
                return new float[] { probabilities[0][0], probabilities[0][1] };
            }
        }
    }

    /**
     * Runs 1D CNN inference on a normalized byte tensor of shape [1, 1, 2187] (BYTE_1D mode).
     * Applies numerically stable Softmax to model logits.
     *
     * @param inputTensor normalized float32 tensor of shape [1][1][2187]
     * @param windowIndex index of the sequential window
     * @param flowKey     identifier of the packet conversation
     * @param pcapFile    source PCAP filename
     * @return DetectionResult containing predictions, probabilities, and confidence
     * @throws OrtException if inference fails
     */
    public DetectionResult detectBytes(float[][][] inputTensor, int windowIndex, String flowKey, String pcapFile) throws OrtException {
        if (inputTensor == null || inputTensor.length != 1 || inputTensor[0].length != 1
                || inputTensor[0][0].length != BYTE_TENSOR_LENGTH) {
            throw new IllegalArgumentException("Byte tensor must have shape [1][1][" + BYTE_TENSOR_LENGTH + "]");
        }
        if (modelType != ModelType.BYTE_1D) {
            throw new UnsupportedOperationException("Detector is configured for " + modelType
                    + " (" + modelPath + "). Use detect(SequentialPacketWindow, ...) or detect(BufferedImage, ...) instead.");
        }

        float[] probs = runByteInference(inputTensor);
        return createDetectionResult(probs[0], probs[1], windowIndex, flowKey, pcapFile);
    }

    private float[] runByteInference(float[][][] inputTensor) throws OrtException {
        if (inputTensor == null || inputTensor.length != 1 || inputTensor[0].length != 1
                || inputTensor[0][0].length != BYTE_TENSOR_LENGTH) {
            throw new IllegalArgumentException("Byte tensor must have shape [1][1][" + BYTE_TENSOR_LENGTH + "]");
        }

        OrtSession targetSession = (byteSession != null) ? byteSession : session;
        String targetInputName = (byteInputName != null) ? byteInputName : inputName;

        try (OnnxTensor tensor = OnnxTensor.createTensor(env, inputTensor)) {
            Map<String, OnnxTensor> inputs = Collections.singletonMap(targetInputName, tensor);
            try (OrtSession.Result result = targetSession.run(inputs)) {
                float[][] rawLogits = (float[][]) result.get(0).getValue();
                float logit0 = rawLogits[0][0];
                float logit1 = rawLogits[0][1];

                // Numerically stable Softmax: p_i = exp(z_i - max(z)) / sum(exp(z - max(z)))
                float maxLogit = Math.max(logit0, logit1);
                float exp0 = (float) Math.exp(logit0 - maxLogit);
                float exp1 = (float) Math.exp(logit1 - maxLogit);
                float sum = exp0 + exp1;
                return new float[] { exp0 / sum, exp1 / sum };
            }
        }
    }

    /**
     * Polymorphic inference method accepting a {@link SequentialPacketWindow}.
     * Automatically routes to 2D RGB image, 1D byte sequence, or HYBRID dual-branch inference
     * based on configured {@link ModelType}.
     *
     * @param window      sequential packet window
     * @param windowIndex index of the sequential window
     * @param flowKey     identifier of the packet conversation
     * @param pcapFile    source PCAP filename
     * @return DetectionResult containing predictions, probabilities, and confidence
     * @throws OrtException if inference fails
     */
    public DetectionResult detect(SequentialPacketWindow window, int windowIndex, String flowKey, String pcapFile) throws OrtException {
        if (window == null) {
            throw new IllegalArgumentException("SequentialPacketWindow cannot be null");
        }

        if (modelType == ModelType.BYTE_1D) {
            if (!window.isFull()) {
                throw new IllegalArgumentException(String.format(
                        "Byte 1D CNN model requires a complete %d-packet window, but received incomplete window with %d packet(s) for flow %s. Incomplete tail windows must be skipped or buffered to prevent distribution mismatch.",
                        window.getTargetWindowSize(), window.size(), window.getFlowId()));
            }
            float[][][] byteTensor = CicIdsBytePreprocessor.extractNormalizedTensor(window);
            return detectBytes(byteTensor, windowIndex, flowKey, pcapFile);
        } else if (modelType == ModelType.HYBRID) {
            if (!window.isFull()) {
                throw new IllegalArgumentException(String.format(
                        "HYBRID model requires a complete %d-packet window, but received incomplete window with %d packet(s) for flow %s. Incomplete tail windows must be skipped or buffered to prevent distribution mismatch.",
                        window.getTargetWindowSize(), window.size(), window.getFlowId()));
            }
            // Execute RGB Branch
            BufferedImage image = PacketImageBuilder.buildImage(window);
            float[] rgbProbs = runRgbInference(image);

            // Execute Byte Branch
            float[][][] byteTensor = CicIdsBytePreprocessor.extractNormalizedTensor(window);
            float[] byteProbs = runByteInference(byteTensor);

            return fusePredictions(rgbProbs[0], rgbProbs[1], byteProbs[0], byteProbs[1],
                    windowIndex, flowKey, pcapFile);
        } else {
            BufferedImage image = PacketImageBuilder.buildImage(window);
            return detect(image, windowIndex, flowKey, pcapFile);
        }
    }

    /**
     * Convenience method executing inference directly on a {@link SequentialPacketWindow}
     * using its embedded window index and flow ID.
     *
     * @param window   sequential packet window
     * @param pcapFile source PCAP filename
     * @return DetectionResult containing predictions, probabilities, and confidence
     * @throws OrtException if inference fails
     */
    public DetectionResult detect(SequentialPacketWindow window, String pcapFile) throws OrtException {
        if (window == null) {
            throw new IllegalArgumentException("SequentialPacketWindow cannot be null");
        }
        return detect(window, window.getWindowIndex(), window.getFlowId(), pcapFile);
    }

    private DetectionResult createDetectionResult(float normalProb, float maliciousProb,
                                                  int windowIndex, String flowKey, String pcapFile) {
        String predictedLabel;
        double confidence;

        if (maliciousProb > normalProb) {
            predictedLabel = LABEL_MALICIOUS;
            confidence = maliciousProb;
        } else {
            predictedLabel = LABEL_NORMAL;
            confidence = normalProb;
        }

        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(new Date());

        return new DetectionResult(
                pcapFile,
                windowIndex,
                flowKey,
                predictedLabel,
                normalProb,
                maliciousProb,
                confidence,
                timestamp
        );
    }

    private DetectionResult fusePredictions(float rgbNormalProb, float rgbMaliciousProb,
                                            float byteNormalProb, float byteMaliciousProb,
                                            int windowIndex, String flowKey, String pcapFile) {
        // Individual branch decisions (threshold 0.5)
        String rgbLabel = (rgbMaliciousProb > rgbNormalProb) ? LABEL_MALICIOUS : LABEL_NORMAL;
        double rgbConf = (rgbMaliciousProb > rgbNormalProb) ? rgbMaliciousProb : rgbNormalProb;

        String byteLabel = (byteMaliciousProb > byteNormalProb) ? LABEL_MALICIOUS : LABEL_NORMAL;
        double byteConf = (byteMaliciousProb > byteNormalProb) ? byteMaliciousProb : byteNormalProb;

        // Correlation status between the two independent branches
        DetectionResult.CorrelationStatus status;
        if (LABEL_NORMAL.equals(rgbLabel) && LABEL_NORMAL.equals(byteLabel)) {
            status = DetectionResult.CorrelationStatus.AGREEMENT_NORMAL;
        } else if (LABEL_MALICIOUS.equals(rgbLabel) && LABEL_MALICIOUS.equals(byteLabel)) {
            status = DetectionResult.CorrelationStatus.AGREEMENT_MALICIOUS;
        } else {
            status = DetectionResult.CorrelationStatus.CONFLICT_RESOLVED;
        }

        // Fused probability formula matching Python evaluate_cic_ids2017_hybrid.py:
        // fused_malicious_prob = alpha * rgb_malicious_prob + (1 - alpha) * byte_malicious_prob
        // Note: For validation-selected alpha = 1.0, fused_malicious_prob == rgb_malicious_prob,
        // which effectively gives the Byte branch zero weight in the numeric score while still
        // performing full independent inference and correlation monitoring.
        double fusedMalicious = (fusionAlpha * rgbMaliciousProb) + ((1.0 - fusionAlpha) * byteMaliciousProb);
        fusedMalicious = Math.max(0.0, Math.min(1.0, fusedMalicious));
        double fusedNormal = 1.0 - fusedMalicious;

        // Final prediction classification against configured decision threshold (default 0.9)
        String finalLabel;
        double finalConf;
        if (fusedMalicious >= fusionThreshold) {
            finalLabel = LABEL_MALICIOUS;
            finalConf = fusedMalicious;
        } else {
            finalLabel = LABEL_NORMAL;
            finalConf = fusedNormal;
        }

        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(new Date());

        return new DetectionResult(
                pcapFile,
                windowIndex,
                flowKey,
                finalLabel,
                fusedNormal,
                fusedMalicious,
                finalConf,
                timestamp,
                rgbLabel,
                rgbNormalProb,
                rgbMaliciousProb,
                rgbConf,
                byteLabel,
                byteNormalProb,
                byteMaliciousProb,
                byteConf,
                status,
                fusedMalicious,
                fusionAlpha,
                fusionThreshold
        );
    }

    public ModelType getModelType() {
        return modelType;
    }

    public String getModelPath() {
        return modelPath;
    }

    public String getByteModelPath() {
        return byteModelPath;
    }

    public double getFusionAlpha() {
        return fusionAlpha;
    }

    public double getFusionThreshold() {
        return fusionThreshold;
    }

    public String getInputName() {
        return inputName;
    }

    public String getByteInputName() {
        return byteInputName;
    }

    public String getModelDescription() {
        if (modelType == ModelType.BYTE_1D) {
            return "best_byte_cnn.onnx (1x1x2187 Byte 1D)";
        } else if (modelType == ModelType.HYBRID) {
            return String.format("HYBRID[RGB=%s, BYTE=%s | alpha=%.2f, thresh=%.2f]",
                    new File(modelPath).getName(),
                    new File(byteModelPath).getName(),
                    fusionAlpha, fusionThreshold);
        } else {
            return "spin_ids_cnn.onnx (27x27x3 RGB)";
        }
    }

    @Override
    public void close() {
        if (session != null) {
            try {
                session.close();
            } catch (OrtException ignored) {}
        }
        if (byteSession != null) {
            try {
                byteSession.close();
            } catch (OrtException ignored) {}
        }
        if (env != null) {
            try {
                env.close();
            } catch (Exception ignored) {}
        }
    }
}

