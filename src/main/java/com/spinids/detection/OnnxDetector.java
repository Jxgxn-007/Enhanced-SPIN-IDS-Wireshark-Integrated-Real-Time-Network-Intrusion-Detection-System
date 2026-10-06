package com.spinids.detection;

import ai.onnxruntime.OnnxTensor;
import ai.onnxruntime.OrtEnvironment;
import ai.onnxruntime.OrtException;
import ai.onnxruntime.OrtSession;

import java.awt.image.BufferedImage;
import java.io.File;
import java.io.FileNotFoundException;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.Date;
import java.util.Map;

/**
 * Executes CNN inference on 27x27 sequential packet images using the trained ONNX model.
 */
public class OnnxDetector implements AutoCloseable {

    public static final String DEFAULT_MODEL_PATH = "ml/models/spin_ids_cnn.onnx";
    public static final String LABEL_NORMAL = "NORMAL";
    public static final String LABEL_MALICIOUS = "MALICIOUS";

    public static final int IMAGE_WIDTH = 27;
    public static final int IMAGE_HEIGHT = 27;
    public static final int CHANNELS = 3;

    private final OrtEnvironment env;
    private final OrtSession session;
    private final String inputName;

    /**
     * Initializes the detector using the default model path (ml/models/spin_ids_cnn.onnx).
     *
     * @throws OrtException if ONNX Runtime fails to initialize
     * @throws FileNotFoundException if the model file does not exist
     */
    public OnnxDetector() throws OrtException, FileNotFoundException {
        this(resolveModelPath(DEFAULT_MODEL_PATH));
    }

    /**
     * Initializes the detector with a custom ONNX model path.
     *
     * @param modelPath path to the .onnx model file
     * @throws OrtException if ONNX Runtime fails to initialize
     * @throws FileNotFoundException if the model file does not exist
     */
    public OnnxDetector(String modelPath) throws OrtException, FileNotFoundException {
        File modelFile = new File(modelPath);
        if (!modelFile.exists()) {
            throw new FileNotFoundException("ONNX model not found at: " + modelFile.getAbsolutePath());
        }

        this.env = OrtEnvironment.getEnvironment();
        OrtSession.SessionOptions options = new OrtSession.SessionOptions();
        this.session = env.createSession(modelFile.getAbsolutePath(), options);

        if (session.getInputNames().isEmpty()) {
            throw new IllegalStateException("ONNX model has no inputs");
        }
        this.inputName = session.getInputNames().iterator().next();
    }

    private static String resolveModelPath(String defaultPath) {
        File f = new File(defaultPath);
        if (f.exists()) return defaultPath;

        // Try parent directory lookup if running from child directory
        File parentAttempt = new File("..", defaultPath);
        if (parentAttempt.exists()) return parentAttempt.getPath();

        return defaultPath;
    }

    /**
     * Runs CNN inference on a 27x27 RGB BufferedImage.
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
                float normalProb = probabilities[0][0];
                float maliciousProb = probabilities[0][1];

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
        }
    }

    public String getInputName() {
        return inputName;
    }

    @Override
    public void close() {
        if (session != null) {
            try {
                session.close();
            } catch (OrtException ignored) {}
        }
        if (env != null) {
            try {
                env.close();
            } catch (Exception ignored) {}
        }
    }
}
