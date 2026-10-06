package com.spinids.detection;

import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Data model encapsulating the inference outcome of the SPIN-IDS CNN model for a sequential window.
 */
public class DetectionResult {

    private final String pcapFile;
    private final int windowIndex;
    private final String flowKey;
    private final String predictedLabel;
    private final double normalProbability;
    private final double maliciousProbability;
    private final double confidence;
    private final String timestamp;

    public DetectionResult(String pcapFile, int windowIndex, String flowKey,
                           String predictedLabel, double normalProbability,
                           double maliciousProbability, double confidence, String timestamp) {
        this.pcapFile = pcapFile != null ? pcapFile : "unknown";
        this.windowIndex = windowIndex;
        this.flowKey = flowKey != null ? flowKey : "unknown";
        this.predictedLabel = predictedLabel != null ? predictedLabel : "NORMAL";
        this.normalProbability = normalProbability;
        this.maliciousProbability = maliciousProbability;
        this.confidence = confidence;
        this.timestamp = (timestamp != null && !timestamp.isEmpty())
                ? timestamp
                : new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(new Date());
    }

    public String getPcapFile() {
        return pcapFile;
    }

    public int getWindowIndex() {
        return windowIndex;
    }

    public String getFlowKey() {
        return flowKey;
    }

    public String getPredictedLabel() {
        return predictedLabel;
    }

    public double getNormalProbability() {
        return normalProbability;
    }

    public double getMaliciousProbability() {
        return maliciousProbability;
    }

    public double getConfidence() {
        return confidence;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public boolean isMalicious() {
        return "MALICIOUS".equalsIgnoreCase(predictedLabel);
    }

    @Override
    public String toString() {
        return String.format("DetectionResult[window=%d, prediction=%s, conf=%.2f%%, normal=%.4f, malicious=%.4f]",
                windowIndex, predictedLabel, confidence * 100.0, normalProbability, maliciousProbability);
    }
}
