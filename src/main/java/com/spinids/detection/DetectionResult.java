package com.spinids.detection;

import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Data model encapsulating the inference outcome of the SPIN-IDS CNN model for a sequential window.
 */
public class DetectionResult {

    public enum CorrelationStatus {
        AGREEMENT_NORMAL,
        AGREEMENT_MALICIOUS,
        CONFLICT_RESOLVED,
        SINGLE_BRANCH
    }

    private final String pcapFile;
    private final int windowIndex;
    private final String flowKey;
    private final String predictedLabel;
    private final double normalProbability;
    private final double maliciousProbability;
    private final double confidence;
    private final String timestamp;

    // Dual-branch inference and correlation metadata
    private final String rgbPredictedLabel;
    private final double rgbNormalProbability;
    private final double rgbMaliciousProbability;
    private final double rgbConfidence;

    private final String bytePredictedLabel;
    private final double byteNormalProbability;
    private final double byteMaliciousProbability;
    private final double byteConfidence;

    private final CorrelationStatus correlationStatus;
    private final double fusedMaliciousProbability;
    private final double fusionAlpha;
    private final double fusionThreshold;

    /**
     * Backward-compatible 8-argument constructor for single-branch detectors.
     */
    public DetectionResult(String pcapFile, int windowIndex, String flowKey,
                           String predictedLabel, double normalProbability,
                           double maliciousProbability, double confidence, String timestamp) {
        this(pcapFile, windowIndex, flowKey, predictedLabel, normalProbability, maliciousProbability, confidence, timestamp,
                predictedLabel, normalProbability, maliciousProbability, confidence,
                null, 0.0, 0.0, 0.0,
                CorrelationStatus.SINGLE_BRANCH, maliciousProbability, 1.0, 0.5);
    }

    /**
     * Dual-branch constructor encapsulating RGB, Byte, and score-fusion correlation outcomes with default fusion parameters.
     */
    public DetectionResult(String pcapFile, int windowIndex, String flowKey,
                           String predictedLabel, double normalProbability,
                           double maliciousProbability, double confidence, String timestamp,
                           String rgbPredictedLabel, double rgbNormalProbability,
                           double rgbMaliciousProbability, double rgbConfidence,
                           String bytePredictedLabel, double byteNormalProbability,
                           double byteMaliciousProbability, double byteConfidence,
                           CorrelationStatus correlationStatus, double fusedMaliciousProbability) {
        this(pcapFile, windowIndex, flowKey, predictedLabel, normalProbability, maliciousProbability, confidence, timestamp,
                rgbPredictedLabel, rgbNormalProbability, rgbMaliciousProbability, rgbConfidence,
                bytePredictedLabel, byteNormalProbability, byteMaliciousProbability, byteConfidence,
                correlationStatus, fusedMaliciousProbability, 1.0, 0.9);
    }

    /**
     * Full dual-branch constructor encapsulating RGB, Byte, correlation status, and explicit fusion parameters.
     */
    public DetectionResult(String pcapFile, int windowIndex, String flowKey,
                           String predictedLabel, double normalProbability,
                           double maliciousProbability, double confidence, String timestamp,
                           String rgbPredictedLabel, double rgbNormalProbability,
                           double rgbMaliciousProbability, double rgbConfidence,
                           String bytePredictedLabel, double byteNormalProbability,
                           double byteMaliciousProbability, double byteConfidence,
                           CorrelationStatus correlationStatus, double fusedMaliciousProbability,
                           double fusionAlpha, double fusionThreshold) {
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

        this.rgbPredictedLabel = rgbPredictedLabel != null ? rgbPredictedLabel : this.predictedLabel;
        this.rgbNormalProbability = rgbNormalProbability;
        this.rgbMaliciousProbability = rgbMaliciousProbability;
        this.rgbConfidence = rgbConfidence;

        this.bytePredictedLabel = bytePredictedLabel;
        this.byteNormalProbability = byteNormalProbability;
        this.byteMaliciousProbability = byteMaliciousProbability;
        this.byteConfidence = byteConfidence;

        this.correlationStatus = correlationStatus != null ? correlationStatus : CorrelationStatus.SINGLE_BRANCH;
        this.fusedMaliciousProbability = fusedMaliciousProbability;
        this.fusionAlpha = fusionAlpha;
        this.fusionThreshold = fusionThreshold;
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

    public String getRgbPredictedLabel() {
        return rgbPredictedLabel;
    }

    public double getRgbNormalProbability() {
        return rgbNormalProbability;
    }

    public double getRgbMaliciousProbability() {
        return rgbMaliciousProbability;
    }

    public double getRgbConfidence() {
        return rgbConfidence;
    }

    public String getBytePredictedLabel() {
        return bytePredictedLabel;
    }

    public double getByteNormalProbability() {
        return byteNormalProbability;
    }

    public double getByteMaliciousProbability() {
        return byteMaliciousProbability;
    }

    public double getByteConfidence() {
        return byteConfidence;
    }

    public CorrelationStatus getCorrelationStatus() {
        return correlationStatus;
    }

    public double getFusedMaliciousProbability() {
        return fusedMaliciousProbability;
    }

    public double getFusionAlpha() {
        return fusionAlpha;
    }

    public double getFusionThreshold() {
        return fusionThreshold;
    }

    public boolean isDualBranch() {
        return correlationStatus != CorrelationStatus.SINGLE_BRANCH;
    }

    public boolean isAgreement() {
        return correlationStatus == CorrelationStatus.AGREEMENT_NORMAL
                || correlationStatus == CorrelationStatus.AGREEMENT_MALICIOUS;
    }

    public boolean isConflict() {
        return correlationStatus == CorrelationStatus.CONFLICT_RESOLVED;
    }

    @Override
    public String toString() {
        if (isDualBranch()) {
            return String.format("DetectionResult[window=%d, final=%s (conf=%.2f%%), status=%s, RGB=%s (%.2f%%), BYTE=%s (%.2f%%)]",
                    windowIndex, predictedLabel, confidence * 100.0, correlationStatus,
                    rgbPredictedLabel, rgbConfidence * 100.0,
                    bytePredictedLabel, byteConfidence * 100.0);
        }
        return String.format("DetectionResult[window=%d, prediction=%s, conf=%.2f%%, normal=%.4f, malicious=%.4f]",
                windowIndex, predictedLabel, confidence * 100.0, normalProbability, maliciousProbability);
    }
}
