package com.spinids.api.dto;

public class DetectionDto {
    private String pcapFile;
    private int windowIndex;
    private String flowKey;
    private String prediction;
    private double normalProbability;
    private double maliciousProbability;
    private double confidence;
    private String timestamp;

    // Dual-branch RGB fields
    private String rgbPrediction;
    private double rgbNormalProbability;
    private double rgbMaliciousProbability;
    private double rgbConfidence;

    // Dual-branch Byte fields
    private String bytePrediction;
    private double byteNormalProbability;
    private double byteMaliciousProbability;
    private double byteConfidence;

    // Correlation and score-fusion metadata
    private String correlationStatus;
    private double fusedMaliciousProbability;
    private double fusionAlpha;
    private double fusionThreshold;
    private boolean dualBranch;

    public DetectionDto() {}

    /**
     * Backward-compatible 8-argument constructor for single-branch detectors.
     */
    public DetectionDto(String pcapFile, int windowIndex, String flowKey,
                        String prediction, double normalProbability,
                        double maliciousProbability, double confidence, String timestamp) {
        this.pcapFile = pcapFile;
        this.windowIndex = windowIndex;
        this.flowKey = flowKey;
        this.prediction = prediction;
        this.normalProbability = normalProbability;
        this.maliciousProbability = maliciousProbability;
        this.confidence = confidence;
        this.timestamp = timestamp;
        this.rgbPrediction = prediction;
        this.rgbNormalProbability = normalProbability;
        this.rgbMaliciousProbability = maliciousProbability;
        this.rgbConfidence = confidence;
        this.bytePrediction = null;
        this.byteNormalProbability = 0.0;
        this.byteMaliciousProbability = 0.0;
        this.byteConfidence = 0.0;
        this.correlationStatus = "SINGLE_BRANCH";
        this.fusedMaliciousProbability = maliciousProbability;
        this.fusionAlpha = 1.0;
        this.fusionThreshold = 0.5;
        this.dualBranch = false;
    }

    public String getPcapFile() {
        return pcapFile;
    }

    public void setPcapFile(String pcapFile) {
        this.pcapFile = pcapFile;
    }

    public int getWindowIndex() {
        return windowIndex;
    }

    public void setWindowIndex(int windowIndex) {
        this.windowIndex = windowIndex;
    }

    public String getFlowKey() {
        return flowKey;
    }

    public void setFlowKey(String flowKey) {
        this.flowKey = flowKey;
    }

    public String getPrediction() {
        return prediction;
    }

    public void setPrediction(String prediction) {
        this.prediction = prediction;
    }

    public double getNormalProbability() {
        return normalProbability;
    }

    public void setNormalProbability(double normalProbability) {
        this.normalProbability = normalProbability;
    }

    public double getMaliciousProbability() {
        return maliciousProbability;
    }

    public void setMaliciousProbability(double maliciousProbability) {
        this.maliciousProbability = maliciousProbability;
    }

    public double getConfidence() {
        return confidence;
    }

    public void setConfidence(double confidence) {
        this.confidence = confidence;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }

    public String getRgbPrediction() {
        return rgbPrediction;
    }

    public void setRgbPrediction(String rgbPrediction) {
        this.rgbPrediction = rgbPrediction;
    }

    public double getRgbNormalProbability() {
        return rgbNormalProbability;
    }

    public void setRgbNormalProbability(double rgbNormalProbability) {
        this.rgbNormalProbability = rgbNormalProbability;
    }

    public double getRgbMaliciousProbability() {
        return rgbMaliciousProbability;
    }

    public void setRgbMaliciousProbability(double rgbMaliciousProbability) {
        this.rgbMaliciousProbability = rgbMaliciousProbability;
    }

    public double getRgbConfidence() {
        return rgbConfidence;
    }

    public void setRgbConfidence(double rgbConfidence) {
        this.rgbConfidence = rgbConfidence;
    }

    public String getBytePrediction() {
        return bytePrediction;
    }

    public void setBytePrediction(String bytePrediction) {
        this.bytePrediction = bytePrediction;
    }

    public double getByteNormalProbability() {
        return byteNormalProbability;
    }

    public void setByteNormalProbability(double byteNormalProbability) {
        this.byteNormalProbability = byteNormalProbability;
    }

    public double getByteMaliciousProbability() {
        return byteMaliciousProbability;
    }

    public void setByteMaliciousProbability(double byteMaliciousProbability) {
        this.byteMaliciousProbability = byteMaliciousProbability;
    }

    public double getByteConfidence() {
        return byteConfidence;
    }

    public void setByteConfidence(double byteConfidence) {
        this.byteConfidence = byteConfidence;
    }

    public String getCorrelationStatus() {
        return correlationStatus;
    }

    public void setCorrelationStatus(String correlationStatus) {
        this.correlationStatus = correlationStatus;
    }

    public double getFusedMaliciousProbability() {
        return fusedMaliciousProbability;
    }

    public void setFusedMaliciousProbability(double fusedMaliciousProbability) {
        this.fusedMaliciousProbability = fusedMaliciousProbability;
    }

    public double getFusionAlpha() {
        return fusionAlpha;
    }

    public void setFusionAlpha(double fusionAlpha) {
        this.fusionAlpha = fusionAlpha;
    }

    public double getFusionThreshold() {
        return fusionThreshold;
    }

    public void setFusionThreshold(double fusionThreshold) {
        this.fusionThreshold = fusionThreshold;
    }

    public boolean isDualBranch() {
        return dualBranch;
    }

    public void setDualBranch(boolean dualBranch) {
        this.dualBranch = dualBranch;
    }
}
