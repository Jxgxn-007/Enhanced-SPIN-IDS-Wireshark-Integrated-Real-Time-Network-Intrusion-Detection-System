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

    public DetectionDto() {}

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
}
