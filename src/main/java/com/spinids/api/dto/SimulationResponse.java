package com.spinids.api.dto;

import java.util.List;

public class SimulationResponse {
    private boolean success;
    private String pcapFile;
    private int capturedPackets;
    private int extractedWindows;
    private boolean anomalyTriggered;
    private double burstRate;
    private List<DetectionDto> detections;

    public SimulationResponse() {}

    public SimulationResponse(boolean success, String pcapFile, int capturedPackets,
                              int extractedWindows, boolean anomalyTriggered, double burstRate,
                              List<DetectionDto> detections) {
        this.success = success;
        this.pcapFile = pcapFile;
        this.capturedPackets = capturedPackets;
        this.extractedWindows = extractedWindows;
        this.anomalyTriggered = anomalyTriggered;
        this.burstRate = burstRate;
        this.detections = detections;
    }

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public String getPcapFile() {
        return pcapFile;
    }

    public void setPcapFile(String pcapFile) {
        this.pcapFile = pcapFile;
    }

    public int getCapturedPackets() {
        return capturedPackets;
    }

    public void setCapturedPackets(int capturedPackets) {
        this.capturedPackets = capturedPackets;
    }

    public int getExtractedWindows() {
        return extractedWindows;
    }

    public void setExtractedWindows(int extractedWindows) {
        this.extractedWindows = extractedWindows;
    }

    public boolean isAnomalyTriggered() {
        return anomalyTriggered;
    }

    public void setAnomalyTriggered(boolean anomalyTriggered) {
        this.anomalyTriggered = anomalyTriggered;
    }

    public double getBurstRate() {
        return burstRate;
    }

    public void setBurstRate(double burstRate) {
        this.burstRate = burstRate;
    }

    public List<DetectionDto> getDetections() {
        return detections;
    }

    public void setDetections(List<DetectionDto> detections) {
        this.detections = detections;
    }
}
