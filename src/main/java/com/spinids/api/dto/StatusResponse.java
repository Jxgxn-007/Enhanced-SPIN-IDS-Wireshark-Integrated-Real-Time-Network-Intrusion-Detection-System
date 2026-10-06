package com.spinids.api.dto;

import java.util.Map;

/**
 * Enhanced StatusResponse DTO exposing engine state, real interface monitoring telemetry,
 * active threshold, bounded capture progress, and cooldown state.
 */
public class StatusResponse {
    private String engineState;
    private double thresholdPps;
    private double currentPps;
    private boolean isAnomalous;
    private Map<String, Object> subsystems;
    private Map<String, Object> stats;

    // Extended fields for real interface monitoring
    private boolean engineRunning;
    private String monitoringMode = "REAL_INTERFACE"; // "REAL_INTERFACE" or "SIMULATION"
    private String selectedInterface;
    private String interfaceDescription;
    private long packetsCaptured;
    private String lastAnomalyTime;
    private String lastPcapFile;
    private boolean captureInProgress;
    private boolean cooldownActive;

    public StatusResponse() {}

    public StatusResponse(String engineState, double thresholdPps, double currentPps,
                          boolean isAnomalous, Map<String, Object> subsystems, Map<String, Object> stats) {
        this.engineState = engineState;
        this.thresholdPps = thresholdPps;
        this.currentPps = currentPps;
        this.isAnomalous = isAnomalous;
        this.subsystems = subsystems;
        this.stats = stats;
        this.engineRunning = "RUNNING".equalsIgnoreCase(engineState);
    }

    public String getEngineState() {
        return engineState;
    }

    public void setEngineState(String engineState) {
        this.engineState = engineState;
        this.engineRunning = "RUNNING".equalsIgnoreCase(engineState);
    }

    public double getThresholdPps() {
        return thresholdPps;
    }

    public void setThresholdPps(double thresholdPps) {
        this.thresholdPps = thresholdPps;
    }

    public double getCurrentPps() {
        return currentPps;
    }

    public void setCurrentPps(double currentPps) {
        this.currentPps = currentPps;
    }

    public boolean isAnomalous() {
        return isAnomalous;
    }

    public void setAnomalous(boolean anomalous) {
        isAnomalous = anomalous;
    }

    public Map<String, Object> getSubsystems() {
        return subsystems;
    }

    public void setSubsystems(Map<String, Object> subsystems) {
        this.subsystems = subsystems;
    }

    public Map<String, Object> getStats() {
        return stats;
    }

    public void setStats(Map<String, Object> stats) {
        this.stats = stats;
    }

    public boolean isEngineRunning() {
        return engineRunning;
    }

    public void setEngineRunning(boolean engineRunning) {
        this.engineRunning = engineRunning;
    }

    public String getMonitoringMode() {
        return monitoringMode;
    }

    public void setMonitoringMode(String monitoringMode) {
        this.monitoringMode = monitoringMode;
    }

    public String getSelectedInterface() {
        return selectedInterface;
    }

    public void setSelectedInterface(String selectedInterface) {
        this.selectedInterface = selectedInterface;
    }

    public String getInterfaceDescription() {
        return interfaceDescription;
    }

    public void setInterfaceDescription(String interfaceDescription) {
        this.interfaceDescription = interfaceDescription;
    }

    public long getPacketsCaptured() {
        return packetsCaptured;
    }

    public void setPacketsCaptured(long packetsCaptured) {
        this.packetsCaptured = packetsCaptured;
    }

    public String getLastAnomalyTime() {
        return lastAnomalyTime;
    }

    public void setLastAnomalyTime(String lastAnomalyTime) {
        this.lastAnomalyTime = lastAnomalyTime;
    }

    public String getLastPcapFile() {
        return lastPcapFile;
    }

    public void setLastPcapFile(String lastPcapFile) {
        this.lastPcapFile = lastPcapFile;
    }

    public boolean isCaptureInProgress() {
        return captureInProgress;
    }

    public void setCaptureInProgress(boolean captureInProgress) {
        this.captureInProgress = captureInProgress;
    }

    public boolean isCooldownActive() {
        return cooldownActive;
    }

    public void setCooldownActive(boolean cooldownActive) {
        this.cooldownActive = cooldownActive;
    }
}
