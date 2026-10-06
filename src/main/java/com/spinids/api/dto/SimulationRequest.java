package com.spinids.api.dto;

import java.util.List;

public class SimulationRequest {
    private Double burstRate = 820.0;
    private Integer burstPackets = 50;
    private Integer targetPort = 54321;

    public SimulationRequest() {}

    public SimulationRequest(Double burstRate, Integer burstPackets, Integer targetPort) {
        this.burstRate = burstRate;
        this.burstPackets = burstPackets;
        this.targetPort = targetPort;
    }

    public Double getBurstRate() {
        return burstRate != null ? burstRate : 820.0;
    }

    public void setBurstRate(Double burstRate) {
        this.burstRate = burstRate;
    }

    public Integer getBurstPackets() {
        return burstPackets != null ? burstPackets : 50;
    }

    public void setBurstPackets(Integer burstPackets) {
        this.burstPackets = burstPackets;
    }

    public Integer getTargetPort() {
        return targetPort != null ? targetPort : 54321;
    }

    public void setTargetPort(Integer targetPort) {
        this.targetPort = targetPort;
    }
}
