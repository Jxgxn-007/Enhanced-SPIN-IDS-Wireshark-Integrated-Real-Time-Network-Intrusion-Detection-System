package com.spinids.api.dto;

public class PcapFileDto {
    private String filename;
    private long sizeBytes;
    private int packetCount;
    private String creationTime;

    public PcapFileDto() {}

    public PcapFileDto(String filename, long sizeBytes, int packetCount, String creationTime) {
        this.filename = filename;
        this.sizeBytes = sizeBytes;
        this.packetCount = packetCount;
        this.creationTime = creationTime;
    }

    public String getFilename() {
        return filename;
    }

    public void setFilename(String filename) {
        this.filename = filename;
    }

    public long getSizeBytes() {
        return sizeBytes;
    }

    public void setSizeBytes(long sizeBytes) {
        this.sizeBytes = sizeBytes;
    }

    public int getPacketCount() {
        return packetCount;
    }

    public void setPacketCount(int packetCount) {
        this.packetCount = packetCount;
    }

    public String getCreationTime() {
        return creationTime;
    }

    public void setCreationTime(String creationTime) {
        this.creationTime = creationTime;
    }
}
