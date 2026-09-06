package com.spinids.features;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Model representing the extracted statistical, directional, and protocol
 * feature set for a network flow. Designed for analysis and downstream
 * machine learning / intrusion detection models.
 */
public class FlowFeatures {

    private final String sourceIp;
    private final String destinationIp;
    private final int sourcePort;
    private final int destinationPort;
    private final String protocol;

    private final long duration;            // Flow duration in milliseconds
    private final long packetCount;        // Total packet count
    private final long totalBytes;          // Total bytes transferred
    private final double avgPacketSize;     // Average packet size in bytes
    private final double packetsPerSecond;  // Flow packet rate (packets / sec)
    private final double bytesPerSecond;    // Flow byte rate (bytes / sec)
    private final long forwardPacketCount; // Packets in the forward direction
    private final long reversePacketCount; // Packets in the reverse direction

    public FlowFeatures(String sourceIp, String destinationIp, int sourcePort, int destinationPort,
                        String protocol, long duration, long packetCount, long totalBytes,
                        double avgPacketSize, double packetsPerSecond, double bytesPerSecond,
                        long forwardPacketCount, long reversePacketCount) {
        this.sourceIp = sourceIp;
        this.destinationIp = destinationIp;
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.protocol = protocol;
        this.duration = duration;
        this.packetCount = packetCount;
        this.totalBytes = totalBytes;
        this.avgPacketSize = avgPacketSize;
        this.packetsPerSecond = packetsPerSecond;
        this.bytesPerSecond = bytesPerSecond;
        this.forwardPacketCount = forwardPacketCount;
        this.reversePacketCount = reversePacketCount;
    }

    // --- Getters ---

    public String getSourceIp() {
        return sourceIp;
    }

    public String getDestinationIp() {
        return destinationIp;
    }

    public int getSourcePort() {
        return sourcePort;
    }

    public int getDestinationPort() {
        return destinationPort;
    }

    public String getProtocol() {
        return protocol;
    }

    public long getDuration() {
        return duration;
    }

    public long getPacketCount() {
        return packetCount;
    }

    public long getTotalBytes() {
        return totalBytes;
    }

    public double getAvgPacketSize() {
        return avgPacketSize;
    }

    public double getPacketsPerSecond() {
        return packetsPerSecond;
    }

    public double getBytesPerSecond() {
        return bytesPerSecond;
    }

    public long getForwardPacketCount() {
        return forwardPacketCount;
    }

    public long getReversePacketCount() {
        return reversePacketCount;
    }

    /**
     * Converts numeric flow features into a double array suitable for
     * machine learning model input / feature vector representations.
     *
     * @return array of numeric feature values
     */
    public double[] toDoubleArray() {
        return new double[] {
            (double) duration,
            (double) packetCount,
            (double) totalBytes,
            avgPacketSize,
            packetsPerSecond,
            bytesPerSecond,
            (double) forwardPacketCount,
            (double) reversePacketCount,
            (double) sourcePort,
            (double) destinationPort
        };
    }

    /**
     * Exports features as a key-value map for serialization or reporting.
     *
     * @return map of feature names to values
     */
    public Map<String, Object> toFeatureMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("sourceIp", sourceIp);
        map.put("destinationIp", destinationIp);
        map.put("sourcePort", sourcePort);
        map.put("destinationPort", destinationPort);
        map.put("protocol", protocol);
        map.put("durationMs", duration);
        map.put("packetCount", packetCount);
        map.put("totalBytes", totalBytes);
        map.put("avgPacketSize", avgPacketSize);
        map.put("packetsPerSecond", packetsPerSecond);
        map.put("bytesPerSecond", bytesPerSecond);
        map.put("forwardPackets", forwardPacketCount);
        map.put("reversePackets", reversePacketCount);
        return map;
    }

    @Override
    public String toString() {
        return String.format(
            "FlowFeatures[%s:%d -> %s:%d | %s | duration=%dms, pkts=%d, bytes=%d, avgSize=%.2f, pkts/s=%.2f, bytes/s=%.2f, fwd=%d, rev=%d]",
            sourceIp, sourcePort, destinationIp, destinationPort, protocol,
            duration, packetCount, totalBytes, avgPacketSize, packetsPerSecond, bytesPerSecond,
            forwardPacketCount, reversePacketCount
        );
    }
}
