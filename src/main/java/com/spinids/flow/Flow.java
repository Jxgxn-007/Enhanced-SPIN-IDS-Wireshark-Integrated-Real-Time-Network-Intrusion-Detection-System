package com.spinids.flow;

import java.util.Objects;

/**
 * Represents a network flow identified by the standard 5-tuple:
 * Source IP, Destination IP, Source Port, Destination Port, and Protocol.
 */
public class Flow {

    private final String sourceIp;
    private final String destinationIp;
    private final int sourcePort;
    private final int destinationPort;
    private final String protocol;

    private long packetCount;
    private long totalBytes;
    private long firstPacketTime;
    private long lastPacketTime;

    /**
     * Constructs a new Flow instance initialized with the first packet's information.
     *
     * @param sourceIp        source IP address
     * @param destinationIp   destination IP address
     * @param sourcePort      source port number
     * @param destinationPort destination port number
     * @param protocol        transport protocol (e.g., TCP, UDP, OTHER)
     * @param packetLength    length in bytes of the first packet
     * @param timestamp       timestamp in milliseconds of the first packet
     */
    public Flow(String sourceIp, String destinationIp, int sourcePort, int destinationPort,
                String protocol, long packetLength, long timestamp) {
        this.sourceIp = sourceIp;
        this.destinationIp = destinationIp;
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.protocol = protocol;

        this.packetCount = 1;
        this.totalBytes = packetLength;
        this.firstPacketTime = timestamp;
        this.lastPacketTime = timestamp;
    }

    /**
     * Updates the flow when a new packet belonging to this 5-tuple arrives.
     *
     * @param packetLength length in bytes of the newly arrived packet
     * @param timestamp    timestamp in milliseconds of the packet
     */
    public void update(long packetLength, long timestamp) {
        this.packetCount++;
        this.totalBytes += packetLength;

        if (timestamp < this.firstPacketTime) {
            this.firstPacketTime = timestamp;
        }
        if (timestamp > this.lastPacketTime) {
            this.lastPacketTime = timestamp;
        }
    }

    /**
     * Alias method for updating the flow with a new packet.
     *
     * @param packetLength length in bytes of the packet
     * @param timestamp    timestamp in milliseconds of the packet
     */
    public void addPacket(long packetLength, long timestamp) {
        update(packetLength, timestamp);
    }

    /**
     * Calculates the duration of the flow in milliseconds.
     *
     * @return flow duration in milliseconds
     */
    public long getDuration() {
        return Math.max(0, lastPacketTime - firstPacketTime);
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

    public long getPacketCount() {
        return packetCount;
    }

    public long getTotalBytes() {
        return totalBytes;
    }

    public long getFirstPacketTime() {
        return firstPacketTime;
    }

    public long getLastPacketTime() {
        return lastPacketTime;
    }

    /**
     * Formatted string for Source IP and Port.
     */
    public String getSourceEndpoint() {
        return sourceIp + ":" + sourcePort;
    }

    /**
     * Formatted string for Destination IP and Port.
     */
    public String getDestinationEndpoint() {
        return destinationIp + ":" + destinationPort;
    }

    // --- Identity: 5-tuple ---

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Flow flow = (Flow) o;
        return sourcePort == flow.sourcePort &&
               destinationPort == flow.destinationPort &&
               Objects.equals(sourceIp, flow.sourceIp) &&
               Objects.equals(destinationIp, flow.destinationIp) &&
               Objects.equals(protocol, flow.protocol);
    }

    @Override
    public int hashCode() {
        return Objects.hash(sourceIp, destinationIp, sourcePort, destinationPort, protocol);
    }

    @Override
    public String toString() {
        return "Flow{" +
                "source=" + getSourceEndpoint() +
                ", destination=" + getDestinationEndpoint() +
                ", protocol='" + protocol + '\'' +
                ", packets=" + packetCount +
                ", bytes=" + totalBytes +
                ", duration=" + getDuration() + " ms" +
                '}';
    }
}
