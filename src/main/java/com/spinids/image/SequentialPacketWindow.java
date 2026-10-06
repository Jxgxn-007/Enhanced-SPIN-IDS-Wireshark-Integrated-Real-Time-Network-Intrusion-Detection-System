package com.spinids.image;

import org.pcap4j.packet.Packet;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Represents a fixed-size window of sequential packets belonging to a single
 * bidirectional network communication flow. Preserves arrival sequence order,
 * packet direction (FORWARD vs BACKWARD), and flow-relative packet numbering.
 */
public class SequentialPacketWindow {

    public static final int DEFAULT_WINDOW_SIZE = 9;

    public enum PacketDirection {
        FORWARD,
        BACKWARD
    }

    /**
     * Individual record of a packet within the sequential window.
     */
    public static class PacketRecord {
        private final int packetNumberInFlow;
        private final int packetNumberInWindow;
        private final PacketDirection direction;
        private final long timestamp;
        private final int length;
        private final Packet packet;

        public PacketRecord(int packetNumberInFlow, int packetNumberInWindow,
                            PacketDirection direction, long timestamp, int length, Packet packet) {
            this.packetNumberInFlow = packetNumberInFlow;
            this.packetNumberInWindow = packetNumberInWindow;
            this.direction = direction;
            this.timestamp = timestamp;
            this.length = length;
            this.packet = packet;
        }

        public int getPacketNumberInFlow() {
            return packetNumberInFlow;
        }

        public int getPacketNumberInWindow() {
            return packetNumberInWindow;
        }

        public PacketDirection getDirection() {
            return direction;
        }

        public long getTimestamp() {
            return timestamp;
        }

        public int getLength() {
            return length;
        }

        public Packet getPacket() {
            return packet;
        }
    }

    public static final String DEFAULT_LABEL = "NORMAL";

    private final String flowId;
    private final int flowIndex;
    private final int windowIndex;
    private final int targetWindowSize;
    private final String label;
    private final List<PacketRecord> packets;

    public SequentialPacketWindow(String flowId, int flowIndex, int windowIndex) {
        this(flowId, flowIndex, windowIndex, DEFAULT_WINDOW_SIZE, DEFAULT_LABEL);
    }

    public SequentialPacketWindow(String flowId, int flowIndex, int windowIndex, String label) {
        this(flowId, flowIndex, windowIndex, DEFAULT_WINDOW_SIZE, label);
    }

    public SequentialPacketWindow(String flowId, int flowIndex, int windowIndex, int targetWindowSize) {
        this(flowId, flowIndex, windowIndex, targetWindowSize, DEFAULT_LABEL);
    }

    public SequentialPacketWindow(String flowId, int flowIndex, int windowIndex, int targetWindowSize, String label) {
        this.flowId = flowId;
        this.flowIndex = flowIndex;
        this.windowIndex = windowIndex;
        this.targetWindowSize = targetWindowSize;
        this.label = (label != null && !label.trim().isEmpty()) ? label.trim().toUpperCase() : DEFAULT_LABEL;
        this.packets = new ArrayList<>(targetWindowSize);
    }

    /**
     * Adds a packet to the sequential window.
     *
     * @param packet             raw Pcap4j packet
     * @param timestamp          packet capture timestamp in milliseconds
     * @param direction          FORWARD or BACKWARD relative to flow initiator
     * @param packetNumberInFlow sequential index of this packet within the flow
     * @return true if added, false if the window is already full
     */
    public boolean addPacket(Packet packet, long timestamp, PacketDirection direction, int packetNumberInFlow) {
        if (isFull()) {
            return false;
        }
        int packetNumberInWindow = packets.size() + 1;
        int length = (packet != null) ? packet.length() : 0;
        packets.add(new PacketRecord(packetNumberInFlow, packetNumberInWindow, direction, timestamp, length, packet));
        return true;
    }

    /**
     * Checks whether the window has reached its target capacity of 9 packets.
     */
    public boolean isFull() {
        return packets.size() >= targetWindowSize;
    }

    /**
     * Returns the number of packets currently in the window.
     */
    public int size() {
        return packets.size();
    }

    public String getFlowId() {
        return flowId;
    }

    public int getFlowIndex() {
        return flowIndex;
    }

    public int getWindowIndex() {
        return windowIndex;
    }

    public int getTargetWindowSize() {
        return targetWindowSize;
    }

    public String getLabel() {
        return label;
    }

    public List<PacketRecord> getPackets() {
        return Collections.unmodifiableList(packets);
    }

    public PacketRecord getPacket(int index) {
        if (index >= 0 && index < packets.size()) {
            return packets.get(index);
        }
        return null;
    }

    @Override
    public String toString() {
        return String.format("SequentialPacketWindow[flow=#%d (%s), window=#%d, label=%s, packets=%d/%d]",
                flowIndex, flowId, windowIndex, label, packets.size(), targetWindowSize);
    }
}
