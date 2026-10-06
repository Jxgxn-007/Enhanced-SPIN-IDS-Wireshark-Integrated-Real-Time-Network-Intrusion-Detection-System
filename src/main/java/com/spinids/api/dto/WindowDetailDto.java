package com.spinids.api.dto;

import java.util.List;

public class WindowDetailDto {
    private int windowIndex;
    private String flowId;
    private int flowIndex;
    private String label;
    private int packetCount;
    private List<PacketItemDto> packets;
    private List<String> matrixPreview; // 81 hex color strings for 9x9 CSS visualizer
    private DetectionDto detection;

    public static class PacketItemDto {
        private int sequence;
        private String protocol;
        private String src;
        private String dst;
        private int length;
        private String direction;
        private String flags;

        public PacketItemDto() {}

        public PacketItemDto(int sequence, String protocol, String src, String dst, int length, String direction, String flags) {
            this.sequence = sequence;
            this.protocol = protocol;
            this.src = src;
            this.dst = dst;
            this.length = length;
            this.direction = direction;
            this.flags = flags;
        }

        public int getSequence() {
            return sequence;
        }

        public void setSequence(int sequence) {
            this.sequence = sequence;
        }

        public String getProtocol() {
            return protocol;
        }

        public void setProtocol(String protocol) {
            this.protocol = protocol;
        }

        public String getSrc() {
            return src;
        }

        public void setSrc(String src) {
            this.src = src;
        }

        public String getDst() {
            return dst;
        }

        public void setDst(String dst) {
            this.dst = dst;
        }

        public int getLength() {
            return length;
        }

        public void setLength(int length) {
            this.length = length;
        }

        public String getDirection() {
            return direction;
        }

        public void setDirection(String direction) {
            this.direction = direction;
        }

        public String getFlags() {
            return flags;
        }

        public void setFlags(String flags) {
            this.flags = flags;
        }
    }

    public WindowDetailDto() {}

    public int getWindowIndex() {
        return windowIndex;
    }

    public void setWindowIndex(int windowIndex) {
        this.windowIndex = windowIndex;
    }

    public String getFlowId() {
        return flowId;
    }

    public void setFlowId(String flowId) {
        this.flowId = flowId;
    }

    public int getFlowIndex() {
        return flowIndex;
    }

    public void setFlowIndex(int flowIndex) {
        this.flowIndex = flowIndex;
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public int getPacketCount() {
        return packetCount;
    }

    public void setPacketCount(int packetCount) {
        this.packetCount = packetCount;
    }

    public List<PacketItemDto> getPackets() {
        return packets;
    }

    public void setPackets(List<PacketItemDto> packets) {
        this.packets = packets;
    }

    public List<String> getMatrixPreview() {
        return matrixPreview;
    }

    public void setMatrixPreview(List<String> matrixPreview) {
        this.matrixPreview = matrixPreview;
    }

    public DetectionDto getDetection() {
        return detection;
    }

    public void setDetection(DetectionDto detection) {
        this.detection = detection;
    }
}
