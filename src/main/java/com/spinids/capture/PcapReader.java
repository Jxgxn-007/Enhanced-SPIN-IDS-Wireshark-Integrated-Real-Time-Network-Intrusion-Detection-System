package com.spinids.capture;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import com.spinids.dataset.DatasetManifestWriter;
import com.spinids.dataset.FeatureDatasetWriter;
import com.spinids.features.FlowFeatures;
import com.spinids.features.FlowFeatureExtractor;
import com.spinids.flow.FlowManager;
import com.spinids.image.PacketImageBuilder;
import com.spinids.image.SequentialPacketWindow;
import com.spinids.image.SequentialPacketWindow.PacketDirection;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.EOFException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class PcapReader {

    static {
        // Automatically configure Npcap library path on Windows if needed
        if (System.getProperty("os.name", "").toLowerCase().contains("win")) {
            String npcapPath = "C:\\Windows\\System32\\Npcap";
            if (new File(npcapPath).exists()) {
                String current = System.getProperty("jna.library.path");
                if (current == null || current.isEmpty()) {
                    System.setProperty("jna.library.path", npcapPath);
                } else if (!current.contains(npcapPath)) {
                    System.setProperty("jna.library.path", current + ";" + npcapPath);
                }
            }
        }
    }

    /**
     * Tracks conversation state for sequential 9-packet window aggregation.
     */
    private static class ConversationTracker {
        final String flowId;
        final int flowIndex;
        final String initiatorEndpoint;
        final String label;
        int packetCount = 0;
        int windowCount = 0;
        SequentialPacketWindow currentWindow;

        ConversationTracker(String flowId, int flowIndex, String initiatorEndpoint, String label) {
            this.flowId = flowId;
            this.flowIndex = flowIndex;
            this.initiatorEndpoint = initiatorEndpoint;
            this.label = (label != null && !label.trim().isEmpty())
                    ? label.trim().toUpperCase()
                    : SequentialPacketWindow.DEFAULT_LABEL;
            this.currentWindow = new SequentialPacketWindow(flowId, flowIndex, 1, this.label);
        }

        ConversationTracker(String flowId, int flowIndex, String initiatorEndpoint) {
            this(flowId, flowIndex, initiatorEndpoint, SequentialPacketWindow.DEFAULT_LABEL);
        }
    }

    /**
     * Reads a PCAP file and extracts sequential 9-packet windows grouped by bidirectional conversation.
     *
     * @param pcapFilePath path to the PCAP or PCAPNG file
     * @param label        classification label to assign to extracted windows (e.g., "NORMAL", "ANOMALY")
     * @return list of SequentialPacketWindow instances (including full and flushed partial windows)
     * @throws Exception if reading the PCAP fails or the file is invalid
     */
    public static List<SequentialPacketWindow> readWindowsFromPcap(String pcapFilePath, String label) throws Exception {
        return readWindowsFromPcap(pcapFilePath, label, null);
    }

    /**
     * Reads a PCAP file and extracts sequential 9-packet windows using the default label ("NORMAL").
     *
     * @param pcapFilePath path to the PCAP or PCAPNG file
     * @return list of SequentialPacketWindow instances
     * @throws Exception if reading the PCAP fails or the file is invalid
     */
    public static List<SequentialPacketWindow> readWindowsFromPcap(String pcapFilePath) throws Exception {
        return readWindowsFromPcap(pcapFilePath, SequentialPacketWindow.DEFAULT_LABEL, null);
    }

    /**
     * Reads a PCAP file and extracts sequential 9-packet windows using the default label ("NORMAL").
     *
     * @param pcapFile PCAP or PCAPNG File object
     * @return list of SequentialPacketWindow instances
     * @throws Exception if reading the PCAP fails or the file is invalid
     */
    public static List<SequentialPacketWindow> readWindowsFromPcap(File pcapFile) throws Exception {
        if (pcapFile == null) {
            throw new IllegalArgumentException("PCAP file cannot be null");
        }
        return readWindowsFromPcap(pcapFile.getAbsolutePath(), SequentialPacketWindow.DEFAULT_LABEL, null);
    }

    /**
     * Reads a PCAP file and extracts sequential 9-packet windows using the specified label.
     *
     * @param pcapFile PCAP or PCAPNG File object
     * @param label    classification label
     * @return list of SequentialPacketWindow instances
     * @throws Exception if reading the PCAP fails or the file is invalid
     */
    public static List<SequentialPacketWindow> readWindowsFromPcap(File pcapFile, String label) throws Exception {
        if (pcapFile == null) {
            throw new IllegalArgumentException("PCAP file cannot be null");
        }
        return readWindowsFromPcap(pcapFile.getAbsolutePath(), label, null);
    }

    /**
     * Core PCAP processing method: reads packets from an offline PCAP file, updates an optional
     * {@link FlowManager}, and groups packets into sequential 9-packet windows per bidirectional conversation.
     *
     * @param pcapFilePath path to the PCAP or PCAPNG file
     * @param label        classification label to assign to extracted windows
     * @param flowManager  optional FlowManager for flow feature extraction, or null
     * @return list of extracted sequential packet windows
     * @throws Exception if reading the PCAP fails or file does not exist
     */
    public static List<SequentialPacketWindow> readWindowsFromPcap(String pcapFilePath,
                                                                  String label,
                                                                  FlowManager flowManager) throws Exception {
        if (pcapFilePath == null || pcapFilePath.trim().isEmpty()) {
            throw new IllegalArgumentException("PCAP file path cannot be null or empty");
        }
        File pcapFile = new File(pcapFilePath);
        if (!pcapFile.exists() || !pcapFile.isFile()) {
            throw new FileNotFoundException("PCAP file not found: " + pcapFilePath);
        }

        String effectiveLabel = (label != null && !label.trim().isEmpty())
                ? label.trim().toUpperCase()
                : SequentialPacketWindow.DEFAULT_LABEL;

        Map<String, ConversationTracker> conversations = new LinkedHashMap<>();
        List<SequentialPacketWindow> completedWindows = new ArrayList<>();

        try (PcapHandle handle = Pcaps.openOffline(pcapFilePath)) {
            Packet packet;
            while (true) {
                try {
                    packet = handle.getNextPacketEx();
                } catch (EOFException e) {
                    break;
                }

                if (packet != null) {
                    Timestamp ts = handle.getTimestamp();
                    long timeMillis = (ts != null) ? ts.getTime() : 0L;

                    if (flowManager != null) {
                        flowManager.processPacket(packet, ts);
                    }

                    IpPacket ipPacket = packet.get(IpPacket.class);
                    if (ipPacket != null) {
                        String srcIp = ipPacket.getHeader().getSrcAddr().getHostAddress();
                        String dstIp = ipPacket.getHeader().getDstAddr().getHostAddress();

                        int srcPort = 0;
                        int dstPort = 0;
                        String proto = "OTHER";

                        TcpPacket tcp = packet.get(TcpPacket.class);
                        UdpPacket udp = packet.get(UdpPacket.class);
                        if (tcp != null) {
                            proto = "TCP";
                            srcPort = tcp.getHeader().getSrcPort().valueAsInt();
                            dstPort = tcp.getHeader().getDstPort().valueAsInt();
                        } else if (udp != null) {
                            proto = "UDP";
                            srcPort = udp.getHeader().getSrcPort().valueAsInt();
                            dstPort = udp.getHeader().getDstPort().valueAsInt();
                        }

                        String epA = srcIp + ":" + srcPort;
                        String epB = dstIp + ":" + dstPort;
                        String convKey = (epA.compareTo(epB) <= 0)
                                ? epA + " <-> " + epB + " [" + proto + "]"
                                : epB + " <-> " + epA + " [" + proto + "]";

                        ConversationTracker conv = conversations.get(convKey);
                        if (conv == null) {
                            int flowIdx = conversations.size() + 1;
                            conv = new ConversationTracker(convKey, flowIdx, epA, effectiveLabel);
                            conversations.put(convKey, conv);
                        }

                        conv.packetCount++;
                        PacketDirection direction = epA.equals(conv.initiatorEndpoint)
                                ? PacketDirection.FORWARD
                                : PacketDirection.BACKWARD;

                        if (conv.currentWindow == null) {
                            conv.currentWindow = new SequentialPacketWindow(convKey, conv.flowIndex, conv.windowCount + 1, effectiveLabel);
                        }

                        conv.currentWindow.addPacket(packet, timeMillis, direction, conv.packetCount);

                        if (conv.currentWindow.isFull()) {
                            completedWindows.add(conv.currentWindow);
                            conv.windowCount++;
                            conv.currentWindow = new SequentialPacketWindow(convKey, conv.flowIndex, conv.windowCount + 1, effectiveLabel);
                        }
                    }
                }
            }

            // Flush partial windows from all active conversations (zero-padding will be applied during image build)
            for (ConversationTracker conv : conversations.values()) {
                if (conv.currentWindow != null && conv.currentWindow.size() > 0) {
                    completedWindows.add(conv.currentWindow);
                    conv.windowCount++;
                    conv.currentWindow = null;
                }
            }
        }

        return completedWindows;
    }

    public static void main(String[] args) {

        String pcapFile = "dataset/captures/normal_traffic.pcapng";
        if (args != null && args.length > 0 && args[0] != null && !args[0].trim().isEmpty()) {
            pcapFile = args[0];
        }
        String datasetPath = FeatureDatasetWriter.DEFAULT_OUTPUT_PATH;
        String label = FeatureDatasetWriter.DEFAULT_LABEL;

        String imagesOutputDir = PacketImageBuilder.getDefaultOutputDir(label);
        int maxWindows = PacketImageBuilder.DEFAULT_MAX_WINDOWS;
        String manifestPath = DatasetManifestWriter.getDefaultManifestPath(label);

        FlowManager flowManager = new FlowManager();

        try {
            System.out.println("PCAP file opened successfully!");
            System.out.println("Processing packets into flows and sequential windows...\n");

            List<SequentialPacketWindow> completedWindows = readWindowsFromPcap(pcapFile, label, flowManager);

            int fullWindowsCount = 0;
            int partialWindowsCount = 0;
            int packetCount = 0;
            Set<String> uniqueFlows = new HashSet<>();

            for (SequentialPacketWindow win : completedWindows) {
                if (win.isFull()) {
                    fullWindowsCount++;
                } else {
                    partialWindowsCount++;
                }
                packetCount += win.size();
                uniqueFlows.add(win.getFlowId());
            }

            // 3. Extract flow features & write CSV dataset
            List<FlowFeatures> features = FlowFeatureExtractor.extractAll(flowManager);
            FeatureDatasetWriter.writeDataset(features, datasetPath, label);

            System.out.println("========================================");
            System.out.println("SPIN-IDS FEATURE DATASET");
            System.out.println("========================================");
            System.out.println("Total Flows   : " + features.size());
            System.out.println("Dataset File  : " + datasetPath);
            System.out.println("Label         : " + label);
            System.out.println("Status        : Successfully written\n");

            // 4. Generate 2D RGB Images from sequential packet windows & create dataset manifest
            List<File> generatedImages = PacketImageBuilder.generateImages(
                    completedWindows,
                    imagesOutputDir,
                    maxWindows,
                    manifestPath,
                    pcapFile
            );

            // 5. Print Image Builder Summary
            PacketImageBuilder.printImageSummary(
                    packetCount,
                    uniqueFlows.size(),
                    fullWindowsCount,
                    partialWindowsCount,
                    generatedImages.size(),
                    imagesOutputDir,
                    manifestPath
            );

        } catch (Exception e) {
            System.err.println("Error reading PCAP:");
            e.printStackTrace();
        }
    }
}