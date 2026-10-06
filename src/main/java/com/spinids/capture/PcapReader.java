package com.spinids.capture;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import com.spinids.dataset.FeatureDatasetWriter;
import com.spinids.features.FlowFeatures;
import com.spinids.features.FlowFeatureExtractor;
import com.spinids.flow.FlowManager;
import com.spinids.image.PacketImageBuilder;
import com.spinids.image.SequentialPacketWindow;
import com.spinids.image.SequentialPacketWindow.PacketDirection;

import java.io.File;
import java.io.EOFException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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
        int packetCount = 0;
        int windowCount = 0;
        SequentialPacketWindow currentWindow;

        ConversationTracker(String flowId, int flowIndex, String initiatorEndpoint) {
            this.flowId = flowId;
            this.flowIndex = flowIndex;
            this.initiatorEndpoint = initiatorEndpoint;
            this.currentWindow = new SequentialPacketWindow(flowId, flowIndex, 1);
        }
    }

    public static void main(String[] args) {

        String pcapFile = "dataset/captures/normal_traffic.pcapng";
        String datasetPath = FeatureDatasetWriter.DEFAULT_OUTPUT_PATH;
        String label = FeatureDatasetWriter.DEFAULT_LABEL;

        int packetCount = 0;
        FlowManager flowManager = new FlowManager();

        Map<String, ConversationTracker> conversations = new LinkedHashMap<>();
        List<SequentialPacketWindow> completedWindows = new ArrayList<>();

        try (PcapHandle handle = Pcaps.openOffline(pcapFile)) {

            System.out.println("PCAP file opened successfully!");
            System.out.println("Processing packets into flows and sequential windows...\n");

            Packet packet;

            while (true) {
                try {
                    packet = handle.getNextPacketEx();
                } catch (EOFException e) {
                    break;
                }

                if (packet != null) {
                    packetCount++;
                    Timestamp ts = handle.getTimestamp();
                    long timeMillis = (ts != null) ? ts.getTime() : 0L;

                    // 1. Existing flow manager processing
                    flowManager.processPacket(packet, ts);

                    // 2. Sequential packet window tracking
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
                            conv = new ConversationTracker(convKey, flowIdx, epA, label);
                            conversations.put(convKey, conv);
                        }

                        conv.packetCount++;
                        PacketDirection direction = epA.equals(conv.initiatorEndpoint)
                                ? PacketDirection.FORWARD
                                : PacketDirection.BACKWARD;

                        if (conv.currentWindow == null) {
                            conv.currentWindow = new SequentialPacketWindow(convKey, conv.flowIndex, conv.windowCount + 1, label);
                        }

                        conv.currentWindow.addPacket(packet, timeMillis, direction, conv.packetCount);

                        if (conv.currentWindow.isFull()) {
                            completedWindows.add(conv.currentWindow);
                            conv.windowCount++;
                            conv.currentWindow = new SequentialPacketWindow(convKey, conv.flowIndex, conv.windowCount + 1, label);
                        }
                    }
                }
            }

            // 2b. Flush partial windows from all active conversations (zero-padding will be applied during image build)
            int fullWindowsCount = completedWindows.size();
            int partialWindowsCount = 0;

            for (ConversationTracker conv : conversations.values()) {
                if (conv.currentWindow != null && conv.currentWindow.size() > 0) {
                    completedWindows.add(conv.currentWindow);
                    conv.windowCount++;
                    partialWindowsCount++;
                    conv.currentWindow = null;
                }
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
                    conversations.size(),
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