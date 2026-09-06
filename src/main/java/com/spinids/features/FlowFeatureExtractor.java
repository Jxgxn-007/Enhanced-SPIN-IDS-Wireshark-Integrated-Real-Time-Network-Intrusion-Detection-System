package com.spinids.features;

import com.spinids.flow.Flow;
import com.spinids.flow.FlowManager;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Extracts statistical, rate, and directional traffic features from network flows.
 * Provides safe calculations with explicit protection against division-by-zero.
 */
public class FlowFeatureExtractor {

    /**
     * Extracts features for a single flow using the FlowManager for reverse flow lookups.
     *
     * @param flow        the target Flow
     * @param flowManager the FlowManager containing all active flows
     * @return extracted FlowFeatures instance
     */
    public static FlowFeatures extract(Flow flow, FlowManager flowManager) {
        if (flow == null) {
            return null;
        }

        Map<String, Flow> flowMap = (flowManager != null) ? flowManager.getFlows() : null;
        return extract(flow, flowMap);
    }

    /**
     * Extracts features for a single flow using a map of flows for reverse flow lookups.
     *
     * @param flow    the target Flow
     * @param flowMap map of active flows keyed by 5-tuple
     * @return extracted FlowFeatures instance
     */
    public static FlowFeatures extract(Flow flow, Map<String, Flow> flowMap) {
        if (flow == null) {
            return null;
        }

        long durationMs = flow.getDuration();
        long packetCount = flow.getPacketCount();
        long totalBytes = flow.getTotalBytes();

        // 1. Average Packet Size (safe against division-by-zero)
        double avgPacketSize = (packetCount > 0) ? ((double) totalBytes / packetCount) : 0.0;

        // 2. Duration in seconds
        double durationSec = durationMs / 1000.0;

        // 3. Packets Per Second & Bytes Per Second (safe against division-by-zero)
        double packetsPerSecond;
        double bytesPerSecond;

        if (durationSec > 0.0) {
            packetsPerSecond = (double) packetCount / durationSec;
            bytesPerSecond = (double) totalBytes / durationSec;
        } else {
            // Duration is 0 ms (single-packet flow or packets arrived in same millisecond)
            packetsPerSecond = 0.0;
            bytesPerSecond = 0.0;
        }

        // 4. Directional metrics: Forward and Reverse packet counts
        long forwardPacketCount = packetCount;
        long reversePacketCount = 0L;

        if (flowMap != null) {
            String reverseKey = FlowManager.generateKey(
                flow.getDestinationIp(),
                flow.getSourceIp(),
                flow.getDestinationPort(),
                flow.getSourcePort(),
                flow.getProtocol()
            );

            Flow reverseFlow = flowMap.get(reverseKey);
            if (reverseFlow != null) {
                reversePacketCount = reverseFlow.getPacketCount();
            }
        }

        return new FlowFeatures(
            flow.getSourceIp(),
            flow.getDestinationIp(),
            flow.getSourcePort(),
            flow.getDestinationPort(),
            flow.getProtocol(),
            durationMs,
            packetCount,
            totalBytes,
            avgPacketSize,
            packetsPerSecond,
            bytesPerSecond,
            forwardPacketCount,
            reversePacketCount
        );
    }

    /**
     * Extracts features for all flows contained in the given FlowManager.
     *
     * @param flowManager the FlowManager containing flows
     * @return list of extracted FlowFeatures in flow arrival order
     */
    public static List<FlowFeatures> extractAll(FlowManager flowManager) {
        List<FlowFeatures> featureList = new ArrayList<>();
        if (flowManager == null) {
            return featureList;
        }

        Map<String, Flow> flowMap = flowManager.getFlows();
        for (Flow flow : flowManager.getFlowList()) {
            FlowFeatures features = extract(flow, flowMap);
            if (features != null) {
                featureList.add(features);
            }
        }
        return featureList;
    }

    /**
     * Prints a formatted feature table for all extracted flow features.
     *
     * @param featuresList list of flow features
     */
    public static void printFeatureSummary(List<FlowFeatures> featuresList) {
        printFeatureSummary(featuresList, -1, -1);
    }

    /**
     * Prints a formatted feature table including total packet count.
     *
     * @param featuresList list of flow features
     * @param totalPackets total packet count
     */
    public static void printFeatureSummary(List<FlowFeatures> featuresList, int totalPackets) {
        printFeatureSummary(featuresList, totalPackets, -1);
    }

    /**
     * Prints a formatted feature table with an optional display limit.
     *
     * @param featuresList list of flow features
     * @param totalPackets total packet count (-1 to omit)
     * @param maxFlows     maximum number of flows to print (-1 for all)
     */
    public static void printFeatureSummary(List<FlowFeatures> featuresList, int totalPackets, int maxFlows) {
        if (featuresList == null || featuresList.isEmpty()) {
            System.out.println("No flow features available.");
            return;
        }

        System.out.println("========================================");
        System.out.println("SPIN-IDS FLOW FEATURE SUMMARY");
        System.out.println("========================================");
        if (totalPackets >= 0) {
            System.out.println("Total Packets : " + totalPackets);
        }
        System.out.println("Total Flows   : " + featuresList.size());
        System.out.println();

        int index = 1;
        for (FlowFeatures f : featuresList) {
            if (maxFlows > 0 && index > maxFlows) {
                System.out.println("... [" + (featuresList.size() - maxFlows) + " more flows not displayed]");
                break;
            }

            System.out.println("Flow #" + index);
            System.out.println("Source IP       : " + f.getSourceIp());
            System.out.println("Destination IP  : " + f.getDestinationIp());
            System.out.println("Source Port     : " + f.getSourcePort());
            System.out.println("Destination Port: " + f.getDestinationPort());
            System.out.println("Protocol        : " + f.getProtocol());
            System.out.println("Duration        : " + f.getDuration() + " ms");
            System.out.println("Packets         : " + f.getPacketCount());
            System.out.println("Total Bytes     : " + f.getTotalBytes());
            System.out.printf("Avg Packet Size : %.2f bytes\n", f.getAvgPacketSize());
            System.out.printf("Packets/sec     : %.2f\n", f.getPacketsPerSecond());
            System.out.printf("Bytes/sec       : %.2f\n", f.getBytesPerSecond());
            System.out.println("Forward Packets : " + f.getForwardPacketCount());
            System.out.println("Reverse Packets : " + f.getReversePacketCount());
            System.out.println();
            index++;
        }
    }
}
