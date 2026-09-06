package com.spinids.flow;

import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Manages network flows generated from packet inspection.
 * Aggregates packets into 5-tuple flows, handles IPv4/IPv6,
 * TCP, UDP, and non-TCP/UDP IP packets cleanly and safely.
 */
public class FlowManager {

    private final Map<String, Flow> flows = new LinkedHashMap<>();
    private long totalProcessedPackets = 0;
    private long totalIpPackets = 0;
    private long totalNonIpPackets = 0;

    /**
     * Generates a unique 5-tuple key for flow lookup.
     *
     * @param sourceIp        source IP address
     * @param destinationIp   destination IP address
     * @param sourcePort      source port number
     * @param destinationPort destination port number
     * @param protocol        protocol name (TCP, UDP, OTHER)
     * @return unique 5-tuple string key
     */
    public static String generateKey(String sourceIp, String destinationIp,
                                     int sourcePort, int destinationPort, String protocol) {
        return sourceIp + ":" + sourcePort + " -> " + destinationIp + ":" + destinationPort + " [" + protocol + "]";
    }

    /**
     * Processes a network packet and associates it with a flow.
     *
     * @param packet    the captured packet
     * @param timestamp timestamp of the packet (from PCAP header)
     * @return the Flow instance the packet was assigned to, or null if ignored (non-IP)
     */
    public Flow processPacket(Packet packet, Timestamp timestamp) {
        long timeMillis = (timestamp != null) ? timestamp.getTime() : System.currentTimeMillis();
        return processPacket(packet, timeMillis);
    }

    /**
     * Processes a network packet with a timestamp in epoch milliseconds.
     *
     * @param packet          the captured packet
     * @param timestampMillis timestamp in epoch milliseconds
     * @return the Flow instance the packet was assigned to, or null if non-IP
     */
    public Flow processPacket(Packet packet, long timestampMillis) {
        if (packet == null) {
            return null;
        }

        totalProcessedPackets++;

        // 1. Check whether packet contains an IP layer (handles IPv4 and IPv6)
        IpPacket ipPacket = packet.get(IpPacket.class);
        if (ipPacket == null) {
            // Safely ignore non-IP packets (e.g. ARP)
            totalNonIpPackets++;
            return null;
        }

        totalIpPackets++;

        // Extract IP addresses (works for both IPv4 and IPv6)
        String sourceIp = ipPacket.getHeader().getSrcAddr().getHostAddress();
        String destinationIp = ipPacket.getHeader().getDstAddr().getHostAddress();

        // 2. Identify transport layer protocol and ports
        String protocol;
        int sourcePort = 0;
        int destinationPort = 0;

        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        UdpPacket udpPacket = packet.get(UdpPacket.class);

        if (tcpPacket != null) {
            protocol = "TCP";
            sourcePort = tcpPacket.getHeader().getSrcPort().valueAsInt();
            destinationPort = tcpPacket.getHeader().getDstPort().valueAsInt();
        } else if (udpPacket != null) {
            protocol = "UDP";
            sourcePort = udpPacket.getHeader().getSrcPort().valueAsInt();
            destinationPort = udpPacket.getHeader().getDstPort().valueAsInt();
        } else {
            // IP packet without TCP/UDP (e.g. ICMP, IGMP, OSPF) - safely handled without crashing
            protocol = "OTHER";
        }

        // 3. Generate unique 5-tuple key
        String flowKey = generateKey(sourceIp, destinationIp, sourcePort, destinationPort, protocol);

        long packetLength = packet.length();

        // 4. Check whether packet belongs to an existing flow
        Flow flow = flows.get(flowKey);
        if (flow != null) {
            flow.update(packetLength, timestampMillis);
        } else {
            flow = new Flow(sourceIp, destinationIp, sourcePort, destinationPort,
                            protocol, packetLength, timestampMillis);
            flows.put(flowKey, flow);
        }

        return flow;
    }

    /**
     * Processes a network packet using the current system time.
     *
     * @param packet the captured packet
     * @return the Flow instance the packet was assigned to, or null if non-IP
     */
    public Flow processPacket(Packet packet) {
        return processPacket(packet, System.currentTimeMillis());
    }

    /**
     * Prints the concise flow summary to standard output.
     *
     * @param totalPackets total number of packets processed from the capture
     */
    public void printFlowSummary(int totalPackets) {
        printFlowSummary(totalPackets, -1);
    }

    /**
     * Prints the flow summary with an optional limit on the number of flows printed.
     *
     * @param totalPackets total number of packets processed
     * @param maxFlows     maximum number of flows to display (-1 for all flows)
     */
    public void printFlowSummary(int totalPackets, int maxFlows) {
        System.out.println("========================================");
        System.out.println("SPIN-IDS FLOW SUMMARY");
        System.out.println("========================================");
        System.out.println("Total Packets : " + totalPackets);
        System.out.println("Total Flows   : " + flows.size());
        System.out.println();

        int index = 1;
        for (Flow flow : flows.values()) {
            if (maxFlows > 0 && index > maxFlows) {
                System.out.println("... [" + (flows.size() - maxFlows) + " more flows not displayed]");
                break;
            }

            System.out.println("Flow #" + index);
            System.out.println("Source       : " + flow.getSourceEndpoint());
            System.out.println("Destination  : " + flow.getDestinationEndpoint());
            System.out.println("Protocol     : " + flow.getProtocol());
            System.out.println("Packets      : " + flow.getPacketCount());
            System.out.println("Total Bytes  : " + flow.getTotalBytes());
            System.out.println("Duration     : " + flow.getDuration() + " ms");
            System.out.println();
            index++;
        }
    }

    // --- Query and Accessor Methods ---

    public Map<String, Flow> getFlows() {
        return Collections.unmodifiableMap(flows);
    }

    public List<Flow> getFlowList() {
        return new ArrayList<>(flows.values());
    }

    public Flow getFlow(String key) {
        return flows.get(key);
    }

    public int getTotalFlows() {
        return flows.size();
    }

    public long getTotalProcessedPackets() {
        return totalProcessedPackets;
    }

    public long getTotalIpPackets() {
        return totalIpPackets;
    }

    public long getTotalNonIpPackets() {
        return totalNonIpPackets;
    }

    public void clear() {
        flows.clear();
        totalProcessedPackets = 0;
        totalIpPackets = 0;
        totalNonIpPackets = 0;
    }
}
