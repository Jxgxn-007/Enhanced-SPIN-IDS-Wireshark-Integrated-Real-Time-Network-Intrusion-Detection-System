package com.spinids.capture;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV6CommonPacket;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.IpNumber;

import java.io.File;
import java.io.EOFException;
import java.sql.Timestamp;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeoutException;

/**
 * Standalone PCAP inspection utility using Pcap4J.
 * Reads an offline capture file and prints inspection details and summary statistics.
 */
public class PcapInspector {

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

    public static void main(String[] args) {
        if (args == null || args.length < 1) {
            System.err.println("Usage: mvn exec:java -Dexec.mainClass=\"com.spinids.capture.PcapInspector\" -Dexec.args=\"<path-to-pcap>\"");
            System.err.println("Error: PCAP file path must be provided as the first command-line argument.");
            System.exit(1);
        }

        String pcapPath = args[0];
        // Handle optional '--pcap <path>' format if provided as first arg
        if ("--pcap".equalsIgnoreCase(pcapPath) && args.length > 1) {
            pcapPath = args[1];
        }

        File pcapFile = new File(pcapPath);
        if (!pcapFile.exists()) {
            System.err.println("Error: File not found at path: " + pcapPath);
            System.exit(1);
        }

        System.out.println("==================================================");
        System.out.println("SPIN-IDS PCAP INSPECTOR");
        System.out.println("==================================================");
        System.out.println("Inspecting file: " + pcapFile.getAbsolutePath());
        System.out.println("File size      : " + pcapFile.length() + " bytes");
        System.out.println();

        int totalPacketCount = 0;
        int tcpCount = 0;
        int udpCount = 0;
        int icmpCount = 0;
        int otherCount = 0;

        Set<String> uniqueSourceIps = new HashSet<>();
        Set<String> uniqueDestinationIps = new HashSet<>();

        System.out.println("--------------------------------------------------");
        System.out.println("First 20 Packets Sample");
        System.out.println("--------------------------------------------------");

        try (PcapHandle handle = Pcaps.openOffline(pcapPath)) {
            while (true) {
                Packet packet;
                try {
                    packet = handle.getNextPacketEx();
                } catch (EOFException e) {
                    // Reached end of PCAP file
                    break;
                } catch (TimeoutException e) {
                    continue;
                } catch (PcapNativeException e) {
                    System.err.println("Warning: Encountered native pcap error reading packet: " + e.getMessage());
                    break;
                }

                if (packet == null) {
                    continue;
                }

                totalPacketCount++;

                Timestamp timestamp = handle.getTimestamp();
                int packetLength = packet.length();

                // Extract IP layer details
                IpPacket ipPacket = packet.get(IpPacket.class);
                String srcIp = null;
                String dstIp = null;

                if (ipPacket != null) {
                    if (ipPacket.getHeader().getSrcAddr() != null) {
                        srcIp = ipPacket.getHeader().getSrcAddr().getHostAddress();
                        uniqueSourceIps.add(srcIp);
                    }
                    if (ipPacket.getHeader().getDstAddr() != null) {
                        dstIp = ipPacket.getHeader().getDstAddr().getHostAddress();
                        uniqueDestinationIps.add(dstIp);
                    }
                }

                // Determine protocol and transport layer details
                String protocol;
                Integer srcPort = null;
                Integer dstPort = null;

                TcpPacket tcp = packet.get(TcpPacket.class);
                UdpPacket udp = packet.get(UdpPacket.class);

                if (tcp != null) {
                    protocol = "TCP";
                    srcPort = tcp.getHeader().getSrcPort().valueAsInt();
                    dstPort = tcp.getHeader().getDstPort().valueAsInt();
                    tcpCount++;
                } else if (udp != null) {
                    protocol = "UDP";
                    srcPort = udp.getHeader().getSrcPort().valueAsInt();
                    dstPort = udp.getHeader().getDstPort().valueAsInt();
                    udpCount++;
                } else if (packet.get(IcmpV4CommonPacket.class) != null
                        || packet.get(IcmpV6CommonPacket.class) != null
                        || isIcmpIpPacket(ipPacket)) {
                    protocol = "ICMP";
                    icmpCount++;
                } else {
                    protocol = "OTHER";
                    otherCount++;
                }

                // Print first 20 packets
                if (totalPacketCount <= 20) {
                    System.out.printf("Packet #%-2d | Timestamp: %s | Length: %4d bytes | Protocol: %-5s%n",
                            totalPacketCount,
                            (timestamp != null ? timestamp.toString() : "N/A"),
                            packetLength,
                            protocol);
                    System.out.println("  Source IP        : " + (srcIp != null ? srcIp : "N/A"));
                    System.out.println("  Destination IP   : " + (dstIp != null ? dstIp : "N/A"));
                    if ("TCP".equals(protocol) || "UDP".equals(protocol)) {
                        System.out.println("  Source Port      : " + srcPort);
                        System.out.println("  Destination Port : " + dstPort);
                    }
                    System.out.println();
                }
            }
        } catch (PcapNativeException e) {
            System.err.println("Fatal: Could not open PCAP file: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        } catch (Exception e) {
            System.err.println("Fatal error during PCAP inspection: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }

        // Print final inspection summary
        System.out.println("==================================================");
        System.out.println("INSPECTION SUMMARY");
        System.out.println("==================================================");
        System.out.println("Total packet count         : " + totalPacketCount);
        System.out.println("Unique source IP count     : " + uniqueSourceIps.size());
        System.out.println("Unique destination IP count: " + uniqueDestinationIps.size());
        System.out.println("TCP packet count           : " + tcpCount);
        System.out.println("UDP packet count           : " + udpCount);
        System.out.println("ICMP packet count          : " + icmpCount);
        System.out.println("Other packet count         : " + otherCount);
        System.out.println("==================================================");
    }

    private static boolean isIcmpIpPacket(IpPacket ipPacket) {
        if (ipPacket instanceof IpV4Packet) {
            IpV4Packet ipV4 = (IpV4Packet) ipPacket;
            return ipV4.getHeader().getProtocol() != null
                    && (IpNumber.ICMPV4.equals(ipV4.getHeader().getProtocol())
                    || ipV4.getHeader().getProtocol().value() == (byte) 1);
        } else if (ipPacket instanceof IpV6Packet) {
            IpV6Packet ipV6 = (IpV6Packet) ipPacket;
            return ipV6.getHeader().getNextHeader() != null
                    && (IpNumber.ICMPV6.equals(ipV6.getHeader().getNextHeader())
                    || ipV6.getHeader().getNextHeader().value() == (byte) 58);
        }
        return false;
    }
}
