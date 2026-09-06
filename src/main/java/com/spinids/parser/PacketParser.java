package com.spinids.parser;

import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

public class PacketParser{

    public static void parse(Packet packet, int packetNumber) {

        System.out.println("========================================");
        System.out.println("Packet #" + packetNumber);

        // Check whether packet contains an IP layer
        IpPacket ipPacket = packet.get(IpPacket.class);

        if (ipPacket == null) {
            System.out.println("Non-IP packet");
            return;
        }

        String sourceIp = ipPacket.getHeader().getSrcAddr().getHostAddress();

        String destinationIp = ipPacket.getHeader().getDstAddr().getHostAddress();

        System.out.println("Source IP      : " + sourceIp);
        System.out.println("Destination IP : " + destinationIp);

        // TCP
        TcpPacket tcpPacket = packet.get(TcpPacket.class);

        if (tcpPacket != null) {

            int sourcePort = tcpPacket.getHeader().getSrcPort().valueAsInt();

            int destinationPort = tcpPacket.getHeader().getDstPort().valueAsInt();

            System.out.println("Protocol       : TCP");
            System.out.println("Source Port    : " + sourcePort);
            System.out.println("Destination Port: " + destinationPort);

            return;
        }

        // UDP
        UdpPacket udpPacket = packet.get(UdpPacket.class);

        if (udpPacket != null) {

            int sourcePort = udpPacket.getHeader().getSrcPort().valueAsInt();

            int destinationPort = udpPacket.getHeader().getDstPort().valueAsInt();

            System.out.println("Protocol       : UDP");
            System.out.println("Source Port    : " + sourcePort);
            System.out.println("Destination Port: " + destinationPort);

            return;
        }

        System.out.println("Protocol       : Other IP protocol");
    }
}