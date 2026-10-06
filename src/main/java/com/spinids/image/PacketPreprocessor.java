package com.spinids.image;

import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.Packet;

import java.util.Arrays;

/**
 * Preprocesses raw network packets into deterministic fixed-length numerical byte
 * representations suitable for spatial layout and 2D RGB image construction.
 */
public class PacketPreprocessor {

    public static final int DEFAULT_BYTES_PER_PACKET = 243; // 9 x 9 pixels x 3 color channels

    // Header metadata offsets within preprocessed packet vector
    public static final int OFFSET_DIRECTION = 0;
    public static final int OFFSET_SEQUENCE = 1;
    public static final int OFFSET_LENGTH_HIGH = 2;
    public static final int OFFSET_LENGTH_LOW = 3;
    public static final int OFFSET_PROTOCOL_DATA = 4;

    public static final boolean DEFAULT_MASK_IP = true;

    // Distinct numerical markers for direction encoding
    public static final byte DIRECTION_FORWARD_VAL = (byte) 100;
    public static final byte DIRECTION_BACKWARD_VAL = (byte) 200;
    public static final byte DIRECTION_PAD_VAL = (byte) 0;

    /**
     * Preprocesses a packet record into a fixed-length numerical byte array using default IP masking.
     *
     * @param record packet record containing metadata and raw packet
     * @return deterministic byte array of length DEFAULT_BYTES_PER_PACKET
     */
    public static byte[] preprocess(SequentialPacketWindow.PacketRecord record) {
        return preprocess(record, DEFAULT_MASK_IP);
    }

    /**
     * Preprocesses a packet record into a fixed-length numerical byte array with configurable IP masking.
     *
     * @param record packet record containing metadata and raw packet
     * @param maskIp whether to mask source and destination IP addresses
     * @return deterministic byte array of length DEFAULT_BYTES_PER_PACKET
     */
    public static byte[] preprocess(SequentialPacketWindow.PacketRecord record, boolean maskIp) {
        if (record == null) {
            return new byte[DEFAULT_BYTES_PER_PACKET];
        }
        return preprocess(
                record.getPacket(),
                record.getDirection(),
                record.getPacketNumberInWindow(),
                DEFAULT_BYTES_PER_PACKET,
                maskIp
        );
    }

    /**
     * Preprocesses a raw packet into a deterministic byte array using default IP masking.
     *
     * @param packet         Pcap4j packet (may be null for padding slots)
     * @param direction      FORWARD or BACKWARD
     * @param sequenceNumber sequential packet index (1 to 9)
     * @param targetBytes    total byte length of output array
     * @return preprocessed byte array
     */
    public static byte[] preprocess(Packet packet,
                                    SequentialPacketWindow.PacketDirection direction,
                                    int sequenceNumber,
                                    int targetBytes) {
        return preprocess(packet, direction, sequenceNumber, targetBytes, DEFAULT_MASK_IP);
    }

    /**
     * Preprocesses a raw packet into a deterministic byte array of the specified capacity with configurable IP masking.
     *
     * @param packet         Pcap4j packet (may be null for padding slots)
     * @param direction      FORWARD or BACKWARD
     * @param sequenceNumber sequential packet index (1 to 9)
     * @param targetBytes    total byte length of output array
     * @param maskIp         whether to mask source and destination IP addresses
     * @return preprocessed byte array
     */
    public static byte[] preprocess(Packet packet,
                                    SequentialPacketWindow.PacketDirection direction,
                                    int sequenceNumber,
                                    int targetBytes,
                                    boolean maskIp) {
        byte[] buffer = new byte[targetBytes];
        Arrays.fill(buffer, (byte) 0); // Deterministic zero-padding baseline

        if (packet == null && direction == null) {
            // Padding / dummy slot
            return buffer;
        }

        // 1. Encode direction marker in byte 0
        if (direction == SequentialPacketWindow.PacketDirection.FORWARD) {
            buffer[OFFSET_DIRECTION] = DIRECTION_FORWARD_VAL;
        } else if (direction == SequentialPacketWindow.PacketDirection.BACKWARD) {
            buffer[OFFSET_DIRECTION] = DIRECTION_BACKWARD_VAL;
        } else {
            buffer[OFFSET_DIRECTION] = DIRECTION_PAD_VAL;
        }

        // 2. Encode sequence index (1 to 9) in byte 1
        buffer[OFFSET_SEQUENCE] = (byte) (sequenceNumber & 0xFF);

        // 3. Encode packet length in bytes 2 and 3
        int packetLength = (packet != null) ? packet.length() : 0;
        buffer[OFFSET_LENGTH_HIGH] = (byte) ((packetLength >> 8) & 0xFF);
        buffer[OFFSET_LENGTH_LOW] = (byte) (packetLength & 0xFF);

        // 4. Extract protocol and payload bytes
        if (packet != null) {
            byte[] rawBytes = null;

            // Prefer IP layer onward (contains IP, TCP/UDP, and payload)
            IpPacket ipPacket = packet.get(IpPacket.class);
            if (ipPacket != null) {
                rawBytes = ipPacket.getRawData();
            }

            // Fallback to full frame if IP layer not available
            if (rawBytes == null) {
                rawBytes = packet.getRawData();
            }

            if (rawBytes != null && rawBytes.length > 0) {
                int availableSpace = targetBytes - OFFSET_PROTOCOL_DATA;
                int bytesToCopy = Math.min(rawBytes.length, availableSpace);
                System.arraycopy(rawBytes, 0, buffer, OFFSET_PROTOCOL_DATA, bytesToCopy);

                // 5. Anonymize/mask IP addresses to prevent CNN identity memorization
                if (maskIp) {
                    maskIpAddresses(buffer, OFFSET_PROTOCOL_DATA, bytesToCopy);
                }
            }
        }

        return buffer;
    }

    /**
     * Anonymizes IP addresses in the preprocessed buffer.
     * For IPv4: zeroes out Source IP (bytes 12..15) and Destination IP (bytes 16..19).
     * For IPv6: zeroes out Source IPv6 (bytes 8..23) and Destination IPv6 (bytes 24..39).
     * Preserves TCP/UDP ports, packet lengths, TTL/Hop Limit, and protocol flags intact.
     *
     * @param buffer         the preprocessed output buffer
     * @param protocolOffset offset where the IP packet begins (OFFSET_PROTOCOL_DATA)
     * @param length         number of valid IP bytes copied into buffer
     */
    public static void maskIpAddresses(byte[] buffer, int protocolOffset, int length) {
        if (buffer == null || length < 1 || protocolOffset < 0 || protocolOffset >= buffer.length) {
            return;
        }

        int version = (buffer[protocolOffset] >> 4) & 0x0F;

        if (version == 4) {
            // IPv4 header: Source IP at 12..15, Destination IP at 16..19
            int srcIpStart = protocolOffset + 12;
            int dstIpStart = protocolOffset + 16;
            for (int i = 0; i < 4; i++) {
                if (srcIpStart + i < protocolOffset + length && srcIpStart + i < buffer.length) {
                    buffer[srcIpStart + i] = 0;
                }
                if (dstIpStart + i < protocolOffset + length && dstIpStart + i < buffer.length) {
                    buffer[dstIpStart + i] = 0;
                }
            }
        } else if (version == 6) {
            // IPv6 header: Source IPv6 at 8..23 (16 bytes), Destination IPv6 at 24..39 (16 bytes)
            int srcIpStart = protocolOffset + 8;
            int dstIpStart = protocolOffset + 24;
            for (int i = 0; i < 16; i++) {
                if (srcIpStart + i < protocolOffset + length && srcIpStart + i < buffer.length) {
                    buffer[srcIpStart + i] = 0;
                }
                if (dstIpStart + i < protocolOffset + length && dstIpStart + i < buffer.length) {
                    buffer[dstIpStart + i] = 0;
                }
            }
        }
    }
}
