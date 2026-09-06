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

    // Distinct numerical markers for direction encoding
    public static final byte DIRECTION_FORWARD_VAL = (byte) 100;
    public static final byte DIRECTION_BACKWARD_VAL = (byte) 200;
    public static final byte DIRECTION_PAD_VAL = (byte) 0;

    /**
     * Preprocesses a packet record into a fixed-length numerical byte array.
     *
     * @param record packet record containing metadata and raw packet
     * @return deterministic byte array of length DEFAULT_BYTES_PER_PACKET
     */
    public static byte[] preprocess(SequentialPacketWindow.PacketRecord record) {
        if (record == null) {
            return new byte[DEFAULT_BYTES_PER_PACKET];
        }
        return preprocess(
                record.getPacket(),
                record.getDirection(),
                record.getPacketNumberInWindow(),
                DEFAULT_BYTES_PER_PACKET
        );
    }

    /**
     * Preprocesses a raw packet into a deterministic byte array of the specified capacity.
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
                // Any remaining space after bytesToCopy is already 0 (zero-padded)
            }
        }

        return buffer;
    }
}
