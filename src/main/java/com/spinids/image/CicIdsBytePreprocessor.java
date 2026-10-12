package com.spinids.image;

import com.spinids.image.SequentialPacketWindow.PacketDirection;
import com.spinids.image.SequentialPacketWindow.PacketRecord;
import org.pcap4j.packet.Packet;

/**
 * Preprocesses network packets and sequential packet windows into continuous 1D byte
 * sequences and normalized tensors matching the CIC-IDS2017 Byte 1D CNN training pipeline.
 *
 * <p>Specification matches Python's {@code ml/extract_cic_ids2017.py:encode_packet()}:
 * <ul>
 *   <li>Packet size: 243 bytes per packet</li>
 *   <li>Byte 0: Direction marker (0 = FORWARD, 1 = BACKWARD)</li>
 *   <li>Byte 1: Sequence index within window (0 to 8, 0-indexed)</li>
 *   <li>Bytes 2-3: 16-bit big-endian unsigned packet length</li>
 *   <li>Bytes 4-242: Raw Ethernet frame with Source and Destination IPv4 addresses
 *       (offsets 26 to 33 inclusive) zeroed out; padded with zeros or truncated to 239 bytes</li>
 *   <li>Window size: 9 sequential packets = 2,187 bytes</li>
 *   <li>Incomplete windows: remaining packet slots beyond the window's actual packet count
 *       are zero-padded with 243 zero bytes per missing slot</li>
 *   <li>Normalization: {@code (byteValue & 0xFF) / 255.0f} producing float32 values in [0.0, 1.0]</li>
 *   <li>Tensor shape: {@code [1][1][2187]} for ONNX input {@code byte_input}</li>
 * </ul>
 */
public final class CicIdsBytePreprocessor {

    public static final int BYTES_PER_PACKET = 243;
    public static final int WINDOW_SIZE = 9;
    public static final int WINDOW_BYTES = WINDOW_SIZE * BYTES_PER_PACKET; // 2,187 bytes
    public static final int PAYLOAD_SPACE = BYTES_PER_PACKET - 4; // 239 bytes

    public static final byte DIRECTION_FORWARD = (byte) 0;
    public static final byte DIRECTION_BACKWARD = (byte) 1;

    private CicIdsBytePreprocessor() {
        // Utility class
    }

    /**
     * Anonymizes IPv4 addresses in a raw Ethernet frame by setting bytes 26..33 to zero.
     * Preserves Ethernet header (bytes 0..13), IPv4 header version/IHL/protocol/ports, and payload.
     * Matches Python's {@code mask_ip_addresses()}.
     *
     * @param rawBytes raw frame byte array (including Ethernet header)
     * @return cloned byte array with IPv4 source/destination addresses zeroed out, or empty array if null
     */
    public static byte[] maskIpAddresses(byte[] rawBytes) {
        if (rawBytes == null) {
            return new byte[0];
        }
        byte[] masked = rawBytes.clone();
        if (masked.length >= 34) {
            for (int i = 26; i < 34; i++) {
                masked[i] = 0;
            }
        }
        return masked;
    }

    /**
     * Encodes a single packet into exactly 243 bytes matching the Python training representation:
     * Byte 0: Direction (0 = forward, 1 = backward)
     * Byte 1: Sequence index (0 to 8)
     * Bytes 2-3: Packet length (16-bit big-endian)
     * Bytes 4-242: IP-masked packet data (239 bytes, zero-padded if shorter)
     *
     * @param rawPacketBytes raw packet bytes (with Ethernet header)
     * @param direction packet direction (FORWARD vs BACKWARD)
     * @param sequenceIndex sequence index within window (0 to 8)
     * @return 243-byte encoded array
     */
    public static byte[] encodePacket(byte[] rawPacketBytes, PacketDirection direction, int sequenceIndex) {
        byte[] buffer = new byte[BYTES_PER_PACKET];
        int pktLen = (rawPacketBytes != null) ? rawPacketBytes.length : 0;
        byte[] maskedData = maskIpAddresses(rawPacketBytes);

        // Byte 0: direction marker (0 = forward, 1 = backward)
        buffer[0] = (direction == PacketDirection.BACKWARD) ? DIRECTION_BACKWARD : DIRECTION_FORWARD;

        // Byte 1: sequence index (0 to 8)
        buffer[1] = (byte) (sequenceIndex & 0xFF);

        // Bytes 2-3: 16-bit packet length in big-endian network byte order
        int encodedLength = Math.min(pktLen, 65535);
        buffer[2] = (byte) ((encodedLength >> 8) & 0xFF);
        buffer[3] = (byte) (encodedLength & 0xFF);

        // Bytes 4-242: payload space (239 bytes)
        if (maskedData.length > 0) {
            int bytesToCopy = Math.min(maskedData.length, PAYLOAD_SPACE);
            System.arraycopy(maskedData, 0, buffer, 4, bytesToCopy);
        }

        return buffer;
    }

    /**
     * Encodes a {@link PacketRecord} into 243 bytes.
     *
     * @param record packet record from a sequential window
     * @param sequenceIndex sequence index within the window (0 to 8)
     * @return 243-byte encoded array
     */
    public static byte[] encodePacket(PacketRecord record, int sequenceIndex) {
        if (record == null) {
            return new byte[BYTES_PER_PACKET];
        }
        Packet packet = record.getPacket();
        byte[] rawBytes = (packet != null) ? packet.getRawData() : null;
        return encodePacket(rawBytes, record.getDirection(), sequenceIndex);
    }

    /**
     * Extracts 2,187 bytes from a {@link SequentialPacketWindow}.
     * Concatenates 9 packets of 243 bytes each. Incomplete windows (fewer than 9 packets)
     * are deterministically padded with zeros for all remaining packet slots.
     *
     * @param window sequential packet window (up to 9 packets)
     * @return 2,187-byte continuous byte array
     */
    public static byte[] extractBytes(SequentialPacketWindow window) {
        byte[] windowBytes = new byte[WINDOW_BYTES];
        if (window == null) {
            return windowBytes;
        }

        int packetCount = window.size();
        for (int slot = 0; slot < WINDOW_SIZE; slot++) {
            if (slot < packetCount) {
                PacketRecord record = window.getPacket(slot);
                byte[] encoded = encodePacket(record, slot);
                System.arraycopy(encoded, 0, windowBytes, slot * BYTES_PER_PACKET, BYTES_PER_PACKET);
            }
        }
        return windowBytes;
    }

    /**
     * Converts a 2,187-byte array into a normalized 3D tensor of shape [1, 1, 2187].
     * Normalization formula: {@code (byteValue & 0xFF) / 255.0f}.
     *
     * @param windowBytes 2,187-byte continuous byte array
     * @return float[1][1][2187] normalized tensor in range [0.0, 1.0]
     */
    public static float[][][] toNormalizedTensor(byte[] windowBytes) {
        if (windowBytes == null || windowBytes.length != WINDOW_BYTES) {
            throw new IllegalArgumentException("Expected window byte array of length " + WINDOW_BYTES
                    + ", got " + (windowBytes == null ? "null" : windowBytes.length));
        }
        float[][][] tensor = new float[1][1][WINDOW_BYTES];
        for (int i = 0; i < WINDOW_BYTES; i++) {
            tensor[0][0][i] = (windowBytes[i] & 0xFF) / 255.0f;
        }
        return tensor;
    }

    /**
     * Extracts and normalizes a {@link SequentialPacketWindow} directly into a 3D tensor of shape [1, 1, 2187].
     *
     * @param window sequential packet window
     * @return float[1][1][2187] normalized tensor in range [0.0, 1.0]
     */
    public static float[][][] extractNormalizedTensor(SequentialPacketWindow window) {
        return toNormalizedTensor(extractBytes(window));
    }

    /**
     * Formats a byte array into a canonical hexadecimal dump (Wireshark / hexdump -C style).
     * Format: {@code 00000000  00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  |................|}
     *
     * @param bytes raw byte array
     * @return canonical formatted multi-line hexadecimal dump string
     */
    public static String formatHexDump(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        int len = bytes.length;
        for (int i = 0; i < len; i += 16) {
            sb.append(String.format("%08X  ", i));
            for (int j = 0; j < 16; j++) {
                if (i + j < len) {
                    sb.append(String.format("%02X ", bytes[i + j]));
                } else {
                    sb.append("   ");
                }
                if (j == 7) {
                    sb.append(" ");
                }
            }
            sb.append(" |");
            for (int j = 0; j < 16 && (i + j) < len; j++) {
                byte b = bytes[i + j];
                char c = (b >= 32 && b <= 126) ? (char) b : '.';
                sb.append(c);
            }
            sb.append("|\n");
        }
        return sb.toString();
    }

    /**
     * Converts a byte array into a continuous uppercase hexadecimal string.
     *
     * @param bytes raw byte array
     * @return continuous hexadecimal string
     */
    public static String toRawHexString(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
