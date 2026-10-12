package com.spinids;

import com.spinids.image.CicIdsBytePreprocessor;
import com.spinids.image.SequentialPacketWindow;
import com.spinids.image.SequentialPacketWindow.PacketDirection;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class CicIdsBytePreprocessorTest {

    private static Packet createSyntheticEthernetPacket(int length, boolean isForward) {
        byte[] raw = new byte[Math.max(length, 54)];
        Arrays.fill(raw, (byte) 0x66);
        // Ethernet Header
        raw[12] = 0x08; raw[13] = 0x00; // IPv4
        // IPv4 Header
        raw[14] = 0x45; // Version 4, IHL 5
        raw[22] = 64;   // TTL
        raw[23] = 6;    // TCP
        if (isForward) {
            raw[26] = (byte) 192; raw[27] = (byte) 168; raw[28] = 10; raw[29] = 50;
            raw[30] = (byte) 172; raw[31] = 16; raw[32] = 0; raw[33] = 1;
            raw[34] = (byte) 0xC0; raw[35] = 0x00; // Port 49152
            raw[36] = 0x00; raw[37] = 0x50; // Port 80
        } else {
            raw[26] = (byte) 172; raw[27] = 16; raw[28] = 0; raw[29] = 1;
            raw[30] = (byte) 192; raw[31] = 16; raw[32] = 10; raw[33] = 50;
            raw[34] = 0x00; raw[35] = 0x50; // Port 80
            raw[36] = (byte) 0xC0; raw[37] = 0x00; // Port 49152
        }
        try {
            return EthernetPacket.newPacket(raw, 0, raw.length);
        } catch (Exception e) {
            throw new RuntimeException("Failed to construct synthetic packet", e);
        }
    }

    private static byte[] loadFixtureBytes(String fixtureName) throws Exception {
        try (InputStream in = CicIdsBytePreprocessorTest.class.getClassLoader().getResourceAsStream("fixtures/" + fixtureName)) {
            if (in != null) {
                return in.readAllBytes();
            }
        }
        File direct = new File("src/test/resources/fixtures/" + fixtureName);
        if (direct.exists()) {
            return Files.readAllBytes(direct.toPath());
        }
        File parentDirect = new File("../src/test/resources/fixtures/" + fixtureName);
        if (parentDirect.exists()) {
            return Files.readAllBytes(parentDirect.toPath());
        }
        throw new IllegalStateException("Test fixture not found: " + fixtureName);
    }

    @Test
    public void testMaskIpAddressesStandardIpv4() {
        // Construct a synthetic 54-byte Ethernet + IPv4 + TCP packet
        byte[] raw = new byte[54];
        Arrays.fill(raw, (byte) 0xAA);

        // Ethernet Destination MAC: 0..5, Source MAC: 6..11, EtherType: 12..13
        raw[12] = 0x08;
        raw[13] = 0x00; // IPv4

        // IP Header (offset 14 onward):
        raw[14] = 0x45; // Version 4, IHL 5
        raw[22] = 64;   // TTL
        raw[23] = 6;    // TCP

        // Source IP: 192.168.10.17 (bytes 26..29)
        raw[26] = (byte) 192;
        raw[27] = (byte) 168;
        raw[28] = (byte) 10;
        raw[29] = (byte) 17;

        // Destination IP: 172.16.0.1 (bytes 30..33)
        raw[30] = (byte) 172;
        raw[31] = (byte) 16;
        raw[32] = (byte) 0;
        raw[33] = (byte) 1;

        // TCP Ports (bytes 34..37): Source Port 80 (0x0050), Dest Port 53438 (0xD0BE)
        raw[34] = 0x00;
        raw[35] = 0x50;
        raw[36] = (byte) 0xD0;
        raw[37] = (byte) 0xBE;

        byte[] masked = CicIdsBytePreprocessor.maskIpAddresses(raw);
        assertNotNull(masked);
        assertEquals(54, masked.length);

        // Verify Ethernet header intact
        assertEquals((byte) 0xAA, masked[0]);
        assertEquals((byte) 0x08, masked[12]);
        assertEquals((byte) 0x00, masked[13]);

        // Verify IP Version & Protocol intact
        assertEquals((byte) 0x45, masked[14]);
        assertEquals((byte) 6, masked[23]);

        // Verify Source and Destination IP addresses zeroed out (offsets 26..33)
        for (int i = 26; i < 34; i++) {
            assertEquals(0, masked[i], "Byte at offset " + i + " must be masked to 0");
        }

        // Verify TCP Ports intact
        assertEquals(0x00, masked[34]);
        assertEquals(0x50, masked[35]);
        assertEquals((byte) 0xD0, masked[36]);
        assertEquals((byte) 0xBE, masked[37]);
    }

    @Test
    public void testMaskIpAddressesShortPacketAndNull() {
        byte[] shortPacket = new byte[20];
        Arrays.fill(shortPacket, (byte) 0x77);

        byte[] maskedShort = CicIdsBytePreprocessor.maskIpAddresses(shortPacket);
        assertEquals(20, maskedShort.length);
        assertArrayEquals(shortPacket, maskedShort);

        byte[] nullResult = CicIdsBytePreprocessor.maskIpAddresses(null);
        assertNotNull(nullResult);
        assertEquals(0, nullResult.length);
    }

    @Test
    public void testEncodePacketDirectionMarkers() {
        byte[] raw = new byte[40];
        byte[] fwd = CicIdsBytePreprocessor.encodePacket(raw, PacketDirection.FORWARD, 0);
        assertEquals(CicIdsBytePreprocessor.DIRECTION_FORWARD, fwd[0]);
        assertEquals(0, fwd[0]);

        byte[] bwd = CicIdsBytePreprocessor.encodePacket(raw, PacketDirection.BACKWARD, 0);
        assertEquals(CicIdsBytePreprocessor.DIRECTION_BACKWARD, bwd[0]);
        assertEquals(1, bwd[0]);
    }

    @Test
    public void testEncodePacketSequenceIndices() {
        byte[] raw = new byte[20];
        for (int seq = 0; seq < 9; seq++) {
            byte[] encoded = CicIdsBytePreprocessor.encodePacket(raw, PacketDirection.FORWARD, seq);
            assertEquals((byte) seq, encoded[1], "Sequence index byte must equal " + seq);
        }
    }

    @Test
    public void testEncodePacketLengthBigEndian() {
        byte[] pkt54 = new byte[54];
        byte[] enc54 = CicIdsBytePreprocessor.encodePacket(pkt54, PacketDirection.FORWARD, 0);
        assertEquals(0, enc54[2]);
        assertEquals(54, enc54[3]);

        byte[] pkt1500 = new byte[1500]; // 0x05DC
        byte[] enc1500 = CicIdsBytePreprocessor.encodePacket(pkt1500, PacketDirection.FORWARD, 0);
        assertEquals((byte) 0x05, enc1500[2]);
        assertEquals((byte) 0xDC, enc1500[3]);
    }

    @Test
    public void testEncodePacketPayloadPaddingAndTruncation() {
        // Short packet: 10 bytes -> padded to 243
        byte[] shortPkt = new byte[10];
        Arrays.fill(shortPkt, (byte) 0x33);
        byte[] encShort = CicIdsBytePreprocessor.encodePacket(shortPkt, PacketDirection.FORWARD, 0);
        assertEquals(CicIdsBytePreprocessor.BYTES_PER_PACKET, encShort.length);
        // Header bytes 0..3
        assertEquals(0, encShort[0]); // fwd
        assertEquals(0, encShort[1]); // seq
        assertEquals(0, encShort[2]); // len high
        assertEquals(10, encShort[3]); // len low
        // Payload bytes 4..13 are 0x33
        for (int i = 4; i < 14; i++) {
            assertEquals((byte) 0x33, encShort[i]);
        }
        // Remaining bytes 14..242 are 0
        for (int i = 14; i < CicIdsBytePreprocessor.BYTES_PER_PACKET; i++) {
            assertEquals(0, encShort[i]);
        }

        // Long packet: 500 bytes -> truncated to 239 bytes payload
        byte[] longPkt = new byte[500];
        Arrays.fill(longPkt, (byte) 0x44);
        byte[] encLong = CicIdsBytePreprocessor.encodePacket(longPkt, PacketDirection.FORWARD, 2);
        assertEquals(CicIdsBytePreprocessor.BYTES_PER_PACKET, encLong.length);
        assertEquals(2, encLong[1]); // seq 2
        for (int i = 4; i < CicIdsBytePreprocessor.BYTES_PER_PACKET; i++) {
            if (i >= 30 && i <= 37) {
                // Offsets 30..37 correspond to masked IPv4 addresses (bytes 26..33 of packet)
                assertEquals(0, encLong[i], "Offset " + i + " must be masked to 0");
            } else {
                assertEquals((byte) 0x44, encLong[i], "Offset " + i + " must be 0x44");
            }
        }
    }

    @Test
    public void testExtractBytesIncompleteWindowZeroPadding() {
        SequentialPacketWindow window = new SequentialPacketWindow("flow-test", 1, 1, 9);
        // Add 3 non-null packets to the window
        for (int i = 0; i < 3; i++) {
            Packet p = createSyntheticEthernetPacket(60, i % 2 == 0);
            window.addPacket(p, System.currentTimeMillis() + i * 10, PacketDirection.FORWARD, i + 1);
        }
        assertEquals(3, window.size());
        assertFalse(window.isFull());

        byte[] windowBytes = CicIdsBytePreprocessor.extractBytes(window);
        assertNotNull(windowBytes);
        assertEquals(CicIdsBytePreprocessor.WINDOW_BYTES, windowBytes.length);

        // Slots 0, 1, 2 should have sequence indices 0, 1, 2 and non-zero payload
        for (int slot = 0; slot < 3; slot++) {
            int offset = slot * CicIdsBytePreprocessor.BYTES_PER_PACKET;
            assertEquals((byte) slot, windowBytes[offset + 1], "Slot " + slot + " sequence byte must equal " + slot);
            assertEquals(60, (windowBytes[offset + 2] << 8) | (windowBytes[offset + 3] & 0xFF));
        }

        // Slots 3 through 8 (all remaining slots) must be completely zero-padded
        for (int slot = 3; slot < 9; slot++) {
            int offset = slot * CicIdsBytePreprocessor.BYTES_PER_PACKET;
            for (int b = 0; b < CicIdsBytePreprocessor.BYTES_PER_PACKET; b++) {
                assertEquals(0, windowBytes[offset + b],
                        "Incomplete slot " + slot + " byte " + b + " must be 0");
            }
        }
    }

    /**
     * Genuine Packet Preprocessing Parity Test:
     * Constructs real Pcap4j {@link EthernetPacket} objects from raw deterministic packet stream
     * (golden_packet_window_raw.bin), populates a {@link SequentialPacketWindow}, passes it
     * through {@link CicIdsBytePreprocessor#extractBytes(SequentialPacketWindow)}, and validates
     * byte-for-byte exact equality against the Python reference output (golden_packet_window_2187.bin).
     *
     * <p>Provenance:
     * - The 9 packets represent varying protocol combinations (TCP SYN, ACK, short payload, full MTU 1500,
     *   variable payloads), both FORWARD and BACKWARD directions.
     * - Generated via Python reference encoder matching {@code encode_packet()} in {@code ml/extract_cic_ids2017.py}:
     *   byte 0: direction (0=fwd, 1=bwd), byte 1: sequence (0..8), bytes 2..3: length (big-endian 16-bit),
     *   bytes 4..242: raw Ethernet frame with IPv4 addresses (offsets 26..33) masked to 0x00.
     * - Fixture SHA256: 55890e439760cc118e946157ee8ff0f322da003b0db546e0800c1cb03b2f61c2.
     */
    @Test
    public void testRealSequentialPacketWindowMatchesPythonGoldenWindow() throws Exception {
        byte[] rawStream = loadFixtureBytes("golden_packet_window_raw.bin");
        byte[] expectedWindow2187 = loadFixtureBytes("golden_packet_window_2187.bin");
        assertEquals(2187, expectedWindow2187.length);

        SequentialPacketWindow window = new SequentialPacketWindow("192.168.10.50:49152 <-> 172.16.0.1:80 [TCP]", 1, 1, 9);

        try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(rawStream))) {
            for (int i = 0; i < 9; i++) {
                int dirByte = dis.readUnsignedByte();
                int pktLen = dis.readInt();
                byte[] rawPkt = new byte[pktLen];
                dis.readFully(rawPkt);

                Packet packet = EthernetPacket.newPacket(rawPkt, 0, rawPkt.length);
                assertNotNull(packet);
                assertEquals(pktLen, packet.length());
                assertNotNull(packet.getRawData());

                PacketDirection direction = (dirByte == 0) ? PacketDirection.FORWARD : PacketDirection.BACKWARD;
                window.addPacket(packet, 1600000000000L + i * 100, direction, i + 1);
            }
        }

        assertTrue(window.isFull());
        assertEquals(9, window.size());

        // Extract bytes from real SequentialPacketWindow containing real Pcap4j packets
        byte[] actualWindow2187 = CicIdsBytePreprocessor.extractBytes(window);
        assertNotNull(actualWindow2187);
        assertEquals(2187, actualWindow2187.length);

        // Byte-for-byte exact equality against Python golden extraction
        assertArrayEquals(expectedWindow2187, actualWindow2187,
                "Java packet preprocessing of genuine Pcap4j packets must match Python extraction byte-for-byte");

        // Verify normalized float32 tensor values
        float[][][] tensor = CicIdsBytePreprocessor.extractNormalizedTensor(window);
        assertEquals(1, tensor.length);
        assertEquals(1, tensor[0].length);
        assertEquals(2187, tensor[0][0].length);

        for (int i = 0; i < 2187; i++) {
            float expectedFloat = (expectedWindow2187[i] & 0xFF) / 255.0f;
            assertEquals(expectedFloat, tensor[0][0][i], 1e-6f,
                    "Normalized tensor at index " + i + " must match Python normalization");
        }
    }

    @Test
    public void testToNormalizedTensorShapeAndScale() {
        byte[] bytes = new byte[CicIdsBytePreprocessor.WINDOW_BYTES];
        bytes[0] = 0;
        bytes[1] = (byte) 100;
        bytes[2] = (byte) 200;
        bytes[3] = (byte) 255;

        float[][][] tensor = CicIdsBytePreprocessor.toNormalizedTensor(bytes);
        assertNotNull(tensor);
        assertEquals(1, tensor.length);
        assertEquals(1, tensor[0].length);
        assertEquals(CicIdsBytePreprocessor.WINDOW_BYTES, tensor[0][0].length);

        assertEquals(0.0f, tensor[0][0][0], 1e-6);
        assertEquals(100.0f / 255.0f, tensor[0][0][1], 1e-6);
        assertEquals(200.0f / 255.0f, tensor[0][0][2], 1e-6);
        assertEquals(1.0f, tensor[0][0][3], 1e-6);

        // Invalid length check
        assertThrows(IllegalArgumentException.class, () -> {
            CicIdsBytePreprocessor.toNormalizedTensor(new byte[100]);
        });
    }

    @Test
    public void testToRawHexString() {
        byte[] bytes = new byte[] { (byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF, 0x00, 0x01 };
        assertEquals("DEADBEEF0001", CicIdsBytePreprocessor.toRawHexString(bytes));
        assertEquals("", CicIdsBytePreprocessor.toRawHexString(null));
        assertEquals("", CicIdsBytePreprocessor.toRawHexString(new byte[0]));
    }

    @Test
    public void testFormatHexDumpCanonicalWiresharkStyle() {
        // Test 16-byte single line
        byte[] bytes16 = new byte[] {
                0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x2C, 0x20, 0x57,
                0x6F, 0x72, 0x6C, 0x64, 0x21, 0x00, 0x01, 0x02
        };
        String dump16 = CicIdsBytePreprocessor.formatHexDump(bytes16);
        assertNotNull(dump16);
        assertTrue(dump16.startsWith("00000000  48 65 6C 6C 6F 2C 20 57  6F 72 6C 64 21 00 01 02  |Hello, World!...|"));
        assertTrue(dump16.endsWith("\n"));

        // Test multi-line 2,187-byte window dump
        byte[] windowBytes = new byte[CicIdsBytePreprocessor.WINDOW_BYTES];
        Arrays.fill(windowBytes, (byte) 0x41); // 'A'
        String dumpWindow = CicIdsBytePreprocessor.formatHexDump(windowBytes);
        assertNotNull(dumpWindow);
        // 2187 bytes = 136 lines of 16 bytes + 1 line of 11 bytes = 137 lines
        String[] lines = dumpWindow.split("\n");
        assertEquals(137, lines.length);
        assertTrue(lines[0].startsWith("00000000  "));
        assertTrue(lines[136].startsWith("00000880  "));
        assertTrue(lines[0].contains("|AAAAAAAAAAAAAAAA|"));

        // Null and empty safety
        assertEquals("", CicIdsBytePreprocessor.formatHexDump(null));
        assertEquals("", CicIdsBytePreprocessor.formatHexDump(new byte[0]));
    }
}
