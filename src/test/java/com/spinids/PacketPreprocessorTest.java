package com.spinids;

import com.spinids.image.PacketPreprocessor;
import com.spinids.image.SequentialPacketWindow.PacketDirection;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class PacketPreprocessorTest {

    @Test
    public void testIpv4AddressMaskingPreservesPortsAndProtocol() {
        // Construct a synthetic IPv4 packet buffer (20 bytes IPv4 header + 8 bytes TCP header)
        byte[] buffer = new byte[PacketPreprocessor.DEFAULT_BYTES_PER_PACKET];
        Arrays.fill(buffer, (byte) 0);

        int protoOffset = PacketPreprocessor.OFFSET_PROTOCOL_DATA; // offset 4

        // IPv4 Header: Version=4, IHL=5 (0x45), TTL=64, Protocol=6 (TCP)
        buffer[protoOffset] = (byte) 0x45;
        buffer[protoOffset + 8] = (byte) 64;   // TTL
        buffer[protoOffset + 9] = (byte) 6;    // Protocol = TCP

        // Source IP: 192.168.1.50 (bytes 12..15 of IP header)
        buffer[protoOffset + 12] = (byte) 192;
        buffer[protoOffset + 13] = (byte) 168;
        buffer[protoOffset + 14] = (byte) 1;
        buffer[protoOffset + 15] = (byte) 50;

        // Destination IP: 10.0.0.1 (bytes 16..19 of IP header)
        buffer[protoOffset + 16] = (byte) 10;
        buffer[protoOffset + 17] = (byte) 0;
        buffer[protoOffset + 18] = (byte) 0;
        buffer[protoOffset + 19] = (byte) 1;

        // Transport Layer (TCP Ports starting at byte 20 of IP header)
        // Source Port: 8080 (0x1F90), Dest Port: 443 (0x01BB)
        buffer[protoOffset + 20] = (byte) 0x1F;
        buffer[protoOffset + 21] = (byte) 0x90;
        buffer[protoOffset + 22] = (byte) 0x01;
        buffer[protoOffset + 23] = (byte) 0xBB;

        // Apply IP address masking
        PacketPreprocessor.maskIpAddresses(buffer, protoOffset, 28);

        // Verify Source IP and Destination IP are zeroed out
        assertEquals(0, buffer[protoOffset + 12]);
        assertEquals(0, buffer[protoOffset + 13]);
        assertEquals(0, buffer[protoOffset + 14]);
        assertEquals(0, buffer[protoOffset + 15]);

        assertEquals(0, buffer[protoOffset + 16]);
        assertEquals(0, buffer[protoOffset + 17]);
        assertEquals(0, buffer[protoOffset + 18]);
        assertEquals(0, buffer[protoOffset + 19]);

        // Verify IP Version/IHL, TTL, and Protocol are preserved
        assertEquals((byte) 0x45, buffer[protoOffset]);
        assertEquals((byte) 64, buffer[protoOffset + 8]);
        assertEquals((byte) 6, buffer[protoOffset + 9]);

        // Verify TCP Ports are fully preserved
        assertEquals((byte) 0x1F, buffer[protoOffset + 20]);
        assertEquals((byte) 0x90, buffer[protoOffset + 21]);
        assertEquals((byte) 0x01, buffer[protoOffset + 22]);
        assertEquals((byte) 0xBB, buffer[protoOffset + 23]);
    }

    @Test
    public void testIpv6AddressMaskingPreservesPortsAndNextHeader() {
        // Construct a synthetic IPv6 buffer (40 bytes IPv6 header + 8 bytes UDP header)
        byte[] buffer = new byte[PacketPreprocessor.DEFAULT_BYTES_PER_PACKET];
        Arrays.fill(buffer, (byte) 0);

        int protoOffset = PacketPreprocessor.OFFSET_PROTOCOL_DATA;

        // IPv6 Header: Version=6 (0x60), Next Header=17 (UDP at byte 6), Hop Limit=128 (at byte 7)
        buffer[protoOffset] = (byte) 0x60;
        buffer[protoOffset + 6] = (byte) 17;   // Next Header = UDP
        buffer[protoOffset + 7] = (byte) 128;  // Hop Limit

        // Source IPv6 (bytes 8..23) and Dest IPv6 (bytes 24..39)
        for (int i = 8; i < 40; i++) {
            buffer[protoOffset + i] = (byte) (i + 1);
        }

        // UDP Ports starting at byte 40: Source Port=53 (0x0035), Dest Port=5353 (0x14E9)
        buffer[protoOffset + 40] = (byte) 0x00;
        buffer[protoOffset + 41] = (byte) 0x35;
        buffer[protoOffset + 42] = (byte) 0x14;
        buffer[protoOffset + 43] = (byte) 0xE9;

        // Apply IP address masking
        PacketPreprocessor.maskIpAddresses(buffer, protoOffset, 48);

        // Verify all 32 bytes of IPv6 addresses are zeroed out
        for (int i = 8; i < 40; i++) {
            assertEquals(0, buffer[protoOffset + i], "IPv6 address byte at offset " + i + " must be masked to 0");
        }

        // Verify Version, Next Header, Hop Limit, and UDP Ports are preserved
        assertEquals((byte) 0x60, buffer[protoOffset]);
        assertEquals((byte) 17, buffer[protoOffset + 6]);
        assertEquals((byte) 128, buffer[protoOffset + 7]);
        assertEquals((byte) 0x00, buffer[protoOffset + 40]);
        assertEquals((byte) 0x35, buffer[protoOffset + 41]);
        assertEquals((byte) 0x14, buffer[protoOffset + 42]);
        assertEquals((byte) 0xE9, buffer[protoOffset + 43]);
    }

    @Test
    public void testPreprocessingSizeAndDeterminism() {
        byte[] preprocessed = PacketPreprocessor.preprocess(null, PacketDirection.FORWARD, 1, PacketPreprocessor.DEFAULT_BYTES_PER_PACKET);
        assertNotNull(preprocessed);
        assertEquals(243, preprocessed.length);
        assertEquals(PacketPreprocessor.DIRECTION_FORWARD_VAL, preprocessed[0]);
        assertEquals(1, preprocessed[1]);

        byte[] preprocessed2 = PacketPreprocessor.preprocess(null, PacketDirection.FORWARD, 1, PacketPreprocessor.DEFAULT_BYTES_PER_PACKET);
        assertArrayEquals(preprocessed, preprocessed2);
    }
}
