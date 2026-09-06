package com.spinids;

import com.spinids.features.FlowFeatures;
import com.spinids.features.FlowFeatureExtractor;
import com.spinids.flow.Flow;
import com.spinids.flow.FlowManager;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class FlowFeatureTest {

    @Test
    public void testFeatureCalculationsWithValidDuration() {
        // Create forward flow: 1000ms duration, 10 packets, 5000 bytes
        Flow forward = new Flow("192.168.1.10", "192.168.1.20", 5000, 80, "TCP", 500, 1000L);
        for (int i = 0; i < 9; i++) {
            forward.update(500, 1000L + (i + 1) * 100); // 1000 to 1900 ms -> duration 900ms
        }
        forward.update(0, 2000L); // total 11 packets, 5000 bytes, duration 1000ms (1.0 sec)

        // Create reverse flow: 5 packets
        Flow reverse = new Flow("192.168.1.20", "192.168.1.10", 80, 5000, "TCP", 200, 1100L);
        for (int i = 0; i < 4; i++) {
            reverse.update(200, 1200L + i * 100);
        }

        Map<String, Flow> flowMap = new HashMap<>();
        String fwdKey = FlowManager.generateKey("192.168.1.10", "192.168.1.20", 5000, 80, "TCP");
        String revKey = FlowManager.generateKey("192.168.1.20", "192.168.1.10", 80, 5000, "TCP");
        flowMap.put(fwdKey, forward);
        flowMap.put(revKey, reverse);

        FlowFeatures features = FlowFeatureExtractor.extract(forward, flowMap);

        assertNotNull(features);
        assertEquals("192.168.1.10", features.getSourceIp());
        assertEquals("192.168.1.20", features.getDestinationIp());
        assertEquals(5000, features.getSourcePort());
        assertEquals(80, features.getDestinationPort());
        assertEquals("TCP", features.getProtocol());
        assertEquals(1000L, features.getDuration());
        assertEquals(11, features.getPacketCount());
        assertEquals(5000L, features.getTotalBytes());
        assertEquals(5000.0 / 11, features.getAvgPacketSize(), 0.001);
        assertEquals(11.0, features.getPacketsPerSecond(), 0.001); // 11 packets / 1.0 sec
        assertEquals(5000.0, features.getBytesPerSecond(), 0.001); // 5000 bytes / 1.0 sec
        assertEquals(11, features.getForwardPacketCount());
        assertEquals(5, features.getReversePacketCount());
    }

    @Test
    public void testDivisionByZeroProtectionForZeroDuration() {
        // Flow with single packet -> duration = 0
        Flow flow = new Flow("10.0.0.1", "10.0.0.2", 1234, 443, "UDP", 100, 5000L);

        FlowFeatures features = FlowFeatureExtractor.extract(flow, (Map<String, Flow>) null);

        assertNotNull(features);
        assertEquals(0L, features.getDuration());
        assertEquals(1L, features.getPacketCount());
        assertEquals(100L, features.getTotalBytes());
        assertEquals(100.0, features.getAvgPacketSize(), 0.001);
        // Packets/sec and Bytes/sec must be 0.0, NOT Double.POSITIVE_INFINITY or NaN
        assertEquals(0.0, features.getPacketsPerSecond(), 0.001);
        assertEquals(0.0, features.getBytesPerSecond(), 0.001);
        assertEquals(1L, features.getForwardPacketCount());
        assertEquals(0L, features.getReversePacketCount());
    }

    @Test
    public void testToDoubleArrayVectorForML() {
        Flow flow = new Flow("10.0.0.1", "10.0.0.2", 1234, 443, "TCP", 100, 1000L);
        FlowFeatures features = FlowFeatureExtractor.extract(flow, (Map<String, Flow>) null);

        double[] vector = features.toDoubleArray();
        assertNotNull(vector);
        assertEquals(10, vector.length);
        assertEquals(features.getDuration(), vector[0]);
        assertEquals(features.getPacketCount(), vector[1]);
        assertEquals(features.getTotalBytes(), vector[2]);
        assertEquals(features.getSourcePort(), vector[8]);
        assertEquals(features.getDestinationPort(), vector[9]);
    }
}
