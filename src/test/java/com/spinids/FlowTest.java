package com.spinids;

import com.spinids.flow.Flow;
import com.spinids.flow.FlowManager;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class FlowTest {

    @Test
    public void testFlowInitializationAndMetrics() {
        Flow flow = new Flow("192.168.1.10", "192.168.1.20", 5000, 80, "TCP", 100, 1000L);

        assertEquals("192.168.1.10", flow.getSourceIp());
        assertEquals("192.168.1.20", flow.getDestinationIp());
        assertEquals(5000, flow.getSourcePort());
        assertEquals(80, flow.getDestinationPort());
        assertEquals("TCP", flow.getProtocol());
        assertEquals(1, flow.getPacketCount());
        assertEquals(100, flow.getTotalBytes());
        assertEquals(1000L, flow.getFirstPacketTime());
        assertEquals(1000L, flow.getLastPacketTime());
        assertEquals(0L, flow.getDuration());

        // Update flow with a second packet
        flow.update(200, 1500L);
        assertEquals(2, flow.getPacketCount());
        assertEquals(300, flow.getTotalBytes());
        assertEquals(1000L, flow.getFirstPacketTime());
        assertEquals(1500L, flow.getLastPacketTime());
        assertEquals(500L, flow.getDuration());

        // Update flow with an out-of-order packet
        flow.update(50, 800L);
        assertEquals(3, flow.getPacketCount());
        assertEquals(350, flow.getTotalBytes());
        assertEquals(800L, flow.getFirstPacketTime());
        assertEquals(1500L, flow.getLastPacketTime());
        assertEquals(700L, flow.getDuration());
    }

    @Test
    public void testFlowEqualityBasedOn5Tuple() {
        Flow flow1 = new Flow("10.0.0.1", "10.0.0.2", 1234, 443, "TCP", 60, 1000L);
        Flow flow2 = new Flow("10.0.0.1", "10.0.0.2", 1234, 443, "TCP", 1500, 2000L);
        Flow flow3 = new Flow("10.0.0.1", "10.0.0.2", 1234, 80, "TCP", 60, 1000L);

        assertEquals(flow1, flow2);
        assertEquals(flow1.hashCode(), flow2.hashCode());
        assertNotEquals(flow1, flow3);
    }

    @Test
    public void testFlowManagerKeyGeneration() {
        String key1 = FlowManager.generateKey("192.168.1.1", "192.168.1.2", 8080, 443, "TCP");
        String key2 = FlowManager.generateKey("192.168.1.1", "192.168.1.2", 8080, 443, "TCP");
        String key3 = FlowManager.generateKey("192.168.1.2", "192.168.1.1", 443, 8080, "TCP");

        assertEquals(key1, key2);
        assertNotEquals(key1, key3);
    }

    @Test
    public void testFlowManagerNullPacketSafety() {
        FlowManager manager = new FlowManager();
        assertNull(manager.processPacket(null));
        assertEquals(0, manager.getTotalFlows());
    }
}
