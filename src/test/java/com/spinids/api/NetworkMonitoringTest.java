package com.spinids.api;

import com.spinids.api.dto.NetworkInterfaceDto;
import com.spinids.api.dto.StatusResponse;
import com.spinids.capture.LiveNetworkMonitor;
import com.spinids.capture.NetworkInterfaceManager;
import com.spinids.trigger.AnomalyTrigger;
import com.spinids.trigger.TrafficMonitor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

public class NetworkMonitoringTest {

    private NetworkInterfaceManager interfaceManager;
    private TrafficMonitor trafficMonitor;
    private AnomalyTrigger anomalyTrigger;
    private LiveNetworkMonitor networkMonitor;
    private SpinEngineController engineController;

    @BeforeEach
    public void setup() {
        interfaceManager = new NetworkInterfaceManager();
        trafficMonitor = new TrafficMonitor(500.0);
        anomalyTrigger = new AnomalyTrigger(trafficMonitor, 10_000L);
        networkMonitor = new LiveNetworkMonitor(trafficMonitor, anomalyTrigger);
        engineController = SpinEngineController.getInstance();
    }

    @Test
    public void testInterfaceManagerDiscovery() {
        assertNotNull(interfaceManager);
        List<NetworkInterfaceDto> dtos = interfaceManager.getInterfaceDtos();
        assertNotNull(dtos, "Interface DTO list should not be null");

        // If running in environment with interfaces, verify DTO properties
        if (!dtos.isEmpty()) {
            NetworkInterfaceDto first = dtos.get(0);
            assertNotNull(first.getName());
            assertNotNull(first.getDisplayName());
            assertNotNull(first.getDescription());
            assertNotNull(first.getAddresses());
        }
    }

    @Test
    public void testInterfaceManagerSearch() {
        // Searching non-existent interface should return null without error
        assertNull(interfaceManager.getInterfaceByName("NonExistent_Adapter_9999"));
        assertNull(interfaceManager.getInterfaceByName(null));
        assertNull(interfaceManager.getInterfaceByName(""));
    }

    @Test
    public void testCaptureConfigurationConstants() {
        assertEquals(500.0, LiveNetworkMonitor.ANOMALY_THRESHOLD_PPS, 0.001);
        assertEquals(5, LiveNetworkMonitor.CAPTURE_DURATION_SECONDS);
        assertEquals(5000, LiveNetworkMonitor.MAX_CAPTURE_PACKETS);
        assertEquals(65536, LiveNetworkMonitor.SNAPLEN);
        assertEquals(20, LiveNetworkMonitor.READ_TIMEOUT_MS);
        assertEquals("dataset/captures/generated/", LiveNetworkMonitor.CAPTURE_OUTPUT_DIR);
    }

    @Test
    public void testMonitorStateAndCooldown() {
        assertFalse(networkMonitor.isRunning());
        assertFalse(networkMonitor.isCaptureInProgress());
        assertFalse(networkMonitor.isCooldownActive());

        // Simulate anomaly trigger
        anomalyTrigger.evaluate(600.0);
        assertTrue(networkMonitor.isCooldownActive(), "Cooldown should be active after trigger fires");

        // Subsequent evaluate during cooldown should return false
        assertFalse(anomalyTrigger.evaluate(650.0), "Cooldown must suppress duplicate triggers");
    }

    @Test
    public void testLiveNetworkMonitorInvalidInterface() {
        // Attempting to start with null interface must throw IllegalArgumentException
        assertThrows(IllegalArgumentException.class, () -> networkMonitor.startMonitoring(null));
    }

    @Test
    public void testEngineControllerInterfaceSelection() {
        // Selection of invalid interface returns false
        assertFalse(engineController.selectInterface("InvalidInterface_FakeName_12345"));
        assertFalse(engineController.selectInterface(null));

        assertNotNull(engineController.getActiveInterfaceDisplayName());
        List<NetworkInterfaceDto> ifaces = engineController.getAvailableInterfaces();
        assertNotNull(ifaces);
    }

    @Test
    public void testExtendedStatusResponse() {
        StatusResponse status = engineController.getStatus();
        assertNotNull(status);
        assertNotNull(status.getEngineState());
        assertNotNull(status.getMonitoringMode());
        assertNotNull(status.getSelectedInterface());
        assertNotNull(status.getInterfaceDescription());
        assertEquals(500.0, status.getThresholdPps(), 0.001);
        assertTrue(status.getPacketsCaptured() >= 0);
        assertFalse(status.isCaptureInProgress());
    }

    @Test
    public void testCaptureEventListenerRegistration() {
        AtomicBoolean triggered = new AtomicBoolean(false);
        networkMonitor.setEventListener(new LiveNetworkMonitor.CaptureEventListener() {
            @Override
            public void onAnomalyTriggered(double rate, double threshold, File targetPcapFile) {
                triggered.set(true);
            }

            @Override
            public void onCaptureCompleted(File pcapFile, int packetCount) {}

            @Override
            public void onError(String errorMessage) {}
        });

        assertFalse(triggered.get());
    }
}
