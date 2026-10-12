package com.spinids;

import com.spinids.alert.AlertManager;
import com.spinids.detection.DetectionResult;
import com.spinids.detection.OnnxDetector;
import com.spinids.detection.OnnxDetector.ModelType;
import com.spinids.image.SequentialPacketWindow;
import com.spinids.image.SequentialPacketWindow.PacketDirection;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;

import java.awt.image.BufferedImage;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration test suite for Byte 1D CNN detector, incomplete window handling,
 * error boundaries, model selection toggles, and alert logging.
 */
public class ByteDetectorIntegrationTest {

    private static OnnxDetector byteDetector;
    private static OnnxDetector rgbDetector;

    @BeforeAll
    public static void setUp() throws Exception {
        byteDetector = OnnxDetector.createByteDetector();
        rgbDetector = OnnxDetector.createRgbDetector();
    }

    @AfterAll
    public static void tearDown() {
        if (byteDetector != null) byteDetector.close();
        if (rgbDetector != null) rgbDetector.close();
    }

    private static Packet createSyntheticEthernetPacket(int length, boolean isForward) {
        byte[] raw = new byte[Math.max(length, 54)];
        Arrays.fill(raw, (byte) 0x66);
        // Ethernet Header: Dst MAC (0..5), Src MAC (6..11), EtherType (12..13)
        raw[12] = 0x08; raw[13] = 0x00; // IPv4
        // IPv4 Header: Version 4, IHL 5 (offset 14)
        raw[14] = 0x45;
        raw[22] = 64;   // TTL
        raw[23] = 6;    // TCP
        if (isForward) {
            raw[26] = (byte) 192; raw[27] = (byte) 168; raw[28] = 1; raw[29] = 10;
            raw[30] = (byte) 192; raw[31] = (byte) 168; raw[32] = 1; raw[33] = 50;
            raw[34] = 0x00; raw[35] = 0x50; // Port 80
            raw[36] = 0x01; raw[37] = (byte) 0xBB; // Port 443
        } else {
            raw[26] = (byte) 192; raw[27] = (byte) 168; raw[28] = 1; raw[29] = 50;
            raw[30] = (byte) 192; raw[31] = (byte) 168; raw[32] = 1; raw[33] = 10;
            raw[34] = 0x01; raw[35] = (byte) 0xBB; // Port 443
            raw[36] = 0x00; raw[37] = 0x50; // Port 80
        }
        try {
            return EthernetPacket.newPacket(raw, 0, raw.length);
        } catch (Exception e) {
            throw new RuntimeException("Failed to construct synthetic packet", e);
        }
    }

    @Test
    public void testModelSelectionDefaultAndExplicit() throws Exception {
        // Default constructor MUST default to RGB_IMAGE for backward compatibility
        try (OnnxDetector defaultDetector = new OnnxDetector()) {
            assertNotNull(defaultDetector);
            assertEquals(ModelType.RGB_IMAGE, defaultDetector.getModelType());
            assertEquals("input", defaultDetector.getInputName());
            assertTrue(defaultDetector.getModelDescription().contains("RGB"));
        }

        assertEquals(ModelType.BYTE_1D, byteDetector.getModelType());
        assertEquals("byte_input", byteDetector.getInputName());
        assertTrue(byteDetector.getModelDescription().contains("Byte 1D"));

        assertEquals(ModelType.RGB_IMAGE, rgbDetector.getModelType());
        assertEquals("input", rgbDetector.getInputName());
    }

    @Test
    public void testFullNinePacketWindowInference() throws Exception {
        SequentialPacketWindow window = new SequentialPacketWindow("192.168.1.10:80->192.168.1.50:443 [TCP]", 1, 10, 9);
        for (int i = 0; i < 9; i++) {
            boolean isForward = (i % 2 == 0);
            PacketDirection dir = isForward ? PacketDirection.FORWARD : PacketDirection.BACKWARD;
            Packet packet = createSyntheticEthernetPacket(64 + i * 10, isForward);
            window.addPacket(packet, System.currentTimeMillis() + i * 10, dir, i + 1);
        }
        assertTrue(window.isFull());
        assertEquals(9, window.size());

        DetectionResult result = byteDetector.detect(window, "live_burst.pcap");
        assertNotNull(result);
        assertEquals(10, result.getWindowIndex());
        assertEquals("192.168.1.10:80->192.168.1.50:443 [TCP]", result.getFlowKey());
        assertEquals("live_burst.pcap", result.getPcapFile());

        String label = result.getPredictedLabel();
        assertTrue("NORMAL".equals(label) || "MALICIOUS".equals(label));

        double sum = result.getNormalProbability() + result.getMaliciousProbability();
        assertEquals(1.0, sum, 1e-4, "Probabilities must sum to 1.0");
        assertEquals(Math.max(result.getNormalProbability(), result.getMaliciousProbability()),
                result.getConfidence(), 1e-6);
    }

    @Test
    public void testIncompleteWindowBlockedFromByteInference() {
        // Window with only 4 packets (incomplete tail window at capture boundary)
        SequentialPacketWindow partialWindow = new SequentialPacketWindow("flow-partial-byte", 2, 5, 9);
        for (int i = 0; i < 4; i++) {
            Packet packet = createSyntheticEthernetPacket(60, true);
            partialWindow.addPacket(packet, System.currentTimeMillis() + i * 5, PacketDirection.FORWARD, i + 1);
        }
        assertFalse(partialWindow.isFull());
        assertEquals(4, partialWindow.size());

        // In BYTE_1D mode, incomplete windows must NEVER reach inference
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> {
            byteDetector.detect(partialWindow, "incomplete_capture.pcap");
        });
        assertTrue(ex.getMessage().contains("Byte 1D CNN model requires a complete 9-packet window"));
        assertTrue(ex.getMessage().contains("received incomplete window with 4 packet(s)"));
    }

    @Test
    public void testIncompleteWindowSucceedsInRgbMode() throws Exception {
        // Window with only 4 packets (incomplete window lifecycle in RGB mode)
        SequentialPacketWindow partialWindow = new SequentialPacketWindow("flow-partial-rgb", 2, 5, 9);
        for (int i = 0; i < 4; i++) {
            Packet packet = createSyntheticEthernetPacket(60, true);
            partialWindow.addPacket(packet, System.currentTimeMillis() + i * 5, PacketDirection.FORWARD, i + 1);
        }
        assertFalse(partialWindow.isFull());
        assertEquals(4, partialWindow.size());

        // In RGB mode, backward compatibility is strictly preserved (zero-padded 27x27 image infers normally)
        DetectionResult result = rgbDetector.detect(partialWindow, "incomplete_capture.pcap");
        assertNotNull(result);
        assertEquals(5, result.getWindowIndex());
        assertEquals("flow-partial-rgb", result.getFlowKey());
        assertEquals(1.0, result.getNormalProbability() + result.getMaliciousProbability(), 1e-4);
        assertNotNull(result.getPredictedLabel());
    }

    @Test
    public void testInferenceErrorHandlingAndBoundaries() {
        // Null window to detect(SequentialPacketWindow)
        assertThrows(IllegalArgumentException.class, () -> {
            byteDetector.detect((SequentialPacketWindow) null, "test.pcap");
        });

        // Calling detect(BufferedImage) on Byte detector must throw UnsupportedOperationException
        BufferedImage img = new BufferedImage(27, 27, BufferedImage.TYPE_INT_RGB);
        assertThrows(UnsupportedOperationException.class, () -> {
            byteDetector.detect(img, 1, "flow-1", "test.pcap");
        });

        // Calling detectBytes on RGB detector must throw UnsupportedOperationException
        float[][][] dummyTensor = new float[1][1][2187];
        assertThrows(UnsupportedOperationException.class, () -> {
            rgbDetector.detectBytes(dummyTensor, 1, "flow-1", "test.pcap");
        });

        // Passing invalid tensor shape to detectBytes must throw IllegalArgumentException
        float[][][] invalidShape = new float[1][1][100];
        assertThrows(IllegalArgumentException.class, () -> {
            byteDetector.detectBytes(invalidShape, 1, "flow-1", "test.pcap");
        });
    }

    @Test
    public void testAlertManagerIntegrationWithByteResult(@TempDir Path tempDir) throws Exception {
        File alertLog = tempDir.resolve("byte_alerts.csv").toFile();
        AlertManager alertManager = new AlertManager(alertLog.getAbsolutePath());

        SequentialPacketWindow window = new SequentialPacketWindow("flow-alert-test", 1, 7, 9);
        for (int i = 0; i < 9; i++) {
            Packet packet = createSyntheticEthernetPacket(70, true);
            window.addPacket(packet, System.currentTimeMillis() + i * 2, PacketDirection.FORWARD, i + 1);
        }

        DetectionResult result = byteDetector.detect(window, "alert_test.pcap");
        assertNotNull(result);

        alertManager.handleDetection(result);

        assertTrue(alertLog.exists());
        try (BufferedReader reader = new BufferedReader(new FileReader(alertLog))) {
            String header = reader.readLine();
            assertNotNull(header);
            assertTrue(header.contains("timestamp,pcap_file,window_index,prediction"));

            String logLine = reader.readLine();
            assertNotNull(logLine);
            assertTrue(logLine.contains("alert_test.pcap"));
            assertTrue(logLine.contains("7"));
            assertTrue(logLine.contains(result.getPredictedLabel()));
        }
    }
}

