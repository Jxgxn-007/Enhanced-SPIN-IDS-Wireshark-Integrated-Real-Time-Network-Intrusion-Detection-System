package com.spinids;

import com.spinids.detection.DetectionResult;
import com.spinids.detection.DetectionResult.CorrelationStatus;
import com.spinids.detection.OnnxDetector;
import com.spinids.detection.OnnxDetector.ModelType;
import com.spinids.image.SequentialPacketWindow;
import com.spinids.image.SequentialPacketWindow.PacketDirection;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;

import java.awt.image.BufferedImage;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration test suite for Phase 1 HYBRID dual-branch inference,
 * validating concurrent RGB + Byte model execution, score fusion mathematics,
 * alpha=1.0 weighting behavior, correlation tracking, and incomplete window enforcement.
 */
public class HybridDetectorIntegrationTest {

    private static OnnxDetector hybridDetector;
    private static OnnxDetector balancedHybridDetector;

    @BeforeAll
    public static void setUp() throws Exception {
        // Default hybrid detector: alpha = 1.0, threshold = 0.9 (from fusion_config.json)
        hybridDetector = OnnxDetector.createHybridDetector();
        // Custom balanced hybrid detector: alpha = 0.5, threshold = 0.5
        balancedHybridDetector = OnnxDetector.createHybridDetector(0.5, 0.5);
    }

    @AfterAll
    public static void tearDown() {
        if (hybridDetector != null) hybridDetector.close();
        if (balancedHybridDetector != null) balancedHybridDetector.close();
    }

    private static Packet createSyntheticPacket(int length, boolean isForward) {
        byte[] raw = new byte[Math.max(length, 54)];
        Arrays.fill(raw, (byte) 0x55);
        // Ethernet Header: IPv4 EtherType (0x0800)
        raw[12] = 0x08; raw[13] = 0x00;
        // IPv4 Header: Version 4, IHL 5
        raw[14] = 0x45;
        raw[22] = 64; // TTL
        raw[23] = 6;  // TCP protocol
        if (isForward) {
            raw[26] = (byte) 10; raw[27] = 0; raw[28] = 0; raw[29] = 1;
            raw[30] = (byte) 10; raw[31] = 0; raw[32] = 0; raw[33] = 2;
            raw[34] = 0x00; raw[35] = (byte) 80;
            raw[36] = (byte) 0xC0; raw[37] = 0x01;
        } else {
            raw[26] = (byte) 10; raw[27] = 0; raw[28] = 0; raw[29] = 2;
            raw[30] = (byte) 10; raw[31] = 0; raw[32] = 0; raw[33] = 1;
            raw[34] = (byte) 0xC0; raw[35] = 0x01;
            raw[36] = 0x00; raw[37] = (byte) 80;
        }
        try {
            return EthernetPacket.newPacket(raw, 0, raw.length);
        } catch (Exception e) {
            throw new RuntimeException("Failed to construct synthetic test packet", e);
        }
    }

    private static SequentialPacketWindow buildWindow(int packetCount) {
        SequentialPacketWindow window = new SequentialPacketWindow("10.0.0.1:80<->10.0.0.2:49153", 9, 100);
        for (int i = 0; i < packetCount; i++) {
            PacketDirection dir = (i % 2 == 0) ? PacketDirection.FORWARD : PacketDirection.BACKWARD;
            Packet pkt = createSyntheticPacket(100 + i * 20, i % 2 == 0);
            window.addPacket(pkt, System.currentTimeMillis() + i * 10, dir, i + 1);
        }
        return window;
    }

    @Test
    public void testHybridDetectorLifecycleAndMetadata() {
        assertNotNull(hybridDetector);
        assertEquals(ModelType.HYBRID, hybridDetector.getModelType());
        assertEquals(1.0, hybridDetector.getFusionAlpha(), 0.0001);
        assertEquals(0.9, hybridDetector.getFusionThreshold(), 0.0001);
        assertNotNull(hybridDetector.getModelPath());
        assertNotNull(hybridDetector.getByteModelPath());
        assertNotNull(hybridDetector.getInputName());
        assertNotNull(hybridDetector.getByteInputName());

        String desc = hybridDetector.getModelDescription();
        assertNotNull(desc);
        assertTrue(desc.contains("HYBRID"), "Description must indicate HYBRID mode: " + desc);
        assertTrue(desc.contains("alpha=1.00"), "Description must reflect alpha=1.00: " + desc);
    }

    @Test
    public void testDualBranchInferenceExecutionOnFullWindow() throws Exception {
        SequentialPacketWindow fullWindow = buildWindow(9);
        assertTrue(fullWindow.isFull());

        DetectionResult result = hybridDetector.detect(fullWindow, 1, fullWindow.getFlowId(), "test_capture.pcap");
        assertNotNull(result);

        // Verify dual-branch state
        assertTrue(result.isDualBranch(), "Result must be flagged as dual-branch");
        assertNotEquals(CorrelationStatus.SINGLE_BRANCH, result.getCorrelationStatus());

        // Verify RGB branch outcomes
        assertNotNull(result.getRgbPredictedLabel());
        assertTrue(result.getRgbNormalProbability() >= 0.0 && result.getRgbNormalProbability() <= 1.0);
        assertTrue(result.getRgbMaliciousProbability() >= 0.0 && result.getRgbMaliciousProbability() <= 1.0);
        assertEquals(1.0, result.getRgbNormalProbability() + result.getRgbMaliciousProbability(), 0.001);
        assertEquals(Math.max(result.getRgbNormalProbability(), result.getRgbMaliciousProbability()),
                result.getRgbConfidence(), 0.001);

        // Verify Byte branch outcomes
        assertNotNull(result.getBytePredictedLabel());
        assertTrue(result.getByteNormalProbability() >= 0.0 && result.getByteNormalProbability() <= 1.0);
        assertTrue(result.getByteMaliciousProbability() >= 0.0 && result.getByteMaliciousProbability() <= 1.0);
        assertEquals(1.0, result.getByteNormalProbability() + result.getByteMaliciousProbability(), 0.001);
        assertEquals(Math.max(result.getByteNormalProbability(), result.getByteMaliciousProbability()),
                result.getByteConfidence(), 0.001);

        // Verify overall fused outcome
        assertNotNull(result.getPredictedLabel());
        assertEquals(1.0, result.getNormalProbability() + result.getMaliciousProbability(), 0.001);
        assertTrue(result.getConfidence() >= 0.0 && result.getConfidence() <= 1.0);

        // Correlation status consistency
        if (result.getRgbPredictedLabel().equals(result.getBytePredictedLabel())) {
            assertTrue(result.isAgreement(), "When both models agree, isAgreement() must be true");
            assertFalse(result.isConflict());
        } else {
            assertTrue(result.isConflict(), "When models disagree, isConflict() must be true");
            assertEquals(CorrelationStatus.CONFLICT_RESOLVED, result.getCorrelationStatus());
        }
    }

    @Test
    public void testSelectedAlpha1EffectIgnoresByteNumericScore() throws Exception {
        // In default configuration (alpha = 1.0, threshold = 0.9):
        // fusedMalicious = 1.0 * rgbMalicious + 0.0 * byteMalicious = rgbMalicious
        SequentialPacketWindow fullWindow = buildWindow(9);
        DetectionResult result = hybridDetector.detect(fullWindow, 2, fullWindow.getFlowId(), "alpha_test.pcap");

        assertEquals(result.getRgbMaliciousProbability(), result.getFusedMaliciousProbability(), 0.0001,
                "Under alpha=1.0, fusedMaliciousProbability must exactly match rgbMaliciousProbability");
        assertEquals(result.getRgbMaliciousProbability(), result.getMaliciousProbability(), 0.0001);
        assertEquals(result.getRgbNormalProbability(), result.getNormalProbability(), 0.0001);

        // Decision threshold is 0.9
        if (result.getFusedMaliciousProbability() >= 0.9) {
            assertEquals("MALICIOUS", result.getPredictedLabel());
            assertEquals(result.getFusedMaliciousProbability(), result.getConfidence(), 0.0001);
        } else {
            assertEquals("NORMAL", result.getPredictedLabel());
            assertEquals(1.0 - result.getFusedMaliciousProbability(), result.getConfidence(), 0.0001);
        }
    }

    @Test
    public void testCustomScoreFusionFormulaWithBalancedAlpha() throws Exception {
        // Balanced hybrid detector: alpha = 0.5, threshold = 0.5
        SequentialPacketWindow fullWindow = buildWindow(9);
        DetectionResult result = balancedHybridDetector.detect(fullWindow, 3, fullWindow.getFlowId(), "balanced.pcap");

        double expectedFused = 0.5 * result.getRgbMaliciousProbability() + 0.5 * result.getByteMaliciousProbability();
        assertEquals(expectedFused, result.getFusedMaliciousProbability(), 0.0001);
        assertEquals(expectedFused, result.getMaliciousProbability(), 0.0001);

        if (expectedFused >= 0.5) {
            assertEquals("MALICIOUS", result.getPredictedLabel());
        } else {
            assertEquals("NORMAL", result.getPredictedLabel());
        }
    }

    @Test
    public void testIncompleteWindowThrowsInHybridMode() {
        SequentialPacketWindow partialWindow = buildWindow(6); // 6 pkts instead of 9
        assertFalse(partialWindow.isFull());

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
                hybridDetector.detect(partialWindow, 4, partialWindow.getFlowId(), "partial.pcap"));
        assertTrue(ex.getMessage().contains("HYBRID model requires a complete 9-packet window"),
                "Exception message must mention HYBRID model complete window requirement: " + ex.getMessage());
    }

    @Test
    public void testUnsupportedDirectInferenceMethodsInHybridMode() {
        BufferedImage dummyImg = new BufferedImage(27, 27, BufferedImage.TYPE_INT_RGB);
        assertThrows(UnsupportedOperationException.class, () ->
                hybridDetector.detect(dummyImg, 1, "flow", "test.pcap"));

        float[][][] dummyBytes = new float[1][1][2187];
        assertThrows(UnsupportedOperationException.class, () ->
                hybridDetector.detectBytes(dummyBytes, 1, "flow", "test.pcap"));
    }

    @Test
    public void testBackwardCompatibilityPreserved() {
        // Single branch DetectionResult constructor backward-compatibility check
        DetectionResult singleResult = new DetectionResult(
                "legacy.pcap", 10, "flow1", "NORMAL", 0.95, 0.05, 0.95, "2026-10-12 12:00:00.000"
        );
        assertEquals("NORMAL", singleResult.getPredictedLabel());
        assertEquals(0.95, singleResult.getNormalProbability(), 0.001);
        assertEquals(0.05, singleResult.getMaliciousProbability(), 0.001);
        assertFalse(singleResult.isDualBranch());
        assertEquals(CorrelationStatus.SINGLE_BRANCH, singleResult.getCorrelationStatus());
        assertNull(singleResult.getBytePredictedLabel());
    }
}
