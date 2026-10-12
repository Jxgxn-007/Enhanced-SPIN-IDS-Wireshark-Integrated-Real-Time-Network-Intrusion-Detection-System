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

import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.File;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verification test suite for Phase 8 integration of the audited CIC-IDS2017 RGB model:
 * - RGB NCHW input layout [1, 3, 27, 27] and 'rgb_input' node name.
 * - Numerically stable Softmax transformation on raw unnormalized logits.
 * - Zero-vector mathematical parity against verified Python ONNX baseline.
 * - Class mapping invariance (index 0 NORMAL, index 1 MALICIOUS).
 * - Legacy model backward compatibility (NHWC [1, 27, 27, 3] and 'input' node name).
 * - Runtime system property override ("spinids.rgb.model").
 * - Independent RGB and BYTE branch prediction availability and HYBRID score fusion.
 */
public class CicIdsRgbOnnxParityTest {

    private static OnnxDetector rgbDetector;

    @BeforeAll
    public static void setUp() throws Exception {
        rgbDetector = OnnxDetector.createRgbDetector();
    }

    @AfterAll
    public static void tearDown() {
        if (rgbDetector != null) {
            rgbDetector.close();
        }
    }

    private static Packet createSyntheticPacket(int length, boolean isForward) {
        byte[] raw = new byte[Math.max(length, 54)];
        Arrays.fill(raw, (byte) 0x33);
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
            throw new RuntimeException("Failed to construct synthetic packet", e);
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
    public void testAuditedRgbModelMetadataAndLayout() {
        assertNotNull(rgbDetector);
        assertEquals(ModelType.RGB_IMAGE, rgbDetector.getModelType());
        assertEquals("rgb_input", rgbDetector.getInputName(), "Audited benchmark model must use input name 'rgb_input'");
        assertTrue(rgbDetector.isNchw(), "Audited benchmark model must be detected as NCHW layout");
        assertTrue(rgbDetector.getModelPath().contains("best_rgb_cnn.onnx"));

        String desc = rgbDetector.getModelDescription();
        assertNotNull(desc);
        assertTrue(desc.contains("best_rgb_cnn.onnx"), "Description must contain model filename: " + desc);
        assertTrue(desc.contains("3x27x27 NCHW"), "Description must reflect NCHW layout: " + desc);
    }

    @Test
    public void testZeroVectorInferenceParityAndStableSoftmax() throws Exception {
        // Benchmark ONNX reference evaluation on zeros tensor [1, 3, 27, 27]:
        // Python ONNX Logits: [0.02031347, -0.2823426]
        // Golden Softmax:
        //   P(NORMAL)    = exp(0.02031347 - 0.02031347) / (exp(0) + exp(-0.2823426 - 0.02031347))
        //                = 1.0 / (1.0 + exp(-0.30265607)) = 1.0 / (1.0 + 0.73885) = 0.57509166
        //   P(MALICIOUS) = 1.0 - 0.57509166 = 0.42490834
        BufferedImage zeroImage = new BufferedImage(27, 27, BufferedImage.TYPE_INT_RGB);

        DetectionResult result = rgbDetector.detect(zeroImage, 0, "flow-zeros", "synthetic-zeros.pcap");
        assertNotNull(result);

        assertEquals(OnnxDetector.LABEL_NORMAL, result.getPredictedLabel());
        assertEquals(0.57509166, result.getNormalProbability(), 1e-4,
                "Normal probability must match Python ONNX golden reference within 1e-4");
        assertEquals(0.42490834, result.getMaliciousProbability(), 1e-4,
                "Malicious probability must match Python ONNX golden reference within 1e-4");
        assertEquals(1.0, result.getNormalProbability() + result.getMaliciousProbability(), 1e-5,
                "Probabilities must sum to 1.0");
        assertEquals(result.getNormalProbability(), result.getConfidence(), 1e-5,
                "Confidence must equal maximum class probability");
    }

    @Test
    public void testClassMappingInvariance() throws Exception {
        BufferedImage img = new BufferedImage(27, 27, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = img.createGraphics();
        g.setColor(new Color(255, 128, 64));
        g.fillRect(0, 0, 27, 27);
        g.dispose();

        DetectionResult result = rgbDetector.detect(img, 1, "flow-test-class", "class_mapping.pcap");
        assertNotNull(result);

        double pNormal = result.getNormalProbability();
        double pMalicious = result.getMaliciousProbability();

        assertTrue(pNormal >= 0.0 && pNormal <= 1.0, "Normal probability must be in [0, 1]");
        assertTrue(pMalicious >= 0.0 && pMalicious <= 1.0, "Malicious probability must be in [0, 1]");
        assertEquals(1.0, pNormal + pMalicious, 1e-5, "Probabilities must sum to 1.0");

        if (pMalicious > pNormal) {
            assertEquals(OnnxDetector.LABEL_MALICIOUS, result.getPredictedLabel());
            assertEquals(pMalicious, result.getConfidence(), 1e-5);
        } else {
            assertEquals(OnnxDetector.LABEL_NORMAL, result.getPredictedLabel());
            assertEquals(pNormal, result.getConfidence(), 1e-5);
        }
    }

    @Test
    public void testLegacyModelBackwardCompatibility() throws Exception {
        File legacyFile = new File(OnnxDetector.resolveModelPath(OnnxDetector.LEGACY_MODEL_PATH));
        assertTrue(legacyFile.exists(), "Legacy model file ml/models/spin_ids_cnn.onnx must exist for rollback safety");

        try (OnnxDetector legacyDetector = new OnnxDetector(OnnxDetector.LEGACY_MODEL_PATH)) {
            assertNotNull(legacyDetector);
            assertEquals(ModelType.RGB_IMAGE, legacyDetector.getModelType());
            assertEquals("input", legacyDetector.getInputName(), "Legacy model must use input name 'input'");
            assertFalse(legacyDetector.isNchw(), "Legacy model must be detected as NHWC layout");
            assertTrue(legacyDetector.getModelDescription().contains("27x27x3 NHWC"));

            BufferedImage sampleImg = new BufferedImage(27, 27, BufferedImage.TYPE_INT_RGB);
            DetectionResult legacyResult = legacyDetector.detect(sampleImg, 10, "legacy-flow", "legacy.pcap");
            assertNotNull(legacyResult);
            assertTrue("NORMAL".equals(legacyResult.getPredictedLabel()) || "MALICIOUS".equals(legacyResult.getPredictedLabel()));
            assertEquals(1.0, legacyResult.getNormalProbability() + legacyResult.getMaliciousProbability(), 1e-4);
        }
    }

    @Test
    public void testRuntimeSystemPropertyOverrideToLegacyModel() throws Exception {
        String originalProp = System.getProperty("spinids.rgb.model");
        try {
            System.setProperty("spinids.rgb.model", OnnxDetector.LEGACY_MODEL_PATH);
            try (OnnxDetector overriddenDetector = OnnxDetector.createRgbDetector()) {
                assertNotNull(overriddenDetector);
                assertTrue(overriddenDetector.getModelPath().contains("spin_ids_cnn.onnx"),
                        "System property override must select legacy model path");
                assertFalse(overriddenDetector.isNchw(), "Overridden legacy model must use NHWC");
                assertEquals("input", overriddenDetector.getInputName());
            }
        } finally {
            if (originalProp != null) {
                System.setProperty("spinids.rgb.model", originalProp);
            } else {
                System.clearProperty("spinids.rgb.model");
            }
        }

        // Verify that after clearing the system property, default returns to audited model
        try (OnnxDetector restoredDetector = OnnxDetector.createRgbDetector()) {
            assertTrue(restoredDetector.getModelPath().contains("best_rgb_cnn.onnx"));
            assertTrue(restoredDetector.isNchw());
            assertEquals("rgb_input", restoredDetector.getInputName());
        }
    }

    @Test
    public void testIndependentByteBranchExecutionAndHybridFusion() throws Exception {
        try (OnnxDetector hybrid = OnnxDetector.createHybridDetector()) {
            assertNotNull(hybrid);
            assertEquals(ModelType.HYBRID, hybrid.getModelType());
            assertTrue(hybrid.isNchw(), "RGB branch must use NCHW layout for audited model");
            assertEquals("rgb_input", hybrid.getInputName());
            assertEquals("byte_input", hybrid.getByteInputName());
            assertEquals(1.0, hybrid.getFusionAlpha(), 0.0001);
            assertEquals(0.9, hybrid.getFusionThreshold(), 0.0001);

            SequentialPacketWindow fullWindow = buildWindow(9);
            assertTrue(fullWindow.isFull());

            DetectionResult result = hybrid.detect(fullWindow, 1, fullWindow.getFlowId(), "hybrid_test.pcap");
            assertNotNull(result);
            assertTrue(result.isDualBranch(), "Result must indicate dual-branch inference");

            // Verify independent RGB branch predictions
            assertNotNull(result.getRgbPredictedLabel());
            assertTrue(result.getRgbNormalProbability() >= 0.0 && result.getRgbNormalProbability() <= 1.0);
            assertTrue(result.getRgbMaliciousProbability() >= 0.0 && result.getRgbMaliciousProbability() <= 1.0);
            assertEquals(1.0, result.getRgbNormalProbability() + result.getRgbMaliciousProbability(), 1e-4);
            assertEquals(Math.max(result.getRgbNormalProbability(), result.getRgbMaliciousProbability()),
                    result.getRgbConfidence(), 1e-4);

            // Verify independent BYTE branch predictions
            assertNotNull(result.getBytePredictedLabel());
            assertTrue(result.getByteNormalProbability() >= 0.0 && result.getByteNormalProbability() <= 1.0);
            assertTrue(result.getByteMaliciousProbability() >= 0.0 && result.getByteMaliciousProbability() <= 1.0);
            assertEquals(1.0, result.getByteNormalProbability() + result.getByteMaliciousProbability(), 1e-4);
            assertEquals(Math.max(result.getByteNormalProbability(), result.getByteMaliciousProbability()),
                    result.getByteConfidence(), 1e-4);

            // Verify score fusion semantics with default alpha=1.0:
            // fusedMalicious = 1.0 * rgbMalicious + 0.0 * byteMalicious = rgbMalicious
            assertEquals(result.getRgbMaliciousProbability(), result.getFusedMaliciousProbability(), 1e-4,
                    "With alpha=1.0, fused malicious probability must equal RGB malicious probability");
            assertEquals(result.getRgbMaliciousProbability(), result.getMaliciousProbability(), 1e-4);

            // Verify correlation status
            if (result.getRgbPredictedLabel().equals(result.getBytePredictedLabel())) {
                assertTrue(result.isAgreement());
                assertFalse(result.isConflict());
            } else {
                assertTrue(result.isConflict());
                assertEquals(CorrelationStatus.CONFLICT_RESOLVED, result.getCorrelationStatus());
            }
        }
    }

    @Test
    public void testCustomFusionWeightingBalancesRgbAndByteBranches() throws Exception {
        // Balanced hybrid detector: alpha = 0.5, threshold = 0.5
        try (OnnxDetector balancedHybrid = OnnxDetector.createHybridDetector(0.5, 0.5)) {
            SequentialPacketWindow fullWindow = buildWindow(9);
            DetectionResult result = balancedHybrid.detect(fullWindow, 2, fullWindow.getFlowId(), "balanced_test.pcap");
            assertNotNull(result);

            double expectedFused = 0.5 * result.getRgbMaliciousProbability() + 0.5 * result.getByteMaliciousProbability();
            assertEquals(expectedFused, result.getFusedMaliciousProbability(), 1e-4,
                    "Balanced alpha=0.5 must weight RGB and BYTE branches equally");
            assertEquals(expectedFused, result.getMaliciousProbability(), 1e-4);
        }
    }
}
