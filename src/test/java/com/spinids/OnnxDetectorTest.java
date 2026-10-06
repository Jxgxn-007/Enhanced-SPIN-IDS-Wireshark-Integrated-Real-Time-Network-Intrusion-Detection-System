package com.spinids;

import com.spinids.alert.AlertManager;
import com.spinids.capture.LivePcapCapture;
import com.spinids.capture.PcapReader;
import com.spinids.detection.DetectionResult;
import com.spinids.detection.OnnxDetector;
import com.spinids.image.PacketImageBuilder;
import com.spinids.image.SequentialPacketWindow;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for ONNX CNN Detector, AlertManager, and LivePcapCapture integration.
 */
public class OnnxDetectorTest {

    @Test
    public void testDetectorInitialization() throws Exception {
        try (OnnxDetector detector = new OnnxDetector()) {
            assertNotNull(detector);
            assertNotNull(detector.getInputName());
            assertEquals("input", detector.getInputName());
        }
    }

    @Test
    public void testInferenceOutputShapeAndPredictions() throws Exception {
        try (OnnxDetector detector = new OnnxDetector()) {
            BufferedImage image = new BufferedImage(27, 27, BufferedImage.TYPE_INT_RGB);
            Graphics2D g2d = image.createGraphics();
            g2d.setColor(Color.BLUE);
            g2d.fillRect(0, 0, 27, 27);
            g2d.dispose();

            DetectionResult result = detector.detect(image, 1, "test-flow", "test.pcap");
            assertNotNull(result);
            assertEquals(1, result.getWindowIndex());
            assertEquals("test-flow", result.getFlowKey());
            assertEquals("test.pcap", result.getPcapFile());

            String label = result.getPredictedLabel();
            assertTrue("NORMAL".equals(label) || "MALICIOUS".equals(label));
        }
    }

    @Test
    public void testProbabilityValidityAndConfidence() throws Exception {
        try (OnnxDetector detector = new OnnxDetector()) {
            BufferedImage image = new BufferedImage(27, 27, BufferedImage.TYPE_INT_RGB);

            DetectionResult result = detector.detect(image, 2, "flow-1", "sample.pcap");
            double normalProb = result.getNormalProbability();
            double maliciousProb = result.getMaliciousProbability();
            double confidence = result.getConfidence();

            assertTrue(normalProb >= 0.0 && normalProb <= 1.0, "Normal probability should be between 0 and 1");
            assertTrue(maliciousProb >= 0.0 && maliciousProb <= 1.0, "Malicious probability should be between 0 and 1");
            assertEquals(1.0, normalProb + maliciousProb, 1e-4, "Probabilities should sum to 1.0");

            double expectedConfidence = Math.max(normalProb, maliciousProb);
            assertEquals(expectedConfidence, confidence, 1e-6, "Confidence should be max probability");
        }
    }

    @Test
    public void testAlertManagerCsvLogging(@TempDir Path tempDir) throws Exception {
        File logFile = tempDir.resolve("test_detection_log.csv").toFile();
        AlertManager alertManager = new AlertManager(logFile.getAbsolutePath());

        assertTrue(logFile.exists(), "CSV file should be created");

        // Verify header
        try (BufferedReader reader = new BufferedReader(new FileReader(logFile))) {
            String header = reader.readLine();
            assertEquals("timestamp,pcap_file,window_index,prediction,normal_probability,malicious_probability,confidence", header);
        }

        // Log result
        DetectionResult result = new DetectionResult(
                "capture.pcap",
                3,
                "flow-abc",
                "MALICIOUS",
                0.05,
                0.95,
                0.95,
                "2026-09-21 23:00:00.000"
        );
        alertManager.handleDetection(result);

        // Verify record appended
        try (BufferedReader reader = new BufferedReader(new FileReader(logFile))) {
            String header = reader.readLine(); // skip header
            String line = reader.readLine();
            assertNotNull(line, "Log record should exist");
            assertTrue(line.contains("capture.pcap"));
            assertTrue(line.contains("MALICIOUS"));
            assertTrue(line.contains("0.950000"));
        }
    }

    @Test
    public void testLivePcapCaptureAndPipelineProcessing(@TempDir Path tempDir) throws Exception {
        LivePcapCapture capture = new LivePcapCapture(tempDir.toString());
        File pcapFile = capture.captureTraffic(null, 18);

        assertNotNull(pcapFile);
        assertTrue(pcapFile.exists());
        assertTrue(pcapFile.length() > 0);
        assertEquals(18, capture.getLastCapturedCount());

        // Extract windows using PcapReader
        List<SequentialPacketWindow> windows = PcapReader.readWindowsFromPcap(pcapFile.getAbsolutePath(), "TEST");
        assertFalse(windows.isEmpty(), "Should extract at least one sequential packet window");

        // Build image and run detection
        try (OnnxDetector detector = new OnnxDetector()) {
            for (SequentialPacketWindow window : windows) {
                BufferedImage img = PacketImageBuilder.buildImage(window);
                assertNotNull(img);
                assertEquals(27, img.getWidth());
                assertEquals(27, img.getHeight());

                DetectionResult result = detector.detect(img, window.getWindowIndex(), window.getFlowId(), pcapFile.getName());
                assertNotNull(result);
                assertNotNull(result.getPredictedLabel());
            }
        }
    }
}
