package com.spinids.api;

import ai.onnxruntime.OrtException;
import com.spinids.api.dto.DetectionDto;
import com.spinids.capture.LivePcapCapture;
import com.spinids.detection.DetectionResult;
import com.spinids.detection.OnnxDetector;
import com.spinids.detection.OnnxDetector.ModelType;
import com.spinids.image.SequentialPacketWindow;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests verification for SpinEngineController detection handling:
 * - Genuine successful inferences recorded normally.
 * - Complete elimination of fabricated fallback classifications and fake alerts on inference failure.
 * - Safe continuation of window processing when one window fails.
 * - Incomplete tail window skipping in Byte mode vs backward-compatible processing in RGB mode.
 */
public class SpinEngineControllerDetectionTest {

    @Test
    public void testSuccessfulInferenceRecordedNormally(@TempDir Path tempDir) throws Exception {
        LivePcapCapture capture = new LivePcapCapture(tempDir.toString());
        File pcapFile = capture.captureTraffic(null, 18); // 2 full 9-packet windows

        SpinEngineController controller = new SpinEngineController();
        int historyBefore = controller.getDetectionHistory().size();

        List<DetectionDto> dtos = controller.processCapturedPcap(pcapFile);

        assertEquals(2, dtos.size(), "Both complete windows should be successfully detected");
        assertEquals(historyBefore + 2, controller.getDetectionHistory().size(),
                "Detection history must increment by exactly the number of successful detections");

        for (DetectionDto dto : dtos) {
            assertNotNull(dto.getPrediction());
            assertTrue("NORMAL".equals(dto.getPrediction()) || "MALICIOUS".equals(dto.getPrediction()));
            assertTrue(dto.getConfidence() >= 0.5);
            // Verify that probabilities are not the obsolete hardcoded dummy values
            assertNotEquals(0.4997, dto.getNormalProbability());
            assertNotEquals(0.5016, dto.getNormalProbability());
            assertNotNull(controller.getWindowDetail(dto.getWindowIndex()));
        }
    }

    @Test
    public void testInferenceFailureDoesNotGenerateFabricatedResultOrAlert(@TempDir Path tempDir) throws Exception {
        LivePcapCapture capture = new LivePcapCapture(tempDir.toString());
        File pcapFile = capture.captureTraffic(null, 18);

        SpinEngineController controller = new SpinEngineController();
        int historyBefore = controller.getDetectionHistory().size();

        // Case 1: Detector is null
        controller.setDetector(null);
        List<DetectionDto> dtosNull = controller.processCapturedPcap(pcapFile);
        assertTrue(dtosNull.isEmpty(), "Null detector must produce zero detection DTOs");
        assertEquals(historyBefore, controller.getDetectionHistory().size(),
                "Detection history must not record any fabricated results when detector is null");

        // Case 2: Detector throws an exception during inference
        OnnxDetector throwingDetector = new OnnxDetector() {
            @Override
            public DetectionResult detect(SequentialPacketWindow window, int windowIndex, String flowKey, String pcapFile) throws OrtException {
                throw new OrtException("Simulated ONNX Runtime core inference crash");
            }
        };
        controller.setDetector(throwingDetector);

        List<DetectionDto> dtosThrow = controller.processCapturedPcap(pcapFile);
        assertTrue(dtosThrow.isEmpty(), "Failing detector must produce zero detection DTOs");
        assertEquals(historyBefore, controller.getDetectionHistory().size(),
                "Detection history must not record any fabricated results when inference fails");
    }

    @Test
    public void testProcessingContinuesSafelyAfterOneWindowFails(@TempDir Path tempDir) throws Exception {
        LivePcapCapture capture = new LivePcapCapture(tempDir.toString());
        File pcapFile = capture.captureTraffic(null, 27); // 3 full 9-packet windows

        SpinEngineController controller = new SpinEngineController();
        int historyBefore = controller.getDetectionHistory().size();

        OnnxDetector realDetector = controller.getDetector();
        assertNotNull(realDetector);

        Set<Integer> failIndices = new HashSet<>();
        // Fail the second window in the batch
        failIndices.add(historyBefore + 2);

        OnnxDetector partialFailingDetector = new OnnxDetector() {
            @Override
            public DetectionResult detect(SequentialPacketWindow window, int windowIndex, String flowKey, String pcapFile) throws OrtException {
                if (failIndices.contains(windowIndex)) {
                    throw new OrtException("Simulated transient inference fault for window " + windowIndex);
                }
                return realDetector.detect(window, windowIndex, flowKey, pcapFile);
            }

            @Override
            public ModelType getModelType() {
                return realDetector.getModelType();
            }
        };

        controller.setDetector(partialFailingDetector);
        List<DetectionDto> dtos = controller.processCapturedPcap(pcapFile);

        assertEquals(2, dtos.size(), "Windows 1 and 3 should succeed while window 2 is safely skipped");
        assertEquals(historyBefore + 2, controller.getDetectionHistory().size(),
                "History should contain only the 2 genuinely successful detections");

        assertEquals(historyBefore + 1, dtos.get(0).getWindowIndex());
        assertEquals(historyBefore + 3, dtos.get(1).getWindowIndex());
    }

    @Test
    public void testIncompleteByteWindowSkippedWhileFullByteWindowInferred(@TempDir Path tempDir) throws Exception {
        LivePcapCapture capture = new LivePcapCapture(tempDir.toString());
        // Capture 14 packets: window 1 has 9 pkts (full), window 2 has 5 pkts (incomplete tail)
        File pcapFile = capture.captureTraffic(null, 14);

        SpinEngineController controller = new SpinEngineController();
        controller.setDetector(OnnxDetector.createByteDetector());

        long skippedBefore = (long) controller.getStatus().getStats().get("skippedIncompleteWindows");
        int historyBefore = controller.getDetectionHistory().size();

        List<DetectionDto> dtos = controller.processCapturedPcap(pcapFile);

        assertEquals(1, dtos.size(), "Only the single full 9-packet window should be inferred in BYTE_1D mode");
        long skippedAfter = (long) controller.getStatus().getStats().get("skippedIncompleteWindows");
        assertEquals(skippedBefore + 1, skippedAfter, "Incomplete tail window must increment skippedIncompleteWindows counter");
        assertEquals(historyBefore + 1, controller.getDetectionHistory().size(),
                "Detection history must only record the complete window");
    }

    @Test
    public void testIncompleteRgbWindowProcessedNormally(@TempDir Path tempDir) throws Exception {
        LivePcapCapture capture = new LivePcapCapture(tempDir.toString());
        // Capture 14 packets: window 1 has 9 pkts (full), window 2 has 5 pkts (partial)
        File pcapFile = capture.captureTraffic(null, 14);

        SpinEngineController controller = new SpinEngineController();
        controller.setDetector(OnnxDetector.createRgbDetector());

        int historyBefore = controller.getDetectionHistory().size();
        List<DetectionDto> dtos = controller.processCapturedPcap(pcapFile);

        assertEquals(2, dtos.size(), "Both full and partial windows should be processed in RGB mode with zero padding");
        assertEquals(historyBefore + 2, controller.getDetectionHistory().size(),
                "RGB mode should record both windows");
    }

    @Test
    public void testIncompleteHybridWindowSkippedWhileFullHybridWindowInferred(@TempDir Path tempDir) throws Exception {
        LivePcapCapture capture = new LivePcapCapture(tempDir.toString());
        // Capture 14 packets: window 1 has 9 pkts (full), window 2 has 5 pkts (incomplete tail)
        File pcapFile = capture.captureTraffic(null, 14);

        SpinEngineController controller = new SpinEngineController();
        controller.setDetector(OnnxDetector.createHybridDetector());

        long skippedBefore = (long) controller.getStatus().getStats().get("skippedIncompleteWindows");
        int historyBefore = controller.getDetectionHistory().size();

        List<DetectionDto> dtos = controller.processCapturedPcap(pcapFile);

        assertEquals(1, dtos.size(), "Only the single full 9-packet window should be inferred in HYBRID mode");
        long skippedAfter = (long) controller.getStatus().getStats().get("skippedIncompleteWindows");
        assertEquals(skippedBefore + 1, skippedAfter, "Incomplete tail window must increment skippedIncompleteWindows counter in HYBRID mode");
        assertEquals(historyBefore + 1, controller.getDetectionHistory().size(),
                "Detection history must only record the complete window");
        assertTrue(controller.getDetectionHistory().get(0).isDualBranch(), "Inferred detection must be dual branch");
    }
}

