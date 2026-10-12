package com.spinids;

import com.spinids.detection.DetectionResult;
import com.spinids.detection.OnnxDetector;
import com.spinids.image.CicIdsBytePreprocessor;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Parity test suite verifying bitwise and numerical alignment between PyTorch,
 * Python ONNX Runtime, and Java ONNX Runtime on the CIC-IDS2017 Byte 1D CNN model.
 *
 * <p>Golden reference values are derived directly from model evaluation of
 * {@code ml/models/cic_ids2017_byte/best_byte_cnn.pt} and {@code best_byte_cnn.onnx}
 * against verified held-out test split samples.
 */
public class ByteOnnxParityTest {

    private static OnnxDetector byteDetector;

    @BeforeAll
    public static void setUp() throws Exception {
        byteDetector = OnnxDetector.createByteDetector();
        assertNotNull(byteDetector);
        assertEquals(OnnxDetector.ModelType.BYTE_1D, byteDetector.getModelType());
        assertEquals("byte_input", byteDetector.getInputName());
    }

    @AfterAll
    public static void tearDown() {
        if (byteDetector != null) {
            byteDetector.close();
        }
    }

    private static byte[] loadFixtureBytes(String fixtureName) throws Exception {
        // Try classpath first
        try (InputStream in = ByteOnnxParityTest.class.getClassLoader().getResourceAsStream("fixtures/" + fixtureName)) {
            if (in != null) {
                return in.readAllBytes();
            }
        }
        // Fallback to direct file paths
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
    public void testParityOnZeroInputVector() throws Exception {
        // Golden Logits from PyTorch & Python ONNX on zeros: [2.2771146, -1.9610409]
        // Golden Softmax: P(NORMAL) = 0.9857703, P(MALICIOUS) = 0.0142297
        float[][][] zeroTensor = new float[1][1][CicIdsBytePreprocessor.WINDOW_BYTES];

        DetectionResult result = byteDetector.detectBytes(zeroTensor, 0, "flow-zero", "synthetic-zeros.pcap");
        assertNotNull(result);

        assertEquals(OnnxDetector.LABEL_NORMAL, result.getPredictedLabel());
        assertEquals(0.9857703, result.getNormalProbability(), 1e-4,
                "Normal probability must match PyTorch golden probability within 1e-4");
        assertEquals(0.0142297, result.getMaliciousProbability(), 1e-4,
                "Malicious probability must match PyTorch golden probability within 1e-4");
        assertEquals(1.0, result.getNormalProbability() + result.getMaliciousProbability(), 1e-5,
                "Probabilities must sum to 1.0");
    }

    @Test
    public void testParityOnGoldenNormalSample() throws Exception {
        // Test Sample #0: Flow 17_192.168.10.17_224.0.0.251_5353_5353_w0 (BENIGN / NORMAL)
        // Verified PyTorch Logits: [7.0123067, -6.176255]
        // Verified Python ONNX Logits: [7.012306, -6.176256]
        // Verified Softmax: P(NORMAL) = 0.9999981, P(MALICIOUS) = 1.8718856e-06
        byte[] rawBytes = loadFixtureBytes("sample_normal_2187.bin");
        assertEquals(2187, rawBytes.length);

        float[][][] tensor = CicIdsBytePreprocessor.toNormalizedTensor(rawBytes);
        DetectionResult result = byteDetector.detectBytes(tensor, 1, "17_192.168.10.17_224.0.0.251_5353_5353_w0", "test.pcap");
        assertNotNull(result);

        assertEquals(OnnxDetector.LABEL_NORMAL, result.getPredictedLabel());
        assertEquals(0.9999981, result.getNormalProbability(), 1e-5,
                "Normal probability must match PyTorch golden probability");
        assertEquals(1.8718856e-06, result.getMaliciousProbability(), 1e-5,
                "Malicious probability must match PyTorch golden probability");
        assertTrue(result.getConfidence() > 0.9999, "Normal sample confidence must exceed 99.99%");
        assertEquals(1.0, result.getNormalProbability() + result.getMaliciousProbability(), 1e-5);
    }

    @Test
    public void testParityOnGoldenMaliciousSample() throws Exception {
        // Test Sample #5209: Flow 6_172.16.0.1_192.168.10.50_80_53438_w0 (DoS Hulk attack)
        // Verified PyTorch Logits: [-2.791313, 2.4238324]
        // Verified Python ONNX Logits: [-2.791313, 2.423832]
        // Verified Softmax: P(NORMAL) = 0.00540428, P(MALICIOUS) = 0.9945957
        byte[] rawBytes = loadFixtureBytes("sample_malicious_2187.bin");
        assertEquals(2187, rawBytes.length);

        float[][][] tensor = CicIdsBytePreprocessor.toNormalizedTensor(rawBytes);
        DetectionResult result = byteDetector.detectBytes(tensor, 5209, "6_172.16.0.1_192.168.10.50_80_53438_w0", "test.pcap");
        assertNotNull(result);

        assertEquals(OnnxDetector.LABEL_MALICIOUS, result.getPredictedLabel());
        assertEquals(0.00540428, result.getNormalProbability(), 1e-5,
                "Normal probability must match PyTorch golden probability");
        assertEquals(0.9945957, result.getMaliciousProbability(), 1e-5,
                "Malicious probability must match PyTorch golden probability");
        assertTrue(result.getConfidence() > 0.9940, "Malicious sample confidence must exceed 99.40%");
        assertEquals(1.0, result.getNormalProbability() + result.getMaliciousProbability(), 1e-5);
    }
}
