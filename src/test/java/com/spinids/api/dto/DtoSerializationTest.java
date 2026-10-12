package com.spinids.api.dto;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.spinids.api.SpinEngineController;
import com.spinids.detection.DetectionResult;
import com.spinids.detection.DetectionResult.CorrelationStatus;
import com.spinids.image.CicIdsBytePreprocessor;
import com.spinids.image.SequentialPacketWindow;
import com.spinids.image.SequentialPacketWindow.PacketDirection;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;

import java.awt.image.BufferedImage;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verification test suite for SPIN-IDS Phase 2 API DTO serialization,
 * dual-branch detection mapping, window-detail hex payload integrity, and backward compatibility.
 */
public class DtoSerializationTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    public void testDetectionDtoDualBranchJacksonSerializationRoundtrip() throws Exception {
        DetectionDto dto = new DetectionDto();
        dto.setPcapFile("traffic_capture.pcap");
        dto.setWindowIndex(42);
        dto.setFlowKey("192.168.1.10:48210 -> 10.0.0.1:80 [TCP]");
        dto.setPrediction("MALICIOUS");
        dto.setNormalProbability(0.0450);
        dto.setMaliciousProbability(0.9550);
        dto.setConfidence(0.9550);
        dto.setTimestamp("2026-10-12 14:30:00.123");

        // Dual-branch RGB fields
        dto.setRgbPrediction("MALICIOUS");
        dto.setRgbNormalProbability(0.0450);
        dto.setRgbMaliciousProbability(0.9550);
        dto.setRgbConfidence(0.9550);

        // Dual-branch Byte fields
        dto.setBytePrediction("MALICIOUS");
        dto.setByteNormalProbability(0.0820);
        dto.setByteMaliciousProbability(0.9180);
        dto.setByteConfidence(0.9180);

        // Correlation and fusion parameters
        dto.setCorrelationStatus("AGREEMENT_MALICIOUS");
        dto.setFusedMaliciousProbability(0.9550);
        dto.setFusionAlpha(1.0);
        dto.setFusionThreshold(0.9);
        dto.setDualBranch(true);

        // Serialize to JSON
        String json = mapper.writeValueAsString(dto);
        assertNotNull(json);

        // Verify JSON includes all Phase 2 properties
        assertTrue(json.contains("\"rgbPrediction\":\"MALICIOUS\""));
        assertTrue(json.contains("\"rgbNormalProbability\":0.045"));
        assertTrue(json.contains("\"rgbMaliciousProbability\":0.955"));
        assertTrue(json.contains("\"rgbConfidence\":0.955"));

        assertTrue(json.contains("\"bytePrediction\":\"MALICIOUS\""));
        assertTrue(json.contains("\"byteNormalProbability\":0.082"));
        assertTrue(json.contains("\"byteMaliciousProbability\":0.918"));
        assertTrue(json.contains("\"byteConfidence\":0.918"));

        assertTrue(json.contains("\"correlationStatus\":\"AGREEMENT_MALICIOUS\""));
        assertTrue(json.contains("\"fusedMaliciousProbability\":0.955"));
        assertTrue(json.contains("\"fusionAlpha\":1.0"));
        assertTrue(json.contains("\"fusionThreshold\":0.9"));
        assertTrue(json.contains("\"dualBranch\":true"));

        // Deserialize from JSON
        DetectionDto deserialized = mapper.readValue(json, DetectionDto.class);
        assertEquals(dto.getPcapFile(), deserialized.getPcapFile());
        assertEquals(dto.getWindowIndex(), deserialized.getWindowIndex());
        assertEquals(dto.getFlowKey(), deserialized.getFlowKey());
        assertEquals(dto.getPrediction(), deserialized.getPrediction());
        assertEquals(dto.getNormalProbability(), deserialized.getNormalProbability(), 0.0001);
        assertEquals(dto.getMaliciousProbability(), deserialized.getMaliciousProbability(), 0.0001);
        assertEquals(dto.getConfidence(), deserialized.getConfidence(), 0.0001);

        assertEquals("MALICIOUS", deserialized.getRgbPrediction());
        assertEquals(0.0450, deserialized.getRgbNormalProbability(), 0.0001);
        assertEquals(0.9550, deserialized.getRgbMaliciousProbability(), 0.0001);
        assertEquals(0.9550, deserialized.getRgbConfidence(), 0.0001);

        assertEquals("MALICIOUS", deserialized.getBytePrediction());
        assertEquals(0.0820, deserialized.getByteNormalProbability(), 0.0001);
        assertEquals(0.9180, deserialized.getByteMaliciousProbability(), 0.0001);
        assertEquals(0.9180, deserialized.getByteConfidence(), 0.0001);

        assertEquals("AGREEMENT_MALICIOUS", deserialized.getCorrelationStatus());
        assertEquals(0.9550, deserialized.getFusedMaliciousProbability(), 0.0001);
        assertEquals(1.0, deserialized.getFusionAlpha(), 0.0001);
        assertEquals(0.9, deserialized.getFusionThreshold(), 0.0001);
        assertTrue(deserialized.isDualBranch());
    }

    @Test
    public void testDetectionDtoSingleBranchBackwardCompatibility() throws Exception {
        DetectionDto legacyDto = new DetectionDto(
                "legacy_test.pcap", 7, "flow:123", "NORMAL",
                0.9850, 0.0150, 0.9850, "2026-10-12 12:00:00"
        );

        assertEquals("NORMAL", legacyDto.getPrediction());
        assertEquals("NORMAL", legacyDto.getRgbPrediction());
        assertNull(legacyDto.getBytePrediction());
        assertEquals("SINGLE_BRANCH", legacyDto.getCorrelationStatus());
        assertFalse(legacyDto.isDualBranch());
        assertEquals(1.0, legacyDto.getFusionAlpha(), 0.0001);

        String json = mapper.writeValueAsString(legacyDto);
        DetectionDto deserialized = mapper.readValue(json, DetectionDto.class);

        assertEquals("NORMAL", deserialized.getPrediction());
        assertEquals("SINGLE_BRANCH", deserialized.getCorrelationStatus());
        assertFalse(deserialized.isDualBranch());
    }

    @Test
    public void testWindowDetailDtoJacksonSerializationRoundtrip() throws Exception {
        WindowDetailDto dto = new WindowDetailDto();
        dto.setWindowIndex(10);
        dto.setFlowId("10.0.0.1:443 <-> 192.168.1.50:54321");
        dto.setFlowIndex(2);
        dto.setLabel("MALICIOUS");
        dto.setPacketCount(9);

        // Genuine hex payload fields
        byte[] dummyWindow = new byte[CicIdsBytePreprocessor.WINDOW_BYTES];
        Arrays.fill(dummyWindow, (byte) 0x7E);
        String hexDump = CicIdsBytePreprocessor.formatHexDump(dummyWindow);
        String rawHex = CicIdsBytePreprocessor.toRawHexString(dummyWindow);

        dto.setHexDump(hexDump);
        dto.setRawHex(rawHex);
        dto.setByteCount(dummyWindow.length);
        dto.setImageBase64("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABsAAAAbCAYAAACN1PRVAAAA");

        List<WindowDetailDto.PacketItemDto> pkts = new ArrayList<>();
        pkts.add(new WindowDetailDto.PacketItemDto(
                1, "TCP", "10.0.0.1:443", "192.168.1.50:54321", 1500, "FORWARD", "ACK", "AABBCCDDEEFF"
        ));
        dto.setPackets(pkts);

        // Serialize
        String json = mapper.writeValueAsString(dto);
        assertNotNull(json);
        assertTrue(json.contains("\"hexDump\":"));
        assertTrue(json.contains("\"rawHex\":"));
        assertTrue(json.contains("\"byteCount\":2187"));
        assertTrue(json.contains("\"imageBase64\":\"data:image/png;base64,"));
        assertTrue(json.contains("\"hex\":\"AABBCCDDEEFF\""));

        // Deserialize
        WindowDetailDto deserialized = mapper.readValue(json, WindowDetailDto.class);
        assertEquals(10, deserialized.getWindowIndex());
        assertEquals("MALICIOUS", deserialized.getLabel());
        assertEquals(2187, deserialized.getByteCount());
        assertEquals(hexDump, deserialized.getHexDump());
        assertEquals(rawHex, deserialized.getRawHex());
        assertEquals(dto.getImageBase64(), deserialized.getImageBase64());
        assertEquals(1, deserialized.getPackets().size());
        assertEquals("AABBCCDDEEFF", deserialized.getPackets().get(0).getHex());
    }

    @Test
    public void testDetectionResultToDtoMappingDualBranch() {
        DetectionResult result = new DetectionResult(
                "pcap_file.pcap", 15, "flow_xyz",
                "MALICIOUS", 0.05, 0.95, 0.95, "2026-10-12 14:00:00.000",
                "MALICIOUS", 0.05, 0.95, 0.95,
                "NORMAL", 0.80, 0.20, 0.80,
                CorrelationStatus.CONFLICT_RESOLVED, 0.95, 1.0, 0.9
        );

        DetectionDto dto = SpinEngineController.toDto(result);
        assertNotNull(dto);
        assertEquals("MALICIOUS", dto.getPrediction());
        assertEquals(0.95, dto.getMaliciousProbability(), 0.0001);

        assertEquals("MALICIOUS", dto.getRgbPrediction());
        assertEquals(0.95, dto.getRgbMaliciousProbability(), 0.0001);

        assertEquals("NORMAL", dto.getBytePrediction());
        assertEquals(0.20, dto.getByteMaliciousProbability(), 0.0001);

        assertEquals("CONFLICT_RESOLVED", dto.getCorrelationStatus());
        assertEquals(0.95, dto.getFusedMaliciousProbability(), 0.0001);
        assertEquals(1.0, dto.getFusionAlpha(), 0.0001);
        assertEquals(0.9, dto.getFusionThreshold(), 0.0001);
        assertTrue(dto.isDualBranch());
    }

    @Test
    public void testGenuinePacketWindowPayloadConstruction() throws Exception {
        SequentialPacketWindow window = new SequentialPacketWindow("192.168.1.1:80<->192.168.1.2:12345", 9, 100);

        byte[] rawPkt = new byte[64];
        Arrays.fill(rawPkt, (byte) 0x11);
        rawPkt[12] = 0x08; rawPkt[13] = 0x00; // IPv4
        rawPkt[14] = 0x45;                    // IPv4 version 4
        rawPkt[23] = 6;                       // TCP

        for (int i = 0; i < 9; i++) {
            Packet p = EthernetPacket.newPacket(rawPkt, 0, rawPkt.length);
            window.addPacket(p, System.currentTimeMillis() + i * 10,
                    (i % 2 == 0) ? PacketDirection.FORWARD : PacketDirection.BACKWARD, i + 1);
        }

        BufferedImage img = new BufferedImage(27, 27, BufferedImage.TYPE_INT_RGB);
        DetectionResult result = new DetectionResult(
                "genuine.pcap", 1, window.getFlowId(),
                "NORMAL", 0.99, 0.01, 0.99, "2026-10-12 14:00:00.000"
        );

        SpinEngineController controller = new SpinEngineController();
        WindowDetailDto dto = controller.createWindowDetailDto(window, 1, img, result);

        assertNotNull(dto);
        assertEquals(1, dto.getWindowIndex());
        assertEquals(2187, dto.getByteCount(), "Window payload must represent exactly 2,187 bytes");
        assertNotNull(dto.getHexDump(), "Hex dump must not be null");
        assertTrue(dto.getHexDump().startsWith("00000000  "), "Hex dump must format starting at offset 00000000");

        assertNotNull(dto.getRawHex());
        assertEquals(2187 * 2, dto.getRawHex().length(), "Raw hex must be 4,374 hex characters");

        assertNotNull(dto.getImageBase64());
        assertTrue(dto.getImageBase64().startsWith("data:image/png;base64,"),
                "Image must be encoded as a valid PNG data URL");

        assertEquals(9, dto.getPackets().size());
        for (WindowDetailDto.PacketItemDto pkt : dto.getPackets()) {
            assertNotNull(pkt.getHex(), "Each packet with raw data must have its raw hex preserved");
            assertEquals(64 * 2, pkt.getHex().length());
        }
    }
}
