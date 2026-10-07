package com.spinids.capture;

import com.spinids.flow.FlowManager;
import com.spinids.image.PacketImageBuilder;
import com.spinids.image.SequentialPacketWindow;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.awt.image.BufferedImage;
import java.io.File;
import java.io.FileNotFoundException;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class PcapReaderTest {

    @Test
    public void testInvalidAndMissingPcapPathFailsSafely() {
        // Null path
        assertThrows(IllegalArgumentException.class, () ->
                PcapReader.readWindowsFromPcap((String) null, "NORMAL"));

        // Empty path
        assertThrows(IllegalArgumentException.class, () ->
                PcapReader.readWindowsFromPcap("   ", "NORMAL"));

        // Null File object
        assertThrows(IllegalArgumentException.class, () ->
                PcapReader.readWindowsFromPcap((File) null, "NORMAL"));

        // Non-existent file
        assertThrows(FileNotFoundException.class, () ->
                PcapReader.readWindowsFromPcap("non_existent_file_path.pcap", "NORMAL"));
    }

    @Test
    public void testReadWindowsFromGeneratedPcap(@TempDir Path tempDir) throws Exception {
        LivePcapCapture capture = new LivePcapCapture(tempDir.toString());
        // Capture 18 packets (should produce exactly 2 full 9-packet windows)
        File pcapFile = capture.captureTraffic(null, 18);

        assertNotNull(pcapFile);
        assertTrue(pcapFile.exists());

        List<SequentialPacketWindow> windows = PcapReader.readWindowsFromPcap(pcapFile.getAbsolutePath(), "ANOMALY");
        assertNotNull(windows);
        assertEquals(2, windows.size());

        for (SequentialPacketWindow window : windows) {
            assertEquals("ANOMALY", window.getLabel());
            assertEquals(9, window.size());
            assertTrue(window.isFull());
            assertNotNull(window.getFlowId());
            assertTrue(window.getFlowIndex() > 0);

            for (int i = 0; i < window.size(); i++) {
                SequentialPacketWindow.PacketRecord record = window.getPacket(i);
                assertNotNull(record);
                assertEquals(i + 1, record.getPacketNumberInWindow());
                assertNotNull(record.getDirection());
                assertTrue(record.getTimestamp() > 0);
            }

            // Verify compatibility with 27x27 RGB image generation
            BufferedImage img = PacketImageBuilder.buildImage(window);
            assertNotNull(img);
            assertEquals(27, img.getWidth());
            assertEquals(27, img.getHeight());
        }
    }

    @Test
    public void testReadWindowsPartialWindowFlushing(@TempDir Path tempDir) throws Exception {
        LivePcapCapture capture = new LivePcapCapture(tempDir.toString());
        // Capture 10 packets (1 full window of 9 + 1 partial window of 1)
        File pcapFile = capture.captureTraffic(null, 10);

        List<SequentialPacketWindow> windows = PcapReader.readWindowsFromPcap(pcapFile.getAbsolutePath(), "TEST");
        assertNotNull(windows);
        assertEquals(2, windows.size());

        // First window is full (9 packets)
        SequentialPacketWindow firstWindow = windows.get(0);
        assertEquals(9, firstWindow.size());
        assertTrue(firstWindow.isFull());

        // Second window is partial (1 packet)
        SequentialPacketWindow secondWindow = windows.get(1);
        assertEquals(1, secondWindow.size());
        assertFalse(secondWindow.isFull());

        // Partial window still successfully builds 27x27 image with deterministic zero-padding
        BufferedImage img = PacketImageBuilder.buildImage(secondWindow);
        assertNotNull(img);
        assertEquals(27, img.getWidth());
        assertEquals(27, img.getHeight());
    }

    @Test
    public void testReadWindowsWithFlowManager(@TempDir Path tempDir) throws Exception {
        LivePcapCapture capture = new LivePcapCapture(tempDir.toString());
        File pcapFile = capture.captureTraffic(null, 9);

        FlowManager flowManager = new FlowManager();
        List<SequentialPacketWindow> windows = PcapReader.readWindowsFromPcap(
                pcapFile.getAbsolutePath(),
                "NORMAL",
                flowManager
        );

        assertNotNull(windows);
        assertEquals(1, windows.size());
        assertEquals("NORMAL", windows.get(0).getLabel());
        assertFalse(flowManager.getFlows().isEmpty());
    }

    @Test
    public void testReadWindowsDefaultLabelAndFileOverload(@TempDir Path tempDir) throws Exception {
        LivePcapCapture capture = new LivePcapCapture(tempDir.toString());
        File pcapFile = capture.captureTraffic(null, 9);

        // Single argument path overload
        List<SequentialPacketWindow> windowsPath = PcapReader.readWindowsFromPcap(pcapFile.getAbsolutePath());
        assertEquals(1, windowsPath.size());
        assertEquals("NORMAL", windowsPath.get(0).getLabel());

        // File object overload
        List<SequentialPacketWindow> windowsFile = PcapReader.readWindowsFromPcap(pcapFile);
        assertEquals(1, windowsFile.size());
        assertEquals("NORMAL", windowsFile.get(0).getLabel());
    }
}
