package com.spinids;

import com.spinids.image.PacketImageBuilder;
import com.spinids.image.PacketPreprocessor;
import com.spinids.image.SequentialPacketWindow;
import com.spinids.image.SequentialPacketWindow.PacketDirection;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.awt.image.BufferedImage;
import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class PacketImageBuilderTest {

    @TempDir
    Path tempDir;

    @Test
    public void testSequentialPacketWindowCreationAndOrdering() {
        SequentialPacketWindow window = new SequentialPacketWindow("192.168.1.10:5000 <-> 10.0.0.1:80 [TCP]", 1, 1);
        assertEquals(9, window.getTargetWindowSize());
        assertEquals(0, window.size());
        assertFalse(window.isFull());

        for (int i = 1; i <= 9; i++) {
            PacketDirection dir = (i % 2 == 1) ? PacketDirection.FORWARD : PacketDirection.BACKWARD;
            boolean added = window.addPacket(null, 1000L + i * 10, dir, i);
            assertTrue(added);
        }

        assertEquals(9, window.size());
        assertTrue(window.isFull());
        assertFalse(window.addPacket(null, 2000L, PacketDirection.FORWARD, 10)); // Window is full

        // Verify packet ordering and directions
        for (int i = 0; i < 9; i++) {
            SequentialPacketWindow.PacketRecord record = window.getPacket(i);
            assertNotNull(record);
            assertEquals(i + 1, record.getPacketNumberInFlow());
            assertEquals(i + 1, record.getPacketNumberInWindow());
            PacketDirection expectedDir = ((i + 1) % 2 == 1) ? PacketDirection.FORWARD : PacketDirection.BACKWARD;
            assertEquals(expectedDir, record.getDirection());
        }
    }

    @Test
    public void testPacketPreprocessorDeterminismAndSafety() {
        // Null packet handling
        byte[] nullBytes = PacketPreprocessor.preprocess(null);
        assertNotNull(nullBytes);
        assertEquals(PacketPreprocessor.DEFAULT_BYTES_PER_PACKET, nullBytes.length);

        // Preprocess with direction and sequence
        byte[] fwdBytes1 = PacketPreprocessor.preprocess(null, PacketDirection.FORWARD, 3, 243);
        byte[] fwdBytes2 = PacketPreprocessor.preprocess(null, PacketDirection.FORWARD, 3, 243);
        byte[] bwdBytes = PacketPreprocessor.preprocess(null, PacketDirection.BACKWARD, 3, 243);

        assertArrayEquals(fwdBytes1, fwdBytes2, "Identical inputs must produce identical byte vectors");
        assertEquals(PacketPreprocessor.DIRECTION_FORWARD_VAL, fwdBytes1[PacketPreprocessor.OFFSET_DIRECTION]);
        assertEquals(3, fwdBytes1[PacketPreprocessor.OFFSET_SEQUENCE]);
        assertEquals(PacketPreprocessor.DIRECTION_BACKWARD_VAL, bwdBytes[PacketPreprocessor.OFFSET_DIRECTION]);
        assertFalse(Arrays.equals(fwdBytes1, bwdBytes), "Different directions must yield distinct vectors");
    }

    @Test
    public void testImageGenerationDimensionsAndRgbValidity() {
        SequentialPacketWindow window = new SequentialPacketWindow("flow_test", 1, 1);
        for (int i = 1; i <= 9; i++) {
            window.addPacket(null, 1000L + i, PacketDirection.FORWARD, i);
        }

        BufferedImage image = PacketImageBuilder.buildImage(window);
        assertNotNull(image);
        assertEquals(27, image.getWidth(), "Image width must be 27 pixels (3x3 grid of 9x9 patches)");
        assertEquals(27, image.getHeight(), "Image height must be 27 pixels (3x3 grid of 9x9 patches)");

        for (int y = 0; y < image.getHeight(); y++) {
            for (int x = 0; x < image.getWidth(); x++) {
                int rgb = image.getRGB(x, y);
                int r = (rgb >> 16) & 0xFF;
                int g = (rgb >> 8) & 0xFF;
                int b = rgb & 0xFF;
                assertTrue(r >= 0 && r <= 255);
                assertTrue(g >= 0 && g <= 255);
                assertTrue(b >= 0 && b <= 255);
            }
        }
    }

    @Test
    public void testDeterministicImageGeneration() {
        SequentialPacketWindow window1 = new SequentialPacketWindow("flow_test", 1, 1);
        SequentialPacketWindow window2 = new SequentialPacketWindow("flow_test", 1, 1);
        for (int i = 1; i <= 9; i++) {
            window1.addPacket(null, 1000L + i, PacketDirection.FORWARD, i);
            window2.addPacket(null, 1000L + i, PacketDirection.FORWARD, i);
        }

        BufferedImage img1 = PacketImageBuilder.buildImage(window1);
        BufferedImage img2 = PacketImageBuilder.buildImage(window2);

        for (int y = 0; y < 27; y++) {
            for (int x = 0; x < 27; x++) {
                assertEquals(img1.getRGB(x, y), img2.getRGB(x, y),
                        "Pixels at (" + x + "," + y + ") must be identical for identical windows");
            }
        }
    }

    @Test
    public void testPartialWindowFewerThanNinePacketsSafeHandling() {
        // Window with only 4 packets (fewer than 9)
        SequentialPacketWindow partialWindow = new SequentialPacketWindow("partial_flow", 2, 1);
        for (int i = 1; i <= 4; i++) {
            partialWindow.addPacket(null, 1000L + i, PacketDirection.FORWARD, i);
        }
        assertEquals(4, partialWindow.size());
        assertFalse(partialWindow.isFull());

        // Must not crash, should produce valid 27x27 image with zero-padded empty slots
        BufferedImage image = PacketImageBuilder.buildImage(partialWindow);
        assertNotNull(image);
        assertEquals(27, image.getWidth());
        assertEquals(27, image.getHeight());

        // Slot 8 (bottom-right patch: px 18..26, py 18..26) should be empty/zero-padded
        int paddedRgb = image.getRGB(20, 20);
        // Byte 0 of unpopulated slot is 0, so R=0, G=0, B=0
        assertEquals(0, paddedRgb & 0x00FFFFFF, "Unpopulated slots must be zero-padded");
    }

    @Test
    public void testSaveImageAndBatchGeneration() throws Exception {
        SequentialPacketWindow window = new SequentialPacketWindow("flow_batch", 1, 1);
        for (int i = 1; i <= 9; i++) {
            window.addPacket(null, 1000L + i, PacketDirection.FORWARD, i);
        }

        List<SequentialPacketWindow> list = new ArrayList<>();
        list.add(window);

        String outputDir = tempDir.resolve("images").toString();
        List<File> files = PacketImageBuilder.generateImages(list, outputDir, 5);

        assertEquals(1, files.size());
        File savedFile = files.get(0);
        assertTrue(savedFile.exists());
        assertTrue(savedFile.length() > 0);
        assertTrue(savedFile.getName().startsWith("flow_001_window_001"));
    }
}
