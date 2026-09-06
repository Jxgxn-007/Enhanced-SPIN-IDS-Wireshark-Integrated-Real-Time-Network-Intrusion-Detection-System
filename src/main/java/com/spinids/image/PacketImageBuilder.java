package com.spinids.image;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Builds 2D RGB image representations from sequential network packet windows.
 * Encodes 9 sequential packets in a 3x3 spatial grid of 9x9 pixel patches,
 * yielding a deterministic 27x27 RGB image suitable for CNN feature extraction.
 */
public class PacketImageBuilder {

    public static final int WINDOW_SIZE = 9;
    public static final int GRID_ROWS = 3;
    public static final int GRID_COLS = 3;
    public static final int PACKET_PATCH_SIZE = 9; // 9x9 pixels per packet patch

    // Image dimensions
    public static final int IMAGE_WIDTH = GRID_COLS * PACKET_PATCH_SIZE;   // 27 pixels
    public static final int IMAGE_HEIGHT = GRID_ROWS * PACKET_PATCH_SIZE; // 27 pixels

    // Bytes required per packet: 9 x 9 pixels x 3 color channels = 243 bytes
    public static final int BYTES_PER_PACKET = PACKET_PATCH_SIZE * PACKET_PATCH_SIZE * 3;

    public static final int DEFAULT_MAX_WINDOWS = 10;
    public static final String DEFAULT_OUTPUT_DIR = "dataset/images/";

    /**
     * Builds a 27x27 RGB BufferedImage from a 9-packet SequentialPacketWindow.
     *
     * @param window sequential packet window (contains up to 9 packets)
     * @return deterministic BufferedImage of size 27x27 in TYPE_INT_RGB
     */
    public static BufferedImage buildImage(SequentialPacketWindow window) {
        BufferedImage image = new BufferedImage(IMAGE_WIDTH, IMAGE_HEIGHT, BufferedImage.TYPE_INT_RGB);

        for (int slot = 0; slot < WINDOW_SIZE; slot++) {
            // Determine 3x3 grid coordinates
            int gridRow = slot / GRID_COLS;
            int gridCol = slot % GRID_COLS;

            int startX = gridCol * PACKET_PATCH_SIZE;
            int startY = gridRow * PACKET_PATCH_SIZE;

            // Retrieve or pad packet record
            byte[] packetBytes;
            if (window != null && slot < window.size()) {
                packetBytes = PacketPreprocessor.preprocess(window.getPacket(slot));
            } else {
                // Deterministic zero-padding for empty / partial window slots
                packetBytes = PacketPreprocessor.preprocess(null, null, slot + 1, BYTES_PER_PACKET);
            }

            // Map 243 bytes into 81 RGB pixels within this 9x9 patch
            int byteIndex = 0;
            for (int py = 0; py < PACKET_PATCH_SIZE; py++) {
                for (int px = 0; px < PACKET_PATCH_SIZE; px++) {
                    int r = packetBytes[byteIndex] & 0xFF;
                    int g = packetBytes[byteIndex + 1] & 0xFF;
                    int b = packetBytes[byteIndex + 2] & 0xFF;
                    byteIndex += 3;

                    int rgb = (r << 16) | (g << 8) | b;
                    image.setRGB(startX + px, startY + py, rgb);
                }
            }
        }

        return image;
    }

    /**
     * Saves a BufferedImage to disk as a PNG file.
     *
     * @param image      the BufferedImage to save
     * @param outputFile destination file
     * @throws IOException if writing fails
     */
    public static void saveImage(BufferedImage image, File outputFile) throws IOException {
        File parentDir = outputFile.getParentFile();
        if (parentDir != null && !parentDir.exists()) {
            parentDir.mkdirs();
        }
        ImageIO.write(image, "PNG", outputFile);
    }

    /**
     * Generates and saves PNG images for the given sequential windows up to maxWindows.
     *
     * @param windows    list of completed sequential packet windows
     * @param outputDir  directory path to save images
     * @param maxWindows maximum number of images to write
     * @return list of generated image files
     * @throws IOException if saving fails
     */
    public static List<File> generateImages(List<SequentialPacketWindow> windows,
                                            String outputDir,
                                            int maxWindows) throws IOException {
        List<File> generatedFiles = new ArrayList<>();
        if (windows == null || windows.isEmpty()) {
            return generatedFiles;
        }

        File dir = new File(outputDir);
        if (!dir.exists()) {
            dir.mkdirs();
        }

        int limit = (maxWindows > 0) ? Math.min(windows.size(), maxWindows) : windows.size();
        for (int i = 0; i < limit; i++) {
            SequentialPacketWindow window = windows.get(i);
            String filename = String.format("flow_%03d_window_%03d.png", window.getFlowIndex(), window.getWindowIndex());
            File outputFile = new File(dir, filename);

            BufferedImage image = buildImage(window);
            saveImage(image, outputFile);
            generatedFiles.add(outputFile);
        }

        return generatedFiles;
    }

    /**
     * Prints a concise summary of the image building process.
     */
    public static void printImageSummary(int packetsProcessed, int flowsFound,
                                         int windowsGenerated, int imagesGenerated,
                                         String outputDirectory) {
        System.out.println("========================================");
        System.out.println("SPIN-IDS IMAGE BUILDER");
        System.out.println("========================================");
        System.out.println("Packets Processed : " + packetsProcessed);
        System.out.println("Flows Found       : " + flowsFound);
        System.out.println("Window Size       : " + WINDOW_SIZE);
        System.out.println("Windows Generated : " + windowsGenerated);
        System.out.println("Images Generated  : " + imagesGenerated);
        System.out.println("Output Directory  : " + outputDirectory);
        System.out.println("Status            : SUCCESS");
        System.out.println("========================================");
    }
}
