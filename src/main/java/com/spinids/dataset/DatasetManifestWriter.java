package com.spinids.dataset;

import com.spinids.image.SequentialPacketWindow;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Manages creation and serialization of the SPIN-IDS image dataset manifest.
 * Records precise metadata tracing every generated 27x27 RGB image back to
 * its source flow, window index, classification label, capture timestamp, and packet count.
 */
public class DatasetManifestWriter {

    public static final String DEFAULT_MANIFEST_PATH = "dataset/images/dataset_manifest.csv";
    public static final String NORMAL_MANIFEST_PATH = "dataset/images/normal_manifest.csv";
    public static final String MALICIOUS_MANIFEST_PATH = "dataset/images/malicious_manifest.csv";

    /**
     * Resolves the default manifest CSV path based on classification label.
     *
     * @param label classification label (e.g. "NORMAL", "MALICIOUS")
     * @return label-aware manifest path
     */
    public static String getDefaultManifestPath(String label) {
        if (label != null && "MALICIOUS".equalsIgnoreCase(label.trim())) {
            return MALICIOUS_MANIFEST_PATH;
        }
        return NORMAL_MANIFEST_PATH;
    }

    public static final String CSV_HEADER =
            "image_path,flow_id,window_index,label,source,timestamp,packet_count";

    /**
     * Data transfer object representing a single row in the dataset manifest.
     */
    public static class ManifestEntry {
        private final String imagePath;
        private final String flowId;
        private final int windowIndex;
        private final String label;
        private final String source;
        private final long timestamp;
        private final int packetCount;

        public ManifestEntry(String imagePath, String flowId, int windowIndex,
                             String label, String source, long timestamp, int packetCount) {
            this.imagePath = normalizePath(imagePath);
            this.flowId = flowId;
            this.windowIndex = windowIndex;
            this.label = (label != null) ? label.trim().toUpperCase() : SequentialPacketWindow.DEFAULT_LABEL;
            this.source = source;
            this.timestamp = timestamp;
            this.packetCount = packetCount;
        }

        public String getImagePath() {
            return imagePath;
        }

        public String getFlowId() {
            return flowId;
        }

        public int getWindowIndex() {
            return windowIndex;
        }

        public String getLabel() {
            return label;
        }

        public String getSource() {
            return source;
        }

        public long getTimestamp() {
            return timestamp;
        }

        public int getPacketCount() {
            return packetCount;
        }

        /**
         * Formats this manifest record into a comma-separated row string.
         */
        public String toCsvRow() {
            return String.format(Locale.US,
                    "%s,%s,%d,%s,%s,%d,%d",
                    escapeCsv(imagePath),
                    escapeCsv(flowId),
                    windowIndex,
                    escapeCsv(label),
                    escapeCsv(source),
                    timestamp,
                    packetCount
            );
        }
    }

    /**
     * Creates a ManifestEntry directly from a saved image file, its corresponding SequentialPacketWindow,
     * and the source PCAP file name.
     */
    public static ManifestEntry createEntry(File imageFile, SequentialPacketWindow window, String sourcePcap) {
        String relativePath = (imageFile != null) ? normalizePath(imageFile.getPath()) : "";
        String flowId = (window != null) ? window.getFlowId() : "";
        int windowIndex = (window != null) ? window.getWindowIndex() : 0;
        String label = (window != null) ? window.getLabel() : SequentialPacketWindow.DEFAULT_LABEL;
        String source = (sourcePcap != null) ? new File(sourcePcap).getName() : "";
        long timestamp = 0L;
        int packetCount = 0;

        if (window != null && window.size() > 0) {
            packetCount = window.size();
            SequentialPacketWindow.PacketRecord firstPkt = window.getPacket(0);
            if (firstPkt != null) {
                timestamp = firstPkt.getTimestamp();
            }
        }

        return new ManifestEntry(relativePath, flowId, windowIndex, label, source, timestamp, packetCount);
    }

    /**
     * Writes manifest entries to the default manifest location.
     */
    public static File writeManifest(List<ManifestEntry> entries) throws IOException {
        return writeManifest(entries, DEFAULT_MANIFEST_PATH);
    }

    /**
     * Writes manifest entries to the specified file path. Overwrites any existing file.
     * Automatically creates parent directories.
     */
    public static File writeManifest(List<ManifestEntry> entries, String outputPath) throws IOException {
        File file = new File(outputPath);
        ensureParentDir(file);

        try (BufferedWriter writer = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(file, false), StandardCharsets.UTF_8))) {

            writer.write(CSV_HEADER);
            writer.newLine();

            if (entries != null) {
                for (ManifestEntry entry : entries) {
                    writer.write(entry.toCsvRow());
                    writer.newLine();
                }
            }
        }

        return file;
    }

    /**
     * Appends manifest entries to an existing manifest file, or creates it with header if absent.
     */
    public static File appendManifest(List<ManifestEntry> entries, String outputPath) throws IOException {
        File file = new File(outputPath);
        ensureParentDir(file);

        boolean writeHeader = !file.exists() || file.length() == 0;

        try (BufferedWriter writer = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(file, true), StandardCharsets.UTF_8))) {

            if (writeHeader) {
                writer.write(CSV_HEADER);
                writer.newLine();
            }

            if (entries != null) {
                for (ManifestEntry entry : entries) {
                    writer.write(entry.toCsvRow());
                    writer.newLine();
                }
            }
        }

        return file;
    }

    private static void ensureParentDir(File file) throws IOException {
        File parentDir = file.getParentFile();
        if (parentDir != null && !parentDir.exists()) {
            boolean created = parentDir.mkdirs();
            if (!created && !parentDir.exists()) {
                throw new IOException("Failed to create directory: " + parentDir.getAbsolutePath());
            }
        }
    }

    private static String normalizePath(String path) {
        if (path == null) return "";
        return path.replace('\\', '/');
    }

    private static String escapeCsv(String value) {
        if (value == null) {
            return "";
        }
        if (value.contains(",") || value.contains("\"") || value.contains("\n") || value.contains("\r")) {
            return "\"" + value.replace("\"", "\"\"") + "\"";
        }
        return value;
    }

    /**
     * Reads and parses a dataset manifest CSV file into a list of ManifestEntry objects.
     *
     * @param manifestFile CSV file to read
     * @return list of parsed ManifestEntry records
     * @throws IOException if reading fails
     */
    public static List<ManifestEntry> readManifest(File manifestFile) throws IOException {
        List<ManifestEntry> entries = new ArrayList<>();
        if (manifestFile == null || !manifestFile.exists()) {
            return entries;
        }

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(new FileInputStream(manifestFile), StandardCharsets.UTF_8))) {
            String line = reader.readLine(); // Header line
            if (line == null) {
                return entries;
            }

            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) {
                    continue;
                }
                List<String> cols = parseCsvLine(line);
                if (cols.size() >= 7) {
                    String imagePath = cols.get(0).trim();
                    String flowId = cols.get(1).trim();
                    int windowIndex = Integer.parseInt(cols.get(2).trim());
                    String label = cols.get(3).trim();
                    String source = cols.get(4).trim();
                    long timestamp = Long.parseLong(cols.get(5).trim());
                    int packetCount = Integer.parseInt(cols.get(6).trim());

                    entries.add(new ManifestEntry(imagePath, flowId, windowIndex, label, source, timestamp, packetCount));
                }
            }
        }
        return entries;
    }

    public static List<ManifestEntry> readManifest(String path) throws IOException {
        return readManifest(new File(path));
    }

    /**
     * Parses a single CSV line into tokens, respecting double-quoted fields.
     */
    public static List<String> parseCsvLine(String line) {
        List<String> tokens = new ArrayList<>();
        if (line == null) {
            return tokens;
        }
        StringBuilder sb = new StringBuilder();
        boolean inQuotes = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '\"') {
                if (inQuotes && i + 1 < line.length() && line.charAt(i + 1) == '\"') {
                    sb.append('\"');
                    i++;
                } else {
                    inQuotes = !inQuotes;
                }
            } else if (c == ',' && !inQuotes) {
                tokens.add(sb.toString());
                sb.setLength(0);
            } else {
                sb.append(c);
            }
        }
        tokens.add(sb.toString());
        return tokens;
    }
}
