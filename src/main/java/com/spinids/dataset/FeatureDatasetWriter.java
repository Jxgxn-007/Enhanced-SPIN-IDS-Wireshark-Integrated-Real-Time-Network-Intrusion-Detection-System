package com.spinids.dataset;

import com.spinids.features.FlowFeatures;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;

/**
 * Writes extracted network flow features into a CSV dataset file
 * for machine learning model training and intrusion detection classification.
 */
public class FeatureDatasetWriter {

    public static final String DEFAULT_OUTPUT_PATH = "dataset/features/normal_traffic_features.csv";
    public static final String DEFAULT_LABEL = "NORMAL";

    public static final String CSV_HEADER =
            "source_ip,destination_ip,source_port,destination_port,protocol," +
            "flow_duration_ms,packet_count,total_bytes,avg_packet_size," +
            "packets_per_second,bytes_per_second,forward_packet_count,reverse_packet_count,label";

    /**
     * Writes flow features into the default CSV file location with the default label "NORMAL".
     *
     * @param featuresList list of extracted flow features
     * @return File object of the written CSV dataset
     * @throws IOException if writing to the file fails
     */
    public static File writeDataset(List<FlowFeatures> featuresList) throws IOException {
        return writeDataset(featuresList, DEFAULT_OUTPUT_PATH, DEFAULT_LABEL);
    }

    /**
     * Writes flow features into the specified CSV file path with the given label.
     * Automatically creates parent directories if they do not exist.
     *
     * @param featuresList list of extracted flow features
     * @param outputPath   target CSV file path
     * @param label        class label to assign (e.g., NORMAL, ATTACK)
     * @return File object of the written CSV dataset
     * @throws IOException if writing to the file fails
     */
    public static File writeDataset(List<FlowFeatures> featuresList, String outputPath, String label) throws IOException {
        File file = new File(outputPath);

        // Ensure parent directories exist
        File parentDir = file.getParentFile();
        if (parentDir != null && !parentDir.exists()) {
            boolean created = parentDir.mkdirs();
            if (!created && !parentDir.exists()) {
                throw new IOException("Failed to create directory: " + parentDir.getAbsolutePath());
            }
        }

        try (BufferedWriter writer = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8))) {

            // Write CSV header
            writer.write(CSV_HEADER);
            writer.newLine();

            // Write feature rows
            if (featuresList != null) {
                for (FlowFeatures f : featuresList) {
                    writer.write(formatRow(f, label));
                    writer.newLine();
                }
            }
        }

        return file;
    }

    /**
     * Formats a single FlowFeatures record into a CSV row string.
     *
     * @param f     the flow features
     * @param label classification label
     * @return comma-separated value row
     */
    public static String formatRow(FlowFeatures f, String label) {
        String lbl = (label != null) ? label : DEFAULT_LABEL;

        return String.format(Locale.US,
                "%s,%s,%d,%d,%s,%d,%d,%d,%.4f,%.4f,%.4f,%d,%d,%s",
                escapeCsv(f.getSourceIp()),
                escapeCsv(f.getDestinationIp()),
                f.getSourcePort(),
                f.getDestinationPort(),
                escapeCsv(f.getProtocol()),
                f.getDuration(),
                f.getPacketCount(),
                f.getTotalBytes(),
                f.getAvgPacketSize(),
                f.getPacketsPerSecond(),
                f.getBytesPerSecond(),
                f.getForwardPacketCount(),
                f.getReversePacketCount(),
                escapeCsv(lbl)
        );
    }

    /**
     * Escapes special characters for standard RFC 4180 CSV compliance.
     *
     * @param value raw string value
     * @return escaped string value
     */
    public static String escapeCsv(String value) {
        if (value == null) {
            return "";
        }
        if (value.contains(",") || value.contains("\"") || value.contains("\n") || value.contains("\r")) {
            return "\"" + value.replace("\"", "\"\"") + "\"";
        }
        return value;
    }
}
