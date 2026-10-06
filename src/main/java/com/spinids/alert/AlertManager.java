package com.spinids.alert;

import com.spinids.detection.DetectionResult;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * Handles alert printing and CSV logging for SPIN-IDS CNN detection events.
 */
public class AlertManager {

    public static final String DEFAULT_LOG_PATH = "dataset/results/detection_log.csv";
    private final String logCsvPath;

    public AlertManager() {
        this(DEFAULT_LOG_PATH);
    }

    public AlertManager(String logCsvPath) {
        this.logCsvPath = logCsvPath != null ? logCsvPath : DEFAULT_LOG_PATH;
        initCsvFile();
    }

    private void initCsvFile() {
        File file = new File(logCsvPath);
        if (file.getParentFile() != null && !file.getParentFile().exists()) {
            file.getParentFile().mkdirs();
        }

        if (!file.exists() || file.length() == 0) {
            try (PrintWriter writer = new PrintWriter(new FileWriter(file, true))) {
                writer.println("timestamp,pcap_file,window_index,prediction,normal_probability,malicious_probability,confidence");
            } catch (IOException e) {
                System.err.println("[-] Error initializing detection CSV log: " + e.getMessage());
            }
        }
    }

    /**
     * Handles a detection event: prints formatted alert to console and appends to CSV log.
     *
     * @param result detection outcome from ONNX CNN
     */
    public synchronized void handleDetection(DetectionResult result) {
        if (result == null) return;

        printAlert(result);
        logToCsv(result);
    }

    /**
     * Prints formatted alert to standard output.
     *
     * @param result detection result
     */
    public void printAlert(DetectionResult result) {
        if (result.isMalicious()) {
            System.out.println("========================================");
            System.out.println("       SPIN-IDS DETECTION ALERT         ");
            System.out.println("========================================");
            System.out.println("Prediction : MALICIOUS");
            System.out.println(String.format("Confidence : %.2f%%", result.getConfidence() * 100.0));
            System.out.println("Window     : " + result.getWindowIndex());
            System.out.println("Timestamp  : " + result.getTimestamp());
            System.out.println("========================================");
        } else {
            System.out.println("Prediction : NORMAL");
            System.out.println(String.format("Confidence : %.2f%%", result.getConfidence() * 100.0));
        }
    }

    /**
     * Appends detection record to detection_log.csv.
     *
     * @param result detection result
     */
    public synchronized void logToCsv(DetectionResult result) {
        File file = new File(logCsvPath);
        try (PrintWriter writer = new PrintWriter(new FileWriter(file, true))) {
            writer.println(String.format("%s,%s,%d,%s,%.6f,%.6f,%.6f",
                    result.getTimestamp(),
                    escapeCsv(result.getPcapFile()),
                    result.getWindowIndex(),
                    result.getPredictedLabel(),
                    result.getNormalProbability(),
                    result.getMaliciousProbability(),
                    result.getConfidence()
            ));
        } catch (IOException e) {
            System.err.println("[-] Error writing to detection CSV log: " + e.getMessage());
        }
    }

    private String escapeCsv(String val) {
        if (val == null) return "";
        if (val.contains(",") || val.contains("\"") || val.contains("\n")) {
            return "\"" + val.replace("\"", "\"\"") + "\"";
        }
        return val;
    }

    public String getLogCsvPath() {
        return logCsvPath;
    }
}
