package com.spinids;

import com.spinids.alert.AlertManager;
import com.spinids.capture.LivePcapCapture;
import com.spinids.capture.PcapReader;
import com.spinids.detection.DetectionResult;
import com.spinids.detection.OnnxDetector;
import com.spinids.generator.AnomalyTrafficGenerator;
import com.spinids.image.PacketImageBuilder;
import com.spinids.image.SequentialPacketWindow;
import com.spinids.trigger.AnomalyTrigger;
import com.spinids.trigger.TrafficMonitor;

import java.awt.image.BufferedImage;
import java.io.File;
import java.util.List;

/**
 * End-to-end SPIN-IDS automation pipeline demonstration.
 *
 * <p>Flow:
 * <ol>
 *   <li>Monitor normal traffic and compute baseline rate.</li>
 *   <li>Detect threshold exceedance when synthetic traffic is generated.</li>
 *   <li>AnomalyTrigger fires (without claiming maliciousness).</li>
 *   <li>LivePcapCapture captures packets into a timestamped PCAP in {@code dataset/captures/generated/}.</li>
 *   <li>PcapReader processes PCAP into sequential packet windows.</li>
 *   <li>PacketImageBuilder creates 27x27 RGB images with IP masking.</li>
 *   <li>OnnxDetector executes CNN inference using {@code ml/models/spin_ids_cnn.onnx}.</li>
 *   <li>AlertManager displays predictions/confidence alerts and appends to {@code dataset/results/detection_log.csv}.</li>
 * </ol>
 * </p>
 */
public class SpinIdsLive {

    public static void main(String[] args) {
        double threshold = TrafficMonitor.DEFAULT_THRESHOLD_PPS; // 500 pps
        long cooldownMs = AnomalyTrigger.DEFAULT_COOLDOWN_MILLIS; // 10,000 ms
        double baselineRate = 42.0;
        double burstRate = 820.0;
        int burstPackets = 50;

        // Parse optional CLI arguments
        for (int i = 0; i < args.length; i++) {
            if ("--threshold".equalsIgnoreCase(args[i]) && i + 1 < args.length) {
                threshold = Double.parseDouble(args[++i]);
            } else if ("--cooldown".equalsIgnoreCase(args[i]) && i + 1 < args.length) {
                cooldownMs = Long.parseLong(args[++i]);
            } else if ("--baseline".equalsIgnoreCase(args[i]) && i + 1 < args.length) {
                baselineRate = Double.parseDouble(args[++i]);
            } else if ("--burst-rate".equalsIgnoreCase(args[i]) && i + 1 < args.length) {
                burstRate = Double.parseDouble(args[++i]);
            } else if ("--burst-packets".equalsIgnoreCase(args[i]) && i + 1 < args.length) {
                burstPackets = Integer.parseInt(args[++i]);
            }
        }

        try {
            // Step 1: Initialize Monitor and Trigger
            TrafficMonitor monitor = new TrafficMonitor(threshold);
            AnomalyTrigger trigger = new AnomalyTrigger(monitor, cooldownMs);

            System.out.println("[*] SPIN-IDS Live Traffic Monitor started");

            // Step 2: Baseline normal traffic monitoring
            monitor.setManualRate(baselineRate);
            System.out.println(String.format("[*] Baseline packet rate: %.0f packets/sec", monitor.getCurrentPacketRate()));
            System.out.println("[*] Status: NORMAL");

            // Step 3: Start synthetic anomaly generator
            System.out.println("[*] Starting synthetic anomaly generator...");
            AnomalyTrafficGenerator generator = new AnomalyTrafficGenerator(
                    AnomalyTrafficGenerator.DEFAULT_TARGET_PORT,
                    burstRate,
                    burstPackets
            );
            generator.attachMonitor(monitor);

            // Step 4: Evaluate anomaly trigger with the burst packet rate
            monitor.setManualRate(burstRate);
            boolean triggered = trigger.evaluate();

            // Step 5: Capture actual anomalous packets to PCAP on disk
            System.out.println("[*] Capturing anomalous burst to PCAP...");
            LivePcapCapture capture = new LivePcapCapture();
            File pcapFile = capture.captureTraffic(generator, burstPackets);

            System.out.println("[*] Saved PCAP to: " + pcapFile.getPath().replace("\\", "/"));
            System.out.println(String.format("[*] Captured %d anomalous packets", capture.getLastCapturedCount()));

            // Step 6: Process captured PCAP into sequential packet windows
            System.out.println("[*] Processing captured PCAP with SPIN-IDS sequential pipeline...");
            List<SequentialPacketWindow> windows = PcapReader.readWindowsFromPcap(pcapFile.getAbsolutePath(), "ANOMALY");
            System.out.println(String.format("[*] Extracted %d sequential packet window(s)", windows.size()));

            // Step 7: Load ONNX CNN model and AlertManager
            AlertManager alertManager = new AlertManager();

            try (OnnxDetector detector = new OnnxDetector()) {
                System.out.println("[*] ONNX CNN model loaded successfully (ml/models/spin_ids_cnn.onnx)");
                System.out.println("[*] Executing inference on sequential packet window images...\n");

                for (SequentialPacketWindow window : windows) {
                    BufferedImage image = PacketImageBuilder.buildImage(window);
                    DetectionResult result = detector.detect(
                            image,
                            window.getWindowIndex(),
                            window.getFlowId(),
                            pcapFile.getName()
                    );
                    alertManager.handleDetection(result);
                }
            }

            System.out.println("\n[*] Detection log saved to: " + alertManager.getLogCsvPath().replace("\\", "/"));
            System.out.println("[*] Trigger-to-Inference pipeline completed successfully");

        } catch (Exception e) {
            System.err.println("[-] Pipeline execution failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
