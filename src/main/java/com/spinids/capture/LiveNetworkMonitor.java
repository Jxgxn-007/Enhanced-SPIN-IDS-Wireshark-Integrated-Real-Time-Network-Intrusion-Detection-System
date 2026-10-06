package com.spinids.capture;

import com.spinids.trigger.AnomalyTrigger;
import com.spinids.trigger.TrafficMonitor;
import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;

import java.io.File;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Passive network interface monitor using Pcap4J and Npcap.
 *
 * <p>Captures live packets from a selected physical or virtual network interface (e.g. Wi-Fi, Ethernet),
 * feeds packet arrivals into {@link TrafficMonitor} to calculate packets-per-second (PPS), and
 * evaluates {@link AnomalyTrigger}. When the rate exceeds 500 PPS, it automatically triggers a bounded,
 * non-disruptive PCAP capture (capped at 5 seconds or 5,000 packets) for downstream CNN inference.</p>
 *
 * <p>Strictly passive: does not inject, modify, or transmit network packets.</p>
 */
public class LiveNetworkMonitor {

    public static final double ANOMALY_THRESHOLD_PPS = 500.0;
    public static final int CAPTURE_DURATION_SECONDS = 5;
    public static final int MAX_CAPTURE_PACKETS = 5000;
    public static final int SNAPLEN = 65536;
    public static final int READ_TIMEOUT_MS = 20;
    public static final String CAPTURE_OUTPUT_DIR = "dataset/captures/generated/";

    public interface CaptureEventListener {
        void onAnomalyTriggered(double rate, double threshold, File targetPcapFile);
        void onCaptureCompleted(File pcapFile, int packetCount);
        void onError(String errorMessage);
    }

    private final TrafficMonitor monitor;
    private final AnomalyTrigger trigger;
    private final String outputDirectory;

    private PcapNetworkInterface activeInterface;
    private PcapHandle pcapHandle;
    private PcapDumper activeDumper;
    private File currentCaptureFile;

    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicBoolean captureInProgress = new AtomicBoolean(false);
    private final AtomicLong totalPacketsCaptured = new AtomicLong(0);

    private volatile int currentBurstPacketCount = 0;
    private volatile long captureEndTimeMs = 0L;
    private volatile String lastError = null;
    private Thread captureThread;
    private CaptureEventListener eventListener;

    public LiveNetworkMonitor(TrafficMonitor monitor, AnomalyTrigger trigger) {
        this(monitor, trigger, CAPTURE_OUTPUT_DIR);
    }

    public LiveNetworkMonitor(TrafficMonitor monitor, AnomalyTrigger trigger, String outputDirectory) {
        this.monitor = monitor != null ? monitor : new TrafficMonitor(ANOMALY_THRESHOLD_PPS);
        this.trigger = trigger != null ? trigger : new AnomalyTrigger(this.monitor);
        this.outputDirectory = outputDirectory != null ? outputDirectory : CAPTURE_OUTPUT_DIR;

        File dir = new File(this.outputDirectory);
        if (!dir.exists()) {
            dir.mkdirs();
        }
    }

    public synchronized void setEventListener(CaptureEventListener listener) {
        this.eventListener = listener;
    }

    /**
     * Initiates continuous passive packet sniffing on the specified network interface.
     *
     * @param nif the PcapNetworkInterface to monitor
     * @throws Exception if interface cannot be opened
     */
    public synchronized void startMonitoring(PcapNetworkInterface nif) throws Exception {
        if (nif == null) {
            throw new IllegalArgumentException("Target network interface cannot be null");
        }

        if (running.get()) {
            stopMonitoring();
        }

        this.activeInterface = nif;
        this.lastError = null;

        // Open live capture handle with fallback from PROMISCUOUS to NONPROMISCUOUS
        try {
            try {
                this.pcapHandle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT_MS);
            } catch (PcapNativeException pne) {
                System.out.println("[*] Promiscuous mode unavailable; attempting NONPROMISCUOUS mode for " + nif.getName());
                this.pcapHandle = nif.openLive(SNAPLEN, PromiscuousMode.NONPROMISCUOUS, READ_TIMEOUT_MS);
            }
        } catch (Throwable t) {
            this.lastError = "Unable to open selected network interface (" + nif.getDescription() +
                    "). Check Npcap installation and administrator permissions.";
            System.err.println("[-] " + this.lastError + " Reason: " + t.getMessage());
            if (eventListener != null) {
                eventListener.onError(this.lastError);
            }
            throw new RuntimeException(this.lastError, t);
        }

        running.set(true);
        captureThread = new Thread(this::runCaptureLoop, "Spin-LiveSniffer-" + nif.getName());
        captureThread.setDaemon(true);
        captureThread.start();

        System.out.println("[*] LiveNetworkMonitor active on: " +
                (nif.getDescription() != null ? nif.getDescription() : nif.getName()));
    }

    /**
     * Halts passive packet capture and finalizes any open PCAP dumper.
     */
    public synchronized void stopMonitoring() {
        running.set(false);

        // Terminate ongoing PCAP capture if active
        finalizeActiveCapture();

        if (pcapHandle != null) {
            try {
                pcapHandle.breakLoop();
            } catch (Exception ignored) {}
            try {
                pcapHandle.close();
            } catch (Exception ignored) {}
            pcapHandle = null;
        }

        if (captureThread != null) {
            captureThread.interrupt();
            captureThread = null;
        }

        System.out.println("[*] LiveNetworkMonitor halted.");
    }

    /**
     * Continuous capture loop executing on the dedicated sniffer daemon thread.
     */
    private void runCaptureLoop() {
        while (running.get() && pcapHandle != null && pcapHandle.isOpen()) {
            try {
                Packet packet = pcapHandle.getNextPacket();
                long now = System.currentTimeMillis();

                if (packet != null) {
                    totalPacketsCaptured.incrementAndGet();
                    monitor.recordPacket();

                    // 1. If automatic bounded capture is currently in progress, dump packet
                    if (captureInProgress.get()) {
                        synchronized (this) {
                            if (activeDumper != null && captureInProgress.get()) {
                                Timestamp ts = new Timestamp(now);
                                activeDumper.dump(packet, ts);
                                currentBurstPacketCount++;

                                // Check bounded window stopping criteria
                                if (currentBurstPacketCount >= MAX_CAPTURE_PACKETS || now >= captureEndTimeMs) {
                                    finalizeActiveCapture();
                                }
                            }
                        }
                    }
                }

                // 2. Check timeout if capture in progress even during temporary idle gaps
                if (captureInProgress.get() && now >= captureEndTimeMs) {
                    synchronized (this) {
                        if (captureInProgress.get()) {
                            finalizeActiveCapture();
                        }
                    }
                }

                // 3. If no capture active, evaluate whether packet rate crossed the 500 PPS threshold
                if (!captureInProgress.get()) {
                    double currentRate = monitor.getCurrentPacketRate();
                    if (currentRate >= monitor.getThreshold()) {
                        // Evaluate AnomalyTrigger (checks 10-second cooldown internally)
                        if (trigger.evaluate(currentRate)) {
                            startBoundedCapture(currentRate);
                        }
                    }
                }

            } catch (NotOpenException noe) {
                break; // Handle closed on stop
            } catch (Exception e) {
                if (running.get()) {
                    System.err.println("[-] Packet capture warning: " + e.getMessage());
                }
            }
        }
    }

    /**
     * Starts a bounded automatic PCAP capture when an anomaly trigger fires.
     */
    private synchronized void startBoundedCapture(double rate) {
        try {
            String timestampStr = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
            File pcapFile = new File(outputDirectory, "real_anomaly_capture_" + timestampStr + ".pcap");

            if (pcapFile.getParentFile() != null) {
                pcapFile.getParentFile().mkdirs();
            }

            this.currentCaptureFile = pcapFile;
            this.activeDumper = pcapHandle.dumpOpen(pcapFile.getAbsolutePath());
            this.currentBurstPacketCount = 0;
            this.captureEndTimeMs = System.currentTimeMillis() + (CAPTURE_DURATION_SECONDS * 1000L);
            this.captureInProgress.set(true);

            System.out.println(String.format("[!] Anomaly triggered (%.0f PPS > %.0f PPS). Starting %ds automatic PCAP capture: %s",
                    rate, monitor.getThreshold(), CAPTURE_DURATION_SECONDS, pcapFile.getName()));

            if (eventListener != null) {
                eventListener.onAnomalyTriggered(rate, monitor.getThreshold(), pcapFile);
            }
        } catch (Exception e) {
            System.err.println("[-] Failed to initiate bounded PCAP capture: " + e.getMessage());
            captureInProgress.set(false);
            if (activeDumper != null) {
                try { activeDumper.close(); } catch (Exception ignored) {}
                activeDumper = null;
            }
        }
    }

    /**
     * Closes the active PCAP dumper and triggers downstream processing callback.
     */
    private synchronized void finalizeActiveCapture() {
        if (!captureInProgress.get() && activeDumper == null) return;

        captureInProgress.set(false);
        final File finishedFile = currentCaptureFile;
        final int finalCount = currentBurstPacketCount;

        if (activeDumper != null) {
            try {
                activeDumper.flush();
                activeDumper.close();
            } catch (Exception e) {
                System.err.println("[-] Error closing PCAP dumper: " + e.getMessage());
            }
            activeDumper = null;
        }

        if (finishedFile != null && finishedFile.exists()) {
            System.out.println(String.format("[*] Automatic PCAP capture completed: %s (%d packets captured)",
                    finishedFile.getName(), finalCount));

            if (eventListener != null) {
                // Execute listener in separate thread so capture loop is never delayed
                new Thread(() -> {
                    try {
                        eventListener.onCaptureCompleted(finishedFile, finalCount);
                    } catch (Exception ex) {
                        System.err.println("[-] Error handling capture completion event: " + ex.getMessage());
                    }
                }, "Spin-PcapProcessor").start();
            }
        }
    }

    public boolean isRunning() {
        return running.get();
    }

    public boolean isCaptureInProgress() {
        return captureInProgress.get();
    }

    public boolean isCooldownActive() {
        long elapsed = System.currentTimeMillis() - trigger.getLastTriggerTimeMs();
        return trigger.getLastTriggerTimeMs() > 0 && elapsed < trigger.getCooldownMillis();
    }

    public long getTotalPacketsCaptured() {
        return totalPacketsCaptured.get();
    }

    public PcapNetworkInterface getActiveInterface() {
        return activeInterface;
    }

    public TrafficMonitor getMonitor() {
        return monitor;
    }

    public AnomalyTrigger getTrigger() {
        return trigger;
    }

    public String getLastError() {
        return lastError;
    }

    public File getCurrentCaptureFile() {
        return currentCaptureFile;
    }
}
