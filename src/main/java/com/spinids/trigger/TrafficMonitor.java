package com.spinids.trigger;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.packet.Packet;

import java.io.File;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Monitors network packet throughput and computes packets-per-second (PPS).
 *
 * <p>Uses a rolling 1-second sliding window to maintain accurate, thread-safe
 * packet rate telemetry against a configurable anomaly threshold.
 * In accordance with SPIN-IDS design guidelines, TrafficMonitor does NOT classify
 * traffic as malicious; it strictly reports whether packet throughput is anomalous.</p>
 */
public class TrafficMonitor {

    public static final double DEFAULT_THRESHOLD_PPS = 500.0;
    private static final int BUCKET_COUNT = 10;
    private static final long BUCKET_DURATION_MS = 100L;
    private static final long WINDOW_SPAN_MS = BUCKET_COUNT * BUCKET_DURATION_MS; // 1,000 ms

    static {
        // Automatically configure Npcap library path on Windows if needed
        if (System.getProperty("os.name", "").toLowerCase().contains("win")) {
            String npcapPath = "C:\\Windows\\System32\\Npcap";
            if (new File(npcapPath).exists()) {
                String current = System.getProperty("jna.library.path");
                if (current == null || current.isEmpty()) {
                    System.setProperty("jna.library.path", npcapPath);
                } else if (!current.contains(npcapPath)) {
                    System.setProperty("jna.library.path", current + ";" + npcapPath);
                }
            }
        }
    }

    private static class Bucket {
        volatile long bucketStartEpochMs = 0L;
        final AtomicInteger count = new AtomicInteger(0);
    }

    private final Bucket[] buckets;
    private volatile double thresholdPps;
    private volatile Double manualOverrideRate = null;

    /**
     * Constructs a TrafficMonitor with a custom packets-per-second threshold.
     *
     * @param thresholdPps threshold above which traffic rate is flagged as anomalous
     */
    public TrafficMonitor(double thresholdPps) {
        this.thresholdPps = Math.max(0.0, thresholdPps);
        this.buckets = new Bucket[BUCKET_COUNT];
        for (int i = 0; i < BUCKET_COUNT; i++) {
            this.buckets[i] = new Bucket();
        }
    }

    /**
     * Constructs a TrafficMonitor with the default threshold of 500 packets/second.
     */
    public TrafficMonitor() {
        this(DEFAULT_THRESHOLD_PPS);
    }

    /**
     * Records the arrival of a single network packet.
     */
    public void recordPacket() {
        recordPackets(1);
    }

    /**
     * Records the arrival of a batch of network packets.
     *
     * @param count number of packets received
     */
    public void recordPackets(int count) {
        if (count <= 0) return;
        long now = System.currentTimeMillis();
        int bucketIndex = (int) ((now / BUCKET_DURATION_MS) % BUCKET_COUNT);
        long expectedBucketStart = (now / BUCKET_DURATION_MS) * BUCKET_DURATION_MS;

        Bucket bucket = buckets[bucketIndex];
        synchronized (bucket) {
            if (bucket.bucketStartEpochMs != expectedBucketStart) {
                bucket.bucketStartEpochMs = expectedBucketStart;
                bucket.count.set(count);
            } else {
                bucket.count.addAndGet(count);
            }
        }
    }

    /**
     * Listener callback handler for Pcap4J packet arrival.
     *
     * @param packet incoming Pcap4J Packet
     */
    public void onPacket(Packet packet) {
        if (packet != null) {
            recordPacket();
        }
    }

    /**
     * Attaches and reads up to maxPackets from a Pcap4J handle.
     *
     * @param handle     PcapHandle instance (live capture or offline)
     * @param maxPackets maximum number of packets to read
     * @throws Exception if handle read fails
     */
    public void processCaptureHandle(PcapHandle handle, int maxPackets) throws Exception {
        if (handle == null) return;
        int processed = 0;
        while (processed < maxPackets) {
            Packet packet = handle.getNextPacket();
            if (packet == null) break;
            recordPacket();
            processed++;
        }
    }

    /**
     * Computes the current packet throughput in packets-per-second (PPS)
     * over the rolling 1-second time window.
     *
     * @return current packets per second
     */
    public double getCurrentPacketRate() {
        if (manualOverrideRate != null) {
            return manualOverrideRate;
        }

        long now = System.currentTimeMillis();
        long windowStartCutoff = now - WINDOW_SPAN_MS;
        int totalPackets = 0;

        for (Bucket bucket : buckets) {
            if (bucket.bucketStartEpochMs >= windowStartCutoff) {
                totalPackets += bucket.count.get();
            }
        }

        // Return packets per second (normalized across the 1.0s window)
        return (double) totalPackets;
    }

    /**
     * Determines whether the current packet rate exceeds the configured threshold.
     *
     * @return true if packet throughput is anomalous (threshold exceeded), false otherwise
     */
    public boolean isThresholdExceeded() {
        return getCurrentPacketRate() >= thresholdPps;
    }

    /**
     * Alias for isThresholdExceeded(). Reports strictly whether traffic is anomalous.
     *
     * @return true if anomalous rate detected
     */
    public boolean isAnomalous() {
        return isThresholdExceeded();
    }

    public double getThreshold() {
        return thresholdPps;
    }

    public void setThreshold(double thresholdPps) {
        this.thresholdPps = Math.max(0.0, thresholdPps);
    }

    /**
     * Sets a manual packet rate override for simulated scenarios and testing.
     * Set to null to restore real-time rolling calculations.
     *
     * @param rate packets per second override, or null
     */
    public void setManualRate(Double rate) {
        this.manualOverrideRate = rate;
    }

    /**
     * Resets all rolling telemetry counters and manual overrides.
     */
    public void reset() {
        manualOverrideRate = null;
        for (Bucket bucket : buckets) {
            synchronized (bucket) {
                bucket.bucketStartEpochMs = 0L;
                bucket.count.set(0);
            }
        }
    }
}
