package com.spinids.generator;

import com.spinids.trigger.TrafficMonitor;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Random;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Generates synthetic anomalous network traffic strictly confined to loopback (127.0.0.1).
 *
 * <p>SAFETY GUARANTEES:
 * <ul>
 *   <li>Only targets loopback localhost (127.0.0.1). Never connects to or targets external networks.</li>
 *   <li>Uses non-destructive, benign UDP datagram payloads.</li>
 *   <li>Supports configurable packet burst rates (PPS) and total packet limits.</li>
 *   <li>Can directly notify a bound {@link TrafficMonitor} for seamless in-process rate tracking.</li>
 * </ul>
 * </p>
 */
public class AnomalyTrafficGenerator {

    public static final String SAFE_LOOPBACK_IP = "127.0.0.1";
    public static final int DEFAULT_TARGET_PORT = 54321;
    public static final double DEFAULT_PPS = 800.0;
    public static final int DEFAULT_PACKET_COUNT = 1000;
    public static final int DEFAULT_PAYLOAD_SIZE = 64;

    private final InetAddress loopbackAddress;
    private int targetPort;
    private double targetPps;
    private int packetCount;
    private int payloadSize;

    private TrafficMonitor attachedMonitor;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicInteger packetsSent = new AtomicInteger(0);
    private Thread workerThread;

    /**
     * Constructs an AnomalyTrafficGenerator with default loopback settings.
     */
    public AnomalyTrafficGenerator() {
        this(DEFAULT_TARGET_PORT, DEFAULT_PPS, DEFAULT_PACKET_COUNT);
    }

    /**
     * Constructs an AnomalyTrafficGenerator with custom loopback port, rate, and packet count.
     *
     * @param targetPort  local UDP port (1024 - 65535)
     * @param targetPps   target packet transmission rate in packets-per-second
     * @param packetCount total number of packets to transmit
     */
    public AnomalyTrafficGenerator(int targetPort, double targetPps, int packetCount) {
        try {
            this.loopbackAddress = InetAddress.getByName(SAFE_LOOPBACK_IP);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to resolve loopback address: " + SAFE_LOOPBACK_IP, e);
        }
        this.targetPort = (targetPort > 0 && targetPort <= 65535) ? targetPort : DEFAULT_TARGET_PORT;
        this.targetPps = Math.max(1.0, targetPps);
        this.packetCount = Math.max(1, packetCount);
        this.payloadSize = DEFAULT_PAYLOAD_SIZE;
    }

    /**
     * Attaches a {@link TrafficMonitor} to register generated packets directly.
     *
     * @param monitor traffic monitor instance
     * @return this instance for fluent chaining
     */
    public AnomalyTrafficGenerator attachMonitor(TrafficMonitor monitor) {
        this.attachedMonitor = monitor;
        return this;
    }

    /**
     * Starts generating synthetic anomaly traffic asynchronously.
     */
    public synchronized void start() {
        if (running.get()) {
            return;
        }
        running.set(true);
        packetsSent.set(0);

        workerThread = new Thread(() -> runGeneration(this.packetCount, this.targetPps), "AnomalyTrafficGenerator-Thread");
        workerThread.setDaemon(true);
        workerThread.start();
    }

    /**
     * Stops traffic generation immediately and waits for worker thread to finish.
     */
    public synchronized void stop() {
        running.set(false);
        if (workerThread != null) {
            workerThread.interrupt();
            try {
                workerThread.join(2000);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
            workerThread = null;
        }
    }

    /**
     * Synchronously generates the specified count of packets at the given rate.
     *
     * @param count total packets to send
     * @param pps   target packets per second
     * @return total packets successfully sent
     */
    public int generateTraffic(int count, double pps) {
        running.set(true);
        packetsSent.set(0);
        try {
            runGeneration(count, pps);
        } finally {
            running.set(false);
        }
        return packetsSent.get();
    }

    private void runGeneration(int count, double pps) {
        byte[] payload = new byte[payloadSize];
        new Random().nextBytes(payload);

        long intervalNanos = (long) (1_000_000_000.0 / Math.max(1.0, pps));

        DatagramSocket socket = null;
        try {
            socket = new DatagramSocket();
            DatagramPacket packet = new DatagramPacket(payload, payload.length, loopbackAddress, targetPort);

            long nextSendTime = System.nanoTime();

            for (int i = 0; i < count && running.get(); i++) {
                // Send safe loopback UDP packet
                try {
                    socket.send(packet);
                } catch (IOException e) {
                    // Socket errors on loopback do not compromise safety
                }

                // Register with attached monitor if present
                if (attachedMonitor != null) {
                    attachedMonitor.recordPacket();
                }

                packetsSent.incrementAndGet();

                // Rate limiting via high-resolution timing
                nextSendTime += intervalNanos;
                long sleepNanos = nextSendTime - System.nanoTime();
                if (sleepNanos > 2_000_000) { // Sleep if more than 2ms
                    try {
                        Thread.sleep(sleepNanos / 1_000_000, (int) (sleepNanos % 1_000_000));
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                } else if (sleepNanos > 0) {
                    // Short busy spin for sub-millisecond precision
                    while (System.nanoTime() < nextSendTime) {
                        Thread.onSpinWait();
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("[-] Warning in AnomalyTrafficGenerator: " + e.getMessage());
        } finally {
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
        }
    }

    public boolean isRunning() {
        return running.get();
    }

    public int getPacketsSent() {
        return packetsSent.get();
    }

    public int getTargetPort() {
        return targetPort;
    }

    public void setTargetPort(int targetPort) {
        this.targetPort = targetPort;
    }

    public double getTargetPps() {
        return targetPps;
    }

    public void setTargetPps(double targetPps) {
        this.targetPps = Math.max(1.0, targetPps);
    }

    public int getPacketCount() {
        return packetCount;
    }

    public void setPacketCount(int packetCount) {
        this.packetCount = Math.max(1, packetCount);
    }

    public int getPayloadSize() {
        return payloadSize;
    }

    public void setPayloadSize(int payloadSize) {
        this.payloadSize = Math.max(16, payloadSize);
    }

    public TrafficMonitor getAttachedMonitor() {
        return attachedMonitor;
    }
}
