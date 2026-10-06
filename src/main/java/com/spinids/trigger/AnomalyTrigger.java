package com.spinids.trigger;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Evaluates packet rate telemetry from {@link TrafficMonitor} and triggers an anomaly event
 * when the configured threshold is exceeded, subject to a cooldown period.
 *
 * <p>In accordance with SPIN-IDS design guidelines, AnomalyTrigger does NOT classify
 * traffic as malicious; it strictly reports rate telemetry and triggers downstream
 * processing when anomalous traffic behavior is detected.</p>
 */
public class AnomalyTrigger {

    public static final long DEFAULT_COOLDOWN_MILLIS = 10_000L; // 10 seconds

    public interface TriggerListener {
        void onAnomalyTriggered(double rate, double threshold);
    }

    private final TrafficMonitor monitor;
    private volatile long cooldownMillis;
    private volatile long lastTriggerTimeMs = 0L;
    private volatile int triggerCount = 0;
    private final List<TriggerListener> listeners = new CopyOnWriteArrayList<>();

    /**
     * Constructs an AnomalyTrigger bound to the specified TrafficMonitor with default 10s cooldown.
     *
     * @param monitor the TrafficMonitor providing packet rate measurements
     */
    public AnomalyTrigger(TrafficMonitor monitor) {
        this(monitor, DEFAULT_COOLDOWN_MILLIS);
    }

    /**
     * Constructs an AnomalyTrigger bound to the specified TrafficMonitor and custom cooldown.
     *
     * @param monitor        the TrafficMonitor providing packet rate measurements
     * @param cooldownMillis minimum duration in milliseconds between triggered events
     */
    public AnomalyTrigger(TrafficMonitor monitor, long cooldownMillis) {
        if (monitor == null) {
            throw new IllegalArgumentException("TrafficMonitor cannot be null");
        }
        this.monitor = monitor;
        this.cooldownMillis = Math.max(0L, cooldownMillis);
    }

    /**
     * Evaluates current packet rate against the monitor's threshold.
     *
     * @return true if an anomaly trigger event fired; false otherwise
     */
    public boolean evaluate() {
        return evaluate(monitor.getCurrentPacketRate());
    }

    /**
     * Evaluates an explicit packet rate value against the monitor's threshold.
     *
     * @param currentRate packet rate in packets/sec
     * @return true if an anomaly trigger event fired; false if normal or suppressed by cooldown
     */
    public synchronized boolean evaluate(double currentRate) {
        double threshold = monitor.getThreshold();
        long now = System.currentTimeMillis();

        if (currentRate >= threshold) {
            long elapsedSinceLast = now - lastTriggerTimeMs;
            if (lastTriggerTimeMs > 0 && elapsedSinceLast < cooldownMillis) {
                long remainingMs = cooldownMillis - elapsedSinceLast;
                System.out.println(String.format(
                        "[*] Packet rate: %.1f packets/sec (threshold: %.1f)", currentRate, threshold));
                System.out.println(String.format(
                        "[*] Cooldown active (%.1fs remaining); suppressing duplicate trigger", remainingMs / 1000.0));
                return false;
            }

            // Fire anomaly trigger
            lastTriggerTimeMs = now;
            triggerCount++;

            System.out.println(String.format("[!] Packet rate threshold exceeded: %.0f packets/sec", currentRate));
            System.out.println("[!] ANOMALY TRIGGERED");

            for (TriggerListener listener : listeners) {
                try {
                    listener.onAnomalyTriggered(currentRate, threshold);
                } catch (Exception e) {
                    System.err.println("[-] Error notifying trigger listener: " + e.getMessage());
                }
            }
            return true;
        } else {
            System.out.println(String.format("[*] Packet rate: %.1f packets/sec", currentRate));
            System.out.println("[*] Status: NORMAL");
            return false;
        }
    }

    public void addListener(TriggerListener listener) {
        if (listener != null) {
            listeners.add(listener);
        }
    }

    public void removeListener(TriggerListener listener) {
        if (listener != null) {
            listeners.remove(listener);
        }
    }

    public TrafficMonitor getMonitor() {
        return monitor;
    }

    public long getCooldownMillis() {
        return cooldownMillis;
    }

    public void setCooldownMillis(long cooldownMillis) {
        this.cooldownMillis = Math.max(0L, cooldownMillis);
    }

    public long getLastTriggerTimeMs() {
        return lastTriggerTimeMs;
    }

    public int getTriggerCount() {
        return triggerCount;
    }

    /**
     * Resets trigger history and cooldown state.
     */
    public synchronized void reset() {
        lastTriggerTimeMs = 0L;
        triggerCount = 0;
    }
}
