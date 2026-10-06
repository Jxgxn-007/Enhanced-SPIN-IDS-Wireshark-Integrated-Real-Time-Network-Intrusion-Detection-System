package com.spinids;

import com.spinids.generator.AnomalyTrafficGenerator;
import com.spinids.trigger.AnomalyTrigger;
import com.spinids.trigger.TrafficMonitor;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for TrafficMonitor, AnomalyTrigger, and AnomalyTrafficGenerator.
 */
public class AnomalyTriggerTest {

    @Test
    public void testDefaultThreshold() {
        TrafficMonitor monitor = new TrafficMonitor();
        assertEquals(500.0, monitor.getThreshold(), 1e-6);

        monitor.setThreshold(750.0);
        assertEquals(750.0, monitor.getThreshold(), 1e-6);
    }

    @Test
    public void testTrafficMonitorNormalRate() {
        TrafficMonitor monitor = new TrafficMonitor(500.0);
        monitor.setManualRate(42.0);

        assertEquals(42.0, monitor.getCurrentPacketRate(), 1e-6);
        assertFalse(monitor.isThresholdExceeded());
        assertFalse(monitor.isAnomalous());
    }

    @Test
    public void testTrafficMonitorAnomalousRate() {
        TrafficMonitor monitor = new TrafficMonitor(500.0);
        monitor.setManualRate(820.0);

        assertEquals(820.0, monitor.getCurrentPacketRate(), 1e-6);
        assertTrue(monitor.isThresholdExceeded());
        assertTrue(monitor.isAnomalous());
    }

    @Test
    public void testAnomalyTriggerNormalEvaluation() {
        TrafficMonitor monitor = new TrafficMonitor(500.0);
        AnomalyTrigger trigger = new AnomalyTrigger(monitor, 10_000L);

        monitor.setManualRate(150.0);
        boolean fired = trigger.evaluate();

        assertFalse(fired);
        assertEquals(0, trigger.getTriggerCount());
    }

    @Test
    public void testAnomalyTriggerThresholdExceededEvaluation() {
        TrafficMonitor monitor = new TrafficMonitor(500.0);
        AnomalyTrigger trigger = new AnomalyTrigger(monitor, 10_000L);

        AtomicBoolean callbackFired = new AtomicBoolean(false);
        trigger.addListener((rate, threshold) -> {
            callbackFired.set(true);
            assertEquals(820.0, rate, 1e-6);
            assertEquals(500.0, threshold, 1e-6);
        });

        monitor.setManualRate(820.0);
        boolean fired = trigger.evaluate();

        assertTrue(fired);
        assertTrue(callbackFired.get());
        assertEquals(1, trigger.getTriggerCount());
    }

    @Test
    public void testAnomalyTriggerCooldownEnforcement() {
        TrafficMonitor monitor = new TrafficMonitor(500.0);
        // 10 second cooldown
        AnomalyTrigger trigger = new AnomalyTrigger(monitor, 10_000L);

        monitor.setManualRate(600.0);

        // First trigger should fire
        boolean firstFired = trigger.evaluate();
        assertTrue(firstFired);
        assertEquals(1, trigger.getTriggerCount());

        // Second evaluation immediately afterwards should be suppressed by cooldown
        boolean secondFired = trigger.evaluate();
        assertFalse(secondFired);
        assertEquals(1, trigger.getTriggerCount());
    }

    @Test
    public void testAnomalyTriggerCooldownExpires() throws InterruptedException {
        TrafficMonitor monitor = new TrafficMonitor(500.0);
        // Very short cooldown for testing: 50ms
        AnomalyTrigger trigger = new AnomalyTrigger(monitor, 50L);

        monitor.setManualRate(600.0);

        boolean firstFired = trigger.evaluate();
        assertTrue(firstFired);
        assertEquals(1, trigger.getTriggerCount());

        // Wait for cooldown to expire
        Thread.sleep(70L);

        boolean secondFired = trigger.evaluate();
        assertTrue(secondFired);
        assertEquals(2, trigger.getTriggerCount());
    }

    @Test
    public void testAnomalyTrafficGeneratorSafeLoopback() {
        AnomalyTrafficGenerator generator = new AnomalyTrafficGenerator(54321, 500.0, 20);

        assertEquals(AnomalyTrafficGenerator.SAFE_LOOPBACK_IP, "127.0.0.1");
        assertEquals(54321, generator.getTargetPort());

        int sent = generator.generateTraffic(20, 1000.0);
        assertEquals(20, sent);
        assertEquals(20, generator.getPacketsSent());
        assertFalse(generator.isRunning());
    }

    @Test
    public void testAnomalyTrafficGeneratorMonitorIntegration() {
        TrafficMonitor monitor = new TrafficMonitor(20.0);
        AnomalyTrafficGenerator generator = new AnomalyTrafficGenerator(54322, 500.0, 25);
        generator.attachMonitor(monitor);

        assertSame(monitor, generator.getAttachedMonitor());

        generator.generateTraffic(25, 1000.0);
        assertEquals(25, generator.getPacketsSent());

        // Monitor should have recorded 25 packets in rolling window
        assertTrue(monitor.getCurrentPacketRate() >= 20.0);
        assertTrue(monitor.isAnomalous());
    }

    @Test
    public void testAnomalyTriggerListenerRegistration() {
        TrafficMonitor monitor = new TrafficMonitor(500.0);
        AnomalyTrigger trigger = new AnomalyTrigger(monitor, 10_000L);

        AtomicInteger callCount = new AtomicInteger(0);
        AnomalyTrigger.TriggerListener listener = (rate, threshold) -> callCount.incrementAndGet();

        trigger.addListener(listener);
        trigger.evaluate(600.0);
        assertEquals(1, callCount.get());

        trigger.removeListener(listener);
        trigger.reset();
        trigger.evaluate(700.0);
        assertEquals(1, callCount.get()); // Did not increment because removed
    }
}
