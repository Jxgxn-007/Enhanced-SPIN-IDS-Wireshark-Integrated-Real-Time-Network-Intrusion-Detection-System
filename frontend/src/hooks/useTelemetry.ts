import { useState, useEffect, useRef, useCallback } from 'react';
import type { DetectionItem, TelemetryPoint, PipelineSseEvent } from '../types/api';
import { api } from '../services/api';

export type StreamStatus = 'LIVE' | 'RECONNECTING' | 'DISCONNECTED';

const MAX_CHART_POINTS = 30;

export function useTelemetry() {
  const [streamStatus, setStreamStatus] = useState<StreamStatus>('DISCONNECTED');
  const [currentPps, setCurrentPps] = useState<number>(0);
  const [threshold, setThreshold] = useState<number>(500);
  const [isAnomalous, setIsAnomalous] = useState<boolean>(false);
  const [monitoringMode, setMonitoringMode] = useState<'REAL_INTERFACE' | 'SIMULATION'>('REAL_INTERFACE');
  const [captureInProgress, setCaptureInProgress] = useState<boolean>(false);
  const [cooldownActive, setCooldownActive] = useState<boolean>(false);
  const [selectedInterface, setSelectedInterface] = useState<string>('');
  const [interfaceDescription, setInterfaceDescription] = useState<string>('');
  const [telemetryHistory, setTelemetryHistory] = useState<TelemetryPoint[]>([]);
  const [latestDetection, setLatestDetection] = useState<DetectionItem | null>(null);
  const [lastPipelineEvent, setLastPipelineEvent] = useState<PipelineSseEvent | null>(null);

  const eventSourceRef = useRef<EventSource | null>(null);
  const pollIntervalRef = useRef<number | null>(null);

  const appendPoint = useCallback((pps: number, thresh: number, anomalous: boolean) => {
    const timeStr = new Date().toLocaleTimeString('en-GB', { hour12: false });
    setTelemetryHistory((prev) => {
      const next = [...prev, { time: timeStr, pps, threshold: thresh, anomalous }];
      if (next.length > MAX_CHART_POINTS) {
        return next.slice(next.length - MAX_CHART_POINTS);
      }
      return next;
    });
  }, []);

  // Connect SSE
  useEffect(() => {
    let isMounted = true;

    function connectSSE() {
      try {
        const sse = new EventSource('/api/stream');
        eventSourceRef.current = sse;

        sse.onopen = () => {
          if (isMounted) {
            setStreamStatus('LIVE');
          }
        };

        sse.addEventListener('connected', () => {
          if (isMounted) setStreamStatus('LIVE');
        });

        sse.addEventListener('rate', (e) => {
          if (!isMounted) return;
          try {
            const data = JSON.parse(e.data);
            const pps = typeof data.pps === 'number' ? Math.round(data.pps) : 0;
            const thresh = typeof data.threshold === 'number' ? data.threshold : 500;
            const anomalous = !!data.anomalous;

            setCurrentPps(pps);
            setThreshold(thresh);
            setIsAnomalous(anomalous);
            if (data.monitoringMode) setMonitoringMode(data.monitoringMode);
            if (typeof data.captureInProgress === 'boolean') setCaptureInProgress(data.captureInProgress);
            if (typeof data.cooldownActive === 'boolean') setCooldownActive(data.cooldownActive);
            if (data.selectedInterface) setSelectedInterface(data.selectedInterface);
            if (data.interfaceDescription) setInterfaceDescription(data.interfaceDescription);

            appendPoint(pps, thresh, anomalous);
          } catch {
            // ignore
          }
        });

        sse.addEventListener('anomaly', (e) => {
          if (!isMounted) return;
          try {
            const ev: PipelineSseEvent = JSON.parse(e.data);
            setLastPipelineEvent(ev);
            setIsAnomalous(true);
            setCaptureInProgress(true);
          } catch {
            // ignore
          }
        });

        sse.addEventListener('capture_start', (e) => {
          if (!isMounted) return;
          try {
            const ev: PipelineSseEvent = JSON.parse(e.data);
            setLastPipelineEvent(ev);
            setCaptureInProgress(true);
          } catch {
            // ignore
          }
        });

        sse.addEventListener('capture_complete', (e) => {
          if (!isMounted) return;
          try {
            const ev: PipelineSseEvent = JSON.parse(e.data);
            setLastPipelineEvent(ev);
            setCaptureInProgress(false);
          } catch {
            // ignore
          }
        });

        sse.addEventListener('detection', (e) => {
          if (!isMounted) return;
          try {
            const d = JSON.parse(e.data);
            setLatestDetection(d);
          } catch {
            // ignore
          }
        });

        sse.onerror = () => {
          if (isMounted) {
            setStreamStatus('RECONNECTING');
          }
        };
      } catch {
        if (isMounted) setStreamStatus('DISCONNECTED');
      }
    }

    connectSSE();

    // Fallback polling if SSE is disconnected
    pollIntervalRef.current = window.setInterval(async () => {
      if (eventSourceRef.current?.readyState !== EventSource.OPEN) {
        try {
          const rateData = await api.getTelemetryRate();
          if (isMounted) {
            const pps = Math.round(rateData.pps);
            setCurrentPps(pps);
            setThreshold(rateData.threshold);
            setIsAnomalous(rateData.anomalous);
            if (rateData.monitoringMode) setMonitoringMode(rateData.monitoringMode);
            if (typeof rateData.captureInProgress === 'boolean') setCaptureInProgress(rateData.captureInProgress);
            if (typeof rateData.cooldownActive === 'boolean') setCooldownActive(rateData.cooldownActive);
            if (rateData.selectedInterface) setSelectedInterface(rateData.selectedInterface);
            if (rateData.interfaceDescription) setInterfaceDescription(rateData.interfaceDescription);

            appendPoint(pps, rateData.threshold, rateData.anomalous);
          }
        } catch {
          if (isMounted) setStreamStatus('DISCONNECTED');
        }
      }
    }, 2000);

    return () => {
      isMounted = false;
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
      }
    };
  }, [appendPoint]);

  return {
    streamStatus,
    currentPps,
    threshold,
    isAnomalous,
    monitoringMode,
    captureInProgress,
    cooldownActive,
    selectedInterface,
    interfaceDescription,
    telemetryHistory,
    latestDetection,
    lastPipelineEvent,
  };
}
