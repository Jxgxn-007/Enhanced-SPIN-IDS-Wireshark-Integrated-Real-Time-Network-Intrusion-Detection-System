import React, { useState, useEffect, useCallback } from 'react';
import { Sidebar, type PageId } from './components/layout/Sidebar';
import { Topbar } from './components/layout/Topbar';
import { Dashboard } from './pages/Dashboard';
import { LiveMonitor } from './pages/LiveMonitor';
import { Detections } from './pages/Detections';
import { PacketWindows } from './pages/PacketWindows';
import { PcapCaptures } from './pages/PcapCaptures';
import { ActivityLogs } from './pages/ActivityLogs';
import { System } from './pages/System';
import { useEngine } from './hooks/useEngine';
import { useTelemetry } from './hooks/useTelemetry';
import { api } from './services/api';
import type { DetectionItem } from './types/api';
import { AlertCircle, CheckCircle2, Info, X } from 'lucide-react';

interface Toast {
  id: number;
  message: string;
  type: 'success' | 'error' | 'warning' | 'info';
}

export const App: React.FC = () => {
  const [activePage, setActivePage] = useState<PageId>('dashboard');
  const [detections, setDetections] = useState<DetectionItem[]>([]);
  const [toasts, setToasts] = useState<Toast[]>([]);

  const {
    status,
    interfaces,
    selectedInterface,
    actionLoading,
    error: engineError,
    startEngine,
    stopEngine,
    simulateAnomaly,
    selectInterface,
    refreshStatus,
    refreshInterfaces,
  } = useEngine();

  const {
    streamStatus,
    currentPps,
    threshold,
    isAnomalous,
    monitoringMode,
    captureInProgress,
    cooldownActive,
    telemetryHistory,
    latestDetection,
    lastPipelineEvent,
  } = useTelemetry();

  const toastCounterRef = React.useRef(0);

  const showToast = useCallback(
    (message: string, type: 'success' | 'error' | 'warning' | 'info' = 'info') => {
      const id = Date.now() + ++toastCounterRef.current;
      setToasts((prev) => [...prev, { id, message, type }]);
      setTimeout(() => {
        setToasts((prev) => prev.filter((t) => t.id !== id));
      }, 4000);
    },
    []
  );

  const fetchDetections = useCallback(async () => {
    try {
      const data = await api.getDetections('ALL', 50);
      setDetections(data);
    } catch {
      // Ignored if offline
    }
  }, []);

  useEffect(() => {
    fetchDetections();
  }, [fetchDetections]);

  // When a live detection event arrives from SSE stream
  useEffect(() => {
    if (latestDetection) {
      setDetections((prev) => {
        const exists = prev.some(
          (d) =>
            d.windowIndex === latestDetection.windowIndex &&
            d.timestamp === latestDetection.timestamp
        );
        if (exists) return prev;
        return [latestDetection, ...prev];
      });

      const isMal = latestDetection.prediction === 'MALICIOUS';
      showToast(
        `CNN Alert: Window ${latestDetection.windowIndex} classified as ${latestDetection.prediction} (${(
          latestDetection.confidence * 100
        ).toFixed(1)}%)`,
        isMal ? 'warning' : 'info'
      );
    }
  }, [latestDetection, showToast]);

  // When an anomaly or capture event arrives from SSE stream
  useEffect(() => {
    if (lastPipelineEvent) {
      if (lastPipelineEvent.type === 'anomaly') {
        showToast(
          `Rate threshold exceeded (${lastPipelineEvent.rate?.toFixed(0)} PPS > ${lastPipelineEvent.threshold} PPS)! Automatic 5s bounded PCAP capture triggered.`,
          'warning'
        );
      } else if (lastPipelineEvent.type === 'capture_complete') {
        showToast(
          `PCAP capture finished: ${lastPipelineEvent.pcapFile} (${lastPipelineEvent.packetCount} pkts). Executing CNN inference...`,
          'success'
        );
        fetchDetections();
      }
    }
  }, [lastPipelineEvent, showToast, fetchDetections]);

  const handleStartEngine = async () => {
    try {
      await startEngine();
      showToast(
        `Live network monitoring active on ${status?.interfaceDescription || selectedInterface || 'selected adapter'}`,
        'success'
      );
    } catch (err) {
      showToast((err as Error).message || 'Failed to start engine', 'error');
    }
  };

  const handleStopEngine = async () => {
    try {
      await stopEngine();
      showToast('Live traffic monitoring paused', 'info');
    } catch (err) {
      showToast((err as Error).message || 'Failed to stop engine', 'error');
    }
  };

  const handleSelectInterface = async (name: string) => {
    try {
      const resp = await selectInterface(name);
      showToast(`Selected interface: ${resp.description || resp.selectedInterface}`, 'info');
      return resp;
    } catch (err) {
      showToast((err as Error).message || 'Failed to switch network interface', 'error');
      throw err;
    }
  };

  const handleSimulate = async (rate?: number, pkts?: number) => {
    try {
      showToast('Executing controlled loopback burst (127.0.0.1)...', 'info');
      const resp = await simulateAnomaly({ burstRate: rate, burstPackets: pkts });
      await fetchDetections();
      if (resp) {
        showToast(
          `Burst complete: ${resp.capturedPackets} packets captured, ${resp.extractedWindows} windows analyzed.`,
          'success'
        );
      }
      return resp;
    } catch (err) {
      showToast((err as Error).message || 'Simulation burst failed', 'error');
      throw err;
    }
  };

  const activeInterfaceName = status?.interfaceDescription || selectedInterface;

  const renderActivePage = () => {
    switch (activePage) {
      case 'dashboard':
        return (
          <Dashboard
            status={status}
            currentPps={currentPps}
            threshold={threshold}
            isAnomalous={isAnomalous}
            monitoringMode={monitoringMode}
            captureInProgress={captureInProgress}
            cooldownActive={cooldownActive}
            telemetryHistory={telemetryHistory}
            detections={detections}
            onNavigate={(p) => setActivePage(p as PageId)}
          />
        );
      case 'live-monitor':
        return (
          <LiveMonitor
            status={status}
            interfaces={interfaces}
            selectedInterface={selectedInterface}
            onSelectInterface={handleSelectInterface}
            onRefreshInterfaces={refreshInterfaces}
            currentPps={currentPps}
            threshold={threshold}
            isAnomalous={isAnomalous}
            monitoringMode={monitoringMode}
            captureInProgress={captureInProgress}
            cooldownActive={cooldownActive}
            telemetryHistory={telemetryHistory}
            actionLoading={actionLoading}
            onStartEngine={handleStartEngine}
            onStopEngine={handleStopEngine}
            onSimulateAnomaly={handleSimulate}
          />
        );
      case 'detections':
        return <Detections detections={detections} onRefresh={fetchDetections} />;
      case 'packet-windows':
        return <PacketWindows />;
      case 'pcap-captures':
        return <PcapCaptures />;
      case 'activity-logs':
        return <ActivityLogs />;
      case 'system':
        return <System status={status} onRefresh={refreshStatus} />;
      default:
        return null;
    }
  };

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-slate-50">
      {/* Fixed Left Navigation Sidebar */}
      <Sidebar
        activePage={activePage}
        onSelectPage={setActivePage}
        engineRunning={Boolean(status?.engineState === 'RUNNING' || status?.engineRunning)}
        currentPps={currentPps}
      />

      {/* Main View Area */}
      <div className="flex-1 flex flex-col h-full overflow-hidden">
        <Topbar
          engineRunning={Boolean(status?.engineState === 'RUNNING' || status?.engineRunning)}
          actionLoading={actionLoading}
          streamStatus={streamStatus}
          currentPps={currentPps}
          activeInterface={activeInterfaceName}
          monitoringMode={monitoringMode}
          onStartEngine={handleStartEngine}
          onStopEngine={handleStopEngine}
          onSimulateAnomaly={() => handleSimulate()}
          onRefresh={() => {
            refreshStatus();
            refreshInterfaces();
            fetchDetections();
            showToast('Refreshed telemetry, interfaces, and detection state', 'info');
          }}
        />

        {/* Global connection error warning if backend unreachable */}
        {engineError && (
          <div className="bg-rose-50 border-b border-rose-200 px-6 py-2.5 text-xs text-rose-800 flex items-center justify-between font-mono">
            <div className="flex items-center gap-2">
              <AlertCircle className="w-4 h-4 text-rose-600 shrink-0" />
              <span>
                Backend warning: {engineError}. Ensure <code>com.spinids.api.SpinServer</code> is running on port 8080.
              </span>
            </div>
            <button
              onClick={refreshStatus}
              className="underline font-bold text-rose-900 hover:text-rose-950"
            >
              Retry
            </button>
          </div>
        )}

        {/* Dynamic Page Container */}
        <main className="flex-1 flex flex-col overflow-hidden">{renderActivePage()}</main>
      </div>

      {/* Toast Notification Container */}
      <div className="fixed bottom-4 right-4 z-50 space-y-2 max-w-sm pointer-events-none">
        {toasts.map((t) => (
          <div
            key={t.id}
            className={`pointer-events-auto px-4 py-3 rounded-lg shadow-lg border text-xs font-mono flex items-start gap-2.5 transition-all ${
              t.type === 'error'
                ? 'bg-rose-900 text-rose-100 border-rose-700'
                : t.type === 'warning'
                ? 'bg-amber-900 text-amber-100 border-amber-700'
                : t.type === 'success'
                ? 'bg-slate-900 text-emerald-300 border-slate-700'
                : 'bg-slate-900 text-slate-100 border-slate-700'
            }`}
          >
            {t.type === 'success' && <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />}
            {t.type === 'error' && <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />}
            {t.type === 'warning' && <AlertCircle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />}
            {t.type === 'info' && <Info className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />}
            <span className="flex-1 leading-snug">{t.message}</span>
            <button
              onClick={() => setToasts((prev) => prev.filter((item) => item.id !== t.id))}
              className="text-slate-400 hover:text-white"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        ))}
      </div>
    </div>
  );
};
export default App;
