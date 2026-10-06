import React, { useState } from 'react';
import {
  Activity,
  Layers,
  ShieldAlert,
  Radio,
  Wifi,
  HardDrive,
  Cpu,
  AlertTriangle,
  Clock,
  CheckCircle2,
} from 'lucide-react';
import { PageContainer } from '../components/layout/PageContainer';
import { MetricCard } from '../components/dashboard/MetricCard';
import { TrafficChart } from '../components/dashboard/TrafficChart';
import { EnginePipeline } from '../components/dashboard/EnginePipeline';
import { DetectionActivity } from '../components/dashboard/DetectionActivity';
import { SystemStatus } from '../components/dashboard/SystemStatus';
import { WindowModal } from '../components/common/WindowModal';
import type { StatusResponse, DetectionItem, TelemetryPoint, WindowDetail } from '../types/api';
import { api } from '../services/api';

interface DashboardProps {
  status: StatusResponse | null;
  currentPps: number;
  threshold: number;
  isAnomalous: boolean;
  monitoringMode?: 'REAL_INTERFACE' | 'SIMULATION';
  captureInProgress?: boolean;
  cooldownActive?: boolean;
  telemetryHistory: TelemetryPoint[];
  detections: DetectionItem[];
  onNavigate: (page: string) => void;
}

export const Dashboard: React.FC<DashboardProps> = ({
  status,
  currentPps,
  threshold,
  isAnomalous,
  monitoringMode = 'REAL_INTERFACE',
  captureInProgress = false,
  cooldownActive = false,
  telemetryHistory,
  detections,
  onNavigate,
}) => {
  const [selectedWindow, setSelectedWindow] = useState<WindowDetail | null>(null);
  const [isModalOpen, setIsModalOpen] = useState<boolean>(false);

  const stats = status?.stats;
  const engineRunning = Boolean(status?.engineState === 'RUNNING' || status?.engineRunning);
  const modelReady = status?.subsystems?.onnxRuntime?.status === 'READY';
  const activeInterfaceName = status?.interfaceDescription || status?.selectedInterface || 'Wi-Fi / Ethernet Adapter';
  const lastPcap = status?.lastPcapFile || stats?.latestPcap || 'real_anomaly_capture_baseline.pcap';
  const latestDetection = detections.length > 0 ? detections[0] : null;

  const handleInspectDetection = async (item: DetectionItem) => {
    try {
      const detail = await api.getWindowDetail(item.windowIndex);
      setSelectedWindow(detail);
      setIsModalOpen(true);
    } catch {
      setSelectedWindow({
        windowIndex: item.windowIndex,
        flowId: item.flowKey,
        flowIndex: 1,
        label: item.prediction,
        packetCount: 9,
        packets: [],
        detection: item,
      });
      setIsModalOpen(true);
    }
  };

  return (
    <PageContainer
      title="Security Overview"
      subtitle="Real-time physical network interface monitoring, automatic bounded PCAP capture, and 2D-CNN threat detection"
      badge={
        isAnomalous ? (
          <span className="text-xs font-mono font-bold px-2.5 py-1 rounded bg-rose-100 text-rose-800 border border-rose-300 animate-pulse flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5" />
            TRAFFIC ANOMALY &gt; {threshold} PPS
          </span>
        ) : (
          <span className="text-xs font-mono font-semibold px-2.5 py-1 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 flex items-center gap-1.5">
            <CheckCircle2 className="w-3.5 h-3.5" />
            PASSIVE INGESTION NOMINAL
          </span>
        )
      }
    >
      {/* Active Capture Banner if threshold was crossed */}
      {captureInProgress && (
        <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-4 mb-2 flex items-center justify-between text-amber-900 font-mono text-xs animate-pulse">
          <div className="flex items-center gap-2.5">
            <Radio className="w-5 h-5 text-amber-600 animate-spin" />
            <div>
              <span className="font-bold text-sm block">TRAFFIC ANOMALY DETECTED — PCAP CAPTURE IN PROGRESS</span>
              <span className="text-amber-700 text-[11px]">
                Automatically writing 5-second bounded PCAP capture on {activeInterfaceName} (Cap: 5,000 packets)
              </span>
            </div>
          </div>
          <span className="px-2 py-1 rounded bg-amber-200/80 text-amber-900 font-bold text-[11px]">
            BOUNDED DUMP ACTIVE
          </span>
        </div>
      )}

      {/* Network Interface & Operational Parameters Status Bar */}
      <div className="bg-white rounded-lg border border-slate-200 p-3.5 shadow-xs flex flex-wrap items-center justify-between gap-4 font-mono text-xs">
        <div className="flex items-center gap-6 flex-wrap">
          <div className="flex items-center gap-2">
            <span className="text-slate-400 text-[11px]">NETWORK STATUS:</span>
            <span
              className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-bold ${
                engineRunning ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' : 'bg-slate-100 text-slate-600'
              }`}
            >
              ● {engineRunning ? 'MONITORING' : 'HALTED'}
            </span>
          </div>

          <div className="flex items-center gap-2">
            <Wifi className="w-3.5 h-3.5 text-blue-600" />
            <span className="text-slate-400 text-[11px]">INTERFACE:</span>
            <span className="font-bold text-slate-800 truncate max-w-[220px]" title={activeInterfaceName}>
              {activeInterfaceName}
            </span>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-slate-400 text-[11px]">MODE:</span>
            <span className="px-2 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200 font-semibold text-[11px]">
              {monitoringMode === 'REAL_INTERFACE' ? 'REAL INTERFACE' : 'CONTROLLED SIMULATION'}
            </span>
          </div>

          {cooldownActive && (
            <div className="flex items-center gap-1.5 text-amber-700">
              <Clock className="w-3.5 h-3.5 text-amber-600" />
              <span className="text-[11px] font-semibold">COOLDOWN ACTIVE (10s Suppress)</span>
            </div>
          )}
        </div>

        <div className="flex items-center gap-4 text-slate-500 text-[11px]">
          <span>Threshold: <strong className="text-slate-900">{threshold} PPS</strong></span>
          <span>Buffer: <strong className="text-slate-900">5s / 5K pkts</strong></span>
        </div>
      </div>

      {/* 4 Core Telemetry Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Current Rate"
          value={`${currentPps} packets/s`}
          subtitle={`Threshold: ${threshold} PPS`}
          icon={<Radio className="w-4 h-4" />}
          variant={isAnomalous ? 'danger' : 'default'}
        />
        <MetricCard
          title="Packets Captured"
          value={stats ? stats.totalPackets.toLocaleString() : '0'}
          subtitle={`Npcap on ${activeInterfaceName.split(' ')[0]}`}
          icon={<Activity className="w-4 h-4" />}
          variant="default"
        />
        <MetricCard
          title="Sequential Windows"
          value={stats ? stats.totalWindows.toLocaleString() : '0'}
          subtitle="9 frames / tensor window"
          icon={<Layers className="w-4 h-4" />}
          variant="default"
        />
        <MetricCard
          title="Detections (Malicious)"
          value={stats ? stats.maliciousWindows.toString() : '0'}
          subtitle="CNN tensor classifications"
          icon={<ShieldAlert className="w-4 h-4" />}
          variant={stats && stats.maliciousWindows > 0 ? 'danger' : 'success'}
        />
      </div>

      {/* Pipeline Summary Bar (Last PCAP & Last Inference) */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
        <div className="bg-white rounded-lg border border-slate-200 p-3 shadow-xs flex items-center justify-between">
          <div className="flex items-center gap-2.5 truncate">
            <HardDrive className="w-4 h-4 text-blue-600 shrink-0" />
            <div className="truncate">
              <span className="text-[10px] text-slate-400 block uppercase">Last Captured PCAP</span>
              <span className="font-bold text-slate-800 truncate block max-w-xs">{lastPcap}</span>
            </div>
          </div>
          <span className="text-[10px] px-2 py-0.5 rounded bg-slate-100 text-slate-600 shrink-0">
            {lastPcap.startsWith('real_anomaly') ? 'REAL INTERFACE' : 'SIMULATED'}
          </span>
        </div>

        <div className="bg-white rounded-lg border border-slate-200 p-3 shadow-xs flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <Cpu className="w-4 h-4 text-blue-600 shrink-0" />
            <div>
              <span className="text-[10px] text-slate-400 block uppercase">Last CNN Inference</span>
              <div className="flex items-center gap-2">
                <span
                  className={`font-bold ${
                    latestDetection?.prediction === 'MALICIOUS' ? 'text-rose-600' : 'text-emerald-600'
                  }`}
                >
                  {latestDetection ? latestDetection.prediction : 'NOMINAL'}
                </span>
                {latestDetection && (
                  <span className="text-slate-500 text-[11px]">
                    ({(latestDetection.confidence * 100).toFixed(1)}% Conf)
                  </span>
                )}
              </div>
            </div>
          </div>
          {latestDetection && latestDetection.confidence < 0.65 && (
            <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200">
              LOW CONFIDENCE
            </span>
          )}
        </div>
      </div>

      {/* Real-time Traffic Area Chart */}
      <TrafficChart
        data={telemetryHistory}
        currentPps={currentPps}
        threshold={threshold}
        isAnomalous={isAnomalous}
      />

      {/* 8-Stage Sequential Pipeline Visualizer */}
      <EnginePipeline
        currentPps={currentPps}
        threshold={threshold}
        isAnomalous={isAnomalous}
        engineRunning={engineRunning}
        modelReady={modelReady}
      />

      {/* Two-Column Row: Recent Inferences & Subsystems Health */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <DetectionActivity
          detections={detections}
          onViewAll={() => onNavigate('detections')}
          onSelectDetection={handleInspectDetection}
        />
        <SystemStatus status={status} />
      </div>

      {/* Modal Detail View */}
      <WindowModal
        windowDetail={selectedWindow}
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
      />
    </PageContainer>
  );
};
