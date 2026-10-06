import React, { useState } from 'react';
import {
  Play,
  Square,
  Zap,
  Cpu,
  Network,
  Radio,
  CheckCircle2,
  RefreshCw,
} from 'lucide-react';
import { PageContainer } from '../components/layout/PageContainer';
import { TrafficChart } from '../components/dashboard/TrafficChart';
import type { StatusResponse, TelemetryPoint, SimulationResponse, NetworkInterfaceDto } from '../types/api';

interface LiveMonitorProps {
  status: StatusResponse | null;
  interfaces: NetworkInterfaceDto[];
  selectedInterface: string;
  onSelectInterface: (name: string) => Promise<any>;
  onRefreshInterfaces: () => Promise<void>;
  currentPps: number;
  threshold: number;
  isAnomalous: boolean;
  monitoringMode?: 'REAL_INTERFACE' | 'SIMULATION';
  captureInProgress?: boolean;
  cooldownActive?: boolean;
  telemetryHistory: TelemetryPoint[];
  actionLoading: boolean;
  onStartEngine: () => Promise<void>;
  onStopEngine: () => Promise<void>;
  onSimulateAnomaly: (rate?: number, pkts?: number) => Promise<SimulationResponse | undefined>;
}

export const LiveMonitor: React.FC<LiveMonitorProps> = ({
  status,
  interfaces,
  selectedInterface,
  onSelectInterface,
  onRefreshInterfaces,
  currentPps,
  threshold,
  isAnomalous,
  monitoringMode = 'REAL_INTERFACE',
  captureInProgress = false,
  cooldownActive = false,
  telemetryHistory,
  actionLoading,
  onStartEngine,
  onStopEngine,
  onSimulateAnomaly,
}) => {
  const [burstRate, setBurstRate] = useState<number>(820);
  const [burstPackets, setBurstPackets] = useState<number>(50);
  const [simResult, setSimResult] = useState<SimulationResponse | null>(null);

  const engineRunning = status?.engineState === 'RUNNING' || status?.engineRunning;
  const currentNif = interfaces.find((i) => i.name === selectedInterface) || interfaces.find((i) => i.recommended) || interfaces[0];

  const handleSimulate = async () => {
    try {
      const resp = await onSimulateAnomaly(burstRate, burstPackets);
      if (resp) {
        setSimResult(resp);
      }
    } catch {
      // Handled in parent toast
    }
  };

  const handleInterfaceChange = async (e: React.ChangeEvent<HTMLSelectElement>) => {
    const newName = e.target.value;
    try {
      await onSelectInterface(newName);
    } catch {
      // Handled in parent toast
    }
  };

  return (
    <PageContainer
      title="Live Traffic Monitor"
      subtitle="Interactive physical network interface telemetry, automatic threshold-triggered capture, and controlled anomaly generation"
    >
      {/* Real-time Bounded Capture Progress Banner */}
      {captureInProgress && (
        <div className="bg-amber-500/15 border-2 border-amber-500 rounded-lg p-4 shadow-sm flex items-center justify-between text-amber-950 font-mono text-xs animate-pulse">
          <div className="flex items-center gap-3">
            <Radio className="w-5 h-5 text-amber-600 animate-spin" />
            <div>
              <span className="font-bold text-sm block">TRAFFIC ANOMALY DETECTED (&gt; {threshold} PPS)</span>
              <span>
                Automatic 5-second bounded PCAP capture active on{' '}
                <strong>{currentNif?.displayName || selectedInterface}</strong> (Cap: 5,000 packets)
              </span>
            </div>
          </div>
          <span className="px-2.5 py-1 rounded bg-amber-200 font-bold text-amber-900 border border-amber-300">
            CAPTURING PCAP...
          </span>
        </div>
      )}

      {/* Network Interface Selection & Control Console */}
      <div className="bg-white rounded-lg border border-slate-200 p-5 shadow-xs">
        <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-100">
          <div className="flex items-center gap-2">
            <Network className="w-4 h-4 text-blue-600" />
            <h3 className="text-sm font-bold text-slate-900 tracking-tight uppercase">
              Physical Network Interface Selection
            </h3>
          </div>
          <button
            onClick={onRefreshInterfaces}
            className="inline-flex items-center gap-1 text-xs text-slate-500 hover:text-slate-800 transition-colors"
            title="Rescan Network Adapters"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Rescan Adapters
          </button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Adapter Dropdown & Key Attributes */}
          <div className="lg:col-span-2 space-y-4 font-mono text-xs">
            <div>
              <label className="block text-slate-700 font-semibold mb-1 text-[11px] uppercase">
                Active Adapter / Capture Device:
              </label>
              <select
                value={selectedInterface}
                onChange={handleInterfaceChange}
                disabled={actionLoading}
                className="w-full px-3 py-2 rounded border border-slate-300 bg-white text-slate-900 font-semibold text-xs focus:ring-2 focus:ring-blue-500 focus:outline-none"
              >
                {interfaces.map((nif) => (
                  <option key={nif.name} value={nif.name}>
                    {nif.displayName} {nif.recommended ? ' ★ [RECOMMENDED]' : ''} {nif.loopback ? ' (Loopback)' : ''}
                  </option>
                ))}
              </select>
            </div>

            {currentNif && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 p-3.5 rounded bg-slate-50 border border-slate-200">
                <div>
                  <span className="text-[10px] text-slate-400 block uppercase">Hardware Description</span>
                  <span className="text-slate-900 font-semibold block truncate" title={currentNif.description}>
                    {currentNif.description}
                  </span>
                </div>

                <div>
                  <span className="text-[10px] text-slate-400 block uppercase">Assigned IPv4 Address</span>
                  <span className="text-blue-600 font-bold block">
                    {currentNif.ipv4Addresses.length > 0 ? currentNif.ipv4Addresses.join(', ') : 'No IPv4 (Link-Local)'}
                  </span>
                </div>

                <div>
                  <span className="text-[10px] text-slate-400 block uppercase">MAC Hardware Address</span>
                  <span className="text-slate-700 block">{currentNif.macAddress || 'Virtual / Loopback'}</span>
                </div>

                <div>
                  <span className="text-[10px] text-slate-400 block uppercase">Operational Link Status</span>
                  <span className="inline-flex items-center gap-1 font-bold text-emerald-700">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                    {currentNif.up ? 'ACTIVE & UP' : 'DOWN'}
                  </span>
                </div>
              </div>
            )}
          </div>

          {/* Quick Action Control & Mode Display */}
          <div className="p-4 rounded-lg bg-slate-900 text-white flex flex-col justify-between font-mono text-xs">
            <div>
              <span className="text-[10px] text-slate-400 block uppercase">Active Monitoring Mode</span>
              <span className="text-sm font-bold text-emerald-400 mt-0.5 block">
                {monitoringMode === 'REAL_INTERFACE' ? 'REAL NETWORK MONITORING' : 'CONTROLLED SIMULATION'}
              </span>
              <p className="text-[11px] text-slate-400 mt-2 leading-relaxed font-sans">
                {engineRunning
                  ? 'Passive Npcap packet capture running. Normal packet rate computed every 1000ms. If rate exceeds 500 PPS, a bounded 5s PCAP is automatically recorded.'
                  : 'Monitoring currently paused. Click Start Sniffing to begin passive packet inspection.'}
              </p>
            </div>

            <div className="pt-4 border-t border-slate-800 mt-4 flex items-center gap-2">
              {engineRunning ? (
                <button
                  onClick={onStopEngine}
                  disabled={actionLoading}
                  className="flex-1 py-2 rounded bg-rose-600 hover:bg-rose-700 text-white font-semibold flex items-center justify-center gap-2 transition-colors disabled:opacity-50"
                >
                  <Square className="w-3.5 h-3.5 fill-white" />
                  Halt Sniffing
                </button>
              ) : (
                <button
                  onClick={onStartEngine}
                  disabled={actionLoading}
                  className="flex-1 py-2 rounded bg-emerald-600 hover:bg-emerald-700 text-white font-semibold flex items-center justify-center gap-2 transition-colors disabled:opacity-50"
                >
                  <Play className="w-3.5 h-3.5 fill-white" />
                  Start Sniffing
                </button>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Real-time Status Metrics Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="p-4 rounded-lg bg-white border border-slate-200 shadow-xs font-mono">
          <span className="text-[11px] text-slate-500 block uppercase">Observed Ingestion Rate</span>
          <span className={`text-2xl font-bold block mt-1 ${isAnomalous ? 'text-rose-600 animate-pulse' : 'text-slate-900'}`}>
            {currentPps} PPS
          </span>
          <span className="text-[10px] text-slate-400">Rolling 1000ms window</span>
        </div>

        <div className="p-4 rounded-lg bg-white border border-slate-200 shadow-xs font-mono">
          <span className="text-[11px] text-slate-500 block uppercase">Anomaly Threshold</span>
          <span className="text-2xl font-bold text-blue-600 block mt-1">{threshold} PPS</span>
          <span className="text-[10px] text-slate-400">Auto-PCAP Trigger Limit</span>
        </div>

        <div className="p-4 rounded-lg bg-white border border-slate-200 shadow-xs font-mono">
          <span className="text-[11px] text-slate-500 block uppercase">Trigger State</span>
          <span
            className={`text-base font-bold block mt-1.5 ${
              isAnomalous ? 'text-rose-600 animate-pulse' : 'text-emerald-600'
            }`}
          >
            {isAnomalous ? 'TRIGGER ACTIVE' : 'NOMINAL'}
          </span>
          <span className="text-[10px] text-slate-400">
            {cooldownActive ? 'Cooldown active (10s suppress)' : 'Trigger armed'}
          </span>
        </div>

        <div className="p-4 rounded-lg bg-white border border-slate-200 shadow-xs font-mono">
          <span className="text-[11px] text-slate-500 block uppercase">Engine Operational State</span>
          <span
            className={`text-base font-bold block mt-1.5 ${
              engineRunning ? 'text-emerald-600' : 'text-slate-500'
            }`}
          >
            {engineRunning ? '● RUNNING' : '● STOPPED'}
          </span>
          <span className="text-[10px] text-slate-400 truncate block">
            {currentNif?.displayName.split(' ')[0] || 'Npcap'}
          </span>
        </div>
      </div>

      {/* Real-time Traffic Area Chart */}
      <TrafficChart
        data={telemetryHistory}
        currentPps={currentPps}
        threshold={threshold}
        isAnomalous={isAnomalous}
      />

      {/* Controlled Synthetic Burst Testing Console */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Burst Configuration */}
        <div className="bg-white rounded-lg border border-slate-200 p-5 shadow-xs">
          <div className="flex items-center gap-2 pb-3 mb-4 border-b border-slate-100">
            <Zap className="w-4 h-4 text-amber-500" />
            <h3 className="text-sm font-bold text-slate-900 tracking-tight">
              Controlled Anomaly Simulation (Loopback Test)
            </h3>
          </div>
          <p className="text-xs text-slate-500 mb-4 leading-relaxed font-mono">
            <strong>Diagnostic Mode:</strong> Confined strictly to localhost (127.0.0.1). Generates a controlled
            synthetic UDP datagram burst to verify threshold triggers and downstream ONNX CNN inference without
            requiring physical network activity.
          </p>

          <div className="space-y-4 text-xs font-mono">
            <div>
              <label className="block text-slate-700 font-semibold mb-1">
                Burst Packet Rate (PPS):
              </label>
              <div className="flex items-center gap-2">
                <input
                  type="range"
                  min="550"
                  max="1500"
                  step="50"
                  value={burstRate}
                  onChange={(e) => setBurstRate(Number(e.target.value))}
                  className="flex-1 accent-blue-600"
                />
                <span className="w-16 px-2 py-1 rounded bg-slate-100 border border-slate-200 text-center font-bold text-slate-900">
                  {burstRate}
                </span>
              </div>
              <span className="text-[11px] text-slate-400 mt-1 block">
                Exceeds configured 500 PPS threshold to trigger capture
              </span>
            </div>

            <div>
              <label className="block text-slate-700 font-semibold mb-1">
                Frame Batch Count (Packets):
              </label>
              <div className="flex items-center gap-2">
                <input
                  type="range"
                  min="20"
                  max="200"
                  step="10"
                  value={burstPackets}
                  onChange={(e) => setBurstPackets(Number(e.target.value))}
                  className="flex-1 accent-blue-600"
                />
                <span className="w-16 px-2 py-1 rounded bg-slate-100 border border-slate-200 text-center font-bold text-slate-900">
                  {burstPackets}
                </span>
              </div>
              <span className="text-[11px] text-slate-400 mt-1 block">
                Aggregates into ~{Math.ceil(burstPackets / 9)} sequential 9-packet windows
              </span>
            </div>

            <button
              onClick={handleSimulate}
              disabled={actionLoading}
              className="w-full py-2.5 rounded bg-blue-600 hover:bg-blue-700 text-white font-semibold flex items-center justify-center gap-2 transition-colors disabled:opacity-50"
            >
              <Zap className="w-3.5 h-3.5" />
              {actionLoading ? 'Executing Inference Pipeline...' : 'Fire Synthetic Burst'}
            </button>
          </div>
        </div>

        {/* Latest Execution Feedback */}
        <div className="bg-white rounded-lg border border-slate-200 p-5 shadow-xs flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-100">
              <div className="flex items-center gap-2">
                <Cpu className="w-4 h-4 text-blue-600" />
                <h3 className="text-sm font-bold text-slate-900 tracking-tight">
                  Pipeline Execution Log
                </h3>
              </div>
              {simResult && (
                <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 font-semibold">
                  BURST COMPLETED
                </span>
              )}
            </div>

            {simResult ? (
              <div className="space-y-3 font-mono text-xs">
                <div className="p-3 rounded bg-slate-50 border border-slate-200 space-y-1.5">
                  <div className="flex justify-between">
                    <span className="text-slate-500">PCAP Capture File:</span>
                    <span className="text-slate-900 font-semibold truncate max-w-[200px]">
                      {simResult.pcapFile}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Packets Dumped:</span>
                    <span className="text-slate-900 font-semibold">
                      {simResult.capturedPackets} frames
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Sequential Windows:</span>
                    <span className="text-blue-600 font-semibold">
                      {simResult.extractedWindows} tensors
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Anomaly Trigger Verdict:</span>
                    <span
                      className={`font-bold ${
                        simResult.anomalyTriggered ? 'text-rose-600' : 'text-emerald-600'
                      }`}
                    >
                      {simResult.anomalyTriggered ? 'THRESHOLD EXCEEDED (> 500 PPS)' : 'NORMAL'}
                    </span>
                  </div>
                </div>

                <div className="border border-slate-200 rounded p-2.5 max-h-36 overflow-y-auto space-y-1">
                  <div className="text-[11px] font-semibold text-slate-700 pb-1 border-b border-slate-100">
                    Inference Outcomes on Extracted Windows:
                  </div>
                  {simResult.detections.map((d) => (
                    <div
                      key={d.windowIndex}
                      className="flex items-center justify-between text-[11px] py-1 border-b border-slate-50 last:border-0"
                    >
                      <span>Win {String(d.windowIndex).padStart(2, '0')}</span>
                      <span
                        className={`font-bold px-1.5 py-0.2 rounded ${
                          d.prediction === 'MALICIOUS'
                            ? 'bg-rose-100 text-rose-700'
                            : 'bg-emerald-100 text-emerald-700'
                        }`}
                      >
                        {d.prediction}
                      </span>
                      <span className="text-slate-500">{(d.confidence * 100).toFixed(2)}%</span>
                      <span className="text-[10px] text-slate-400">
                        {d.confidence < 0.65 ? 'LOW CONF' : 'HIGH CONF'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="py-12 text-center text-xs text-slate-400 font-mono">
                No active burst run in this session. Click &quot;Fire Synthetic Burst&quot; to test the
                pipeline.
              </div>
            )}
          </div>

          <div className="pt-3 border-t border-slate-100 text-[11px] text-slate-400 font-mono flex items-center justify-between">
            <span>Safety: Loopback 127.0.0.1</span>
            <span>Target: Port 54321</span>
          </div>
        </div>
      </div>
    </PageContainer>
  );
};
