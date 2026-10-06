import React from 'react';
import {
  Server,
  CheckCircle2,
  Cpu,
  Layers,
  Database,
  Network,
  ShieldCheck,
  RefreshCw,
} from 'lucide-react';
import { PageContainer } from '../components/layout/PageContainer';
import type { StatusResponse } from '../types/api';

interface SystemProps {
  status: StatusResponse | null;
  onRefresh: () => void;
}

export const System: React.FC<SystemProps> = ({ status, onRefresh }) => {
  const engineRunning = status?.engineState === 'RUNNING';
  const subsystems = status?.subsystems || {};

  const components = [
    {
      name: 'SPIN-IDS Engine Orchestrator',
      status: engineRunning ? 'Running' : 'Stopped',
      desc: 'Central coordination daemon managing packet ingestion, window partition, and alerting',
      icon: <Server className="w-4 h-4 text-blue-600" />,
      badge: engineRunning ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-slate-100 text-slate-700 border-slate-200',
    },
    {
      name: 'Traffic Monitor',
      status: engineRunning ? 'Running' : 'Stopped',
      desc: `1000ms rolling window rate tracking with threshold monitoring (currently ${status?.thresholdPps || 500} PPS)`,
      icon: <Network className="w-4 h-4 text-blue-600" />,
      badge: engineRunning ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-slate-100 text-slate-700 border-slate-200',
    },
    {
      name: 'Anomaly Trigger',
      status: 'Ready',
      desc: 'Cooldown-governed threshold detection trigger (10,000ms suppress duplicate window)',
      icon: <CheckCircle2 className="w-4 h-4 text-emerald-600" />,
      badge: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    },
    {
      name: 'PCAP Capture Subsystem',
      status: subsystems.captureRing?.status === 'READY' ? 'Ready' : 'Online',
      desc: 'Npcap v1.79 native driver integration for live promiscuous packet streaming',
      icon: <Database className="w-4 h-4 text-blue-600" />,
      badge: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    },
    {
      name: 'Packet Image Builder',
      status: 'Ready',
      desc: '9 sequential frames converted into 27×27 RGB image feature matrices with source IP masking',
      icon: <Layers className="w-4 h-4 text-blue-600" />,
      badge: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    },
    {
      name: 'ONNX CNN Inference Engine',
      status: subsystems.onnxRuntime?.status === 'READY' ? 'Ready' : 'Error',
      desc: 'Microsoft ONNX Runtime 1.18.0 executing 2D-CNN feature extraction on FP32 tensors',
      icon: <Cpu className="w-4 h-4 text-blue-600" />,
      badge: subsystems.onnxRuntime?.status === 'READY' ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-rose-50 text-rose-700 border-rose-200',
    },
    {
      name: 'REST & SSE API Server',
      status: 'Running',
      desc: 'Embedded JDK 17 HTTP Server delivering REST telemetry endpoints and Server-Sent Events',
      icon: <ShieldCheck className="w-4 h-4 text-emerald-600" />,
      badge: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    },
  ];

  return (
    <PageContainer
      title="System Architecture & Diagnostics"
      subtitle="Subsystem component registry, model specifications, and execution environment parameters"
      actions={
        <button
          onClick={onRefresh}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-white border border-slate-200 text-xs font-semibold text-slate-700 hover:bg-slate-50 transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Poll Status
        </button>
      }
    >
      {/* Component Registry */}
      <div className="bg-white rounded-lg border border-slate-200 shadow-xs overflow-hidden mb-6">
        <div className="p-4 border-b border-slate-200 bg-slate-50 flex items-center justify-between">
          <h3 className="text-sm font-bold text-slate-900 tracking-tight">
            Component Subsystem Status
          </h3>
          <span className="text-xs font-mono text-slate-500">
            Runtime: Java 17 • Host: localhost:8080
          </span>
        </div>

        <div className="divide-y divide-slate-100">
          {components.map((c, i) => (
            <div key={i} className="p-4 flex items-start justify-between gap-4">
              <div className="flex items-start gap-3">
                <div className="p-2 rounded bg-slate-50 border border-slate-200 shrink-0 mt-0.5">
                  {c.icon}
                </div>
                <div>
                  <h4 className="text-xs font-bold text-slate-900">{c.name}</h4>
                  <p className="text-xs text-slate-500 mt-0.5 leading-relaxed">{c.desc}</p>
                </div>
              </div>

              <span
                className={`text-[11px] font-mono font-bold px-2.5 py-1 rounded border shrink-0 ${c.badge}`}
              >
                ● {c.status}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Model & Specifications Matrix */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-white rounded-lg border border-slate-200 p-5 shadow-xs">
          <h3 className="text-sm font-bold text-slate-900 pb-3 mb-4 border-b border-slate-100">
            Model Specifications &amp; Hyperparameters
          </h3>
          <div className="space-y-3 text-xs font-mono text-slate-600">
            <div className="flex justify-between p-2 rounded bg-slate-50">
              <span className="text-slate-500">Model Name:</span>
              <span className="text-slate-900 font-bold">SPIN-IDS CNN / ONNX</span>
            </div>
            <div className="flex justify-between p-2 rounded bg-slate-50">
              <span className="text-slate-500">Model File:</span>
              <span className="text-slate-900 font-bold truncate max-w-[200px]">
                ml/models/spin_ids_cnn.onnx
              </span>
            </div>
            <div className="flex justify-between p-2 rounded bg-slate-50">
              <span className="text-slate-500">Input Image Size:</span>
              <span className="text-slate-900 font-bold">27 × 27 RGB</span>
            </div>
            <div className="flex justify-between p-2 rounded bg-slate-50">
              <span className="text-slate-500">Tensor Input Format:</span>
              <span className="text-slate-900 font-bold">[1, 27, 27, 3] FP32</span>
            </div>
            <div className="flex justify-between p-2 rounded bg-slate-50">
              <span className="text-slate-500">Classification Classes:</span>
              <span className="text-slate-900 font-bold">NORMAL, MALICIOUS</span>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg border border-slate-200 p-5 shadow-xs">
          <h3 className="text-sm font-bold text-slate-900 pb-3 mb-4 border-b border-slate-100">
            Pipeline Ingestion Parameters
          </h3>
          <div className="space-y-3 text-xs font-mono text-slate-600">
            <div className="flex justify-between p-2 rounded bg-slate-50">
              <span className="text-slate-500">Rate Anomaly Threshold:</span>
              <span className="text-blue-600 font-bold">{status?.thresholdPps || 500} PPS</span>
            </div>
            <div className="flex justify-between p-2 rounded bg-slate-50">
              <span className="text-slate-500">Trigger Cooldown:</span>
              <span className="text-slate-900 font-bold">10,000 ms</span>
            </div>
            <div className="flex justify-between p-2 rounded bg-slate-50">
              <span className="text-slate-500">Sliding Window Capacity:</span>
              <span className="text-slate-900 font-bold">9 consecutive packets</span>
            </div>
            <div className="flex justify-between p-2 rounded bg-slate-50">
              <span className="text-slate-500">Packet Patch Dimension:</span>
              <span className="text-slate-900 font-bold">9 × 9 pixels (243 bytes)</span>
            </div>
            <div className="flex justify-between p-2 rounded bg-slate-50">
              <span className="text-slate-500">IP Masking:</span>
              <span className="text-emerald-700 font-bold">Enabled (Prevents IP memorization)</span>
            </div>
          </div>
        </div>
      </div>
    </PageContainer>
  );
};
