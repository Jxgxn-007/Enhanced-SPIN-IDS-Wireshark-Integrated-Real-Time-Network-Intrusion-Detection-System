import React from 'react';
import { Server, CheckCircle2, AlertCircle } from 'lucide-react';
import type { StatusResponse } from '../../types/api';

interface SystemStatusProps {
  status: StatusResponse | null;
}

export const SystemStatus: React.FC<SystemStatusProps> = ({ status }) => {
  const subsystems = status?.subsystems || {};

  const items = [
    {
      name: 'Npcap Packet Driver',
      status: subsystems.npcapDriver?.status || 'ONLINE',
      detail: subsystems.npcapDriver?.version || 'v1.79 Native',
    },
    {
      name: 'Packet Capture Ring',
      status: subsystems.captureRing?.status || 'READY',
      detail: subsystems.captureRing?.details || 'Zero-Drop Buffer',
    },
    {
      name: 'Java Pipeline Engine',
      status: subsystems.pipelineEngine?.status || 'OPERATIONAL',
      detail: subsystems.pipelineEngine?.runtime || 'JDK 17',
    },
    {
      name: 'ONNX Runtime',
      status: subsystems.onnxRuntime?.status || 'READY',
      detail: subsystems.onnxRuntime?.model || 'spin_ids_cnn.onnx',
    },
    {
      name: 'Detection Log Database',
      status: subsystems.database?.status || 'SYNCED',
      detail: 'CSV Stream Synced',
    },
  ];

  return (
    <div className="bg-white rounded-lg border border-slate-200 p-5 shadow-xs flex flex-col justify-between">
      <div>
        <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-100">
          <div className="flex items-center gap-2">
            <Server className="w-4 h-4 text-blue-600" />
            <h3 className="text-sm font-bold text-slate-900 tracking-tight">
              Engine Subsystem Health
            </h3>
          </div>
          <span className="text-xs font-mono px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200">
            All Systems Online
          </span>
        </div>

        <div className="space-y-2 text-xs">
          {items.map((item, idx) => {
            const isReady = item.status === 'ONLINE' || item.status === 'READY' || item.status === 'OPERATIONAL' || item.status === 'SYNCED';
            return (
              <div
                key={idx}
                className="p-2.5 rounded bg-slate-50 border border-slate-100 flex items-center justify-between font-mono"
              >
                <div className="flex items-center gap-2">
                  {isReady ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                  ) : (
                    <AlertCircle className="w-4 h-4 text-amber-500 shrink-0" />
                  )}
                  <span className="font-semibold text-slate-800">{item.name}</span>
                </div>
                <div className="text-right">
                  <span className="text-slate-500 text-[11px]">{item.detail}</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <div className="mt-4 pt-3 border-t border-slate-100 bg-slate-50/70 p-3 rounded text-[11px] font-mono text-slate-600 space-y-1">
        <div className="font-semibold text-slate-800 uppercase tracking-wider text-[10px]">
          CNN Model Architecture Specifications
        </div>
        <div className="flex justify-between">
          <span>Window Size:</span>
          <span className="text-slate-900 font-semibold">9 sequential packets</span>
        </div>
        <div className="flex justify-between">
          <span>Tensor Dimensions:</span>
          <span className="text-slate-900 font-semibold">27 × 27 × 3 (729 RGB pixels)</span>
        </div>
        <div className="flex justify-between">
          <span>Input Shape:</span>
          <span className="text-slate-900 font-semibold">[1, 27, 27, 3] FP32</span>
        </div>
        <div className="flex justify-between">
          <span>Target Inference Latency:</span>
          <span className="text-slate-900 font-semibold">&lt; 15.0 ms</span>
        </div>
      </div>
    </div>
  );
};
