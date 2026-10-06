import React from 'react';
import { X, ShieldAlert, ShieldCheck, Layers, FileText } from 'lucide-react';
import type { WindowDetail } from '../../types/api';

interface WindowModalProps {
  windowDetail: WindowDetail | null;
  isOpen: boolean;
  onClose: () => void;
}

export const WindowModal: React.FC<WindowModalProps> = ({
  windowDetail,
  isOpen,
  onClose,
}) => {
  if (!isOpen || !windowDetail) return null;

  const isMalicious =
    windowDetail.detection?.prediction === 'MALICIOUS' ||
    windowDetail.label === 'MALICIOUS';

  const confPct = windowDetail.detection?.confidence
    ? (windowDetail.detection.confidence * 100).toFixed(2) + '%'
    : '50.00%';

  const normalPct = windowDetail.detection?.normalProbability
    ? (windowDetail.detection.normalProbability * 100).toFixed(2)
    : '50.00';

  const malPct = windowDetail.detection?.maliciousProbability
    ? (windowDetail.detection.maliciousProbability * 100).toFixed(2)
    : '50.00';

  const isLowConf = (windowDetail.detection?.confidence ?? 0.5) < 0.65;
  const matrixCells = windowDetail.matrixPreview || [];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs select-none">
      <div className="w-full max-w-2xl bg-white rounded-lg shadow-xl border border-slate-200 overflow-hidden flex flex-col max-h-[90vh]">
        {/* Modal Header */}
        <div className="px-5 py-4 border-b border-slate-200 flex items-center justify-between bg-slate-50">
          <div className="flex items-center gap-3">
            <div
              className={`p-2 rounded-md ${
                isMalicious
                  ? 'bg-rose-100 text-rose-700'
                  : 'bg-emerald-100 text-emerald-700'
              }`}
            >
              {isMalicious ? <ShieldAlert className="w-5 h-5" /> : <ShieldCheck className="w-5 h-5" />}
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-900 tracking-tight">
                Window {String(windowDetail.windowIndex).padStart(2, '0')} Inspection
              </h3>
              <p className="text-xs text-slate-500 font-mono">
                Flow: {windowDetail.flowId || '127.0.0.1:48210 → :80'} • 9 Sequential Packets
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-md text-slate-400 hover:text-slate-700 hover:bg-slate-200 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-5 space-y-5 overflow-y-auto">
          {/* Verdict Banner */}
          <div className="p-3.5 rounded-lg border border-slate-200 bg-slate-50 flex items-center justify-between font-mono">
            <div>
              <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider block">
                CNN Classification Verdict
              </span>
              <div className="flex items-center gap-2 mt-1">
                <span
                  className={`text-sm font-bold px-2 py-0.5 rounded ${
                    isMalicious
                      ? 'bg-rose-100 text-rose-700 border border-rose-200'
                      : 'bg-emerald-100 text-emerald-700 border border-emerald-200'
                  }`}
                >
                  {isMalicious ? 'MALICIOUS' : 'NORMAL'}
                </span>
                {isLowConf ? (
                  <span className="text-xs font-semibold px-2 py-0.5 rounded bg-slate-200 text-slate-700">
                    LOW CONFIDENCE (Decision Boundary)
                  </span>
                ) : (
                  <span className="text-xs font-semibold px-2 py-0.5 rounded bg-emerald-100 text-emerald-800">
                    HIGH CONFIDENCE
                  </span>
                )}
              </div>
            </div>

            <div className="text-right">
              <span className="text-[11px] text-slate-500 block">Confidence:</span>
              <span className="text-lg font-bold text-slate-900">{confPct}</span>
            </div>
          </div>

          {/* Probability Distribution Bar */}
          <div className="space-y-1.5 font-mono text-xs">
            <div className="flex justify-between text-slate-600">
              <span className="text-emerald-700 font-semibold">Normal: {normalPct}%</span>
              <span className="text-rose-700 font-semibold">Malicious: {malPct}%</span>
            </div>
            <div className="w-full h-2.5 bg-slate-200 rounded-full overflow-hidden flex">
              <div
                style={{ width: `${normalPct}%` }}
                className="bg-emerald-500 h-full transition-all duration-300"
              />
              <div
                style={{ width: `${malPct}%` }}
                className="bg-rose-500 h-full transition-all duration-300"
              />
            </div>
          </div>

          {/* 27×27 Tensor Feature Map Visualization */}
          <div className="border border-slate-200 rounded-lg p-3 bg-white">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-1.5 text-xs font-bold text-slate-800">
                <Layers className="w-4 h-4 text-blue-600" />
                <span>27×27 RGB Image Representation (81 Sampled Patches)</span>
              </div>
              <span className="text-[11px] font-mono text-slate-500">
                729 Byte Feature Vector
              </span>
            </div>

            <div className="flex justify-center p-3 bg-slate-900 rounded border border-slate-800">
              <div className="grid grid-cols-9 gap-0.5 p-1 bg-slate-950 rounded">
                {matrixCells.slice(0, 81).map((hex, i) => (
                  <div
                    key={i}
                    style={{ backgroundColor: hex }}
                    title={`Patch ${i + 1}: ${hex}`}
                    className="w-4 h-4 rounded-[1px] transition-transform hover:scale-125"
                  />
                ))}
              </div>
            </div>
            <div className="flex justify-between text-[10px] font-mono text-slate-400 mt-2 px-1">
              <span>Offset 0x000 (Packet 1 Headers)</span>
              <span>Offset 0x2D9 (Packet 9 Payload)</span>
            </div>
          </div>

          {/* Sequential Packet Sequence Breakdown */}
          <div className="border border-slate-200 rounded-lg p-3 bg-white">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-1.5 text-xs font-bold text-slate-800">
                <FileText className="w-4 h-4 text-blue-600" />
                <span>9 Sequential Packets in Flow Window</span>
              </div>
              <span className="text-[11px] font-mono text-slate-500">
                Sequential Stride: 1
              </span>
            </div>

            <div className="space-y-1.5 font-mono text-xs max-h-44 overflow-y-auto pr-1">
              {windowDetail.packets?.map((p) => (
                <div
                  key={p.sequence}
                  className="p-2 rounded bg-slate-50 border border-slate-100 flex items-center justify-between text-[11px]"
                >
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-slate-500 w-5">#{p.sequence}</span>
                    <span className="px-1 py-0.5 rounded bg-slate-200 font-bold text-slate-700 text-[10px]">
                      {p.protocol}
                    </span>
                    <span className="text-slate-800">
                      {p.src} → {p.dst}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 text-slate-500">
                    <span>{p.length} B</span>
                    <span className="font-semibold text-slate-700">[{p.flags}]</span>
                    <span className="text-[10px] px-1 py-0.5 rounded bg-blue-50 text-blue-700">
                      {p.direction}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="px-5 py-3 border-t border-slate-200 bg-slate-50 flex items-center justify-between">
          <span className="text-xs font-mono text-slate-500 truncate max-w-sm">
            Source: {windowDetail.detection?.pcapFile || 'anomaly_capture.pcap'}
          </span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 text-xs font-semibold rounded bg-slate-900 hover:bg-slate-800 text-white transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
