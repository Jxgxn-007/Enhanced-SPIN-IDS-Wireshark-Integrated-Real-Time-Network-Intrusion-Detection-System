import React, { useState } from 'react';
import {
  X,
  ShieldAlert,
  ShieldCheck,
  Layers,
  FileText,
  Binary,
  Copy,
  Check,
  AlertTriangle,
  Cpu,
  CheckCircle2,
} from 'lucide-react';
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
  const [copiedHex, setCopiedHex] = useState(false);

  if (!isOpen || !windowDetail) return null;

  const det = windowDetail.detection;
  const isMalicious =
    det?.prediction === 'MALICIOUS' || windowDetail.label === 'MALICIOUS';

  const confPct = det?.confidence
    ? (det.confidence * 100).toFixed(2) + '%'
    : '50.00%';

  const normalPct = det?.normalProbability
    ? (det.normalProbability * 100).toFixed(2)
    : '50.00';

  const malPct = det?.maliciousProbability
    ? (det.maliciousProbability * 100).toFixed(2)
    : '50.00';

  const isLowConf = (det?.confidence ?? 0.5) < 0.65;
  const matrixCells = windowDetail.matrixPreview || [];

  // Dual-branch metadata
  const isDualBranch = det?.dualBranch ?? (!!det?.rgbPrediction && !!det?.bytePrediction);
  const rgbPred = det?.rgbPrediction || det?.prediction || 'NORMAL';
  const rgbConf = det?.rgbConfidence !== undefined ? (det.rgbConfidence * 100).toFixed(2) + '%' : confPct;
  const rgbNormPct = det?.rgbNormalProbability !== undefined ? (det.rgbNormalProbability * 100).toFixed(2) : normalPct;
  const rgbMalPct = det?.rgbMaliciousProbability !== undefined ? (det.rgbMaliciousProbability * 100).toFixed(2) : malPct;

  const bytePred = det?.bytePrediction || 'N/A';
  const hasByteBranch = !!det?.bytePrediction;
  const byteConf = det?.byteConfidence !== undefined ? (det.byteConfidence * 100).toFixed(2) + '%' : 'N/A';
  const byteNormPct = det?.byteNormalProbability !== undefined ? (det.byteNormalProbability * 100).toFixed(2) : '50.00';
  const byteMalPct = det?.byteMaliciousProbability !== undefined ? (det.byteMaliciousProbability * 100).toFixed(2) : '50.00';

  const correlationStatus = det?.correlationStatus || 'SINGLE_BRANCH';
  const fusionAlpha = det?.fusionAlpha !== undefined ? det.fusionAlpha : 1.0;
  const fusionThreshold = det?.fusionThreshold !== undefined ? det.fusionThreshold : 0.9;
  const fusedMalPct = det?.fusedMaliciousProbability !== undefined
    ? (det.fusedMaliciousProbability * 100).toFixed(2) + '%'
    : malPct + '%';

  const handleCopyHex = () => {
    if (windowDetail.hexDump) {
      navigator.clipboard.writeText(windowDetail.hexDump);
      setCopiedHex(true);
      setTimeout(() => setCopiedHex(false), 2000);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs select-none">
      <div className="w-full max-w-4xl bg-white rounded-lg shadow-2xl border border-slate-200 overflow-hidden flex flex-col max-h-[92vh]">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between bg-slate-50">
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
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-slate-900 tracking-tight">
                  Window {String(windowDetail.windowIndex).padStart(2, '0')} Deep Inspection
                </h3>
                {isDualBranch && (
                  <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-blue-100 text-blue-800 border border-blue-200">
                    DUAL-BRANCH HYBRID
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-500 font-mono">
                Flow: {windowDetail.flowId || '127.0.0.1:48210 → :80'} • 9 Sequential Packets (2,187 Bytes)
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
        <div className="p-6 space-y-5 overflow-y-auto">
          {/* Primary Verdict & Correlation Banner */}
          <div className="p-4 rounded-lg border border-slate-200 bg-slate-50 flex flex-col md:flex-row md:items-center justify-between gap-4 font-mono">
            <div>
              <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider block">
                Ensemble Decision Verdict
              </span>
              <div className="flex items-center gap-2 mt-1.5">
                <span
                  className={`text-sm font-bold px-2.5 py-0.5 rounded ${
                    isMalicious
                      ? 'bg-rose-100 text-rose-700 border border-rose-200'
                      : 'bg-emerald-100 text-emerald-700 border border-emerald-200'
                  }`}
                >
                  {isMalicious ? 'MALICIOUS' : 'NORMAL'}
                </span>
                {isLowConf ? (
                  <span className="text-xs font-semibold px-2 py-0.5 rounded bg-slate-200 text-slate-700">
                    LOW CONFIDENCE (Boundary)
                  </span>
                ) : (
                  <span className="text-xs font-semibold px-2 py-0.5 rounded bg-emerald-100 text-emerald-800">
                    HIGH CONFIDENCE
                  </span>
                )}
              </div>
            </div>

            {/* Correlation Status Badge */}
            <div className="flex flex-col md:items-end">
              <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider block">
                Branch Correlation
              </span>
              <div className="mt-1 flex items-center gap-1.5">
                {correlationStatus === 'AGREEMENT_NORMAL' && (
                  <span className="inline-flex items-center gap-1 text-xs font-bold px-2.5 py-1 rounded bg-emerald-100 text-emerald-800 border border-emerald-200">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                    AGREEMENT (Benign)
                  </span>
                )}
                {correlationStatus === 'AGREEMENT_MALICIOUS' && (
                  <span className="inline-flex items-center gap-1 text-xs font-bold px-2.5 py-1 rounded bg-rose-100 text-rose-800 border border-rose-200">
                    <ShieldAlert className="w-3.5 h-3.5 text-rose-600" />
                    AGREEMENT (Threat Confirmed)
                  </span>
                )}
                {correlationStatus === 'CONFLICT_RESOLVED' && (
                  <span className="inline-flex items-center gap-1 text-xs font-bold px-2.5 py-1 rounded bg-amber-100 text-amber-800 border border-amber-200">
                    <AlertTriangle className="w-3.5 h-3.5 text-amber-600" />
                    CONFLICT RESOLVED
                  </span>
                )}
                {correlationStatus === 'SINGLE_BRANCH' && (
                  <span className="inline-flex items-center gap-1 text-xs font-bold px-2.5 py-1 rounded bg-slate-100 text-slate-700 border border-slate-200">
                    <Cpu className="w-3.5 h-3.5 text-slate-500" />
                    SINGLE BRANCH
                  </span>
                )}
              </div>
            </div>

            <div className="text-left md:text-right">
              <span className="text-[11px] text-slate-500 block">Fused Probability:</span>
              <span className="text-lg font-bold text-slate-900">{confPct}</span>
            </div>
          </div>

          {/* Fusion Parameters Notice */}
          {isDualBranch && (
            <div className="px-3.5 py-2.5 rounded-md bg-blue-50/70 border border-blue-200 text-xs font-mono text-blue-900 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <strong>Score-Fusion Weight:</strong> &alpha; = {fusionAlpha.toFixed(2)} (RGB), (1 - &alpha;) = {(1.0 - fusionAlpha).toFixed(2)} (BYTE) • <strong>Threshold:</strong> &tau; = {fusionThreshold.toFixed(2)} • <strong>Fused P(Malicious):</strong> {fusedMalPct}
              </div>
              {fusionAlpha === 1.0 && (
                <span className="text-[10px] text-blue-700 bg-blue-100/80 px-2 py-0.5 rounded shrink-0">
                  &alpha;=1.0: RGB score governs verdict; Byte independently cross-validates
                </span>
              )}
            </div>
          )}

          {/* Separate RGB and BYTE Prediction Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* RGB 2D CNN Card */}
            <div className="border border-blue-200 bg-blue-50/20 rounded-lg p-4 font-mono space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="p-1.5 rounded bg-blue-100 text-blue-700">
                    <Layers className="w-4 h-4" />
                  </div>
                  <div>
                    <h4 className="text-xs font-bold text-slate-900">2D Spatial RGB Branch</h4>
                    <span className="text-[10px] text-slate-500">spin_ids_cnn.onnx (27×27×3)</span>
                  </div>
                </div>
                <span
                  className={`text-xs font-bold px-2 py-0.5 rounded ${
                    rgbPred === 'MALICIOUS'
                      ? 'bg-rose-100 text-rose-700 border border-rose-200'
                      : 'bg-emerald-100 text-emerald-700 border border-emerald-200'
                  }`}
                >
                  {rgbPred}
                </span>
              </div>

              <div className="flex justify-between text-xs text-slate-600">
                <span>Confidence: <strong className="text-slate-900">{rgbConf}</strong></span>
                <span className="text-[11px] text-slate-500">P(Norm): {rgbNormPct}% | P(Mal): {rgbMalPct}%</span>
              </div>

              <div className="w-full h-2 bg-slate-200 rounded-full overflow-hidden flex">
                <div style={{ width: `${rgbNormPct}%` }} className="bg-emerald-500 h-full" title={`Normal: ${rgbNormPct}%`} />
                <div style={{ width: `${rgbMalPct}%` }} className="bg-rose-500 h-full" title={`Malicious: ${rgbMalPct}%`} />
              </div>
            </div>

            {/* BYTE 1D CNN Card */}
            <div className="border border-purple-200 bg-purple-50/20 rounded-lg p-4 font-mono space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="p-1.5 rounded bg-purple-100 text-purple-700">
                    <Binary className="w-4 h-4" />
                  </div>
                  <div>
                    <h4 className="text-xs font-bold text-slate-900">1D Sequential Byte Branch</h4>
                    <span className="text-[10px] text-slate-500">best_byte_cnn.onnx (1×1×2187)</span>
                  </div>
                </div>
                {hasByteBranch ? (
                  <span
                    className={`text-xs font-bold px-2 py-0.5 rounded ${
                      bytePred === 'MALICIOUS'
                        ? 'bg-rose-100 text-rose-700 border border-rose-200'
                        : 'bg-emerald-100 text-emerald-700 border border-emerald-200'
                    }`}
                  >
                    {bytePred}
                  </span>
                ) : (
                  <span className="text-[11px] font-semibold px-2 py-0.5 rounded bg-slate-100 text-slate-500 border border-slate-200">
                    INACTIVE
                  </span>
                )}
              </div>

              {hasByteBranch ? (
                <>
                  <div className="flex justify-between text-xs text-slate-600">
                    <span>Confidence: <strong className="text-slate-900">{byteConf}</strong></span>
                    <span className="text-[11px] text-slate-500">P(Norm): {byteNormPct}% | P(Mal): {byteMalPct}%</span>
                  </div>

                  <div className="w-full h-2 bg-slate-200 rounded-full overflow-hidden flex">
                    <div style={{ width: `${byteNormPct}%` }} className="bg-emerald-500 h-full" title={`Normal: ${byteNormPct}%`} />
                    <div style={{ width: `${byteMalPct}%` }} className="bg-rose-500 h-full" title={`Malicious: ${byteMalPct}%`} />
                  </div>
                </>
              ) : (
                <p className="text-[11px] text-slate-400 italic">
                  Byte CNN branch was not invoked. Start engine with HYBRID or BYTE mode to enable.
                </p>
              )}
            </div>
          </div>

          {/* Visual Tensor & Feature Map Inspection */}
          <div className="border border-slate-200 rounded-lg p-4 bg-white">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-1.5 text-xs font-bold text-slate-800">
                <Layers className="w-4 h-4 text-blue-600" />
                <span>2D Spatial Representation: 27×27 RGB Image & 9×9 Sampled Patches</span>
              </div>
              <span className="text-[11px] font-mono text-slate-500">
                729 Pixels (2,187 Bytes)
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 items-center">
              {/* Full 27×27 RGB Image */}
              <div className="flex flex-col items-center justify-center p-3 bg-slate-900 rounded-lg border border-slate-800">
                <span className="text-[10px] font-mono text-slate-400 mb-2 font-semibold">
                  Full 27×27 Pixel RGB Image (Magnified)
                </span>
                {windowDetail.imageBase64 ? (
                  <img
                    src={windowDetail.imageBase64}
                    alt="27x27 RGB Window Representation"
                    className="w-28 h-28 border border-slate-700 rounded shadow-md"
                    style={{ imageRendering: 'pixelated' }}
                  />
                ) : (
                  <div className="w-28 h-28 bg-slate-950 border border-slate-800 rounded flex items-center justify-center text-[10px] font-mono text-slate-500 text-center p-2">
                    27×27 PNG Generated during Inference
                  </div>
                )}
                <span className="text-[10px] font-mono text-slate-500 mt-2">
                  3×3 Grid of 9×9 Packet Tiles
                </span>
              </div>

              {/* 9x9 Macro Sampled Grid */}
              <div className="flex flex-col items-center justify-center p-3 bg-slate-900 rounded-lg border border-slate-800">
                <span className="text-[10px] font-mono text-slate-400 mb-2 font-semibold">
                  Sampled Macro Grid (81 Color Patches)
                </span>
                <div className="grid grid-cols-9 gap-0.5 p-1 bg-slate-950 rounded border border-slate-800">
                  {matrixCells.slice(0, 81).map((hex, i) => (
                    <div
                      key={i}
                      style={{ backgroundColor: hex }}
                      title={`Patch ${i + 1}: ${hex}`}
                      className="w-3.5 h-3.5 rounded-[1px] transition-transform hover:scale-125"
                    />
                  ))}
                </div>
                <div className="flex justify-between w-full text-[10px] font-mono text-slate-500 mt-2 px-3">
                  <span>Offset 0x000</span>
                  <span>Offset 0x88B</span>
                </div>
              </div>
            </div>
          </div>

          {/* Genuine Hexadecimal Dump */}
          <div className="border border-slate-200 rounded-lg p-4 bg-white space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5 text-xs font-bold text-slate-800">
                <Binary className="w-4 h-4 text-purple-600" />
                <span>Window Raw Hexadecimal Dump (Wireshark Canonical Format)</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[11px] font-mono text-slate-500">
                  {windowDetail.byteCount ? `${windowDetail.byteCount.toLocaleString()} Bytes` : '2,187 Bytes'}
                </span>
                {windowDetail.hexDump && (
                  <button
                    onClick={handleCopyHex}
                    className="inline-flex items-center gap-1 px-2 py-0.5 text-[11px] font-mono font-medium rounded bg-slate-100 hover:bg-slate-200 text-slate-700 transition-colors"
                  >
                    {copiedHex ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                    {copiedHex ? 'Copied' : 'Copy'}
                  </button>
                )}
              </div>
            </div>

            {windowDetail.hexDump ? (
              <pre className="p-3 bg-slate-950 text-emerald-400 font-mono text-[11px] leading-relaxed rounded-md border border-slate-800 max-h-52 overflow-y-auto overflow-x-auto whitespace-pre select-text">
                {windowDetail.hexDump}
              </pre>
            ) : (
              <div className="p-4 bg-slate-50 rounded border border-slate-200 text-center text-xs font-mono text-slate-400">
                Raw capture stream not retained in historical preloaded record. Genuine hex dumps are captured for all live PCAP flows and simulated bursts.
              </div>
            )}
          </div>

          {/* Sequential Packet Sequence Breakdown */}
          <div className="border border-slate-200 rounded-lg p-4 bg-white">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-1.5 text-xs font-bold text-slate-800">
                <FileText className="w-4 h-4 text-blue-600" />
                <span>9 Sequential Packets in Flow Window</span>
              </div>
              <span className="text-[11px] font-mono text-slate-500">
                Sequential Stride: 1
              </span>
            </div>

            <div className="space-y-1.5 font-mono text-xs max-h-40 overflow-y-auto pr-1">
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
        <div className="px-6 py-3 border-t border-slate-200 bg-slate-50 flex items-center justify-between">
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

