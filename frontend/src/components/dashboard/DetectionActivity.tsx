import React from 'react';
import { ShieldAlert, ArrowRight, ExternalLink } from 'lucide-react';
import type { DetectionItem } from '../../types/api';

interface DetectionActivityProps {
  detections: DetectionItem[];
  onViewAll: () => void;
  onSelectDetection?: (item: DetectionItem) => void;
}

export const DetectionActivity: React.FC<DetectionActivityProps> = ({
  detections,
  onViewAll,
  onSelectDetection,
}) => {
  const displayItems = detections.slice(0, 5);

  return (
    <div className="bg-white rounded-lg border border-slate-200 p-5 shadow-xs flex flex-col justify-between">
      <div>
        <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-100">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-rose-600" />
            <h3 className="text-sm font-bold text-slate-900 tracking-tight">
              Recent CNN Inferences
            </h3>
          </div>
          <button
            onClick={onViewAll}
            className="inline-flex items-center gap-1 text-xs font-semibold text-blue-600 hover:text-blue-800 transition-colors"
          >
            All Results
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {displayItems.length === 0 ? (
          <div className="py-8 text-center text-xs text-slate-400 font-mono">
            No detection events recorded yet. Run a simulation or capture traffic.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-100 text-[11px] font-mono uppercase text-slate-400">
                  <th className="pb-2 font-semibold">Time</th>
                  <th className="pb-2 font-semibold">Window</th>
                  <th className="pb-2 font-semibold">Verdict</th>
                  <th className="pb-2 font-semibold text-right">Confidence</th>
                  <th className="pb-2 font-semibold text-center">Assessment</th>
                  <th className="pb-2 font-semibold text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-mono">
                {displayItems.map((item, idx) => {
                  const isMal = item.prediction === 'MALICIOUS';
                  const isLowConf = item.confidence < 0.65;
                  const timePart = item.timestamp.split(' ')[1] || item.timestamp;

                  return (
                    <tr
                      key={idx}
                      className="hover:bg-slate-50/70 transition-colors cursor-pointer"
                      onClick={() => onSelectDetection && onSelectDetection(item)}
                    >
                      <td className="py-2.5 text-slate-600">{timePart}</td>
                      <td className="py-2.5 font-semibold text-slate-800">
                        Win {String(item.windowIndex).padStart(2, '0')}
                      </td>
                      <td className="py-2.5">
                        <span
                          className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-bold ${
                            isMal
                              ? 'bg-rose-50 text-rose-700 border border-rose-200'
                              : 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                          }`}
                        >
                          {item.prediction}
                        </span>
                      </td>
                      <td className="py-2.5 text-right font-semibold text-slate-900">
                        {(item.confidence * 100).toFixed(2)}%
                      </td>
                      <td className="py-2.5 text-center">
                        {isLowConf ? (
                          <span className="text-[10px] uppercase font-bold px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200">
                            Low Confidence
                          </span>
                        ) : (
                          <span className="text-[10px] uppercase font-bold px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200">
                            High Confidence
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectDetection && onSelectDetection(item);
                          }}
                          className="p-1 rounded text-slate-400 hover:text-blue-600 hover:bg-slate-100"
                          title="Inspect Window"
                        >
                          <ExternalLink className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="pt-3 mt-3 border-t border-slate-100 text-[11px] text-slate-400 font-mono flex items-center justify-between">
        <span>Model: ONNX CNN (FP32)</span>
        <span>Windows buffered: {detections.length}</span>
      </div>
    </div>
  );
};
