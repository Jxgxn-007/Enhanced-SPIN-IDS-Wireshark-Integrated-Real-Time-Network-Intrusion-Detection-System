import React, { useState, useEffect } from 'react';
import { Eye, RefreshCw } from 'lucide-react';
import { PageContainer } from '../components/layout/PageContainer';
import { WindowModal } from '../components/common/WindowModal';
import type { WindowDetail } from '../types/api';
import { api } from '../services/api';

export const PacketWindows: React.FC = () => {
  const [windows, setWindows] = useState<WindowDetail[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedWindow, setSelectedWindow] = useState<WindowDetail | null>(null);
  const [isModalOpen, setIsModalOpen] = useState<boolean>(false);

  const fetchWindows = async () => {
    setLoading(true);
    try {
      const data = await api.getWindows();
      setWindows(data);
    } catch (err) {
      console.error('Failed to fetch windows:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchWindows();
  }, []);

  const openDetail = (win: WindowDetail) => {
    setSelectedWindow(win);
    setIsModalOpen(true);
  };

  return (
    <PageContainer
      title="Sequential Packet Windows"
      subtitle="9-frame sliding window tensor chunks partitioned from bidirectional network flows"
      actions={
        <button
          onClick={fetchWindows}
          disabled={loading}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-white border border-slate-200 text-xs font-semibold text-slate-700 hover:bg-slate-50 transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh Windows
        </button>
      }
    >
      <div className="bg-white rounded-lg border border-slate-200 p-4 shadow-xs mb-6 text-xs text-slate-600 leading-relaxed font-mono">
        <strong className="text-slate-900">Partitioning Scheme:</strong> Each bidirectional flow is aggregated into sequential 9-packet frames.
        Packet payloads and header metadata are preprocessed into 243-byte feature vectors, zero-padded for partial flows, and mapped into a 27×27 RGB image tensor (3×3 grid of 9×9 patches) for spatial CNN inference.
      </div>

      {loading ? (
        <div className="p-12 text-center text-xs font-mono text-slate-400">
          Loading sequential packet windows from backend...
        </div>
      ) : windows.length === 0 ? (
        <div className="p-12 text-center text-xs font-mono text-slate-400 bg-white rounded-lg border border-slate-200">
          No sequential packet windows currently loaded. Run a burst simulation to generate new window tensors.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {windows.map((win) => {
            const isMal = win.label === 'MALICIOUS' || win.detection?.prediction === 'MALICIOUS';
            const matrixCells = win.matrixPreview || [];

            return (
              <div
                key={win.windowIndex}
                className="bg-white rounded-lg border border-slate-200 p-4 shadow-xs flex flex-col justify-between hover:border-slate-300 transition-colors"
              >
                <div>
                  {/* Card Header */}
                  <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-100">
                    <div>
                      <div className="font-bold text-sm text-slate-900 font-mono">
                        Window {String(win.windowIndex).padStart(2, '0')}
                      </div>
                      <div className="text-[11px] font-mono text-slate-500 truncate max-w-[180px]">
                        {win.flowId || 'Flow 127.0.0.1:48210 → :80'}
                      </div>
                    </div>
                    <span
                      className={`text-xs font-mono font-bold px-2 py-0.5 rounded ${
                        isMal
                          ? 'bg-rose-100 text-rose-800 border border-rose-200'
                          : 'bg-emerald-100 text-emerald-800 border border-emerald-200'
                      }`}
                    >
                      {win.label}
                    </span>
                  </div>

                  {/* 27x27 Matrix Preview (9x9 visualizer) */}
                  <div className="flex items-center gap-4 my-3">
                    <div className="w-20 h-20 bg-slate-950 p-1 rounded border border-slate-800 shrink-0 grid grid-cols-9 gap-0.5">
                      {matrixCells.slice(0, 81).map((color, i) => (
                        <div
                          key={i}
                          style={{ backgroundColor: color }}
                          className="w-1.5 h-1.5 rounded-[0.5px]"
                        />
                      ))}
                    </div>

                    <div className="space-y-1 font-mono text-xs text-slate-600">
                      <div>
                        Frames: <strong className="text-slate-900">{win.packetCount} packets</strong>
                      </div>
                      <div>
                        Shape: <span className="text-slate-700">27 × 27 RGB</span>
                      </div>
                      <div>
                        Bytes: <span className="text-slate-700">729 features</span>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="mt-4 pt-3 border-t border-slate-100 flex items-center justify-between">
                  <span className="text-[11px] font-mono text-slate-400">
                    {win.packets?.length || 9} packets analyzed
                  </span>
                  <button
                    onClick={() => openDetail(win)}
                    className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-semibold rounded bg-slate-50 hover:bg-slate-100 text-slate-700 border border-slate-200 transition-colors"
                  >
                    <Eye className="w-3.5 h-3.5" />
                    Inspect Details
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      <WindowModal
        windowDetail={selectedWindow}
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
      />
    </PageContainer>
  );
};
