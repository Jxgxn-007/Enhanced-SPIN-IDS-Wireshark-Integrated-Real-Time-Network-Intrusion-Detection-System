import React, { useState } from 'react';
import { Filter, Search, ExternalLink } from 'lucide-react';
import { PageContainer } from '../components/layout/PageContainer';
import { WindowModal } from '../components/common/WindowModal';
import type { DetectionItem, WindowDetail } from '../types/api';
import { api } from '../services/api';

interface DetectionsProps {
  detections: DetectionItem[];
  onRefresh: () => void;
}

export const Detections: React.FC<DetectionsProps> = ({ detections, onRefresh }) => {
  const [filter, setFilter] = useState<'ALL' | 'MALICIOUS' | 'NORMAL' | 'LOW_CONF'>('ALL');
  const [search, setSearch] = useState<string>('');
  const [selectedWindow, setSelectedWindow] = useState<WindowDetail | null>(null);
  const [isModalOpen, setIsModalOpen] = useState<boolean>(false);

  const filteredItems = detections.filter((item) => {
    if (filter === 'MALICIOUS' && item.prediction !== 'MALICIOUS') return false;
    if (filter === 'NORMAL' && item.prediction !== 'NORMAL') return false;
    if (filter === 'LOW_CONF' && item.confidence >= 0.65) return false;

    if (search.trim()) {
      const q = search.toLowerCase();
      return (
        item.pcapFile.toLowerCase().includes(q) ||
        item.flowKey.toLowerCase().includes(q) ||
        String(item.windowIndex).includes(q) ||
        item.prediction.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const handleInspect = async (item: DetectionItem) => {
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
      title="Detection Results"
      subtitle="CNN deep feature tensor inference outcomes for 9-packet sequential windows"
      badge={
        <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200">
          {detections.length} Records
        </span>
      }
    >
      <div className="bg-white rounded-lg border border-slate-200 shadow-xs overflow-hidden">
        {/* Table Filters & Search */}
        <div className="p-4 border-b border-slate-200 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 bg-slate-50/60">
          {/* Filter Pills */}
          <div className="flex items-center gap-1.5 flex-wrap font-mono text-xs">
            <span className="text-slate-400 mr-1 flex items-center gap-1">
              <Filter className="w-3.5 h-3.5" />
              Filter:
            </span>
            {(['ALL', 'MALICIOUS', 'NORMAL', 'LOW_CONF'] as const).map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`px-2.5 py-1 rounded transition-colors ${
                  filter === f
                    ? 'bg-blue-600 text-white font-semibold'
                    : 'bg-white border border-slate-200 text-slate-600 hover:bg-slate-100'
                }`}
              >
                {f === 'LOW_CONF' ? 'Low Confidence' : f}
              </button>
            ))}
          </div>

          {/* Search Box */}
          <div className="relative w-full sm:w-64">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search window, PCAP, flow..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 rounded border border-slate-200 text-xs font-mono bg-white focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
          </div>
        </div>

        {/* Data Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50 text-[11px] uppercase tracking-wider text-slate-500">
                <th className="py-3 px-4 font-semibold">Timestamp</th>
                <th className="py-3 px-4 font-semibold">PCAP Source</th>
                <th className="py-3 px-4 font-semibold">Window</th>
                <th className="py-3 px-4 font-semibold">Prediction</th>
                <th className="py-3 px-4 font-semibold text-right">Normal Prob</th>
                <th className="py-3 px-4 font-semibold text-right">Malicious Prob</th>
                <th className="py-3 px-4 font-semibold text-right">Confidence</th>
                <th className="py-3 px-4 font-semibold text-center">Status / Assessment</th>
                <th className="py-3 px-4 font-semibold text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {filteredItems.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-8 text-center text-slate-400 text-xs">
                    No detections match the selected criteria.
                  </td>
                </tr>
              ) : (
                filteredItems.map((item, idx) => {
                  const isMal = item.prediction === 'MALICIOUS';
                  const isLowConf = item.confidence < 0.65;

                  return (
                    <tr
                      key={idx}
                      onClick={() => handleInspect(item)}
                      className="hover:bg-slate-50/80 transition-colors cursor-pointer"
                    >
                      <td className="py-3 px-4 text-slate-600 whitespace-nowrap">
                        {item.timestamp}
                      </td>
                      <td className="py-3 px-4 text-slate-700 max-w-[180px] truncate" title={item.pcapFile}>
                        {item.pcapFile}
                      </td>
                      <td className="py-3 px-4 font-bold text-slate-900">
                        Win {String(item.windowIndex).padStart(2, '0')}
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-bold ${
                            isMal
                              ? 'bg-rose-100 text-rose-800 border border-rose-200'
                              : 'bg-emerald-100 text-emerald-800 border border-emerald-200'
                          }`}
                        >
                          {item.prediction}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right text-slate-600">
                        {(item.normalProbability * 100).toFixed(2)}%
                      </td>
                      <td className="py-3 px-4 text-right text-slate-600">
                        {(item.maliciousProbability * 100).toFixed(2)}%
                      </td>
                      <td className="py-3 px-4 text-right font-bold text-slate-900">
                        {(item.confidence * 100).toFixed(2)}%
                      </td>
                      <td className="py-3 px-4 text-center">
                        {isLowConf ? (
                          <span className="inline-block text-[10px] font-bold px-2 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200">
                            LOW CONFIDENCE
                          </span>
                        ) : (
                          <span className="inline-block text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200">
                            CONFIRMED
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleInspect(item);
                          }}
                          className="p-1.5 rounded text-slate-400 hover:text-blue-600 hover:bg-slate-100"
                          title="Inspect Window"
                        >
                          <ExternalLink className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Footer */}
        <div className="p-3 border-t border-slate-200 bg-slate-50 flex items-center justify-between text-xs text-slate-500 font-mono">
          <span>Displaying {filteredItems.length} of {detections.length} recorded inference events</span>
          <button
            onClick={onRefresh}
            className="text-blue-600 hover:underline font-semibold"
          >
            Refresh Log
          </button>
        </div>
      </div>

      <WindowModal
        windowDetail={selectedWindow}
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
      />
    </PageContainer>
  );
};
