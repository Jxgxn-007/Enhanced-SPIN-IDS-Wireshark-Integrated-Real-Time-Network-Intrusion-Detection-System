import React, { useState, useEffect } from 'react';
import { Download, Filter, Search, RefreshCw } from 'lucide-react';
import { PageContainer } from '../components/layout/PageContainer';
import type { DetectionItem } from '../types/api';
import { api } from '../services/api';

export const ActivityLogs: React.FC = () => {
  const [logs, setLogs] = useState<DetectionItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [filter, setFilter] = useState<'ALL' | 'MALICIOUS' | 'NORMAL' | 'LOW_CONF'>('ALL');
  const [search, setSearch] = useState<string>('');

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const data = await api.getLogs('json');
      if (Array.isArray(data)) {
        setLogs(data);
      }
    } catch (err) {
      console.error('Failed to load logs:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, []);

  const handleExportCsv = () => {
    window.open(api.getLogsCsvUrl(), '_blank');
  };

  const filteredLogs = logs.filter((item) => {
    if (filter === 'MALICIOUS' && item.prediction !== 'MALICIOUS') return false;
    if (filter === 'NORMAL' && item.prediction !== 'NORMAL') return false;
    if (filter === 'LOW_CONF' && item.confidence >= 0.65) return false;

    if (search.trim()) {
      const q = search.toLowerCase();
      return (
        item.pcapFile.toLowerCase().includes(q) ||
        String(item.windowIndex).includes(q) ||
        item.prediction.toLowerCase().includes(q) ||
        item.timestamp.toLowerCase().includes(q)
      );
    }
    return true;
  });

  return (
    <PageContainer
      title="Detection Activity Logs"
      subtitle="Audit trail of CNN inferences appended continuously to dataset/results/detection_log.csv"
      actions={
        <div className="flex items-center gap-2">
          <button
            onClick={fetchLogs}
            disabled={loading}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-white border border-slate-200 text-xs font-semibold text-slate-700 hover:bg-slate-50 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            onClick={handleExportCsv}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold shadow-xs transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            Export CSV Log
          </button>
        </div>
      }
    >
      <div className="bg-white rounded-lg border border-slate-200 shadow-xs overflow-hidden">
        {/* Filter Toolbar */}
        <div className="p-4 border-b border-slate-200 bg-slate-50/60 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
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

          <div className="relative w-full sm:w-64">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search in log records..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 rounded border border-slate-200 text-xs font-mono bg-white focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
          </div>
        </div>

        {/* Logs Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50 text-[11px] uppercase tracking-wider text-slate-500">
                <th className="py-3 px-4 font-semibold">Timestamp</th>
                <th className="py-3 px-4 font-semibold">Interface / Mode</th>
                <th className="py-3 px-4 font-semibold">PCAP Source</th>
                <th className="py-3 px-4 font-semibold">Window</th>
                <th className="py-3 px-4 font-semibold">Prediction</th>
                <th className="py-3 px-4 font-semibold text-right">Normal Probability</th>
                <th className="py-3 px-4 font-semibold text-right">Malicious Probability</th>
                <th className="py-3 px-4 font-semibold text-right">Confidence</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {loading ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-400">
                    Loading detection activity logs...
                  </td>
                </tr>
              ) : filteredLogs.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-400">
                    No log records match the selected filter.
                  </td>
                </tr>
              ) : (
                filteredLogs.map((item, idx) => {
                  const isMal = item.prediction === 'MALICIOUS';
                  const isReal = item.pcapFile.startsWith('real_anomaly_capture_');
                  return (
                    <tr key={idx} className="hover:bg-slate-50/80 transition-colors">
                      <td className="py-2.5 px-4 text-slate-600 whitespace-nowrap">{item.timestamp}</td>
                      <td className="py-2.5 px-4 whitespace-nowrap">
                        <span
                          className={`inline-block text-[10px] font-bold px-2 py-0.5 rounded border ${
                            isReal
                              ? 'bg-blue-50 text-blue-700 border-blue-200'
                              : 'bg-slate-100 text-slate-700 border-slate-200'
                          }`}
                        >
                          {isReal ? 'REAL INTERFACE' : 'SIMULATED'}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 text-slate-700 max-w-[200px] truncate" title={item.pcapFile}>
                        {item.pcapFile}
                      </td>
                      <td className="py-2.5 px-4 font-bold text-slate-900">
                        Win {String(item.windowIndex).padStart(2, '0')}
                      </td>
                      <td className="py-2.5 px-4">
                        <span
                          className={`inline-block text-[11px] font-bold px-2 py-0.5 rounded ${
                            isMal
                              ? 'bg-rose-100 text-rose-800 border border-rose-200'
                              : 'bg-emerald-100 text-emerald-800 border border-emerald-200'
                          }`}
                        >
                          {item.prediction}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 text-right text-slate-600">
                        {(item.normalProbability * 100).toFixed(4)}%
                      </td>
                      <td className="py-2.5 px-4 text-right text-slate-600">
                        {(item.maliciousProbability * 100).toFixed(4)}%
                      </td>
                      <td className="py-2.5 px-4 text-right font-bold text-slate-900">
                        {(item.confidence * 100).toFixed(4)}%
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        <div className="p-3 border-t border-slate-200 bg-slate-50 flex items-center justify-between text-xs text-slate-500 font-mono">
          <span>{filteredLogs.length} Records Shown</span>
          <span>Synced with <code>dataset/results/detection_log.csv</code></span>
        </div>
      </div>
    </PageContainer>
  );
};
