import React, { useState, useEffect } from 'react';
import { FileArchive, Download, RefreshCw, HardDrive, CheckCircle2 } from 'lucide-react';
import { PageContainer } from '../components/layout/PageContainer';
import type { PcapFileItem } from '../types/api';
import { api } from '../services/api';

export const PcapCaptures: React.FC = () => {
  const [pcaps, setPcaps] = useState<PcapFileItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);

  const fetchPcaps = async () => {
    setLoading(true);
    try {
      const data = await api.getPcaps();
      setPcaps(data);
    } catch (err) {
      console.error('Failed to fetch PCAPs:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPcaps();
  }, []);

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    return `${(bytes / 1024).toFixed(1)} KB`;
  };

  const handleDownload = (filename: string) => {
    const url = api.getPcapDownloadUrl(filename);
    window.open(url, '_blank');
  };

  return (
    <PageContainer
      title="PCAP Captures"
      subtitle="Raw libpcap capture files written automatically by Npcap upon AnomalyTrigger activation"
      actions={
        <button
          onClick={fetchPcaps}
          disabled={loading}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-white border border-slate-200 text-xs font-semibold text-slate-700 hover:bg-slate-50 transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh List
        </button>
      }
    >
      <div className="bg-white rounded-lg border border-slate-200 shadow-xs overflow-hidden">
        <div className="p-4 border-b border-slate-200 bg-slate-50 flex items-center justify-between font-mono text-xs text-slate-600">
          <div className="flex items-center gap-2">
            <HardDrive className="w-4 h-4 text-blue-600" />
            <span>Target Directory: <code>dataset/captures/generated/</code></span>
          </div>
          <span>{pcaps.length} Capture Files Found</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50/50 text-[11px] uppercase tracking-wider text-slate-500">
                <th className="py-3 px-4 font-semibold">PCAP Filename</th>
                <th className="py-3 px-4 font-semibold text-center">Capture Source</th>
                <th className="py-3 px-4 font-semibold">Timestamp Created</th>
                <th className="py-3 px-4 font-semibold text-right">Frames</th>
                <th className="py-3 px-4 font-semibold text-right">File Size</th>
                <th className="py-3 px-4 font-semibold text-center">Pipeline State</th>
                <th className="py-3 px-4 font-semibold text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {loading ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-400">
                    Scanning capture storage...
                  </td>
                </tr>
              ) : pcaps.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-400">
                    No PCAP capture files found in <code>dataset/captures/generated/</code>. Run an anomaly simulation or live capture to generate records.
                  </td>
                </tr>
              ) : (
                pcaps.map((p, idx) => {
                  const isReal = p.filename.startsWith('real_anomaly_capture_');
                  return (
                    <tr key={idx} className="hover:bg-slate-50/80 transition-colors">
                      <td className="py-3 px-4 font-semibold text-slate-900 flex items-center gap-2">
                        <FileArchive className="w-4 h-4 text-slate-400 shrink-0" />
                        <span className="truncate max-w-[240px]" title={p.filename}>
                          {p.filename}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-center">
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
                      <td className="py-3 px-4 text-slate-600 whitespace-nowrap">{p.creationTime}</td>
                      <td className="py-3 px-4 text-right text-slate-800 font-bold">{p.packetCount} pkts</td>
                      <td className="py-3 px-4 text-right text-slate-600">{formatSize(p.sizeBytes)}</td>
                      <td className="py-3 px-4 text-center">
                        <span className="inline-flex items-center gap-1 text-[11px] font-bold px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200">
                          <CheckCircle2 className="w-3 h-3" />
                          PROCESSED
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => handleDownload(p.filename)}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-semibold rounded bg-blue-50 text-blue-700 hover:bg-blue-100 border border-blue-200 transition-colors"
                        >
                          <Download className="w-3.5 h-3.5" />
                          Download PCAP
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </PageContainer>
  );
};
