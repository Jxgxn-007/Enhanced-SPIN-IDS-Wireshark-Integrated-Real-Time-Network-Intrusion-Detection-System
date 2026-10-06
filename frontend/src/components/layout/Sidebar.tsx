import React from 'react';
import {
  LayoutDashboard,
  Activity,
  ShieldAlert,
  Layers,
  FileArchive,
  FileText,
  Server,
  Shield,
  Radio,
} from 'lucide-react';

export type PageId =
  | 'dashboard'
  | 'live-monitor'
  | 'detections'
  | 'packet-windows'
  | 'pcap-captures'
  | 'activity-logs'
  | 'system';

interface SidebarProps {
  activePage: PageId;
  onSelectPage: (page: PageId) => void;
  engineRunning: boolean;
  currentPps: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activePage,
  onSelectPage,
  engineRunning,
  currentPps,
}) => {
  const navItems: { id: PageId; label: string; icon: React.ReactNode }[] = [
    { id: 'dashboard', label: 'Dashboard', icon: <LayoutDashboard className="w-4 h-4" /> },
    { id: 'live-monitor', label: 'Live Monitor', icon: <Activity className="w-4 h-4" /> },
    { id: 'detections', label: 'Detection Results', icon: <ShieldAlert className="w-4 h-4" /> },
    { id: 'packet-windows', label: 'Packet Windows', icon: <Layers className="w-4 h-4" /> },
    { id: 'pcap-captures', label: 'PCAP Captures', icon: <FileArchive className="w-4 h-4" /> },
    { id: 'activity-logs', label: 'Activity Logs', icon: <FileText className="w-4 h-4" /> },
    { id: 'system', label: 'System', icon: <Server className="w-4 h-4" /> },
  ];

  return (
    <aside className="w-64 bg-slate-900 text-slate-300 flex flex-col h-screen border-r border-slate-800 shrink-0 select-none">
      {/* Brand Header */}
      <div className="p-4 border-b border-slate-800 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded bg-blue-600/20 border border-blue-500/30 flex items-center justify-center text-blue-400">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <div className="font-semibold text-white tracking-tight flex items-center gap-1.5 text-sm">
              SPIN-IDS
              <span className="text-[10px] font-mono uppercase px-1 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800">
                v1.0
              </span>
            </div>
            <div className="text-xs text-slate-400">Network Security</div>
          </div>
        </div>
      </div>

      {/* Navigation section */}
      <div className="px-3 pt-4 pb-2 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
        Navigation
      </div>
      <nav className="flex-1 px-2 space-y-1 overflow-y-auto">
        {navItems.map((item) => {
          const isActive = activePage === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectPage(item.id)}
              className={`w-full flex items-center gap-3 px-3 py-2 text-sm rounded-md transition-colors text-left font-medium ${
                isActive
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-300 hover:text-white hover:bg-slate-800/80'
              }`}
            >
              <span className={isActive ? 'text-white' : 'text-slate-400'}>{item.icon}</span>
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Live Telemetry Pill in Sidebar */}
      <div className="p-3 mx-2 mb-2 rounded bg-slate-950 border border-slate-800 text-xs font-mono">
        <div className="flex items-center justify-between text-slate-400 mb-1">
          <span className="flex items-center gap-1">
            <Radio className="w-3.5 h-3.5 text-blue-400 animate-pulse" />
            Throughput
          </span>
          <span className="text-white font-semibold">{currentPps} PPS</span>
        </div>
        <div className="text-[11px] text-slate-400 flex justify-between">
          <span>Threshold:</span>
          <span className="text-slate-300">500 PPS</span>
        </div>
      </div>

      {/* Engine Status Footer */}
      <div className="p-3 border-t border-slate-800 bg-slate-950/60 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span
            className={`w-2.5 h-2.5 rounded-full ${
              engineRunning ? 'bg-emerald-500 ring-2 ring-emerald-500/20 animate-pulse' : 'bg-rose-500'
            }`}
          />
          <div className="text-xs">
            <div className="font-medium text-white">
              {engineRunning ? 'Engine Running' : 'Engine Stopped'}
            </div>
            <div className="text-[11px] text-slate-400 font-mono">
              {engineRunning ? 'Promiscuous Sniffing' : 'Offline / Idle'}
            </div>
          </div>
        </div>
      </div>
    </aside>
  );
};
