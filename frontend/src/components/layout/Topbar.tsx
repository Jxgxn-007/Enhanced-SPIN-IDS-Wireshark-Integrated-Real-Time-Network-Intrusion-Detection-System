import React, { useState, useEffect } from 'react';
import { Play, Square, Zap, RefreshCw, Wifi } from 'lucide-react';
import type { StreamStatus } from '../../hooks/useTelemetry';

interface TopbarProps {
  engineRunning: boolean;
  actionLoading: boolean;
  streamStatus: StreamStatus;
  currentPps: number;
  activeInterface?: string;
  monitoringMode?: string;
  onStartEngine: () => void;
  onStopEngine: () => void;
  onSimulateAnomaly: () => void;
  onRefresh: () => void;
}

export const Topbar: React.FC<TopbarProps> = ({
  engineRunning,
  actionLoading,
  streamStatus,
  currentPps,
  activeInterface,
  monitoringMode,
  onStartEngine,
  onStopEngine,
  onSimulateAnomaly,
  onRefresh,
}) => {
  const [timeStr, setTimeStr] = useState<string>('');

  useEffect(() => {
    const updateTime = () => {
      setTimeStr(new Date().toLocaleTimeString('en-GB', { hour12: false }));
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const getStreamBadge = () => {
    switch (streamStatus) {
      case 'LIVE':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 text-xs font-mono font-medium">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            LIVE STREAM
          </span>
        );
      case 'RECONNECTING':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-amber-50 text-amber-700 border border-amber-200 text-xs font-mono font-medium">
            <span className="w-2 h-2 rounded-full bg-amber-500 animate-pulse" />
            RECONNECTING
          </span>
        );
      case 'DISCONNECTED':
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-100 text-slate-600 border border-slate-200 text-xs font-mono font-medium">
            <span className="w-2 h-2 rounded-full bg-slate-400" />
            OFFLINE
          </span>
        );
    }
  };

  return (
    <header className="h-16 bg-white border-b border-slate-200 px-6 flex items-center justify-between shrink-0 select-none">
      {/* Title & Info */}
      <div className="flex items-center gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-base font-bold text-slate-900 tracking-tight">
              SPIN-IDS Network Intrusion Detection System
            </h1>
            <span
              className="inline-flex items-center gap-1 text-xs px-2.5 py-0.5 rounded bg-slate-100 text-slate-700 font-mono border border-slate-200 truncate max-w-[240px]"
              title={activeInterface || 'Wi-Fi / Ethernet'}
            >
              <Wifi className="w-3 h-3 text-blue-600 shrink-0" />
              {activeInterface ? activeInterface.split(' ')[0] : 'Npcap Live'}
              {monitoringMode === 'REAL_INTERFACE' ? ' (Real)' : ' (Sim)'}
            </span>
          </div>
          <p className="text-xs text-slate-500">
            2D-CNN feature tensor classification on raw sequential packet windows
          </p>
        </div>
      </div>

      {/* Real-time Status & Quick Controls */}
      <div className="flex items-center gap-3">
        {/* Stream Status */}
        {getStreamBadge()}

        {/* Real-time Rate Chip */}
        <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-50 border border-slate-200 text-xs font-mono text-slate-700">
          <span className="text-slate-400">PPS:</span>
          <span className="font-semibold text-slate-900">{currentPps}</span>
        </div>

        {/* Clock */}
        <div className="hidden md:block px-2.5 py-1 rounded bg-slate-50 border border-slate-200 text-xs font-mono text-slate-600">
          {timeStr}
        </div>

        {/* Refresh button */}
        <button
          onClick={onRefresh}
          title="Refresh Data"
          className="p-1.5 rounded text-slate-500 hover:text-slate-800 hover:bg-slate-100 transition-colors"
        >
          <RefreshCw className="w-4 h-4" />
        </button>

        {/* Engine Controls */}
        <div className="flex items-center gap-1.5 pl-2 border-l border-slate-200">
          {engineRunning ? (
            <button
              onClick={onStopEngine}
              disabled={actionLoading}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-300 transition-colors disabled:opacity-50"
            >
              <Square className="w-3.5 h-3.5 text-rose-600 fill-rose-600" />
              Stop Engine
            </button>
          ) : (
            <button
              onClick={onStartEngine}
              disabled={actionLoading}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded bg-emerald-600 hover:bg-emerald-700 text-white shadow-xs transition-colors disabled:opacity-50"
            >
              <Play className="w-3.5 h-3.5 fill-white" />
              Start Engine
            </button>
          )}

          <button
            onClick={onSimulateAnomaly}
            disabled={actionLoading}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded bg-blue-600 hover:bg-blue-700 text-white shadow-xs transition-colors disabled:opacity-50"
          >
            <Zap className="w-3.5 h-3.5" />
            Simulate Anomaly
          </button>
        </div>
      </div>
    </header>
  );
};
