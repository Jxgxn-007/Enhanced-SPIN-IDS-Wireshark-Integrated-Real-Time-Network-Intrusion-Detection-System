import React from 'react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ReferenceLine,
  CartesianGrid,
} from 'recharts';
import { Activity, AlertTriangle } from 'lucide-react';
import type { TelemetryPoint } from '../../types/api';

interface TrafficChartProps {
  data: TelemetryPoint[];
  currentPps: number;
  threshold: number;
  isAnomalous: boolean;
}

export const TrafficChart: React.FC<TrafficChartProps> = ({
  data,
  currentPps,
  threshold,
  isAnomalous,
}) => {
  return (
    <div className="bg-white rounded-lg border border-slate-200 p-5 shadow-xs">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 pb-4 mb-4 border-b border-slate-100">
        <div>
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-blue-600" />
            <h3 className="text-sm font-bold text-slate-900 tracking-tight">
              Network Traffic — Packets Per Second (PPS)
            </h3>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Rolling 1-second sliding window telemetry against anomaly threshold
          </p>
        </div>

        <div className="flex items-center gap-2">
          {isAnomalous && (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-200 text-xs font-mono font-semibold animate-pulse">
              <AlertTriangle className="w-3.5 h-3.5" />
              RATE ANOMALY &gt; {threshold} PPS
            </span>
          )}
          <div className="px-2.5 py-1 rounded bg-slate-50 border border-slate-200 text-xs font-mono">
            <span className="text-slate-500">Current: </span>
            <span className={`font-bold ${isAnomalous ? 'text-rose-600' : 'text-slate-900'}`}>
              {currentPps} PPS
            </span>
          </div>
        </div>
      </div>

      {/* Chart Canvas */}
      <div className="h-64 w-full">
        {data.length === 0 ? (
          <div className="h-full flex items-center justify-center text-xs text-slate-400 font-mono">
            Connecting to real-time telemetry stream...
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="ppsGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#2563eb" stopOpacity={0.2} />
                  <stop offset="95%" stopColor="#2563eb" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
              <XAxis
                dataKey="time"
                tick={{ fontSize: 11, fill: '#64748b' }}
                tickLine={false}
                axisLine={{ stroke: '#e2e8f0' }}
              />
              <YAxis
                domain={[0, (dataMax: number) => Math.max(dataMax + 100, 600)]}
                tick={{ fontSize: 11, fill: '#64748b' }}
                tickLine={false}
                axisLine={{ stroke: '#e2e8f0' }}
              />
              <Tooltip
                content={({ active, payload }) => {
                  if (active && payload && payload.length) {
                    const d = payload[0].payload as TelemetryPoint;
                    return (
                      <div className="bg-slate-900 text-white p-2.5 rounded shadow-md border border-slate-800 text-xs font-mono">
                        <div className="text-slate-400">{d.time}</div>
                        <div className="font-bold text-blue-400 mt-0.5">
                          {d.pps} packets/sec
                        </div>
                        <div className="text-[11px] text-slate-400">
                          Threshold: {d.threshold} PPS
                        </div>
                        {d.anomalous && (
                          <div className="text-rose-400 font-semibold mt-1">
                            Threshold Exceeded
                          </div>
                        )}
                      </div>
                    );
                  }
                  return null;
                }}
              />
              {/* Threshold line */}
              <ReferenceLine
                y={threshold}
                stroke="#f43f5e"
                strokeDasharray="4 4"
                label={{
                  value: `ANOMALY THRESHOLD (${threshold} PPS)`,
                  fill: '#f43f5e',
                  fontSize: 10,
                  position: 'insideTopRight',
                }}
              />
              <Area
                type="monotone"
                dataKey="pps"
                stroke="#2563eb"
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#ppsGradient)"
                isAnimationActive={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>

      <div className="mt-3 pt-3 border-t border-slate-100 flex flex-wrap items-center justify-between text-xs text-slate-500">
        <div className="flex items-center gap-4">
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-blue-600" />
            Observed Ingestion Rate
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-0.5 bg-rose-500" />
            Anomaly Threshold (500 PPS)
          </span>
        </div>
        <span className="text-[11px] font-mono text-slate-400">
          Auto-updated via Server-Sent Events (/api/stream)
        </span>
      </div>
    </div>
  );
};
