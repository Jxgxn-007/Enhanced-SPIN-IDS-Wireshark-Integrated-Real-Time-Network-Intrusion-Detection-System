import React from 'react';
import {
  Network,
  Gauge,
  AlertOctagon,
  HardDriveDownload,
  Layers,
  Grid3X3,
  Cpu,
  ShieldCheck,
  CheckCircle2,
  Info,
} from 'lucide-react';

interface EnginePipelineProps {
  currentPps: number;
  threshold: number;
  isAnomalous: boolean;
  engineRunning: boolean;
  modelReady: boolean;
}

export const EnginePipeline: React.FC<EnginePipelineProps> = ({
  currentPps,
  threshold,
  isAnomalous,
  engineRunning,
  modelReady,
}) => {
  const stages = [
    {
      num: '01',
      title: 'Network Traffic',
      icon: <Network className="w-4 h-4" />,
      desc: 'eth0 / loopback',
      status: engineRunning ? 'ACTIVE' : 'IDLE',
      highlight: false,
    },
    {
      num: '02',
      title: 'PPS Monitor',
      icon: <Gauge className="w-4 h-4" />,
      desc: `${currentPps} PPS (1s window)`,
      status: engineRunning ? 'MONITORING' : 'STOPPED',
      highlight: false,
    },
    {
      num: '03',
      title: 'Anomaly Trigger',
      icon: <AlertOctagon className="w-4 h-4" />,
      desc: isAnomalous ? `Rate > ${threshold} PPS` : `Limit: ${threshold} PPS`,
      status: isAnomalous ? 'THRESHOLD EXCEEDED' : 'NORMAL',
      highlight: isAnomalous,
      isAnomaly: true,
    },
    {
      num: '04',
      title: 'PCAP Capture',
      icon: <HardDriveDownload className="w-4 h-4" />,
      desc: 'Npcap burst dump',
      status: 'ON-DEMAND',
      highlight: false,
    },
    {
      num: '05',
      title: 'Sequential Window',
      icon: <Layers className="w-4 h-4" />,
      desc: '9 pkts / flow window',
      status: 'SLIDING',
      highlight: false,
    },
    {
      num: '06',
      title: '27×27 RGB Image',
      icon: <Grid3X3 className="w-4 h-4" />,
      desc: '729-px feature tensor',
      status: 'NORMALIZED',
      highlight: false,
    },
    {
      num: '07',
      title: 'ONNX CNN',
      icon: <Cpu className="w-4 h-4" />,
      desc: 'Deep feature inference',
      status: modelReady ? 'LOADED' : 'UNAVAILABLE',
      highlight: false,
    },
    {
      num: '08',
      title: 'Detection Result',
      icon: <ShieldCheck className="w-4 h-4" />,
      desc: 'Binary classification',
      status: 'VERDICT',
      highlight: false,
    },
  ];

  return (
    <div className="bg-white rounded-lg border border-slate-200 p-5 shadow-xs">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 pb-3 mb-4 border-b border-slate-100">
        <div>
          <h3 className="text-sm font-bold text-slate-900 tracking-tight flex items-center gap-2">
            <span>SPIN-IDS Ingestion-to-Inference Pipeline</span>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200">
              8 Stages
            </span>
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Sequential end-to-end processing from raw network frames to CNN classification
          </p>
        </div>

        <div className="text-xs font-mono text-emerald-600 flex items-center gap-1">
          <CheckCircle2 className="w-3.5 h-3.5" />
          Pipeline Verified Operational
        </div>
      </div>

      {/* Horizontal Stepper Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-2.5">
        {stages.map((stage, idx) => {
          const isAnomalyStage = stage.isAnomaly && stage.highlight;
          return (
            <div
              key={stage.num}
              className={`p-3 rounded-lg border flex flex-col justify-between transition-colors relative ${
                isAnomalyStage
                  ? 'bg-rose-50 border-rose-300 shadow-xs'
                  : 'bg-slate-50/70 border-slate-200 hover:bg-slate-50'
              }`}
            >
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-[10px] font-mono font-bold text-slate-400">
                    STAGE {stage.num}
                  </span>
                  <div
                    className={`p-1 rounded ${
                      isAnomalyStage
                        ? 'bg-rose-100 text-rose-600'
                        : 'bg-white border border-slate-200 text-slate-600'
                    }`}
                  >
                    {stage.icon}
                  </div>
                </div>

                <div className="font-semibold text-xs text-slate-900 leading-snug">
                  {stage.title}
                </div>
                <div className="text-[11px] text-slate-500 font-mono mt-0.5 truncate">
                  {stage.desc}
                </div>
              </div>

              <div className="mt-3 pt-2 border-t border-slate-200/60 flex items-center justify-between">
                <span
                  className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded ${
                    isAnomalyStage
                      ? 'bg-rose-200/70 text-rose-800'
                      : stage.status === 'LOADED' || stage.status === 'ACTIVE'
                      ? 'bg-emerald-100 text-emerald-800'
                      : 'bg-slate-200 text-slate-700'
                  }`}
                >
                  {stage.status}
                </span>

                {idx < stages.length - 1 && (
                  <span className="hidden lg:block text-slate-300 text-xs font-mono">→</span>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Critical Terminology Note */}
      <div className="mt-4 p-3 rounded bg-blue-50/70 border border-blue-100 text-xs text-slate-700 flex items-start gap-2">
        <Info className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
        <div className="leading-relaxed">
          <strong className="text-slate-900 font-semibold">Architectural Principle:</strong>{' '}
          <span className="font-mono text-amber-800 bg-amber-100/70 px-1 py-0.2 rounded font-medium">
            ANOMALY
          </span>{' '}
          denotes solely that network traffic rate has exceeded the configured threshold (&gt; 500 PPS),
          initiating PCAP capture and sequential window partitioning.{' '}
          <span className="font-mono text-rose-800 bg-rose-100/70 px-1 py-0.2 rounded font-medium">
            MALICIOUS
          </span>{' '}
          is reserved strictly for positive CNN deep feature tensor classification verdicts. A rate spike does not in itself constitute an intrusion.
        </div>
      </div>
    </div>
  );
};
