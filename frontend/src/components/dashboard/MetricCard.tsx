import React from 'react';

interface MetricCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: React.ReactNode;
  variant?: 'default' | 'success' | 'warning' | 'danger';
}

export const MetricCard: React.FC<MetricCardProps> = ({
  title,
  value,
  subtitle,
  icon,
  variant = 'default',
}) => {
  const getBadgeStyle = () => {
    switch (variant) {
      case 'danger':
        return 'bg-rose-50 text-rose-600 border-rose-200';
      case 'warning':
        return 'bg-amber-50 text-amber-600 border-amber-200';
      case 'success':
        return 'bg-emerald-50 text-emerald-600 border-emerald-200';
      case 'default':
      default:
        return 'bg-blue-50 text-blue-600 border-blue-200';
    }
  };

  return (
    <div className="bg-white rounded-lg border border-slate-200 p-4 shadow-xs flex flex-col justify-between">
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">
          {title}
        </span>
        <div className={`p-2 rounded-md border ${getBadgeStyle()}`}>
          {icon}
        </div>
      </div>

      <div className="mt-3">
        <div className="text-2xl font-bold font-mono text-slate-900 tracking-tight">
          {value}
        </div>
        {subtitle && (
          <p className="text-xs text-slate-500 mt-1 font-mono">{subtitle}</p>
        )}
      </div>
    </div>
  );
};
