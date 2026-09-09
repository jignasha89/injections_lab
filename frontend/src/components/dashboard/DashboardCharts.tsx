'use client';

import { Chart as ChartJS, Tooltip, Legend, CategoryScale, LinearScale, BarElement, Title } from 'chart.js';
import { Bar } from 'react-chartjs-2';

ChartJS.register(Tooltip, Legend, CategoryScale, LinearScale, BarElement, Title);

interface DashboardChartsProps {
  categoryStats: { [key: string]: number };
  owaspStats: { [key: string]: number };
}

export default function DashboardCharts({ categoryStats, owaspStats }: DashboardChartsProps) {
  // Horizontal bar — sorted by count descending for triage
  const sortedCategories = Object.entries(categoryStats).sort((a, b) => b[1] - a[1]);
  const triageLabels = sortedCategories.map(c => c[0]);
  const triageValues = sortedCategories.map(c => c[1]);
  
  const horizontalBarData = {
    labels: triageLabels,
    datasets: [
      {
        label: 'Findings',
        data: triageValues,
        backgroundColor: [
          'rgba(239, 68, 68, 0.85)',   // Critical #EF4444
          'rgba(249, 115, 22, 0.85)',  // High #F97316
          'rgba(234, 179, 8, 0.85)',   // Medium #EAB308
          'rgba(16, 185, 129, 0.85)',  // Low #10B981
          'rgba(14, 165, 233, 0.85)',  // Info #0EA5E9
        ],
        borderRadius: 4,
        barThickness: 12,
      },
    ],
  };

  const horizontalBarOptions = {
    indexAxis: 'y' as const,
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: '#1A202C', // surface-hover
        titleColor: '#F8FAFC',
        bodyColor: '#94A3B8',
        borderColor: '#2D3748', // border-strong
        borderWidth: 1,
        padding: 12,
        boxPadding: 6,
        usePointStyle: true,
        titleFont: { family: 'IBM Plex Sans', size: 13, weight: 600 as const },
        bodyFont: { family: 'IBM Plex Mono', size: 12 },
      }
    },
    scales: {
      x: {
        grid: { color: 'rgba(31, 39, 55, 0.5)' }, // border-subtle
        ticks: {
          color: '#94A3B8',
          font: { size: 10, family: 'IBM Plex Mono' as const },
          stepSize: 1,
        },
        border: { display: false },
      },
      y: {
        grid: { display: false },
        ticks: {
          color: '#F8FAFC',
          font: { size: 12, family: 'IBM Plex Sans' as const, weight: 500 as const },
          callback: function(this: any, _val: any, index: number) {
            const label = triageLabels[index] || '';
            return label.length > 22 ? label.slice(0, 20) + '…' : label;
          },
        },
        border: { display: false },
      },
    },
  };

  // OWASP bar chart
  const owaspShortLabels: Record<string, string> = {
    'A01: Access Control': 'A01',
    'A03: Injection': 'A03',
    'A07: Identification Failures': 'A07',
    'A09: Logging': 'A09',
  };

  const barLabels = Object.keys(owaspStats);
  const barDisplayLabels = barLabels.map(l => owaspShortLabels[l] || l);
  const barValues = Object.values(owaspStats);

  const barData = {
    labels: barDisplayLabels,
    datasets: [
      {
        label: 'Identified risks',
        data: barValues,
        backgroundColor: 'rgba(59, 130, 246, 0.15)', // brand-primary
        borderColor: '#3B82F6',
        borderWidth: 1,
        borderRadius: 4,
        hoverBackgroundColor: 'rgba(59, 130, 246, 0.25)',
        barThickness: 32,
      },
    ],
  };

  const barOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: '#1A202C',
        titleColor: '#F8FAFC',
        bodyColor: '#94A3B8',
        borderColor: '#2D3748',
        borderWidth: 1,
        padding: 12,
        titleFont: { family: 'IBM Plex Sans', size: 13, weight: 600 as const },
        bodyFont: { family: 'IBM Plex Mono', size: 12 },
        callbacks: {
          title: function(items: any[]) {
            const idx = items[0]?.dataIndex;
            return barLabels[idx] || '';
          }
        }
      }
    },
    scales: {
      x: {
        grid: { display: false },
        ticks: {
          color: '#3B82F6', // brand-primary for emphasis
          font: { size: 12, family: 'IBM Plex Mono' as const, weight: 600 as const },
          maxRotation: 0,
          minRotation: 0,
        },
        border: { display: false },
      },
      y: {
        grid: { color: 'rgba(31, 39, 55, 0.5)' },
        ticks: {
          color: '#94A3B8',
          font: { size: 10, family: 'IBM Plex Mono' as const },
          stepSize: 1,
        },
        border: { display: false },
      },
    },
  };

  // Full label legend for OWASP categories
  const owaspLegend = barLabels.map((label, i) => ({
    short: barDisplayLabels[i],
    full: label,
    value: barValues[i],
  }));

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* Triage horizontal bar */}
      <div className="cyber-card p-6 flex flex-col h-[360px] shadow-sm">
        <div className="flex items-center justify-between mb-6 border-b border-border-subtle pb-4">
          <div>
            <h3 className="text-sm font-semibold text-text-primary">
              Vector triage
            </h3>
            <p className="text-xs text-text-secondary mt-1">Sorted by frequency</p>
          </div>
        </div>
        <div className="flex-1 relative min-h-0">
          <Bar data={horizontalBarData} options={horizontalBarOptions} />
        </div>
      </div>

      {/* OWASP coverage */}
      <div className="cyber-card p-6 flex flex-col h-[360px] shadow-sm">
        <div className="flex items-center justify-between mb-6 border-b border-border-subtle pb-4">
          <div>
            <h3 className="text-sm font-semibold text-text-primary">
              OWASP Top 10
            </h3>
            <p className="text-xs text-text-secondary mt-1">Risk taxonomy coverage</p>
          </div>
        </div>
        <div className="flex-1 relative min-h-0">
          <Bar data={barData} options={barOptions} />
        </div>
        {/* Category legend */}
        <div className="mt-4 pt-4 border-t border-border-subtle flex flex-wrap gap-x-6 gap-y-2">
          {owaspLegend.map(item => (
            <span key={item.short} className="text-[11px] text-text-secondary font-mono flex items-center gap-2">
              <span className="text-brand-primary font-semibold px-1.5 py-0.5 bg-brand-primary/10 rounded">{item.short}</span> 
              <span>{item.full.split(': ')[1]}</span>
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}
