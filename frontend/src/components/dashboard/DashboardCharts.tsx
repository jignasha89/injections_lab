'use client';

import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement, Title } from 'chart.js';
import { Pie, Bar } from 'react-chartjs-2';

// Register ChartJS elements
ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement, Title);

interface DashboardChartsProps {
  categoryStats: { [key: string]: number };
  owaspStats: { [key: string]: number };
}

export default function DashboardCharts({ categoryStats, owaspStats }: DashboardChartsProps) {
  // 1. Pie Chart Data: Categories of Injection
  const pieLabels = Object.keys(categoryStats);
  const pieValues = Object.values(categoryStats);
  
  const pieData = {
    labels: pieLabels,
    datasets: [
      {
        label: 'Injection Types Count',
        data: pieValues,
        backgroundColor: [
          'rgba(37, 99, 235, 0.65)',  // Accent Blue
          'rgba(9, 9, 11, 0.65)',     // Primary Black
          'rgba(220, 38, 38, 0.65)',  // Danger Red
          'rgba(22, 163, 74, 0.65)',  // Success Green
          'rgba(234, 88, 12, 0.65)',  // Warning Orange
        ],
        borderColor: [
          '#2563eb',
          '#09090b',
          '#dc2626',
          '#16a34a',
          '#ea580c',
        ],
        borderWidth: 1.5,
      },
    ],
  };

  const pieOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'bottom' as const,
        labels: {
          color: '#0f172a', // Slate 900
          font: { size: 16, family: 'Inter', weight: 'bold' as const },
          boxWidth: 16,
          padding: 16,
        },
      },
    },
  };

  // 2. Bar Chart Data: OWASP Categories Completed
  const barLabels = Object.keys(owaspStats);
  const barValues = Object.values(owaspStats);

  const barData = {
    labels: barLabels,
    datasets: [
      {
        label: 'Completed Labs Count',
        data: barValues,
        backgroundColor: 'rgba(37, 99, 235, 0.25)',
        borderColor: '#2563eb',
        borderWidth: 1.5,
        borderRadius: 6,
        hoverBackgroundColor: 'rgba(37, 99, 235, 0.45)',
      },
    ],
  };

  const barOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        display: false,
      },
    },
    scales: {
      x: {
        grid: {
          color: 'rgba(0, 0, 0, 0.05)',
        },
        ticks: {
          color: '#0f172a', // High contrast slate-900
          font: { size: 16, family: 'Inter', weight: 'bold' as const },
        },
      },
      y: {
        grid: {
          color: 'rgba(0, 0, 0, 0.05)',
        },
        ticks: {
          color: '#0f172a', // High contrast slate-900
          font: { size: 16, family: 'Inter', weight: 'bold' as const },
          stepSize: 1,
        },
      },
    },
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
      {/* Category Pie Chart */}
      <div className="bg-white p-6 rounded-3xl border border-slate-200 shadow-sm hover:shadow-md transition-all h-[480px]">
        <h3 className="text-base md:text-lg font-black tracking-wide text-slate-900 uppercase mb-4">
          Injection Categories Distribution
        </h3>
        <div className="flex-1 relative min-h-0 h-[380px]">
          <Pie data={pieData} options={pieOptions} />
        </div>
      </div>

      {/* OWASP Coverage Bar Chart */}
      <div className="bg-white p-6 rounded-3xl border border-slate-200 shadow-sm hover:shadow-md transition-all h-[480px]">
        <h3 className="text-base md:text-lg font-black tracking-wide text-slate-900 uppercase mb-4">
          OWASP Top 10 Lab Completion
        </h3>
        <div className="flex-1 relative min-h-0 h-[380px]">
          <Bar data={barData} options={barOptions} />
        </div>
      </div>
    </div>
  );
}
