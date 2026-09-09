'use client';

import { useRef, useEffect } from 'react';
import AssessmentEngineProgress from '@/components/dashboard/AssessmentEngineProgress';
import { Terminal, Radio } from 'lucide-react';

export interface EventLogItem {
  id: number;
  time: string;
  text: string;
  status: string;
  type: 'info' | 'success' | 'warning' | 'critical';
}

export interface RightPanelProps {
  eventLogs: EventLogItem[];
  progressStage?: number;
  progressPercent?: number;
}

export default function RightPanel({
  eventLogs,
  progressStage,
  progressPercent
}: RightPanelProps) {
  const logContainerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [eventLogs]);

  return (
    <div className="space-y-6 font-mono">
      {/* Assessment Engine Progress Component */}
      <AssessmentEngineProgress className="w-full" />

      {/* Recent Activity Log (EVENT LOG) */}
      <div className="p-6 rounded-2xl bg-[#070b1e]/90 border border-[#00d4ff]/35 shadow-[0_0_25px_rgba(0,212,255,0.12)]">
        <div className="flex items-center justify-between border-b border-[#00d4ff]/20 pb-3 mb-4">
          <h3 className="text-sm font-bold text-[#00d4ff] uppercase tracking-widest flex items-center gap-2">
            <Terminal className="w-4 h-4 text-[#00d4ff]" /> EVENT LOG
          </h3>
          <span className="text-[10px] font-mono text-[#00ff00] flex items-center gap-1 font-bold">
            <span className="w-2 h-2 rounded-full bg-[#00ff00] animate-pulse" /> STREAMING
          </span>
        </div>

        {/* Event Log Stream */}
        <div
          ref={logContainerRef}
          className="h-44 overflow-y-auto font-mono text-xs space-y-2 pr-2 scrollbar-thin scrollbar-thumb-[#00d4ff]/30"
        >
          {eventLogs.map((log) => {
            let statusColor = 'text-[#00d4ff]';
            if (log.type === 'critical') statusColor = 'text-[#ff0051] font-bold';
            else if (log.type === 'warning') statusColor = 'text-[#ff9500] font-bold';
            else if (log.type === 'success') statusColor = 'text-[#00ff00] font-bold';

            return (
              <div
                key={log.id}
                className="p-2 rounded bg-[#040714] border border-[#00d4ff]/15 flex items-center justify-between text-[11px] hover:border-[#00d4ff]/40 transition-colors"
              >
                <div className="flex items-center gap-2 truncate">
                  <span className="text-[#a0aec0] font-mono">[{log.time}]</span>
                  <span className="text-slate-200 truncate">{log.text}</span>
                </div>
                <span className={`text-[10px] font-mono uppercase shrink-0 ml-2 ${statusColor}`}>
                  {log.status}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
