import { create } from 'zustand';
import { api } from '@/lib/api';
import { io, Socket } from 'socket.io-client';

export interface Finding {
  type: string;
  injectionFamily: string;
  location: string;
  parameter?: string;
  paramValue?: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  confidence: 'Confirmed' | 'Likely' | 'Possible' | 'Low';
  cvss: number;
  cwe: string;
  owasp: string;
  description: string;
  evidence: string;
  pocPayload: string;
  recommendation: string;
  httpMethod?: string;
  paramLocation?: string;
}

export interface ScanResult {
  targetUrl: string;
  scanTimestamp: string;
  parameters: string[];
  paramValues: Record<string, string>;
  pathSegments: string[];
  domain: string;
  techStackClues: string[];
  potentialInjectionPoints: {
    type: string;
    location: string;
    risk: string;
    reason: string;
  }[];
  findings: Finding[];
  summary: {
    totalPages: number;
    injectionPoints: number;
    parameters: number;
    riskScore: number;
    highestSeverity: string;
    owaspCoverage: string[];
    familiesTested: string[];
    injectionFamilyCounts: Record<string, number>;
  };
}

interface LiveLog {
  timestamp: string;
  message: string;
  level: string;
  tool: string;
}

export type ScanState = 'idle' | 'running' | 'stopping' | 'stopped' | 'completed';

interface ScannerState {
  url: string;
  setUrl: (url: string) => void;
  authorized: boolean;
  setAuthorized: (authorized: boolean) => void;
  loading: boolean;
  result: ScanResult | null;
  error: string;
  setError: (error: string) => void;
  setResult: (result: ScanResult | null) => void;
  
  scanId: string | null;
  scanState: ScanState;
  liveLogs: LiveLog[];
  appendLiveLog: (log: LiveLog) => void;
  
  startScan: () => Promise<void>;
  stopScan: () => Promise<void>;
  reset: () => void;
  resetScan: () => void;
}

// Keep the socket reference outside the store so all actions can access it
let _activeSocket: Socket | null = null;

function disconnectSocket() {
  if (_activeSocket) {
    _activeSocket.removeAllListeners();
    _activeSocket.disconnect();
    _activeSocket = null;
  }
}

export const useScannerStore = create<ScannerState>((set, get) => ({
  url: '',
  setUrl: (url: string) => set({ url }),
  authorized: false,
  setAuthorized: (authorized: boolean) => set({ authorized }),
  loading: false,
  result: null,
  error: '',
  setError: (error: string) => set({ error }),
  setResult: (result: ScanResult | null) => set({ result }),
  
  scanId: null,
  scanState: 'idle',
  liveLogs: [],
  appendLiveLog: (log) => set((state) => {
    const newLogs = [...state.liveLogs, log];
    if (newLogs.length > 300) {
      return { liveLogs: newLogs.slice(newLogs.length - 300) };
    }
    return { liveLogs: newLogs };
  }),

  startScan: async () => {
    const { url, authorized, appendLiveLog, scanState } = get();
    if (!authorized) {
      set({ error: 'You must confirm authorization before scanning.' });
      return;
    }

    // Prevent double-start
    if (scanState === 'running' || scanState === 'stopping') {
      return;
    }

    // Clean up any previous socket before starting fresh
    disconnectSocket();

    // Reset ALL previous scan state — new scan gets clean slate
    set({ 
      loading: true, 
      error: '', 
      result: null, 
      scanId: null, 
      scanState: 'running', 
      liveLogs: [] 
    });

    try {
      // 1. Start scan in Python engine via Node.js
      const res = await api.post('/scanner/analyze', { url, authorized });
      const { scanId } = res.data;
      set({ scanId });

      // 2. Connect to Python WebSocket for live updates via socket.io
      const socket = io('http://localhost:8000', {
        transports: ['websocket'],
        reconnectionAttempts: 3,
        reconnectionDelay: 1000,
      });
      _activeSocket = socket;

      socket.on('connect', () => {
        console.log('Connected to socket.io server');
        appendLiveLog({
          timestamp: new Date().toLocaleTimeString(),
          message: 'Connected to scan engine. Streaming live updates...',
          level: 'info',
          tool: 'system',
        });
      });

      socket.on('tool_output', (data) => {
        if (data.scan_id === scanId) {
          appendLiveLog({
            timestamp: new Date().toLocaleTimeString(),
            message: data.output_line,
            level: data.level || 'info',
            tool: data.tool_name || 'scanner',
          });
        }
      });

      socket.on('crawl_update', (data) => {
        if (data.scan_id === scanId) {
          let message = 'Crawling update';
          if (data.new_url) {
            message = `Discovered endpoint: ${data.new_url}`;
          } else if (data.urls_total !== undefined) {
            message = `Crawl phase complete. Discovered ${data.urls_total} endpoints total.`;
          }

          appendLiveLog({
            timestamp: new Date().toLocaleTimeString(),
            message,
            level: 'info',
            tool: 'crawler',
          });
        }
      });

      socket.on('scan_progress', (data) => {
        if (data.scan_id === scanId) {
          // Sync state if the engine reports a status change
          const phase = data.phase || '';
          if (phase) {
            appendLiveLog({
              timestamp: new Date().toLocaleTimeString(),
              message: `Phase: ${phase} (${data.percentage ?? 0}%)`,
              level: 'info',
              tool: 'orchestrator',
            });
          }
        }
      });

      socket.on('finding_discovered', (data) => {
        if (data.scan_id === scanId && data.finding) {
          appendLiveLog({
            timestamp: new Date().toLocaleTimeString(),
            message: `[FINDING] ${data.finding.title || data.finding.injection_family || 'Vulnerability'} detected at ${data.finding.affected_url || 'unknown'}`,
            level: 'warn',
            tool: 'executor',
          });
        }
      });

      socket.on('scan_completed', async (data) => {
        if (data.scan_id === scanId) {
          disconnectSocket();
          appendLiveLog({
            timestamp: new Date().toLocaleTimeString(),
            message: `Scan completed. ${data.total_findings ?? 0} unique findings in ${((data.duration ?? 0) / 1000).toFixed(1)}s`,
            level: 'info',
            tool: 'system',
          });
          try {
            const resultsRes = await api.get(`/scanner/results/${scanId}?url=${encodeURIComponent(url)}`);
            set({ result: resultsRes.data, loading: false, scanState: 'completed' });
          } catch (err: unknown) {
            const error = err as { response?: { data?: { error?: string } } };
            set({ error: error.response?.data?.error || 'Failed to fetch final results.', loading: false, scanState: 'completed' });
          }
        }
      });

      socket.on('scan_error', (data) => {
        if (data.scan_id === scanId) {
          disconnectSocket();
          set({ error: data.error_message || 'Engine scan error', loading: false, scanState: 'stopped' });
        }
      });

      socket.on('connect_error', (err) => {
        console.error('Socket connect error:', err);
        // Only fail on first connection attempt, not on reconnects
        const currentState = get().scanState;
        if (currentState === 'running') {
          set({ error: 'WebSocket connection to scan engine failed. Ensure the Python engine is running on port 8000.', loading: false, scanState: 'stopped' });
          disconnectSocket();
        }
      });

      socket.on('disconnect', (reason) => {
        console.log('Socket disconnected:', reason);
      });

    } catch (err: unknown) {
      const error = err as { response?: { data?: { error?: string } }, message?: string };
      set({ 
        error: error.response?.data?.error || error.message || 'An unexpected error occurred during the scan.', 
        loading: false,
        scanState: 'stopped'
      });
      disconnectSocket();
    }
  },

  stopScan: async () => {
    const { scanId, scanState, appendLiveLog } = get();
    if (!scanId || scanState !== 'running') return;

    // Immediately update to stopping state to prevent double-clicks
    set({ scanState: 'stopping' });

    try {
      await api.post(`/scanner/${scanId}/stop`);
      disconnectSocket();
      set({ scanState: 'stopped', loading: false });
      appendLiveLog({
        timestamp: new Date().toLocaleTimeString(),
        message: 'Scan stopped by user.',
        level: 'warn',
        tool: 'system',
      });
    } catch (err: any) {
      // Even if the stop request fails, transition to stopped
      disconnectSocket();
      set({ 
        scanState: 'stopped', 
        loading: false,
        error: err.response?.data?.error || 'Failed to stop scan gracefully'
      });
    }
  },

  resetScan: () => {
    disconnectSocket();
    set({ url: '', authorized: false, loading: false, result: null, error: '', scanId: null, scanState: 'idle', liveLogs: [] });
  },
  reset: () => {
    disconnectSocket();
    set({ url: '', authorized: false, loading: false, result: null, error: '', scanId: null, scanState: 'idle', liveLogs: [] });
  },
}));
