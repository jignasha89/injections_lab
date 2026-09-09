'use client';

import { useEffect, useRef, useState, useMemo } from 'react';
import dynamic from 'next/dynamic';
import { ShieldAlert, X, Activity, Zap, Radio, ArrowUpRight } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

const Globe = dynamic(() => import('react-globe.gl'), { ssr: false });

export interface CompactGlobeRegion {
  label: string;
  lat: number;
  lng: number;
  events: number;
  rate: number;
  color: string;
  threatLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  vector: string;
  evasion: string;
  endpoints: string[];
}

export const DEFAULT_THREAT_REGIONS: CompactGlobeRegion[] = [
  {
    label: "GERMANY",
    lat: 51.16,
    lng: 10.45,
    events: 11157,
    rate: 14,
    color: "#00d4ff", // Cyan
    threatLevel: "MEDIUM",
    vector: "LDAP & XPath Injection Vectors",
    evasion: "84.1%",
    endpoints: ["/api/v1/directory", "/api/auth/saml"]
  },
  {
    label: "UK",
    lat: 51.5,
    lng: -0.12,
    events: 23321,
    rate: 22,
    color: "#ec4899", // Pink
    threatLevel: "HIGH",
    vector: "Blind SSRF & Header Injection",
    evasion: "88.6%",
    endpoints: ["/api/gateway/proxy", "/auth/oauth/token"]
  },
  {
    label: "JAPAN",
    lat: 35.67,
    lng: 139.65,
    events: 10560,
    rate: 12,
    color: "#3b82f6", // Blue
    threatLevel: "MEDIUM",
    vector: "DOM XSS & Template Injection",
    evasion: "86.2%",
    endpoints: ["/api/v1/render", "/api/notifications"]
  },
  {
    label: "CHINA",
    lat: 35.86,
    lng: 104.19,
    events: 38900,
    rate: 45,
    color: "#ff9500", // Orange
    threatLevel: "CRITICAL",
    vector: "Time-Based SQLi & Remote Code Exec",
    evasion: "98.4%",
    endpoints: ["/api/v2/auth/login", "/query/graphql", "/admin/exec"]
  },
  {
    label: "INDIA",
    lat: 20.59,
    lng: 78.96,
    events: 17035,
    rate: 25,
    color: "#10b981", // Green
    threatLevel: "HIGH",
    vector: "Error-Based SQLi & Form Fuzzing",
    evasion: "93.1%",
    endpoints: ["/api/v1/search", "/store/item/details"]
  },
  {
    label: "VIETNAM",
    lat: 14.05,
    lng: 108.27,
    events: 9654,
    rate: 15,
    color: "#00d4ff", // Cyan (reused for variety)
    threatLevel: "MEDIUM",
    vector: "Reflected XSS & Path Traversal",
    evasion: "85.4%",
    endpoints: ["/api/v1/download", "/view/file"]
  },
  {
    label: "SOUTH KOREA",
    lat: 35.9,
    lng: 127.76,
    events: 15098,
    rate: 18,
    color: "#3b82f6", // Blue
    threatLevel: "HIGH",
    vector: "Command Injection & API Fuzzing",
    evasion: "89.2%",
    endpoints: ["/api/v1/system/exec", "/api/v2/health"]
  },
  {
    label: "SINGAPORE",
    lat: 1.35,
    lng: 103.81,
    events: 13585,
    rate: 16,
    color: "#ff9500", // Orange
    threatLevel: "HIGH",
    vector: "REST API Fuzzing & Out-of-Band SQLi",
    evasion: "92.0%",
    endpoints: ["/api/v1/trading/exec", "/api/v1/wallet"]
  }
];

// Top particle arcs between threat nodes
const TOP_ARCS_DATA = [
  { startLat: 35.86, startLng: 104.19, endLat: 51.5, endLng: -0.12, color: ['#ff9500', '#ec4899'] }, // China -> UK
  { startLat: 20.59, startLng: 78.96, endLat: 51.16, endLng: 10.45, color: ['#ff9500', '#3b82f6'] },  // India -> Germany
  { startLat: 35.67, startLng: 139.65, endLat: 35.86, endLng: 104.19, color: ['#3b82f6', '#ff9500'] }, // Japan -> China
  { startLat: 1.35, startLng: 103.81, endLat: 35.9, endLng: 127.76, color: ['#ec4899', '#3b82f6'] }    // Singapore -> S. Korea
];

export interface CompactGlobeProps {
  data?: CompactGlobeRegion[];
  width?: number;
  height?: number;
  className?: string;
  onSelectRegion?: (region: CompactGlobeRegion) => void;
}

export default function CompactGlobe({
  data = DEFAULT_THREAT_REGIONS,
  width = 350,
  height = 300,
  className = '',
  onSelectRegion
}: CompactGlobeProps) {
  const globeRef = useRef<any>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const idleTimerRef = useRef<NodeJS.Timeout | null>(null);
  
  const [mounted, setMounted] = useState(false);
  const [hoveredRegion, setHoveredRegion] = useState<CompactGlobeRegion | null>(null);
  const [selectedRegion, setSelectedRegion] = useState<CompactGlobeRegion | null>(null);

  // Live count state
  const countersRef = useRef<Record<string, number>>(
    Object.fromEntries(data.map(r => [r.label, r.events]))
  );

  useEffect(() => {
    setMounted(true);
  }, []);

  // Live event ticker increment simulation
  useEffect(() => {
    const interval = setInterval(() => {
      for (const r of data) {
        countersRef.current[r.label] += Math.floor(Math.random() * (r.rate / 4)) + 1;
        const countEl = document.getElementById(`cg-count-${r.label}`);
        if (countEl) {
          countEl.textContent = countersRef.current[r.label].toLocaleString();
        }
        const persistentEl = document.getElementById(`persistent-count-${r.label}`);
        if (persistentEl) {
          persistentEl.textContent = countersRef.current[r.label].toLocaleString();
        }
      }
    }, 1500);

    return () => clearInterval(interval);
  }, [data]);

  // Idle timeout auto-rotate reset (5 seconds idle)
  const resetIdleTimer = () => {
    if (globeRef.current) {
      const controls = globeRef.current.controls();
      if (controls) {
        controls.autoRotate = false;
      }
    }
    if (idleTimerRef.current) clearTimeout(idleTimerRef.current);
    idleTimerRef.current = setTimeout(() => {
      if (globeRef.current) {
        const controls = globeRef.current.controls();
        if (controls) controls.autoRotate = true;
      }
    }, 5000);
  };

  // Generate lightweight HTML elements for compact markers + tooltips
  const htmlElementsMap = useMemo(() => {
    const map: Record<string, HTMLElement> = {};

    for (const r of data) {
      const wrapper = document.createElement('div');
      wrapper.className = 'group relative flex flex-col items-center justify-center pointer-events-auto cursor-pointer select-none';

      // Compact Marker Dot
      const dotContainer = document.createElement('div');
      dotContainer.style.cssText = 'position:relative;display:flex;align-items:center;justify-content:center;width:14px;height:14px;';

      // Pulse ring for critical/high threat
      if (r.label === 'CHINA' || r.threatLevel === 'CRITICAL') {
        const pulse = document.createElement('div');
        pulse.style.cssText = `position:absolute;width:12px;height:12px;border-radius:50%;border:1px solid ${r.color};box-shadow:0 0 8px ${r.color};animation:ping 1.8s cubic-bezier(0,0,0.2,1) infinite;opacity:0.75;`;
        dotContainer.appendChild(pulse);
      }

      // Solid 5px Dot
      const dot = document.createElement('div');
      dot.style.cssText = `width:5px;height:5px;border-radius:50%;background:${r.color};box-shadow:0 0 8px ${r.color}, 0 0 14px ${r.color}88;transition:transform 0.2s ease;z-index:2;`;
      dotContainer.appendChild(dot);

      // Persistent label box for country threat info
      const label = document.createElement('div');
      label.className = 'region-label';
      // Determine vertical placement: above for northern latitudes, below for southern
      const verticalPos = r.lat >= 0 ? 'top' : 'bottom';
      const verticalOffset = r.lat >= 0 ? '-40px' : '40px';
      // Add small random jitter to reduce label overlap
      const jitterX = (Math.random() - 0.5) * 30; // -15px to 15px
      const jitterY = (Math.random() - 0.5) * 20; // -10px to 10px
      label.style.cssText = `
           position: absolute;
           ${verticalPos}: ${verticalOffset};
           left: 50%;
           transform: translateX(-50%) translateY(${jitterY}px);
           /* jitter offset horizontally */
           margin-left: ${jitterX}px;
           max-width: 140px;
           background: #0a0e27; /* solid dark navy */
           border: 1px solid ${r.color};
           box-shadow: 0 0 12px ${r.color}, 0 0 16px ${r.color}99; /* neon glow */
           border-radius: 8px;
           padding: 8px 12px;
           font-family: 'Inter', sans-serif;
           font-size: 13px;
           font-weight: 800;
           text-transform: uppercase;
           font-variant: small-caps;
           color: #e0f7ff;
           text-align: center;
           z-index: 10;
         `;

      label.innerHTML = `
         <div style="font-weight: 800; color: ${r.color}; font-size: 14px; margin-bottom: 4px;">
           ${r.label}
         </div>
         <div style="font-weight: 700; font-size: 13px; color: #e0f7ff;">
           <span id="label-count-${r.label}">${r.events.toLocaleString()}</span> <span style="font-size: 10px; color: #a0aec0;">EVENTS/HR</span>
         </div>
       `;

      wrapper.appendChild(label);
      wrapper.appendChild(dotContainer);

      // Mouse events (keep hover effects for dot, but not for label visibility)
      wrapper.onmouseenter = () => {
        dot.style.transform = 'scale(1.8)';
        setHoveredRegion(r);
      };

      wrapper.onmouseleave = () => {
        dot.style.transform = 'scale(1)';
        setHoveredRegion(null);
      };

      wrapper.onclick = (e) => {
        e.stopPropagation();
        setSelectedRegion(r);
        if (onSelectRegion) onSelectRegion(r);
      };

      map[r.label] = wrapper;
    }

    return map;
  }, [data, onSelectRegion]);

  if (!mounted) return null;

  return (
    <div
      ref={containerRef}
      onMouseDown={resetIdleTimer}
      onWheel={resetIdleTimer}
      className={`relative flex items-center justify-center overflow-hidden rounded-xl bg-transparent select-none p-4 ${className}`}
      style={{ width: `${width}px`, height: `${height}px` }}
    >
      {/* Background Star Dots (Twinkling Effect) */}
      <div className="absolute inset-0 pointer-events-none opacity-40 overflow-hidden">
        <div className="absolute top-4 left-6 w-1 h-1 bg-cyan-300 rounded-full animate-ping" style={{ animationDuration: '3s' }} />
        <div className="absolute top-12 right-10 w-1 h-1 bg-white rounded-full opacity-60" />
        <div className="absolute bottom-8 left-12 w-1 h-1 bg-amber-300 rounded-full animate-ping" style={{ animationDuration: '4s' }} />
        <div className="absolute bottom-14 right-14 w-1.5 h-1.5 bg-cyan-400 rounded-full opacity-80" />
      </div>

      {/* Occasional Horizontal Scanline Line Overlay */}
      <div className="absolute inset-0 pointer-events-none z-10 opacity-20 bg-[linear-gradient(to_bottom,transparent_0px,rgba(0,212,255,0.08)_1px,transparent_3px)] bg-[size:100%_8px]" />

      {/* Subtle Glow Ring Around Globe Edges */}
      <div className="absolute inset-0 flex items-center justify-center pointer-events-none z-0">
        <div className="w-[200px] h-[200px] rounded-full border border-cyan-400/25 shadow-[0_0_45px_rgba(0,212,255,0.25),inset_0_0_30px_rgba(0,212,255,0.15)] animate-pulse" />
      </div>

      {/* Three.js Globe Container */}
      <div className="relative z-10 flex items-center justify-center">
        <Globe
          ref={globeRef}
          width={width - 10}
          height={height - 10}
          backgroundColor="rgba(0,0,0,0)"
          globeImageUrl="//unpkg.com/three-globe/example/img/earth-blue-marble.jpg"
          bumpImageUrl="//unpkg.com/three-globe/example/img/earth-topology.png"
          atmosphereColor="#00d4ff"
          atmosphereAltitude={0.22}
          htmlElementsData={data}
          htmlElement={(d: object) => htmlElementsMap[(d as CompactGlobeRegion).label]}
          htmlAltitude={0.04}
          arcsData={TOP_ARCS_DATA}
          arcColor={(d: any) => d.color}
          arcDashLength={0.4}
          arcDashGap={0.2}
          arcDashInitialGap={() => Math.random()}
          arcDashAnimateTime={2200}
          arcStroke={1.1}
          enablePointerInteraction={true}
          onGlobeReady={() => {
            setTimeout(() => {
              if (globeRef.current) {
                const controls = globeRef.current.controls();
                if (controls) {
                  controls.autoRotate = true;
                  controls.autoRotateSpeed = 0.85;
                  controls.enableZoom = true;
                  controls.minDistance = 150;
                  controls.maxDistance = 400;
                }
                // Position view centered over Europe/Asia/Americas
                globeRef.current.pointOfView({ lat: 20, lng: 10, altitude: 2.3 }, 800);
              }
            }, 100);
          }}
        />
      </div>

      {/* Interactive Detail Modal on Click */}
      <AnimatePresence>
        {selectedRegion && (
          <motion.div
            initial={{ opacity: 0, scale: 0.9, y: 8 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.9, y: 8 }}
            transition={{ duration: 0.18 }}
            className="absolute inset-2 z-30 bg-[#0a0e27]/95 border border-cyan-500/40 rounded-xl p-3.5 backdrop-blur-md shadow-[0_0_25px_rgba(0,212,255,0.3)] text-slate-100 flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center justify-between border-b border-cyan-500/20 pb-2 mb-2">
                <div className="flex items-center gap-2">
                  <div
                    className="w-2.5 h-2.5 rounded-full shadow-[0_0_8px_currentColor]"
                    style={{ backgroundColor: selectedRegion.color, color: selectedRegion.color }}
                  />
                  <h4 className="text-xs font-mono font-bold tracking-wider text-white">
                    {selectedRegion.label} THREAT NODE
                  </h4>
                </div>
                <button
                  onClick={() => setSelectedRegion(null)}
                  className="p-1 rounded text-slate-400 hover:text-white hover:bg-cyan-500/20 transition-colors"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>

              <div className="grid grid-cols-2 gap-2 text-[10px] font-mono mb-2">
                <div className="p-1.5 rounded bg-[#070a1c] border border-cyan-500/20">
                  <span className="text-slate-400 block">Threat Level</span>
                  <span
                    className="font-bold inline-block mt-0.5 px-1.5 py-0.2 rounded border"
                    style={{
                      color: selectedRegion.color,
                      borderColor: selectedRegion.color,
                      backgroundColor: `${selectedRegion.color}22`
                    }}
                  >
                    {selectedRegion.threatLevel}
                  </span>
                </div>

                <div className="p-1.5 rounded bg-[#070a1c] border border-cyan-500/20">
                  <span className="text-slate-400 block">Events / Hour</span>
                  <span className="font-bold text-cyan-300 block mt-0.5">
                    {(countersRef.current[selectedRegion.label] || selectedRegion.events).toLocaleString()}
                  </span>
                </div>
              </div>

              <div className="p-1.5 rounded bg-[#070a1c] border border-cyan-500/20 mb-2">
                <span className="text-[9px] font-mono text-slate-400 block">Primary Attack Vector</span>
                <span className="text-[10px] font-bold text-white block mt-0.5 truncate">
                  {selectedRegion.vector}
                </span>
              </div>
            </div>

            <div className="flex items-center justify-between pt-1 border-t border-cyan-500/20 text-[9px] font-mono">
              <span className="text-emerald-400 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" /> Live Telemetry
              </span>
              <button
                onClick={() => setSelectedRegion(null)}
                className="px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-bold hover:bg-cyan-500/30 transition-colors"
              >
                Dismiss
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
