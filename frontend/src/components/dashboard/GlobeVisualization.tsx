'use client';

import { useEffect, useRef, useState, useMemo } from 'react';
import dynamic from 'next/dynamic';
import { ShieldAlert, X, Activity, Zap, Radio, Lock, ArrowUpRight } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

const Globe = dynamic(() => import('react-globe.gl'), { ssr: false });

export interface RegionData {
  label: string;
  lat: number;
  lng: number;
  base: number;
  rate: number;
  color: string;
  threatLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  topVector: string;
  evasionRate: string;
  activeEndpoints: string[];
  offsetDir: 'up' | 'down' | 'left' | 'right';
}

const RAW_COUNTRIES: Array<[string, number, number, number, number, string, RegionData['threatLevel'], string, string, string[], 'up' | 'down' | 'left' | 'right']> = [
  ["CHINA", 35.86, 104.19, 31129, 35, "#EF4444", "CRITICAL", "Time-Based SQLi & Remote Code Exec", "98.4%", ["/api/v2/auth/login", "/query/graphql", "/admin/exec"], "down"],
  ["USA", 37.09, -95.71, 7943, 18, "#06B6D4", "HIGH", "Second-Order SQLi & OOB Exfiltration", "91.2%", ["/v1/user/profile", "/api/payments/checkout"], "up"],
  ["UK", 51.5, -0.12, 7943, 14, "#3B82F6", "MEDIUM", "Blind SSRF & Header Injection", "88.6%", ["/api/gateway/proxy", "/auth/oauth/token"], "left"],
  ["INDIA", 20.59, 78.96, 8500, 20, "#F97316", "HIGH", "Error-Based SQLi & Form Fuzzing", "93.1%", ["/api/v1/search", "/store/item/details"], "up"],
  ["UAE", 23.42, 53.84, 5228, 12, "#F97316", "MEDIUM", "NoSQL Injection & JWT Tampering", "87.4%", ["/api/v1/account", "/api/v2/config"], "up"],
  ["BRAZIL", -14.23, -51.92, 9243, 16, "#EAB308", "HIGH", "Reflected XSS & Command Injection", "90.8%", ["/upload/document", "/api/v1/filter"], "down"],
  ["RUSSIA", 55.75, 37.61, 18450, 25, "#EC4899", "CRITICAL", "Stacked Queries & Polyglot Injection", "96.5%", ["/api/v1/db/raw", "/system/config"], "right"],
  ["JAPAN", 35.67, 139.65, 12500, 15, "#8B5CF6", "MEDIUM", "DOM XSS & Template Injection", "86.2%", ["/api/v1/render", "/api/notifications"], "up"],
  ["GERMANY", 51.16, 10.45, 8400, 10, "#3B82F6", "LOW", "LDAP & XPath Injection Vectors", "84.1%", ["/api/v1/directory", "/api/auth/saml"], "up"],
  ["SINGAPORE", 1.35, 103.81, 9500, 14, "#EF4444", "HIGH", "REST API Fuzzing & Out-of-Band SQLi", "92.0%", ["/api/v1/trading/exec", "/api/v1/wallet"], "left"]
];

const COUNTRY_NODES: RegionData[] = RAW_COUNTRIES.map(
  ([label, lat, lng, base, rate, color, threatLevel, topVector, evasionRate, activeEndpoints, offsetDir]) => ({
    label,
    lat,
    lng,
    base,
    rate,
    color,
    threatLevel,
    topVector,
    evasionRate,
    activeEndpoints,
    offsetDir
  })
).sort((a, b) => b.base - a.base);

// Animated Particle Arcs between key threat nodes
const ARCS_DATA = [
  { startLat: 35.86, startLng: 104.19, endLat: 37.09, endLng: -95.71, color: ['#EF4444', '#06B6D4'] }, // China -> USA
  { startLat: 55.75, startLng: 37.61, endLat: 51.5, endLng: -0.12, color: ['#EC4899', '#3B82F6'] },   // Russia -> UK
  { startLat: 20.59, startLng: 78.96, endLat: 23.42, endLng: 53.84, color: ['#F97316', '#F59E0B'] },   // India -> UAE
  { startLat: -14.23, startLng: -51.92, endLat: 37.09, endLng: -95.71, color: ['#EAB308', '#06B6D4'] }, // Brazil -> USA
  { startLat: 35.86, startLng: 104.19, endLat: 20.59, endLng: 78.96, color: ['#EF4444', '#F97316'] }, // China -> India
  { startLat: 35.67, startLng: 139.65, endLat: 37.09, endLng: -95.71, color: ['#8B5CF6', '#06B6D4'] }  // Japan -> USA
];

export default function GlobeVisualization() {
  const globeRef = useRef<any>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [mounted, setMounted] = useState(false);
  const [dimensions, setDimensions] = useState<{ width: number; height: number }>({ width: 0, height: 0 });
  const [selectedRegion, setSelectedRegion] = useState<RegionData | null>(null);

  const countersRef = useRef<Record<string, number>>(
    Object.fromEntries(COUNTRY_NODES.map(n => [n.label, n.base]))
  );

  useEffect(() => {
    setMounted(true);
  }, []);

  useEffect(() => {
    if (!containerRef.current) return;

    const updateDimensions = () => {
      if (containerRef.current) {
        setDimensions({
          width: containerRef.current.clientWidth,
          height: containerRef.current.clientHeight,
        });
      }
    };

    updateDimensions();

    const resizeObserver = new ResizeObserver(() => {
      updateDimensions();
    });

    resizeObserver.observe(containerRef.current);

    return () => {
      resizeObserver.disconnect();
    };
  }, []);

  // Live counter DOM patching with flash ripple effect
  useEffect(() => {
    const iv = setInterval(() => {
      for (const n of COUNTRY_NODES) {
        countersRef.current[n.label] += Math.floor(Math.random() * n.rate) + 1;
        const el = document.getElementById(`glbl-${n.label}`);
        if (el) el.textContent = countersRef.current[n.label].toLocaleString();
        
        // Flash ripple on update
        const cardEl = document.getElementById(`glbl-card-${n.label}`);
        if (cardEl) {
          cardEl.style.boxShadow = `0 0 25px 4px ${n.color}99, inset 0 1px 2px ${n.color}`;
          cardEl.style.borderColor = n.color;
          setTimeout(() => {
            if (cardEl) {
              cardEl.style.boxShadow = `0 0 18px ${n.color}44, 0 4px 14px -2px rgba(0,0,0,0.85)`;
              cardEl.style.borderColor = `${n.color}aa`;
            }
          }, 450);
        }
      }
    }, 1200);
    return () => clearInterval(iv);
  }, []);

  // Hover auto-rotate pause handlers
  const handleMouseEnter = () => {
    if (globeRef.current) {
      const c = globeRef.current.controls();
      if (c) c.autoRotate = false;
    }
  };

  const handleMouseLeave = () => {
    if (globeRef.current) {
      const c = globeRef.current.controls();
      if (c) c.autoRotate = true;
    }
  };

  // Stable HTML element map — spaced cards with directional leader stems & click expansion
  const elementMap = useMemo<Record<string, HTMLElement>>(() => {
    const map: Record<string, HTMLElement> = {};
    for (const n of COUNTRY_NODES) {
      const wrap = document.createElement('div');
      wrap.style.cssText = 'display:flex;flex-direction:column;align-items:center;pointer-events:auto;cursor:pointer;position:relative;user-select:none;';

      const card = document.createElement('div');
      card.id = `glbl-card-${n.label}`;
      card.style.cssText = `background:linear-gradient(135deg, rgba(10,14,39,0.96) 0%, rgba(6,9,24,0.98) 100%);border:1.5px solid ${n.color}aa;border-radius:10px;padding:6px 12px 7px;display:flex;flex-direction:column;align-items:center;min-width:96px;backdrop-filter:blur(16px);box-shadow:0 0 20px ${n.color}44, 0 4px 16px -2px rgba(0,0,0,0.85);transition:all 0.25s cubic-bezier(0.4, 0, 0.2, 1);`;

      const lbl = document.createElement('div');
      lbl.style.cssText = `font-size:11px;color:${n.color};font-family:Cambria, Georgia, serif;text-transform:uppercase;letter-spacing:.08em;font-weight:800;display:flex;align-items:center;gap:4px;`;
      lbl.innerHTML = `<span>${n.label}</span>${n.threatLevel === 'CRITICAL' ? '<span style="width:6px;height:6px;border-radius:50%;background:#EF4444;box-shadow:0 0 8px #EF4444;"></span>' : ''}`;

      const num = document.createElement('div');
      num.id = `glbl-${n.label}`;
      num.style.cssText = 'font-size:15px;color:#FFFFFF;font-family:Cambria, Georgia, serif;font-weight:800;letter-spacing:.02em;';
      num.textContent = n.base.toLocaleString();

      const sub = document.createElement('div');
      sub.style.cssText = 'font-size:9px;color:#94A3B8;text-transform:uppercase;letter-spacing:.07em;font-family:Cambria, Georgia, serif;font-weight:700;';
      sub.textContent = 'events/hr';

      card.append(lbl, num, sub);

      const stem = document.createElement('div');
      stem.style.cssText = `width:1.5px;height:10px;background:linear-gradient(to bottom, ${n.color}, ${n.color}33);`;

      const dotContainer = document.createElement('div');
      dotContainer.style.cssText = 'position:relative;display:flex;align-items:center;justify-content:center;width:18px;height:18px;';

      const halo = document.createElement('div');
      halo.style.cssText = `position:absolute;width:16px;height:16px;border-radius:50%;border:1.5px solid ${n.color};box-shadow:0 0 14px ${n.color};animation:ping 2s cubic-bezier(0,0,0.2,1) infinite;opacity:0.85;`;

      const dot = document.createElement('div');
      dot.style.cssText = `width:7px;height:7px;border-radius:50%;background:${n.color};box-shadow:0 0 12px ${n.color}, 0 0 24px ${n.color};transition:all 0.25s ease;position:relative;z-index:2;`;

      dotContainer.append(halo, dot);

      // Hover pop & highlight
      wrap.onmouseenter = () => {
        card.style.transform = 'scale(1.18) translateY(-4px)';
        card.style.borderColor = n.color;
        card.style.boxShadow = `0 0 32px ${n.color}bb, inset 0 1px 3px ${n.color}`;
        dot.style.transform = 'scale(1.6)';
      };
      wrap.onmouseleave = () => {
        card.style.transform = 'scale(1) translateY(0)';
        card.style.borderColor = `${n.color}aa`;
        card.style.boxShadow = `0 0 18px ${n.color}44, 0 4px 14px -2px rgba(0,0,0,0.85)`;
        dot.style.transform = 'scale(1)';
      };

      // Click to open detailed metrics modal
      wrap.onclick = (e) => {
        e.stopPropagation();
        setSelectedRegion(n);
      };

      if (n.offsetDir === "down") {
        wrap.append(dotContainer, stem, card);
      } else {
        wrap.append(card, stem, dotContainer);
      }

      map[n.label] = wrap;
    }
    return map;
  }, []);

  if (!mounted) return null;

  return (
    <div 
      ref={containerRef} 
      onMouseEnter={handleMouseEnter} 
      onMouseLeave={handleMouseLeave}
      className="w-full h-full relative flex items-center justify-center overflow-hidden select-none bg-[#0a0e27]"
    >
      {/* Animated Scan Line Overlay Moving Across Globe View */}
      <div className="absolute inset-0 pointer-events-none z-10 opacity-30 bg-[linear-gradient(to_bottom,transparent_0px,rgba(6,182,212,0.06)_1px,transparent_2px)] bg-[size:100%_6px]" />
      <div className="absolute inset-x-0 h-24 bg-gradient-to-b from-cyan-500/10 to-transparent pointer-events-none z-10 animate-pulse" />

      {/* Outer Atmosphere Soft Glow Halo */}
      <div className="absolute inset-0 flex items-center justify-center pointer-events-none z-0">
        <div className="w-[390px] sm:w-[480px] h-[390px] sm:h-[480px] rounded-full border border-cyan-400/30 shadow-[0_0_110px_rgba(6,182,212,0.3),inset_0_0_80px_rgba(99,102,241,0.25)] blur-[2px] animate-pulse" />
        <div className="w-[82%] h-[82%] rounded-full bg-cyan-600/10 blur-[110px] absolute" />
      </div>

      <div className="absolute inset-0 flex items-center justify-center">
        <Globe
          ref={globeRef}
          width={dimensions.width || undefined}
          height={dimensions.height || undefined}
          backgroundColor="rgba(0,0,0,0)"
          globeImageUrl="//unpkg.com/three-globe/example/img/earth-blue-marble.jpg"
          bumpImageUrl="//unpkg.com/three-globe/example/img/earth-topology.png"
          atmosphereColor="#38bdf8"
          atmosphereAltitude={0.35}
          htmlElementsData={COUNTRY_NODES}
          htmlElement={(d: object) => elementMap[(d as RegionData).label]}
          htmlAltitude={0.06}
          arcsData={ARCS_DATA}
          arcColor={(d: any) => d.color}
          arcDashLength={0.4}
          arcDashGap={0.2}
          arcDashInitialGap={() => Math.random()}
          arcDashAnimateTime={2000}
          arcStroke={1.3}
          enablePointerInteraction={true}
          onGlobeReady={() => {
            setTimeout(() => {
              if (globeRef.current) {
                const c = globeRef.current.controls();
                c.autoRotate = true;
                c.autoRotateSpeed = 0.95; // smooth continuous rotation
                c.enableZoom = false;

                globeRef.current.pointOfView({ lat: 22, lng: 20, altitude: 3.1 }, 1000);
              }
            }, 150);
          }}
        />
      </div>

      {/* Detailed Metrics Modal for Clicked Threat Marker */}
      <AnimatePresence>
        {selectedRegion && (
          <motion.div 
            initial={{ opacity: 0, scale: 0.9, y: 10 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.9, y: 10 }}
            transition={{ duration: 0.2 }}
            className="absolute inset-4 md:inset-auto md:top-6 md:right-6 md:w-[380px] z-30 bg-[#070b1c]/95 border border-cyan-500/40 rounded-2xl p-6 backdrop-blur-xl shadow-[0_0_40px_rgba(6,182,212,0.35)] text-text-primary flex flex-col justify-between"
          >
            {/* Modal Header */}
            <div>
              <div className="flex items-center justify-between border-b border-cyan-500/20 pb-3 mb-4">
                <div className="flex items-center gap-3">
                  <div 
                    className="w-3.5 h-3.5 rounded-full shadow-[0_0_12px_currentColor]"
                    style={{ backgroundColor: selectedRegion.color, color: selectedRegion.color }}
                  />
                  <div>
                    <h4 className="text-lg font-extrabold tracking-tight text-white flex items-center gap-2">
                      {selectedRegion.label} REGION
                    </h4>
                    <p className="text-xs text-text-secondary font-mono">Telemetry Node ID: #3D-THREAT-{selectedRegion.label}</p>
                  </div>
                </div>

                <button 
                  onClick={() => setSelectedRegion(null)}
                  className="p-1.5 rounded-lg text-text-secondary hover:text-white hover:bg-cyan-500/20 transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {/* Stat Grid */}
              <div className="grid grid-cols-2 gap-3 mb-4">
                <div className="p-3 rounded-xl bg-[#0b1029] border border-cyan-500/20">
                  <span className="text-[10px] font-mono uppercase text-text-secondary block font-bold">Threat Level</span>
                  <span 
                    className="text-xs font-mono font-extrabold px-2.5 py-0.5 rounded border inline-block mt-1 uppercase"
                    style={{ 
                      borderColor: selectedRegion.color, 
                      color: selectedRegion.color, 
                      backgroundColor: `${selectedRegion.color}22` 
                    }}
                  >
                    {selectedRegion.threatLevel}
                  </span>
                </div>

                <div className="p-3 rounded-xl bg-[#0b1029] border border-cyan-500/20">
                  <span className="text-[10px] font-mono uppercase text-text-secondary block font-bold">Current Volume</span>
                  <span className="text-sm font-mono font-extrabold text-cyan-300 mt-1 block">
                    {(countersRef.current[selectedRegion.label] || selectedRegion.base).toLocaleString()} /hr
                  </span>
                </div>

                <div className="p-3 rounded-xl bg-[#0b1029] border border-cyan-500/20 col-span-2">
                  <span className="text-[10px] font-mono uppercase text-text-secondary block font-bold">Primary Attack Vector</span>
                  <span className="text-xs font-bold text-white mt-1 block truncate">
                    {selectedRegion.topVector}
                  </span>
                </div>

                <div className="p-3 rounded-xl bg-[#0b1029] border border-cyan-500/20">
                  <span className="text-[10px] font-mono uppercase text-text-secondary block font-bold">WAF Bypass Rate</span>
                  <span className="text-sm font-mono font-extrabold text-emerald-400 mt-1 block">
                    {selectedRegion.evasionRate}
                  </span>
                </div>

                <div className="p-3 rounded-xl bg-[#0b1029] border border-cyan-500/20">
                  <span className="text-[10px] font-mono uppercase text-text-secondary block font-bold">Grid Telemetry</span>
                  <span className="text-xs font-mono font-bold text-cyan-400 mt-1 flex items-center gap-1">
                    <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" /> Active
                  </span>
                </div>
              </div>

              {/* Target Endpoints Stream */}
              <div className="space-y-2">
                <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-purple-300 block">
                  Inspected Target Endpoints:
                </span>
                <div className="space-y-1.5 font-mono text-xs">
                  {selectedRegion.activeEndpoints.map((ep, i) => (
                    <div key={i} className="p-2 rounded-lg bg-[#040714] border border-slate-800 text-slate-200 flex items-center justify-between">
                      <span className="truncate">{ep}</span>
                      <ArrowUpRight className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Action Footer */}
            <div className="mt-4 pt-3 border-t border-cyan-500/20 flex justify-end">
              <button 
                onClick={() => setSelectedRegion(null)}
                className="px-4 py-2 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 text-xs font-bold border border-cyan-500/40 transition-colors"
              >
                Close Metrics
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

