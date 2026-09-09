'use client';

import { useEffect, useRef, useState, useMemo } from 'react';
import dynamic from 'next/dynamic';

const Globe = dynamic(() => import('react-globe.gl'), { ssr: false });

const RAW_COUNTRIES = [
  ["India", 20.59, 78.96, 12000, 15, "#F97316"], ["USA", 37.09, -95.71, 24000, 22, "#EF4444"],
  ["Japan", 35.67, 139.65, 15000, 14, "#8B5CF6"], ["Germany", 51.16, 10.45, 8400, 8, "#3B82F6"],
  ["Russia", 55.75, 37.61, 18000, 16, "#EC4899"], ["China", 35.86, 104.19, 31000, 25, "#F59E0B"],
  ["Brazil", -14.23, -51.92, 9200, 9, "#10B981"], ["UK", 51.5, -0.12, 7900, 7, "#06B6D4"],
  ["France", 46.22, 2.21, 6500, 6, "#3B82F6"], ["Canada", 56.13, -106.34, 4500, 5, "#EF4444"],
  ["Australia", -25.27, 133.77, 3200, 4, "#F59E0B"], ["South Africa", -30.55, 22.93, 4100, 5, "#10B981"],
  ["Mexico", 23.63, -102.55, 5800, 6, "#F97316"], ["Italy", 41.87, 12.56, 5100, 5, "#8B5CF6"],
  ["Spain", 40.46, -3.74, 4900, 5, "#EC4899"], ["South Korea", 35.9, 127.76, 11000, 12, "#3B82F6"],
  ["Indonesia", -0.78, 113.92, 8500, 10, "#F59E0B"], ["Turkey", 38.96, 35.24, 6200, 7, "#EF4444"],
  ["Saudi Arabia", 23.88, 45.07, 3800, 4, "#10B981"], ["Iran", 32.42, 53.68, 5500, 6, "#F97316"],
  ["Argentina", -38.41, -63.61, 3500, 4, "#06B6D4"], ["Nigeria", 9.08, 8.67, 4200, 5, "#8B5CF6"],
  ["Egypt", 26.82, 30.8, 3100, 4, "#F59E0B"], ["Pakistan", 30.37, 69.34, 5900, 7, "#10B981"],
  ["Vietnam", 14.05, 108.27, 6800, 8, "#EC4899"], ["Thailand", 15.87, 100.99, 4700, 6, "#3B82F6"],
  ["Philippines", 12.87, 121.77, 5100, 6, "#EF4444"], ["Malaysia", 4.21, 101.97, 3900, 5, "#F97316"],
  ["Colombia", 4.57, -74.29, 2900, 3, "#8B5CF6"], ["Chile", -35.67, -71.54, 2100, 3, "#06B6D4"],
  ["Peru", -9.19, -75.01, 2300, 3, "#10B981"], ["Venezuela", 6.42, -66.58, 1800, 2, "#F59E0B"],
  ["Kenya", -0.02, 37.9, 1900, 2, "#3B82F6"], ["Ethiopia", 9.14, 40.48, 1400, 2, "#EC4899"],
  ["Morocco", 31.79, -7.09, 1600, 2, "#EF4444"], ["Algeria", 28.03, 1.65, 1500, 2, "#F97316"],
  ["Ukraine", 48.37, 31.16, 7500, 9, "#06B6D4"], ["Poland", 51.91, 19.14, 3800, 5, "#8B5CF6"],
  ["Netherlands", 52.13, 5.29, 6100, 7, "#F59E0B"], ["Sweden", 60.12, 18.64, 3100, 4, "#3B82F6"],
  ["Switzerland", 46.81, 8.22, 4200, 5, "#EF4444"], ["Austria", 47.51, 14.55, 2500, 3, "#10B981"],
  ["Norway", 60.47, 8.46, 2100, 3, "#F97316"], ["Finland", 61.92, 25.74, 1900, 2, "#EC4899"],
  ["Ireland", 53.41, -8.24, 2800, 4, "#06B6D4"], ["New Zealand", -40.9, 174.88, 1500, 2, "#8B5CF6"],
  ["Singapore", 1.35, 103.81, 9500, 12, "#EF4444"], ["UAE", 23.42, 53.84, 5200, 6, "#F59E0B"],
  ["Israel", 31.04, 34.85, 6800, 8, "#3B82F6"], ["Romania", 45.94, 24.96, 2400, 3, "#F97316"],
  ["Kazakhstan", 48.01, 66.92, 1700, 2, "#10B981"], ["Uzbekistan", 41.37, 64.58, 1300, 2, "#EC4899"],
  ["Bangladesh", 23.68, 90.35, 3200, 4, "#06B6D4"], ["Sri Lanka", 7.87, 80.77, 1200, 2, "#8B5CF6"],
  ["Myanmar", 21.91, 95.95, 1100, 1, "#EF4444"], ["Nepal", 28.39, 84.12, 800, 1, "#F59E0B"],
  ["Afghanistan", 33.93, 67.7, 900, 1, "#3B82F6"], ["Iraq", 33.22, 43.67, 1800, 2, "#10B981"],
  ["Syria", 34.8, 38.99, 1200, 2, "#F97316"], ["Yemen", 15.55, 48.51, 600, 1, "#EC4899"],
  ["Angola", -11.2, 17.87, 700, 1, "#06B6D4"], ["Ghana", 7.94, -1.02, 1100, 1, "#8B5CF6"],
  ["Tanzania", -6.36, 34.88, 800, 1, "#EF4444"], ["Uganda", 1.37, 32.29, 600, 1, "#F59E0B"],
  ["Bolivia", -16.29, -63.58, 500, 1, "#3B82F6"], ["Paraguay", -23.44, -58.44, 400, 1, "#10B981"],
  ["Uruguay", -32.52, -55.76, 700, 1, "#F97316"], ["Ecuador", -1.83, -78.18, 900, 1, "#EC4899"]
];

const COUNTRY_NODES = RAW_COUNTRIES.map(([label, lat, lng, base, rate, color]) => ({
  label: label as string,
  lat: lat as number,
  lng: lng as number,
  base: base as number,
  rate: rate as number,
  color: color as string
}))
  .sort((a, b) => b.base - a.base)
  .slice(0, 15); // Show only top 15 to avoid clustering

export default function GlobeVisualization() {
  const globeRef = useRef<any>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [mounted, setMounted] = useState(false);
  const [dimensions, setDimensions] = useState<{ width: number; height: number }>({ width: 0, height: 0 });
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
              cardEl.style.boxShadow = `0 0 16px ${n.color}33, 0 4px 14px -2px rgba(0,0,0,0.7)`;
              cardEl.style.borderColor = `${n.color}77`;
            }
          }, 450);
        }
      }
    }, 1200);
    return () => clearInterval(iv);
  }, []);

  // Stable HTML element map — one element per country
  const elementMap = useMemo<Record<string, HTMLElement>>(() => {
    const map: Record<string, HTMLElement> = {};
    for (const n of COUNTRY_NODES) {
      const wrap = document.createElement('div');
      wrap.style.cssText = 'display:flex;flex-direction:column;align-items:center;pointer-events:auto;cursor:pointer;position:relative;';

      const card = document.createElement('div');
      card.id = `glbl-card-${n.label}`;
      card.style.cssText = `background:linear-gradient(135deg, rgba(16,22,38,0.96) 0%, rgba(8,12,22,0.98) 100%);border:1px solid ${n.color}77;border-radius:8px;padding:4px 10px 5px;display:flex;flex-direction:column;align-items:center;min-width:72px;backdrop-filter:blur(12px);box-shadow:0 0 16px ${n.color}33, 0 4px 14px -2px rgba(0,0,0,0.7);transition:all 0.25s cubic-bezier(0.4, 0, 0.2, 1);`;

      const lbl = document.createElement('div');
      lbl.style.cssText = `font-size:8px;color:${n.color};font-family:Cambria, Georgia, serif;text-transform:uppercase;letter-spacing:.1em;font-weight:700;`;
      lbl.textContent = n.label;

      const num = document.createElement('div');
      num.id = `glbl-${n.label}`;
      num.style.cssText = 'font-size:12px;color:#FFFFFF;font-family:Cambria, Georgia, serif;font-weight:700;letter-spacing:.02em;';
      num.textContent = n.base.toLocaleString();

      const sub = document.createElement('div');
      sub.style.cssText = 'font-size:7px;color:#94A3B8;text-transform:uppercase;letter-spacing:.07em;font-family:Cambria, Georgia, serif;font-weight:600;';
      sub.textContent = 'events/hr';

      card.append(lbl, num, sub);

      const stem = document.createElement('div');
      stem.style.cssText = `width:1.5px;height:7px;background:linear-gradient(to bottom, ${n.color}, ${n.color}33);`;

      const dotContainer = document.createElement('div');
      dotContainer.style.cssText = 'position:relative;display:flex;align-items:center;justify-content:center;width:12px;height:12px;';

      const halo = document.createElement('div');
      halo.style.cssText = `position:absolute;width:10px;height:10px;border-radius:50%;border:1px solid ${n.color};box-shadow:0 0 10px ${n.color};animation:ping 2s cubic-bezier(0,0,0.2,1) infinite;opacity:0.75;`;

      const dot = document.createElement('div');
      dot.style.cssText = `width:5px;height:5px;border-radius:50%;background:${n.color};box-shadow:0 0 8px ${n.color}, 0 0 16px ${n.color};transition:all 0.25s ease;position:relative;z-index:2;`;

      dotContainer.append(halo, dot);

      card.onmouseenter = () => {
        card.style.transform = 'scale(1.15) translateY(-4px)';
        card.style.borderColor = n.color;
        card.style.boxShadow = `0 0 28px ${n.color}bb, inset 0 1px 2px ${n.color}`;
        dot.style.transform = 'scale(1.5)';
        dot.style.boxShadow = `0 0 16px ${n.color}, 0 0 25px ${n.color}`;
      };
      card.onmouseleave = () => {
        card.style.transform = 'scale(1) translateY(0)';
        card.style.borderColor = `${n.color}77`;
        card.style.boxShadow = `0 0 16px ${n.color}33, 0 4px 14px -2px rgba(0,0,0,0.7)`;
        dot.style.transform = 'scale(1)';
        dot.style.boxShadow = `0 0 8px ${n.color}, 0 0 16px ${n.color}`;
      };

      wrap.append(card, stem, dotContainer);
      map[n.label] = wrap;
    }
    return map;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (!mounted) return null;

  return (
    <div ref={containerRef} className="w-full h-full relative flex items-center justify-center overflow-hidden">
      {/* soft atmospheric glow */}
      <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
        <div className="w-[80%] h-[80%] rounded-full bg-brand-primary/10 blur-[100px]" />
      </div>

      <div className="absolute inset-0 flex items-center justify-center">
        <Globe
          ref={globeRef}
          width={dimensions.width || undefined}
          height={dimensions.height || undefined}
          backgroundColor="rgba(0,0,0,0)"
          globeImageUrl="//unpkg.com/three-globe/example/img/earth-blue-marble.jpg"
          bumpImageUrl="//unpkg.com/three-globe/example/img/earth-topology.png"
          atmosphereColor="#3b82f6"
          atmosphereAltitude={0.25}
          htmlElementsData={COUNTRY_NODES}
          htmlElement={(d: object) => elementMap[(d as { label: string }).label]}
          htmlAltitude={0.06}
          enablePointerInteraction={true}
          onGlobeReady={() => {
            // setTimeout ensures the WebGL canvas is fully painted before moving camera
            setTimeout(() => {
              if (globeRef.current) {
                const c = globeRef.current.controls();
                c.autoRotate = true;
                c.autoRotateSpeed = 2.0; // smooth, slightly faster rotation
                c.enableZoom = false;

                // altitude 3.2 adjusts camera distance so globe and labels fit comfortably inside box container
                globeRef.current.pointOfView({ lat: 25, lng: 20, altitude: 3.2 }, 1000);
              }
            }, 150);
          }}
        />
      </div>
    </div>
  );
}
