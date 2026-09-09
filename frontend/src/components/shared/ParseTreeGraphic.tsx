'use client';

import { useEffect, useState, useId } from 'react';

/**
 * Parse Tree / Syntax Graph — signature element.
 * Represents untrusted input breaking the expected structure of a query:
 * a few connected nodes forming an asymmetric branching structure where
 * one branch is visibly offset and differently colored.
 */

interface ParseTreeProps {
  /** When true, nodes light up sequentially as if being parsed */
  active?: boolean;
  /** Size multiplier (default 1 = 80×80) */
  scale?: number;
  className?: string;
}

export default function ParseTreeGraphic({ active = false, scale = 1, className = '' }: ParseTreeProps) {
  const [step, setStep] = useState(-1);
  const id = useId();

  useEffect(() => {
    if (!active) {
      setStep(-1);
      return;
    }

    // Check prefers-reduced-motion
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    if (mq.matches) {
      setStep(5); // Show all nodes lit, skip animation
      return;
    }

    let current = 0;
    const interval = setInterval(() => {
      setStep(current);
      current++;
      if (current > 5) current = 0;
    }, 400);

    return () => clearInterval(interval);
  }, [active]);

  const w = 80 * scale;
  const h = 80 * scale;
  const s = scale;

  const nodeColor = (index: number) => {
    if (!active) return 'var(--color-text-secondary)';
    return step >= index ? 'var(--color-brand-primary)' : 'var(--color-text-secondary)';
  };

  const nodeOpacity = (index: number) => {
    if (!active) return 0.25;
    return step >= index ? 1 : 0.2;
  };

  const edgeColor = (index: number) => {
    if (!active) return 'var(--color-text-secondary)';
    return step >= index ? 'var(--color-brand-primary)' : 'var(--color-text-secondary)';
  };

  const edgeOpacity = (index: number) => {
    if (!active) return 0.15;
    return step >= index ? 0.7 : 0.12;
  };

  return (
    <svg
      width={w}
      height={h}
      viewBox="0 0 80 80"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      aria-hidden="true"
      role="img"
    >
      {/* Edges — drawn first so nodes render on top */}
      {/* Root → Left child */}
      <line
        x1="40" y1="16" x2="22" y2="38"
        stroke={edgeColor(1)}
        strokeWidth="1.5"
        strokeOpacity={edgeOpacity(1)}
        style={{ transition: 'stroke 0.4s ease, stroke-opacity 0.4s ease' }}
      />
      {/* Root → Right child */}
      <line
        x1="40" y1="16" x2="58" y2="38"
        stroke={edgeColor(2)}
        strokeWidth="1.5"
        strokeOpacity={edgeOpacity(2)}
        style={{ transition: 'stroke 0.4s ease, stroke-opacity 0.4s ease' }}
      />
      {/* Left child → Left leaf */}
      <line
        x1="22" y1="38" x2="14" y2="58"
        stroke={edgeColor(3)}
        strokeWidth="1.5"
        strokeOpacity={edgeOpacity(3)}
        style={{ transition: 'stroke 0.4s ease, stroke-opacity 0.4s ease' }}
      />
      {/* Left child → Middle leaf */}
      <line
        x1="22" y1="38" x2="32" y2="58"
        stroke={edgeColor(3)}
        strokeWidth="1.5"
        strokeOpacity={edgeOpacity(3)}
        style={{ transition: 'stroke 0.4s ease, stroke-opacity 0.4s ease' }}
      />
      {/* Right child → Malformed branch (offset, dashed) */}
      <line
        x1="58" y1="38" x2="62" y2="62"
        stroke={edgeColor(4)}
        strokeWidth="1.5"
        strokeOpacity={edgeOpacity(4)}
        strokeDasharray={active ? '4 3' : 'none'}
        style={{ transition: 'stroke 0.4s ease, stroke-opacity 0.4s ease' }}
      />

      {/* Nodes */}
      {/* Root node */}
      <circle
        cx="40" cy="16" r="5"
        fill={nodeColor(0)}
        opacity={nodeOpacity(0)}
        style={{ transition: 'fill 0.4s ease, opacity 0.4s ease' }}
      />
      {/* Left child */}
      <circle
        cx="22" cy="38" r="4"
        fill={nodeColor(1)}
        opacity={nodeOpacity(1)}
        style={{ transition: 'fill 0.4s ease, opacity 0.4s ease' }}
      />
      {/* Right child */}
      <circle
        cx="58" cy="38" r="4"
        fill={nodeColor(2)}
        opacity={nodeOpacity(2)}
        style={{ transition: 'fill 0.4s ease, opacity 0.4s ease' }}
      />
      {/* Left leaf */}
      <circle
        cx="14" cy="58" r="3"
        fill={nodeColor(3)}
        opacity={nodeOpacity(3)}
        style={{ transition: 'fill 0.4s ease, opacity 0.4s ease' }}
      />
      {/* Middle leaf */}
      <circle
        cx="32" cy="58" r="3"
        fill={nodeColor(3)}
        opacity={nodeOpacity(3)}
        style={{ transition: 'fill 0.4s ease, opacity 0.4s ease' }}
      />
      {/* Malformed / Untrusted branch — deliberately offset, diamond shape */}
      <rect
        x="58" y="58" width="7" height="7"
        rx="1"
        fill={active && step >= 4 ? 'var(--color-severity-high)' : 'var(--color-text-secondary)'}
        opacity={nodeOpacity(4)}
        transform="rotate(45 62 62)"
        style={{ transition: 'fill 0.4s ease, opacity 0.4s ease' }}
      />
    </svg>
  );
}
