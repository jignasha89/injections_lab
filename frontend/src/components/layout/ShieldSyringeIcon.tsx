'use client';

import React from 'react';

export default function ShieldSyringeIcon({ className = '' }: { className?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 64 64"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      {/* Shield outline */}
      <path
        d="M32 2L8 12v16c0 14 9 27 24 34 15-7 24-20 24-34V12L32 2z"
        stroke="#c0c0c0"
        strokeWidth="4"
        fill="rgba(200,200,200,0.1)"
      />
      {/* Syringe body */}
      <rect x="28" y="22" width="8" height="20" fill="#00d4ff" />
      {/* Syringe needle */}
      <line x1="32" y1="42" x2="32" y2="56" stroke="#00d4ff" strokeWidth="2" />
      {/* Binary digits */}
      <text x="30" y="35" fill="#ffffff" fontSize="6" fontFamily="monospace">0/1</text>
      {/* Glow effect */}
      <circle cx="32" cy="48" r="4" fill="#00d4ff" opacity="0.4" />
    </svg>
  );
}
