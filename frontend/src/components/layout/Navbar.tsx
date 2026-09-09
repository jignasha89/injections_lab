'use client';

import { useStore } from '@/lib/store';
import { Menu } from 'lucide-react';

interface NavbarProps {
  onToggleSidebar?: () => void;
}

export default function Navbar({ onToggleSidebar }: NavbarProps) {
  const { user } = useStore();

  return (
    <header className="bg-bg-base/80 border-b border-border-subtle sticky top-0 z-40 px-4 md:px-6 h-16 flex items-center justify-between gap-4 backdrop-blur-md">
      <div className="flex items-center gap-4">
        <button 
          onClick={onToggleSidebar}
          className="lg:hidden p-2 rounded-md text-text-secondary hover:text-text-primary hover:bg-surface-base transition-colors"
          aria-label="Toggle navigation menu"
        >
          <Menu className="w-5 h-5" />
        </button>
      </div>

      <div className="flex items-center gap-4">
        {user && (
          <div className="text-sm font-medium text-text-primary">
            {user.username}
          </div>
        )}
      </div>
    </header>
  );
}
