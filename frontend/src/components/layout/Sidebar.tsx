'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useStore } from '@/lib/store';
import { 
  LayoutDashboard, 
  ScanLine, 
  FileBarChart2, 
  History,
  Info,
  HelpCircle,
  LogOut,
  X,

 } from 'lucide-react';
import ShieldSyringeIcon from './ShieldSyringeIcon';
import { clsx } from 'clsx';

const menuItems = [
  { name: 'Workspace', href: '/dashboard', icon: LayoutDashboard },
  { name: 'Scanner', href: '/scanner', icon: ScanLine, badge: '55 RULES' },
  { name: 'Reports', href: '/reports', icon: FileBarChart2 },
  { name: 'History', href: '/history', icon: History },
  { name: 'Injection Details', href: '/injection-details', icon: Info },
  { name: 'Help', href: '/help', icon: HelpCircle },
];

interface SidebarProps {
  isOpen?: boolean;
  onClose?: () => void;
}

export default function Sidebar({ isOpen, onClose }: SidebarProps) {
  const pathname = usePathname();
  const { logout } = useStore();

  const handleLinkClick = () => {
    if (onClose) onClose();
  };

  return (
    <aside 
      className={clsx(
        "w-[200px] bg-[#0a0e27] border-r border-[#00d4ff]/30 flex flex-col h-screen fixed inset-y-0 left-0 lg:sticky lg:top-0 z-50 transition-transform duration-300 ease-in-out font-mono py-6 px-3 select-none shrink-0",
        isOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0"
      )}
    >
      {/* Header */}
      <div className="flex items-center justify-between mb-8 pb-3 border-b border-[#00d4ff]/20">
        <Link href="/dashboard" className="flex items-center gap-2 group overflow-visible" onClick={handleLinkClick}>
          <div className="w-7 h-7 rounded-lg bg-[#00d4ff]/10 border border-[#00d4ff]/40 flex items-center justify-center text-[#00d4ff] shadow-[0_0_12px_rgba(0,212,255,0.3)] shrink-0">
            <ShieldSyringeIcon className="w-4 h-4 text-[#00d4ff]" />
          </div>
          <div className="flex flex-col min-w-0">
            <span className="text-[16px] font-bold tracking-tight text-[#00d4ff] group-hover:text-[#33ddff] transition-colors leading-tight font-mono">
              InjectionLab
            </span>
            <span className="text-[9px] font-mono tracking-widest text-[#a0aec0] uppercase font-bold mt-0.5">
              Security Scanner
            </span>
          </div>
        </Link>
        
        {/* Close button for mobile */}
        <button 
          onClick={onClose}
          className="lg:hidden p-1 rounded text-[#a0aec0] hover:text-white transition-colors shrink-0"
          aria-label="Close menu"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Navigation Items */}
      <nav className="flex-1 space-y-1 overflow-y-auto">
        {menuItems.map((item) => {
          const isActive = pathname === item.href || (item.href !== '/dashboard' && pathname.startsWith(item.href));
          const Icon = item.icon;
          return (
            <Link
              key={item.name}
              href={item.href}
              onClick={handleLinkClick}
              className={clsx(
                "flex items-center justify-between p-3 rounded-lg text-xs font-mono font-bold transition-all duration-200 group relative active:scale-[0.98]",
                isActive 
                  ? "text-[#00d4ff] bg-[#00d4ff]/20 border border-[#00d4ff]/50 shadow-[0_0_12px_rgba(0,212,255,0.3)]" 
                  : "text-[#a0aec0] hover:text-[#00d4ff] hover:bg-[#00d4ff]/10 border border-transparent"
              )}
            >
              <div className="flex items-center gap-2.5 truncate">
                <Icon className={clsx("w-4 h-4 transition-colors shrink-0", isActive ? "text-[#00d4ff]" : "text-[#a0aec0] group-hover:text-[#00d4ff]")} />
                <span className="truncate">{item.name}</span>
              </div>
              {item.badge && (
                <span className={clsx(
                  "text-[8px] font-mono px-1.5 py-0.5 rounded uppercase tracking-wider font-bold shrink-0 ml-1",
                  isActive ? "bg-[#00d4ff]/30 text-[#00d4ff] border border-[#00d4ff]/50" : "bg-[#040714] border border-[#00d4ff]/20 text-[#a0aec0]"
                )}>
                  {item.badge}
                </span>
              )}
            </Link>
          );
        })}
      </nav>

      {/* Footer: Sign Out Button (Red text) */}
      <div className="pt-3 border-t border-[#00d4ff]/20">
        <button
          onClick={logout}
          className="w-full flex items-center justify-start gap-2 p-3 rounded-lg text-xs font-mono font-bold text-red-400 hover:text-red-300 hover:bg-red-500/10 border border-transparent hover:border-red-500/30 transition-all active:scale-[0.98]"
        >
          <LogOut className="w-4 h-4 text-red-400" />
          Sign out
        </button>
      </div>
    </aside>
  );
}
