'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useStore } from '@/lib/store';
import { 
  LayoutDashboard, 
  ScanLine, 
  FlaskConical, 
  FileBarChart2, 
  Wrench, 
  BookOpen, 
  Settings as SettingsIcon, 
  User as UserIcon, 
  Info,
  LogOut,
  ShieldCheck,
  X
} from 'lucide-react';
import { clsx } from 'clsx';

const menuItems = [
  { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
  { name: 'Scanner', href: '/scanner', icon: ScanLine },
  { name: 'Demo Labs', href: '/labs', icon: FlaskConical },
  { name: 'Reports', href: '/reports', icon: FileBarChart2 },
  { name: 'Fix Guide', href: '/fix-guide', icon: Wrench },
  { name: 'Encyclopedia', href: '/encyclopedia', icon: BookOpen },
  { name: 'Settings', href: '/settings', icon: SettingsIcon },
  { name: 'Profile', href: '/profile', icon: UserIcon },
  { name: 'About', href: '/about', icon: Info },
];

interface SidebarProps {
  isOpen?: boolean;
  onClose?: () => void;
}

export default function Sidebar({ isOpen, onClose }: SidebarProps) {
  const pathname = usePathname();
  const { user, logout } = useStore();

  const handleLinkClick = () => {
    if (onClose) onClose();
  };

  return (
    <aside 
      className={clsx(
        "w-64 bg-[#0a0b10] border-r border-zinc-800/80 flex flex-col h-screen fixed inset-y-0 left-0 lg:sticky lg:top-0 z-50 transition-transform duration-300 ease-in-out shadow-2xl lg:shadow-none text-zinc-200",
        isOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0"
      )}
    >
      {/* Brand Logo */}
      <div className="p-5 border-b border-zinc-800/80 flex items-center justify-between gap-3">
        <Link href="/dashboard" className="flex items-center gap-3 group">
          <div className="relative overflow-hidden rounded-2xl bg-black/40 border border-cyan-500/40 p-0.5 shadow-[0_0_20px_rgba(0,240,255,0.3)] shrink-0">
            <img 
              src="/logo.png" 
              alt="InjectionLab Logo" 
              className="w-12 h-12 object-contain dark-logo scale-105"
            />
          </div>
          <div>
            <h1 className="font-extrabold text-lg tracking-wider text-white flex items-center gap-1 font-mono">
              Injection<span className="text-cyan-400">Lab</span>
            </h1>
            <p className="text-[9px] text-cyan-400 font-bold uppercase tracking-widest font-mono">
              Learn • Test • Secure
            </p>
          </div>
        </Link>
        
        {/* Close Button for Mobile */}
        <button 
          onClick={onClose}
          className="lg:hidden p-2 rounded-xl text-zinc-400 hover:text-white hover:bg-zinc-800/60"
          aria-label="Close Menu"
        >
          <X className="w-5 h-5" />
        </button>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-6 space-y-1.5 overflow-y-auto">
        {menuItems.map((item) => {
          const isActive = pathname.startsWith(item.href);
          const Icon = item.icon;
          return (
            <Link
              key={item.name}
              href={item.href}
              onClick={handleLinkClick}
              className={clsx(
                "flex items-center gap-3.5 px-4 py-3 rounded-xl text-sm font-semibold transition-all duration-200 border",
                isActive 
                  ? "bg-cyan-500/10 text-cyan-400 border-cyan-500/40 shadow-[0_0_15px_rgba(0,240,255,0.15)]" 
                  : "text-zinc-400 hover:text-white hover:bg-zinc-900/60 border-transparent"
              )}
            >
              <Icon className={clsx("w-4.5 h-4.5", isActive ? "text-cyan-400" : "text-zinc-500")} />
              {item.name}
            </Link>
          );
        })}
      </nav>

      {/* Footer Info */}
      <div className="p-4 border-t border-zinc-800/80 space-y-3.5 bg-[#07080c]">
        {user && (
          <div className="flex items-center gap-3 px-2">
            <div className="w-9 h-9 rounded-full bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 flex items-center justify-center font-bold text-xs shadow-inner">
              {user.username[0].toUpperCase()}
            </div>
            <div className="overflow-hidden">
              <p className="text-xs font-bold text-white truncate">{user.username}</p>
              <p className="text-[10px] text-zinc-400 font-mono capitalize">{user.role}</p>
            </div>
          </div>
        )}
        <button
          onClick={logout}
          className="w-full flex items-center gap-2.5 px-3.5 py-2.5 rounded-xl text-xs font-semibold text-rose-400 hover:bg-rose-500/10 hover:text-rose-300 transition-colors border border-transparent hover:border-rose-500/20"
        >
          <LogOut className="w-4 h-4" />
          Sign Out
        </button>
      </div>
    </aside>
  );
}

