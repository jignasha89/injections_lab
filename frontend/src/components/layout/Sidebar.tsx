'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useStore } from '@/lib/store';
import { 
  LayoutDashboard, 
  ScanLine, 
  FileBarChart2, 
  User as UserIcon,
  History,
  Info,
  HelpCircle,
  LogOut,
  X,
} from 'lucide-react';
import { clsx } from 'clsx';


const menuItems = [
  { name: 'Workspace', href: '/dashboard', icon: LayoutDashboard },
  { name: 'Scanner', href: '/scanner', icon: ScanLine, badge: '55 Rules' },
  { name: 'Reports', href: '/reports', icon: FileBarChart2 },
  { name: 'History', href: '/history', icon: History },
  { name: 'Injection Details', href: '/injection-details', icon: Info },
  { name: 'Help', href: '/help', icon: HelpCircle },
  { name: 'Profile', href: '/profile', icon: UserIcon },
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
        "w-60 bg-bg-base border-r border-border-subtle flex flex-col h-screen fixed inset-y-0 left-0 lg:sticky lg:top-0 z-50 transition-transform duration-300 ease-in-out shadow-xl lg:shadow-none",
        isOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0"
      )}
    >
      {/* Brand Logo */}
      <div className="px-4 py-3 border-b border-border-subtle flex items-center justify-between gap-2 h-20 bg-surface-base/40">
        <Link href="/dashboard" className="flex items-center group overflow-visible" onClick={handleLinkClick}>
          <img 
            src="/assets/logo_transparent.png" 
            alt="InjectionLab Logo" 
            className="h-11 w-auto object-contain max-w-[180px] drop-shadow-[0_0_12px_rgba(6,182,212,0.45)] group-hover:scale-[1.03] transition-all duration-200" 
          />
        </Link>
        
        {/* Close button for mobile */}
        <button 
          onClick={onClose}
          className="lg:hidden p-1.5 rounded-md text-text-secondary hover:text-text-primary hover:bg-surface-base transition-colors shrink-0"
          aria-label="Close menu"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-5 space-y-0.5 overflow-y-auto">
        {menuItems.map((item) => {
          const isActive = pathname === item.href || (item.href !== '/dashboard' && pathname.startsWith(item.href));
          const Icon = item.icon;
          return (
            <Link
              key={item.name}
              href={item.href}
              onClick={handleLinkClick}
              className={clsx(
                "flex items-center justify-between px-3.5 py-2.5 rounded-lg text-sm transition-all duration-200 group relative active:scale-[0.98]",
                isActive 
                  ? "text-text-primary font-semibold bg-gradient-to-r from-brand-primary/20 via-brand-primary/10 to-transparent border border-brand-primary/50 shadow-[0_0_14px_rgba(99,102,241,0.25)]" 
                  : "text-text-secondary font-medium hover:text-text-primary hover:bg-surface-hover/80 hover:border-brand-primary/40 hover:shadow-[0_0_12px_rgba(99,102,241,0.2)] border border-transparent"
              )}
            >

              <div className="flex items-center gap-3">
                <Icon className={clsx("w-4 h-4 transition-colors", isActive ? "text-brand-primary" : "text-text-secondary group-hover:text-text-primary")} />
                <span>{item.name}</span>
              </div>
              {item.badge && (
                <span className={clsx(
                  "text-[9px] font-mono px-2 py-0.5 rounded uppercase tracking-widest",
                  isActive ? "bg-brand-primary/10 text-brand-primary border border-brand-primary/20" : "bg-surface-hover border border-border-subtle text-text-secondary/70"
                )}>
                  {item.badge}
                </span>
              )}
            </Link>
          );
        })}
      </nav>

      {/* User Footer */}
      <div className="p-4 space-y-2">
        <button
          onClick={logout}
          className="w-full flex items-center justify-start gap-2 px-3 py-2.5 rounded-md text-xs font-medium text-text-secondary hover:bg-surface-base hover:text-text-primary border border-transparent hover:border-border-subtle transition-all active:scale-[0.98]"
        >
          <LogOut className="w-3.5 h-3.5" />
          Sign out
        </button>
      </div>
    </aside>
  );
}
