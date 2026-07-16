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
        "w-64 bg-white border-r border-slate-200 flex flex-col h-screen fixed inset-y-0 left-0 lg:sticky lg:top-0 z-50 transition-transform duration-300 ease-in-out shadow-lg lg:shadow-none",
        isOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0"
      )}
    >
      {/* Brand Logo */}
      <div className="p-6 border-b border-slate-200 flex items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-slate-900 text-white shadow-sm">
            <ShieldCheck className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="font-extrabold text-lg tracking-wider text-slate-900">
              InjectionLab
            </h1>
            <p className="text-[10px] text-slate-500 uppercase tracking-widest font-bold">Learn. Detect. Fix.</p>
          </div>
        </div>
        
        {/* Close Button for Mobile */}
        <button 
          onClick={onClose}
          className="lg:hidden p-2 rounded-xl text-slate-400 hover:text-slate-700 hover:bg-slate-100"
          aria-label="Close Menu"
        >
          <X className="w-5 h-5" />
        </button>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-4 py-6 space-y-2 overflow-y-auto">
        {menuItems.map((item) => {
          const isActive = pathname.startsWith(item.href);
          const Icon = item.icon;
          return (
            <Link
              key={item.name}
              href={item.href}
              onClick={handleLinkClick}
              className={clsx(
                "flex items-center gap-3.5 px-4 py-3.5 rounded-2xl text-sm font-bold transition-all duration-200 border-2",
                isActive 
                  ? "bg-blue-600 text-white border-black shadow-md shadow-blue-100" 
                  : "text-slate-600 hover:text-slate-900 hover:bg-slate-50 border-transparent"
              )}
            >
              <Icon className={clsx("w-5 h-5", isActive ? "text-white" : "text-slate-500")} />
              {item.name}
            </Link>
          );
        })}
      </nav>

      {/* Footer Info */}
      <div className="p-4 border-t border-slate-200 space-y-4">
        {user && (
          <div className="flex items-center gap-3 px-2">
            <div className="w-10 h-10 rounded-full bg-slate-900 text-white flex items-center justify-center font-bold text-sm shadow-sm">
              {user.username[0].toUpperCase()}
            </div>
            <div className="overflow-hidden">
              <p className="text-sm font-bold text-slate-900 truncate">{user.username}</p>
              <p className="text-xs text-slate-500 font-semibold capitalize">{user.role}</p>
            </div>
          </div>
        )}
        <button
          onClick={logout}
          className="w-full flex items-center gap-3 px-4 py-3 rounded-2xl text-sm font-bold text-red-600 hover:bg-red-50 hover:text-red-700 transition-colors border border-transparent hover:border-red-100"
        >
          <LogOut className="w-4 h-4" />
          Sign Out
        </button>
      </div>
    </aside>
  );
}
