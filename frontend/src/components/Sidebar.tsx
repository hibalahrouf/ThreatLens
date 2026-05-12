"use client";

import { Suspense } from 'react';
import Link from 'next/link';
import { usePathname, useSearchParams } from 'next/navigation';
import { LayoutDashboard, UploadCloud, List, Settings, LogOut, Zap, FileSearch, Layers } from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';

function SidebarContent() {
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const currentMode = searchParams.get('mode');
  const { logout, user } = useAuth();

  const links = [
    { name: 'Dashboard',        href: '/',                    icon: LayoutDashboard, description: 'Overview & metrics',  mode: undefined as string | undefined },
    { name: 'New Scan',         href: '/scans/upload',        icon: UploadCloud,     description: 'Upload APK/IPA',     mode: undefined as string | undefined },
    { name: 'Scan History',     href: '/scans',               icon: List,            description: 'All audit results',   mode: undefined as string | undefined },
    { name: 'Static Analysis',  href: '/scans?mode=static',   icon: FileSearch,      description: 'Static scans only',   mode: 'static'  },
    { name: 'Static + Dynamic', href: '/scans?mode=dynamic',  icon: Layers,          description: 'Combined analysis',   mode: 'dynamic' },
    { name: 'Settings',         href: '/settings',            icon: Settings,        description: 'Configure platform',  mode: undefined as string | undefined },
  ];

  return (
    <aside
      className="w-64 flex-shrink-0 h-full flex flex-col relative overflow-hidden"
      style={{
        background: '#070D1E',
        borderRight: '1px solid rgba(255,255,255,0.08)',
        transition: 'background 0.3s ease, border-color 0.3s ease',
      }}
    >
      {/* ── Logo ── */}
      <div
        className="relative z-10 px-4 py-5"
        style={{ borderBottom: '1px solid rgba(255,255,255,0.08)' }}
      >
        <div className="rounded-2xl px-3 py-3" style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }}>
          <img
            src="/threatlens-logo.png"
            alt="ThreatLens"
            className="h-12 w-full object-contain"
          />
        </div>
      </div>

      {/* ── Navigation ── */}
      <nav className="relative z-10 flex-1 px-3 py-5 space-y-1">
        {links.map((link) => {
          const Icon = link.icon;
          let isActive = false;
          const isScansSection = pathname === '/scans' || (pathname.startsWith('/scans/') && pathname !== '/scans/upload');
          if (link.mode) {
            // Mode-specific links: active on /scans or /scans/[id] when mode param matches
            isActive = isScansSection && currentMode === link.mode;
          } else if (link.href === '/scans') {
            // Scan History: active for /scans (no mode) or /scans/[id] (no mode)
            isActive = isScansSection && !currentMode;
          } else {
            isActive = pathname === link.href;
          }

          const groupLabel = link.name === 'Dashboard'
            ? 'Overview'
            : link.name === 'Scan History'
            ? 'Analysis'
            : link.name === 'Settings'
            ? 'System'
            : null;

          return (
            <div key={link.name}>
              {groupLabel && (
                <p className={`text-[9px] font-bold uppercase tracking-[0.2em] px-4 mb-1 ${groupLabel === 'Overview' ? '' : 'mt-5'}`} style={{ color: 'rgba(255,255,255,0.38)' }}>
                  {groupLabel}
                </p>
              )}
            <Link
              href={link.href}
              className={`group relative flex items-center gap-3 px-4 py-3 text-sm rounded-xl transition-all duration-200 ${
                isActive
                  ? 'font-semibold'
                  : 'hover:bg-white/[0.06]'
              }`}
              style={{
                background: isActive ? 'rgba(23,105,255,0.16)' : undefined,
                color: isActive ? '#FFFFFF' : 'rgba(255,255,255,0.72)',
              }}
            >
              {isActive && (
                <span className="absolute left-0 top-2 bottom-2 w-1 rounded-r-full" style={{ background: '#1769FF' }} />
              )}
              <div
                className="flex items-center justify-center w-8 h-8 rounded-lg transition-all flex-shrink-0"
                style={{
                  background: isActive ? 'rgba(23,105,255,0.22)' : 'rgba(255,255,255,0.04)',
                  border: `1px solid ${isActive ? 'rgba(23,105,255,0.30)' : 'rgba(255,255,255,0.06)'}`,
                }}
              >
                <Icon
                  size={15}
                  style={{ color: isActive ? '#5DA2FF' : 'rgba(255,255,255,0.68)' }}
                />
              </div>
              <div className="min-w-0 flex-1">
                <span className="block text-sm">{link.name}</span>
                <span
                  className="block text-[10px] transition-colors"
                  style={{ color: isActive ? 'rgba(255,255,255,0.72)' : 'rgba(255,255,255,0.42)' }}
                >
                  {link.description}
                </span>
              </div>
            </Link>
            </div>
          );
        })}
      </nav>

      {/* ── Dynamic Analyzer Status Badge ── */}
      <div
        className="relative z-10 mx-3 mb-2 px-3 py-2.5 rounded-xl"
        style={{ background: 'rgba(23,105,255,0.08)', border: '1px solid rgba(23,105,255,0.18)' }}
      >
        <div className="flex items-center gap-2">
          <Layers size={13} className="flex-shrink-0" style={{ color: '#5DA2FF' }} />
          <div>
            <p className="text-[11px] font-semibold" style={{ color: '#FFFFFF' }}>Dynamic Analyzer</p>
            <p className="text-[10px]" style={{ color: 'rgba(255,255,255,0.48)' }}>MobSF Emulator</p>
          </div>
          <div className="ml-auto flex items-center gap-1.5">
            <div className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
            <span className="text-[9px] font-bold uppercase tracking-wider text-emerald-400">Ready</span>
          </div>
        </div>
      </div>

      {/* ── AI Status Badge ── */}
      <div
        className="relative z-10 mx-3 mb-3 px-3 py-2.5 rounded-xl"
        style={{ background: 'rgba(23,105,255,0.12)', border: '1px solid rgba(23,105,255,0.22)' }}
      >
        <div className="flex items-center gap-2">
          <Zap size={13} className="flex-shrink-0" style={{ color: '#5DA2FF' }} />
          <div>
            <p className="text-[11px] font-semibold" style={{ color: '#FFFFFF' }}>AI Engine Active</p>
            <p className="text-[10px]" style={{ color: 'rgba(255,255,255,0.48)' }}>Ollama / Llama 3</p>
          </div>
          <div className="ml-auto w-2 h-2 rounded-full bg-emerald-400 flex-shrink-0 animate-pulse" />
        </div>
      </div>

      {/* ── User + Logout ── */}
      <div
        className="relative z-10 p-3"
        style={{ borderTop: '1px solid rgba(255,255,255,0.08)' }}
      >
        <div className="flex items-center gap-3 px-3 py-2 mb-1 rounded-xl"
          style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }}
        >
          <div
            className="w-7 h-7 rounded-lg flex items-center justify-center text-xs font-bold flex-shrink-0"
            style={{ background: '#1769FF', color: '#FFFFFF' }}
          >
            {(user?.full_name || user?.email || 'U')[0].toUpperCase()}
          </div>
          <div className="min-w-0">
            <p className="text-xs font-semibold truncate" style={{ color: '#FFFFFF' }}>
              {user?.full_name || 'Security Admin'}
            </p>
            <p className="text-[10px] truncate" style={{ color: 'rgba(255,255,255,0.48)' }}>
              {user?.email || ''}
            </p>
          </div>
        </div>

        <button
          onClick={() => logout()}
          className="w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm transition-all cursor-pointer group"
          style={{ color: 'rgba(255,255,255,0.58)' }}
          onMouseEnter={(e) => {
            (e.currentTarget as HTMLElement).style.background = 'rgba(239,68,68,0.08)';
            (e.currentTarget as HTMLElement).style.color = '#E5483A';
          }}
          onMouseLeave={(e) => {
            (e.currentTarget as HTMLElement).style.background = 'transparent';
            (e.currentTarget as HTMLElement).style.color = 'rgba(255,255,255,0.58)';
          }}
        >
          <LogOut size={15} />
          Sign Out
        </button>
      </div>
    </aside>
  );
}

export default function Sidebar() {
  return (
    <Suspense>
      <SidebarContent />
    </Suspense>
  );
}
