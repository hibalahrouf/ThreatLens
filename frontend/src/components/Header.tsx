"use client";

import { useState } from 'react';
import { Bell, Search, Command, ChevronDown, Sun, Moon } from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';
import { useTheme } from '@/contexts/ThemeContext';
import Link from 'next/link';

export default function Header() {
  const { user } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const [searchFocused, setSearchFocused] = useState(false);

  const isLight = theme === 'light';

  return (
    <header
      className="h-16 flex-shrink-0 flex items-center justify-between px-6 z-20 relative"
      style={{
        background: 'var(--header-bg)',
        borderBottom: '1px solid var(--border)',
        backdropFilter: 'blur(20px)',
        transition: 'background 0.3s ease, border-color 0.3s ease',
      }}
    >
      {/* Search bar */}
      <div className={`relative flex-1 max-w-sm transition-all duration-300 ${searchFocused ? 'max-w-md' : ''}`}>
        <Search
          className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 transition-colors duration-200"
          style={{ color: searchFocused ? 'var(--accent)' : 'var(--fg-muted)' }}
        />
        <input
          type="text"
          placeholder="Search scans, findings..."
          onFocus={() => setSearchFocused(true)}
          onBlur={() => setSearchFocused(false)}
          className="w-full py-2 pl-10 pr-10 text-sm rounded-xl transition-all duration-200"
          style={{
            background: 'var(--input-bg)',
            border: `1px solid ${searchFocused ? 'color-mix(in srgb, var(--accent) 40%, transparent)' : 'var(--border)'}`,
            color: 'var(--fg)',
            boxShadow: searchFocused ? '0 0 20px var(--glow), 0 0 0 3px var(--accent-dim)' : 'none',
            outline: 'none',
          }}
        />
        <div className="absolute right-3 top-1/2 -translate-y-1/2 flex items-center gap-0.5 opacity-30">
          <Command size={11} style={{ color: 'var(--fg-muted)' }} />
          <span className="text-[10px] font-mono" style={{ color: 'var(--fg-muted)' }}>K</span>
        </div>
      </div>

      {/* Right side */}
      <div className="flex items-center gap-2 ml-4">
        {/* 🌙☀️ Theme Toggle */}
        <button
          onClick={toggleTheme}
          title={isLight ? 'Switch to Dark Mode' : 'Switch to Light Mode'}
          className="relative w-9 h-9 flex items-center justify-center rounded-xl transition-all duration-200 cursor-pointer overflow-hidden"
          style={{
            background: isLight ? '#FFFFFF' : 'rgba(56,189,248,0.06)',
            border: `1px solid ${isLight ? 'rgba(15,27,45,0.10)' : 'var(--border)'}`,
          }}
        >
          <div className={`transition-all duration-300 ${isLight ? 'rotate-0 scale-100' : '-rotate-90 scale-0 absolute'}`}>
            <Sun size={16} style={{ color: '#f59e0b' }} />
          </div>
          <div className={`transition-all duration-300 ${!isLight ? 'rotate-0 scale-100' : 'rotate-90 scale-0 absolute'}`}>
            <Moon size={16} style={{ color: 'var(--accent)' }} />
          </div>
        </button>

        {/* Notification bell */}
        <button
          className="relative w-9 h-9 flex items-center justify-center rounded-xl transition-all"
          style={{ background: 'var(--accent-dim)', border: '1px solid var(--border)' }}
        >
          <Bell className="w-4 h-4" style={{ color: 'var(--fg-muted)' }} />
          <span
            className="absolute top-1.5 right-1.5 w-1.5 h-1.5 rounded-full"
            style={{ background: 'var(--accent)', boxShadow: '0 0 6px var(--glow)' }}
          />
        </button>

        {/* Divider */}
        <div className="w-px h-6 mx-1" style={{ background: 'var(--border)' }} />

        {/* User chip */}
        <Link
          href="/settings"
          className="flex items-center gap-2.5 px-3 py-1.5 rounded-xl transition-all"
          style={{ background: 'var(--accent-dim)', border: '1px solid var(--border)' }}
        >
          <div
            className="w-6 h-6 rounded-lg flex items-center justify-center text-xs font-bold flex-shrink-0"
            style={{ background: 'var(--accent)', color: '#FFFFFF' }}
          >
            {(user?.full_name || user?.email || 'U')[0].toUpperCase()}
          </div>
          <div className="hidden sm:block min-w-0">
            <p className="text-xs font-semibold truncate leading-tight" style={{ color: 'var(--fg)' }}>
              {user?.full_name || 'Admin'}
            </p>
          </div>
          <ChevronDown size={12} className="flex-shrink-0 hidden sm:block" style={{ color: 'var(--fg-muted)' }} />
        </Link>
      </div>
    </header>
  );
}
