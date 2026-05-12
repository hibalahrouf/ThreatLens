"use client";

import { usePathname } from "next/navigation";
import Sidebar from "@/components/Sidebar";
import Header from "@/components/Header";
import { AuthProvider } from "@/contexts/AuthContext";
import { ThemeProvider } from "@/contexts/ThemeContext";

export default function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const isAuthPage = pathname === "/login" || pathname === "/register";

  return (
    <ThemeProvider>
      <AuthProvider>
        {isAuthPage ? (
          children
        ) : (
          <>
            <Sidebar />
            <div className="flex-1 flex flex-col h-full overflow-hidden relative"
              style={{ background: 'var(--bg)', transition: 'background 0.3s ease' }}
            >
              {/* Ambient glows — theme-aware */}
              <Header />
              <main className="flex-1 overflow-y-auto z-10 w-full relative"
                style={{ scrollbarGutter: 'stable' }}
              >
                {children}
              </main>
            </div>
          </>
        )}
      </AuthProvider>
    </ThemeProvider>
  );
}
