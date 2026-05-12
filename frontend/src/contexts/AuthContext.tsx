"use client";

import React, { createContext, useContext, useState, useEffect, ReactNode } from "react";
import { useRouter, usePathname } from "next/navigation";
import { api } from "@/services/api";

type User = {
  id: number;
  email: string;
  full_name?: string;
};

type AuthContextType = {
  user: User | null;
  token: string | null;
  isLoading: boolean;
  login: (access_token: string) => Promise<void>;
  logout: () => void;
};

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    // Check locally stored token on mount
    const storedToken = localStorage.getItem("masvs_token");
    if (storedToken) {
      setToken(storedToken);
      fetchUser(storedToken);
    } else {
      setIsLoading(false);
      handleRedirect();
    }
  }, []);

  useEffect(() => {
    // Re-run redirect logic when user state or path changes
    if (!isLoading) {
      handleRedirect();
    }
  }, [user, isLoading, pathname]);

  const handleRedirect = () => {
    const isAuthRoute = pathname === "/login" || pathname === "/register";
    if (!user && !isAuthRoute) {
      router.push("/login");
    } else if (user && isAuthRoute) {
      router.push("/");
    }
  };

  const fetchUser = async (authToken: string) => {
    try {
      const me = await api.get("/auth/me");
      setUser({ id: me.id, email: me.email, full_name: me.full_name });
    } catch (error) {
      console.error("Auth verification failed", error);
      logout();
    } finally {
      setIsLoading(false);
    }
  };

  const login = async (access_token: string) => {
    localStorage.setItem("masvs_token", access_token);
    setToken(access_token);
    await fetchUser(access_token);
  };

  const logout = () => {
    localStorage.removeItem("masvs_token");
    setToken(null);
    setUser(null);
    router.push("/login");
  };

  const isAuthRoute = pathname === "/login" || pathname === "/register";

  return (
    <AuthContext.Provider value={{ user, token, isLoading, login, logout }}>
      {isLoading ? (
        <div className="h-screen w-screen flex items-center justify-center bg-[#0f111a] text-white">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
        </div>
      ) : (!user && !isAuthRoute) ? (
        <div className="h-screen w-screen bg-[#0f111a]" /> // Blank while redirecting
      ) : (
        children
      )}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
