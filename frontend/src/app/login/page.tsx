"use client";

import { useState } from "react";
import { Mail, Lock, ArrowRight, Loader2, Eye, EyeOff } from "lucide-react";
import { api } from "@/services/api";
import { useAuth } from "@/contexts/AuthContext";

export default function LoginPage() {
  const [isRegistering, setIsRegistering] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const { login } = useAuth();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setIsLoading(true);
    try {
      if (isRegistering) {
        const payload: any = { email, password };
        if (name) payload.full_name = name;
        const response = await api.post("/auth/register", payload, false);
        await login(response.access_token);
      } else {
        const response = await api.post("/auth/login", { email, password }, false);
        await login(response.access_token);
      }
    } catch (err: any) {
      setError(err.message || "An unexpected error occurred");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="w-full h-screen flex relative overflow-hidden" style={{ background: '#F6F8FF' }}>
      {/* LEFT PANEL — Branding */}
      <div className="hidden lg:flex flex-col justify-between w-[45%] p-12 relative overflow-hidden"
        style={{
          background: '#070D1E',
          borderRight: '1px solid rgba(255,255,255,0.08)',
        }}
      >
        {/* Animated grid background */}
        <div className="absolute inset-0 opacity-20"
          style={{
            backgroundImage: `
              linear-gradient(rgba(23,105,255,0.10) 1px, transparent 1px),
              linear-gradient(90deg, rgba(124,58,237,0.08) 1px, transparent 1px)
            `,
            backgroundSize: '48px 48px',
          }}
        />
        {/* Logo */}
        <div className="relative z-10">
          <img src="/threatlens-logo.png" alt="ThreatLens" className="h-20 w-72 object-contain object-left" />
        </div>

        {/* Center content */}
        <div className="relative z-10 space-y-8">
          <div>
            <h2 className="text-5xl font-heading font-bold text-white leading-tight mb-4">
              See threats.<br />
              Understand risks.<br />
              <span style={{ color: '#5DA2FF' }}>Build secure.</span>
            </h2>
            <p className="text-slate-500 text-sm leading-relaxed max-w-sm">
              Automated OWASP MASVS v2 compliance scanning, AI-powered vulnerability triage, and instant secure code remediation.
            </p>
          </div>

          {/* Feature pills */}
          <div className="space-y-2.5">
            {[
              { label: 'MobSF Static Analysis', color: '#1769FF' },
              { label: 'AI Triage via Ollama / LLama 3', color: '#7C3AED' },
              { label: 'CVSS v3.1 Scoring', color: '#14B8A6' },
              { label: 'PDF / SARIF / Markdown Reports', color: '#f59e0b' },
            ].map(({ label, color }) => (
              <div key={label} className="flex items-center gap-3">
                <div className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ backgroundColor: color, boxShadow: `0 0 6px ${color}` }} />
                <span className="text-sm text-slate-400">{label}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Bottom badge */}
        <div className="relative z-10">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-medium text-slate-500"
            style={{ background: 'rgba(56,189,248,0.06)', border: '1px solid rgba(56,189,248,0.1)' }}
          >
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            OWASP MASVS v2 Compliant
          </div>
        </div>
      </div>

      {/* RIGHT PANEL — Form */}
      <div className="flex-1 flex flex-col items-center justify-center p-6 relative">
        <div className="w-full max-w-sm relative z-10">
          {/* Mobile logo */}
          <div className="lg:hidden text-center mb-8">
            <img src="/threatlens-logo.png" alt="ThreatLens" className="mx-auto h-20 w-72 object-contain" />
          </div>

          {/* Form card */}
          <div className="rounded-2xl p-8"
            style={{
              background: '#FFFFFF',
              border: '1px solid rgba(16,24,40,0.10)',
              boxShadow: '0 24px 60px rgba(16,24,40,0.12)',
            }}
          >
            <div className="mb-7">
              <h2 className="text-xl font-bold font-heading text-[var(--fg)] mb-1">
                {isRegistering ? "Create account" : "Welcome back"}
              </h2>
              <p className="text-sm text-slate-500">
                {isRegistering ? "Start your security audit journey" : "Sign in to continue your audit session"}
              </p>
            </div>

            {error && (
              <div className="mb-5 p-3 rounded-xl text-sm flex items-start gap-2"
                style={{ background: 'rgba(240,68,56,0.08)', border: '1px solid rgba(240,68,56,0.2)', color: 'var(--danger)' }}
              >
                <span>{error}</span>
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">
              {isRegistering && (
                <div>
                  <label className="block text-xs font-semibold text-slate-500 mb-1.5 uppercase tracking-wider">Full Name</label>
                  <input
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="John Doe"
                    className="input-field"
                  />
                </div>
              )}

              <div>
                <label className="block text-xs font-semibold text-slate-500 mb-1.5 uppercase tracking-wider">Email</label>
                <div className="relative">
                  <Mail className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-600" />
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="input-field pl-10"
                    placeholder="admin@masvs.local"
                  />
                </div>
              </div>

              <div>
                <div className="flex justify-between mb-1.5">
                  <label className="block text-xs font-semibold text-slate-500 uppercase tracking-wider">Password</label>
                  {!isRegistering && (
                    <a href="#" className="text-xs font-medium" style={{ color: 'var(--accent)' }}>Forgot?</a>
                  )}
                </div>
                <div className="relative">
                  <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-600" />
                  <input
                    type={showPassword ? "text" : "password"}
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="input-field pl-10 pr-10"
                    placeholder="••••••••"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-600 hover:text-slate-400 transition-colors"
                  >
                    {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
              </div>

              <button
                type="submit"
                disabled={isLoading}
                className="premium-button w-full flex items-center justify-center gap-2 py-3 mt-2 text-sm"
              >
                {isLoading ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <>
                    {isRegistering ? "Create Account" : "Sign In"}
                    <ArrowRight size={16} />
                  </>
                )}
              </button>
            </form>

            <p className="text-center text-sm text-slate-600 mt-6">
              {isRegistering ? "Already have an account?" : "Don't have an account?"}{" "}
              <button
                type="button"
                onClick={() => { setIsRegistering(!isRegistering); setError(""); }}
                className="font-semibold transition-colors"
                style={{ color: 'var(--accent)' }}
              >
                {isRegistering ? "Sign in" : "Sign up"}
              </button>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
