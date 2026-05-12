"use client";

import { useState, useEffect } from "react";
import {
  User, Lock, Key, Bell, Trash2, Save, Eye, EyeOff,
  CheckCircle, AlertCircle, Shield, Cpu, Database, RefreshCw,
  ChevronRight,
} from "lucide-react";
import { api } from "@/services/api";
import { useAuth } from "@/contexts/AuthContext";

type Tab = "profile" | "security" | "integrations" | "danger";

function SectionHeader({ title, description, icon: Icon }: { title: string; description: string; icon: any }) {
  return (
    <div className="flex items-start gap-4 mb-6">
      <div className="p-3 rounded-2xl" style={{ background: 'rgba(23,105,255,0.10)', border: '1px solid rgba(23,105,255,0.18)' }}>
        <Icon size={22} className="text-[var(--accent)]" />
      </div>
      <div>
        <h2 className="text-lg font-bold font-heading text-[var(--fg)]">{title}</h2>
        <p className="text-sm text-[var(--fg-muted)] mt-0.5">{description}</p>
      </div>
    </div>
  );
}

function Toast({ message, type }: { message: string; type: "success" | "error" }) {
  return (
    <div className={`fixed bottom-6 right-6 flex items-center gap-3 px-4 py-3 rounded-xl border shadow-xl z-50 animate-in slide-in-from-bottom-4 duration-300 ${
      type === "success"
        ? "bg-green-500/10 border-green-500/30 text-green-400"
        : "bg-red-500/10 border-red-500/30 text-red-400"
    }`}>
      {type === "success" ? <CheckCircle size={18} /> : <AlertCircle size={18} />}
      <span className="text-sm font-medium">{message}</span>
    </div>
  );
}

export default function SettingsPage() {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState<Tab>("profile");
  const [toast, setToast] = useState<{ message: string; type: "success" | "error" } | null>(null);

  // Profile form
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [savingProfile, setSavingProfile] = useState(false);

  // Security form
  const [currentPwd, setCurrentPwd] = useState("");
  const [newPwd, setNewPwd] = useState("");
  const [confirmPwd, setConfirmPwd] = useState("");
  const [showCurrentPwd, setShowCurrentPwd] = useState(false);
  const [showNewPwd, setShowNewPwd] = useState(false);
  const [savingPassword, setSavingPassword] = useState(false);

  // Integrations - stored locally in browser (not in DB for security)
  const [mobsfKey, setMobsfKey] = useState("");
  const [mobsfUrl, setMobsfUrl] = useState("http://mobsf:8000");

  const [openaiKey, setOpenaiKey] = useState("");
  const [ollamaUrl, setOllamaUrl] = useState("http://host.docker.internal:11434");
  const [llmProvider, setLlmProvider] = useState("ollama");
  const [scanTimeout, setScanTimeout] = useState("300");

  useEffect(() => {
    if (user) {
      setFullName(user.full_name || "");
      setEmail(user.email || "");
    }
    // Load integration settings from localStorage
    setMobsfKey(localStorage.getItem("settings_mobsf_key") || "");
    setMobsfUrl(localStorage.getItem("settings_mobsf_url") || "http://mobsf:8000");
    setOpenaiKey(localStorage.getItem("settings_openai_key") || "");
    setOllamaUrl(localStorage.getItem("settings_ollama_url") || "http://host.docker.internal:11434");
    setLlmProvider(localStorage.getItem("settings_llm_provider") || "ollama");
    setScanTimeout(localStorage.getItem("settings_scan_timeout") || "300");
  }, [user]);

  const showToast = (message: string, type: "success" | "error") => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 4000);
  };

  const handleSaveProfile = async () => {
    if (!fullName.trim()) {
      showToast("Full name cannot be empty.", "error");
      return;
    }
    setSavingProfile(true);
    try {
      await api.patch("/auth/me", { full_name: fullName });
      showToast("Profile updated successfully!", "success");
    } catch (err: any) {
      showToast(err.message || "Failed to update profile.", "error");
    } finally {
      setSavingProfile(false);
    }
  };

  const handleChangePassword = async () => {
    if (!currentPwd || !newPwd || !confirmPwd) {
      showToast("Please fill all password fields.", "error");
      return;
    }
    if (newPwd !== confirmPwd) {
      showToast("New passwords do not match.", "error");
      return;
    }
    if (newPwd.length < 8) {
      showToast("New password must be at least 8 characters.", "error");
      return;
    }
    setSavingPassword(true);
    try {
      await api.patch("/auth/me", { current_password: currentPwd, new_password: newPwd });
      showToast("Password changed successfully!", "success");
      setCurrentPwd("");
      setNewPwd("");
      setConfirmPwd("");
    } catch (err: any) {
      showToast(err.message || "Failed to change password.", "error");
    } finally {
      setSavingPassword(false);
    }
  };

  const handleSaveIntegrations = () => {
    localStorage.setItem("settings_mobsf_key", mobsfKey);
    localStorage.setItem("settings_mobsf_url", mobsfUrl);
    localStorage.setItem("settings_openai_key", openaiKey);
    localStorage.setItem("settings_ollama_url", ollamaUrl);
    localStorage.setItem("settings_llm_provider", llmProvider);
    localStorage.setItem("settings_scan_timeout", scanTimeout);
    showToast("Integration settings saved to browser.", "success");
  };

  const tabs: { id: Tab; label: string; icon: any }[] = [
    { id: "profile", label: "Profile", icon: User },
    { id: "security", label: "Security", icon: Lock },
    { id: "integrations", label: "Integrations", icon: Cpu },
    { id: "danger", label: "Danger Zone", icon: Trash2 },
  ];

  return (
    <div className="max-w-5xl mx-auto pb-20 p-7">
      <div className="mb-8">
        <p className="text-[11px] font-bold uppercase tracking-[0.22em] text-[var(--fg-muted)] mb-1.5">Workspace</p>
        <h1 className="text-[32px] leading-tight font-bold font-heading text-[var(--fg)]">Settings</h1>
        <p className="text-[var(--fg-muted)] mt-1">Manage your account, security, and integrations.</p>
      </div>

      <div className="flex gap-6">
        {/* Left: Tab Navigation */}
        <div className="w-52 flex-shrink-0">
          <nav className="glass-panel p-2 space-y-1">
            {tabs.map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                onClick={() => setActiveTab(id)}
                className={`w-full flex items-center justify-between gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all group ${
                  activeTab === id
                    ? "bg-[rgba(23,105,255,0.10)] text-[var(--accent)] border border-[rgba(23,105,255,0.18)]"
                    : "text-[var(--fg-muted)] hover:bg-[var(--accent-dim)] hover:text-[var(--fg)]"
                } ${id === "danger" ? "hover:text-red-400" : ""}`}
              >
                <div className="flex items-center gap-3">
                  <Icon size={16} className={id === "danger" && activeTab !== id ? "text-red-500/50" : ""} />
                  {label}
                </div>
                <ChevronRight size={14} className="opacity-40" />
              </button>
            ))}
          </nav>

          {/* Session Info Card */}
          <div className="glass-panel p-4 mt-4">
            <p className="text-xs text-slate-500 mb-2 font-medium uppercase tracking-wider">Session</p>
            <div className="flex items-center gap-2 mb-1">
              <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
              <span className="text-xs text-green-400 font-medium">Active</span>
            </div>
            <p className="text-xs text-slate-400 truncate">{email}</p>
            <p className="text-xs text-slate-500 mt-1">ID #{user?.id}</p>
          </div>
        </div>

        {/* Right: Tab Content */}
        <div className="flex-1 space-y-6">

          {/* ─── Profile Tab ─── */}
          {activeTab === "profile" && (
            <div className="glass-panel p-6">
              <SectionHeader
                title="Profile Information"
                description="Update your display name and view your account details."
                icon={User}
              />

              {/* Avatar */}
              <div className="flex items-center gap-4 mb-8 p-4 bg-[var(--accent-dim)] rounded-2xl border border-[var(--border)]">
                <div className="w-16 h-16 rounded-full flex items-center justify-center text-2xl font-bold shadow-lg" style={{ background: 'linear-gradient(135deg, #1769FF, #7C3AED)', color: '#FFFFFF' }}>
                  {(fullName || email || "?")[0].toUpperCase()}
                </div>
                <div>
                  <p className="font-semibold text-[var(--fg)]">{fullName || "No name set"}</p>
                  <p className="text-sm text-slate-400">{email}</p>
                  <span className="inline-flex items-center gap-1 mt-1 px-2 py-0.5 rounded-full bg-[rgba(23,105,255,0.10)] border border-[rgba(23,105,255,0.18)] text-[var(--accent)] text-xs font-medium">
                    <Shield size={10} /> Security Auditor
                  </span>
                </div>
              </div>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-1.5">Full Name</label>
                  <input
                    type="text"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    placeholder="Your full name"
                    className="w-full bg-[#141620] border border-[#334155] rounded-lg px-4 py-2.5 text-white placeholder-slate-600 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 transition-all"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-1.5">Email Address</label>
                  <input
                    type="email"
                    value={email}
                    disabled
                    className="w-full bg-[#0f111a]/80 border border-[#334155]/50 rounded-lg px-4 py-2.5 text-slate-500 cursor-not-allowed"
                  />
                  <p className="text-xs text-slate-600 mt-1">Email cannot be changed after registration.</p>
                </div>
              </div>

              <div className="mt-6 flex justify-end">
                <button
                  onClick={handleSaveProfile}
                  disabled={savingProfile}
                  className="premium-button flex items-center gap-2 disabled:opacity-50"
                >
                  {savingProfile ? <RefreshCw size={16} className="animate-spin" /> : <Save size={16} />}
                  {savingProfile ? "Saving..." : "Save Profile"}
                </button>
              </div>
            </div>
          )}

          {/* ─── Security Tab ─── */}
          {activeTab === "security" && (
            <div className="space-y-6">
              <div className="glass-panel p-6">
                <SectionHeader
                  title="Change Password"
                  description="Make sure your account uses a long, random password."
                  icon={Lock}
                />

                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-1.5">Current Password</label>
                    <div className="relative">
                      <input
                        type={showCurrentPwd ? "text" : "password"}
                        value={currentPwd}
                        onChange={(e) => setCurrentPwd(e.target.value)}
                        placeholder="Enter current password"
                        className="w-full bg-[#141620] border border-[#334155] rounded-lg px-4 py-2.5 text-white placeholder-slate-600 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 transition-all pr-10"
                      />
                      <button onClick={() => setShowCurrentPwd(!showCurrentPwd)} className="absolute right-3 top-3 text-slate-500 hover:text-slate-300">
                        {showCurrentPwd ? <EyeOff size={16} /> : <Eye size={16} />}
                      </button>
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-1.5">New Password</label>
                    <div className="relative">
                      <input
                        type={showNewPwd ? "text" : "password"}
                        value={newPwd}
                        onChange={(e) => setNewPwd(e.target.value)}
                        placeholder="At least 8 characters"
                        className="w-full bg-[#141620] border border-[#334155] rounded-lg px-4 py-2.5 text-white placeholder-slate-600 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 transition-all pr-10"
                      />
                      <button onClick={() => setShowNewPwd(!showNewPwd)} className="absolute right-3 top-3 text-slate-500 hover:text-slate-300">
                        {showNewPwd ? <EyeOff size={16} /> : <Eye size={16} />}
                      </button>
                    </div>
                    {/* Password strength */}
                    {newPwd && (
                      <div className="mt-2 space-y-1">
                        <div className="flex gap-1">
                          {[...Array(4)].map((_, i) => (
                            <div key={i} className={`h-1 flex-1 rounded-full transition-colors ${
                              newPwd.length >= (i + 1) * 3
                                ? newPwd.length >= 12 ? "bg-green-500" : newPwd.length >= 8 ? "bg-amber-500" : "bg-red-500"
                                : "bg-[#334155]"
                            }`} />
                          ))}
                        </div>
                        <p className="text-xs text-slate-500">
                          {newPwd.length < 8 ? "Too short" : newPwd.length < 12 ? "Good" : "Strong"}
                        </p>
                      </div>
                    )}
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-1.5">Confirm New Password</label>
                    <input
                      type="password"
                      value={confirmPwd}
                      onChange={(e) => setConfirmPwd(e.target.value)}
                      placeholder="Re-enter new password"
                      className={`w-full bg-[#141620] border rounded-lg px-4 py-2.5 text-white placeholder-slate-600 focus:outline-none focus:ring-1 transition-all ${
                        confirmPwd && confirmPwd !== newPwd
                          ? "border-red-500/50 focus:border-red-500 focus:ring-red-500/30"
                          : "border-[#334155] focus:border-blue-500 focus:ring-blue-500/30"
                      }`}
                    />
                    {confirmPwd && confirmPwd !== newPwd && (
                      <p className="text-xs text-red-400 mt-1 flex items-center gap-1"><AlertCircle size={12} /> Passwords do not match</p>
                    )}
                  </div>
                </div>

                <div className="mt-6 flex justify-end">
                  <button
                    onClick={handleChangePassword}
                    disabled={savingPassword}
                    className="premium-button flex items-center gap-2 disabled:opacity-50"
                  >
                    {savingPassword ? <RefreshCw size={16} className="animate-spin" /> : <Lock size={16} />}
                    {savingPassword ? "Updating..." : "Update Password"}
                  </button>
                </div>
              </div>

              {/* Security Info */}
              <div className="glass-panel p-5">
                <p className="text-sm font-semibold text-slate-300 mb-4 flex items-center gap-2"><Shield size={16} className="text-blue-400" /> Security Recommendations</p>
                <ul className="space-y-2.5">
                  {[
                    "Use a password manager to generate a strong, unique password.",
                    "Never reuse passwords across different applications.",
                    "Your JWT access token expires after 30 minutes automatically.",
                    "Refresh tokens are valid for 7 days."
                  ].map((tip, i) => (
                    <li key={i} className="flex items-start gap-2 text-sm text-slate-400">
                      <CheckCircle size={14} className="text-green-500 mt-0.5 flex-shrink-0" />
                      {tip}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          )}

          {/* ─── Integrations Tab ─── */}
          {activeTab === "integrations" && (
            <div className="space-y-6">
              {/* MobSF */}
              <div className="glass-panel p-6">
                <SectionHeader
                  title="MobSF Integration"
                  description="Mobile Security Framework — used for static analysis of APK/IPA files."
                  icon={Database}
                />
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-1.5">MobSF API Key</label>
                    <div className="relative">
                      <Key size={16} className="absolute left-3 top-3 text-slate-500" />
                      <input
                        type="password"
                        value={mobsfKey}
                        onChange={(e) => setMobsfKey(e.target.value)}
                        placeholder="Paste your MobSF REST API key here"
                        className="w-full bg-[#141620] border border-[#334155] rounded-lg pl-9 pr-4 py-2.5 text-white placeholder-slate-600 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 transition-all font-mono text-sm"
                      />
                    </div>
                    <p className="text-xs text-slate-500 mt-1.5">
                      Get your key from{" "}
                      <a href="http://localhost:8080" target="_blank" className="text-blue-400 hover:underline">http://localhost:8080</a>
                      {" "}→ REST API section.
                    </p>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-1.5">MobSF URL (internal)</label>
                    <input
                      type="text"
                      value={mobsfUrl}
                      onChange={(e) => setMobsfUrl(e.target.value)}
                      placeholder="http://mobsf:8000"
                      className="w-full bg-[#141620] border border-[#334155] rounded-lg px-4 py-2.5 text-white placeholder-slate-600 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 transition-all font-mono text-sm"
                    />
                  </div>
                </div>
              </div>
              {/* LLM Integration */}
              <div className="glass-panel p-6">
                <SectionHeader
                  title="LLM / AI Integration"
                  description="Enable AI-powered triage and auto-remediation code generation."
                  icon={Cpu}
                />
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-1.5">Primary Provider</label>
                    <select
                      value={llmProvider}
                      onChange={(e) => setLlmProvider(e.target.value)}
                      className="w-full bg-[#141620] border border-[#334155] rounded-lg px-4 py-2.5 text-white focus:outline-none focus:border-blue-500 transition-all font-sans text-sm"
                    >
                      <option value="ollama">Ollama (Local - Free)</option>
                      <option value="openai">OpenAI (Cloud - Paid)</option>
                    </select>
                  </div>

                  {llmProvider === "openai" ? (
                    <div>
                      <label className="block text-sm font-medium text-slate-300 mb-1.5">OpenAI API Key</label>
                      <div className="relative">
                        <Key size={16} className="absolute left-3 top-3 text-slate-500" />
                        <input
                          type="password"
                          value={openaiKey}
                          onChange={(e) => setOpenaiKey(e.target.value)}
                          placeholder="sk-..."
                          className="w-full bg-[#141620] border border-[#334155] rounded-lg pl-9 pr-4 py-2.5 text-white placeholder-slate-600 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 transition-all font-mono text-sm"
                        />
                      </div>
                    </div>
                  ) : (
                    <div>
                      <label className="block text-sm font-medium text-slate-300 mb-1.5">Ollama URL</label>
                      <div className="relative">
                        <RefreshCw size={16} className="absolute left-3 top-3 text-slate-500" />
                        <input
                          type="text"
                          value={ollamaUrl}
                          onChange={(e) => setOllamaUrl(e.target.value)}
                          placeholder="http://host.docker.internal:11434"
                          className="w-full bg-[#141620] border border-[#334155] rounded-lg pl-9 pr-4 py-2.5 text-white placeholder-slate-600 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 transition-all font-mono text-sm"
                        />
                      </div>
                      <p className="text-xs text-slate-500 mt-1.5">Use <b>host.docker.internal</b> to reach Ollama on your host machine from Docker.</p>
                    </div>
                  )}

                  <div className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-sm ${llmProvider === 'ollama' || (llmProvider === 'openai' && openaiKey) ? "bg-green-500/5 border-green-500/20 text-green-400" : "bg-slate-800/50 border-[#334155] text-slate-500"}`}>
                    <div className={`w-2 h-2 rounded-full ${llmProvider === 'ollama' || (llmProvider === 'openai' && openaiKey) ? "bg-green-500 animate-pulse" : "bg-slate-600"}`} />
                    {llmProvider === 'ollama' ? "Local LLM ready" : openaiKey ? "OpenAI enabled" : "Missing API Key"}
                  </div>
                </div>
              </div>


              {/* Scan Preferences */}
              <div className="glass-panel p-6">
                <SectionHeader
                  title="Scan Preferences"
                  description="Adjust timeouts and scan behaviour."
                  icon={RefreshCw}
                />
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-1.5">
                    Scan Timeout (seconds)
                    <span className="ml-2 text-blue-400 font-bold">{scanTimeout}s</span>
                  </label>
                  <input
                    type="range"
                    min="60"
                    max="900"
                    step="30"
                    value={scanTimeout}
                    onChange={(e) => setScanTimeout(e.target.value)}
                    className="w-full accent-blue-500"
                  />
                  <div className="flex justify-between text-xs text-slate-600 mt-1">
                    <span>60s</span><span>15min</span>
                  </div>
                </div>
              </div>

              <div className="flex justify-end">
                <button onClick={handleSaveIntegrations} className="premium-button flex items-center gap-2">
                  <Save size={16} /> Save Integration Settings
                </button>
              </div>
            </div>
          )}

          {/* ─── Danger Zone Tab ─── */}
          {activeTab === "danger" && (
            <div className="glass-panel p-6 border border-red-500/20">
              <SectionHeader
                title="Danger Zone"
                description="These actions are irreversible. Please be absolutely sure."
                icon={Trash2}
              />

              <div className="space-y-4">
                <div className="p-4 bg-red-500/5 border border-red-500/15 rounded-xl flex items-center justify-between gap-4">
                  <div>
                    <p className="font-semibold text-white text-sm">Delete All Scans</p>
                    <p className="text-xs text-slate-400 mt-0.5">Permanently remove all scan history and findings from your account.</p>
                  </div>
                  <button
                    onClick={async () => {
                      if (confirm("Delete ALL scans and their findings? This cannot be undone.")) {
                        try {
                          await api.delete("/scans/");
                          showToast("All scans have been successfully deleted.", "success");
                        } catch (err: any) {
                          showToast(err.message || "Failed to delete scans.", "error");
                        }
                      }
                    }}
                    className="flex-shrink-0 px-4 py-2 bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 text-red-400 rounded-lg text-sm font-medium transition-all"
                  >
                    Delete All Scans
                  </button>
                </div>

                <div className="p-4 bg-red-500/5 border border-red-500/15 rounded-xl flex items-center justify-between gap-4">
                  <div>
                    <p className="font-semibold text-white text-sm">Delete Account</p>
                    <p className="text-xs text-slate-400 mt-0.5">Permanently delete your account, all projects, scans and reports.</p>
                  </div>
                  <button
                    onClick={() => {
                      if (confirm("Delete your account permanently? This cannot be undone.")) {
                        showToast("Account deletion is not yet implemented. Contact your administrator.", "error");
                      }
                    }}
                    className="flex-shrink-0 px-4 py-2 bg-red-600/20 hover:bg-red-600/30 border border-red-600/30 text-red-400 rounded-lg text-sm font-medium transition-all"
                  >
                    Delete Account
                  </button>
                </div>
              </div>

              <div className="mt-6 p-4 bg-amber-500/5 border border-amber-500/15 rounded-xl">
                <p className="text-xs text-amber-400 flex items-start gap-2">
                  <AlertCircle size={14} className="flex-shrink-0 mt-0.5" />
                  All destructive actions require confirmation and are logged for security audit purposes.
                </p>
              </div>
            </div>
          )}

        </div>
      </div>

      {/* Toast notification */}
      {toast && <Toast message={toast.message} type={toast.type} />}
    </div>
  );
}
