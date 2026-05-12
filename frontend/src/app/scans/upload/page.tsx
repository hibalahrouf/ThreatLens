"use client";

import { useState, useRef } from "react";
import { UploadCloud, CheckCircle2, ShieldAlert, FileText, ArrowRight, X, Cpu, Search, Package, Zap, FlaskConical, Info } from "lucide-react";
import { useRouter } from "next/navigation";
import { api } from "@/services/api";

const PIPELINE_STEPS = [
  { icon: Search, label: "MobSF Static Analysis", desc: "Deep APK decompilation & SAST" },
  { icon: ShieldAlert, label: "MASVS v2 Mapping", desc: "Map to 7 MASVS categories" },
  { icon: Cpu, label: "AI Triage (Ollama)", desc: "LLM false-positive detection" },
  { icon: Package, label: "SBOM & CVE Scan", desc: "OSV.dev dependency audit" },
  { icon: FileText, label: "Report Generation", desc: "PDF / SARIF / Markdown" },
];

export default function UploadPage() {
  const router = useRouter();
  const [isDragging, setIsDragging] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [projectName, setProjectName] = useState("Default Project");
  const [appVersion, setAppVersion] = useState("1.0.0");
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [scanStatus, setScanStatus] = useState("Waiting for upload...");
  const [scanError, setScanError] = useState("");
  const [activeStep, setActiveStep] = useState(0);
  const wsRef = useRef<WebSocket | null>(null);
  const [scanMode, setScanMode] = useState<"static" | "dynamic">("static");

  const handleFile = (selected: File) => {
    if (!selected.name.endsWith('.apk') && !selected.name.endsWith('.ipa')) {
      alert("Please upload a valid Android (.apk) or iOS (.ipa) application file.");
      return;
    }
    setFile(selected);
  };

  const startScan = async () => {
    if (!file) return;
    setIsScanning(true);
    setScanStatus("Uploading securely to audit engine...");
    setScanError("");
    setActiveStep(0);

    try {
      const formData = new FormData();
      formData.append("file", file);
      if (projectName) formData.append("project_name", projectName);
      if (appVersion) formData.append("app_version", appVersion);
      formData.append("scan_mode", scanMode);

      const response = await api.upload("/scans/upload", formData);
      const scanId = response.scan_id;
      if (!scanId) throw new Error("Invalid response: No scan_id received");

      setScanStatus("Upload complete. Connecting to analysis engine...");
      connectWebSocket(scanId);
    } catch (err: any) {
      setScanError(err.message || "Failed to start upload");
      setIsScanning(false);
    }
  };

  const connectWebSocket = (scanId: number) => {
    const token = localStorage.getItem("masvs_token");
    const wsUrl = api.getWsUrl(`/scans/${scanId}/ws?token=${token || ""}`);
    wsRef.current = new WebSocket(wsUrl);

    wsRef.current.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        const p = data.progress || 0;
        setProgress(p);
        setScanStatus(data.status || "Processing...");
        // Update active pipeline step based on progress
        setActiveStep(Math.min(Math.floor(p / 20), 4));

        if (data.status === "failed") { wsRef.current?.close(); setScanError(data.error_message || "Scan pipeline failed."); }
        if (data.status === "done" || p === 100) {
          wsRef.current?.close();
          setActiveStep(5);
          setTimeout(() => router.push(`/scans/${scanId}`), 1500);
        }
      } catch (e) {}
    };
    wsRef.current.onerror = () => setScanError("Connection to scan engine lost.");
  };

  return (
    <div className="max-w-4xl mx-auto p-7">
      {/* Header */}
      <div className="mb-8">
        <p className="text-[11px] font-bold uppercase tracking-[0.22em] text-[var(--fg-muted)] mb-1.5">Audit</p>
        <h1 className="font-heading text-[32px] leading-tight font-bold text-[var(--fg)]">New Security Audit</h1>
        <p className="text-[var(--fg-muted)] text-sm mt-1">Upload your Android APK or iOS IPA to begin automated MASVS v2 compliance scanning.</p>
      </div>

      {!isScanning ? (
        <div className="space-y-5">
          {/* Drop Zone */}
          <div
            onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
            onDragLeave={() => setIsDragging(false)}
            onDrop={(e) => { e.preventDefault(); setIsDragging(false); if (e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0]); }}
            className="relative rounded-[28px] transition-all duration-300 overflow-hidden"
            style={{
              background: isDragging
                ? 'linear-gradient(135deg, rgba(23,105,255,0.12) 0%, rgba(20,184,166,0.10) 100%)'
                : '#FFFFFF',
              border: `2px dashed ${isDragging ? 'rgba(23,105,255,0.48)' : file ? 'rgba(20,184,166,0.42)' : 'rgba(23,105,255,0.20)'}`,
              boxShadow: isDragging ? '0 20px 48px rgba(23,105,255,0.14)' : '0 14px 34px rgba(16,24,40,0.08)',
            }}
          >
            <input
              type="file"
              accept=".apk,.ipa"
              onChange={(e) => { if (e.target.files?.[0]) handleFile(e.target.files[0]); }}
              className="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-10"
            />
            <div className="flex flex-col items-center justify-center py-14 px-6 text-center">
              <div className={`w-16 h-16 rounded-2xl flex items-center justify-center mb-4 transition-all duration-300 ${
                isDragging ? 'scale-110' : ''
              }`}
                style={{
                  background: file
                    ? 'linear-gradient(135deg, rgba(20,184,166,0.18), rgba(20,184,166,0.08))'
                    : isDragging
                      ? 'linear-gradient(135deg, rgba(23,105,255,0.18), rgba(20,184,166,0.12))'
                      : 'rgba(23,105,255,0.08)',
                  border: `1px solid ${file ? 'rgba(20,184,166,0.3)' : 'rgba(23,105,255,0.14)'}`,
                }}
              >
                {file
                  ? <CheckCircle2 size={28} className="text-emerald-400" />
                  : <UploadCloud size={28} style={{ color: isDragging ? '#1769FF' : '#667085' }} />
                }
              </div>

              {file ? (
                <div className="space-y-1 pointer-events-none">
                  <p className="font-semibold text-[var(--fg)] text-sm">{file.name}</p>
                  <p className="text-xs text-slate-500">{(file.size / (1024 * 1024)).toFixed(2)} MB • Ready to scan</p>
                </div>
              ) : (
                <div>
                  <p className="text-base text-[var(--fg)] font-medium mb-1">
                    <span style={{ color: '#1769FF' }}>Click to upload</span> or drag and drop
                  </p>
                  <p className="text-xs text-slate-600">Android (.apk) and iOS (.ipa) supported</p>
                </div>
              )}
            </div>

            {file && (
              <button
                onClick={(e) => { e.stopPropagation(); setFile(null); }}
                className="absolute top-3 right-3 z-20 w-7 h-7 flex items-center justify-center rounded-lg text-slate-500 hover:text-white transition-colors"
                style={{ background: 'rgba(23,105,255,0.08)', border: '1px solid rgba(23,105,255,0.14)' }}
              >
                <X size={14} />
              </button>
            )}
          </div>

          {/* Config + Pipeline grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Configuration */}
            <div className="glass-panel p-5">
              <h3 className="text-xs font-bold uppercase tracking-widest text-slate-500 mb-4">Audit Configuration</h3>
              <div className="space-y-3">
                <div>
                  <label className="block text-xs font-medium text-slate-500 mb-1.5">Project Name</label>
                  <input
                    type="text"
                    value={projectName}
                    onChange={(e) => setProjectName(e.target.value)}
                    placeholder="e.g. Banking App"
                    className="input-field text-sm py-2.5"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-500 mb-1.5">App Version</label>
                  <input
                    type="text"
                    value={appVersion}
                    onChange={(e) => setAppVersion(e.target.value)}
                    placeholder="e.g. 2.4.1"
                    className="input-field text-sm py-2.5"
                  />
                </div>
              </div>
            </div>

            {/* Pipeline steps */}
            <div className="glass-panel p-5">
              <h3 className="text-xs font-bold uppercase tracking-widest text-slate-500 mb-4">Analysis Pipeline</h3>
              <ul className="space-y-2.5">
                {PIPELINE_STEPS.map(({ icon: Icon, label, desc }) => (
                  <li key={label} className="flex items-center gap-3">
                    <div className="w-6 h-6 rounded-md flex items-center justify-center flex-shrink-0"
                      style={{ background: 'rgba(23,105,255,0.08)', border: '1px solid rgba(23,105,255,0.12)' }}
                    >
                      <Icon size={12} style={{ color: 'var(--accent)' }} />
                    </div>
                    <div>
                      <p className="text-xs font-medium text-slate-300">{label}</p>
                      <p className="text-[10px] text-slate-600">{desc}</p>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* ── Scan Mode Toggle ── */}
          <div className="glass-panel p-5">
            <h3 className="text-xs font-bold uppercase tracking-widest text-slate-500 mb-4">Scan Mode</h3>
            <div className="grid grid-cols-2 gap-3">
              {/* Static */}
              <button
                type="button"
                onClick={() => setScanMode("static")}
                className={`group relative rounded-xl p-4 text-left transition-all duration-200 cursor-pointer border ${
                  scanMode === "static"
                    ? "bg-[rgba(23,105,255,0.08)] border-[rgba(23,105,255,0.24)]"
                    : "bg-white border-[var(--border)] hover:border-[var(--border-hover)]"
                }`}
                style={scanMode === "static" ? { boxShadow: '0 14px 28px rgba(23,105,255,0.10)' } : {}}
              >
                <div className="flex items-center gap-2.5 mb-2">
                  <div className={`w-8 h-8 rounded-lg flex items-center justify-center transition-colors ${
                    scanMode === "static"
                      ? "bg-[rgba(23,105,255,0.14)] border border-[rgba(23,105,255,0.24)]"
                      : "bg-slate-500/8 border border-slate-500/15"
                  }`}>
                    <Zap size={16} className={scanMode === "static" ? "text-[var(--accent)]" : "text-slate-500"} />
                  </div>
                  <span className={`text-sm font-semibold ${
                    scanMode === "static" ? "text-[var(--fg)]" : "text-slate-400"
                  }`}>Static Analysis</span>
                </div>
                <p className="text-[11px] text-slate-500 leading-relaxed pl-[42px]">
                  MobSF static scan only. Fast (~2 min).
                </p>
                {scanMode === "static" && (
                  <div className="absolute top-3 right-3 w-2 h-2 rounded-full bg-[var(--accent)]" />
                )}
              </button>

              {/* Dynamic */}
              <button
                type="button"
                onClick={() => setScanMode("dynamic")}
                className={`group relative rounded-xl p-4 text-left transition-all duration-200 cursor-pointer border ${
                  scanMode === "dynamic"
                    ? "bg-[rgba(124,58,237,0.08)] border-[rgba(124,58,237,0.24)]"
                    : "bg-white border-[var(--border)] hover:border-[var(--border-hover)]"
                }`}
                style={scanMode === "dynamic" ? { boxShadow: '0 14px 28px rgba(124,58,237,0.10)' } : {}}
              >
                <div className="flex items-center gap-2.5 mb-2">
                  <div className={`w-8 h-8 rounded-lg flex items-center justify-center transition-colors ${
                    scanMode === "dynamic"
                      ? "bg-[rgba(124,58,237,0.14)] border border-[rgba(124,58,237,0.24)]"
                      : "bg-slate-500/8 border border-slate-500/15"
                  }`}>
                    <FlaskConical size={16} className={scanMode === "dynamic" ? "text-[#7C3AED]" : "text-slate-500"} />
                  </div>
                  <span className={`text-sm font-semibold ${
                    scanMode === "dynamic" ? "text-[var(--fg)]" : "text-slate-400"
                  }`}>Static + Dynamic</span>
                </div>
                <p className="text-[11px] text-slate-500 leading-relaxed pl-[42px]">
                  Static + runtime analysis on Android emulator. (~5 min)
                </p>
                {scanMode === "dynamic" && (
                  <div className="absolute top-3 right-3 w-2 h-2 rounded-full bg-[#7C3AED]" />
                )}
              </button>
            </div>

            {/* Info note for dynamic mode */}
            {scanMode === "dynamic" && (
              <div className="mt-3 flex items-start gap-2 p-2.5 rounded-lg border" style={{ background: 'rgba(124,58,237,0.06)', borderColor: 'rgba(124,58,237,0.14)' }}>
                <Info size={14} className="text-[#7C3AED] flex-shrink-0 mt-0.5" />
                <p className="text-[11px] leading-relaxed" style={{ color: '#7C3AED' }}>
                  Requires Android emulator (AVD) to be running. Dynamic analysis will start automatically after static scan completes.
                </p>
              </div>
            )}
          </div>

          {scanError && (
            <div className="p-4 rounded-xl text-sm flex items-start gap-3"
              style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)', color: '#f87171' }}
            >
              <ShieldAlert size={16} className="flex-shrink-0 mt-0.5" />
              {scanError}
            </div>
          )}

          <div className="flex justify-end">
            <button
              onClick={startScan}
              disabled={!file}
              className="premium-button flex items-center gap-2 px-8 py-3"
            >
              Start Security Audit <ArrowRight size={16} />
            </button>
          </div>
        </div>
      ) : (
        /* Scanning progress */
        <div className="rounded-[28px] p-10 text-center max-w-md mx-auto"
          style={{
            background: '#FFFFFF',
            border: '1px solid rgba(16,24,40,0.10)',
            boxShadow: '0 18px 44px rgba(16,24,40,0.10)',
          }}
        >
          {scanError ? (
            <div className="text-red-400">
              <ShieldAlert size={48} className="mx-auto mb-4 opacity-70" />
              <h2 className="text-lg font-bold mb-2">Analysis Failed</h2>
              <p className="text-sm text-red-400/70 mb-6">{scanError}</p>
              <button
                onClick={() => { setIsScanning(false); setScanError(""); setProgress(0); }}
                className="premium-button-outline text-sm px-5 py-2"
              >
                Try Again
              </button>
            </div>
          ) : (
            <>
              {/* SVG Progress Ring */}
              <div className="relative w-28 h-28 mx-auto mb-7">
                <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
                  <circle cx="50" cy="50" r="44" fill="none" stroke="rgba(23,105,255,0.10)" strokeWidth="6" />
                  <circle
                    cx="50" cy="50" r="44" fill="none"
                    stroke="url(#ringGrad)"
                    strokeWidth="6" strokeLinecap="round"
                    strokeDasharray="276.5"
                    strokeDashoffset={276.5 - (276.5 * progress) / 100}
                    className="transition-all duration-1000 ease-in-out"
                  />
                  <defs>
                    <linearGradient id="ringGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                      <stop offset="0%" stopColor="#1769FF" />
                      <stop offset="100%" stopColor="#14B8A6" />
                    </linearGradient>
                  </defs>
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <span className="text-2xl font-bold font-heading text-[var(--fg)]">{progress}%</span>
                </div>
              </div>

              <h2 className="text-base font-bold text-[var(--fg)] mb-1 capitalize">{scanStatus}</h2>
              <p className="text-xs text-slate-600 mb-7">Do not close this window. This may take a few minutes.</p>

              {/* Mini pipeline progress */}
              <div className="space-y-2 text-left">
                {PIPELINE_STEPS.map(({ icon: Icon, label }, idx) => {
                  const done = idx < activeStep;
                  const active = idx === activeStep;
                  return (
                    <div key={label} className="flex items-center gap-2.5 px-3 py-2 rounded-lg transition-all"
                      style={{
                        background: active ? 'rgba(23,105,255,0.08)' : done ? 'rgba(20,184,166,0.06)' : 'transparent',
                        border: `1px solid ${active ? 'rgba(23,105,255,0.2)' : done ? 'rgba(20,184,166,0.14)' : 'rgba(16,24,40,0.06)'}`,
                      }}
                    >
                      <div className="w-5 h-5 flex-shrink-0 flex items-center justify-center">
                        {done
                          ? <CheckCircle2 size={14} className="text-emerald-400" />
                          : <Icon size={14} style={{ color: active ? '#1769FF' : '#98A2B3' }} className={active ? 'animate-pulse' : ''} />
                        }
                      </div>
                      <span className="text-xs" style={{ color: active ? '#1769FF' : done ? '#667085' : '#98A2B3' }}>
                        {label}
                      </span>
                    </div>
                  );
                })}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}
