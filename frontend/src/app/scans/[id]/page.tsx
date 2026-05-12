"use client";

import { useState, useEffect, useRef, useCallback, use } from "react";
import Link from "next/link";
import { Download, ChevronLeft, ShieldAlert, CheckCircle, Code, Loader2, Cpu, Check, X, AlertTriangle, Lock, Wifi, Smartphone, Database, KeyRound, Fingerprint, Shield, Clock, ListOrdered, Crosshair, ChevronDown, Search, Activity, Zap, Ban, MessageSquare, ThumbsUp, ThumbsDown, ShieldCheck } from "lucide-react";
import { api } from "@/services/api";

type ScanData = {
  id: number;
  file_name: string;
  score: number | null;
  grade: string;
  status: string;
  started_at: string;
  scan_mode?: string;
  dynamic_status?: string;
  dynamic_error?: string | null;
};

type Finding = {
  id: number;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  masvs_control: string;
  cvss_score: number | null;
  cvss_vector: string;
  triage_result: string;
  triage_justification: string | null;
  test_name: string | null;
  description: string;
  remediation_description: string | null;
  remediation_code: string | null;
  estimated_effort_hours?: number | null;
  priority_label?: string | null;
  mapping_confidence?: number | null;
  root_cause?: string | null;
  source?: string;
  status?: string;
};

export default function ReportPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [activeTab, setActiveTab] = useState("findings");
  const [scanData, setScanData] = useState<ScanData | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState("");
  const [expandedFinding, setExpandedFinding] = useState<number | null>(null);
  const [filterSeverity, setFilterSeverity] = useState("all");
  const [filterCategory, setFilterCategory] = useState("all");
  const [filterAI, setFilterAI] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");

  // ─── Auditor HITL Feedback State ───
  const [feedbackModal, setFeedbackModal] = useState<{ findingId: number; action: string; title: string } | null>(null);
  const [feedbackReason, setFeedbackReason] = useState("");
  const [feedbackLoading, setFeedbackLoading] = useState(false);

  // ─── Auto-polling for dynamic analysis status (Task 3) ───
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const CANCELLABLE = new Set(["pending", "running", "analyzing", "uploading", "generating_report"]);

  const cancelScan = async () => {
    if (!confirm("Cancel this scan?")) return;
    try {
      await api.post(`/scans/${id}/cancel`, {});
      fetchScanData();
    } catch (err) {
      console.error("Failed to cancel scan:", err);
    }
  };

  const fetchScanData = useCallback(async () => {
    try {
      const parentScan = await api.get(`/scans/${id}`);
      setScanData(parentScan);

      const fList = await api.get(`/scans/${id}/findings`);
      setFindings(fList || []);
    } catch (err: any) {
      setError(err.message || "Failed to fetch scan report.");
    } finally {
      setIsLoading(false);
    }
  }, [id]);

  useEffect(() => {
    fetchScanData();
  }, [fetchScanData]);

  // Poll when dynamic_status is "queued" or "running"
  useEffect(() => {
    const dynStatus = scanData?.dynamic_status;
    if (dynStatus === "queued" || dynStatus === "running") {
      pollingRef.current = setInterval(async () => {
        try {
          const updated = await api.get(`/scans/${id}`);
          setScanData(updated);
          // Also refresh findings when dynamic completes
          if (updated?.dynamic_status === "completed" || updated?.dynamic_status === "failed") {
            const fList = await api.get(`/scans/${id}/findings`);
            setFindings(fList || []);
          }
        } catch {
          // Silently ignore polling errors
        }
      }, 5000);
    } else {
      if (pollingRef.current) {
        clearInterval(pollingRef.current);
        pollingRef.current = null;
      }
    }
    return () => {
      if (pollingRef.current) {
        clearInterval(pollingRef.current);
        pollingRef.current = null;
      }
    };
  }, [scanData?.dynamic_status, id]);

  const getSeverityCount = (severity: string) => {
    return findings.filter(f => f.severity.toLowerCase() === severity).length;
  };

  const downloadReport = async (format: "pdf" | "markdown" | "sarif") => {
    try {
      const response = await api.post(`/reports/${id}/${format}`, {});
      if (response && response.download_url) {
        // Use authenticated api.download to fetch the file binary data (Blob)
        const endpoint = response.download_url.replace('/api', '');
        const blob = await api.download(endpoint);
        
        // Create an Object URL and trigger a hidden download link
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;
        // Extract filename from download_url or provide a default
        a.download = `audit_report_${id}.${format}`;
        
        document.body.appendChild(a);
        a.click();
        
        // Cleanup
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
      }
    } catch (err) {
      console.error("Download failed:", err);
      alert("Failed to generate report.");
    }
  };

  // ─── Auditor HITL: Update Finding Status ───
  const updateFindingStatus = async (findingId: number, newStatus: string, reason?: string) => {
    try {
      setFeedbackLoading(true);
      await api.patch(`/findings/${findingId}/status`, {
        status: newStatus,
        reason: reason || undefined,
      });
      const fList = await api.get(`/scans/${id}/findings`);
      setFindings(fList || []);
      setFeedbackModal(null);
      setFeedbackReason("");
    } catch (err) {
      console.error("Failed to update finding status:", err);
      alert("Failed to update finding status.");
    } finally {
      setFeedbackLoading(false);
    }
  };

  if (isLoading) {
    return (
      <div className="h-full flex items-center justify-center">
        <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    );
  }

  if (error || !scanData) {
    return (
      <div className="max-w-6xl mx-auto space-y-6 pt-10">
        <div className="p-6 bg-red-500/10 border border-red-500/20 text-red-500 rounded-xl text-center">
           <ShieldAlert className="mx-auto mb-3 h-8 w-8" />
           {error || "Report not found."}
           <div className="mt-4">
             <Link href="/" className="text-blue-400 hover:underline">Back to Dashboard</Link>
           </div>
        </div>
      </div>
    );
  }

  // ─── Executive Summary Computed Values ───
  const score = scanData.score ?? 0;
  const grade = scanData.grade || '?';
  const riskLevel = score < 40
    ? { label: 'Critical Risk', color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/20', ring: '#f87171', glow: 'rgba(248,113,113,0.15)' }
    : score < 60
    ? { label: 'High Risk', color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/20', ring: '#fb923c', glow: 'rgba(251,146,60,0.15)' }
    : score < 80
    ? { label: 'Medium Risk', color: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/20', ring: '#fbbf24', glow: 'rgba(251,191,36,0.15)' }
    : { label: 'Low Risk', color: 'text-green-400', bg: 'bg-green-500/10', border: 'border-green-500/20', ring: '#4ade80', glow: 'rgba(74,222,128,0.15)' };

  const totalFindings = findings.length;
  const confirmed = findings.filter(f => f.triage_result === 'true_positive').length;
  const dismissed = findings.filter(f => f.triage_result === 'false_positive').length;
  const masvsFailed = new Set(
    findings.filter(f => f.triage_result !== 'false_positive' && f.masvs_control).map(f => f.masvs_control)
  ).size;

  const sevOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const highestRiskFinding = [...findings]
    .filter(f => f.triage_result !== 'false_positive')
    .sort((a, b) => (sevOrder[a.severity] ?? 5) - (sevOrder[b.severity] ?? 5) || (b.cvss_score ?? 0) - (a.cvss_score ?? 0))[0] || null;

  const critCount = findings.filter(f => f.severity === 'critical' && f.triage_result !== 'false_positive').length;
  const highCount = findings.filter(f => f.severity === 'high' && f.triage_result !== 'false_positive').length;
  const summaryText = (critCount > 0 || highCount > 0)
    ? `Immediate remediation is required for ${critCount + highCount} high-risk vulnerabilit${(critCount + highCount) === 1 ? 'y' : 'ies'} affecting authentication and platform security.`
    : totalFindings > 0
      ? 'The application security posture is acceptable. Remaining findings are recommendations for hardening.'
      : 'No security findings detected. The application meets baseline MASVS compliance.';

  const scoreRadius = 54;
  const scoreStroke = 7;
  const scoreCircumference = 2 * Math.PI * scoreRadius;
  const scoreDashOffset = scoreCircumference * (1 - score / 100);

  return (
    <div className="max-w-[1600px] mx-auto pb-12 px-7">
      {/* Top Header Row */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Link href="/" className="p-2 bg-white rounded-xl border border-[var(--border)] hover:bg-[var(--accent-dim)] transition-colors shadow-sm">
            <ChevronLeft size={20} className="text-slate-300" />
          </Link>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h1 className="text-[28px] leading-tight font-bold font-heading text-[var(--fg)]">Security Audit #{scanData.id}</h1>
              {/* ── Scan Mode Badge ── */}
              {scanData.scan_mode === "dynamic" ? (
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-blue-500/12 text-blue-400 border border-blue-500/20">
                  Dynamic
                </span>
              ) : (
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-slate-500/12 text-slate-400 border border-slate-500/20">
                  Static
                </span>
              )}
              {/* ── Dynamic Status Badge (only for dynamic scans) ── */}
              {scanData.scan_mode === "dynamic" && scanData.dynamic_status && scanData.dynamic_status !== "not_requested" && (
                <>
                  {scanData.dynamic_status === "queued" && (
                    <span className="flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-slate-500/12 text-slate-400 border border-slate-500/20">
                      <Clock size={10} /> Queued
                    </span>
                  )}
                  {scanData.dynamic_status === "running" && (
                    <span className="pulse-badge flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-orange-500/12 text-orange-400 border border-orange-500/20">
                      <Activity size={10} /> Dynamic Running...
                    </span>
                  )}
                  {scanData.dynamic_status === "completed" && (
                    <span className="flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-green-500/12 text-green-400 border border-green-500/20">
                      <Check size={10} /> Dynamic ✓
                    </span>
                  )}
                  {scanData.dynamic_status === "failed" && (
                    <span className="flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-red-500/12 text-red-400 border border-red-500/20">
                      <X size={10} /> Dynamic Failed
                    </span>
                  )}
                </>
              )}
            </div>
            <p className="text-slate-400 text-sm">{scanData.file_name} • {new Date(scanData.started_at).toLocaleString()}</p>
            {/* Dynamic error message */}
            {scanData.scan_mode === "dynamic" && scanData.dynamic_status === "failed" && scanData.dynamic_error && (
              <p className="text-xs text-red-400/80 mt-1 font-mono bg-red-500/5 border border-red-500/10 rounded px-2 py-1">
                {scanData.dynamic_error}
              </p>
            )}
          </div>
        </div>
        
        <div className="flex items-center gap-3">
          {scanData.status && CANCELLABLE.has(scanData.status) && (
            <button onClick={cancelScan} className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg text-red-400 bg-red-500/10 hover:bg-red-500/20 border border-red-500/20 transition-all cursor-pointer">
              <Ban size={16} /> Cancel Scan
            </button>
          )}
          <button onClick={() => downloadReport("sarif")} className="premium-button-outline flex items-center gap-2">
            <Download size={16} /> Export SARIF
          </button>
          <button onClick={() => downloadReport("pdf")} className="premium-button flex items-center gap-2">
            <Download size={16} /> PDF Report
          </button>
        </div>
      </div>

      {/* ═══ Dashboard Grid ═══ */}
      <div className="grid grid-cols-12 gap-4 mt-4">

      {/* ═══ Executive Summary ═══ */}
      <div className="glass-panel overflow-hidden col-span-12 lg:col-span-4">
        {/* Card Header */}
        <div className="px-4 py-3 border-b border-[var(--border)] bg-[var(--accent-dim)] flex items-center gap-2">
          <ShieldAlert size={18} className="text-cyan-400" />
          <h2 className="text-sm font-bold text-[var(--fg)] uppercase tracking-wider">Executive Summary</h2>
        </div>

        <div className="p-4 space-y-4">
          {/* Score Row */}
          <div className="flex items-center gap-4 flex-wrap">
            {/* SVG Score Ring */}
            <div className="relative flex-shrink-0">
              <svg width="110" height="110" viewBox="0 0 128 128">
                <circle cx="64" cy="64" r={scoreRadius} fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth={scoreStroke} />
                <circle
                  cx="64" cy="64" r={scoreRadius}
                  fill="none"
                  stroke={riskLevel.ring}
                  strokeWidth={scoreStroke}
                  strokeLinecap="round"
                  strokeDasharray={scoreCircumference}
                  strokeDashoffset={scoreDashOffset}
                  transform="rotate(-90 64 64)"
                  style={{ transition: 'stroke-dashoffset 1s ease-out', filter: `drop-shadow(0 0 6px ${riskLevel.glow})` }}
                />
                <text x="64" y="58" textAnchor="middle" fill="var(--fg)" fontSize="28" fontWeight="700" style={{ fontFamily: 'var(--font-heading, Syne, sans-serif)' }}>
                  {score.toFixed(0)}
                </text>
                <text x="64" y="78" textAnchor="middle" fill="var(--fg-muted)" fontSize="12">
                  / 100
                </text>
              </svg>
            </div>

            {/* Score Info */}
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-2 flex-wrap">
                <span className={`px-2 py-0.5 rounded-lg font-bold text-sm border ${riskLevel.bg} ${riskLevel.color} ${riskLevel.border}`}>
                  Grade {grade}
                </span>
                <span className={`px-2 py-0.5 rounded-lg text-xs font-semibold border ${riskLevel.bg} ${riskLevel.color} ${riskLevel.border}`}>
                  {riskLevel.label}
                </span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                {summaryText}
              </p>
            </div>
          </div>

          {/* Metric Cards */}
          <div className="grid grid-cols-2 gap-2">
            {[
              { label: 'Total', value: totalFindings, icon: <ShieldAlert size={14} />, accent: 'text-cyan-400', bg: 'bg-cyan-500/10', border: 'border-cyan-500/15' },
              { label: 'Confirmed', value: confirmed, icon: <CheckCircle size={14} />, accent: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/15' },
              { label: 'Dismissed', value: dismissed, icon: <X size={14} />, accent: 'text-slate-400', bg: 'bg-slate-500/10', border: 'border-slate-500/15' },
              { label: 'MASVS Fail', value: masvsFailed, icon: <AlertTriangle size={14} />, accent: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/15' },
            ].map((metric) => (
              <div key={metric.label} className={`rounded-lg p-2.5 border ${metric.bg} ${metric.border} transition-all`}>
                <div className={`flex items-center gap-1.5 mb-1 ${metric.accent}`}>
                  {metric.icon}
                  <span className="text-[10px] font-semibold uppercase tracking-wider">{metric.label}</span>
                </div>
                <span className="text-xl font-bold text-[var(--fg)] font-heading">{metric.value}</span>
              </div>
            ))}
          </div>

          {/* Primary Risk Alert */}
          {highestRiskFinding && (
            <div className={`flex items-start gap-2 p-3 rounded-lg border ${
              highestRiskFinding.severity === 'critical' ? 'bg-red-500/10 border-red-500/20' : 'bg-orange-500/10 border-orange-500/20'
            }`}>
              <AlertTriangle size={16} className={`mt-0.5 flex-shrink-0 ${
                highestRiskFinding.severity === 'critical' ? 'text-red-400' : 'text-orange-400'
              }`} />
              <div>
                <span className={`text-xs font-bold uppercase tracking-wider ${
                  highestRiskFinding.severity === 'critical' ? 'text-red-400' : 'text-orange-400'
                }`}>Primary Risk</span>
                <p className="text-sm text-slate-200 mt-0.5 font-medium">{highestRiskFinding.title}</p>
                {highestRiskFinding.masvs_control && (
                  <span className="text-xs font-mono text-slate-500 mt-1 inline-block">{highestRiskFinding.masvs_control}</span>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ═══ MASVS v2 Compliance Overview ═══ */}
      <div className="glass-panel overflow-hidden col-span-12 lg:col-span-4">
        <div className="px-4 py-3 border-b border-[var(--border)] bg-[var(--accent-dim)] flex items-center gap-2">
          <Shield size={18} className="text-cyan-400" />
          <h2 className="text-sm font-bold text-[var(--fg)] uppercase tracking-wider">MASVS v2 Compliance Overview</h2>
        </div>

        <div className="p-3">
          <div className="grid grid-cols-2 gap-2">
            {[
              { key: 'STORAGE', name: 'Storage', desc: 'Data at rest', icon: <Database size={16} /> },
              { key: 'CRYPTO', name: 'Crypto', desc: 'Cryptographic primitives', icon: <Lock size={16} /> },
              { key: 'AUTH', name: 'Auth', desc: 'Access control', icon: <KeyRound size={16} /> },
              { key: 'NETWORK', name: 'Network', desc: 'Data transmission', icon: <Wifi size={16} /> },
              { key: 'PLATFORM', name: 'Platform', desc: 'Platform APIs', icon: <Smartphone size={16} /> },
              { key: 'CODE', name: 'Code', desc: 'Code quality', icon: <Code size={16} /> },
              { key: 'RESILIENCE', name: 'Resilience', desc: 'Anti-tampering', icon: <Fingerprint size={16} /> },
            ].map((cat) => {
              const prefix = `MASVS-${cat.key}`;
              const activeFindings = findings.filter(
                f => f.triage_result !== 'false_positive' && f.masvs_control && f.masvs_control.toUpperCase().startsWith(prefix)
              );
              const hasIssues = activeFindings.length > 0;
              const hasFindingsAtAll = findings.length > 0;
              const status: 'ISSUES' | 'PASS' | 'NOT TESTED' = hasIssues
                ? 'ISSUES'
                : hasFindingsAtAll
                  ? 'PASS'
                  : 'NOT TESTED';
              const statusStyle = status === 'ISSUES'
                ? { badge: 'bg-red-500/10 text-red-400 border-red-500/20', card: 'border-red-500/15 hover:border-red-500/30', iconColor: 'text-red-400' }
                : status === 'PASS'
                  ? { badge: 'bg-green-500/10 text-green-400 border-green-500/20', card: 'border-green-500/15 hover:border-green-500/30', iconColor: 'text-green-400' }
                  : { badge: 'bg-slate-500/10 text-slate-500 border-slate-500/20', card: 'border-[#334155]/40 hover:border-[#334155]/70', iconColor: 'text-slate-500' };

              return (
                <div key={cat.key} className={`rounded-lg p-2.5 border bg-[#141620]/40 ${statusStyle.card} transition-all`}>
                  <div className="flex items-start justify-between mb-1.5">
                    <div className={`p-1.5 rounded-md bg-[#1e2130] ${statusStyle.iconColor}`}>
                      {cat.icon}
                    </div>
                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider border ${statusStyle.badge}`}>
                      {status === 'ISSUES' ? `${activeFindings.length} ISSUE${activeFindings.length > 1 ? 'S' : ''}` : status}
                    </span>
                  </div>
                  <h3 className="text-xs font-bold text-[var(--fg)] mb-0.5">{cat.name}</h3>
                  <p className="text-[10px] text-slate-500 leading-tight">{cat.desc}</p>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* ═══ Priority Action Plan ═══ */}
      {(() => {
        const activeFindingsSorted = [...findings]
          .filter(f => f.triage_result !== 'false_positive')
          .sort((a, b) => (sevOrder[a.severity] ?? 5) - (sevOrder[b.severity] ?? 5) || (b.cvss_score ?? 0) - (a.cvss_score ?? 0));

        const weekItems = activeFindingsSorted.filter(f => f.severity === 'critical' || f.severity === 'high');
        const monthItems = activeFindingsSorted.filter(f => f.severity === 'medium');
        const monitorItems = activeFindingsSorted.filter(f => f.severity === 'low' || f.severity === 'info');

        const getPriority = (sev: string) => {
          if (sev === 'critical' || sev === 'high') return { label: 'P1', cls: 'bg-red-500/15 text-red-400 border-red-500/25' };
          if (sev === 'medium') return { label: 'P2', cls: 'bg-amber-500/15 text-amber-400 border-amber-500/25' };
          return { label: 'P3', cls: 'bg-slate-500/15 text-slate-400 border-slate-500/25' };
        };

        const getEffort = (sev: string) => {
          if (sev === 'critical' || sev === 'high') return '1–2 days';
          if (sev === 'medium') return '3–5 days';
          return 'Monitor';
        };

        const renderRow = (f: Finding) => {
          const p = getPriority(f.severity);
          return (
            <div key={f.id} className="flex items-center gap-3 py-3 px-4 border-b border-[#334155]/20 last:border-b-0 hover:bg-[#1e2130]/30 transition-colors">
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${p.cls} flex-shrink-0`}>{p.label}</span>
              <span className="text-sm text-slate-200 flex-1 min-w-0 truncate" title={f.title}>{f.title}</span>
              <span className={`badge badge-${f.severity} flex-shrink-0 text-[10px]`}>{f.severity.toUpperCase()}</span>
              {f.masvs_control && <span className="text-[10px] font-mono text-slate-500 bg-black/20 px-1.5 py-0.5 rounded flex-shrink-0 hidden sm:inline">{f.masvs_control}</span>}
              <span className="text-[11px] text-slate-500 flex-shrink-0 w-16 text-right hidden md:inline">{getEffort(f.severity)}</span>
            </div>
          );
        };

        if (activeFindingsSorted.length === 0) return null;

        return (
          <div className="glass-panel overflow-hidden col-span-12 lg:col-span-4">
            <div className="px-4 py-3 border-b border-[var(--border)] bg-[var(--accent-dim)] flex items-center gap-2">
              <ListOrdered size={18} className="text-cyan-400" />
              <h2 className="text-sm font-bold text-[var(--fg)] uppercase tracking-wider">Priority Action Plan</h2>
            </div>

            <div className="divide-y divide-[#334155]/30">
              {/* Fix This Week */}
              {weekItems.length > 0 && (
                <div className="p-3">
                  <div className="flex items-center gap-2 mb-2">
                    <div className="w-2 h-2 rounded-full bg-red-400"></div>
                    <h3 className="text-xs font-bold text-red-400 uppercase tracking-wider">Fix This Week</h3>
                    <span className="text-[10px] text-slate-500 ml-1">({weekItems.length} item{weekItems.length > 1 ? 's' : ''})</span>
                  </div>
                  <div className="rounded-lg border border-red-500/10 bg-[#141620]/40 overflow-hidden">
                    {weekItems.slice(0, 3).map(renderRow)}
                  </div>
                  {weekItems.length > 3 && (
                    <p className="text-[10px] text-slate-500 mt-1 pl-2">View All ({weekItems.length})</p>
                  )}
                </div>
              )}

              {/* Fix This Month */}
              {monthItems.length > 0 && (
                <div className="p-3">
                  <div className="flex items-center gap-2 mb-2">
                    <div className="w-2 h-2 rounded-full bg-amber-400"></div>
                    <h3 className="text-xs font-bold text-amber-400 uppercase tracking-wider">Fix This Month</h3>
                    <span className="text-[10px] text-slate-500 ml-1">({monthItems.length} item{monthItems.length > 1 ? 's' : ''})</span>
                  </div>
                  <div className="rounded-lg border border-amber-500/10 bg-[#141620]/40 overflow-hidden">
                    {monthItems.slice(0, 2).map(renderRow)}
                  </div>
                  {monthItems.length > 2 && (
                    <p className="text-[10px] text-slate-500 mt-1 pl-2">View All ({monthItems.length})</p>
                  )}
                </div>
              )}

              {/* Monitor */}
              {monitorItems.length > 0 && (
                <div className="p-3">
                  <div className="flex items-center gap-2 mb-2">
                    <div className="w-2 h-2 rounded-full bg-slate-400"></div>
                    <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Monitor</h3>
                    <span className="text-[10px] text-slate-500 ml-1">({monitorItems.length} item{monitorItems.length > 1 ? 's' : ''})</span>
                  </div>
                  <div className="rounded-lg border border-[#334155]/30 bg-[#141620]/40 overflow-hidden">
                    {monitorItems.slice(0, 2).map(renderRow)}
                  </div>
                  {monitorItems.length > 2 && (
                    <p className="text-[10px] text-slate-500 mt-1 pl-2">View All ({monitorItems.length})</p>
                  )}
                </div>
              )}
            </div>
          </div>
        );
      })()}

      {/* ═══ Attack Scenarios ═══ */}
      {(() => {
        const activeFindings = findings.filter(f => f.triage_result !== 'false_positive');
        const matchFindings = (keywords: string[], controls: string[]) => {
          return activeFindings.filter(f => {
            const t = `${f.title} ${f.description}`.toLowerCase();
            const c = (f.masvs_control || '').toUpperCase();
            return keywords.some(k => t.includes(k)) || controls.some(p => c.startsWith(p));
          });
        };

        const scenarios: { title: string; risk: string; access: string; explanation: string; findings: Finding[]; riskColor: string }[] = [];

        const s1 = matchFindings(
          ['allowbackup', 'backup enabled', 'sensitive data storage', 'data stored', 'insecure storage'],
          ['MASVS-STORAGE']
        );
        if (s1.length > 0) scenarios.push({
          title: 'Local Data Extraction via ADB',
          risk: 'HIGH',
          access: 'Physical / ADB access',
          explanation: 'An attacker with physical or debugging access may extract local application data if backup is enabled or sensitive data is stored insecurely.',
          findings: s1,
          riskColor: 'red',
        });

        const s2 = matchFindings(
          ['exported activity', 'exported content provider', 'exported broadcast receiver', 'android:exported=true', 'not protected', 'exported component'],
          ['MASVS-PLATFORM', 'MASVS-AUTH']
        );
        if (s2.length > 0) scenarios.push({
          title: 'Unauthorized Component Access',
          risk: 'HIGH',
          access: 'Local malicious app',
          explanation: 'A malicious application installed on the same device may access exposed Android components and trigger sensitive application flows.',
          findings: s2,
          riskColor: 'orange',
        });

        const s3 = matchFindings(
          ['minsdk', 'targetsdk', 'outdated android', 'vulnerable unpatched', 'strandhogg', 'target sdk', 'min sdk'],
          []
        );
        if (s3.length > 0) scenarios.push({
          title: 'Platform Exploitation via Outdated SDK',
          risk: 'MEDIUM',
          access: 'Local / Remote',
          explanation: 'Outdated platform configuration can expose the application to known Android platform vulnerabilities and task hijacking attacks.',
          findings: s3,
          riskColor: 'amber',
        });

        const riskColors: Record<string, { badge: string; border: string; dot: string }> = {
          red: { badge: 'bg-red-500/10 text-red-400 border-red-500/20', border: 'border-red-500/15', dot: 'bg-red-400' },
          orange: { badge: 'bg-orange-500/10 text-orange-400 border-orange-500/20', border: 'border-orange-500/15', dot: 'bg-orange-400' },
          amber: { badge: 'bg-amber-500/10 text-amber-400 border-amber-500/20', border: 'border-amber-500/15', dot: 'bg-amber-400' },
        };

        return (
          <div className="glass-panel overflow-hidden col-span-12 lg:col-span-4">
            <div className="px-4 py-3 border-b border-[var(--border)] bg-[var(--accent-dim)] flex items-center gap-2">
              <Crosshair size={18} className="text-cyan-400" />
              <h2 className="text-sm font-bold text-[var(--fg)] uppercase tracking-wider">Attack Scenarios</h2>
            </div>

            <div className="p-4">
              {scenarios.length === 0 ? (
                <div className="text-center py-8">
                  <ShieldAlert size={32} className="mx-auto mb-3 text-slate-600" />
                  <p className="text-sm text-slate-500">No chained attack scenario detected from current static findings.</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {scenarios.slice(0, 2).map((sc) => {
                    const colors = riskColors[sc.riskColor] || riskColors.amber;
                    return (
                      <div key={sc.title} className={`rounded-xl border ${colors.border} bg-[#141620]/40 overflow-hidden`}>
                        <div className="p-4">
                          <div className="flex items-start justify-between mb-2 flex-wrap gap-2">
                            <div className="flex items-center gap-2">
                              <div className={`w-2 h-2 rounded-full ${colors.dot}`}></div>
                              <h3 className="text-sm font-bold text-[var(--fg)]">{sc.title}</h3>
                            </div>
                            <div className="flex items-center gap-2">
                              <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider border ${colors.badge}`}>{sc.risk}</span>
                              <span className="text-[10px] text-slate-500 bg-[#1e2130] px-2 py-0.5 rounded">{sc.access}</span>
                            </div>
                          </div>
                          <p className="text-xs text-slate-400 leading-relaxed mb-3">{sc.explanation}</p>
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="text-[10px] text-slate-500 font-semibold uppercase tracking-wider">Related ({sc.findings.length}):</span>
                            {sc.findings.slice(0, 3).map((f) => (
                              <span key={f.id} className="text-[10px] text-slate-400 bg-black/20 px-2 py-0.5 rounded border border-[#334155]/30 truncate max-w-[200px]" title={f.title}>{f.title}</span>
                            ))}
                            {sc.findings.length > 3 && (
                              <span className="text-[10px] text-slate-500">+{sc.findings.length - 3} more</span>
                            )}
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        );
      })()}

      {/* ═══ Detailed Findings ═══ */}
      {(() => {
        const q = searchQuery.toLowerCase();
        const filtered = findings.filter(f => {
          if (filterSeverity !== 'all' && f.severity !== filterSeverity) return false;
          if (filterCategory !== 'all' && !(f.masvs_control || '').toUpperCase().startsWith(`MASVS-${filterCategory}`)) return false;
          if (filterAI === 'confirmed' && f.triage_result !== 'true_positive') return false;
          if (filterAI === 'dismissed' && f.triage_result !== 'false_positive') return false;
          if (filterAI === 'review' && (f.triage_result === 'true_positive' || f.triage_result === 'false_positive')) return false;
          if (q && !`${f.title} ${f.description} ${f.masvs_control || ''} ${f.test_name || ''}`.toLowerCase().includes(q)) return false;
          return true;
        });

        const impactFallback: Record<string, string> = {
          STORAGE: 'Sensitive user data may be exposed through insecure local storage mechanisms.',
          CRYPTO: 'Weak cryptographic practices may compromise data confidentiality and integrity.',
          AUTH: 'Authentication or authorization flaws may allow unauthorized access to protected resources.',
          NETWORK: 'Insecure network communication may expose data to interception or tampering.',
          PLATFORM: 'Improper platform API usage may allow other apps to access sensitive functionality.',
          CODE: 'Code quality issues may introduce exploitable vulnerabilities or unstable behavior.',
          RESILIENCE: 'Insufficient protections may allow reverse engineering or runtime tampering.',
        };
        const getImpact = (f: Finding) => {
          const ctrl = (f.masvs_control || '').toUpperCase();
          for (const [k, v] of Object.entries(impactFallback)) {
            if (ctrl.startsWith(`MASVS-${k}`)) return v;
          }
          return 'This finding may impact the overall security posture of the application.';
        };

        const getAIBadge = (result: string) => {
          if (result === 'true_positive') return { label: 'AI Confirmed', cls: 'bg-green-500/10 border-green-500/20 text-green-400', icon: <Check size={10} /> };
          if (result === 'false_positive') return { label: 'Dismissed', cls: 'bg-slate-500/10 border-slate-500/20 text-slate-400', icon: <X size={10} /> };
          return { label: 'Needs Review', cls: 'bg-amber-500/10 border-amber-500/20 text-amber-400', icon: <AlertTriangle size={10} /> };
        };

        const sevButtons = ['all', 'critical', 'high', 'medium', 'low', 'info'] as const;
        const catButtons = ['all', 'STORAGE', 'CRYPTO', 'AUTH', 'NETWORK', 'PLATFORM', 'CODE', 'RESILIENCE'] as const;
        const aiButtons = [{ key: 'all', label: 'All' }, { key: 'confirmed', label: 'Confirmed' }, { key: 'dismissed', label: 'Dismissed' }, { key: 'review', label: 'Needs Review' }] as const;

        return (
          <div className="glass-panel overflow-hidden col-span-12 lg:col-span-8">
            <div className="px-4 py-3 border-b border-[var(--border)] bg-[var(--accent-dim)] flex items-center justify-between">
              <div className="flex items-center gap-2">
                <ShieldAlert size={18} className="text-cyan-400" />
                <h2 className="text-sm font-bold text-[var(--fg)] uppercase tracking-wider">Detailed Findings</h2>
              </div>
              <span className="text-xs text-slate-500">Showing {filtered.length} of {findings.length} findings</span>
            </div>

            {/* Filters */}
            <div className="px-4 py-3 border-b border-[#334155]/20 bg-[#141620]/30 space-y-2">
              {/* Search */}
              <div className="relative">
                <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  type="text"
                  placeholder="Search by title, description, MASVS control..."
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                  className="w-full pl-9 pr-4 py-2 rounded-lg bg-[#0c1425] border border-[#334155]/40 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/30 transition-colors"
                />
              </div>

              {/* Filter Row */}
              <div className="flex flex-wrap gap-x-6 gap-y-2">
                {/* Severity */}
                <div className="flex items-center gap-1.5">
                  <span className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold mr-1">Severity</span>
                  {sevButtons.map(s => {
                    const sevActiveStyles: Record<string, string> = {
                      all: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
                      critical: 'bg-red-500/15 text-red-400 border-red-500/30',
                      high: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
                      medium: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
                      low: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
                      info: 'bg-slate-500/15 text-slate-400 border-slate-500/30',
                    };
                    return (
                      <button key={s} onClick={() => setFilterSeverity(s)} className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase transition-all border ${
                        filterSeverity === s
                          ? sevActiveStyles[s] || sevActiveStyles.all
                          : 'bg-transparent text-slate-500 border-transparent hover:text-slate-300'
                      }`}>{s === 'all' ? 'All' : s.charAt(0).toUpperCase() + s.slice(1)}</button>
                    );
                  })}
                </div>

                {/* MASVS Category */}
                <div className="flex items-center gap-1.5">
                  <span className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold mr-1">MASVS</span>
                  {catButtons.map(c => (
                    <button key={c} onClick={() => setFilterCategory(c)} className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase transition-all border ${
                      filterCategory === c
                        ? 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30'
                        : 'bg-transparent text-slate-500 border-transparent hover:text-slate-300'
                    }`}>{c === 'all' ? 'All' : c}</button>
                  ))}
                </div>

                {/* AI Status */}
                <div className="flex items-center gap-1.5">
                  <span className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold mr-1">AI</span>
                  {aiButtons.map(a => (
                    <button key={a.key} onClick={() => setFilterAI(a.key)} className={`px-2 py-0.5 rounded text-[10px] font-semibold transition-all border ${
                      filterAI === a.key
                        ? 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30'
                        : 'bg-transparent text-slate-500 border-transparent hover:text-slate-300'
                    }`}>{a.label}</button>
                  ))}
                </div>
              </div>
            </div>

            {/* Findings List */}
            <div className="p-4 space-y-2 max-h-[600px] overflow-y-auto">
              {filtered.length === 0 && (
                <div className="text-center py-10 text-slate-500">
                  <ShieldAlert size={28} className="mx-auto mb-2 text-slate-600" />
                  <p className="text-sm">No findings match current filters.</p>
                </div>
              )}

              {filtered.map((finding, idx) => {
                const isOpen = expandedFinding === finding.id;
                const aiBadge = getAIBadge(finding.triage_result);

                return (
                  <div key={finding.id} className="border border-[#334155]/40 bg-[#141620]/40 rounded-xl overflow-hidden transition-all">
                    {/* Collapsed Header — always visible */}
                    <button
                      onClick={() => setExpandedFinding(isOpen ? -1 : finding.id)}
                      className="w-full p-4 flex items-center gap-3 text-left hover:bg-[#1e2130]/30 transition-colors cursor-pointer"
                    >
                      <span className={`badge badge-${finding.severity} flex-shrink-0 text-[10px]`}>{finding.severity.toUpperCase()}</span>
                      <span className="text-sm font-medium text-[var(--fg)] flex-1 min-w-0 truncate">{finding.title}</span>
                      {/* ── Source Badge (Task 2) ── */}
                      {finding.source === "dynamic" && (
                        <span className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-orange-500/12 text-orange-400 border border-orange-500/20 flex-shrink-0">
                          <Zap size={9} /> Dynamic
                        </span>
                      )}
                      {finding.source === "frida" && (
                        <span className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-purple-500/12 text-purple-400 border border-purple-500/20 flex-shrink-0">
                          <Zap size={9} /> Frida
                        </span>
                      )}
                      {finding.source === "network" && (
                        <span className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-green-500/12 text-green-400 border border-green-500/20 flex-shrink-0">
                          <Wifi size={9} /> Network
                        </span>
                      )}
                      {finding.masvs_control && <span className="text-[10px] font-mono text-slate-500 bg-black/20 px-1.5 py-0.5 rounded hidden sm:inline">{finding.masvs_control}</span>}
                      {finding.cvss_score != null && <span className="text-[10px] font-mono text-slate-500 bg-black/20 px-1.5 py-0.5 rounded hidden md:inline">CVSS {finding.cvss_score.toFixed(1)}</span>}
                      <span className={`flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold border ${aiBadge.cls} flex-shrink-0`}>{aiBadge.icon} {aiBadge.label}</span>
                      <ChevronDown size={16} className={`text-slate-500 flex-shrink-0 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
                    </button>

                    {/* Expanded Body */}
                    {isOpen && (
                      <div className="px-5 pb-5 pt-2 border-t border-[#334155]/30 space-y-4">
                        {/* Description */}
                        {finding.description && (
                          <div>
                            <h4 className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1">Description</h4>
                            <p className="text-sm text-slate-300 leading-relaxed">{finding.description}</p>
                          </div>
                        )}

                        {/* Business Impact */}
                        <div>
                          <h4 className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1">Business Impact</h4>
                          <p className="text-xs text-slate-400 leading-relaxed">{getImpact(finding)}</p>
                        </div>

                        {/* AI Verification */}
                        {finding.triage_justification && (
                          <div className="p-3 bg-blue-500/5 border border-blue-500/10 rounded-lg">
                            <div className="flex items-center gap-2 mb-1">
                              <Cpu size={14} className="text-blue-400" />
                              <span className="text-[10px] font-bold text-blue-400 uppercase tracking-wider">AI Verification</span>
                            </div>
                            <p className="text-xs text-slate-400 leading-relaxed italic">“{finding.triage_justification}”</p>
                          </div>
                        )}

                        {/* Affected File */}
                        {finding.test_name && (
                          <div className="flex items-center gap-2">
                            <Code size={14} className="text-slate-500" />
                            <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Affected File</span>
                            <span className="font-mono text-xs text-slate-400 bg-black/20 px-2 py-0.5 rounded">{finding.test_name}</span>
                          </div>
                        )}

                        {/* CVSS Vector */}
                        {finding.cvss_vector && (
                          <div className="flex items-center gap-2">
                            <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">CVSS Vector</span>
                            <span className="font-mono text-[10px] text-slate-500 bg-black/20 px-2 py-0.5 rounded">{finding.cvss_vector}</span>
                          </div>
                        )}

                        {/* Recommended Fix */}
                        {(finding.remediation_description || finding.remediation_code) && (
                          <div className="space-y-2">
                            <div className="flex items-center gap-2 text-purple-400">
                              <Cpu size={14} />
                              <span className="text-[10px] font-bold uppercase tracking-wider">Recommended Fix</span>
                            </div>
                            {finding.remediation_description && (
                              <div className="text-xs text-slate-400 bg-purple-500/5 border-l-2 border-purple-500/30 p-3 rounded-r-lg leading-relaxed">
                                {finding.remediation_description}
                              </div>
                            )}
                            {finding.remediation_code && (
                              <div className="relative">
                                <div className="absolute top-2 right-3 text-[10px] font-mono text-slate-600 font-bold uppercase select-none">SECURE FIX</div>
                                <pre className="bg-[#0f111a] p-4 rounded-xl border border-purple-500/20 overflow-x-auto text-xs font-mono text-indigo-300 leading-relaxed">{finding.remediation_code}</pre>
                              </div>
                            )}
                          </div>
                        )}

                        {/* ─── Auditor HITL Actions ─── */}
                        <div className="pt-3 mt-3 border-t border-[#334155]/30">
                          <div className="flex items-center gap-2 mb-2">
                            <ShieldCheck size={14} className="text-cyan-400" />
                            <span className="text-[10px] font-bold text-cyan-400 uppercase tracking-wider">Auditor Decision</span>
                            {finding.status && finding.status !== 'open' && (
                              <span className={`ml-auto px-2 py-0.5 rounded text-[10px] font-bold border ${finding.status === 'confirmed' ? 'bg-green-500/10 text-green-400 border-green-500/20' : finding.status === 'false_positive' ? 'bg-slate-500/10 text-slate-400 border-slate-500/20' : finding.status === 'accepted_risk' ? 'bg-amber-500/10 text-amber-400 border-amber-500/20' : 'bg-slate-500/10 text-slate-400 border-slate-500/20'}`}>
                                {finding.status.replace('_', ' ').toUpperCase()}
                              </span>
                            )}
                          </div>
                          <div className="flex items-center gap-2 flex-wrap">
                            <button onClick={() => updateFindingStatus(finding.id, 'confirmed')} disabled={feedbackLoading || finding.status === 'confirmed'} className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${finding.status === 'confirmed' ? 'bg-green-500/20 text-green-300 border border-green-500/30 opacity-60' : 'bg-green-500/10 text-green-400 border border-green-500/20 hover:bg-green-500/20'}`}>
                              <ThumbsUp size={12} /> Confirm TP
                            </button>
                            <button onClick={() => setFeedbackModal({ findingId: finding.id, action: 'false_positive', title: finding.title })} disabled={feedbackLoading || finding.status === 'false_positive'} className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${finding.status === 'false_positive' ? 'bg-slate-500/20 text-slate-300 border border-slate-500/30 opacity-60' : 'bg-slate-500/10 text-slate-400 border border-slate-500/20 hover:bg-slate-500/20'}`}>
                              <ThumbsDown size={12} /> False Positive
                            </button>
                            <button onClick={() => setFeedbackModal({ findingId: finding.id, action: 'accepted_risk', title: finding.title })} disabled={feedbackLoading || finding.status === 'accepted_risk'} className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${finding.status === 'accepted_risk' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30 opacity-60' : 'bg-amber-500/10 text-amber-400 border border-amber-500/20 hover:bg-amber-500/20'}`}>
                              <ShieldAlert size={12} /> Accept Risk
                            </button>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        );
      })()}

      </div>{/* end grid */}

      {/* ─── Auditor Feedback Modal ─── */}
      {feedbackModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#1a1d2e] border border-[#334155]/50 rounded-2xl shadow-2xl w-full max-w-md mx-4 overflow-hidden">
            <div className="px-5 py-4 border-b border-[#334155]/30 bg-[#141620]/60">
              <div className="flex items-center gap-2">
                <MessageSquare size={18} className={feedbackModal.action === 'false_positive' ? 'text-slate-400' : 'text-amber-400'} />
                <h3 className="text-sm font-bold text-[var(--fg)]">{feedbackModal.action === 'false_positive' ? 'Mark as False Positive' : 'Accept Risk'}</h3>
              </div>
              <p className="text-xs text-slate-500 mt-1 truncate" title={feedbackModal.title}>{feedbackModal.title}</p>
            </div>
            <div className="p-5 space-y-3">
              <label className="block">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">{feedbackModal.action === 'accepted_risk' ? 'Reason (required)' : 'Reason (optional)'}</span>
                <textarea value={feedbackReason} onChange={(e) => setFeedbackReason(e.target.value)} placeholder={feedbackModal.action === 'false_positive' ? 'e.g., This is a test stub, not production code.' : 'e.g., Risk accepted per CISO approval.'} rows={3} className="mt-1.5 w-full px-3 py-2 rounded-lg bg-[#0c1425] border border-[#334155]/40 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/30 transition-colors resize-none" />
              </label>
            </div>
            <div className="px-5 py-3 border-t border-[#334155]/30 bg-[#141620]/40 flex items-center justify-end gap-2">
              <button onClick={() => { setFeedbackModal(null); setFeedbackReason(''); }} className="px-4 py-1.5 rounded-lg text-xs font-semibold text-slate-400 bg-transparent border border-[#334155]/40 hover:bg-[#1e2130] transition-all cursor-pointer">Cancel</button>
              <button onClick={() => updateFindingStatus(feedbackModal.findingId, feedbackModal.action, feedbackReason)} disabled={feedbackLoading || (feedbackModal.action === 'accepted_risk' && !feedbackReason.trim())} className={`px-4 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer flex items-center gap-1.5 ${feedbackModal.action === 'false_positive' ? 'bg-slate-500/20 text-slate-300 border border-slate-500/30 hover:bg-slate-500/30' : 'bg-amber-500/20 text-amber-300 border border-amber-500/30 hover:bg-amber-500/30'} disabled:opacity-40 disabled:cursor-not-allowed`}>
                {feedbackLoading ? <Loader2 size={12} className="animate-spin" /> : <Check size={12} />}
                {feedbackLoading ? 'Saving...' : 'Submit'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
