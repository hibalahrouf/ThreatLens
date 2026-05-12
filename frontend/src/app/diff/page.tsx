"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  ArrowLeftRight,
  ChevronLeft,
  GitMerge,
  Loader2,
  Search,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { api } from "@/services/api";

type Scan = {
  id: number;
  file_name: string;
  app_version?: string | null;
  status: string;
  score: number | null;
  grade: string | null;
  findings_count?: number | null;
  completed_at?: string | null;
  created_at: string;
};

type Finding = {
  id: number;
  title: string;
  severity: string;
  masvs_control?: string | null;
  affected_file?: string | null;
  cvss_score?: number | null;
};

type DiffResult = {
  scan_id_1: number;
  scan_id_2: number;
  new_findings: Finding[];
  fixed_findings: Finding[];
  persistent_findings: Finding[];
  score_change: number | null;
};

const severityClasses: Record<string, string> = {
  critical: "text-red-400 bg-red-500/10 border-red-500/20",
  high: "text-orange-400 bg-orange-500/10 border-orange-500/20",
  medium: "text-amber-400 bg-amber-500/10 border-amber-500/20",
  low: "text-blue-400 bg-blue-500/10 border-blue-500/20",
  info: "text-slate-400 bg-slate-500/10 border-slate-500/20",
};

export default function DiffPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [olderId, setOlderId] = useState("");
  const [newerId, setNewerId] = useState("");
  const [diff, setDiff] = useState<DiffResult | null>(null);
  const [activeTab, setActiveTab] = useState<"all" | "new" | "resolved" | "persistent">("all");
  const [query, setQuery] = useState("");
  const [isLoading, setIsLoading] = useState(true);
  const [isComparing, setIsComparing] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    async function loadScans() {
      setIsLoading(true);
      setError("");
      try {
        const res = await api.get("/scans/?page=1&page_size=100");
        const doneScans = (res?.scans || []).filter((scan: Scan) => scan.status === "done");
        setScans(doneScans);
        if (doneScans.length >= 2) {
          setNewerId(String(doneScans[0].id));
          setOlderId(String(doneScans[1].id));
        }
      } catch (err: unknown) {
        setError(errorMessage(err, "Failed to load scans."));
      } finally {
        setIsLoading(false);
      }
    }
    loadScans();
  }, []);

  useEffect(() => {
    async function compare() {
      if (!olderId || !newerId || olderId === newerId) {
        setDiff(null);
        return;
      }
      setIsComparing(true);
      setError("");
      try {
        const result = await api.get(`/scans/${olderId}/diff?compare=${newerId}`);
        setDiff(result);
      } catch (err: unknown) {
        setDiff(null);
        setError(errorMessage(err, "Failed to compare scans."));
      } finally {
        setIsComparing(false);
      }
    }
    compare();
  }, [olderId, newerId]);

  const older = scans.find((scan) => String(scan.id) === olderId) || null;
  const newer = scans.find((scan) => String(scan.id) === newerId) || null;

  const visibleGroups = useMemo(() => {
    const q = query.trim().toLowerCase();
    const matches = (finding: Finding) => {
      if (!q) return true;
      return `${finding.title} ${finding.masvs_control || ""} ${finding.affected_file || ""}`
        .toLowerCase()
        .includes(q);
    };
    return {
      newItems: (diff?.new_findings || []).filter(matches),
      fixedItems: (diff?.fixed_findings || []).filter(matches),
      persistentItems: (diff?.persistent_findings || []).filter(matches),
    };
  }, [diff, query]);

  return (
    <div className="max-w-6xl mx-auto space-y-6 p-7">
      <div className="flex items-center gap-4 mb-4">
        <Link href="/" className="p-2 bg-white rounded-xl border border-[var(--border)] hover:bg-[var(--accent-dim)] transition-colors shadow-sm">
          <ChevronLeft size={20} className="text-slate-300" />
        </Link>
        <div>
          <p className="text-[11px] font-bold uppercase tracking-[0.22em] text-[var(--fg-muted)] mb-1.5">Compare</p>
          <h1 className="text-[32px] leading-tight font-bold font-heading text-[var(--fg)] flex items-center gap-3">
            <ArrowLeftRight className="text-[var(--accent)]" /> Version Comparison
          </h1>
          <p className="text-[var(--fg-muted)] text-sm mt-1">Compare two completed scans and review the security delta.</p>
        </div>
      </div>

      <div className="glass-panel p-4 grid grid-cols-1 md:grid-cols-[1fr_1fr_auto] gap-3 items-end">
        <ScanSelect label="Older scan" value={olderId} scans={scans} onChange={setOlderId} />
        <ScanSelect label="Newer scan" value={newerId} scans={scans} onChange={setNewerId} />
        <div className="text-xs text-slate-500 pb-2">
          {isComparing ? "Comparing..." : diff ? `Delta ready for #${olderId} -> #${newerId}` : "Select two scans"}
        </div>
      </div>

      {isLoading && (
        <div className="glass-panel p-12 flex items-center justify-center text-slate-400">
          <Loader2 className="animate-spin mr-2" size={20} /> Loading completed scans...
        </div>
      )}

      {!isLoading && scans.length < 2 && (
        <div className="glass-panel p-12 text-center text-slate-400">
          <ShieldAlert className="mx-auto mb-3 text-slate-500" size={36} />
          At least two completed scans are required for comparison.
        </div>
      )}

      {error && (
        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
          {error}
        </div>
      )}

      {older && newer && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 relative">
          <div className="hidden md:flex absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-10 h-10 bg-white border border-[var(--border)] rounded-full items-center justify-center text-[var(--fg-muted)] font-bold z-10 shadow-sm">
            VS
          </div>
          <ScanCard scan={older} accent="border-l-slate-500" />
          <ScanCard scan={newer} accent="border-l-[var(--accent)] bg-[var(--accent-dim)]" scoreDelta={diff?.score_change ?? null} />
        </div>
      )}

      {diff && (
        <>
          <div className="grid grid-cols-3 gap-4">
            <DeltaButton active={activeTab === "new"} onClick={() => setActiveTab("new")} value={`+${diff.new_findings.length}`} label="Newly Introduced" tone="red" />
            <DeltaButton active={activeTab === "resolved"} onClick={() => setActiveTab("resolved")} value={`-${diff.fixed_findings.length}`} label="Resolved / Fixed" tone="green" />
            <DeltaButton active={activeTab === "persistent"} onClick={() => setActiveTab("persistent")} value={String(diff.persistent_findings.length)} label="Persistent Issues" tone="slate" />
          </div>

          <div className="glass-panel overflow-hidden">
            <div className="p-4 border-b border-[var(--border)] bg-[var(--accent-dim)] flex flex-col sm:flex-row gap-3 sm:items-center sm:justify-between">
              <h3 className="font-heading font-semibold text-[var(--fg)] flex items-center gap-2">
                <GitMerge size={18} className="text-[var(--accent)]" /> Finding Delta
              </h3>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 w-4 h-4" />
                <input
                  type="text"
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder="Filter findings..."
                  className="input-field pl-9 pr-3 py-1.5 text-sm"
                />
              </div>
            </div>

            <div className="divide-y divide-[#334155]/50">
              {(activeTab === "all" || activeTab === "new") && (
                <FindingGroup items={visibleGroups.newItems} kind="new" />
              )}
              {(activeTab === "all" || activeTab === "resolved") && (
                <FindingGroup items={visibleGroups.fixedItems} kind="fixed" />
              )}
              {(activeTab === "all" || activeTab === "persistent") && (
                <FindingGroup items={visibleGroups.persistentItems} kind="persistent" />
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function ScanSelect({ label, value, scans, onChange }: { label: string; value: string; scans: Scan[]; onChange: (value: string) => void }) {
  return (
    <label className="block">
      <span className="block text-xs font-semibold uppercase tracking-wider text-slate-500 mb-1.5">{label}</span>
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="input-field px-3 py-2.5 text-sm"
      >
        <option value="">Select scan</option>
        {scans.map((scan) => (
          <option key={scan.id} value={scan.id}>
            #{scan.id} - {scan.app_version || scan.file_name} - {scan.score ?? "N/A"}/100
          </option>
        ))}
      </select>
    </label>
  );
}

function errorMessage(error: unknown, fallback: string) {
  return error instanceof Error ? error.message : fallback;
}

function ScanCard({ scan, accent, scoreDelta }: { scan: Scan; accent: string; scoreDelta?: number | null }) {
  return (
    <div className={`glass-panel p-6 border-l-4 ${accent}`}>
      <div className="flex justify-between items-start mb-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="bg-[var(--accent-dim)] text-[var(--fg-muted)] px-2 py-0.5 rounded text-xs font-mono font-medium">
              {scan.app_version || "No version"}
            </span>
            <span className="text-xs text-slate-500">
              {new Date(scan.completed_at || scan.created_at).toLocaleDateString()}
            </span>
          </div>
          <h2 className="text-lg font-bold font-heading text-[var(--fg)]">Scan #{scan.id}</h2>
          <p className="text-xs text-slate-500 truncate max-w-sm">{scan.file_name}</p>
        </div>
        {scoreDelta !== undefined && scoreDelta !== null && (
          <div className={`px-3 py-1 rounded-full text-sm font-bold border ${
            scoreDelta >= 0 ? "bg-green-500/20 text-green-400 border-green-500/30" : "bg-red-500/20 text-red-400 border-red-500/30"
          }`}>
            {scoreDelta >= 0 ? "+" : ""}{scoreDelta.toFixed(1)} pts
          </div>
        )}
      </div>
      <div className="flex items-end gap-3">
        <div>
          <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">Score</p>
          <span className="text-3xl font-bold text-amber-500">{scan.score?.toFixed(0) ?? "N/A"}</span>
        </div>
        <div className="pl-6 border-l border-[var(--border)]">
          <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">Findings</p>
          <span className="text-xl font-bold text-[var(--fg)]">{scan.findings_count ?? "N/A"}</span>
        </div>
      </div>
    </div>
  );
}

function DeltaButton({ active, onClick, value, label, tone }: { active: boolean; onClick: () => void; value: string; label: string; tone: "red" | "green" | "slate" }) {
  const toneClass = tone === "red" ? "text-red-400 border-t-red-500" : tone === "green" ? "text-green-400 border-t-green-500" : "text-slate-300 border-t-slate-500";
  return (
    <button onClick={onClick} className={`glass-panel p-4 text-center border-t-2 transition-colors ${active ? toneClass + " bg-white/5" : "border-t-transparent hover:bg-white/5"}`}>
      <div className={`text-2xl font-bold mb-1 ${toneClass.split(" ")[0]}`}>{value}</div>
      <div className="text-sm text-slate-400">{label}</div>
    </button>
  );
}

function FindingGroup({ items, kind }: { items: Finding[]; kind: "new" | "fixed" | "persistent" }) {
  if (items.length === 0) return null;
  const config = {
    new: { marker: "+", label: "Introduced", cls: "bg-red-500/10 text-red-400 border-red-500/20" },
    fixed: { marker: "-", label: "Fixed", cls: "bg-green-500/10 text-green-400 border-green-500/20" },
    persistent: { marker: "=", label: "Unchanged", cls: "bg-slate-800 text-slate-400 border-slate-700" },
  }[kind];

  return (
    <>
      {items.map((finding) => (
        <div key={`${kind}-${finding.id}`} className="p-4 hover:bg-white/[0.02] flex items-center justify-between gap-4">
          <div className="flex items-center gap-4 min-w-0">
            <div className={`w-8 h-8 rounded flex items-center justify-center font-bold border flex-shrink-0 ${config.cls}`}>
              {config.marker}
            </div>
            <div className="min-w-0">
              <h4 className={`${kind === "fixed" ? "text-slate-400 line-through" : "text-[var(--fg)]"} font-medium truncate`}>
                {finding.title}
              </h4>
              <div className="text-xs text-slate-500 flex gap-2 mt-1 flex-wrap">
                {finding.masvs_control && <span className="font-mono bg-[var(--accent-dim)] px-1 rounded">{finding.masvs_control}</span>}
                {finding.affected_file && <span>in {finding.affected_file}</span>}
                {finding.cvss_score != null && <span>CVSS {finding.cvss_score.toFixed(1)}</span>}
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            <span className={`text-[10px] uppercase font-bold border px-2 py-1 rounded ${severityClasses[finding.severity] || severityClasses.info}`}>
              {finding.severity}
            </span>
            <span className={`text-xs font-medium px-2 py-1 rounded border flex items-center gap-1 ${config.cls}`}>
              {kind === "fixed" && <ShieldCheck size={12} />} {config.label}
            </span>
          </div>
        </div>
      ))}
    </>
  );
}
