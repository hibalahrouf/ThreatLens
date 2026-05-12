"use client";

import { useState, useEffect, useCallback, Suspense } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
  Search, Filter, UploadCloud, ChevronRight, Loader2,
  ShieldAlert, CheckCircle, Clock, XCircle,
  RefreshCw, List, AlertTriangle, FileSearch, Layers, Ban,
} from "lucide-react";
import { api } from "@/services/api";

type Scan = {
  id: number;
  file_name: string;
  status: string;
  score: number | null;
  grade: string | null;
  progress: number;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  scan_mode?: string;
};

const STATUS_CONFIG: Record<string, { label: string; color: string; icon: any; badge: string }> = {
  done:              { label: "Done",      color: "text-green-400",  icon: CheckCircle,  badge: "bg-[rgba(20,184,166,0.10)] border-[rgba(20,184,166,0.22)] text-[#14B8A6]" },
  running:           { label: "Running",   color: "text-blue-400",   icon: RefreshCw,    badge: "bg-[rgba(23,105,255,0.10)] border-[rgba(23,105,255,0.22)] text-[var(--accent)]" },
  analyzing:         { label: "Analyzing", color: "text-blue-400",   icon: RefreshCw,    badge: "bg-[rgba(23,105,255,0.10)] border-[rgba(23,105,255,0.22)] text-[var(--accent)]" },
  pending:           { label: "Pending",   color: "text-slate-400",  icon: Clock,        badge: "bg-slate-500/10 border-slate-500/20 text-slate-400" },
  uploading:         { label: "Uploading", color: "text-amber-400",  icon: Clock,        badge: "bg-amber-500/10 border-amber-500/20 text-amber-400" },
  generating_report: { label: "Generating",color: "text-amber-400",  icon: RefreshCw,    badge: "bg-amber-500/10 border-amber-500/20 text-amber-400" },
  failed:            { label: "Failed",    color: "text-red-400",    icon: XCircle,      badge: "bg-[rgba(240,68,56,0.10)] border-[rgba(240,68,56,0.22)] text-[var(--danger)]" },
};

const GRADE_COLOR: Record<string, string> = {
  "A+": "text-green-400", "A": "text-green-400",
  "B": "text-lime-400",
  "C": "text-amber-400",
  "D": "text-orange-400",
  "F": "text-red-400",
};

function ScoreBar({ score }: { score: number | null }) {
  if (score === null) return <span className="text-slate-600 text-sm">—</span>;
  const color = score >= 85 ? "bg-[#14B8A6]" : score >= 60 ? "bg-[#F79009]" : "bg-[var(--danger)]";
  return (
    <div className="flex items-center gap-2 min-w-[120px]">
      <div className="flex-1 h-1.5 bg-[var(--fg-subtle)] rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${score}%` }} />
      </div>
      <span className="text-sm font-mono text-[var(--fg)] w-10 text-right">{score.toFixed(0)}</span>
    </div>
  );
}

function ScanHistoryContent() {
  const searchParams = useSearchParams();
  const modeParam = searchParams.get("mode"); // "static" | "dynamic" | null

  const [scans, setScans] = useState<Scan[]>([]);
  const [total, setTotal] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [page, setPage] = useState(1);
  const PAGE_SIZE = 15;
  const CANCELLABLE = new Set(["pending", "running", "analyzing", "uploading", "generating_report"]);

  const cancelScan = async (scanId: number) => {
    if (!confirm("Cancel this scan?")) return;
    try {
      await api.post(`/scans/${scanId}/cancel`, {});
      fetchScans();
    } catch (err) {
      console.error("Failed to cancel scan:", err);
    }
  };

  // Derive page title & icon from mode
  const pageTitle = modeParam === "static" ? "Static Analysis" : modeParam === "dynamic" ? "Static + Dynamic" : "Scan History";
  const PageIcon = modeParam === "static" ? FileSearch : modeParam === "dynamic" ? Layers : List;

  const fetchScans = useCallback(async () => {
    setIsLoading(true);
    try {
      const params = new URLSearchParams({
        page: String(page),
        page_size: String(PAGE_SIZE),
      });
      const res = await api.get(`/scans/?${params}`);
      setScans(res?.scans || []);
      setTotal(res?.total || 0);
    } catch (err) {
      console.error("Failed to fetch scans:", err);
    } finally {
      setIsLoading(false);
    }
  }, [page]);

  useEffect(() => {
    fetchScans();
  }, [fetchScans]);

  // Client-side filter (search + status + scan_mode)
  const filtered = scans.filter((s) => {
    const matchSearch = s.file_name.toLowerCase().includes(search.toLowerCase());
    const matchStatus = statusFilter === "all" || s.status === statusFilter;
    const matchMode = !modeParam || s.scan_mode === modeParam;
    return matchSearch && matchStatus && matchMode;
  });

  const totalPages = Math.ceil(total / PAGE_SIZE);

  return (
    <div className="max-w-7xl mx-auto pb-20 space-y-6 p-7">

      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <p className="text-[11px] font-bold uppercase tracking-[0.22em] text-[var(--fg-muted)] mb-1.5">Scans</p>
          <h1 className="text-[32px] leading-tight font-bold font-heading text-[var(--fg)] flex items-center gap-3">
            <PageIcon className="text-[var(--accent)]" size={28} />
            {pageTitle}
          </h1>
          <p className="text-[var(--fg-muted)] mt-1">{filtered.length} scan{filtered.length !== 1 ? "s" : ""}{modeParam ? ` (${modeParam})` : ` total`}</p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={fetchScans}
            className="premium-button-outline flex items-center gap-2"
            disabled={isLoading}
          >
            <RefreshCw size={16} className={isLoading ? "animate-spin" : ""} />
            Refresh
          </button>
          <Link href="/scans/upload" className="premium-button flex items-center gap-2">
            <UploadCloud size={16} /> New Scan
          </Link>
        </div>
      </div>

      {/* Filters Row */}
      <div className="glass-panel p-4 flex flex-col sm:flex-row gap-3">
        {/* Search */}
        <div className="relative flex-1">
          <Search size={16} className="absolute left-3 top-3 text-slate-500" />
          <input
            type="text"
            placeholder="Search by file name…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="input-field pl-9 pr-4 py-2.5 text-sm"
          />
        </div>

        {/* Status filter */}
        <div className="relative">
          <Filter size={16} className="absolute left-3 top-3 text-slate-500" />
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="input-field pl-9 pr-8 py-2.5 text-sm appearance-none cursor-pointer"
          >
            <option value="all">All statuses</option>
            <option value="done">Done</option>
            <option value="running">Running</option>
            <option value="analyzing">Analyzing</option>
            <option value="pending">Pending</option>
            <option value="failed">Failed</option>
          </select>
        </div>
      </div>

      {/* Scans Table */}
      <div className="glass-panel overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center py-20">
            <Loader2 size={32} className="animate-spin text-[var(--accent)]" />
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 text-slate-500">
            <AlertTriangle size={40} className="mb-3 text-slate-600" />
            <p className="font-medium">No scans found</p>
            <p className="text-sm mt-1">Try adjusting your filters or upload a new APK.</p>
            <Link href="/scans/upload" className="mt-4 premium-button text-sm">
              Upload APK
            </Link>
          </div>
        ) : (
          <>
            {/* Table Header */}
            <div className="grid grid-cols-12 gap-4 px-6 py-3 text-xs font-semibold uppercase tracking-wider text-[var(--fg-muted)] border-b border-[var(--border)] bg-[var(--accent-dim)]">
              <div className="col-span-1">#</div>
              <div className="col-span-4">File</div>
              <div className="col-span-2">Status</div>
              <div className="col-span-2">Score</div>
              <div className="col-span-2">Date</div>
              <div className="col-span-1"></div>
            </div>

            {/* Table Rows */}
            {filtered.map((scan) => {
              const cfg = STATUS_CONFIG[scan.status] || STATUS_CONFIG.pending;
              const StatusIcon = cfg.icon;
              const isActive = scan.status === "running" || scan.status === "analyzing" || scan.status === "uploading" || scan.status === "generating_report";

              return (
                <div
                  key={scan.id}
                  className="grid grid-cols-12 gap-4 px-6 py-4 border-b border-[var(--border)] hover:bg-[#EEF5FF] transition-colors items-center group"
                >
                  {/* ID */}
                  <div className="col-span-1 text-slate-600 text-sm font-mono">#{scan.id}</div>

                  {/* File */}
                  <div className="col-span-4 min-w-0">
                    <div className="flex items-center gap-2">
                      <div className="flex-shrink-0 bg-white border border-[var(--border)] rounded-lg p-1.5">
                        <ShieldAlert size={14} className="text-[var(--accent)]" />
                      </div>
                      <div className="min-w-0">
                        <p className="text-[var(--fg)] text-sm font-medium truncate">{scan.file_name}</p>
                        {isActive && (
                          <div className="flex items-center gap-2 mt-0.5">
                            <div className="h-1 flex-1 max-w-[120px] bg-[var(--fg-subtle)] rounded-full overflow-hidden">
                              <div
                                className="h-full bg-[var(--accent)] rounded-full transition-all duration-500"
                                style={{ width: `${scan.progress || 0}%` }}
                              />
                            </div>
                            <span className="text-xs text-slate-500">{scan.progress || 0}%</span>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Status Badge */}
                  <div className="col-span-2">
                    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${cfg.badge}`}>
                      <StatusIcon size={12} className={isActive ? "animate-spin" : ""} />
                      {cfg.label}
                    </span>
                  </div>

                  {/* Score */}
                  <div className="col-span-2 flex items-center gap-2">
                    {scan.grade && (
                      <span className={`font-bold text-sm ${GRADE_COLOR[scan.grade] || "text-slate-400"}`}>
                        {scan.grade}
                      </span>
                    )}
                    <ScoreBar score={scan.score} />
                  </div>

                  {/* Date */}
                  <div className="col-span-2 text-xs text-slate-500">
                    {scan.completed_at
                      ? new Date(scan.completed_at).toLocaleDateString("fr-FR", { day: "2-digit", month: "short", year: "numeric" })
                      : scan.created_at
                      ? new Date(scan.created_at).toLocaleDateString("fr-FR", { day: "2-digit", month: "short", year: "numeric" })
                      : "—"}
                  </div>

                  {/* Action */}
                  <div className="col-span-1 flex justify-end gap-2">
                    {scan.status === "done" ? (
                      <Link
                        href={`/scans/${scan.id}${modeParam ? `?mode=${modeParam}` : ''}`}
                        className="flex items-center gap-1 text-[var(--accent)] text-xs font-medium opacity-0 group-hover:opacity-100 transition-opacity"
                      >
                        Report <ChevronRight size={14} />
                      </Link>
                    ) : CANCELLABLE.has(scan.status) ? (
                      <button
                        onClick={() => cancelScan(scan.id)}
                        className="flex items-center gap-1 text-red-400 hover:text-red-300 text-xs font-medium opacity-0 group-hover:opacity-100 transition-opacity cursor-pointer"
                      >
                        <Ban size={12} /> Cancel
                      </button>
                    ) : (
                      <span className="text-xs text-slate-600 opacity-0 group-hover:opacity-100">
                        {cfg.label}
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <p className="text-sm text-slate-500">
            Page {page} of {totalPages} ({total} total)
          </p>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
              className="premium-button-outline text-sm disabled:opacity-30 disabled:cursor-not-allowed px-3 py-1.5"
            >
              ← Previous
            </button>
            {[...Array(Math.min(totalPages, 5))].map((_, i) => {
              const pageNum = i + 1;
              return (
                <button
                  key={pageNum}
                  onClick={() => setPage(pageNum)}
                  className={`w-8 h-8 rounded-lg text-sm font-medium transition-all ${
                    page === pageNum
                      ? "bg-[var(--accent)] text-white"
                      : "bg-white border border-[var(--border)] text-[var(--fg-muted)] hover:text-[var(--fg)] hover:bg-[var(--accent-dim)]"
                  }`}
                >
                  {pageNum}
                </button>
              );
            })}
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
              className="premium-button-outline text-sm disabled:opacity-30 disabled:cursor-not-allowed px-3 py-1.5"
            >
              Next →
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default function ScanHistoryPage() {
  return (
    <Suspense fallback={
      <div className="flex items-center justify-center py-20">
        <Loader2 size={32} className="animate-spin text-[var(--accent)]" />
      </div>
    }>
      <ScanHistoryContent />
    </Suspense>
  );
}
