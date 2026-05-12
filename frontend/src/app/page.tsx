"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowRight, ShieldAlert, CheckCircle, Activity, Smartphone, Loader2, Target } from "lucide-react";
import { ResponsiveContainer, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar, Tooltip as RechartsTooltip } from "recharts";
import { api } from "@/services/api";

export default function Dashboard() {
  const [recentScans, setRecentScans] = useState<any[]>([]);
  const [masvsData, setMasvsData] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [stats, setStats] = useState({ total: 0, avgScore: 0, criticals: 0 });

  useEffect(() => { fetchDashboardData(); }, []);

  const fetchDashboardData = async () => {
    try {
      const scansResponse = await api.get("/scans/");
      const scansList: any[] = scansResponse?.scans || [];
      const totalScans: number = scansResponse?.total || 0;
      setRecentScans(scansList.slice(0, 10));

      let totalCriticals = 0;
      let totalScore = 0;

      const domainsMap: Record<string, { total: number; vulnerabilities: number }> = {
        "Arc/Design": { total: 0, vulnerabilities: 0 },
        "Storage": { total: 0, vulnerabilities: 0 },
        "Crypto": { total: 0, vulnerabilities: 0 },
        "Auth": { total: 0, vulnerabilities: 0 },
        "Network": { total: 0, vulnerabilities: 0 },
        "Platform": { total: 0, vulnerabilities: 0 },
        "Code": { total: 0, vulnerabilities: 0 },
      };

      for (const scan of scansList) {
        totalScore += scan.score || 0;
        try {
          const findings = await api.get(`/scans/${scan.id}/findings`);
          for (const f of findings) {
            if (f.severity === "critical") totalCriticals++;
            const cat = (f.masvs_category || "").toLowerCase();
            let domain = "Code";
            if (cat.includes("storage")) domain = "Storage";
            else if (cat.includes("crypt")) domain = "Crypto";
            else if (cat.includes("auth")) domain = "Auth";
            else if (cat.includes("network")) domain = "Network";
            else if (cat.includes("platform")) domain = "Platform";
            else if (cat.includes("architecture")) domain = "Arc/Design";
            domainsMap[domain].vulnerabilities += 1;
          }
          Object.keys(domainsMap).forEach(k => { domainsMap[k].total += 8; });
        } catch (e) {}
      }

      setStats({
        total: totalScans,
        avgScore: scansList.length ? Math.round(totalScore / scansList.length) : 0,
        criticals: totalCriticals,
      });

      const mappedMasvs = Object.entries(domainsMap).map(([subject, counts]) => {
        const penalty = (counts.vulnerabilities / (counts.total || 1)) * 100;
        return { subject, A: Math.round(Math.max(0, 100 - penalty)), fullMark: 100 };
      });
      setMasvsData(mappedMasvs.length > 0 ? mappedMasvs : [
        { subject: "Arc/Design", A: 100, fullMark: 100 },
        { subject: "Storage", A: 100, fullMark: 100 },
        { subject: "Crypto", A: 100, fullMark: 100 },
        { subject: "Auth", A: 100, fullMark: 100 },
        { subject: "Network", A: 100, fullMark: 100 },
        { subject: "Platform", A: 100, fullMark: 100 },
        { subject: "Code", A: 100, fullMark: 100 },
      ]);
    } catch (error) {
      console.error("Failed to fetch dashboard data:", error);
    } finally {
      setIsLoading(false);
    }
  };

  if (isLoading) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="w-12 h-12 rounded-full border-2 border-[var(--accent-dim)] border-t-[var(--accent)] animate-spin" />
          <p className="text-sm text-slate-500">Loading security data...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-7">
      {/* Page header */}
      <div className="flex justify-between items-end">
        <div>
          <p className="text-[11px] font-bold uppercase tracking-[0.22em] text-[var(--fg-muted)] mb-1.5">Overview</p>
          <h1 className="font-heading text-[32px] leading-tight font-bold text-[var(--fg)]">Security Dashboard</h1>
          <p className="text-[var(--fg-muted)] text-sm mt-1">Real-time MASVS compliance across your mobile portfolio</p>
        </div>
        <Link href="/scans/upload" className="premium-button flex items-center gap-2 text-sm">
          <span>New Audit</span>
          <ArrowRight size={15} />
        </Link>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <StatCard title="Total Scans" value={stats.total} icon={Activity} accent="#1769FF" sub="All time" />
        <SecurityScoreCard score={stats.avgScore} sub="Across all monitored applications" />
        <StatCard title="Critical Risks" value={stats.criticals} icon={ShieldAlert} accent="#F04438" sub="Requires attention" urgent={stats.criticals > 0} />
        <StatCard title="Apps Monitored" value={new Set(recentScans.map(s => s.project?.id || s.id)).size} icon={Target} accent="#7C3AED" sub="Unique projects" />
      </div>

      {/* Charts + Table */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Radar chart */}
        <div className="p-5 lg:col-span-1 rounded-[20px] border border-[rgba(255,255,255,0.08)] shadow-[0_18px_44px_rgba(7,13,30,0.22)]" style={{ background: '#070D1E' }}>
          <div className="mb-4">
            <h2 className="font-heading text-sm font-bold mb-0.5" style={{ color: '#FFFFFF' }}>MASVS Maturity Index</h2>
            <p className="text-xs" style={{ color: 'rgba(255,255,255,0.58)' }}>Global compliance across all apps</p>
          </div>
          <div className="h-[280px]">
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart cx="50%" cy="50%" outerRadius="65%" data={masvsData}>
                <PolarGrid stroke="rgba(255,255,255,0.16)" />
                <PolarAngleAxis dataKey="subject" tick={{ fill: 'rgba(255,255,255,0.68)', fontSize: 10, fontWeight: 600 }} />
                <PolarRadiusAxis angle={30} domain={[0, 100]} tick={false} axisLine={false} />
                <Radar name="Compliance %" dataKey="A" stroke="#5DA2FF" fill="#1769FF" fillOpacity={0.30} strokeWidth={2} />
                <RechartsTooltip
                  contentStyle={{ backgroundColor: '#FFFFFF', color: '#162033', border: '1px solid rgba(15,27,45,0.10)', borderRadius: '10px', fontSize: '12px', boxShadow: '0 2px 12px rgba(0,0,0,0.07)' }}
                  itemStyle={{ color: '#1769FF' }}
                />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Recent Scans Table */}
        <div className="glass-panel rounded-2xl overflow-hidden lg:col-span-2">
          <div className="px-5 py-4 flex justify-between items-center" style={{ borderBottom: '1px solid rgba(56,189,248,0.07)' }}>
            <div>
              <h2 className="text-sm font-bold text-[var(--fg)]">Recent Audits</h2>
              <p className="text-xs text-[var(--fg-muted)] mt-0.5">Latest automated security scans</p>
            </div>
            <Link href="/scans" className="text-xs font-semibold transition-colors" style={{ color: 'var(--accent)' }}>
              View All →
            </Link>
          </div>

          <div className="overflow-x-auto px-2 py-1">
            <table className="w-full text-left">
              <thead>
                <tr className="text-[10px] font-bold uppercase tracking-widest text-[var(--fg-muted)]"
                  style={{ borderBottom: '1px solid rgba(15,27,45,0.06)' }}
                >
                  <th className="p-0"></th>
                  <th className="px-5 py-4">Application</th>
                  <th className="px-5 py-4">Score</th>
                  <th className="px-5 py-4 hidden md:table-cell">Date</th>
                  <th className="px-5 py-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                {recentScans.length === 0 && (
                  <tr>
                    <td colSpan={5} className="px-5 py-12 text-center">
                      <div className="flex flex-col items-center gap-3">
                        <div className="w-12 h-12 rounded-full flex items-center justify-center"
                          style={{ background: 'rgba(23,105,255,0.08)', border: '1px solid rgba(23,105,255,0.15)' }}
                        >
                          <Smartphone size={20} style={{ color: 'rgba(23,105,255,0.62)' }} />
                        </div>
                        <p className="text-sm text-[var(--fg-muted)]">No scans yet. Upload an APK to get started.</p>
                        <Link href="/scans/upload" className="text-xs font-semibold" style={{ color: 'var(--accent)' }}>Start your first scan →</Link>
                      </div>
                    </td>
                  </tr>
                )}
                {recentScans.map((scan) => {
                  const score = scan.score;
                  const scoreColor = score >= 85 ? '#14B8A6' : score >= 60 ? '#F79009' : '#F04438';
                  return (
                    <tr key={scan.id} className="group transition-all duration-200 hover:bg-[#F0FAF9]"
                      style={{ borderBottom: '1px solid rgba(15,27,45,0.06)' }}
                    >
                      <td className="p-0">
                        <div
                          className="w-1 h-8 rounded-full"
                          style={{ backgroundColor: scan.status === "done" ? scoreColor : '#94a3b8' }}
                        />
                      </td>
                      <td className="px-5 py-4">
                        <div className="flex items-center gap-3">
                          <div className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
                            style={{ background: 'rgba(23,105,255,0.08)', border: '1px solid rgba(23,105,255,0.12)' }}
                          >
                            <Smartphone size={14} style={{ color: 'rgba(23,105,255,0.72)' }} />
                          </div>
                          <div className="min-w-0">
                            <p className="text-sm font-medium text-[var(--fg)] truncate max-w-[160px]">{scan.file_name}</p>
                            <p className="text-[10px] text-[var(--fg-muted)]">#{scan.id} • {scan.project?.name || 'Default'}</p>
                          </div>
                        </div>
                      </td>
                      <td className="px-5 py-4">
                        {scan.status === "done" ? (
                          <div className="flex items-center gap-2">
                            <div className="w-24 h-1.5 rounded-full bg-slate-200 overflow-hidden">
                              <div
                                className="h-full rounded-full transition-all duration-500"
                                style={{ width: `${Math.max(0, Math.min(score || 0, 100))}%`, backgroundColor: scoreColor }}
                              />
                            </div>
                            <span className="text-xs font-bold" style={{ color: scoreColor }}>
                              {score !== null ? score.toFixed(1) : '—'}
                            </span>
                            <span className="text-xs text-[var(--fg-muted)]">/100</span>
                          </div>
                        ) : (
                          <span className={`text-[10px] font-bold uppercase px-2.5 py-0.5 rounded-full ${
                            scan.status === "failed"
                              ? "border bg-[rgba(240,68,56,0.10)] text-[#F04438] border-[rgba(240,68,56,0.22)]"
                              : "border bg-[rgba(23,105,255,0.10)] text-[var(--accent)] border-[rgba(23,105,255,0.22)] animate-pulse"
                          }`}>{scan.status}</span>
                        )}
                      </td>
                      <td className="px-5 py-4 hidden md:table-cell">
                        <span className="text-xs text-[var(--fg-muted)]">{new Date(scan.started_at).toLocaleDateString()}</span>
                      </td>
                      <td className="px-5 py-4 text-right">
                        {scan.status === "done" ? (
                          <Link
                            href={`/scans/${scan.id}`}
                            className="text-xs font-semibold px-3 py-1.5 rounded-lg border transition-all duration-200 hover:scale-105 opacity-0 group-hover:opacity-100"
                            style={{ color: 'var(--accent)', borderColor: 'var(--accent)' }}
                          >
                            View →
                          </Link>
                        ) : (
                          <span className="text-xs text-[var(--fg-muted)] animate-pulse">Processing...</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}

function SecurityScoreCard({ score, sub }: { score: number; sub: string }) {
  const radius = 60;
  const circumference = 2 * Math.PI * radius;
  const normalizedScore = Math.max(score || 0, 3);
  const strokeDashoffset = circumference - (normalizedScore / 100) * circumference;
  const isLow = (score || 0) < 40;
  const strokeColor = (score || 0) >= 70 ? '#14B8A6' : (score || 0) >= 40 ? '#F79009' : '#F04438';

  return (
    <div className="glass-panel relative md:col-span-2 p-6 overflow-hidden border-l-4 border-l-[var(--accent)]">
      <div className="relative flex items-center justify-between gap-6">
        <div className="min-w-0">
          <p className="font-heading text-base font-bold text-[var(--fg)]">Security Score</p>
          <p className="mt-1 text-xs text-[var(--fg-muted)]">{sub}</p>
          <div className="mt-5 grid grid-cols-3 gap-3">
            {[
              { label: "Low", dot: "bg-green-500" },
              { label: "Medium", dot: "bg-[#F79009]" },
              { label: "High", dot: "bg-[#F04438]" },
            ].map((item) => (
              <div key={item.label} className="rounded-xl border border-[var(--border)] bg-[var(--bg)]/45 p-3">
                <div className="flex items-center gap-2">
                  <span className={`h-2 w-2 rounded-full ${item.dot}`} />
                  <span className="text-xs font-medium text-[var(--fg-muted)]">{item.label}</span>
                </div>
                <p className="mt-2 font-heading text-lg font-bold text-[var(--fg)]">—</p>
              </div>
            ))}
          </div>
        </div>
        <div
          className="relative flex h-40 w-40 flex-shrink-0 items-center justify-center rounded-full"
          style={{ filter: isLow ? 'drop-shadow(0 0 22px rgba(240,68,56,0.42))' : 'drop-shadow(0 10px 22px rgba(23,105,255,0.18))' }}
        >
          <svg width="156" height="156" viewBox="0 0 156 156">
            <defs>
              <linearGradient id="scoreGaugeGradient" x1="20" y1="20" x2="136" y2="136" gradientUnits="userSpaceOnUse">
                <stop offset="0%" stopColor={strokeColor} stopOpacity="0.78" />
                <stop offset="100%" stopColor={strokeColor} />
              </linearGradient>
            </defs>
            <circle cx="78" cy="78" r={radius} fill="none" stroke="rgba(148,163,184,0.18)" strokeWidth="12" strokeLinecap="round" />
            <circle
              cx="78"
              cy="78"
              r={radius}
              fill="none"
              stroke="url(#scoreGaugeGradient)"
              strokeWidth="12"
              strokeLinecap="round"
              strokeDasharray={circumference}
              strokeDashoffset={strokeDashoffset}
              transform="rotate(-90 78 78)"
              style={{ transition: "stroke-dashoffset 1s ease-out" }}
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="font-heading text-6xl font-bold" style={{ color: strokeColor }}>{score}</span>
            <span className="text-xs font-semibold text-[var(--fg-muted)]">/100</span>
          </div>
        </div>
      </div>
    </div>
  );
}

function StatCard({ title, value, suffix, icon: Icon, accent, sub, urgent }: any) {
  return (
    <div className="glass-panel p-5 relative overflow-hidden group cursor-default border-l-4"
      style={urgent ? { borderColor: 'rgba(240,68,56,0.22)', borderLeftColor: accent } : { borderLeftColor: accent }}
    >
      <div className="flex justify-between items-start mb-4">
        <p className="text-[11px] font-bold text-[var(--fg-muted)] uppercase tracking-[0.18em]">{title}</p>
        <div className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0"
          style={{ background: `${accent}15`, border: `1px solid ${accent}25` }}
        >
          <Icon size={15} style={{ color: accent }} />
        </div>
      </div>
      <div className="flex items-end gap-1">
        <p className="font-heading text-3xl font-bold text-[var(--fg)]" style={urgent ? { color: 'var(--danger)' } : {}}>
          {value}
        </p>
        {suffix && <span className="text-sm text-[var(--fg-muted)] mb-0.5">{suffix}</span>}
      </div>
      <p className="text-xs text-[var(--fg-muted)] mt-1">{sub}</p>
    </div>
  );
}
