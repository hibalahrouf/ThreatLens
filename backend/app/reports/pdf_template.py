"""
MASVS Audit Copilot — PDF CSS Template
Consulting-grade white-background design with deep blue accent.
"""

PDF_CSS = """
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

:root { --accent: #1e3a5f; --accent-light: #2d5a8e; --accent-bg: #f0f4f8; --border: #d1d9e6; --text: #1a1a2e; --muted: #4a5568; --pass: #16a34a; --fail: #dc2626; --warn: #d97706; --gray: #9ca3af; }

* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Inter', -apple-system, sans-serif; color: var(--text); line-height: 1.7; font-size: 10pt; background: white; }

@page { margin: 2cm; @bottom-center { content: "Confidential — MASVS Audit Copilot"; font-size: 7pt; color: var(--gray); } @bottom-right { content: counter(page); font-size: 7pt; color: var(--gray); } }
@page :first { margin: 0; @bottom-center { content: none; } @bottom-right { content: none; } }

/* ─── Cover ─── */
.cover { page-break-after: always; height: 100vh; display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center; background: white; padding: 60px; position: relative; }
.cover::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 6px; background: var(--accent); }
.cover-brand { font-size: 10pt; font-weight: 700; color: var(--accent); letter-spacing: 4px; text-transform: uppercase; margin-bottom: 50px; }
.cover h1 { font-size: 28pt; font-weight: 700; color: var(--accent); margin-bottom: 6px; }
.cover .sub { font-size: 12pt; color: var(--muted); margin-bottom: 50px; }
.grade-ring { width: 150px; height: 150px; border-radius: 50%; border: 4px solid var(--accent); display: flex; flex-direction: column; align-items: center; justify-content: center; margin: 0 auto 12px; }
.grade-ring .letter { font-size: 58pt; font-weight: 700; color: var(--accent); line-height: 1; }
.grade-ring .label { font-size: 8pt; color: var(--muted); text-transform: uppercase; letter-spacing: 2px; }
.cover .score { font-size: 15pt; color: var(--text); font-weight: 600; margin-bottom: 50px; }
.cover .meta { font-size: 9pt; color: var(--muted); line-height: 2.2; }
.cover .meta strong { color: var(--text); }

/* ─── Section ─── */
h2 { color: var(--accent); font-size: 15pt; margin: 28px 0 14px; padding-bottom: 5px; border-bottom: 2px solid var(--accent); page-break-after: avoid; }
h3 { color: var(--accent-light); font-size: 10.5pt; margin: 14px 0 6px; }
.section { page-break-before: always; }

/* ─── Metrics ─── */
.metrics { display: flex; gap: 10px; margin: 14px 0 18px; }
.mc { flex: 1; border: 1px solid var(--border); border-radius: 8px; padding: 14px 10px; text-align: center; background: var(--accent-bg); }
.mc .v { font-size: 24pt; font-weight: 700; color: var(--accent); }
.mc .l { font-size: 7.5pt; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; margin-top: 2px; }
.mc.grade .v { font-size: 28pt; }

/* ─── Summary Block ─── */
.summary-block { font-size: 10.5pt; line-height: 1.9; color: var(--text); margin: 14px 0; padding: 16px 20px; background: var(--accent-bg); border-left: 4px solid var(--accent); border-radius: 0 6px 6px 0; }

/* ─── Tables ─── */
table { width: 100%; border-collapse: collapse; margin: 10px 0; font-size: 9pt; }
th { background: var(--accent); color: white; padding: 7px 10px; text-align: left; font-weight: 600; font-size: 7.5pt; text-transform: uppercase; letter-spacing: 0.5px; }
td { padding: 6px 10px; border-bottom: 1px solid #e5e7eb; vertical-align: top; }
tr:nth-child(even) { background: #f9fafb; }

/* ─── Heatmap ─── */
.heatmap { display: flex; flex-wrap: wrap; gap: 8px; margin: 12px 0; }
.hc { flex: 1 1 30%; border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px; min-width: 170px; }
.hc .cn { font-size: 9pt; font-weight: 600; color: var(--text); }
.hc .ci { font-size: 7pt; color: var(--muted); margin-bottom: 6px; }
.pill { display: inline-block; padding: 2px 10px; border-radius: 10px; font-size: 7.5pt; font-weight: 600; }
.pill-pass { background: #dcfce7; color: var(--pass); }
.pill-issues { background: #fef2f2; color: var(--fail); }
.pill-not-tested { background: #f3f4f6; color: var(--gray); }

/* ─── Badges ─── */
.sev { display: inline-block; padding: 2px 10px; border-radius: 10px; font-size: 7.5pt; font-weight: 600; color: white; }
.sev-critical { background: #dc2626; }
.sev-high { background: #ea580c; }
.sev-medium { background: #d97706; }
.sev-low { background: #2563eb; }
.sev-info { background: #6b7280; }
.pri { display: inline-block; padding: 1px 6px; border-radius: 4px; font-size: 7pt; font-weight: 700; margin-right: 4px; }
.pri-p0 { background: #fef2f2; color: var(--fail); }
.pri-p1 { background: #fffbeb; color: var(--warn); }
.pri-p2 { background: #f0f4f8; color: var(--accent); }

/* ─── Finding Card ─── */
.fc { border: 1px solid var(--border); border-radius: 8px; margin: 16px 0; page-break-inside: avoid; overflow: hidden; }
.fc-head { padding: 12px 16px; background: var(--accent-bg); border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }
.fc-title { font-weight: 600; font-size: 10.5pt; color: var(--text); max-width: 70%; }
.fc-body { padding: 14px 16px; }
.fc-row { display: flex; gap: 20px; margin-bottom: 8px; font-size: 8.5pt; color: var(--muted); flex-wrap: wrap; }
.fc-row b { color: var(--text); font-weight: 600; margin-right: 3px; }
.fc-section { margin-top: 12px; padding-top: 10px; border-top: 1px solid #eee; }
.fc-section h3 { margin-top: 0; font-size: 9.5pt; }
.fc-desc { font-size: 9.5pt; color: var(--text); margin: 6px 0; line-height: 1.7; }
.fc-impact { font-size: 9pt; color: #7c3aed; background: #f5f3ff; padding: 8px 12px; border-radius: 4px; border-left: 3px solid #7c3aed; margin: 8px 0; }
.ai-tag { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 7pt; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
.ai-ok { background: #dcfce7; color: var(--pass); }
.ai-no { background: #f3f4f6; color: var(--gray); }

/* ─── Code ─── */
.code { background: #1e293b; color: #e2e8f0; padding: 10px 14px; border-radius: 6px; font-family: 'Courier New', monospace; font-size: 8pt; white-space: pre-wrap; margin: 6px 0; line-height: 1.5; }

/* ─── Scenario ─── */
.sc { border: 1px solid var(--border); border-radius: 8px; padding: 14px 16px; margin: 10px 0; page-break-inside: avoid; }
.sc.sc-high { border-left: 4px solid var(--fail); }
.sc.sc-medium { border-left: 4px solid var(--warn); }
.sc-name { font-weight: 600; font-size: 10pt; color: var(--text); margin-bottom: 2px; }
.sc-access { font-size: 7.5pt; color: var(--muted); margin-bottom: 8px; }
.sc-body { font-size: 9pt; color: var(--muted); line-height: 1.7; }

/* ─── Matrix ─── */
.mx-pass { color: var(--pass); font-weight: 600; }
.mx-fail { color: var(--fail); font-weight: 600; }
.mx-nt { color: var(--gray); }
.mx-summary { font-size: 9pt; color: var(--muted); margin: 8px 0 12px; }

/* ─── Priority Labels ─── */
.pg { margin: 12px 0; }
.pg-label { font-size: 8.5pt; font-weight: 700; padding: 5px 12px; border-radius: 6px 6px 0 0; display: inline-block; }
.pg-urgent { background: #fef2f2; color: var(--fail); }
.pg-soon { background: #fffbeb; color: var(--warn); }
.pg-watch { background: #f0f4f8; color: var(--accent); }

.footer { text-align: center; font-size: 7pt; color: var(--gray); margin-top: 40px; padding-top: 12px; border-top: 1px solid var(--border); }
.hint { font-size: 8.5pt; color: var(--muted); margin-bottom: 14px; }
"""
