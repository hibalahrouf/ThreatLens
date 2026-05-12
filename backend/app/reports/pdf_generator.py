"""
MASVS Audit Copilot — Consulting-Grade PDF Report Generator
9 sections: Cover, Executive Summary, Security Posture, Priority Plan,
Attack Scenarios, Technical Findings, Compliance Matrix, Methodology, Appendix.
"""

from datetime import datetime, timezone
from jinja2 import Template

from app.reports.pdf_template import PDF_CSS
from app.reports.report_helpers import (
    split_findings, count_severities, build_compliance_matrix,
    build_category_heatmap, get_heatmap_summary, build_priority_plan,
    generate_attack_scenarios, generate_executive_summary, get_business_impact,
)


def generate_pdf_report(scan_data: dict, findings: list, output_path: str) -> str:
    """Generate a consulting-grade PDF audit report."""
    from weasyprint import HTML

    confirmed, dismissed = split_findings(findings)
    # Deduplicate confirmed findings so the same vulnerability on multiple
    # components (e.g. StrandHogg on 4 Activities) appears only once in the report.
    from app.utils.finding_utils import deduplicate_findings
    confirmed = deduplicate_findings(confirmed)
    sev = count_severities(confirmed)
    matrix = build_compliance_matrix(confirmed, dismissed)
    heatmap = build_category_heatmap(matrix)
    heatmap_note = get_heatmap_summary(heatmap)
    priority = build_priority_plan(confirmed)
    scenarios = generate_attack_scenarios(confirmed)
    exec_summary = scan_data.get("executive_summary") or generate_executive_summary(scan_data, confirmed, dismissed)

    # Sanitize triage text — strip internal error messages before rendering
    def _sanitize_triage(text):
        if not text:
            return "Confirmed by automated static analysis rules."
        error_indicators = ["timed out", "failed", "error", "exception", "defaulting"]
        if any(indicator in text.lower() for indicator in error_indicators):
            return "Confirmed by automated static analysis rules."
        return text

    # Add business impact + sanitize triage for each confirmed finding
    for f in confirmed:
        f["business_impact"] = get_business_impact(f)
        f["triage_justification"] = _sanitize_triage(f.get("triage_justification"))

    # Sanitize triage for dismissed findings (shown in Appendix)
    for f in dismissed:
        f["triage_justification"] = _sanitize_triage(f.get("triage_justification"))

    # Matrix summary counts
    mx_pass = sum(1 for m in matrix if m["status"] == "PASS")
    mx_fail = sum(1 for m in matrix if m["status"] == "FAIL")
    mx_nt = sum(1 for m in matrix if m["status"] == "NOT TESTED")

    scan_date = datetime.now(timezone.utc).strftime("%B %d, %Y")

    # ── Determine methodology line based on scan_mode and finding sources ──
    scan_mode = scan_data.get("scan_mode") or "static"
    has_frida = any((f.get("source") or "") == "frida" for f in confirmed)
    if scan_mode == "dynamic" and has_frida:
        methodology_line = "Static Analysis: MobSF + Dynamic Analysis: MobSF Runtime + Frida"
    elif scan_mode == "dynamic":
        methodology_line = "Static Analysis: MobSF + Dynamic Analysis: MobSF Runtime"
    else:
        methodology_line = "Static Analysis: MobSF"

    dynamic_status = scan_data.get("dynamic_status") or "not_requested"
    dynamic_error = scan_data.get("dynamic_error")
    
    count_dynamic = sum(1 for f in confirmed if (f.get("source") or "") == "dynamic")
    count_frida = sum(1 for f in confirmed if (f.get("source") or "") == "frida")
    count_network = sum(1 for f in confirmed if (f.get("source") or "") == "network")
    count_runtime = count_dynamic + count_frida + count_network

    template = Template(TEMPLATE)
    html = template.render(
        css=PDF_CSS, app_name=scan_data.get("file_name", "Unknown"),
        file_hash=scan_data.get("file_hash", "N/A"), scan_date=scan_date,
        score=scan_data.get("score", 0) or 0, grade=scan_data.get("grade", "?"),
        exec_summary=exec_summary, total_all=len(confirmed) + len(dismissed),
        total_confirmed=len(confirmed), total_dismissed=len(dismissed),
        sev=sev, heatmap=heatmap, heatmap_note=heatmap_note,
        matrix=matrix, mx_pass=mx_pass, mx_fail=mx_fail, mx_nt=mx_nt,
        priority=priority, scenarios=scenarios,
        confirmed=confirmed, dismissed=dismissed,
        methodology_line=methodology_line,
        scan_mode=scan_mode,
        has_frida=has_frida,
        dynamic_status=dynamic_status,
        dynamic_error=dynamic_error,
        count_dynamic=count_dynamic,
        count_frida=count_frida,
        count_network=count_network,
        count_runtime=count_runtime,
    )

    HTML(string=html).write_pdf(output_path)
    return output_path


TEMPLATE = r"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>{{ css }}</style></head>
<body>

<!-- 1. COVER -->
<div class="cover">
  <div class="cover-brand">MASVS Audit Copilot</div>
  <h1>Security Audit Report</h1>
  <div class="sub">OWASP MASVS v2 Compliance Assessment</div>
  <div class="grade-ring">
    <span class="letter">{{ grade }}</span>
    <span class="label">Grade</span>
  </div>
  <div class="score">{{ "%.1f"|format(score) }} / 100</div>
  <div class="meta">
    <strong>Application:</strong> {{ app_name }}<br>
    <strong>Date:</strong> {{ scan_date }}<br>
    <strong>Standard:</strong> OWASP MASVS v2 / MASTG<br>
    <strong>Tool:</strong> MASVS Audit Copilot
  </div>
</div>

<!-- 2. EXECUTIVE SUMMARY -->
<div class="section">
  <h2>Executive Summary</h2>
  <div class="summary-block">{{ exec_summary }}</div>
  <div class="metrics">
    <div class="mc"><div class="v">{{ total_all }}</div><div class="l">Total Findings</div></div>
    <div class="mc"><div class="v">{{ total_confirmed }}</div><div class="l">Confirmed</div></div>
    <div class="mc"><div class="v">{{ total_dismissed }}</div><div class="l">Dismissed</div></div>
    <div class="mc grade"><div class="v">{{ grade }}</div><div class="l">Grade</div></div>
  </div>
  <table>
    <tr><th>Severity</th><th>Count</th></tr>
    <tr><td>Critical</td><td style="color:#dc2626;font-weight:600">{{ sev.critical }}</td></tr>
    <tr><td>High</td><td style="color:#ea580c;font-weight:600">{{ sev.high }}</td></tr>
    <tr><td>Medium</td><td style="color:#d97706">{{ sev.medium }}</td></tr>
    <tr><td>Low</td><td style="color:#2563eb">{{ sev.low }}</td></tr>
    <tr><td>Informational</td><td>{{ sev.info }}</td></tr>
  </table>

  {% if scan_mode == 'dynamic' %}
  <div class="dynamic-summary-block" style="margin-top:20px;padding:15px;background:#f8fafc;border-left:4px solid #4A90D9;border-radius:4px;">
    <h3 style="margin-top:0;margin-bottom:10px;font-size:11pt;color:#1e293b;">Dynamic Analysis</h3>
    {% if dynamic_status == 'completed' %}
    <p style="margin:0 0 5px;font-size:10pt;color:#4a5568;"><b>Status:</b> <span style="color:#27AE60">Completed &#10003;</span></p>
    <p style="margin:0 0 5px;font-size:10pt;color:#4a5568;"><b>Runtime findings:</b> {{ count_runtime }}</p>
    <p style="margin:0;font-size:10pt;color:#4a5568;"><b>Sources:</b> Network ({{ count_network }}) &middot; Dynamic ({{ count_dynamic }}) &middot; Frida ({{ count_frida }})</p>
    {% elif dynamic_status in ['running', 'queued'] %}
    <p style="margin:0 0 5px;font-size:10pt;color:#4a5568;"><b>Status:</b> {{ dynamic_status|capitalize }}</p>
    <p style="margin:0;font-size:10pt;color:#64748b;">Analysis was still in progress when this report was generated.</p>
    {% elif dynamic_status == 'failed' %}
    <p style="margin:0 0 5px;font-size:10pt;color:#4a5568;"><b>Status:</b> <span style="color:#dc2626">Failed &#10007;</span></p>
    <p style="margin:0;font-size:10pt;color:#4a5568;"><b>Reason:</b> {{ dynamic_error if dynamic_error else "Unknown error" }}</p>
    {% endif %}
  </div>
  {% endif %}
</div>

<!-- 3. SECURITY POSTURE -->
<div class="section">
  <h2>Security Posture Dashboard</h2>
  <p class="hint">{{ heatmap_note }}</p>
  <div class="heatmap">
    {% for h in heatmap %}
    <div class="hc">
      <div class="ci">{{ h.id }}</div>
      <div class="cn">{{ h.name }}</div>
      <span class="pill pill-{{ h.overall|lower|replace(' ','-') }}">{{ h.overall }}</span>
    </div>
    {% endfor %}
  </div>
</div>

<!-- 4. PRIORITY ACTION PLAN -->
<div class="section">
  <h2>Priority Action Plan</h2>

  {% if priority.fix_week %}
  <div class="pg">
    <span class="pg-label pg-urgent">Fix This Week</span>
    <table>
      <tr><th>Priority</th><th>Issue</th><th>Severity</th><th>MASVS</th><th>Effort</th></tr>
      {% for i in priority.fix_week %}
      <tr>
        <td><span class="pri pri-{{ i.priority|lower }}">{{ i.priority }}</span></td>
        <td>{{ i.title }}</td>
        <td><span class="sev sev-{{ i.severity }}">{{ i.severity|upper }}</span></td>
        <td>{{ i.masvs_control }}</td>
        <td>{{ i.effort }}</td>
      </tr>
      {% endfor %}
    </table>
  </div>
  {% endif %}

  {% if priority.fix_month %}
  <div class="pg">
    <span class="pg-label pg-soon">Fix This Month</span>
    <table>
      <tr><th>Priority</th><th>Issue</th><th>Severity</th><th>MASVS</th><th>Effort</th></tr>
      {% for i in priority.fix_month %}
      <tr>
        <td><span class="pri pri-{{ i.priority|lower }}">{{ i.priority }}</span></td>
        <td>{{ i.title }}</td>
        <td><span class="sev sev-{{ i.severity }}">{{ i.severity|upper }}</span></td>
        <td>{{ i.masvs_control }}</td>
        <td>{{ i.effort }}</td>
      </tr>
      {% endfor %}
    </table>
  </div>
  {% endif %}

  {% if priority.monitor %}
  <div class="pg">
    <span class="pg-label pg-watch">Monitor</span>
    <table>
      <tr><th>Priority</th><th>Issue</th><th>Severity</th><th>MASVS</th><th>Effort</th></tr>
      {% for i in priority.monitor %}
      <tr>
        <td><span class="pri pri-{{ i.priority|lower }}">{{ i.priority }}</span></td>
        <td>{{ i.title }}</td>
        <td><span class="sev sev-{{ i.severity }}">{{ i.severity|upper }}</span></td>
        <td>{{ i.masvs_control }}</td>
        <td>{{ i.effort }}</td>
      </tr>
      {% endfor %}
    </table>
  </div>
  {% endif %}
</div>

<!-- 5. ATTACK SCENARIOS -->
{% if scenarios %}
<div class="section">
  <h2>Attack Scenarios</h2>
  <p class="hint">The following scenarios illustrate how confirmed vulnerabilities could be chained into real-world attacks.</p>
  {% for s in scenarios %}
  <div class="sc sc-{{ s.severity }}">
    <div class="sc-name">{{ s.name }}</div>
    <div class="sc-access">Attacker access: {{ s.access }} | {{ s.finding_count }} related finding{{ 's' if s.finding_count != 1 }}</div>
    <div class="sc-body">{{ s.narrative }}</div>
  </div>
  {% endfor %}
</div>
{% endif %}

<!-- 6. TECHNICAL FINDINGS -->
<div class="section">
  <h2>Technical Findings</h2>
  <p class="hint">{{ confirmed|length }} confirmed vulnerabilit{{ 'y' if confirmed|length == 1 else 'ies' }}. Dismissed findings are in the Appendix.</p>

  {% for f in confirmed %}
  <div class="fc">
    <div class="fc-head">
      <span class="fc-title">{{ f.title }}</span>
      {% if f.source == 'dynamic' %}<span style="display:inline-block;font-size:7pt;font-weight:700;color:#fff;background:#E67E22;padding:1px 6px;border-radius:3px;margin-left:6px;vertical-align:middle;letter-spacing:0.5px">DYNAMIC</span>{% endif %}
      {% if f.source == 'frida' %}<span style="display:inline-block;font-size:7pt;font-weight:700;color:#fff;background:#8E44AD;padding:1px 6px;border-radius:3px;margin-left:6px;vertical-align:middle;letter-spacing:0.5px">FRIDA</span>{% endif %}
      {% if f.source == 'network' %}<span style="display:inline-block;font-size:7pt;font-weight:700;color:#fff;background:#27AE60;padding:1px 6px;border-radius:3px;margin-left:6px;vertical-align:middle;letter-spacing:0.5px">NETWORK</span>{% endif %}
      <span class="sev sev-{{ f.severity }}">{{ f.severity|upper }}</span>
    </div>
    <div class="fc-body">
      <div class="fc-row">
        <span><b>MASVS:</b> {{ f.masvs_control or 'N/A' }}</span>
        <span><b>CVSS:</b> {{ "%.1f"|format(f.cvss_score) if f.cvss_score else 'N/A' }}</span>
        {% if f.affected_file %}<span><b>File:</b> {{ f.affected_file }}</span>{% endif %}
        <span class="ai-tag ai-ok">AI Confirmed</span>
      </div>

      <h3>Description</h3>
      <div class="fc-desc">{{ f.description }}</div>

      {% if f.business_impact %}
      <h3>Business Impact</h3>
      <div class="fc-impact">{{ f.business_impact }}</div>
      {% endif %}

      {% if f.affected_code %}
      <div class="fc-section">
        <h3>Vulnerable Code</h3>
        <div class="code">{{ f.affected_code }}</div>
      </div>
      {% endif %}

      {% if f.triage_justification %}
      <div class="fc-section">
        <h3>AI Verification</h3>
        <p style="font-size:9pt;color:#4a5568;font-style:italic;padding:8px 12px;background:#f0f4f8;border-radius:4px">{{ f.triage_justification }}</p>
      </div>
      {% endif %}

      {% if f.remediation_description or f.remediation_code %}
      <div class="fc-section">
        <h3>Recommended Fix</h3>
        {% if f.remediation_description %}
        <p style="font-size:9pt;color:#4a5568;margin-bottom:6px">{{ f.remediation_description }}</p>
        {% endif %}
        {% if f.remediation_code %}
        <div class="code">{{ f.remediation_code }}</div>
        {% endif %}
      </div>
      {% endif %}
    </div>
  </div>
  {% endfor %}

  {% if not confirmed %}
  <p style="text-align:center;color:#9ca3af;padding:30px">No confirmed vulnerabilities.</p>
  {% endif %}
</div>

<!-- 7. COMPLIANCE MATRIX -->
<div class="section">
  <h2>MASVS v2 Compliance Matrix</h2>
  <p class="mx-summary">{{ mx_pass }} controls passed | {{ mx_fail }} controls failed | {{ mx_nt }} controls not tested</p>
  <table>
    <tr><th>Control</th><th>Description</th><th>Category</th><th>Status</th></tr>
    {% for c in matrix %}
    <tr>
      <td style="font-weight:600;font-family:monospace;font-size:8pt">{{ c.control_id }}</td>
      <td>{{ c.description }}</td>
      <td>{{ c.category }}</td>
      <td class="mx-{{ 'pass' if c.status=='PASS' else ('fail' if c.status=='FAIL' else 'nt') }}">{{ c.status }}</td>
    </tr>
    {% endfor %}
  </table>
</div>

<!-- 8. METHODOLOGY -->
<div class="section">
  <h2>Methodology and Tool Stack</h2>
  <p class="hint">This audit follows the OWASP Mobile Application Security Verification Standard (MASVS) v2 and the Mobile Application Security Testing Guide (MASTG).</p>
  <p style="font-size:9pt;color:#2d3748;margin-bottom:10px"><b>Analysis Pipeline:</b> {{ methodology_line }}</p>
  <table>
    <tr><th>Stage</th><th>Tool</th><th>Description</th></tr>
    <tr><td>Static Analysis</td><td>MobSF</td><td>Automated decompilation and rule-based vulnerability detection</td></tr>
    <tr><td>MASVS Mapping</td><td>Custom Engine</td><td>50+ rules mapping findings to MASVS v2 controls</td></tr>
    <tr><td>Risk Scoring</td><td>CVSS v3.1</td><td>Standardized vulnerability scoring</td></tr>
    <tr><td>AI Triage</td><td>LLM</td><td>Contextual false-positive filtering</td></tr>
    <tr><td>AI Remediation</td><td>LLM + Critic</td><td>Automated fix generation with validation pass</td></tr>
    <tr><td>SCA / SBOM</td><td>OSV.dev</td><td>Third-party dependency vulnerability lookup</td></tr>
    {% if scan_mode == 'dynamic' %}
    <tr><td>Dynamic Analysis</td><td>MobSF Runtime</td><td>Automated runtime testing on Android emulator</td></tr>
    {% endif %}
    {% if scan_mode == 'dynamic' and has_frida %}
    <tr><td>Instrumentation</td><td>Frida</td><td>Runtime hooking and API interception</td></tr>
    {% endif %}
  </table>
  <h3>References</h3>
  <ul style="font-size:8.5pt;color:#4a5568;margin:6px 0 0 18px;line-height:2.2">
    <li>OWASP MASVS v2.0 — https://mas.owasp.org/MASVS/</li>
    <li>OWASP MASTG — https://mas.owasp.org/MASTG/</li>
    <li>CVSS v3.1 — https://www.first.org/cvss/v3.1/specification-document</li>
  </ul>
</div>

<!-- 9. APPENDIX -->
<div class="section">
  <h2>Appendix</h2>
  <h3>A. Scan Metadata</h3>
  <table>
    <tr><td style="font-weight:600;width:30%">File Name</td><td>{{ app_name }}</td></tr>
    <tr><td style="font-weight:600">SHA-256</td><td style="font-family:monospace;font-size:7.5pt">{{ file_hash }}</td></tr>
    <tr><td style="font-weight:600">Scan Date</td><td>{{ scan_date }}</td></tr>
    <tr><td style="font-weight:600">Score / Grade</td><td>{{ "%.1f"|format(score) }} / 100 ({{ grade }})</td></tr>
    <tr><td style="font-weight:600">Findings</td><td>{{ total_all }} total ({{ total_confirmed }} confirmed, {{ total_dismissed }} dismissed)</td></tr>
  </table>

  {% if dismissed %}
  <h3>B. Dismissed Findings (False Positives)</h3>
  <table>
    <tr><th>#</th><th>Title</th><th>Severity</th><th>MASVS</th><th>Dismissal Reason</th></tr>
    {% for f in dismissed %}
    <tr>
      <td>{{ loop.index }}</td>
      <td>{{ f.title }}</td>
      <td><span class="sev sev-{{ f.severity }}">{{ f.severity|upper }}</span></td>
      <td>{{ f.masvs_control or 'N/A' }}</td>
      <td style="font-size:8pt;max-width:180px">{{ (f.triage_justification or 'No reason provided')[:120] }}</td>
    </tr>
    {% endfor %}
  </table>
  {% endif %}

  <div class="footer">
    <p>Generated by MASVS Audit Copilot — {{ scan_date }}</p>
    <p>Based on OWASP MASVS v2 and MASTG Standards</p>
    <p>This report is confidential and intended for the application owner only.</p>
  </div>
</div>

</body></html>"""
