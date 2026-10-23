"""Professional PDF VAPT report generator using ReportLab.

Includes: cover page, executive summary, severity distribution, methodology,
detailed findings with full metadata, tools/limitations disclaimer.
"""
import html
from datetime import date
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable,
)
from modules.risk import count_by_severity, SEVERITY_ORDER

# ── Colour palette ──────────────────────────────────────────────────────
SEV_COLORS = {
    "Critical": colors.HexColor("#7B2D26"),
    "High": colors.HexColor("#C0392B"),
    "Medium": colors.HexColor("#E67E22"),
    "Low": colors.HexColor("#2E86C1"),
    "Informational": colors.HexColor("#7D8C8E"),
}
BRAND = colors.HexColor("#1A2332")


def _esc(text) -> str:
    """Escape untrusted text for ReportLab XML paragraphs."""
    if text is None:
        return "N/A"
    return html.escape(str(text)).replace("\n", "<br/>")


def _build_styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("CoverTitle", parent=styles["Title"], fontSize=28,
                              textColor=BRAND, spaceAfter=6))
    styles.add(ParagraphStyle("CoverSub", parent=styles["Normal"], fontSize=14,
                              textColor=colors.grey, spaceAfter=20))
    styles.add(ParagraphStyle("SectionHead", parent=styles["Heading1"], fontSize=16,
                              textColor=BRAND, spaceBefore=18, spaceAfter=8))
    styles.add(ParagraphStyle("FindingTitle", parent=styles["Heading2"], fontSize=13,
                              textColor=BRAND, spaceBefore=12, spaceAfter=4))
    styles.add(ParagraphStyle("Meta", parent=styles["Normal"], fontSize=9,
                              textColor=colors.grey))
    styles.add(ParagraphStyle("Body", parent=styles["BodyText"], fontSize=10,
                              leading=14))
    styles.add(ParagraphStyle("Disclaimer", parent=styles["Normal"], fontSize=8,
                              textColor=colors.grey, spaceBefore=10))
    return styles


def generate_report(target: str, findings: list, output_file: str,
                    recon: dict | None = None, tools_used: list | None = None):
    """Generate a professional PDF report."""
    styles = _build_styles()
    doc = SimpleDocTemplate(output_file, pagesize=A4,
                            topMargin=0.75*inch, bottomMargin=0.75*inch,
                            leftMargin=0.75*inch, rightMargin=0.75*inch)
    elements: list = []

    # ── Cover page ──────────────────────────────────────────────────
    elements.append(Spacer(1, 120))
    elements.append(Paragraph("Web Application VAPT", styles["CoverTitle"]))
    elements.append(Paragraph("Vulnerability Assessment &amp; Penetration Testing Report", styles["CoverSub"]))
    elements.append(HRFlowable(width="80%", color=BRAND, thickness=2))
    elements.append(Spacer(1, 30))
    elements.append(Paragraph(f"<b>Target:</b> {_esc(target)}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Date:</b> {date.today().isoformat()}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Tool:</b> WebVAPT Automated Framework V1", styles["Normal"]))
    if tools_used:
        elements.append(Paragraph(f"<b>Engines:</b> {_esc(', '.join(tools_used))}", styles["Normal"]))
    elements.append(PageBreak())

    # ── Executive summary ───────────────────────────────────────────
    elements.append(Paragraph("1. Executive Summary", styles["SectionHead"]))
    counts = count_by_severity(findings)
    total = sum(counts.values())
    if total == 0:
        elements.append(Paragraph(
            "No automated findings were identified during this assessment. "
            "This does not guarantee the absence of vulnerabilities. Manual testing is recommended.",
            styles["Body"]))
    else:
        elements.append(Paragraph(
            f"The automated assessment identified <b>{total}</b> finding(s) across the target application. "
            f"Findings are classified by severity below. "
            f"<b>Automated severity ratings are based on technical impact and may not reflect business risk.</b> "
            f"Manual validation and business-impact analysis are recommended.",
            styles["Body"]))
    elements.append(Spacer(1, 10))

    # ── Severity distribution table ─────────────────────────────────
    elements.append(Paragraph("2. Severity Distribution", styles["SectionHead"]))
    table_data = [["Severity", "Count"]]
    row_colors = []
    for sev in ["Critical", "High", "Medium", "Low", "Informational"]:
        table_data.append([sev, str(counts.get(sev, 0))])
        row_colors.append(SEV_COLORS.get(sev, colors.grey))

    table = Table(table_data, colWidths=[200, 100])
    style_cmds = [
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("BACKGROUND", (0, 0), (-1, 0), BRAND),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
    ]
    for i, c in enumerate(row_colors, start=1):
        style_cmds.append(("TEXTCOLOR", (0, i), (0, i), c))
    table.setStyle(TableStyle(style_cmds))
    elements.append(table)
    elements.append(Spacer(1, 15))

    # ── Scope & methodology ─────────────────────────────────────────
    elements.append(Paragraph("3. Scope &amp; Methodology", styles["SectionHead"]))
    elements.append(Paragraph(
        f"The assessment targeted <b>{_esc(target)}</b>. "
        "The following methodology was applied: HTTP reconnaissance, header/cookie analysis, "
        "port/service scanning (Nmap), web application scanning (OWASP ZAP), "
        "template-based scanning (Nuclei), finding normalization, deduplication, and risk classification.",
        styles["Body"]))
    if recon:
        elements.append(Paragraph(
            f"<b>HTTP Status:</b> {recon.get('status_code', 'N/A')} | "
            f"<b>Server:</b> {_esc(recon.get('server', 'N/A'))} | "
            f"<b>Title:</b> {_esc(recon.get('title', 'N/A'))}",
            styles["Meta"]))
    elements.append(Spacer(1, 10))

    # ── Detailed findings ───────────────────────────────────────────
    elements.append(Paragraph("4. Detailed Findings", styles["SectionHead"]))
    if not findings:
        elements.append(Paragraph("No findings to report.", styles["Body"]))
    for i, f in enumerate(sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity", ""), 0), reverse=True), 1):
        sev = f.get("severity", "Informational")
        sev_color = SEV_COLORS.get(sev, colors.grey)

        elements.append(Paragraph(
            f"{i}. {_esc(f.get('title', 'Unnamed'))}",
            styles["FindingTitle"]))

        # Metadata table
        meta = [
            ["Severity", sev, "Confidence", f.get("confidence", "N/A")],
            ["Status", f.get("status", "N/A"), "Tool(s)", ", ".join(f.get("sources", [f.get("tool", "N/A")]))],
            ["Endpoint", _esc(f.get("endpoint") or "N/A"), "Parameter", _esc(f.get("parameter") or "N/A")],
            ["CWE", f.get("cwe") or "N/A", "CVE", f.get("cve") or "N/A"],
            ["CVSS", str(f.get("cvss") or "N/A"), "OWASP", f.get("owasp") or "N/A"],
        ]
        meta_table = Table(meta, colWidths=[70, 170, 70, 170])
        meta_style = [
            ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("TEXTCOLOR", (1, 0), (1, 0), sev_color),
        ]
        meta_table.setStyle(TableStyle(meta_style))
        elements.append(meta_table)

        desc = f.get("description") or "No description available."
        elements.append(Paragraph(f"<b>Description:</b> {_esc(desc[:2000])}", styles["Body"]))

        evidence = f.get("evidence")
        if evidence:
            elements.append(Paragraph(f"<b>Evidence:</b> {_esc(str(evidence)[:1000])}", styles["Body"]))

        impact = f.get("impact")
        if impact:
            elements.append(Paragraph(f"<b>Impact:</b> {_esc(str(impact)[:500])}", styles["Body"]))

        remediation = f.get("remediation")
        if remediation:
            elements.append(Paragraph(f"<b>Remediation:</b> {_esc(str(remediation)[:1000])}", styles["Body"]))

        refs = f.get("references")
        if refs:
            elements.append(Paragraph(f"<b>References:</b> {_esc(str(refs)[:500])}", styles["Body"]))

        elements.append(HRFlowable(width="100%", color=colors.lightgrey, thickness=0.5))
        elements.append(Spacer(1, 8))

    # ── Limitations & disclaimer ────────────────────────────────────
    elements.append(PageBreak())
    elements.append(Paragraph("5. Tools, Limitations &amp; Disclaimer", styles["SectionHead"]))
    elements.append(Paragraph(
        "This report was generated by an automated framework. Automated tools may produce false positives "
        "and cannot detect all vulnerability classes. Business logic flaws, access control issues, and "
        "context-dependent vulnerabilities require manual expert testing. "
        "<b>Automated severity ratings are not a substitute for business-impact analysis.</b> "
        "Findings marked 'Potential' or 'Needs Manual Validation' should be verified by a qualified assessor.",
        styles["Body"]))
    if tools_used:
        elements.append(Paragraph(f"<b>Tools used:</b> {_esc(', '.join(tools_used))}", styles["Body"]))
    elements.append(Paragraph(
        f"Report generated on {date.today().isoformat()} by WebVAPT Framework V1.",
        styles["Disclaimer"]))

    doc.build(elements)
