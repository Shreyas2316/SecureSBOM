"""
Report Generation Service
Generates PDF, JSON, and CSV vulnerability reports.
Reports clearly separate verified findings (Category A) from AI assessments (Category B).
"""
import csv
import html
import io
import json
import logging
import os
import uuid
import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger("securesbom.reports")


def utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


# ─────────────────────────────────────────────────────────────
# JSON Report
# ─────────────────────────────────────────────────────────────

def generate_json_report(
    scan_data: Dict[str, Any],
    ai_findings: List[Dict[str, Any]],
    alternatives: List[Dict[str, Any]],
    report_id: str,
) -> bytes:
    """
    Generate a structured JSON report for a complete scan.
    Verified findings and AI findings are in separate top-level keys.
    """
    report = {
        "report_id": report_id,
        "report_type": "full_scan",
        "generated_at": utc_now().isoformat(),
        "generator": "SecureSBOM v2.0",
        "disclaimer": (
            "This report contains two categories of findings. "
            "Category A (verified_findings) are produced by deterministic OSV/NVD matching. "
            "Category B (ai_findings) are AI-generated assessments and have NOT been confirmed "
            "as vulnerabilities. They require independent verification before action."
        ),
        "scan_metadata": {
            "scan_id": scan_data.get("summary", {}).get("scan_id"),
            "project_name": scan_data.get("summary", {}).get("project_name"),
            "timestamp": str(scan_data.get("summary", {}).get("timestamp", "")),
            "total_deps": scan_data.get("summary", {}).get("total_deps", 0),
            "direct_deps": scan_data.get("summary", {}).get("direct_deps", 0),
            "transitive_deps": scan_data.get("summary", {}).get("transitive_deps", 0),
            "scan_duration_seconds": scan_data.get("summary", {}).get("scan_duration_seconds", 0),
        },
        "component_inventory": scan_data.get("components", []),
        "verified_findings": {
            "count": scan_data.get("summary", {}).get("unique_vuln_count", 0),
            "advisory_records_count": scan_data.get("summary", {}).get("advisory_record_count", 0),
            "affected_components_count": scan_data.get("summary", {}).get("affected_components_count", 0),
            "severity_distribution": {
                "CRITICAL": scan_data.get("summary", {}).get("critical_count", 0),
                "HIGH": scan_data.get("summary", {}).get("high_count", 0),
                "MEDIUM": scan_data.get("summary", {}).get("medium_count", 0),
                "LOW": scan_data.get("summary", {}).get("low_count", 0),
                "INFO": scan_data.get("summary", {}).get("info_count", 0),
                "UNKNOWN": scan_data.get("summary", {}).get("unknown_count", 0),
            },
            "data_sources": ["OSV", "NVD"],
            "findings": scan_data.get("vulnerabilities", []),
        },
        "ai_findings": {
            "count": len(ai_findings),
            "note": (
                "AI-generated assessments only. Not confirmed vulnerabilities. "
                "AI finding counts are separate from verified_findings counts."
            ),
            "findings": ai_findings,
        },
        "safer_alternatives": {
            "count": len(alternatives),
            "note": "Recommendations require manual review before applying.",
            "recommendations": alternatives,
        },
    }

    return json.dumps(report, indent=2, default=str).encode("utf-8")


# ─────────────────────────────────────────────────────────────
# CSV Report
# ─────────────────────────────────────────────────────────────

def generate_csv_report(
    scan_data: Dict[str, Any],
    ai_findings: List[Dict[str, Any]],
) -> bytes:
    """
    Generate CSV summary with two sections: verified findings and AI findings.
    """
    output = io.StringIO()
    writer = csv.writer(output)

    # Header metadata
    writer.writerow(["SecureSBOM Vulnerability Report"])
    writer.writerow(["Generated At", utc_now().isoformat()])
    writer.writerow(["Project", scan_data.get("summary", {}).get("project_name", "")])
    writer.writerow(["Scan ID", scan_data.get("summary", {}).get("scan_id", "")])
    writer.writerow([])

    # ── Section A: Verified Findings ──
    writer.writerow(["SECTION A: VERIFIED VULNERABILITY FINDINGS (OSV/NVD)"])
    writer.writerow([
        "Canonical ID", "CVE ID", "Severity", "CVSS Score", "Priority Tier",
        "Affected Package", "Affected Version", "Fixed Version",
        "Summary", "Sources"
    ])

    for v in scan_data.get("vulnerabilities", []):
        writer.writerow([
            v.get("canonical_id", ""),
            v.get("cve_id", "") or "",
            v.get("severity", "UNKNOWN"),
            v.get("cvss_score", "") or "",
            v.get("priority_tier", ""),
            v.get("affected_component_name", ""),
            v.get("affected_component_version", ""),
            v.get("fixed_version", "") or "",
            (v.get("summary", "") or "")[:200],
            "; ".join(v.get("sources", [])),
        ])

    writer.writerow([])

    # ── Section B: AI Findings ──
    writer.writerow(["SECTION B: AI-ASSESSED EMERGING VULNERABILITIES (UNVERIFIED)"])
    writer.writerow(["DISCLAIMER: These are AI-generated assessments and are NOT confirmed vulnerabilities."])
    writer.writerow([
        "Finding ID", "Package", "Version", "Assessment Type",
        "Title", "Confidence", "Status", "Model", "Created At"
    ])

    for f in ai_findings:
        writer.writerow([
            f.get("finding_id", ""),
            f.get("package_name", ""),
            f.get("package_version", ""),
            f.get("assessment_type", ""),
            f.get("title", ""),
            f.get("confidence", ""),
            f.get("status", ""),
            f.get("model_name", "") or "",
            str(f.get("created_at", "")),
        ])

    # ── Section C: Component Inventory ──
    components = scan_data.get("components", [])
    if components:
        writer.writerow([])
        writer.writerow(["SECTION C: COMPONENT INVENTORY & DEPENDENCIES"])
        writer.writerow(["Package Name", "Version", "Ecosystem", "Dependency Type", "PURL"])
        for c in components:
            writer.writerow([
                c.get("name", ""),
                c.get("version", ""),
                c.get("ecosystem", "PyPI"),
                "Direct" if c.get("is_direct") else "Transitive",
                c.get("purl", ""),
            ])

    return output.getvalue().encode("utf-8")


# ─────────────────────────────────────────────────────────────
# PDF Report (using reportlab if available, fallback to text/HTML)
# ─────────────────────────────────────────────────────────────

def _try_import_reportlab():
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            PageBreak, HRFlowable
        )
        return True
    except ImportError:
        return False


def generate_pdf_report(
    scan_data: Dict[str, Any],
    ai_findings: List[Dict[str, Any]],
    alternatives: List[Dict[str, Any]],
    report_id: str,
) -> bytes:
    """
    Generate PDF report. Uses reportlab if available.
    Falls back to plain-text PDF-like bytes if reportlab is not installed.
    """
    if _try_import_reportlab():
        return _generate_pdf_reportlab(scan_data, ai_findings, alternatives, report_id)
    else:
        logger.warning("reportlab not installed; generating plain-text report instead of PDF")
        return _generate_plaintext_report(scan_data, ai_findings, alternatives, report_id)


def _generate_pdf_reportlab(
    scan_data: Dict[str, Any],
    ai_findings: List[Dict[str, Any]],
    alternatives: List[Dict[str, Any]],
    report_id: str,
) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, HRFlowable
    )

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2.5 * cm,
        bottomMargin=2 * cm,
        title=f"SecureSBOM Security Report — {report_id}",
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=20,
        textColor=colors.HexColor("#1a1a2e"),
        spaceAfter=6,
    )
    h1_style = ParagraphStyle(
        "H1",
        parent=styles["Heading1"],
        fontSize=14,
        textColor=colors.HexColor("#16213e"),
        spaceBefore=14,
        spaceAfter=6,
    )
    h2_style = ParagraphStyle(
        "H2",
        parent=styles["Heading2"],
        fontSize=11,
        textColor=colors.HexColor("#0f3460"),
        spaceBefore=10,
        spaceAfter=4,
    )
    body_style = styles["BodyText"]
    body_style.fontSize = 9
    mono_style = ParagraphStyle(
        "Mono",
        parent=styles["Code"],
        fontSize=8,
        textColor=colors.HexColor("#334155"),
    )
    disclaimer_style = ParagraphStyle(
        "Disclaimer",
        parent=styles["BodyText"],
        fontSize=8,
        textColor=colors.HexColor("#b91c1c"),
        borderPad=4,
        backColor=colors.HexColor("#fee2e2"),
        borderRadius=4,
    )

    summary = scan_data.get("summary", {})
    story = []

    # ── Title Page ──
    story.append(Paragraph("SecureSBOM Security Report", title_style))
    story.append(Paragraph(f"Report ID: {report_id}", mono_style))
    story.append(Paragraph(f"Generated: {utc_now().strftime('%Y-%m-%d %H:%M:%S UTC')}", mono_style))
    story.append(Spacer(1, 0.3 * cm))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))
    story.append(Spacer(1, 0.3 * cm))

    # Disclaimer
    story.append(Paragraph(
        "⚠ IMPORTANT: This report contains two categories of findings. "
        "Section A contains verified findings from OSV/NVD advisory databases. "
        "Section B contains AI-generated assessments that have NOT been confirmed as vulnerabilities "
        "and require independent verification.",
        disclaimer_style
    ))
    story.append(Spacer(1, 0.5 * cm))

    # ── Scan Metadata ──
    story.append(Paragraph("Scan Overview", h1_style))
    meta_data = [
        ["Project", summary.get("project_name", "Unknown")],
        ["Scan ID", str(summary.get("scan_id", ""))],
        ["Timestamp", str(summary.get("timestamp", ""))],
        ["Total Components", str(summary.get("total_deps", 0))],
        ["Direct Dependencies", str(summary.get("direct_deps", 0))],
        ["Transitive Dependencies", str(summary.get("transitive_deps", 0))],
        ["Scan Duration (s)", str(summary.get("scan_duration_seconds", 0))],
    ]
    meta_table = Table(meta_data, colWidths=[5 * cm, 12 * cm])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#475569")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.4 * cm))

    # Severity Distribution Overview
    story.append(Paragraph("Vulnerability Severity Breakdown", h2_style))
    sev_counts = summary.get("severity_counts") or {
        "CRITICAL": summary.get("critical_count", 0),
        "HIGH": summary.get("high_count", 0),
        "MEDIUM": summary.get("medium_count", 0),
        "LOW": summary.get("low_count", 0),
        "INFO": summary.get("info_count", 0),
        "UNKNOWN": summary.get("unknown_count", 0),
    }
    sev_table_data = [
        ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO / OTHER", "TOTAL VERIFIED"],
        [
            str(sev_counts.get("CRITICAL", 0)),
            str(sev_counts.get("HIGH", 0)),
            str(sev_counts.get("MEDIUM", 0)),
            str(sev_counts.get("LOW", 0)),
            str(sev_counts.get("INFO", sev_counts.get("INFORMATIONAL", 0)) + sev_counts.get("UNKNOWN", 0)),
            str(len(scan_data.get("vulnerabilities", []))),
        ]
    ]
    sev_table = Table(sev_table_data, colWidths=[2.8 * cm, 2.8 * cm, 2.8 * cm, 2.8 * cm, 2.8 * cm, 3.0 * cm])
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#dc2626")),
        ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#ea580c")),
        ("BACKGROUND", (2, 0), (2, 0), colors.HexColor("#d97706")),
        ("BACKGROUND", (3, 0), (3, 0), colors.HexColor("#2563eb")),
        ("BACKGROUND", (4, 0), (4, 0), colors.HexColor("#64748b")),
        ("BACKGROUND", (5, 0), (5, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(sev_table)
    story.append(Spacer(1, 0.4 * cm))

    # ── Section A: Verified Findings ──
    story.append(PageBreak())
    story.append(Paragraph("Section A: Verified Vulnerability Findings", h1_style))
    story.append(Paragraph(
        "These findings are produced by deterministic package/version matching against "
        "OSV and NVD advisory databases. Severity ratings use source-provided CVSS scores.",
        body_style
    ))
    story.append(Spacer(1, 0.3 * cm))

    verified_vulns = scan_data.get("vulnerabilities", [])
    story.append(Paragraph(f"Total Canonical Vulnerabilities: {len(verified_vulns)}", h2_style))

    if verified_vulns:
        vuln_table_data = [["ID", "Severity", "CVSS", "Package", "Version", "Fixed", "Summary"]]
        for v in verified_vulns:
            summary_raw = (v.get("summary") or "")[:120]
            summary_esc = html.escape(summary_raw)
            vuln_id = html.escape(str(v.get("canonical_id", "")[:28]))
            pkg_name = html.escape(str(v.get("affected_component_name", "")[:22]))
            cvss_val = v.get("cvss_score")
            cvss_str = f"{cvss_val:.1f}" if isinstance(cvss_val, (int, float)) else str(cvss_val or "—")
            fixed = html.escape(str(v.get("fixed_version", "") or "—")[:15])
            ver = html.escape(str(v.get("affected_component_version", "") or "—")[:15])

            vuln_table_data.append([
                Paragraph(vuln_id, mono_style),
                v.get("severity", "UNKNOWN"),
                cvss_str,
                Paragraph(pkg_name, body_style),
                ver,
                fixed,
                Paragraph(summary_esc, body_style),
            ])

        SEV_COLORS = {
            "CRITICAL": colors.HexColor("#fee2e2"),
            "HIGH": colors.HexColor("#fff7ed"),
            "MEDIUM": colors.HexColor("#fefce8"),
            "LOW": colors.HexColor("#eff6ff"),
            "INFO": colors.HexColor("#f8fafc"),
            "UNKNOWN": colors.HexColor("#f8fafc"),
        }

        vuln_table = Table(
            vuln_table_data,
            colWidths=[3.2 * cm, 1.8 * cm, 1.4 * cm, 2.5 * cm, 1.8 * cm, 1.8 * cm, 4.5 * cm]
        )
        table_styles = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]
        for i, v in enumerate(verified_vulns, 1):
            sev = v.get("severity", "UNKNOWN").upper()
            bg = SEV_COLORS.get(sev, colors.white)
            table_styles.append(("BACKGROUND", (0, i), (-1, i), bg))

        vuln_table.setStyle(TableStyle(table_styles))
        story.append(vuln_table)
    else:
        story.append(Paragraph("No verified vulnerabilities found.", body_style))

    # ── Section B: AI Findings ──
    story.append(PageBreak())
    story.append(Paragraph("Section B: AI-Assessed Emerging Vulnerabilities", h1_style))
    story.append(Paragraph(
        "⚠ DISCLAIMER: The following findings are AI-generated assessments. "
        "They are NOT confirmed vulnerabilities. Review the evidence and perform "
        "independent verification before taking action. AI assessments are NOT "
        "included in the verified vulnerability count above.",
        disclaimer_style
    ))
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph(f"Total AI Assessments: {len(ai_findings)}", h2_style))

    for finding in ai_findings:
        story.append(Spacer(1, 0.3 * cm))
        f_id = html.escape(str(finding.get('finding_id', '')))
        f_title = html.escape(str(finding.get('title', '')))
        story.append(Paragraph(
            f"Finding: {f_id} — {f_title}",
            h2_style
        ))
        f_pkg = html.escape(str(finding.get('package_name', '')))
        f_ver = html.escape(str(finding.get('package_version', '')))
        f_conf = html.escape(str(finding.get('confidence', '')))
        f_stat = html.escape(str(finding.get('status', '')))
        story.append(Paragraph(
            f"Package: {f_pkg} @ {f_ver} | Confidence: {f_conf} | Status: {f_stat}",
            mono_style
        ))
        if finding.get("description"):
            story.append(Paragraph(html.escape(finding["description"][:600]), body_style))
        if finding.get("limitations"):
            story.append(Paragraph(f"Limitations: {html.escape(finding['limitations'])}", disclaimer_style))

    # ── Safer Alternatives ──
    if alternatives:
        story.append(PageBreak())
        story.append(Paragraph("Safer Dependency Alternatives", h1_style))
        story.append(Paragraph(
            "Recommendations require manual review. Do NOT apply automatically.",
            disclaimer_style
        ))
        story.append(Spacer(1, 0.3 * cm))

        alt_table_data = [["Package", "Current", "Recommended Version", "Type", "Complexity"]]
        for alt in alternatives:
            alt_table_data.append([
                Paragraph(html.escape(str(alt.get("package_name", ""))), body_style),
                html.escape(str(alt.get("package_version", ""))),
                html.escape(str(alt.get("recommended_version", "") or alt.get("alternative_version", "") or "N/A")),
                html.escape(str(alt.get("label", alt.get("recommendation_type", "")))),
                html.escape(str(alt.get("migration_complexity", "unknown"))),
            ])

        alt_table = Table(
            alt_table_data,
            colWidths=[4 * cm, 2.5 * cm, 3 * cm, 4.5 * cm, 3 * cm]
        )
        alt_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f3460")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("ROWBACKGROUNDS", (1, 0), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(alt_table)

    # ── Page numbers via canvas ──
    def add_page_number(canvas_obj, doc_obj):
        canvas_obj.saveState()
        canvas_obj.setFont("Helvetica", 8)
        canvas_obj.setFillColor(colors.HexColor("#94a3b8"))
        canvas_obj.drawRightString(
            A4[0] - 2 * cm,
            1.5 * cm,
            f"Page {doc_obj.page} | SecureSBOM Report {report_id}"
        )
        canvas_obj.restoreState()

    doc.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)
    return buf.getvalue()


def _generate_plaintext_report(
    scan_data: Dict[str, Any],
    ai_findings: List[Dict[str, Any]],
    alternatives: List[Dict[str, Any]],
    report_id: str,
) -> bytes:
    """Fallback plain-text report when reportlab is unavailable."""
    lines = [
        "SecureSBOM Security Report",
        f"Report ID: {report_id}",
        f"Generated: {utc_now().isoformat()}",
        "",
        "DISCLAIMER: Section B contains AI-generated assessments. NOT confirmed vulnerabilities.",
        "",
        "=== SECTION A: VERIFIED VULNERABILITY FINDINGS ===",
    ]
    for v in scan_data.get("vulnerabilities", []):
        lines.append(
            f"[{v.get('severity', 'UNKNOWN')}] {v.get('canonical_id', '')} — "
            f"{v.get('affected_component_name', '')}@{v.get('affected_component_version', '')} — "
            f"{(v.get('summary', '') or '')[:100]}"
        )

    lines += ["", "=== SECTION B: AI FINDINGS (UNVERIFIED) ==="]
    for f in ai_findings:
        lines.append(
            f"[{f.get('confidence', '')}] {f.get('finding_id', '')} — "
            f"{f.get('package_name', '')}@{f.get('package_version', '')} — {f.get('title', '')}"
        )

    return "\n".join(lines).encode("utf-8")


# ─────────────────────────────────────────────────────────────
# File persistence helpers
# ─────────────────────────────────────────────────────────────

def save_report_to_disk(content: bytes, report_id: str, fmt: str, output_dir: str) -> str:
    """Save report bytes to disk and return the file path."""
    ext_map = {"pdf": "pdf", "json": "json", "csv": "csv", "txt": "txt"}
    ext = ext_map.get(fmt, "bin")
    filename = f"report_{report_id}.{ext}"
    filepath = os.path.join(output_dir, "reports", filename)
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "wb") as f:
        f.write(content)
    logger.info("Report saved: %s (%d bytes)", filepath, len(content))
    return filepath
