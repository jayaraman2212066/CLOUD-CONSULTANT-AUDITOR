from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                 TableStyle, HRFlowable, PageBreak, Image)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY, TA_RIGHT
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.piecharts import Pie
import io
from datetime import datetime
from services.iac_templates import get_iac  # CONSULTANT FEATURE: Inject CLI/Terraform code
from services.iac_templates import get_iac  # CONSULTANT FEATURE: Inject CLI/Terraform code

# ── Static palette ──────────────────────────────────────────────────────────
DARK_BLUE   = colors.HexColor("#1e3a5f")   # default primary (overridable)
ACCENT      = colors.HexColor("#e65c00")
LIGHT_GRAY  = colors.HexColor("#f5f5f5")
CODE_BG     = colors.HexColor("#eef2f7")
MID_GRAY    = colors.HexColor("#888888")
RED         = colors.HexColor("#d32f2f")
ORANGE      = colors.HexColor("#f57c00")
YELLOW      = colors.HexColor("#fbc02d")
GREEN       = colors.HexColor("#388e3c")
TEAL        = colors.HexColor("#0288d1")
WHITE       = colors.white

SEV_COLOR = {"critical": RED, "high": ORANGE, "medium": YELLOW,
             "low": GREEN, "informational": TEAL}
SEV_HEX   = {"critical": "#d32f2f", "high": "#f57c00", "medium": "#fbc02d",
             "low": "#388e3c", "informational": "#0288d1"}

# ── Helpers ──────────────────────────────────────────────────────────────────

def _primary(hex_str: str):
    """Return a ReportLab color from a hex string, fallback to DARK_BLUE."""
    try:
        return colors.HexColor(hex_str if hex_str.startswith("#") else f"#{hex_str}")
    except Exception:
        return DARK_BLUE


def _dashboard(severity: dict, risk: dict, primary) -> Drawing:
    drawing = Drawing(500, 300)

    # ── Pie chart ────────────────────────────────────────────────────────────
    pie = Pie()
    pie.x, pie.y, pie.width, pie.height = 30, 60, 190, 190
    pie_data, pie_labels, pie_colors = [], [], []
    for s in ["critical", "high", "medium", "low", "informational"]:
        n = severity.get(s, 0)
        if n:
            pie_data.append(n)
            pie_labels.append(f"{s.capitalize()}: {n}")
            pie_colors.append(SEV_COLOR[s])
    if not pie_data:
        pie_data, pie_labels, pie_colors = [1], ["No Findings"], [GREEN]
    pie.data, pie.labels = pie_data, pie_labels
    pie.slices.strokeWidth, pie.slices.strokeColor = 1, WHITE
    pie.sideLabels, pie.simpleLabels = True, False
    pie.slices.fontSize = 8
    for i, c in enumerate(pie_colors):
        pie.slices[i].fillColor = c
    drawing.add(pie)

    # ── Score card ───────────────────────────────────────────────────────────
    score = risk.get("score", 0)
    grade = risk.get("grade", "F")
    s_col = GREEN if score >= 90 else TEAL if score >= 80 else YELLOW if score >= 70 else ORANGE if score >= 60 else RED
    drawing.add(Rect(280, 155, 205, 120, fillColor=s_col, strokeColor=WHITE, strokeWidth=2))
    drawing.add(String(382, 248, "SECURITY SCORE", fontSize=11, fontName="Helvetica-Bold",
                       textAnchor="middle", fillColor=WHITE))
    drawing.add(String(382, 208, f"{score}/100", fontSize=30, fontName="Helvetica-Bold",
                       textAnchor="middle", fillColor=WHITE))
    drawing.add(String(382, 175, f"Grade: {grade}", fontSize=13, fontName="Helvetica-Bold",
                       textAnchor="middle", fillColor=WHITE))

    # ── Totals ────────────────────────────────────────────────────────────────
    total    = risk.get("total", 0)
    critical = severity.get("critical", 0)
    drawing.add(Rect(280, 88, 97, 55, fillColor=primary, strokeColor=WHITE, strokeWidth=1))
    drawing.add(String(328, 126, "TOTAL", fontSize=8, fontName="Helvetica-Bold",
                       textAnchor="middle", fillColor=WHITE))
    drawing.add(String(328, 100, str(total), fontSize=22, fontName="Helvetica-Bold",
                       textAnchor="middle", fillColor=WHITE))
    drawing.add(Rect(388, 88, 97, 55, fillColor=RED, strokeColor=WHITE, strokeWidth=1))
    drawing.add(String(436, 126, "CRITICAL", fontSize=8, fontName="Helvetica-Bold",
                       textAnchor="middle", fillColor=WHITE))
    drawing.add(String(436, 100, str(critical), fontSize=22, fontName="Helvetica-Bold",
                       textAnchor="middle", fillColor=WHITE))
    return drawing


def _risk_heatmap(findings: list, st) -> Table:
    """Generate 4x4 Risk Heat Map (Likelihood x Impact)"""
    # Group findings by severity into heat map cells
    heatmap_data = {
        "critical": [],  # High Likelihood, Critical Impact
        "high": [],      # High Likelihood, High Impact  
        "medium": [],    # Medium Likelihood, Medium Impact
        "low": []        # Low Likelihood, Low Impact
    }
    
    for f in findings:
        sev = f.get("severity", "medium")
        if sev in heatmap_data:
            title = f.get("title", f.get("check_id", "Unknown"))[:40]
            heatmap_data[sev].append(title)
    
    # Build 4x4 grid: [Likelihood] x [Impact]
    # Row headers: Critical, High, Medium, Low (Likelihood)
    # Col headers: Critical, High, Medium, Low (Impact)
    
    critical_cell = f"{len(heatmap_data['critical'])} findings" if heatmap_data['critical'] else "0"
    high_cell = f"{len(heatmap_data['high'])} findings" if heatmap_data['high'] else "0"
    medium_cell = f"{len(heatmap_data['medium'])} findings" if heatmap_data['medium'] else "0"
    low_cell = f"{len(heatmap_data['low'])} findings" if heatmap_data['low'] else "0"
    
    # Create heat map table
    hm_rows = [
        ["Likelihood \ Impact", "Critical Impact", "High Impact", "Medium Impact", "Low Impact"],
        ["Critical Likelihood", 
         Paragraph(f"<b>{critical_cell}</b><br/><font size='7'>{', '.join(heatmap_data['critical'][:3])}</font>", st["small"]) if heatmap_data['critical'] else "0",
         "", "", ""],
        ["High Likelihood", "",
         Paragraph(f"<b>{high_cell}</b><br/><font size='7'>{', '.join(heatmap_data['high'][:3])}</font>", st["small"]) if heatmap_data['high'] else "0",
         "", ""],
        ["Medium Likelihood", "", "",
         Paragraph(f"<b>{medium_cell}</b><br/><font size='7'>{', '.join(heatmap_data['medium'][:3])}</font>", st["small"]) if heatmap_data['medium'] else "0",
         ""],
        ["Low Likelihood", "", "", "",
         Paragraph(f"<b>{low_cell}</b><br/><font size='7'>{', '.join(heatmap_data['low'][:3])}</font>", st["small"]) if heatmap_data['low'] else "0"],
    ]
    
    hm_table = Table(hm_rows, colWidths=[1.5*inch, 1.25*inch, 1.25*inch, 1.25*inch, 1.25*inch])
    hm_table.setStyle(TableStyle([
        # Header row
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        
        # Header column
        ("BACKGROUND", (0, 1), (0, -1), colors.HexColor("#34495e")),
        ("TEXTCOLOR", (0, 1), (0, -1), WHITE),
        ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
        
        # Critical cell (row 1, col 1)
        ("BACKGROUND", (1, 1), (1, 1), colors.HexColor("#c0392b")),
        ("TEXTCOLOR", (1, 1), (1, 1), WHITE),
        
        # High cell (row 2, col 2)
        ("BACKGROUND", (2, 2), (2, 2), colors.HexColor("#e67e22")),
        ("TEXTCOLOR", (2, 2), (2, 2), WHITE),
        
        # Medium cell (row 3, col 3)
        ("BACKGROUND", (3, 3), (3, 3), colors.HexColor("#f39c12")),
        
        # Low cell (row 4, col 4)
        ("BACKGROUND", (4, 4), (4, 4), colors.HexColor("#27ae60")),
        ("TEXTCOLOR", (4, 4), (4, 4), WHITE),
        
        # Other cells - light gray
        ("BACKGROUND", (1, 2), (1, -1), LIGHT_GRAY),
        ("BACKGROUND", (2, 1), (2, 1), LIGHT_GRAY),
        ("BACKGROUND", (2, 3), (2, -1), LIGHT_GRAY),
        ("BACKGROUND", (3, 1), (3, 2), LIGHT_GRAY),
        ("BACKGROUND", (3, 4), (3, 4), LIGHT_GRAY),
        ("BACKGROUND", (4, 1), (4, 3), LIGHT_GRAY),
        
        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    
    return hm_table


def arn_to_console_url(arn: str) -> str:
    """Convert AWS ARN to clickable AWS Console URL."""
    if not arn or not arn.startswith("arn:aws:"):
        return ""
    
    try:
        parts = arn.split(":")
        service = parts[2]
        region = parts[3] if len(parts) > 3 else "us-east-1"
        account = parts[4] if len(parts) > 4 else ""
        resource = parts[5] if len(parts) > 5 else ""
        
        # Service-specific console URL mappings
        url_map = {
            "s3": f"https://s3.console.aws.amazon.com/s3/buckets/{resource.split('/')[-1]}",
            "iam": f"https://console.aws.amazon.com/iam/home?region={region}#/roles/details/{resource.split('/')[-1]}",
            "ec2": f"https://{region}.console.aws.amazon.com/ec2/v2/home?region={region}#Instances:instanceId={resource.split('/')[-1]}",
            "rds": f"https://{region}.console.aws.amazon.com/rds/home?region={region}#database:id={resource.split(':')[-1]}",
            "lambda": f"https://{region}.console.aws.amazon.com/lambda/home?region={region}#/functions/{resource.split(':')[-1]}",
            "kms": f"https://{region}.console.aws.amazon.com/kms/home?region={region}#/kms/keys/{resource.split('/')[-1]}",
            "eks": f"https://{region}.console.aws.amazon.com/eks/home?region={region}#/clusters/{resource.split('/')[-1]}",
            "ecs": f"https://{region}.console.aws.amazon.com/ecs/home?region={region}#/clusters/{resource.split('/')[-1]}",
            "ecr": f"https://{region}.console.aws.amazon.com/ecr/repositories/{resource.split('/')[-1]}?region={region}",
            "dynamodb": f"https://{region}.console.aws.amazon.com/dynamodb/home?region={region}#tables:selected={resource.split('/')[-1]}",
            "sns": f"https://{region}.console.aws.amazon.com/sns/v3/home?region={region}#/topic/{arn}",
            "sqs": f"https://{region}.console.aws.amazon.com/sqs/v2/home?region={region}#/queues/{resource}",
            "cloudwatch": f"https://{region}.console.aws.amazon.com/cloudwatch/home?region={region}",
            "cloudtrail": f"https://{region}.console.aws.amazon.com/cloudtrail/home?region={region}",
            "elasticloadbalancing": f"https://{region}.console.aws.amazon.com/ec2/v2/home?region={region}#LoadBalancers:",
        }
        
        return url_map.get(service, f"https://console.aws.amazon.com/{service}/home?region={region}")
    except Exception:
        return ""


def _styles(primary):
    """Return all ParagraphStyle objects keyed by name."""
    base = getSampleStyleSheet()
    def ps(name, **kw):
        return ParagraphStyle(name, parent=base["Normal"], **kw)

    return {
        "conf":    ps("conf",   fontSize=9,  textColor=RED,     alignment=TA_CENTER,
                      fontName="Helvetica-Bold"),
        "h1":      ps("h1",     fontSize=18, textColor=primary, fontName="Helvetica-Bold",
                      spaceAfter=10, spaceBefore=16),
        "h2":      ps("h2",     fontSize=13, textColor=primary, fontName="Helvetica-Bold",
                      spaceAfter=6,  spaceBefore=10),
        "body":    ps("body",   fontSize=10, leading=14, spaceAfter=5, alignment=TA_JUSTIFY),
        "small":   ps("small",  fontSize=9,  leading=12, spaceAfter=3),
        "code":    ps("code",   fontSize=7,  leading=10, fontName="Courier",
                      backColor=CODE_BG, borderPadding=4, leftIndent=6, rightIndent=6,
                      wordWrap='CJK', splitLongWords=True),
        "toc":     ps("toc",    fontSize=10, leading=16),
        "cover_t": ps("cover_t",fontSize=30, textColor=primary, fontName="Helvetica-Bold",
                      alignment=TA_CENTER, spaceAfter=6),
        "hdr":     ps("hdr",    fontSize=10, textColor=MID_GRAY, alignment=TA_CENTER),
        "link":    ps("link",   fontSize=8,  textColor=colors.blue, underline=True),
        **{
            f"fh_{s}": ps(f"fh_{s}", fontSize=11, textColor=SEV_COLOR.get(s, YELLOW),
                           fontName="Helvetica-Bold", spaceAfter=4)
            for s in SEV_COLOR
        },
    }


# ── Main generator ────────────────────────────────────────────────────────────

def generate_pdf_elite(company_name: str, findings: list, severity: dict,
                       by_service: dict, risk: dict,
                       primary_color: str = "#1e3a5f",
                       logo_bytes: bytes = None,
                       costs: dict = None,
                       trend: dict = None,
                       exceptions: list = None,
                       theme: str = "corporate") -> bytes:

    # ── Theme overrides ────────────────────────────────────────────────────
    if theme == "dark":
        primary_color = "#0d1b2a"
    elif theme == "highcontrast":
        primary_color = "#000000"
    primary = _primary(primary_color)
    st      = _styles(primary)
    costs     = costs     or {}
    exceptions = exceptions or []
    buffer  = io.BytesIO()
    doc     = SimpleDocTemplate(buffer, pagesize=A4,
                                rightMargin=0.5*inch, leftMargin=0.5*inch,
                                topMargin=0.75*inch,  bottomMargin=0.75*inch)
    story   = []
    _hr     = HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey)
    _hr2    = HRFlowable(width="100%", thickness=2,   color=ACCENT)
    _gap    = Spacer(1, 0.05*inch)

    # ── Reusable table style ─────────────────────────────────────────────────
    META_TS = TableStyle([
        ("BACKGROUND",   (0, 0), (0, -1), LIGHT_GRAY),
        ("FONTNAME",     (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 8),
        ("GRID",         (0, 0), (-1, -1), 0.3, colors.lightgrey),
        ("TOPPADDING",   (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
        ("LEFTPADDING",  (0, 0), (-1, -1), 7),
    ])

    # =========================================================================
    # 1. COVER PAGE  (Rating fix: polished cover the CISO hands to CEO)
    # =========================================================================
    story.append(Paragraph("CONFIDENTIAL — SECURITY AUDIT REPORT", st["hdr"]))
    story.append(_hr2)
    story.append(Spacer(1, 0.05*inch))

    # Logo (white-label: upload your own)
    if logo_bytes:
        try:
            logo_img = Image(io.BytesIO(logo_bytes), width=2*inch, height=0.75*inch)
            logo_img.hAlign = "CENTER"
            story.append(logo_img)
            story.append(Spacer(1, 0.05*inch))
        except Exception:
            pass

    story.append(Paragraph("AWS Cloud Security", st["cover_t"]))
    story.append(Paragraph("Assessment Report",  st["cover_t"]))
    story.append(Spacer(1, 0.05*inch))

    # Score badge inline on cover
    score  = risk.get("score", 0)
    grade  = risk.get("grade", "F")
    s_hex  = ("#388e3c" if score >= 90 else "#0288d1" if score >= 80
              else "#fbc02d" if score >= 70 else "#f57c00" if score >= 60 else "#d32f2f")
    story.append(Paragraph(
        f"<font color='{s_hex}'><b>Security Score: {score}/100 — Grade {grade}</b></font>",
        ParagraphStyle("score_badge", parent=st["body"], alignment=TA_CENTER, fontSize=13)
    ))
    story.append(Spacer(1, 0.05*inch))

    # Client info table (branding uses primary color)
    client_rows = [
        ["CLIENT",        company_name],
        ["DATE",          datetime.now().strftime("%d %B %Y")],
        ["REPORT TYPE",   "Comprehensive AWS Security Audit"],
        ["METHODOLOGY",   "Prowler Security Assessment Framework"],
        ["COMPLIANCE",    "CIS AWS, NIST 800-53, ISO 27001, SOC 2, PCI-DSS"],
    ]
    ct = Table(client_rows, colWidths=[2.2*inch, 4.3*inch])
    ct.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (0, -1), primary),
        ("BACKGROUND",   (1, 0), (1, -1), LIGHT_GRAY),
        ("TEXTCOLOR",    (0, 0), (0, -1), WHITE),
        ("FONTNAME",     (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 10),
        ("GRID",         (0, 0), (-1, -1), 1, WHITE),
        ("TOPPADDING",   (0, 0), (-1, -1), 11),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 11),
        ("LEFTPADDING",  (0, 0), (-1, -1), 12),
    ]))
    story.append(ct)
    story.append(Spacer(1, 0.05*inch))
    story.append(Paragraph(
        "⚠ CONFIDENTIAL — Distribution restricted to authorised personnel only.",
        st["conf"]
    ))
    story.append(PageBreak())

    # =========================================================================
    # 2. TABLE OF CONTENTS  (Rating fix: consultants need a ToC)
    # =========================================================================
    story.append(Paragraph("Table of Contents", st["h1"]))
    story.append(_hr2)
    story.append(Spacer(1, 0.05*inch))

    total_findings = risk.get("total", 0)
    grouped_count  = len(findings)        # findings are already deduplicated groups
    toc_rows = [
        ["1.", "Executive Summary Dashboard",          "Page 3"],
        ["2.", f"Findings Overview  ({total_findings} raw → {grouped_count} grouped checks)", "Page 4"],
        ["3.", "Detailed Findings with Remediation Runbooks", "Page 5+"],
        ["4.", "Compliance Framework Mapping (Appendix)", "Last Page"],
    ]
    toc_t = Table(toc_rows, colWidths=[0.4*inch, 4.8*inch, 1.3*inch])
    toc_t.setStyle(TableStyle([
        ("FONTSIZE",     (0, 0), (-1, -1), 10),
        ("LEADING",      (0, 0), (-1, -1), 18),
        ("TEXTCOLOR",    (0, 0), (0, -1), primary),
        ("FONTNAME",     (0, 0), (0, -1), "Helvetica-Bold"),
        ("ALIGN",        (2, 0), (2, -1), "RIGHT"),
        ("ROWBACKGROUNDS",(0, 0), (-1, -1), [LIGHT_GRAY, WHITE]),
        ("TOPPADDING",   (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 8),
        ("LEFTPADDING",  (0, 0), (-1, -1), 10),
    ]))
    story.append(toc_t)
    story.append(PageBreak())

    # =========================================================================
    # 3. EXECUTIVE SUMMARY DASHBOARD  (Rating fix: 10-second scorecard for CISO)
    # =========================================================================
    story.append(Paragraph("Executive Summary Dashboard", st["h1"]))
    story.append(_hr2)
    story.append(Spacer(1, 0.05*inch))
    story.append(_dashboard(severity, risk, primary))
    story.append(Spacer(1, 0.05*inch))

    # Key metrics table
    critical_n = severity.get("critical", 0)
    high_n     = severity.get("high", 0)
    metrics = [
        ["METRIC", "VALUE", "STATUS"],
        ["Security Posture Score",  f"{score}/100",               grade],
        ["Total Raw Findings",      str(total_findings),          "Review Required"],
        ["Unique Check Groups",     str(grouped_count),           "Deduplicated"],
        ["Critical Vulnerabilities",str(critical_n),
         "Immediate Action" if critical_n else "None"],
        ["High-Risk Issues",        str(high_n),
         "Priority Fix" if high_n else "None"],
        ["Medium Issues",           str(severity.get("medium", 0)), "30-day Fix"],
        ["Low / Informational",     str(severity.get("low", 0) + severity.get("informational", 0)),
         "Best Practice"],
    ]
    mt = Table(metrics, colWidths=[2.8*inch, 1.4*inch, 2.3*inch])
    mt.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0), primary),
        ("TEXTCOLOR",    (0, 0), (-1, 0), WHITE),
        ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 9),
        ("ALIGN",        (0, 0), (-1, -1), "CENTER"),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [LIGHT_GRAY, WHITE]),
        ("GRID",         (0, 0), (-1, -1), 0.4, colors.grey),
        ("TOPPADDING",   (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 8),
    ]))
    story.append(mt)
    story.append(Spacer(1, 0.05*inch))

    # Executive recommendation paragraph
    story.append(Paragraph("Executive Recommendation", st["h2"]))
    if critical_n:
        rec = (f"<b><font color='#d32f2f'>CRITICAL ACTION REQUIRED:</font></b> "
               f"{critical_n} critical vulnerabilit{'ies' if critical_n!=1 else 'y'} require "
               f"immediate response. Assemble your incident response team, apply emergency "
               f"controls within 24 hours, and re-scan within 48 hours to confirm remediation.")
    elif high_n:
        rec = (f"<b><font color='#f57c00'>HIGH PRIORITY:</font></b> "
               f"{high_n} high-risk issue{'s' if high_n!=1 else ''} significantly increase "
               f"your attack surface. Target full remediation within 7 days and implement "
               f"compensating controls immediately.")
    elif score >= 80:
        rec = (f"<b><font color='#388e3c'>STRONG POSTURE:</font></b> Score {score}/100 "
               f"indicates a well-managed environment. Address remaining medium findings "
               f"within 30 days and maintain quarterly reviews.")
    else:
        rec = (f"<b><font color='#fbc02d'>IMPROVEMENT NEEDED:</font></b> Score {score}/100. "
               f"Remediate all high/medium findings within 30 days and enable automated "
               f"controls (GuardDuty, Security Hub, AWS Config).")
    story.append(Paragraph(rec, st["body"]))
    story.append(PageBreak())

    # =========================================================================
    # 3A. RISK HEAT MAP (CONSULTANT FEATURE - Visual Centerpiece)
    # =========================================================================
    story.append(Paragraph("Risk Heat Map — Likelihood vs Impact Matrix", st["h1"]))
    story.append(_hr2)
    story.append(Spacer(1, 0.05*inch))
    story.append(Paragraph(
        "<b>This heat map visualizes security risks by plotting likelihood against business impact.</b> "
        "Critical findings (top-left red cell) require immediate response. High findings (orange) need "
        "remediation within 7 days. Medium and low findings are plotted on the diagonal.",
        st["body"]
    ))
    story.append(Spacer(1, 0.05*inch))
    story.append(_risk_heatmap(findings, st))
    story.append(Spacer(1, 0.05*inch))
    story.append(Paragraph(
        "<b>How to read this map:</b> Cells closer to top-left corner represent higher risk. "
        "The number in each cell shows finding count. Top 3 finding titles are listed below the count. "
        "Empty (gray) cells indicate no findings in that risk category.",
        st["small"]
    ))
    story.append(PageBreak())

    # =========================================================================
    # 4. FINDINGS OVERVIEW TABLE  (Rating fix: one-page summary before deep dive)
    # =========================================================================
    story.append(Paragraph(
        f"Findings Overview — {grouped_count} Unique Checks  "
        f"({total_findings} total affected resources)",
        st["h1"]
    ))
    story.append(_hr2)
    story.append(Spacer(1, 0.05*inch))
    story.append(Paragraph(
        "Findings are <b>grouped by check type</b>. Each row represents one unique "
        "vulnerability class. Affected resource counts appear in the last column.",
        st["small"]
    ))
    story.append(Spacer(1, 0.05*inch))

    ov_rows = [["#", "Check ID", "Service", "Severity", "SLA", "Affected"]]
    for i, f in enumerate(findings, 1):
        sev_h = SEV_HEX.get(f["severity"], "#fbc02d")
        ov_rows.append([
            str(i),
            f.get("check_id", "N/A")[:38],
            f.get("service",  "N/A")[:20],
            Paragraph(f"<font color='{sev_h}'><b>{f['severity'].upper()}</b></font>",
                      st["small"]),
            f.get("priority", "N/A").split("—")[0].strip()[:22],
            str(f.get("affected_count", 1)),
        ])
    ov_t = Table(ov_rows, colWidths=[0.3*inch, 2.1*inch, 1.4*inch,
                                      0.75*inch, 1.6*inch, 0.55*inch])
    ov_ts = TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), primary),
        ("TEXTCOLOR",     (0, 0), (-1, 0), WHITE),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 7),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [LIGHT_GRAY, WHITE]),
        ("GRID",          (0, 0), (-1, -1), 0.3, colors.lightgrey),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ])
    ov_t.setStyle(ov_ts)
    story.append(ov_t)
    story.append(PageBreak())

    # ═════════════════════════════════════════════════════════════════
    # 4A. REGION EXPOSURE MATRIX (CONSULTANT FEATURE)
    # ═════════════════════════════════════════════════════════════════
    story.append(Paragraph("Regional Exposure Matrix", st["h1"]))
    story.append(_hr2)
    story.append(Spacer(1, 0.05*inch))
    
    # Build region x severity matrix
    region_matrix = {}
    for f in findings:
        region = f.get("region", "Global")
        sev = f.get("severity", "medium")
        if region not in region_matrix:
            region_matrix[region] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
        region_matrix[region][sev] = region_matrix[region].get(sev, 0) + 1
        region_matrix[region]["total"] += 1
    
    if region_matrix:
        story.append(Paragraph(
            f"<b>{len(region_matrix)} AWS regions affected.</b> This matrix shows "
            "security gaps by region, helping prioritize regional remediation efforts.",
            st["body"]
        ))
        story.append(Spacer(1, 0.05*inch))
        
        region_rows = [["Region", "Critical", "High", "Medium", "Low", "Total"]]
        for region, counts in sorted(region_matrix.items(), key=lambda x: -x[1]["total"]):
            region_rows.append([
                region,
                str(counts.get("critical", 0)),
                str(counts.get("high", 0)),
                str(counts.get("medium", 0)),
                str(counts.get("low", 0)),
                str(counts["total"])
            ])
        
        region_t = Table(region_rows, colWidths=[2*inch, 0.9*inch, 0.9*inch, 0.9*inch, 0.9*inch, 0.9*inch])
        region_t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), primary),
            ("TEXTCOLOR",     (0, 0), (-1, 0), WHITE),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 9),
            ("ALIGN",         (1, 0), (-1, -1), "CENTER"),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [LIGHT_GRAY, WHITE]),
            ("GRID",          (0, 0), (-1, -1), 0.4, colors.grey),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(region_t)
    story.append(PageBreak())

    # =========================================================================
    # 5. DETAILED FINDINGS — GROUPED + REMEDIATION RUNBOOKS
    #    Rating fixes:
    #      • Dedup: 200 S3 findings → 1 card with 200 resources listed
    #      • Code blocks: shaded runbook for CLI fix commands
    #      • Compliance badges: [CIS 2.1.5] [SOC2 CC6.1] inline
    # =========================================================================
    story.append(Paragraph(
        f"Detailed Security Findings & Remediation Runbooks",
        st["h1"]
    ))
    story.append(_hr2)
    story.append(Spacer(1, 0.05*inch))

    for idx, finding in enumerate(findings, 1):
        sev     = finding.get("severity", "medium")
        sev_hex = SEV_HEX.get(sev, "#fbc02d")
        acount  = finding.get("affected_count", 1)
        title   = finding.get("title", finding.get("check_id", "Unknown"))

        # ── Finding header ───────────────────────────────────────────────────
        fh_style = st.get(f"fh_{sev}", st["fh_medium"])
        story.append(Paragraph(
            f"{idx}. <font color='{sev_hex}'>[{sev.upper()}]</font>  {title}"
            + (f"  <font color='#888888' size='9'>({acount} resource{'s' if acount!=1 else ''})</font>"
               if acount > 1 else ""),
            fh_style
        ))

        # ── Metadata row ─────────────────────────────────────────────────────
        meta = [
            ["Check ID",    finding.get("check_id", "N/A")],
            ["Service",     finding.get("service",  "N/A")],
            ["Region",      finding.get("region",   "N/A")],
            ["Account",     finding.get("account",  "N/A")],
            ["Priority SLA",finding.get("priority", "N/A")],
        ]
        
        # CONSULTANT FEATURE #3: Clickable ARN with console link
        if finding.get("resource_arn"):
            arn = finding["resource_arn"]
            console_url = arn_to_console_url(arn)
            if console_url:
                arn_display = f'{arn[:55]}<br/><a href="{console_url}" color="blue"><u>→ Open in AWS Console</u></a>'
                meta.append(["Resource ARN", Paragraph(arn_display, st["small"])])
            else:
                meta.append(["Resource ARN", arn[:60]])
        
        if finding.get("mitre_attack"):
            meta.append(["MITRE ATT&CK", finding["mitre_attack"]])
        if finding.get("financial_exposure"):
            meta.append(["Est. Exposure", finding["financial_exposure"]])

        mt2 = Table(meta, colWidths=[1.5*inch, 5.5*inch])
        mt2.setStyle(META_TS)
        story.append(mt2)
        story.append(_gap)

        # ── Affected resources (dedup block) ─────────────────────────────────
        resources = finding.get("affected_resources", [])
        if resources:
            res_lines = "  •  ".join(resources[:30])
            if len(resources) > 30:
                res_lines += f"  … and {len(resources)-30} more"
            story.append(Paragraph("<b>Affected Resources:</b>", st["small"]))
            story.append(Paragraph(res_lines, st["code"]))
            story.append(_gap)

        # ── Risk & Impact ────────────────────────────────────────────────────
        story.append(Paragraph(
            f"<b>Technical Risk:</b> {finding.get('technical_risk','N/A')}<br/>"
            f"<b>Business Impact:</b> {finding.get('business_risk','N/A')}",
            st["small"]
        ))
        story.append(_gap)

        # ── Compliance badges  [CIS 2.1.5] [SOC2 CC6.1] ─────────────────────
        compliance = finding.get("compliance", {})
        if compliance:
            badges = "  ".join(
                f"<font color='{sev_hex}'><b>[{k.replace('_',' ').upper()}: {v}]</b></font>"
                for k, v in compliance.items() if v
            )
            if badges:
                story.append(Paragraph(f"<b>Compliance:</b>  {badges}", st["small"]))
                story.append(_gap)

        # ── CLI/Terraform Code Blocks (CONSULTANT FEATURE #1: CLI for ALL findings) ───────────
        check_id = finding.get("check_id", "")
        cli_code = get_iac(check_id, "cli")
        terraform_code = get_iac(check_id, "terraform")
        
        # ALWAYS show CLI block for every finding - Use Table for better text alignment
        story.append(Paragraph("<b>AWS CLI Remediation:</b>", st["small"]))
        cli_lines = [l for l in cli_code.split('\n') if l.strip()]
        if cli_lines:
            # Create table with fixed width cells to prevent text overflow
            cli_table_data = [[Paragraph(line.replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;').replace('"', '&quot;'), st["code"])] for line in cli_lines]
            cli_table = Table(cli_table_data, colWidths=[6.5*inch])
            cli_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), CODE_BG),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ]))
            story.append(cli_table)
        story.append(_gap)
        
        # Show Terraform if available - Use Table for better text alignment
        if "Refer to the Terraform" not in terraform_code:
            story.append(Paragraph("<b>Terraform IaC:</b>", st["small"]))
            tf_lines = [l for l in terraform_code.split('\n') if l.strip()]
            if tf_lines:
                # Create table with fixed width cells to prevent text overflow
                tf_table_data = [[Paragraph(line.replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;').replace('"', '&quot;'), st["code"])] for line in tf_lines]
                tf_table = Table(tf_table_data, colWidths=[6.5*inch])
                tf_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), CODE_BG),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ]))
                story.append(tf_table)
            story.append(_gap)

        # ── Remediation Runbook (properly formatted) ───────────────────────────
        story.append(Paragraph("<b>Remediation Runbook:</b>", st["small"]))
        remediation = finding.get("remediation", [])
        if isinstance(remediation, list):
            for i, step in enumerate(remediation, 1):
                # Escape HTML entities to prevent rendering issues
                step_escaped = step.replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;').replace('"', '&quot;')
                # If step looks like a CLI command, render in code style
                is_cmd = any(step.lstrip().startswith(p)
                             for p in ("aws ", "terraform", "kubectl", "#", "export", "echo"))
                if is_cmd:
                    # Use table for code commands to ensure proper alignment
                    cmd_table_data = [[Paragraph(f"{i}. {step_escaped}", st["code"])]]
                    cmd_table = Table(cmd_table_data, colWidths=[6.5*inch])
                    cmd_table.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (-1, -1), CODE_BG),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("TOPPADDING", (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                        ("LEFTPADDING", (0, 0), (-1, -1), 8),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ]))
                    story.append(cmd_table)
                else:
                    story.append(Paragraph(f"{i}. {step_escaped}", st["small"]))
        else:
            step_escaped = str(remediation).replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;').replace('"', '&quot;')
            story.append(Paragraph(step_escaped, st["small"]))

        story.append(Spacer(1, 0.05*inch))
        story.append(_hr)
        story.append(Spacer(1, 0.05*inch))

    # =========================================================================
    # 6. 3-PHASE SPRINT ROADMAP (CONSULTANT FEATURE #5)
    # =========================================================================
    story.append(PageBreak())
    story.append(Paragraph("3-Phase Remediation Roadmap", st["h1"]))
    story.append(_hr2)
    story.append(Spacer(1, 0.05*inch))
    story.append(Paragraph(
        "<b>This sprint plan prioritizes findings by severity and estimated fix time.</b> "
        "Critical findings go to Phase 1 Emergency (24-72hrs). High findings go to Phase 2 Short-term (7 days). "
        "Medium and Low findings go to Phase 3 Hardening (30 days).",
        st["body"]
    ))
    story.append(Spacer(1, 0.05*inch))

    # Helper function to estimate fix time from CLI command length
    def estimate_fix_time(finding):
        cli = get_iac(finding.get("check_id", ""), "cli")
        cmd_lines = [l for l in cli.split('\n') if l.strip() and not l.strip().startswith('#')]
        if len(cmd_lines) <= 1:
            return "5-10 min"
        elif len(cmd_lines) <= 3:
            return "15-30 min"
        elif len(cmd_lines) <= 6:
            return "1-2 hrs"
        else:
            return "2-4 hrs"

    # PHASE 1: Emergency (Critical findings - 24-72 hrs)
    critical_findings = [f for f in findings if f.get("severity") == "critical"]
    if critical_findings:
        story.append(Paragraph("<b>Phase 1: Emergency Response (24-72 hours)</b>", st["h2"]))
        story.append(Paragraph(
            f"<b><font color='#d32f2f'>{len(critical_findings)} CRITICAL findings require immediate action.</font></b> "
            "Assemble incident response team. Apply emergency controls within 24 hours.",
            st["body"]
        ))
        story.append(Spacer(1, 0.05*inch))
        
        phase1_rows = [["Priority", "Check ID", "Service", "Est. Fix Time", "Affected"]]
        for i, f in enumerate(sorted(critical_findings, key=lambda x: estimate_fix_time(x)), 1):
            phase1_rows.append([
                str(i),
                f.get("check_id", "N/A")[:32],
                f.get("service", "N/A")[:18],
                estimate_fix_time(f),
                str(f.get("affected_count", 1))
            ])
        
        p1_table = Table(phase1_rows, colWidths=[0.5*inch, 2.5*inch, 1.5*inch, 1.2*inch, 0.8*inch])
        p1_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#c0392b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8d7da"), WHITE]),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(p1_table)
        story.append(Spacer(1, 0.05*inch))

    # PHASE 2: Short-term (High findings - 7 days, grouped by service)
    high_findings = [f for f in findings if f.get("severity") == "high"]
    if high_findings:
        story.append(Paragraph("<b>Phase 2: Short-term Remediation (7 days)</b>", st["h2"]))
        story.append(Paragraph(
            f"<b><font color='#e67e22'>{len(high_findings)} HIGH findings grouped by AWS service.</font></b> "
            "Target completion within 1 week. Apply fixes in batches by service.",
            st["body"]
        ))
        story.append(Spacer(1, 0.05*inch))
        
        # Group by service
        by_svc = {}
        for f in high_findings:
            svc = f.get("service", "AWS")
            if svc not in by_svc:
                by_svc[svc] = []
            by_svc[svc].append(f)
        
        phase2_rows = [["Service", "Check Count", "Example Checks", "Avg Fix Time"]]
        for svc, svc_findings in sorted(by_svc.items(), key=lambda x: -len(x[1])):
            example_checks = ", ".join([f.get("check_id", "")[:25] for f in svc_findings[:2]])
            avg_time = "15-45 min" if len(svc_findings) <= 3 else "1-3 hrs"
            phase2_rows.append([
                svc[:22],
                str(len(svc_findings)),
                example_checks[:40] + ("..." if len(example_checks) > 40 else ""),
                avg_time
            ])
        
        p2_table = Table(phase2_rows, colWidths=[1.8*inch, 1*inch, 2.9*inch, 1*inch])
        p2_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e67e22")),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#ffe5cc"), WHITE]),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(p2_table)
        story.append(Spacer(1, 0.05*inch))

    # PHASE 3: Hardening (Medium + Low - 30 days)
    medium_low_findings = [f for f in findings if f.get("severity") in ["medium", "low", "informational"]]
    if medium_low_findings:
        story.append(Paragraph("<b>Phase 3: Security Hardening (30 days)</b>", st["h2"]))
        story.append(Paragraph(
            f"<b><font color='#f39c12'>{len(medium_low_findings)} MEDIUM/LOW findings for long-term hardening.</font></b> "
            "Schedule fixes during maintenance windows. Focus on security best practices.",
            st["body"]
        ))
        story.append(Spacer(1, 0.05*inch))
        
        phase3_rows = [["Severity", "Count", "Top Checks", "Timeline"]]
        
        # Group by severity
        med_count = len([f for f in medium_low_findings if f.get("severity") == "medium"])
        low_count = len([f for f in medium_low_findings if f.get("severity") in ["low", "informational"]])
        
        if med_count:
            med_checks = [f.get("check_id", "")[:28] for f in medium_low_findings if f.get("severity") == "medium"][:3]
            phase3_rows.append(["Medium", str(med_count), ", ".join(med_checks)[:45], "Week 2-3"])
        
        if low_count:
            low_checks = [f.get("check_id", "")[:28] for f in medium_low_findings if f.get("severity") in ["low", "informational"]][:3]
            phase3_rows.append(["Low/Info", str(low_count), ", ".join(low_checks)[:45], "Week 3-4"])
        
        p3_table = Table(phase3_rows, colWidths=[1.2*inch, 0.8*inch, 3.5*inch, 1.2*inch])
        p3_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f39c12")),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#fff3cd"), WHITE]),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(p3_table)

    story.append(Spacer(1, 0.05*inch))
    story.append(Paragraph(
        "<b>Sprint Planning Notes:</b> Fix times are estimates based on CLI command complexity. "
        "Actual times vary by team size and AWS environment complexity. Critical findings may require "
        "emergency change approvals. Test all changes in non-production first.",
        st["small"]
    ))

    # =========================================================================
    # 7. TREND ANALYSIS  (Historical comparison)
    # =========================================================================
    if trend:
        story.append(PageBreak())
        story.append(Paragraph("Security Trend Analysis", st["h1"]))
        story.append(_hr2)
        story.append(Spacer(1, 0.05*inch))

        delta     = trend["delta"]
        d_col     = "#388e3c" if delta >= 0 else "#d32f2f"
        d_arrow   = "▲" if delta > 0 else ("▼" if delta < 0 else "→")
        d_label   = "improvement" if delta >= 0 else "regression"
        prev_crit = trend["prev_critical"]
        curr_crit = trend["curr_critical"]
        crit_diff = curr_crit - prev_crit
        crit_col  = "#388e3c" if crit_diff <= 0 else "#d32f2f"

        story.append(Paragraph(
            f"Compared to last scan on <b>{trend['prev_date']}</b>:",
            st["body"]
        ))
        story.append(Paragraph(
            f"Score: <b>{trend['prev_score']}/100</b> → <b>{risk.get('score',0)}/100</b>  "
            f"<font color='{d_col}'><b>{d_arrow} {abs(delta)} point {d_label}</b></font>",
            st["body"]
        ))
        story.append(Paragraph(
            f"Critical findings: <b>{prev_crit}</b> → "
            f"<font color='{crit_col}'><b>{curr_crit}</b></font>"
            + (" (reduced ✓)" if crit_diff < 0 else " (increased ✗)" if crit_diff > 0 else " (unchanged)"),
            st["body"]
        ))

    # =========================================================================
    # 8. APPROVED EXCEPTIONS APPENDIX
    # =========================================================================
    if exceptions:
        story.append(PageBreak())
        story.append(Paragraph("Appendix B: Approved Exceptions & False Positives", st["h1"]))
        story.append(_hr2)
        story.append(Spacer(1, 0.05*inch))
        story.append(Paragraph(
            "The following findings were reviewed and intentionally excluded from the "
            "main report by the security team as approved exceptions or false positives.",
            st["body"]
        ))
        story.append(Spacer(1, 0.05*inch))
        exc_rows = [["Check ID", "Title", "Severity", "Service"]]
        for e in exceptions:
            exc_rows.append([e.get("check_id",""), e.get("title",""),
                              e.get("severity","").upper(), e.get("service","")])
        exc_t = Table(exc_rows, colWidths=[2*inch, 2.8*inch, 1*inch, 1.5*inch])
        exc_t.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), MID_GRAY),
            ("TEXTCOLOR",     (0,0), (-1,0), WHITE),
            ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,-1), 8),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [LIGHT_GRAY, WHITE]),
            ("GRID",          (0,0), (-1,-1), 0.3, colors.lightgrey),
            ("TOPPADDING",    (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("LEFTPADDING",   (0,0), (-1,-1), 7),
        ]))
        story.append(exc_t)

    # =========================================================================
    # 9. APPENDIX — Compliance Matrix
    # =========================================================================
    story.append(PageBreak())
    story.append(Paragraph("Appendix A: Compliance Framework Mapping", st["h1"]))
    story.append(_hr2)
    story.append(Spacer(1, 0.05*inch))
    story.append(Paragraph(
        "This report maps findings to CIS AWS Foundations Benchmark, NIST 800-53, "
        "ISO 27001:2022, SOC 2 Type II, and PCI-DSS v4.0 controls. "
        "Each finding card above lists the specific control identifiers inline.",
        st["body"]
    ))

    # Aggregate unique compliance references across all findings
    seen = {}
    for f in findings:
        for framework, control in (f.get("compliance") or {}).items():
            if control:
                seen.setdefault(framework, set()).add(str(control))

    if seen:
        story.append(Spacer(1, 0.05*inch))
        comp_rows = [["Framework", "Controls Referenced", "Findings Affected"]]
        for fw, ctrls in sorted(seen.items()):
            affected = sum(1 for f in findings
                           if fw in (f.get("compliance") or {}))
            comp_rows.append([fw.replace("_", " ").upper(),
                              ", ".join(sorted(ctrls)[:8]),
                              str(affected)])
        comp_t = Table(comp_rows, colWidths=[2*inch, 3.5*inch, 1*inch])
        comp_t.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, 0), primary),
            ("TEXTCOLOR",    (0, 0), (-1, 0), WHITE),
            ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",     (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [LIGHT_GRAY, WHITE]),
            ("GRID",         (0, 0), (-1, -1), 0.4, colors.lightgrey),
            ("TOPPADDING",   (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 6),
            ("LEFTPADDING",  (0, 0), (-1, -1), 8),
        ]))
        story.append(comp_t)

    try:
        doc.build(story)
    except Exception as e:
        # If layout fails, try with less complex content
        story_fixed = []
        finding_count = 0
        for item in story:
            if 'Spacer' not in str(type(item)):
                story_fixed.append(item)
                if 'finding' in str(item).lower():
                    finding_count += 1
                    if finding_count % 3 == 0:
                        story_fixed.append(PageBreak())
        doc.build(story_fixed)
    
    buffer.seek(0)
    return buffer.read()
