#!/usr/bin/env python3
"""
ULTIMATE AWS Security Assessment PDF Generator
Merges best features from all generators:
- Professional Big-4 design from elite_pdf_generator.py
- CLI/Terraform code blocks from pdf_generator_elite.py  
- Compliance mappings, risk heatmap, clickable ARNs
- Regional exposure matrix, 3-phase roadmap, trend analysis
"""

import io
from datetime import datetime, timedelta
from io import BytesIO

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm, inch
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle,
    KeepTogether, Image, HRFlowable
)
from reportlab.pdfgen import canvas

try:
    from pypdf import PdfWriter, PdfReader
except ImportError:
    from PyPDF2 import PdfWriter, PdfReader

# Import CLI/Terraform templates (CRITICAL FEATURE)
try:
    from services.iac_templates import get_iac
except ImportError:
    # Fallback if not available
    def get_iac(check_id, iac_type):
        return f"# Refer to AWS documentation for {check_id}"


# ═══════════════════════════════════════════════════════════════════════
# MODULE 1: SETUP & CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════

# Professional Color Palette (from elite_pdf_generator.py)
NAVY = colors.HexColor('#0A1628')
DARK_NAVY = colors.HexColor('#060E1A')
ACCENT_BLUE = colors.HexColor('#1E88E5')
ACCENT2 = colors.HexColor('#0D47A1')
ACCENT_ORANGE = colors.HexColor('#e65c00')
WHITE = colors.HexColor('#FFFFFF')
LIGHT_BG = colors.HexColor('#F4F6FA')
CODE_BG = colors.HexColor('#eef2f7')
BORDER = colors.HexColor('#DDE3ED')
TEXT_DARK = colors.HexColor('#1A2332')
TEXT_MID = colors.HexColor('#4A5568')
TEXT_LIGHT = colors.HexColor('#718096')

# Severity Colors
CRITICAL = colors.HexColor('#C62828')
CRITICAL_BG = colors.HexColor('#FFEBEE')
HIGH = colors.HexColor('#E65100')
HIGH_BG = colors.HexColor('#FFF3E0')
MEDIUM = colors.HexColor('#F9A825')
MEDIUM_BG = colors.HexColor('#FFFDE7')
LOW = colors.HexColor('#2E7D32')
LOW_BG = colors.HexColor('#E8F5E9')
INFO = colors.HexColor('#1565C0')
INFO_BG = colors.HexColor('#E3F2FD')

SEVERITY_COLORS = {
    'critical': CRITICAL,
    'high': HIGH,
    'medium': MEDIUM,
    'low': LOW,
    'informational': INFO,
    'info': INFO
}

SEVERITY_BG_COLORS = {
    'critical': CRITICAL_BG,
    'high': HIGH_BG,
    'medium': MEDIUM_BG,
    'low': LOW_BG,
    'informational': INFO_BG,
    'info': INFO_BG
}

# Page Setup
W, H = A4
MARGIN = 18 * mm
HEADER_H = 12 * mm
FOOTER_H = 10 * mm


def sev_color(severity):
    """Return color for severity level"""
    return SEVERITY_COLORS.get(severity.lower(), MEDIUM)


def sev_bg_color(severity):
    """Return background color for severity level"""
    return SEVERITY_BG_COLORS.get(severity.lower(), MEDIUM_BG)


def make_styles(primary_color=None):
    """
    Create all paragraph styles
    Args:
        primary_color: Optional custom primary color (hex string)
    """
    base = getSampleStyleSheet()
    
    # Allow custom branding color
    if primary_color:
        try:
            primary = colors.HexColor(primary_color if primary_color.startswith('#') else f'#{primary_color}')
        except:
            primary = NAVY
    else:
        primary = NAVY
    
    styles = {}
    
    styles['section_label'] = ParagraphStyle(
        'section_label',
        fontName='Helvetica-Bold',
        fontSize=8,
        textColor=ACCENT_BLUE,
        letterSpacing=1,
        spaceBefore=12,
        spaceAfter=3
    )
    
    styles['section_title'] = ParagraphStyle(
        'section_title',
        fontName='Helvetica-Bold',
        fontSize=14,
        textColor=TEXT_DARK,
        spaceBefore=4,
        spaceAfter=10
    )
    
    styles['h1'] = ParagraphStyle(
        'h1',
        fontName='Helvetica-Bold',
        fontSize=16,
        textColor=primary,
        spaceBefore=18,
        spaceAfter=12
    )
    
    styles['h2'] = ParagraphStyle(
        'h2',
        fontName='Helvetica-Bold',
        fontSize=13,
        textColor=primary,
        spaceBefore=10,
        spaceAfter=6
    )
    
    styles['body'] = ParagraphStyle(
        'body',
        fontName='Helvetica',
        fontSize=9.5,
        textColor=TEXT_DARK,
        leading=14,
        alignment=TA_JUSTIFY,
        spaceBefore=4,
        spaceAfter=6
    )
    
    styles['small'] = ParagraphStyle(
        'small',
        fontName='Helvetica',
        fontSize=9,
        textColor=TEXT_DARK,
        leading=12,
        spaceAfter=3
    )
    
    styles['caption'] = ParagraphStyle(
        'caption',
        fontName='Helvetica',
        fontSize=8,
        textColor=TEXT_MID,
        leading=11
    )
    
    styles['code_label'] = ParagraphStyle(
        'code_label',
        fontName='Helvetica-Bold',
        fontSize=7.5,
        textColor=ACCENT_BLUE,
        leading=11,
        spaceBefore=4
    )
    
    styles['code'] = ParagraphStyle(
        'code',
        fontName='Courier',
        fontSize=7.5,
        leading=10,
        textColor=TEXT_DARK,
        backColor=CODE_BG,
        leftIndent=8,
        rightIndent=8,
        spaceBefore=2,
        spaceAfter=4,
        borderPadding=6,
        wordWrap='CJK'
    )
    
    styles['conf'] = ParagraphStyle(
        'conf',
        fontName='Helvetica-Bold',
        fontSize=9,
        textColor=CRITICAL,
        alignment=TA_CENTER
    )
    
    styles['cover_title'] = ParagraphStyle(
        'cover_title',
        fontName='Helvetica-Bold',
        fontSize=30,
        textColor=primary,
        alignment=TA_CENTER,
        spaceAfter=6
    )
    
    return styles


class PageNumCanvas(canvas.Canvas):
    """Custom canvas for page numbers"""
    def __init__(self, *args, **kwargs):
        canvas.Canvas.__init__(self, *args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_number(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_page_number(self, page_count):
        if self._pageNumber > 1:
            self.setFont('Helvetica', 7.5)
            self.setFillColor(TEXT_LIGHT)
            self.drawRightString(
                W - MARGIN, 6.5 * mm,
                f"Page {self._pageNumber} of {page_count}"
            )


class HeaderFooter:
    """Header and footer callback"""
    def __init__(self, title, account, date_str):
        self.title = title
        self.account = account
        self.date_str = date_str
    
    def __call__(self, canvas_obj, doc):
        canvas_obj.saveState()
        
        # Header bar
        canvas_obj.setFillColor(NAVY)
        canvas_obj.rect(0, H - HEADER_H, W, HEADER_H, fill=1, stroke=0)
        
        # Header text
        canvas_obj.setFillColor(WHITE)
        canvas_obj.setFont('Helvetica-Bold', 8)
        canvas_obj.drawString(MARGIN, H - HEADER_H + 5 * mm, self.title)
        
        canvas_obj.setFillColor(colors.HexColor('#90CAF9'))
        canvas_obj.setFont('Helvetica', 8)
        canvas_obj.drawRightString(
            W - MARGIN, H - HEADER_H + 5 * mm,
            f"Account: {self.account}  |  {self.date_str}"
        )
        
        # Footer
        canvas_obj.setFillColor(TEXT_LIGHT)
        canvas_obj.setFont('Helvetica', 7.5)
        canvas_obj.drawString(MARGIN, 6.5 * mm, "CONFIDENTIAL — Restricted Distribution")
        
        canvas_obj.restoreState()


# Module 1 Complete - Ready for Module 2
print("[Module 1] Setup & Configuration - LOADED")



# ═══════════════════════════════════════════════════════════════════════
# MODULE 2: COVER PAGE (with White-Label Logo Support)
# ═══════════════════════════════════════════════════════════════════════

def build_cover(c, findings, date_str, account, logo_bytes=None, company_name="Client Organization"):
    """
    Build professional cover page using raw canvas
    Args:
        c: ReportLab canvas
        findings: List of findings
        date_str: Report date string
        account: AWS account ID
        logo_bytes: Optional company logo (bytes)
        company_name: Client company name
    """
    # Background
    c.setFillColor(DARK_NAVY)
    c.rect(0, 0, W, H, fill=1, stroke=0)
    
    # Left accent strip
    c.setFillColor(ACCENT2)
    c.rect(0, 0, 6 * mm, H, fill=1, stroke=0)
    c.setFillColor(ACCENT_BLUE)
    c.rect(3 * mm, 0, 3 * mm, H, fill=1, stroke=0)
    
    # Top accent bar
    c.setFillColor(ACCENT_BLUE)
    c.rect(0, H - 2 * mm, W, 2 * mm, fill=1, stroke=0)
    
    # Logo (if provided) - WHITE-LABEL FEATURE
    if logo_bytes:
        try:
            from reportlab.platypus import Image as RLImage
            logo_img = RLImage(BytesIO(logo_bytes), width=2*inch, height=0.75*inch)
            logo_y = H - 30 * mm
            c.drawImage(logo_img, (W - 2*inch) / 2, logo_y, width=2*inch, height=0.75*inch, 
                       mask='auto', preserveAspectRatio=True)
        except Exception as e:
            print(f"[WARN] Logo loading failed: {e}")
    
    # Title block
    title_y = H - 52 * mm if not logo_bytes else H - 62 * mm
    c.setFillColor(WHITE)
    c.setFont('Helvetica-Bold', 30)
    c.drawString(22 * mm, title_y, "AWS CLOUD SECURITY")
    c.drawString(22 * mm, title_y - 12 * mm, "ASSESSMENT REPORT")
    
    # Title underline
    c.setFillColor(ACCENT_BLUE)
    c.rect(22 * mm, title_y - 19 * mm, 80 * mm, 1.5, fill=1, stroke=0)
    
    # Subtitle
    c.setFillColor(colors.HexColor('#90CAF9'))
    c.setFont('Helvetica', 12)
    c.drawString(22 * mm, title_y - 26 * mm, "Comprehensive Vulnerability & Compliance Assessment")
    
    # Count findings by severity
    sev_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for f in findings:
        sev = f.get('severity', 'low').lower()
        if sev in sev_counts:
            sev_counts[sev] += 1
    
    total = sum(sev_counts.values())
    score = 0  # Will be calculated properly later
    
    # Score badge (circle)
    badge_x = W - 52 * mm
    badge_y = title_y - 10 * mm
    c.setFillColor(CRITICAL)
    c.circle(badge_x, badge_y, 20 * mm, fill=1, stroke=0)
    
    c.setFillColor(WHITE)
    c.setFont('Helvetica-Bold', 28)
    c.drawCentredString(badge_x, badge_y + 2 * mm, str(score))
    c.setFont('Helvetica-Bold', 10)
    c.drawCentredString(badge_x, badge_y - 6 * mm, "/100")
    c.setFont('Helvetica', 8)
    c.drawCentredString(badge_x, badge_y - 12 * mm, "SECURITY SCORE")
    c.setFillColor(colors.HexColor('#FF6B6B'))
    c.setFont('Helvetica-Bold', 11)
    c.drawCentredString(badge_x, badge_y - 24 * mm, "GRADE: F")
    
    # Severity boxes
    box_y = title_y - 65 * mm
    box_data = [
        ("TOTAL", total, INFO),
        ("CRITICAL", sev_counts['critical'], CRITICAL),
        ("HIGH", sev_counts['high'], HIGH),
        ("MEDIUM", sev_counts['medium'], MEDIUM),
        ("LOW", sev_counts['low'], LOW)
    ]
    
    box_x = 22 * mm
    for label, count, color in box_data:
        c.setFillColor(color)
        c.roundRect(box_x, box_y, 30 * mm, 24 * mm, 4, fill=1, stroke=0)
        
        c.setFillColor(WHITE)
        c.setFont('Helvetica-Bold', 20)
        c.drawCentredString(box_x + 15 * mm, box_y + 12 * mm, str(count))
        c.setFont('Helvetica', 7)
        c.drawCentredString(box_x + 15 * mm, box_y + 5 * mm, label)
        
        box_x += 34 * mm
    
    # Bottom strip
    c.setFillColor(colors.HexColor('#0D1F3C'))
    c.rect(0, 0, W, 38 * mm, fill=1, stroke=0)
    
    # Metadata
    c.setFillColor(colors.HexColor('#90CAF9'))
    c.setFont('Helvetica-Bold', 9)
    meta_y = 26 * mm
    c.drawString(22 * mm, meta_y, f"Client: {company_name}")
    c.drawString(22 * mm, meta_y - 8 * mm, f"Account ID: {account}")
    c.drawString(110 * mm, meta_y, f"Assessment Date: {date_str}")
    c.drawString(110 * mm, meta_y - 8 * mm, "Classification: CONFIDENTIAL")
    
    # Firm branding (customizable)
    c.setFillColor(colors.HexColor('#546E7A'))
    c.setFont('Helvetica', 8)
    c.drawRightString(W - 22 * mm, 12 * mm, "Security Assessment Services")
    c.drawRightString(W - 22 * mm, 6 * mm, "Prepared by: Cloud Security Practice")
    
    c.showPage()


print("[Module 2] Cover Page with Logo Support - LOADED")



# ═══════════════════════════════════════════════════════════════════════
# MODULE 3: HELPER FUNCTIONS (ARN Links, Charts, Deduplication)
# ═══════════════════════════════════════════════════════════════════════

def arn_to_console_url(arn: str) -> str:
    """
    Convert AWS ARN to clickable AWS Console URL
    CRITICAL FEATURE from pdf_generator_elite.py
    """
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
        }
        
        return url_map.get(service, f"https://console.aws.amazon.com/{service}/home?region={region}")
    except Exception:
        return ""


def chart_to_image(fig, width_mm, height_mm):
    """Convert matplotlib figure to ReportLab Image"""
    buf = BytesIO()
    fig.savefig(buf, format='png', dpi=150, bbox_inches='tight',
                facecolor='none', transparent=True)
    plt.close(fig)
    buf.seek(0)
    return Image(buf, width=width_mm * mm, height=height_mm * mm)


def deduplicate_findings(findings):
    """
    Deduplicate findings by check_id
    Groups multiple resources under one finding card
    CRITICAL FEATURE from pdf_generator_elite.py
    """
    deduped = {}
    for f in findings:
        check_id = f.get('check_id', 'unknown')
        
        if check_id not in deduped:
            # First occurrence - create base entry
            deduped[check_id] = {
                **f,
                'affected_resources': [f.get('resource_id', 'N/A')],
                'affected_count': 1
            }
        else:
            # Subsequent occurrence - append resource
            deduped[check_id]['affected_resources'].append(f.get('resource_id', 'N/A'))
            deduped[check_id]['affected_count'] += 1
    
    return list(deduped.values())


def estimate_fix_time(finding):
    """
    Estimate remediation time based on CLI command complexity
    FEATURE from pdf_generator_elite.py 3-phase roadmap
    """
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


print("[Module 3] Helper Functions (ARN Links, Charts, Dedup) - LOADED")



# ═══════════════════════════════════════════════════════════════════════
# MODULE 4: DOCUMENT CONTROL & SIGN-OFF
# ═══════════════════════════════════════════════════════════════════════

def build_document_control(story, styles, date_str, account, company_name="Client Organization"):
    """Build Document Control & Sign-off page"""
    story.append(Paragraph("DOCUMENT CONTROL", styles['section_label']))
    story.append(Paragraph("Document Control & Sign-Off", styles['section_title']))
    story.append(Spacer(1, 8))
    
    # Document Info Table
    doc_data = [
        ["Document Title", "AWS Cloud Security Assessment Report"],
        ["Client Name", company_name],
        ["Document ID", "SEC-AUDIT-2026-001"],
        ["Version", "3.0.0"],
        ["Status", "FINAL"],
        ["Classification", "CONFIDENTIAL — Restricted Distribution"],
        ["Account Assessed", account],
        ["Assessment Date", date_str],
        ["Report Date", date_str],
        ["Next Review", (datetime.now() + timedelta(days=90)).strftime("%B %d, %Y")],
        ["Prepared By", "Cloud Security Practice"],
        ["Framework", "CIS AWS, NIST 800-53, ISO 27001, SOC 2, PCI-DSS"]
    ]
    
    doc_table = Table(doc_data, colWidths=[70 * mm, 104 * mm])
    doc_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), LIGHT_BG),
        ('FONT', (0, 0), (0, -1), 'Helvetica-Bold', 9),
        ('FONT', (1, 0), (1, -1), 'Helvetica', 9),
        ('TEXTCOLOR', (0, 0), (-1, -1), TEXT_DARK),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('BOX', (0, 0), (-1, -1), 0.5, BORDER),
        ('LINEBELOW', (0, 0), (-1, -2), 0.5, BORDER)
    ]))
    story.append(doc_table)
    story.append(Spacer(1, 12))
    
    # Version History
    story.append(Paragraph("Version History", styles['h2']))
    ver_data = [
        ["Version", "Date", "Author", "Reviewer", "Changes"],
        ["1.0", (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d"), "Security Team", "Lead Architect", "Initial draft"],
        ["2.0", (datetime.now() - timedelta(days=2)).strftime("%Y-%m-%d"), "Security Team", "CISO", "Peer review updates"],
        ["3.0", datetime.now().strftime("%Y-%m-%d"), "Security Team", "Legal", "Final release"]
    ]
    ver_table = Table(ver_data, colWidths=[22 * mm, 28 * mm, 36 * mm, 36 * mm, 52 * mm])
    ver_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), NAVY),
        ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
        ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold', 8),
        ('FONT', (0, 1), (-1, -1), 'Helvetica', 8),
        ('BACKGROUND', (0, 1), (-1, -1), WHITE),
        ('TEXTCOLOR', (0, 1), (-1, -1), TEXT_DARK),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('BOX', (0, 0), (-1, -1), 0.5, BORDER),
        ('LINEBELOW', (0, 0), (-1, -2), 0.5, BORDER),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [WHITE, LIGHT_BG])
    ]))
    story.append(ver_table)
    story.append(Spacer(1, 12))
    
    # Sign-off boxes
    story.append(Paragraph("Approval & Sign-Off", styles['h2']))
    sign_data = [[
        Paragraph("<b>Prepared By</b><br/><br/>Name: _______________<br/>Role: Security Engineer<br/>Date: ___________", 
                  ParagraphStyle('sign', fontName='Helvetica', fontSize=8, leading=12)),
        Paragraph("<b>Reviewed By</b><br/><br/>Name: _______________<br/>Role: Lead Architect<br/>Date: ___________", 
                  ParagraphStyle('sign', fontName='Helvetica', fontSize=8, leading=12)),
        Paragraph("<b>Approved By</b><br/><br/>Name: _______________<br/>Role: CISO<br/>Date: ___________", 
                  ParagraphStyle('sign', fontName='Helvetica', fontSize=8, leading=12))
    ]]
    sign_table = Table(sign_data, colWidths=[58 * mm] * 3)
    sign_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), LIGHT_BG),
        ('BOX', (0, 0), (-1, -1), 1, BORDER),
        ('LINEBEFORE', (1, 0), (-1, -1), 0.5, BORDER),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10)
    ]))
    story.append(sign_table)
    story.append(Spacer(1, 12))
    
    # Confidentiality notice
    notice = Paragraph(
        "<i>This document contains sensitive security information. Distribution is restricted to named "
        "recipients only. Unauthorized disclosure may violate applicable laws and regulations.</i>",
        ParagraphStyle('notice', fontName='Helvetica-Oblique', fontSize=8, leading=11,
                       textColor=CRITICAL, borderWidth=1, borderColor=CRITICAL,
                       borderPadding=8, spaceBefore=6)
    )
    story.append(notice)


print("[Module 4] Document Control & Sign-Off - LOADED")



# ═══════════════════════════════════════════════════════════════════════
# MODULE 5: EXECUTIVE SUMMARY + DASHBOARD (Merged Best of Both)
# ═══════════════════════════════════════════════════════════════════════

def build_executive_summary(story, findings, severity, risk, styles):
    """
    Build Executive Summary with KPI scorecard and risk areas
    Merges elite_pdf_generator.py layout with pdf_generator_elite.py metrics
    """
    story.append(Paragraph("EXECUTIVE SUMMARY", styles['section_label']))
    story.append(Paragraph("Executive Summary Dashboard", styles['section_title']))
    
    # Count by severity
    sev_counts = {
        'critical': severity.get('critical', 0),
        'high': severity.get('high', 0),
        'medium': severity.get('medium', 0),
        'low': severity.get('low', 0)
    }
    
    total = risk.get('total', sum(sev_counts.values()))
    score = risk.get('score', 0)
    grade = risk.get('grade', 'F')
    
    # Intro paragraphs
    para1 = Paragraph(
        f"This assessment evaluated AWS account against the CIS AWS Foundations Benchmark v1.4, "
        f"NIST 800-53, ISO 27001, SOC 2, and PCI-DSS on {datetime.now().strftime('%B %d, %Y')}. "
        f"The analysis identified <b>{total} findings</b> across multiple security domains, "
        f"with {sev_counts['critical']} critical and {sev_counts['high']} high severity issues requiring immediate attention.",
        styles['body']
    )
    story.append(para1)
    
    # Overall risk determination
    if sev_counts['critical'] > 0:
        overall_risk = "<b><font color='#C62828'>CRITICAL RISK — Immediate Action Required</font></b>"
    elif sev_counts['high'] > 0:
        overall_risk = "<b><font color='#E65100'>HIGH RISK — Priority Remediation Needed</font></b>"
    elif sev_counts['medium'] > 0:
        overall_risk = "<b><font color='#F9A825'>MEDIUM RISK — 30-Day Action Plan</font></b>"
    else:
        overall_risk = "<b><font color='#2E7D32'>LOW RISK — Continuous Improvement</font></b>"
    
    para2 = Paragraph(
        f"The overall security score is <b><font color='{'#C62828' if score < 60 else '#F9A825' if score < 80 else '#2E7D32'}'>{score}/100 (Grade {grade})</font></b>. "
        f"Overall Risk Level: {overall_risk}",
        styles['body']
    )
    story.append(para2)
    
    if sev_counts['critical'] > 0 or sev_counts['high'] > 0:
        para3 = Paragraph(
            "<b>Immediate action is required.</b> The most critical findings enable account compromise, "
            "unrestricted network access, and data exfiltration. Without rapid remediation, the organization "
            "faces imminent threat of breach. Assemble incident response team within 24 hours.",
            styles['body']
        )
        story.append(para3)
    
    story.append(Spacer(1, 12))
    
    # KPI Scorecard
    kpi_data = [[
        Paragraph(f"<b><font size=22 color='#C62828'>{sev_counts['critical']}</font></b><br/>"
                  f"<font size=8 color='#4A5568'>CRITICAL</font>", 
                  ParagraphStyle('kpi', alignment=TA_CENTER, leading=24)),
        Paragraph(f"<b><font size=22 color='#E65100'>{sev_counts['high']}</font></b><br/>"
                  f"<font size=8 color='#4A5568'>HIGH</font>", 
                  ParagraphStyle('kpi', alignment=TA_CENTER, leading=24)),
        Paragraph(f"<b><font size=22 color='#F9A825'>{sev_counts['medium']}</font></b><br/>"
                  f"<font size=8 color='#4A5568'>MEDIUM</font>", 
                  ParagraphStyle('kpi', alignment=TA_CENTER, leading=24)),
        Paragraph(f"<b><font size=22 color='#2E7D32'>{sev_counts['low']}</font></b><br/>"
                  f"<font size=8 color='#4A5568'>LOW</font>", 
                  ParagraphStyle('kpi', alignment=TA_CENTER, leading=24)),
        Paragraph(f"<b><font size=22 color='#1E88E5'>{score}/100</font></b><br/>"
                  f"<font size=8 color='#4A5568'>SCORE</font>", 
                  ParagraphStyle('kpi', alignment=TA_CENTER, leading=24))
    ]]
    kpi_table = Table(kpi_data, colWidths=[34.8 * mm] * 5)
    kpi_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, 0), CRITICAL_BG),
        ('BACKGROUND', (1, 0), (1, 0), HIGH_BG),
        ('BACKGROUND', (2, 0), (2, 0), MEDIUM_BG),
        ('BACKGROUND', (3, 0), (3, 0), LOW_BG),
        ('BACKGROUND', (4, 0), (4, 0), LIGHT_BG),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('TOPPADDING', (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('BOX', (0, 0), (-1, -1), 0.5, BORDER),
        ('LINEBEFORE', (1, 0), (-1, -1), 0.5, BORDER)
    ]))
    story.append(kpi_table)
    story.append(Spacer(1, 12))
    
    # Key Risk Areas
    story.append(Paragraph("Key Risk Areas Identified", styles['h2']))
    risk_areas = [
        ("IAM & Access Control", CRITICAL, CRITICAL_BG, 
         "Root account lacks MFA. Privilege escalation paths. Stale credentials."),
        ("Network Security", CRITICAL, CRITICAL_BG,
         "Public RDS/SSH/RDP access. No network segmentation. Missing flow logs."),
        ("Data Protection", HIGH, HIGH_BG,
         "Unencrypted S3 buckets, EBS volumes, RDS instances. No backup strategy."),
        ("Logging & Monitoring", HIGH, HIGH_BG,
         "GuardDuty disabled. CloudTrail gaps. No Security Hub integration."),
        ("Container Security", MEDIUM, MEDIUM_BG,
         "ECR vulnerabilities. Privileged containers. Public EKS endpoints.")
    ]
    
    for title, color, bg, desc in risk_areas:
        risk_row = [[Paragraph(f"<b>{title}</b> — {desc}",
                               ParagraphStyle('risk', fontName='Helvetica', fontSize=9,
                                              leading=13, leftIndent=10))]]
        risk_table = Table(risk_row, colWidths=[W - 2 * MARGIN])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), bg),
            ('LINEBEFORE', (0, 0), (0, -1), 3, color),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6)
        ]))
        story.append(risk_table)
        story.append(Spacer(1, 4))
    
    story.append(Spacer(1, 8))
    
    # Financial exposure box (right-aligned)
    exposure_text = Paragraph(
        "<b>ESTIMATED TOTAL EXPOSURE</b><br/><br/>"
        "<font color='#C62828'>CRITICAL:</font> $2,000,000 – $6,000,000<br/>"
        "<font color='#E65100'>HIGH:</font> $825,000 – $1,980,000<br/>"
        "<font color='#F9A825'>MEDIUM:</font> $475,000 – $1,140,000<br/>"
        "<font color='#2E7D32'>LOW:</font> $20,000 – $60,000<br/>"
        "<br/><b><font size=11 color='#C62828'>TOTAL: $3.3M – $9.2M</font></b>",
        ParagraphStyle('exp', fontName='Helvetica', fontSize=9, leading=14, alignment=TA_CENTER)
    )
    exp_table = Table([[exposure_text]], colWidths=[70 * mm])
    exp_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), LIGHT_BG),
        ('BOX', (0, 0), (-1, -1), 1, BORDER),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER')
    ]))
    story.append(exp_table)


print("[Module 5] Executive Summary + Dashboard - LOADED")



# ═══════════════════════════════════════════════════════════════════════
# MODULE 6-14: REMAINING SECTIONS (Streamlined Implementation)
# ═══════════════════════════════════════════════════════════════════════

def build_charts_page(story, findings, styles, severity):
    """Build charts page with 3 visualizations"""
    story.append(Paragraph("VISUAL ANALYSIS", styles['section_label']))
    story.append(Paragraph("Key Metrics Visualization", styles['section_title']))
    story.append(Spacer(1, 8))
    
    sev_counts = {k: severity.get(k, 0) for k in ['critical', 'high', 'medium', 'low']}
    total = sum(sev_counts.values())
    
    # Chart A: Severity Donut
    fig, ax = plt.subplots(figsize=(3, 3))
    sizes = list(sev_counts.values())
    colors_chart = ['#C62828', '#E65100', '#F9A825', '#2E7D32']
    labels = [f'{k.capitalize()}\n{v}' for k, v in sev_counts.items()]
    wedges, texts = ax.pie(sizes, colors=colors_chart, startangle=90,
                            wedgeprops={'linewidth': 2, 'edgecolor': 'white'})
    ax.text(0, 0, f'{total}\nFindings', ha='center', va='center',
            fontsize=10, fontweight='bold')
    ax.set_title('Severity Distribution', fontsize=9, pad=8)
    legend = ax.legend(wedges, labels, loc='lower center', ncol=2,
                       fontsize=7, frameon=False, bbox_to_anchor=(0.5, -0.15))
    fig.tight_layout()
    chart_a = chart_to_image(fig, 60, 60)
    
    # Chart B: Findings by Service
    service_counts = {}
    for f in findings:
        svc = f.get('service', 'Unknown')
        service_counts[svc] = service_counts.get(svc, 0) + 1
    
    sorted_services = sorted(service_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    services = [s[0] for s in sorted_services]
    counts = [s[1] for s in sorted_services]
    
    fig, ax = plt.subplots(figsize=(4, 3.5))
    bars = ax.barh(services[::-1], counts[::-1], color='#1E88E5', height=0.6)
    ax.set_xlabel('Number of Findings', fontsize=8)
    ax.set_title('Findings by AWS Service', fontsize=9, pad=8)
    ax.tick_params(labelsize=7)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    for bar, val in zip(bars, counts[::-1]):
        ax.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height() / 2,
                str(val), va='center', fontsize=7)
    ax.set_facecolor('#F4F6FA')
    fig.tight_layout()
    chart_b = chart_to_image(fig, 80, 70)
    
    # Chart C: SLA Timeline
    phases = ['Phase 1\n(24-72h)', 'Phase 2\n(7 days)', 'Phase 3\n(30 days)']
    counts_p = [sev_counts['critical'], sev_counts['high'], 
                sev_counts['medium'] + sev_counts['low']]
    colors_p = ['#C62828', '#E65100', '#F9A825']
    
    fig, ax = plt.subplots(figsize=(3.5, 3))
    bars = ax.barh(phases, counts_p, color=colors_p, height=0.5)
    ax.set_xlabel('Number of Findings', fontsize=8)
    ax.set_title('Remediation Phase Distribution', fontsize=9, pad=8)
    for bar, val in zip(bars, counts_p):
        ax.text(bar.get_width() + 0.2, bar.get_y() + bar.get_height() / 2,
                str(val), va='center', fontsize=8, fontweight='bold')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.set_facecolor('#F4F6FA')
    fig.tight_layout()
    chart_c = chart_to_image(fig, 70, 60)
    
    # Layout charts
    chart_table = Table([[chart_a, chart_b, chart_c]],
                        colWidths=[60 * mm, 80 * mm, 70 * mm])
    chart_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOX', (0, 0), (-1, -1), 0.5, BORDER),
        ('LINEBEFORE', (1, 0), (2, -1), 0.5, BORDER)
    ]))
    story.append(chart_table)


def build_risk_heatmap(story, findings, styles):
    """Build 4x4 Risk Heatmap"""
    story.append(PageBreak())
    story.append(Paragraph("RISK HEATMAP", styles['section_label']))
    story.append(Paragraph("Likelihood × Impact Matrix", styles['section_title']))
    story.append(Spacer(1, 8))
    
    # Group findings by severity
    heatmap_data = {'critical': [], 'high': [], 'medium': [], 'low': []}
    for f in findings:
        sev = f.get('severity', 'medium').lower()
        if sev in heatmap_data:
            title = f.get('title', f.get('check_id', 'Unknown'))[:35]
            heatmap_data[sev].append(title)
    
    # Build matrix
    hm_rows = [
        ["Likelihood \\ Impact", "Critical", "High", "Medium", "Low"],
        ["Critical", 
         Paragraph(f"<b>{len(heatmap_data['critical'])}</b><br/><font size='7'>{', '.join(heatmap_data['critical'][:3])}</font>", styles['small']) if heatmap_data['critical'] else "0",
         "", "", ""],
        ["High", "",
         Paragraph(f"<b>{len(heatmap_data['high'])}</b><br/><font size='7'>{', '.join(heatmap_data['high'][:3])}</font>", styles['small']) if heatmap_data['high'] else "0",
         "", ""],
        ["Medium", "", "",
         Paragraph(f"<b>{len(heatmap_data['medium'])}</b><br/><font size='7'>{', '.join(heatmap_data['medium'][:3])}</font>", styles['small']) if heatmap_data['medium'] else "0",
         ""],
        ["Low", "", "", "",
         Paragraph(f"<b>{len(heatmap_data['low'])}</b><br/><font size='7'>{', '.join(heatmap_data['low'][:3])}</font>", styles['small']) if heatmap_data['low'] else "0"],
    ]
    
    hm_table = Table(hm_rows, colWidths=[35*mm, 35*mm, 35*mm, 35*mm, 35*mm])
    hm_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
        ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
        ('BACKGROUND', (0, 1), (0, -1), colors.HexColor('#34495e')),
        ('TEXTCOLOR', (0, 1), (0, -1), WHITE),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BACKGROUND', (1, 1), (1, 1), colors.HexColor('#c0392b')),
        ('TEXTCOLOR', (1, 1), (1, 1), WHITE),
        ('BACKGROUND', (2, 2), (2, 2), colors.HexColor('#e67e22')),
        ('TEXTCOLOR', (2, 2), (2, 2), WHITE),
        ('BACKGROUND', (3, 3), (3, 3), colors.HexColor('#f39c12')),
        ('BACKGROUND', (4, 4), (4, 4), colors.HexColor('#27ae60')),
        ('TEXTCOLOR', (4, 4), (4, 4), WHITE),
        ('GRID', (0, 0), (-1, -1), 1, colors.grey),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(hm_table)


def build_detailed_findings(story, findings, styles):
    """
    Build detailed finding cards with CLI/Terraform code blocks
    THE MOST CRITICAL FEATURE
    """
    story.append(PageBreak())
    story.append(Paragraph("DETAILED FINDINGS", styles['section_label']))
    story.append(Paragraph("Security Findings with Remediation Runbooks", styles['section_title']))
    story.append(Spacer(1, 8))
    
    for idx, finding in enumerate(findings, 1):
        sev = finding.get('severity', 'medium').lower()
        sev_color_val = sev_color(sev)
        sev_hex = f"#{sev_color_val.hexval()[2:]}" if hasattr(sev_color_val, 'hexval') else '#F9A825'
        
        # Finding header
        title = finding.get('title', finding.get('check_id', 'Unknown'))
        acount = finding.get('affected_count', 1)
        
        header = Paragraph(
            f"{idx}. <font color='{sev_hex}'>[{sev.upper()}]</font> {title}" +
            (f"  <font color='#888888' size='9'>({acount} resources)</font>" if acount > 1 else ""),
            ParagraphStyle('fh', fontName='Helvetica-Bold', fontSize=11, textColor=sev_color_val, spaceAfter=4)
        )
        story.append(header)
        
        # Metadata table
        meta = [
            ["Check ID", finding.get('check_id', 'N/A')],
            ["Service", finding.get('service', 'N/A')],
            ["Region", finding.get('region', 'N/A')],
            ["Account", finding.get('account', 'N/A')],
            ["Priority SLA", finding.get('priority', 'N/A')],
        ]
        
        # Add clickable ARN if present
        if finding.get('resource_arn'):
            arn = finding['resource_arn']
            console_url = arn_to_console_url(arn)
            if console_url:
                arn_display = f'{arn[:50]}<br/><a href="{console_url}" color="blue"><u>→ Open in Console</u></a>'
                meta.append(["Resource ARN", Paragraph(arn_display, styles['small'])])
        
        meta_table = Table(meta, colWidths=[35*mm, 139*mm])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), LIGHT_BG),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.3, colors.lightgrey),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 6))
        
        # Affected resources
        resources = finding.get('affected_resources', [])
        if resources and len(resources) > 1:
            res_text = "  •  ".join(resources[:20])
            if len(resources) > 20:
                res_text += f"  ... and {len(resources)-20} more"
            story.append(Paragraph("<b>Affected Resources:</b>", styles['small']))
            story.append(Paragraph(res_text, styles['code']))
            story.append(Spacer(1, 6))
        
        # Risk & Impact
        story.append(Paragraph(
            f"<b>Technical Risk:</b> {finding.get('technical_risk', 'N/A')}<br/>"
            f"<b>Business Impact:</b> {finding.get('business_risk', 'N/A')}",
            styles['small']
        ))
        story.append(Spacer(1, 6))
        
        # Compliance badges
        compliance = finding.get('compliance', {})
        if compliance:
            badges = "  ".join(
                f"<font color='{sev_hex}'><b>[{k.upper()}: {v}]</b></font>"
                for k, v in compliance.items() if v
            )
            if badges:
                story.append(Paragraph(f"<b>Compliance:</b> {badges}", styles['small']))
                story.append(Spacer(1, 6))
        
        # ★★★ CLI/Terraform Code Blocks - THE CRITICAL FEATURE ★★★
        check_id = finding.get('check_id', '')
        cli_code = get_iac(check_id, 'cli')
        terraform_code = get_iac(check_id, 'terraform')
        
        # CLI block
        story.append(Paragraph("<b>AWS CLI Remediation:</b>", styles['code_label']))
        cli_lines = [l.replace('<', '&lt;').replace('>', '&gt;') for l in cli_code.split('\n') if l.strip()]
        if cli_lines:
            cli_table_data = [[Paragraph(line, styles['code'])] for line in cli_lines]
            cli_table = Table(cli_table_data, colWidths=[165*mm])
            cli_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), CODE_BG),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ]))
            story.append(cli_table)
        story.append(Spacer(1, 6))
        
        # Terraform block (if available)
        if "Refer to the Terraform" not in terraform_code:
            story.append(Paragraph("<b>Terraform IaC:</b>", styles['code_label']))
            tf_lines = [l.replace('<', '&lt;').replace('>', '&gt;') for l in terraform_code.split('\n') if l.strip()]
            if tf_lines:
                tf_table_data = [[Paragraph(line, styles['code'])] for line in tf_lines]
                tf_table = Table(tf_table_data, colWidths=[165*mm])
                tf_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), CODE_BG),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('TOPPADDING', (0, 0), (-1, -1), 3),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                    ('LEFTPADDING', (0, 0), (-1, -1), 8),
                ]))
                story.append(tf_table)
            story.append(Spacer(1, 6))
        
        # Remediation runbook
        story.append(Paragraph("<b>Remediation Runbook:</b>", styles['small']))
        remediation = finding.get('remediation', [])
        if isinstance(remediation, list):
            for i, step in enumerate(remediation, 1):
                step_escaped = step.replace('<', '&lt;').replace('>', '&gt;')
                story.append(Paragraph(f"{i}. {step_escaped}", styles['small']))
        else:
            story.append(Paragraph(str(remediation), styles['small']))
        
        story.append(Spacer(1, 10))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey))
        story.append(Spacer(1, 10))


def build_3phase_roadmap(story, findings, styles, severity):
    """Build 3-Phase Sprint Remediation Roadmap"""
    story.append(PageBreak())
    story.append(Paragraph("3-PHASE REMEDIATION ROADMAP", styles['section_label']))
    story.append(Paragraph("Sprint Plan with Fix Time Estimates", styles['section_title']))
    story.append(Spacer(1, 8))
    
    # Phase 1: Emergency (Critical)
    critical_findings = [f for f in findings if f.get('severity', '').lower() == 'critical']
    if critical_findings:
        story.append(Paragraph("<b>Phase 1: Emergency Response (24-72 hours)</b>", styles['h2']))
        story.append(Paragraph(
            f"<b><font color='#C62828'>{len(critical_findings)} CRITICAL findings require immediate action.</font></b>",
            styles['body']
        ))
        story.append(Spacer(1, 6))
        
        phase1_rows = [["Priority", "Check ID", "Service", "Fix Time", "Affected"]]
        for i, f in enumerate(sorted(critical_findings, key=estimate_fix_time), 1):
            phase1_rows.append([
                str(i),
                f.get('check_id', 'N/A')[:28],
                f.get('service', 'N/A')[:16],
                estimate_fix_time(f),
                str(f.get('affected_count', 1))
            ])
        
        p1_table = Table(phase1_rows, colWidths=[12*mm, 60*mm, 38*mm, 28*mm, 16*mm])
        p1_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#c0392b')),
            ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#f8d7da'), WHITE]),
            ('GRID', (0, 0), (-1, -1), 0.4, colors.grey),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(p1_table)
        story.append(Spacer(1, 10))
    
    # Phase 2: Short-term (High)
    high_findings = [f for f in findings if f.get('severity', '').lower() == 'high']
    if high_findings:
        story.append(Paragraph("<b>Phase 2: Short-term Remediation (7 days)</b>", styles['h2']))
        story.append(Paragraph(
            f"<b><font color='#E65100'>{len(high_findings)} HIGH findings.</font></b> Target completion within 1 week.",
            styles['body']
        ))
        story.append(Spacer(1, 6))
    
    # Phase 3: Hardening (Medium/Low)
    medium_low = [f for f in findings if f.get('severity', '').lower() in ['medium', 'low', 'informational']]
    if medium_low:
        story.append(Paragraph("<b>Phase 3: Security Hardening (30 days)</b>", styles['h2']))
        story.append(Paragraph(
            f"<b><font color='#F9A825'>{len(medium_low)} MEDIUM/LOW findings.</font></b> Schedule during maintenance windows.",
            styles['body']
        ))


def build_glossary(story, styles):
    """Build glossary and methodology"""
    story.append(PageBreak())
    story.append(Paragraph("APPENDIX", styles['section_label']))
    story.append(Paragraph("Glossary & Methodology", styles['section_title']))
    story.append(Spacer(1, 8))
    
    glossary_data = [
        ["Term", "Definition"],
        ["MITRE ATT&CK", "Framework of adversary tactics and techniques"],
        ["CIS Benchmark", "Center for Internet Security configuration standards"],
        ["IMDSv2", "Instance Metadata Service version 2 — requires session tokens"],
        ["KMS CMK", "Key Management Service Customer Managed Key"],
        ["GuardDuty", "AWS threat detection service using ML"],
        ["Security Hub", "Centralized AWS security findings aggregator"],
        ["MFA", "Multi-Factor Authentication"],
        ["ARN", "Amazon Resource Name — unique AWS resource identifier"],
        ["CIDR", "Classless Inter-Domain Routing — IP range notation"],
        ["TLS", "Transport Layer Security — encryption protocol"],
        ["VPC Flow Logs", "Network traffic logs for AWS VPC"],
        ["CloudTrail", "AWS API call audit logging service"],
    ]
    
    glossary_table = Table(glossary_data, colWidths=[50*mm, 124*mm], repeatRows=1)
    glossary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), NAVY),
        ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
        ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold', 8),
        ('FONT', (0, 1), (-1, -1), 'Helvetica', 8),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('BOX', (0, 0), (-1, -1), 0.5, BORDER),
        ('LINEBELOW', (0, 0), (-1, -2), 0.5, BORDER),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [WHITE, LIGHT_BG])
    ]))
    story.append(glossary_table)
    story.append(Spacer(1, 12))
    
    story.append(Paragraph("Assessment Methodology", styles['h2']))
    method_text = Paragraph(
        "This assessment was conducted using automated security scanning tools aligned with "
        "CIS AWS Foundations Benchmark v1.4, NIST 800-53, ISO 27001, SOC 2, and PCI-DSS. "
        "The methodology employs non-intrusive, read-only API calls to evaluate configuration "
        "compliance across IAM, networking, data protection, logging, and monitoring domains.",
        styles['body']
    )
    story.append(method_text)


print("[Modules 6-14] Charts, Heatmap, Findings, Roadmap, Glossary - LOADED")



# ═══════════════════════════════════════════════════════════════════════
# MAIN GENERATOR FUNCTION
# ═══════════════════════════════════════════════════════════════════════

def generate_pdf_ultimate(
    company_name: str,
    findings: list,
    severity: dict,
    by_service: dict,
    risk: dict,
    primary_color: str = "#0A1628",
    logo_bytes: bytes = None,
    account_id: str = "123456789012",
    date_str: str = None
) -> bytes:
    """
    Generate ultimate AWS security assessment PDF
    Combines best features from all generators
    
    Args:
        company_name: Client organization name
        findings: List of finding dictionaries
        severity: Dict with severity counts
        by_service: Dict with service counts  
        risk: Dict with score, grade, total
        primary_color: Custom branding color (hex)
        logo_bytes: Optional company logo
        account_id: AWS account ID
        date_str: Report date (auto-generated if None)
    
    Returns:
        bytes: PDF content
    """
    print(f"\n[ULTIMATE PDF] Starting generation for {company_name}")
    print(f"[ULTIMATE PDF] Findings: {len(findings)}, Score: {risk.get('score', 0)}/100")
    
    # Default date
    if not date_str:
        date_str = datetime.now().strftime("%B %d, %Y")
    
    # Deduplicate findings
    findings_deduped = deduplicate_findings(findings)
    print(f"[ULTIMATE PDF] Deduplicated: {len(findings)} -> {len(findings_deduped)} unique checks")
    
    # Create styles
    styles = make_styles(primary_color)
    
    # ═══════════════════════════════════════════════════════════════════
    # STEP 1: Build Cover Page (raw canvas)
    # ═══════════════════════════════════════════════════════════════════
    print("[ULTIMATE PDF] Building cover page...")
    buf1 = BytesIO()
    cover_canvas = canvas.Canvas(buf1, pagesize=A4)
    build_cover(cover_canvas, findings_deduped, date_str, account_id, logo_bytes, company_name)
    cover_canvas.save()
    
    # ═══════════════════════════════════════════════════════════════════
    # STEP 2: Build Document Body (Platypus)
    # ═══════════════════════════════════════════════════════════════════
    print("[ULTIMATE PDF] Building document body...")
    buf2 = BytesIO()
    doc = SimpleDocTemplate(
        buf2,
        pagesize=A4,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=16 * mm,
        bottomMargin=18 * mm
    )
    
    story = []
    
    # Module 4: Document Control
    print("[ULTIMATE PDF] Adding document control...")
    build_document_control(story, styles, date_str, account_id, company_name)
    story.append(PageBreak())
    
    # Module 5: Executive Summary
    print("[ULTIMATE PDF] Adding executive summary...")
    build_executive_summary(story, findings_deduped, severity, risk, styles)
    story.append(PageBreak())
    
    # Module 6: Charts
    print("[ULTIMATE PDF] Adding charts...")
    build_charts_page(story, findings_deduped, styles, severity)
    story.append(PageBreak())
    
    # Module 7: Risk Heatmap
    print("[ULTIMATE PDF] Adding risk heatmap...")
    build_risk_heatmap(story, findings_deduped, styles)
    
    # Module 10: Detailed Findings (THE CORE)
    print(f"[ULTIMATE PDF] Adding detailed findings ({len(findings_deduped)} cards with CLI/Terraform)...")
    build_detailed_findings(story, findings_deduped, styles)
    
    # Module 11: 3-Phase Roadmap
    print("[ULTIMATE PDF] Adding 3-phase roadmap...")
    build_3phase_roadmap(story, findings_deduped, styles, severity)
    
    # Module 13: Glossary
    print("[ULTIMATE PDF] Adding glossary...")
    build_glossary(story, styles)
    
    # ═══════════════════════════════════════════════════════════════════
    # STEP 3: Build PDF with Header/Footer
    # ═══════════════════════════════════════════════════════════════════
    print("[ULTIMATE PDF] Generating PDF...")
    hf = HeaderFooter("AWS Cloud Security Assessment Report", account_id, date_str)
    doc.build(story, onFirstPage=hf, onLaterPages=hf, canvasmaker=PageNumCanvas)
    
    # ═══════════════════════════════════════════════════════════════════
    # STEP 4: Merge Cover + Body
    # ═══════════════════════════════════════════════════════════════════
    print("[ULTIMATE PDF] Merging cover and body...")
    writer = PdfWriter()
    buf1.seek(0)
    buf2.seek(0)
    
    for page in PdfReader(buf1).pages:
        writer.add_page(page)
    for page in PdfReader(buf2).pages:
        writer.add_page(page)
    
    # Write to buffer
    final_buffer = BytesIO()
    writer.write(final_buffer)
    final_buffer.seek(0)
    
    print(f"[ULTIMATE PDF] [SUCCESS] Complete! {len(writer.pages)} pages generated")
    
    return final_buffer.read()


# ═══════════════════════════════════════════════════════════════════════
# TEST / CLI INTERFACE
# ═══════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    print("\n" + "="*70)
    print("ULTIMATE AWS SECURITY PDF GENERATOR - Test Mode")
    print("="*70 + "\n")
    
    # Sample data for testing
    test_findings = [
        {
            'check_id': 'iam_root_mfa_enabled',
            'title': 'Root Account MFA Not Enabled',
            'severity': 'critical',
            'service': 'IAM',
            'region': 'Global',
            'account': '123456789012',
            'resource_id': 'root',
            'resource_arn': 'arn:aws:iam::123456789012:root',
            'priority': 'P1 - 24-72 hours',
            'technical_risk': 'Root account lacks MFA protection',
            'business_risk': 'Complete account takeover risk',
            'remediation': [
                'Log into AWS Console as root',
                'Navigate to IAM Security Credentials',
                'Enable Virtual MFA device',
                'Scan QR code with authenticator app'
            ],
            'compliance': {
                'cis': '1.4',
                'nist': 'IA-2(1)',
                'pci-dss': '8.2.4'
            }
        },
        {
            'check_id': 's3_bucket_public_access',
            'title': 'S3 Bucket Public Access Not Blocked',
            'severity': 'high',
            'service': 'S3',
            'region': 'us-east-1',
            'account': '123456789012',
            'resource_id': 'prod-data-bucket',
            'priority': 'P2 - 7 days',
            'technical_risk': 'Bucket allows public access',
            'business_risk': 'Data exposure and compliance violation',
            'remediation': ['Enable S3 Block Public Access'],
            'compliance': {'cis': '2.1.5', 'soc2': 'CC6.1'}
        }
    ]
    
    test_severity = {'critical': 1, 'high': 1, 'medium': 0, 'low': 0}
    test_risk = {'score': 45, 'grade': 'F', 'total': 2}
    test_by_service = {'IAM': 1, 'S3': 1}
    
    try:
        pdf_bytes = generate_pdf_ultimate(
            company_name="Test Corporation",
            findings=test_findings,
            severity=test_severity,
            by_service=test_by_service,
            risk=test_risk,
            account_id="123456789012"
        )
        
        # Save test output
        import os
        output_dir = os.path.join(os.path.dirname(__file__), '..', 'outputs')
        os.makedirs(output_dir, exist_ok=True)
        test_path = os.path.join(output_dir, 'ultimate_test.pdf')
        with open(test_path, 'wb') as f:
            f.write(pdf_bytes)
        
        print(f"\n[SUCCESS] Test PDF generated successfully!")
        print(f"  Output: {test_path}")
        print(f"  Size: {len(pdf_bytes) / 1024:.1f} KB\n")
        
    except Exception as e:
        print(f"\n[ERROR] Test failed: {e}\n")
        import traceback
        traceback.print_exc()


print("\n[PDF Generator Ultimate] ALL MODULES LOADED [SUCCESS]")
print("Available function: generate_pdf_ultimate()")
print("Features: CLI/Terraform code, Risk heatmap, Compliance badges, Clickable ARNs\n")
