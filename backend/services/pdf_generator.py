from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, PageBreak, ListFlowable, ListItem
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
import io
from datetime import datetime

DARK_BLUE = colors.HexColor("#1e3a5f")
ACCENT_ORANGE = colors.HexColor("#e65c00")
LIGHT_GRAY = colors.HexColor("#f5f5f5")
MID_GRAY = colors.HexColor("#888888")
RED = colors.HexColor("#d32f2f")
ORANGE = colors.HexColor("#f57c00")
YELLOW = colors.HexColor("#b8860b")
GREEN = colors.HexColor("#388e3c")
BLUE = colors.HexColor("#0288d1")
SEVERITY_COLORS = {"critical": RED, "high": ORANGE, "medium": YELLOW, "low": GREEN, "informational": BLUE}

def generate_pdf(company_name: str, findings: list, severity: dict, by_service: dict, risk: dict) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=0.5*inch, leftMargin=0.5*inch,
                            topMargin=0.75*inch, bottomMargin=0.75*inch)
    styles = getSampleStyleSheet()
    story = []

    # Cover page
    cover_title = ParagraphStyle("CT", parent=styles["Title"], fontSize=28, textColor=DARK_BLUE, spaceAfter=12, alignment=TA_CENTER)
    cover_sub = ParagraphStyle("CS", parent=styles["Normal"], fontSize=14, textColor=MID_GRAY, alignment=TA_CENTER, spaceAfter=6)
    story.append(Spacer(1, 1.5*inch))
    story.append(Paragraph("AWS Security Assessment Report", cover_title))
    story.append(Spacer(1, 0.3*inch))
    story.append(Paragraph(f"<b>Client:</b> {company_name}", cover_sub))
    story.append(Paragraph(f"<b>Assessment Date:</b> {datetime.now().strftime('%d %B %Y')}", cover_sub))
    story.append(Paragraph("<b>Assessment Tool:</b> Prowler AWS Security Assessment", cover_sub))
    story.append(Spacer(1, 0.5*inch))

    score = risk.get("score", 0)
    grade = risk.get("grade", "F")
    score_color = GREEN if score >= 80 else (ORANGE if score >= 60 else RED)
    score_table = Table([[f"{score}/100", f"Grade: {grade}"]], colWidths=[2.5*inch, 2.5*inch])
    score_table.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTSIZE", (0, 0), (0, 0), 36), ("FONTSIZE", (1, 0), (1, 0), 24),
        ("TEXTCOLOR", (0, 0), (0, 0), score_color), ("TEXTCOLOR", (1, 0), (1, 0), DARK_BLUE),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("BACKGROUND", (0, 0), (-1, -1), LIGHT_GRAY),
        ("TOPPADDING", (0, 0), (-1, -1), 20), ("BOTTOMPADDING", (0, 0), (-1, -1), 20),
    ]))
    story.append(score_table)
    story.append(PageBreak())

    # Styles
    h1 = ParagraphStyle("H1", parent=styles["Heading1"], fontSize=16, textColor=DARK_BLUE, spaceAfter=12, spaceBefore=18)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=14, textColor=DARK_BLUE, spaceAfter=8, spaceBefore=12)
    body = ParagraphStyle("Body", parent=styles["Normal"], fontSize=10, leading=14, spaceAfter=6, alignment=TA_JUSTIFY)
    small = ParagraphStyle("Small", parent=styles["Normal"], fontSize=9, leading=12, spaceAfter=4)

    # Executive Summary
    story.append(Paragraph("Executive Summary", h1))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT_ORANGE))
    story.append(Spacer(1, 0.15*inch))
    
    # Determine overall risk level
    critical_count = severity.get('critical', 0)
    high_count = severity.get('high', 0)
    if critical_count > 0:
        overall_risk = "<b><font color='#d32f2f'>CRITICAL</font></b>"
    elif high_count > 0:
        overall_risk = "<b><font color='#f57c00'>HIGH</font></b>"
    elif severity.get('medium', 0) > 0:
        overall_risk = "<b><font color='#b8860b'>MEDIUM</font></b>"
    else:
        overall_risk = "<b><font color='#388e3c'>LOW</font></b>"
    
    # Security Posture Score Table
    story.append(Paragraph("<b>Security Posture Score</b>", body))
    story.append(Spacer(1, 0.1*inch))
    posture_data = [
        ["Severity", "Findings"],
        ["Critical", str(severity.get('critical', 0))],
        ["High", str(severity.get('high', 0))],
        ["Medium", str(severity.get('medium', 0))],
        ["Low", str(severity.get('low', 0))],
    ]
    posture_table = Table(posture_data, colWidths=[3*inch, 2*inch])
    posture_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), DARK_BLUE), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [LIGHT_GRAY, colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(posture_table)
    story.append(Spacer(1, 0.2*inch))
    
    story.append(Paragraph(f"<b>Overall Risk Level:</b> {overall_risk}", body))
    story.append(Spacer(1, 0.15*inch))
    
    # Summary text with key issues
    if critical_count > 0 or high_count > 0:
        key_issue = "The most significant issue is "
        if critical_count > 0:
            # Find first critical finding
            for f in findings:
                if f['severity'] == 'critical':
                    key_issue += f"{f['title'].lower()}."
                    break
        else:
            for f in findings:
                if f['severity'] == 'high':
                    key_issue += f"{f['title'].lower()}."
                    break
        summary_text = f"The AWS environment contains several security weaknesses requiring immediate attention. {key_issue}"
    else:
        summary_text = f"The AWS environment has been assessed with {risk['total']} findings identified. Review and remediation of these items will improve the security posture."
    
    story.append(Paragraph(summary_text, body))
    story.append(PageBreak())

    # Key Findings Section
    story.append(Paragraph("Key Findings", h1))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT_ORANGE))
    story.append(Spacer(1, 0.15*inch))

    # Display top 10 findings (prioritized by severity)
    top_findings = findings[:10] if len(findings) > 10 else findings
    
    for idx, finding in enumerate(top_findings, 1):
        sev = finding.get("severity", "medium")
        sev_color = SEVERITY_COLORS.get(sev, YELLOW)
        
        # Finding title with number
        finding_title = ParagraphStyle("FT", parent=h2, fontSize=12, textColor=sev_color, fontName="Helvetica-Bold")
        story.append(Paragraph(f"Finding {idx}: {finding.get('title', finding.get('check_id', 'Unknown'))}", finding_title))
        story.append(Spacer(1, 0.08*inch))
        
        # Severity and Resource
        story.append(Paragraph(f"<b>Severity:</b> <font color='{sev_color.hexval()}'>{sev.capitalize()}</font>", body))
        story.append(Paragraph(f"<b>Affected Resource:</b> {finding.get('resource_id', 'N/A')}", body))
        story.append(Spacer(1, 0.08*inch))
        
        # Description
        story.append(Paragraph("<b>Description</b>", body))
        tech_risk = finding.get('technical_risk', 'N/A')
        story.append(Paragraph(tech_risk, body))
        story.append(Spacer(1, 0.08*inch))
        
        # Business Impact
        story.append(Paragraph("<b>Business Impact</b>", body))
        business_risk = finding.get('business_risk', 'N/A')
        
        # Parse business impact into bullet points if it contains common risk indicators
        if any(word in business_risk.lower() for word in ['could', 'may', 'risk', 'expose']):
            # Create bullet points from the business risk
            impact_items = []
            
            # Try to extract specific impacts based on check type
            check_id = finding.get('check_id', '')
            if 'root' in check_id and 'mfa' in check_id:
                impact_items = [
                    "Delete infrastructure",
                    "Access sensitive data",
                    "Disable security controls",
                    "Create unauthorized resources"
                ]
            elif 's3' in check_id and 'public' in check_id:
                impact_items = [
                    "Customer data exposure",
                    "Internal documents leak",
                    "Backup data compromise"
                ]
            elif 'ec2' in check_id and 'public' in check_id:
                impact_items = [
                    "Port scanning attacks",
                    "Exploitation attempts",
                    "Unauthorized access"
                ]
            else:
                # Generic impact description
                story.append(Paragraph(business_risk, body))
            
            if impact_items:
                for item in impact_items:
                    story.append(Paragraph(f"• {item}", body))
        else:
            story.append(Paragraph(business_risk, body))
        
        story.append(Spacer(1, 0.08*inch))
        
        # Recommendation
        story.append(Paragraph("<b>Recommendation</b>", body))
        remediation = finding.get('remediation', [])
        if isinstance(remediation, list) and remediation:
            for step in remediation[:3]:  # Show first 3 steps
                story.append(Paragraph(f"• {step}", body))
        else:
            story.append(Paragraph(str(remediation), body))
        
        story.append(Spacer(1, 0.15*inch))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey))
        story.append(Spacer(1, 0.15*inch))
    
    if len(findings) > 10:
        story.append(Paragraph(f"<i>Note: {len(findings) - 10} additional findings are detailed in the complete findings section.</i>", small))
        story.append(Spacer(1, 0.1*inch))
    
    story.append(PageBreak())

    # Prioritized Remediation Plan
    story.append(Paragraph("Prioritized Remediation Plan", h1))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT_ORANGE))
    story.append(Spacer(1, 0.15*inch))
    
    # Create prioritized table
    priority_data = [["Priority", "Action", "Severity"]]
    priority_counter = 1
    
    # Add critical findings first
    for f in findings:
        if f['severity'] == 'critical':
            action = f['title'][:60] + '...' if len(f['title']) > 60 else f['title']
            priority_data.append([str(priority_counter), action, "Critical"])
            priority_counter += 1
            if priority_counter > 10:  # Limit to top 10
                break
    
    # Add high findings
    if priority_counter <= 10:
        for f in findings:
            if f['severity'] == 'high':
                action = f['title'][:60] + '...' if len(f['title']) > 60 else f['title']
                priority_data.append([str(priority_counter), action, "High"])
                priority_counter += 1
                if priority_counter > 10:
                    break
    
    # Add medium findings
    if priority_counter <= 10:
        for f in findings:
            if f['severity'] == 'medium':
                action = f['title'][:60] + '...' if len(f['title']) > 60 else f['title']
                priority_data.append([str(priority_counter), action, "Medium"])
                priority_counter += 1
                if priority_counter > 10:
                    break
    
    priority_table = Table(priority_data, colWidths=[0.8*inch, 4.5*inch, 1.2*inch])
    priority_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), DARK_BLUE), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (0, 0), (0, -1), "CENTER"), ("ALIGN", (2, 0), (2, -1), "CENTER"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [LIGHT_GRAY, colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(priority_table)
    story.append(Spacer(1, 0.2*inch))
    
    # Auditor Conclusion
    story.append(Paragraph("Auditor Conclusion", h1))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT_ORANGE))
    story.append(Spacer(1, 0.15*inch))
    
    # Generate conclusion based on findings
    conclusion = ""
    if severity.get('critical', 0) > 0 or severity.get('high', 0) > 0:
        critical_issues = []
        if severity.get('critical', 0) > 0:
            for f in findings:
                if f['severity'] == 'critical':
                    if 'mfa' in f['check_id'].lower() and 'root' in f['check_id'].lower():
                        critical_issues.append("absence of MFA on the root account")
                        break
            if not critical_issues:
                critical_issues.append(f"{severity.get('critical', 0)} critical security findings")
        
        if severity.get('high', 0) > 0:
            for f in findings:
                if f['severity'] == 'high':
                    if 's3' in f['check_id'].lower() and 'public' in f['check_id'].lower():
                        critical_issues.append("publicly accessible storage resources")
                        break
        
        issues_text = " and ".join(critical_issues) if critical_issues else "identified security gaps"
        conclusion = f"The environment does not currently meet AWS security best practices due to the {issues_text}. Immediate remediation of critical and high-risk findings is recommended."
    else:
        conclusion = f"The AWS environment demonstrates a reasonable security posture with {severity.get('medium', 0)} medium and {severity.get('low', 0)} low severity findings. Continued improvement and adherence to AWS security best practices is recommended."
    
    story.append(Paragraph(conclusion, body))
    story.append(PageBreak())

    # ALL FINDINGS - Detailed Cards
    story.append(Paragraph(f"Security Findings — All {len(findings)} Issues", h1))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT_ORANGE))
    story.append(Spacer(1, 0.15*inch))

    for idx, finding in enumerate(findings, 1):
        sev = finding.get("severity", "medium")
        sev_color = SEVERITY_COLORS.get(sev, YELLOW)
        
        # Finding header
        header_style = ParagraphStyle("FH", parent=styles["Normal"], fontSize=11, textColor=sev_color, 
                                      fontName="Helvetica-Bold", spaceAfter=4)
        story.append(Paragraph(f"{idx}. [{sev.upper()}] {finding.get('title', finding.get('check_id', 'Unknown'))}", header_style))
        
        # Metadata table with enriched fields
        meta_data = [
            ["Check ID", finding.get('check_id', 'N/A')],
            ["Service", finding.get('service', 'N/A')],
            ["Resource", finding.get('resource_id', 'N/A')],
        ]
        
        # Add Resource ARN if present
        if finding.get('resource_arn'):
            meta_data.append(["Resource ARN", finding.get('resource_arn', 'N/A')])
        
        meta_data.extend([
            ["Region", finding.get('region', 'N/A')],
            ["Account", finding.get('account', 'N/A')],
            ["Priority", finding.get('priority', 'N/A')],
        ])
        
        # Add MITRE ATT&CK if present
        if finding.get('mitre_attack'):
            meta_data.append(["MITRE ATT&CK", finding.get('mitre_attack', 'N/A')])
        
        # Add Financial Exposure if present
        if finding.get('financial_exposure'):
            meta_data.append(["Financial Exposure", finding.get('financial_exposure', 'N/A')])
        
        # Add Remediation Effort if present
        if finding.get('remediation_effort'):
            meta_data.append(["Remediation Effort", finding.get('remediation_effort', 'N/A')])
        
        meta_table = Table(meta_data, colWidths=[1.6*inch, 5.4*inch])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), LIGHT_GRAY),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
            ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 0.08*inch))
        
        # Technical Risk
        story.append(Paragraph("<b>Technical Risk:</b>", small))
        story.append(Paragraph(finding.get('technical_risk', 'N/A'), small))
        story.append(Spacer(1, 0.05*inch))
        
        # Business Risk
        story.append(Paragraph("<b>Business Impact:</b>", small))
        story.append(Paragraph(finding.get('business_risk', 'N/A'), small))
        story.append(Spacer(1, 0.05*inch))
        
        # Remediation Steps
        story.append(Paragraph("<b>Remediation Steps:</b>", small))
        remediation = finding.get('remediation', [])
        if isinstance(remediation, list):
            for step_idx, step in enumerate(remediation, 1):
                story.append(Paragraph(f"{step_idx}. {step}", small))
        else:
            story.append(Paragraph(str(remediation), small))
        story.append(Spacer(1, 0.05*inch))
        
        # Compliance Mappings
        compliance = finding.get('compliance', {})
        if compliance:
            story.append(Paragraph("<b>Compliance Mappings:</b>", small))
            # Format: Framework: Control | Framework: Control
            comp_items = []
            for framework, control in compliance.items():
                if control:
                    # Clean up framework name for display
                    display_framework = framework.replace("-", " ").replace("_", " ").upper()
                    comp_items.append(f"{display_framework}: {control}")
            if comp_items:
                # Join with line breaks for better readability
                comp_text = " | ".join(comp_items)
                story.append(Paragraph(comp_text, small))
        
        # Separator
        story.append(Spacer(1, 0.1*inch))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey))
        story.append(Spacer(1, 0.1*inch))
        
        # Page break every 3 findings to avoid overflow
        if idx % 3 == 0 and idx < len(findings):
            story.append(PageBreak())

    doc.build(story)
    buffer.seek(0)
    return buffer.read()
