"""
Remediation Script Builder
Bundles AWS CLI fix commands for selected findings into .sh / .ps1
"""
from typing import List, Dict
from services.iac_templates import get_iac
from datetime import datetime
import textwrap


def _sanitize_text(text: str, max_len: int = 80) -> str:
    """Sanitize and wrap text for proper shell script formatting."""
    # Remove any problematic characters
    text = text.replace('\r', '').replace('\t', '    ')
    # Escape special shell characters but NOT for bash variables
    text = text.replace('`', '\\`').replace('"', '\\"')
    # Don't escape $ as it's used for bash variables
    return text


def _format_cli_block(cli_code: str, indent: str = "") -> str:
    """Format CLI code with proper indentation and line breaks."""
    lines = []
    for line in cli_code.split('\n'):
        line = line.rstrip()
        if line:
            # Preserve existing indentation and add block indent
            lines.append(f"{indent}{line}")
    return '\n'.join(lines)


def build_script(findings: List[Dict], fmt: str = "sh") -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = []

    if fmt == "sh":
        lines += [
            "#!/usr/bin/env bash",
            "#" + "=" * 78,
            f"#  AWS Security Remediation Script",
            f"#  Generated: {now}",
            "#" + "=" * 78,
            "#",
            "#  IMPORTANT: REVIEW EACH COMMAND BEFORE EXECUTING IN PRODUCTION",
            "#",
            "#  This script contains AWS CLI commands to remediate security findings.",
            "#  Commands use placeholders like <BUCKET_NAME> that must be replaced",
            "#  with actual resource identifiers before execution.",
            "#",
            "#  RECOMMENDATIONS:",
            "#    1. Test all commands in a non-production environment first",
            "#    2. Create backups before making changes",
            "#    3. Execute commands one at a time and verify results",
            "#    4. Review AWS documentation for each service being modified",
            "#",
            "#" + "=" * 78,
            "",
            "set -euo pipefail  # Exit on error, undefined variables, and pipe failures",
            "",
            "# Color codes for output",
            "RED='\\033[0;31m'",
            "GREEN='\\033[0;32m'",
            "YELLOW='\\033[1;33m'",
            "NC='\\033[0m'  # No Color",
            "",
            'echo -e "${GREEN}AWS Security Remediation Script${NC}"',
            f'echo -e "${{YELLOW}}Generated: {now}${{NC}}"',
            'echo ""',
            "",
        ]
        
        for idx, f in enumerate(findings, 1):
            cid   = f.get("check_id", "unknown")
            title = _sanitize_text(f.get("title", cid)[:80])
            sev   = f.get('severity', 'medium').upper()
            snippet = get_iac(cid, "cli")
            
            # Format header with proper alignment
            lines += [
                "#" + "-" * 78,
                f"# Finding {idx}: {title}",
                f"# Severity: {sev}",
                f"# Check ID: {cid}",
                "#" + "-" * 78,
                "",
            ]
            
            # Format CLI commands with proper indentation
            formatted_snippet = _format_cli_block(snippet)
            lines.append(formatted_snippet)
            lines.append("")
            # Use raw string for bash variable references
            lines.append(f'echo -e "${{GREEN}}✓ Completed: {title[:50]}${{NC}}"')
            lines.append("")
        
        lines += [
            "#" + "=" * 78,
            "# Script execution completed",
            "#" + "=" * 78,
            "",
            'echo -e "${GREEN}All remediation commands completed successfully!${NC}"',
            'echo -e "${YELLOW}Remember to verify changes in AWS Console${NC}"',
        ]
        
        return "\n".join(lines)

    else:  # PowerShell
        lines += [
            "#" + "=" * 78,
            f"#  AWS Security Remediation Script (PowerShell)",
            f"#  Generated: {now}",
            "#" + "=" * 78,
            "#",
            "#  IMPORTANT: REVIEW EACH COMMAND BEFORE EXECUTING IN PRODUCTION",
            "#",
            "#  This script contains AWS CLI commands to remediate security findings.",
            "#  Commands use placeholders like <BUCKET_NAME> that must be replaced",
            "#  with actual resource identifiers before execution.",
            "#",
            "#  RECOMMENDATIONS:",
            "#    1. Test all commands in a non-production environment first",
            "#    2. Create backups before making changes",
            "#    3. Execute commands one at a time and verify results",
            "#    4. Review AWS documentation for each service being modified",
            "#",
            "#" + "=" * 78,
            "",
            "$ErrorActionPreference = 'Stop'  # Exit on any error",
            "",
            "Write-Host 'AWS Security Remediation Script' -ForegroundColor Green",
            f"Write-Host 'Generated: {now}' -ForegroundColor Yellow",
            "Write-Host ''",
            "",
        ]
        
        for idx, f in enumerate(findings, 1):
            cid   = f.get("check_id", "unknown")
            title = _sanitize_text(f.get("title", cid)[:80])
            sev   = f.get('severity', 'medium').upper()
            snippet = get_iac(cid, "cli")
            
            # Format header with proper alignment
            lines += [
                "#" + "-" * 78,
                f"# Finding {idx}: {title}",
                f"# Severity: {sev}",
                f"# Check ID: {cid}",
                "#" + "-" * 78,
                "",
            ]
            
            # Convert bash-specific syntax to PowerShell where possible
            ps_snippet = snippet.replace('\\\n', '`')
            formatted_snippet = _format_cli_block(ps_snippet)
            lines.append(formatted_snippet)
            lines.append("")
            lines.append(f"Write-Host '✓ Completed: {title[:50]}' -ForegroundColor Green")
            lines.append("")
        
        lines += [
            "#" + "=" * 78,
            "# Script execution completed",
            "#" + "=" * 78,
            "",
            "Write-Host 'All remediation commands completed successfully!' -ForegroundColor Green",
            "Write-Host 'Remember to verify changes in AWS Console' -ForegroundColor Yellow",
        ]
        
        return "\n".join(lines)
