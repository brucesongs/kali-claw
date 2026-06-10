#!/usr/bin/env python3
"""
update-skill-standard.py — Align SKILL.md files with Agent Skills Open Standard.

Supports two modes:
  1. Initial setup (no existing frontmatter): adds frontmatter + progressive disclosure
  2. Repair (--repair): re-fixes frontmatter on files that already have it

Fixes:
  - Truncated descriptions (sentence-boundary truncation, not [:300])
  - Fallback "Security skill domain" (matches ## Purpose, ## Overview, etc.)
  - Missing origin field (ECC requirement)
  - YAML injection (escapes inner quotes and colons)
  - Summary/Description duplication (concise summary)
  - tool_count: 0 (matches ## Tools, ## Core Tools, sub-tables)

Usage:
  python3 validation/update-skill-standard.py [--dry-run] [--skill <name>] [--repair]
"""

import os
import re
import sys

SKILLS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "skills")
VERSION = "0.1.20"
ORIGIN = "openclaw"

COMPATIBILITY = ["openclaw", "claude-code", "cursor", "windsurf"]

SECURITY_TOOLS = ["Bash", "Read", "Write", "Edit", "WebSearch", "WebFetch"]
ANALYSIS_TOOLS = ["Bash", "Read", "Write", "Edit", "WebSearch", "WebFetch", "Agent"]

ANALYSIS_SKILLS = {
    "article-writing", "chronicle", "codebase-onboarding", "continuous-learning",
    "council", "deep-research", "engagement-manager", "exa-search", "knowledge-ops",
    "mcp-server-patterns", "multi-agent-collaboration", "search-first",
    "security-review", "repo-scan", "verification-loop", "tool-mastery",
    "browser-qa", "data-scraper-agent", "terminal-ops", "autonomous-loops",
    "safety-guard", "pentest-reporting"
}

ATTACK_SKILLS = {
    "web-sqli", "web-xss", "web-ssrf", "web-auth-bypass", "web-access-control",
    "web-xxe", "file-inclusion", "api-security", "network-pentest",
    "network-sniffing-mitm", "dns-attacks", "wifi-pentest",
    "exploit-development", "payload-generation", "av-edr-evasion",
    "post-exploitation", "privilege-escalation", "password-attack",
    "cms-framework-attack", "binary-reverse", "mobile-security",
    "hardware-security", "digital-forensics", "steganography",
    "social-engineering", "social-intelligence", "osint", "recon-osint",
    "vulnerability-assessment", "cloud-security", "container-security",
    "supply-chain-security", "crypto-attacks", "insecure-design",
    "logging-monitoring", "security-misconfiguration", "docker-patterns",
    "ai-security", "ai-fuzzing", "security-bounty-hunter",
    "bluetooth-rfid-nfc", "network-tunneling-proxy", "firmware-reverse",
    "scada-ics-security", "database-attack", "voip-sip-attack",
    "anti-forensics",
    "ad-ldap-attack"
}

DOMAIN_MAP = {
    "web-sqli": "web-attack", "web-xss": "web-attack", "web-ssrf": "web-attack",
    "web-auth-bypass": "web-attack", "web-access-control": "web-attack",
    "web-xxe": "web-attack", "file-inclusion": "web-attack", "api-security": "web-attack",
    "network-pentest": "network-attack", "network-sniffing-mitm": "network-attack",
    "dns-attacks": "network-attack", "wifi-pentest": "network-attack",
    "exploit-development": "exploitation", "payload-generation": "exploitation",
    "av-edr-evasion": "exploitation",
    "post-exploitation": "post-exploitation", "privilege-escalation": "post-exploitation",
    "password-attack": "credential-access",
    "cms-framework-attack": "web-attack",
    "binary-reverse": "binary-analysis", "mobile-security": "mobile",
    "hardware-security": "hardware", "digital-forensics": "forensics",
    "steganography": "forensics",
    "social-engineering": "social", "social-intelligence": "osint",
    "osint": "osint", "recon-osint": "osint",
    "vulnerability-assessment": "assessment",
    "cloud-security": "cloud", "container-security": "cloud",
    "supply-chain-security": "supply-chain",
    "crypto-attacks": "cryptography", "insecure-design": "design",
    "logging-monitoring": "defense", "security-misconfiguration": "defense",
    "docker-patterns": "infrastructure", "ai-security": "ai", "ai-fuzzing": "ai",
    "security-bounty-hunter": "assessment",
    "article-writing": "knowledge", "chronicle": "knowledge",
    "codebase-onboarding": "knowledge", "continuous-learning": "knowledge",
    "council": "analysis", "deep-research": "research", "engagement-manager": "management",
    "exa-search": "research", "knowledge-ops": "knowledge",
    "mcp-server-patterns": "infrastructure", "multi-agent-collaboration": "infrastructure",
    "search-first": "workflow", "security-review": "assessment",
    "repo-scan": "assessment", "verification-loop": "workflow",
    "tool-mastery": "knowledge", "browser-qa": "testing",
    "data-scraper-agent": "research", "terminal-ops": "workflow",
    "autonomous-loops": "infrastructure", "safety-guard": "defense",
    "bluetooth-rfid-nfc": "wireless", "network-tunneling-proxy": "network-attack",
    "firmware-reverse": "firmware", "scada-ics-security": "ics",
    "database-attack": "database", "voip-sip-attack": "voip",
    "anti-forensics": "forensics", "pentest-reporting": "reporting",
    "ad-ldap-attack": "enterprise",
}

OWASP_MAP = {
    "web-sqli": "A03:2021-Injection", "web-xss": "A03:2021-Injection",
    "web-ssrf": "A10:2021-SSRF", "web-auth-bypass": "A07:2021-Identification",
    "web-access-control": "A01:2021-Broken Access Control",
    "web-xxe": "A05:2021-Security Misconfiguration",
    "file-inclusion": "A01:2021-Broken Access Control",
    "api-security": "API Security Top 10",
    "crypto-attacks": "A04:2021-Cryptographic Failures",
    "insecure-design": "A06:2025-Insecure Design",
    "security-misconfiguration": "A02:2025-Misconfiguration",
    "logging-monitoring": "A09:2021-Logging Failures",
    "supply-chain-security": "A08:2021-Software Integrity",
}

MITRE_MAP = {
    "recon-osint": "TA0043-Reconnaissance", "osint": "TA0043-Reconnaissance",
    "social-engineering": "TA0043-Reconnaissance",
    "social-intelligence": "TA0043-Reconnaissance",
    "network-pentest": "TA0046-Initial Access",
    "wifi-pentest": "TA0046-Initial Access",
    "web-sqli": "T1190-Exploit Public-Facing App",
    "web-xss": "T1189-Drive-by Compromise",
    "web-ssrf": "T1190-Exploit Public-Facing App",
    "password-attack": "TA0006-Credential Access",
    "privilege-escalation": "TA0004-Privilege Escalation",
    "post-exploitation": "TA0005-Defense Evasion",
    "payload-generation": "TA0007-Command and Control",
    "av-edr-evasion": "TA0005-Defense Evasion",
    "exploit-development": "TA0002-Execution",
    "dns-attacks": "TA0011-Command and Control",
    "network-sniffing-mitm": "TA0006-Credential Access",
    "cloud-security": "TA0008-Lateral Movement",
    "container-security": "TA0008-Lateral Movement",
    "bluetooth-rfid-nfc": "TA0046-Initial Access",
    "firmware-reverse": "TA0002-Execution",
    "scada-ics-security": "TA0100-ICS Attack",
    "database-attack": "TA0006-Credential Access",
    "voip-sip-attack": "TA0046-Initial Access",
    "anti-forensics": "TA0005-Defense Evasion",
    "network-tunneling-proxy": "TA0008-Lateral Movement",
    "ad-ldap-attack": "TA0006-Credential Access",
}

# Non-tool entries to skip in tool tables
SKIP_TOOLS = {
    'First Principles', 'Trust but Verify', 'Divergent Thinking',
    'Minimize Attack Surface', 'Defense in Depth', 'Assume Breach',
    'Least Privilege', "Murphy's Security Law", 'Obscurity Is Not Security',
    'Skill Over Credentials', 'Pre-condition', 'Post-condition',
    'Verification', 'Supply Chain Trust', 'Network Egress',
    'Endpoint Protection', 'Email/Web Gateway', 'Process Monitoring',
    'Capture tool', 'MITM framework', 'Poisoning technique',
    'SSL stripping', 'Credential cracking', 'Coverage-Guided Testing',
    'Sanitizer Integration', 'Write-Blockers', 'Hash Verification',
    'Chain of Custody', 'Imaging Best Practices', 'Documentation',
    'Tool Validation', 'Code Obfuscation', 'Certificate Pinning',
    'Root/Jailbreak Detection', 'Anti-Tampering', 'Secure Storage',
    'Anti-Debug', 'Input Validation', 'Rate Limiting', 'OAuth2 + JWT',
    'Response Filtering', 'GraphQL Protection', 'API Gateway',
    'Security Awareness Training', 'Email Filtering (SPF/DKIM/DMARC)',
    'MFA (Multi-Factor Auth)', 'Verification Procedures',
    'Physical Access Control', 'USB Port Policy',
    'Employee OPSEC training', 'Social media monitoring',
    'Username hygiene', 'Information classification',
    'Glassdoor/Reddit monitoring',
    'Output Encoding', 'Content Security Policy', 'Cookie Protection',
    'Framework Built-in Protection', 'DOMPurify',
    'Password Policy', 'Session Management', 'MFA Enforcement',
    'Login Monitoring', 'JWT Best Practices',
    'Centralized Logging', 'Tamper-Proof Storage', 'Standardized Format',
    'Real-Time Alerting', 'Log Integrity Verification', 'Automated Analysis',
    'Lock Files', 'Signature Verification', 'SBOM (Software Bill of Materials)',
    'SCA Tools', 'Version Pinning', 'Private Registry', 'CI/CD Hardening',
    'Disable DTDs', 'Disable External Entities', 'Disable Parameter Entities',
    'XML Parser Hardening', 'WAF/IPS Rules', 'Safe Coding',
    'Core Asset', 'Extract & Update', 'Rebuild', 'Deprecate', 'Manual Analysis',
    'NX (No-eXecute)', 'ASLR', 'Stack Canary', 'PIE', 'Full RELRO',
    'NX (DEP)', 'Seccomp',
    'OWASP Threat Dragon', 'STRIDE Methodology',
    'draw.io / diagrams.net', 'Python threading / asyncio',
    'Burp Suite (Turbo Intruder)', 'Python asyncio',
    'OSS-Fuzz', 'CI/CD Fuzzing', 'Address Sanitizer (ASAN)',
}


def ensure_terminal_punctuation(text: str) -> str:
    """Ensure text ends with terminal punctuation, stripping trailing markdown artifacts."""
    text = text.rstrip()
    # Strip trailing markdown bold, quotes, brackets, colons, ampersands
    while text and text[-1] in '*"):]&\'\n':
        text = text[:-1].rstrip()
    if text and text[-1] not in '.!?':
        text += '.'
    return text


def truncate_at_sentence(text: str, max_len: int = 280) -> str:
    """Truncate text at the last sentence boundary before max_len."""
    text = re.sub(r'\s+', ' ', text).strip()
    if len(text) <= max_len:
        return text

    # Find last sentence-ending punctuation before max_len
    truncated = text[:max_len]
    for sep in ['. ', '.\n', '! ', '? ']:
        last = truncated.rfind(sep)
        if last > 0:
            return text[:last + 1].strip()

    # No sentence boundary found — try comma or semicolon
    for sep in [', ', '; ', ' — ', ' - ']:
        last = truncated.rfind(sep)
        if last > max_len * 0.5:
            return text[:last].strip()

    # Last resort: cut at last space before max_len
    last_space = truncated.rfind(' ')
    if last_space > max_len * 0.5:
        return text[:last_space].strip()

    return truncated.strip()


def escape_yaml_string(text: str) -> str:
    """Escape a string for safe YAML double-quoted value."""
    text = text.replace('\\', '\\\\')
    text = text.replace('"', '\\"')
    return text


def extract_description(content: str) -> str:
    """Extract description from multiple possible section headers."""
    # Strip code blocks first to avoid template content (e.g. article-writing)
    no_code = re.sub(r'```.*?```', '', content, flags=re.DOTALL)
    # Also strip inline code that might contain placeholder text
    no_code = re.sub(r'`[^`]+`', '', no_code)

    # Try in order: ## Description, ## Overview, ## Purpose
    patterns = [
        r'## Description\s*\n\n(.+?)(?:\n\n|\n---|\n\*\*)',
        r'## Overview\s*\n\n(.+?)(?:\n\n|\n---|\n\*\*)',
        r'## Purpose\s*\n\n(.+?)(?:\n\n|\n---|\n\*\*)',
    ]

    for pattern in patterns:
        match = re.search(pattern, no_code, re.DOTALL)
        if match:
            desc = match.group(1).strip()
            # Skip template placeholders
            if desc.startswith('[') and desc.endswith(']'):
                continue
            if '[What is' in desc or '[Describe' in desc:
                continue
            desc = re.sub(r'\s+', ' ', desc)
            return truncate_at_sentence(desc)

    # Try extracting from first paragraph after ## Summary (but NOT "Security skill domain")
    summary_match = re.search(
        r'## Summary\s*\n\n(.+?)(?:\n\n|\n\*\*)',
        no_code, re.DOTALL
    )
    if summary_match:
        desc = summary_match.group(1).strip()
        desc = re.sub(r'\s+', ' ', desc)
        if desc != "Security skill domain" and len(desc) > 30:
            return truncate_at_sentence(desc)

    # Try ## Core Principle first paragraph (not bullet lists)
    cp_match = re.search(
        r'## Core Principle\s*\n\n(.+?)(?:\n\n|\n## )',
        no_code, re.DOTALL
    )
    if cp_match:
        desc = cp_match.group(1).strip()
        # Skip if it's a bullet list
        if not desc.startswith('-') and not desc.startswith('*'):
            desc = re.sub(r'\s+', ' ', desc)
            if len(desc) > 20:
                return truncate_at_sentence(desc)

    # Try first paragraph after ## Activation
    for header in ['## Activation']:
        act_match = re.search(
            rf'{re.escape(header)}.*?\n\n((?:[-*] .+\n?)+)',
            no_code, re.DOTALL
        )
        if not act_match:
            act_match = re.search(
                rf'{re.escape(header)}\s*\n\n(.+?)(?:\n\n|\n## )',
                no_code, re.DOTALL
            )
        if act_match:
            desc = act_match.group(1).strip()
            desc = re.sub(r'\s+', ' ', desc)
            # Clean bullet prefixes
            desc = re.sub(r'^[-*] ', '', desc, flags=re.MULTILINE)
            if len(desc) > 20:
                return truncate_at_sentence(desc)

    # Final fallback: first meaningful paragraph after the title
    title_match = re.search(r'^# .+$', no_code, re.MULTILINE)
    if title_match:
        after_title = no_code[title_match.end():]
        para_match = re.search(r'\n\n([A-Z][^.]*\.)', after_title, re.DOTALL)
        if para_match:
            desc = para_match.group(1).strip()
            desc = re.sub(r'\s+', ' ', desc)
            return truncate_at_sentence(desc)

    return "Security skill domain"


def extract_tool_names(content: str) -> list[str]:
    """Extract tool names from any tool table (## Core Tools, ## Tools, sub-sections)."""
    seen: list[str] = []

    # Match any section with "Tools" in the header
    tools_section = re.search(
        r'## (?:Core )?Tools.*?\n\n((?:\|.*\n)+)',
        content, re.DOTALL
    )
    if not tools_section:
        # Try sub-section: ### .*Tools
        tools_section = re.search(
            r'### .*Tools.*?\n\n((?:\|.*\n)+)',
            content, re.DOTALL
        )

    if tools_section:
        for line in tools_section.group(1).split('\n'):
            m = re.match(r'\|\s*\*\*(.+?)\*\*', line)
            if m:
                name = m.group(1).strip()
                if name not in SKIP_TOOLS and name not in seen:
                    seen.append(name)

    # Also check for tool tables embedded in sub-sections
    for sub_match in re.finditer(
        r'(?:###|##) .*?(?:tool|scanner|framework|utility).*?\n\n((?:\|.*\n)+)',
        content, re.DOTALL | re.IGNORECASE
    ):
        for line in sub_match.group(1).split('\n'):
            m = re.match(r'\|\s*\*\*(.+?)\*\*', line)
            if m:
                name = m.group(1).strip()
                if name not in SKIP_TOOLS and name not in seen:
                    seen.append(name)

    return seen


def strip_frontmatter(content: str) -> str:
    """Remove existing YAML frontmatter."""
    return re.sub(r'^---\n.*?\n---\n?', '', content, flags=re.DOTALL)


def strip_old_summary(content: str) -> str:
    """Remove old ## Summary section that was auto-generated."""
    return re.sub(
        r'\n## Summary\s*\n\n.*?(?=\n## |\Z)',
        '',
        content,
        flags=re.DOTALL
    )


def build_frontmatter(skill_name: str, content: str) -> str:
    """Build YAML frontmatter for a SKILL.md file."""
    description = ensure_terminal_punctuation(extract_description(content))
    tool_names = extract_tool_names(content)
    domain = DOMAIN_MAP.get(skill_name, "security")

    if skill_name in ATTACK_SKILLS:
        allowed_tools = SECURITY_TOOLS
    elif skill_name in ANALYSIS_SKILLS:
        allowed_tools = ANALYSIS_TOOLS
    else:
        allowed_tools = ["Bash", "Read", "Write", "Edit", "WebSearch", "WebFetch", "Agent"]

    guides_dir = os.path.join(SKILLS_DIR, skill_name, "guides")
    guide_count = 0
    if os.path.isdir(guides_dir):
        guide_count = len([f for f in os.listdir(guides_dir) if f.endswith('.md')])

    lines = ["---"]
    lines.append(f"name: {skill_name}")
    lines.append(f'description: "{escape_yaml_string(description)}"')
    lines.append(f"origin: {ORIGIN}")
    lines.append(f'version: "{VERSION}"')
    lines.append("compatibility:")
    for c in COMPATIBILITY:
        lines.append(f"  - {c}")
    lines.append("allowed-tools:")
    for t in allowed_tools:
        lines.append(f"  - {t}")
    lines.append("metadata:")
    lines.append(f"  domain: {domain}")
    lines.append(f"  tool_count: {len(tool_names)}")
    lines.append(f"  guide_count: {guide_count}")
    owasp = OWASP_MAP.get(skill_name, "")
    if owasp:
        lines.append(f'  owasp: "{owasp}"')
    mitre = MITRE_MAP.get(skill_name, "")
    if mitre:
        lines.append(f'  mitre: "{mitre}"')
    lines.append("---")

    return "\n".join(lines)


def build_summary(skill_name: str, content: str) -> str:
    """Build concise Summary section distinct from Description.

    Strategy: use ## Purpose if available and different from Description,
    otherwise generate a skill-name-based summary, never just copy Description.
    """
    description = extract_description(content)
    tool_names = extract_tool_names(content)
    domain = DOMAIN_MAP.get(skill_name, "security")

    # Strip code blocks for clean extraction
    no_code = re.sub(r'```.*?```', '', content, flags=re.DOTALL)

    # Try ## Purpose first — it's usually a different angle than ## Description
    summary_text = ""
    purpose_match = re.search(
        r'## Purpose\s*\n\n(.+?)(?:\n\n|\n---|\n\*\*)',
        no_code, re.DOTALL
    )
    if purpose_match:
        purpose_text = purpose_match.group(1).strip()
        purpose_text = re.sub(r'\s+', ' ', purpose_text)
        # Only use if meaningfully different from description
        if purpose_text[:60] != description[:60] and len(purpose_text) > 20:
            summary_text = truncate_at_sentence(purpose_text, max_len=200)

    # Fallback: use second sentence of description if it has multiple sentences
    if not summary_text:
        for sep in ['. ', '.\n']:
            pos = description.find(sep)
            if pos > 0:
                second_part = description[pos + len(sep):].strip()
                if len(second_part) > 20:
                    summary_text = truncate_at_sentence(second_part, max_len=200)
                    break

    # Last resort: generate from skill name + domain
    if not summary_text:
        summary_text = f"{skill_name.replace('-', ' ').title()} skill domain covering {domain.replace('-', ' ')} operations."

    summary_text = ensure_terminal_punctuation(summary_text)

    summary = f"\n## Summary\n\n{summary_text}\n"

    if tool_names:
        tools_str = ', '.join(tool_names[:8])
        if len(tool_names) > 8:
            tools_str += f" (+{len(tool_names) - 8} more)"
        summary += f"\n**Tools**: {tools_str}\n"

    summary += f"\n**Domain**: {domain}\n"

    owasp = OWASP_MAP.get(skill_name)
    if owasp:
        summary += f"\n**OWASP**: {owasp}\n"
    mitre = MITRE_MAP.get(skill_name)
    if mitre:
        summary += f"\n**MITRE ATT&CK**: {mitre}\n"

    return summary


def process_skill(skill_name: str, dry_run: bool = False, repair: bool = False) -> bool:
    """Process a single SKILL.md: add or repair frontmatter + summary."""
    skill_path = os.path.join(SKILLS_DIR, skill_name, "SKILL.md")
    if not os.path.exists(skill_path):
        print(f"  SKIP {skill_name}: no SKILL.md found")
        return False

    with open(skill_path, 'r') as f:
        original = f.read()

    has_frontmatter = original.startswith('---')

    if has_frontmatter and not repair:
        print(f"  SKIP {skill_name}: already has frontmatter (use --repair to re-fix)")
        return False

    if not has_frontmatter and repair:
        print(f"  SKIP {skill_name}: no frontmatter to repair")
        return False

    # Strip old frontmatter and old summary
    body = strip_frontmatter(original)
    body = strip_old_summary(body)

    # Build new frontmatter and summary
    frontmatter = build_frontmatter(skill_name, body)
    summary = build_summary(skill_name, body)

    # Insert summary after title/supplementary block, before first ## section
    # Find first ## header after the > block
    insert_pos = 0
    lines = body.split('\n')
    past_header = False
    for i, line in enumerate(lines):
        if line.startswith('# ') and not past_header:
            past_header = True
            continue
        if past_header and line.startswith('## '):
            insert_pos = i
            break

    if insert_pos > 0:
        before = '\n'.join(lines[:insert_pos]).rstrip()
        after = '\n'.join(lines[insert_pos:])
        new_body = before + "\n" + summary + "\n" + after
    else:
        new_body = body + summary

    new_content = frontmatter + "\n\n" + new_body

    if dry_run:
        desc_preview = extract_description(body)[:80]
        tools = extract_tool_names(body)
        print(f"  WOULD FIX {skill_name}: desc=\"{desc_preview}...\", tools={len(tools)}")
    else:
        with open(skill_path, 'w') as f:
            f.write(new_content)
        desc_preview = extract_description(body)[:80]
        tools = extract_tool_names(body)
        print(f"  FIXED {skill_name}: desc=\"{desc_preview}...\", tools={len(tools)}, {len(original)} -> {len(new_content)} chars")

    return True


def main() -> None:
    dry_run = "--dry-run" in sys.argv
    repair = "--repair" in sys.argv
    skill_filter = None
    for i, arg in enumerate(sys.argv):
        if arg == "--skill" and i + 1 < len(sys.argv):
            skill_filter = sys.argv[i + 1]

    skills = sorted([
        d for d in os.listdir(SKILLS_DIR)
        if os.path.isdir(os.path.join(SKILLS_DIR, d))
    ])

    if skill_filter:
        skills = [s for s in skills if s == skill_filter]

    mode = "repair" if repair else "initial setup"
    print(f"Processing {len(skills)} skills (mode={mode}, dry_run={dry_run})")
    print(f"Fixes: sentence-boundary descriptions, origin field, YAML escaping, tool extraction, concise summaries")
    print()

    updated = 0
    skipped = 0
    for skill in skills:
        if process_skill(skill, dry_run, repair):
            updated += 1
        else:
            skipped += 1

    print()
    print(f"Done: {updated} updated, {skipped} skipped, {len(skills)} total")

    if not dry_run:
        print(f"\nVerification:")
        print(f"  grep -l '^origin: openclaw' skills/*/SKILL.md | wc -l")
        print(f"  grep -c 'tool_count: 0' skills/*/SKILL.md")
        print(f"  bash validation/heartbeat.sh")


if __name__ == "__main__":
    main()
